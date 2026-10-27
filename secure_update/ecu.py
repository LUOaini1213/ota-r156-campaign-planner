"""ECU 硬件模型：非易失存储、A/B 两个槽位、启动控制块、防回滚计数器、ECU 身份密钥，以及 bootloader。

启动控制块（RedundantRecord，原子更新）是唯一决定“从哪个槽启动”的地方：
  active          已提交、确认可用的槽
  pending         等待试运行的新槽（None 表示没有）
  tries_left      pending 槽还剩几次试启动机会；bootloader 每次先减一并写回，再跳转
  pending_attempt 这次激活属于第几次升级尝试
  swid            已提交的软件标识（含 RXSWIN），与 active 在同一次写入里切换
  last_result     最近一次激活的结果（COMMITTED / ROLLED_BACK），供断电后的客户端判断走到了哪一步

防回滚计数器模拟一个只能递增、断电不丢失的硬件计数器（真实 ECU 用什么硬件实现不在本项目范围）：
bootloader 拒绝 secure_version 低于它的镜像。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .canonical import sha256_hex
from .crypto import SigningKey
from .metadata import encode, format_time, sign
from .nvstore import ChecksummedRecord, NVStore, RedundantRecord

SLOTS = ("A", "B")
MAX_TRIAL_BOOTS = 3          # 新镜像最多试启动 3 次（演示值）
SECURITY_LOG_SIZE = 16       # 安全日志保留最近 16 条（演示值）
IDENTITY_FIELDS = ("ecu_identifier", "hardware_identifier", "image_filename", "image_length", "image_sha256",
                   "sw_version", "secure_version", "release_counter", "rxswin")


def other_slot(slot: str) -> str:
    return "B" if slot == "A" else "A"


def identity_of(header: dict) -> dict:
    """槽头 → 软件标识（R156 意义上的软件版本 + 完整性验证数据 + RXSWIN）。"""
    return {key: header[key] for key in IDENTITY_FIELDS}


@dataclass
class BootResult:
    slot: str | None
    trial: bool = False
    note: str = ""


class ECU:
    def __init__(self, nv: NVStore, *, ecu_id: str, hw_id: str, identity_key: SigningKey, slot_capacity: int,
                 chunk_size: int) -> None:
        self.nv = nv
        self.ecu_id = ecu_id
        self.hw_id = hw_id
        self.identity_key = identity_key      # §5.4.1：每个 ECU 独有的密钥，用来签版本报告（真实 ECU 放在 HSM 里）
        self.slot_capacity = slot_capacity
        self.chunk_size = chunk_size
        self.bootctl = RedundantRecord(nv, "bootctl")
        self.counter_record = RedundantRecord(nv, "anti_rollback_counter")
        self.journal = RedundantRecord(nv, "update_journal")
        self.trust = RedundantRecord(nv, "trusted_metadata")
        self.security_log = RedundantRecord(nv, "security_log")
        self.headers = {slot: ChecksummedRecord(nv, f"slot{slot}.header") for slot in SLOTS}
        self.running: str | None = None       # 易失状态：当前从哪个槽运行；断电后丢失

    # ---------------------------------------------------------------- 出厂
    def provision(self, image: bytes, identity: dict, trust: dict) -> None:
        """出厂刷写（不计入断电扫描）：槽 A 写出厂镜像，启动控制块指向 A，计数器等于出厂镜像的 secure_version，
        预置两个仓库的 root 元数据（§5.4.1：出厂时具备足够新的 Uptane 元数据）。"""
        for index in range(0, len(image), self.chunk_size):
            self.write_chunk("A", index // self.chunk_size, image[index:index + self.chunk_size], "出厂：写槽 A")
        self.headers["A"].write({"valid": True, **identity}, "出厂：槽 A 槽头")
        self.headers["B"].write({"valid": False}, "出厂：槽 B 为空")
        self.bootctl.write({"active": "A", "pending": None, "tries_left": 0, "pending_attempt": None,
                            "swid": dict(identity), "last_result": None}, "出厂：启动控制块")
        self.counter_record.write({"value": identity["secure_version"]}, "出厂：防回滚计数器")
        self.journal.write({"state": "IDLE", "attempt": 0, "result": "FACTORY", "target": None}, "出厂：更新日志")
        self.trust.write(trust, "出厂：预置 root 元数据")
        self.security_log.write({"events": []}, "出厂：安全日志")

    # ---------------------------------------------------------------- 槽位读写
    def write_chunk(self, slot: str, index: int, data: bytes, label: str) -> None:
        self.nv.write(f"slot{slot}.chunk{index:05d}", data, label)

    def read_image(self, slot: str, length: int) -> bytes:
        out = bytearray()
        index = 0
        while len(out) < length:
            piece = self.nv.read(f"slot{slot}.chunk{index:05d}")
            if piece is None:
                break
            out += piece
            index += 1
        return bytes(out[:length])

    def slot_bootable(self, slot: str, counter: int) -> bool:
        """bootloader 的检查：槽头有效、硬件标识相符、secure_version 不低于计数器、镜像哈希与槽头一致。
        真实 ECU 的安全启动还会验镜像签名；这里只重算哈希（槽头是在完整校验之后才写的）。"""
        header = self.headers[slot].read()
        if not isinstance(header, dict) or not header.get("valid"):
            return False
        if header["hardware_identifier"] != self.hw_id or header["secure_version"] < counter:
            return False
        data = self.read_image(slot, header["image_length"])
        return len(data) == header["image_length"] and sha256_hex(data) == header["image_sha256"]

    # ---------------------------------------------------------------- 防回滚计数器
    def counter(self) -> int:
        record = self.counter_record.read()
        return record["value"] if record else 0

    def raise_counter(self, value: int, label: str) -> None:
        """只能升不能降；值没有变就不写。"""
        if value > self.counter():
            self.counter_record.write({"value": value}, label)

    # ---------------------------------------------------------------- bootloader
    def boot(self) -> BootResult:
        bc = self.bootctl.read()
        counter = self.counter()
        pending = bc["pending"]
        if pending:
            if bc["tries_left"] > 0 and self.slot_bootable(pending, counter):
                self.bootctl.write({**bc, "tries_left": bc["tries_left"] - 1},
                                   f"bootloader：消耗一次试启动机会（剩 {bc['tries_left'] - 1} 次）")
                self.running = pending
                return BootResult(pending, trial=True)
            reason = "TRIAL_BOOTS_EXHAUSTED" if bc["tries_left"] <= 0 else "PENDING_IMAGE_INVALID"
            bc = {**bc, "pending": None, "tries_left": 0, "pending_attempt": None,
                  "last_result": {"attempt": bc["pending_attempt"], "result": "ROLLED_BACK", "reason": reason}}
            self.bootctl.write(bc, f"bootloader：自动回滚（{reason}）")
        if self.slot_bootable(bc["active"], counter):
            self.running = bc["active"]
            return BootResult(bc["active"])
        self.running = None
        return BootResult(None, note=f"active 槽 {bc['active']} 不可启动")

    # ---------------------------------------------------------------- 软件标识（RXSWIN）与版本报告
    def active_identity(self) -> dict:
        return dict(self.bootctl.read()["swid"])

    def read_software_identification(self) -> dict:
        """模拟经诊断接口（OBD）读取软件标识和 RXSWIN（R156 7.2.1.2.2）。
        committed 是已提交的记录；试运行期间另给出 trial（待提交的镜像），提交之前 committed 不变。"""
        bc = self.bootctl.read()
        trial = None
        if bc["pending"] and self.running == bc["pending"]:
            header = self.headers[bc["pending"]].read()
            trial = identity_of(header) if isinstance(header, dict) and header.get("valid") else None
        return {"committed": dict(bc["swid"]), "trial": trial}

    def log_security_event(self, attack: str, detail: str, now: datetime) -> None:
        """安全事件写入非易失日志（支撑 R155 7.3.7 的检测与取证；条数是演示值）。"""
        log = self.security_log.read() or {"events": []}
        events = (log["events"] + [{"time": format_time(now), "attack": attack, "detail": detail[:200]}])
        self.security_log.write({"events": events[-SECURITY_LOG_SIZE:]}, f"安全日志：{attack}")

    def version_report(self, nonce: str, now: datetime) -> bytes:
        """ECU 版本报告，用 ECU 身份密钥签名。§5.4.2.1.2 要求的字段：ECU 标识、已安装镜像的文件名 / 长度 / 哈希、
        检测到的攻击、nonce 或计数器；custom 里的软件版本、RXSWIN 等是本项目加的 OEM 字段。"""
        bc = self.bootctl.read()
        swid = bc["swid"]
        events = (self.security_log.read() or {"events": []})["events"]
        signed = {
            "_type": "ecu_version_report",
            "ecu_identifier": self.ecu_id,
            "installed_image": {"filename": swid["image_filename"], "length": swid["image_length"],
                                "hashes": {"sha256": swid["image_sha256"]}},
            "attack_detected": events[-1]["attack"] if events else "",
            "nonce": nonce,
            "report_time": format_time(now),
            "custom": {"hardware_identifier": swid["hardware_identifier"], "sw_version": swid["sw_version"],
                       "secure_version": swid["secure_version"], "release_counter": swid["release_counter"],
                       "rxswin": swid["rxswin"], "update_in_progress": bc["pending"] is not None},
        }
        return encode(sign(signed, [self.identity_key]))
