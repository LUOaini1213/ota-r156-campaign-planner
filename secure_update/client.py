"""ECU 更新客户端：校验元数据 → 下载到非活动槽 → 读回校验 → 写槽头 → 标记 pending → 重启试运行 →
健康检查（或试启动次数用完）→ 提交，或自动回滚。

设计要点：
  - 每一步只做一次持久化写入，而且可以重复执行（幂等）。断电后从非易失存储里的状态接着走。
  - 下载和写入只碰非活动槽；active 槽只在“提交”那一次原子写入里切换，所以任何时刻 active 槽都可启动。
  - 软件标识 / RXSWIN 记录和 active 槽在同一次写入里切换，不会出现“新软件配旧 RXSWIN”。
  - 防回滚计数器在提交之后才提升；试运行失败时旧槽仍然可以启动。
  - 每次会话都重新做完整的元数据校验，包括断点续传和激活之前：活动被叫停（Director 撤回指派）就丢弃未完成的下载。
"""
from __future__ import annotations

from datetime import datetime
from typing import Callable, Iterable, Iterator

from .canonical import sha256_hex
from .ecu import ECU, MAX_TRIAL_BOOTS, BootResult, identity_of, other_slot
from .errors import (AntiRollbackError, ArbitrarySoftwareError, BrickedError, DownloadIncomplete, EndlessDataError,
                     NetworkUnavailable, RollbackAttackError, SecureUpdateError, WrongEcuError)
from .verifier import FullVerifier, VerifiedTarget

MAX_STEPS = 1000
MAX_IMAGE_RETRIES = 1        # 读回哈希不符时重新下载 1 次，仍不符就拒装（与 P3 控制点 C19 一致）

HealthCheck = Callable[[dict], str]           # 返回 "OK" / "FAIL" / "CRASH"
Preconditions = Callable[[], Iterable[str]]   # 返回未满足的先决条件，例如 ["LOW_SOC"]


def bounded_chunks(stream: Iterable[bytes], remaining: int, chunk_size: int, what: str) -> Iterator[bytes]:
    """按 chunk_size 切块，最多读 remaining 字节（Uptane 2.1.0 §5.4.3.3：最多下载 Targets 元数据写明的字节数）。
    流提前结束 → DownloadIncomplete（只交出完整的块）；流里的数据多于签名长度 → 立刻停止，EndlessDataError。"""
    it = iter(stream)
    buf = bytearray()
    while remaining > 0:
        want = min(chunk_size, remaining)
        while len(buf) < want:
            piece = next(it, b"")
            if not piece:
                raise DownloadIncomplete(f"{what}: 数据流提前结束，还差 {remaining - len(buf)} 字节")
            buf += piece
        if len(buf) > remaining:
            raise EndlessDataError(f"{what}: 收到的数据多于签名元数据写明的长度，已停止读取", role="image")
        if want == remaining and next(it, b""):           # 最后一块：先确认后面没有多余数据
            raise EndlessDataError(f"{what}: 收到的数据多于签名元数据写明的长度，已停止读取", role="image")
        piece, buf = bytes(buf[:want]), buf[want:]
        remaining -= want
        yield piece


class UpdateClient:
    def __init__(self, ecu: ECU, transport, clock: Callable[[], datetime], *, inventory: dict[str, str],
                 health_check: HealthCheck | None = None, preconditions: Preconditions | None = None) -> None:
        self.ecu = ecu
        self.transport = transport
        self.clock = clock
        self.inventory = dict(inventory)
        self.health_check = health_check or (lambda header: "OK")
        self.preconditions = preconditions or (lambda: [])

    # ================================================================ 对外接口
    def update(self) -> str:
        """一次 OTA 会话（上电 → 检查 → 安装 → 提交 / 回滚）。返回结果码。
        检测到攻击时：写安全日志，结束本次尝试，抛出对应异常；ECU 的 active 槽、软件标识和计数器都不变。"""
        self.power_on()
        bc, journal = self.ecu.bootctl.read(), self.ecu.journal.read()
        if bc["pending"] or (journal["state"] == "READY" and self._activation_done(bc, journal)):
            return self._drive()                           # 激活已经开始：先把它走完（提交或回滚）
        try:
            target = self._verify_metadata()
        except NetworkUnavailable:
            return "DEFERRED_NO_NETWORK"                   # 联网确认不了活动仍然有效，就不继续
        if journal["state"] != "IDLE" and (target is None or target.to_dict() != journal["target"]):
            self._finish(journal, "ABORTED_ASSIGNMENT_CHANGED")   # 活动被叫停或换了目标：丢弃未完成的下载
            if target is None:
                return "ABORTED_ASSIGNMENT_CHANGED"
            journal = self.ecu.journal.read()
        if target is None:
            return "NO_UPDATE"
        if journal["state"] == "IDLE":
            last = journal.get("target") or {}
            if journal["result"] == "ROLLED_BACK" and last.get("sha256") == target.sha256:
                return "SKIPPED_PREVIOUSLY_ROLLED_BACK"    # 同一个镜像健康检查失败过，不自动重试，等后端决定
            self._guarded(self._precheck, target)
            self.ecu.journal.write({"state": "DOWNLOADING", "attempt": journal["attempt"] + 1,
                                    "target": target.to_dict(), "slot": other_slot(bc["active"]),
                                    "offset": 0, "retries": 0}, "更新日志：开始下载到非活动槽")
        return self._drive()

    def power_on(self) -> BootResult:
        """上电或复位：易失状态清空，由 bootloader 决定从哪个槽运行。"""
        self.ecu.running = None
        result = self.ecu.boot()
        if result.slot is None:
            raise BrickedError(result.note)
        return result

    # ================================================================ 元数据与镜像检查
    def _verify_metadata(self) -> VerifiedTarget | None:
        trust = self.ecu.trust.read()
        verifier = FullVerifier.from_trust(trust, self.inventory)
        installed = {self.ecu.ecu_id: self.ecu.active_identity()["image_sha256"]}
        try:
            found = verifier.verify(self.transport, self.clock(), installed)
        except SecureUpdateError as exc:
            self._log(exc)
            raise
        finally:
            new_trust = verifier.trust()                   # 只包含通过校验的文件
            if new_trust != trust:
                self.ecu.trust.write(new_trust, "持久化已信任元数据")
        return found.get(self.ecu.ecu_id)

    def _precheck(self, t: VerifiedTarget) -> None:
        """下载前的镜像层检查：Uptane 2.1.0 §5.4.3.4 的硬件标识、release counter，加上本项目的容量和防回滚下限。"""
        active = self.ecu.active_identity()
        if t.hardware_identifier != self.ecu.hw_id:
            raise WrongEcuError(f"{t.filename}: 硬件标识 {t.hardware_identifier} 与本 ECU 的 {self.ecu.hw_id} 不符",
                                role="image")
        if t.length > self.ecu.slot_capacity:
            raise EndlessDataError(f"{t.filename}: 声明长度 {t.length} 超过槽位容量 {self.ecu.slot_capacity}", role="image")
        if t.release_counter < active["release_counter"]:
            raise RollbackAttackError(f"{t.filename}: release counter {t.release_counter} 低于已安装镜像的 "
                                      f"{active['release_counter']}", role="image")
        if t.secure_version < self.ecu.counter():
            raise AntiRollbackError(f"{t.filename}: secure_version {t.secure_version} 低于防回滚计数器 "
                                    f"{self.ecu.counter()}", role="image")

    # ================================================================ 状态机
    def _drive(self) -> str:
        try:
            return self._run()
        except DownloadIncomplete:
            return "DOWNLOAD_INCOMPLETE"                   # 断点留在日志里，下次会话重新校验元数据后续传
        except NetworkUnavailable:
            return "DEFERRED_NO_NETWORK"

    def _run(self) -> str:
        for _ in range(MAX_STEPS):
            bc, journal = self.ecu.bootctl.read(), self.ecu.journal.read()
            if bc["pending"]:
                if self.ecu.running == bc["pending"]:
                    self._trial(bc)
                else:
                    self.power_on()
                continue
            state = journal["state"]
            if state == "IDLE":
                return journal["result"]
            if state == "DOWNLOADING":
                self._guarded(self._download, journal)
            elif state == "DOWNLOADED":
                self._guarded(self._verify_image, journal)
            elif state == "READY":
                if self._activation_done(bc, journal):
                    self._finalize(bc, journal)
                else:
                    missing = list(self.preconditions())
                    if missing:                            # R156 7.2.2.5：先决条件不满足就不执行，下载保留
                        return "DEFERRED_PRECONDITIONS:" + ",".join(missing)
                    self._activate(bc, journal)
            else:
                raise RuntimeError(f"未知的更新日志状态 {state}")
        raise RuntimeError("更新状态机没有收敛")

    def _download(self, journal: dict) -> None:
        t = VerifiedTarget.from_dict(journal["target"])
        slot, offset = journal["slot"], journal["offset"]
        if offset == 0:
            self.ecu.headers[slot].write({"valid": False}, f"槽 {slot}：作废旧槽头")
        stream = self.transport.fetch_image(t.filename, offset)
        for piece in bounded_chunks(stream, t.length - offset, self.ecu.chunk_size, t.filename):
            index = offset // self.ecu.chunk_size
            self.ecu.write_chunk(slot, index, piece, f"槽 {slot}：写第 {index} 块")
            offset += len(piece)
            state = "DOWNLOADED" if offset == t.length else "DOWNLOADING"
            self.ecu.journal.write({**journal, "state": state, "offset": offset},
                                   f"更新日志：已写 {offset}/{t.length} 字节")

    def _verify_image(self, journal: dict) -> None:
        """读回非活动槽，核对长度和 SHA-256（§5.4.3.4：哈希一致，并且长度与元数据一致）。核对的是已写进 Flash 的内容。"""
        t = VerifiedTarget.from_dict(journal["target"])
        slot = journal["slot"]
        data = self.ecu.read_image(slot, t.length)
        if len(data) != t.length or sha256_hex(data) != t.sha256:
            if journal["retries"] < MAX_IMAGE_RETRIES:
                self.ecu.journal.write({**journal, "state": "DOWNLOADING", "offset": 0, "retries": journal["retries"] + 1},
                                       "更新日志：读回哈希不符，重新下载")
                return
            raise ArbitrarySoftwareError(f"{t.filename}: 重新下载后哈希仍与已签名元数据不符，拒装", role="image")
        header = {"valid": True, "ecu_identifier": self.ecu.ecu_id, "hardware_identifier": t.hardware_identifier,
                  "image_filename": t.filename, "image_length": t.length, "image_sha256": t.sha256,
                  "sw_version": t.sw_version, "secure_version": t.secure_version,
                  "release_counter": t.release_counter, "rxswin": t.rxswin}
        self.ecu.headers[slot].write(header, f"槽 {slot}：写入已校验的槽头")
        self.ecu.journal.write({**journal, "state": "READY"}, "更新日志：镜像已校验，等待激活")

    def _activate(self, bc: dict, journal: dict) -> None:
        self.ecu.bootctl.write({**bc, "pending": journal["slot"], "tries_left": MAX_TRIAL_BOOTS,
                                "pending_attempt": journal["attempt"]},
                               f"启动控制：槽 {journal['slot']} 标记为 pending（最多试启动 {MAX_TRIAL_BOOTS} 次）")
        self.power_on()

    def _trial(self, bc: dict) -> None:
        header = self.ecu.headers[bc["pending"]].read()
        verdict = self.health_check(header)
        if verdict == "CRASH":                 # 新镜像跑不起来：看门狗复位，不写任何东西；bootloader 已经扣过次数
            self.power_on()
            return
        attempt = bc["pending_attempt"]
        if verdict == "OK":
            self.ecu.bootctl.write({"active": bc["pending"], "pending": None, "tries_left": 0, "pending_attempt": None,
                                    "swid": identity_of(header),
                                    "last_result": {"attempt": attempt, "result": "COMMITTED", "reason": "HEALTH_CHECK_OK"}},
                                   "启动控制：提交（active 切到新槽，软件标识 / RXSWIN 在同一次写入里更新）")
            return
        self.ecu.bootctl.write({**bc, "pending": None, "tries_left": 0, "pending_attempt": None,
                                "last_result": {"attempt": attempt, "result": "ROLLED_BACK", "reason": "HEALTH_CHECK_FAILED"}},
                               "启动控制：健康检查失败，清除 pending（回滚）")
        self.power_on()

    def _finalize(self, bc: dict, journal: dict) -> None:
        result = bc["last_result"]["result"]
        if result == "COMMITTED":
            secure_version = self.ecu.active_identity()["secure_version"]
            self.ecu.raise_counter(secure_version, f"防回滚计数器提升到 {secure_version}（提交之后才提升）")
        elif bc["last_result"]["reason"] == "PENDING_IMAGE_INVALID":
            # 校验通过之后槽里的内容又变了（闪存损坏或被改写）：bootloader 拒绝启动，这里记一条安全事件
            self.ecu.log_security_event("BOOT_INTEGRITY", "pending 槽的内容与已校验的槽头不一致，bootloader 拒绝启动",
                                        self.clock())
        self._finish(journal, result)

    # ================================================================ 小工具
    @staticmethod
    def _activation_done(bc: dict, journal: dict) -> bool:
        last = bc.get("last_result")
        return bool(last) and last.get("attempt") == journal.get("attempt")

    def _finish(self, journal: dict, result: str) -> None:
        self.ecu.journal.write({"state": "IDLE", "attempt": journal["attempt"], "result": result,
                                "target": journal.get("target")}, f"更新日志：结束（{result}）")

    def _log(self, exc: SecureUpdateError) -> None:
        self.ecu.log_security_event(exc.attack, str(exc), self.clock())

    def _guarded(self, step: Callable, *args) -> None:
        """执行一步；如果检测到攻击：写安全日志、结束本次尝试（日志回到 IDLE），再把异常抛给调用方。"""
        try:
            step(*args)
        except SecureUpdateError as exc:
            self._log(exc)
            journal = self.ecu.journal.read()
            if journal["state"] != "IDLE":
                self._finish(journal, f"REJECTED_{exc.attack}")
            raise
