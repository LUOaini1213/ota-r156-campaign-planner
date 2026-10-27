"""测试和演示共用的场景搭建（全部是合成数据，密钥在运行时生成）。

UpdateBed = Image 仓库 + Director 仓库 + 不可信镜像通道（Mirror）+ 一台 ECU 及其更新客户端。
攻击者的手段只有两类：在通道里替换 / 丢弃 / 无限灌数据（bed.mirror.overrides / image_overrides），
或者拿到某个仓库的部分密钥后自己签名（用 bed.director / bed.image_repo 上的密钥模拟“密钥被盗”）。
"""
from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .canonical import sha256_hex, strict_loads
from .client import HealthCheck, Preconditions, UpdateClient
from .crypto import SigningKey
from .ecu import ECU, identity_of
from .metadata import decode, encode, format_time, sign
from .nvstore import NVStore, PowerCut
from .repository import Repository
from .transport import Mirror
from .verifier import RepoState

NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)      # 与 P3 演示的 as_of 一致
ECU_ID, HW_ID = "ECU-DEMO-01", "A-H1"                  # 合成编号；硬件代号沿用 P3 合成车队里虚构的 A-H1 / A-H2
OTHER_ECU_ID, OTHER_HW_ID = "ECU-DEMO-02", "A-H2"
INVENTORY = {ECU_ID: HW_ID, OTHER_ECU_ID: OTHER_HW_ID}  # 车上有哪些 ECU（Primary 用来核对 Director 的指派）
CHUNK_SIZE = 512
SLOT_CAPACITY = 16 * 1024
IMAGE_SIZE = 2048


@dataclass(frozen=True)
class Release:
    """一次软件发布。sw_version 是给人看的版本号；secure_version 是防回滚下限；release_counter 是 Uptane 的发布计数。"""

    sw_version: str
    secure_version: int
    release_counter: int
    rxswin: str
    hardware_identifiers: tuple[str, ...] = (HW_ID,)
    size: int = IMAGE_SIZE

    @property
    def filename(self) -> str:
        return f"demo-ecu_{self.sw_version}_rc{self.release_counter}.bin"

    def payload(self) -> bytes:
        """确定性的合成镜像内容（不是真实固件）。"""
        seed = self.filename.encode()
        blocks = b"".join(hashlib.sha256(seed + i.to_bytes(4, "big")).digest() for i in range(self.size // 32 + 1))
        return blocks[: self.size]

    def custom(self) -> dict:
        """Image 仓库的自定义元数据（§5.2.3.1.1：release counter、硬件标识；其余是本项目加的 OEM 字段）。"""
        return {"hardware_identifiers": list(self.hardware_identifiers), "release_counter": self.release_counter,
                "sw_version": self.sw_version, "secure_version": self.secure_version, "rxswin": self.rxswin}


# 版本号与 RXSWIN 沿用 P3 活动配置里 MODEL_A 的登记册：1.4.2 / 1.5.0 → A-RX-06，1.6.0 → A-RX-07
FACTORY = Release("1.5.0", secure_version=2, release_counter=5, rxswin="A-RX-06")
NEW = Release("1.6.0", secure_version=3, release_counter=6, rxswin="A-RX-07")
OLD_VULNERABLE = Release("1.4.2", secure_version=1, release_counter=4, rxswin="A-RX-06")
PAIRS = {(FACTORY.sw_version, FACTORY.rxswin), (NEW.sw_version, NEW.rxswin)}


def identity(release: Release) -> dict:
    data = release.payload()
    return {"ecu_identifier": ECU_ID, "hardware_identifier": release.hardware_identifiers[0],
            "image_filename": release.filename, "image_length": len(data), "image_sha256": sha256_hex(data),
            "sw_version": release.sw_version, "secure_version": release.secure_version,
            "release_counter": release.release_counter, "rxswin": release.rxswin}


class UpdateBed:
    __test__ = False      # 不让 pytest 把它当测试类收集

    def __init__(self, *, health_check: HealthCheck | None = None, preconditions: Preconditions | None = None,
                 factory: Release = FACTORY) -> None:
        self.now = NOW
        self.factory = factory
        self.health_check = health_check
        self.preconditions = preconditions
        self.image_repo = Repository.image_repository(NOW)
        self.director = Repository.director_repository(NOW)
        self.release(factory)
        self.director.publish()
        self.mirror = Mirror(self.director, self.image_repo)
        self.ecu_key = SigningKey()
        self.nv = NVStore()
        self.ecu = self._new_ecu()
        self.ecu.provision(factory.payload(), identity(factory), self.initial_trust())
        self.client = self._new_client()

    def initial_trust(self) -> dict:
        return {name: RepoState(root=decode(repo.files["1.root.json"], "root")["signed"]).to_dict()
                for name, repo in (("director", self.director), ("image", self.image_repo))}

    def _new_ecu(self) -> ECU:
        return ECU(self.nv, ecu_id=ECU_ID, hw_id=HW_ID, identity_key=self.ecu_key,
                   slot_capacity=SLOT_CAPACITY, chunk_size=CHUNK_SIZE)

    def _new_client(self) -> UpdateClient:
        return UpdateClient(self.ecu, self.mirror, lambda: self.now, inventory=INVENTORY,
                            health_check=self.health_check, preconditions=self.preconditions)

    # ---------------------------------------------------------------- OEM 的合法操作
    def release(self, rel: Release, **publish_kwargs) -> dict:
        entry = self.image_repo.add_target(rel.filename, rel.payload(), rel.custom())
        self.image_repo.publish(**publish_kwargs)
        return entry

    def director_entry(self, rel: Release, *, ecu_id: str = ECU_ID, hardware_identifier: str | None = None,
                       **custom) -> dict:
        image_entry = self.image_repo.targets[rel.filename]
        return {"length": image_entry["length"], "hashes": dict(image_entry["hashes"]),
                "custom": {"ecu_identifier": ecu_id,
                           "hardware_identifier": hardware_identifier or rel.hardware_identifiers[0],
                           "release_counter": rel.release_counter, "rxswin": rel.rxswin, **custom}}

    def assign(self, rel: Release, *, ecu_id: str = ECU_ID, hardware_identifier: str | None = None, **custom) -> dict:
        """Director 指派：给某个 ECU 装某个镜像（每个 ECU 只保留一个指派）。"""
        entry = self.director_entry(rel, ecu_id=ecu_id, hardware_identifier=hardware_identifier, **custom)
        self.director.targets = {k: v for k, v in self.director.targets.items()
                                 if v["custom"]["ecu_identifier"] != ecu_id}
        self.director.set_target_entry(rel.filename, entry)
        self.director.publish()
        return entry

    def halt_campaign(self) -> None:
        """后端叫停活动：Director 撤回全部指派（对应 P3 的 HALT 闸门）。"""
        self.director.targets.clear()
        self.director.publish()

    def advance(self, *, refresh: bool = True, **delta) -> None:
        """时间前进。refresh=True 表示两个仓库照常重签元数据（正常运营）。"""
        self.now += timedelta(**delta)
        for repo in (self.director, self.image_repo):
            repo.now = self.now
            if refresh:
                repo.publish()

    # ---------------------------------------------------------------- 断电与复制
    def restart(self) -> None:
        """断电后重新上电：易失状态全部丢失，只剩非易失存储。"""
        self.nv.restore_power()
        self.ecu = self._new_ecu()
        self.client = self._new_client()

    def fork(self) -> "UpdateBed":
        """复制一份：共用仓库和通道（只读），非易失存储各自独立。断电扫描里每个断点用一份。"""
        twin = copy.copy(self)
        twin.nv = self.nv.clone()
        twin.ecu = twin._new_ecu()
        twin.client = twin._new_client()
        return twin

    # ---------------------------------------------------------------- 观察
    def ecu_state(self) -> dict:
        """与安全相关的 ECU 状态：攻击被拒之后，这几项必须保持不变。"""
        bc = self.ecu.bootctl.read()
        return {"active": bc["active"], "pending": bc["pending"], "swid": bc["swid"], "counter": self.ecu.counter()}

    def committed_pair(self) -> tuple[str, str]:
        swid = self.ecu.bootctl.read()["swid"]
        return swid["sw_version"], swid["rxswin"]


# ==================================================================== 攻击者用的签名工具
def craft_timestamp(repo: Repository, snapshot_bytes: bytes, *, version: int, keys=None) -> bytes:
    """用（被盗的）timestamp 密钥签一个指向任意 snapshot 的 timestamp。"""
    snapshot_version = strict_loads(snapshot_bytes)["signed"]["version"]
    return repo.sign_role("timestamp", repo.timestamp_signed(snapshot_bytes, snapshot_version, version), keys)


def craft_snapshot(repo: Repository, *, targets_version: int, version: int, keys=None) -> bytes:
    signed = {"_type": "snapshot", "version": version, "expires": format_time(repo.now + timedelta(days=7)),
              "meta": {"targets.json": {"version": targets_version}}}
    return repo.sign_role("snapshot", signed, keys)


def craft_root(repo: Repository, *, version: int, root_keys: list[SigningKey], signers: list[SigningKey]) -> bytes:
    """伪造一版 root：列出 root_keys 作为 root 角色的密钥，用 signers 签名。"""
    signed = repo.root_signed(version)
    for key in root_keys:
        signed["keys"][key.keyid] = key.public
    signed["roles"]["root"] = {"keyids": [k.keyid for k in root_keys], "threshold": repo.thresholds["root"]}
    return encode(sign(signed, signers))


def tamper_signed(data: bytes, mutate) -> bytes:
    """改动 signed 部分但保留原签名（攻击者没有密钥时只能这样）。"""
    env = strict_loads(data)
    mutate(env["signed"])
    return encode(env)


# ==================================================================== 断电扫描
def check_invariants(bed: UpdateBed, allowed_pairs: set[tuple[str, str]]) -> list[str]:
    """一次会话结束后必须成立的性质；返回发现的问题（空列表 = 全部成立）。"""
    problems = []
    ecu = bed.ecu
    bc = ecu.bootctl.read()
    header = ecu.headers[bc["active"]].read()
    if bc["pending"]:
        problems.append("会话结束后仍有 pending 槽")
    if ecu.running != bc["active"]:
        problems.append(f"正在运行的槽 {ecu.running} 不是 active 槽 {bc['active']}")
    if not ecu.slot_bootable(bc["active"], ecu.counter()):
        problems.append("active 槽不可启动")
    if not isinstance(header, dict) or bc["swid"] != identity_of(header):
        problems.append("已提交的软件标识与 active 槽内容不一致")
    if bed.committed_pair() not in allowed_pairs:
        problems.append(f"软件版本与 RXSWIN 配对异常：{bed.committed_pair()}")
    if isinstance(header, dict) and ecu.counter() > header["secure_version"]:
        problems.append("防回滚计数器高于 active 镜像的 secure_version")
    if ecu.journal.read()["state"] != "IDLE":
        problems.append("更新日志没有回到 IDLE")
    return problems


def bootable_at_cut(bed: UpdateBed, allowed_pairs: set[tuple[str, str]]) -> list[str]:
    """断电那一刻（还没恢复）：active 槽必须可启动，已提交的配对必须是新旧之一。"""
    problems = []
    bc = bed.ecu.bootctl.read()
    if not bed.ecu.slot_bootable(bc["active"], bed.ecu.counter()):
        problems.append("断电时 active 槽不可启动")
    if bed.committed_pair() not in allowed_pairs:
        problems.append(f"断电时软件版本与 RXSWIN 配对异常：{bed.committed_pair()}")
    return problems


def write_steps(template: UpdateBed) -> tuple[str, list[str]]:
    """在 template 的一个副本上跑一次不断电的会话，返回结果和每次持久化写入的步骤名。"""
    probe = template.fork()
    result = probe.client.update()
    return result, list(probe.nv.trace)


def power_cut_sweep(template: UpdateBed, *, torn: bool, allowed_pairs: set[tuple[str, str]] = PAIRS,
                    second_cut: bool = False) -> list[dict]:
    """在一次升级会话的每一次持久化写入处断电；重新上电后再跑一次会话，检查不变量。
    second_cut=True 时，恢复过程中再在每个可能的写入处断一次电（两次断电的全部组合）。"""
    _, steps = write_steps(template)
    rows = []
    for k, step in enumerate(steps, start=1):
        recovery_cuts = [None]
        if second_cut:
            twin = template.fork()
            twin.nv.arm_power_cut(k, torn=torn)
            try:
                twin.client.update()
            except PowerCut:
                pass
            twin.restart()
            start = twin.nv.writes
            twin.client.update()
            recovery_cuts = list(range(1, twin.nv.writes - start + 1))
        for j in recovery_cuts:
            bed = template.fork()
            bed.nv.arm_power_cut(k, torn=torn)
            row = {"write_no": k, "step": step, "second_cut": j, "torn": torn, "problems": []}
            try:
                bed.client.update()
                row["problems"].append("预期的断电没有发生")
            except PowerCut:
                pass
            row["problems"] += bootable_at_cut(bed, allowed_pairs)
            bed.restart()
            if j is not None:
                bed.nv.arm_power_cut(j, torn=torn)
                try:
                    bed.client.update()
                    row["problems"].append("预期的第二次断电没有发生")
                except PowerCut:
                    row["problems"] += bootable_at_cut(bed, allowed_pairs)
                    bed.restart()
            row["final"] = bed.client.update()
            row["final_pair"] = bed.committed_pair()
            row["problems"] += check_invariants(bed, allowed_pairs)
            rows.append(row)
    return rows
