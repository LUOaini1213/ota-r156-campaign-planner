"""车端元数据校验，参照 Uptane Standard 2.1.0 §5.4.4.2 full verification。

ECU 为每个仓库（Director、Image）保存一份“已信任状态”：最新 root，以及上次通过校验的 timestamp / snapshot / targets。
状态只在某个文件通过全部检查之后才更新，所以攻击者提供的文件永远进不了已信任状态。
各函数注释里的 step 编号对应 Uptane 2.1.0 相应小节的步骤。
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Protocol

from .canonical import sha256_hex
from .errors import (ArbitrarySoftwareError, EndlessDataError, ExpiredMetadataError, MetadataFormatError,
                     MixAndMatchError, NetworkUnavailable, RollbackAttackError, RootRotationError, WrongEcuError)
from .metadata import (decode, is_expired, require_threshold, validate_root, validate_snapshot, validate_targets,
                       validate_timestamp)

# 下载字节上限：§5.4.4.3 的 X、§5.4.4.4 的 Y、§5.4.4.6 的 Z 由实现方自定（下面是演示值）；
# snapshot 的上限取 timestamp 里写明的长度（§5.4.4.5 step 1）。
MAX_BYTES = {"root": 64 * 1024, "timestamp": 16 * 1024, "targets": 256 * 1024}
MAX_ROOT_ROTATIONS = 32


class Transport(Protocol):
    def fetch(self, repo: str, filename: str) -> Iterable[bytes] | None: ...


def read_limited(stream: Iterable[bytes], limit: int, what: str) -> bytes:
    """最多读 limit 字节；一旦超过就停止读取并报 endless data。空块按流结束处理。"""
    buf = bytearray()
    for piece in stream:
        if not piece:
            break
        buf += piece
        if len(buf) > limit:
            raise EndlessDataError(f"{what}: 超过 {limit} 字节上限，已停止读取")
    return bytes(buf)


@dataclass
class RepoState:
    """一个仓库的已信任状态（各字段都是 signed 部分；snapshot_sha256 用于判断 snapshot 有没有变化）。"""

    root: dict
    timestamp: dict | None = None
    snapshot: dict | None = None
    snapshot_sha256: str | None = None
    targets: dict | None = None

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "RepoState":
        return cls(**data)


def _keys_changed(old: dict, new: dict, role: str) -> bool:
    return set(old["roles"][role]["keyids"]) != set(new["roles"][role]["keyids"])


class RepoVerifier:
    def __init__(self, name: str, state: RepoState) -> None:
        self.name = name
        self.state = state

    def _download(self, transport: Transport, filename: str, limit: int) -> bytes | None:
        stream = transport.fetch(self.name, filename)
        return None if stream is None else read_limited(stream, limit, f"{self.name}/{filename}")

    def _require(self, transport: Transport, filename: str, limit: int) -> bytes:
        data = self._download(transport, filename, limit)
        if data is None:
            raise NetworkUnavailable(f"{self.name}/{filename} 不可用")
        return data

    # ---------------------------------------------------------------- §5.4.4.3 root
    def update_root(self, transport: Transport, now: datetime) -> None:
        for _ in range(MAX_ROOT_ROTATIONS):
            n = self.state.root["version"]
            name = f"{n + 1}.root.json"
            data = self._download(transport, name, MAX_BYTES["root"])           # step 2.2（最多 X 字节）
            if data is None:                                                    # 没有 N+1：当前就是最新
                break
            env = decode(data, "root", repo=self.name)
            new = env["signed"]
            validate_root(new, repo=self.name)
            require_threshold(env, "root", self.state.root, repo=self.name, label=f"{name}（旧 root 门限）")  # step 2.3
            require_threshold(env, "root", new, repo=self.name, label=f"{name}（新 root 门限）")              # step 2.3
            if new["version"] < n + 1:                                          # step 2.4：版本倒退
                raise RollbackAttackError(f"{name} 里的版本是 {new['version']}，低于 {n + 1}", repo=self.name, role="root")
            if new["version"] != n + 1:
                raise RootRotationError(f"{name} 里的版本是 {new['version']}，跳过了 {n + 1}", repo=self.name, role="root")
            old, self.state.root = self.state.root, new                         # step 2.5
            if _keys_changed(old, new, "timestamp") or _keys_changed(old, new, "snapshot"):   # step 4
                self.state.timestamp = self.state.snapshot = self.state.snapshot_sha256 = None
        else:
            raise RootRotationError(f"一次更新里 root 轮换超过 {MAX_ROOT_ROTATIONS} 次", repo=self.name, role="root")
        if is_expired(self.state.root, now):                                    # step 3：防 freeze
            raise ExpiredMetadataError(f"{self.name}/root 已过期（{self.state.root['expires']}），可能是 freeze attack",
                                       repo=self.name, role="root")

    # ---------------------------------------------------------------- §5.4.4.4 timestamp
    def update_timestamp(self, transport: Transport, now: datetime) -> None:
        data = self._require(transport, "timestamp.json", MAX_BYTES["timestamp"])   # step 1（最多 Y 字节）
        env = decode(data, "timestamp", repo=self.name)
        new = env["signed"]
        validate_timestamp(new, repo=self.name)
        require_threshold(env, "timestamp", self.state.root, repo=self.name)        # step 2
        old = self.state.timestamp
        if old is not None and new["version"] < old["version"]:                     # step 3
            raise RollbackAttackError(f"timestamp 版本 {new['version']} 低于已信任的 {old['version']}",
                                      repo=self.name, role="timestamp")
        if is_expired(new, now):                                                    # step 4
            raise ExpiredMetadataError(f"{self.name}/timestamp 已过期（{new['expires']}），可能是 freeze attack",
                                       repo=self.name, role="timestamp")
        self.state.timestamp = new

    # ---------------------------------------------------------------- §5.4.4.5 snapshot
    def update_snapshot(self, transport: Transport, now: datetime) -> bool:
        """返回 False 表示 snapshot 与新 timestamp 描述的一致，没有新内容（§5.4.4.2 step 4 / step 8）。"""
        meta = self.state.timestamp["meta"]["snapshot.json"]
        if (self.state.snapshot is not None and self.state.snapshot_sha256 == meta["hashes"]["sha256"]
                and self.state.snapshot["version"] == meta["version"]):
            return False
        data = self._require(transport, "snapshot.json", meta["length"])            # step 1（timestamp 写明的长度）
        if sha256_hex(data) != meta["hashes"]["sha256"]:                            # step 2
            raise MixAndMatchError("snapshot 的哈希与 timestamp 描述的不一致", repo=self.name, role="snapshot")
        env = decode(data, "snapshot", repo=self.name)
        new = env["signed"]
        if new["version"] != meta["version"]:                                       # step 2
            raise MixAndMatchError(f"snapshot 版本 {new['version']} 与 timestamp 描述的 {meta['version']} 不一致",
                                   repo=self.name, role="snapshot")
        validate_snapshot(new, repo=self.name)
        require_threshold(env, "snapshot", self.state.root, repo=self.name)         # step 3
        old = self.state.snapshot
        if old is not None:
            if new["version"] < old["version"]:                                     # step 4
                raise RollbackAttackError(f"snapshot 版本 {new['version']} 低于已信任的 {old['version']}",
                                          repo=self.name, role="snapshot")
            for filename, info in old["meta"].items():
                if filename not in new["meta"]:                                     # step 6
                    raise RollbackAttackError(f"{filename} 从 snapshot 中消失", repo=self.name, role="snapshot")
                if new["meta"][filename]["version"] < info["version"]:              # step 5
                    raise RollbackAttackError(f"snapshot 里 {filename} 的版本倒退", repo=self.name, role="snapshot")
        if is_expired(new, now):                                                    # step 7
            raise ExpiredMetadataError(f"{self.name}/snapshot 已过期", repo=self.name, role="snapshot")
        self.state.snapshot, self.state.snapshot_sha256 = new, sha256_hex(data)
        return True

    def targets_current(self) -> bool:
        return (self.state.targets is not None
                and self.state.targets["version"] == self.state.snapshot["meta"]["targets.json"]["version"])

    # ---------------------------------------------------------------- §5.4.4.6 targets
    def update_targets(self, transport: Transport, now: datetime, *, inventory: dict[str, str] | None = None) -> None:
        """inventory 不为空表示这是 Director 的 targets，要做 Director 专属检查（本 ECU 充当 Primary）。"""
        expected = self.state.snapshot["meta"]["targets.json"]["version"]
        data = self._require(transport, "targets.json", MAX_BYTES["targets"])        # step 1（最多 Z 字节）
        env = decode(data, "targets", repo=self.name)
        new = env["signed"]
        if new["version"] != expected:                                              # step 2
            raise MixAndMatchError(f"targets 版本 {new['version']} 与 snapshot 列出的 {expected} 不一致",
                                   repo=self.name, role="targets")
        validate_targets(new, repo=self.name)
        require_threshold(env, "targets", self.state.root, repo=self.name)          # step 3
        old = self.state.targets
        if old is not None and new["version"] < old["version"]:                     # step 4
            raise RollbackAttackError("targets 版本倒退", repo=self.name, role="targets")
        if is_expired(new, now):                                                    # step 5
            raise ExpiredMetadataError(f"{self.name}/targets 已过期（{new['expires']}）", repo=self.name, role="targets")
        if inventory is not None:
            if "delegations" in new:                                                # step 6
                raise MetadataFormatError("Director 的 targets 不能有委派", repo=self.name, role="targets")
            seen: set[str] = set()
            for filename, entry in new["targets"].items():
                ecu = entry["custom"].get("ecu_identifier")
                if not isinstance(ecu, str):
                    raise MetadataFormatError(f"{filename}: 缺少 ecu_identifier", repo=self.name, role="targets")
                if ecu in seen:                                                     # step 7
                    raise WrongEcuError(f"ECU 标识 {ecu} 在 Director 的 targets 里出现了两次", repo=self.name, role="targets")
                if ecu not in inventory:                                            # step 8（Primary）
                    raise WrongEcuError(f"Director 指向车上不存在的 ECU {ecu}", repo=self.name, role="targets")
                seen.add(ecu)
        self.state.targets = new

    def require_fresh(self, now: datetime) -> None:
        """本次没有重新下载的 snapshot / targets，用之前也要确认没有过期（本项目的保守做法）。"""
        for role in ("snapshot", "targets"):
            signed = getattr(self.state, role)
            if signed is not None and is_expired(signed, now):
                raise ExpiredMetadataError(f"{self.name}/{role} 已过期（{signed['expires']}）", repo=self.name, role=role)


@dataclass(frozen=True)
class VerifiedTarget:
    """通过 full verification 的一个镜像：Director 的指派与 Image 仓库的发布记录已逐项核对一致。"""

    filename: str
    length: int
    sha256: str
    ecu_identifier: str
    hardware_identifier: str
    release_counter: int
    sw_version: str
    secure_version: int
    rxswin: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "VerifiedTarget":
        return cls(**data)


def _release_record(name: str, custom: dict) -> tuple[list, int, str, int, str]:
    hw, rc, ver = custom.get("hardware_identifiers"), custom.get("release_counter"), custom.get("sw_version")
    sv, rx = custom.get("secure_version"), custom.get("rxswin")
    if (not isinstance(hw, list) or not all(isinstance(h, str) for h in hw) or not isinstance(rc, int)
            or not isinstance(ver, str) or not isinstance(sv, int) or not isinstance(rx, str)):
        raise MetadataFormatError(f"{name}: Image 仓库的自定义元数据不完整", repo="image", role="targets")
    return hw, rc, ver, sv, rx


def match_director_and_image(name: str, d_entry: dict, i_entry: dict | None) -> VerifiedTarget:
    """§5.4.4.2 steps 11–12：Director 列出的镜像必须在 Image 仓库里，且长度、哈希、硬件标识、release counter 一致。"""
    if i_entry is None:                                                             # step 11
        raise ArbitrarySoftwareError(f"Director 指定的 {name} 不在 Image 仓库的已签名 targets 里", repo="image")
    if d_entry["length"] != i_entry["length"] or d_entry["hashes"] != i_entry["hashes"]:   # step 12.1
        raise MixAndMatchError(f"{name}: Director 与 Image 仓库的长度或哈希不一致", repo="director")
    hw_list, rc, ver, sv, rx = _release_record(name, i_entry.get("custom", {}))
    dc = d_entry["custom"]
    if dc.get("hardware_identifier") not in hw_list:                                # step 12.2
        raise WrongEcuError(f"{name}: Director 指定的硬件标识 {dc.get('hardware_identifier')} 不在镜像兼容列表 {hw_list} 里",
                            repo="director")
    if dc.get("release_counter") != rc:                                             # step 12.2
        raise MixAndMatchError(f"{name}: Director 与 Image 仓库的 release counter 不一致", repo="director")
    if "rxswin" in dc and dc["rxswin"] != rx:                                       # 本项目扩展：RXSWIN 也要一致
        raise MixAndMatchError(f"{name}: Director 写的 RXSWIN {dc['rxswin']} 与发布记录 {rx} 不一致", repo="director")
    return VerifiedTarget(filename=name, length=i_entry["length"], sha256=i_entry["hashes"]["sha256"],
                          ecu_identifier=dc["ecu_identifier"], hardware_identifier=dc["hardware_identifier"],
                          release_counter=rc, sw_version=ver, secure_version=sv, rxswin=rx)


class FullVerifier:
    """§5.4.4.2 full verification。本 ECU 充当 Primary：核对 Director 列出的全部镜像（step 10）。"""

    def __init__(self, director: RepoVerifier, image: RepoVerifier, inventory: dict[str, str]) -> None:
        self.director, self.image, self.inventory = director, image, dict(inventory)

    @classmethod
    def from_trust(cls, trust: dict, inventory: dict[str, str]) -> "FullVerifier":
        return cls(RepoVerifier("director", RepoState.from_dict(trust["director"])),
                   RepoVerifier("image", RepoState.from_dict(trust["image"])), inventory)

    def trust(self) -> dict:
        return {"director": self.director.state.to_dict(), "image": self.image.state.to_dict()}

    def verify(self, transport: Transport, now: datetime, installed: dict[str, str]) -> dict[str, VerifiedTarget]:
        """返回 {ECU 标识: 已核对的镜像}，只含尚未安装的指派。now 来自 ECU 的安全时间源（step 1，这里由调用方注入）。"""
        d, i = self.director, self.image
        d.update_root(transport, now)                                               # step 2
        d.update_timestamp(transport, now)                                          # step 3
        if d.update_snapshot(transport, now) or not d.targets_current():            # step 4
            d.update_targets(transport, now, inventory=self.inventory)              # step 5
        d.require_fresh(now)
        assigned = {name: entry for name, entry in d.state.targets["targets"].items()
                    if installed.get(entry["custom"]["ecu_identifier"]) != entry["hashes"]["sha256"]}
        if not assigned:                                                            # step 6：没有新镜像
            return {}
        i.update_root(transport, now)                                               # step 6（续）
        i.update_timestamp(transport, now)                                          # step 7
        if i.update_snapshot(transport, now) or not i.targets_current():            # step 8
            i.update_targets(transport, now)                                        # step 9
        i.require_fresh(now)
        image_targets = i.state.targets["targets"]
        return {entry["custom"]["ecu_identifier"]: match_director_and_image(name, entry, image_targets.get(name))
                for name, entry in assigned.items()}                                # steps 10–12
