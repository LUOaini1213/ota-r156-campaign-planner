"""仓库端（后端）模拟：Image 仓库和 Director 仓库各自持有 root / targets / snapshot / timestamp 四个角色的密钥并签发元数据。

对应 Uptane Standard 2.1.0：
  §5.1    四个角色；§5.1.1–§5.1.4 各角色签什么。
  §5.3.1  Image 仓库主要由人工控制、更新不频繁（这里 targets 用 3 把密钥、门限 2）。
  §5.3.2  Director 主要由自动化在线流程控制，按需生成签名元数据，指示 ECU 安装哪个镜像（这里在线角色门限 1）。
密钥数量、门限和有效期都是演示用的设计参数；“在线 / 离线”只是本项目的分组说法，Uptane 2.1.0 这两节没有规定密钥存放方式。
所有私钥只存在于内存中的 SigningKey 对象里。
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta
from typing import Iterable

from .canonical import canonical_bytes, sha256_hex, strict_loads
from .crypto import SigningKey, keyid_of, verify_signature
from .errors import MetadataFormatError, RollbackAttackError, SignatureThresholdError
from .metadata import ROLES, encode, format_time, sign

# 各角色元数据的有效期（演示用的设计参数，不来自标准）
DEFAULT_EXPIRY = {"root": timedelta(days=365), "targets": timedelta(days=30),
                  "snapshot": timedelta(days=7), "timestamp": timedelta(days=1)}


class Repository:
    """一个仓库。files 是对外发布的元数据文件（字节），images 是镜像本体（只有 Image 仓库有）。"""

    def __init__(self, name: str, now: datetime, *, key_counts: dict[str, int], thresholds: dict[str, int],
                 expiry: dict[str, timedelta] | None = None) -> None:
        self.name = name
        self.now = now
        self.thresholds = dict(thresholds)
        self.keys = {role: [SigningKey() for _ in range(key_counts[role])] for role in ROLES}
        self.expiry = {**DEFAULT_EXPIRY, **(expiry or {})}
        self.root_version = 0
        self.versions = {"targets": 0, "snapshot": 0, "timestamp": 0}
        self.targets: dict[str, dict] = {}
        self.images: dict[str, bytes] = {}
        self.files: dict[str, bytes] = {}
        self.publish_root()

    @classmethod
    def image_repository(cls, now: datetime) -> "Repository":
        return cls("image", now, key_counts={"root": 3, "targets": 3, "snapshot": 1, "timestamp": 1},
                   thresholds={"root": 2, "targets": 2, "snapshot": 1, "timestamp": 1})

    @classmethod
    def director_repository(cls, now: datetime) -> "Repository":
        return cls("director", now, key_counts={"root": 3, "targets": 1, "snapshot": 1, "timestamp": 1},
                   thresholds={"root": 2, "targets": 1, "snapshot": 1, "timestamp": 1})

    # ------------------------------------------------------------------ root 与密钥轮换
    def root_signed(self, version: int | None = None) -> dict:
        return {
            "_type": "root",
            "version": self.root_version if version is None else version,
            "expires": format_time(self.now + self.expiry["root"]),
            "keys": {k.keyid: k.public for role in ROLES for k in self.keys[role]},
            "roles": {role: {"keyids": [k.keyid for k in self.keys[role]], "threshold": self.thresholds[role]}
                      for role in ROLES},
        }

    def publish_root(self, previous_root_keys: Iterable[SigningKey] = ()) -> None:
        """签发 root N+1，文件名 N+1.root.json（§5.4.4.3 用 VERSION_NUMBER.FILENAME.EXT 取 root）。
        由新 root 的密钥签名；轮换时再加上一版 root 的密钥，满足“新旧两个门限都要够”。"""
        self.root_version += 1
        signers = list(self.keys["root"]) + [k for k in previous_root_keys if k not in self.keys["root"]]
        self.files[f"{self.root_version}.root.json"] = encode(sign(self.root_signed(), signers))

    def rotate(self, role: str, *, new_keys: list[SigningKey] | None = None, threshold: int | None = None) -> list:
        """撤销并替换某个角色的全部密钥，签发新版 root（§5.2.2：root 分发密钥，也分发密钥的撤销）。返回被撤销的旧密钥。"""
        old_root_keys = list(self.keys["root"])
        revoked = self.keys[role]
        self.keys[role] = list(new_keys) if new_keys is not None else [SigningKey() for _ in revoked]
        if threshold is not None:
            self.thresholds[role] = threshold
        self.publish_root(previous_root_keys=old_root_keys)
        return revoked

    # ------------------------------------------------------------------ targets / snapshot / timestamp
    def add_target(self, filename: str, data: bytes, custom: dict) -> dict:
        """Image 仓库发布一个镜像：记录长度、SHA-256 和自定义元数据（§5.2.3.1、§5.2.3.1.1）。"""
        entry = {"length": len(data), "hashes": {"sha256": sha256_hex(data)}, "custom": copy.deepcopy(custom)}
        self.targets[filename] = entry
        self.images[filename] = data
        return entry

    def set_target_entry(self, filename: str, entry: dict) -> None:
        """Director 用：只写元数据条目，不带镜像本体。"""
        self.targets[filename] = copy.deepcopy(entry)

    def sign_role(self, role: str, signed: dict, keys: Iterable[SigningKey] | None = None) -> bytes:
        return encode(sign(signed, self.keys[role] if keys is None else keys))

    def publish(self, *, resign_targets: bool = True, targets_signers: Iterable[SigningKey] | None = None) -> None:
        """依次签发 targets → snapshot → timestamp，各自版本号加一。
        resign_targets=False：只重签 snapshot 和 timestamp，targets 文件保持不变（演示 targets 过期）。
        targets_signers：指定用哪些密钥签 targets（演示门限不足、重复签名、用错角色的密钥）。"""
        if resign_targets or "targets.json" not in self.files:
            self.versions["targets"] += 1
            signed = {"_type": "targets", "version": self.versions["targets"],
                      "expires": format_time(self.now + self.expiry["targets"]), "targets": copy.deepcopy(self.targets)}
            self.files["targets.json"] = self.sign_role("targets", signed, targets_signers)
        self.versions["snapshot"] += 1
        snapshot = {"_type": "snapshot", "version": self.versions["snapshot"],
                    "expires": format_time(self.now + self.expiry["snapshot"]),
                    "meta": {"targets.json": {"version": self.versions["targets"]}}}
        self.files["snapshot.json"] = self.sign_role("snapshot", snapshot)
        self.publish_timestamp()

    def timestamp_signed(self, snapshot_bytes: bytes, snapshot_version: int, version: int) -> dict:
        return {"_type": "timestamp", "version": version, "expires": format_time(self.now + self.expiry["timestamp"]),
                "meta": {"snapshot.json": {"version": snapshot_version, "length": len(snapshot_bytes),
                                           "hashes": {"sha256": sha256_hex(snapshot_bytes)}}}}

    def publish_timestamp(self) -> None:
        """只重签 timestamp（版本加一，新的有效期），指向当前 snapshot。运营中会定期执行。"""
        self.versions["timestamp"] += 1
        snap = self.files["snapshot.json"]
        signed = self.timestamp_signed(snap, self.versions["snapshot"], self.versions["timestamp"])
        self.files["timestamp.json"] = self.sign_role("timestamp", signed)


def verify_version_report(data: bytes, ecu_public_key: dict, expected_nonce: str) -> dict:
    """后端（Director）核对 ECU 版本报告：ECU 身份密钥签名有效、nonce 是本次下发的（§5.4.2.1.2：nonce 或计数器防重放）。"""
    env = strict_loads(data)
    if not isinstance(env, dict) or not isinstance(env.get("signed"), dict) or not isinstance(env.get("signatures"), list):
        raise MetadataFormatError("版本报告格式不对", role="ecu_version_report")
    signed, keyid = env["signed"], keyid_of(ecu_public_key)
    payload = canonical_bytes(signed)
    if not any(isinstance(s, dict) and s.get("keyid") == keyid and verify_signature(ecu_public_key, s.get("sig"), payload)
               for s in env["signatures"]):
        raise SignatureThresholdError("版本报告的 ECU 签名无效", role="ecu_version_report")
    if signed.get("nonce") != expected_nonce:
        raise RollbackAttackError("版本报告的 nonce 不是本次下发的，可能是重放", role="ecu_version_report")
    return signed
