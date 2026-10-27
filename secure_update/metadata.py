"""元数据公共部分：角色、时间格式、签名信封、门限验签、结构检查。仓库端和车端共用。

信封结构参照 Uptane Standard 2.1.0 §5.2.1（两个属性：载荷 + 签名；载荷含角色类型、过期时间、整数版本号）：
  {"signatures": [{"keyid": ..., "sig": ...}],
   "signed": {"_type": 角色, "version": 正整数, "expires": "YYYY-MM-DDTHH:MM:SSZ", ...}}
具体字段名和 JSON 布局是本项目自定的（§5.2：标准不强制格式）。
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable

from .canonical import canonical_bytes, strict_loads
from .crypto import SigningKey, keyid_of, raw_public, verify_signature
from .errors import MetadataFormatError, SignatureThresholdError

ROLES = ("root", "targets", "snapshot", "timestamp")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# 目标文件名：不允许路径分隔符、".." 开头等，避免写到预期之外的位置
FILENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")


def format_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(TIME_FORMAT)


def parse_time(text: object) -> datetime:
    try:
        return datetime.strptime(text, TIME_FORMAT).replace(tzinfo=timezone.utc)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise MetadataFormatError(f"时间格式不对：{text!r}") from None


def is_expired(signed: dict, now: datetime) -> bool:
    """§5.4.4.3 step 3、§5.4.4.4 step 4 等：当前（或最近一次可信）时间必须早于 expires，否则视为过期。"""
    return not now < parse_time(signed["expires"])


def sign(signed: dict, keys: Iterable[SigningKey]) -> dict:
    data = canonical_bytes(signed)
    return {"signatures": [{"keyid": k.keyid, "sig": k.sign(data)} for k in keys], "signed": signed}


def encode(envelope: dict) -> bytes:
    return canonical_bytes(envelope)


def _is_int(value: object, minimum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def decode(data: bytes, expected_type: str, *, repo: str = "") -> dict:
    """解析信封并检查公共字段。只检查格式，不验签。"""
    env = strict_loads(data)
    if not isinstance(env, dict) or set(env) != {"signatures", "signed"}:
        raise MetadataFormatError("信封必须正好有 signatures 和 signed 两个字段", repo=repo, role=expected_type)
    sigs, signed = env["signatures"], env["signed"]
    if not isinstance(sigs, list) or not all(
            isinstance(s, dict) and isinstance(s.get("keyid"), str) and isinstance(s.get("sig"), str) for s in sigs):
        raise MetadataFormatError("signatures 格式不对", repo=repo, role=expected_type)
    if not isinstance(signed, dict) or signed.get("_type") != expected_type:
        got = signed.get("_type") if isinstance(signed, dict) else type(signed).__name__
        raise MetadataFormatError(f"角色类型应为 {expected_type}，收到 {got}", repo=repo, role=expected_type)
    if not _is_int(signed.get("version"), 1):
        raise MetadataFormatError("version 必须是正整数", repo=repo, role=expected_type)
    parse_time(signed.get("expires"))
    return env


def valid_signers(envelope: dict, role: str, root: dict) -> set[str]:
    """返回对 envelope 给出有效签名、且被 root 授权给 role 的 keyid 集合。

    - 同一个 keyid 只算一次，同一把公钥换个 keyid 也只算一次（防止复制签名凑门限）；
    - keyid 必须等于公钥描述的哈希；
    - 未被授权给该角色的密钥（哪怕是本仓库其他角色的合法密钥）不计数。
    """
    authorised = set(root["roles"][role]["keyids"])
    data = canonical_bytes(envelope["signed"])
    counted: set[str] = set()
    counted_raw: set[bytes] = set()
    for entry in envelope["signatures"]:
        keyid = entry["keyid"]
        if keyid in counted or keyid not in authorised:
            continue
        key = root["keys"].get(keyid)
        raw = raw_public(key)
        if raw is None or raw in counted_raw or keyid_of(key) != keyid:
            continue
        if verify_signature(key, entry["sig"], data):
            counted.add(keyid)
            counted_raw.add(raw)
    return counted


def require_threshold(envelope: dict, role: str, root: dict, *, repo: str = "", label: str = "") -> None:
    """§5.4.4.4 step 2 等：SHALL 由 root 中规定数量（门限）的不同密钥签名。"""
    threshold = root["roles"][role]["threshold"]
    got = len(valid_signers(envelope, role, root))
    if got < threshold:
        raise SignatureThresholdError(f"{repo}/{label or role}: 授权密钥的有效签名 {got} 个，门限 {threshold}",
                                      repo=repo, role=role)


def validate_root(signed: dict, *, repo: str = "") -> None:
    """§5.2.2：root 列出四个角色的公钥，以及每个角色的公钥和签名门限。"""
    keys, roles = signed.get("keys"), signed.get("roles")
    if not isinstance(keys, dict) or not isinstance(roles, dict) or set(roles) != set(ROLES):
        raise MetadataFormatError("root 必须有 keys，并且正好列出四个角色", repo=repo, role="root")
    for keyid, key in keys.items():
        if raw_public(key) is None or keyid_of(key) != keyid:
            raise MetadataFormatError(f"keyid {keyid[:8]}… 与公钥不对应", repo=repo, role="root")
    for role in ROLES:
        info = roles[role]
        keyids = info.get("keyids") if isinstance(info, dict) else None
        threshold = info.get("threshold") if isinstance(info, dict) else None
        if (not isinstance(keyids, list) or not all(isinstance(k, str) and k in keys for k in keyids)
                or len(set(keyids)) != len(keyids)):
            raise MetadataFormatError(f"{role} 的 keyids 不合法", repo=repo, role="root")
        if not _is_int(threshold, 1) or threshold > len(keyids):
            raise MetadataFormatError(f"{role} 的门限不合法", repo=repo, role="root")


def _check_file_meta(meta: object, *, need_hash: bool, repo: str, role: str) -> None:
    if not isinstance(meta, dict) or not _is_int(meta.get("version"), 1):
        raise MetadataFormatError("文件描述缺少 version", repo=repo, role=role)
    if need_hash:
        hashes = meta.get("hashes")
        if (not _is_int(meta.get("length"), 0) or not isinstance(hashes, dict)
                or not isinstance(hashes.get("sha256"), str) or not SHA256_RE.fullmatch(hashes["sha256"])):
            raise MetadataFormatError("文件描述缺少 length 或 sha256", repo=repo, role=role)


def validate_timestamp(signed: dict, *, repo: str = "") -> None:
    """§5.2.5：最新 snapshot 的文件名、版本号和哈希（这里另加长度，用作下载上限）。"""
    meta = signed.get("meta")
    if not isinstance(meta, dict) or set(meta) != {"snapshot.json"}:
        raise MetadataFormatError("timestamp 必须且只能描述 snapshot.json", repo=repo, role="timestamp")
    _check_file_meta(meta["snapshot.json"], need_hash=True, repo=repo, role="timestamp")


def validate_snapshot(signed: dict, *, repo: str = "") -> None:
    """§5.2.4：列出所有 targets 元数据文件的文件名和版本号。"""
    meta = signed.get("meta")
    if not isinstance(meta, dict) or "targets.json" not in meta:
        raise MetadataFormatError("snapshot 必须列出 targets.json", repo=repo, role="snapshot")
    for item in meta.values():
        _check_file_meta(item, need_hash=False, repo=repo, role="snapshot")


def validate_targets(signed: dict, *, repo: str = "") -> None:
    """§5.2.3.1：每个镜像至少有文件名、字节数、一个或多个哈希（这里只用 SHA-256）。"""
    targets = signed.get("targets")
    if not isinstance(targets, dict):
        raise MetadataFormatError("targets 字段缺失", repo=repo, role="targets")
    for name, entry in targets.items():
        if not FILENAME_RE.fullmatch(name):
            raise MetadataFormatError(f"非法的镜像文件名 {name!r}", repo=repo, role="targets")
        _check_file_meta({**entry, "version": 1} if isinstance(entry, dict) else None,
                         need_hash=True, repo=repo, role="targets")
        if not isinstance(entry.get("custom", {}), dict):
            raise MetadataFormatError(f"{name}: custom 必须是对象", repo=repo, role="targets")
