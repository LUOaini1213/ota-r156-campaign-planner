"""确定性（canonical）JSON 序列化与严格解析。

签名和验签都基于同一份字节：只要一方多一个空格、换一个键序，签名就对不上。
Uptane Standard 2.1.0 §5.2 写明标准不强制元数据整体的格式和编码，所以下面的规则是本项目自定的：
  - 键排序、无多余空白、UTF-8 输出；
  - 只允许 dict（键必须是 str）、list、str、int、bool、None；拒绝浮点数（同一个数可以有多种写法）；
  - 字符串必须已经是 Unicode NFC 形式（§5.2：字符串 SHALL 按 RFC 5198 编码，包括规范化为 NFC）。
严格解析另外拒绝重复键和 NaN / Infinity，避免不同解析器从同一份字节读出不同内容。
本项目不声称符合 OLPC canonical JSON 或 RFC 8785。
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

from .errors import MetadataFormatError


def _check(value: Any, path: str) -> None:
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return
    if isinstance(value, float):
        raise MetadataFormatError(f"{path}: 不允许浮点数")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise MetadataFormatError(f"{path}: 字符串不是 NFC 形式")
        return
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise MetadataFormatError(f"{path}: 键必须是字符串，收到 {type(key).__name__}")
            _check(key, f"{path}.<key>")
            _check(item, f"{path}.{key}")
        return
    raise MetadataFormatError(f"{path}: 不支持的类型 {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """按上面的规则序列化；不符合规则就抛 MetadataFormatError。"""
    _check(value, "$")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for key, item in pairs:
        if key in out:
            raise MetadataFormatError(f"重复的键 {key!r}")
        out[key] = item
    return out


def _reject_float(text: str) -> Any:
    raise MetadataFormatError(f"不允许浮点数：{text}")


def _reject_constant(text: str) -> Any:
    raise MetadataFormatError(f"不允许 {text}")


def strict_loads(data: bytes) -> Any:
    """严格解析收到的字节：必须是 UTF-8、合法 JSON，没有重复键、浮点数、NaN，字符串是 NFC。"""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MetadataFormatError(f"不是合法的 UTF-8：{exc.reason}") from None
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicates, parse_float=_reject_float,
                           parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:  # JSONDecodeError 是 ValueError 的子类
        raise MetadataFormatError(f"不是合法的 JSON：{exc}") from None
    _check(value, "$")
    return value


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
