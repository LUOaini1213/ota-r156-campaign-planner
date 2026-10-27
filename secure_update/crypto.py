"""Ed25519 签名与验签（RFC 8032 定义的 EdDSA 实例）。

全部调用已安装的 cryptography 库；本项目不自己实现任何密码算法。
  - 私钥只在内存里生成和使用：测试和演示运行时临时生成，不写盘、不提交，也没有导出接口。
  - keyid = 公钥描述（canonical JSON）的 SHA-256。Uptane Standard 2.1.0 §5.2.2：每个密钥 SHALL 有唯一的公钥标识。
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes, sha256_hex

KEYTYPE = SCHEME = "ed25519"


def public_key_dict(raw_public: bytes) -> dict:
    return {"keytype": KEYTYPE, "scheme": SCHEME, "keyval": {"public": raw_public.hex()}}


def keyid_of(key: dict) -> str:
    return sha256_hex(canonical_bytes(key))


def raw_public(key: object) -> bytes | None:
    """公钥描述 → 32 字节原始公钥；格式不对返回 None。"""
    try:
        if key["keytype"] != KEYTYPE or key["scheme"] != SCHEME:  # type: ignore[index]
            return None
        raw = bytes.fromhex(key["keyval"]["public"])  # type: ignore[index]
    except (KeyError, TypeError, ValueError):
        return None
    return raw if len(raw) == 32 else None


def verify_signature(key: dict, signature_hex: object, data: bytes) -> bool:
    raw = raw_public(key)
    if raw is None or not isinstance(signature_hex, str):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(bytes.fromhex(signature_hex), data)
    except (InvalidSignature, ValueError):
        return False
    return True


class SigningKey:
    """内存中的 Ed25519 私钥。没有任何导出或序列化私钥的方法；repr 只显示 keyid 前缀。"""

    __slots__ = ("_private", "public", "keyid")

    def __init__(self) -> None:
        self._private = Ed25519PrivateKey.generate()
        raw = self._private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public = public_key_dict(raw)
        self.keyid = keyid_of(self.public)

    def sign(self, data: bytes) -> str:
        return self._private.sign(data).hex()

    def __repr__(self) -> str:
        return f"SigningKey(keyid={self.keyid[:8]}…)"
