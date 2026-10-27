"""模拟非易失存储（Flash / EEPROM）和断电注入。

- 每次 write() 是一次持久化写入，也是一个可能断电的点。arm_power_cut(n) 让“从现在起的第 n 次写入”断电。
- torn=True：被打断的那次写入只写了一半（前半段新数据，后半段保留旧数据），模拟撕裂写入。
- 断电后存储进入“无电”状态，之后的写入全部失败，直到 restore_power()（重新上电）。
- 记录层：ChecksummedRecord（单份 + SHA-256 校验）、RedundantRecord（两份 + 序号，原子更新）。
"""
from __future__ import annotations

import json

from .canonical import canonical_bytes, sha256_hex


class PowerCut(Exception):
    """模拟断电：发生在某次持久化写入时。"""


class NVStore:
    def __init__(self) -> None:
        self._cells: dict[str, bytes] = {}
        self.writes = 0
        self.trace: list[str] = []
        self.powered = True
        self._cut_at: int | None = None
        self._torn = True

    def clone(self) -> "NVStore":
        twin = NVStore()
        twin._cells = dict(self._cells)      # 值是不可变的 bytes，浅拷贝就够
        return twin

    def arm_power_cut(self, nth_write: int, *, torn: bool = True) -> None:
        self._cut_at = self.writes + nth_write
        self._torn = torn

    def restore_power(self) -> None:
        self.powered = True
        self._cut_at = None

    def write(self, key: str, value: bytes, label: str) -> None:
        if not self.powered:
            raise PowerCut(f"无电时尝试写入：{label}")
        self.writes += 1
        self.trace.append(label)
        if self.writes == self._cut_at:
            self._cut_at = None
            self.powered = False
            if self._torn:
                old = self._cells.get(key, b"")
                half = len(value) // 2
                self._cells[key] = value[:half] + old[half:]
            raise PowerCut(label)
        self._cells[key] = value

    def read(self, key: str) -> bytes | None:
        return self._cells.get(key)


def _pack(value: object) -> bytes:
    payload = canonical_bytes(value)
    return payload + b"\n" + sha256_hex(payload).encode("ascii")


def _unpack(raw: bytes | None) -> object | None:
    if not raw:
        return None
    payload, sep, digest = raw.rpartition(b"\n")
    if not sep or sha256_hex(payload).encode("ascii") != digest:
        return None
    try:
        return json.loads(payload)
    except ValueError:
        return None


class ChecksummedRecord:
    """单份记录 + SHA-256 校验。撕裂写入后校验失败，读出 None，等同“无效”。用于槽头。"""

    def __init__(self, nv: NVStore, key: str) -> None:
        self.nv, self.key = nv, key

    def read(self):
        return _unpack(self.nv.read(self.key))

    def write(self, value: object, label: str) -> None:
        self.nv.write(self.key, _pack(value), label)


class RedundantRecord:
    """两份带序号的副本。

    写入总是覆盖较旧（或已损坏）的那份，所以撕裂写入只会毁掉正在写的那份；读取取序号最大的有效副本。
    结果：每次更新都是原子的，读到的要么是旧值，要么是新值，不会是半新半旧。
    """

    def __init__(self, nv: NVStore, key: str) -> None:
        self.nv, self.key = nv, key

    def _copies(self) -> dict[int, dict]:
        copies = {}
        for i in (0, 1):
            record = _unpack(self.nv.read(f"{self.key}.{i}"))
            if isinstance(record, dict) and isinstance(record.get("seq"), int):
                copies[i] = record
        return copies

    def read(self):
        copies = self._copies()
        return max(copies.values(), key=lambda r: r["seq"])["value"] if copies else None

    def write(self, value: object, label: str) -> None:
        copies = self._copies()
        newest = max((r["seq"] for r in copies.values()), default=0)
        if len(copies) == 2:
            target = min(copies, key=lambda i: copies[i]["seq"])
        elif len(copies) == 1:
            target = 1 - next(iter(copies))
        else:
            target = 0
        self.nv.write(f"{self.key}.{target}", _pack({"seq": newest + 1, "value": value}), label)
