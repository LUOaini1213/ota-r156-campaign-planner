"""不可信的分发通道（CDN、蜂窝网络、被攻破的镜像站都算）。

它只搬运字节，车端不信任它：所有安全性来自元数据签名和车端校验。
测试通过 overrides 扮演攻击者：替换某个文件、丢弃它、或者返回一个永远读不完的数据流。
"""
from __future__ import annotations

from typing import Callable, Iterable, Iterator, Optional, Union

from .errors import NetworkUnavailable
from .repository import Repository

Override = Optional[Union[bytes, Callable[[], Iterable[bytes]]]]
ImageOverride = Union[bytes, Callable[[int], Iterable[bytes]]]


class Mirror:
    def __init__(self, director: Repository, image: Repository, *, chunk_size: int = 256) -> None:
        self.repos = {"director": director, "image": image}
        self.overrides: dict[tuple[str, str], Override] = {}      # (仓库, 元数据文件名) → 攻击者提供的内容
        self.image_overrides: dict[str, ImageOverride] = {}         # 镜像文件名 → 攻击者提供的内容
        self.online = True
        self.chunk_size = chunk_size
        self.bytes_served = 0
        self.image_bytes_served = 0
        self.log: list[tuple] = []

    def _stream(self, data: bytes, image: bool) -> Iterator[bytes]:
        for i in range(0, len(data), self.chunk_size):
            yield from self._count([data[i:i + self.chunk_size]], image)

    def _count(self, stream: Iterable[bytes], image: bool) -> Iterator[bytes]:
        for piece in stream:
            self.bytes_served += len(piece)
            if image:
                self.image_bytes_served += len(piece)
            yield piece

    def fetch(self, repo: str, filename: str) -> Iterator[bytes] | None:
        """取元数据文件。文件不存在返回 None（例如还没有 N+1 版 root）。"""
        if not self.online:
            raise NetworkUnavailable(f"{repo}/{filename}: 网络不可用")
        self.log.append(("meta", repo, filename))
        key = (repo, filename)
        if key in self.overrides:
            override = self.overrides[key]
            if override is None:
                return None
            if callable(override):
                return self._count(override(), image=False)
            return self._stream(override, image=False)
        data = self.repos[repo].files.get(filename)
        return None if data is None else self._stream(data, image=False)

    def fetch_image(self, filename: str, offset: int = 0) -> Iterator[bytes]:
        """取镜像，从 offset 开始（断点续传）。"""
        if not self.online:
            raise NetworkUnavailable(f"{filename}: 网络不可用")
        self.log.append(("image", filename, offset))
        if filename in self.image_overrides:
            override = self.image_overrides[filename]
            if callable(override):
                return self._count(override(offset), image=True)
            return self._stream(override[offset:], image=True)
        data = self.repos["image"].images.get(filename)
        if data is None:
            raise NetworkUnavailable(f"{filename}: 镜像站上没有这个文件")
        return self._stream(data[offset:], image=True)
