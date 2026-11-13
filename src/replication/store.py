"""本地对象根的存储原语：哈希、安全路径、锁、字节复制、fsync。

两个对象根都是普通本地目录。所有路径先经 safe_path 解析回根目录内，
避免清单里出现 `..`/绝对路径时越界读写。只接受普通文件，不跟随符号链接。
"""

from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Iterator


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def try_sha256_file(path: Path) -> tuple[str | None, str | None]:
    """返回 (摘要, 错误)。缺失返回 (None, "missing")。只接受普通文件。"""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None, "missing"
    except OSError as exc:
        return None, f"unreadable:{exc.errno}"
    import stat as stat_module

    if not stat_module.S_ISREG(info.st_mode):
        return None, "not_regular_file"
    try:
        return sha256_file(path), None
    except OSError as exc:
        return None, f"unreadable:{exc.errno}"


def safe_path(root: Path, key: str) -> Path:
    """把清单 key 解析为 root 下路径，并确认没有逃逸。"""
    from .errors import Blocked

    try:
        resolved_root = root.resolve(strict=True)
    except FileNotFoundError:
        raise Blocked("root_missing", {"root": str(root)}) from None
    # 词法拼接、不解析符号链接：符号链接本身要被识别为“非普通文件”，
    # 既不能顺着它读到根外，也不能被当成合法对象。
    pure = PurePosixPath(key)
    if pure.is_absolute() or any(part == ".." for part in pure.parts):
        raise Blocked("path_escape", {"key": key})
    candidate = resolved_root.joinpath(*pure.parts)
    try:
        if candidate != resolved_root and resolved_root not in candidate.parents:
            raise Blocked("path_escape", {"key": key, "path": str(candidate)})
    except OSError as exc:  # pragma: no cover
        raise Blocked("path_escape", {"key": key, "error": str(exc)}) from None
    return candidate


def fsync_file(path: Path) -> None:
    with path.open("rb+") as stream:
        os.fsync(stream.fileno())


def fsync_dir(path: Path) -> None:
    if os.name != "posix":  # pragma: no cover - 仅影响崩溃持久性，不影响正确性
        return
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:  # pragma: no cover
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes) -> None:
    """写临时文件 → fsync → os.replace → fsync 目录。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temp.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)
    fsync_dir(path.parent)


def read_chunk(stream: io.BufferedReader, offset: int, length: int) -> bytes:
    """从源文件精确读取 [offset, offset+length)；短读或越界抛 Blocked。"""
    from .errors import Blocked

    stream.seek(offset)
    data = stream.read(length)
    if len(data) != length:
        raise Blocked(
            "source_changed_during_transfer",
            {"reason": "short_read", "offset": offset, "expected": length, "actual": len(data)},
        )
    return data


@contextmanager
def flock(path: Path) -> Iterator[None]:
    """跨进程互斥锁，避免两个复制器同时改同一目标根。"""
    import fcntl

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            from .errors import Blocked

            raise Blocked("target_locked", {"lock": str(path)}) from None
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
