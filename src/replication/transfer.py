"""分块复制、断点续传校验、目标隔离与原子提升。

关键不变量：

* 每个临时块是独立文件，记录自己的 SHA256 和来源对象摘要；
* 续传时逐块重算并核对摘要链，同时确认源对象身份（路径/inode/大小/mtime）
  与完整摘要未变——绝不只按“已写字节偏移”继续；
* 整对象拼接后验证 SHA256/长度，才原子提升为可见对象；
* 目标已有损坏对象先移入隔离区留证，再放行新对象；
* 目标根里其他对象一律不回收；清理只针对本次复制的临时块/暂存文件。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .errors import Blocked, TransferInterrupted
from .manifest import ObjectRef
from .store import atomic_write, fsync_dir, fsync_file, read_chunk, safe_path, sha256_file, try_sha256_file
from .paths import journal_path, parts_dir, quarantine_root, staged_data_path, staging_root


@dataclass
class TransferPolicy:
    chunk_bytes: int
    inject_after_chunks: tuple[int, ...] = ()
    inject: bool = True


@dataclass
class ChunkRecord:
    index: int
    offset: int
    length: int
    chunk_sha256: str
    cumulative_sha256: str
    source_sha256: str

    def to_json(self) -> dict:
        return {
            "index": self.index,
            "offset": self.offset,
            "length": self.length,
            "chunk_sha256": self.chunk_sha256,
            "cumulative_sha256": self.cumulative_sha256,
            "source_sha256": self.source_sha256,
        }


@dataclass
class TransferEvidence:
    key: str
    sha256: str
    bytes: int
    chunk_bytes: int
    chunks_total: int
    resumed_from_byte: int
    resumed_from_chunk: int
    chunks_transferred_this_run: int
    source_sha256: str
    target_paths: list[str] = field(default_factory=list)
    quarantined: list[dict] = field(default_factory=list)
    dedup_skipped_keys: list[str] = field(default_factory=list)
    journal_used: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        return {
            "key": self.key,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "chunk_bytes": self.chunk_bytes,
            "chunks_total": self.chunks_total,
            "resumed_from_byte": self.resumed_from_byte,
            "resumed_from_chunk": self.resumed_from_chunk,
            "chunks_transferred_this_run": self.chunks_transferred_this_run,
            "source_sha256": self.source_sha256,
            "target_paths": self.target_paths,
            "quarantined": self.quarantined,
            "dedup_skipped_keys": self.dedup_skipped_keys,
            "journal_used": self.journal_used,
        }


def _source_identity(path: Path) -> dict:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise Blocked("source_object_missing", {"path": str(path)}) from None
    import stat as stat_module

    if not stat_module.S_ISREG(info.st_mode):
        raise Blocked("source_object_untrusted", {"path": str(path), "reason": "not_regular_file"})
    return {
        "path": str(path),
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "inode": info.st_ino,
        "device": info.st_dev,
    }


def load_journal(target_root: Path, ref: ObjectRef, policy: TransferPolicy) -> dict | None:
    path = journal_path(target_root, ref.sha256)
    if not path.is_file():
        return None
    try:
        journal = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Blocked("journal_unreadable", {"journal": str(path), "error": str(exc)}) from None
    if journal.get("version") != 1:
        raise Blocked("journal_unreadable", {"journal": str(path), "reason": "unknown_version"})
    for field_name in ("key", "sha256", "bytes", "source_sha256", "chunk_bytes", "chunks", "committed_bytes", "source_identity"):
        if field_name not in journal:
            raise Blocked("journal_unreadable", {"journal": str(path), "reason": f"missing:{field_name}"})
    if journal["sha256"] != ref.sha256 or journal["bytes"] != ref.bytes:
        raise Blocked(
            "journal_identity_mismatch",
            {"journal": str(path), "journal_sha256": journal["sha256"], "expected_sha256": ref.sha256},
        )
    return journal


def validate_resume(
    target_root: Path,
    ref: ObjectRef,
    journal: dict,
    policy: TransferPolicy,
) -> tuple[int, dict]:
    """校验断点：块摘要链、暂存块字节、源对象身份与摘要。返回 (累计字节, 源身份)。

    任何不一致都返回 Blocked，而不是“从上次字节数继续”。
    """
    if journal["chunk_bytes"] != policy.chunk_bytes:
        raise Blocked(
            "resume_chunk_size_changed",
            {"journal_chunk_bytes": journal["chunk_bytes"], "requested": policy.chunk_bytes},
        )
    if journal["source_sha256"] != ref.sha256:
        raise Blocked(
            "resume_source_identity_changed",
            {"journal_source_sha256": journal["source_sha256"], "expected": ref.sha256},
        )
    if journal["key"] != ref.key:
        raise Blocked(
            "resume_object_changed",
            {"journal_key": journal["key"], "requested_key": ref.key},
        )

    source_path = Path(journal["source_identity"]["path"])
    try:
        current_identity = _source_identity(source_path)
    except Blocked as exc:
        raise Blocked("resume_source_missing", {"key": ref.key, "source": str(source_path)}) from exc
    if current_identity != journal["source_identity"]:
        raise Blocked(
            "resume_source_identity_changed",
            {
                "key": ref.key,
                "recorded": journal["source_identity"],
                "current": current_identity,
            },
        )
    actual_source_digest = sha256_file(source_path)
    if actual_source_digest != journal["source_sha256"]:
        raise Blocked(
            "resume_source_identity_changed",
            {
                "key": ref.key,
                "recorded_source_sha256": journal["source_sha256"],
                "current_source_sha256": actual_source_digest,
            },
        )
    try:
        actual_source_size = source_path.stat().st_size
    except OSError as exc:  # pragma: no cover - 身份校验后极少发生
        raise Blocked("resume_source_missing", {"key": ref.key, "error": str(exc)}) from None
    if actual_source_size != ref.bytes:
        raise Blocked(
            "source_object_changed",
            {"key": ref.key, "expected_bytes": ref.bytes, "actual_bytes": actual_source_size},
        )

    # 块摘要链：偏移必须连续、累计摘要可重算、暂存块文件字节与记录一致。
    cumulative = hashlib.sha256()
    offset = 0
    parts_directory = parts_dir(target_root, ref.sha256)
    for expected_index, record in enumerate(journal["chunks"]):
        for name in ("index", "offset", "length", "chunk_sha256", "cumulative_sha256", "source_sha256"):
            if name not in record:
                raise Blocked("partial_chunk_mismatch", {"chunk": expected_index, "reason": f"missing:{name}"})
        if record["index"] != expected_index or record["offset"] != offset:
            raise Blocked(
                "partial_chunk_mismatch",
                {"chunk": expected_index, "index": record["index"], "offset": record["offset"], "expected_offset": offset},
            )
        if record["source_sha256"] != journal["source_sha256"]:
            raise Blocked(
                "partial_chunk_foreign_source",
                {"chunk": expected_index, "source_sha256": record["source_sha256"], "expected": journal["source_sha256"]},
            )
        if record["length"] <= 0 or record["offset"] + record["length"] > ref.bytes:
            raise Blocked("partial_chunk_mismatch", {"chunk": expected_index, "reason": "bad_length"})
        part_path = parts_directory / f"{expected_index:06d}.part"
        actual = try_sha256_file(part_path)
        actual_digest, actual_error = actual
        if actual_digest is None:
            raise Blocked(
                "partial_chunk_missing",
                {"chunk": expected_index, "path": str(part_path), "error": actual_error},
            )
        if actual_digest != record["chunk_sha256"]:
            raise Blocked(
                "partial_chunk_mismatch",
                {"chunk": expected_index, "recorded": record["chunk_sha256"], "actual": actual_digest},
            )
        try:
            chunk_bytes_read = part_path.read_bytes()
        except OSError as exc:
            raise Blocked("partial_chunk_missing", {"chunk": expected_index, "error": str(exc)}) from None
        if len(chunk_bytes_read) != record["length"]:
            raise Blocked(
                "partial_chunk_mismatch",
                {"chunk": expected_index, "reason": "length", "recorded": record["length"], "actual": len(chunk_bytes_read)},
            )
        cumulative.update(chunk_bytes_read)
        if cumulative.hexdigest() != record["cumulative_sha256"]:
            raise Blocked(
                "partial_chunk_mismatch",
                {"chunk": expected_index, "reason": "cumulative_digest_mismatch"},
            )
        offset += record["length"]

    if offset != journal["committed_bytes"]:
        raise Blocked(
            "partial_chunk_mismatch",
            {"reason": "committed_bytes", "records": offset, "journal": journal["committed_bytes"]},
        )
    if offset > ref.bytes:
        raise Blocked("partial_chunk_mismatch", {"reason": "overrun", "committed": offset, "expected": ref.bytes})
    return offset, current_identity


def transfer_object(
    source_root: Path,
    target_root: Path,
    ref: ObjectRef,
    policy: TransferPolicy,
) -> TransferEvidence:
    """把一个对象（按摘要）复制到目标暂存区；可续传。不做最终可见性提升。"""
    source_path = safe_path(source_root, ref.key)
    source_actual = sha256_file(source_path)
    if source_actual != ref.sha256:
        raise Blocked(
            "source_object_corrupt",
            {"key": ref.key, "expected_sha256": ref.sha256, "actual_sha256": source_actual},
        )
    identity = _source_identity(source_path)

    journal = load_journal(target_root, ref, policy)
    resumed_from_byte = 0
    resumed_from_chunk = 0
    if journal is not None:
        resumed_from_byte, _ = validate_resume(target_root, ref, journal, policy)
        resumed_from_chunk = len(journal["chunks"])
    else:
        journal = {
            "version": 1,
            "key": ref.key,
            "sha256": ref.sha256,
            "bytes": ref.bytes,
            "source_sha256": ref.sha256,
            "chunk_bytes": policy.chunk_bytes,
            "chunks": [],
            "committed_bytes": 0,
            "source_identity": identity,
            "injection_used": False,
        }

    staging_root(target_root).mkdir(parents=True, exist_ok=True)
    parts_directory = parts_dir(target_root, ref.sha256)
    parts_directory.mkdir(parents=True, exist_ok=True)
    cumulative = hashlib.sha256()
    for record in journal["chunks"]:
        part_path = parts_directory / f"{record['index']:06d}.part"
        cumulative.update(part_path.read_bytes())
    if cumulative.hexdigest() != (journal["chunks"][-1]["cumulative_sha256"] if journal["chunks"] else hashlib.sha256().hexdigest()):
        raise Blocked("partial_chunk_mismatch", {"reason": "resume_cumulative_rebuild"})

    committed = resumed_from_byte
    transferred = 0
    total_chunks = (ref.bytes + policy.chunk_bytes - 1) // policy.chunk_bytes
    injection_used = bool(journal.get("injection_used"))

    with source_path.open("rb") as source:
        for index in range(resumed_from_chunk, total_chunks):
            current_identity = _source_identity(source_path)
            if current_identity != identity:
                raise Blocked(
                    "source_changed_during_transfer",
                    {"key": ref.key, "recorded": identity, "current": current_identity, "at_chunk": index},
                )
            offset = index * policy.chunk_bytes
            length = min(policy.chunk_bytes, ref.bytes - offset)
            data = read_chunk(source, offset, length)
            chunk_digest = hashlib.sha256(data).hexdigest()
            cumulative.update(data)
            cumulative_digest = cumulative.hexdigest()
            record = ChunkRecord(
                index=index,
                offset=offset,
                length=length,
                chunk_sha256=chunk_digest,
                cumulative_sha256=cumulative_digest,
                source_sha256=journal["source_sha256"],
            )
            part_path = parts_directory / f"{index:06d}.part"
            # 块先写同目录临时文件再替换：崩溃时不会留下“看似完整”的半块。
            temp_part = parts_directory / f".{index:06d}.part.tmp"
            with temp_part.open("wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_part, part_path)
            fsync_dir(parts_directory)
            journal["chunks"].append(record.to_json())
            journal["committed_bytes"] = offset + length
            journal["source_identity"] = identity
            committed = offset + length
            transferred += 1
            atomic_write(journal_path(target_root, ref.sha256), json.dumps(journal, sort_keys=True, indent=2).encode("utf-8") + b"\n")

            if (
                policy.inject
                and not injection_used
                and transferred in policy.inject_after_chunks
            ):
                journal["injection_used"] = True
                atomic_write(journal_path(target_root, ref.sha256), json.dumps(journal, sort_keys=True, indent=2).encode("utf-8") + b"\n")
                raise TransferInterrupted(ref.key, committed, index + 1)

    # 全部块到位后，逐块再验摘要并把它们拼成完整对象。
    if committed != ref.bytes:
        raise Blocked("partial_chunk_mismatch", {"reason": "incomplete", "committed": committed, "expected": ref.bytes})
    full_temp = staging_root(target_root) / f".{ref.sha256}.assembling"
    hasher = hashlib.sha256()
    with full_temp.open("wb") as out:
        for index in range(total_chunks):
            part_path = parts_directory / f"{index:06d}.part"
            data = part_path.read_bytes()
            hasher.update(data)
            out.write(data)
        out.flush()
        os.fsync(out.fileno())
    actual_digest = hasher.hexdigest()
    if actual_digest != ref.sha256:
        raise Blocked(
            "assembled_digest_mismatch",
            {"key": ref.key, "expected_sha256": ref.sha256, "actual_sha256": actual_digest},
        )
    if full_temp.stat().st_size != ref.bytes:
        raise Blocked(
            "assembled_size_mismatch",
            {"key": ref.key, "expected_bytes": ref.bytes, "actual_bytes": full_temp.stat().st_size},
        )
    os.chmod(full_temp, 0o644)
    os.replace(full_temp, staged_data_path(target_root, ref.sha256))

    # 清掉本次复制的临时块与日志；只动本摘要的暂存区。
    _cleanup_staging(target_root, ref.sha256)

    return TransferEvidence(
        key=ref.key,
        sha256=ref.sha256,
        bytes=ref.bytes,
        chunk_bytes=policy.chunk_bytes,
        chunks_total=total_chunks,
        resumed_from_byte=resumed_from_byte,
        resumed_from_chunk=resumed_from_chunk,
        chunks_transferred_this_run=transferred,
        source_sha256=ref.sha256,
        journal_used=[str(journal_path(target_root, ref.sha256))],
    )


def _cleanup_staging(target_root: Path, digest: str) -> None:
    parts_directory = parts_dir(target_root, digest)
    if parts_directory.is_dir():
        shutil.rmtree(parts_directory)
    journal = journal_path(target_root, digest)
    for path in (journal, staging_root(target_root) / f".{digest}.assembling"):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _unreadable_label(error: str | None) -> str:
    return hashlib.sha256(f"unreadable:{error}".encode("utf-8")).hexdigest()[:32]


def quarantine_damaged(target_root: Path, dest: Path, *, key: str, expected_sha256: str) -> dict:
    """把目标已有的不匹配对象移入隔离区留证，返回隔离证据。"""
    actual, error = try_sha256_file(dest)
    if actual is None and error == "missing":
        return {}
    if actual == expected_sha256:
        return {}
    quarantine_root(target_root).mkdir(parents=True, exist_ok=True)
    slot = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    slot_dir = quarantine_root(target_root) / slot
    slot_dir.mkdir(parents=True, exist_ok=True)
    label = actual or _unreadable_label(error)
    candidate = slot_dir / f"{label}.{os.getpid()}.q"
    counter = 0
    while candidate.exists():
        counter += 1
        candidate = slot_dir / f"{label}.{os.getpid()}.{counter}.q"
    target = candidate
    os.replace(dest, target)
    fsync_dir(dest.parent)
    if target.is_file() and not target.is_symlink():
        fsync_file(target)
    return {
        "key": key,
        "original_path": str(dest),
        "quarantine_path": str(target),
        "expected_sha256": expected_sha256,
        "actual_sha256": actual,
        "actual_error": error,
        "bytes": target.stat().st_size if target.is_file() and not target.is_symlink() else None,
    }


def promote_object(target_root: Path, ref: ObjectRef) -> dict:
    """把已验证的完整对象原子放到可见位置；必要时先隔离损坏副本。"""
    staged = staged_data_path(target_root, ref.sha256)
    if not staged.is_file():
        raise Blocked("staged_object_missing", {"key": ref.key, "staged": str(staged)})
    actual = sha256_file(staged)
    if actual != ref.sha256:
        raise Blocked("staged_object_corrupt", {"key": ref.key, "expected": ref.sha256, "actual": actual})

    dest = safe_path(target_root, ref.key)
    current, error = try_sha256_file(dest)
    if current == ref.sha256:
        return {"key": ref.key, "path": str(dest), "action": "already_present_verified", "quarantined": None}
    quarantine = quarantine_damaged(target_root, dest, key=ref.key, expected_sha256=ref.sha256)
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = dest.with_name(f".{dest.name}.promote-{os.getpid()}")
    try:
        os.link(staged, temp)
    except OSError:
        shutil.copyfile(staged, temp)
    os.chmod(temp, 0o644)
    fsync_file(temp)
    os.replace(temp, dest)
    fsync_dir(dest.parent)
    # 复核可见对象，防止替换后字节不符。
    final = sha256_file(dest)
    if final != ref.sha256:
        raise Blocked("promoted_object_corrupt", {"key": ref.key, "expected": ref.sha256, "actual": final})
    return {"key": ref.key, "path": str(dest), "action": "promoted_after_verified", "quarantined": quarantine or None}
