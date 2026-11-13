"""目标闭包独立验证与 root 指针发布。

验证只依赖目标根自己：从清单存储按内容摘要读取清单，重走父链，
逐对象按字节重算 SHA256。指针只在该验证通过后原子替换。
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .errors import Blocked
from .manifest import Manifest, ManifestChain, walk_chain
from .paths import manifest_store_path, pointer_path
from .store import atomic_write, safe_path, try_sha256_file


@dataclass
class ClosureVerification:
    ok: bool
    source_closure_sha256: str
    target_closure_sha256: str
    manifests: list[dict] = field(default_factory=list)
    objects: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)


def closure_digest(manifest_digests: list[tuple[str, str]], objects: list[tuple[str, int, str]]) -> str:
    lines = [f"manifest {digest} {key}" for key, digest in manifest_digests]
    lines += [f"object {key} {size} {digest}" for key, size, digest in objects]
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def verify_target_closure(
    target_root: Path,
    *,
    entry_key: str,
    entry_digest: str,
    expected_source_closure_sha256: str = "",
) -> ClosureVerification:
    """从目标清单存储重建闭包并逐字节核验；不信任文件名与大小。"""
    entry_path = manifest_store_path(target_root, entry_digest)
    errors: list[dict] = []
    manifests_out: list[dict] = []
    objects_out: list[dict] = []
    try:
        chain = walk_chain(
            entry_path,
            entry_key,
            entry_digest,
            resolve_parent=lambda parent: manifest_store_path(target_root, parent.sha256),
        )
    except Blocked as exc:
        return ClosureVerification(
            ok=False,
            source_closure_sha256=expected_source_closure_sha256,
            target_closure_sha256="",
            errors=[{"code": exc.code, **exc.detail}],
        )

    manifest_pairs: list[tuple[str, str]] = []
    object_triples: list[tuple[str, int, str]] = []
    for manifest in chain.manifests:
        stored, error = try_sha256_file(manifest_store_path(target_root, manifest.digest))
        if stored != manifest.digest:
            errors.append(
                {
                    "code": "target_manifest_corrupt",
                    "key": manifest.key,
                    "expected_sha256": manifest.digest,
                    "actual_sha256": stored,
                    "error": error,
                }
            )
        manifests_out.append(
            {
                "key": manifest.key,
                "sha256": manifest.digest,
                "target_path": str(manifest_store_path(target_root, manifest.digest)),
                "verified": stored == manifest.digest,
            }
        )
        manifest_pairs.append((manifest.key, manifest.digest))

    for ref in sorted(chain.closure.values(), key=lambda item: item.key):
        path = safe_path(target_root, ref.key)
        actual, error = try_sha256_file(path)
        verified = actual == ref.sha256
        if verified:
            size = path.stat().st_size
            if size != ref.bytes:
                verified = False
                errors.append(
                    {
                        "code": "target_object_corrupt",
                        "key": ref.key,
                        "reason": "size",
                        "expected_bytes": ref.bytes,
                        "actual_bytes": size,
                    }
                )
        else:
            errors.append(
                {
                    "code": "target_object_missing" if actual is None and error == "missing" else "target_object_corrupt",
                    "key": ref.key,
                    "expected_sha256": ref.sha256,
                    "actual_sha256": actual,
                    "error": error,
                }
            )
        objects_out.append(
            {
                "key": ref.key,
                "bytes": ref.bytes,
                "sha256": ref.sha256,
                "actual_sha256": actual,
                "verified": verified,
            }
        )
        if verified:
            object_triples.append((ref.key, ref.bytes, ref.sha256))

    target_digest = closure_digest(manifest_pairs, object_triples)
    return ClosureVerification(
        ok=not errors,
        source_closure_sha256=expected_source_closure_sha256,
        target_closure_sha256=target_digest,
        manifests=manifests_out,
        objects=objects_out,
        errors=errors,
    )


def read_pointer(target_root: Path) -> dict | None:
    path = pointer_path(target_root)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise Blocked("pointer_unreadable", {"pointer": str(path), "error": str(exc)}) from None


def publish_pointer(
    target_root: Path,
    *,
    entry_key: str,
    entry_digest: str,
    chain: ManifestChain,
    source_closure_sha256: str,
    target_closure_sha256: str,
) -> dict:
    """完整闭包在目标验证通过后，原子切换 root 指针。"""
    pointer = {
        "version": 1,
        "root_manifest_key": entry_key,
        "root_manifest_sha256": entry_digest,
        "manifest_digests": [manifest.digest for manifest in chain.manifests],
        "manifests": [{"key": manifest.key, "sha256": manifest.digest} for manifest in chain.manifests],
        "objects": [
            {"key": ref.key, "bytes": ref.bytes, "sha256": ref.sha256}
            for ref in sorted(chain.closure.values(), key=lambda item: item.key)
        ],
        "source_closure_sha256": source_closure_sha256,
        "target_closure_sha256": target_closure_sha256,
        "published_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write(pointer_path(target_root), (json.dumps(pointer, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    return pointer


def write_manifest_copy(target_root: Path, manifest: Manifest) -> dict:
    """把已验证的清单按内容摘要写入目标清单存储。"""
    dest = manifest_store_path(target_root, manifest.digest)
    source_actual, error = try_sha256_file(manifest.path)
    if source_actual != manifest.digest:
        raise Blocked(
            "manifest_digest_mismatch",
            {"key": manifest.key, "expected": manifest.digest, "actual": source_actual, "error": error},
        )
    data = manifest.path.read_bytes()
    atomic_write(dest, data)
    stored, stored_error = try_sha256_file(dest)
    if stored != manifest.digest:
        raise Blocked(
            "manifest_copy_corrupt",
            {"key": manifest.key, "expected": manifest.digest, "actual": stored, "error": stored_error},
        )
    return {"key": manifest.key, "sha256": manifest.digest, "target_path": str(dest), "verified": True}
