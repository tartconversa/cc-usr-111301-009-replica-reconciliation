"""不可变清单的解析与校验（父链、环、越界键、同键异摘要、摘要格式）。

清单是普通本地 JSON 文件：:

    {"manifest_id": "...", "parent": null | {"key": "...", "sha256": "..."},
     "objects": [{"key": "...", "bytes": 3, "sha256": "..."}]}

清单自身的内容摘要 = 文件字节的 SHA256，由父条目或复制的入口摘要钉住。
对象 key 是相对路径；内容寻址键按“字节哈希”解释，名字只用于定位，
绝不单独作为可信依据。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .errors import Blocked

MANIFEST_SUFFIXES = (".json",)
_SHA256_CHARS = set("0123456789abcdef")


def is_sha256_hex(value: Any) -> bool:
    """严格校验 64 位小写十六进制摘要。"""
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value) <= _SHA256_CHARS
    )


def validate_relative_key(key: Any, *, what: str = "key") -> str:
    """只接受规范化相对 POSIX 路径；拒绝绝对路径与 `..` 越界。

    返回规范化后的 key。拒绝而不是静默修正，因为 key 是清单声明的身份
    的一部分；同一内容在不同 key 下就是不同的引用关系，需要作者显式改清单。
    """
    if not isinstance(key, str) or not key:
        raise Blocked("invalid_key", {"what": what, "key": key, "reason": "empty_or_not_string"})
    if "\\" in key:
        raise Blocked("invalid_key", {"what": what, "key": key, "reason": "backslash"})
    if key.startswith("/"):
        raise Blocked("invalid_key", {"what": what, "key": key, "reason": "absolute"})
    parts = PurePosixPath(key).parts
    if any(part == ".." for part in parts):
        raise Blocked("path_escape", {"what": what, "key": key, "reason": "dotdot"})
    if any(part in ("", ".") for part in parts):
        raise Blocked("invalid_key", {"what": what, "key": key, "reason": "non_canonical"})
    return key


@dataclass(frozen=True)
class ObjectRef:
    key: str
    bytes: int
    sha256: str


@dataclass(frozen=True)
class ParentRef:
    key: str
    sha256: str


@dataclass(frozen=True)
class Manifest:
    path: Path
    key: str
    digest: str
    manifest_id: str
    parent: ParentRef | None
    objects: tuple[ObjectRef, ...]


def parse_manifest(path: Path, key: str, digest: str) -> Manifest:
    """解析并校验清单结构。任何结构问题都以 Blocked 报告。"""
    import json

    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise Blocked("manifest_missing", {"key": key, "path": str(path)}) from None
    except OSError as exc:
        raise Blocked("manifest_unreadable", {"key": key, "error": str(exc)}) from None

    import hashlib

    actual = hashlib.sha256(raw).hexdigest()
    if actual != digest:
        raise Blocked(
            "manifest_digest_mismatch",
            {"key": key, "expected": digest, "actual": actual},
        )

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Blocked("manifest_malformed", {"key": key, "error": str(exc)}) from None

    if not isinstance(data, dict):
        raise Blocked("manifest_malformed", {"key": key, "reason": "not_an_object"})
    unknown = set(data) - {"manifest_id", "parent", "objects"}
    if unknown:
        raise Blocked("manifest_malformed", {"key": key, "reason": "unknown_fields", "fields": sorted(unknown)})

    manifest_id = data.get("manifest_id")
    if not isinstance(manifest_id, str) or not manifest_id:
        raise Blocked("manifest_malformed", {"key": key, "reason": "missing_manifest_id"})

    parent = _parse_parent(data.get("parent"), key)
    objects = _parse_objects(data.get("objects"), key)
    _check_duplicate_keys(objects, key)
    return Manifest(
        path=path,
        key=key,
        digest=actual,
        manifest_id=manifest_id,
        parent=parent,
        objects=tuple(objects),
    )


def _parse_parent(value: Any, key: str) -> ParentRef | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise Blocked("manifest_malformed", {"key": key, "reason": "parent_not_object"})
    unknown = set(value) - {"key", "sha256"}
    if unknown:
        raise Blocked("manifest_malformed", {"key": key, "reason": "parent_unknown_fields", "fields": sorted(unknown)})
    parent_key = validate_relative_key(value.get("key"), what=f"parent of {key}")
    if not parent_key.endswith(MANIFEST_SUFFIXES):
        raise Blocked("manifest_malformed", {"key": key, "reason": "parent_not_manifest", "parent": parent_key})
    if not is_sha256_hex(value.get("sha256")):
        raise Blocked("manifest_malformed", {"key": key, "reason": "parent_bad_sha256"})
    return ParentRef(key=parent_key, sha256=value["sha256"])


def _parse_objects(value: Any, key: str) -> list[ObjectRef]:
    if not isinstance(value, list):
        raise Blocked("manifest_malformed", {"key": key, "reason": "objects_not_list"})
    result: list[ObjectRef] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise Blocked("manifest_malformed", {"key": key, "index": index, "reason": "object_not_mapping"})
        unknown = set(item) - {"key", "bytes", "sha256"}
        if unknown:
            raise Blocked(
                "manifest_malformed",
                {"key": key, "index": index, "reason": "object_unknown_fields", "fields": sorted(unknown)},
            )
        object_key = validate_relative_key(item.get("key"), what=f"object[{index}] of {key}")
        if object_key.endswith(MANIFEST_SUFFIXES):
            raise Blocked(
                "manifest_malformed",
                {"key": key, "index": index, "reason": "object_key_looks_like_manifest", "object": object_key},
            )
        size = item.get("bytes")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise Blocked("manifest_malformed", {"key": key, "index": index, "reason": "bad_bytes"})
        if not is_sha256_hex(item.get("sha256")):
            raise Blocked("manifest_malformed", {"key": key, "index": index, "reason": "bad_sha256"})
        result.append(ObjectRef(key=object_key, bytes=size, sha256=item["sha256"]))
    return result


def _check_duplicate_keys(objects: list[ObjectRef], key: str) -> None:
    seen: dict[str, ObjectRef] = {}
    for item in objects:
        prior = seen.get(item.key)
        if prior is None:
            seen[item.key] = item
            continue
        if prior.sha256 != item.sha256 or prior.bytes != item.bytes:
            # 同键不同摘要：绝不“后者覆盖前者”，也不在目标里二选一。
            raise Blocked(
                "key_conflict",
                {
                    "manifest": key,
                    "object": item.key,
                    "first": {"bytes": prior.bytes, "sha256": prior.sha256},
                    "second": {"bytes": item.bytes, "sha256": item.sha256},
                },
            )


@dataclass
class ManifestChain:
    """入口 manifest 及其全部祖先，按子→父顺序排列。"""

    manifests: list[Manifest]
    closure: dict[str, ObjectRef]

    @property
    def root_manifest(self) -> Manifest:
        """入口清单（子→父链的第一项）。"""
        return self.manifests[0]

    def closure_digest(self) -> str:
        """清单闭包的稳定摘要：对 (清单摘要, 对象键, 对象摘要) 排序后哈希。"""
        import hashlib

        lines = sorted(
            f"{m.digest} {ref.key} {ref.sha256}" for m in self.manifests for ref in m.objects
        )
        return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def walk_chain(
    entry_path: Path,
    entry_key: str,
    entry_digest: str,
    *,
    resolve_parent: "Callable[[ParentRef], Path] | None" = None,
) -> ManifestChain:
    """从入口清单沿 parent 递归，检测环、重复祖先与对象冲突。

    只读取清单文件；不写入任何内容。对象是否存在于源端由调用方另行核验。
    resolve_parent 决定父清单的物理位置：源根按逻辑名相邻，目标清单存储
    按父摘要寻址。缺省为“入口清单所在目录 + 父逻辑名”。
    """
    manifests: list[Manifest] = []
    visited_paths: dict[Path, str] = {}  # 物理清单路径 -> 首次出现时的逻辑 key
    visited_keys: dict[str, str] = {}  # 逻辑 key -> 首次解析时的摘要
    trail: list[str] = []
    current_path, current_key, current_digest = entry_path, entry_key, entry_digest
    while True:
        resolved_path = Path(os.path.realpath(current_path))
        if resolved_path in visited_paths:
            # 父链回到已读过的物理清单：环（无论记录摘要是否一致）。
            raise Blocked(
                "manifest_cycle",
                {
                    "kind": "physical_path",
                    "path": str(resolved_path),
                    "first_key": visited_paths[resolved_path],
                    "current_key": current_key,
                    "trail": trail + [current_key],
                },
            )
        if current_key in visited_keys:
            # 逻辑 key 重入：同一份清单被指为祖先。摘要相同就是纯环，
            # 摘要不同则是清单被原地改写，同样拒绝继续。
            raise Blocked(
                "manifest_cycle",
                {
                    "kind": "logical_key",
                    "key": current_key,
                    "first_sha256": visited_keys[current_key],
                    "current_sha256": current_digest,
                    "trail": trail + [current_key],
                },
            )
        visited_paths[resolved_path] = current_key
        visited_keys[current_key] = current_digest
        trail.append(current_key)

        manifest = parse_manifest(current_path, current_key, current_digest)
        manifests.append(manifest)
        if manifest.parent is None:
            break
        parent = manifest.parent
        if resolve_parent is not None:
            current_path = resolve_parent(parent)
        else:
            current_path = manifest.path.parent / parent.key
        current_key = parent.key
        current_digest = parent.sha256

    closure: dict[str, ObjectRef] = {}
    for manifest in manifests:
        for ref in manifest.objects:
            prior = closure.get(ref.key)
            if prior is None:
                closure[ref.key] = ref
            elif prior.sha256 != ref.sha256 or prior.bytes != ref.bytes:
                raise Blocked(
                    "key_conflict",
                    {
                        "object": ref.key,
                        "first": {"bytes": prior.bytes, "sha256": prior.sha256},
                        "second": {"bytes": ref.bytes, "sha256": ref.sha256},
                    },
                )
    return ManifestChain(manifests=manifests, closure=closure)
