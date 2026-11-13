"""固定 root 的读者视图。

旧读者在发布新 root 之前拿到指针快照；此后即使新 root 发布，它仍按自己钉住的
清单摘要与对象摘要读取，不会看到半发布状态，也不会被新对象挤掉。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .errors import Blocked
from .manifest import walk_chain
from .paths import manifest_store_path
from .store import safe_path, try_sha256_file


@dataclass(frozen=True)
class PinnedReader:
    target_root: Path
    pointer: dict

    @classmethod
    def pin(cls, target_root: Path, pointer_path: Path | None = None) -> "PinnedReader":
        path = pointer_path or (target_root / ".replica" / "published-root.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(target_root=target_root, pointer=data)

    @property
    def root_manifest_key(self) -> str:
        return self.pointer["root_manifest_key"]

    @property
    def root_manifest_sha256(self) -> str:
        return self.pointer["root_manifest_sha256"]

    def chain(self):
        entry = manifest_store_path(self.target_root, self.root_manifest_sha256)
        return walk_chain(
            entry,
            self.root_manifest_key,
            self.root_manifest_sha256,
            resolve_parent=lambda parent: manifest_store_path(self.target_root, parent.sha256),
        )

    def read_object(self, key: str) -> bytes:
        """按指针声明的摘要读取对象；每次读取都重算字节摘要。"""
        declared = None
        for item in self.pointer["objects"]:
            if item["key"] == key:
                declared = item["sha256"]
                break
        if declared is None:
            raise Blocked("object_not_in_pinned_root", {"key": key})
        path = safe_path(self.target_root, key)
        data = path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != declared:
            raise Blocked(
                "pinned_object_corrupt",
                {"key": key, "expected_sha256": declared, "actual_sha256": actual},
            )
        return data

    def verify(self) -> list[dict]:
        """逐清单/逐对象核验，返回问题列表；空列表表示固定视图完好。"""
        problems: list[dict] = []
        for entry in self.pointer["manifests"]:
            actual, error = try_sha256_file(manifest_store_path(self.target_root, entry["sha256"]))
            if actual != entry["sha256"]:
                problems.append(
                    {
                        "kind": "manifest",
                        "key": entry["key"],
                        "expected_sha256": entry["sha256"],
                        "actual_sha256": actual,
                        "error": error,
                    }
                )
        for item in self.pointer["objects"]:
            actual, error = try_sha256_file(safe_path(self.target_root, item["key"]))
            if actual != item["sha256"]:
                problems.append(
                    {
                        "kind": "object",
                        "key": item["key"],
                        "expected_sha256": item["sha256"],
                        "actual_sha256": actual,
                        "error": error,
                    }
                )
        return problems
