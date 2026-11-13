"""只读差异计划：检查清单闭包、源端可信性、目标端现状，给出定向动作。

计划阶段绝不写文件、不移动目标对象、不创建临时目录；所有问题都记录在
Plan 证据里，供 apply 使用或供人审阅。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from pathlib import Path

from .errors import Blocked, ConfigError, PlanRejected
from .manifest import ManifestChain, ObjectRef, walk_chain
from .paths import manifest_store_path
from .store import safe_path, try_sha256_file


@dataclass(frozen=True)
class ReplicationConfig:
    source_root: Path
    target_root: Path
    root_manifest: str
    root_sha256: str
    chunk_bytes: int
    source_readonly: bool
    fault_injection_after_chunks: tuple[int, ...]
    target_bad_object_policy: str

    @classmethod
    def from_dict(cls, data: dict, *, base: Path) -> "ReplicationConfig":
        if not isinstance(data, dict):
            raise ConfigError("复制配置必须是 JSON 对象")
        required = ("source_root", "target_root", "root_manifest", "root_sha256")
        missing = [name for name in required if name not in data]
        if missing:
            raise ConfigError(f"复制配置缺少字段: {missing}")
        chunk_bytes = data.get("chunk_bytes", 1024 * 1024)
        if isinstance(chunk_bytes, bool) or not isinstance(chunk_bytes, int) or chunk_bytes <= 0:
            raise ConfigError("chunk_bytes 必须是正整数")
        injections = data.get("fault_injection_after_chunks", [])
        if not isinstance(injections, list) or any(
            isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in injections
        ):
            raise ConfigError("fault_injection_after_chunks 必须是正整数列表")
        policy = data.get("target_bad_object_policy", "quarantine_then_repair")
        if policy != "quarantine_then_repair":
            raise ConfigError("仅支持 target_bad_object_policy=quarantine_then_repair")
        readonly = data.get("source_readonly", True)
        if readonly is not True:
            raise ConfigError("source_readonly 必须为 true；复制器从不写入源根")
        return cls(
            source_root=_under_base(base, data["source_root"]),
            target_root=_under_base(base, data["target_root"]),
            root_manifest=data["root_manifest"],
            root_sha256=data["root_sha256"],
            chunk_bytes=chunk_bytes,
            source_readonly=True,
            fault_injection_after_chunks=tuple(injections),
            target_bad_object_policy=policy,
        )


def _under_base(base: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        raise ConfigError(f"配置路径必须是相对路径: {value}")
    return (base / path).resolve(strict=False)


@dataclass
class ObjectPlan:
    ref: ObjectRef
    source_state: str
    source_actual_sha256: str | None
    target_state: str
    target_actual_sha256: str | None
    action: str  # present | copy | repair | blocked
    blocked: Blocked | None = None
    dedup_group: str = ""

    @property
    def transfer_needed(self) -> bool:
        return self.action in ("copy", "repair")


@dataclass
class ManifestPlan:
    key: str
    digest: str
    target_path: Path
    target_state: str
    target_actual_sha256: str | None
    action: str  # present | write | repair

    @property
    def transfer_needed(self) -> bool:
        return self.action in ("write", "repair")


@dataclass
class Plan:
    config: ReplicationConfig
    chain: ManifestChain
    objects: list[ObjectPlan]
    manifests: list[ManifestPlan]
    blocked: list[Blocked] = field(default_factory=list)
    entry_manifest_path: Path | None = None

    @property
    def publishable(self) -> bool:
        return not self.blocked

    @property
    def unique_payloads(self) -> dict[str, list[ObjectPlan]]:
        """按对象摘要分组：同一内容被多个清单/键引用时只传一次。"""
        groups: dict[str, list[ObjectPlan]] = {}
        for item in self.objects:
            if item.action == "blocked":
                continue
            groups.setdefault(item.ref.sha256, []).append(item)
        return groups

    def source_closure_digest(self) -> str:
        lines = [f"manifest {m.digest} {m.key}" for m in self.chain.manifests]
        lines += [f"object {ref.key} {ref.bytes} {ref.sha256}" for ref in sorted(self.chain.closure.values(), key=lambda r: r.key)]
        return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def build_plan(config: ReplicationConfig, *, source_root: Path | None = None, target_root: Path | None = None) -> Plan:
    """构建只读计划。不修改任何文件。"""
    source_root = (source_root or config.source_root).resolve(strict=False)
    target_root = (target_root or config.target_root).resolve(strict=False)
    if not source_root.is_dir():
        raise ConfigError(f"源根不存在或不是目录: {source_root}")
    if not target_root.is_dir():
        raise ConfigError(f"目标根不存在或不是目录: {target_root}")
    config = replace(config, source_root=source_root, target_root=target_root)

    entry_path = safe_path(source_root, config.root_manifest)
    blocked: list[Blocked] = []
    try:
        chain = walk_chain(entry_path, config.root_manifest, config.root_sha256)
    except Blocked as exc:
        raise PlanRejected([exc]) from None

    manifests: list[ManifestPlan] = []
    for manifest in chain.manifests:
        target_path = manifest_store_path(target_root, manifest.digest)
        actual, error = try_sha256_file(target_path)
        if actual == manifest.digest:
            state, action = "present", "present"
        elif actual is None and error == "missing":
            state, action = "missing", "write"
        else:
            state, action = f"corrupt:{error or actual}", "repair"
        manifests.append(
            ManifestPlan(
                key=manifest.key,
                digest=manifest.digest,
                target_path=target_path,
                target_state=state,
                target_actual_sha256=actual,
                action=action,
            )
        )

    objects: list[ObjectPlan] = []
    for ref in sorted(chain.closure.values(), key=lambda item: item.key):
        objects.append(_plan_object(source_root, target_root, ref))

    for item in objects:
        if item.source_state != "ok" and item.action == "blocked" and item.blocked:
            blocked.append(item.blocked)
    if not chain.manifests:
        blocked.append(Blocked("manifest_chain_empty", {}))

    return Plan(
        config=config,
        chain=chain,
        objects=objects,
        manifests=manifests,
        blocked=blocked,
        entry_manifest_path=entry_path,
    )


def _plan_object(source_root: Path, target_root: Path, ref: ObjectRef) -> ObjectPlan:
    source_path = safe_path(source_root, ref.key)
    source_actual, source_error = try_sha256_file(source_path)
    if source_actual is None:
        source_state = f"missing:{source_error}" if source_error == "missing" else f"unreadable:{source_error}"
        block = Blocked(
            "source_object_missing" if source_error == "missing" else "source_object_untrusted",
            {"key": ref.key, "error": source_error, "expected_sha256": ref.sha256},
        )
    elif source_actual != ref.sha256:
        source_state = f"corrupt:{source_actual}"
        block = Blocked(
            "source_object_corrupt",
            {"key": ref.key, "expected_sha256": ref.sha256, "actual_sha256": source_actual},
        )
    else:
        source_state, block = "ok", None
        try:
            if source_path.stat().st_size != ref.bytes:
                source_state = "corrupt:length"
                block = Blocked(
                    "source_object_corrupt",
                    {
                        "key": ref.key,
                        "expected_bytes": ref.bytes,
                        "actual_bytes": source_path.stat().st_size,
                    },
                )
        except OSError as exc:  # pragma: no cover - 读取成功后极少发生
            source_state = f"unreadable:{exc.errno}"
            block = Blocked("source_object_untrusted", {"key": ref.key, "error": str(exc)})

    target_path = safe_path(target_root, ref.key)
    target_actual, target_error = try_sha256_file(target_path)
    if target_actual == ref.sha256:
        target_state, action = "present_ok", "present"
    elif target_actual is None and target_error == "missing":
        target_state, action = "missing", "copy"
    else:
        target_state, action = f"damaged:{target_error or target_actual}", "repair"

    if block is not None:
        action = "blocked"

    return ObjectPlan(
        ref=ref,
        source_state=source_state,
        source_actual_sha256=source_actual,
        target_state=target_state,
        target_actual_sha256=target_actual,
        action=action,
        blocked=block,
        dedup_group=ref.sha256,
    )
