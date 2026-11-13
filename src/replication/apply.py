"""执行编排：只读计划 → 清单/对象分块复制 → 隔离坏副本 → 闭包验证 → 发布指针。

发布顺序保证旧读者不受扰动：新对象都在旧对象旁边以新摘要可见，清单按内容
摘要追加写入，最后才原子替换 `.replica/published-root.json`。旧指针引用的
对象和清单从不删除。
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .closure import (
    ClosureVerification,
    publish_pointer,
    read_pointer,
    verify_target_closure,
    write_manifest_copy,
)
from .errors import Blocked, TransferInterrupted
from .paths import evidence_root, manifest_store_path, staging_root
from .plan import Plan
from .store import flock, safe_path, try_sha256_file
from .transfer import (
    TransferEvidence,
    TransferPolicy,
    promote_object,
    transfer_object,
)


@dataclass
class ApplyResult:
    entry_key: str
    entry_digest: str
    source_closure_sha256: str
    plan: Plan
    verification: ClosureVerification | None
    pointer: dict | None
    transfers: list[TransferEvidence] = field(default_factory=list)
    promotions: list[dict] = field(default_factory=list)
    manifests_written: list[dict] = field(default_factory=list)
    dedup_skipped: dict[str, list[str]] = field(default_factory=dict)
    interrupted: dict | None = None
    quarantined: list[dict] = field(default_factory=list)
    transferred_unique_objects: int = 0
    referenced_objects: int = 0

    @property
    def published(self) -> bool:
        return self.pointer is not None

    def evidence(self) -> dict:
        return {
            "entry": {"key": self.entry_key, "sha256": self.entry_digest},
            "source_closure_sha256": self.source_closure_sha256,
            "target_closure_sha256": self.verification.target_closure_sha256 if self.verification else None,
            "closures_verified": bool(self.verification and self.verification.ok),
            "objects_referenced": self.referenced_objects,
            "objects_transferred_unique": self.transferred_unique_objects,
            "chunk_bytes": self.plan.config.chunk_bytes,
            "transfers": [item.to_json() for item in self.transfers],
            "promotions": self.promotions,
            "manifests_written": self.manifests_written,
            "dedup_skipped": self.dedup_skipped,
            "quarantined": self.quarantined,
            "interrupted": self.interrupted,
            "published": self.published,
            "pointer": self.pointer,
            "verification": self.verification.__dict__ if self.verification else None,
            "blocked": [
                {"code": item.code, **item.detail} for item in self.plan.blocked
            ],
        }


def run(
    plan: Plan,
    *,
    policy: TransferPolicy,
    publish: bool = True,
    write_evidence: bool = True,
) -> ApplyResult:
    """按计划执行。计划里存在阻塞时不做任何写入。"""
    result = ApplyResult(
        entry_key=plan.config.root_manifest,
        entry_digest=plan.config.root_sha256,
        source_closure_sha256=plan.source_closure_digest(),
        plan=plan,
        verification=None,
        pointer=None,
    )
    result.referenced_objects = len(plan.chain.closure)
    if plan.blocked:
        result.interrupted = {"blocked_before_write": True}
        return result

    target_root = plan.config.target_root
    with flock(target_root / ".replica" / "writer.lock"):
        return _run_locked(plan, policy=policy, publish=publish, write_evidence=write_evidence, result=result)


def _run_locked(
    plan: Plan,
    *,
    policy: TransferPolicy,
    publish: bool,
    write_evidence: bool,
    result: ApplyResult,
) -> ApplyResult:
    target_root = plan.config.target_root
    source_root = plan.config.source_root

    # 1) 清单先按内容摘要入库；对象还没有同步，不会影响旧读者。
    for manifest in plan.chain.manifests:
        existing = try_sha256_file(manifest_store_path(target_root, manifest.digest))
        if existing[0] == manifest.digest:
            continue
        result.manifests_written.append(write_manifest_copy(target_root, manifest))

    # 2) 对象按内容摘要去重：同一摘要只传一次，再逐 key 提升。
    groups = plan.unique_payloads
    payloads = sorted(groups, key=lambda digest: (len(groups[digest]), digest))
    interrupted: dict | None = None
    for digest in payloads:
        group = groups[digest]
        if not any(item.transfer_needed for item in group):
            continue
        reference = next(item for item in group if item.transfer_needed)
        try:
            evidence = transfer_object(
                source_root,
                target_root,
                reference.ref,
                policy,
            )
        except TransferInterrupted as exc:
            result.interrupted = {
                "kind": "interrupted",
                "key": exc.key,
                "committed_bytes": exc.committed_bytes,
                "next_chunk": exc.next_chunk,
                "journal": str(staging_root(target_root) / f"{digest}.json"),
                "partial_parts": sorted(
                    str(path)
                    for path in (staging_root(target_root) / f"{digest}.parts").glob("*.part")
                ),
            }
            interrupted = result.interrupted
            break
        except Blocked as exc:
            result.interrupted = {"kind": "blocked", "code": exc.code, **exc.detail}
            interrupted = result.interrupted
            break
        result.transfers.append(evidence)
        result.transferred_unique_objects += 1

        if len(group) > 1:
            result.dedup_skipped[digest] = [item.ref.key for item in group if item.ref.key != reference.ref.key]

        for item in group:
            promotion = promote_object(target_root, item.ref)
            result.promotions.append(promotion)
            if promotion.get("quarantined"):
                result.quarantined.append(promotion["quarantined"])
        # 所有 key 都提升成功后清掉共享的暂存数据。
        try:
            (staging_root(target_root) / f"{digest}.data").unlink()
        except FileNotFoundError:
            pass

    if interrupted is not None:
        result.verification = None
        return result

    # 3) 独立验证目标闭包；不过关就不动指针。
    verification = verify_target_closure(
        target_root,
        entry_key=result.entry_key,
        entry_digest=result.entry_digest,
        expected_source_closure_sha256=result.source_closure_sha256,
    )
    result.verification = verification
    if not verification.ok:
        result.interrupted = {"blocked_at_verification": True, "errors": verification.errors}
        return result

    # 4) 关闭/拒绝清理旧指针仍引用的对象。
    previous = read_pointer(target_root)
    _assert_old_closure_intact(target_root, previous)

    if publish:
        result.pointer = publish_pointer(
            target_root,
            entry_key=result.entry_key,
            entry_digest=result.entry_digest,
            chain=plan.chain,
            source_closure_sha256=result.source_closure_sha256,
            target_closure_sha256=verification.target_closure_sha256,
        )
        if write_evidence:
            _write_evidence(target_root, result)
    return result


def _assert_old_closure_intact(target_root: Path, pointer: dict | None) -> None:
    """发布前确认旧指针仍可解析；任何对象缺失/损坏都只告警而不删除其他对象。

    复制器不执行回收，因此这里不删除任何东西；该检查把证据写入结果由调用方
    决定是否阻塞发布。当前策略：若旧指针引用对象已损坏，仍然允许发布新闭包，
    但记录告警，因为修复它需要上一次发布的清单，而不是删除它。
    """
    if pointer is None:
        return
    for item in pointer.get("objects", []):
        actual, error = try_sha256_file(safe_path(target_root, item["key"]))
        if actual != item["sha256"]:
            import warnings

            warnings.warn(
                f"旧 root 指针引用的对象不可用（不回收、不覆盖）：{item['key']} {error or actual}",
                RuntimeWarning,
                stacklevel=2,
            )


def _write_evidence(target_root: Path, result: ApplyResult) -> None:
    """把对象级修复证据写到目标根的 .replica/evidence 下（不影响闭包）。"""
    directory = evidence_root(target_root)
    directory.mkdir(parents=True, exist_ok=True)

    def write(name: str, payload: dict) -> None:
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:16]
        path = directory / f"{name}.{digest}.json"
        temp = directory / f".{name}.{digest}.tmp"
        data = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
        with temp.open("wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)

    evidence = result.evidence()
    write("replication", evidence)
    write("objects", {
        "entry": evidence["entry"],
        "source_closure_sha256": evidence["source_closure_sha256"],
        "target_closure_sha256": evidence["target_closure_sha256"],
        "objects": [
            {
                "key": item.ref.key,
                "bytes": item.ref.bytes,
                "sha256": item.ref.sha256,
                "source_state": item.source_state,
                "target_state_before": item.target_state,
                "action": item.action,
            }
            for item in result.plan.objects
        ],
        "transfers": [item.to_json() for item in result.transfers],
        "promotions": result.promotions,
        "quarantined": result.quarantined,
    })
