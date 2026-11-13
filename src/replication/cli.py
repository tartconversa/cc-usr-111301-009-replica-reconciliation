"""命令行入口：只读计划、修复、恢复、验证、旧读者检查。

    python -m src.replication plan      fixtures/replication.json
    python -m src.replication repair    fixtures/replication.json
    python -m src.replication resume    fixtures/replication.json
    python -m src.replication verify    fixtures/replication.json
    python -m src.replication reader    fixtures/replication.json
    python -m src.replication demo
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

from .apply import run
from .closure import verify_target_closure
from .errors import ConfigError, PlanRejected
from .plan import Plan, ReplicationConfig, build_plan
from .store import try_sha256_file
from .transfer import TransferPolicy


def load_config(path: Path) -> tuple[ReplicationConfig, dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    config = ReplicationConfig.from_dict(data, base=path.resolve().parent)
    return config, data


def _plan_payload(plan: Plan) -> dict:
    return {
        "entry": {"key": plan.config.root_manifest, "sha256": plan.config.root_sha256},
        "source_closure_sha256": plan.source_closure_digest(),
        "publishable": plan.publishable,
        "manifests": [
            {
                "key": manifest.key,
                "digest": manifest.digest,
                "target_path": str(manifest.target_path),
                "target_state": manifest.target_state,
                "target_actual_sha256": manifest.target_actual_sha256,
                "action": manifest.action,
            }
            for manifest in plan.manifests
        ],
        "objects": [
            {
                "key": item.ref.key,
                "bytes": item.ref.bytes,
                "sha256": item.ref.sha256,
                "source_state": item.source_state,
                "source_actual_sha256": item.source_actual_sha256,
                "target_state": item.target_state,
                "target_actual_sha256": item.target_actual_sha256,
                "action": item.action,
                "dedup_group": item.dedup_group,
            }
            for item in plan.objects
        ],
        "blocked": [{"code": item.code, **item.detail} for item in plan.blocked],
        "transfer_budget": {
            "chunk_bytes": plan.config.chunk_bytes,
            "unique_payloads": len(plan.unique_payloads),
            "referenced_objects": len(plan.chain.closure),
        },
    }


def _print(payload: dict) -> None:
    print(json.dumps(payload, sort_keys=True, indent=2))


def command_plan(config: ReplicationConfig) -> int:
    try:
        plan = build_plan(config)
    except PlanRejected as exc:
        print(json.dumps({"publishable": False, "blocked": [b.detail for b in exc.rejected]}, indent=2))
        return 2
    _print(_plan_payload(plan))
    return 0 if plan.publishable else 2


def _policy(config: ReplicationConfig, *, inject: bool) -> TransferPolicy:
    return TransferPolicy(
        chunk_bytes=config.chunk_bytes,
        inject_after_chunks=config.fault_injection_after_chunks,
        inject=inject,
    )


def command_repair(config: ReplicationConfig, *, inject: bool) -> int:
    try:
        plan = build_plan(config)
    except PlanRejected as exc:
        print(json.dumps({"published": False, "blocked": [b.detail for b in exc.rejected]}, indent=2))
        return 2
    result = run(plan, policy=_policy(config, inject=inject))
    _print(result.evidence())
    return 0 if result.published else 2


def command_resume(config: ReplicationConfig) -> int:
    return command_repair(config, inject=False)


def command_verify(config: ReplicationConfig) -> int:
    from .paths import pointer_path

    path = pointer_path(config.target_root)
    try:
        pointer = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        _print({"ok": False, "error": "pointer_missing", "pointer": str(path)})
        return 2
    except (OSError, json.JSONDecodeError) as exc:
        _print({"ok": False, "error": "pointer_unreadable", "detail": str(exc)})
        return 2
    verification = verify_target_closure(
        config.target_root,
        entry_key=pointer["root_manifest_key"],
        entry_digest=pointer["root_manifest_sha256"],
        expected_source_closure_sha256=pointer["source_closure_sha256"],
    )
    payload = {
        "ok": verification.ok,
        "pointer_root_manifest_sha256": pointer["root_manifest_sha256"],
        "source_closure_sha256": pointer["source_closure_sha256"],
        "target_closure_sha256": verification.target_closure_sha256,
        "manifests": verification.manifests,
        "objects": verification.objects,
        "errors": verification.errors,
    }
    _print(payload)
    return 0 if verification.ok else 2


def command_reader(config: ReplicationConfig) -> int:
    """检查旧/新读者能否各自钉住自己的 root 清单且内容可验。"""
    from .paths import pointer_path

    path = pointer_path(config.target_root)
    try:
        pointer = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        _print({"readable": False, "error": "pointer_missing", "pointer": str(path)})
        return 2
    except (OSError, json.JSONDecodeError) as exc:
        _print({"readable": False, "error": "pointer_unreadable", "detail": str(exc)})
        return 2
    rows = []
    ok = True
    for entry in pointer["manifests"]:
        path = config.target_root / ".replica" / "manifests" / f"{entry['sha256']}.json"
        actual, error = try_sha256_file(path)
        rows.append({"key": entry["key"], "pinned_sha256": entry["sha256"], "actual_sha256": actual, "error": error})
        ok = ok and actual == entry["sha256"]
    _print({"readable": ok, "manifests": rows})
    return 0 if ok else 2


def command_demo() -> int:
    """在临时工作区复制 fixtures，演示计划无副作用、中断续传、发布。"""
    root = Path(__file__).resolve().parents[2]
    fixtures = root / "fixtures"
    with tempfile.TemporaryDirectory(prefix="replica-demo-") as directory:
        work = Path(directory)
        shutil.copytree(fixtures / "source", work / "source")
        shutil.copytree(fixtures / "target", work / "target")
        config, _ = load_config(fixtures / "replication.json")
        config = ReplicationConfig(
            source_root=work / "source",
            target_root=work / "target",
            root_manifest=config.root_manifest,
            root_sha256=config.root_sha256,
            chunk_bytes=config.chunk_bytes,
            source_readonly=True,
            fault_injection_after_chunks=config.fault_injection_after_chunks,
            target_bad_object_policy=config.target_bad_object_policy,
        )
        before = _tree_digest(work)
        plan = build_plan(config)
        after_plan = _tree_digest(work)
        print(json.dumps({"stage": "plan", "readonly": before == after_plan, "objects": len(plan.objects)}))
        first = run(plan, policy=_policy(config, inject=True))
        print(json.dumps({"stage": "interrupted", "interrupted": first.interrupted, "published": first.published}))
        second = run(build_plan(config), policy=_policy(config, inject=False))
        print(json.dumps({"stage": "resumed", "evidence": second.evidence()}, sort_keys=True))
        return 0 if second.published else 2


def _tree_digest(root: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(str(path.relative_to(root)).encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _guard_write_targets(config: ReplicationConfig, command: str, *, force: bool) -> str | None:
    """写入型命令默认拒绝直接改仓库内 fixtures 原件。

    输入契约要求原始资料不被覆盖；演示与演练应在副本上进行。需要显式演练
    时可加 --force，但源根始终只读。
    """
    if command not in ("repair", "resume"):
        return None
    repo_fixtures = Path(__file__).resolve().parents[2] / "fixtures"
    try:
        target = config.target_root.resolve(strict=False)
        guarded = (repo_fixtures / "target").resolve(strict=False)
        source = config.source_root.resolve(strict=False)
    except OSError:  # pragma: no cover
        return None
    if source == (repo_fixtures / "source").resolve(strict=False) and target == guarded and not force:
        return (
            "拒绝直接写入 fixtures/target（原始资料不应被覆盖）；"
            "请先把 source/target 复制到工作目录，或使用 --force 明确允许演练。"
        )
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="本地对象根清单闭包复制与修复")
    parser.add_argument(
        "command",
        choices=("plan", "repair", "resume", "verify", "reader", "demo"),
    )
    parser.add_argument("config", nargs="?")
    parser.add_argument(
        "--force",
        action="store_true",
        help="允许 repair/resume 直接写入 fixtures/target（仅用于本地演练）",
    )
    args = parser.parse_args(argv)
    if args.command == "demo":
        return command_demo()
    if not args.config:
        parser.error("该命令需要 replication 配置路径")
    try:
        config, _ = load_config(Path(args.config))
    except (OSError, json.JSONDecodeError, ConfigError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 2
    refusal = _guard_write_targets(config, args.command, force=args.force)
    if refusal:
        print(json.dumps({"error": refusal, "readonly_alternative": "python -m src.replication demo"}))
        return 3
    handlers = {
        "plan": lambda: command_plan(config),
        "repair": lambda: command_repair(config, inject=True),
        "resume": lambda: command_resume(config),
        "verify": lambda: command_verify(config),
        "reader": lambda: command_reader(config),
    }
    return handlers[args.command]()


if __name__ == "__main__":
    sys.exit(main())
