"""复制器行为测试：全部在临时目录对 fixtures 的副本操作，绝不改写 fixtures。"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # 允许 `python -m unittest` 与直接运行
    sys.path.insert(0, str(ROOT))

from src.replication.apply import run
from src.replication.closure import verify_target_closure
from src.replication.errors import Blocked, PlanRejected, TransferInterrupted
from src.replication.manifest import walk_chain
from src.replication.paths import (
    journal_path,
    manifest_store_path,
    parts_dir,
    pointer_path,
    quarantine_root,
    staged_data_path,
    staging_root,
)
from src.replication.plan import ReplicationConfig, build_plan
from src.replication.reader import PinnedReader
from src.replication.store import sha256_file, try_sha256_file
from src.replication.transfer import TransferPolicy, promote_object, transfer_object, validate_resume

ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
ABD = "a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9"
ROOT_DIGEST = "e69c2107abd04d275dc6fd507478b0b81ee3a76b097f24607474fcd19299c342"
PARENT_DIGEST = "49c996b2b7b1879c00ea051ba71ab86ff6eb0035f6d83fe95f63edd350675005"
OBJ_KEY = f"objects/{ABC}"
ROOT_KEY = "root.json"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_state(root: Path) -> dict[str, tuple[int, str]]:
    """记录整棵树的 (大小, 内容摘要)，用于断言只读/无副作用。"""
    return {
        str(path.relative_to(root)): (path.stat().st_size, sha256_file(path))
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def make_workspace(directory: Path, *, chunk_bytes: int = 2, injections=(1,)) -> tuple[ReplicationConfig, Path]:
    work = directory
    shutil.copytree(ROOT / "fixtures" / "source", work / "source")
    shutil.copytree(ROOT / "fixtures" / "target", work / "target")
    config = ReplicationConfig(
        source_root=(work / "source").resolve(),
        target_root=(work / "target").resolve(),
        root_manifest=ROOT_KEY,
        root_sha256=ROOT_DIGEST,
        chunk_bytes=chunk_bytes,
        source_readonly=True,
        fault_injection_after_chunks=tuple(injections),
        target_bad_object_policy="quarantine_then_repair",
    )
    return config, work


def write_manifest(directory: Path, name: str, payload: dict) -> tuple[str, str]:
    data = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
    (directory / name).write_bytes(data)
    return name, sha(data)


def put_object(root: Path, key: str, data: bytes) -> None:
    path = root / key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


class ReplicationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="replica-test-")
        self.work = Path(self._temp.name)
        self.config, _ = make_workspace(self.work)

    def tearDown(self) -> None:
        self._temp.cleanup()

    @property
    def source(self) -> Path:
        return self.config.source_root

    @property
    def target(self) -> Path:
        return self.config.target_root

    def policy(self, *, inject: bool = False) -> TransferPolicy:
        return TransferPolicy(
            chunk_bytes=self.config.chunk_bytes,
            inject_after_chunks=self.config.fault_injection_after_chunks,
            inject=inject,
        )


class ReadOnlyPlanTests(ReplicationTestCase):
    def test_plan_reports_one_payload_for_two_manifests(self) -> None:
        before_source = tree_state(self.source)
        before_target = tree_state(self.target)
        plan = build_plan(self.config)
        self.assertTrue(plan.publishable)
        self.assertEqual(len(plan.chain.manifests), 2)
        self.assertEqual(len(plan.objects), 1, "两个清单引用同一对象，闭包去重后只想修一次")
        self.assertEqual(plan.objects[0].action, "repair")
        self.assertEqual(plan.objects[0].target_state, f"damaged:{ABD}")
        self.assertEqual(len(plan.unique_payloads), 1)
        self.assertEqual(len(plan.chain.closure), 1)
        self.assertEqual(tree_state(self.source), before_source)
        self.assertEqual(tree_state(self.target), before_target)
        self.assertFalse((self.target / ".replica").exists(), "只读计划不得创建任何目标文件")

    def test_plan_missing_target_is_copy_not_present(self) -> None:
        (self.target / OBJ_KEY).unlink()
        plan = build_plan(self.config)
        self.assertEqual(plan.objects[0].action, "copy")
        self.assertEqual(plan.objects[0].target_state, "missing")
        self.assertEqual(tree_state(self.target), tree_state(self.target))
        self.assertFalse((self.target / ".replica").exists())

    def test_plan_rejects_same_key_different_digest(self) -> None:
        parent_payload = json.loads((self.source / "parent.json").read_text())
        parent_payload["objects"] = [
            {"key": OBJ_KEY, "bytes": 3, "sha256": ABD}
        ]
        parent_key, parent_digest = write_manifest(
            self.source, "parent.json", parent_payload
        )
        root_payload = {
            "manifest_id": "root",
            "parent": {"key": parent_key, "sha256": parent_digest},
            "objects": [{"key": OBJ_KEY, "bytes": 3, "sha256": ABC}],
        }
        root_key, root_digest = write_manifest(self.source, "root.json", root_payload)
        config = ReplicationConfig(
            **{**self.config.__dict__, "root_sha256": root_digest}
        )
        with self.assertRaises(PlanRejected) as caught:
            build_plan(config)
        self.assertIn("key_conflict", {error.code for error in caught.exception.rejected})
        # 源端损坏/冲突时不写目标。
        self.assertFalse((self.target / ".replica").exists())

    def test_plan_detects_manifest_cycle(self) -> None:
        # 自引用清单：钉住自己的逻辑名。父摘要无法等于自身摘要（摘要随内容变化），
        # 因此只要求父摘要是“当前文件摘要”，由 walk_chain 在重入时判定为环。
        payload = {
            "manifest_id": "looped",
            "parent": {"key": "looped.json", "sha256": "0" * 64},
            "objects": [],
        }
        _, digest = write_manifest(self.source, "looped.json", payload)
        config = ReplicationConfig(
            **{**self.config.__dict__, "root_manifest": "looped.json", "root_sha256": digest}
        )
        with self.assertRaises(PlanRejected) as caught:
            build_plan(config)
        self.assertIn("manifest_cycle", {error.code for error in caught.exception.rejected})
        # 环在源端被发现，不写目标。
        self.assertFalse((self.target / ".replica").exists())

    def test_plan_rejects_absolute_and_parent_escape_keys(self) -> None:
        root_payload = json.loads((self.source / "root.json").read_text())
        root_payload["objects"] = [{"key": "../escaped.bin", "bytes": 3, "sha256": ABC}]
        (self.source / "root.json").write_text(json.dumps(root_payload))
        digest = sha((self.source / "root.json").read_bytes())
        config = ReplicationConfig(**{**self.config.__dict__, "root_sha256": digest})
        with self.assertRaises(PlanRejected) as caught:
            build_plan(config)
        self.assertIn("path_escape", {error.code for error in caught.exception.rejected})

    def test_plan_blocks_corrupt_source_and_never_writes(self) -> None:
        put_object(self.source, OBJ_KEY, b"abd")
        before = tree_state(self.target)
        plan = build_plan(self.config)
        self.assertFalse(plan.publishable)
        self.assertEqual(plan.objects[0].action, "blocked")
        self.assertEqual(plan.objects[0].blocked.code, "source_object_corrupt")
        result = run(plan, policy=self.policy())
        self.assertFalse(result.published)
        self.assertFalse((self.target / ".replica").exists())
        self.assertEqual(tree_state(self.target), before, "源不可信时不得动目标（尤其不能反向覆盖源）")
        self.assertEqual((self.source / OBJ_KEY).read_bytes(), b"abd")

    def test_plan_blocks_missing_source(self) -> None:
        (self.source / OBJ_KEY).unlink()
        plan = build_plan(self.config)
        self.assertFalse(plan.publishable)
        self.assertEqual(plan.objects[0].blocked.code, "source_object_missing")
        self.assertFalse((self.target / ".replica").exists())


class TransferTests(ReplicationTestCase):
    def test_interruption_then_resume_verifies_source_and_chunks(self) -> None:
        first = run(build_plan(self.config), policy=self.policy(inject=True))
        self.assertFalse(first.published)
        self.assertIsNotNone(first.interrupted)
        self.assertEqual(first.interrupted["kind"], "interrupted")
        self.assertEqual(first.interrupted["committed_bytes"], 2)
        self.assertTrue(len(first.interrupted["partial_parts"]) == 1)
        journal = json.loads(journal_path(self.target, ABC).read_text())
        self.assertEqual(len(journal["chunks"]), 1)
        self.assertEqual(journal["chunks"][0]["chunk_sha256"], sha(b"ab"))
        self.assertEqual(journal["chunks"][0]["source_sha256"], ABC)

        second = run(build_plan(self.config), policy=self.policy(inject=False))
        self.assertTrue(second.published)
        transfer = second.transfers[0]
        self.assertEqual(transfer.resumed_from_byte, 2)
        self.assertEqual(transfer.resumed_from_chunk, 1)
        self.assertEqual(transfer.chunks_transferred_this_run, 1)
        self.assertEqual(second.verification.target_closure_sha256, second.source_closure_sha256)
        # 完成后暂存块与日志被清理。
        self.assertFalse(parts_dir(self.target, ABC).exists())
        self.assertFalse(journal_path(self.target, ABC).exists())

    def test_source_change_refuses_resume(self) -> None:
        run(build_plan(self.config), policy=self.policy(inject=True))
        # 中断后源对象被改成同摘要的大小不同的内容（批次重写）。
        put_object(self.source, OBJ_KEY, b"xyz")
        plan = build_plan(self.config)
        # 计划阶段就直接阻塞：源摘要与清单不符。
        self.assertFalse(plan.publishable)
        result = run(plan, policy=self.policy())
        self.assertFalse(result.published)
        self.assertEqual(result.plan.objects[0].blocked.code, "source_object_corrupt")
        # 目标保持旧状态，绝不把中断内容提升。
        self.assertEqual((self.target / OBJ_KEY).read_bytes(), b"abd")

    def test_resume_rejects_identity_change_even_with_same_digest_content(self) -> None:
        run(build_plan(self.config), policy=self.policy(inject=True))
        journal = json.loads(journal_path(self.target, ABC).read_text())
        # 模拟源文件被替换为同摘要内容：用原子替换改写文件，mtime/inode 变。
        replacement = self.work / "replacement.bin"
        replacement.write_bytes(b"abc")
        os.replace(replacement, self.source / OBJ_KEY)
        os.utime(self.source / OBJ_KEY, ns=(1, 1))
        with self.assertRaises(Blocked) as caught:
            validate_resume(self.target, type("R", (), {"key": OBJ_KEY, "sha256": ABC, "bytes": 3})(), journal, self.policy())
        self.assertIn(caught.exception.code, {"resume_source_identity_changed"})

    def test_partial_chunk_tamper_refuses_resume(self) -> None:
        run(build_plan(self.config), policy=self.policy(inject=True))
        part = parts_dir(self.target, ABC) / "000000.part"
        part.write_bytes(b"xy")
        plan = build_plan(self.config)
        result = run(plan, policy=self.policy())
        self.assertFalse(result.published)
        self.assertEqual(result.interrupted["kind"], "blocked")
        self.assertEqual(result.interrupted["code"], "partial_chunk_mismatch")

    def test_damaged_target_quarantined_before_repair(self) -> None:
        result = run(build_plan(self.config), policy=self.policy())
        self.assertTrue(result.published)
        self.assertEqual(len(result.quarantined), 1)
        record = result.quarantined[0]
        self.assertEqual(record["actual_sha256"], ABD)
        self.assertEqual(record["expected_sha256"], ABC)
        quarantined = Path(record["quarantine_path"])
        self.assertTrue(quarantined.is_file())
        self.assertEqual(quarantined.read_bytes(), b"abd")
        self.assertTrue(quarantined.is_relative_to(quarantine_root(self.target)))
        visible = (self.target / OBJ_KEY).read_bytes()
        self.assertEqual(visible, b"abc")
        self.assertEqual(sha(visible), ABC)

    def test_no_target_reverse_overwrite(self) -> None:
        run(build_plan(self.config), policy=self.policy(inject=True))
        # 目标暂存块被外部改成源端不存在的内容；源端仍是 abc。
        part = parts_dir(self.target, ABC) / "000000.part"
        part.write_bytes(b"zz")
        plan = build_plan(self.config)
        result = run(plan, policy=self.policy())
        self.assertFalse(result.published)
        self.assertEqual((self.source / OBJ_KEY).read_bytes(), b"abc")
        self.assertEqual((self.target / OBJ_KEY).read_bytes(), b"abd")

    def test_dedup_transfers_once_for_two_manifests(self) -> None:
        result = run(build_plan(self.config), policy=self.policy())
        self.assertTrue(result.published)
        self.assertEqual(result.referenced_objects, 1)
        self.assertEqual(result.transferred_unique_objects, 1)
        for transfer in result.transfers:
            self.assertEqual(transfer.sha256, ABC)
        # 两个清单都指向同一个目标键，只提升一次。
        self.assertEqual(len(result.promotions), 1)
        self.assertEqual(len(result.pointer["manifests"]), 2)

    def test_second_run_is_noop(self) -> None:
        run(build_plan(self.config), policy=self.policy())
        pointer_before = pointer_path(self.target).read_bytes()
        result = run(build_plan(self.config), policy=self.policy(inject=True))
        self.assertTrue(result.published)
        self.assertEqual(result.transfers, [])
        self.assertEqual((self.target / OBJ_KEY).read_bytes(), b"abc")
        self.assertEqual(pointer_path(self.target).read_bytes()[:40], pointer_before[:40])

    def test_quarantine_then_repair_evidence_counts(self) -> None:
        result = run(build_plan(self.config), policy=self.policy())
        evidence = result.evidence()
        self.assertTrue(evidence["closures_verified"])
        self.assertEqual(evidence["source_closure_sha256"], evidence["target_closure_sha256"])
        self.assertEqual(evidence["objects_referenced"], 1)
        self.assertEqual(evidence["objects_transferred_unique"], 1)
        self.assertEqual(evidence["chunk_bytes"], 2)
        self.assertEqual(evidence["blocked"], [])

    def test_same_digest_under_two_keys_copies_once(self) -> None:
        # 两个不同 key 引用同一摘要：只传一次，但两个可见对象都建立。
        put_object(self.source, "objects/dup-a", b"abc")
        put_object(self.source, "objects/dup-b", b"abc")
        parent_payload = {
            "manifest_id": "parent",
            "parent": None,
            "objects": [{"key": OBJ_KEY, "bytes": 3, "sha256": ABC}],
        }
        parent_key, parent_digest = write_manifest(self.source, "p.json", parent_payload)
        root_payload = {
            "manifest_id": "root",
            "parent": {"key": parent_key, "sha256": parent_digest},
            "objects": [
                {"key": "objects/dup-a", "bytes": 3, "sha256": ABC},
                {"key": "objects/dup-b", "bytes": 3, "sha256": ABC},
            ],
        }
        _, root_digest = write_manifest(self.source, "r.json", root_payload)
        config = ReplicationConfig(
            **{**self.config.__dict__, "root_manifest": "r.json", "root_sha256": root_digest}
        )
        result = run(build_plan(config), policy=self.policy())
        self.assertTrue(result.published)
        self.assertEqual(result.transferred_unique_objects, 1)
        self.assertEqual(result.plan.chain.closure.__len__(), 3)
        self.assertTrue(result.dedup_skipped)
        for key in ("objects/dup-a", "objects/dup-b", OBJ_KEY):
            self.assertEqual((self.target / key).read_bytes(), b"abc")


class PublicationTests(ReplicationTestCase):
    def test_pointer_absent_when_closure_verification_fails(self) -> None:
        run(build_plan(self.config), policy=self.policy())
        pointer = json.loads(pointer_path(self.target).read_text())
        # 发布后破坏目标对象：闭包验证必须失败，指针不变。
        damaged = self.target / OBJ_KEY
        damaged.write_bytes(b"abd")
        verification = verify_target_closure(
            self.target,
            entry_key=pointer["root_manifest_key"],
            entry_digest=pointer["root_manifest_sha256"],
        )
        self.assertFalse(verification.ok)
        self.assertEqual(verification.errors[0]["code"], "target_object_corrupt")
        self.assertTrue(pointer_path(self.target).exists())
        self.assertEqual(json.loads(pointer_path(self.target).read_text()), pointer)

    def test_old_reader_pinned_to_previous_root_is_undisturbed(self) -> None:
        # 第一版：两个清单、一个对象。
        first = run(build_plan(self.config), policy=self.policy())
        self.assertTrue(first.published)
        old_reader = PinnedReader.pin(self.target)
        old_bytes = old_reader.read_object(OBJ_KEY)
        self.assertEqual(old_bytes, b"abc")
        old_pointer = dict(old_reader.pointer)

        # 发布新版本：入口 root2 指向一个新增对象。
        put_object(self.source, "objects/def", b"def")
        def_digest = sha(b"def")
        new_root_payload = {
            "manifest_id": "root2",
            "parent": {"key": ROOT_KEY, "sha256": ROOT_DIGEST},
            "objects": [{"key": "objects/def", "bytes": 3, "sha256": def_digest}],
        }
        _, new_root_digest = write_manifest(self.source, "root2.json", new_root_payload)
        config = ReplicationConfig(
            **{**self.config.__dict__, "root_manifest": "root2.json", "root_sha256": new_root_digest}
        )
        second = run(build_plan(config), policy=TransferPolicy(chunk_bytes=2, inject=False))
        self.assertTrue(second.published)
        self.assertEqual(second.pointer["root_manifest_sha256"], new_root_digest)

        # 旧读者仍读旧指针、旧清单、旧对象；对象字节未被新发布改动。
        self.assertEqual(old_reader.read_object(OBJ_KEY), b"abc")
        self.assertEqual(old_reader.verify(), [])
        self.assertEqual(old_reader.pointer, old_pointer)
        # 旧清单文件仍在目标清单存储里（清理不回收）。
        self.assertTrue(manifest_store_path(self.target, ROOT_DIGEST).is_file())
        self.assertTrue(manifest_store_path(self.target, PARENT_DIGEST).is_file())

    def test_new_root_not_published_when_one_closure_object_fails(self) -> None:
        put_object(self.source, "objects/def", b"def")
        def_digest = sha(b"def")
        new_root_payload = {
            "manifest_id": "root2",
            "parent": {"key": ROOT_KEY, "sha256": ROOT_DIGEST},
            "objects": [{"key": "objects/def", "bytes": 3, "sha256": def_digest}],
        }
        _, new_root_digest = write_manifest(self.source, "root2.json", new_root_payload)
        config = ReplicationConfig(
            **{**self.config.__dict__, "root_manifest": "root2.json", "root_sha256": new_root_digest}
        )
        plan = build_plan(config)
        self.assertTrue(plan.publishable)
        result = run(plan, policy=TransferPolicy(chunk_bytes=2, inject=False))
        self.assertTrue(result.published)
        # 删除新增对象后再跑：闭包不通过，旧指针保持。
        (self.target / "objects/def").unlink()
        before_pointer = pointer_path(self.target).read_text()
        verify = verify_target_closure(
            self.target,
            entry_key="root2.json",
            entry_digest=new_root_digest,
        )
        self.assertFalse(verify.ok)
        self.assertEqual(pointer_path(self.target).read_text(), before_pointer)


class TargetManifestTests(ReplicationTestCase):
    def test_corrupt_target_manifest_is_rewritten_from_source(self) -> None:
        run(build_plan(self.config), policy=TransferPolicy(chunk_bytes=2, inject=False))
        stored = manifest_store_path(self.target, PARENT_DIGEST)
        stored.write_bytes(b"not the manifest")
        plan = build_plan(self.config)
        manifest_plan = next(item for item in plan.manifests if item.digest == PARENT_DIGEST)
        self.assertEqual(manifest_plan.action, "repair")
        result = run(plan, policy=TransferPolicy(chunk_bytes=2, inject=False))
        self.assertTrue(result.published)
        self.assertEqual(sha256_file(stored), PARENT_DIGEST)
        self.assertEqual(json.loads(pointer_path(self.target).read_text())["root_manifest_sha256"], ROOT_DIGEST)

    def test_manifest_store_missing_parent_blocks_publish(self) -> None:
        run(build_plan(self.config), policy=TransferPolicy(chunk_bytes=2, inject=False))
        manifest_store_path(self.target, PARENT_DIGEST).unlink()
        verify = verify_target_closure(
            self.target,
            entry_key=ROOT_KEY,
            entry_digest=ROOT_DIGEST,
        )
        self.assertFalse(verify.ok)
        self.assertEqual(verify.errors[0]["code"], "manifest_missing")


class ManifestChainTests(ReplicationTestCase):
    def test_parent_chain_digest_pinning(self) -> None:
        chain = walk_chain(
            self.source / ROOT_KEY, ROOT_KEY, ROOT_DIGEST
        )
        self.assertEqual([m.manifest_id for m in chain.manifests], ["root", "parent"])
        self.assertEqual(len(chain.closure), 1)

    def test_manifest_digest_mismatch_is_blocked(self) -> None:
        with self.assertRaises(Blocked) as caught:
            walk_chain(self.source / ROOT_KEY, ROOT_KEY, "0" * 64)
        self.assertEqual(caught.exception.code, "manifest_digest_mismatch")

    def test_manifest_missing_parent_is_blocked(self) -> None:
        with self.assertRaises(Blocked) as caught:
            walk_chain(
                self.source / ROOT_KEY,
                ROOT_KEY,
                ROOT_DIGEST,
                resolve_parent=lambda parent: self.source / "absent.json",
            )
        self.assertEqual(caught.exception.code, "manifest_missing")

    def test_cycle_through_logical_key_with_changed_digest_rejected(self) -> None:
        # 父摘要在被指清单处被改写：同一逻辑 key 以两个摘要出现，拒绝继续。
        payload = {"manifest_id": "a", "parent": {"key": "b.json", "sha256": "2" * 64}, "objects": []}
        (self.source / "a.json").write_text(json.dumps(payload))
        a_digest = sha((self.source / "a.json").read_bytes())
        cyclic = {"manifest_id": "c", "parent": {"key": "a.json", "sha256": a_digest}, "objects": []}
        (self.source / "c.json").write_text(json.dumps(cyclic))
        c_digest = sha((self.source / "c.json").read_bytes())
        with self.assertRaises(Blocked) as caught:
            walk_chain(
                self.source / "c.json",
                "c.json",
                c_digest,
                resolve_parent=lambda parent: self.source / "c.json",
            )
        self.assertEqual(caught.exception.code, "manifest_cycle")

    def test_cycle_detected_by_physical_path(self) -> None:
        # 两个不同逻辑名解析到同一物理清单：即便无法固定摘要也判定为环。
        (self.source / "alias.json").write_text((self.source / "root.json").read_text())
        root_payload = json.loads((self.source / "root.json").read_text())
        rooted = {"manifest_id": "r", "parent": {"key": "root.json", "sha256": ROOT_DIGEST}, "objects": []}
        (self.source / "r.json").write_text(json.dumps(rooted))
        r_digest = sha((self.source / "r.json").read_bytes())
        with self.assertRaises(Blocked) as caught:
            walk_chain(
                self.source / "r.json",
                "r.json",
                r_digest,
                resolve_parent=lambda parent: self.source / "root.json",
            )
        # 第一跳合法，第二跳父链回到 root.json 自身；root 的父是 parent.json，
        # 用强制解析器让 root 的父回到 root.json 形成物理环。
        with self.assertRaises(Blocked) as caught2:
            walk_chain(
                self.source / "r.json",
                "r.json",
                r_digest,
                resolve_parent=lambda parent: self.source / "r.json",
            )
        self.assertEqual(caught2.exception.code, "manifest_cycle")

    def test_duplicate_object_with_same_digest_is_ok(self) -> None:
        payload = json.loads((self.source / "parent.json").read_text())
        payload["objects"] = [
            {"key": OBJ_KEY, "bytes": 3, "sha256": ABC},
            {"key": OBJ_KEY, "bytes": 3, "sha256": ABC},
        ]
        (self.source / "parent.json").write_text(json.dumps(payload))
        parent_digest = sha((self.source / "parent.json").read_bytes())
        root_payload = json.loads((self.source / "root.json").read_text())
        root_payload["parent"]["sha256"] = parent_digest
        (self.source / "root.json").write_text(json.dumps(root_payload))
        root_digest = sha((self.source / "root.json").read_bytes())
        chain = walk_chain(self.source / ROOT_KEY, ROOT_KEY, root_digest)
        self.assertEqual(len(chain.closure), 1)


class PromotionTests(ReplicationTestCase):
    def test_promote_requires_verified_staged_bytes(self) -> None:
        ref = type("Ref", (), {"key": OBJ_KEY, "sha256": ABC, "bytes": 3})()
        staged_data_path(self.target, ABC).parent.mkdir(parents=True, exist_ok=True)
        staged_data_path(self.target, ABC).write_bytes(b"abd")
        with self.assertRaises(Blocked) as caught:
            promote_object(self.target, ref)
        self.assertEqual(caught.exception.code, "staged_object_corrupt")
        self.assertEqual((self.target / OBJ_KEY).read_bytes(), b"abd", "坏暂存体不得提升")

    def test_target_symlink_is_not_trusted(self) -> None:
        real = self.work / "outside.bin"
        real.write_bytes(b"abc")
        (self.target / OBJ_KEY).unlink()
        os.symlink(real, self.target / OBJ_KEY)
        plan = build_plan(self.config)
        self.assertEqual(plan.objects[0].target_state, "damaged:not_regular_file")
        result = run(plan, policy=TransferPolicy(chunk_bytes=2, inject=False))
        self.assertTrue(result.published)
        self.assertFalse((self.target / OBJ_KEY).is_symlink())
        self.assertEqual((self.target / OBJ_KEY).read_bytes(), b"abc")


class EvidenceTests(ReplicationTestCase):
    def test_evidence_files_written_with_object_level_proof(self) -> None:
        result = run(build_plan(self.config), policy=TransferPolicy(chunk_bytes=2, inject=False))
        self.assertTrue(result.published)
        evidence_dir = self.target / ".replica" / "evidence"
        files = list(evidence_dir.glob("*.json"))
        self.assertEqual(len(files), 2)
        replication = next(p for p in files if p.name.startswith("replication"))
        payload = json.loads(replication.read_text())
        self.assertTrue(payload["closures_verified"])
        self.assertEqual(payload["source_closure_sha256"], payload["target_closure_sha256"])
        self.assertEqual(payload["entry"], {"key": ROOT_KEY, "sha256": ROOT_DIGEST})
        objects = next(p for p in files if p.name.startswith("objects"))
        body = json.loads(objects.read_text())
        self.assertEqual(len(body["transfers"]), 1)
        self.assertEqual(body["objects"][0]["sha256"], ABC)
        self.assertEqual(body["quarantined"][0]["actual_sha256"], ABD)


if __name__ == "__main__":
    unittest.main()
