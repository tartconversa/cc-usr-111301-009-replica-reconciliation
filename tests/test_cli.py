"""命令行与 fixtures 级契约测试。"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


def run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "src.replication", *args],
        cwd=cwd or ROOT,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(ROOT), "PATH": "/usr/local/bin:/usr/bin:/bin"},
    )


class FixtureContractTests(unittest.TestCase):
    def test_fixture_inventory_matches_bytes(self) -> None:
        import hashlib

        for item in json.loads((ROOT / "material-index.json").read_text()):
            with self.subTest(path=item["path"]):
                data = (ROOT / item["path"]).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), item["sha256"])
                self.assertEqual(len(data), item["size_bytes"])

    def test_plan_cli_is_read_only_on_real_fixtures(self) -> None:
        before = self._tree(FIXTURES)
        completed = run_cli("plan", "fixtures/replication.json")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["publishable"])
        self.assertEqual(payload["transfer_budget"], {"chunk_bytes": 2, "referenced_objects": 1, "unique_payloads": 1})
        self.assertEqual(payload["objects"][0]["action"], "repair")
        self.assertEqual(payload["objects"][0]["target_actual_sha256"], "a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9")
        self.assertEqual(self._tree(FIXTURES), before, "plan 命令不得改动 fixtures")

    def test_cli_repair_resume_verify_reader_cycle(self) -> None:
        with tempfile.TemporaryDirectory(prefix="replica-cli-") as directory:
            work = Path(directory)
            shutil.copytree(FIXTURES / "source", work / "source")
            shutil.copytree(FIXTURES / "target", work / "target")
            config_path = work / "replication.json"
            config = json.loads((FIXTURES / "replication.json").read_text())
            config_path.write_text(json.dumps(config))

            first = run_cli("repair", str(config_path))
            self.assertEqual(first.returncode, 2, first.stdout + first.stderr)
            body = json.loads(first.stdout)
            self.assertFalse(body["published"])
            self.assertEqual(body["interrupted"]["kind"], "interrupted")

            second = run_cli("resume", str(config_path))
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            evidence = json.loads(second.stdout)
            self.assertTrue(evidence["closures_verified"])
            self.assertEqual(evidence["transfers"][0]["resumed_from_byte"], 2)
            self.assertEqual(evidence["source_closure_sha256"], evidence["target_closure_sha256"])

            verify = run_cli("verify", str(config_path))
            self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
            self.assertTrue(json.loads(verify.stdout)["ok"])

            reader = run_cli("reader", str(config_path))
            self.assertEqual(reader.returncode, 0, reader.stdout + reader.stderr)
            self.assertTrue(json.loads(reader.stdout)["readable"])

            visible = (work / "target" / "objects" / ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")).read_bytes()
            self.assertEqual(visible, b"abc")

    def test_demo_subcommand_completes(self) -> None:
        completed = run_cli("demo")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        stages = [json.loads(line) for line in completed.stdout.strip().splitlines()]
        by_stage = {item["stage"]: item for item in stages}
        self.assertTrue(by_stage["plan"]["readonly"])
        self.assertFalse(by_stage["interrupted"]["published"])
        self.assertTrue(by_stage["resumed"]["evidence"]["published"])

    @staticmethod
    def _tree(root: Path) -> dict[str, str]:
        import hashlib

        return {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }


if __name__ == "__main__":
    unittest.main()
