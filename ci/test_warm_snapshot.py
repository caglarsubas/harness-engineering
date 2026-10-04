from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

LOCKER_PATH = Path(__file__).with_name("lock_warm_snapshot.py")
SPEC = importlib.util.spec_from_file_location("warm_snapshot_locker", LOCKER_PATH)
assert SPEC and SPEC.loader
LOCKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LOCKER
SPEC.loader.exec_module(LOCKER)


def git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        text=True,
        capture_output=True,
        shell=False,
        check=True,
    )
    return completed.stdout.strip()


class WarmSnapshotTest(unittest.TestCase):
    def test_git_environment_scrubs_credentials_and_alternates(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "EXAMPLE_API_KEY": "must-not-pass",
                "GITHUB_TOKEN": "must-not-pass",
                "SSH_AUTH_SOCK": "/private/tmp/agent.sock",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/private/tmp/objects",
                "SAFE_SETTING": "preserved",
            },
            clear=True,
        ):
            environment = LOCKER.git_environment()
        self.assertNotIn("SAFE_SETTING", environment)
        self.assertEqual("1", environment["GIT_NO_LAZY_FETCH"])
        self.assertEqual("0", environment["GIT_OPTIONAL_LOCKS"])
        self.assertEqual("0", environment["GIT_TERMINAL_PROMPT"])
        self.assertNotIn("EXAMPLE_API_KEY", environment)
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertNotIn("SSH_AUTH_SOCK", environment)
        self.assertNotIn("GIT_ALTERNATE_OBJECT_DIRECTORIES", environment)

    def test_rejects_actual_missing_promised_blob(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "snapshot"
            snapshot.mkdir()
            git(snapshot, "init", "--initial-branch=main")
            git(snapshot, "config", "user.name", "Fixture")
            git(snapshot, "config", "user.email", "fixture@example.invalid")
            tracked = snapshot / "tracked.txt"
            tracked.write_text("promised then absent\n", encoding="utf-8")
            git(snapshot, "add", "tracked.txt")
            git(snapshot, "commit", "-m", "fixture")
            blob_object = git(snapshot, "rev-parse", "HEAD:tracked.txt")
            git(snapshot, "config", "extensions.partialClone", "origin")
            git(snapshot, "config", "remote.origin.promisor", "true")
            git(snapshot, "config", "remote.origin.partialclonefilter", "blob:none")
            loose_object = snapshot / ".git/objects" / blob_object[:2] / blob_object[2:]
            self.assertTrue(loose_object.is_file())
            loose_object.unlink()

            with self.assertRaisesRegex(
                LOCKER.SnapshotError,
                "missing or has the wrong kind",
            ):
                LOCKER.verify_local_objects(
                    snapshot,
                    [{"path": "tracked.txt", "kind": "blob", "gitObject": blob_object}],
                )

    def test_rejects_promised_or_missing_object_response(self) -> None:
        object_id = "1" * 40
        entries = [{"path": "missing.txt", "kind": "blob", "gitObject": object_id}]
        with mock.patch.object(
            LOCKER,
            "run_git",
            return_value=f"{object_id} missing\n",
        ), self.assertRaisesRegex(
            LOCKER.SnapshotError,
            "missing or has the wrong kind",
        ):
            LOCKER.verify_local_objects(Path("/unused"), entries)

    def test_rejects_local_object_with_wrong_kind(self) -> None:
        object_id = "2" * 40
        entries = [{"path": "data.txt", "kind": "blob", "gitObject": object_id}]
        with mock.patch.object(
            LOCKER,
            "run_git",
            return_value=f"{object_id} tree\n",
        ), self.assertRaisesRegex(
            LOCKER.SnapshotError,
            "missing or has the wrong kind",
        ):
            LOCKER.verify_local_objects(Path("/unused"), entries)

    def test_locks_exact_detached_inventory_and_disables_remotes(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="met-002-observer.",
            # macOS keeps the historical /private/tmp parent; Linux has only /tmp.
            dir="/private/tmp" if os.path.isdir("/private/tmp") else "/tmp",
        ) as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            git(snapshot, "init", "--initial-branch=main")
            git(snapshot, "config", "user.name", "Fixture")
            git(snapshot, "config", "user.email", "fixture@example.invalid")
            (snapshot / "fixtures").mkdir()
            (snapshot / "fixtures/data.txt").write_text("fixed\n", encoding="utf-8")
            git(snapshot, "add", "fixtures/data.txt")
            git(snapshot, "commit", "-m", "fixture")
            commit = git(snapshot, "rev-parse", "HEAD")
            tree_object = git(snapshot, "rev-parse", f"{commit}:fixtures")
            blob_object = git(snapshot, "rev-parse", f"{commit}:fixtures/data.txt")
            git(snapshot, "remote", "add", "origin", "https://example.invalid/source.git")
            git(snapshot, "checkout", "--detach", commit)

            authority_root = root / "authority"
            (authority_root / "architecture").mkdir(parents=True)
            repository = "git@github.com:caglarsubas/llm_inference_engine.git"
            index = {
                "sources": [
                    {
                        "repository": repository,
                        "commit": commit,
                        "paths": [
                            {"path": "fixtures/", "kind": "tree", "gitObject": tree_object},
                            {"path": "fixtures/data.txt", "kind": "blob", "gitObject": blob_object},
                        ],
                    }
                ]
            }
            (authority_root / "architecture/reuse-path-index.yaml").write_text(
                yaml.safe_dump(index), encoding="utf-8"
            )
            original_root = LOCKER.ROOT
            LOCKER.ROOT = authority_root
            try:
                indexed_commit, entries = LOCKER.load_index(repository)
                LOCKER.verify_snapshot(
                    snapshot,
                    repository,
                    indexed_commit,
                    entries,
                    require_locked=False,
                )
                LOCKER.run_git(
                    snapshot,
                    ["remote", "set-url", "origin", LOCKER.NO_FETCH_REMOTE],
                )
                LOCKER.run_git(
                    snapshot,
                    ["remote", "set-url", "--push", "origin", LOCKER.NO_PUSH_REMOTE],
                )
                LOCKER.remove_write_bits(snapshot)
                evidence = LOCKER.verify_snapshot(
                    snapshot,
                    repository,
                    indexed_commit,
                    entries,
                    require_locked=True,
                )
                self.assertTrue(evidence["objectsLocal"])
                self.assertTrue(evidence["objectAlternatesDisabled"])
                self.assertTrue(evidence["ambientCredentialsScrubbed"])
                self.assertTrue(evidence["writeBitsRemoved"])
                self.assertEqual(2, evidence["indexedPathCount"])
            finally:
                LOCKER.ROOT = original_root
                for path in [snapshot, *snapshot.rglob("*")]:
                    if not path.is_symlink():
                        os.chmod(path, stat.S_IMODE(path.stat().st_mode) | 0o700)


if __name__ == "__main__":
    unittest.main()
