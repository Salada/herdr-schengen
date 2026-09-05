#!/usr/bin/env python3
"""Crash recovery and single-writer tests for the runtime installer."""

import fcntl
import json
import sys
import tempfile
import unittest
import warnings
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import cmd.schengen_install as schengen_install


class TestInstallerCrashRecovery(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        self.source = self.root / "source"
        self.target = self.root / "runtime" / "herdr-schengen"
        payload = self.source / "scripts/payload.py"
        payload.parent.mkdir(parents=True)
        payload.write_text("current\n", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    @contextmanager
    def installer(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(schengen_install, "REPO_ROOT", self.source))
            stack.enter_context(
                patch.object(schengen_install, "CANONICAL_TARGETS", frozenset({self.target.absolute()}))
            )
            stack.enter_context(patch.object(schengen_install, "source_is_clean", return_value=True))
            stack.enter_context(
                patch.object(schengen_install, "tracked_files", return_value=(Path("scripts/payload.py"),))
            )
            stack.enter_context(patch.object(schengen_install, "source_revision", return_value="current-revision"))
            yield

    def write_install(self, root: Path, revision: str = "old-revision") -> None:
        root.mkdir(parents=True)
        (root / schengen_install.PROVENANCE_FILE).write_text(
            json.dumps({"revision": revision}), encoding="utf-8"
        )

    def backup(self, suffix: str = "0" * 32) -> Path:
        return self.target.parent / f".{self.target.name}.backup-{suffix}"

    def stage(self, name: str = ".herdr-schengen.stage") -> Path:
        return self.target.parent / name

    def test_missing_target_restores_backup_before_install(self):
        backup = self.backup()
        self.write_install(backup)
        sentinel = backup / "unmanaged.txt"
        sentinel.write_text("keep", encoding="utf-8")
        self.stage().mkdir()

        with self.installer():
            manifest = schengen_install.install(self.target)

        self.assertEqual(manifest["revision"], "current-revision")
        self.assertEqual((self.target / "unmanaged.txt").read_text(encoding="utf-8"), "keep")
        self.assertFalse(backup.exists())
        self.assertFalse(self.stage().exists())

    def test_activated_target_discards_single_backup_only_after_validation(self):
        self.write_install(self.target, "new-revision")
        backup = self.backup()
        self.write_install(backup)

        with self.installer():
            schengen_install.install(self.target)

        self.assertFalse(backup.exists())
        self.assertEqual(
            json.loads((self.target / schengen_install.PROVENANCE_FILE).read_text())["revision"],
            "current-revision",
        )

    def test_any_number_of_valid_stages_is_purged_under_lock(self):
        self.write_install(self.target)
        fixed = self.stage()
        fixed.mkdir()
        legacy = Path(tempfile.mkdtemp(prefix=".herdr-schengen.stage-", dir=self.target.parent))

        with self.installer():
            schengen_install.install(self.target)

        self.assertFalse(fixed.exists())
        self.assertFalse(legacy.exists())

    def test_multiple_backups_fail_closed_without_deletion(self):
        backups = (self.backup("0" * 32), self.backup("1" * 32))
        for backup in backups:
            self.write_install(backup)

        with self.installer(), self.assertRaisesRegex(ValueError, "multiple backup"):
            schengen_install.install(self.target)

        self.assertTrue(all(path.exists() for path in backups))
        self.assertFalse(self.target.exists())

    def test_invalid_backup_provenance_is_preserved(self):
        backup = self.backup()
        backup.mkdir(parents=True)

        with self.installer(), self.assertRaisesRegex(ValueError, "backup provenance"):
            schengen_install.install(self.target)

        self.assertTrue(backup.exists())
        self.assertFalse(self.target.exists())

    def test_invalid_target_provenance_preserves_backup(self):
        self.target.mkdir(parents=True)
        backup = self.backup()
        self.write_install(backup)

        with self.installer(), self.assertRaisesRegex(ValueError, "target provenance"):
            schengen_install.install(self.target)

        self.assertTrue(self.target.exists())
        self.assertTrue(backup.exists())

    def test_symlinked_stage_fails_closed_without_following(self):
        outside = self.root / "outside"
        outside.mkdir()
        marker = outside / "marker"
        marker.write_text("safe", encoding="utf-8")
        self.target.parent.mkdir(parents=True)
        self.stage().symlink_to(outside, target_is_directory=True)

        with self.installer(), self.assertRaisesRegex(ValueError, "untrusted installer artifact"):
            schengen_install.install(self.target)

        self.assertEqual(marker.read_text(encoding="utf-8"), "safe")
        self.assertTrue(self.stage().is_symlink())

    def test_near_miss_stage_is_warned_and_preserved(self):
        self.target.parent.mkdir(parents=True)
        near_miss = self.stage(".herdr-schengen.stage-not-the-emitted-shape")
        near_miss.mkdir()

        with self.installer(), warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            schengen_install.install(self.target)

        self.assertTrue(near_miss.exists())
        self.assertTrue(any("unrecognized stage-like" in str(item.message) for item in caught))

    def test_concurrent_installer_fails_without_mutating_target(self):
        self.write_install(self.target)
        sentinel = self.target / "sentinel"
        sentinel.write_text("old", encoding="utf-8")
        lock_path = self.target.parent / f".{self.target.name}.install.lock"
        with lock_path.open("a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.installer(), self.assertRaisesRegex(RuntimeError, "installer lock held"):
                schengen_install.install(self.target)

        self.assertEqual(sentinel.read_text(encoding="utf-8"), "old")
        self.assertFalse(self.stage().exists())


if __name__ == "__main__":
    unittest.main()
