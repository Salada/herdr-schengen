"""Unit tests for daemon external kill detection and status synchronization."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import cmd.schengen_watcher as schengen_watcher
from cmd.schengen_watcher import is_process_smartgate_watcher, list_active_guard_locks


class TestDaemonKillSync(unittest.TestCase):
    """Test daemon process verification, stale lock cleanup, and status synchronization."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_dir = Path(self.tmp_dir.name)
        self.orig_db_dir = schengen_watcher.DB_DIR
        schengen_watcher.DB_DIR = self.db_dir

    def tearDown(self):
        schengen_watcher.DB_DIR = self.orig_db_dir
        self.tmp_dir.cleanup()

    def test_stale_lock_cleanup_on_dead_pid(self):
        """Verify lockfile with a non-existent PID is automatically deleted."""
        lock_file = self.db_dir / "schengen_auto.lock"
        # 999999 is definitely not running
        lock_file.write_text("999999\n")

        active = list_active_guard_locks()
        self.assertEqual(active, [])
        self.assertFalse(lock_file.exists())

    @patch("cmd.schengen_watcher.is_process_smartgate_watcher")
    def test_active_lock_preserved_for_live_daemon(self, mock_is_watcher):
        """Verify lockfile for a genuine running watcher daemon is preserved."""
        mock_is_watcher.return_value = True
        lock_file = self.db_dir / "schengen_auto.lock"
        current_pid = os.getpid()
        lock_file.write_text(f"{current_pid}\n")

        active = list_active_guard_locks()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0][0], "auto")
        self.assertEqual(active[0][2], current_pid)
        self.assertTrue(lock_file.exists())

    @patch("subprocess.run")
    def test_recycled_pid_for_other_app_cleaned_up(self, mock_ps):
        """Verify if PID exists but belongs to an unrelated app (e.g. bash), it is cleaned up."""
        mock_ps.return_value = MagicMock(returncode=0, stdout="/bin/bash -i\n")
        current_pid = os.getpid()
        is_watcher = is_process_smartgate_watcher(current_pid)
        self.assertFalse(is_watcher)

    @patch("subprocess.run")
    def test_genuine_watcher_process_recognized(self, mock_ps):
        """Verify python invocation running schengen_watcher is recognized."""
        mock_ps.return_value = MagicMock(
            returncode=0,
            stdout="python3 /Users/kyjbusan/code/herdr-schengen/scripts/cmd/schengen_watcher.py --target auto\n",
        )
        current_pid = os.getpid()
        is_watcher = is_process_smartgate_watcher(current_pid)
        self.assertTrue(is_watcher)


if __name__ == "__main__":
    unittest.main()
