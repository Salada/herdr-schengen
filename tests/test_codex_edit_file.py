"""Codex edit_file evaluator tests (#7759, INV-EF-1..3).

The evaluator's edit_file/create_file block now collects ALL newline-delimited
paths and validates EACH against the denylist (all-or-nothing, INV-EF-2):
6. single-file safe regression (INV-EF-3 parity).
7. multi-file all-safe -> FAST_TRACK_AST.
8. multi-file with ONE sensitive path -> SECRET_GUARD fail-closed.
9. multi-file with ONE T4 path -> GRAY_ZONE_MATRIX fail-closed.
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import core.guard_db as guard_db
from core.security_evaluator import DecisionLayer, audit_shell_command


class TestCodexEditFileEvaluator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_single_file_safe_regression(self):
        safe, reason, layer = audit_shell_command("edit_file /tmp/a.py")
        self.assertTrue(safe, reason)
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_multi_file_all_safe_fast_tracks(self):
        safe, reason, layer = audit_shell_command("edit_file /tmp/a.py\n/tmp/b.py")
        self.assertTrue(safe, reason)
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_multi_file_one_sensitive_fails_closed(self):
        # One sensitive path among safe ones -> SECRET_GUARD, all-or-nothing.
        sensitive = "/tmp/x/id_" + "rsa"
        safe, reason, layer = audit_shell_command(f"edit_file /tmp/ok.txt\n{sensitive}")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SECRET_GUARD)

    def test_multi_file_one_t4_fails_closed(self):
        # One T4 path among safe ones -> GRAY_ZONE_MATRIX, all-or-nothing.
        safe, reason, layer = audit_shell_command("edit_file /tmp/ok.txt\n/etc/passwd")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.GRAY_ZONE_MATRIX)

    def test_edit_file_with_no_paths_fail_closed(self):
        # Bare edit_file (no path) -> NOT_ALLOWLISTED (INV-EF-1).
        safe, reason, layer = audit_shell_command("edit_file")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.NOT_ALLOWLISTED)


if __name__ == "__main__":
    unittest.main()
