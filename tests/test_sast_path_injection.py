"""SAST PATH injection tests (issue #45).

Verifies `_inject_runtime_path` prepends existing host binary dirs to PATH
(so shellcheck/semgrep become discoverable), is idempotent, and never adds
non-existent dirs.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from cmd.schengen_watcher import _inject_runtime_path


class TestSastPathInjection(unittest.TestCase):
    def test_prepends_existing_dir_to_front(self):
        fake_dir = "/fake/opt/homebrew/bin"
        with patch.object(
            sys.modules["cmd.schengen_watcher"], "_RUNTIME_BIN_DIRS", (fake_dir,)
        ), patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}, clear=False), patch(
            "os.path.isdir", side_effect=lambda p: p == fake_dir
        ):
            _inject_runtime_path()
            self.assertTrue(
                os.environ["PATH"].startswith(f"{fake_dir}{os.pathsep}"),
                f"Expected {fake_dir} at FRONT of PATH, got: {os.environ['PATH']!r}",
            )
            self.assertIn(fake_dir, os.environ["PATH"])
            self.assertIn("/usr/bin", os.environ["PATH"])

    def test_idempotent_no_duplicate(self):
        fake_dir = "/fake/opt/homebrew/bin"
        with patch.object(
            sys.modules["cmd.schengen_watcher"], "_RUNTIME_BIN_DIRS", (fake_dir,)
        ), patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}, clear=False), patch(
            "os.path.isdir", side_effect=lambda p: p == fake_dir
        ):
            _inject_runtime_path()
            _inject_runtime_path()
            self.assertEqual(os.environ["PATH"].count(fake_dir), 1, os.environ["PATH"])

    def test_already_in_path_not_duplicated(self):
        fake_dir = "/fake/opt/homebrew/bin"
        with patch.object(
            sys.modules["cmd.schengen_watcher"], "_RUNTIME_BIN_DIRS", (fake_dir,)
        ), patch.dict(os.environ, {"PATH": f"/usr/bin:{fake_dir}:/bin"}, clear=False), patch(
            "os.path.isdir", return_value=True
        ):
            _inject_runtime_path()
            self.assertEqual(os.environ["PATH"].count(fake_dir), 1, os.environ["PATH"])

    def test_non_existent_dir_not_added(self):
        fake_dir = "/nonexistent/dir/bin"
        with patch.object(
            sys.modules["cmd.schengen_watcher"], "_RUNTIME_BIN_DIRS", (fake_dir,)
        ), patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}, clear=False), patch(
            "os.path.isdir", return_value=False
        ):
            _inject_runtime_path()
            self.assertNotIn(fake_dir, os.environ["PATH"])
            self.assertEqual(os.environ["PATH"], "/usr/bin:/bin")


if __name__ == "__main__":
    unittest.main()
