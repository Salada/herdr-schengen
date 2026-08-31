"""SAST PATH injection tests (issue #45).

Verifies `_inject_runtime_path` prepends existing host binary dirs to PATH
(so shellcheck/semgrep become discoverable), is idempotent, never adds
non-existent dirs, and preserves highest-priority-first ordering
(/opt/homebrew/bin > /usr/local/bin > ~/.local/bin) rather than letting the
LAST tuple entry shadow Homebrew binaries. Also covers the platform guard on
`_RUNTIME_BIN_DIRS` and the empty-vs-"." PATH entry behavior.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from cmd.schengen_watcher import _RUNTIME_BIN_DIRS, _inject_runtime_path


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

    # ---- issue #45.1: highest-priority-first prepend order -----------------

    def test_prepend_order_homebrew_before_usrlocal_before_local(self):
        # All three dirs exist: the FIRST tuple entry (/opt/homebrew/bin) must
        # end up FIRST, then /usr/local/bin, then ~/.local/bin — the reverse
        # iteration fix prevents ~/.local/bin from shadowing Homebrew.
        dirs = ("/fake/opt/homebrew/bin", "/fake/usr/local/bin", "/fake/.local/bin")
        with patch.object(
            sys.modules["cmd.schengen_watcher"], "_RUNTIME_BIN_DIRS", dirs
        ), patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}, clear=False), patch(
            "os.path.isdir", return_value=True
        ):
            _inject_runtime_path()
            self.assertEqual(
                os.environ["PATH"],
                os.pathsep.join([*dirs, "/usr/bin", "/bin"]),
                f"Expected {dirs[0]} > {dirs[1]} > {dirs[2]}, got: {os.environ['PATH']!r}",
            )

    # ---- issue #45.2: empty entries dropped, "." kept ----------------------

    def test_empty_path_entries_dropped_dot_kept(self):
        # Consecutive colons / leading & trailing colons are empty entries and
        # are dropped; a literal "." is an explicit current-directory marker
        # with real PATH semantics and MUST be preserved (documented behavior).
        with patch.object(
            sys.modules["cmd.schengen_watcher"], "_RUNTIME_BIN_DIRS", ()
        ), patch.dict(os.environ, {"PATH": ":/usr/bin::/bin:.:"}, clear=False), patch(
            "os.path.isdir", return_value=False
        ):
            _inject_runtime_path()
            self.assertEqual(os.environ["PATH"], "/usr/bin:/bin:.")

    # ---- issue #45.3: platform guard on _RUNTIME_BIN_DIRS ------------------

    def test_runtime_bin_dirs_platform_guard(self):
        # macOS keeps the historical set; Linux gains the Linuxbrew path.
        if sys.platform.startswith("linux"):
            self.assertEqual(_RUNTIME_BIN_DIRS[0], "/home/linuxbrew/.linuxbrew/bin")
            self.assertIn("/usr/local/bin", _RUNTIME_BIN_DIRS)
        else:
            self.assertEqual(_RUNTIME_BIN_DIRS[0], "/opt/homebrew/bin")
            self.assertIn("/usr/local/bin", _RUNTIME_BIN_DIRS)
            self.assertIn(os.path.expanduser("~/.local/bin"), _RUNTIME_BIN_DIRS)
            self.assertNotIn("/home/linuxbrew/.linuxbrew/bin", _RUNTIME_BIN_DIRS)


if __name__ == "__main__":
    unittest.main()
