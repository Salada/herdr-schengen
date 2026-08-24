"""Unit tests for the OpenCode host runtime verification (Phase 4)."""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from schengen_watcher import verify_agy_runtime_environment, verify_host_runtime_environment

_AGY_KEYS = ("ANTIGRAVITY_AGENT", "AI_AGENT", "ANTIGRAVITY_CONVERSATION_ID")


class TestHostRuntimeEnvironment(unittest.TestCase):
    def test_agy_markers_accepted(self):
        with mock.patch.dict(os.environ, {"ANTIGRAVITY_AGENT": "1"}, clear=True):
            verify_host_runtime_environment()  # must not raise

    def test_opencode_marker_accepted(self):
        with mock.patch.dict(os.environ, {"OPENCODE": "1"}, clear=True):
            verify_host_runtime_environment()  # must not raise

    def test_opencode_falsy_value_rejected(self):
        with mock.patch.dict(os.environ, {"OPENCODE": "0"}, clear=True):
            with self.assertRaises(SystemExit):
                verify_host_runtime_environment()

    def test_standalone_rejected(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit):
                verify_host_runtime_environment()

    def test_backward_compat_alias(self):
        self.assertIs(verify_agy_runtime_environment, verify_host_runtime_environment)


class TestStrictParentDieWithParent(unittest.TestCase):
    def test_strict_parent_returns_false_when_parent_dead(self):
        from schengen_watcher import is_parent_alive

        with mock.patch.dict(os.environ, {"SCHENGEN_STRICT_PARENT": "1"}, clear=False):
            with mock.patch("schengen_watcher.os.kill", side_effect=ProcessLookupError()):
                # Parent dead + strict mode -> False (no Herdr fallback).
                self.assertFalse(is_parent_alive(99999))

    def test_parent_alive_returns_true_even_in_strict_mode(self):
        from schengen_watcher import is_parent_alive

        with mock.patch.dict(os.environ, {"SCHENGEN_STRICT_PARENT": "1"}, clear=False):
            with mock.patch("schengen_watcher.os.kill", return_value=None):
                self.assertTrue(is_parent_alive(99999))


if __name__ == "__main__":
    unittest.main()
