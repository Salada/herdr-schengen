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


def _clear_agent_markers():
    for k in _AGY_KEYS:
        os.environ.pop(k, None)
    os.environ.pop("OPENCODE", None)


class TestHostRuntimeEnvironment(unittest.TestCase):
    def test_agy_markers_accepted(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            _clear_agent_markers()
            os.environ["ANTIGRAVITY_AGENT"] = "1"
            verify_host_runtime_environment()  # must not raise

    def test_opencode_marker_accepted(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            _clear_agent_markers()
            os.environ["OPENCODE"] = "1"
            verify_host_runtime_environment()  # must not raise

    def test_standalone_rejected(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            _clear_agent_markers()
            with self.assertRaises(SystemExit):
                verify_host_runtime_environment()

    def test_backward_compat_alias(self):
        self.assertIs(verify_agy_runtime_environment, verify_host_runtime_environment)


if __name__ == "__main__":
    unittest.main()
