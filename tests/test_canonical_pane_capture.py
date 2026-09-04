"""Canonical pane capture prefers Herdr's soft-wrap-aware read source."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from adapters.agent_adapters.agy import AgyAdapter
from adapters.agent_adapters.base import AgentAdapter
from adapters.agent_adapters.codex import CodexAdapter
from adapters.herdr_client import get_pane_text


class _EchoAdapter(AgentAdapter):
    def parse_permission_request(self, text):
        return text.removeprefix("CMD:").strip() if text.startswith("CMD:") else None

    def dialog_is_live(self, text):
        return text.startswith("CMD:")


class TestCanonicalPaneCapture(unittest.TestCase):
    def test_explicit_unwrapped_source_reaches_herdr(self):
        with patch("adapters.herdr_client.run_cmd", return_value="CMD: git status") as run:
            self.assertEqual(
                get_pane_text("w1D:p1", source="recent-unwrapped"),
                "CMD: git status",
            )
        run.assert_called_once_with(
            ["herdr", "pane", "read", "w1D:p1", "--source", "recent-unwrapped", "--lines", "80"]
        )

    def test_canonical_request_prefers_unwrapped_text(self):
        adapter = _EchoAdapter()
        with patch(
            "adapters.agent_adapters.base.get_pane_text",
            return_value="CMD: git status && rm -rf /tmp/example",
        ) as read:
            request, source = adapter.get_canonical_request(
                "w1D:p1", "CMD: git status && rm -rf\n/tmp/example"
            )
        self.assertEqual(request, "git status && rm -rf /tmp/example")
        self.assertEqual(source, "recent-unwrapped")
        read.assert_called_once_with("w1D:p1", lines=80, source="recent-unwrapped")

    def test_empty_unwrapped_read_falls_back_to_visible(self):
        adapter = _EchoAdapter()
        with patch("adapters.agent_adapters.base.get_pane_text", return_value=""):
            request, source = adapter.get_canonical_request("w1D:p1", "CMD: git status")
        self.assertEqual(request, "git status")
        self.assertEqual(source, "visible-fallback")

    def test_stale_recent_text_cannot_resurrect_a_cleared_dialog(self):
        adapter = _EchoAdapter()
        with patch(
            "adapters.agent_adapters.base.get_pane_text",
            return_value="CMD: stale command",
        ) as read:
            request, source = adapter.get_canonical_request("w1D:p1", "command finished")
        self.assertIsNone(request)
        self.assertEqual(source, "visible")
        read.assert_not_called()

    def test_live_but_unparsed_visible_dialog_does_not_trust_recent_text(self):
        adapter = _EchoAdapter()
        with patch(
            "adapters.agent_adapters.base.get_pane_text",
            return_value="CMD: stale command",
        ) as read:
            request, source = adapter.get_canonical_request("w1D:p1", "CMD:")
        self.assertIsNone(request)
        self.assertEqual(source, "visible-unparsed")
        read.assert_not_called()

    def test_agy_stale_recent_dialog_cannot_override_live_command(self):
        adapter = AgyAdapter()
        visible = "Requesting permission for:\nrm -rf /home/user/important\nDo you want to proceed?"
        recent = "Requesting permission for:\necho hello\nDo you want to proceed?\n" + visible
        with patch("adapters.agent_adapters.base.get_pane_text", return_value=recent):
            request, source = adapter.get_canonical_request("w1D:p1", visible)
        self.assertEqual(request, "rm -rf /home/user/important")
        self.assertEqual(source, "visible-mismatch")

    def test_codex_stale_recent_dialog_cannot_override_live_command(self):
        adapter = CodexAdapter()
        footer = "\n› 1. Yes, proceed\nPress enter to confirm or esc to cancel"
        visible = "Would you like to run the following command?\n$ rm -rf /home/user/important" + footer
        recent = "Would you like to run the following command?\n$ echo hello" + footer + "\n" + visible
        with patch("adapters.agent_adapters.base.get_pane_text", return_value=recent):
            request, source = adapter.get_canonical_request("w1D:p1", visible)
        self.assertEqual(request, "rm -rf /home/user/important")
        self.assertEqual(source, "visible-mismatch")


if __name__ == "__main__":
    unittest.main()
