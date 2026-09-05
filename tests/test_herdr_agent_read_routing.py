#!/usr/bin/env python3
"""Agent-thread context routing with terminal-buffer fallback."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from adapters.herdr_client import get_agent_or_pane_text


def _agent_info(status="working", session_value="session-1"):
    return {
        "pane_id": "w1D:p1",
        "agent_status": status,
        "agent_session": {"kind": "id", "value": session_value},
    }


class TestAgentThreadReadRouting(unittest.TestCase):
    def test_live_agent_statuses_use_agent_thread(self):
        for status in ("working", "idle", "done", "blocked", " BLOCKED "):
            with self.subTest(status=status):
                with patch("adapters.herdr_client.get_pane_info", return_value=_agent_info(status)), patch(
                    "adapters.herdr_client.run_cmd", return_value="agent thread\n"
                ) as run, patch("adapters.herdr_client.get_pane_text") as pane_read:
                    text, source = get_agent_or_pane_text("w1D:p1", lines=42)

                self.assertEqual(text, "agent thread\n")
                self.assertEqual(source, "agent:recent-unwrapped")
                run.assert_called_once_with(
                    [
                        "herdr",
                        "agent",
                        "read",
                        "w1D:p1",
                        "--source",
                        "recent-unwrapped",
                        "--lines",
                        "42",
                    ]
                )
                pane_read.assert_not_called()

    def test_missing_or_unrecognized_agent_metadata_uses_pane(self):
        cases = (
            None,
            _agent_info("unknown"),
            _agent_info("exited"),
            _agent_info(""),
            _agent_info("working", ""),
            {"pane_id": "w1D:p1", "agent_status": "working", "agent_session": "bad-schema"},
        )
        for pane_info in cases:
            with self.subTest(pane_info=pane_info):
                with patch("adapters.herdr_client.get_pane_info", return_value=pane_info), patch(
                    "adapters.herdr_client.run_cmd"
                ) as agent_read, patch(
                    "adapters.herdr_client.get_pane_text", return_value="raw pane"
                ) as pane_read:
                    text, source = get_agent_or_pane_text("w1D:p1", lines=80)

                self.assertEqual((text, source), ("raw pane", "pane:visible"))
                agent_read.assert_not_called()
                pane_read.assert_called_once_with(
                    "w1D:p1", lines=80, full_dump=False, source=None
                )

    def test_empty_or_failed_agent_read_falls_back_to_pane(self):
        for agent_output in (None, "", " \n\t"):
            with self.subTest(agent_output=agent_output):
                with patch("adapters.herdr_client.get_pane_info", return_value=_agent_info()), patch(
                    "adapters.herdr_client.run_cmd", return_value=agent_output
                ) as agent_read, patch(
                    "adapters.herdr_client.get_pane_text", return_value="fallback pane"
                ) as pane_read:
                    text, source = get_agent_or_pane_text("w1D:p1", lines=80)

                self.assertEqual((text, source), ("fallback pane", "pane:visible"))
                agent_read.assert_called_once()
                pane_read.assert_called_once_with(
                    "w1D:p1", lines=80, full_dump=False, source=None
                )

    def test_full_dump_bypasses_agent_and_reports_scrollback(self):
        with patch("adapters.herdr_client.get_pane_info") as pane_info, patch(
            "adapters.herdr_client.get_pane_text", return_value="full pane dump"
        ) as pane_read:
            text, source = get_agent_or_pane_text("w1D:p1", lines=500, full_dump=True)

        self.assertEqual((text, source), ("full pane dump", "pane:scrollback"))
        pane_info.assert_not_called()
        pane_read.assert_called_once_with(
            "w1D:p1", lines=500, full_dump=True, source=None
        )

    def test_explicit_source_bypasses_agent_and_reports_exact_source(self):
        with patch("adapters.herdr_client.get_pane_info") as pane_info, patch(
            "adapters.herdr_client.get_pane_text", return_value="canonical pane"
        ) as pane_read:
            text, source = get_agent_or_pane_text(
                "w1D:p1", lines=80, source="recent-unwrapped"
            )

        self.assertEqual((text, source), ("canonical pane", "pane:recent-unwrapped"))
        pane_info.assert_not_called()
        pane_read.assert_called_once_with(
            "w1D:p1", lines=80, full_dump=False, source="recent-unwrapped"
        )

    def test_large_line_fallback_reports_actual_scrollback_source(self):
        with patch("adapters.herdr_client.get_pane_info", return_value=None), patch(
            "adapters.herdr_client.get_pane_text", return_value="raw history"
        ):
            text, source = get_agent_or_pane_text("w1D:p1", lines=101)

        self.assertEqual((text, source), ("raw history", "pane:scrollback"))


if __name__ == "__main__":
    unittest.main()
