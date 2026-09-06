#!/usr/bin/env python3
"""Bounded Herdr CLI calls and fail-closed adapter delivery."""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from adapters.agent_adapters.agy import AgyAdapter
from adapters.agent_adapters.codex import CodexAdapter
from adapters.herdr_client import (
    DEFAULT_HERDR_TIMEOUT_SECONDS,
    get_agent_or_pane_text,
    get_all_panes,
    run_cmd,
)


def _completed(stdout=""):
    return subprocess.CompletedProcess(["herdr"], 0, stdout=stdout, stderr="")


class TestHerdrClientTimeouts(unittest.TestCase):
    def test_run_cmd_uses_bounded_default_and_returns_stdout(self):
        with patch("adapters.herdr_client.subprocess.run", return_value=_completed("ok\n")) as run:
            self.assertEqual(run_cmd(["herdr", "agent", "list"]), "ok\n")

        run.assert_called_once_with(
            ["herdr", "agent", "list"],
            capture_output=True,
            text=True,
            check=True,
            timeout=DEFAULT_HERDR_TIMEOUT_SECONDS,
        )

    def test_run_cmd_passes_custom_timeout_and_none_opt_out(self):
        for timeout in (12.0, None):
            with self.subTest(timeout=timeout), patch(
                "adapters.herdr_client.subprocess.run", return_value=_completed()
            ) as run:
                run_cmd(["herdr", "agent", "wait"], timeout=timeout)
                self.assertEqual(run.call_args.kwargs["timeout"], timeout)

    def test_run_cmd_maps_cli_failure_and_timeout_to_none(self):
        failures = (
            subprocess.CalledProcessError(1, ["herdr"]),
            subprocess.TimeoutExpired(["herdr"], DEFAULT_HERDR_TIMEOUT_SECONDS),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), patch(
                "adapters.herdr_client.subprocess.run", side_effect=failure
            ):
                self.assertIsNone(run_cmd(["herdr", "agent", "list"]))

    def test_run_cmd_keeps_missing_binary_loud(self):
        with patch(
            "adapters.herdr_client.subprocess.run",
            side_effect=FileNotFoundError("herdr missing"),
        ):
            with self.assertRaisesRegex(FileNotFoundError, "herdr missing"):
                run_cmd(["herdr", "agent", "list"])

    def test_agent_list_timeout_falls_back_to_pane_list(self):
        panes = {"result": {"panes": [{"pane_id": "w1D:p1"}]}}
        with patch(
            "adapters.herdr_client.subprocess.run",
            side_effect=[
                subprocess.TimeoutExpired(["herdr", "agent", "list"], 5.0),
                _completed(json.dumps(panes)),
            ],
        ):
            self.assertEqual(get_all_panes(), panes["result"]["panes"])

    def test_agent_read_timeout_falls_back_to_pane_read(self):
        agents = {
            "result": {
                "agents": [{
                    "pane_id": "w1D:p1",
                    "agent_status": "working",
                    "agent_session": {"kind": "id", "value": "session-1"},
                }]
            }
        }
        with patch(
            "adapters.herdr_client.subprocess.run",
            side_effect=[
                _completed(json.dumps(agents)),
                subprocess.TimeoutExpired(["herdr", "agent", "read"], 5.0),
                _completed("raw pane"),
            ],
        ):
            self.assertEqual(
                get_agent_or_pane_text("w1D:p1"),
                ("raw pane", "pane:visible"),
            )


class TestAdapterTimeoutDelivery(unittest.TestCase):
    def test_agy_approval_fails_closed_when_delivery_is_unknown(self):
        with patch("adapters.agent_adapters.agy.run_cmd", return_value=None):
            approved, reason = AgyAdapter().inject_approval("w1D:p1", "git status")

        self.assertFalse(approved)
        self.assertIn("delivery unknown", reason)

    def test_codex_approval_fails_closed_when_delivery_is_unknown(self):
        with patch("adapters.agent_adapters.codex.run_cmd", return_value=None):
            approved, reason = CodexAdapter().inject_approval("w1D:p1", "git status")

        self.assertFalse(approved)
        self.assertIn("delivery unknown", reason)


if __name__ == "__main__":
    unittest.main()
