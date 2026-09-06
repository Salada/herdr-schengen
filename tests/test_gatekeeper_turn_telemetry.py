#!/usr/bin/env python3
"""Redacted per-escalation Gatekeeper timing timeline regressions."""

import io
import hashlib
import json
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from email.message import Message
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import core.gatekeeper_telemetry as telemetry
from cmd import schengen_history
from cmd.schengen_watcher import cancel_stale_human_escalation
from core.cloud_judge import post_cloud_judge, set_telemetry_hook
from core.gatekeeper_telemetry import GatekeeperTimeline
from tools.schengen_agent_llm import SchengenAgentChat, execute_tool_call


_ESCALATION = {
    "id": 245,
    "pane_id": "w1D:p1",
    "agent_kind": "codex",
    "raw_command": "secret-command --token hunter2",
    "decision_layer": "NOT_ALLOWLISTED",
    "safety_reason": "manual review",
    "origin": "A",
    "cwd": "/secret/worktree",
}


class _Response:
    def __init__(self, *, status=200, finish_reason="stop", content: Optional[str] = "Advisory", tool_calls=None):
        self.status_code = status
        self.headers = {}
        self.text = "sensitive upstream response"
        self._finish_reason = finish_reason
        self._content = content
        self._tool_calls = tool_calls

    def json(self):
        return {
            "choices": [{
                "finish_reason": self._finish_reason,
                "message": {"content": self._content, "tool_calls": self._tool_calls},
            }],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3},
        }


class _Client:
    def __init__(self, responses, on_post=None):
        self.responses = list(responses)
        self.on_post = on_post

    async def post(self, *args, **kwargs):
        if self.on_post:
            self.on_post()
        return self.responses.pop(0)

    async def aclose(self):
        return None


def _tool_call(name):
    return [{
        "id": "call-1",
        "type": "function",
        "function": {
            "name": name,
            "arguments": json.dumps({
                "escalation_id": 245,
                "english_feedback": "sensitive feedback",
                "target_path": "/secret/worktree",
            }),
        },
    }]


def _chat():
    chat = SchengenAgentChat(api_key="test-key")
    chat.inspector_api_key = chat.judge_api_key = "test-key"
    chat.inspector_base_url = chat.judge_base_url = "https://example.invalid/v1"
    chat.inspector_model = chat.judge_model = "test-model"
    return chat


class TestTimelineDocument(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_patch = patch.object(telemetry, "TIMELINE_DIR", Path(self.temp_dir.name))
        self.dir_patch.start()

    def tearDown(self):
        self.dir_patch.stop()
        self.temp_dir.cleanup()

    def test_timeline_is_ordered_and_redacted_by_construction(self):
        timeline = GatekeeperTimeline.begin(
            245,
            decision_layer="NOT_ALLOWLISTED",
            detected_ns=10,
            evaluation_started_ns=20,
            evaluation_finished_ns=30,
            queued_ns=40,
        )
        timeline.record(
            "tool_call",
            started_ns=50,
            finished_ns=60,
            outcome="failed",
            phase="Inspector",
            turn=1,
            tool="read_file_snippet; cat /secret",
            raw_command="secret-command --token hunter2",
            tool_output="hunter2",
        )
        timeline.finish("deferred", "tool_failure", "complete")

        snapshot = timeline.snapshot()
        starts = [event["started_monotonic_ns"] for event in snapshot["events"]]
        self.assertEqual(starts, sorted(starts))
        self.assertTrue(all(event["duration_ms"] >= 0 for event in snapshot["events"]))
        self.assertEqual([event["sequence"] for event in snapshot["events"]], list(range(1, len(starts) + 1)))
        self.assertEqual(len(snapshot["correlation_id"]), 32)
        serialized = json.dumps(snapshot)
        self.assertNotIn("hunter2", serialized)
        self.assertNotIn("secret-command", serialized)
        self.assertNotIn("/secret", serialized)
        self.assertEqual(snapshot["terminal"]["outcome"], "deferred")

    def test_history_cli_reads_one_metadata_only_timeline(self):
        GatekeeperTimeline.begin(
            245,
            decision_layer="NOT_ALLOWLISTED",
            detected_ns=10,
            evaluation_started_ns=20,
            evaluation_finished_ns=30,
            queued_ns=40,
        ).finish("deferred", "model_no_tool_call", "complete")
        output = io.StringIO()
        with patch.object(sys, "argv", ["schengen_history.py", "--timeline", "245"]), redirect_stdout(output):
            schengen_history.main()
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["escalation_id"], 245)
        self.assertEqual(payload["terminal"]["outcome"], "deferred")
        self.assertNotIn("raw_command", output.getvalue())

    def test_reader_drops_unknown_fields_from_a_tampered_file(self):
        path = Path(self.temp_dir.name) / "escalation-245.json"
        path.write_text(json.dumps({
            "schema_version": 1,
            "correlation_id": "a" * 32,
            "escalation_id": 245,
            "decision_layer": "NOT_ALLOWLISTED",
            "raw_command": "secret-command --token hunter2",
            "events": [{
                "sequence": 1,
                "stage": "tool_call",
                "started_monotonic_ns": 10,
                "finished_monotonic_ns": 20,
                "outcome": "complete",
                "tool_output": "hunter2",
            }],
            "terminal": None,
        }), encoding="utf-8")
        serialized = json.dumps(GatekeeperTimeline.load(245).snapshot())
        self.assertNotIn("hunter2", serialized)
        self.assertNotIn("raw_command", serialized)
        self.assertNotIn("tool_output", serialized)

    def test_stale_escalation_cancellation_finishes_the_timeline(self):
        command = "secret-command --token hunter2"
        GatekeeperTimeline.begin(
            245, decision_layer="NOT_ALLOWLISTED", detected_ns=10,
            evaluation_started_ns=20, evaluation_finished_ns=30, queued_ns=40,
        )
        row = {
            "id": 245,
            "command_hash": hashlib.sha256(command.encode("utf-8")).hexdigest()[:16],
        }
        with patch("cmd.schengen_watcher.get_pending_escalations", return_value=[row]), patch(
            "cmd.schengen_watcher.resolve_escalation"
        ) as resolve:
            cancel_stale_human_escalation("w1D:p1", command)
        self.assertEqual(GatekeeperTimeline.load(245).snapshot()["terminal"]["outcome"], "cancelled")
        resolve.assert_called_once()


class TestPreEscalationJudgeTelemetry(unittest.TestCase):
    @patch("core.cloud_judge.time.sleep")
    @patch("core.cloud_judge.urllib.request.urlopen")
    def test_cloud_judge_retry_emits_attempt_backoff_and_turn(self, urlopen, _sleep):
        rate_limited = urllib.error.HTTPError(
            url="http://dummy", code=429, msg="secret upstream detail",
            hdrs=Message(), fp=io.BytesIO(b"{}"),
        )
        success = MagicMock()
        success.__enter__.return_value = io.BytesIO(b'{"is_safe":true}')
        urlopen.side_effect = [rate_limited, success]
        events = []
        set_telemetry_hook(events.append)
        try:
            result = post_cloud_judge(
                messages=[{"role": "user", "content": "secret-command"}],
                endpoint="http://dummy", model="dummy", api_key="secret-key",
                reasoning_effort="low", max_retries=2,
            )
        finally:
            set_telemetry_hook(None)
        self.assertTrue(result["is_safe"])
        self.assertEqual(
            [event["stage"] for event in events],
            ["llm_attempt", "retry_backoff", "llm_attempt", "judge_turn"],
        )
        self.assertNotIn("secret", json.dumps(events))
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(
            telemetry, "TIMELINE_DIR", Path(temp_dir)
        ):
            timeline = GatekeeperTimeline.begin(
                245, decision_layer="CLOUD_JUDGE", detected_ns=1,
                evaluation_started_ns=2, evaluation_finished_ns=3,
                queued_ns=4, pre_events=events,
            )
            stages = [event["stage"] for event in timeline.snapshot()["events"]]
            self.assertIn("judge_turn", stages)
            self.assertIn("retry_backoff", stages)


class TestTurnTelemetry(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_patch = patch.object(telemetry, "TIMELINE_DIR", Path(self.temp_dir.name))
        self.dir_patch.start()

    async def asyncTearDown(self):
        self.dir_patch.stop()
        self.temp_dir.cleanup()

    async def _run(self, client, *, tool_result=None):
        chat = _chat()
        patches = [
            patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=dict(_ESCALATION)),
            patch("tools.schengen_agent_llm.has_human_opinion", return_value=False),
            patch("tools.schengen_agent_llm.record_model_no_tool_call"),
            patch("tools.schengen_agent_llm.httpx.AsyncClient", return_value=client),
            patch("tools.schengen_agent_llm.asyncio.sleep", return_value=None),
        ]
        if tool_result is not None:
            patches.append(patch("tools.schengen_agent_llm.execute_tool_call", return_value=tool_result))
        for active in patches:
            active.start()
        try:
            result = await chat.send_message("review secret-command --token hunter2")
        finally:
            for active in reversed(patches):
                active.stop()
        return result, GatekeeperTimeline.load(245).snapshot()

    async def test_retry_backoff_and_tool_failure_are_timed_without_payloads(self):
        client = _Client([
            _Response(status=500),
            _Response(finish_reason="tool_calls", content=None, tool_calls=_tool_call("read_file_snippet")),
            _Response(content="Advisory only"),
        ])
        result, snapshot = await self._run(client, tool_result='{"error":"secret tool output"}')

        self.assertIn("MODEL_NO_TOOL_CALL", result)
        stages = [event["stage"] for event in snapshot["events"]]
        self.assertIn("retry_backoff", stages)
        self.assertIn("tool_call", stages)
        tool_event = next(event for event in snapshot["events"] if event["stage"] == "tool_call")
        self.assertEqual(tool_event["outcome"], "failed")
        self.assertEqual(snapshot["terminal"]["outcome"], "deferred")
        serialized = json.dumps(snapshot)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("hunter2", serialized)

    async def test_truncation_is_terminal_defer(self):
        client = _Client([_Response(finish_reason="length", content="partial")])
        result, snapshot = await self._run(client)
        self.assertIn("MAX_TOKENS_REACHED", result)
        self.assertEqual(snapshot["terminal"]["outcome"], "deferred")
        self.assertEqual(snapshot["terminal"]["completion_state"], "truncated")

    async def test_cancellation_is_terminal_and_preserves_response_behavior(self):
        chat = _chat()
        client = _Client([_Response()], on_post=chat.cancel)
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=dict(_ESCALATION)), patch(
            "tools.schengen_agent_llm.httpx.AsyncClient", return_value=client
        ):
            result = await chat.send_message("review")
        snapshot = GatekeeperTimeline.load(245).snapshot()
        self.assertIn("Interrupted", result)
        self.assertEqual(snapshot["terminal"]["outcome"], "cancelled")
        self.assertEqual(snapshot["terminal"]["completion_state"], "cancelled")

    async def test_approve_reject_and_delivery_failure_outcomes(self):
        cases = (
            ("approve_escalation", True, "approved", "success"),
            ("reject_escalation", True, "rejected", "success"),
            ("approve_escalation", False, "delivery_failed", "error"),
        )
        for index, (tool, injected, expected, expected_status) in enumerate(cases):
            escalation = dict(_ESCALATION, id=245 + index)
            timeline = GatekeeperTimeline.begin(
                escalation["id"], decision_layer="NOT_ALLOWLISTED",
                detected_ns=10, evaluation_started_ns=20,
                evaluation_finished_ns=30, queued_ns=40,
            )
            inject_name = "_inject_approval" if tool == "approve_escalation" else "_inject_rejection"
            with self.subTest(tool=tool, expected=expected), patch(
                "tools.schengen_agent_llm.get_current_command_escalation", return_value=escalation
            ), patch("tools.schengen_agent_llm._get_escalation_row", return_value=escalation), patch(
                "tools.schengen_agent_llm.get_instruction_delivery_config", return_value={}
            ), patch("tools.schengen_agent_llm." + inject_name, return_value=(injected, "failed")), patch(
                "tools.schengen_agent_llm.resolve_escalation"
            ), patch("tools.schengen_agent_llm.record_adjudication"):
                result = execute_tool_call(
                    tool,
                    {"escalation_id": escalation["id"], "english_feedback": "sensitive feedback"},
                    context={"cwd": "/secret/worktree", "telemetry": timeline},
                )
            snapshot = GatekeeperTimeline.load(escalation["id"]).snapshot()
            self.assertEqual(json.loads(result)["status"], expected_status)
            self.assertEqual(snapshot["terminal"]["outcome"], expected)
            delivery = [event for event in snapshot["events"] if event["stage"] == "terminal_delivery"]
            self.assertEqual(len(delivery), 1)

    async def test_unwritable_telemetry_does_not_change_decision_behavior(self):
        client = _Client([_Response(content="same advisory")])
        with patch.object(telemetry, "TIMELINE_DIR", Path("/dev/null/not-a-directory")):
            result, _snapshot = await self._run(client)
        self.assertIn("same advisory", result)
        self.assertIn("MODEL_NO_TOOL_CALL", result)


if __name__ == "__main__":
    unittest.main()
