#!/usr/bin/env python3
"""Completion-token ceiling and truncation regressions."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from tools.schengen_agent_llm import SchengenAgentChat  # noqa: E402


class _Response:
    def __init__(self, *, content="Advisory only.", finish_reason="stop", tool_calls=None,
                 status_code=200, prompt_tokens=3, completion_tokens=2):
        self.status_code = status_code
        self.headers = {}
        self.text = "temporary failure" if status_code != 200 else ""
        self._payload = {
            "choices": [{
                "finish_reason": finish_reason,
                "message": {"content": content, "tool_calls": tool_calls},
            }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            },
        }

    def json(self):
        return self._payload


class _SequenceClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.payloads = []

    async def post(self, *args, **kwargs):
        self.payloads.append(kwargs["json"])
        return self.responses.pop(0)

    async def aclose(self):
        return None


def _chat(client):
    chat = SchengenAgentChat(api_key="test-key")
    chat.inspector_api_key = chat.judge_api_key = "test-key"
    chat.inspector_base_url = chat.judge_base_url = "https://example.invalid/v1"
    chat.inspector_model = "inspector"
    chat.judge_model = "judge"
    return chat


class TestCompletionTokenConfig(unittest.TestCase):
    def test_defaults_and_valid_bounds_are_read_once(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SCHENGEN_INSPECTOR_MAX_TOKENS", None)
            os.environ.pop("SCHENGEN_JUDGE_MAX_TOKENS", None)
            defaulted = SchengenAgentChat(api_key="test")
        self.assertEqual(defaulted.inspector_max_tokens, 4096)
        self.assertEqual(defaulted.judge_max_tokens, 4096)

        with patch.dict(os.environ, {
            "SCHENGEN_INSPECTOR_MAX_TOKENS": "64",
            "SCHENGEN_JUDGE_MAX_TOKENS": "4096",
        }):
            configured = SchengenAgentChat(api_key="test")
            os.environ["SCHENGEN_INSPECTOR_MAX_TOKENS"] = "900"
            os.environ["SCHENGEN_JUDGE_MAX_TOKENS"] = "900"
            self.assertEqual(configured.inspector_max_tokens, 64)
            self.assertEqual(configured.judge_max_tokens, 4096)

    def test_invalid_override_matrix_falls_back(self):
        invalid = [
            "", "800.0", "+800", "-800", "0x320", "800 ",
            "True", "False", "800abc", "0", "63", "4097", "999999", "٨٠٠",
        ]
        for value in invalid:
            with self.subTest(value=value), patch.dict(os.environ, {
                "SCHENGEN_INSPECTOR_MAX_TOKENS": value,
                "SCHENGEN_JUDGE_MAX_TOKENS": value,
            }):
                chat = SchengenAgentChat(api_key="test")
                self.assertEqual(chat.inspector_max_tokens, 4096)
                self.assertEqual(chat.judge_max_tokens, 4096)


class TestCompletionTokenPayloads(unittest.IsolatedAsyncioTestCase):
    async def test_inspector_and_judge_payloads_include_explicit_ceilings(self):
        client = _SequenceClient([_Response(), _Response(content="Final advisory.")])
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=None), patch(
            "tools.schengen_agent_llm.httpx.AsyncClient", return_value=client
        ):
            chat = _chat(client)
            await chat.send_message("review")

        self.assertEqual([payload["max_tokens"] for payload in client.payloads], [4096, 4096])

    async def test_inspector_can_execute_tool_call_beyond_old_800_token_ceiling(self):
        tool_calls = [{
            "id": "complete",
            "type": "function",
            "function": {
                "name": "investigate_path_details",
                "arguments": '{"target_path":"."}',
            },
        }]
        client = _SequenceClient([
            _Response(
                content=None,
                finish_reason="tool_calls",
                tool_calls=tool_calls,
                completion_tokens=801,
            ),
            _Response(content="Investigation complete."),
        ])
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=None), patch(
            "tools.schengen_agent_llm.httpx.AsyncClient", return_value=client
        ), patch("tools.schengen_agent_llm.execute_tool_call", return_value='{"exists":true}') as execute:
            chat = _chat(client)
            chat.judge_model = chat.inspector_model
            result = await chat.send_message("review escalation 5620")

        self.assertEqual(client.payloads[0]["max_tokens"], 4096)
        execute.assert_called_once_with(
            "investigate_path_details",
            {"target_path": "."},
            context={"cwd": ""},
        )
        self.assertEqual(result, "Investigation complete.")

    async def test_custom_ceiling_is_stable_across_turns(self):
        client = _SequenceClient([_Response(), _Response()])
        with patch.dict(os.environ, {"SCHENGEN_INSPECTOR_MAX_TOKENS": "700"}), patch(
            "tools.schengen_agent_llm.get_current_command_escalation", return_value=None
        ), patch("tools.schengen_agent_llm.httpx.AsyncClient", return_value=client):
            chat = _chat(client)
            chat.judge_model = chat.inspector_model
            await chat.send_message("first")
            os.environ["SCHENGEN_INSPECTOR_MAX_TOKENS"] = "900"
            await chat.send_message("second")

        self.assertEqual([payload["max_tokens"] for payload in client.payloads], [700, 700])

    async def test_retry_reuses_the_bounded_payload(self):
        client = _SequenceClient([_Response(status_code=500), _Response()])
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=None), patch(
            "tools.schengen_agent_llm.httpx.AsyncClient", return_value=client
        ), patch("tools.schengen_agent_llm.asyncio.sleep", return_value=None):
            chat = _chat(client)
            chat.judge_model = chat.inspector_model
            await chat.send_message("review")

        self.assertEqual(len(client.payloads), 2)
        self.assertTrue(all(payload["max_tokens"] == 4096 for payload in client.payloads))

    async def test_inspector_length_drops_every_tool_call_and_accounts_usage(self):
        tool_calls = [{
            "id": "partial",
            "type": "function",
            "function": {"name": "approve_escalation", "arguments": "{\"escalation_id\":235}"},
        }]
        client = _SequenceClient([
            _Response(
                content=None,
                finish_reason="length",
                tool_calls=tool_calls,
                prompt_tokens=11,
                completion_tokens=4096,
            )
        ])
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=None), patch(
            "tools.schengen_agent_llm.httpx.AsyncClient", return_value=client
        ), patch("tools.schengen_agent_llm.execute_tool_call") as execute:
            chat = _chat(client)
            result = await chat.send_message("review")

        execute.assert_not_called()
        self.assertIn("[MAX_TOKENS_REACHED]", result)
        self.assertIn("Inspector", result)
        self.assertIn("4096-token ceiling", result)
        self.assertIn("remains pending", result)
        self.assertEqual(chat.total_completion_tokens, 4096)
        self.assertEqual(chat.inspector_completion_tokens, 4096)

    async def test_judge_length_is_visible_and_preserves_pending_audit(self):
        escalation = {
            "id": 235,
            "pane_id": "w1D:p1",
            "agent_kind": "codex",
            "raw_command": "git commit",
            "decision_layer": "NOT_ALLOWLISTED",
            "safety_reason": "manual review",
            "origin": "A",
        }
        client = _SequenceClient([
            _Response(prompt_tokens=5, completion_tokens=4),
            _Response(
                content="Partial risk briefing",
                finish_reason="length",
                prompt_tokens=7,
                completion_tokens=4096,
            ),
        ])
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=escalation), patch(
            "tools.schengen_agent_llm.has_human_opinion", return_value=False
        ), patch("tools.schengen_agent_llm.httpx.AsyncClient", return_value=client), patch(
            "tools.schengen_agent_llm.record_model_no_tool_call"
        ) as record:
            chat = _chat(client)
            result = await chat.send_message("review")

        record.assert_called_once_with(escalation, "Judge")
        self.assertIn("[MODEL_NO_TOOL_CALL]", result)
        self.assertIn("[MAX_TOKENS_REACHED]", result)
        self.assertIn("4096-token ceiling", result)
        self.assertIn("Partial risk briefing", result)
        self.assertIn("remains pending", result)
        self.assertEqual(chat.total_prompt_tokens, 12)
        self.assertEqual(chat.total_completion_tokens, 4100)
        self.assertEqual(chat.inspector_completion_tokens, 4)
        self.assertEqual(chat.judge_completion_tokens, 4096)

    async def test_configured_over_cap_defers_without_api_or_audit(self):
        escalation = {
            "id": 5829,
            "pane_id": "w1D:p1",
            "agent_kind": "codex",
            "raw_command": "git status",
            "decision_layer": "NOT_ALLOWLISTED",
            "safety_reason": "manual review",
            "origin": "A",
        }
        client = _SequenceClient([])
        timeline = unittest.mock.Mock()
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {
            "SCHENGEN_INSPECTOR_CONTEXT_WINDOW": "8192",
        }), patch(
            "tools.schengen_agent_llm.get_current_command_escalation", return_value=escalation
        ), patch(
            "tools.schengen_agent_llm.GatekeeperTimeline.load", return_value=timeline
        ), patch(
            "tools.schengen_agent_llm.httpx.AsyncClient", return_value=client
        ), patch(
            "tools.schengen_agent_llm.record_model_no_tool_call"
        ) as record:
            chat = SchengenAgentChat(api_key="test-key", sessions_dir=Path(tmpdir))
            chat.inspector_api_key = chat.judge_api_key = "test-key"
            chat.inspector_base_url = chat.judge_base_url = "https://example.invalid/v1"
            result = await chat.send_message("X" * 8_000)
            transcript = chat.log_file.read_text(encoding="utf-8")

        self.assertIn("[CONTEXT_CAP_EXCEEDED]", result)
        self.assertEqual(client.payloads, [])
        record.assert_not_called()
        timeline.finish.assert_called_once_with(
            "deferred", "context_cap_exceeded", "truncated"
        )
        self.assertIn("CONTEXT_CAP_EXCEEDED", transcript)
        stats = chat.get_token_usage_stats()
        self.assertEqual(stats["inspector_context_budget_state"], "deferred_over_cap")
        self.assertEqual(stats["inspector_context_cap_defers"], 1)
        self.assertEqual(stats["api_calls"], 0)

    async def test_malformed_tool_relationship_defers_before_api(self):
        escalation = {
            "id": 5830,
            "pane_id": "w1D:p1",
            "agent_kind": "codex",
            "raw_command": "git status",
            "decision_layer": "NOT_ALLOWLISTED",
            "safety_reason": "manual review",
            "origin": "A",
        }
        client = _SequenceClient([])
        timeline = unittest.mock.Mock()
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {
            "SCHENGEN_INSPECTOR_CONTEXT_WINDOW": "8192",
        }), patch(
            "tools.schengen_agent_llm.get_current_command_escalation", return_value=escalation
        ), patch(
            "tools.schengen_agent_llm.GatekeeperTimeline.load", return_value=timeline
        ), patch("tools.schengen_agent_llm.httpx.AsyncClient", return_value=client):
            chat = SchengenAgentChat(api_key="test-key", sessions_dir=Path(tmpdir))
            chat._current_esc_id = escalation["id"]
            chat.history = [{
                "role": "assistant",
                "content": None,
                "tool_calls": [{
                    "id": "missing-result",
                    "type": "function",
                    "function": {"name": "read_file_snippet", "arguments": "{}"},
                }],
            }]
            result = await chat.send_message("X" * 8_000)

        self.assertIn("[CONTEXT_CAP_EXCEEDED]", result)
        self.assertEqual(client.payloads, [])
        self.assertEqual(chat.history[0]["tool_calls"][0]["id"], "missing-result")
        timeline.finish.assert_called_once_with(
            "deferred", "context_cap_exceeded", "truncated"
        )

    async def test_judge_cap_defers_after_inspector_without_second_api_call(self):
        client = _SequenceClient([_Response(prompt_tokens=100)])
        timeline = unittest.mock.Mock()
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {
            "SCHENGEN_INSPECTOR_CONTEXT_WINDOW": "300000",
            "SCHENGEN_JUDGE_CONTEXT_WINDOW": "8192",
        }), patch(
            "tools.schengen_agent_llm.get_current_command_escalation", return_value=None
        ), patch(
            "tools.schengen_agent_llm.httpx.AsyncClient", return_value=client
        ):
            chat = SchengenAgentChat(api_key="test-key", sessions_dir=Path(tmpdir))
            chat.inspector_base_url = "https://inspector.invalid/v1"
            chat.judge_base_url = "https://judge.invalid/v1"
            chat.inspector_model = "inspector"
            chat.judge_model = "judge"
            with patch("tools.schengen_agent_llm.GatekeeperTimeline.load", return_value=timeline):
                result = await chat.send_message("X" * 8_000)

        self.assertIn("[CONTEXT_CAP_EXCEEDED]", result)
        self.assertEqual(len(client.payloads), 1)
        self.assertEqual(chat.total_api_calls, 1)
        self.assertEqual(
            chat.get_token_usage_stats()["judge_context_budget_state"],
            "deferred_over_cap",
        )

    async def test_success_samples_are_phase_local_and_flat_stats_are_updated(self):
        client = _SequenceClient([
            _Response(prompt_tokens=101),
            _Response(content="Final advisory.", prompt_tokens=202),
        ])
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {
            "SCHENGEN_INSPECTOR_CONTEXT_WINDOW": "100000",
            "SCHENGEN_JUDGE_CONTEXT_WINDOW": "200000",
        }), patch(
            "tools.schengen_agent_llm.get_current_command_escalation", return_value=None
        ), patch("tools.schengen_agent_llm.httpx.AsyncClient", return_value=client):
            chat = SchengenAgentChat(api_key="test-key", sessions_dir=Path(tmpdir))
            chat.inspector_base_url = "https://inspector.invalid/v1"
            chat.judge_base_url = "https://judge.invalid/v1"
            chat.inspector_model = "inspector"
            chat.judge_model = "judge"
            await chat.send_message("review")

        self.assertEqual(chat._context_budget["inspector"]["samples"][0][1], 101)
        self.assertEqual(chat._context_budget["judge"]["samples"][0][1], 202)
        stats = chat.get_token_usage_stats()
        self.assertEqual(stats["inspector_context_budget_state"], "within_budget")
        self.assertEqual(stats["judge_context_budget_state"], "within_budget")
        self.assertGreater(stats["inspector_input_estimate_tokens"], 0)
        self.assertGreater(stats["judge_growth_headroom_tokens"], 0)

    async def test_missing_usage_adds_no_estimator_sample(self):
        response = _Response()
        response._payload["usage"] = {"prompt_tokens": "unknown"}
        client = _SequenceClient([response])
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {
            "SCHENGEN_INSPECTOR_CONTEXT_WINDOW": "100000",
        }), patch(
            "tools.schengen_agent_llm.get_current_command_escalation", return_value=None
        ), patch("tools.schengen_agent_llm.httpx.AsyncClient", return_value=client):
            chat = SchengenAgentChat(api_key="test-key", sessions_dir=Path(tmpdir))
            chat.judge_model = chat.inspector_model
            await chat.send_message("review")

        self.assertEqual(chat._context_budget["inspector"]["samples"], [])
        self.assertEqual(chat.total_prompt_tokens, 0)


if __name__ == "__main__":
    unittest.main()
