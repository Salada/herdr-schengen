#!/usr/bin/env python3
"""Completion-token ceiling and truncation regressions."""

from __future__ import annotations

import os
import sys
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
        self.assertEqual(defaulted.inspector_max_tokens, 800)
        self.assertEqual(defaulted.judge_max_tokens, 600)

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
                self.assertEqual(chat.inspector_max_tokens, 800)
                self.assertEqual(chat.judge_max_tokens, 600)


class TestCompletionTokenPayloads(unittest.IsolatedAsyncioTestCase):
    async def test_inspector_and_judge_payloads_include_explicit_ceilings(self):
        client = _SequenceClient([_Response(), _Response(content="Final advisory.")])
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=None), patch(
            "tools.schengen_agent_llm.httpx.AsyncClient", return_value=client
        ):
            chat = _chat(client)
            await chat.send_message("review")

        self.assertEqual([payload["max_tokens"] for payload in client.payloads], [800, 600])

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
        self.assertTrue(all(payload["max_tokens"] == 800 for payload in client.payloads))

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
                completion_tokens=800,
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
        self.assertIn("800-token ceiling", result)
        self.assertIn("remains pending", result)
        self.assertEqual(chat.total_completion_tokens, 800)
        self.assertEqual(chat.inspector_completion_tokens, 800)

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
                completion_tokens=600,
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
        self.assertIn("600-token ceiling", result)
        self.assertIn("Partial risk briefing", result)
        self.assertIn("remains pending", result)
        self.assertEqual(chat.total_prompt_tokens, 12)
        self.assertEqual(chat.total_completion_tokens, 604)
        self.assertEqual(chat.inspector_completion_tokens, 4)
        self.assertEqual(chat.judge_completion_tokens, 600)


if __name__ == "__main__":
    unittest.main()
