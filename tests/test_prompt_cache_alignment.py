#!/usr/bin/env python3
"""Regression tests for static system-prompt prefix cache alignment."""

import hashlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from tools.schengen_agent_llm import (
    SchengenAgentChat,
    build_escalation_context_block,
    build_system_prompt,
)


_ESC = {
    "id": 231,
    "pane_id": "w1D:p1",
    "agent_kind": "codex",
    "raw_command": "git commit -m cache-alignment",
    "safety_reason": "manual review",
    "decision_layer": "NOT_ALLOWLISTED",
    "capture_source": "recent-unwrapped",
    "normalization_relation": "same",
    "normalization_ambiguous": 0,
    "raw_capture_evaluated": 1,
    "origin": "A",
}


class _Response:
    status_code = 200

    def json(self):
        return {
            "choices": [{"message": {"content": "Advisory only."}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }


class _CapturingClient:
    def __init__(self):
        self.payloads = []

    async def post(self, *args, **kwargs):
        self.payloads.append(kwargs["json"])
        return _Response()

    async def aclose(self):
        return None


def _tool_round(call_id, content):
    return [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": call_id,
                "type": "function",
                "function": {"name": "investigate_pane_history", "arguments": "{}"},
            }],
        },
        {"role": "tool", "tool_call_id": call_id, "content": content},
    ]


class TestPromptCacheAlignment(unittest.IsolatedAsyncioTestCase):
    def test_static_variants_match_pre_refactor_golden_hashes(self):
        expected = {
            True: "4846bce67f22d051d48ef94959aa71d20a846109ed6a388eed2d93f7eb308a87",
            False: "665896921e33fe7eadde61695401effba50ad0df3ab3f015fa10c38027d09d18",
        }
        for allow_adjudication, digest in expected.items():
            prompt = build_system_prompt(
                language="english",
                allow_adjudication=allow_adjudication,
                has_active=True,
            )
            self.assertEqual(hashlib.sha256(prompt.encode()).hexdigest(), digest)
            for stale in ("Escalation ID", "Target Pane", "Canonical Command", "{active_esc"):
                self.assertNotIn(stale, prompt)

        other = dict(_ESC, id=999, pane_id="w9:p9", raw_command="rm -rf /tmp/example")
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=_ESC):
            first = build_system_prompt(language="english")
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=other):
            second = build_system_prompt(language="english")
        self.assertEqual(first, second)

    def test_context_block_is_complete_delimited_and_payload_invariant(self):
        changed = dict(
            _ESC,
            id=999,
            pane_id="w9:p9",
            raw_command="rm -rf /tmp/example",
            decision_layer="SHELL_CRITICAL",
        )
        with patch("tools.schengen_agent_llm.has_human_opinion", return_value=True):
            context = build_escalation_context_block(changed)
        self.assertTrue(context.startswith("[BEGIN UNTRUSTED ESCALATION DATA UNDER REVIEW]"))
        self.assertTrue(context.endswith("[END UNTRUSTED ESCALATION DATA UNDER REVIEW]"))
        for value in ("#999", "w9:p9", "rm -rf /tmp/example", "SHELL_CRITICAL",
                      "recent-unwrapped", "same", "Human Opinion Recorded: True"):
            self.assertIn(value, context)
        self.assertEqual(
            build_system_prompt(language="english", has_active=True),
            build_system_prompt(language="english", has_active=bool(changed)),
        )

    def test_idle_prompt_and_empty_context_are_exact(self):
        self.assertEqual(build_escalation_context_block(None), "")
        self.assertEqual(
            build_system_prompt(language="english", has_active=False),
            "You are the autonomous Security Gatekeeper & Inspector Agent for Herdr SmartGate.\n"
            "There are currently NO active pending escalations.\n"
            "All previous tasks are finished. If the user asks questions, answer them in concise professional English.",
        )

    async def test_every_turn_uses_one_fresh_snapshot_and_clears_stale_context(self):
        client = _CapturingClient()
        get_active = unittest.mock.Mock(side_effect=[_ESC, None])
        with patch("tools.schengen_agent_llm.get_current_command_escalation", get_active), patch(
            "tools.schengen_agent_llm.has_human_opinion", return_value=False
        ), patch(
            "tools.schengen_agent_llm.record_model_no_tool_call"
        ), patch("tools.schengen_agent_llm.httpx.AsyncClient", return_value=client):
            chat = SchengenAgentChat(api_key="test")
            chat.inspector_api_key = chat.judge_api_key = "test"
            chat.inspector_base_url = chat.judge_base_url = "https://example.invalid/v1"
            chat.inspector_model = chat.judge_model = "same"
            await chat.send_message("first")
            await chat.send_message("second")

        self.assertEqual(get_active.call_count, 2)
        first_user = client.payloads[0]["messages"][-1]["content"]
        second_user = client.payloads[1]["messages"][-1]["content"]
        self.assertIn("Escalation ID: #231", first_user)
        self.assertEqual(second_user, "second")
        self.assertNotIn("Escalation ID: #231", str(client.payloads[1]["messages"]))

    async def test_latest_per_turn_context_survives_existing_compaction(self):
        client = _CapturingClient()
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=_ESC) as get_active, patch(
            "tools.schengen_agent_llm.has_human_opinion", return_value=False
        ), patch(
            "tools.schengen_agent_llm.record_model_no_tool_call"
        ), patch("tools.schengen_agent_llm.httpx.AsyncClient", return_value=client):
            chat = SchengenAgentChat(api_key="test")
            chat.inspector_api_key = chat.judge_api_key = "test"
            chat.inspector_base_url = chat.judge_base_url = "https://example.invalid/v1"
            chat.inspector_model = chat.judge_model = "same"
            chat._current_esc_id = _ESC["id"]
            chat.history = [
                *_tool_round("old-1", "A" * 25_000),
                *_tool_round("old-2", "B" * 25_000),
                *_tool_round("latest", "C" * 4_000),
            ]
            await chat.send_message("review current escalation")
            expected_context = build_escalation_context_block(_ESC)

        self.assertEqual(get_active.call_count, 1)
        payload_messages = client.payloads[0]["messages"]
        self.assertEqual(
            payload_messages[-1]["content"],
            f"{expected_context}\n\nreview current escalation",
        )
        self.assertNotIn("A" * 2_000, str(payload_messages))
        self.assertIn("C" * 4_000, str(payload_messages))


if __name__ == "__main__":
    unittest.main()
