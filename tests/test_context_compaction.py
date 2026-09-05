#!/usr/bin/env python3
"""Deterministic, evidence-preserving context compaction tests."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from core.redaction import redact_for_cloud
from tools.schengen_agent_llm import (
    COMPACTION_HEAD_EXCERPT_CHARS,
    COMPACTION_TAIL_EXCERPT_CHARS,
    SchengenAgentChat,
    _compact_tool_observations,
    _message_chars,
)


def _round(call_id: str, content: str, *, second_content: str | None = None):
    calls = [
        {
            "id": call_id,
            "type": "function",
            "function": {"name": "investigate_pane_history", "arguments": "{}"},
        }
    ]
    tools = [{"role": "tool", "tool_call_id": call_id, "content": content}]
    if second_content is not None:
        second_id = f"{call_id}-second"
        calls.append(
            {
                "id": second_id,
                "type": "function",
                "function": {"name": "read_file_snippet", "arguments": "{}"},
            }
        )
        tools.append({"role": "tool", "tool_call_id": second_id, "content": second_content})
    assistant = {
        "role": "assistant",
        "content": None,
        "reasoning_content": f"reasoning-{call_id}",
        "tool_calls": calls,
    }
    return [assistant, *tools]


def _large_messages(old_size: int = 25_000, latest_size: int = 4_000):
    messages = [{"role": "system", "content": "security invariants"}]
    messages.extend(_round("old-1", "A" * old_size))
    messages.extend(_round("old-2", "B" * old_size))
    messages.extend(_round("old-3", "C" * old_size))
    messages.extend(_round("latest", "D" * latest_size, second_content="E" * latest_size))
    messages.append({"role": "user", "content": "current escalation evidence"})
    return messages


class TestContextCompaction(unittest.TestCase):
    def test_compaction_skips_when_under_total_threshold(self):
        messages = [{"role": "system", "content": "guard"}, *_round("latest", "x" * 2_000)]
        compacted, stats = _compact_tool_observations(messages)
        self.assertIs(compacted, messages)
        self.assertEqual(stats["compacted_tool_results"], 0)

    def test_compaction_leaves_latest_multi_tool_round_untouched(self):
        messages = _large_messages()
        latest_assistant = messages[-4]
        latest_tools = messages[-3:-1]

        compacted, stats = _compact_tool_observations(messages)

        self.assertGreater(stats["compacted_tool_results"], 0)
        self.assertEqual(compacted[-4], latest_assistant)
        self.assertEqual(compacted[-3:-1], latest_tools)
        self.assertEqual(compacted[0], messages[0])
        self.assertEqual(compacted[-1], messages[-1])

    def test_compaction_replaces_older_large_observations_deterministically(self):
        messages = _large_messages()
        compacted, stats = _compact_tool_observations(messages)
        again, again_stats = _compact_tool_observations(messages)

        record = json.loads(compacted[2]["content"])
        original = messages[2]["content"]
        self.assertTrue(record["_compacted"])
        self.assertEqual(record["tool"], "investigate_pane_history")
        self.assertEqual(record["tool_call_id"], "old-1")
        self.assertEqual(record["original_char_count"], len(original))
        self.assertEqual(record["sha256"], hashlib.sha256(original.encode("utf-8")).hexdigest())
        self.assertEqual(record["head_excerpt"], original[:COMPACTION_HEAD_EXCERPT_CHARS])
        self.assertEqual(record["tail_excerpt"], original[-COMPACTION_TAIL_EXCERPT_CHARS:])
        self.assertEqual(compacted, again)
        self.assertEqual(stats, again_stats)

    def test_compaction_reduces_large_sequence_by_at_least_55_percent(self):
        messages = _large_messages()
        compacted, stats = _compact_tool_observations(messages)
        reduction = 1 - (_message_chars(compacted) / _message_chars(messages))

        self.assertGreaterEqual(reduction, 0.55)
        self.assertEqual(stats["compacted_tool_results"], 3)
        self.assertEqual(stats["after_chars"], _message_chars(compacted))

    def test_compaction_handles_malformed_tool_id_by_returning_original(self):
        messages = _large_messages()
        messages.insert(1, {"role": "tool", "tool_call_id": "orphan", "content": "Z" * 2_000})
        compacted, stats = _compact_tool_observations(messages)

        self.assertIs(compacted, messages)
        self.assertEqual(stats["compacted_tool_results"], 0)

    def test_internal_compaction_error_returns_original(self):
        messages = _large_messages()
        with self.assertLogs("tools.schengen_agent_llm", level="ERROR"):
            with patch("tools.schengen_agent_llm.copy.deepcopy", side_effect=RuntimeError("boom")):
                compacted, stats = _compact_tool_observations(messages)

        self.assertIs(compacted, messages)
        self.assertEqual(stats["after_chars"], stats["before_chars"])
        self.assertEqual(stats["compacted_tool_results"], 0)

    def test_latest_round_over_budget_returns_original(self):
        messages = [{"role": "system", "content": "guard"}, *_round("latest", "X" * 51_000)]
        compacted, stats = _compact_tool_observations(messages)

        self.assertIs(compacted, messages)
        self.assertEqual(stats["warning"], "latest_tool_round_exceeds_compaction_budget")

    def test_trigger_with_no_eligible_observation_is_noop(self):
        messages = [{"role": "system", "content": "S" * 51_000}, *_round("latest", "small")]
        compacted, stats = _compact_tool_observations(messages)

        self.assertIs(compacted, messages)
        self.assertEqual(stats["compacted_tool_results"], 0)

    def test_compaction_uses_already_redacted_content(self):
        secret = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
        redacted = redact_for_cloud(f"Authorization: Bearer {secret}\n" + "A" * 25_000)
        messages = [{"role": "system", "content": "guard"}]
        messages.extend(_round("old-1", redacted))
        messages.extend(_round("old-2", "B" * 25_000))
        messages.extend(_round("latest", "latest" * 1_000))

        compacted, _ = _compact_tool_observations(messages)

        self.assertNotIn(secret, compacted[2]["content"])
        self.assertEqual(
            json.loads(compacted[2]["content"])["sha256"],
            hashlib.sha256(redacted.encode("utf-8")).hexdigest(),
        )

    def test_jsonl_keeps_full_observation_before_prompt_compaction(self):
        raw = "full-audit-observation:" + "Q" * 25_000
        messages = [{"role": "system", "content": "guard"}]
        messages.extend(_round("old-1", raw))
        messages.extend(_round("old-2", "B" * 25_000))
        messages.extend(_round("latest", "latest" * 1_000))

        with tempfile.TemporaryDirectory() as tmpdir:
            chat = SchengenAgentChat(api_key="test")
            chat.log_file = Path(tmpdir) / "session.jsonl"
            chat._append_transcript(role="tool", content=raw)
            compacted = chat._compact_messages_for_request(messages)
            transcript = chat.log_file.read_text(encoding="utf-8")

        self.assertIn(raw, transcript)
        self.assertNotIn(raw, compacted[2]["content"])
        self.assertEqual(chat.compaction_events, 1)
        self.assertGreater(chat.compaction_chars_saved, 0)


if __name__ == "__main__":
    unittest.main()
