#!/usr/bin/env python3
"""Deterministic, evidence-preserving context compaction tests."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from core.redaction import redact_for_cloud
from core.gatekeeper_telemetry import GatekeeperTimeline
from tools.schengen_agent_llm import (
    COMPACTION_HEAD_EXCERPT_CHARS,
    COMPACTION_TAIL_EXCERPT_CHARS,
    COMPACTION_TOOL_RESULT_THRESHOLD,
    COMPACTION_TRIGGER_TOTAL_CHARS,
    SchengenAgentChat,
    _canonical_prompt_bytes,
    _compact_latest_complete_tool_round,
    _compact_tool_observations,
    _message_chars,
    _secure_append_session_line,
    _sweep_old_session_logs,
    _trusted_session_directory,
    _trusted_session_file,
)
from tools import schengen_agent_llm


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
    def test_conservative_defaults(self):
        self.assertEqual(COMPACTION_TRIGGER_TOTAL_CHARS, 12_000)
        self.assertEqual(COMPACTION_TOOL_RESULT_THRESHOLD, 1_000)
        self.assertEqual(COMPACTION_HEAD_EXCERPT_CHARS, 300)
        self.assertEqual(COMPACTION_TAIL_EXCERPT_CHARS, 300)

    def test_total_threshold_boundary(self):
        messages = [{"role": "system", "content": ""}]
        messages.extend(_round("old", "A" * (COMPACTION_TOOL_RESULT_THRESHOLD + 1)))
        messages.extend(_round("latest", "latest"))
        padding = COMPACTION_TRIGGER_TOTAL_CHARS - _message_chars(messages)
        self.assertGreaterEqual(padding, 0)
        messages[0]["content"] = "S" * padding
        self.assertEqual(_message_chars(messages), COMPACTION_TRIGGER_TOTAL_CHARS)

        compacted, stats = _compact_tool_observations(messages)
        self.assertIs(compacted, messages)
        self.assertEqual(stats["compacted_tool_results"], 0)

        messages[0]["content"] += "S"
        compacted, stats = _compact_tool_observations(messages)
        self.assertIsNot(compacted, messages)
        self.assertEqual(stats["compacted_tool_results"], 1)

    def test_tool_result_threshold_boundary(self):
        messages = [{"role": "system", "content": ""}]
        messages.extend(_round("at-limit", "A" * COMPACTION_TOOL_RESULT_THRESHOLD))
        messages.extend(_round("over-limit", "B" * (COMPACTION_TOOL_RESULT_THRESHOLD + 1)))
        messages.extend(_round("latest", "latest"))
        padding = COMPACTION_TRIGGER_TOTAL_CHARS + 1 - _message_chars(messages)
        self.assertGreaterEqual(padding, 0)
        messages[0]["content"] = "S" * padding

        compacted, stats = _compact_tool_observations(messages)

        self.assertEqual(compacted[2], messages[2])
        self.assertTrue(json.loads(compacted[4]["content"])["_compacted"])
        self.assertEqual(stats["compacted_tool_results"], 1)

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

    def test_compacted_output_is_idempotent(self):
        messages = _large_messages()
        compacted, _ = _compact_tool_observations(messages)
        compacted_again, stats = _compact_tool_observations(compacted)

        self.assertIs(compacted_again, compacted)
        self.assertEqual(stats["compacted_tool_results"], 0)

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

        chat = SchengenAgentChat(api_key="test")
        self.assertIs(chat._compact_messages_for_request(messages), messages)
        self.assertEqual(
            chat.get_token_usage_stats()["compaction_last_warning"],
            "latest_tool_round_exceeds_compaction_budget",
        )

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
            Path(tmpdir).chmod(0o700)
            chat = SchengenAgentChat(api_key="test")
            chat.log_file = Path(tmpdir) / "session.jsonl"
            chat._append_transcript(role="tool", content=raw)
            compacted = chat._compact_messages_for_request(messages)
            transcript = chat.log_file.read_text(encoding="utf-8")

        self.assertIn(raw, transcript)
        self.assertNotIn(raw, compacted[2]["content"])
        self.assertEqual(chat.compaction_events, 1)
        self.assertGreater(chat.compaction_chars_saved, 0)

    def test_latest_round_compacts_every_result_atomically(self):
        messages = _large_messages()
        stage1, _ = _compact_tool_observations(messages)
        compacted, stats = _compact_latest_complete_tool_round(stage1)

        self.assertEqual(stats["compacted_tool_results"], 2)
        self.assertEqual(compacted[-4], messages[-4])
        self.assertEqual(compacted[-1], messages[-1])
        for original, replacement in zip(messages[-3:-1], compacted[-3:-1]):
            record = json.loads(replacement["content"])
            content = original["content"]
            self.assertEqual(record["tool_call_id"], original["tool_call_id"])
            self.assertEqual(record["original_byte_count"], len(content.encode("utf-8")))
            self.assertEqual(record["sha256"], hashlib.sha256(content.encode("utf-8")).hexdigest())
            self.assertEqual(record["head_excerpt"], content[:300])
            self.assertEqual(record["tail_excerpt"], content[-300:])

    def test_latest_round_excerpts_are_redacted_and_scalar_status_is_retained(self):
        secret = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
        content = json.dumps({
            "status": "ok",
            "output": f"Authorization: Bearer {secret}\n" + "Z" * 2_000,
        })
        messages = [{"role": "system", "content": "guard"}, *_round("latest", content)]
        compacted, _ = _compact_latest_complete_tool_round(messages)
        record = json.loads(compacted[-1]["content"])
        self.assertEqual(record["status"], "ok")
        self.assertNotIn(secret, record["head_excerpt"] + record["tail_excerpt"])

    def test_latest_round_malformed_relationship_is_zero_change(self):
        messages = _large_messages()
        messages[-2]["tool_call_id"] = "wrong"
        compacted, stats = _compact_latest_complete_tool_round(messages)
        self.assertIs(compacted, messages)
        self.assertEqual(stats["compacted_tool_results"], 0)
        self.assertEqual(stats["error"], "MALFORMED_TOOL_RELATIONSHIP")

    def test_adversarial_multi_tool_corpus_reduces_bytes_and_estimate_by_40_percent(self):
        messages = _large_messages(old_size=10_000, latest_size=8_000)
        before = len(_canonical_prompt_bytes(messages))
        stage1, _ = _compact_tool_observations(messages, allow_oversized_latest=True)
        stage2, _ = _compact_latest_complete_tool_round(stage1)
        after = len(_canonical_prompt_bytes(stage2))
        before_estimate = before
        after_estimate = after

        self.assertGreaterEqual(1 - after / before, 0.40)
        # Cold estimation is intentionally one token per canonical UTF-8 byte.
        self.assertGreaterEqual(1 - after_estimate / before_estimate, 0.40)

    def test_phase_budget_formula_estimator_and_headroom_are_isolated(self):
        env = {
            "SCHENGEN_INSPECTOR_CONTEXT_WINDOW": "20000",
            "SCHENGEN_JUDGE_CONTEXT_WINDOW": "300000",
        }
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, env, clear=False):
            chat = SchengenAgentChat(api_key="test", sessions_dir=Path(tmpdir))
        stats = chat.get_token_usage_stats()
        self.assertEqual(stats["inspector_context_window_tokens"], 20_000)
        self.assertEqual(stats["inspector_effective_input_cap_tokens"], 15_904)
        self.assertEqual(stats["judge_effective_input_cap_tokens"], 262_144)
        self.assertEqual(stats["inspector_context_budget_state"], "configured")

        chat._context_budget["inspector"]["samples"] = [(1_000, 600), (1_200, 900)]
        self.assertEqual(chat._estimate_input_tokens("inspector", 1_500), 1_200)
        self.assertEqual(chat._estimate_input_tokens("judge", 1_500), 1_500)
        self.assertEqual(chat._growth_headroom("inspector"), 3_976)
        self.assertEqual(chat._growth_headroom("judge"), 4_096)
        chat._context_budget["inspector"]["effective_input_cap_tokens"] = 4_096
        chat._context_budget["inspector"]["samples"] = [(100, 100), (200, 2_000)]
        chat._context_budget["inspector"]["positive_prompt_deltas"] = [1_900]
        self.assertEqual(chat._growth_headroom("inspector"), 1_900)

    def test_growth_headroom_retains_last_four_positive_deltas(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {
            "SCHENGEN_INSPECTOR_CONTEXT_WINDOW": "8192",
        }):
            chat = SchengenAgentChat(api_key="test", sessions_dir=Path(tmpdir))
            for prompt_tokens in (100, 2_100, 2_000, 5_000, 4_000, 8_000, 13_000):
                chat._context_budget["inspector"]["prepared_payload_bytes"] = 20_000
                chat._record_context_usage("inspector", prompt_tokens)
        self.assertEqual(
            chat._context_budget["inspector"]["positive_prompt_deltas"],
            [2_000, 3_000, 4_000, 5_000],
        )
        self.assertEqual(chat._growth_headroom("inspector"), 5_000)

    def test_configured_budget_runs_stage1_then_atomic_stage2(self):
        messages = _large_messages(old_size=25_000, latest_size=8_000)
        stage1, _ = _compact_tool_observations(messages, allow_oversized_latest=True)
        stage2, _ = _compact_latest_complete_tool_round(stage1)
        stage1_bytes = len(_canonical_prompt_bytes(stage1))
        stage2_bytes = len(_canonical_prompt_bytes(stage2))
        self.assertLess(stage2_bytes, stage1_bytes)

        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {
            "SCHENGEN_INSPECTOR_CONTEXT_WINDOW": "300000",
        }):
            chat = SchengenAgentChat(api_key="test", sessions_dir=Path(tmpdir))
            headroom = chat._growth_headroom("inspector")
            chat._context_budget["inspector"]["effective_input_cap_tokens"] = stage2_bytes + headroom
            prepared, error = chat._prepare_context_request("inspector", messages, None, None)

        self.assertIsNone(error)
        self.assertEqual(prepared, stage2)
        self.assertEqual(
            chat.get_token_usage_stats()["inspector_context_budget_state"],
            "stage2_compacted",
        )

    def test_configured_budget_reports_stage1_compaction(self):
        messages = _large_messages(old_size=25_000, latest_size=4_000)
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {
            "SCHENGEN_INSPECTOR_CONTEXT_WINDOW": "300000",
        }):
            chat = SchengenAgentChat(api_key="test", sessions_dir=Path(tmpdir))
            prepared, error = chat._prepare_context_request("inspector", messages, None, None)
        self.assertIsNone(error)
        self.assertIsNot(prepared, messages)
        self.assertEqual(
            chat.get_token_usage_stats()["inspector_context_budget_state"],
            "stage1_compacted",
        )

    def test_missing_and_invalid_context_windows_disable_independently(self):
        with patch.dict(os.environ, {
            "SCHENGEN_INSPECTOR_CONTEXT_WINDOW": "8192",
            "SCHENGEN_JUDGE_CONTEXT_WINDOW": "٨١٩٢",
        }, clear=False), tempfile.TemporaryDirectory() as tmpdir:
            chat = SchengenAgentChat(api_key="test", sessions_dir=Path(tmpdir))
        stats = chat.get_token_usage_stats()
        self.assertEqual(stats["inspector_effective_input_cap_tokens"], 4096)
        self.assertEqual(stats["judge_context_window_tokens"], 0)
        self.assertEqual(stats["judge_context_budget_state"], "disabled_invalid")

        with patch.dict(os.environ, {}, clear=False), tempfile.TemporaryDirectory() as tmpdir:
            os.environ.pop("SCHENGEN_INSPECTOR_CONTEXT_WINDOW", None)
            os.environ.pop("SCHENGEN_JUDGE_CONTEXT_WINDOW", None)
            missing = SchengenAgentChat(api_key="test", sessions_dir=Path(tmpdir))
        self.assertEqual(
            missing.get_token_usage_stats()["inspector_context_budget_state"],
            "disabled_missing",
        )

    def test_context_window_invalid_matrix(self):
        for value in ("8191", " 8192", "+8192", "8192 ", "8192.0", "12345678901", "٨١٩٢"):
            with self.subTest(value=value), patch.dict(os.environ, {
                "SCHENGEN_INSPECTOR_CONTEXT_WINDOW": value,
            }):
                chat = SchengenAgentChat(api_key="test", sessions_dir=Path(tempfile.gettempdir()))
                stats = chat.get_token_usage_stats()
                self.assertEqual(stats["inspector_context_window_tokens"], 0)
                self.assertEqual(stats["inspector_effective_input_cap_tokens"], 0)
                self.assertEqual(stats["inspector_context_budget_state"], "disabled_invalid")

    def test_context_window_is_read_once_per_chat_process(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {
            "SCHENGEN_INSPECTOR_CONTEXT_WINDOW": "10000",
            "SCHENGEN_JUDGE_CONTEXT_WINDOW": "20000",
        }):
            chat = SchengenAgentChat(api_key="test", sessions_dir=Path(tmpdir))
            os.environ["SCHENGEN_INSPECTOR_CONTEXT_WINDOW"] = "99999"
            os.environ["SCHENGEN_JUDGE_CONTEXT_WINDOW"] = "99999"
            stats = chat.get_token_usage_stats()
        self.assertEqual(stats["inspector_context_window_tokens"], 10_000)
        self.assertEqual(stats["judge_context_window_tokens"], 20_000)

    def test_context_cap_terminal_reason_is_validated(self):
        loaded = {
            "escalation_id": 259,
            "correlation_id": "a" * 32,
            "events": [],
            "terminal": {
                "at_monotonic_ns": 10,
                "outcome": "deferred",
                "reason": "context_cap_exceeded",
                "completion_state": "truncated",
            },
        }
        clean = GatekeeperTimeline._sanitized_data(259, loaded)
        self.assertEqual(clean["terminal"], loaded["terminal"])


class TestSessionRetention(unittest.TestCase):
    def setUp(self):
        schengen_agent_llm._last_session_sweep_monotonic = None

    def test_secure_append_rejects_symlink_and_permissive_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            directory.chmod(0o700)
            target = directory / "target"
            target.write_text("unchanged", encoding="utf-8")
            target.chmod(0o600)
            link = directory / "session_link.jsonl"
            link.symlink_to(target)
            self.assertFalse(_secure_append_session_line(link, b"bad\n"))
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")

            unsafe = directory / "session_unsafe.jsonl"
            unsafe.write_text("unchanged", encoding="utf-8")
            unsafe.chmod(0o644)
            self.assertFalse(_secure_append_session_line(unsafe, b"bad\n"))
            self.assertEqual(unsafe.stat().st_mode & 0o777, 0o644)

            created = directory / "session_created.jsonl"
            self.assertTrue(_secure_append_session_line(created, b"ok\n"))
            self.assertEqual(created.read_bytes(), b"ok\n")
            self.assertEqual(created.stat().st_mode & 0o777, 0o600)

    def test_trust_checks_reject_wrong_uid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            directory.chmod(0o700)
            transcript = directory / "session_owned.jsonl"
            transcript.write_text("data", encoding="utf-8")
            transcript.chmod(0o600)
            with patch("tools.schengen_agent_llm.os.getuid", return_value=os.getuid() + 1):
                self.assertFalse(_trusted_session_directory(directory))
                self.assertFalse(_trusted_session_file(transcript))

    def test_retention_removes_only_trusted_exact_old_logs_and_throttles(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            directory.chmod(0o700)
            now = time.time()
            old = directory / "session_old.jsonl"
            old.write_text("old", encoding="utf-8")
            old.chmod(0o600)
            os.utime(old, (now - 31 * 86_400, now - 31 * 86_400))
            unrelated = directory / "other.jsonl"
            unrelated.write_text("keep", encoding="utf-8")
            unrelated.chmod(0o600)
            unsafe = directory / "session_unsafe.jsonl"
            unsafe.write_text("keep", encoding="utf-8")
            unsafe.chmod(0o644)
            os.utime(unsafe, (0, 0))
            boundary = directory / "session_boundary.jsonl"
            boundary.write_text("keep", encoding="utf-8")
            boundary.chmod(0o600)
            os.utime(boundary, (now - 30 * 86_400, now - 30 * 86_400))

            self.assertEqual(
                _sweep_old_session_logs(directory, wall_time=now, monotonic_time=10), 1
            )
            self.assertFalse(old.exists())
            self.assertTrue(unrelated.exists())
            self.assertTrue(unsafe.exists())
            self.assertTrue(boundary.exists())

            later_old = directory / "session_later.jsonl"
            later_old.write_text("old", encoding="utf-8")
            later_old.chmod(0o600)
            os.utime(later_old, (now - 31 * 86_400, now - 31 * 86_400))
            self.assertEqual(
                _sweep_old_session_logs(directory, wall_time=now, monotonic_time=11), 0
            )
            self.assertTrue(later_old.exists())
            self.assertEqual(
                _sweep_old_session_logs(directory, wall_time=now, monotonic_time=86_411), 1
            )
            self.assertFalse(later_old.exists())

    def test_retention_rejects_unsafe_directory_without_repair(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            directory.chmod(0o755)
            old = directory / "session_old.jsonl"
            old.write_text("old", encoding="utf-8")
            old.chmod(0o600)
            os.utime(old, (0, 0))
            self.assertEqual(
                _sweep_old_session_logs(directory, wall_time=time.time(), monotonic_time=1), 0
            )
            self.assertTrue(old.exists())
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)

    def test_retention_rejects_symlink_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            real = root / "real"
            real.mkdir(mode=0o700)
            old = real / "session_old.jsonl"
            old.write_text("old", encoding="utf-8")
            old.chmod(0o600)
            os.utime(old, (0, 0))
            link = root / "sessions"
            link.symlink_to(real, target_is_directory=True)
            self.assertEqual(
                _sweep_old_session_logs(link, wall_time=time.time(), monotonic_time=1), 0
            )
            self.assertTrue(old.exists())


if __name__ == "__main__":
    unittest.main()
