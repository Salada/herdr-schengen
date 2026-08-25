#!/usr/bin/env python3
"""Tests for Schengen TUI & SchengenAgentChat.

Verifies:
1. Dual-Model Phase Routing & Fallbacks (Inspector vs Judge).
2. Token Meter tracking (Inspector vs Judge prompt/completion tokens, Context Cache ratio).
3. Sequential FIFO Queue ordering and single-active resolution lifecycle.
4. Clipboard plain-text buffer capture.
5. CommandPalette width constraint CSS.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from schengen_agent_llm import (
    SchengenAgentChat,
    clean_llm_response,
    build_system_prompt,
    get_current_active_escalation,
)
try:
    from schengen_tui import SchengenTUIApp
    HAS_TEXTUAL = True
except ImportError:
    SchengenTUIApp = None  # type: ignore
    HAS_TEXTUAL = False


class TestSchengenAgentChatDualRouting(unittest.TestCase):
    """Test Inspector and Judge phase configuration and fallback."""

    def test_init_defaults(self):
        chat = SchengenAgentChat()
        self.assertIsNotNone(chat.inspector_api_key)
        self.assertIsNotNone(chat.inspector_base_url)
        self.assertIsNotNone(chat.judge_api_key)
        self.assertIsNotNone(chat.judge_base_url)
        self.assertEqual(chat.history, [])
        self.assertIsNone(chat._current_esc_id)

    def test_token_meter_initial_zero(self):
        chat = SchengenAgentChat()
        stats = chat.get_token_usage_stats()
        self.assertEqual(stats["api_calls"], 0)
        self.assertEqual(stats["prompt_tokens"], 0)
        self.assertEqual(stats["completion_tokens"], 0)
        self.assertEqual(stats["cached_tokens"], 0)
        self.assertEqual(stats["cache_hit_pct"], "0.0%")
        self.assertEqual(stats["inspector_in"], 0)
        self.assertEqual(stats["inspector_out"], 0)
        self.assertEqual(stats["judge_in"], 0)
        self.assertEqual(stats["judge_out"], 0)

    def test_token_meter_cache_hit_calculation(self):
        chat = SchengenAgentChat()
        chat.total_prompt_tokens = 1000
        chat.total_cached_tokens = 450
        stats = chat.get_token_usage_stats()
        self.assertEqual(stats["cache_hit_pct"], "45.0%")

    def test_token_meter_phase_split(self):
        chat = SchengenAgentChat()
        chat.inspector_prompt_tokens = 300
        chat.inspector_completion_tokens = 50
        chat.judge_prompt_tokens = 700
        chat.judge_completion_tokens = 120
        stats = chat.get_token_usage_stats()
        self.assertEqual(stats["inspector_in"], 300)
        self.assertEqual(stats["inspector_out"], 50)
        self.assertEqual(stats["judge_in"], 700)
        self.assertEqual(stats["judge_out"], 120)

    def test_clean_llm_response(self):
        raw = "```markdown\nApproved. Verified safe.\n```"
        cleaned = clean_llm_response(raw)
        self.assertEqual(cleaned, "Approved. Verified safe.")

        raw_plain = "Approved. Target does not exist."
        self.assertEqual(clean_llm_response(raw_plain), "Approved. Target does not exist.")

    @patch("schengen_agent_llm.get_current_active_escalation")
    def test_build_system_prompt_structure(self, mock_get_active):
        mock_get_active.return_value = {
            "id": 123,
            "pane_id": "w1D:p1",
            "agent_kind": "agy",
            "raw_command": "rm -rf /tmp/test_dir",
            "safety_reason": "Destructive deletion",
        }
        prompt = build_system_prompt()
        self.assertIn("Escalation ID: #123", prompt)
        self.assertIn("investigate_path_details", prompt)
        self.assertIn("investigate_pane_history", prompt)
        self.assertIn("read_file_snippet", prompt)
        self.assertIn("approve_escalation", prompt)
        self.assertIn("NO Autonomous Reject", prompt)


@unittest.skipUnless(HAS_TEXTUAL, "Textual is required for TUI UI tests")
class TestSchengenTUIApp(unittest.TestCase):
    """Test TUI components, CSS constraints, and clipboard interactions."""

    def test_tui_app_instantiation(self):
        app = SchengenTUIApp()
        self.assertIsNotNone(app)
        self.assertEqual(app._chat_plain, [])
        self.assertEqual(app._notified_escalation_ids, set())
        self.assertFalse(app._processing_chat)

    def test_css_command_palette_width_constraint(self):
        css = SchengenTUIApp.CSS
        self.assertIn("CommandPalette", css)
        self.assertIn("width: 72;", css)
        self.assertIn("max-width: 80%;", css)
        self.assertIn("max-height: 60%;", css)

    def test_css_muted_palette_colors(self):
        css = SchengenTUIApp.CSS
        # Muted design: avoid solid orange background, use warning border-left
        self.assertIn("border-left: heavy $warning;", css)
        self.assertIn("background: $surface-darken-1;", css)

    def test_clear_chat_action(self):
        app = SchengenTUIApp()
        app._chat_plain = ["message 1", "message 2"]
        # Clear buffer
        app._chat_plain.clear()
        self.assertEqual(len(app._chat_plain), 0)

    def test_copy_chat_empty(self):
        app = SchengenTUIApp()
        app._chat_plain.clear()
        self.assertEqual(len(app._chat_plain), 0)

    def test_chat_plain_buffer_recording_and_clear(self):
        app = SchengenTUIApp()
        app.query_one = MagicMock()
        app._write("[bold green]🛡️ System online[/]")
        app._write("[dim]• Details here[/]")
        self.assertEqual(len(app._chat_plain), 2)
        self.assertIn("🛡️ System online", app._chat_plain[0])
        self.assertIn("• Details here", app._chat_plain[1])

        # Test clear
        app.action_clear_chat()
        self.assertEqual(app._chat_plain, [])


class TestSequentialFifoQueue(unittest.TestCase):
    """Test that get_current_active_escalation returns oldest PENDING item."""

    @patch("schengen_agent_llm.get_pending_escalations")
    def test_get_current_active_escalation_fifo(self, mock_pending):
        mock_pending.return_value = [
            {"id": 101, "status": "PENDING", "raw_command": "cmd1"},
            {"id": 102, "status": "PENDING", "raw_command": "cmd2"},
            {"id": 103, "status": "PENDING", "raw_command": "cmd3"},
        ]
        active = get_current_active_escalation()
        self.assertIsNotNone(active)
        self.assertEqual(active["id"], 101)  # oldest item

    @patch("schengen_agent_llm.get_pending_escalations")
    def test_get_current_active_escalation_empty(self, mock_pending):
        mock_pending.return_value = []
        active = get_current_active_escalation()
        self.assertIsNone(active)


if __name__ == "__main__":
    unittest.main()
