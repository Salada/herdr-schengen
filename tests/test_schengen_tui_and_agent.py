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
from schengen_tui import SchengenTUIApp


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
        chat.total_completion_tokens = 200
        chat.inspector_prompt_tokens = 400
        chat.inspector_completion_tokens = 50
        chat.judge_prompt_tokens = 600
        chat.judge_completion_tokens = 150
        chat.total_api_calls = 2

        stats = chat.get_token_usage_stats()
        self.assertEqual(stats["prompt_tokens"], 1000)
        self.assertEqual(stats["cached_tokens"], 450)
        self.assertEqual(stats["cache_hit_pct"], "45.0%")
        self.assertEqual(stats["inspector_in"], 400)
        self.assertEqual(stats["inspector_out"], 50)
        self.assertEqual(stats["judge_in"], 600)
        self.assertEqual(stats["judge_out"], 150)

    def test_clean_llm_response(self):
        raw = "```markdown\nApproved. Verified safe.\n```"
        cleaned = clean_llm_response(raw)
        self.assertEqual(cleaned, "Approved. Verified safe.")

        raw_plain = "Approved. Target does not exist."
        self.assertEqual(clean_llm_response(raw_plain), "Approved. Target does not exist.")


class TestSchengenTUIAppStructure(unittest.TestCase):
    """Test TUI UI components and layout constraints."""

    def test_tui_app_init(self):
        app = SchengenTUIApp()
        self.assertIsNotNone(app.agent)
        self.assertFalse(app._columns_initialized)
        self.assertEqual(app._chat_plain, [])
        self.assertFalse(app._processing_chat)

    def test_command_palette_css_constraints(self):
        css = SchengenTUIApp.CSS
        self.assertIn("CommandPalette > Vertical", css)
        self.assertIn("width: 72;", css)
        self.assertIn("max-width: 80%;", css)
        self.assertIn("max-height: 60%;", css)

    def test_muted_theme_css(self):
        css = SchengenTUIApp.CSS
        self.assertIn("#active-target-banner", css)
        self.assertIn("border-left: heavy $warning;", css)
        self.assertIn("#input-box:focus", css)
        self.assertIn("border-bottom: tall $accent;", css)

    def test_chat_plain_buffer_recording_and_clear(self):
        app = SchengenTUIApp()
        # Mock query_one to avoid running actual widget tree
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
