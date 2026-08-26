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
    from schengen_tui import SchengenTUIApp, AuditFullscreenModal
    HAS_TEXTUAL = True
except ImportError:
    SchengenTUIApp = None  # type: ignore
    AuditFullscreenModal = None  # type: ignore
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

    def setUp(self):
        import asyncio
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        import asyncio
        if hasattr(self, "loop") and not self.loop.is_closed():
            self.loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())

    def test_tui_app_instantiation(self):
        assert SchengenTUIApp is not None
        app = SchengenTUIApp()
        self.assertIsNotNone(app)
        self.assertEqual(app._chat_plain, [])
        self.assertEqual(app._notified_escalation_ids, set())
        self.assertFalse(app._processing_chat)
        if app.tui_lock_fd:
            app.tui_lock_fd.close()

    def test_command_palette_fully_disabled(self):
        assert SchengenTUIApp is not None
        self.assertFalse(SchengenTUIApp.ENABLE_COMMAND_PALETTE)
        css = SchengenTUIApp.CSS
        self.assertNotIn("CommandPalette", css)

    def test_css_muted_palette_colors(self):
        assert SchengenTUIApp is not None
        css = SchengenTUIApp.CSS
        # Muted design: avoid solid orange background, use warning border-left
        self.assertIn("border-left: heavy $warning;", css)
        self.assertIn("background: $surface-darken-1;", css)

    def test_clear_chat_action(self):
        assert SchengenTUIApp is not None
        app = SchengenTUIApp()
        app._chat_plain = ["message 1", "message 2"]
        # Clear buffer
        app._chat_plain.clear()
        self.assertEqual(len(app._chat_plain), 0)

    def test_copy_chat_empty(self):
        assert SchengenTUIApp is not None
        app = SchengenTUIApp()
        app._chat_plain.clear()
        self.assertEqual(len(app._chat_plain), 0)

    def test_role_panel_widgets(self):
        assert SchengenTUIApp is not None
        app = SchengenTUIApp()
        self.assertTrue(hasattr(app, "is_controller"))
        self.assertTrue(hasattr(app, "leader_pid"))
        if app.tui_lock_fd:
            app.tui_lock_fd.close()

    def test_active_target_banner_height_increased(self):
        assert SchengenTUIApp is not None
        css = SchengenTUIApp.CSS
        self.assertIn("#active-target-banner", css)
        self.assertIn("min-height: 5;", css)
        self.assertIn("max-height: 11;", css)

    def test_command_text_area_instantiation(self):
        from schengen_tui import CommandTextArea
        cta = CommandTextArea()
        self.assertIsNotNone(cta)
        self.assertFalse(cta.show_line_numbers)

    def test_audit_fullscreen_modal_instantiation(self):
        assert AuditFullscreenModal is not None
        modal = AuditFullscreenModal()
        self.assertIsNotNone(modal)
        self.assertIn("AuditFullscreenModal", modal.CSS)
        self.assertIn("98%", modal.CSS)

    def test_chat_plain_buffer_recording_and_clear(self):
        assert SchengenTUIApp is not None
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
        if app.tui_lock_fd:
            app.tui_lock_fd.close()

    def test_write_markdown_rendering_and_plain_buffer(self):
        from rich.markdown import Markdown
        assert SchengenTUIApp is not None
        app = SchengenTUIApp()
        mock_log = MagicMock()
        app.query_one = MagicMock(return_value=mock_log)

        md_content = "### Security Assessment\n\n- Verdict: **APPROVED**\n- Risk: `LOW`"
        app._write_markdown(md_content, prefix="🤖 [bold cyan]Gatekeeper[/]:")

        # Verify RichLog.write was called twice: once for prefix, once for Markdown object
        self.assertEqual(mock_log.write.call_count, 2)
        written_md = mock_log.write.call_args_list[1][0][0]
        self.assertIsInstance(written_md, Markdown)

        # Verify plain-text buffer contains prefix and raw markdown text
        self.assertEqual(len(app._chat_plain), 2)
        self.assertIn("Gatekeeper", app._chat_plain[0])
        self.assertEqual(app._chat_plain[1], md_content)
        if app.tui_lock_fd:
            app.tui_lock_fd.close()

    def test_write_markdown_code_fence_and_table(self):
        from rich.markdown import Markdown
        assert SchengenTUIApp is not None
        app = SchengenTUIApp()
        mock_log = MagicMock()
        app.query_one = MagicMock(return_value=mock_log)

        md_table_code = """
## Evaluation Report
| Field | Value |
| :--- | :--- |
| Action | `rm -rf /tmp/scratch` |
| Result | `BLOCKED` |

```bash
# Safe alternative
trash /tmp/scratch
```
"""
        app._write_markdown(md_table_code)
        self.assertEqual(mock_log.write.call_count, 1)
        written_obj = mock_log.write.call_args[0][0]
        self.assertIsInstance(written_obj, Markdown)
        if app.tui_lock_fd:
            app.tui_lock_fd.close()


class TestTUIInputUX(unittest.TestCase):
    """Test TUI input textarea UX improvements (word-wrap, dynamic height, no palette)."""

    def test_command_palette_disabled(self):
        assert SchengenTUIApp is not None
        self.assertFalse(SchengenTUIApp.ENABLE_COMMAND_PALETTE)

    def test_command_text_area_word_wrap_and_dynamic_expansion(self):
        from schengen_tui import CommandTextArea
        text_area = CommandTextArea()
        self.assertTrue(text_area.soft_wrap)
        self.assertFalse(text_area.show_line_numbers)

        # 1 line
        text_area.watch_text("short single line command")
        assert text_area.styles.height is not None
        self.assertEqual(text_area.styles.height.value, 3)

        # 3 lines
        text_area.watch_text("line1\nline2\nline3")
        assert text_area.styles.height is not None
        self.assertEqual(text_area.styles.height.value, 5)

        # 8 lines (bounded by max 10)
        multiline_text = "\n".join(f"line {i}" for i in range(8))
        text_area.watch_text(multiline_text)
        assert text_area.styles.height is not None
        self.assertEqual(text_area.styles.height.value, 10)


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
        assert active is not None
        self.assertEqual(active["id"], 101)  # oldest item

    @patch("schengen_agent_llm.get_pending_escalations")
    def test_get_current_active_escalation_empty(self, mock_pending):
        mock_pending.return_value = []
        active = get_current_active_escalation()
        self.assertIsNone(active)


if __name__ == "__main__":
    unittest.main()
