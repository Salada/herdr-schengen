#!/usr/bin/env python3
"""Tests for Schengen TUI & SchengenAgentChat.

Verifies:
1. Dual-Model Phase Routing & Fallbacks (Inspector vs Judge).
2. Token Meter tracking (Inspector vs Judge prompt/completion tokens, Context Cache ratio).
3. Sequential FIFO Queue ordering and single-active resolution lifecycle.
4. Clipboard plain-text buffer capture.
5. CommandPalette width constraint CSS.
"""

import json
import os
import sys
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from tools.schengen_agent_llm import (
    SchengenAgentChat,
    clean_llm_response,
    build_system_prompt,
    get_current_active_escalation,
)
try:
    import asyncio
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    from cmd.schengen_tui import SchengenTUIApp, AuditFullscreenModal
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

        # Broken DeepSeek DSML / XML tag leak regression test
        raw_dsml_leak = """~/code/herdr-schengen/scripts/tools/schengen_agent_llm.py</｜｜DSML｜｜parameter>
</｜｜DSML｜｜invoke>

~/code/herdr-schengen/scripts/herdr_client.py</｜｜DSML｜｜parameter>
</｜｜DSML｜｜invoke>

<｜tool_calls｜><｜tool_call｜>investigate_path_details<｜/tool_call｜></｜tool_calls｜>
</｜｜DSML｜｜tool_calls>
Approved. All files verified safely."""
        cleaned_dsml = clean_llm_response(raw_dsml_leak)
        self.assertNotIn("DSML", cleaned_dsml)
        self.assertNotIn("parameter", cleaned_dsml)
        self.assertNotIn("invoke", cleaned_dsml)
        self.assertNotIn("tool_calls", cleaned_dsml)
        self.assertIn("Approved. All files verified safely.", cleaned_dsml)

    def test_format_tool_call_beautified(self):
        from tools.schengen_agent_llm import format_tool_call_beautified
        # 1. Path check
        s1 = format_tool_call_beautified("investigate_path_details", {"target_path": "~/code/file.py"})
        self.assertIn("🔍 **[Path Check]**", s1)
        self.assertIn("~/code/file.py", s1)

        # 2. Pane buffer
        s2 = format_tool_call_beautified("investigate_pane_history", {"pane_id": "w1D:p1", "lines": 100, "full_dump": True})
        self.assertIn("📜 **[Pane Buffer]**", s2)
        self.assertIn("scrollback", s2)

        # 3. File read
        s3 = format_tool_call_beautified("read_file_snippet", {"target_path": "TODO.md"})
        self.assertIn("📄 **[File Read]**", s3)

        # 4. Approval
        s4 = format_tool_call_beautified("approve_escalation", {"escalation_id": 42, "english_feedback": "Approved."})
        self.assertIn("✅ **[Auto Approve]**", s4)
        self.assertIn("#42", s4)

        # 5. Reject
        s5 = format_tool_call_beautified("reject_escalation", {"escalation_id": 42, "english_feedback": "Critical risk."})
        self.assertIn("🛑 **[Action Reject]**", s5)

    @patch("tools.schengen_agent_llm.get_current_active_escalation")
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
        self.assertIn("AGY Worker Context", prompt)

    @patch("tools.schengen_agent_llm.get_current_active_escalation")
    def test_build_system_prompt_language_directive(self, mock_get_active):
        mock_get_active.return_value = {
            "id": 123,
            "pane_id": "w1D:p1",
            "agent_kind": "agy",
            "raw_command": "rm -rf /tmp/test_dir",
            "safety_reason": "Destructive deletion",
        }
        en = build_system_prompt(language="english")
        self.assertIn("concise professional English", en)
        ko = build_system_prompt(language="korean")
        self.assertIn("간결하고 건조한 한국어", ko)
        ja = build_system_prompt(language="japanese")
        self.assertIn("簡潔で淡々とした日本語", ja)
        # herdr instruction (english_feedback) must remain English regardless of language.
        self.assertIn("english_feedback", ko)
        self.assertIn("professional English", ko)

    @patch("tools.schengen_agent_llm.get_pane_text")
    def test_investigate_pane_history_full_dump(self, mock_get_pane):
        from tools.schengen_agent_llm import execute_tool_call
        mock_get_pane.return_value = "multiline script line 1\nmultiline script line 2\n"
        
        result_json = execute_tool_call("investigate_pane_history", {
            "pane_id": "w1D:p1",
            "lines": 150,
            "full_dump": True,
        })
        parsed = json.loads(result_json)
        self.assertEqual(parsed["pane_id"], "w1D:p1")
        self.assertEqual(parsed["lines_read"], 150)
        self.assertTrue(parsed["full_dump"])
        self.assertIn("multiline script line 1", parsed["pane_text_snippet"])
        mock_get_pane.assert_called_once_with("w1D:p1", lines=150, full_dump=True)


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

    def test_chat_timestamp_date_only_on_day_change(self):
        assert SchengenTUIApp is not None
        app = SchengenTUIApp()
        try:
            with patch("cmd.schengen_tui.datetime") as mock_dt:
                mock_dt.now.return_value = datetime(2026, 8, 29, 14, 5, 30)
                ts1 = app._timestamp()
                self.assertIn("2026-08-29", ts1)  # first message of a new day -> date + time
                self.assertIn("14:05:30", ts1)

                mock_dt.now.return_value = datetime(2026, 8, 29, 15, 10, 0)
                ts2 = app._timestamp()
                self.assertNotIn("2026-08-29", ts2)  # same day -> time only
                self.assertIn("15:10:00", ts2)

                mock_dt.now.return_value = datetime(2026, 8, 30, 9, 0, 0)
                ts3 = app._timestamp()
                self.assertIn("2026-08-30", ts3)  # new day -> date + time again
                self.assertIn("09:00:00", ts3)
        finally:
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

    def test_css_selection_visibility(self):
        assert SchengenTUIApp is not None
        css = SchengenTUIApp.CSS
        # Text selection must be an opaque bright-cyan block with black text.
        self.assertIn("Screen > .screen--selection", css)
        self.assertIn("background: #00FFFF;", css)
        self.assertIn("color: #000000;", css)

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
        from cmd.schengen_tui import CommandTextArea
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


@unittest.skipUnless(HAS_TEXTUAL, "Textual is required for TUI UI tests")
class TestTUIInputUX(unittest.TestCase):
    """Test TUI input textarea UX improvements (word-wrap, dynamic height, no palette)."""

    def setUp(self):
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

    def test_command_palette_disabled(self):
        assert SchengenTUIApp is not None
        self.assertFalse(SchengenTUIApp.ENABLE_COMMAND_PALETTE)

    def test_command_text_area_word_wrap_and_dynamic_expansion(self):
        from cmd.schengen_tui import CommandTextArea
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

    def test_chat_log_focusable(self):
        from cmd.schengen_tui import FocusableRichLog
        log_widget = FocusableRichLog()
        self.assertTrue(log_widget.can_focus)

    def test_slim_scrollbar_css(self):
        assert SchengenTUIApp is not None
        css = SchengenTUIApp.CSS
        self.assertIn("scrollbar-size-vertical: 1;", css)

    def test_inflight_input_retention_on_enter(self):
        from cmd.schengen_tui import CommandTextArea
        text_area = CommandTextArea()
        mock_app = MagicMock()
        mock_app._processing_chat = True
        setattr(text_area, "_app", mock_app)

        text_area.text = "inflight command to retain"
        event = MagicMock()
        event.key = "enter"
        event.name = "enter"
        text_area.on_key(event)

        # Inflight: text must NOT be erased
        self.assertEqual(text_area.text, "inflight command to retain")
        mock_app.notify.assert_called_once()


class TestSequentialFifoQueue(unittest.TestCase):
    """Test that get_current_active_escalation returns oldest PENDING item."""

    @patch("tools.schengen_agent_llm.get_pending_escalations")
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

    @patch("tools.schengen_agent_llm.get_pending_escalations")
    def test_get_current_active_escalation_empty(self, mock_pending):
        mock_pending.return_value = []
        active = get_current_active_escalation()
        self.assertIsNone(active)


class TestTUIControllerObserverMode(unittest.TestCase):
    """Test Controller and Observer role acquisition and permission segregation."""

    def test_controller_role_acquisition_and_toggle_permission(self):
        from cmd.schengen_tui import acquire_tui_role, SchengenTUIApp
        fd, is_controller, leader_pid = acquire_tui_role()
        try:
            if is_controller and fd:
                self.assertTrue(is_controller)
                self.assertIsNone(leader_pid)
                # Second attempt while lock is held must yield Observer role
                fd2, is_controller2, leader_pid2 = acquire_tui_role()
                try:
                    self.assertFalse(is_controller2)
                    self.assertEqual(leader_pid2, os.getpid())
                finally:
                    if fd2:
                        fd2.close()
        finally:
            if fd:
                fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_observer_toggle_daemon_rejected(self):
        from cmd.schengen_tui import SchengenTUIApp
        app = SchengenTUIApp()
        app.is_controller = False  # Force Observer
        msg = app.toggle_guard_daemon()
        self.assertIn("관찰자 모드", msg)
        if app.tui_lock_fd:
            app.tui_lock_fd.close()


class TestTUIFeatureAndSelection(unittest.IsolatedAsyncioTestCase):
    """Test /feature command execution and mouse text selection in TUI."""

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_feature_command_and_list_execution(self):
        from cmd.schengen_tui import SchengenTUIApp
        app = SchengenTUIApp()
        async with app.run_test() as pilot:
            w1 = app.process_user_chat("/feature TUI 알림 사운드 커스텀 --desc 볼륨 조절 지원 --priority HIGH")
            await w1.wait()
            await pilot.pause()
            
            w2 = app.process_user_chat("/features")
            await w2.wait()
            await pilot.pause()
            
            # Verify feature command response in chat plain buffer
            plain_text = "\n".join(app._chat_plain)
            self.assertIn("TUI 알림 사운드 커스텀", plain_text)
            self.assertIn("/features", plain_text)
            if app.tui_lock_fd:
                app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_chat_view_mouse_drag_selection(self):
        from cmd.schengen_tui import SchengenTUIApp, FocusableRichLog
        app = SchengenTUIApp()
        async with app.run_test() as pilot:
            chat = app.query_one("#chat-log", FocusableRichLog)
            chat.write("Selectable Schengen Audit Message Line 1\nLine 2")
            await pilot.pause()
            
            # Simulate mouse drag selection
            await pilot.mouse_down(chat, offset=(0, 0))
            await pilot.hover(chat, offset=(10, 0))
            await pilot.mouse_up(chat, offset=(10, 0))
            await pilot.pause()
            
            sel = app.screen.get_selected_text()
            self.assertIsNotNone(sel)
            self.assertTrue(len(sel) > 0)
            self.assertEqual(app.clipboard, sel)
            if app.tui_lock_fd:
                app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_selection_component_style_high_contrast(self):
        from cmd.schengen_tui import SchengenTUIApp
        app = SchengenTUIApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            st = app.screen.get_component_styles("screen--selection")
            self.assertEqual(st.color.hex, "#000000")
            self.assertEqual(st.background.hex, "#00FFFF")
            self.assertTrue(st.text_style.bold)
            if app.tui_lock_fd:
                app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_answer_language_radio_set(self):
        from cmd.schengen_tui import SchengenTUIApp
        from textual.widgets import RadioSet
        from unittest.mock import patch
        app = SchengenTUIApp()
        with patch("cmd.schengen_tui.get_answer_language", return_value="korean"):
            async with app.run_test() as pilot:
                await pilot.pause()
                radio_set = app.query_one("#answer-language-set", RadioSet)
                radios = list(radio_set.query("RadioButton"))
                self.assertEqual([r.id for r in radios], ["lang-english", "lang-korean", "lang-japanese"])
                # Default is korean.
                self.assertTrue(app.query_one("#lang-korean").value)
                self.assertFalse(app.query_one("#lang-english").value)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_audit_detail_modal_renders(self):
        from cmd.schengen_tui import SchengenTUIApp, AuditDetailModal
        app = SchengenTUIApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.push_screen(AuditDetailModal(999999999))
            await pilot.pause()
            self.assertIsInstance(app.screen, AuditDetailModal)
            detail = app.screen
            self.assertTrue(detail.query_one("#detail-fields"))
            self.assertTrue(detail.query_one("#detail-command"))
            self.assertTrue(detail.query_one("#detail-opinions"))
            if app.tui_lock_fd:
                app.tui_lock_fd.close()


class TestTUIInterruptAndDoubleESC(unittest.IsolatedAsyncioTestCase):
    """Test /interrupt command and double-ESC abort functionality."""

    def test_agent_cancel_flags(self):
        chat = SchengenAgentChat()
        self.assertFalse(chat._cancel_requested)
        chat.cancel()
        self.assertTrue(chat._cancel_requested)
        chat.reset_cancel()
        self.assertFalse(chat._cancel_requested)

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_interrupt_command_aborts_inflight(self):
        from cmd.schengen_tui import SchengenTUIApp
        app = SchengenTUIApp()
        async with app.run_test() as pilot:
            app._processing_chat = True
            w = app.process_user_chat("/interrupt /features")
            await w.wait()
            await pilot.pause()
            self.assertFalse(app._processing_chat)
            plain_text = "\n".join(app._chat_plain)
            self.assertIn("In-flight LLM call interrupted", plain_text)
            self.assertIn("/features", plain_text)
            if app.tui_lock_fd:
                app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_double_esc_aborts_inflight(self):
        from cmd.schengen_tui import SchengenTUIApp
        app = SchengenTUIApp()
        async with app.run_test() as pilot:
            app._processing_chat = True
            # First ESC: records timestamp
            first_esc_aborted = app.handle_esc_press()
            self.assertFalse(first_esc_aborted)
            self.assertTrue(app._processing_chat)
            
            # Second immediate ESC within 0.4s: triggers abort
            second_esc_aborted = app.handle_esc_press()
            self.assertTrue(second_esc_aborted)
            self.assertFalse(app._processing_chat)
            plain_text = "\n".join(app._chat_plain)
            self.assertIn("Double-ESC pressed", plain_text)
            if app.tui_lock_fd:
                app.tui_lock_fd.close()


class TestTUIAuditScrollAndModal(unittest.IsolatedAsyncioTestCase):
    """Test Recent Audits scroll disabling and Fullscreen Modal scroll configuration."""

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_audit_table_scroll_disabled(self):
        from cmd.schengen_tui import SchengenTUIApp, AuditDataTable
        app = SchengenTUIApp()
        async with app.run_test() as pilot:
            table = app.query_one("#audit-table", AuditDataTable)
            self.assertFalse(table.show_vertical_scrollbar)
            self.assertFalse(table.show_horizontal_scrollbar)
            self.assertFalse(table.show_cursor)
            if app.tui_lock_fd:
                app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_audit_table_selection_triggers_modal(self):
        from cmd.schengen_tui import SchengenTUIApp, AuditDataTable, AuditFullscreenModal
        app = SchengenTUIApp()
        async with app.run_test(size=(120, 40)) as pilot:
            app.update_radar_data(force=True)
            await pilot.pause()
            table = app.query_one("#audit-table", AuditDataTable)
            
            # RowSelected message test
            if table.row_count > 0:
                row_key = table.ordered_rows[0].key
                table.post_message(AuditDataTable.RowSelected(table, cursor_row=0, row_key=row_key))
                await pilot.pause()
                self.assertGreater(len(app.screen_stack), 1)
                self.assertIsInstance(app.screen, AuditFullscreenModal)
                app.pop_screen()
                await pilot.pause()
                
            if app.tui_lock_fd:
                app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_audit_table_real_mouse_press_opens_modal(self):
        from cmd.schengen_tui import SchengenTUIApp, AuditDataTable, AuditSectionHeader, AuditFullscreenModal
        app = SchengenTUIApp()
        async with app.run_test(size=(140, 50)) as pilot:
            app.update_radar_data(force=True)
            await pilot.pause()
            table = app.query_one("#audit-table", AuditDataTable)

            # A real mouse press (MouseDown) must open the modal even though
            # show_cursor=False prevents DataTable from emitting RowSelected/Click.
            await pilot.mouse_down(table, offset=(4, 4))
            await pilot.pause()
            self.assertIsInstance(app.screen, AuditFullscreenModal)
            self.assertGreater(len(app.screen_stack), 1)
            app.pop_screen()
            await pilot.pause()

            # The section header label must also open the modal on press.
            header = app.query_one(AuditSectionHeader)
            await pilot.mouse_down(header, offset=(2, 0))
            await pilot.pause()
            self.assertIsInstance(app.screen, AuditFullscreenModal)

            if app.tui_lock_fd:
                app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_fullscreen_modal_css_scroll_styling(self):
        from cmd.schengen_tui import AuditFullscreenModal
        css = AuditFullscreenModal.CSS
        self.assertIn("scrollbar-size-vertical: 1;", css)
        self.assertIn("scrollbar-size-horizontal: 1;", css)
        self.assertIn("overflow-y: scroll;", css)
        self.assertIn("overflow-x: scroll;", css)

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_modal_close_button_shared_convention(self):
        """Both audit modals share one top-right ✕ close-button convention.

        The same MODAL_CLOSE_CSS block (single source of truth) must be embedded
        in both modals, and each must compose a Horizontal(id="modal-title-bar")
        title row plus a Button(id="modal-close", classes="modal-close").
        """
        from cmd.schengen_tui import (
            AuditDetailModal,
            AuditFullscreenModal,
            MODAL_CLOSE_CSS,
            ModalCloseMixin,
        )

        for modal in (AuditFullscreenModal, AuditDetailModal):
            css = modal.CSS
            self.assertIn(MODAL_CLOSE_CSS, css)
            self.assertIn("#modal-title-bar", css)
            self.assertIn("#modal-close", css)
            # Both modals must share the exact same close-button styling source.
            self.assertTrue(css.endswith(MODAL_CLOSE_CSS))
            self.assertTrue(issubclass(modal, ModalCloseMixin))

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_modal_close_button_mouse_dismisses(self):
        """Clicking the top-right ✕ pops both audit modals (mouse-only dismissal)."""
        from cmd.schengen_tui import (
            AuditDetailModal,
            AuditFullscreenModal,
            SchengenTUIApp,
        )
        from textual.widgets import Button

        app = SchengenTUIApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()

            # Fullscreen ledger modal: X must exist in the title row and dismiss on click.
            app.push_screen(AuditFullscreenModal())
            await pilot.pause()
            close_btn = app.screen.query_one("#modal-close", Button)
            self.assertIsNotNone(close_btn)
            self.assertIn("modal-close", close_btn.classes)
            title_bar = close_btn.parent
            self.assertEqual(title_bar.id, "modal-title-bar")
            await pilot.click(close_btn)
            await pilot.pause()
            self.assertEqual(len(app.screen_stack), 1)

            # Detail modal: same convention, same dismissal behavior.
            app.push_screen(AuditDetailModal(999999999))
            await pilot.pause()
            close_btn = app.screen.query_one("#modal-close", Button)
            self.assertIsNotNone(close_btn)
            self.assertEqual(close_btn.parent.id, "modal-title-bar")
            await pilot.click(close_btn)
            await pilot.pause()
            self.assertEqual(len(app.screen_stack), 1)

            if app.tui_lock_fd:
                app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_no_pixel_mouse_driver_wired_and_disables_pixel_resize(self):
        from cmd.schengen_tui import NoPixelMouseDriver, SchengenTUIApp
        from textual.drivers.linux_driver import LinuxDriver

        self.assertTrue(issubclass(NoPixelMouseDriver, LinuxDriver))

        # The overrides are no-ops: they must not write escape sequences nor
        # flip the driver's internal pixel-mouse / in-band-resize flags.
        d = NoPixelMouseDriver.__new__(NoPixelMouseDriver)
        d._mouse_pixels = False
        d._in_band_window_resize = False
        d._enable_mouse_pixels()
        d._query_in_band_window_resize()
        d._enable_in_band_window_resize()
        self.assertFalse(getattr(d, "_mouse_pixels", True))
        self.assertFalse(getattr(d, "_in_band_window_resize", True))

        # The TUI app must select this driver so mouse coords stay in cell mode.
        app = SchengenTUIApp()
        try:
            self.assertIs(app.driver_class, NoPixelMouseDriver)
        finally:
            if app.tui_lock_fd:
                app.tui_lock_fd.close()


class TestTUIInputExpansionAndObserverDisabled(unittest.IsolatedAsyncioTestCase):
    """Test dynamic height expansion in CommandTextArea and observer mode input disablement."""

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_input_text_area_multiline_expansion(self):
        from cmd.schengen_tui import CommandTextArea
        box = CommandTextArea()
        box.text = "Line 1"
        self.assertEqual(box.styles.height.value, 3)
        
        box.text = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5"
        self.assertEqual(box.styles.height.value, 7)
        
        # Long prompt with 20 newlines should clamp to 16
        box.text = "\n".join([f"Prompt line {i}" for i in range(20)])
        self.assertEqual(box.styles.height.value, 16)

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_observer_mode_input_disabled(self):
        from cmd.schengen_tui import SchengenTUIApp, CommandTextArea
        app = SchengenTUIApp()
        app.is_controller = False  # Simulate observer mode
        async with app.run_test() as pilot:
            input_box = app.query_one("#input-box", CommandTextArea)
            self.assertTrue(input_box.disabled)
            self.assertIn("Observer Mode", input_box.placeholder)
            if app.tui_lock_fd:
                app.tui_lock_fd.close()


class TestToolRedactionIntegration(unittest.TestCase):
    """Test redaction wrapper integration during file reading and pane inspection."""

    def test_read_file_snippet_redacts_secrets(self):
        import tempfile
        from tools.schengen_agent_llm import execute_tool_call
        dummy_aws = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".env") as f:
            f.write(f"DB_PASSWORD=SuperSecretPass123\nAWS_SECRET={dummy_aws}\nBearer secrettoken123\n")
            temp_path = f.name
        try:
            res_str = execute_tool_call("read_file_snippet", {"target_path": temp_path})
            data = json.loads(res_str)
            self.assertIn("path", data)
            content = data["content"]
            self.assertNotIn("SuperSecretPass123", content)
            self.assertNotIn(dummy_aws, content)
            self.assertIn("DB_PASSWORD=***", content)
            self.assertIn("Bearer ***", content)
        finally:
            os.remove(temp_path)


class TestTUIBadgesAndDeepLinks(unittest.TestCase):
    """Sprint 2 observability: phase3 queue status taxonomy + universal deep-link.

    Presentation-only: badges derive exclusively from existing stored fields
    (status, decision_layer, resolution, approver, FIFO position) and deep-links
    reuse the existing AuditDetailModal open path.
    """

    def test_pending_queue_badge_taxonomy(self):
        from cmd.schengen_tui import format_pending_queue_badge

        # Active FIFO head, non-question -> Human Action Required (a persisted
        # PENDING/DELIVERED row is always awaiting human /approve; in-flight
        # Phase-1 inspection is never persisted, so "Gatekeeper Checking" is
        # never inferred).
        b = format_pending_queue_badge(
            {"id": 1, "status": "PENDING", "decision_layer": "COMPLEXITY_TAX"},
            active_id=1,
        )
        self.assertIn("Human Action Required", b)
        self.assertNotIn("Gatekeeper Checking", b)
        self.assertNotIn("Deferred", b)

        # Active FIFO head QUESTION -> Human Action Required (user answers in pane)
        b = format_pending_queue_badge(
            {"id": 1, "status": "DELIVERED", "decision_layer": "QUESTION"},
            active_id=1,
        )
        self.assertIn("Human Action Required", b)
        self.assertNotIn("Gatekeeper Checking", b)

        # Non-head row -> Deferred behind the active single slot (FIFO position)
        b = format_pending_queue_badge(
            {"id": 3, "status": "PENDING", "decision_layer": "SECRET_GUARD"},
            active_id=1,
            slot=3,
        )
        self.assertIn("Deferred (Slot #3)", b)
        self.assertNotIn("Gatekeeper Checking", b)

        # Deferred wins over QUESTION (positional fact: not actionable yet)
        b = format_pending_queue_badge(
            {"id": 4, "status": "PENDING", "decision_layer": "QUESTION"},
            active_id=1,
            slot=4,
        )
        self.assertIn("Deferred (Slot #4)", b)

        # No active slot known -> Human Action Required (never "checking")
        b = format_pending_queue_badge(
            {"id": 9, "status": "PENDING", "decision_layer": "SHELL_AST"},
        )
        self.assertIn("Human Action Required", b)
        self.assertNotIn("Gatekeeper Checking", b)
        self.assertNotIn("Deferred", b)

    def test_non_question_head_awaits_human(self):
        from cmd.schengen_tui import format_pending_queue_badge

        b = format_pending_queue_badge(
            {"id": 5, "status": "PENDING", "decision_layer": "GRAY_ZONE"},
            active_id=5,
        )
        self.assertIn("Human Action Required", b)
        self.assertNotIn("Gatekeeper Checking", b)

    def test_delivered_head_awaits_human(self):
        from cmd.schengen_tui import format_pending_queue_badge

        b = format_pending_queue_badge(
            {"id": 6, "status": "DELIVERED", "decision_layer": "SHELL_CRITICAL"},
            active_id=6,
        )
        self.assertIn("Human Action Required", b)
        self.assertNotIn("Gatekeeper Checking", b)

    def test_question_head(self):
        from cmd.schengen_tui import format_pending_queue_badge

        b = format_pending_queue_badge(
            {"id": 7, "status": "PENDING", "decision_layer": "QUESTION"},
            active_id=7,
        )
        self.assertIn("Human Action Required", b)
        self.assertNotIn("Gatekeeper Checking", b)

    def test_deferred_slot(self):
        from cmd.schengen_tui import format_pending_queue_badge

        b = format_pending_queue_badge(
            {"id": 8, "status": "PENDING", "decision_layer": "SECRET_GUARD"},
            active_id=5,
            slot=2,
        )
        self.assertIn("Deferred (Slot #2)", b)
        self.assertNotIn("Human Action Required", b)

    def test_terminal_status(self):
        from cmd.schengen_tui import format_pending_queue_badge

        b = format_pending_queue_badge(
            {"id": 10, "status": "RESOLVED", "decision_layer": "GRAY_ZONE"},
            active_id=10,
        )
        self.assertIn("RESOLVED", b)
        self.assertIn("✖", b)
        self.assertNotIn("Human Action Required", b)

    def test_resolved_badge_from_fields(self):
        from cmd.schengen_tui import format_resolved_badge

        self.assertIn("Approved (Gatekeeper)", format_resolved_badge("APPROVED", "gatekeeper"))
        self.assertIn("Approved (Human)", format_resolved_badge("APPROVED", "human-tui"))
        self.assertIn("Approved (Pane-Direct)", format_resolved_badge("APPROVED", "pane-direct"))
        self.assertEqual(format_resolved_badge("ANSWERED", None), "[cyan]ANS[/]")
        self.assertEqual(format_resolved_badge("REJECTED", None), "[red]RJ[/]")
        self.assertEqual(format_resolved_badge("UNANSWERED", None), "[yellow]UA[/]")
        self.assertEqual(format_resolved_badge(None, None), "[dim]—[/]")

    def test_linkify_tokens_and_plain_text(self):
        from cmd.schengen_tui import _chat_plain_text, _linkify_chat_markup

        markup = "[yellow]▶ Escalation [#42] Intercepted [cyan][▼ Details][/][/]"
        t = _linkify_chat_markup(markup, default_target=(42, "escalation"))
        # tokens survive markup parsing; tags are consumed
        self.assertIn("[#42]", t.plain)
        self.assertIn("[▼ Details]", t.plain)
        self.assertNotIn("[yellow]", t.plain)
        self.assertNotIn("[cyan]", t.plain)

        # [Audit #N] token renders literally
        t2 = _linkify_chat_markup("see [Audit #7771] for context")
        self.assertIn("[Audit #7771]", t2.plain)

        # bare [▼ Details] without a target renders literally (no invented link)
        t3 = _linkify_chat_markup("just [▼ Details] alone")
        self.assertIn("[▼ Details]", t3.plain)

        # clipboard plain text keeps deep-link tokens but strips markup tags
        plain = _chat_plain_text(markup)
        self.assertIn("[#42]", plain)
        self.assertIn("[▼ Details]", plain)
        self.assertNotIn("[yellow]", plain)
        self.assertNotIn("[cyan]", plain)

    def test_link_target_in_line_hit_test(self):
        from cmd.schengen_tui import _link_target_in_line
        from rich.text import Text

        line = Text()
        line.append("Escalation ")
        link = Text("[#42]", style="bold underline cyan")
        line.append_text(link)
        line.append(" queued  ")
        details = Text("[▼ Details]", style="bold")
        line.append_text(details)

        class FakeSeg:
            def __init__(self, text):
                self.text = text

        segments = [FakeSeg(ch) for ch in line.plain]
        # hit the [#42] token cells (11..15: after "Escalation ")
        self.assertEqual(_link_target_in_line(segments, 12), (42, "escalation"))
        self.assertEqual(_link_target_in_line(segments, 15), (42, "escalation"))
        # [▼ Details] inherits the preceding [#N] target on the same line
        details_start = line.plain.index("[▼ Details]")
        self.assertEqual(_link_target_in_line(segments, details_start + 2), (42, "escalation"))
        # miss: plain text cell
        self.assertIsNone(_link_target_in_line(segments, 3))


class TestTUIBadgesAndDeepLinksAsync(unittest.IsolatedAsyncioTestCase):
    """Async half of the Sprint 2 badge/deep-link tests (needs a live app)."""

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_chat_link_click_opens_audit_detail_modal(self):
        from cmd.schengen_tui import AuditDetailModal, FocusableRichLog, SchengenTUIApp
        from rich.text import Text

        app = SchengenTUIApp()
        async with app.run_test(size=(120, 40)) as pilot:
            chat = app.query_one("#chat-log", FocusableRichLog)
            chat.clear()
            t = Text()
            t.append("x ")
            link = Text("[#42]", style="bold underline cyan")
            t.append_text(link)
            chat.write(t)
            await pilot.pause()
            # [#42] occupies content cells 2..7; click inside it
            # (y=2 skips border+padding into the first content row)
            await pilot.click(chat, offset=(4, 2))
            await pilot.pause()
            self.assertIsInstance(app.screen, AuditDetailModal)
            if app.tui_lock_fd:
                app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_chat_link_click_off_token_does_not_open_modal(self):
        from cmd.schengen_tui import AuditDetailModal, FocusableRichLog, SchengenTUIApp
        from rich.text import Text

        app = SchengenTUIApp()
        async with app.run_test(size=(120, 40)) as pilot:
            chat = app.query_one("#chat-log", FocusableRichLog)
            chat.clear()
            t = Text()
            t.append("x ")
            link = Text("[#42]", style="bold underline cyan")
            t.append_text(link)
            chat.write(t)
            await pilot.pause()
            # click on the "x " prefix (cell 0) -> no modal
            await pilot.click(chat, offset=(0, 2))
            await pilot.pause()
            self.assertNotIsInstance(app.screen, AuditDetailModal)
            if app.tui_lock_fd:
                app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_escalation_list_item_selection_opens_detail(self):
        from cmd.schengen_tui import AuditDetailModal, SchengenTUIApp
        from textual.widgets import Label, ListItem, ListView

        app = SchengenTUIApp()
        async with app.run_test(size=(120, 40)) as pilot:
            esc_list = app.query_one("#escalation-list", ListView)
            li = ListItem(Label("[#777] test"))
            li.esc_id = 777
            esc_list.append(li)
            await pilot.pause()
            esc_list.index = 0
            await pilot.pause()
            esc_list.post_message(esc_list.Selected(esc_list, li, 0))
            await pilot.pause()
            self.assertIsInstance(app.screen, AuditDetailModal)
            if app.tui_lock_fd:
                app.tui_lock_fd.close()


def _fake_escalation(**overrides):
    """Minimal pending escalation dict shaped like guard_db rows."""
    base = {
        "id": 7494,
        "pane_id": "w1D:p1",
        "agent_kind": "opencode",
        "raw_command": "git push --force origin main",
        "command_hash": "h",
        "safety_reason": "Force-push to shared branch (Fail-Closed)",
        "decision_layer": "GIT_IRREVERSIBLE",
        "dialog_snapshot": None,
        "status": "PENDING",
        "started_at": "",
        "delivered_at": None,
        "last_transitioned_at": "",
        "cwd": "",
        "origin": "A",
    }
    base.update(overrides)
    return base


class TestTUIActionRequiredPanel(unittest.TestCase):
    """Sprint 2 action-required panel: decision card + clipboard fidelity."""

    def test_decision_card_structure(self):
        from cmd.schengen_tui import format_decision_card
        from rich.cells import cell_len

        esc = _fake_escalation(
            raw_command="git show --stat HEAD | head -12 && git push --force origin main",
            decision_layer="FAIL_CLOSED",
            safety_reason="Not in fast-track allowlist",
        )
        card = format_decision_card(esc, width=70)
        plain = card.plain
        self.assertIn("ACTION REQUIRED", plain)
        self.assertIn("[#7494]", plain)  # deep-link token in the frame
        self.assertIn("Human Authorization Required", plain)
        self.assertIn("w1D:p1 (opencode)", plain)
        self.assertIn("git show --stat HEAD | head -12", plain)
        self.assertIn("FAIL_CLOSED", plain)
        self.assertIn("/approve 7494", plain)
        self.assertIn("/reject 7494 [reason]", plain)
        self.assertIn("/allow-last", plain)
        # every rendered line is exactly `width` terminal cells
        self.assertEqual(len({cell_len(l) for l in plain.splitlines()}), 1)
        self.assertEqual(cell_len(plain.splitlines()[0]), 70)

    def test_decision_card_width_alignment(self):
        from cmd.schengen_tui import format_decision_card
        from rich.cells import cell_len

        esc = _fake_escalation(raw_command="x" * 300, safety_reason="r" * 300)
        for w in (52, 60, 70, 78):
            card = format_decision_card(esc, width=w)
            widths = {cell_len(l) for l in card.plain.splitlines()}
            self.assertEqual(widths, {w}, f"misaligned at width {w}")
            self.assertLessEqual(len(card.plain.splitlines()), 12)

    def test_decision_card_fallback_reason(self):
        from cmd.schengen_tui import format_decision_card

        esc = _fake_escalation(safety_reason="", decision_layer="SECRET_GUARD")
        plain = format_decision_card(esc, width=60).plain
        self.assertIn("SECRET_GUARD — Deferred to human review", plain)

    def test_chat_plain_text_preserves_card_tokens(self):
        from cmd.schengen_tui import _chat_plain_text

        plain = _chat_plain_text(
            "[bold red]🚨 ▶ ACTION REQUIRED: Escalation [#7494] Awaiting Human Decision[/]\n"
            "[dim]   [✔ Approve] /approve 7494 · [✖ Reject] /reject 7494 [reason] · [🔒 Always Allow] /allow-last[/]\n"
            "╭── [ESCALATION #7494] ──╮"
        )
        self.assertIn("[#7494]", plain)
        self.assertIn("[✔ Approve]", plain)
        self.assertIn("[✖ Reject]", plain)
        self.assertIn("[🔒 Always Allow]", plain)
        self.assertIn("[reason]", plain)
        self.assertIn("[ESCALATION #7494]", plain)
        self.assertNotIn("[bold red]", plain)
        self.assertNotIn("[dim]", plain)


class TestTUIActionRequiredPanelAsync(unittest.IsolatedAsyncioTestCase):
    """Async half: live app rendering of banner / radar card / chat card."""

    def _mount_patches(self, active_esc, pending):
        from unittest.mock import MagicMock, patch

        return [
            patch("cmd.schengen_tui.get_current_active_escalation", return_value=active_esc),
            patch("cmd.schengen_tui.get_pending_escalations", return_value=pending),
            patch("cmd.schengen_tui.list_active_guard_locks", return_value=[]),
            patch("cmd.schengen_tui.get_recent_audit_logs", return_value=[]),
            patch("cmd.schengen_tui.get_pane_info", return_value={"agent_status": "blocked"}),
            patch("cmd.schengen_tui.get_pane_direct_config", return_value={}),
            patch("cmd.schengen_tui.get_batch_approval_config", return_value={"batch_approval_enabled": False}),
            patch("cmd.schengen_tui.subprocess.Popen", return_value=MagicMock()),
        ]

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_alarm_banner_and_radar_card_when_active(self):
        from cmd.schengen_tui import SchengenTUIApp, Static
        from contextlib import ExitStack
        from unittest.mock import MagicMock

        esc = _fake_escalation()
        app = SchengenTUIApp()
        app.is_controller = True
        with ExitStack() as stack:
            for p in self._mount_patches(esc, [esc]):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                app.process_user_chat = MagicMock()
                await pilot.pause(0.7)
                banner = app.query_one("#active-target-banner", Static)
                self.assertIn("ACTION REQUIRED", banner.content)
                self.assertIn("#7494", banner.content)
                self.assertIn("/approve 7494", banner.content)
                card = app.query_one("#action-card", Static)
                self.assertTrue(card.display)
                self.assertIn("Blocked Pane", card.content)
                self.assertIn("w1D:p1", card.content)
                self.assertIn("(opencode)", card.content)
                self.assertIn("HUMAN INTERVENTION REQUIRED", card.content)
                # commander prompt placeholder
                self.assertIn("/approve 7494", app.query_one("#input-box").placeholder)
                # decision card reached the chat
                chat_plain = "\n".join(app._chat_plain)
                self.assertIn("ACTION REQUIRED", chat_plain)
                self.assertIn("/approve 7494", chat_plain)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_idle_keeps_non_alarm_banner_and_hides_card(self):
        from cmd.schengen_tui import SchengenTUIApp, Static
        from contextlib import ExitStack

        app = SchengenTUIApp()
        with ExitStack() as stack:
            for p in self._mount_patches(None, []):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.7)
                banner = app.query_one("#active-target-banner", Static)
                self.assertIn("No active escalations", banner.content)
                self.assertNotIn("ACTION REQUIRED", banner.content)
                card = app.query_one("#action-card", Static)
                self.assertFalse(card.display)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_question_keeps_pane_answer_presentation(self):
        from cmd.schengen_tui import SchengenTUIApp, Static
        from contextlib import ExitStack

        esc = _fake_escalation(decision_layer="QUESTION", raw_command="rm -rf /tmp/scratch?")
        app = SchengenTUIApp()
        app.is_controller = True
        with ExitStack() as stack:
            for p in self._mount_patches(esc, [esc]):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.7)
                banner = app.query_one("#active-target-banner", Static)
                # question flow keeps the in-pane answer presentation
                self.assertIn("❓", banner.content)
                self.assertIn("Answer this question", banner.content)
                self.assertNotIn("ACTION REQUIRED", banner.content)
                # radar card still flags human intervention (answer in pane)
                card = app.query_one("#action-card", Static)
                self.assertTrue(card.display)
                self.assertIn("HUMAN INTERVENTION REQUIRED", card.content)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()


class TestTUIStatusCardAndSettings(unittest.TestCase):
    """Sprint 2: sidebar System Status card + consolidated Settings modal.

    Presentation/organization only: every value comes from EXISTING config
    (guard_config getters, daemon lock state, runtime role). Approval Bias /
    Fast-Track have no backing config keys and are intentionally absent.
    """

    def test_status_card_text_render(self):
        from cmd.schengen_tui import format_status_card_text

        text = format_status_card_text(
            is_controller=True,
            leader_pid=None,
            guard_pid=4242,
            lang="korean",
            send_approve_instruction=False,
            send_reject_instruction=True,
        )
        self.assertIn("Mode  :", text)
        self.assertIn("Controller (👑)", text)
        self.assertIn("Guard :", text)
        self.assertIn("ACTIVE (🛡️) PID 4242", text)
        self.assertIn("Lang  :", text)
        self.assertIn("Korean (KO)", text)
        self.assertIn("Instr :", text)
        self.assertIn("Reject-only", text)
        # no invented rows
        self.assertNotIn("Bias", text)
        self.assertNotIn("Fast", text)

    def test_status_card_text_variants(self):
        from cmd.schengen_tui import format_status_card_text

        obs = format_status_card_text(
            is_controller=False, leader_pid=7, guard_pid=None,
            lang="english", send_approve_instruction=True, send_reject_instruction=True,
        )
        self.assertIn("Observer (👁) — Leader PID 7", obs)
        self.assertIn("INACTIVE (○)", obs)
        self.assertIn("English (EN)", obs)
        self.assertIn("Approve+Reject", obs)

        off = format_status_card_text(
            is_controller=True, leader_pid=None, guard_pid=None,
            lang="japanese", send_approve_instruction=False, send_reject_instruction=False,
        )
        self.assertIn("Japanese (JA)", off)
        self.assertIn("None", off)

        approve_only = format_status_card_text(
            is_controller=True, leader_pid=None, guard_pid=None,
            lang="korean", send_approve_instruction=True, send_reject_instruction=False,
        )
        self.assertIn("Approve-only", approve_only)

        unknown = format_status_card_text(
            is_controller=True, leader_pid=None, guard_pid=None,
            lang="esperanto", send_approve_instruction=False, send_reject_instruction=True,
        )
        self.assertIn("esperanto", unknown)  # unknown lang passes through

    def test_settings_bindings_and_open_action(self):
        from cmd.schengen_tui import SchengenTUIApp

        actions = {b.action for b in SchengenTUIApp.BINDINGS}
        self.assertIn("open_settings", actions)
        self.assertTrue(hasattr(SchengenTUIApp, "action_open_settings"))
        # at least one settings binding is footer-visible (^s)
        self.assertTrue(any(b.action == "open_settings" and b.show for b in SchengenTUIApp.BINDINGS))


class TestTUISettingsModalAsync(unittest.IsolatedAsyncioTestCase):
    """Async half: live modal open/close/toggle + status-card live updates."""

    def _config_patches(self, state):
        from unittest.mock import patch

        return [
            patch("cmd.schengen_tui.list_active_guard_locks", side_effect=lambda: state["locks"]),
            patch("cmd.schengen_tui.get_instruction_delivery_config", side_effect=lambda: dict(state["instr"])),
            patch("cmd.schengen_tui.set_instruction_delivery_config",
                  side_effect=lambda **kw: state["instr"].update({k: v for k, v in kw.items()})),
            patch("cmd.schengen_tui.get_answer_language", side_effect=lambda: state["lang"]),
            patch("cmd.schengen_tui.set_answer_language", side_effect=lambda lang: state.update(lang=lang)),
            patch("cmd.schengen_tui.get_channel_approve_config", side_effect=lambda: state["chan"]),
            patch("cmd.schengen_tui.set_channel_approve_config", side_effect=lambda v: state.update(chan=v)),
            patch("cmd.schengen_tui.get_current_active_escalation", return_value=None),
            patch("cmd.schengen_tui.get_pending_escalations", return_value=[]),
            patch("cmd.schengen_tui.get_recent_audit_logs", return_value=[]),
        ]

    @staticmethod
    def _fresh_state():
        return {
            "locks": [],
            "instr": {"send_approve_instruction": False, "send_reject_instruction": True},
            "lang": "korean",
            "chan": False,
        }

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_status_card_live_updates_from_config(self):
        from cmd.schengen_tui import SchengenTUIApp, Static
        from contextlib import ExitStack

        state = self._fresh_state()
        app = SchengenTUIApp()
        with ExitStack() as stack:
            for p in self._config_patches(state):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.7)
                card = app.query_one("#status-card", Static)
                self.assertIn("INACTIVE", card.content)
                self.assertIn("Reject-only", card.content)
                # guard comes up -> next radar tick reflects it
                state["locks"].append(("auto", "/tmp/l", 1234))
                await pilot.pause(0.7)
                self.assertIn("ACTIVE (🛡️) PID 1234", card.content)
                # instruction change -> card flips
                state["instr"]["send_approve_instruction"] = True
                await pilot.pause(0.7)
                self.assertIn("Approve+Reject", card.content)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_settings_modal_opens_via_slash_command_and_toggles(self):
        from cmd.schengen_tui import SchengenTUIApp, SettingsModal, Static
        from contextlib import ExitStack
        from textual.widgets import Button

        state = self._fresh_state()
        app = SchengenTUIApp()
        with ExitStack() as stack:
            for p in self._config_patches(state):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                w = app.process_user_chat("/config")
                await w.wait()
                await pilot.pause()
                self.assertIsInstance(app.screen, SettingsModal)
                modal = app.screen
                # initial labels from config
                self.assertIn("OFF", modal.query_one("#set-approve-instr", Button).label.plain)
                self.assertIn("ON", modal.query_one("#set-reject-instr", Button).label.plain)
                # toggle approve instruction
                modal.query_one("#set-approve-instr", Button).press()
                await pilot.pause()
                self.assertTrue(state["instr"]["send_approve_instruction"])
                self.assertIn("ON", modal.query_one("#set-approve-instr", Button).label.plain)
                # sidebar toggle synced
                self.assertIn("ON", app.query_one("#btn-toggle-approve-instr").label.plain)
                # status card behind the modal synced
                self.assertIn("Approve+Reject", app.query_one("#status-card", Static).content)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_settings_modal_f2_and_language_change(self):
        from cmd.schengen_tui import SchengenTUIApp, SettingsModal
        from contextlib import ExitStack
        from textual.widgets import RadioButton

        state = self._fresh_state()
        app = SchengenTUIApp()
        with ExitStack() as stack:
            for p in self._config_patches(state):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.press("f2")
                await pilot.pause()
                self.assertIsInstance(app.screen, SettingsModal)
                modal = app.screen
                # switch language inside the modal
                modal.query_one("#lang-english", RadioButton).value = True
                await pilot.pause()
                self.assertEqual(state["lang"], "english")
                # sidebar language radio synced
                sidebar_english = app.query_one("#answer-language-set").query_one("#lang-english", RadioButton)
                self.assertTrue(sidebar_english.value)
                # close via ESC
                await pilot.press("escape")
                await pilot.pause()
                self.assertNotIsInstance(app.screen, SettingsModal)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_settings_modal_close_button_and_reopen(self):
        from cmd.schengen_tui import SchengenTUIApp, SettingsModal
        from contextlib import ExitStack

        state = self._fresh_state()
        app = SchengenTUIApp()
        with ExitStack() as stack:
            for p in self._config_patches(state):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                app.action_open_settings()
                await pilot.pause()
                modal = app.screen
                # ✕ close pops exactly once (ModalCloseMixin via MRO)
                modal.query_one("#modal-close").press()
                await pilot.pause()
                self.assertNotIsInstance(app.screen, SettingsModal)
                # reopen with ^s
                await pilot.press("ctrl+s")
                await pilot.pause()
                self.assertIsInstance(app.screen, SettingsModal)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()


if __name__ == "__main__":
    unittest.main()
