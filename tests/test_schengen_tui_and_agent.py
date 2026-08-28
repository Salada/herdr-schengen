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


if __name__ == "__main__":
    unittest.main()
