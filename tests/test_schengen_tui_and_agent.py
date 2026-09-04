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
from unittest.mock import AsyncMock, MagicMock, patch

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
    from cmd.schengen_tui import (
        SchengenTUIApp,
        AuditFullscreenModal,
        format_approver_badge,
        rich_escape,
    )
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

    @patch("tools.schengen_agent_llm.get_current_command_escalation")
    def test_build_system_prompt_structure(self, mock_get_active):
        mock_get_active.return_value = {
            "id": 123,
            "pane_id": "w1D:p1",
            "agent_kind": "agy",
            "raw_command": "rm -rf /tmp/test_dir",
            "safety_reason": "Destructive deletion",
            "decision_layer": "GRAY_ZONE",
        }
        prompt = build_system_prompt()
        self.assertIn("Escalation ID: #123", prompt)
        self.assertIn("investigate_path_details", prompt)
        self.assertIn("investigate_pane_history", prompt)
        self.assertIn("read_file_snippet", prompt)
        self.assertIn("ADVISORY SECURITY REVIEW", prompt)
        self.assertIn("TRIAGE", prompt)
        self.assertIn("OBVIOUS-SAFE FORM", prompt)
        self.assertIn("NO AUTONOMOUS REJECT", prompt)
        self.assertIn("- Decision Layer: GRAY_ZONE", prompt)
        self.assertNotIn("DISAGREE & COMMIT", prompt)

    @patch("tools.schengen_agent_llm.get_current_command_escalation")
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
        # The Answer Language selector was relocated into the SettingsModal
        # (first-screen declutter); assert the modal's RadioSet instead.
        from cmd.schengen_tui import SchengenTUIApp, SettingsModal
        from textual.widgets import RadioSet
        from unittest.mock import patch
        app = SchengenTUIApp()
        with patch("cmd.schengen_tui.get_answer_language", return_value="korean"):
            async with app.run_test() as pilot:
                await pilot.pause()
                app.action_open_settings()
                await pilot.pause()
                self.assertIsInstance(app.screen, SettingsModal)
                modal = app.screen
                radio_set = modal.query_one("#settings-lang-set", RadioSet)
                radios = list(radio_set.query("RadioButton"))
                self.assertEqual([r.id for r in radios], ["lang-english", "lang-korean", "lang-japanese"])
                # Default is korean.
                self.assertTrue(modal.query_one("#lang-korean").value)
                self.assertFalse(modal.query_one("#lang-english").value)
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


class TestTUIFreeTextDirectiveProvenance(unittest.IsolatedAsyncioTestCase):
    """Explicit directives execute deterministically with human provenance."""

    _ACTIVE_ESC = {"id": 4242, "pane_id": "w1D:p1", "agent_kind": "codex"}

    def _make_app(self):
        from cmd.schengen_tui import SchengenTUIApp
        return SchengenTUIApp()

    async def _run_directive(self, app, msg: str):
        from cmd.schengen_tui import (
            get_current_command_escalation,
            record_human_opinion,
        )
        app.is_controller = True
        with (
            patch("cmd.schengen_tui.get_current_command_escalation", return_value=dict(self._ACTIVE_ESC)),
            patch("cmd.schengen_tui.record_human_opinion") as mock_opinion,
            patch("cmd.schengen_tui.execute_tool_call", return_value='{"status":"success"}') as mock_execute,
            patch.object(SchengenAgentChat, "send_message", new=AsyncMock(return_value="ok")) as mock_send,
            patch.object(app, "update_radar_data"),
        ):
            async with app.run_test() as pilot:
                w = app.process_user_chat(msg)
                await w.wait()
                await pilot.pause()
        return mock_opinion, mock_execute, mock_send

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_free_text_directive_records_opinion(self):
        app = self._make_app()
        try:
            mock_opinion, mock_execute, mock_send = await self._run_directive(app, "yes, do it")
            mock_opinion.assert_called_once_with(self._ACTIVE_ESC["id"], "yes, do it")
            mock_execute.assert_called_once()
            self.assertTrue(mock_execute.call_args.args[1]["directive"])
            mock_send.assert_not_awaited()
        finally:
            if app.tui_lock_fd:
                app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_free_text_directive_approve_it_records_opinion(self):
        app = self._make_app()
        try:
            mock_opinion, mock_execute, mock_send = await self._run_directive(app, "approve it, that's fine")
            mock_opinion.assert_called_once_with(self._ACTIVE_ESC["id"], "approve it, that's fine")
            mock_execute.assert_called_once()
            mock_send.assert_not_awaited()
        finally:
            if app.tui_lock_fd:
                app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_non_directive_message_does_not_record_opinion(self):
        app = self._make_app()
        try:
            mock_opinion, mock_execute, mock_send = await self._run_directive(app, "why was this command blocked?")
            mock_opinion.assert_not_called()
            mock_execute.assert_not_called()
            mock_send.assert_awaited_once()
        finally:
            if app.tui_lock_fd:
                app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_slash_command_does_not_record_free_text_opinion(self):
        # Slash-prefixed messages are routed by the slash handlers (which own
        # their own record_human_opinion); the free-text path must skip them.
        app = self._make_app()
        try:
            mock_opinion, mock_execute, mock_send = await self._run_directive(app, "/custom-command xyz")
            mock_opinion.assert_not_called()
            mock_execute.assert_not_called()
            mock_send.assert_awaited_once()
        finally:
            if app.tui_lock_fd:
                app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_korean_directive_executes_without_llm(self):
        app = self._make_app()
        try:
            mock_opinion, mock_execute, mock_send = await self._run_directive(app, "승인해주세요")
            mock_opinion.assert_called_once_with(self._ACTIVE_ESC["id"], "승인해주세요")
            self.assertEqual(mock_execute.call_args.args[0], "approve_escalation")
            self.assertEqual(mock_execute.call_args.args[1]["escalation_id"], self._ACTIVE_ESC["id"])
            mock_send.assert_not_awaited()
        finally:
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
    def test_fullscreen_modal_keyboard_selection_uses_cursor_row(self):
        from cmd.schengen_tui import AuditFullscreenModal
        from textual.widgets import DataTable

        modal = AuditFullscreenModal()
        event = DataTable.RowSelected(DataTable(), cursor_row=2, row_key=None)

        with patch.object(modal, "_open_detail") as open_detail:
            modal.on_data_table_row_selected(event)

        open_detail.assert_called_once_with(2)

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_audit_table_paging_scroll_config(self):
        # Infinite-scroll sidebar table (Sprint: audit ledger UI): the compact
        # table must NOT steal horizontal scroll, must stay click-to-open
        # (no visible cursor), and must allow VERTICAL scrolling once paged
        # rows overflow (CSS overflow-y: auto + Textual auto scrollbar).
        from cmd.schengen_tui import SchengenTUIApp, AuditDataTable
        app = SchengenTUIApp()
        async with app.run_test() as pilot:
            table = app.query_one("#audit-table", AuditDataTable)
            self.assertFalse(table.show_cursor)
            self.assertFalse(table.show_horizontal_scrollbar)
            css = SchengenTUIApp.CSS
            self.assertIn("overflow-y: auto;", css)
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


def _audit_page_rows(count: int, newest_id: int = 0) -> list:
    """Synthetic audit rows ordered newest-first (id DESC) for paging tests."""
    start = newest_id or count
    return [
        {
            "id": start - i,
            "timestamp": f"2026-09-03T09:{i % 60:02d}:00Z",
            "pane_id": "wAUDIT:t",
            "agent_kind": "opencode",
            "raw_command": f"echo probe-{i} " + "x" * 120,
            "decision": "ESCALATED",
            "safety_reason": "paging probe",
            "decision_layer": "SHELL_AST",
            "resolution": None,
            "approver": None,
        }
        for i in range(count)
    ]


class TestAuditLedgerTruncationAndPaging(unittest.IsolatedAsyncioTestCase):
    """Sprint: audit-ledger UI — command-cell truncation + infinite scroll."""

    # ---- display truncation helpers (pure) -------------------------------

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_truncate_cmd_display_short_command_untouched(self):
        from cmd.schengen_tui import truncate_cmd_display
        self.assertEqual(truncate_cmd_display("ls -la"), "ls -la")
        # newlines collapse to a single space; outer whitespace trims
        self.assertEqual(truncate_cmd_display("  rm -rf\n/tmp/x  "), "rm -rf /tmp/x")

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_truncate_cmd_display_long_command_capped_with_ellipsis(self):
        from rich.cells import cell_len
        from cmd.schengen_tui import AUDIT_CMD_MAX_CELLS, truncate_cmd_display

        long = "curl -sS https://example.com/api/v1/items?page=1&limit=500 " + "A" * 400
        out = truncate_cmd_display(long)  # default 90-cell cap
        self.assertLessEqual(cell_len(out), AUDIT_CMD_MAX_CELLS)
        self.assertTrue(out.endswith("…"))
        # the FULL command is never lost by the helper — only the display form
        self.assertGreater(len(long), len(out))

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_truncate_cmd_display_respects_wide_cells(self):
        from cmd.schengen_tui import truncate_cmd_display
        # 50 two-cell CJK glyphs = 100 cells > 90 cap -> truncated, no split glyph
        cjk = "가" * 50
        out = truncate_cmd_display(cjk, max_cells=90)
        self.assertTrue(out.endswith("…"))

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_modal_cells_truncate_command_and_escape_markup(self):
        from cmd.schengen_tui import modal_audit_cells

        log = {
            "id": 42, "timestamp": "2026-09-03T09:30:00Z", "pane_id": "w1D:p1",
            "agent_kind": "opencode", "raw_command": "echo [probe] " + "B" * 200,
            "decision": "ESCALATED", "safety_reason": "reason [x]", "decision_layer": "SHELL_AST",
            "resolution": "APPROVED", "approver": "human-tui",
        }
        cells = modal_audit_cells(log)
        self.assertEqual(cells[0], "#42")
        self.assertEqual(len(cells), 9)  # existing column layout preserved
        # command cell: markup-escaped (renders literally) and truncated
        self.assertIn("…", cells[8])
        self.assertIn(r"\[probe]", cells[8])  # [ escaped so it can't break markup
        self.assertNotIn("B" * 200, cells[8])  # full command NOT in the table cell
        self.assertEqual(cells[7], r"reason \[x]")  # reason escaped too

    # ---- guard_db offset pagination --------------------------------------

    def test_get_recent_audit_logs_offset_pagination(self):
        from core.guard_db import get_db_connection, get_recent_audit_logs, init_db, record_audit_log
        init_db()
        pane = f"wPAGEPROBE:{os.getpid()}"
        cmds = [f"echo page-probe-{i}" for i in range(6)]
        try:
            for i, c in enumerate(cmds):
                record_audit_log(
                    pane_id=pane, raw_command=c, decision="AUTO_APPROVED",
                    safety_reason="offset pagination unit probe", agent_kind="agy",
                    decision_layer="FAST_TRACK_AST",
                )
            page1 = get_recent_audit_logs(limit=4, offset=0, pane_id=pane)
            page2 = get_recent_audit_logs(limit=4, offset=4, pane_id=pane)
            self.assertEqual(len(page1), 4)
            self.assertEqual(len(page2), 2)  # short tail page
            # newest-first ordering + disjoint windows over the same query
            ids1 = [r["id"] for r in page1]
            ids2 = [r["id"] for r in page2]
            self.assertEqual(ids1, sorted(ids1, reverse=True))
            self.assertTrue(all(a > b for a in ids1 for b in ids2))
            # offset beyond the ledger -> empty page (end of infinite scroll)
            self.assertEqual(get_recent_audit_logs(limit=4, offset=20, pane_id=pane), [])
        finally:
            with get_db_connection() as conn:
                conn.execute("DELETE FROM audit_logs WHERE pane_id = ?", (pane,))

    # ---- live paging (mounted widgets) -----------------------------------

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_fullscreen_modal_pages_older_rows_on_scroll_bottom(self):
        from contextlib import ExitStack
        from unittest.mock import patch

        from cmd.schengen_tui import (
            AUDIT_MODAL_HEAD,
            AUDIT_PAGE_SIZE,
            AuditFullscreenModal,
            PagedAuditDataTable,
            SchengenTUIApp,
        )

        rows = _audit_page_rows(250)
        fake = lambda limit=10, decision=None, pane_id=None, layer=None, offset=0: rows[offset:offset + limit]
        app = SchengenTUIApp()
        with ExitStack() as stack:
            stack.enter_context(patch("cmd.schengen_tui.get_recent_audit_logs", side_effect=fake))
            async with app.run_test(size=(140, 50)) as pilot:
                app.push_screen(AuditFullscreenModal())
                await pilot.pause(0.6)
                modal = app.screen
                table = modal.query_one("#audit-modal-table", PagedAuditDataTable)
                self.assertEqual(table.row_count, AUDIT_MODAL_HEAD)          # initial batch
                self.assertEqual(len(table.audit_records), table.row_count)  # detail mapping
                self.assertEqual(table.audit_records[0]["id"], 250)          # newest first

                # web-style: each scroll-to-bottom appends the NEXT batch
                table.scroll_end(animate=False, immediate=True)
                await pilot.pause(0.4)
                self.assertEqual(table.row_count, AUDIT_MODAL_HEAD + AUDIT_PAGE_SIZE)

                table.scroll_end(animate=False, immediate=True)
                await pilot.pause(0.4)
                self.assertEqual(table.row_count, AUDIT_MODAL_HEAD + 2 * AUDIT_PAGE_SIZE)

                # exhausted: a further scroll-to-bottom loads nothing
                table.scroll_end(animate=False, immediate=True)
                await pilot.pause(0.4)
                table.scroll_end(animate=False, immediate=True)
                await pilot.pause(0.4)
                self.assertEqual(table.row_count, 250)
                self.assertTrue(table._audit_all_loaded)
                self.assertEqual(len(table.audit_records), 250)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_sidebar_audit_table_pages_older_rows(self):
        from contextlib import ExitStack
        from unittest.mock import patch

        from cmd.schengen_tui import (
            AUDIT_PAGE_SIZE,
            AUDIT_SIDEBAR_HEAD,
            AuditDataTable,
            SchengenTUIApp,
        )

        rows = _audit_page_rows(120, newest_id=120)
        fake = lambda limit=10, decision=None, pane_id=None, layer=None, offset=0: rows[offset:offset + limit]
        app = SchengenTUIApp()
        with ExitStack() as stack:
            stack.enter_context(patch("cmd.schengen_tui.get_recent_audit_logs", side_effect=fake))
            stack.enter_context(patch("cmd.schengen_tui.get_current_command_escalation", return_value=None))
            stack.enter_context(patch("cmd.schengen_tui.get_oldest_question_escalation", return_value=None))
            stack.enter_context(patch("cmd.schengen_tui.get_pending_escalations", return_value=[]))
            stack.enter_context(patch("cmd.schengen_tui.list_active_guard_locks", return_value=[]))
            stack.enter_context(patch("cmd.schengen_tui.read_in_flight_state", return_value=[]))
            stack.enter_context(patch("cmd.schengen_tui.get_pane_info", return_value={"agent_status": "idle"}))
            stack.enter_context(patch("cmd.schengen_tui.get_batch_approval_config", return_value={"batch_approval_enabled": False}))
            stack.enter_context(patch("cmd.schengen_tui.get_pane_direct_config", return_value={}))
            stack.enter_context(patch("cmd.schengen_tui.subprocess.Popen", return_value=MagicMock()))
            async with app.run_test(size=(140, 50)) as pilot:
                await pilot.pause(0.8)  # radar tick fills the live head page
                table = app.query_one("#audit-table", AuditDataTable)
                self.assertEqual(table.row_count, AUDIT_SIDEBAR_HEAD)
                self.assertEqual(len(table.audit_records), AUDIT_SIDEBAR_HEAD)
                self.assertEqual(table.audit_records[0]["id"], 120)  # newest first

                # Scroll to the bottom of the loaded rows -> AuditPageMixin
                # appends the NEXT batch (web-style infinite scroll).
                table.scroll_end(animate=False, immediate=True)
                await pilot.pause(0.4)
                self.assertEqual(table.row_count, AUDIT_SIDEBAR_HEAD + AUDIT_PAGE_SIZE)
                self.assertEqual(len(table.audit_records), table.row_count)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()


def _search_probe_rows(count: int = 200) -> list:
    """Newest-first audit rows with UNIQUE search tokens per row (id 200..1)."""
    return [
        {
            "id": count - i,
            "timestamp": f"2026-09-04T09:{i % 60:02d}:00Z",
            "pane_id": "wSRCH:t",
            "agent_kind": "opencode",
            "raw_command": f"deploy service-{count - i:03d} --env prod",
            "decision": "ESCALATED",
            "safety_reason": f"release reason-{count - i:03d}",
            "decision_layer": "SHELL_AST",
            "resolution": None,
            "approver": None,
        }
        for i in range(count)
    ]


class TestAuditLedgerFuzzySearch(unittest.IsolatedAsyncioTestCase):
    """Sprint: fullscreen-ledger search — fuzzy match + 5 tolerance levels.

    Pure predicates + live modal behavior (filter on type / tolerance change /
    scroll-to-search-deeper), preserving row_index → record mapping.
    """

    # ---- pure match predicates -------------------------------------------

    def test_tolerance_threshold_mapping(self):
        from cmd.schengen_tui import (
            AUDIT_SEARCH_TOL_ORDER,
            AUDIT_SEARCH_TOLERANCE_THRESHOLDS,
        )
        # 5 distinct levels, spec thresholds
        self.assertEqual(len(AUDIT_SEARCH_TOL_ORDER), 5)
        self.assertEqual(
            {tol: AUDIT_SEARCH_TOLERANCE_THRESHOLDS[tol] for tol in AUDIT_SEARCH_TOL_ORDER},
            {"exact": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4, "loose": 0.2},
        )

    def test_record_match_tolerance_levels(self):
        from cmd.schengen_tui import audit_record_matches

        log = {
            "raw_command": "rm -rf /tmp/scratch && git push origin main",
            "safety_reason": "force delete of scratch",
            "pane_id": "w1D:p1", "agent_kind": "opencode",
            "decision_layer": "GRAY_ZONE", "id": 42,
        }
        # substring passes at every level (Exact = substring / ratio == 1.0)
        for tol in ("exact", "high", "medium", "low", "loose"):
            self.assertTrue(audit_record_matches(log, "git push", tol), tol)
        # typo "git psh": caught only from Medium down (token-level ratio ~0.6)
        self.assertFalse(audit_record_matches(log, "git psh", "exact"))
        self.assertFalse(audit_record_matches(log, "git psh", "high"))
        self.assertTrue(audit_record_matches(log, "git psh", "medium"))
        # empty query restores everything, on any level
        self.assertTrue(audit_record_matches(log, "", "exact"))
        self.assertTrue(audit_record_matches(log, "   ", "loose"))
        # reason + extra fields are searchable
        self.assertTrue(audit_record_matches(log, "force delete", "exact"))
        self.assertTrue(audit_record_matches(log, "w1d:p1", "exact"))
        self.assertTrue(audit_record_matches(log, "opencode", "exact"))

    def test_record_match_monotonic_looser_is_superset(self):
        from cmd.schengen_tui import AUDIT_SEARCH_TOL_ORDER, audit_record_matches

        import random
        rng = random.Random(7)
        for _ in range(50):
            log = {
                "raw_command": " ".join(rng.choice(["deploy", "rollback", "scale", "inspect", "delete"])
                                       for _ in range(4)),
                "safety_reason": "reason text here",
                "pane_id": "wT:p1", "agent_kind": "opencode",
                "decision_layer": "SHELL_AST", "id": rng.randint(1, 9999),
            }
            q = rng.choice(["deploy", "rollbak", "scale", "scael", "delete", "inspec", "zzz"])
            order = AUDIT_SEARCH_TOL_ORDER  # exact → loose (strict → permissive)
            verdicts = [audit_record_matches(log, q, tol) for tol in order]
            # a looser level must never match FEWER records than a stricter one
            for strict, loose in zip(verdicts, verdicts[1:]):
                self.assertGreaterEqual(loose, strict,
                                        f"non-monotonic for q={q!r} order={order}")

    # ---- live modal: filter on type / tolerance / restore -----------------

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_modal_search_filters_and_restores_rows(self):
        from contextlib import ExitStack
        from unittest.mock import patch

        from textual.widgets import Input, Label, RadioButton

        from cmd.schengen_tui import (
            AUDIT_MODAL_HEAD,
            AuditFullscreenModal,
            PagedAuditDataTable,
            SchengenTUIApp,
        )

        rows = _search_probe_rows()
        fake = lambda limit=10, decision=None, pane_id=None, layer=None, offset=0: rows[offset:offset + limit]
        app = SchengenTUIApp()
        with ExitStack() as stack:
            stack.enter_context(patch("cmd.schengen_tui.get_recent_audit_logs", side_effect=fake))
            async with app.run_test(size=(140, 50)) as pilot:
                app.push_screen(AuditFullscreenModal())
                await pilot.pause(0.6)
                modal = app.screen
                table = modal.query_one("#audit-modal-table", PagedAuditDataTable)
                search = modal.query_one("#audit-search-input", Input)
                self.assertEqual(table.row_count, AUDIT_MODAL_HEAD)

                # Exact tolerance isolates the one row carrying the token
                modal.query_one("#audit-search-tol-exact", RadioButton).value = True
                await pilot.pause(0.3)
                search.value = "service-178"
                await pilot.pause(0.5)
                self.assertEqual(table.row_count, 1)
                self.assertEqual(table.record_at_row(0)["id"], 178)  # row->record intact
                status = modal.query_one("#audit-search-status", Label).content
                self.assertIn("1 / 100", status)

                # clearing restores every loaded row
                search.value = ""
                await pilot.pause(0.5)
                self.assertEqual(table.row_count, AUDIT_MODAL_HEAD)
                self.assertEqual(len(table.audit_records), AUDIT_MODAL_HEAD)
                self.assertIsNone(table._filtered_indices)

                # searchable extra field: pane id (all 100 rows share wSRCH)
                search.value = "wSRCH"
                await pilot.pause(0.5)
                self.assertEqual(table.row_count, AUDIT_MODAL_HEAD)
                search.value = "zzz-no-such-token"
                await pilot.pause(0.5)
                self.assertEqual(table.row_count, 0)
                search.value = ""
                await pilot.pause(0.4)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_modal_search_tolerance_radio_refilters_live(self):
        # Typo'd token "service-17x": Exact rejects it (0 rows), Loose admits
        # every loaded row; intermediates are monotonic along exact→loose.
        from contextlib import ExitStack
        from unittest.mock import patch

        from textual.widgets import Input, RadioButton

        from cmd.schengen_tui import (
            AUDIT_SEARCH_TOL_ORDER,
            AUDIT_SEARCH_TOL_BUTTON_IDS,
            AuditFullscreenModal,
            PagedAuditDataTable,
            SchengenTUIApp,
        )

        rows = _search_probe_rows()
        fake = lambda limit=10, decision=None, pane_id=None, layer=None, offset=0: rows[offset:offset + limit]
        app = SchengenTUIApp()
        with ExitStack() as stack:
            stack.enter_context(patch("cmd.schengen_tui.get_recent_audit_logs", side_effect=fake))
            async with app.run_test(size=(140, 50)) as pilot:
                app.push_screen(AuditFullscreenModal())
                await pilot.pause(0.6)
                modal = app.screen
                table = modal.query_one("#audit-modal-table", PagedAuditDataTable)
                search = modal.query_one("#audit-search-input", Input)
                search.value = "service-17x"
                await pilot.pause(0.5)

                counts = []
                for tol in AUDIT_SEARCH_TOL_ORDER:
                    btn = modal.query_one(f"#{AUDIT_SEARCH_TOL_BUTTON_IDS[tol]}", RadioButton)
                    btn.value = True
                    await pilot.pause(0.4)
                    counts.append(table.row_count)
                    # live re-filter keeps the loaded-record count untouched
                    self.assertEqual(len(table.audit_records), 100)
                exact, high, medium, low, loose = counts
                self.assertEqual(exact, 0)   # typo is NOT a substring / ratio 1.0
                self.assertEqual(loose, 100)  # loosest admits every row
                # strict -> loose must be non-decreasing (monotonic tolerance)
                for stricter, looser in zip(counts, counts[1:]):
                    self.assertGreaterEqual(looser, stricter)
                self.assertGreaterEqual(high, 1)  # token-level typo caught from High
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_modal_search_scrolls_deeper_into_history(self):
        # A query matching only an OLD record (beyond the initial 100) shows 0
        # rows; paging while the filter is active searches deeper and appends
        # just the matching rows (id-dedupe + filter-aware append).
        from contextlib import ExitStack
        from unittest.mock import patch

        from textual.widgets import Input, RadioButton

        from cmd.schengen_tui import (
            AUDIT_MODAL_HEAD,
            AUDIT_PAGE_SIZE,
            AuditFullscreenModal,
            PagedAuditDataTable,
            SchengenTUIApp,
        )

        rows = _search_probe_rows(200)  # ids 200..1 (newest first)
        fake = lambda limit=10, decision=None, pane_id=None, layer=None, offset=0: rows[offset:offset + limit]
        app = SchengenTUIApp()
        with ExitStack() as stack:
            stack.enter_context(patch("cmd.schengen_tui.get_recent_audit_logs", side_effect=fake))
            async with app.run_test(size=(140, 50)) as pilot:
                app.push_screen(AuditFullscreenModal())
                await pilot.pause(0.6)
                modal = app.screen
                table = modal.query_one("#audit-modal-table", PagedAuditDataTable)
                search = modal.query_one("#audit-search-input", Input)
                modal.query_one("#audit-search-tol-exact", RadioButton).value = True
                await pilot.pause(0.3)

                # id 60 is NOT among the first 100 loaded (ids 200..101)
                search.value = "service-060"
                await pilot.pause(0.5)
                self.assertEqual(table.row_count, 0)
                self.assertEqual(len(table.audit_records), AUDIT_MODAL_HEAD)

                # wheel/scroll at the bottom loads the next page; only the
                # matching row from that page is appended (filter preserved)
                table._maybe_load_next_page()
                await pilot.pause(0.4)
                self.assertEqual(len(table.audit_records), AUDIT_MODAL_HEAD + AUDIT_PAGE_SIZE)
                self.assertEqual(table.row_count, 1)
                self.assertEqual(table.record_at_row(0)["id"], 60)
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

    def test_rich_escape_escapes_bare_brackets(self):
        # Regression: rich.markup.escape left bare brackets in shell commands
        # unescaped (e.g. `[by [`, stray `]`, heredoc contents), crashing
        # Text.from_markup with MarkupError. The local rich_escape must escape
        # ALL `[` so arbitrary command text renders literally.
        from rich.text import Text

        cmd = "cat > /tmp/x <<'EOF'\n[by [magenta]gatekeeper[/]]\nEOF\n"
        escaped = rich_escape(cmd)
        self.assertNotIn("[by [", escaped)
        Text.from_markup(escaped)  # must render without MarkupError

    def test_rich_escape_preserves_backslashes(self):
        # Regression: rich_escape must NOT double backslashes — Rich renders a
        # standalone `\` literally (only `\[` is an escape). A command like
        # `sed -E 's/\//_/g'` must round-trip with its backslash intact (INV-HR-6).
        from rich.text import Text

        cmd = "sed -E 's/\\//_/g'"
        escaped = rich_escape(cmd)
        self.assertEqual(escaped, cmd)  # no backslash doubling
        self.assertEqual(Text.from_markup(escaped).plain, cmd)  # round-trips

    def test_adjudication_exchange_line_plain_by_prefix(self):
        # Regression: the "by {approver}" prefix in the adjudication exchange line
        # must be PLAIN text, not wrapped in Rich tag brackets — "[by [magenta]
        # gatekeeper[/]]" is malformed markup (MarkupError in Textual Static.update).
        from rich.text import Text

        badge = format_approver_badge("gatekeeper", "")
        line = f"[green]APPROVE[/]  by {badge}  [dim]02:03[/]  —  ok"
        self.assertNotIn("[by [", line)
        Text.from_markup(line)  # must render without MarkupError

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

    def test_queue_badge_judging_shows_checking(self):
        from cmd.schengen_tui import format_pending_queue_badge

        # Active head while the judge LLM is investigating -> "Gatekeeper
        # Checking" (INV-HR-1/2), NOT "Human Action Required".
        b = format_pending_queue_badge(
            {"id": 1, "status": "PENDING", "decision_layer": "COMPLEXITY_TAX"},
            active_id=1,
            judging=True,
        )
        self.assertIn("Gatekeeper Checking", b)
        self.assertNotIn("Human Action Required", b)

        # Once judging is False (judge finished), the head shows Human Required.
        b = format_pending_queue_badge(
            {"id": 1, "status": "PENDING", "decision_layer": "COMPLEXITY_TAX"},
            active_id=1,
            judging=False,
        )
        self.assertIn("Human Action Required", b)
        self.assertNotIn("Gatekeeper Checking", b)

        # judging=True on a deferred row still shows Deferred (never "Checking").
        b = format_pending_queue_badge(
            {"id": 3, "status": "PENDING", "decision_layer": "SECRET_GUARD"},
            active_id=1,
            slot=3,
            judging=True,
        )
        self.assertIn("Deferred (Slot #3)", b)
        self.assertNotIn("Gatekeeper Checking", b)

        # judging=True on a QUESTION head still shows Human Action Required
        # (a question is never under judge investigation).
        b = format_pending_queue_badge(
            {"id": 1, "status": "DELIVERED", "decision_layer": "QUESTION"},
            active_id=1,
            judging=True,
        )
        self.assertIn("Human Action Required", b)
        self.assertNotIn("Gatekeeper Checking", b)

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
        lines = plain.splitlines()
        # frame lines (top / header box / separator / bottom) are exactly
        # `width` cells; the flat body lines never exceed the card width
        self.assertEqual(cell_len(lines[0]), 70)   # top frame
        self.assertEqual(cell_len(lines[-1]), 70)  # bottom frame
        self.assertTrue(all(cell_len(l) <= 70 for l in lines))
        # INV-HR-6: the command/reason lines are flat — no │ box chars
        cmd_line = next(l for l in lines if l.startswith("💻 Command"))
        self.assertFalse(cmd_line.startswith("│"))
        self.assertFalse(any(
            l.startswith("│") and "git show" in l or l.startswith("│") and "Not in fast-track" in l
            for l in lines
        ))

    def test_decision_card_width_alignment(self):
        from cmd.schengen_tui import format_decision_card
        from rich.cells import cell_len

        # "§"/"£" never appear in the card's static text, so their counts
        # prove the full command/reason survive wrapping (no truncation).
        esc = _fake_escalation(raw_command="§" * 300, safety_reason="£" * 300)
        for w in (52, 60, 70, 78):
            card = format_decision_card(esc, width=w)
            lines = card.plain.splitlines()
            # frame lines stay exactly `w` cells; flat body fits within it
            self.assertEqual(cell_len(lines[0]), w, f"misaligned frame at width {w}")
            self.assertEqual(cell_len(lines[-1]), w, f"misaligned frame at width {w}")
            self.assertTrue(all(cell_len(l) <= w for l in lines), f"body overflows at width {w}")
            # Bug 3: the full command/reason survive — wrapped, never truncated
            self.assertEqual(card.plain.count("§"), 300)
            self.assertEqual(card.plain.count("£"), 300)
            self.assertNotIn("…", card.plain)

    def test_decision_card_copy_paste_flat_no_box(self):
        # INV-HR-6: the full command and full reason are copy-paste-able as
        # original text — no │ box chars interleaved, no padding that needs
        # sanitizing, no truncation. The box only frames the header badge.
        from cmd.schengen_tui import format_decision_card

        esc = _fake_escalation(
            raw_command="git push --force origin main",
            safety_reason="Force-push rewrites published history",
        )
        card = format_decision_card(esc, width=70)
        plain = card.plain
        lines = plain.splitlines()
        # the full command and full reason appear intact on flat lines
        self.assertIn("git push --force origin main", plain)
        self.assertIn("Force-push rewrites published history", plain)
        # no box char wraps the command or the reason
        self.assertNotIn("│ git push", plain)
        self.assertNotIn("│ Force-push", plain)
        self.assertFalse(any(
            (l.startswith("│") and "git push" in l) or (l.startswith("│") and "Force-push" in l)
            for l in lines
        ))
        # the flat command line carries only the label prefix (separate column)
        cmd_line = next(l for l in lines if "git push --force origin main" in l)
        self.assertEqual(cmd_line, "💻 Command  : git push --force origin main")
        # deep-link token + action bar preserved (MUST-NOT-break)
        self.assertIn("[#7494]", plain)
        self.assertIn("/approve 7494", plain)
        self.assertIn("/reject 7494 [reason]", plain)
        self.assertIn("/allow-last", plain)

    def test_decision_card_wrapped_command_flat_lines(self):
        # a command longer than the card wraps onto flat continuation lines —
        # pure text, no │ borders, no indentation padding, nothing truncated
        from cmd.schengen_tui import format_decision_card

        long_cmd = "rm -rf /tmp/herdr-staging && mv -v /tmp/herdr-staging /opt/app"
        esc = _fake_escalation(raw_command=long_cmd, safety_reason="x")
        card = format_decision_card(esc, width=70)
        plain = card.plain
        lines = plain.splitlines()
        self.assertNotIn("…", plain)
        # every word of the command is present, on flat (non-│) lines
        for word in ("rm", "-rf", "/tmp/herdr-staging", "&&", "mv", "-v", "/opt/app"):
            self.assertIn(word, plain)
        # the wrapped command occupies ≥2 lines; the first carries the label
        cmd_lines = [l for l in lines if ("rm" in l or "/opt" in l) and not l.startswith("│")]
        self.assertGreaterEqual(len(cmd_lines), 2)
        self.assertTrue(cmd_lines[0].startswith("💻 Command"))
        # continuation lines are pure original text — no box, no indent padding
        for l in cmd_lines[1:]:
            self.assertFalse(l.startswith("│"))
            self.assertFalse(l.startswith(" "))

    def test_decision_card_fallback_reason(self):
        from cmd.schengen_tui import format_decision_card

        esc = _fake_escalation(safety_reason="", decision_layer="SECRET_GUARD")
        plain = format_decision_card(esc, width=60).plain
        self.assertIn("SECRET_GUARD — Deferred to human review", plain)

    def test_chat_plain_text_preserves_card_tokens(self):
        from cmd.schengen_tui import _chat_plain_text

        plain = _chat_plain_text(
            "[bold red blink]🚨 ▶ ACTION REQUIRED: Escalation [#7494] Awaiting Commander Decision[/]\n"
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

    def _mount_patches(self, active_esc, pending, question_esc=None):
        from unittest.mock import MagicMock, patch

        return [
            # Command-slot head EXCLUDES questions (INV-QN-1/2); the question is
            # surfaced via the sidebar #question-hint (get_oldest_question_escalation).
            patch("cmd.schengen_tui.get_current_command_escalation", return_value=active_esc),
            patch("cmd.schengen_tui.get_oldest_question_escalation", return_value=question_esc),
            patch("cmd.schengen_tui.get_pending_escalations", return_value=pending),
            patch("cmd.schengen_tui.list_active_guard_locks", return_value=[]),
            patch("cmd.schengen_tui.get_recent_audit_logs", return_value=[]),
            patch("cmd.schengen_tui.get_pane_info", return_value={"agent_status": "blocked"}),
            patch("cmd.schengen_tui.get_pane_direct_config", return_value={}),
            patch("cmd.schengen_tui.get_batch_approval_config", return_value={"batch_approval_enabled": False}),
            patch("cmd.schengen_tui.read_in_flight_state", return_value=[]),
            patch("cmd.schengen_tui.subprocess.Popen", return_value=MagicMock()),
        ]

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_alarm_banner_and_radar_card_when_active(self):
        # Phase 2b (INV-HR-1/2): first tick shows "Gatekeeper Checking" while
        # the judge round-trip is in flight; once the judge finishes and the
        # escalation is still PENDING, the red banner/action-card/decision
        # card render.
        from cmd.schengen_tui import SchengenTUIApp, Static
        from contextlib import ExitStack
        from unittest.mock import MagicMock

        esc = _fake_escalation()
        app = SchengenTUIApp()
        app.is_controller = True
        # Patch the judge invocation BEFORE run_test: on_mount's first radar
        # tick runs the first-sight block, which would otherwise schedule the
        # REAL @work process_user_chat — its judge worker calls the LLM (fails
        # fast with no key) and its finally clears _judging_escalation_id
        # before the first assertion. Mocking pre-mount keeps the two-phase
        # transition deterministic regardless of whether an LLM key is present.
        app.process_user_chat = MagicMock()
        with ExitStack() as stack:
            for p in self._mount_patches(esc, [esc]):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.7)
                banner = app.query_one("#active-target-banner", Static)
                # judge in flight -> checking state, never the red card
                self.assertIn("Gatekeeper Checking", banner.content)
                self.assertIn("Autonomous inspection in progress", banner.content)
                self.assertNotIn("ACTION REQUIRED", banner.content)
                # radar card tier 2 (gatekeeper judging): visible but NOT
                # claiming human intervention yet (INV-HR-1/2)
                card = app.query_one("#action-card", Static)
                self.assertTrue(card.display)
                self.assertIn("Gatekeeper", card.content)
                self.assertNotIn("HUMAN INTERVENTION REQUIRED", card.content)
                # judge round-trip completes (finally clears state)
                app._judging_escalation_id = None
                app._processing_chat = False
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
                # decision card reached the chat at Phase 2b
                chat_plain = "\n".join(app._chat_plain)
                self.assertIn("Human Authorization Required", chat_plain)
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
        # Question 분리 (INV-QN-1/2): a QUESTION no longer occupies the Command
        # Approval banner — it is surfaced via the sidebar #question-hint and
        # answered in the pane (never adjudicated).
        from cmd.schengen_tui import SchengenTUIApp, Static
        from contextlib import ExitStack

        esc = _fake_escalation(decision_layer="QUESTION", raw_command="rm -rf /tmp/scratch?")
        app = SchengenTUIApp()
        app.is_controller = True
        with ExitStack() as stack:
            for p in self._mount_patches(None, [esc], question_esc=esc):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.7)
                banner = app.query_one("#active-target-banner", Static)
                # command slot is EMPTY — the question must NOT appear in it
                self.assertNotIn("❓", banner.content)
                self.assertNotIn("Answer this question", banner.content)
                self.assertNotIn("ACTION REQUIRED", banner.content)
                # the question is surfaced as a non-blocking sidebar hint
                hint = app.query_one("#question-hint", Static)
                self.assertTrue(hint.display)
                self.assertIn("Question Awaiting Answer", hint.content)
                self.assertIn("w1D:p1", hint.content)
                # radar card hidden (no command awaiting adjudication)
                card = app.query_one("#action-card", Static)
                self.assertFalse(card.display)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()


class TestTUIStatusCardAndSettings(unittest.TestCase):
    """Sprint 2: sidebar System Status card + consolidated Settings modal.

    Presentation/organization only: every value comes from EXISTING config
    (guard_config getters, daemon lock state, runtime role). Approval Bias /
    Fast-Track have no backing config keys and are intentionally absent.
    First screen shows ONLY Guard daemon + Mode (SettingsModal holds the rest).
    """

    def test_status_card_text_render(self):
        from cmd.schengen_tui import format_status_card_text

        text = format_status_card_text(
            is_controller=True,
            leader_pid=None,
            guard_pid=4242,
        )
        self.assertIn("Mode  :", text)
        self.assertIn("Controller (👑)", text)
        self.assertIn("Guard :", text)
        self.assertIn("ACTIVE (🛡️) PID 4242", text)
        # first-screen declutter: secondary knobs must NOT appear on the card
        self.assertNotIn("Lang  :", text)
        self.assertNotIn("Instr :", text)
        # no invented rows
        self.assertNotIn("Bias", text)
        self.assertNotIn("Fast", text)

    def test_status_card_text_variants(self):
        from cmd.schengen_tui import format_status_card_text

        obs = format_status_card_text(
            is_controller=False, leader_pid=7, guard_pid=None,
        )
        self.assertIn("Observer (👁) — Leader PID 7", obs)
        self.assertIn("INACTIVE (○)", obs)
        self.assertNotIn("English (EN)", obs)
        self.assertNotIn("Approve+Reject", obs)

        off = format_status_card_text(
            is_controller=True, leader_pid=None, guard_pid=None,
        )
        self.assertIn("Controller (👑)", off)
        self.assertIn("INACTIVE (○)", off)

        with_target = format_status_card_text(
            is_controller=True, leader_pid=None, guard_pid=9, guard_target="auto",
        )
        self.assertIn("ACTIVE (🛡️) PID 9", with_target)
        self.assertIn("auto", with_target)

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

        def _set_instr(**kw):
            state["instr"].update({k: v for k, v in kw.items()})

        def _set_batch(enabled=None, ttl_seconds=None):
            if enabled is not None:
                state["batch"]["batch_approval_enabled"] = enabled
            if ttl_seconds is not None:
                state["batch"]["human_approval_ttl_seconds"] = ttl_seconds

        def _set_origin(enabled=None):
            if enabled is not None:
                state["origin"]["origin_weighting_enabled"] = enabled

        def _set_pd(enabled=None, confirm_polls=None):
            if enabled is not None:
                state["pd"]["pane_direct_eviction_enabled"] = enabled
            if confirm_polls is not None:
                state["pd"]["pane_direct_confirm_polls"] = confirm_polls

        return [
            patch("cmd.schengen_tui.list_active_guard_locks", side_effect=lambda: state["locks"]),
            patch("cmd.schengen_tui.get_instruction_delivery_config", side_effect=lambda: dict(state["instr"])),
            patch("cmd.schengen_tui.set_instruction_delivery_config", side_effect=_set_instr),
            patch("cmd.schengen_tui.get_answer_language", side_effect=lambda: state["lang"]),
            patch("cmd.schengen_tui.set_answer_language", side_effect=lambda lang: state.update(lang=lang)),
            patch("cmd.schengen_tui.get_channel_approve_config", side_effect=lambda: state["chan"]),
            patch("cmd.schengen_tui.set_channel_approve_config", side_effect=lambda v: state.update(chan=v)),
            patch("cmd.schengen_tui.get_batch_approval_config", side_effect=lambda: dict(state["batch"])),
            patch("cmd.schengen_tui.set_batch_approval_config", side_effect=_set_batch),
            patch("cmd.schengen_tui.get_origin_weighting_config", side_effect=lambda: dict(state["origin"])),
            patch("cmd.schengen_tui.set_origin_weighting_config", side_effect=_set_origin),
            patch("cmd.schengen_tui.get_pane_direct_config", side_effect=lambda: dict(state["pd"])),
            patch("cmd.schengen_tui.set_pane_direct_config", side_effect=_set_pd),
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
            "batch": {"batch_approval_enabled": True},
            "origin": {"origin_weighting_enabled": True},
            "pd": {"pane_direct_eviction_enabled": True},
        }

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_status_card_live_updates_from_config(self):
        from cmd.schengen_tui import SchengenTUIApp, Static
        from contextlib import ExitStack
        from textual.widgets import Button

        state = self._fresh_state()
        app = SchengenTUIApp()
        with ExitStack() as stack:
            for p in self._config_patches(state):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.7)
                card = app.query_one("#status-card", Static)
                self.assertIn("INACTIVE", card.content)
                guard_btn = app.query_one("#btn-toggle-guard", Button)
                self.assertIn("INACTIVE", guard_btn.label.plain)
                # guard comes up -> next radar tick reflects it
                state["locks"].append(("auto", "/tmp/l", 1234))
                await pilot.pause(0.7)
                self.assertIn("ACTIVE (🛡️) PID 1234", card.content)
                self.assertIn("ACTIVE", guard_btn.label.plain)
                # first-screen declutter: Lang/Instr rows never appear
                self.assertNotIn("Lang  :", card.content)
                self.assertNotIn("Instr :", card.content)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_settings_modal_opens_via_slash_command_and_toggles(self):
        from cmd.schengen_tui import SchengenTUIApp, SettingsModal
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

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_first_screen_decluttered_guard_and_mode_only(self):
        """First screen keeps ONLY the Guard toggle + Mode; secondary knobs live
        in the SettingsModal (docs/todo/TODO_phase3.md "[Task/UX] Settings Modal 분리")."""
        from cmd.schengen_tui import SchengenTUIApp, Static
        from contextlib import ExitStack
        from textual.widgets import Button

        state = self._fresh_state()
        app = SchengenTUIApp()
        with ExitStack() as stack:
            for p in self._config_patches(state):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.7)
                # the 2 always-visible controls exist
                guard_btn = app.query_one("#btn-toggle-guard", Button)
                self.assertIn("Guard", guard_btn.label.plain)
                card = app.query_one("#status-card", Static)
                self.assertIn("Mode  :", card.content)
                self.assertIn("Guard :", card.content)
                # settings entry button present
                app.query_one("#btn-open-settings", Button)
                # relocated controls are GONE from the first screen
                for gone_id in (
                    "#instruction-control",
                    "#answer-language-set",
                    "#btn-toggle-approve-instr",
                    "#btn-toggle-reject-instr",
                    "#btn-toggle-channel-approve",
                ):
                    try:
                        app.query_one(gone_id)
                        self.fail(f"first screen must not contain {gone_id}")
                    except Exception:
                        pass
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_settings_button_opens_modal(self):
        from cmd.schengen_tui import SchengenTUIApp, SettingsModal
        from contextlib import ExitStack
        from textual.widgets import Button

        state = self._fresh_state()
        app = SchengenTUIApp()
        with ExitStack() as stack:
            for p in self._config_patches(state):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                app.query_one("#btn-open-settings", Button).press()
                await pilot.pause()
                self.assertIsInstance(app.screen, SettingsModal)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_settings_modal_automation_toggles(self):
        """Batch approval / origin weighting / pane-direct toggles use the
        EXISTING guard_config setters (UI relocation only, no semantics change)."""
        from cmd.schengen_tui import SchengenTUIApp, SettingsModal
        from contextlib import ExitStack
        from textual.widgets import Button

        state = self._fresh_state()
        app = SchengenTUIApp()
        with ExitStack() as stack:
            for p in self._config_patches(state):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                app.action_open_settings()
                await pilot.pause()
                modal = app.screen
                self.assertIsInstance(modal, SettingsModal)
                # initial states (all ON by default in the fresh state)
                batch_btn = modal.query_one("#set-batch-approval", Button)
                origin_btn = modal.query_one("#set-origin-weighting", Button)
                pd_btn = modal.query_one("#set-pane-direct", Button)
                self.assertIn("ON", batch_btn.label.plain)
                self.assertIn("ON", origin_btn.label.plain)
                self.assertIn("ON", pd_btn.label.plain)
                # toggle each -> config flips via the existing setters
                batch_btn.press()
                await pilot.pause()
                self.assertFalse(state["batch"]["batch_approval_enabled"])
                self.assertIn("OFF", modal.query_one("#set-batch-approval", Button).label.plain)
                origin_btn.press()
                await pilot.pause()
                self.assertFalse(state["origin"]["origin_weighting_enabled"])
                self.assertIn("OFF", modal.query_one("#set-origin-weighting", Button).label.plain)
                pd_btn.press()
                await pilot.pause()
                self.assertFalse(state["pd"]["pane_direct_eviction_enabled"])
                self.assertIn("OFF", modal.query_one("#set-pane-direct", Button).label.plain)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()


class TestQuestionNonBlockingTUI(unittest.TestCase):
    """Question 분리 (non-blocking) TUI surface (#160 / INV-QN-1..5).

    A PENDING QUESTION is surfaced via the sidebar #question-hint, never in the
    Command Approval banner; /jump focuses an arbitrary pane.
    """

    def test_format_question_hint(self):
        from cmd.schengen_tui import format_question_hint

        hint = format_question_hint({"pane_id": "w1D:p5"})
        self.assertIn("💬 [w1D:p5 Question Awaiting Answer]", hint)

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_question_does_not_block_command_slot(self):
        from cmd.schengen_tui import SchengenTUIApp

        app = SchengenTUIApp.__new__(SchengenTUIApp)
        app._columns_initialized = True
        app.is_controller = False
        app.leader_pid = None
        app._last_guard_active = False
        app._last_audit_hash = ""
        app._last_escalation_hash = ""
        app._pane_direct_polls = {}
        app._pane_direct_head = None
        app._last_active_id = None
        app._last_resolved_ref = None
        app._notified_escalation_ids = set()
        app._processing_chat = False
        app._write = MagicMock()
        app.agent = MagicMock()
        app.agent.get_token_usage_stats.return_value = {
            "api_calls": 1,
            "prompt_tokens": 2,
            "completion_tokens": 3,
            "cached_tokens": 4,
            "cache_hit_pct": "0%",
            "inspector_in": 0,
            "inspector_out": 0,
            "judge_in": 0,
            "judge_out": 0,
        }

        # Per-id fake widgets: capture banner + question-hint content.
        captured = {}

        def fake_query_one(selector, *a, **kw):
            sel = selector if isinstance(selector, str) else str(selector)
            if sel not in captured:
                w = MagicMock()
                w.size.width = 40
                w.content_region.width = 74
                captured[sel] = w
            return captured[sel]

        app.query_one = fake_query_one

        command_esc = {
            "id": 2,
            "pane_id": "w1D:c",
            "agent_kind": "agy",
            "decision_layer": "GRAY_ZONE",
            "raw_command": "rm -rf /tmp/command_slot",
            "safety_reason": "test command",
        }
        question_esc = {
            "id": 1,
            "pane_id": "w1D:q",
            "agent_kind": "agy",
            "decision_layer": "QUESTION",
            "raw_command": "question: proceed?",
            "safety_reason": "test question",
        }
        with patch("cmd.schengen_tui.get_current_command_escalation", return_value=command_esc), patch(
            "cmd.schengen_tui.get_oldest_question_escalation", return_value=question_esc
        ), patch("cmd.schengen_tui.list_active_guard_locks", return_value=[]), patch(
            "cmd.schengen_tui.get_recent_audit_logs", return_value=[]
        ), patch("cmd.schengen_tui.get_pending_escalations", return_value=[]), patch(
            "cmd.schengen_tui.get_answer_language", return_value="korean"
        ), patch("cmd.schengen_tui.get_instruction_delivery_config", return_value={}):
            app.update_radar_data(force=True)

        banner_text = captured["#active-target-banner"].update.call_args.args[0]
        self.assertIn("rm -rf /tmp/command_slot", banner_text)   # COMMAND in the slot
        self.assertNotIn("question: proceed?", banner_text)       # QUESTION NOT in the slot

        hint_text = captured["#question-hint"].update.call_args.args[0]
        self.assertIn("💬 [w1D:q Question Awaiting Answer]", hint_text)  # sidebar hint

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_jump_command_dispatch(self):
        import asyncio

        from cmd.schengen_tui import SchengenTUIApp

        app = SchengenTUIApp.__new__(SchengenTUIApp)
        app._processing_chat = False
        app.is_controller = True
        app.leader_pid = None
        app._write = MagicMock()
        app.update_radar_data = MagicMock()
        app.query_one = MagicMock()
        app._last_chat_date = None
        # process_user_chat is @work-decorated (needs a live Textual app); call
        # the unwrapped coroutine directly on the bare instance.
        process_chat = SchengenTUIApp.process_user_chat.__wrapped__
        with patch("cmd.schengen_tui.run_cmd", return_value="") as mock_run:
            asyncio.run(process_chat(app, "/jump w1D:p9"))
        mock_run.assert_called_once_with(["herdr", "pane", "focus", "w1D:p9"])
        app._write.assert_any_call("[bold cyan]↩ Focusing agent pane w1D:p9...[/]")
        app.update_radar_data.assert_called_once_with(force=True)

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_jump_requires_pane_id(self):
        import asyncio

        from cmd.schengen_tui import SchengenTUIApp

        app = SchengenTUIApp.__new__(SchengenTUIApp)
        app._processing_chat = False
        app.is_controller = True
        app.leader_pid = None
        app._write = MagicMock()
        app.update_radar_data = MagicMock()
        app.query_one = MagicMock()
        app._last_chat_date = None
        process_chat = SchengenTUIApp.process_user_chat.__wrapped__
        with patch("cmd.schengen_tui.run_cmd", return_value="") as mock_run:
            asyncio.run(process_chat(app, "/jump"))
        mock_run.assert_not_called()
        app._write.assert_any_call("[bold yellow]⚠️ Usage: /jump <pane_id>[/]")


class TestTUIPhase2JudgeGating(unittest.TestCase):
    """Phase-2 gating (INV-HR-1..3): judge-in-flight vs final human-required.

    The red "Human Authorization Required" card must appear ONLY at the final
    stage — after the TUI-local judge LLM finishes and the escalation is still
    PENDING. During the judge round-trip the TUI shows a checking state.
    """

    def test_judging_state_initialized(self):
        from cmd.schengen_tui import SchengenTUIApp

        app = SchengenTUIApp()
        self.assertIsNone(app._judging_escalation_id)
        self.assertEqual(app._decision_card_written, set())
        if app.tui_lock_fd:
            app.tui_lock_fd.close()

    def test_author_label_inspector_vs_user(self):
        # INV-HR-3: author="inspector" renders the system label, not "👤 You:"
        from cmd.schengen_tui import _chat_plain_text

        plain = _chat_plain_text("[bold cyan]🤖 Inspector → Gatekeeper:[/] evaluating…")
        self.assertIn("Inspector → Gatekeeper", plain)
        self.assertNotIn("👤 You:", plain)
        plain_user = _chat_plain_text("\n[bold yellow]👤 You:[/] /approve 1")
        self.assertIn("👤 You:", plain_user)
        self.assertNotIn("Inspector → Gatekeeper", plain_user)

    def test_decision_card_full_text_wrapped_not_truncated(self):
        # Bug 3: the full command and reason survive word-wrap (no "…").
        from cmd.schengen_tui import format_decision_card

        esc = _fake_escalation(
            raw_command=" ".join(f"flag-{i}" for i in range(40)),
            safety_reason=" ".join(f"reasonword{i}" for i in range(40)),
        )
        plain = format_decision_card(esc, width=70).plain
        self.assertIn("flag-39", plain)
        self.assertIn("reasonword39", plain)
        self.assertNotIn("…", plain)
        # deep-link token + action bar preserved (MUST-NOT-break)
        self.assertIn("[#7494]", plain)
        self.assertIn("/approve 7494", plain)
        self.assertIn("/reject 7494 [reason]", plain)
        self.assertIn("/allow-last", plain)
        self.assertIn("Human Authorization Required", plain)


class TestTUIPhase2JudgeGatingAsync(unittest.IsolatedAsyncioTestCase):
    """Live radar gating scenarios (INV-HR-1..5).

    NOTE: mocks must be installed BEFORE ``run_test()`` — the first radar tick
    can fire during app startup, before the first ``pilot.pause()``.
    """

    def _patches(self, active_esc, pending):
        from unittest.mock import MagicMock, patch

        return [
            patch("cmd.schengen_tui.get_current_command_escalation", return_value=active_esc),
            patch("cmd.schengen_tui.get_oldest_question_escalation", return_value=None),
            patch("cmd.schengen_tui.get_pending_escalations", return_value=pending),
            patch("cmd.schengen_tui.list_active_guard_locks", return_value=[]),
            patch("cmd.schengen_tui.get_recent_audit_logs", return_value=[]),
            patch("cmd.schengen_tui.get_pane_info", return_value={"agent_status": "blocked"}),
            patch("cmd.schengen_tui.get_pane_direct_config", return_value={}),
            patch("cmd.schengen_tui.get_batch_approval_config", return_value={"batch_approval_enabled": False}),
            patch("cmd.schengen_tui.read_in_flight_state", return_value=[]),
            patch("cmd.schengen_tui.subprocess.Popen", return_value=MagicMock()),
        ]

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_1_judging_shows_checking_not_human_required(self):
        # INV-HR-1: while the judge investigates, the banner says
        # "Gatekeeper Checking", never "Human Authorization Required"; the
        # action card is hidden and no decision card is written.
        from cmd.schengen_tui import SchengenTUIApp, Static
        from contextlib import ExitStack
        from unittest.mock import MagicMock

        esc = _fake_escalation()
        app = SchengenTUIApp()
        app.is_controller = True
        app.process_user_chat = MagicMock()  # judge invoked but never completes
        with ExitStack() as stack:
            for p in self._patches(esc, [esc]):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.7)
                banner = app.query_one("#active-target-banner", Static)
                self.assertIn("Gatekeeper Checking", banner.content)
                self.assertNotIn("ACTION REQUIRED", banner.content)
                self.assertNotIn("Human Authorization", banner.content)
                # radar card tier 2: gatekeeper phase visible, human NOT required
                card = app.query_one("#action-card", Static)
                self.assertTrue(card.display)
                self.assertIn("Gatekeeper judging", card.content)
                self.assertNotIn("HUMAN INTERVENTION REQUIRED", card.content)
                chat_plain = "\n".join(app._chat_plain)
                self.assertNotIn("Human Authorization Required", chat_plain)
                # judge was invoked exactly once, authored by the inspector
                app.process_user_chat.assert_called_once()
                self.assertEqual(app.process_user_chat.call_args.kwargs.get("author"), "inspector")
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_2_judge_finished_pending_renders_red_card(self):
        # INV-HR-2: judge finished + escalation still PENDING -> Phase 2b red
        # banner/action-card/decision card.
        from cmd.schengen_tui import SchengenTUIApp, Static
        from contextlib import ExitStack
        from unittest.mock import MagicMock

        esc = _fake_escalation()
        app = SchengenTUIApp()
        app.is_controller = True
        app.process_user_chat = MagicMock()
        with ExitStack() as stack:
            for p in self._patches(esc, [esc]):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.7)
                # judge round-trip completes; escalation stays PENDING
                app._judging_escalation_id = None
                app._processing_chat = False
                await pilot.pause(0.7)
                banner = app.query_one("#active-target-banner", Static)
                self.assertIn("ACTION REQUIRED", banner.content)
                self.assertNotIn("Gatekeeper Checking", banner.content)
                card = app.query_one("#action-card", Static)
                self.assertTrue(card.display)
                chat_plain = "\n".join(app._chat_plain)
                self.assertIn("Human Authorization Required", chat_plain)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_3_inspector_invocation_label_in_chat(self):
        # INV-HR-3: the judge invocation renders "Inspector → Gatekeeper",
        # never "👤 You:". The REAL process_user_chat runs (its send_message is
        # mocked) so the author label is actually written to the chat.
        from cmd.schengen_tui import SchengenTUIApp
        from contextlib import ExitStack
        from unittest.mock import AsyncMock

        esc = _fake_escalation()
        app = SchengenTUIApp()
        app.is_controller = True
        app.agent.send_message = AsyncMock(return_value="ok")
        with ExitStack() as stack:
            for p in self._patches(esc, [esc]):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.7)
                chat_plain = "\n".join(app._chat_plain)
                self.assertIn("Inspector → Gatekeeper", chat_plain)
                self.assertNotIn("👤 You:", chat_plain)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_4_user_input_still_renders_you_label(self):
        from cmd.schengen_tui import SchengenTUIApp
        from contextlib import ExitStack
        from unittest.mock import AsyncMock

        app = SchengenTUIApp()
        app.agent.send_message = AsyncMock(return_value="Understood.")
        with ExitStack() as stack:
            for p in self._patches(None, []):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                w = app.process_user_chat("hello gatekeeper")
                await w.wait()
                await pilot.pause()
                chat_plain = "\n".join(app._chat_plain)
                self.assertIn("👤 You: hello gatekeeper", chat_plain)
                self.assertNotIn("Inspector → Gatekeeper", chat_plain)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_5_judging_flag_cleared_on_round_trip_completion(self):
        from cmd.schengen_tui import SchengenTUIApp
        from contextlib import ExitStack
        from unittest.mock import AsyncMock

        app = SchengenTUIApp()
        app.agent.send_message = AsyncMock(return_value="ok")
        with ExitStack() as stack:
            for p in self._patches(None, []):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                app._judging_escalation_id = 7494
                w = app.process_user_chat(
                    "New escalation intercepted. Evaluate command safety, investigate using tools if necessary, and report or adjudicate.",
                    author="inspector",
                )
                await w.wait()
                await pilot.pause()
                self.assertIsNone(app._judging_escalation_id)
                self.assertFalse(app._processing_chat)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_6_judge_auto_resolve_queue_clear_no_red_card(self):
        from cmd.schengen_tui import SchengenTUIApp, Static
        from contextlib import ExitStack
        from unittest.mock import MagicMock, patch

        esc = _fake_escalation()
        state = {"esc": esc}
        app = SchengenTUIApp()
        app.is_controller = True
        app.process_user_chat = MagicMock()
        with ExitStack() as stack:
            for p in self._patches(None, []):
                stack.enter_context(p)
            stack.enter_context(patch(
                "cmd.schengen_tui.get_current_command_escalation",
                side_effect=lambda **kw: state["esc"],
            ))
            stack.enter_context(patch(
                "cmd.schengen_tui.get_pending_escalations",
                side_effect=lambda **kw: [state["esc"]] if state["esc"] else [],
            ))
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.7)
                banner = app.query_one("#active-target-banner", Static)
                self.assertIn("Gatekeeper Checking", banner.content)
                # the judge auto-resolves the escalation -> queue clears
                state["esc"] = None
                app._judging_escalation_id = None
                app._processing_chat = False
                await pilot.pause(0.7)
                banner = app.query_one("#active-target-banner", Static)
                self.assertIn("No active escalations", banner.content)
                self.assertNotIn("ACTION REQUIRED", banner.content)
                chat_plain = "\n".join(app._chat_plain)
                self.assertNotIn("Human Authorization Required", chat_plain)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_7_judge_error_falls_back_to_red_card(self):
        # fail-safe: a judge round-trip error clears the judging state and the
        # still-PENDING escalation renders the Phase-2b red card.
        from cmd.schengen_tui import SchengenTUIApp, Static
        from contextlib import ExitStack
        from unittest.mock import AsyncMock

        esc = _fake_escalation()
        app = SchengenTUIApp()
        app.is_controller = True
        app.agent.send_message = AsyncMock(side_effect=RuntimeError("LLM down"))
        with ExitStack() as stack:
            for p in self._patches(esc, [esc]):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                # wait for the failing judge round-trip to finish (finally
                # clears the judging state)
                for _ in range(8):
                    await pilot.pause(0.3)
                    if app._judging_escalation_id is None:
                        break
                await pilot.pause(0.7)  # next tick -> Phase 2b
                banner = app.query_one("#active-target-banner", Static)
                self.assertIn("ACTION REQUIRED", banner.content)
                chat_plain = "\n".join(app._chat_plain)
                self.assertIn("Human Authorization Required", chat_plain)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    async def test_8_judge_worker_guard_return_clears_flag(self):
        # Fix 2: a judge worker that hits the _processing_chat guard (early
        # return BEFORE the LLM try/finally) must still clear
        # _judging_escalation_id — otherwise the escalation stays stuck in
        # "Gatekeeper Checking" with the red card suppressed forever. The
        # wrapper finally must NOT clobber the OTHER chat's in-flight flag.
        from cmd.schengen_tui import SchengenTUIApp
        from contextlib import ExitStack
        from unittest.mock import AsyncMock

        app = SchengenTUIApp()
        app.is_controller = True
        app.agent.send_message = AsyncMock(return_value="ok")
        with ExitStack() as stack:
            for p in self._patches(None, []):
                stack.enter_context(p)
            async with app.run_test(size=(120, 40)) as pilot:
                # simulate the sub-tick race: another chat owns _processing_chat
                # when the inspector's judge worker starts
                app._processing_chat = True
                app._judging_escalation_id = 7494
                w = app.process_user_chat(
                    "New escalation intercepted. Evaluate command safety, investigate using tools if necessary, and report or adjudicate.",
                    author="inspector",
                )
                await w.wait()
                await pilot.pause()
                # guard returned early, but the wrapper finally cleared the flag
                self.assertIsNone(app._judging_escalation_id)
                # _processing_chat belongs to the other in-flight chat — untouched
                self.assertTrue(app._processing_chat)
                if app.tui_lock_fd:
                    app.tui_lock_fd.close()


if __name__ == "__main__":
    unittest.main()
