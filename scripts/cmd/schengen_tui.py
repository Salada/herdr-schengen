#!/usr/bin/env python3
"""Schengen Guardian TUI (Textual 2-Column Agent Interface).

Key Features:
- Sequential FIFO Pipeline: Only the oldest pending escalation is sent to chat. Next pending is delivered ONLY after the current one is resolved.
- Cumulative Token & Context Cache Meter (#token-meter-box): Real-time display of tokens & prefix cache hit %.
- Floating Active Target Banner (#active-target-banner): Always shows the currently pending escalation at top of chat.
- Clean Escalation List: Removes raw 'PEND' string artifact; clean badges only.
- AGY Tab Amend Key Flow: Tab -> send security note -> Enter.
- Distinct Visual Dividers: Clear separator lines between turns and escalation lifecycle events.
"""

import asyncio
import logging
import os
import re
import signal
import subprocess
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Prevent TUI process from exiting on SIGHUP daemon reloads
if hasattr(signal, "SIGHUP"):
    try:
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
    except Exception:
        pass

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parent
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from rich.markdown import Markdown
from rich.markup import escape as rich_escape
from rich.segment import Segment
from rich.style import Style
from rich.text import Text
from textual import events, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.drivers.linux_driver import LinuxDriver
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.selection import Selection
from textual.strip import Strip
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Static,
    TextArea,
)

from core.feature_db import (
    add_feature_request,
    create_feature_request_with_similars,
    list_feature_requests,
    search_similar_feature_requests,
)
from core.guard_db import (
    LOG_DIR,
    get_instruction_delivery_config,
    get_pending_escalations,
    get_recent_audit_logs,
    get_session_dashboard_summary,
    set_instruction_delivery_config,
)
from tools.schengen_agent_llm import SchengenAgentChat, get_current_active_escalation
from cmd.schengen_watcher import list_active_guard_locks


def format_local_time(iso_ts: str) -> str:
    """Convert UTC ISO timestamp string into Local Time HH:MM format."""
    try:
        if not iso_ts:
            return ""
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local_dt = dt.astimezone()
        return local_dt.strftime("%H:%M")
    except Exception:
        return iso_ts.split("T")[-1][:5] if "T" in iso_ts else iso_ts[:5]


# --- Mouse-event diagnostic logging (gated by SCHENGEN_MOUSE_DEBUG) ---------
#
# Permanent, opt-in instrumentation for debugging terminal mouse-coordinate /
# click-routing issues (e.g. the "Recent Audits click -> focus goes to chat"
# bug). It is OFF by default and only writes when the environment variable
# SCHENGEN_MOUSE_DEBUG is set to a truthy value (1/true/yes/on). Logs rotate
# via a standard RotatingFileHandler so it never grows unbounded.

MOUSE_DEBUG_LOG_PATH = LOG_DIR / "schengen_tui_mouse.log"
_mouse_debug_logger: Optional[logging.Logger] = None


def _mouse_debug_enabled() -> bool:
    return os.environ.get("SCHENGEN_MOUSE_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")


def _mouse_debug_log(message: str) -> None:
    """Append a mouse-event line to the rotating debug log (no-op unless enabled)."""
    global _mouse_debug_logger
    if not _mouse_debug_enabled():
        return
    if _mouse_debug_logger is None:
        _mouse_debug_logger = logging.getLogger("schengen.tui.mouse")
        _mouse_debug_logger.setLevel(logging.DEBUG)
        _mouse_debug_logger.propagate = False
        handler = RotatingFileHandler(
            MOUSE_DEBUG_LOG_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        _mouse_debug_logger.addHandler(handler)
    _mouse_debug_logger.debug(message)


class FocusableRichLog(RichLog):
    """RichLog supporting keyboard focus, mouse scroll, visual selection, and page navigation."""
    can_focus = True

    def get_selection(self, selection: Selection) -> Optional[Tuple[str, str]]:
        """Extract text under the user's mouse selection."""
        text = "\n".join("".join(s.text for s in strip._segments) for strip in self.lines)
        return selection.extract(text), "\n"

    def selection_updated(self, selection: Optional[Selection]) -> None:
        """Invalidate render cache on selection update."""
        self._line_cache.clear()
        self.refresh()

    def _render_line(self, y: int, scroll_x: int, width: int) -> Strip:
        """Render line with offset metadata and active text selection styling."""
        if y >= len(self.lines):
            return Strip.blank(width, self.rich_style)

        key = (y + self._start_line, scroll_x, width, self._widest_line_width, self.text_selection)
        if key in self._line_cache:
            return self._line_cache[key]

        line = self.lines[y].crop_extend(scroll_x, scroll_x + width, self.rich_style)

        selection = self.text_selection
        if selection is not None:
            span = selection.get_span(y)
            if span is not None:
                start, end = span
                selection_style = self.screen.get_component_rich_style("screen--selection")
                new_segments = []
                curr_x = 0
                for seg in line._segments:
                    seg_len = len(seg.text)
                    seg_start = curr_x
                    seg_end = curr_x + seg_len
                    curr_x = seg_end
                    if end != -1 and seg_start >= end:
                        new_segments.append(seg)
                    elif seg_end <= start:
                        new_segments.append(seg)
                    else:
                        s = max(0, start - seg_start)
                        e = seg_len if end == -1 else min(seg_len, end - seg_start)
                        part1 = seg.text[:s]
                        part2 = seg.text[s:e]
                        part3 = seg.text[e:]
                        base_style = seg.style or Style()
                        sel_style = base_style + selection_style
                        if part1:
                            new_segments.append(Segment(part1, seg.style))
                        if part2:
                            new_segments.append(Segment(part2, sel_style))
                        if part3:
                            new_segments.append(Segment(part3, seg.style))
                line = Strip(new_segments, line.cell_length)

        line = line.apply_offsets(scroll_x, y)
        self._line_cache[key] = line
        return line

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape":
            app = getattr(self, "app", None) or getattr(self, "_app", None)
            if app and hasattr(app, "handle_esc_press"):
                if app.handle_esc_press():
                    event.stop()
                    event.prevent_default()
                    return
        elif event.key == "pageup":
            event.stop()
            self.scroll_page_up()
        elif event.key == "pagedown":
            event.stop()
            self.scroll_page_down()
        elif event.key == "home":
            event.stop()
            self.scroll_home()
        elif event.key == "end":
            event.stop()
            self.scroll_end()
        elif event.key == "up":
            event.stop()
            self.scroll_up()
        elif event.key == "down":
            event.stop()
            self.scroll_down()


class AuditFullscreenModal(ModalScreen):
    """Fullscreen expanded view for Recent Audit Ledger with full single-line command display."""
    CSS = """
    AuditFullscreenModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.85);
    }
    #audit-modal-dialog {
        width: 98%;
        height: 94%;
        background: $surface-darken-1;
        border: tall $accent;
        padding: 1;
        layout: vertical;
    }
    #audit-modal-table {
        width: 100%;
        height: 1fr;
        background: $surface;
        border: solid $surface-lighten-1;
        margin-top: 1;
        margin-bottom: 1;
        overflow-y: scroll;
        overflow-x: scroll;
        scrollbar-size-vertical: 1;
        scrollbar-size-horizontal: 1;
        scrollbar-color: $surface-lighten-2;
        scrollbar-color-hover: $accent;
        scrollbar-color-active: $accent-lighten-1;
        scrollbar-background: transparent;
    }
    #audit-modal-help {
        dock: bottom;
        color: $text-muted;
        text-align: center;
    }
    """

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back (ESC)", show=True),
        Binding("q", "app.pop_screen", "Close (q)", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="audit-modal-dialog"):
            yield Label("[bold cyan]📜 Schengen Security Audit Ledger (Fullscreen Maximize)[/]")
            yield DataTable(id="audit-modal-table")
            yield Label("[dim]Press [bold yellow]ESC[/] to return · ↑/↓ navigate rows · ←/→ horizontal scroll for full single-line command[/]", id="audit-modal-help")

    def on_mount(self) -> None:
        table = self.query_one("#audit-modal-table", DataTable)
        table.clear(columns=True)
        table.add_columns("ID", "Time", "Pane", "Agent", "Verdict", "Layer", "Reason", "Full Command Line")
        table.cursor_type = "row"
        logs = get_recent_audit_logs(limit=100)
        for log in logs:
            dec = log['decision']
            badge = f"[green]APPROVED[/]" if "APPROVE" in dec else f"[red]ESCALATED[/]"
            full_cmd = log['raw_command'].replace("\n", " ").strip()
            time_str = format_local_time(log['timestamp'])
            table.add_row(
                f"#{log['id']}",
                time_str,
                log['pane_id'],
                log.get('agent_kind', 'agy'),
                badge,
                log.get('decision_layer', 'SHELL_AST'),
                log.get('safety_reason', '')[:45],
                rich_escape(full_cmd)
            )
        table.focus()


class FixedHeader(Header):
    """Header that does not expand or toggle tall mode on click."""
    ALLOW_SELECT = False

    def on_click(self, event: events.Click) -> None:
        event.stop()


class UnselectableLabel(Label):
    """Label that explicitly rejects text drag selection to prevent suppressing click events."""
    ALLOW_SELECT = False


class AuditDataTable(DataTable):
    """Compact Recent Audits table with scrolling disabled; opens fullscreen modal on click or selection."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            show_cursor=False,
            **kwargs,
        )
        self.show_vertical_scrollbar = False
        self.show_horizontal_scrollbar = False

    def _open_modal(self) -> None:
        # Prevent opening modal multiple times if already present
        if len(self.app.screen_stack) == 1:
            self.app.push_screen(AuditFullscreenModal())

    def on_mouse_down(self, event: events.MouseDown) -> None:
        # DataTable with show_cursor=False never brokers a Click message nor posts
        # Row/CellSelected on a mouse click, so opening on press is the only reliable
        # mouse trigger (immune to micro-drag and release-position).
        event.stop()
        self._open_modal()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        event.stop()
        self._open_modal()

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        event.stop()
        self._open_modal()

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        event.stop()
        self._open_modal()

    def on_mouse_scroll_down(self, event: events.MouseScrollDown) -> None:
        event.stop()

    def on_mouse_scroll_up(self, event: events.MouseScrollUp) -> None:
        event.stop()


class AuditSectionHeader(Label):
    """Clickable header for Recent Audits section."""
    ALLOW_SELECT = False

    def _open_modal(self) -> None:
        if len(self.app.screen_stack) == 1:
            self.app.push_screen(AuditFullscreenModal())

    def on_mouse_down(self, event: events.MouseDown) -> None:
        # Open on press for reliability against micro-drag (Label ALLOW_SELECT=False
        # prevents text drag-selection from swallowing the press).
        event.stop()
        self._open_modal()


class CommandTextArea(TextArea):
    """Multi-line expanding command input with full word-wrap, Shift+Enter for newline, and Enter to submit."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            show_line_numbers=False,
            soft_wrap=True,
            highlight_cursor_line=False,
            **kwargs,
        )

    def _update_height(self, new_text: Optional[str] = None) -> None:
        """Dynamically adjust height upward based on multiline contents and word-wrap."""
        txt = new_text if new_text is not None else self.text
        if not txt:
            self.styles.height = 3
            return

        total_lines = 0
        w = max(20, self.size.width - 4) if self.size.width > 0 else 80
        for segment in txt.split("\n"):
            seg_len = len(segment)
            total_lines += max(1, (seg_len + w - 1) // w if seg_len > 0 else 1)

        target_height = min(16, max(3, total_lines + 2))
        self.styles.height = target_height

    def load_text(self, text: str) -> None:
        super().load_text(text)
        self._update_height(text)

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        self._update_height(event.text_area.text)

    def watch_text(self, new_text: str) -> None:
        self._update_height(new_text)

    def on_key(self, event: events.Key) -> None:
        is_shift_enter = (
            event.key in ("shift+enter", "ctrl+j", "alt+enter")
            or event.name in ("shift+enter", "ctrl+j", "alt+enter")
        )
        if event.key == "enter" and not is_shift_enter:
            event.prevent_default()
            event.stop()
            text = self.text.strip()
            if text:
                app = None
                try:
                    app = self.app
                except Exception:
                    app = getattr(self, "_app", None)

                if app and getattr(app, "_processing_chat", False):
                    if hasattr(app, "notify"):
                        app.notify("⏳ Another investigation is in-flight. Input retained.", severity="warning")
                    return
                self.text = ""
                self.styles.height = 3
                process_fn = getattr(app, "process_user_chat", None)
                if callable(process_fn):
                    process_fn(text)
        elif event.key == "escape":
            app = getattr(self, "app", None) or getattr(self, "_app", None)
            if app and hasattr(app, "handle_esc_press"):
                if app.handle_esc_press():
                    event.stop()
                    event.prevent_default()
                    return
        elif is_shift_enter:
            event.prevent_default()
            event.stop()
            self.insert("\n")


TUI_LOCK_FILE = Path.home() / ".local" / "state" / "herdr-schengen" / "schengen_tui.lock"


def acquire_tui_role() -> Tuple[Optional[Any], bool, Optional[int]]:
    """Acquire exclusive singleton lock for TUI Controller (Leader-Observer pattern)."""
    import fcntl
    TUI_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = open(TUI_LOCK_FILE, "a+")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fd.seek(0)
        fd.truncate()
        fd.write(f"{os.getpid()}\n")
        fd.flush()
        return fd, True, None
    except (OSError, BlockingIOError):
        leader_pid = None
        try:
            with open(TUI_LOCK_FILE) as f:
                content = f.read().strip()
                if content.isdigit():
                    leader_pid = int(content)
        except Exception:
            pass
        return None, False, leader_pid


class NoPixelMouseDriver(LinuxDriver):
    """LinuxDriver that never enables SGR pixel mouse (1016) or in-band resize (2048).

    The Herdr terminal emulator reports in-band window resize (2048) as supported
    but does NOT implement SGR pixel mouse (1016). Textual responds by sending
    2048h + 1016h; the terminal then sends a resize report with pixel dimensions,
    which makes Textual's parser set mouse_pixels=True and divide the (cell)
    SGR coordinates as pixels — collapsing every click to the top-left. Disabling
    both requests keeps the parser in cell mode.
    """

    def _enable_mouse_pixels(self) -> None:
        pass

    def _enable_in_band_window_resize(self) -> None:
        pass


class SchengenTUIApp(App):
    CSS = """
    Screen {
        layout: vertical;
        background: $surface-darken-2;
    }
    #main-body {
        width: 100%;
        height: 1fr;
        layout: horizontal;
    }
    #chat-column {
        width: 1fr;
        height: 100%;
        border-right: solid $surface-lighten-1;
        padding: 0 1;
        layout: vertical;
    }
    #radar-column {
        width: 38;
        max-width: 42;
        min-width: 32;
        height: 100%;
        padding: 0 1;
        layout: vertical;
    }
    /* Active escalation / Clean state banner (dynamic height for up to 5 cmd lines) */
    #active-target-banner {
        min-height: 5;
        max-height: 11;
        height: auto;
        background: $surface-darken-1;
        border-left: heavy $warning;
        border-top: solid $surface-lighten-1;
        border-bottom: solid $surface-lighten-1;
        color: $text;
        padding: 0 1;
        margin-bottom: 1;
        content-align: left middle;
    }
    #chat-log {
        height: 1fr;
        background: $surface;
        border: solid $surface-lighten-1;
        padding: 1;
        overflow-y: scroll;
        overflow-x: hidden;
        scrollbar-size-vertical: 1;
        scrollbar-color: $surface-lighten-2;
        scrollbar-color-hover: $accent;
        scrollbar-color-active: $accent-lighten-1;
        scrollbar-background: transparent;
    }
    #chat-log:focus {
        border: solid $accent;
    }
    /* Command input: expanding textarea with word-wrap and dynamic multiline height */
    #input-box {
        dock: bottom;
        height: 3;
        min-height: 3;
        max-height: 16;
        margin-top: 1;
        margin-bottom: 0;
        border: tall $surface-lighten-2;
        background: $surface-darken-1;
        overflow-x: hidden;
    }
    #input-box:focus {
        border-bottom: tall $accent;
        border-top: tall $surface-lighten-2;
        border-left: tall $surface-lighten-2;
        border-right: tall $surface-lighten-2;
    }
    #input-box:disabled {
        opacity: 0.5;
        background: $surface-darken-2;
        border: solid $surface-lighten-1;
        color: $text-muted;
    }
    #status-container {
        height: 4;
        layout: horizontal;
        margin-top: 1;
        margin-bottom: 1;
    }
    #status-box {
        width: 1fr;
        height: 100%;
        background: $surface-darken-1;
        border: solid $surface-lighten-1;
        padding: 0;
        content-align: center middle;
    }
    #btn-toggle-guard {
        width: 12;
        height: 100%;
        margin-left: 1;
        min-width: 10;
        padding: 0;
    }
    #role-box {
        height: 4;
        background: $surface-darken-1;
        border: solid $surface-lighten-1;
        padding: 0 1;
        margin-bottom: 1;
        content-align: left middle;
    }
    #token-meter-box {
        height: 7;
        background: $surface-darken-1;
        border: solid $surface-lighten-1;
        padding: 0 1;
        margin-bottom: 1;
        content-align: left middle;
    }
    #audit-table {
        height: 11;
        background: $surface-darken-1;
        border: solid $surface-lighten-1;
        margin-bottom: 1;
        overflow-x: hidden;
        overflow-y: hidden;
    }
    DataTable {
        height: 11;
        background: $surface-darken-1;
        border: solid $surface-lighten-1;
        margin-bottom: 1;
    }
    ListView {
        height: 7;
        background: $surface-darken-1;
        border: solid $surface-lighten-1;
    }
    ListItem {
        padding: 0 1;
    }
    .section-title {
        color: $text-muted;
        text-style: bold;
        margin-top: 0;
        margin-bottom: 0;
    }
    """

    ENABLE_COMMAND_PALETTE = False

    BINDINGS = [
        Binding("ctrl+l", "clear_chat", "Clear Chat", show=True),
        Binding("ctrl+t", "toggle_daemon", "Toggle Guard", show=True),
        Binding("ctrl+y", "copy_chat", "Copy Chat", show=True),
        Binding("ctrl+a", "open_audit_modal", "Audit Ledger", show=True),
    ]

    def __init__(self):
        super().__init__(driver_class=NoPixelMouseDriver)
        self.tui_lock_fd, self.is_controller, self.leader_pid = acquire_tui_role()
        self.agent = SchengenAgentChat()
        self._columns_initialized = False
        self._last_audit_hash = ""
        self._chat_plain: List[str] = []  # Plain-text buffer for clipboard copy
        self._last_escalation_hash = ""
        self._notified_escalation_ids: Set[int] = set()
        self._last_active_id: Optional[int] = None
        self._processing_chat: bool = False
        self._last_guard_active: bool = False
        self._last_esc_time: float = 0.0

    def handle_esc_press(self) -> bool:
        """Handle ESC key press with double-press (<= 0.4s) abort for in-flight LLM call."""
        # If audit modal is currently active on top, do not capture ESC for chat abort
        if len(self.screen_stack) > 1:
            return False
        import time as _time
        now = _time.monotonic()
        if now - self._last_esc_time <= 0.4:
            self._last_esc_time = 0.0
            if self._processing_chat:
                self.interrupt_inflight_chat(reason="Double-ESC pressed")
                return True
        else:
            self._last_esc_time = now
        return False

    def interrupt_inflight_chat(self, reason: str = "User interrupted") -> None:
        """Interrupt and abort current in-flight LLM agent call."""
        if hasattr(self, "agent") and self.agent:
            self.agent.cancel()
        self._processing_chat = False
        self._write(f"\n[bold red]🛑 [Aborted]:[/] In-flight LLM call interrupted ({reason}).\n")
        self.update_radar_data(force=True)

    def compose(self) -> ComposeResult:
        yield FixedHeader(show_clock=True)
        with Horizontal(id="main-body"):
            # Left: Chat log fills space; banner floats just above input
            with Vertical(id="chat-column"):
                yield UnselectableLabel("[bold cyan]🤖 Schengen Security Gatekeeper (DeepSeek Flash)[/]")
                yield FocusableRichLog(id="chat-log", highlight=True, markup=True, wrap=True, auto_scroll=True)
                yield Static(id="active-target-banner")
                yield CommandTextArea(placeholder="Ask Gatekeeper or type command (Enter to submit, Shift+Enter for newline)...", id="input-box")

            # Right: Compact Radar with Token Meter
            with Vertical(id="radar-column"):
                with Horizontal(id="status-container"):
                    yield Static(id="status-box")
                    yield Button("⚡ Toggle", id="btn-toggle-guard", variant="warning")
                with Horizontal(id="instruction-control"):
                    yield Button("📤 Approve Instr: OFF", id="btn-toggle-approve-instr")
                    yield Button("📤 Reject Instr: ON", id="btn-toggle-reject-instr")
                yield Static(id="role-box")
                yield Label("⚡ Token & Cache Meter", classes="section-title")
                yield Static(id="token-meter-box")
                yield AuditSectionHeader("📜 Recent Audits (Click: ⛶ Fullscreen)", classes="section-title")
                yield AuditDataTable(id="audit-table")
                yield Label("🚨 Pending Escalations Queue", classes="section-title")
                yield ListView(id="escalation-list")
        yield Footer()

    def action_open_audit_modal(self) -> None:
        if len(self.screen_stack) == 1:
            self.push_screen(AuditFullscreenModal())

    def _log_mouse_event(self, kind: str, event: events.MouseEvent) -> None:
        if not _mouse_debug_enabled():
            return
        target = getattr(event, "widget", None)
        t_id = getattr(target, "id", "") or ""
        t_cls = target.__class__.__name__ if target is not None else "None"
        under = "NoWidget"
        try:
            w, _r = self.screen.get_widget_at(event.screen_x, event.screen_y)
            under = f"{w.__class__.__name__}({getattr(w, 'id', '')})"
        except Exception:
            pass
        _mouse_debug_log(
            f"[{kind}] screen_x={event.screen_x} screen_y={event.screen_y} "
            f"event_widget={t_cls}({t_id}) under={under}"
        )

    def on_mouse_down(self, event: events.MouseDown) -> None:
        self._log_mouse_event("mouse_down", event)

    def on_mouse_up(self, event: events.MouseUp) -> None:
        self._log_mouse_event("mouse_up", event)

    def on_mouse_move(self, event: events.MouseMove) -> None:
        self._log_mouse_event("mouse_move", event)

    def on_click(self, event: events.Click) -> None:
        self._log_mouse_event("click", event)

    def on_mount(self) -> None:
        self.title = "Herdr Schengen Security Gatekeeper"
        self.sub_title = "Autonomous Governance & Advisory TUI"

        table = self.query_one(DataTable)
        table.clear(columns=True)
        table.add_columns("Time", "P", "V", "Cmd")
        table.cursor_type = "row"
        self._columns_initialized = True

        self._refresh_instruction_buttons()

        existing = get_pending_escalations(include_delivered=True)
        for e in existing:
            if e["status"] != "PENDING":
                self._notified_escalation_ids.add(e["id"])

        input_widget = self.query_one("#input-box", CommandTextArea)
        if not self.is_controller:
            input_widget.disabled = True
            input_widget.placeholder = "🔒 [Observer Mode]: Read-only instance (Input disabled). Leader PID controls gate."
        else:
            input_widget.focus()

        self.set_interval(0.5, self.update_radar_data)

        if self.is_controller:
            self._write("[bold green]🛡️ Schengen Security Gatekeeper TUI is online (Controller Mode).[/]")
            self._write("[dim]• [bold yellow]⚡ Toggle Guard[/]: Button or [bold cyan]Ctrl+T[/] (or /start, /stop)\n• Role: [green]Controller (Active Authority)[/]\n• Mode: Strict Sequential Single-Pending FIFO[/]\n")
        else:
            self._write(f"[bold yellow]👁️ Schengen Security Gatekeeper TUI is online (Observer Mode - PID {os.getpid()}).[/]")
            self._write(f"[dim]• Role: [yellow]Observer (Read-Only)[/]\n• Active Controller: Leader PID {self.leader_pid or 'Active'}\n• Input & mutation actions are disabled.\n[/]")

    def on_unmount(self) -> None:
        if self.tui_lock_fd:
            try:
                self.tui_lock_fd.close()
            except Exception:
                pass

    def toggle_guard_daemon(self) -> str:
        if not self.is_controller:
            return "⛔ 관찰자 모드입니다. 컨트롤러 인스턴스에서 조작하십시오."
        locks = list_active_guard_locks()
        watcher_script = SCRIPT_DIR / "schengen_watcher.py"
        python_bin = sys.executable
        if locks:
            subprocess.run([python_bin, str(watcher_script), "--stop"], capture_output=True, timeout=5.0)
            return "🔴 SmartGate 가드 데몬을 안전하게 정지했습니다."
        else:
            env = dict(os.environ)
            env["HERDR_ENV"] = "1"
            env["ANTIGRAVITY_AGENT"] = "1"
            env.pop("SCHENGEN_STRICT_PARENT", None)
            
            p = subprocess.Popen(
                [python_bin, str(watcher_script), "--target", "auto"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                env=env,
                start_new_session=True,
            )
            return f"🟢 SmartGate 가드 데몬을 백그라운드로 기동했습니다 (PID: {p.pid}, Target: auto)."

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-toggle-guard":
            msg = self.toggle_guard_daemon()
            self._write(f"[bold yellow]⚙️ [Daemon Control]:[/] {msg}")
            self.update_radar_data(force=True)
        elif event.button.id == "btn-toggle-approve-instr":
            cfg = get_instruction_delivery_config()
            new_val = not cfg.get("send_approve_instruction", False)
            set_instruction_delivery_config(send_approve_instruction=new_val)
            self._write(
                f"[bold yellow]📤 [Instruction Delivery]:[/] Approve instruction {'[green]ENABLED[/]' if new_val else '[dim]DISABLED[/]'}."
            )
            self._refresh_instruction_buttons()
        elif event.button.id == "btn-toggle-reject-instr":
            cfg = get_instruction_delivery_config()
            new_val = not cfg.get("send_reject_instruction", True)
            set_instruction_delivery_config(send_reject_instruction=new_val)
            self._write(
                f"[bold yellow]📤 [Instruction Delivery]:[/] Reject instruction {'[green]ENABLED[/]' if new_val else '[dim]DISABLED[/]'}."
            )
            self._refresh_instruction_buttons()

    def _refresh_instruction_buttons(self) -> None:
        """Sync the instruction-delivery toggle button labels to the current config."""
        cfg = get_instruction_delivery_config()
        try:
            approve_btn = self.query_one("#btn-toggle-approve-instr", Button)
            approve_btn.label = "📤 Approve Instr: ON" if cfg.get("send_approve_instruction") else "📤 Approve Instr: OFF"
        except Exception:
            pass
        try:
            reject_btn = self.query_one("#btn-toggle-reject-instr", Button)
            reject_btn.label = "📤 Reject Instr: ON" if cfg.get("send_reject_instruction") else "📤 Reject Instr: OFF"
        except Exception:
            pass

    def action_toggle_daemon(self) -> None:
        msg = self.toggle_guard_daemon()
        self._write(f"[bold yellow]⚙️ [Daemon Control]:[/] {msg}")
        self.update_radar_data(force=True)

    def update_radar_data(self, force: bool = False) -> None:
        if not self._columns_initialized:
            return

        # 0. Update Role header box (full width, dedicated panel)
        try:
            role_box = self.query_one("#role-box", Static)
        except Exception:
            return

        if self.is_controller:
            role_box.update(f"[bold green]👑 CONTROLLER MODE[/]  [dim]PID {os.getpid()}[/]\n[dim]Autonomous LLM & Key Injection active[/]")
        else:
            role_box.update(f"[bold yellow]👁 OBSERVER MODE[/]  [dim]Leader PID {self.leader_pid or 'active'}[/]\n[dim]Read-only monitoring (Actions disabled)[/]")

        # 1. Update status header box (muted tones — accent only on state)
        locks = list_active_guard_locks()
        is_guard_active = bool(locks)
        if self._last_guard_active and not is_guard_active:
            # External kill detected!
            self._write("\n[bold red]⚠️ [Guard Daemon Alert]:[/] SmartGate 가드 데몬이 외부에서 종료되었습니다 (INACTIVE). 다시 시작하려면 [bold yellow]Ctrl+T[/] 또는 ⚡ Toggle을 누르십시오.\n")
        self._last_guard_active = is_guard_active

        status_box = self.query_one("#status-box", Static)
        if locks:
            tgt, lpath, pid = locks[0]
            status_box.update(f"[green]● ACTIVE[/]  [dim]PID {pid}[/]\n[dim]{tgt}[/]")
        else:
            status_box.update("[dim]○ Inactive[/]\n[dim]Toggle / Ctrl+T to start[/]")

        # 2. Update Token Meter (muted: data in white, labels in dim)
        stats = self.agent.get_token_usage_stats()
        meter_box = self.query_one("#token-meter-box", Static)
        meter_box.update(
            f"[dim]Calls[/]   [white]{stats['api_calls']:,}[/]\n"
            f"[dim]In[/]      [white]{stats['prompt_tokens']:,}[/] tk\n"
            f"[dim]Out[/]     [white]{stats['completion_tokens']:,}[/] tk\n"
            f"[dim]Cached[/]  [white]{stats['cached_tokens']:,}[/] tk  [dim]{stats['cache_hit_pct']} hit[/]\n"
            f"[dim]Inspector  In {stats['inspector_in']:,} / Out {stats['inspector_out']:,}[/]\n"
            f"[dim]Judge      In {stats['judge_in']:,} / Out {stats['judge_out']:,}[/]"
        )

        # 3. Active Target Banner (left-accent line only; no solid fill)
        active_esc = get_current_active_escalation()
        banner = self.query_one("#active-target-banner", Static)

        if active_esc:
            active_id = active_esc["id"]
            raw_cmd = active_esc['raw_command'].strip()
            cmd_lines = raw_cmd.splitlines()
            if len(cmd_lines) > 5:
                cmd_display = "\n".join(cmd_lines[:5]) + f"\n[dim]… (+{len(cmd_lines) - 5} lines truncated)[/]"
            else:
                cmd_display = "\n".join(cmd_lines)
            
            reason_short = active_esc['safety_reason'][:72]
            banner.update(
                f"[bold yellow]▶ #{active_id}[/]  [bold white]{active_esc['pane_id']}[/]  [dim]({active_esc.get('agent_kind','agent')})[/]\n"
                f"[bold white]{rich_escape(cmd_display)}[/]\n"
                f"[dim]⚠ {rich_escape(reason_short)}[/]\n"
                f"[dim]   ⚡ Awaiting adjudication or autonomous inspection completion...[/]"
            )

            # STRICT SEQUENTIAL FIFO: Only CONTROLLER awakens/delivers chat for active escalation
            if self.is_controller and active_id not in self._notified_escalation_ids and not self._processing_chat:
                self._notified_escalation_ids.add(active_id)
                self._last_active_id = active_id

                # Sound alert
                try:
                    subprocess.Popen(
                        ["herdr", "notification", "show", "Schengen — Escalation Intercepted", "--body", f"Pending on {active_esc['pane_id']}", "--sound", "request"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    subprocess.Popen(["afplay", "/System/Library/Sounds/Ping.aiff"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    self.bell()

                safe_cmd = rich_escape(active_esc['raw_command'])
                safe_reason = rich_escape(active_esc['safety_reason'])

                self._write(f"\n[yellow]{'─'*20} ▶ Escalation #{active_id} Intercepted {'─'*20}[/]")
                self._write(f"  [dim]Pane:[/]   {active_esc['pane_id']} ({active_esc.get('agent_kind', 'agent')})")
                self._write(f"  [dim]Cmd:[/]    [white]{safe_cmd}[/]")
                self._write(f"  [dim]Reason:[/] {safe_reason}")
                self._write(f"[dim]  ⚡ Autonomous inspector awakening...[/]\n")

                self.process_user_chat("New escalation intercepted. Evaluate command safety, investigate using tools if necessary, and report or adjudicate.")

        else:
            banner.update(
                "\n[bold green]✔ No active escalations  —  Queue clear[/]\n"
                "[dim]🛡️  Autonomous border control active across all Herdr workspaces[/]\n"
                "[dim]   Listening for Gray-Zone mutations and critical AST denylists[/]"
            )
            if self._last_active_id is not None:
                self._write(f"\n[dim]{'─'*20} ✔ Escalation #{self._last_active_id} resolved {'─'*20}[/]\n")
                self._last_active_id = None


        radar_col = self.query_one("#radar-column")
        radar_width = radar_col.size.width if radar_col.size.width > 0 else 36
        cmd_allowed_len = max(6, radar_width - 24)

        # 4. Update 10 Audit Table
        audit_table = self.query_one("#audit-table", DataTable)
        recent_audits = get_recent_audit_logs(limit=10)
        current_audit_hash = str([(a["id"], a["decision"]) for a in recent_audits])
        
        if current_audit_hash != self._last_audit_hash:
            self._last_audit_hash = current_audit_hash
            audit_table.clear()
            for log in recent_audits:
                short_cmd = log['raw_command'].replace("\n", " ").strip()
                if len(short_cmd) > cmd_allowed_len:
                    short_cmd = short_cmd[:cmd_allowed_len] + "…"
                time_str = log['timestamp'][11:19] if len(log['timestamp']) >= 19 else log['timestamp']
                
                dec = log['decision']
                badge = f"[green]OK[/]" if "APPROVE" in dec else f"[red]ES[/]"
                audit_table.add_row(time_str, log['pane_id'], badge, short_cmd)

        # 5. Update Recent Escalations List
        esc_list = self.query_one("#escalation-list", ListView)
        all_escalations = get_pending_escalations(include_delivered=True)
        recent_escalations = all_escalations[-5:] if all_escalations else []
        current_esc_hash = str([(e["id"], e["status"]) for e in recent_escalations])
        
        if current_esc_hash != self._last_escalation_hash:
            self._last_escalation_hash = current_esc_hash
            esc_list.clear()
            for esc in recent_escalations:
                cmd_short = esc['raw_command'].replace("\n", " ").strip()
                if len(cmd_short) > 28:
                    cmd_short = cmd_short[:28] + "…"
                status = esc['status']
                if status == "PENDING":
                    state_badge = "[bold yellow]⏳ PEND[/]"
                elif status == "RESOLVED":
                    state_badge = "[green]✅ OK[/]"
                else:
                    state_badge = "[red]❌ NO[/]"
                
                esc_list.append(
                    ListItem(
                        Label(
                            f"[bold cyan]#{esc['id']}[/] {state_badge} [bold white]{rich_escape(cmd_short)}[/]"
                        )
                    )
                )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "audit-table":
            self.push_screen(AuditFullscreenModal())

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        if event.data_table.id == "audit-table":
            self.push_screen(AuditFullscreenModal())

    def on_resize(self, event: events.Resize) -> None:
        self.update_radar_data(force=True)

    @work(exclusive=False)
    async def process_user_chat(self, user_msg: str) -> None:
        trimmed = user_msg.strip()

        # 1. Non-blocking Feature Request Command Handling (Queues immediately even if an agent task is in-flight)
        if (trimmed.startswith("/feature-request") or trimmed.startswith("/feature") or 
            trimmed.startswith("/idea") or trimmed.startswith("/features") or trimmed.startswith("/feature-list")):
            safe_user_msg = rich_escape(user_msg)
            self._write(f"\n[bold yellow]👤 You:[/] {safe_user_msg}")

            if trimmed in ("/features", "/feature-list", "/feature --list", "/feature-request --list"):
                items = list_feature_requests(status="PENDING", limit=10)
                if not items:
                    self._write("📋 [bold cyan][Feature Backlog]:[/] No pending feature requests in queue.")
                else:
                    self._write(f"📋 [bold cyan][Feature Backlog ({len(items)} pending)]:[/]")
                    for it in items:
                        self._write(f"  • [bold yellow]#{it['id']}[/] ({it['priority']}) [white]{rich_escape(it['title'])}[/]")
                return

            content = trimmed
            for pfx in ("/feature-request", "/feature", "/idea"):
                if content.startswith(pfx):
                    content = content[len(pfx):].strip()
                    break

            if not content:
                self._write("[dim]💡 Usage: [bold yellow]/feature-request <title>[/] [dim]or[/] [bold yellow]/feature <title> --desc <desc>[/]")
                return

            desc = ""
            priority = "NORMAL"

            # Extract and strip --priority <LEVEL> case-insensitively
            p_match = re.search(r"--priority\s+(CRITICAL|HIGH|NORMAL|LOW)", content, re.IGNORECASE)
            if p_match:
                priority = p_match.group(1).upper()
                content = re.sub(r"--priority\s+(?:CRITICAL|HIGH|NORMAL|LOW)", "", content, flags=re.IGNORECASE).strip()

            if " --desc " in content:
                parts = content.split(" --desc ", 1)
                title = parts[0].strip()
                desc = parts[1].strip()
            elif " -d " in content:
                parts = content.split(" -d ", 1)
                title = parts[0].strip()
                desc = parts[1].strip()
            else:
                title = content.strip()

            created = create_feature_request_with_similars(
                title=title,
                description=desc,
                requester="user",
                priority=priority,
                source="tui_command",
                similars_limit=3,
            )
            req_id = created["id"]
            similars = created["similar_items"]

            self._write(f"💡 [bold green][Feature Request Queued]:[/] #{req_id} [bold white]{rich_escape(title)}[/] [dim](Priority: {priority})[/]")
            if similars:
                self._write(f"  [dim]🔍 {len(similars)} similar request(s) found in backlog via FTS5 CJK trigram:[/]")
                for sim in similars:
                    self._write(f"    • [dim]#{sim['id']} [{sim['status']}][/] [dim]{rich_escape(sim['title'])}[/]")
            return

        # 2. In-flight Interruption Command Handling (/interrupt [new_message])
        if trimmed == "/interrupt" or trimmed.startswith("/interrupt "):
            new_msg = trimmed[len("/interrupt"):].strip()
            self.interrupt_inflight_chat(reason="/interrupt command")
            if new_msg:
                # Dispatch the new message immediately after abort
                self.process_user_chat(new_msg)
            return

        if self._processing_chat:
            self._write("[dim]⏳ Another investigation/chat is currently in-flight. Press ESC twice or type [bold yellow]/interrupt[/] to abort.[/]")
            return

        if not self.is_controller and (user_msg.startswith("/approve") or user_msg.startswith("/reject") or user_msg.startswith("/start") or user_msg.startswith("/stop")):
            self._write(f"[bold yellow]⚠️ [Observer Mode]:[/] Read-only instance. Leader PID {self.leader_pid} controls execution.")
            return

        self._processing_chat = True
        try:
            safe_user_msg = rich_escape(user_msg)
            self._write(f"\n[bold yellow]👤 You:[/] {safe_user_msg}")

            if user_msg.strip() in ("/start", "/stop", "/toggle"):
                msg = self.toggle_guard_daemon()
                self._write(f"[bold yellow]⚙️ [Daemon Control]:[/] {msg}")
                self.update_radar_data(force=True)
                return

            if user_msg.startswith("/approve "):
                parts = user_msg.split(maxsplit=2)
                esc_id = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                reason = parts[2] if len(parts) > 2 else "Approved via TUI"
                resp = await self.agent.send_message(f"Approve escalation #{esc_id} with English note: '{reason}'")
                self._write("🤖 [bold cyan]Gatekeeper[/]:")
                self._write_markdown(resp)
                self.update_radar_data(force=True)
                return

            if user_msg.startswith("/reject "):
                parts = user_msg.split(maxsplit=2)
                esc_id = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                reason = parts[2] if len(parts) > 2 else "Rejected via TUI"
                resp = await self.agent.send_message(f"Reject escalation #{esc_id} with English reason: '{reason}'")
                self._write("🤖 [bold cyan]Gatekeeper[/]:")
                self._write_markdown(resp)
                self.update_radar_data(force=True)
                return

            def on_tool(chunk: str):
                self._write_markdown(chunk)

            resp = await self.agent.send_message(user_msg, on_chunk=on_tool)
            self._write("🤖 [bold cyan]Gatekeeper[/]:")
            self._write_markdown(resp)
            self._write(f"[dim]{'─'*70}[/]")
            self.update_radar_data(force=True)
        except Exception as exc:
            self._write(f"[bold red]❌ [Investigation Error]:[/] {exc}")
            try:
                input_box = self.query_one("#input-box", CommandTextArea)
                input_box.text = user_msg
            except Exception:
                pass
        finally:
            self._processing_chat = False

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        val = event.value.strip()
        if not val:
            return
        event.input.value = ""
        self.process_user_chat(val)

    def _write_markdown(self, md_text: str, prefix: Optional[str] = None) -> None:
        """Render structured GFM Markdown (syntax highlighting, tables, lists) to RichLog."""
        if prefix:
            self._write(prefix)
        if md_text and md_text.strip():
            md = Markdown(md_text.strip(), code_theme="monokai", justify="left")
            self._write(md)

    def _write(self, msg: Any) -> None:
        """Write to RichLog and append plain-text to clipboard buffer."""
        import re as _re
        chat_log = self.query_one(RichLog)
        chat_log.write(msg)
        if isinstance(msg, Markdown):
            raw_text = getattr(msg, "markup", str(msg)).strip()
            if raw_text:
                self._chat_plain.append(raw_text)
        else:
            plain = _re.sub(r"\[/?[^\]]*\]", "", str(msg)).strip()
            if plain:
                self._chat_plain.append(plain)

    def action_clear_chat(self) -> None:
        self.query_one(RichLog).clear()
        self._chat_plain.clear()

    def action_copy_chat(self) -> None:
        """Copy full chat history to macOS clipboard via pbcopy."""
        if not self._chat_plain:
            self._write("[dim]  (clipboard: nothing to copy yet)[/]")
            return
        text = "\n".join(self._chat_plain)
        try:
            subprocess.run(["pbcopy"], input=text.encode("utf-8"), capture_output=True, timeout=5.0)
            n = len(self._chat_plain)
            self._write(f"[dim]  ✔ {n} lines copied to clipboard[/]")
        except Exception as e:
            self._write(f"[dim]  ✘ clipboard copy failed: {e}[/]")

    def on_text_selected(self, event: events.TextSelected) -> None:
        """Automatically copy mouse-dragged text selection to macOS and Textual clipboard."""
        sel_text = self.screen.get_selected_text()
        if sel_text:
            self.copy_to_clipboard(sel_text)
            try:
                subprocess.run(["pbcopy"], input=sel_text.encode("utf-8"), capture_output=True, timeout=2.0)
            except Exception:
                pass


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Herdr Schengen Security Gatekeeper TUI")
    parser.add_argument(
        "--send-approve-instruction",
        dest="send_approve_instruction",
        action="store_true",
        default=None,
        help="Send the gatekeeper approval instruction/feedback to the target pane (default: off).",
    )
    parser.add_argument(
        "--no-send-approve-instruction",
        dest="send_approve_instruction",
        action="store_false",
        help="Do NOT send the approval instruction (default).",
    )
    parser.add_argument(
        "--send-reject-instruction",
        dest="send_reject_instruction",
        action="store_true",
        default=None,
        help="Send the reject instruction/feedback to the target pane (default: on).",
    )
    parser.add_argument(
        "--no-send-reject-instruction",
        dest="send_reject_instruction",
        action="store_false",
        help="Do NOT send the reject instruction.",
    )
    args = parser.parse_args()

    set_instruction_delivery_config(
        send_approve_instruction=args.send_approve_instruction,
        send_reject_instruction=args.send_reject_instruction,
    )

    app = SchengenTUIApp()
    app.run()
