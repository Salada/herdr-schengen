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
import os
import re
import signal
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Prevent TUI process from exiting on SIGHUP daemon reloads
if hasattr(signal, "SIGHUP"):
    try:
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
    except Exception:
        pass

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from rich.markdown import Markdown
from rich.markup import escape as rich_escape
from rich.text import Text
from textual import events, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
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

from feature_db import (
    add_feature_request,
    create_feature_request_with_similars,
    list_feature_requests,
    search_similar_feature_requests,
)
from guard_db import (
    get_pending_escalations,
    get_recent_audit_logs,
    get_session_dashboard_summary,
)
from schengen_agent_llm import SchengenAgentChat, get_current_active_escalation
from schengen_watcher import list_active_guard_locks


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


class FocusableRichLog(RichLog):
    """RichLog supporting keyboard focus, mouse scroll, selection, and page navigation."""
    can_focus = True

    def on_key(self, event: events.Key) -> None:
        if event.key == "pageup":
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
    def on_click(self, event: events.Click) -> None:
        event.stop()


class AuditDataTable(DataTable):
    """Custom DataTable that triggers fullscreen audit modal on click or selection."""
    def on_click(self, event: events.Click) -> None:
        event.stop()
        self.app.push_screen(AuditFullscreenModal())


class AuditSectionHeader(Label):
    """Clickable header for Recent Audits section."""
    def on_click(self, event: events.Click) -> None:
        event.stop()
        self.app.push_screen(AuditFullscreenModal())


class CommandTextArea(TextArea):
    """Multi-line expanding command input with full word-wrap, Shift+Enter for newline, and Enter to submit."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            show_line_numbers=False,
            soft_wrap=True,
            highlight_cursor_line=False,
            **kwargs,
        )

    def watch_text(self, new_text: str) -> None:
        """Dynamically adjust height based on multiline contents."""
        line_count = new_text.count("\n") + 1
        target_height = min(10, max(3, line_count + 2))
        self.styles.height = target_height

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
        max-height: 10;
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
        super().__init__()
        self.tui_lock_fd, self.is_controller, self.leader_pid = acquire_tui_role()
        self.agent = SchengenAgentChat()
        self._columns_initialized = False
        self._last_audit_hash = ""
        self._chat_plain: List[str] = []  # Plain-text buffer for clipboard copy
        self._last_escalation_hash = ""
        self._notified_escalation_ids: Set[int] = set()
        self._last_active_id: Optional[int] = None
        self._processing_chat: bool = False

    def compose(self) -> ComposeResult:
        yield FixedHeader(show_clock=True)
        with Horizontal(id="main-body"):
            # Left: Chat log fills space; banner floats just above input
            with Vertical(id="chat-column"):
                yield Label("[bold cyan]🤖 Schengen Security Gatekeeper (DeepSeek Flash)[/]")
                yield FocusableRichLog(id="chat-log", highlight=True, markup=True, wrap=True, auto_scroll=True)
                yield Static(id="active-target-banner")
                yield CommandTextArea(placeholder="Ask Gatekeeper or type command (Enter to submit, Shift+Enter for newline)...", id="input-box")

            # Right: Compact Radar with Token Meter
            with Vertical(id="radar-column"):
                with Horizontal(id="status-container"):
                    yield Static(id="status-box")
                    yield Button("⚡ Toggle", id="btn-toggle-guard", variant="warning")
                yield Static(id="role-box")
                yield Label("⚡ Token & Cache Meter", classes="section-title")
                yield Static(id="token-meter-box")
                yield AuditSectionHeader("📜 Recent Audits (Click: ⛶ Fullscreen)", classes="section-title")
                yield AuditDataTable(id="audit-table")
                yield Label("🚨 Pending Escalations Queue", classes="section-title")
                yield ListView(id="escalation-list")
        yield Footer()

    def action_open_audit_modal(self) -> None:
        self.push_screen(AuditFullscreenModal())

    def on_mount(self) -> None:
        self.title = "Herdr Schengen Security Gatekeeper"
        self.sub_title = "Autonomous Governance & Advisory TUI"

        table = self.query_one(DataTable)
        table.clear(columns=True)
        table.add_columns("Time", "P", "V", "Cmd")
        table.cursor_type = "row"
        self._columns_initialized = True

        existing = get_pending_escalations(include_delivered=True)
        for e in existing:
            if e["status"] != "PENDING":
                self._notified_escalation_ids.add(e["id"])

        input_widget = self.query_one("#input-box", CommandTextArea)
        input_widget.focus()

        self.set_interval(0.5, self.update_radar_data)

        if self.is_controller:
            self._write("[bold green]🛡️ Schengen Security Gatekeeper TUI is online (Controller Mode).[/]")
            self._write("[dim]• [bold yellow]⚡ Toggle Guard[/]: Button or [bold cyan]Ctrl+T[/] (or /start, /stop)\n• Role: [green]Controller (Active Authority)[/]\n• Mode: Strict Sequential Single-Pending FIFO[/]\n")
        else:
            self._write(f"[bold yellow]👁️ Schengen TUI is running in OBSERVER MODE (Leader PID: {self.leader_pid}).[/]")
            self._write("[dim]• Read-only dashboard active. Auto-awaken and key injection are disabled on this instance.[/]\n")

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

    def action_toggle_daemon(self) -> None:
        msg = self.toggle_guard_daemon()
        self._write(f"[bold yellow]⚙️ [Daemon Control]:[/] {msg}")
        self.update_radar_data(force=True)

    def update_radar_data(self, force: bool = False) -> None:
        if not self._columns_initialized:
            return

        # 0. Update Role header box (full width, dedicated panel)
        role_box = self.query_one("#role-box", Static)
        if self.is_controller:
            role_box.update(f"[bold green]👑 CONTROLLER MODE[/]  [dim]PID {os.getpid()}[/]\n[dim]Autonomous LLM & Key Injection active[/]")
        else:
            role_box.update(f"[bold yellow]👁 OBSERVER MODE[/]  [dim]Leader PID {self.leader_pid or 'active'}[/]\n[dim]Read-only monitoring (Actions disabled)[/]")

        # 1. Update status header box (muted tones — accent only on state)
        locks = list_active_guard_locks()
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

        if self._processing_chat:
            self._write("[dim]⏳ Another investigation/chat is currently in-flight. Please wait...[/]")
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


if __name__ == "__main__":
    app = SchengenTUIApp()
    app.run()
