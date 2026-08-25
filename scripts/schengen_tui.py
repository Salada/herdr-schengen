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
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from rich.markup import escape as rich_escape
from rich.text import Text
from textual import events, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
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


class UnfocusableRichLog(RichLog):
    """RichLog subclass that cannot be focused."""
    can_focus = False


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
        layout: horizontal;
        background: $surface-darken-2;
    }
    #chat-column {
        width: 1fr;
        height: 1fr;
        border-right: solid $surface-lighten-1;
        padding: 0 1;
        layout: vertical;
    }
    #radar-column {
        width: 38;
        max-width: 42;
        min-width: 32;
        height: 1fr;
        padding: 0 1;
        layout: vertical;
    }
    /* Active escalation: left accent line only, no solid fill */
    #active-target-banner {
        height: 4;
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
    }
    /* Input: clean gray border, single accent line on focus */
    #input-box {
        dock: bottom;
        margin-top: 1;
        margin-bottom: 0;
        border: tall $surface-lighten-2;
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
    /* CommandPalette width constraint (ADR-009) */
    CommandPalette > Vertical {
        width: 72;
        max-width: 80%;
        max-height: 60%;
        align: center middle;
    }
    """

    BINDINGS = [
        Binding("ctrl+l", "clear_chat", "Clear Chat", show=True),
        Binding("ctrl+t", "toggle_daemon", "Toggle Guard", show=True),
        Binding("ctrl+y", "copy_chat", "Copy Chat", show=True),
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
        yield Header(show_clock=True)
        # Left: Chat log fills space; banner floats just above input
        with Vertical(id="chat-column"):
            yield Label("[bold cyan]🤖 Schengen Security Gatekeeper (DeepSeek Flash)[/]")
            yield UnfocusableRichLog(id="chat-log", highlight=True, markup=True, wrap=True, auto_scroll=True)
            yield Static(id="active-target-banner")
            yield Input(placeholder="Ask Gatekeeper or type command (e.g. /start, /stop, /approve 978)...", id="input-box")

        # Right: Compact Radar with Token Meter
        with Vertical(id="radar-column"):
            with Horizontal(id="status-container"):
                yield Static(id="status-box")
                yield Button("⚡ Toggle", id="btn-toggle-guard", variant="warning")
            yield Static(id="role-box")
            yield Label("⚡ Token & Cache Meter", classes="section-title")
            yield Static(id="token-meter-box")
            yield Label("📜 Recent Audits (Last 10)", classes="section-title")
            yield DataTable(id="audit-table")
            yield Label("🚨 Pending Escalations Queue", classes="section-title")
            yield ListView(id="escalation-list")
        yield Footer()

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

        input_widget = self.query_one(Input)
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
            cmd_short = active_esc['raw_command'].replace("\n", " ").strip()
            if len(cmd_short) > 72:
                cmd_short = cmd_short[:72] + "…"
            reason_short = active_esc['safety_reason'][:56]
            banner.update(
                f"[yellow]▶ #{active_id}[/]  [white]{active_esc['pane_id']}[/]  [dim]{active_esc.get('agent_kind','agent')}[/]\n"
                f"[white]$ {rich_escape(cmd_short)}[/]\n"
                f"[dim]⚠ {rich_escape(reason_short)}[/]"
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
            banner.update("[dim]✔ No active escalations  —  queue clear[/]")
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

    def on_resize(self, event: events.Resize) -> None:
        self.update_radar_data(force=True)

    @work(exclusive=False)
    async def process_user_chat(self, user_msg: str) -> None:
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
                self._write(f"🤖 Gatekeeper: {resp}")
                self.update_radar_data(force=True)
                return

            if user_msg.startswith("/reject "):
                parts = user_msg.split(maxsplit=2)
                esc_id = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                reason = parts[2] if len(parts) > 2 else "Rejected via TUI"
                resp = await self.agent.send_message(f"Reject escalation #{esc_id} with English reason: '{reason}'")
                self._write(f"🤖 Gatekeeper: {resp}")
                self.update_radar_data(force=True)
                return

            def on_tool(chunk: str):
                self._write(chunk)

            resp = await self.agent.send_message(user_msg, on_chunk=on_tool)
            self._write(f"🤖 Gatekeeper:\n{resp}")
            self._write(f"[dim]{'─'*70}[/]")
            self.update_radar_data(force=True)
        finally:
            self._processing_chat = False

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        val = event.value.strip()
        if not val:
            return
        event.input.value = ""
        self.process_user_chat(val)

    def _write(self, msg: Any) -> None:
        """Write to RichLog and append plain-text to clipboard buffer."""
        import re as _re
        chat_log = self.query_one(RichLog)
        chat_log.write(msg)
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
