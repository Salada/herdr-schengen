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
import json
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

from rich.cells import cell_len
from rich.markdown import Markdown
def rich_escape(text) -> str:
    """Escape arbitrary text so it renders literally inside Rich markup.

    rich.markup.escape only escapes ``[`` when it begins a tag (``[a-z#/@]...``),
    leaving bare brackets in shell commands (e.g. ``[by ``, stray ``]``, heredoc
    contents) unescaped, which crashes Text.from_markup with MarkupError. Escape
    ALL ``[`` (a lone ``]`` is literal in Rich markup and needs no escape), and
    leave backslashes untouched — Rich renders a standalone ``\\`` literally
    (only ``\\[`` is an escape sequence), so doubling them would corrupt
    copy-paste fidelity (INV-HR-6).
    """
    return str(text).replace("[", "\\[")
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
    RadioButton,
    RadioSet,
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
    add_to_allowlist,
    get_adjudications_for_audit,
    get_answer_language,
    get_audit_log_by_id,
    get_batch_approval_config,
    get_channel_approve_config,
    get_escalation_approver,
    get_escalation_resolution,
    get_instruction_delivery_config,
    get_origin_weighting_config,
    get_pane_direct_config,
    get_pending_command_escalations,
    get_pending_escalations,
    get_recent_audit_logs,
    get_session_dashboard_summary,
    group_pending_escalations,
    list_allowlist_rules,
    read_in_flight_state,
    record_human_opinion,
    resolve_escalation,
    revoke_allowlist_rule,
    set_answer_language,
    set_batch_approval_config,
    set_channel_approve_config,
    set_instruction_delivery_config,
    set_origin_weighting_config,
    set_pane_direct_config,
)
from tools.schengen_agent_llm import (
    SchengenAgentChat,
    approve_batch_escalations,
    get_current_active_escalation,
    get_current_command_escalation,
    get_oldest_question_escalation,
    reject_batch_escalations,
)
from adapters.agent_adapters import get_adapter
from adapters.herdr_client import get_pane_info, get_pane_text, run_cmd
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


def format_resolution_badge(resolution: Optional[str], short: bool = False) -> str:
    """Render the post-escalation processing status (APPROVED/REJECTED/UNANSWERED/ANSWERED)."""
    if resolution == "APPROVED":
        return "[green]AP[/]" if short else "[green]APPROVED[/]"
    if resolution == "REJECTED":
        return "[red]RJ[/]" if short else "[red]REJECTED[/]"
    if resolution == "UNANSWERED":
        return "[yellow]UA[/]" if short else "[yellow]UNANSWERED[/]"
    if resolution == "ANSWERED":
        return "[cyan]ANS[/]" if short else "[cyan]ANSWERED[/]"
    return "[dim]—[/]"


def format_question_hint(q_esc: dict) -> str:
    """Render the non-blocking sidebar hint for the oldest pending question.

    A QUESTION stays PENDING (for the hint + #2800 auto-dissolve) but never
    occupies the Command Approval slot (INV-QN-2/3).
    """
    return f"[bold yellow]💬 [{q_esc['pane_id']} Question Awaiting Answer][/]"


def format_approver_badge(approver: Optional[str], decision: str = "") -> str:
    """Render WHO approved/rejected an escalation: machine / human-tui /
    gatekeeper / pane-direct / other (INV-AP-1 accurate provenance)."""
    if decision in ("AUTO_APPROVED", "ALLOWLIST_BYPASS"):
        return "[dim]machine[/]"
    if approver == "human-tui":
        return "[cyan]human-tui[/]"
    if approver == "gatekeeper":
        return "[magenta]gatekeeper[/]"
    if approver == "pane-direct":
        return "[yellow]pane-direct[/]"
    if approver == "other":
        return "[dim]other[/]"
    return "[dim]—[/]"


# --- Audit-ledger display helpers (user-requested table UX) -----------------
#
# Two table concerns shared by the sidebar #audit-table and the fullscreen
# #audit-modal-table:
#   1. The command cell is DISPLAY-truncated to ~AUDIT_CMD_MAX_CELLS cells with a
#      trailing "…" so long raw_commands no longer force deep horizontal scroll.
#      Presentation-only: the FULL command stays in the audit record and remains
#      reachable via AuditDetailModal (only the table cell is shortened).
#   2. Both tables page through history (offset/limit pagination): an initial
#      batch loads, and the next batch APPENDS when the user scrolls to the
#      bottom (AuditPageMixin below — see class for the trigger model).

AUDIT_CMD_MAX_CELLS = 90      # display cap for the "Full Command Line" cell (~90 chars)
AUDIT_SIDEBAR_HEAD = 10       # sidebar initial batch (live "recent" head)
AUDIT_MODAL_HEAD = 100        # fullscreen initial batch
AUDIT_PAGE_SIZE = 50          # rows appended per load-more batch


def truncate_cmd_display(raw_cmd: Any, max_cells: int = AUDIT_CMD_MAX_CELLS) -> str:
    """Single-line DISPLAY form of a raw command for a table cell.

    Newlines collapse to single spaces and outer whitespace is trimmed. When the
    result is wider than ``max_cells`` terminal cells it is hard-truncated at a
    cell boundary with a trailing ``…`` (wide CJK/emoji glyphs count as 2 cells).
    This is presentation-only: the full command remains in the audit record and
    is reachable through the detail modal.
    """
    text = " ".join(str(raw_cmd or "").split())
    if cell_len(text) <= max_cells:
        return text
    budget = max(0, int(max_cells) - 1)  # reserve 1 cell for the ellipsis
    out: List[str] = []
    used = 0
    for ch in text:
        w = cell_len(ch)
        if used + w > budget:
            break
        out.append(ch)
        used += w
    return "".join(out) + "…"


def audit_verdict_badge(decision: Any, resolution: Any, approver: Any) -> str:
    """Sidebar "V" verdict cell from existing stored fields (presentation only)."""
    dec = str(decision or "")
    if "APPROVE" in dec:
        return "[green]OK[/]"
    if resolution == "APPROVED":
        if approver == "human-tui":
            return "[green]AP·👤[/]"
        if approver == "gatekeeper":
            return "[green]AP·🤖[/]"
        if approver == "pane-direct":
            return "[green]AP·⌨️[/]"
        return "[green]AP·❓[/]"
    if resolution == "REJECTED":
        if approver == "human-tui":
            return "[red]RJ·👤[/]"
        if approver == "gatekeeper":
            return "[red]RJ·🤖[/]"
        if approver == "pane-direct":
            return "[red]RJ·⌨️[/]"
        return "[red]RJ·❓[/]"
    if resolution == "UNANSWERED":
        return "[yellow]UA[/]"
    if resolution == "ANSWERED":
        return "[cyan]ANS[/]"
    return "[red]ES[/]"


def sidebar_audit_cells(log: dict, cmd_max_cells: int = AUDIT_CMD_MAX_CELLS) -> Tuple[str, str, str, str]:
    """The 4 sidebar cells (Time, P, V, Cmd) for one audit row."""
    ts = str(log.get("timestamp") or "")
    time_str = ts[11:19] if len(ts) >= 19 else ts
    return (
        time_str,
        str(log.get("pane_id") or ""),
        audit_verdict_badge(log.get("decision"), log.get("resolution"), log.get("approver")),
        rich_escape(truncate_cmd_display(log.get("raw_command"), max_cells=cmd_max_cells)),
    )


def modal_audit_cells(log: dict) -> Tuple[str, ...]:
    """The 9 fullscreen-ledger cells for one audit row.

    The command + reason cells are escaped so shell text (``[``, ``]``, …)
    renders literally (rich_escape, #181/#182) and the command cell is capped at
    AUDIT_CMD_MAX_CELLS — the FULL command stays in the record / detail modal.
    """
    dec = str(log.get("decision") or "")
    badge = "[green]APPROVED[/]" if "APPROVE" in dec else "[red]ESCALATED[/]"
    full_cmd = truncate_cmd_display(log.get("raw_command"), max_cells=AUDIT_CMD_MAX_CELLS)
    reason = " ".join(str(log.get("safety_reason") or "").split())[:45]
    return (
        f"#{log.get('id')}",
        format_local_time(str(log.get("timestamp") or "")),
        str(log.get("pane_id") or ""),
        str(log.get("agent_kind") or "agy"),
        badge,
        format_resolution_badge(log.get("resolution"), short=True),
        str(log.get("decision_layer") or "SHELL_AST"),
        rich_escape(reason),
        rich_escape(full_cmd),
    )


class AuditPageMixin:
    """Web-style infinite scroll for audit DataTables.

    Trigger model: the NEXT page (``audit_page_size`` rows at the current
    ``offset``) is appended whenever the user reaches the bottom of the loaded
    rows —
      * ``watch_scroll_y`` fires while scrolling down toward the bottom
        (``scroll_y`` increases and lands at/below the max scroll), and
      * an explicit wheel-down at the bottom (where nothing can scroll further)
        fires the same load via ``on_mouse_scroll_down``.
    Appending grows ``max_scroll_y`` below the viewport, so the user keeps
    scrolling to pull in further pages; the viewport never jumps. A short page
    (fewer than ``audit_page_size`` rows) or an empty page marks the end of the
    ledger (``_audit_all_loaded``). Rows are id-deduplicated so a live insert
    between page loads can never render a duplicate. ``audit_records`` keeps the
    records in ROW ORDER, so ``row_index`` always maps to the record that
    rendered it (used by the detail-modal openers).

    Subclasses provide ``_audit_fetch_page(offset, limit)`` and
    ``_audit_row_cells(log)`` and must call ``_init_audit_paging()`` from their
    ``__init__`` (or ``on_mount``).
    """

    audit_page_size = AUDIT_PAGE_SIZE

    def _init_audit_paging(self) -> None:
        self.audit_records: List[dict] = []           # loaded records, row order
        self._audit_displayed_ids: Set[int] = set()   # id dedupe across pages
        self._audit_fetched: int = 0                  # DB rows consumed (next offset)
        self._audit_all_loaded: bool = False
        self._audit_loading: bool = False
        self._audit_cmd_max_cells: int = AUDIT_CMD_MAX_CELLS

    # -- subclass hooks -----------------------------------------------------
    def _audit_fetch_page(self, offset: int, limit: int) -> List[dict]:
        raise NotImplementedError

    def _audit_row_cells(self, log: dict) -> Tuple[Any, ...]:
        raise NotImplementedError

    # -- state helpers ------------------------------------------------------
    def _audit_prime(self, head_logs: List[dict], initial_batch: int) -> None:
        """Clear the table and re-baseline on the newest head page (live refresh)."""
        self.clear()
        self.audit_records.clear()
        self._audit_displayed_ids.clear()
        self._audit_fetched = len(head_logs)
        self._audit_all_loaded = len(head_logs) < max(1, int(initial_batch))
        self._audit_loading = False
        self._audit_append_rows(head_logs)

    def _audit_append_rows(self, logs: List[dict]) -> int:
        n = 0
        for log in logs:
            if log.get("id") in self._audit_displayed_ids:
                continue
            self.add_row(*self._audit_row_cells(log))
            self.audit_records.append(log)
            self._audit_displayed_ids.add(log["id"])
            n += 1
        return n

    def _at_scroll_bottom(self) -> bool:
        try:
            return float(self.scroll_y) >= float(self.max_scroll_y) - 0.5
        except Exception:
            return False

    def _maybe_load_next_page(self) -> None:
        if self._audit_loading or self._audit_all_loaded:
            return
        if not self._at_scroll_bottom():
            return
        self._audit_loading = True
        try:
            page = self._audit_fetch_page(self._audit_fetched, self.audit_page_size)
            if not page:
                self._audit_all_loaded = True
                return
            self._audit_fetched += len(page)
            self._audit_append_rows(page)
            if len(page) < self.audit_page_size:
                self._audit_all_loaded = True
        except Exception:
            self._audit_all_loaded = True  # fail-stop: never loop on an error
        finally:
            self._audit_loading = False

    def watch_scroll_y(self, old_value: float, new_value: float) -> None:
        super().watch_scroll_y(old_value, new_value)
        try:
            # Only a DOWNWARD scroll that lands at the bottom pages more; a
            # programmatic clamp back to the top (head refresh) never triggers.
            if float(new_value) > float(old_value) and self._at_scroll_bottom():
                self._maybe_load_next_page()
        except Exception:
            pass

    def on_mouse_scroll_down(self, event: events.MouseScrollDown) -> None:
        # Wheel at the very bottom cannot scroll further — load the next page.
        # (A mid-list wheel is left to the base DataTable scroll handler; the
        # stop() keeps the event from bubbling to ancestor containers.)
        if self._at_scroll_bottom():
            self._maybe_load_next_page()
        event.stop()

    def on_mouse_scroll_up(self, event: events.MouseScrollUp) -> None:
        event.stop()

# --- Phase3 queue status taxonomy + universal deep-link (Sprint 2) ----------
#
# Presentation-only helpers: every badge is derived from EXISTING stored fields
# (status, decision_layer, resolution, approver, FIFO position). No new data is
# invented. See docs/todo/TODO_phase3.md "Pending Queue Status Taxonomy" + "Universal
# Deep-Link".

# Deep-link tokens rendered in chat / queue lists. `[#N]` and `[Audit #N]` carry
# their record id; a bare `[▼ Details]` inherits the nearest preceding token's
# target (or the caller-supplied default) on the same message.
_LINK_TOKEN_RE = re.compile(r"(\[Audit\s*#(\d+)\])|(\[#(\d+)\])|(\[▼\s*Details\])")
_LINK_STYLE = "bold underline cyan"


def format_inflight_phase_badge(phase: str) -> str:
    """Render the Phase-1 in-flight sub-phase badge (INV-PH1-1).

    Sourced ONLY from the watcher-published read_in_flight_state(); a PENDING
    escalation always renders the Phase-2 "Human Action Required" map instead.
    """
    if phase == "gatekeeper":
        return "[dim magenta]🤖 Gatekeeper: judging[/]"
    return "[dim]🔍 Inspector: checking[/]"


def format_pending_queue_badge(
    esc: dict,
    active_id: Optional[int] = None,
    slot: Optional[int] = None,
    judging: bool = False,
) -> str:
    """Render the phase3 pending-queue status badge from existing fields.

    Precedence (only what is determinable from stored data + judging state):
      1. Not the active FIFO slot  -> ``⏳ [Deferred (Slot #N)]``
         (strict single-pending FIFO: every non-head row waits behind the
         active slot; ``slot`` is the row's 1-based position in the FIFO line)
      2. ``decision_layer == QUESTION`` -> ``🚨 [Human Action Required]``
         (the user answers in the pane; nothing else can auto-resolve it)
      3. ``judging`` (active head, judge LLM investigating) ->
         ``🔍 [Gatekeeper Checking]`` (INV-HR-1/2: NOT yet "Human Required")
      4. Otherwise -> ``🚨 [Human Action Required]``

    NOTE (logic dependency): a PENDING/DELIVERED non-question HEAD is ALWAYS
    awaiting human /approve — the inspector reaches a final verdict BEFORE
    ``enqueue_pending_escalation`` is called, so in-flight (Phase-1) inspection
    is never persisted and must not be inferred from stored fields. The judge
    round-trip (Phase 2a) is a TUI-local state passed via ``judging``.
    """
    status = esc.get("status", "PENDING")
    if status not in ("PENDING", "DELIVERED"):
        return f"[red]✖ [{rich_escape(str(status or 'UNKNOWN'))}][/]"
    if active_id is not None and esc.get("id") != active_id:
        n = int(slot) if slot else 1
        return f"[bold yellow]⏳ [Deferred (Slot #{n})][/]"
    if esc.get("decision_layer") == "QUESTION":
        # QUESTION outranks judging by control flow (INV-HR-1/2): a question is
        # never under judge investigation, so it must never render "Checking".
        return "[bold red]🚨 [Human Action Required][/]"
    if judging:
        return "[bold cyan]🔍 [Gatekeeper Checking][/]"
    return "[bold red]🚨 [Human Action Required][/]"


def format_resolved_badge(resolution: Optional[str], approver: Optional[str]) -> str:
    """Render the post-adjudication badge from existing resolution + approver fields."""
    if resolution == "ANSWERED":
        return "[cyan]ANS[/]"
    if resolution == "REJECTED":
        return "[red]RJ[/]"
    if resolution == "UNANSWERED":
        return "[yellow]UA[/]"
    if resolution == "APPROVED":
        if approver == "gatekeeper":
            return "[green]⚡ [Approved (Gatekeeper)][/]"
        if approver == "human-tui":
            return "[cyan]👤 [Approved (Human)][/]"
        if approver == "pane-direct":
            return "[yellow]⌨️ [Approved (Pane-Direct)][/]"
        return "[green]⚡ [Approved][/]"
    return "[dim]—[/]"


def _pad_cells(text: str, target: int) -> str:
    """Right-pad ``text`` to ``target`` terminal cells (CJK/emoji aware)."""
    return text + " " * max(0, target - cell_len(text))


def _wrap_flat_lines(text: str, max_cells: int, label: str) -> List[str]:
    """Word-wrap ``text`` into lines that fit within ``max_cells`` terminal cells.

    ``label`` (a fixed-width prefix column such as ``💻 Command:  ``) is
    prepended to the FIRST line only. Continuation lines carry the PURE
    original text — no indentation, no added padding — so the command and
    reason select and copy as-is (INV-HR-6). Original newlines in ``text``
    are preserved as hard line breaks. Long unbreakable tokens are hard-split
    on cell boundaries. Nothing is truncated.
    """
    avail = max(8, max_cells - cell_len(label))
    out: List[str] = []

    def _wrap_segment(seg: str) -> List[str]:
        lines: List[str] = []
        cur = ""
        cur_cells = 0

        def flush() -> None:
            nonlocal cur, cur_cells
            if cur:
                lines.append(cur)
                cur, cur_cells = "", 0

        for word in seg.split(" "):
            w = cell_len(word)
            if cur and cur_cells + 1 + w <= avail:
                cur += " " + word
                cur_cells += 1 + w
                continue
            if w <= avail:
                flush()
                cur, cur_cells = word, w
                continue
            # unbreakable token longer than one line: hard-split on cells
            flush()
            remaining = word
            while cell_len(remaining) > avail:
                chunk = ""
                used = 0
                for ch in remaining:
                    cw = cell_len(ch)
                    if used + cw > avail:
                        break
                    chunk += ch
                    used += cw
                lines.append(chunk)
                remaining = remaining[len(chunk):]
            cur, cur_cells = remaining, cell_len(remaining)
        flush()
        return lines

    for i, seg in enumerate(text.split("\n")):
        seg_lines = _wrap_segment(seg)
        for j, ln in enumerate(seg_lines):
            if i == 0 and j == 0:
                out.append(label + ln)
            else:
                out.append(ln)
    return out


def format_decision_card(esc: dict, width: int = 74) -> Text:
    """Render the "Human Authorization Required" decision card.

    Only the header badge is framed. The target / command / reason / action
    lines below the frame are FLAT text — no ``│`` box borders and no added
    padding — so the full command and full reason can be selected and copied
    as original text (INV-HR-6). Body lines word-wrap to the card width and
    are never truncated. The ``[#<id>]`` frame token stays in the top frame
    line, where it remains a deep-link (hit-tested by
    ``FocusableRichLog._link_target_at`` on the rendered text).
    """
    width = max(52, int(width))
    frame_inner = width - 2   # between ╭…╮ / ├…┤ / ╰…╯
    box_inner = width - 3     # between │ … │ (after "│ " and before "│")
    esc_id = int(esc["id"])
    esc_token = f"[#{esc_id}]"
    pane = str(esc.get("pane_id") or "?")
    agent = str(esc.get("agent_kind") or "agent")
    # Preserve the original whitespace of the command/reason (only outer trim);
    # the raw text must copy-paste faithfully (INV-HR-6).
    cmd = str(esc.get("raw_command") or "").strip()
    layer = str(esc.get("decision_layer") or "UNKNOWN")
    reason = str(esc.get("safety_reason") or "").strip()
    if not reason:
        reason = f"Deferred to human review ({layer})."

    card = Text()

    def box_line(inner: str, styles: Optional[List[Tuple[int, int, str]]] = None) -> None:
        """Append ``│ <inner padded to box_inner> │`` and apply relative styles."""
        pad = max(0, box_inner - cell_len(inner))
        start = len(card.plain)
        card.append("│ " + inner + " " * pad + "│\n")
        if styles:
            base = start + 2
            for s, e, style in styles:
                card.stylize(style, base + s, base + e)

    # ── Top frame: ╭── 🚨 ACTION REQUIRED ── Escalation [#id]────╮
    #    The [#id] deep-link token lives in this frame line (MUST stay in the
    #    rendered text for FocusableRichLog._link_target_at hit-testing).
    prefix = "── 🚨 ACTION REQUIRED ── Escalation "
    suffix = "──"
    filler = max(1, frame_inner - cell_len(prefix + esc_token + suffix))
    top = "╭" + prefix + esc_token + "─" * filler + suffix + "╮"
    card.append(top, style="bold red")
    tok_start = top.index(esc_token)
    card.stylize("bold underline cyan", tok_start, tok_start + len(esc_token))
    card.append("\n")

    # ── Header badge (framed) ──
    header = f"🚨 [ESCALATION #{esc_id}] Human Authorization Required"
    for ln in _wrap_flat_lines(header, box_inner, ""):
        box_line(ln, [(0, len(ln), "bold red")])

    # ── Separator ──
    card.append("├" + "─" * frame_inner + "┤\n", style="dim")

    # ── Flat body: target / command / reason — copy-paste-able (INV-HR-6) ──
    def flat_field(icon: str, name: str, value: str, value_style: str = "white") -> None:
        label = f"{icon} {name:<9}: "
        lines = _wrap_flat_lines(value, width, label)
        for i, ln in enumerate(lines):
            start = len(card.plain)
            card.append(ln + "\n")
            if i == 0:
                card.stylize("bold", start, start + cell_len(label))
                card.stylize(value_style, start + cell_len(label), start + len(ln))
            else:
                # continuation lines are pure text; dim styling only (copy
                # output is unaffected — the characters are unchanged)
                card.stylize("dim", start, start + len(ln))

    flat_field("🌐", "Target", f"{pane} ({agent})", "bold white")
    flat_field("💻", "Command", cmd, "white")
    flat_field("⚠️", "Reason", f"{layer} — {reason}", "yellow")

    # ── Flat action bar (copy-paste-able) ──
    start = len(card.plain)
    card.append("👉 MANDATORY ACTION (type to execute):\n")
    card.stylize("bold yellow", start, start + len("👉 MANDATORY ACTION (type to execute):"))

    def action(label: str, value: str, label_style: str) -> None:
        padded = _pad_cells(label, 17)
        line = padded + " : " + value
        start = len(card.plain)
        card.append(line + "\n")
        card.stylize(label_style, start, start + cell_len(label))
        card.stylize("white", start + cell_len(padded) + 3, start + len(line))

    action("[✔ Approve]", f"/approve {esc_id}", "bold green")
    action("[✖ Reject]", f"/reject {esc_id} [reason]", "bold red")
    action("[🔒 Always Allow]", "/allow-last", "bold cyan")

    # ── Bottom frame ──
    card.append("╰" + "─" * frame_inner + "╯\n", style="bold red")
    return card


def resolve_audit_id_for_escalation(esc_id: int) -> Optional[int]:
    """Map an escalation id to the audit_logs id that best represents it.

    1. If the id itself IS an audit record, use it directly.
    2. Otherwise locate the pending escalation and match the newest audit row
       with the same (pane_id, raw_command).
    3. Return None when nothing matches — callers then fall back to
       ``AuditDetailModal(esc_id)`` (the modal renders "Record not found.").
    """
    esc_id = int(esc_id)
    try:
        if get_audit_log_by_id(esc_id):
            return esc_id
    except Exception:
        pass
    try:
        pending = get_pending_escalations(include_delivered=True)
    except Exception:
        return None
    for esc in pending:
        if esc.get("id") == esc_id:
            pane = esc.get("pane_id", "")
            cmd = esc.get("raw_command", "")
            try:
                logs = get_recent_audit_logs(limit=100, pane_id=pane)
            except Exception:
                return None
            for log in logs:  # newest first (id DESC)
                if log.get("raw_command") == cmd:
                    return log["id"]
            return None
    return None


def _linkify_chat_markup(
    markup: str,
    default_target: Optional[Tuple[int, str]] = None,
) -> Text:
    """Convert ``[Audit #N]`` / ``[#N]`` / ``[▼ Details]`` tokens into links.

    Rich markup must NOT see the raw ``[#N]`` form (it parses ``#N`` as a hex
    color and swallows it), so tokens are first replaced with sentinels, the
    remaining string is parsed as ordinary rich markup, then the sentinels are
    spliced back as styled, clickable Text spans. ``[▼ Details]`` inherits the
    nearest preceding token target in the same message, else ``default_target``.

    The resulting Text is hit-tested by ``FocusableRichLog._link_target_at``
    (RichLog strips segment meta during offset rendering, so click handling
    re-derives the target from the rendered line text).
    """
    tokens: List[Tuple[str, Optional[int], Optional[str]]] = []
    last_target: Optional[Tuple[int, str]] = default_target

    def _protect(m: "re.Match[str]") -> str:
        nonlocal last_target
        label = m.group(0)
        if m.group(2):  # [Audit #N]
            target: Optional[int] = int(m.group(2))
            kind: Optional[str] = "audit"
        elif m.group(4):  # [#N]
            target = int(m.group(4))
            kind = "escalation"
        else:  # [▼ Details]
            target, kind = last_target if last_target else (None, None)
        if target is not None:
            last_target = (target, kind or "escalation")
        tokens.append((label, target, kind))
        return f"\x00T{len(tokens) - 1}\x01"

    protected = _LINK_TOKEN_RE.sub(_protect, markup)
    try:
        base = Text.from_markup(protected)
    except Exception:
        base = Text(protected)

    out = Text()
    pos = 0
    for m in re.finditer(r"\x00T(\d+)\x01", base.plain):
        if m.start() > pos:
            out.append_text(base[pos : m.start()])
        label, target, kind = tokens[int(m.group(1))]
        if target is None:
            out.append(label)  # bare token: render literally, not as a link
        else:
            link = Text(label, style=_LINK_STYLE)
            out.append_text(link)
        pos = m.end()
    if pos < len(base.plain):
        out.append_text(base[pos:])
    return out


def _chat_plain_text(msg: str) -> str:
    """Strip rich markup for the clipboard buffer while preserving meaningful
    bracket tokens: deep-links (``[#N]`` / ``[Audit #N]`` / ``[▼ Details]``),
    the decision-card header/action labels (``[ESCALATION #N]``,
    ``[✔ Approve]``, ``[✖ Reject]``, ``[🔒 Always Allow]``, ``[reason]``).
    """
    protect_re = re.compile(
        r"(\[(?:Audit\s+)?#\d+\])|(\[▼\s*Details\])|(\[ESCALATION\s*#\d+\])"
        r"|(\[[✔✖🔒][^\]\n]*\])|(\[reason\])"
    )
    protected = protect_re.sub(
        lambda m: m.group(0).replace("[", "\x00").replace("]", "\x01"), str(msg)
    )
    plain = re.sub(r"\[/?[^\]]*\]", "", protected)
    return plain.replace("\x00", "[").replace("\x01", "]")


def _update_static_if_changed(widget: Static, content: str) -> None:
    """Update a Static only when its content changes, avoiding redundant re-render/layout.

    `Static.update()` always refreshes with `layout=True`, so unconditional calls
    (e.g. from a periodic timer) cause constant re-render + re-layout and visible
    flickering. Guard with a content comparison.
    """
    if getattr(widget, "content", None) != content:
        widget.update(content)


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


def _link_target_in_line(segments: List[Any], x: int) -> Optional[Tuple[int, str]]:
    """Hit-test a deep-link token in one rendered line at content cell ``x``.

    ``segments`` are the line's rich Segments (as stored in RichLog.lines).
    Returns (record_id, kind) for the token under the cell, with a bare
    ``[▼ Details]`` inheriting the nearest preceding token target on the line.
    Wide (CJK) glyphs are accounted for via cell widths.
    """
    if x < 0:
        return None
    chars: List[str] = []
    char_cell: List[int] = []
    cell = 0
    for seg in segments:
        for ch in getattr(seg, "text", ""):
            char_cell.append(cell)
            chars.append(ch)
            cell += cell_len(ch)
    if not char_cell or x >= cell:
        return None
    target_char = None
    for i, start in enumerate(char_cell):
        if x >= start and x < start + cell_len(chars[i]):
            target_char = i
            break
    if target_char is None:
        return None
    line_text = "".join(chars)
    last_target: Optional[Tuple[int, str]] = None
    for m in _LINK_TOKEN_RE.finditer(line_text):
        s, e = m.span()
        if m.group(2):  # [Audit #N]
            last_target = (int(m.group(2)), "audit")
        elif m.group(4):  # [#N]
            last_target = (int(m.group(4)), "escalation")
        if s <= target_char < e:
            return last_target  # Details inherits the nearest preceding target
    return None


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

    def _link_target_at(self, x: int, y: int) -> Optional[Tuple[int, str]]:
        """Return (record_id, kind) for the deep-link token under content cell (x, y).

        ``kind`` is "audit" (the id IS an audit_logs id) or "escalation"
        (resolve to an audit record at open time). Returns None when no link
        token is under the cell. Coordinates are widget-relative (as delivered
        by Click events); border + padding are converted to content coords and
        wide (CJK) glyphs are accounted for via cell widths.
        """
        try:
            cr = self.content_region
            r = self.region
            cx = x - (cr.x - r.x)
            cy = y - (cr.y - r.y)
        except Exception:
            cx, cy = x, y
        if cx < 0 or cy < 0:
            return None
        line_idx = self._start_line + cy
        if not (0 <= line_idx < len(self.lines)):
            return None
        return _link_target_in_line(self.lines[line_idx]._segments, cx)

    def on_click(self, event: events.Click) -> None:
        """Open AuditDetailModal when a deep-link token is clicked in chat."""
        if event.button != 1:
            return
        hit = self._link_target_at(event.x, event.y)
        if hit is None:
            return
        event.stop()
        app = getattr(self, "app", None) or getattr(self, "_app", None)
        if app is None or len(app.screen_stack) > 1:
            return
        record_id, kind = hit
        if kind == "audit":
            app.push_screen(AuditDetailModal(record_id))
        else:
            resolved = resolve_audit_id_for_escalation(record_id)
            app.push_screen(AuditDetailModal(resolved if resolved is not None else record_id))


# --- Modal close-button convention (shared by every audit modal) -----------
#
# Any modal that wants a mouse-only dismiss path composes a
# Horizontal(id="modal-title-bar") as its first dialog child, containing the
# title Label (left, 1fr) and a Button(id="modal-close", classes="modal-close")
# at the far right, then inherits ModalCloseMixin. Same id/class/styling/
# placement everywhere — this is the house convention, not a one-off.

MODAL_CLOSE_CSS = """
    #modal-title-bar {
        height: auto;
        layout: horizontal;
    }
    #modal-title-bar > Label {
        width: 1fr;
        height: 1;
        content-align: left middle;
    }
    #modal-close {
        width: 3;
        height: 1;
        min-width: 3;
        max-width: 3;
        margin: 0;
        padding: 0;
        border: none;
        background: transparent;
        color: $text-muted;
        text-style: bold;
        content-align: center middle;
    }
    #modal-close:hover {
        background: $error-darken-1;
        color: $text;
    }
    #modal-close:focus {
        background: $error-darken-1;
        color: $text;
        border: solid $accent;
    }
"""


class ModalCloseMixin:
    """Shared modal-close convention: a top-right ✕ button pops the modal screen.

    Compose a ``Button("✕", id="modal-close", classes="modal-close")`` as the
    last child of a ``Horizontal(id="modal-title-bar")`` row and inherit this
    mixin to get mouse dismissal. The existing keyboard bindings (escape/q)
    remain untouched.
    """

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if getattr(event.button, "id", None) == "modal-close":
            event.stop()
            self.app.pop_screen()


class AuditFullscreenModal(ModalCloseMixin, ModalScreen):
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
    CSS += MODAL_CLOSE_CSS

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back (ESC)", show=True),
        Binding("q", "app.pop_screen", "Close (q)", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="audit-modal-dialog"):
            with Horizontal(id="modal-title-bar"):
                yield Label("[bold cyan]📜 Schengen Security Audit Ledger (Fullscreen Maximize)[/]")
                yield Button("✕", id="modal-close", classes="modal-close")
            yield PagedAuditDataTable(id="audit-modal-table")
            yield Label("[dim]Press [bold yellow]ESC[/] to return · ↑/↓ navigate · [bold yellow]Enter[/] or [bold yellow]click[/] a row for detail · scroll to bottom to load more[/]", id="audit-modal-help")

    def on_mount(self) -> None:
        table = self.query_one("#audit-modal-table", PagedAuditDataTable)
        self._audit_table = table
        table.clear(columns=True)
        table.add_columns("ID", "Time", "Pane", "Agent", "Verdict", "Res", "Layer", "Reason", "Full Command Line")
        table.cursor_type = "row"
        # Initial batch (newest AUDIT_MODAL_HEAD); older rows page in on scroll.
        head = get_recent_audit_logs(limit=AUDIT_MODAL_HEAD)
        table._audit_prime(head, AUDIT_MODAL_HEAD)
        table.focus()

    def _open_detail(self, row_index: int) -> None:
        if len(self.app.screen_stack) != 2:
            return
        records = getattr(getattr(self, "_audit_table", None), "audit_records", None) or []
        if not (0 <= row_index < len(records)):
            return
        audit_id = records[row_index]["id"]
        self.app.push_screen(AuditDetailModal(audit_id))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        event.stop()
        self._open_detail(event.row_index)

    def on_mouse_down(self, event: events.MouseDown) -> None:
        meta = getattr(event.style, "meta", None) or {}
        row = meta.get("row")
        if isinstance(row, int):
            self._open_detail(row)


class AuditDetailModal(ModalCloseMixin, ModalScreen):
    """Fullscreen detail view of a single audit record, joined with past adjudication opinions."""

    CSS = """
    AuditDetailModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.85);
    }
    #detail-dialog {
        width: 96%;
        height: 94%;
        background: $surface-darken-1;
        border: tall $accent;
        padding: 1;
        layout: vertical;
    }
    #detail-scroll {
        width: 100%;
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
    }
    #detail-command {
        background: $surface-darken-1;
        border: solid $surface-lighten-1;
        padding: 1;
        margin-top: 1;
        margin-bottom: 1;
        width: 100%;
        height: auto;
    }
    #detail-opinions {
        background: $surface-darken-1;
        border: solid $surface-lighten-1;
        padding: 0 1;
        margin-top: 1;
        width: 100%;
        height: auto;
    }
    #detail-help {
        dock: bottom;
        color: $text-muted;
        text-align: center;
    }
    .detail-section {
        color: $text-muted;
        text-style: bold;
        margin-top: 1;
        margin-bottom: 0;
    }
    """
    CSS += MODAL_CLOSE_CSS

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back (ESC)", show=True),
        Binding("q", "app.pop_screen", "Close (q)", show=False),
    ]

    def __init__(self, audit_id: int) -> None:
        super().__init__()
        self.audit_id = audit_id

    def compose(self) -> ComposeResult:
        with Vertical(id="detail-dialog"):
            with Horizontal(id="modal-title-bar"):
                yield Label("[bold cyan]📜 Audit Record Detail[/]", id="detail-title")
                yield Button("✕", id="modal-close", classes="modal-close")
            with VerticalScroll(id="detail-scroll"):
                yield Static(id="detail-fields")
                yield Label("Full Command Line", classes="detail-section")
                yield Static(id="detail-command")
                yield Label("Adjudication Exchange (human opinion → gatekeeper decision)", classes="detail-section")
                yield Static(id="detail-opinions")
            yield Label("[dim]Press [bold yellow]ESC[/] to return to the ledger[/]", id="detail-help")

    def on_mount(self) -> None:
        log = get_audit_log_by_id(self.audit_id)
        if not log:
            self.query_one("#detail-fields", Static).update("[bold red]Record not found.[/]")
            return

        dec = log.get("decision", "")
        badge = "[green]APPROVED[/]" if "APPROVE" in str(dec) else "[red]ESCALATED[/]"
        resolution = get_escalation_resolution(log.get("pane_id", ""), log.get("raw_command", ""))
        approver = get_escalation_approver(log.get("pane_id", ""), log.get("raw_command", ""))
        fields = (
            f"[bold]ID[/]: #{log['id']}    [bold]Time[/]: {format_local_time(log.get('timestamp', ''))}\n"
            f"[bold]Pane[/]: {log.get('pane_id', '')}    [bold]Agent[/]: {log.get('agent_kind', 'unknown')}\n"
            f"[bold]Verdict[/]: {badge}    [bold]Resolution[/]: {format_resolution_badge(resolution)}    [bold]Approver[/]: {format_approver_badge(approver, dec)}\n"
            f"[bold]Layer[/]: {log.get('decision_layer', 'FAST_TRACK_AST')}\n"
            f"[bold]Reason[/]: {rich_escape(str(log.get('safety_reason', '')))}\n"
            f"[bold]Origin[/]: {log.get('origin', 'A')}    [bold]Consequence[/]: {log.get('consequence', 'NONE')}    [bold]Mechanism[/]: {log.get('mechanism', 'none')}\n"
            f"[bold]Gate[/]: {log.get('gate_state', 'ENFORCE')}    [bold]Shadow[/]: {'ON' if log.get('shadow_mode') else 'OFF'}"
        )
        self.query_one("#detail-fields", Static).update(fields)
        self.query_one("#detail-command", Static).update(rich_escape(str(log.get('raw_command', ''))))

        adjudications = get_adjudications_for_audit(log.get("pane_id", ""), log.get("raw_command", ""))
        if not adjudications:
            self.query_one("#detail-opinions", Static).update("[dim](no past adjudication opinions recorded)[/]")
            return
        lines = []
        for a in adjudications:
            if a.get("action") == "HUMAN_OPINION":
                lines.append(
                    f"[bold cyan]👤 [Human Opinion][/]  [dim]{format_local_time(a.get('created_at', ''))}[/]  —  "
                    f"{rich_escape(str(a.get('human_note', '')))}"
                )
                continue
            action_badge = "[green]APPROVE[/]" if a["action"] == "APPROVE" else "[red]REJECT[/]"
            lines.append(
                f"{action_badge}  by {format_approver_badge(a.get('approver'), '')}  "
                f"[dim]{format_local_time(a.get('created_at', ''))}[/]  —  "
                f"{rich_escape(str(a.get('feedback', '')))}"
            )
        self.query_one("#detail-opinions", Static).update("\n".join(lines))



class SettingsModal(ModalCloseMixin, ModalScreen):
    """Consolidated settings window (^s / F2 / settings button / /config / /settings).

    Every control reads from and writes to the EXISTING guard_config setters
    (instruction delivery, channel approve, answer language, batch approval,
    origin weighting, pane-direct auto-eviction) or the existing daemon
    lifecycle toggle. Settings that have no backing config key (Approval Bias,
    Fast-Track) are intentionally absent — see docs/todo/TODO_phase3.md.
    """

    CSS = """
    SettingsModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.85);
    }
    #settings-dialog {
        width: 64;
        max-width: 90%;
        height: auto;
        max-height: 92%;
        background: $surface-darken-1;
        border: tall $accent;
        padding: 1;
        layout: vertical;
        overflow-y: auto;
    }
    #settings-dialog .settings-category {
        color: $text-muted;
        text-style: bold;
        margin-top: 1;
        margin-bottom: 0;
    }
    .settings-row {
        layout: horizontal;
        height: 3;
        margin-top: 0;
        margin-bottom: 0;
    }
    .settings-row > Label {
        width: 1fr;
        height: 3;
        content-align: left middle;
    }
    .settings-row > Button {
        width: 24;
        height: 3;
        min-width: 24;
        padding: 0 1;
    }
    .settings-row > Static {
        width: 24;
        height: 3;
        content-align: right middle;
    }
    #settings-help {
        dock: bottom;
        color: $text-muted;
        text-align: center;
        margin-top: 1;
    }
    """
    CSS += MODAL_CLOSE_CSS

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Close (ESC)", show=True),
        Binding("q", "app.pop_screen", "Close (q)", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="settings-dialog"):
            with Horizontal(id="modal-title-bar"):
                yield Label("[bold cyan]⚙️ Settings[/]")
                yield Button("✕", id="modal-close", classes="modal-close")
            yield Label("🛡 Operation", classes="settings-category")
            with Horizontal(classes="settings-row"):
                yield Label("Guard daemon")
                yield Button("—", id="set-guard-daemon")
            with Horizontal(classes="settings-row"):
                yield Label("Mode (runtime role)")
                yield Static("—", id="set-mode")
            yield Label("📤 Instruction Delivery", classes="settings-category")
            with Horizontal(classes="settings-row"):
                yield Label("Send approve instruction")
                yield Button("—", id="set-approve-instr")
            with Horizontal(classes="settings-row"):
                yield Label("Send reject instruction")
                yield Button("—", id="set-reject-instr")
            with Horizontal(classes="settings-row"):
                yield Label("OpenCode channel approve")
                yield Button("—", id="set-channel-approve")
            yield Label("🤖 Automation", classes="settings-category")
            with Horizontal(classes="settings-row"):
                yield Label("Batch approval")
                yield Button("—", id="set-batch-approval")
            with Horizontal(classes="settings-row"):
                yield Label("Origin weighting (M5)")
                yield Button("—", id="set-origin-weighting")
            with Horizontal(classes="settings-row"):
                yield Label("Pane-direct auto-eviction")
                yield Button("—", id="set-pane-direct")
            yield Label("🗣️ Answer Language", classes="settings-category")
            with RadioSet(id="settings-lang-set"):
                yield RadioButton("English", id="lang-english")
                yield RadioButton("한국어", id="lang-korean", value=True)
                yield RadioButton("日本語", id="lang-japanese")
            yield Label("[dim]Changes apply immediately · ESC / q closes · ^s or F2 reopens[/]", id="settings-help")

    def on_mount(self) -> None:
        self._refresh()

    def _refresh(self) -> None:
        """Re-read live config and daemon state into the modal controls."""
        app = getattr(self, "app", None)
        try:
            locks = list_active_guard_locks()
            self.query_one("#set-guard-daemon", Button).label = (
                f"🛡️ Guard: ACTIVE (PID {locks[0][2]})" if locks else "🛡️ Guard: INACTIVE"
            )
            if app is not None:
                if app.is_controller:
                    self.query_one("#set-mode", Static).update(
                        f"[green]Controller (👑) PID {os.getpid()}[/]"
                    )
                else:
                    self.query_one("#set-mode", Static).update(
                        f"[yellow]Observer (👁) — Leader PID {app.leader_pid or 'active'}[/]"
                    )
        except Exception:
            pass
        cfg = get_instruction_delivery_config()
        try:
            self.query_one("#set-approve-instr", Button).label = (
                "Approve Instr: ON" if cfg.get("send_approve_instruction") else "Approve Instr: OFF"
            )
            self.query_one("#set-reject-instr", Button).label = (
                "Reject Instr: ON" if cfg.get("send_reject_instruction") else "Reject Instr: OFF"
            )
            self.query_one("#set-channel-approve", Button).label = (
                "Channel Approve: ON" if get_channel_approve_config() else "Channel Approve: OFF"
            )
        except Exception:
            pass
        # automation toggles (existing guard_config keys, human-only setters)
        try:
            self.query_one("#set-batch-approval", Button).label = (
                "Batch Approval: ON" if get_batch_approval_config().get("batch_approval_enabled", True) else "Batch Approval: OFF"
            )
        except Exception:
            pass
        try:
            self.query_one("#set-origin-weighting", Button).label = (
                "Origin Weighting: ON" if get_origin_weighting_config().get("origin_weighting_enabled", True) else "Origin Weighting: OFF"
            )
        except Exception:
            pass
        try:
            self.query_one("#set-pane-direct", Button).label = (
                "Pane-Direct: ON" if get_pane_direct_config().get("pane_direct_eviction_enabled", True) else "Pane-Direct: OFF"
            )
        except Exception:
            pass
        # language radios
        try:
            lang = get_answer_language()
            btn_id = _BUTTON_ID_BY_LANG.get(lang)
            if btn_id:
                btn = self.query_one(f"#{btn_id}", RadioButton)
                btn.value = True
        except Exception:
            pass

    def _notify_app(self) -> None:
        """Sync the first-screen status card after a change.

        The modal refreshes its own controls in-place; the app only needs the
        radar/status-card refresh so the first screen (Guard + Mode) reflects
        the new config immediately.
        """
        app = getattr(self, "app", None)
        if app is None:
            return
        try:
            app.update_radar_data(force=True)
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = getattr(event.button, "id", None)
        if bid == "modal-close":
            return  # ModalCloseMixin's handler (MRO) pops the screen once
        app = getattr(self, "app", None)
        if bid == "set-guard-daemon":
            if app is not None and hasattr(app, "toggle_guard_daemon"):
                msg = app.toggle_guard_daemon()
                try:
                    app._write(f"[bold yellow]⚙️ [Daemon Control]:[/] {msg}")
                except Exception:
                    pass
        elif bid == "set-approve-instr":
            cfg = get_instruction_delivery_config()
            set_instruction_delivery_config(send_approve_instruction=not cfg.get("send_approve_instruction", False))
        elif bid == "set-reject-instr":
            cfg = get_instruction_delivery_config()
            set_instruction_delivery_config(send_reject_instruction=not cfg.get("send_reject_instruction", True))
        elif bid == "set-channel-approve":
            set_channel_approve_config(not get_channel_approve_config())
        elif bid == "set-batch-approval":
            cfg = get_batch_approval_config()
            set_batch_approval_config(enabled=not cfg.get("batch_approval_enabled", True))
        elif bid == "set-origin-weighting":
            cfg = get_origin_weighting_config()
            set_origin_weighting_config(enabled=not cfg.get("origin_weighting_enabled", True))
        elif bid == "set-pane-direct":
            cfg = get_pane_direct_config()
            set_pane_direct_config(enabled=not cfg.get("pane_direct_eviction_enabled", True))
        else:
            return
        self._refresh()
        self._notify_app()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        lang = _LANG_BY_BUTTON_ID.get(event.pressed.id or "")
        if not lang:
            return
        event.stop()  # the app-level handler targets the sidebar RadioSet
        set_answer_language(lang)
        self._refresh()
        self._notify_app()


def format_status_card_text(
    *,
    is_controller: bool,
    leader_pid: Optional[int],
    guard_pid: Optional[int],
    guard_target: Optional[str] = None,
) -> str:
    """Render the sidebar System Status card from EXISTING live state.

    First-screen declutter (docs/todo/TODO_phase3.md "[Task/UX] TUI 토글/설정
    옵션 전용 윈도우(Settings Modal) 분리"): the sidebar top shows ONLY the 2
    core states — Guard daemon (ACTIVE/INACTIVE) and Mode (Controller/
    Observer). Instruction-delivery / language / automation knobs live in the
    SettingsModal (^s / F2 / settings button / /config / /settings) instead.
    """
    mode = "Controller (👑)" if is_controller else f"Observer (👁) — Leader PID {leader_pid or 'active'}"
    if guard_pid:
        guard = f"ACTIVE (🛡️) PID {guard_pid}"
        if guard_target:
            guard += f" · {guard_target}"
    else:
        guard = "INACTIVE (○)"
    return (
        f"[bold]Mode  :[/] {mode}\n"
        f"[bold]Guard :[/] {guard}"
    )


class FixedHeader(Header):
    """Header that does not expand or toggle tall mode on click."""
    ALLOW_SELECT = False

    def on_click(self, event: events.Click) -> None:
        event.stop()


class UnselectableLabel(Label):
    """Label that explicitly rejects text drag selection to prevent suppressing click events."""
    ALLOW_SELECT = False


class AuditDataTable(AuditPageMixin, DataTable):
    """Compact Recent Audits table; opens fullscreen modal on click or selection.

    Live widget: ``update_radar_data`` re-baselines the newest page via
    ``refresh_head``; the user can then scroll down past it and older batches
    append web-style (AuditPageMixin). Rows beyond the viewport scroll with a
    slim vertical scrollbar; horizontal scrolling stays off (the command cell is
    display-truncated, so it never forces deep horizontal scroll).
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            show_cursor=False,
            **kwargs,
        )
        # Do NOT force show_vertical_scrollbar here: Textual auto-shows it once
        # the content overflows (CSS overflow-y: auto). show_cursor stays False
        # so click always opens the fullscreen ledger, never a cell cursor.
        self.show_horizontal_scrollbar = False
        self._init_audit_paging()

    def _audit_fetch_page(self, offset: int, limit: int) -> List[dict]:
        return get_recent_audit_logs(limit=limit, offset=offset)

    def _audit_row_cells(self, log: dict) -> Tuple[str, str, str, str]:
        return sidebar_audit_cells(log, cmd_max_cells=self._audit_cmd_max_cells)

    def refresh_head(self, head_logs: List[dict], cmd_max_cells: Optional[int] = None) -> None:
        """Re-baseline on the newest head page (live refresh / first fill)."""
        self._audit_cmd_max_cells = cmd_max_cells or AUDIT_CMD_MAX_CELLS
        self._audit_prime(head_logs, AUDIT_SIDEBAR_HEAD)

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


class PagedAuditDataTable(AuditPageMixin, DataTable):
    """Fullscreen-ledger DataTable that appends OLDER audit rows on scroll.

    The modal owns the initial fill (``_audit_prime`` in on_mount); every
    subsequent batch is fetched by the mixin when the user scrolls to the
    bottom of the loaded rows.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._init_audit_paging()

    def _audit_fetch_page(self, offset: int, limit: int) -> List[dict]:
        return get_recent_audit_logs(limit=limit, offset=offset)

    def _audit_row_cells(self, log: dict) -> Tuple[Any, ...]:
        return modal_audit_cells(log)


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
    but does NOT implement SGR pixel mouse (1016). If Textual enables 2048, the
    terminal sends a resize report with pixel dimensions; Textual's parser then
    sets mouse_pixels=True and divides the (cell) SGR coordinates as pixels —
    collapsing every click to the top-left.

    So we disable the whole 2048 handshake — the capability query (2048$p), the
    enable request (2048h), and pixel-mouse (1016) — and rely on Textual's
    SIGWINCH fallback for resize events instead. Querying alone is not enough:
    the terminal's "supported" reply flips the driver's internal
    ``_in_band_window_resize`` flag to True, which then silences the SIGWINCH
    resize handler and leaves the app stuck at its original size.
    """

    def _enable_mouse_pixels(self) -> None:
        pass

    def _query_in_band_window_resize(self) -> None:
        pass

    def _enable_in_band_window_resize(self) -> None:
        pass


_LANG_BY_BUTTON_ID = {
    "lang-english": "english",
    "lang-korean": "korean",
    "lang-japanese": "japanese",
}
_BUTTON_ID_BY_LANG = {v: k for k, v in _LANG_BY_BUTTON_ID.items()}


class SchengenTUIApp(App):
    CSS = """
    Screen {
        layout: vertical;
        background: $surface-darken-2;
    }
    /* Maximize text-selection visibility: opaque bright cyan block with black text. */
    Screen > .screen--selection {
        background: #00FFFF;
        color: #000000;
        text-style: bold;
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
    /* "Go to agent pane" helper: hidden until a question escalation is active. */
    #btn-go-to-pane {
        display: none;
        height: 3;
        dock: bottom;
        margin-bottom: 1;
    }
    /* Guard daemon toggle: full-width row (guard state lives in #status-card) */
    #btn-toggle-guard {
        width: 100%;
        height: 3;
        min-width: 10;
        margin-bottom: 1;
        padding: 0 1;
    }
    /* Settings button: opens the consolidated SettingsModal (^s / F2 / /config) */
    #btn-open-settings {
        width: 100%;
        height: 3;
        min-width: 10;
        margin-bottom: 1;
        padding: 0 1;
    }
    /* Sidebar System Status card: live consolidated guard state (phase3).
       Decluttered to the 2 core first-screen states (Guard + Mode); all
       secondary knobs moved into the SettingsModal. */
    #status-card {
        height: auto;
        min-height: 5;
        max-height: 7;
        background: $surface-darken-1;
        border: solid $surface-lighten-1;
        border-left: heavy $accent;
        padding: 0 1;
        margin-bottom: 1;
        content-align: left middle;
    }
    /* Radar "Action Required" live status card (Sprint 2b, 3-tier):
       tier 1 = autonomous inspection in progress (Phase-1 in-flight),
       tier 2 = gatekeeper judging (INV-HR-1/2 — not yet human-required),
       tier 3 = PENDING/DELIVERED command escalation awaiting the commander.
       Amber border signals "attention" at all tiers; the red alarm is carried
       by the tier-3 content so the autonomous/checking tiers stay calm. */
    #action-card {
        display: none;
        height: auto;
        min-height: 4;
        max-height: 7;
        background: $surface-darken-1;
        border: tall $warning;
        border-left: heavy $warning;
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
        /* auto: Textual shows the slim vertical scrollbar only once appended
           (infinite-scroll) rows overflow the 10-row viewport. */
        overflow-y: auto;
        scrollbar-size-vertical: 1;
        scrollbar-color: $surface-lighten-2;
        scrollbar-color-hover: $accent;
        scrollbar-color-active: $accent-lighten-1;
        scrollbar-background: transparent;
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
        Binding("ctrl+s", "open_settings", "Settings", show=True),
        Binding("f2", "open_settings", "Settings", show=False),
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
        # INV-HR-1: id of the escalation whose TUI-local judge round-trip is
        # in flight. While it equals the active escalation id, the red
        # "Human Authorization Required" card is suppressed (Phase 2a
        # "Gatekeeper Checking…"); it renders only at Phase 2b (judge
        # finished AND the escalation is still PENDING).
        self._judging_escalation_id: Optional[int] = None
        # Escalation ids that already rendered the Phase-2b decision card
        # (written exactly once, when judging completes). Grows unboundedly —
        # sqlite ids never recycle, so this is harmless (a few entries per
        # FIFO head over the TUI's lifetime).
        self._decision_card_written: Set[int] = set()
        # Pane-direct pre-render eviction (INV-PD-4/5): escalation_id ->
        # CONSECUTIVE not-live renders. Eviction requires confirm_polls
        # consecutive not-live reads AND a non-blocked pane status — a single
        # transient read or a still-blocked agent never fake-approves (#7771).
        self._pane_direct_polls: Dict[int, int] = {}
        # FIFO head escalation id whose pane-direct counters are live; the
        # counter dict is reset whenever the head id changes.
        self._pane_direct_head: Optional[int] = None
        self._last_active_id: Optional[int] = None
        self._last_resolved_ref: Optional[Tuple[str, str]] = None  # (pane_id, raw_command) of last FIFO head
        self._last_escalation_link: Optional[Tuple[int, str]] = None  # default target for bare [▼ Details]
        self._processing_chat: bool = False
        self._last_guard_active: bool = False
        self._last_esc_time: float = 0.0
        self._last_chat_date = None  # last chat-message date (for day-change timestamp)

    def _timestamp(self) -> str:
        """Return a dim chat timestamp: HH:MM:SS, prefixed with the date only on day change."""
        now = datetime.now()
        if self._last_chat_date != now.date():
            self._last_chat_date = now.date()
            return f"[dim]{now.strftime('%Y-%m-%d %H:%M:%S')}[/]"
        return f"[dim]{now.strftime('%H:%M:%S')}[/]"

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
        # The judge round-trip is over: the escalation (if still PENDING)
        # falls back to the Phase-2b red path (fail-safe).
        self._judging_escalation_id = None
        self._write(f"\n[bold red]🛑 [Aborted]:[/] In-flight LLM call interrupted ({reason}).\n")
        self.update_radar_data(force=True)

    def compose(self) -> ComposeResult:
        yield FixedHeader(show_clock=True)
        with Horizontal(id="main-body"):
            # Left: Chat log fills space; banner floats just above input
            with Vertical(id="chat-column"):
                yield UnselectableLabel("[bold cyan]🤖 Schengen Security Gatekeeper (GPT)[/]")
                yield FocusableRichLog(id="chat-log", highlight=True, markup=True, wrap=True, auto_scroll=True)
                yield Static(id="active-target-banner")
                yield Button("↩ Go to agent pane", id="btn-go-to-pane", variant="primary")
                yield CommandTextArea(placeholder="Ask Gatekeeper or type command (Enter to submit, Shift+Enter for newline)...", id="input-box")

            # Right: Compact Radar with Token Meter
            with Vertical(id="radar-column"):
                yield Button("⚡ Toggle Guard", id="btn-toggle-guard", variant="warning")
                yield Button("⚙️ Settings (^s)", id="btn-open-settings", variant="default")
                yield Static(id="status-card")
                yield Static(id="question-hint")
                yield Static(id="action-card")
                yield Label("⚡ Token & Cache Meter", classes="section-title")
                yield Static(id="token-meter-box")
                yield AuditSectionHeader("📜 Recent Audits (Click: ⛶ Fullscreen)", classes="section-title")
                yield AuditDataTable(id="audit-table")
                yield Label("🚨 Pending Escalations Queue [dim](click item: details)[/]", classes="section-title")
                yield ListView(id="escalation-list")
        yield Footer()

    def action_open_audit_modal(self) -> None:
        if len(self.screen_stack) == 1:
            self.push_screen(AuditFullscreenModal())

    def action_open_settings(self) -> None:
        """Open the consolidated settings modal (^s / F2 / /config / /settings)."""
        if len(self.screen_stack) == 1:
            self.push_screen(SettingsModal())

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
        widget = getattr(event, "widget", None)
        if widget is not None and getattr(widget, "id", None) == "question-hint":
            self._focus_question_pane()

    def _focus_question_pane(self) -> None:
        """Focus the pane of the oldest pending question (same as /jump).

        Non-adjudicating navigation: a QUESTION is answered in the agent pane
        (AGENTS.md rule 10); the hint click / /jump just brings it into view.
        """
        q_esc = get_oldest_question_escalation()
        if q_esc:
            target = q_esc["pane_id"]
            run_cmd(["herdr", "pane", "focus", target])
            self._write(f"[bold cyan]↩ Focusing question pane {target}...[/]")
        else:
            self._write("[dim]No pending question to focus.[/]")

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
            # die-with-parent (ADR-003/ADR-008): the daemon must exit when the TUI
            # (single lifecycle owner) closes — never orphan. The daemon's
            # is_parent_alive poller self-terminates it when this process exits.
            env["SCHENGEN_STRICT_PARENT"] = "1"

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
        elif event.button.id == "btn-open-settings":
            self.action_open_settings()
        elif event.button.id == "btn-go-to-pane":
            # Command-slot head excludes questions (INV-QN-1/2); the "Go to
            # agent pane" button focuses the ACTIVE COMMAND's pane.
            active_esc = get_current_command_escalation()
            if active_esc:
                target = active_esc["pane_id"]
                subprocess.Popen(
                    ["herdr", "agent", "focus", target],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self._write(f"[bold cyan]↩ Focusing agent pane {target} ({active_esc.get('agent_kind','agent')})...[/]")
            else:
                self._write("[dim]No active question to focus.[/]")

    def _set_action_state_ui(self, active_esc: Optional[dict] = None) -> None:
        """Show/hide the "Go to agent pane" helper and sync the input state.

        Three presentation states, driven by the active escalation:
        - QUESTION escalation: disable the command input (the user answers in
          the agent pane, not the TUI) and surface a button that focuses the
          agent pane (AGENTS.md rule 10: questions are never adjudicated).
        - Command escalation (Phase 2, awaiting human): keep the input enabled
          and hint the commander's quick actions in the placeholder.
        - No escalation: restore the default input state and placeholder.
        """
        try:
            go_btn = self.query_one("#btn-go-to-pane", Button)
            input_widget = self.query_one("#input-box", CommandTextArea)
            is_question = bool(active_esc and active_esc.get("decision_layer") == "QUESTION")
            if is_question:
                go_btn.display = True
                go_btn.label = f"↩ Go to {active_esc['pane_id']} ({active_esc.get('agent_kind','agent')})"
                if self.is_controller:
                    input_widget.disabled = True
                    input_widget.placeholder = "🔒 Question pending — answer in the agent pane (use ↩ Go to agent pane)"
            elif active_esc:
                go_btn.display = False
                if self.is_controller:
                    input_widget.disabled = False
                    input_widget.placeholder = (
                        f"/approve {active_esc['id']} · /reject {active_esc['id']} [reason] · "
                        f"/allow-last — or ask Gatekeeper"
                    )
            else:
                go_btn.display = False
                if self.is_controller:
                    input_widget.disabled = False
                    input_widget.placeholder = "Ask Gatekeeper or type command (Enter to submit, Shift+Enter for newline)..."
        except Exception:
            pass

    def action_toggle_daemon(self) -> None:
        msg = self.toggle_guard_daemon()
        self._write(f"[bold yellow]⚙️ [Daemon Control]:[/] {msg}")
        self.update_radar_data(force=True)

    def _pane_direct_liveness_guard(self, active_esc: dict, confirm_polls: int = 2) -> bool:
        """INV-PD-4/5 pane-direct pre-render guard for the active FIFO escalation.

        Returns True when the escalation was auto-evicted this cycle
        (approver=pane-direct). Rules:
        - QUESTION escalations are liveness-checked via adapter.question_is_live
          (footer-keyed, INV-Q-3) and resolved as ANSWERED — never APPROVED
          (INV-Q-1); non-question escalations use dialog_is_live and resolve
          APPROVED.
        - Unknown adapters (None) are never evicted (fail-closed).
        - While the pane agent_status is 'blocked' the dialog is treated as live
          and NEVER evicted (INV-PD-4) — a blocked agent is by definition still
          waiting on the user.
        - Otherwise the dialog is liveness-checked; eviction requires
          `confirm_polls` (default 2) CONSECUTIVE not-live renders (INV-PD-5 /
          INV-Q-5 debounce) so a single transient read can never fake-approve a
          live dialog. A live read resets the counter.
        - Pane-read errors fail closed (treated live).
        The counter dict is reset whenever the FIFO head escalation id changes.
        """
        active_id = active_esc["id"]
        pane_id = active_esc["pane_id"]
        if active_id != self._pane_direct_head:
            self._pane_direct_head = active_id
            self._pane_direct_polls.clear()
        is_question = active_esc.get("decision_layer") == "QUESTION"
        adapter = get_adapter(active_esc.get("agent_kind") or "")
        if adapter is None:
            return False
        status = ""
        try:
            info = get_pane_info(pane_id)
        except Exception:
            return False  # INV-PD-4: unknown status -> never evict (fail-closed)
        if not info or not info.get("agent_status"):
            return False  # INV-PD-4: unknown status -> never evict (fail-closed)
        status = info["agent_status"]
        if status == "blocked":
            self._pane_direct_polls[active_id] = 0   # INV-PD-4: blocked -> NEVER evict
            return False
        try:
            pane_text = get_pane_text(pane_id, lines=80)
            # INV-Q-3: questions are footer-keyed (question_is_live); approval
            # dialogs use dialog_is_live.
            live = adapter.question_is_live(pane_text) if is_question else adapter.dialog_is_live(pane_text)
        except Exception:
            live = True  # fail-closed: never evict on read error
        if live:
            self._pane_direct_polls[active_id] = 0
            return False
        n = self._pane_direct_polls.get(active_id, 0) + 1
        self._pane_direct_polls[active_id] = n
        if n >= max(1, int(confirm_polls)):  # INV-PD-5 / INV-Q-5: debounced
            # INV-Q-1: a cleared question is ANSWERED (the user answered it in
            # the pane) — never APPROVED; non-questions keep APPROVED.
            resolve_escalation(
                pane_id=pane_id,
                resolution="ANSWERED" if is_question else "APPROVED",
                approver="pane-direct",
            )
            return True
        return False

    def update_radar_data(self, force: bool = False) -> None:
        if not self._columns_initialized:
            return

        # 0. Update Sidebar System Status card (consolidated live state)
        try:
            status_card = self.query_one("#status-card", Static)
        except Exception:
            return

        locks = list_active_guard_locks()
        status_card_text = format_status_card_text(
            is_controller=self.is_controller,
            leader_pid=self.leader_pid,
            guard_pid=locks[0][2] if locks else None,
            guard_target=locks[0][0] if locks else None,
        )
        _update_static_if_changed(status_card, status_card_text)

        # 0a. Guard toggle button carries the live ACTIVE/INACTIVE state on the
        #     first screen (docs/todo/TODO_phase3.md: Guard daemon + Mode are
        #     the only always-visible sidebar controls).
        try:
            guard_btn = self.query_one("#btn-toggle-guard", Button)
            new_label = (
                f"⚡ Guard: ACTIVE (🛡️ PID {locks[0][2]})" if locks else "⚡ Guard: INACTIVE"
            )
            if getattr(guard_btn, "label", None) is None or guard_btn.label.plain != new_label:
                guard_btn.label = new_label
        except Exception:
            pass

        # 0b. Non-blocking QUESTION hint (INV-QN-3): the oldest pending question
        #     is surfaced here instead of the Command Approval slot; clicking it
        #     focuses the pane (same as /jump). Auto-dissolves when the #2800
        #     ANSWERED sweep resolves it.
        try:
            question_hint = self.query_one("#question-hint", Static)
        except Exception:
            question_hint = None
        if question_hint is not None:
            q_esc = get_oldest_question_escalation()
            if q_esc:
                _update_static_if_changed(question_hint, format_question_hint(q_esc))
                question_hint.display = True
            else:
                question_hint.display = False

        # 1. Guard state edge detection (external kill alert) — the ACTIVE/
        #    INACTIVE display itself now lives in the #status-card above.
        is_guard_active = bool(locks)
        if self._last_guard_active and not is_guard_active:
            # External kill detected!
            self._write("\n[bold red]⚠️ [Guard Daemon Alert]:[/] SmartGate 가드 데몬이 외부에서 종료되었습니다 (INACTIVE). 다시 시작하려면 [bold yellow]Ctrl+T[/] 또는 ⚡ Toggle을 누르십시오.\n")
        self._last_guard_active = is_guard_active

        # 2. Update Token Meter (muted: data in white, labels in dim)
        stats = self.agent.get_token_usage_stats()
        meter_box = self.query_one("#token-meter-box", Static)
        meter_text = (
            f"[dim]Calls[/]   [white]{stats['api_calls']:,}[/]\n"
            f"[dim]In[/]      [white]{stats['prompt_tokens']:,}[/] tk\n"
            f"[dim]Out[/]     [white]{stats['completion_tokens']:,}[/] tk\n"
            f"[dim]Cached[/]  [white]{stats['cached_tokens']:,}[/] tk  [dim]{stats['cache_hit_pct']} hit[/]\n"
            f"[dim]Inspector  In {stats['inspector_in']:,} / Out {stats['inspector_out']:,}[/]\n"
            f"[dim]Judge      In {stats['judge_in']:,} / Out {stats['judge_out']:,}[/]"
        )
        _update_static_if_changed(meter_box, meter_text)

        # 3. Active Target Banner + radar Action-Required card (Phase 2).
        #    Command-slot head EXCLUDES questions (INV-QN-1/2): a PENDING
        #    QUESTION is surfaced via the sidebar #question-hint instead of
        #    occupying the Command Approval slot.
        active_esc = get_current_command_escalation()
        banner = self.query_one("#active-target-banner", Static)
        action_card = self.query_one("#action-card", Static)

        # Phase-1 in-flight IPC (INV-PH1-1/2): while the inspector evaluates
        # (BEFORE any escalation), show the live sub-phase badge. Sourced ONLY
        # from read_in_flight_state() (watcher-written, TTL 30s). A PENDING
        # command escalation ALWAYS outranks the informational Phase-1 badge
        # (INV-PH1-4): on multi-pane concurrency a different pane may already be
        # awaiting human /approve, and that Action-Required banner must not be
        # hidden behind an in-flight "checking" badge.
        in_flight = read_in_flight_state()
        if in_flight and not active_esc:
            oldest = min(in_flight, key=lambda e: e.get("started_at", 0))
            pane_id = oldest.get("pane_id", "?")
            agent = oldest.get("agent_kind") or "agent"
            preview = (oldest.get("command_preview") or "")[:60]
            # Top banner, autonomous tier: calm dim line — NO red alarm, because
            # no escalation awaits the commander yet (INV-PH1-4: a PENDING
            # command escalation ALWAYS outranks this informational state).
            _update_static_if_changed(
                banner,
                f"\n[dim]⚡ Autonomous inspection in progress...[/]\n"
                f"[bold cyan]⏳ Phase-1 In-Flight (pre-escalation)[/]\n"
                f"[dim]   {format_inflight_phase_badge(oldest.get('phase', 'inspector'))}[/]\n"
                f"[dim]   Pane {pane_id}: {rich_escape(preview)}[/]",
            )
            # Radar status card, tier 1 (autonomous): the pane is held while the
            # inspector evaluates; no human action due. Label is "Inspecting"
            # (not "Blocked") because the pane is being evaluated, not
            # blocked-awaiting-human (2b reviewer follow-up).
            _update_static_if_changed(
                action_card,
                f"[bold cyan]🔍 Autonomous Inspection[/]\n"
                f"[dim]Inspecting Pane :[/] [bold white]{pane_id}[/] [dim]({agent})[/]\n"
                f"[dim]Awaiting     :[/] [dim]⚡ Autonomous inspection in progress...[/]",
            )
            action_card.display = True
            self._set_action_state_ui(None)
        elif active_esc:
            active_id = active_esc["id"]
            is_question = active_esc.get('decision_layer') == "QUESTION"
            raw_cmd = active_esc['raw_command'].strip()
            # #91: remember the current FIFO head command so /allow-last can
            # persist an exact-literal (re.escape'd) allowlist rule for it.
            self._last_intercepted_cmd = active_esc["raw_command"]

            # PANE-DIRECT pre-render slot validation (INV-PD-4/5): never evict a
            # blocked pane, and only evict a not-live dialog after confirm_polls
            # CONSECUTIVE not-live renders (debounce) — a single transient read
            # must never fake-approve a still-live dialog (#7771). Delegates to
            # _pane_direct_liveness_guard; adapter None / read error fail closed.
            pane_direct_evicted = False
            try:
                confirm_polls = int(get_pane_direct_config().get("pane_direct_confirm_polls", 2))
            except Exception:
                confirm_polls = 2
            pane_direct_evicted = self._pane_direct_liveness_guard(active_esc, confirm_polls=confirm_polls)

            if pane_direct_evicted:
                _update_static_if_changed(
                    banner,
                    "\n[bold green]✔ Dialog answered in-pane  —  escalation auto-evicted[/]\n"
                    "[dim]🛡️  Stale escalation resolved via pane-direct.[/]",
                )
                action_card.display = False
                self._set_action_state_ui(None)
            else:
                cmd_lines = raw_cmd.splitlines()
                if len(cmd_lines) > 5:
                    cmd_display = "\n".join(cmd_lines[:5]) + f"\n[dim]… (+{len(cmd_lines) - 5} lines truncated)[/]"
                else:
                    cmd_display = "\n".join(cmd_lines)
                # Alarm banner keeps the command compact (2 lines) so the
                # ACTION REQUIRED header, reason, and action hint stay visible.
                if len(cmd_lines) > 2:
                    alarm_cmd = "\n".join(cmd_lines[:2]) + f"\n[dim]… (+{len(cmd_lines) - 2} lines truncated)[/]"
                else:
                    alarm_cmd = "\n".join(cmd_lines)

                reason_short = active_esc['safety_reason'][:72]

                # ── STRICT SEQUENTIAL FIFO first-sight notification (INV-HR-4):
                #    runs ONCE, BEFORE any red presentation, so the judge is
                #    invoked on the first tick and the escalation is marked as
                #    under review (INV-HR-1) before the banner renders.
                if self.is_controller and active_id not in self._notified_escalation_ids and not self._processing_chat:
                    self._notified_escalation_ids.add(active_id)
                    self._last_active_id = active_id
                    # Remember the FIFO head reference so the queue-clear notice
                    # can render its post-adjudication badge (resolution +
                    # approver) from existing stored fields.
                    self._last_resolved_ref = (active_esc["pane_id"], active_esc["raw_command"])
                    # Deep-link context: bare [▼ Details] tokens in the notices
                    # below inherit this escalation.
                    self._last_escalation_link = (active_id, "escalation")

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

                    if is_question:
                        safe_cmd = rich_escape(active_esc['raw_command'])
                        self._write(f"\n[cyan]{'─'*20} ❓ Question [#{active_id}] {'─'*20}[/]")
                        self._write(f"  [dim]Pane:[/]     {active_esc['pane_id']} ({active_esc.get('agent_kind', 'agent')})")
                        self._write(f"  [dim]Question:[/] [white]{safe_cmd}[/]")
                        self._write(f"[dim]  ↩ Answer directly in the pane — resolves automatically.  [cyan][▼ Details][/][/]\n")
                        # Read-only interpretation (NO approve/reject tools): surface the
                        # question in the TUI chat so the user notices it, without giving
                        # the gatekeeper any ability to adjudicate (AGENTS.md rule 10).
                        self._interpret_question()
                    else:
                        # INV-HR-1: mark the escalation as under judge review.
                        # The red "Human Authorization Required" card is NOT
                        # written yet — it renders only at Phase 2b (judge
                        # finished AND the escalation is still PENDING). The
                        # first-sight notice shows the checking state instead.
                        self._judging_escalation_id = active_id
                        self._write("\n[bold cyan]🔍 Gatekeeper Checking…[/]")
                        self._write(f"  [dim]Escalation [#{active_id}] · {active_esc['pane_id']} ({active_esc.get('agent_kind','agent')})[/]")
                        self._write("[dim]  Judge LLM evaluating command safety — you will be prompted only if human review is required.[/]\n")
                        self.process_user_chat(
                            "New escalation intercepted. Evaluate command safety, investigate using tools if necessary, and report or adjudicate.",
                            author="inspector",
                        )

                # ── INV-HR-1/INV-HR-2 phase gate: while the judge investigates
                #    this escalation, render the checking state — never the red
                #    "Human Authorization Required" card.
                is_judging = (
                    not is_question
                    and self.is_controller
                    and self._judging_escalation_id == active_id
                )
                if is_judging:
                    _update_static_if_changed(
                        banner,
                        f"\n[bold cyan]🔍 Gatekeeper Checking…[/]\n"
                        f"[dim]⚡ Autonomous inspection in progress...[/]\n"
                        f"[dim]   Escalation [#{active_id}] · {active_esc['pane_id']} ({active_esc.get('agent_kind','agent')})[/]\n"
                        f"[dim]   Judge evaluating command safety — no action required yet.[/]",
                    )
                    # Radar status card, tier 2 (gatekeeper): the judge LLM is
                    # still investigating (INV-HR-1/2) — NOT yet human-required.
                    _update_static_if_changed(
                        action_card,
                        f"[bold cyan]🔍 Gatekeeper Checking[/]\n"
                        f"[dim]Judging Pane :[/] [bold white]{active_esc['pane_id']}[/] [dim]({active_esc.get('agent_kind','agent')})[/]\n"
                        f"[dim]Awaiting     :[/] [bold cyan]🤖 Gatekeeper judging…[/]",
                    )
                    action_card.display = True
                    self._set_action_state_ui(None)
                else:
                    # ── Phase 2b: judge finished (or no judge) and the
                    #    escalation is still PENDING — human authorization due.
                    if is_question:
                        banner_text = (
                            f"[bold cyan]❓ #{active_id}[/]  [bold white]{active_esc['pane_id']}[/]  [dim]({active_esc.get('agent_kind','agent')})[/]\n"
                            f"[bold white]{rich_escape(cmd_display)}[/]\n"
                            f"[dim]   ↩ Answer this question directly in the pane — resolves automatically.[/]"
                        )
                    else:
                        # M7 anti-fatigue (INV-13): when the FIFO head group aggregates
                        # >1 identical (decision_layer, canonical_pattern) rows, surface a
                        # batch line with one-key /approve-batch | /reject-batch actions.
                        # The banner shows the ACTUAL raw command list of the head batch
                        # (get_pending_command_escalations() — QUESTION rows excluded,
                        # INV-QN-1/2) rather than a quoted canonical-pattern abbreviation,
                        # so the operator consents to the real commands being approved.
                        # Bounded: only the first MAX_RAW_LIST raw commands render, then a
                        # visible "[+N more]" indicator (never an unbounded dump).
                        batch_note = ""
                        try:
                            batch_cfg = get_batch_approval_config()
                            if batch_cfg.get("batch_approval_enabled", True):
                                groups = group_pending_escalations(get_pending_command_escalations())
                                head = groups[0] if groups else None
                                if head and head["count"] > 1 and head["items"][0]["id"] == active_id:
                                    MAX_RAW_LIST = 3
                                    raw_list_lines = []
                                    for it in head["items"][:MAX_RAW_LIST]:
                                        one_line = str(it["raw_command"]).replace("\n", " ").strip()
                                        if not one_line:
                                            one_line = "(empty)"
                                        raw_list_lines.append(
                                            f"    · [white]{rich_escape(one_line[:100])}[/]"
                                            f" [dim]({it['pane_id']})[/]"
                                        )
                                    extra = head["count"] - len(raw_list_lines)
                                    if extra > 0:
                                        raw_list_lines.append(f"    [dim]… [+{extra} more][/]")
                                    batch_note = (
                                        f"[bold magenta]⚠ {head['count']} similar commands — raw:[/]\n"
                                        + "\n".join(raw_list_lines) + "\n"
                                        f"[dim]   (layer: {head['decision_layer']})[/]\n"
                                        f"[dim]   [/][bold magenta]/approve-batch[/] [dim]or[/] [bold magenta]/reject-batch[/] [dim]for one-key resolution[/]\n"
                                    )
                        except Exception:
                            batch_note = ""
                        banner_text = (
                            f"[bold red blink]🚨 ▶ ACTION REQUIRED: Escalation #{active_id} Awaiting Commander Decision[/]\n"
                            f"[bold white]Cmd:[/] {rich_escape(alarm_cmd)}\n"
                            f"{batch_note}"
                            f"[bold yellow]Reason:[/] {rich_escape(reason_short)}\n"
                            f"[dim]   [✔ Approve] /approve {active_id} · [✖ Reject] /reject {active_id} <reason> · [🔒 Always Allow] /allow-last[/]"
                        )
                    _update_static_if_changed(banner, banner_text)
                    # Radar side state card (live, while human intervention is due)
                    _update_static_if_changed(
                        action_card,
                        f"[bold red]🚨 Action Required[/]\n"
                        f"[dim]Blocked Pane :[/] [bold white]{active_esc['pane_id']}[/] [dim]({active_esc.get('agent_kind','agent')})[/]\n"
                        f"[dim]Awaiting     :[/] [bold yellow]👤 HUMAN INTERVENTION REQUIRED[/]",
                    )
                    action_card.display = True
                    self._set_action_state_ui(active_esc)

                    # Phase-2b decision card: written exactly once, only after
                    # the judge finished and the escalation is still PENDING
                    # (INV-HR-2) — never while it is being investigated.
                    if (not is_question
                            and active_id in self._notified_escalation_ids
                            and active_id not in self._decision_card_written):
                        self._decision_card_written.add(active_id)
                        try:
                            chat_log = self.query_one("#chat-log", FocusableRichLog)
                            cw = chat_log.content_region.width
                        except Exception:
                            cw = 0
                        card_width = max(52, min(78, (cw - 2) if cw else 74))
                        self._write(format_decision_card(active_esc, width=card_width))
                        self._write("\n")

        else:
            action_card.display = False
            self._set_action_state_ui(None)
            _update_static_if_changed(
                banner,
                "\n[dim]⚡ Autonomous inspection in progress...[/]\n"
                "[bold green]✔ No active escalations  —  Queue clear[/]\n"
                "[dim]🛡️  Autonomous border control active across all Herdr workspaces[/]\n"
                "[dim]   Listening for Gray-Zone mutations and critical AST denylists[/]",
            )
            if self._last_active_id is not None:
                # Post-adjudication badge from existing stored fields (resolution
                # + approver of the last FIFO head), when still resolvable.
                badge_str = ""
                try:
                    if self._last_resolved_ref:
                        _pane, _cmd = self._last_resolved_ref
                        _res = get_escalation_resolution(_pane, _cmd)
                        _appr = get_escalation_approver(_pane, _cmd)
                        badge_str = f" {format_resolved_badge(_res, _appr)}"
                except Exception:
                    badge_str = ""
                self._last_escalation_link = (self._last_active_id, "escalation")
                self._write(
                    f"\n[dim]{'─'*20} ✔ Escalation [#{self._last_active_id}] resolved"
                    f"{badge_str}  [cyan][▼ Details][/] {'─'*20}[/]\n"
                )
                self._last_active_id = None
                self._last_resolved_ref = None


        radar_col = self.query_one("#radar-column")
        radar_width = radar_col.size.width if radar_col.size.width > 0 else 36
        cmd_allowed_len = max(6, radar_width - 24)

        # 4. Update Audit Table (live newest-page head; older rows page in on
        #    scroll-to-bottom via AuditDataTable/AuditPageMixin). The hash covers
        #    only the head page so appended history survives unchanged ticks and
        #    re-baselines (clear + newest page) only when new audits arrive.
        audit_table = self.query_one("#audit-table", AuditDataTable)
        recent_audits = get_recent_audit_logs(limit=AUDIT_SIDEBAR_HEAD)
        current_audit_hash = str([(a["id"], a["decision"], a.get("resolution")) for a in recent_audits])

        if current_audit_hash != self._last_audit_hash:
            self._last_audit_hash = current_audit_hash
            audit_table.refresh_head(recent_audits, cmd_max_cells=cmd_allowed_len)

        # 5. Update Recent Escalations List (FIFO head first, then deferred)
        esc_list = self.query_one("#escalation-list", ListView)
        all_escalations = get_pending_escalations(include_delivered=True)
        # Strict sequential single-pending FIFO: show the pipeline from the head
        # (active slot) forward so Deferred (Slot #N) badges read in order.
        recent_escalations = all_escalations[:5] if all_escalations else []
        active_id = active_esc["id"] if active_esc else None
        fifo_slots = {e["id"]: i + 1 for i, e in enumerate(all_escalations)}
        current_esc_hash = str(
            [(e["id"], e["status"], e.get("decision_layer")) for e in recent_escalations] + [active_id]
        )

        if current_esc_hash != self._last_escalation_hash:
            self._last_escalation_hash = current_esc_hash
            esc_list.clear()
            for esc in recent_escalations:
                cmd_short = esc['raw_command'].replace("\n", " ").strip()
                if len(cmd_short) > 24:
                    cmd_short = cmd_short[:24] + "…"
                badge = format_pending_queue_badge(
                    esc,
                    active_id=active_id,
                    slot=fifo_slots.get(esc["id"]),
                    judging=(esc["id"] == self._judging_escalation_id),
                )
                item_label = Text()
                item_label.append(f"[#{esc['id']}]", style="bold cyan")
                item_label.append(" ")
                item_label.append_text(Text.from_markup(badge))
                item_label.append(" ")
                item_label.append(cmd_short, style="bold white")
                item_label.append("  ")
                item_label.append("[▼ Details]", style="dim italic")
                item = ListItem(Label(item_label))
                item.esc_id = esc["id"]  # deep-link target for selection/Enter
                esc_list.append(item)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "audit-table":
            self.push_screen(AuditFullscreenModal())

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        if event.data_table.id == "audit-table":
            self.push_screen(AuditFullscreenModal())

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Deep-link: Enter/click on a queue item opens its audit detail modal."""
        item = getattr(event, "item", None)
        esc_id = getattr(item, "esc_id", None)
        if esc_id is None:
            return
        try:
            event.stop()
        except Exception:
            pass
        if len(self.screen_stack) > 1:
            return
        resolved = resolve_audit_id_for_escalation(int(esc_id))
        self.push_screen(AuditDetailModal(resolved if resolved is not None else int(esc_id)))

    def on_resize(self, event: events.Resize) -> None:
        self.update_radar_data(force=True)

    @work(exclusive=False)
    async def _interpret_question(self) -> None:
        """Read-only interpretation of the pending question (NO adjudication tools).

        Invokes the gatekeeper LLM with allow_adjudication=False so it can surface
        and interpret the question in the chat, but can never approve/reject it.
        """
        if self._processing_chat:
            return
        self._processing_chat = True
        try:
            def on_tool(chunk: str):
                self._write_markdown(chunk)

            resp = await self.agent.send_message(
                "Interpret this pending question and suggest how the user should answer it.",
                on_chunk=on_tool,
                allow_adjudication=False,
            )
            self._write(f"{self._timestamp()} 🤖 [bold cyan]Gatekeeper (interpretation)[/]:")
            self._write_markdown(resp)
            self._write(f"[dim]{'─'*70}[/]")
        except Exception as exc:
            self._write(f"[bold red]❌ [Interpretation Error]:[/] {exc}")
        finally:
            self._processing_chat = False

    @work(exclusive=False)
    async def process_user_chat(self, user_msg: str, author: str = "user") -> None:
        # INV-HR-1 exit guarantee: the judge round-trip (author="inspector")
        # MUST clear _judging_escalation_id on EVERY exit path — including the
        # early returns inside _process_user_chat_impl (feature-request,
        # /interrupt, /config, the _processing_chat guard, the observer guard).
        # In a sub-tick race a judge worker can hit the _processing_chat guard
        # and return before the LLM try/finally; without this unconditional
        # clear the escalation would stay stuck in "Gatekeeper Checking" with
        # the red card suppressed forever.
        try:
            await self._process_user_chat_impl(user_msg, author)
        finally:
            if author == "inspector":
                self._judging_escalation_id = None

    async def _process_user_chat_impl(self, user_msg: str, author: str) -> None:
        trimmed = user_msg.strip()
        # INV-HR-3: label the message author — real user input renders
        # "👤 You:", while the inspector's judge invocation renders a system
        # label so it is not mistaken for a human-typed message.
        _author_label = (
            "[bold yellow]👤 You:"
            if author == "user"
            else "[bold cyan]🤖 Inspector → Gatekeeper:"
        )

        # 1. Non-blocking Feature Request Command Handling (Queues immediately even if an agent task is in-flight)
        if (trimmed.startswith("/feature-request") or trimmed.startswith("/feature") or 
            trimmed.startswith("/idea") or trimmed.startswith("/features") or trimmed.startswith("/feature-list")):
            safe_user_msg = rich_escape(user_msg)
            self._write(f"\n{_author_label}[/] {safe_user_msg}")

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

        # 2b. Settings modal entry (works even while an investigation is in-flight)
        if trimmed in ("/config", "/settings"):
            self._write("[dim]⚙ Opening settings… (ESC/q closes · changes apply immediately)[/]")
            self.action_open_settings()
            return

        if self._processing_chat:
            self._write("[dim]⏳ Another investigation/chat is currently in-flight. Press ESC twice or type [bold yellow]/interrupt[/] to abort.[/]")
            return

        if not self.is_controller and (user_msg.startswith("/approve") or user_msg.startswith("/reject") or user_msg.startswith("/start") or user_msg.startswith("/stop") or user_msg.startswith("/allow") or user_msg.startswith("/revoke") or user_msg.startswith("/jump")):
            self._write(f"[bold yellow]⚠️ [Observer Mode]:[/] Read-only instance. Leader PID {self.leader_pid} controls execution.")
            return

        self._processing_chat = True
        try:
            safe_user_msg = rich_escape(user_msg)
            self._write(f"\n{self._timestamp()} {_author_label}[/] {safe_user_msg}")

            if user_msg.strip() in ("/start", "/stop", "/toggle"):
                msg = self.toggle_guard_daemon()
                self._write(f"[bold yellow]⚙️ [Daemon Control]:[/] {msg}")
                self.update_radar_data(force=True)
                return

            if user_msg.startswith("/approve "):
                parts = user_msg.split(maxsplit=2)
                esc_id = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                reason = parts[2] if len(parts) > 2 else "Approved via TUI"
                # Provenance split (INV-HO-1): persist the human's raw opinion
                # BEFORE the gatekeeper LLM call so it survives an LLM outage.
                # Non-fatal — an opinion write failure must not block the flow.
                try:
                    if esc_id:
                        record_human_opinion(esc_id, reason)
                except Exception:
                    pass
                resp = await self.agent.send_message(f"Approve escalation #{esc_id} with English note: '{reason}'")
                self._write(f"{self._timestamp()} 🤖 [bold cyan]Gatekeeper[/]:")
                self._write_markdown(resp)
                self.update_radar_data(force=True)
                return

            if user_msg.startswith("/reject "):
                parts = user_msg.split(maxsplit=2)
                esc_id = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                reason = parts[2] if len(parts) > 2 else "Rejected via TUI"
                # Provenance split (INV-HO-1): persist the human's raw opinion
                # BEFORE the gatekeeper LLM call so it survives an LLM outage.
                # Non-fatal — an opinion write failure must not block the flow.
                try:
                    if esc_id:
                        record_human_opinion(esc_id, reason)
                except Exception:
                    pass
                resp = await self.agent.send_message(f"Reject escalation #{esc_id} with English reason: '{reason}'")
                self._write(f"{self._timestamp()} 🤖 [bold cyan]Gatekeeper[/]:")
                self._write_markdown(resp)
                self.update_radar_data(force=True)
                return

            # M7 anti-fatigue (INV-13): one-key batch resolution. Deterministic
            # loop DIRECTLY on the FIFO head batch — NOT via the gatekeeper LLM.
            if user_msg.startswith("/approve-batch") or user_msg.startswith("/reject-batch"):
                batch_cfg = get_batch_approval_config()
                if not batch_cfg.get("batch_approval_enabled", True):
                    self._write("[dim]⏸ [Batch approval disabled] — /approve-batch and /reject-batch are no-ops. Use /approve <id> or /reject <id>.[/]")
                    return
                parts = user_msg.split(maxsplit=1)
                reason = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
                if user_msg.startswith("/approve-batch"):
                    result = await asyncio.to_thread(approve_batch_escalations, reason or "Approved in batch via TUI")
                else:
                    result = await asyncio.to_thread(reject_batch_escalations, reason or "Rejected in batch via TUI")
                self._write(f"{self._timestamp()} 🤖 [bold cyan]Batch Gatekeeper[/]:")
                self._write_markdown(f"```json\n{json.dumps(result, ensure_ascii=False, indent=2)}\n```")
                self.update_radar_data(force=True)
                return

            # Question 분리 (INV-QN-2): focus an arbitrary agent pane — e.g. the
            # pane showing a pending question (answered in-pane, never
            # adjudicated). Non-adjudicating navigation (AGENTS.md rule 10).
            if user_msg.startswith("/jump"):
                parts = user_msg.split(maxsplit=1)
                pane_id = parts[1].strip() if len(parts) > 1 else ""
                if not pane_id:
                    self._write("[bold yellow]⚠️ Usage: /jump <pane_id>[/]")
                    return
                run_cmd(["herdr", "pane", "focus", pane_id])
                self._write(f"[bold cyan]↩ Focusing agent pane {pane_id}...[/]")
                self.update_radar_data(force=True)
                return

            # #91 Persistent Allowlist CUD — human-typed input channel
            # (INV-PL-1): explicit human provenance (created_by/revoked_by
            # = "human-tui"), TUI-controller only (observer guard above blocks
            # read-only instances). Audited GLOBAL_RULE rows (INV-PL-3).
            if user_msg.startswith("/allow "):
                parts = user_msg.split(maxsplit=1)
                rest = parts[1].strip() if len(parts) > 1 else ""
                pat, _, desc = rest.partition(" ")
                if not pat:
                    self._write("[bold yellow]⚠️ Usage: /allow <pattern> [description][/]")
                    return
                try:
                    add_to_allowlist(pat, description=desc.strip(), created_by="human-tui")
                except ValueError as e:
                    self._write(f"[bold red]❌ {e}[/]")
                    return
                self._write(f"[bold green]✅ Allowlist rule added:[/] [white]{rich_escape(pat)}[/]")
                self.update_radar_data(force=True)
                return

            if user_msg.startswith("/allow-last"):
                parts = user_msg.split(maxsplit=1)
                desc = parts[1].strip() if len(parts) > 1 else ""
                last_cmd = getattr(self, "_last_intercepted_cmd", "") or ""
                if not last_cmd:
                    self._write("[bold yellow]⚠️ No intercepted command to allow (queue empty).[/]")
                    return
                # re.escape -> EXACT literal match, NOT regex-interpreted (#91).
                escaped = re.escape(last_cmd)
                try:
                    add_to_allowlist(
                        escaped,
                        description=desc or f"allow-last: {last_cmd[:60]}",
                        created_by="human-tui",
                    )
                except ValueError as e:
                    self._write(f"[bold red]❌ {e}[/]")
                    return
                self._write(f"[bold green]✅ Allowlist rule added (exact literal):[/] [white]{rich_escape(escaped)}[/]")
                self.update_radar_data(force=True)
                return

            if user_msg.startswith("/revoke "):
                parts = user_msg.split(maxsplit=1)
                target = parts[1].strip() if len(parts) > 1 else ""
                if not target:
                    self._write("[bold yellow]⚠️ Usage: /revoke <id|pattern>[/]")
                    return
                affected = 0
                if target.isdigit():
                    affected = revoke_allowlist_rule(int(target), revoked_by="human-tui")
                else:
                    # Resolve a pattern to its active rule id (or accept numeric id).
                    for r in list_allowlist_rules():
                        if r["pattern_regex"] == target:
                            affected = revoke_allowlist_rule(r["id"], revoked_by="human-tui")
                            break
                if affected:
                    self._write(f"[bold green]✅ Allowlist rule revoked:[/] [white]{rich_escape(target)}[/]")
                else:
                    self._write(f"[bold yellow]⚠️ No active allowlist rule matched:[/] [white]{rich_escape(target)}[/]")
                self.update_radar_data(force=True)
                return

            if user_msg.strip() == "/allow-list":
                rules = list_allowlist_rules()
                if not rules:
                    self._write("[dim]Allowlist is empty.[/]")
                    return
                lines = [f"[bold]Allowlist ({len(rules)} active rules):[/]"]
                for r in rules:
                    lines.append(
                        f"  [dim]#{r['id']}[/] ✅ [white]{rich_escape(r['pattern_regex'])}[/] "
                        f"[dim](by {r['created_by'] or '?'} @ {r['created_at'] or '?'})[/]"
                    )
                self._write("\n".join(lines))
                return

            def on_tool(chunk: str):
                self._write_markdown(chunk)

            resp = await self.agent.send_message(user_msg, on_chunk=on_tool)
            self._write(f"{self._timestamp()} 🤖 [bold cyan]Gatekeeper[/]:")
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
            # INV-HR-1: the judge round-trip for this escalation is complete;
            # the next radar tick may now render the Phase-2b red card if the
            # escalation is still PENDING (fail-safe on error paths too).
            self._judging_escalation_id = None

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
        chat_log = self.query_one(RichLog)
        if isinstance(msg, str):
            chat_log.write(
                _linkify_chat_markup(
                    msg, default_target=getattr(self, "_last_escalation_link", None)
                )
            )
        else:
            chat_log.write(msg)
        if isinstance(msg, Markdown):
            raw_text = getattr(msg, "markup", str(msg)).strip()
            if raw_text:
                self._chat_plain.append(raw_text)
        else:
            plain = _chat_plain_text(str(msg)).strip()
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
