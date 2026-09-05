#!/usr/bin/env python3
"""Autonomous Inspector & Security Gatekeeper Agent Loop for Schengen Guardian.

Core Capabilities:
1. Dual-Model Phase Routing:
   - Inspector Phase (tool-calling investigation): uses SCHENGEN_INSPECTOR_API_KEY + SCHENGEN_INSPECTOR_BASE_URL
   - Judge Phase (final text adjudication): uses SCHENGEN_JUDGE_API_KEY + SCHENGEN_JUDGE_BASE_URL
   - Both fall back to shared OPENAI_API_KEY / OPENAI_BASE_URL if phase-specific vars are not set.
   - Architecture note: OpenCode/AGY is the supervised *worker* — not the judge.
     Judge = the final no-tool-call text turn in the LLM chat loop, fully independent of OpenCode.
2. AGY Tab Amend Protocol: Tab → security note → Enter for AGY approvals.
3. Strict Single-Task FIFO: one pending escalation resolved at a time.
"""

import asyncio
import json
import os
import random
import re
import stat
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import httpx
    _HTTP_EXCEPTIONS = (httpx.HTTPError, httpx.TimeoutException)
except ImportError:
    httpx = None  # type: ignore
    _HTTP_EXCEPTIONS = (Exception,)

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parent
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from core.gray_zone_evaluator import (
    canonicalize_path,
    classify_operation,
    classify_resource_tier,
    evaluate_gray_zone_operation,
    is_inside_git_work_tree,
    is_git_clean_and_committed,
)
from core.feature_db import (
    add_feature_request,
    create_feature_request_with_similars,
    search_similar_feature_requests,
)
from core.guard_db import (
    enqueue_pending_escalation,
    get_answer_language,
    get_db_connection,
    get_instruction_delivery_config,
    get_pending_command_escalations,
    get_pending_escalations,
    get_recent_audit_logs,
    group_pending_escalations,
    has_human_opinion,
    init_db,
    record_adjudication,
    record_audit_log,
    resolve_escalation,
)
from adapters.herdr_client import get_pane_text
from adapters.agent_adapters import INJECT_SKIP_CHANGED, get_adapter
from adapters.agent_adapters.base import INJECT_REJECT_NOT_IMPLEMENTED
from adapters.auto_advance import run_auto_advance
from core.cloud_judge import DEFAULT_REASONING_EFFORT
from core.redaction import redact_for_cloud

# ── Shared fallback config ──────────────────────────────────────────
# POLICY (ADR-011): OpenAI-standard env vars only. DeepSeek defaults are removed.
# To keep using DeepSeek at home, set OPENAI_BASE_URL=https://api.deepseek.com/v1
# (and OPENAI_API_KEY=<deepseek key>). See ADR-011.
_SHARED_KEY  = os.environ.get("OPENAI_API_KEY", "")
_SHARED_URL  = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")


def resolve_subagent_model(default: str = "gpt-5.6-luna") -> str:
    """Resolve model for subagents/fast inspector from OpenCode config or ENV."""
    env_model = os.environ.get("OPENCODE_SUBAGENT_MODEL") or os.environ.get("OPENCODE_MODEL")
    if env_model:
        return env_model.split("/")[-1]
    
    config_path = Path.home() / ".config" / "opencode" / "opencode.jsonc"
    if config_path.exists():
        try:
            raw = config_path.read_text(encoding="utf-8")
            clean_json = re.sub(r"//.*", "", raw)
            data = json.loads(clean_json)
            agent_schengen = data.get("agent", {}).get("schengen", {}).get("model")
            if agent_schengen:
                return str(agent_schengen).split("/")[-1]
            small_model = data.get("small_model")
            if small_model:
                return str(small_model).split("/")[-1]
        except Exception:
            pass
    return default


# ── Phase-specific overrides ────────────────────────────────────────
# Inspector (investigation tool-calling phase)
INSPECTOR_API_KEY  = os.environ.get("SCHENGEN_INSPECTOR_API_KEY")  or _SHARED_KEY
INSPECTOR_BASE_URL = os.environ.get("SCHENGEN_INSPECTOR_BASE_URL") or _SHARED_URL
INSPECTOR_MODEL    = os.environ.get("SCHENGEN_INSPECTOR_MODEL")    or resolve_subagent_model("gpt-5.6-luna")

# Judge (final adjudication text phase)
JUDGE_API_KEY  = os.environ.get("SCHENGEN_JUDGE_API_KEY")  or _SHARED_KEY
JUDGE_BASE_URL = os.environ.get("SCHENGEN_JUDGE_BASE_URL") or _SHARED_URL
JUDGE_MODEL    = os.environ.get("SCHENGEN_JUDGE_MODEL")    or resolve_subagent_model("gpt-5.6-luna")

SESSIONS_DIR = Path.home() / ".local" / "state" / "herdr-schengen" / "sessions"
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


GUARD_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "investigate_pane_history",
            "description": "Inspect terminal text or full script dump of the target worker pane (especially for AGY multi-line scripts) to verify developer intent before adjudication.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pane_id": {
                        "type": "string",
                        "description": "Target pane ID (e.g. 'w1D:p1').",
                    },
                    "lines": {
                        "type": "integer",
                        "description": "Number of recent lines to read (default: 100).",
                        "default": 100,
                    },
                    "full_dump": {
                        "type": "boolean",
                        "description": "If true, read complete scrollback script buffer (ctrl+g dump) for AGY panes.",
                        "default": False,
                    },
                },
                "required": ["pane_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_path_details",
            "description": "Inspect target filesystem state (existence, directory/file type, size, Git status, sibling backup files).",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "Filesystem path to inspect.",
                    },
                },
                "required": ["target_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file_snippet",
            "description": "Safely read up to 8KB of a file or script to inspect its payload before approval.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "Path of the file to inspect.",
                    },
                },
                "required": ["target_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "approve_escalation",
            "description": "Approve the escalation and send approval keystrokes (Tab Amend + Enter for AGY) along with an English Security Gatekeeper note.",
            "parameters": {
                "type": "object",
                "properties": {
                    "escalation_id": {
                        "type": "integer",
                        "description": "Escalation ID to approve.",
                    },
                    "english_feedback": {
                        "type": "string",
                        "description": "Concise, professional English security note for the worker agent (e.g. 'Approved. Target does not exist (0B). Avoid habituated -rf flags.').",
                    },
                    "directive": {
                        "type": "boolean",
                        "description": "true when executing an explicit human directive (/approve, /reject, or free-text). Records approver='human-tui'. false/omitted for autonomous obvious-safe approve or autonomous critical reject (approver='gatekeeper').",
                        "default": False,
                    },
                },
                "required": ["escalation_id", "english_feedback"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "reject_escalation",
            "description": "Reject the escalation and send 'escape' key to target pane along with an English rejection reason.",
            "parameters": {
                "type": "object",
                "properties": {
                    "escalation_id": {
                        "type": "integer",
                        "description": "Escalation ID to reject.",
                    },
                    "english_feedback": {
                        "type": "string",
                        "description": "Concise, professional English guidance explaining why the command was rejected and suggesting alternatives.",
                    },
                    "directive": {
                        "type": "boolean",
                        "description": "true when executing an explicit human directive (/approve, /reject, or free-text). Records approver='human-tui'. false/omitted for autonomous obvious-safe approve or autonomous critical reject (approver='gatekeeper').",
                        "default": False,
                    },
                },
                "required": ["escalation_id", "english_feedback"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_feature_request",
            "description": "Record a user feature request, enhancement proposal, or self-improvement task into the independent SQLite backlog queue.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Concise title of the requested feature or improvement.",
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed explanation, rationale, user context, or acceptance criteria.",
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["LOW", "NORMAL", "HIGH", "CRITICAL"],
                        "description": "Priority level of the feature request (default: NORMAL).",
                    },
                    "category": {
                        "type": "string",
                        "description": "Category tag (e.g. UI, SECURITY, LLM, WORKFLOW).",
                    },
                },
                "required": ["title"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_feature_requests",
            "description": "Search existing feature requests using FTS5 CJK trigram similarity search to check for duplicates or related improvement ideas.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query or keywords.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results to return (default: 5).",
                    },
                },
                "required": ["query"],
            },
        },
    },
]


def _sanitize_feedback(text: str) -> str:
    """Sanitize feedback to prevent shell command injection via newlines or terminal control characters."""
    if not text:
        return "Approved by security gatekeeper."
    # Strip non-printable/control chars (ASCII 0-31, except normal spaces) and replace newlines with space
    cleaned = re.sub(r"[\r\n\x00-\x1f\x7f]", " ", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:256]


def get_current_active_escalation() -> Optional[Dict[str, Any]]:
    """Return the oldest (FIFO) active pending escalation so tasks are processed in strict sequence.

    DEPRECATED for the Command Approval slot: this INCLUDES QUESTION rows. The
    command slot (banner, approve/reject head checks, batch head, system prompt,
    send_message) must use get_current_command_escalation() instead (INV-QN-1) —
    a question is surfaced via get_oldest_question_escalation() + the sidebar
    hint. Kept for backward compatibility only.
    """
    pending = get_pending_escalations(include_delivered=False)
    return pending[0] if pending else None


def get_current_command_escalation() -> Optional[Dict[str, Any]]:
    """Return the oldest (FIFO) active COMMAND escalation (QUESTION excluded).

    A PENDING QUESTION must not occupy the Command Approval slot (strict
    FIFO, INV-QN-1/2) — it stays PENDING for the sidebar hint + auto-dissolve
    (#2800) while the command head proceeds.
    """
    pending = get_pending_command_escalations(include_delivered=False)
    return pending[0] if pending else None


def get_oldest_question_escalation() -> Optional[Dict[str, Any]]:
    """Return the oldest PENDING QUESTION escalation (sidebar hint, INV-QN-3)."""
    pending = get_pending_escalations(include_delivered=False)
    return next((r for r in pending if r.get("decision_layer") == "QUESTION"), None)


def _get_escalation_row(esc_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_escalations WHERE id = ?", (esc_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _inject_approval(
    target_pane: str,
    agent_kind: str,
    req_cmd: str,
    feedback: str,
    send_instruction: bool,
) -> Tuple[bool, str]:
    """Inject an approval into the target pane via the verified-inject path.

    Mirrors the approve_escalation tool's inject-first semantics (issue #23/#1910):
    channel approve (opencode permission.reply) -> keystroke inject (codex 'y',
    opencode enter+self-correction), with the AGY Tab Amend Flow when
    instructions are enabled. The caller must ONLY record/adjudicate AFTER this
    returns injected=True, so 'APPROVED' in the DB actually implies the dialog
    got approved. Returns (injected, inject_reason).
    """
    injected = False
    inject_reason = ""
    if not target_pane:
        return False, "no target pane"
    if agent_kind == "agy" and send_instruction and feedback:
        # AGY Tab Amend Flow: Tab -> send feedback note -> Enter
        subprocess.run(["herdr", "agent", "send-keys", target_pane, "tab"], capture_output=True, timeout=5.0)
        subprocess.run(["herdr", "pane", "send-text", target_pane, f"# [SECURITY GATEKEEPER]: {feedback}"], capture_output=True, timeout=5.0)
        subprocess.run(["herdr", "agent", "send-keys", target_pane, "enter"], capture_output=True, timeout=5.0)
        injected = True  # best-effort (unchanged AGY sequence)
    else:
        # Agent-kind-specific approval (issue #23): use the adapter's channel
        # approve (opencode permission.reply) then its keystroke inject_approval
        # (codex 'y', opencode enter+self-correction), NOT a bare enter.
        adapter = get_adapter(agent_kind)
        if adapter is not None:
            ch_approved, ch_reason = adapter.channel_approve(target_pane, req_cmd)
            if ch_approved:
                injected = True
            else:
                ok, inject_reason = adapter.inject_approval(target_pane, req_cmd)
                injected = ok
        else:
            # no registered adapter: best-effort bare enter (unchanged legacy path)
            subprocess.run(["herdr", "agent", "send-keys", target_pane, "enter"], capture_output=True, timeout=5.0)
            injected = True
    return injected, inject_reason


def _inject_rejection(
    target_pane: str,
    agent_kind: str,
    req_cmd: str,
    feedback: str,
    send_instruction: bool,
    send_after_adapter: bool = True,
) -> Tuple[bool, str]:
    """Dismiss the verified live request before recording a rejection."""
    if not target_pane:
        return False, "no target pane"
    adapter = get_adapter(agent_kind)
    handled = False
    if adapter is not None:
        handled, reason = adapter.inject_reject(target_pane, req_cmd)
        if not handled and reason != INJECT_REJECT_NOT_IMPLEMENTED:
            return False, reason
    if not handled:
        subprocess.run(
            ["herdr", "agent", "send-keys", target_pane, "escape"],
            capture_output=True,
            timeout=5.0,
        )
    if send_instruction and feedback and (send_after_adapter or not handled):
        subprocess.run(
            ["herdr", "pane", "send-text", target_pane, f"# [SECURITY GATEKEEPER]: {feedback}"],
            capture_output=True,
            timeout=5.0,
        )
        subprocess.run(
            ["herdr", "agent", "send-keys", target_pane, "enter"],
            capture_output=True,
            timeout=5.0,
        )
    return True, "rejection delivered"


def approve_batch_escalations(feedback: str = "Approved in batch via TUI") -> Dict[str, Any]:
    """One-key approve (M7 INV-13/INV-25..28): resolve the FIFO head batch.

    The head batch is the FIRST (decision_layer, canonical_pattern) group of
    currently-PENDING escalations (FIFO id ASC). Each item is approved via the
    SAME verified-inject path as approve_escalation (inject-first, record-only-
    on-verified-inject); on inject failure the item stays PENDING (per-item, not
    all-or-nothing). Every resolved row gets approver='human-tui' provenance and
    its own adjudication_log entry. Later groups stay PENDING (FIFO head-only).
    Returns {"status": "empty"|"ok", "resolved": [...], "deferred": [...]}.
    """
    # Question 분리 (INV-QN-1/2/4): the batch head EXCLUDES questions — they are
    # never injected/resolved/adjudicated by the batch path (AGENTS.md rule 10).
    pending = get_pending_command_escalations()
    groups = group_pending_escalations(pending)
    if not groups:
        return {"status": "empty", "resolved": 0}
    head = groups[0]
    resolved, deferred = [], []
    cfg = get_instruction_delivery_config()
    send_instruction = bool(cfg.get("send_approve_instruction", False))
    safe_feedback = _sanitize_feedback(feedback)
    for item in head["items"]:
        esc_id = item["id"]
        pane = item["pane_id"]
        kind = item["agent_kind"]
        req = item["raw_command"]
        injected, inject_reason = _inject_approval(pane, kind, req, safe_feedback, send_instruction)
        if not injected:
            if inject_reason == INJECT_SKIP_CHANGED:
                # Sprint 1c Auto-Advance (P0): the dialog trampolined to a NEW
                # request B while we were evaluating A. Same contract as
                # approve_escalation: reconcile A SUPERSEDED (never APPROVED,
                # INV-AA-7), auto-advance B through the FULL evaluator, or
                # enqueue B fresh (do NOT stall).
                aa = run_auto_advance(
                    pane, kind, req,
                    cwd=item.get("cwd") or "", scope=pane, agent_id=kind,
                    use_llm_judge=False, reasoning_effort=DEFAULT_REASONING_EFFORT,
                )
                if aa.outcome != "not_trampolined" and aa.new_req_cmd:
                    resolve_escalation(
                        pane_id="", escalation_id=esc_id, resolution_status="CANCELLED",
                        approver="other", resolution="SUPERSEDED",
                    )
                if aa.outcome == "advanced_safe":
                    # B was already injected by run_auto_advance (verified-inject).
                    # B has NO escalation row, so there is nothing to resolve here;
                    # record_audit_log below (mechanism="auto-advance") is the sole
                    # provenance capture. Do NOT resolve_escalation(pane_id=...) —
                    # it would over-broadly machine-resolve unrelated stale
                    # escalations for this pane — and do NOT record_adjudication(0, ...)
                    # (a dangling escalation_id=0 reference).
                    try:
                        record_audit_log(
                            pane_id=pane, raw_command=aa.new_req_cmd,
                            decision="AUTO_APPROVED", safety_reason=aa.reason or "",
                            agent_kind=kind,
                            decision_layer=aa.layer.value if aa.layer else "FAST_TRACK_AST",
                            origin="A",
                            consequence=(aa.taxonomy or {}).get("consequence", "NONE"),
                            mechanism="auto-advance",
                            gate_state=(aa.taxonomy or {}).get("gate_state", "ENFORCE"),
                            shadow_mode=(aa.taxonomy or {}).get("shadow_mode", False),
                        )
                    except Exception:
                        pass
                    resolved.append(esc_id)
                    continue
                if aa.outcome in ("advanced_unsafe", "parse_failed", "budget_exhausted") and aa.new_req_cmd:
                    enqueue_pending_escalation(
                        pane_id=pane,
                        raw_command=aa.new_req_cmd,
                        safety_reason=aa.reason or f"auto-advance blocked ({aa.outcome})",
                        decision_layer=aa.layer.value if aa.layer else "NOT_ALLOWLISTED",
                        agent_kind=kind,
                        cwd=item.get("cwd") or "",
                        origin="A",
                    )
                    # A was SUPERSEDED (never approved); B is enqueued fresh for
                    # human review — count A's slot as deferred (not approved).
                    deferred.append(esc_id)
                    continue
                # not_trampolined / no new command -> A stays PENDING (defer).
                deferred.append(esc_id)
                continue
            deferred.append(esc_id)
            continue
        resolve_escalation(
            pane_id=pane,
            escalation_id=esc_id,
            resolution_status="RESOLVED",
            is_approval=True,
            approver="human-tui",
        )
        record_adjudication(esc_id, pane, kind, "APPROVE", safe_feedback, approver="human-tui", human_note=safe_feedback)
        resolved.append(esc_id)
    return {"status": "ok", "resolved": resolved, "deferred": deferred}


def reject_batch_escalations(feedback: str = "Rejected in batch via TUI") -> Dict[str, Any]:
    """One-key reject (M7): cancel the FIFO head batch deterministically.

    Mirrors reject_escalation per item: fire the agent-kind-specific reject
    protocol (M7 item 4 — opencode permission.reply 'reject' channel, codex/agy
    escape dismiss), resolve the row as CANCELLED, and record a REJECT
    adjudication — no gatekeeper LLM call. When the adapter is missing or has
    no inject_reject implementation, fall back to the legacy bare-escape
    dismiss (reject_escalation parity). A real reject failure defers the item
    (stays PENDING, fail-closed).
    Returns {"status": "empty"|"ok", "resolved": [...], "deferred": [...]}.
    """
    # Question 분리 (INV-QN-1/2/4): the batch head EXCLUDES questions — they are
    # never injected/resolved/adjudicated by the batch path (AGENTS.md rule 10).
    pending = get_pending_command_escalations()
    groups = group_pending_escalations(pending)
    if not groups:
        return {"status": "empty", "resolved": 0}
    head = groups[0]
    resolved, deferred = [], []
    cfg = get_instruction_delivery_config()
    send_instruction = bool(cfg.get("send_reject_instruction", True))
    safe_feedback = _sanitize_feedback(feedback)
    for item in head["items"]:
        esc_id = item["id"]
        pane = item["pane_id"]
        kind = item["agent_kind"]
        req = item.get("raw_command", "")
        try:
            injected, _inject_reason = _inject_rejection(
                pane, kind, req, safe_feedback, send_instruction,
                send_after_adapter=False,
            )
            if not injected:
                deferred.append(esc_id)
                continue
            resolve_escalation(
                pane_id=pane, escalation_id=esc_id, resolution_status="CANCELLED", approver="human-tui"
            )
            record_adjudication(esc_id, pane, kind, "REJECT", safe_feedback, approver="human-tui", human_note=safe_feedback)
            resolved.append(esc_id)
        except Exception:
            deferred.append(esc_id)
    return {"status": "ok", "resolved": resolved, "deferred": deferred}


def execute_tool_call(name: str, args: Dict[str, Any]) -> str:
    if name == "investigate_pane_history":
        pane_id = args.get("pane_id", "")
        lines = args.get("lines", 100)
        full_dump = bool(args.get("full_dump", False))
        try:
            raw = get_pane_text(pane_id, lines=lines, full_dump=full_dump)
            safe_text = redact_for_cloud(raw)
            return json.dumps({
                "pane_id": pane_id,
                "lines_read": lines,
                "full_dump": full_dump,
                "pane_text_snippet": safe_text[-12000:] if safe_text else "",
            }, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)})

    elif name == "investigate_path_details":
        target = args.get("target_path", "")
        try:
            p = canonicalize_path(target)
            exists = p.exists()
            is_dir = p.is_dir() if exists else False
            is_file = p.is_file() if exists else False
            size = p.stat().st_size if exists and is_file else 0

            tier = classify_resource_tier(str(p))
            in_git = is_inside_git_work_tree(p)
            clean_git = is_git_clean_and_committed(p) if in_git else False

            parent_exists = p.parent.exists()
            sibling_count = len(list(p.parent.iterdir())) if parent_exists and p.parent.is_dir() else 0

            return json.dumps({
                "target_path": str(p),
                "exists": exists,
                "is_dir": is_dir,
                "is_file": is_file,
                "size_bytes": size,
                "resource_tier": tier.value,
                "is_inside_git": in_git,
                "git_clean_and_committed": clean_git,
                "parent_exists": parent_exists,
                "sibling_count": sibling_count,
            }, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)})

    elif name == "read_file_snippet":
        target = args.get("target_path", "")
        try:
            p = canonicalize_path(target)
            if not p.exists() or not p.is_file():
                return json.dumps({"error": f"File '{p}' does not exist or is not a regular file."})
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(8192)
            safe_content = redact_for_cloud(content)
            return json.dumps({"path": str(p), "content": safe_content}, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)})

    elif name == "approve_escalation":
        raw_id = args.get("escalation_id")
        esc_id = int(raw_id) if raw_id is not None and str(raw_id).isdigit() else 0
        raw_feedback = args.get("english_feedback") or args.get("feedback") or "Approved by security gatekeeper."
        feedback = _sanitize_feedback(raw_feedback)
        try:
            # Enforce FIFO Head validation before keystroke injection. The
            # command-slot head EXCLUDES questions (INV-QN-1/2) so a pending
            # QUESTION can never block approve_escalation.
            active_head = get_current_command_escalation()
            if not active_head or active_head["id"] != esc_id:
                active_id = active_head["id"] if active_head else None
                return json.dumps({
                    "status": "error",
                    "error": f"Escalation #{esc_id} is not the current active FIFO head (active: #{active_id}).",
                })

            esc_row = _get_escalation_row(esc_id) if esc_id > 0 else None
            target_pane = esc_row.get("pane_id") if esc_row else ""
            agent_kind = esc_row.get("agent_kind", "agy") if esc_row else "agy"
            req_cmd = esc_row.get("raw_command", "") if esc_row else ""

            cfg = get_instruction_delivery_config()
            send_instruction = bool(cfg.get("send_approve_instruction", False))

            # FIX 1 (issue #23/#1910): the injection happens FIRST; resolve_escalation
            # + record_adjudication run ONLY after a verified injection success, so
            # 'APPROVED' in the DB actually implies the dialog got approved.
            injected, inject_reason = _inject_approval(target_pane, agent_kind, req_cmd, feedback, send_instruction)

            if not injected:
                # FIX 1/4 (issue #23/#1910): do NOT resolve/adjudicate on failure —
                # the escalation stays PENDING so a retry is possible and the FIFO
                # head check will not wrongly reject a second attempt. Distinguish a
                # hard delivery failure from a dialog-changed deferral so the
                # gatekeeper can act appropriately.
                if inject_reason == INJECT_SKIP_CHANGED:
                    # Sprint 1c Auto-Advance (P0, Refs #3689): the live dialog
                    # trampolined to a NEW request B while we were evaluating A.
                    # A's enter was never delivered — reconcile A SUPERSEDED
                    # (INV-AA-7, NEVER APPROVED), then re-parse + re-evaluate B
                    # through the FULL evaluator and inject it if safe (INV-AA-1/2).
                    # Prior-approval inheritance is FORBIDDEN: B gets a fresh
                    # verdict; B inherits A's cwd/scope/agent_id but re-derives
                    # origin (Origin.AGENT).
                    aa = run_auto_advance(
                        target_pane, agent_kind, req_cmd,
                        cwd=(esc_row or {}).get("cwd") or "", scope=target_pane, agent_id=agent_kind,
                        use_llm_judge=False, reasoning_effort=DEFAULT_REASONING_EFFORT,
                    )
                    if aa.outcome != "not_trampolined" and aa.new_req_cmd:
                        # A's enter was never delivered — reconcile as
                        # CANCELLED/SUPERSEDED (approver="other"), NEVER APPROVED.
                        resolve_escalation(
                            pane_id="", escalation_id=esc_id, resolution_status="CANCELLED",
                            approver="other", resolution="SUPERSEDED",
                        )
                    if aa.outcome == "advanced_safe":
                        # The run loop already injected B (verified-inject path).
                        # B has NO escalation row; record_audit_log below
                        # (mechanism="auto-advance") is the sole provenance capture.
                        # Do NOT resolve_escalation(pane_id=...) (over-broad) or
                        # record_adjudication(0, ...) (dangling escalation_id=0).
                        try:
                            record_audit_log(
                                pane_id=target_pane, raw_command=aa.new_req_cmd,
                                decision="AUTO_APPROVED", safety_reason=aa.reason or "",
                                agent_kind=agent_kind,
                                decision_layer=aa.layer.value if aa.layer else "FAST_TRACK_AST",
                                origin="A",
                                consequence=(aa.taxonomy or {}).get("consequence", "NONE"),
                                mechanism="auto-advance",
                                gate_state=(aa.taxonomy or {}).get("gate_state", "ENFORCE"),
                                shadow_mode=(aa.taxonomy or {}).get("shadow_mode", False),
                            )
                        except Exception:
                            pass
                        return json.dumps({
                            "status": "success",
                            "action": "AUTO_ADVANCED",
                            "escalation_id": esc_id,
                            "target_pane": target_pane,
                            "new_escalation": aa.new_req_cmd,
                            "reason": aa.reason,
                        }, ensure_ascii=False)
                    if aa.outcome in ("advanced_unsafe", "parse_failed", "budget_exhausted") and aa.new_req_cmd:
                        # INV-AA-5/3: B is unsafe or unverifiable (fail-closed) —
                        # enqueue B FRESH for human review (do NOT stall). A was
                        # reconciled SUPERSEDED above.
                        enqueue_pending_escalation(
                            pane_id=target_pane,
                            raw_command=aa.new_req_cmd,
                            safety_reason=aa.reason or f"auto-advance blocked ({aa.outcome})",
                            decision_layer=aa.layer.value if aa.layer else "NOT_ALLOWLISTED",
                            agent_kind=agent_kind,
                            cwd=(esc_row or {}).get("cwd") or "",
                            origin="A",
                        )
                        return json.dumps({
                            "status": "advanced_unsafe",
                            "action": "AUTO_ADVANCE_BLOCKED",
                            "escalation_id": esc_id,
                            "target_pane": target_pane,
                            "new_escalation": aa.new_req_cmd,
                            "reason": aa.reason,
                        }, ensure_ascii=False)
                    # not_trampolined (or no new command found): fall through to
                    # the existing re-polling deferral — A stays PENDING so the
                    # next poll re-parses and re-evaluates it normally.
                    return json.dumps({
                        "status": "error",
                        "error": f"approval deferred ({agent_kind}): dialog changed mid-evaluation; re-polling",
                    }, ensure_ascii=False)
                return json.dumps({
                    "status": "error",
                    "error": f"approval injection failed ({agent_kind}): {inject_reason or 'no adapter'}",
                }, ensure_ascii=False)

            # Only a VERIFIED injection success records the adjudication (FIX 1).
            # INV-AP-1/2/3: an autonomous approve records provenance as
            # "gatekeeper" (least-privileged) — it never seeds the novelty gate
            # and never auto-promotes workspace rules. Executing an EXPLICIT
            # human directive (/approve, /reject, or free-text) records
            # approver="human-tui" — the human is the final decision authority
            # and their approval seeds the novelty gate (directive=true).
            resolve_escalation(pane_id="", escalation_id=esc_id, resolution_status="RESOLVED", is_approval=True)
            directive = bool(args.get("directive"))
            approver = "human-tui" if directive else "gatekeeper"
            record_adjudication(
                esc_id, target_pane, agent_kind, "APPROVE", feedback,
                approver=approver, human_note=(feedback if directive else None),
            )

            if send_instruction and feedback:
                subprocess.run(["herdr", "pane", "send-text", target_pane, f"# [SECURITY GATEKEEPER]: {feedback}"], capture_output=True, timeout=5.0)
                subprocess.run(["herdr", "agent", "send-keys", target_pane, "enter"], capture_output=True, timeout=5.0)

            return json.dumps({
                "status": "success",
                "escalation_id": esc_id,
                "target_pane": target_pane,
                "action": "APPROVED",
                "feedback": feedback,
            }, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"status": "error", "error": str(e)})

    elif name == "reject_escalation":
        raw_id = args.get("escalation_id")
        esc_id = int(raw_id) if raw_id is not None and str(raw_id).isdigit() else 0
        raw_feedback = args.get("english_feedback") or args.get("reason") or "Rejected by security gatekeeper."
        feedback = _sanitize_feedback(raw_feedback)
        try:
            # Enforce FIFO Head validation before keystroke injection. The
            # command-slot head EXCLUDES questions (INV-QN-1/2).
            active_head = get_current_command_escalation()
            if not active_head or active_head["id"] != esc_id:
                active_id = active_head["id"] if active_head else None
                return json.dumps({
                    "status": "error",
                    "error": f"Escalation #{esc_id} is not the current active FIFO head (active: #{active_id}).",
                })

            esc_row = _get_escalation_row(esc_id) if esc_id > 0 else None
            target_pane = esc_row.get("pane_id") if esc_row else ""
            agent_kind = esc_row.get("agent_kind", "agy") if esc_row else "agy"
            req_cmd = esc_row.get("raw_command", "") if esc_row else ""

            cfg = get_instruction_delivery_config()
            send_instruction = bool(cfg.get("send_reject_instruction", True))
            injected, inject_reason = _inject_rejection(
                target_pane, agent_kind, req_cmd, feedback, send_instruction
            )
            if not injected:
                return json.dumps({
                    "status": "error",
                    "error": f"rejection injection failed ({agent_kind}): {inject_reason or 'no adapter'}",
                }, ensure_ascii=False)

            resolve_escalation(pane_id="", escalation_id=esc_id, resolution_status="CANCELLED")
            directive = bool(args.get("directive"))
            approver = "human-tui" if directive else "gatekeeper"
            record_adjudication(
                esc_id, target_pane, "", "REJECT", feedback,
                approver=approver, human_note=(feedback if directive else None),
            )

            return json.dumps({
                "status": "success",
                "escalation_id": esc_id,
                "target_pane": target_pane,
                "action": "REJECTED",
                "feedback": feedback,
            }, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"status": "error", "error": str(e)})

    elif name == "create_feature_request":
        title = str(args.get("title", "")).strip()
        desc = str(args.get("description", "")).strip()
        priority = str(args.get("priority", "NORMAL")).upper()
        category = str(args.get("category", "GENERAL")).upper()
        if not title:
            return json.dumps({"error": "Title is required for feature request."})
        try:
            created = create_feature_request_with_similars(
                title=title,
                description=desc,
                requester="user",
                priority=priority,
                category=category,
                source="agent_tool",
                similars_limit=3,
            )
            return json.dumps({
                "status": "created",
                "id": created["id"],
                "title": created["title"],
                "priority": created["priority"],
                "similar_items": created["similar_items"],
            }, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)})

    elif name == "search_feature_requests":
        query = str(args.get("query", "")).strip()
        raw_limit = args.get("limit", 5)
        limit = int(raw_limit) if str(raw_limit).isdigit() else 5
        try:
            results = search_similar_feature_requests(query, limit=limit)
            return json.dumps({
                "query": query,
                "count": len(results),
                "results": results,
            }, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)})

    return json.dumps({"error": f"Unknown tool: {name}"})


def clean_llm_response(text: str) -> str:
    if not text:
        return ""
    # 1. Strip DSML / special token markers (e.g. <｜tool_calls｜>, </...>) from LLM responses.
    cleaned = re.sub(r"<\/?(?:｜|\|){1,4}[^>]*>", "", text)
    cleaned = re.sub(r"<[｜|][^>]+>", "", cleaned)
    cleaned = re.sub(r"<\/[｜|][^>]+>", "", cleaned)
    # 2. Strip XML tool-calling and internal thinking tags
    cleaned = re.sub(r"<\/?\s*(?:invoke|parameter|tool_call|tool_calls|tool_response|tool_outputs|function_call|function|call|result|thought|thinking|artifact)[^>]*>", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"<\?xml.*?\?>", "", cleaned, flags=re.IGNORECASE)
    # 3. Strip standalone trailing XML close tags
    cleaned = re.sub(r"<\/\S+>", "", cleaned)
    # 4. Strip raw embedded JSON tool call artifacts
    cleaned = re.sub(r"```json\s*\{.*?\}\s*```", "", cleaned, flags=re.DOTALL)
    # 5. Clean excess whitespace and blank lines
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    # 6. Strip wrapping markdown code blocks if whole string is wrapped
    if cleaned.startswith("```markdown\n") and cleaned.endswith("\n```"):
        cleaned = cleaned[12:-4].strip()
    elif cleaned.startswith("```\n") and cleaned.endswith("\n```"):
        cleaned = cleaned[4:-4].strip()
    return cleaned


def format_tool_call_beautified(fn_name: str, fn_args: Dict[str, Any]) -> str:
    """Format Inspector tool invocation into a high-visibility semantic badge."""
    if fn_name == "investigate_path_details":
        target = fn_args.get("target_path", "")
        return f"🔍 **[Path Check]**: `{target}`"

    elif fn_name == "investigate_pane_history":
        pane = fn_args.get("pane_id", "")
        lines = fn_args.get("lines", 100)
        dump = " · scrollback" if fn_args.get("full_dump") else ""
        return f"📜 **[Pane Buffer]**: `{pane}` ({lines} lines{dump})"

    elif fn_name == "read_file_snippet":
        target = fn_args.get("target_path", "")
        return f"📄 **[File Read]**: `{target}`"

    elif fn_name == "approve_escalation":
        esc_id = fn_args.get("escalation_id", "")
        note = fn_args.get("english_feedback", "")
        note_short = f" — *{note[:60]}…*" if len(note) > 60 else f" — *{note}*"
        return f"✅ **[Auto Approve]**: Escalation `#{esc_id}`{note_short}"

    elif fn_name == "reject_escalation":
        esc_id = fn_args.get("escalation_id", "")
        reason = fn_args.get("english_feedback", "")
        return f"🛑 **[Action Reject]**: Escalation `#{esc_id}` — *{reason}*"

    elif fn_name == "create_feature_request":
        title = fn_args.get("title", "")
        prio = fn_args.get("priority", "NORMAL")
        return f"💡 **[Feature Queued]**: `{title}` *(Priority: {prio})*"

    elif fn_name == "search_feature_requests":
        query = fn_args.get("query", "")
        return f"🔎 **[Backlog Search]**: *\"{query}\"*"

    raw = json.dumps(fn_args, ensure_ascii=False)
    return f"⚙️ **[Inspector]**: `{fn_name}` `{raw}`"


_ANSWER_LANGUAGE_MAP = {
    "english": "concise professional English",
    "korean": "간결하고 건조한 한국어 (dry Korean)",
    "japanese": "簡潔で淡々とした日本語 (dry Japanese)",
}


def build_system_prompt(language: Optional[str] = None, allow_adjudication: bool = True) -> str:
    lang = language or get_answer_language()
    lang_instruction = _ANSWER_LANGUAGE_MAP.get(lang, _ANSWER_LANGUAGE_MAP["korean"])

    # Command-slot head excludes questions (INV-QN-1/2); a pending QUESTION is
    # surfaced via the sidebar hint, never blocks the gatekeeper prompt.
    active_esc = get_current_command_escalation()

    if not active_esc:
        return f"""You are the autonomous Security Gatekeeper & Inspector Agent for Herdr SmartGate.
There are currently NO active pending escalations.
All previous tasks are finished. If the user asks questions, answer them in {lang_instruction}."""

    op_type, detected_target = classify_operation(active_esc['raw_command'])
    target_candidate = detected_target or "unknown"

    if allow_adjudication:
        # Advisory-only gatekeeper redesign: the gatekeeper is an ADVISOR, never
        # the final decision authority. Autonomous approve is restricted to the
        # closed obvious-safe (Tier B) form; autonomous reject to denylist
        # critical (Tier A) layers. Everything else (Tier C) is deferred to the
        # human. STEP 3 (HUMAN DIRECTIVE) is unconditional — an expressed human
        # decision ALWAYS wins over any Tier A/B/C assessment (no Disagree &
        # Commit branch).
        protocol = """[🔬 ADVISORY SECURITY REVIEW PROTOCOL]:

STEP 0 — RISK BRIEFING (produce this BEFORE any action):
- Decompose the command into risk segments and state your understanding factually. Mark each PRESENT or ABSENT with its consequence (NONE | EXFIL | DEST | INT | AVAIL | PERS):
  1. CHAINED SEGMENTS: `;` `&&` `||` `|` pipes, subshells, `xargs`, `eval`, sequencing.
  2. MUTATIONS: writes, deletes, truncates, moves, chmod/chown, or any irreversible filesystem/state change.
  3. NETWORK EGRESS: curl/wget/nc/ssh/scp/rsync/git-push or outbound network/HTTP.
  4. SENSITIVE PATHS: secrets (`.env`, `id_*`, tokens, keys) or system roots (`/etc`, `/System`, `/var`, `/usr`, `/dev`, `/volume*`, Keychain, TCC).
  5. SUBSTITUTIONS: `$(...)`, backticks, `<(...)`, env-var expansion, dynamic payload injection.
- This briefing is your ADVISORY REPORT to the human. It is NOT itself a verdict and NOT a gate — do not use it to force a rejection.

STEP 1 — INVESTIGATION (optional; use tools to verify facts):
- Verify unverified claims with `investigate_path_details`, `investigate_pane_history`, or `read_file_snippet` as appropriate.
- You may skip tools when the command is Tier B (obvious-safe) or Tier A (unambiguous critical) with certainty. "It looks simple" alone is NOT a skip reason — the command must match the closed Tier-B form.

STEP 2 — TRIAGE (choose exactly one tier, driven by the Decision Layer). OVERALL BIAS — APPROVE BY DEFAULT: you are a flow-enabler, not a blocker. Withhold approval only on a concrete, named red flag — never on vague unease, and never because you cannot prove a negative.
- Tier A — UNAMBIGUOUS CRITICAL (denylist): Decision Layer is one of SHELL_CRITICAL, SECRET_GUARD, SANDBOX_GUARD, PYTHON_AST, ORIGIN_GUARD. For these ONLY you MAY autonomously call `reject_escalation`. Always include the STEP 0 briefing in your response.
- Tier B — OBVIOUS-SAFE: Decision Layer is NOT_ALLOWLISTED AND the command matches the closed obvious-safe form (see below). For these ONLY you MAY autonomously call `approve_escalation` with a concise note; do NOT open investigation loops.
- Tier C — GRAY-ZONE / AMBIGUOUS / COMPLEX (everything else). These are ordinary developer operations — `git add <paths>`, `git commit -m "..."`, `git pull --ff-only`, `mkdir`, file edits, test runs. Your DEFAULT is to APPROVE. After a quick red-flag scan (STEP 0), if you find NO concrete red flag — a destructive/irreversible flag (`--hard`, `--force`, `clean -f`, `--amend`, `reset`, `checkout --`), network egress, a sensitive path, or a `$()`/backtick substitution — call `approve_escalation` immediately. Do NOT require proof of safety: require EVIDENCE OF DANGER to withhold approval. Skip investigation tools for routine reversible operations. Only a specific, unresolved red flag justifies deferring — and even then, NEVER call `reject_escalation`; present the risk and wait for the human.

[OBVIOUS-SAFE FORM (Tier B) — closed, never weakens the denylist]:
- Single segment: no `|`, `&`, `;`, `&&`, `||`, no shell newline separators, no `$(...)`/backticks, no `>`/`<` redirection.
- AND one of:
  * a version/help query: `<interpreter> --version|-v|-V|version|--help|-h` (e.g. `node --version`, `python --version`, `git --version`, `rustc --version`);
  * a read-only builtin/utility with no dangerous flags: `ls`, `pwd`, `echo <text>`, `which <x>`, `cat|head|tail|grep <path>` on a NON-sensitive, non-root path;
  * a read-only git query: `git status|log|diff|show|branch|tag|remote -v`.
- NEVER Tier B if Decision Layer is a denylist layer, or the command touches a sensitive/system path, mutates, or egresses. A denylist layer ALWAYS wins over obvious-safe.

STEP 3 — HUMAN DIRECTIVE (always binding — never override):
- The human is the final decision authority. Their expressed decision ALWAYS wins over your Tier A/B/C assessment.
- A directive may arrive as `/approve <id> [reason]`, `/reject <id> [reason]`, OR any free-text message expressing intent to allow/proceed/run/approve (or block/reject/stop) the current escalation.
- When you detect a directive, EXECUTE it: call `approve_escalation` (approval) or `reject_escalation` (rejection) with `directive=true`.
- Record your INDEPENDENT confirmation in `english_feedback` (do NOT echo the human's words verbatim): name the risk segments you found, state the residual risk if your assessment conflicts, and affirm the directive was executed. You do NOT override the human.
- NO AUTONOMOUS REJECT (restored): do NOT call `reject_escalation` on your own judgment for any Tier-C command. Autonomous APPROVAL of a red-flag-free Tier-C command is the default (see STEP 2); only the REJECT decision is reserved for the human or Tier A. Autonomous reject is permitted ONLY for Tier A.

STEP 4 — FEEDBACK FORMAT:
- `english_feedback` MUST be professional English and embed a condensed risk-segment summary. Examples:
  - Approve (obvious-safe): `Approved. Segments: chained=none, mutation=none, egress=none, sensitive=none, substitution=none.`
  - Approve (human directive): `Executed human approval. Segments: mutation=rm -rf /tmp/foo. Residual risk: none beyond /tmp/foo.`
  - Reject (critical): `Rejected. Segments: mutation=rm -rf /; sensitive=/. Alternative: <safe alternative>.`
- Your final text response to the human MUST begin with the STEP 0 risk-segment briefing, then the triage tier, then the verdict (or the deferral note)."""
    else:
        protocol = f"""[🔬 READ-ONLY INTERPRETATION MODE (NO ADJUDICATION)]:
- The current escalation is a HUMAN QUESTION dialog, not a command to approve.
- You have NO approve/reject capability this turn — do NOT attempt to adjudicate.
- Interpret the question and its surrounding context, and suggest how the human should answer it in the agent pane, in {lang_instruction}."""

    # Multi-line scripts (AGY dumps etc.) render in a fenced code block so the
    # LLM sees the full payload unambiguously instead of a truncated inline span.
    raw_command_text = active_esc['raw_command']
    if "\n" in raw_command_text:
        raw_command_line = f"- Canonical Command:\n```bash\n{raw_command_text}\n```"
    else:
        raw_command_line = f"- Canonical Command: `{raw_command_text}`"

    return f"""You are the autonomous Security Gatekeeper & Inspector Agent for Herdr SmartGate.

[🗣️ ANSWER LANGUAGE]:
- Render your FINAL response, risk report, and any explanation to the human user in {lang_instruction}.

[🎯 CURRENT ACTIVE ESCALATION TARGET]:
- Escalation ID: #{active_esc['id']}
- Target Pane: {active_esc['pane_id']} ({active_esc.get('agent_kind', 'agent')})
{raw_command_line}
- Command Representation: canonical (the only executable candidate)
- Capture Source: {active_esc.get('capture_source') or 'unknown'}
- Normalization Relation: {active_esc.get('normalization_relation') or 'unknown'}
- Normalization Ambiguous: {bool(active_esc.get('normalization_ambiguous'))}
- Raw Capture Evaluated: {bool(active_esc.get('raw_capture_evaluated'))}
- Intercepted Reason: {active_esc['safety_reason']}
- Detected Target: `{target_candidate}`
- Decision Layer: {active_esc.get('decision_layer', 'UNKNOWN')}
- Human Opinion Recorded: {has_human_opinion(active_esc['id'])}

{protocol}

[NORMALIZATION SAFETY CONTRACT]:
- You may suggest a reconstructed command only as advisory text.
- Never treat your reconstruction as executable or adjudicated. Every candidate
  must re-enter deterministic capture, normalization, denylist, and TOCTOU guards.
"""


def record_model_no_tool_call(active_esc: Dict[str, Any], phase: str) -> str:
    """Persist a fail-closed LLM turn that produced text but no action tool."""
    reason = (
        f"{phase} returned briefing text without an adjudication tool call; "
        "escalation remains pending for human review"
    )
    started_at = active_esc.get("started_at")
    if started_at:
        init_db()
        with get_db_connection() as conn:
            duplicate = conn.execute(
                """
                SELECT 1 FROM audit_logs
                WHERE pane_id = ? AND raw_command = ? AND decision = 'MODEL_NO_TOOL_CALL'
                  AND timestamp >= ?
                LIMIT 1
                """,
                (active_esc["pane_id"], active_esc["raw_command"], started_at),
            ).fetchone()
        if duplicate:
            return reason
    record_audit_log(
        pane_id=active_esc["pane_id"],
        raw_command=active_esc["raw_command"],
        decision="MODEL_NO_TOOL_CALL",
        safety_reason=reason,
        agent_kind=active_esc.get("agent_kind", "unknown"),
        decision_layer=active_esc.get("decision_layer", "NOT_ALLOWLISTED"),
        origin=active_esc.get("origin") or "A",
        mechanism=f"{phase.lower()}-no-tool-call",
        decision_source="LLM",
    )
    return reason


class SchengenAgentChat:
    def __init__(self, api_key: Optional[str] = None):
        self.inspector_api_key = api_key or INSPECTOR_API_KEY
        self.inspector_base_url = INSPECTOR_BASE_URL
        self.inspector_model = INSPECTOR_MODEL
        self.judge_api_key = api_key or JUDGE_API_KEY
        self.judge_base_url = JUDGE_BASE_URL
        self.judge_model = JUDGE_MODEL
        self.session_id = f"session_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        self.log_file = SESSIONS_DIR / f"{self.session_id}.jsonl"
        self.history: List[Dict[str, Any]] = []
        self._current_esc_id: Optional[int] = None
        self._cancel_requested: bool = False
        
        # Token Meter: Total & Breakdown by Phase
        self.total_api_calls = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_cached_tokens = 0
        
        # Inspector Phase vs Judge Phase Breakdown
        self.inspector_prompt_tokens = 0
        self.inspector_completion_tokens = 0
        self.judge_prompt_tokens = 0
        self.judge_completion_tokens = 0

    def cancel(self) -> None:
        """Flag current in-flight LLM call to abort immediately."""
        self._cancel_requested = True

    def reset_cancel(self) -> None:
        """Reset the cancellation flag before starting a new chat turn."""
        self._cancel_requested = False

    def get_token_usage_stats(self) -> Dict[str, Any]:
        """Return cumulative token usage and cache hit ratio breakdown."""
        total_in = self.total_prompt_tokens
        cached = self.total_cached_tokens
        cache_ratio = (cached / total_in * 100.0) if total_in > 0 else 0.0
        return {
            "api_calls": self.total_api_calls,
            "prompt_tokens": total_in,
            "completion_tokens": self.total_completion_tokens,
            "cached_tokens": cached,
            "cache_hit_pct": f"{cache_ratio:.1f}%",
            "inspector_in": self.inspector_prompt_tokens,
            "inspector_out": self.inspector_completion_tokens,
            "judge_in": self.judge_prompt_tokens,
            "judge_out": self.judge_completion_tokens,
        }

    def _append_transcript(self, role: str, content: Any, tool_calls: Optional[List[Dict[str, Any]]] = None) -> None:
        try:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": self.session_id,
                "role": role,
                "content": content,
            }
            if tool_calls:
                entry["tool_calls"] = tool_calls
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    async def send_message(self, user_text: str, on_chunk: Optional[Callable[[str], None]] = None, allow_adjudication: bool = True) -> str:
        if not self.inspector_api_key:
            return "⚠️ No API key found. Set OPENAI_API_KEY or SCHENGEN_INSPECTOR_API_KEY."

        self.reset_cancel()
        # Command-slot head excludes questions (INV-QN-1/2).
        active_esc = get_current_command_escalation()
        active_id = active_esc["id"] if active_esc else None

        if active_id != self._current_esc_id:
            self._current_esc_id = active_id
            self.history = []

        self._append_transcript(role="user", content=user_text)

        messages = [{"role": "system", "content": build_system_prompt(allow_adjudication=allow_adjudication)}]
        messages.extend(self.history)
        messages.append({"role": "user", "content": user_text})

        # Phase-aware clients: Inspector uses tool-calling model, Judge uses adjudication model
        if httpx is None:
            return "Error: 'httpx' library is required for LLM agent API calls."

        transport_timeout = httpx.Timeout(connect=5.0, read=25.0, write=10.0, pool=5.0)
        inspector_client = httpx.AsyncClient(timeout=transport_timeout)
        judge_client = (
            httpx.AsyncClient(timeout=transport_timeout)
            if (self.judge_api_key != self.inspector_api_key or self.judge_base_url != self.inspector_base_url)
            else inspector_client
        )

        async def _post_with_adaptive_retry(
            client: Any, url: str, headers: Dict[str, str], payload: Dict[str, Any], phase_name: str
        ) -> Tuple[Optional[Any], Optional[str]]:
            """Execute POST with adaptive exponential retry (up to 10 attempts) for network/API errors."""
            max_retries = 10
            retryable_statuses = {429, 500, 502, 503, 504}
            last_err_msg = ""
            for attempt in range(1, max_retries + 1):
                if self._cancel_requested:
                    return None, "🛑 [Interrupted]: LLM call was aborted by user."
                try:
                    resp = await client.post(url, json=payload, headers=headers)
                    if self._cancel_requested:
                        return None, "🛑 [Interrupted]: LLM call was aborted by user."
                    if resp.status_code == 200:
                        return resp, None
                    if resp.status_code in retryable_statuses and attempt < max_retries:
                        retry_after = resp.headers.get("Retry-After")
                        delay = min(10.0, float(retry_after)) if retry_after and retry_after.isdigit() else min(5.0, 0.1 * (1.5 ** (attempt - 1))) + random.uniform(0, 0.05)
                        await asyncio.sleep(delay)
                        continue
                    return None, f"⚠️ {phase_name} API Error ({resp.status_code}): {resp.text}"
                except _HTTP_EXCEPTIONS as exc:
                    last_err_msg = str(exc)
                    if attempt < max_retries:
                        delay = min(5.0, 0.1 * (1.5 ** (attempt - 1))) + random.uniform(0, 0.05)
                        await asyncio.sleep(delay)
                        continue
                    return None, f"⚠️ {phase_name} Network/API Error after {max_retries} retries: {last_err_msg}"
            return None, f"⚠️ {phase_name} Error: Max retries exceeded ({last_err_msg})"

        try:
            for loop_turn in range(4):
                if self._cancel_requested:
                    return "🛑 [Interrupted]: LLM investigation aborted by user."
                inspector_headers = {
                    "Authorization": f"Bearer {self.inspector_api_key}",
                    "Content-Type": "application/json",
                }
                judge_headers = {
                    "Authorization": f"Bearer {self.judge_api_key}",
                    "Content-Type": "application/json",
                }

                tools = [
                    t for t in GUARD_TOOLS
                    if allow_adjudication or t["function"]["name"] not in ("approve_escalation", "reject_escalation")
                ]
                payload = {
                    "model": self.inspector_model,
                    "messages": messages,
                    "tools": tools,
                    "temperature": 0.0,
                    "stream": False,
                }
                resp, err = await _post_with_adaptive_retry(
                    inspector_client,
                    f"{self.inspector_base_url}/chat/completions",
                    inspector_headers,
                    payload,
                    "Inspector",
                )
                if err or resp is None:
                    return err or "⚠️ Unknown Inspector Error"

                data = resp.json()
                self.total_api_calls += 1

                usage = data.get("usage", {})
                p_tokens = usage.get("prompt_tokens", 0)
                c_tokens = usage.get("completion_tokens", 0)
                cached = usage.get("prompt_cache_hit_tokens", 0) or (usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0)

                self.total_prompt_tokens += p_tokens
                self.total_completion_tokens += c_tokens
                self.total_cached_tokens += cached

                choice = data["choices"][0]
                msg = choice["message"]
                tool_calls = msg.get("tool_calls")

                if not tool_calls:
                    # Record Inspector prompt tokens spent for the check
                    self.inspector_prompt_tokens += p_tokens
                    self.inspector_completion_tokens += c_tokens

                    # ── Judge Phase ─────────────────────────────────────────────
                    final_phase = "Inspector"
                    if (self.judge_api_key != self.inspector_api_key or 
                        self.judge_base_url != self.inspector_base_url or 
                        self.judge_model != self.inspector_model):
                        judge_payload = {
                            "model": self.judge_model,
                            "messages": messages,
                            "temperature": 0.0,
                            "stream": False,
                        }
                        judge_resp, judge_err = await _post_with_adaptive_retry(
                            judge_client,
                            f"{self.judge_base_url}/chat/completions",
                            judge_headers,
                            judge_payload,
                            "Judge",
                        )
                        if judge_err or judge_resp is None:
                            return judge_err or "⚠️ Unknown Judge Error"

                        judge_data = judge_resp.json()
                        self.total_api_calls += 1
                        j_usage = judge_data.get("usage", {})
                        jp_tokens = j_usage.get("prompt_tokens", 0)
                        jc_tokens = j_usage.get("completion_tokens", 0)
                        j_cached = j_usage.get("prompt_cache_hit_tokens", 0) or (j_usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0)

                        self.total_prompt_tokens += jp_tokens
                        self.total_completion_tokens += jc_tokens
                        self.total_cached_tokens += j_cached

                        self.judge_prompt_tokens += jp_tokens
                        self.judge_completion_tokens += jc_tokens
                        msg = judge_data["choices"][0]["message"]
                        final_phase = "Judge"
                    else:
                        self.judge_prompt_tokens += p_tokens
                        self.judge_completion_tokens += c_tokens

                    raw_content = msg.get("content") or ""
                    final_content = clean_llm_response(raw_content)
                    if not final_content:
                        final_content = "⚠️ No explicit verdict returned by Inspector/Judge; deferring to human operator."

                    if allow_adjudication and active_esc:
                        record_model_no_tool_call(active_esc, final_phase)
                        final_content = (
                            f"⚠️ [MODEL_NO_TOOL_CALL] {final_phase} supplied advisory text but did not "
                            "execute an approval or rejection. The escalation remains pending.\n\n"
                            + final_content
                        )

                    self._append_transcript(role="assistant", content=final_content)
                    self.history.append({"role": "user", "content": user_text})
                    self.history.append({"role": "assistant", "content": final_content})
                    return final_content

                # ── Inspector Phase (tool turn) ──────────────────────────────
                self.inspector_prompt_tokens += p_tokens
                self.inspector_completion_tokens += c_tokens

                messages.append(msg)
                self._append_transcript(role="assistant", content=msg.get("content", ""), tool_calls=tool_calls)
                for tc in tool_calls:
                    fn_name = tc["function"]["name"]
                    try:
                        fn_args = json.loads(tc["function"]["arguments"])
                    except Exception:
                        fn_args = {}

                    if on_chunk:
                        chunk_msg = format_tool_call_beautified(fn_name, fn_args)
                        on_chunk(chunk_msg)

                    tool_result = execute_tool_call(fn_name, fn_args)
                    self._append_transcript(role="tool", content=tool_result)

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": tool_result,
                    })

                    if fn_name in ("approve_escalation", "reject_escalation"):
                        self.history = []

        finally:
            await inspector_client.aclose()
            if judge_client is not inspector_client:
                await judge_client.aclose()

        return "Investigation and execution completed."
