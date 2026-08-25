#!/usr/bin/env python3
"""Autonomous Inspector & Security Gatekeeper Agent Loop for Schengen Guardian.

Core Capabilities:
1. Dual-Model Phase Routing:
   - Inspector Phase (tool-calling investigation): uses SCHENGEN_INSPECTOR_API_KEY + SCHENGEN_INSPECTOR_BASE_URL
   - Judge Phase (final text adjudication): uses SCHENGEN_JUDGE_API_KEY + SCHENGEN_JUDGE_BASE_URL
   - Both fall back to shared DEEPSEEK_API_KEY / DEEPSEEK_BASE_URL if phase-specific vars are not set.
   - Architecture note: OpenCode/AGY is the supervised *worker* — not the judge.
     Judge = the final no-tool-call text turn in DeepSeek's chat loop, fully independent of OpenCode.
2. AGY Tab Amend Protocol: Tab → security note → Enter for AGY approvals.
3. Strict Single-Task FIFO: one pending escalation resolved at a time.
"""

import json
import os
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
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from gray_zone_evaluator import (
    canonicalize_path,
    classify_operation,
    classify_resource_tier,
    evaluate_gray_zone_operation,
    is_inside_git_work_tree,
    is_git_clean_and_committed,
)
from guard_db import (
    get_db_connection,
    get_pending_escalations,
    get_recent_audit_logs,
    resolve_escalation,
)
from herdr_client import get_pane_text

# ── Shared fallback config ──────────────────────────────────────────
_SHARED_KEY  = os.environ.get("OPENCODE_DEEPSEEK_API_KEY") or os.environ.get("DEEPSEEK_API_KEY", "")
_SHARED_URL  = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")


def resolve_subagent_model(default: str = "deepseek-chat") -> str:
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
INSPECTOR_MODEL    = os.environ.get("SCHENGEN_INSPECTOR_MODEL")    or resolve_subagent_model("deepseek-chat")

# Judge (final adjudication text phase)
JUDGE_API_KEY  = os.environ.get("SCHENGEN_JUDGE_API_KEY")  or _SHARED_KEY
JUDGE_BASE_URL = os.environ.get("SCHENGEN_JUDGE_BASE_URL") or _SHARED_URL
JUDGE_MODEL    = os.environ.get("SCHENGEN_JUDGE_MODEL")    or resolve_subagent_model("deepseek-chat")

SESSIONS_DIR = Path.home() / ".local" / "state" / "herdr-schengen" / "sessions"
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


GUARD_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "investigate_pane_history",
            "description": "Inspect recent terminal text of the target worker pane to verify developer intent and context before making a decision.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pane_id": {
                        "type": "string",
                        "description": "Target pane ID (e.g. 'w1D:p1').",
                    },
                    "lines": {
                        "type": "integer",
                        "description": "Number of recent lines to read (default: 30).",
                        "default": 30,
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
                },
                "required": ["escalation_id", "english_feedback"],
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
    """Return the oldest (FIFO) active pending escalation so tasks are processed in strict sequence."""
    pending = get_pending_escalations(include_delivered=False)
    return pending[0] if pending else None


def _get_escalation_row(esc_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_escalations WHERE id = ?", (esc_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def execute_tool_call(name: str, args: Dict[str, Any]) -> str:
    if name == "investigate_pane_history":
        pane_id = args.get("pane_id", "")
        lines = args.get("lines", 30)
        try:
            raw = get_pane_text(pane_id, lines=lines)
            return json.dumps({
                "pane_id": pane_id,
                "pane_text_snippet": raw[-2000:] if raw else "",
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
            return json.dumps({"path": str(p), "content": content}, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)})

    elif name == "approve_escalation":
        raw_id = args.get("escalation_id")
        esc_id = int(raw_id) if raw_id is not None and str(raw_id).isdigit() else 0
        raw_feedback = args.get("english_feedback") or args.get("feedback") or "Approved by security gatekeeper."
        feedback = _sanitize_feedback(raw_feedback)
        try:
            # Enforce FIFO Head validation before keystroke injection
            active_head = get_current_active_escalation()
            if not active_head or active_head["id"] != esc_id:
                active_id = active_head["id"] if active_head else None
                return json.dumps({
                    "status": "error",
                    "error": f"Escalation #{esc_id} is not the current active FIFO head (active: #{active_id}).",
                })

            esc_row = _get_escalation_row(esc_id) if esc_id > 0 else None
            target_pane = esc_row.get("pane_id") if esc_row else ""
            agent_kind = esc_row.get("agent_kind", "agy") if esc_row else "agy"
            
            resolve_escalation(pane_id="", escalation_id=esc_id, resolution_status="RESOLVED")

            if target_pane:
                if agent_kind == "agy" and feedback:
                    # AGY Tab Amend Flow: Tab -> send feedback note -> Enter
                    subprocess.run(["herdr", "agent", "send-keys", target_pane, "tab"], capture_output=True, timeout=5.0)
                    subprocess.run(["herdr", "pane", "send-text", target_pane, f"# [SECURITY GATEKEEPER]: {feedback}"], capture_output=True, timeout=5.0)
                    subprocess.run(["herdr", "agent", "send-keys", target_pane, "enter"], capture_output=True, timeout=5.0)
                else:
                    # Standard Enter Flow
                    subprocess.run(["herdr", "agent", "send-keys", target_pane, "enter"], capture_output=True, timeout=5.0)
                    if feedback:
                        subprocess.run(["herdr", "pane", "send-text", target_pane, f"# [SECURITY GATEKEEPER]: {feedback}"], capture_output=True, timeout=5.0)
                        subprocess.run(["herdr", "pane", "send-keys", target_pane, "enter"], capture_output=True, timeout=5.0)

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
            # Enforce FIFO Head validation before keystroke injection
            active_head = get_current_active_escalation()
            if not active_head or active_head["id"] != esc_id:
                active_id = active_head["id"] if active_head else None
                return json.dumps({
                    "status": "error",
                    "error": f"Escalation #{esc_id} is not the current active FIFO head (active: #{active_id}).",
                })

            esc_row = _get_escalation_row(esc_id) if esc_id > 0 else None
            target_pane = esc_row.get("pane_id") if esc_row else ""

            resolve_escalation(pane_id="", escalation_id=esc_id, resolution_status="CANCELLED")

            if target_pane:
                subprocess.run(["herdr", "agent", "send-keys", target_pane, "escape"], capture_output=True, timeout=5.0)
                if feedback:
                    subprocess.run(["herdr", "pane", "send-text", target_pane, f"# [SECURITY GATEKEEPER]: {feedback}"], capture_output=True, timeout=5.0)
                    subprocess.run(["herdr", "pane", "send-keys", target_pane, "enter"], capture_output=True, timeout=5.0)

            return json.dumps({
                "status": "success",
                "escalation_id": esc_id,
                "target_pane": target_pane,
                "action": "REJECTED",
                "feedback": feedback,
            }, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"status": "error", "error": str(e)})

    return json.dumps({"error": f"Unknown tool: {name}"})


def clean_llm_response(text: str) -> str:
    cleaned = re.sub(r"<[｜|][^>｜|]+[｜|]>", "", text)
    cleaned = re.sub(r"<[｜|][^>]+>", "", cleaned)
    cleaned = re.sub(r"```json\s*\{.*?\}\s*```", "", cleaned, flags=re.DOTALL)
    cleaned = re.sub(r"<\/?(?:invoke|parameter|tool_call)[^>]*>", "", cleaned)
    cleaned = cleaned.strip()
    # Strip wrapping markdown code blocks if whole string is wrapped
    if cleaned.startswith("```markdown\n") and cleaned.endswith("\n```"):
        cleaned = cleaned[12:-4].strip()
    elif cleaned.startswith("```\n") and cleaned.endswith("\n```"):
        cleaned = cleaned[4:-4].strip()
    return cleaned


def build_system_prompt() -> str:
    active_esc = get_current_active_escalation()

    if not active_esc:
        return """You are the autonomous Security Gatekeeper & Inspector Agent for Herdr SmartGate.
There are currently NO active pending escalations.
All previous tasks are finished. If the user asks questions, inform them that no pending escalations are currently queued."""

    op_type, detected_target = classify_operation(active_esc['raw_command'])
    target_candidate = detected_target or "unknown"

    return f"""You are the autonomous Security Gatekeeper & Inspector Agent for Herdr SmartGate.

[🎯 CURRENT ACTIVE ESCALATION TARGET]:
- Escalation ID: #{active_esc['id']}
- Target Pane: {active_esc['pane_id']} ({active_esc.get('agent_kind', 'agent')})
- Raw Command: `{active_esc['raw_command']}`
- Intercepted Reason: {active_esc['safety_reason']}
- Detected Target: `{target_candidate}`

[🔬 AUTONOMOUS INVESTIGATION & ADJUDICATION PROTOCOL]:
1. **Autonomous Triaging & Investigation**:
   - Assess the intercepted command. You have full discretion to call investigation tools:
     - Call `investigate_path_details(target_path='{target_candidate}')` if the target filesystem status is unverified.
     - Call `investigate_pane_history(pane_id='{active_esc['pane_id']}')` to inspect worker intent from recent terminal buffer.
     - Call `read_file_snippet(target_path=...)` if a script/payload needs inspection.
     - If the command is an obvious safe operation, you may skip tools.

2. **Adjudication Rules**:
   - **Autonomous Approval**: If investigation confirms zero data loss risk (e.g. target path does not exist, or clean VCS commit verified), you MAY autonomously call `approve_escalation` with a concise English security note.
   - **NO Autonomous Reject**: Do NOT call `reject_escalation` autonomously. If dangerous data loss or critical system risk is detected, report the factual risks clearly to the human user in dry Korean and wait for explicit human instructions (e.g. '거절', '차단', 'reject').

3. **Feedback Format**:
   - `english_feedback` MUST be in professional English: `Approved. <Direct Verified Fact>. <Actionable Note/Warning>.`
   - Example when target doesn't exist: `Approved. Target path does not exist (0B). Zero data loss risk. Note: Avoid habituated -rf flags on non-existent targets and verify path spelling.`
"""


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

    async def send_message(self, user_text: str, on_chunk: Optional[Callable[[str], None]] = None) -> str:
        if not self.inspector_api_key:
            return "⚠️ No API key found. Set DEEPSEEK_API_KEY or SCHENGEN_INSPECTOR_API_KEY."

        active_esc = get_current_active_escalation()
        active_id = active_esc["id"] if active_esc else None

        if active_id != self._current_esc_id:
            self._current_esc_id = active_id
            self.history = []

        self._append_transcript(role="user", content=user_text)

        messages = [{"role": "system", "content": build_system_prompt()}]
        messages.extend(self.history)
        messages.append({"role": "user", "content": user_text})

        # Phase-aware clients: Inspector uses tool-calling model, Judge uses adjudication model
        if httpx is None:
            return "Error: 'httpx' library is required for LLM agent API calls."

        inspector_client = httpx.AsyncClient(timeout=45.0)
        judge_client = (
            httpx.AsyncClient(timeout=45.0)
            if (self.judge_api_key != self.inspector_api_key or self.judge_base_url != self.inspector_base_url)
            else inspector_client
        )

        try:
            for loop_turn in range(4):
                inspector_headers = {
                    "Authorization": f"Bearer {self.inspector_api_key}",
                    "Content-Type": "application/json",
                }
                judge_headers = {
                    "Authorization": f"Bearer {self.judge_api_key}",
                    "Content-Type": "application/json",
                }

                payload = {
                    "model": self.inspector_model,
                    "messages": messages,
                    "tools": GUARD_TOOLS,
                    "temperature": 0.0,
                    "stream": False,
                }
                try:
                    resp = await inspector_client.post(
                        f"{self.inspector_base_url}/chat/completions",
                        json=payload,
                        headers=inspector_headers,
                    )
                except _HTTP_EXCEPTIONS as exc:
                    return f"⚠️ Inspector Network/API Error: {exc}"

                if resp.status_code != 200:
                    return f"⚠️ Inspector API Error ({resp.status_code}): {resp.text}"

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
                    if (self.judge_api_key != self.inspector_api_key or 
                        self.judge_base_url != self.inspector_base_url or 
                        self.judge_model != self.inspector_model):
                        judge_payload = {
                            "model": self.judge_model,
                            "messages": messages,
                            "temperature": 0.0,
                            "stream": False,
                        }
                        try:
                            judge_resp = await judge_client.post(
                                f"{self.judge_base_url}/chat/completions",
                                json=judge_payload,
                                headers=judge_headers,
                            )
                        except _HTTP_EXCEPTIONS as exc:
                            return f"⚠️ Judge Network/API Error: {exc}"

                        if judge_resp.status_code != 200:
                            return f"⚠️ Judge API Error ({judge_resp.status_code}): {judge_resp.text}"

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
                    else:
                        self.judge_prompt_tokens += p_tokens
                        self.judge_completion_tokens += c_tokens

                    final_content = clean_llm_response(msg.get("content", ""))
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
                        on_chunk(f"\n⚙️ [Inspector]: `{fn_name}` {json.dumps(fn_args, ensure_ascii=False)}\n")

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


