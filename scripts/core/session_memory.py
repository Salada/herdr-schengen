"""Pane-Scoped Session Memory Module for Herdr Schengen (SmartGate).

Provides pane-isolated approval memory (ADR-010):
- Caches and remembers prior approvals (Inspector LLM, Cloud Judge, Human Operator)
  strictly isolated per Herdr pane (`pane_id` / `scope`).
- Intercepts evaluation BEFORE expensive Inspector/Judge calls to enable 0.1ms fast-path.
- Guarantees strict cross-pane isolation: approvals in pane A never leak to pane B.
"""

import hashlib
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from core.guard_db import get_db_connection

# Safe repeatable pattern templates recognized across development sessions
SAFE_DYNAMIC_TEMPLATE_PATTERNS = [
    # Search / List queries with changing keyword arguments
    (re.compile(r"^(python3?\s+[\w/.-]+\.py\s+--(?:search|find|list|query|status))\s+.*$", re.IGNORECASE), r"\1 *"),
    # Safe read of temporary or worktree files
    (re.compile(r"^(cat\s+(?:/tmp/|~?/?[\w/.-]+worktrees/)[^|;&]+)$", re.IGNORECASE), r"cat <SAFE_PATH>"),
    # Git read/inspection operations with changing commit/branch hashes
    (re.compile(r"^(git\s+(?:show|log|diff|rev-parse|status|branch|worktree\s+list))\b.*$", re.IGNORECASE), r"git <READ_OP> *"),
    # Test suite runners
    (re.compile(r"^(python3?\s+-m\s+(?:unittest|pytest)\b).*$", re.IGNORECASE), r"\1 *"),
]


def extract_safe_command_template(cmd: str) -> Optional[str]:
    """Extract generalized template if command matches safe, repeatable development patterns."""
    clean = cmd.strip()
    for pattern, repl in SAFE_DYNAMIC_TEMPLATE_PATTERNS:
        if pattern.match(clean):
            return pattern.sub(repl, clean)
    return None


def _normalize_cmd_fingerprint(raw_cmd: str, cwd: str = "") -> str:
    """Compute normalized SHA256 fingerprint for a command within a directory."""
    norm_cmd = raw_cmd.strip()
    norm_cwd = str(cwd).strip() if cwd else ""
    canonical = f"cmd={norm_cmd}|cwd={norm_cwd}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PaneSessionMemory:
    """In-memory and SQLite-backed pane-scoped approval memory and pattern store."""

    def __init__(self):
        # In-memory fast cache: dict[pane_id, dict[cmd_fingerprint, record]]
        self._memory: Dict[str, Dict[str, Dict[str, Any]]] = {}
        # In-memory pattern template cache: dict[pane_id, dict[template_str, record]]
        self._template_memory: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._memory_lock = threading.RLock()

    def record_approval(
        self,
        pane_id: str,
        raw_cmd: str,
        decision_layer: str,
        reason: str,
        cwd: str = "",
        ttl_seconds: int = 3600,
        db_path: Optional[Path] = None,
    ) -> None:
        """Record an approved command for a specific pane."""
        norm_pane = str(pane_id).strip() if pane_id else "default"
        fingerprint = _normalize_cmd_fingerprint(raw_cmd, cwd)
        now = time.time()
        expires_at = now + ttl_seconds

        record = {
            "pane_id": norm_pane,
            "raw_command": raw_cmd.strip(),
            "cwd": cwd,
            "decision_layer": decision_layer,
            "reason": reason,
            "created_at": now,
            "expires_at": expires_at,
        }

        # 1. Update in-memory
        # 1. Update in-memory exact and template caches atomically.
        template = extract_safe_command_template(raw_cmd)
        with self._memory_lock:
            self._memory.setdefault(norm_pane, {})[fingerprint] = record
            if template:
                self._template_memory.setdefault(norm_pane, {})[template] = record

        # 2. Persist to DB cache table (evaluation_cache)
        try:
            con = get_db_connection(db_path)
            with con:
                con.execute(
                    """
                    INSERT INTO evaluation_cache (
                        cache_key, raw_command, is_safe, safety_reason, decision_layer,
                        taxonomy_json, cwd, scope, agent_id, origin, ruleset_version,
                        created_at, expires_at
                    ) VALUES (?, ?, 1, ?, ?, '{}', ?, ?, 'default', 'MEM', 'session-mem', datetime('now'), datetime(?, 'unixepoch'))
                    ON CONFLICT(cache_key) DO UPDATE SET
                        is_safe=1,
                        safety_reason=excluded.safety_reason,
                        decision_layer=excluded.decision_layer,
                        expires_at=excluded.expires_at
                    """,
                    (
                        f"pane_mem:{norm_pane}:{fingerprint}",
                        raw_cmd.strip(),
                        reason,
                        decision_layer,
                        cwd,
                        norm_pane,
                        int(expires_at),
                    ),
                )
        except Exception:
            pass

    def check_approval(
        self,
        pane_id: str,
        raw_cmd: str,
        cwd: str = "",
        db_path: Optional[Path] = None,
    ) -> Optional[Tuple[bool, str, str]]:
        """Check if command or its safe template was previously approved in this exact pane.

        Returns (is_safe, reason, decision_layer) if valid memory exists, None otherwise.
        """
        norm_pane = str(pane_id).strip() if pane_id else "default"
        fingerprint = _normalize_cmd_fingerprint(raw_cmd, cwd)
        now = time.time()

        # 1. Check exact fingerprint in-memory
        template = extract_safe_command_template(raw_cmd)
        with self._memory_lock:
            rec = self._memory.get(norm_pane, {}).get(fingerprint)
            if rec:
                if rec["expires_at"] > now:
                    return (True, f"[Session Memory: {norm_pane}] {rec['reason']}", rec["decision_layer"])
                del self._memory[norm_pane][fingerprint]

            # 1b. Check safe pattern template in-memory
            tmpl_rec = self._template_memory.get(norm_pane, {}).get(template) if template else None
            if tmpl_rec:
                if tmpl_rec["expires_at"] > now:
                    return (
                        True,
                        f"[Session Pattern Memory: {norm_pane}] Matches previously approved template '{template}'",
                        tmpl_rec["decision_layer"],
                    )
                del self._template_memory[norm_pane][template]

        # 2. Check DB
        try:
            con = get_db_connection(db_path)
            cur = con.execute(
                """
                SELECT safety_reason, decision_layer, strftime('%s', expires_at)
                FROM evaluation_cache
                WHERE cache_key = ? AND is_safe = 1
                """,
                (f"pane_mem:{norm_pane}:{fingerprint}",),
            )
            row = cur.fetchone()
            if row:
                reason, layer, exp_ts = row[0], row[1], row[2]
                if exp_ts and int(exp_ts) > now:
                    # Restore to in-memory
                    with self._memory_lock:
                        self._memory.setdefault(norm_pane, {})[fingerprint] = {
                            "pane_id": norm_pane,
                            "raw_command": raw_cmd.strip(),
                            "cwd": cwd,
                            "decision_layer": layer,
                            "reason": reason,
                            "created_at": now,
                            "expires_at": int(exp_ts),
                        }
                        if template:
                            self._template_memory.setdefault(norm_pane, {})[template] = self._memory[norm_pane][fingerprint]
                    return (True, f"[Session Memory: {norm_pane}] {reason}", layer)
                else:
                    con.execute("DELETE FROM evaluation_cache WHERE cache_key = ?", (f"pane_mem:{norm_pane}:{fingerprint}",))
        except Exception:
            pass

        return None

    def clear(self, pane_id: Optional[str] = None) -> None:
        """Clear memory for a specific pane or all panes."""
        with self._memory_lock:
            if pane_id:
                norm_pane = str(pane_id).strip()
                self._memory.pop(norm_pane, None)
                self._template_memory.pop(norm_pane, None)
            else:
                self._memory.clear()
                self._template_memory.clear()


# Global Singleton Instance
_GLOBAL_PANE_MEMORY = PaneSessionMemory()


def record_pane_approval(
    pane_id: str,
    raw_cmd: str,
    decision_layer: str = "SESSION_MEMORY",
    reason: str = "Previously approved in session",
    cwd: str = "",
    ttl_seconds: int = 3600,
    db_path: Optional[Path] = None,
) -> None:
    """Record an approval in the global pane session memory."""
    _GLOBAL_PANE_MEMORY.record_approval(
        pane_id=pane_id,
        raw_cmd=raw_cmd,
        decision_layer=decision_layer,
        reason=reason,
        cwd=cwd,
        ttl_seconds=ttl_seconds,
        db_path=db_path,
    )


def check_pane_approval(
    pane_id: str,
    raw_cmd: str,
    cwd: str = "",
    db_path: Optional[Path] = None,
) -> Optional[Tuple[bool, str, str]]:
    """Check if command is approved in global pane session memory."""
    return _GLOBAL_PANE_MEMORY.check_approval(
        pane_id=pane_id,
        raw_cmd=raw_cmd,
        cwd=cwd,
        db_path=db_path,
    )


def clear_pane_approval_memory(pane_id: Optional[str] = None) -> None:
    """Clear memory globally or per pane."""
    _GLOBAL_PANE_MEMORY.clear(pane_id)


# Backward compatibility alias
clear_pane_memory = clear_pane_approval_memory
