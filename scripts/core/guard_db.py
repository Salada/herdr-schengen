"""SQLite3 persistence and pattern analysis module for Herdr Schengen (SmartGate).

Stores:
1. audit_logs: Every detected permission request, decision, safety check, and timestamp.
2. pattern_stats: Aggregated frequency and approval count per normalized command template.
3. user_allowlist: Persisted custom approval rules reviewed by human engineers.

Database location: ~/.local/state/herdr-schengen/schengen_history.db (XDG compliant, no skill pollution)
"""

import os
import re
import sqlite3
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

DB_DIR = Path.home() / ".local" / "state" / "herdr-schengen"
DB_PATH = DB_DIR / "schengen_history.db"


def _resolve_log_dir() -> Path:
    """Resolve the operational log directory.

    Follows the Unix convention of logging under /var/log/<name>, but falls back
    to the XDG state dir when /var/log is not writable (e.g. macOS non-root) so
    the daemon never crashes on startup. Honors SCHENGEN_LOG_DIR for
    containerized/test environments.
    """
    candidate = Path(os.environ.get("SCHENGEN_LOG_DIR", "/var/log/herdr-schengen"))
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        probe = candidate / ".writable"
        probe.touch()
        probe.unlink()
        return candidate
    except OSError:
        return DB_DIR


LOG_DIR = _resolve_log_dir()
LOG_FILE = LOG_DIR / "schengen.log"


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Initialize DB directory and connect to SQLite3 database with WAL & busy timeout."""
    target_path = Path(db_path) if db_path else DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db():
    """Create database tables if they do not exist."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.executescript("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            pane_id TEXT NOT NULL,
            agent_kind TEXT,
            raw_command TEXT NOT NULL,
            normalized_pattern TEXT NOT NULL,
            decision TEXT NOT NULL, -- 'AUTO_APPROVED' | 'MANUAL_DELEGATED' | 'ALLOWLIST_BYPASS' | 'SHADOW_BLOCKED'
            safety_reason TEXT NOT NULL,
            decision_layer TEXT DEFAULT 'FAST_TRACK_AST',
            origin TEXT DEFAULT 'A', -- 'H' (Human) | 'A' (Agent) | 'I' (Injected) | 'E' (Emergent)
            consequence TEXT DEFAULT 'NONE', -- 'NONE' | 'DEST' | 'EXFIL' | 'INT' | 'AVAIL' | 'PERS'
            mechanism TEXT DEFAULT 'none',
            gate_state TEXT DEFAULT 'ENFORCE', -- 'ENFORCE' | 'OBSERVE' | 'DEGRADED'
            shadow_mode INTEGER DEFAULT 0 -- 0: false, 1: true
        );

        CREATE TABLE IF NOT EXISTS pattern_stats (
            pattern TEXT PRIMARY KEY,
            total_occurrences INTEGER DEFAULT 1,
            auto_approved_count INTEGER DEFAULT 0,
            delegated_count INTEGER DEFAULT 0,
            last_seen TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_allowlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern_regex TEXT NOT NULL UNIQUE,
            description TEXT,
            created_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS pending_escalations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pane_id TEXT NOT NULL,
            session_id TEXT, -- Unique Herdr Agent Session UUID (e.g. 63be805c-d36e-4767-a0f1-f7ce847987ce)
            agent_kind TEXT DEFAULT 'unknown',
            raw_command TEXT NOT NULL,
            command_hash TEXT NOT NULL,
            safety_reason TEXT NOT NULL,
            decision_layer TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING', -- 'PENDING' | 'DELIVERED' | 'RESOLVED' | 'STALE_EXPIRED' | 'CANCELLED' | 'SESSION_MISMATCH'
            started_at TEXT NOT NULL,
            delivered_at TEXT,
            last_transitioned_at TEXT NOT NULL,
            UNIQUE(pane_id, command_hash)
        );

        CREATE TABLE IF NOT EXISTS evaluation_cache (
            cache_key TEXT PRIMARY KEY,
            raw_command TEXT NOT NULL,
            cwd TEXT,
            scope TEXT,
            agent_id TEXT,
            origin TEXT,
            ruleset_version TEXT,
            is_safe INTEGER NOT NULL,
            safety_reason TEXT NOT NULL,
            decision_layer TEXT NOT NULL,
            taxonomy_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            hit_count INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_pattern ON audit_logs(normalized_pattern);
        CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_escalations(status);
        CREATE INDEX IF NOT EXISTS idx_pending_pane ON pending_escalations(pane_id);
        CREATE INDEX IF NOT EXISTS idx_cache_expires ON evaluation_cache(expires_at);
        """)
        # Migration: Ensure columns exist in older schemas (Idempotent schema evolution)
        cursor.execute("PRAGMA table_info(audit_logs)")
        columns = [c[1] for c in cursor.fetchall()]
        if "decision_layer" not in columns:
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN decision_layer TEXT DEFAULT 'FAST_TRACK_AST'")
        if "origin" not in columns:
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN origin TEXT DEFAULT 'A'")
        if "consequence" not in columns:
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN consequence TEXT DEFAULT 'NONE'")
        if "mechanism" not in columns:
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN mechanism TEXT DEFAULT 'none'")
        if "gate_state" not in columns:
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN gate_state TEXT DEFAULT 'ENFORCE'")
        if "shadow_mode" not in columns:
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN shadow_mode INTEGER DEFAULT 0")

        # Migration: Ensure session_id column exists in pending_escalations
        cursor.execute("PRAGMA table_info(pending_escalations)")
        p_columns = [c[1] for c in cursor.fetchall()]
        if "session_id" not in p_columns:
            cursor.execute("ALTER TABLE pending_escalations ADD COLUMN session_id TEXT")
        if "dialog_snapshot" not in p_columns:
            cursor.execute("ALTER TABLE pending_escalations ADD COLUMN dialog_snapshot TEXT")

        # Create indices after ensuring columns exist
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_layer ON audit_logs(decision_layer);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_origin ON audit_logs(origin);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_consequence ON audit_logs(consequence);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pending_session ON pending_escalations(session_id);")
        conn.commit()


# In-memory true LRU evaluation cache: cache_key -> (is_safe, safety_reason, decision_layer, taxonomy, expiry_timestamp)
_IN_MEMORY_EVAL_CACHE: OrderedDict[str, tuple[bool, str, str, dict[str, Any], float]] = OrderedDict()
_MAX_MEMORY_CACHE_SIZE = 1000


def clear_in_memory_cache():
    """Clear all entries from in-memory cache."""
    _IN_MEMORY_EVAL_CACHE.clear()


def get_cached_evaluation(cache_key: str) -> Optional[dict[str, Any]]:
    """Retrieve cached security evaluation result by cache_key with true LRU ordering."""
    import json

    now_ts = datetime.now(timezone.utc).timestamp()

    # 1. Check in-memory cache first (<0.1ms)
    if cache_key in _IN_MEMORY_EVAL_CACHE:
        is_safe, safety_reason, decision_layer, taxonomy, exp_ts = _IN_MEMORY_EVAL_CACHE[cache_key]
        if exp_ts > now_ts:
            _IN_MEMORY_EVAL_CACHE.move_to_end(cache_key)  # True LRU: move to most recent
            return {
                "cache_key": cache_key,
                "is_safe": is_safe,
                "safety_reason": safety_reason,
                "decision_layer": decision_layer,
                "taxonomy": taxonomy,
                "from_memory": True,
            }
        else:
            _IN_MEMORY_EVAL_CACHE.pop(cache_key, None)

    # 2. Check SQLite persistent cache
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT raw_command, is_safe, safety_reason, decision_layer, taxonomy_json, expires_at, hit_count
                FROM evaluation_cache
                WHERE cache_key = ? AND expires_at > ?
            """,
                (cache_key, now_iso),
            )
            row = cursor.fetchone()
            if row:
                is_safe = bool(row["is_safe"])
                safety_reason = row["safety_reason"]
                decision_layer = row["decision_layer"]
                try:
                    taxonomy = json.loads(row["taxonomy_json"])
                except Exception:
                    taxonomy = {}

                # Update hit count
                cursor.execute(
                    "UPDATE evaluation_cache SET hit_count = hit_count + 1 WHERE cache_key = ?", (cache_key,)
                )
                conn.commit()

                # Populate memory cache with true LRU eviction
                try:
                    exp_dt = datetime.fromisoformat(row["expires_at"])
                    exp_ts = exp_dt.timestamp()
                except Exception:
                    exp_ts = now_ts + 3600.0

                while len(_IN_MEMORY_EVAL_CACHE) >= _MAX_MEMORY_CACHE_SIZE:
                    _IN_MEMORY_EVAL_CACHE.popitem(last=False)  # True LRU: pop least recently used
                _IN_MEMORY_EVAL_CACHE[cache_key] = (is_safe, safety_reason, decision_layer, taxonomy, exp_ts)

                return {
                    "cache_key": cache_key,
                    "is_safe": is_safe,
                    "safety_reason": safety_reason,
                    "decision_layer": decision_layer,
                    "taxonomy": taxonomy,
                    "from_memory": False,
                }
    except Exception:
        pass

    return None


def set_cached_evaluation(
    cache_key: str,
    raw_command: str,
    is_safe: bool,
    safety_reason: str,
    decision_layer: str,
    taxonomy: dict[str, Any],
    cwd: str = "",
    scope: str = "default",
    agent_id: str = "default",
    origin: str = "A",
    ruleset_version: str = "1.0",
    ttl_seconds: int = 3600,
):
    """Store security evaluation result in both in-memory LRU and SQLite persistent cache."""
    import json

    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    exp_dt = now_dt + timedelta(seconds=ttl_seconds)
    exp_iso = exp_dt.isoformat()
    exp_ts = exp_dt.timestamp()

    # 1. Update in-memory LRU cache
    while len(_IN_MEMORY_EVAL_CACHE) >= _MAX_MEMORY_CACHE_SIZE:
        _IN_MEMORY_EVAL_CACHE.popitem(last=False)  # True LRU eviction
    _IN_MEMORY_EVAL_CACHE[cache_key] = (is_safe, safety_reason, decision_layer, taxonomy, exp_ts)
    _IN_MEMORY_EVAL_CACHE.move_to_end(cache_key)

    # 2. Update SQLite persistent cache
    try:
        tax_json = json.dumps(taxonomy)
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO evaluation_cache (
                    cache_key, raw_command, cwd, scope, agent_id, origin,
                    ruleset_version, is_safe, safety_reason, decision_layer,
                    taxonomy_json, created_at, expires_at, hit_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT hit_count FROM evaluation_cache WHERE cache_key = ?), 0))
            """,
                (
                    cache_key,
                    raw_command,
                    cwd,
                    scope,
                    agent_id,
                    origin,
                    ruleset_version,
                    1 if is_safe else 0,
                    safety_reason,
                    decision_layer,
                    tax_json,
                    now_iso,
                    exp_iso,
                    cache_key,
                ),
            )
            conn.commit()
    except Exception:
        pass


def purge_expired_cache_entries() -> int:
    """Purge expired cache rows from SQLite evaluation_cache table."""
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM evaluation_cache WHERE expires_at <= ?", (now_iso,))
            deleted = cursor.rowcount
            conn.commit()
            return deleted
    except Exception:
        return 0


def normalize_command(cmd_str: str) -> str:
    """Normalize specific arguments (hashes, commit msgs, file names) into reusable patterns.

    Example:
    'git commit -m "feat: add doc"' -> 'git commit -m <STRING>'
    '/Users/kyjbusan/foo/bar.py'    -> '<PATH>'
    """
    norm = cmd_str.strip()
    # Normalize quoted strings
    norm = re.sub(r'["\'][^"\']*["\']', "<STRING>", norm)
    # Normalize absolute paths
    norm = re.sub(r"/(Users|home)/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_.-]+)+", "<PATH>", norm)
    # Normalize hex hashes
    norm = re.sub(r"\b[0-9a-f]{7,40}\b", "<HASH>", norm)
    # Collapse multiple whitespaces
    norm = re.sub(r"\s+", " ", norm)
    return norm


def record_audit_log(
    pane_id: str,
    raw_command: str,
    decision: str,
    safety_reason: str,
    agent_kind: Optional[str] = "unknown",
    decision_layer: str = "FAST_TRACK_AST",
    origin: str = "A",
    consequence: str = "NONE",
    mechanism: str = "none",
    gate_state: str = "ENFORCE",
    shadow_mode: bool = False,
):
    """Record an audit entry with 2D Taxonomy and update pattern frequency statistics."""
    init_db()
    norm_pattern = normalize_command(raw_command)
    now_iso = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        # 1. Insert audit log
        cursor.execute(
            """
            INSERT INTO audit_logs (
                timestamp, pane_id, agent_kind, raw_command, normalized_pattern,
                decision, safety_reason, decision_layer, origin, consequence,
                mechanism, gate_state, shadow_mode
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                now_iso,
                pane_id,
                agent_kind,
                raw_command,
                norm_pattern,
                decision,
                safety_reason,
                decision_layer,
                origin,
                consequence,
                mechanism,
                gate_state,
                1 if shadow_mode else 0,
            ),
        )

        # 2. Upsert pattern frequency stats
        cursor.execute(
            """
            INSERT INTO pattern_stats (pattern, total_occurrences, auto_approved_count, delegated_count, last_seen)
            VALUES (?, 1, ?, ?, ?)
            ON CONFLICT(pattern) DO UPDATE SET
                total_occurrences = total_occurrences + 1,
                auto_approved_count = auto_approved_count + ?,
                delegated_count = delegated_count + ?,
                last_seen = ?
        """,
            (
                norm_pattern,
                1 if decision in ("AUTO_APPROVED", "ALLOWLIST_BYPASS") else 0,
                1 if decision == "MANUAL_DELEGATED" else 0,
                now_iso,
                1 if decision in ("AUTO_APPROVED", "ALLOWLIST_BYPASS") else 0,
                1 if decision == "MANUAL_DELEGATED" else 0,
                now_iso,
            ),
        )
        conn.commit()


def get_pattern_analysis() -> list[dict]:
    """Retrieve frequency and recommendation stats for human review."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT pattern, total_occurrences, auto_approved_count, delegated_count, last_seen
            FROM pattern_stats
            ORDER BY total_occurrences DESC
        """)
        return [dict(row) for row in cursor.fetchall()]


def check_persisted_allowlist(cmd_str: str) -> tuple[bool, Optional[str]]:
    """Check if command matches any human-persisted allowlist regex."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT pattern_regex, description FROM user_allowlist WHERE" " is_active = 1")
        for row in cursor.fetchall():
            pat = row["pattern_regex"]
            if re.search(pat, cmd_str):
                return True, f"Matched User Allowlist: {row['description'] or pat}"
    return False, None


def add_to_allowlist(pattern_regex: str, description: str = ""):
    """Add a verified pattern to the persistent allowlist with safety validation."""
    init_db()
    pat_stripped = pattern_regex.strip()
    dangerous_catch_alls = {".*", ".+", "^.*$", "^.+$", ".*?", ".+?", "^.*", ".*$"}
    if pat_stripped in dangerous_catch_alls or len(pat_stripped) < 3:
        raise ValueError(f"Overbroad or dangerous allowlist pattern rejected: '{pattern_regex}'")

    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO user_allowlist (pattern_regex, description, created_at, is_active)
            VALUES (?, ?, ?, 1)
        """,
            (pattern_regex, description, now_iso),
        )
        conn.commit()


def get_recent_audit_logs(
    limit: int = 10,
    decision: Optional[str] = None,
    pane_id: Optional[str] = None,
    layer: Optional[str] = None,
) -> list[dict]:
    """Retrieve recent audit events from SQLite3 database with flexible filtering."""
    init_db()
    query = "SELECT id, timestamp, pane_id, agent_kind, raw_command, normalized_pattern, decision, safety_reason, COALESCE(decision_layer, 'FAST_TRACK_AST') as decision_layer FROM audit_logs WHERE 1=1"
    params = []

    if decision:
        query += " AND decision = ?"
        params.append(decision.upper())
    if pane_id:
        query += " AND pane_id = ?"
        params.append(pane_id)
    if layer:
        query += " AND UPPER(decision_layer) = ?"
        params.append(layer.upper())

    query += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, limit))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]


def search_audit_logs(keyword: str, limit: int = 20) -> list[dict]:
    """Search audit logs by keyword across raw_command, pattern, reason, or layer."""
    init_db()
    query = """
        SELECT id, timestamp, pane_id, agent_kind, raw_command, normalized_pattern, decision, safety_reason, COALESCE(decision_layer, 'FAST_TRACK_AST') as decision_layer
        FROM audit_logs
        WHERE raw_command LIKE ? OR safety_reason LIKE ? OR normalized_pattern LIKE ? OR decision_layer LIKE ?
        ORDER BY id DESC LIMIT ?
    """
    pattern = f"%{keyword}%"
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, (pattern, pattern, pattern, pattern, max(1, limit)))
        return [dict(row) for row in cursor.fetchall()]


def get_state_file_paths() -> dict[str, str]:
    """Return dictionary of all SmartGate / Schengen state and database paths."""
    return {
        "state_dir": str(DB_DIR),
        "db_path": str(DB_PATH),
        "lock_file": str(DB_DIR / "schengen.lock"),
        "log_file": str(LOG_FILE),
        "log_dir": str(LOG_DIR),
    }


def enqueue_pending_escalation(
    pane_id: str,
    raw_command: str,
    safety_reason: str,
    decision_layer: str,
    agent_kind: str = "unknown",
    session_id: Optional[str] = None,
    dialog_snapshot: Optional[str] = None,
) -> int:
    """Enqueue a blocked dangerous command into persistent escalations queue (At-Least-Once)."""
    import hashlib

    init_db()
    cmd_hash = hashlib.sha256(raw_command.encode("utf-8")).hexdigest()[:16]
    now_iso = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO pending_escalations (
                pane_id, session_id, agent_kind, raw_command, command_hash, safety_reason, decision_layer, dialog_snapshot, status, started_at, last_transitioned_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)
            ON CONFLICT(pane_id, command_hash) DO UPDATE SET
                session_id = excluded.session_id,
                status = 'PENDING',
                safety_reason = excluded.safety_reason,
                decision_layer = excluded.decision_layer,
                dialog_snapshot = excluded.dialog_snapshot,
                last_transitioned_at = excluded.last_transitioned_at
        """,
            (pane_id, session_id, agent_kind, raw_command, cmd_hash, safety_reason, decision_layer, dialog_snapshot, now_iso, now_iso),
        )
        last_id = cursor.lastrowid
        if not last_id:
            cursor.execute(
                "SELECT id FROM pending_escalations WHERE pane_id = ? AND command_hash = ?", (pane_id, cmd_hash)
            )
            row = cursor.fetchone()
            last_id = row["id"] if row else 0
        conn.commit()
        return last_id


def get_pending_escalations(
    pane_id: Optional[str] = None,
    include_delivered: bool = False,
    active_session_map: Optional[dict[str, Optional[str]]] = None,
) -> list[dict]:
    """Retrieve active pending escalations.

    If active_session_map is provided (mapping pane_id -> current_session_uuid):
    - Verifies whether the pane is still alive. If dead, marks PANE_DEAD / CANCELLED.
    - Verifies whether the session UUID matches. If mismatched (e.g. pane recycled days later),
      marks SESSION_MISMATCH and filters it out automatically.
    """
    init_db()
    statuses = "('PENDING', 'DELIVERED')" if include_delivered else "('PENDING')"
    query = f"SELECT id, pane_id, session_id, agent_kind, raw_command, command_hash, safety_reason, decision_layer, dialog_snapshot, status, started_at, delivered_at, last_transitioned_at FROM pending_escalations WHERE status IN {statuses}"
    params = []
    if pane_id:
        query += " AND pane_id = ?"
        params.append(pane_id)
    query += " ORDER BY id ASC"

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]

    if active_session_map is None:
        return rows

    valid_escalations = []
    mismatched_ids = []
    dead_pane_ids = []

    for r in rows:
        pid = r["pane_id"]
        expected_session = r.get("session_id")

        if pid not in active_session_map:
            # Pane no longer exists in Herdr
            dead_pane_ids.append(r["id"])
            continue

        current_session = active_session_map.get(pid)
        # If both records have session UUIDs and they do not match, it's a recycled pane / ghost session
        if expected_session and current_session and expected_session != current_session:
            mismatched_ids.append(r["id"])
            continue

        valid_escalations.append(r)

    if mismatched_ids:
        cleanup_escalations(
            escalation_ids=mismatched_ids,
            new_status="SESSION_MISMATCH",
            reason="Herdr pane was recycled with a new agent session UUID",
        )

    if dead_pane_ids:
        cleanup_escalations(
            escalation_ids=dead_pane_ids, new_status="CANCELLED", reason="Herdr pane closed or terminated"
        )

    return valid_escalations


def mark_escalation_delivered(escalation_id: int):
    """Mark an escalation as delivered to the agent/user interface."""
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE pending_escalations
            SET status = 'DELIVERED', delivered_at = ?, last_transitioned_at = ?
            WHERE id = ? AND status = 'PENDING'
        """,
            (now_iso, now_iso, escalation_id),
        )
        conn.commit()


def resolve_escalation(
    pane_id: str,
    command_hash: Optional[str] = None,
    escalation_id: Optional[int] = None,
    resolution_status: str = "RESOLVED",
    is_approval: bool = False,
):
    """Mark escalation(s) as resolved or cancelled after user/agent action (ACK)."""
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        approved_cmds: list[tuple[str, str]] = []
        if resolution_status == "RESOLVED" and is_approval:
            # Fetch raw commands to record in pane session memory only on explicit approval
            if escalation_id:
                cursor.execute("SELECT pane_id, raw_command FROM pending_escalations WHERE id = ?", (escalation_id,))
            elif command_hash:
                cursor.execute("SELECT pane_id, raw_command FROM pending_escalations WHERE pane_id = ? AND command_hash = ?", (pane_id, command_hash))
            else:
                cursor.execute("SELECT pane_id, raw_command FROM pending_escalations WHERE pane_id = ? AND status IN ('PENDING', 'DELIVERED')", (pane_id,))
            approved_cmds = [(row["pane_id"], row["raw_command"]) for row in cursor.fetchall()]

        if escalation_id:
            cursor.execute(
                """
                UPDATE pending_escalations
                SET status = ?, last_transitioned_at = ?
                WHERE id = ?
            """,
                (resolution_status, now_iso, escalation_id),
            )
        elif command_hash:
            cursor.execute(
                """
                UPDATE pending_escalations
                SET status = ?, last_transitioned_at = ?
                WHERE pane_id = ? AND command_hash = ? AND status IN ('PENDING', 'DELIVERED')
            """,
                (resolution_status, now_iso, pane_id, command_hash),
            )
        else:
            cursor.execute(
                """
                UPDATE pending_escalations
                SET status = ?, last_transitioned_at = ?
                WHERE pane_id = ? AND status IN ('PENDING', 'DELIVERED')
            """,
                (resolution_status, now_iso, pane_id),
            )
        conn.commit()

        # Record in PaneSessionMemory for fast-path 0.1ms approval ONLY on explicit approval
        if approved_cmds:
            try:
                from core.session_memory import record_pane_approval
                for p_id, raw_c in approved_cmds:
                    record_pane_approval(p_id, raw_c, decision_layer="HUMAN_APPROVAL", reason="Approved by human operator")
            except Exception:
                pass


def cleanup_escalations(
    escalation_ids: Optional[list[int]] = None,
    pane_id: Optional[str] = None,
    older_than_hours: Optional[float] = None,
    new_status: str = "STALE_EXPIRED",
    purge_deleted: bool = False,
    reason: str = "",
) -> int:
    """Clean up stale or cancelled escalations by transitioning status or purging old resolved rows."""
    init_db()
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        if purge_deleted:
            # Purge terminal status rows older than 7 days
            cutoff_iso = (now - timedelta(days=7)).isoformat()
            cursor.execute(
                """
                DELETE FROM pending_escalations
                WHERE status IN ('RESOLVED', 'STALE_EXPIRED', 'CANCELLED')
                  AND last_transitioned_at < ?
            """,
                (cutoff_iso,),
            )
            deleted = cursor.rowcount
            conn.commit()
            return deleted

        if escalation_ids:
            placeholders = ",".join("?" * len(escalation_ids))
            cursor.execute(
                f"""
                UPDATE pending_escalations
                SET status = ?, last_transitioned_at = ?
                WHERE id IN ({placeholders})
            """,
                [new_status, now_iso] + escalation_ids,
            )
            affected = cursor.rowcount
            conn.commit()
            return affected

        if older_than_hours is not None:
            cutoff_iso = (now - timedelta(hours=older_than_hours)).isoformat()
            cursor.execute(
                """
                UPDATE pending_escalations
                SET status = ?, last_transitioned_at = ?
                WHERE status IN ('PENDING', 'DELIVERED')
                  AND started_at < ?
            """,
                (new_status, now_iso, cutoff_iso),
            )
            affected = cursor.rowcount
            conn.commit()
            return affected

        if pane_id:
            cursor.execute(
                """
                UPDATE pending_escalations
                SET status = ?, last_transitioned_at = ?
                WHERE pane_id = ? AND status IN ('PENDING', 'DELIVERED')
            """,
                (new_status, now_iso, pane_id),
            )
            affected = cursor.rowcount
            conn.commit()
            return affected

    return 0


def tail_state_log(lines: int = 20) -> list[str]:
    """Safely retrieve the last N lines of the schengen log file without spawning shell subshells."""
    log_file = LOG_FILE
    if not log_file.exists():
        return []
    try:
        with open(log_file, encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
            return all_lines[-max(1, lines) :]
    except Exception as e:
        return [f"Error reading log file: {e}\n"]


def get_session_dashboard_summary(
    pane_id: Optional[str] = None,
    audit_limit: int = 10,
    escalation_limit: int = 5,
    include_terminal_escalations: bool = True,
) -> dict[str, Any]:
    """Retrieve full dashboard summary for UI rendering: audit history (10) + escalations (5)."""
    init_db()

    # 1. Audit logs (most recent audit_limit items)
    recent_audits = get_recent_audit_logs(limit=audit_limit, pane_id=pane_id)

    # 2. Escalation timeline (both pending and recent resolved/cancelled, up to escalation_limit)
    escalations = []
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if include_terminal_escalations:
            query = """
                SELECT id, pane_id, session_id, agent_kind, raw_command, command_hash,
                       safety_reason, decision_layer, status, started_at, delivered_at, last_transitioned_at
                FROM pending_escalations
            """
            params = []
            if pane_id:
                query += " WHERE pane_id = ?"
                params.append(pane_id)
            query += " ORDER BY id DESC LIMIT ?"
            params.append(escalation_limit)
        else:
            query = """
                SELECT id, pane_id, session_id, agent_kind, raw_command, command_hash,
                       safety_reason, decision_layer, status, started_at, delivered_at, last_transitioned_at
                FROM pending_escalations
                WHERE status IN ('PENDING', 'DELIVERED')
            """
            params = []
            if pane_id:
                query += " AND pane_id = ?"
                params.append(pane_id)
            query += " ORDER BY id DESC LIMIT ?"
            params.append(escalation_limit)

        cursor.execute(query, params)
        escalations = [dict(r) for r in cursor.fetchall()]

    return {
        "pane_id": pane_id,
        "recent_audits": recent_audits,
        "escalations": escalations,
    }


if __name__ == "__main__":
    import argparse
    import json
    import sys

    init_db()
    parser = argparse.ArgumentParser(description="Herdr SmartGate / Schengen Audit DB CLI")
    parser.add_argument(
        "--recent", "-n", type=int, nargs="?", const=10, default=None, help="Display recent audit logs (default: 10)"
    )
    parser.add_argument("--search", "-s", type=str, help="Search audit logs by keyword")
    parser.add_argument(
        "--tail", "-t", type=int, nargs="?", const=20, default=None, help="Tail schengen.log file (default: 20 lines)"
    )
    parser.add_argument("--paths", "--find-state", action="store_true", help="Print SmartGate state file paths")
    parser.add_argument("--stats", action="store_true", help="Display pattern analysis stats from DB and exit")
    parser.add_argument("--layer", type=str, help="Filter by decision layer (e.g. SECRET_GUARD, SHELL_CRITICAL)")
    parser.add_argument(
        "--decision", type=str, help="Filter by decision (AUTO_APPROVED, MANUAL_DELEGATED, ALLOWLIST_BYPASS)"
    )
    parser.add_argument("--json", action="store_true", help="Output results in JSON format for agent parsing")

    args = parser.parse_args()

    if args.paths:
        paths = get_state_file_paths()
        if args.json:
            print(json.dumps(paths, indent=2))
        else:
            print("🗂️  SmartGate / Herdr Schengen State Paths:")
            for k, v in paths.items():
                print(f"  • {k:<12}: {v}")
        sys.exit(0)

    if args.tail is not None:
        log_lines = tail_state_log(args.tail)
        if args.json:
            print(json.dumps({"lines": log_lines}, indent=2))
        else:
            print(f"📜 Last {len(log_lines)} lines of schengen.log:")
            print("".join(log_lines), end="")
        sys.exit(0)

    if args.stats:
        stats = get_pattern_analysis()
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            print("\n📊 Herdr Schengen - Pattern Analysis & Review Board")
            print("=" * 80)
            if not stats:
                print("No command patterns recorded yet.")
            for row in stats:
                print(
                    f"• Frequency: {row['total_occurrences']} (Approved:"
                    f" {row['auto_approved_count']}, Delegated:"
                    f" {row['delegated_count']})"
                )
                print(f"  Pattern: {row['pattern']}")
                print(f"  Last Seen: {row['last_seen']}")
                print("-" * 80)
        sys.exit(0)

    if args.search:
        results = search_audit_logs(args.search)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(f"🔍 Search results for '{args.search}' ({len(results)} found):")
            for r in results:
                symbol = "✅" if r["decision"] in ("AUTO_APPROVED", "ALLOWLIST_BYPASS") else "🚨"
                print(
                    f"{symbol} [{r['timestamp'][:19]}] #{r['id']} {r['pane_id']} - {r['decision']} [Layer: {r['decision_layer']}] ({r['safety_reason']})"
                )
                print(f"   Cmd: {r['raw_command']}")
        sys.exit(0)

    if args.recent is not None or len(sys.argv) == 1:
        limit = args.recent if args.recent is not None else 10
        logs = get_recent_audit_logs(limit=limit, decision=args.decision, layer=args.layer)
        if args.json:
            print(json.dumps(logs, indent=2))
        else:
            print(f"📜 Recent SmartGate Audit Events (Limit: {limit}):")
            print("=" * 90)
            if not logs:
                print("   (No audit events found matching criteria)")
            for r in logs:
                symbol = "✅" if r["decision"] in ("AUTO_APPROVED", "ALLOWLIST_BYPASS") else "🚨"
                cmd_prev = (r["raw_command"][:70] + "...") if len(r["raw_command"]) > 70 else r["raw_command"]
                print(
                    f"{symbol} [{r['timestamp'][:19]}] #{r['id']:<3} {r['pane_id']:<6} | {r['decision']:<16} | Layer: {r['decision_layer']:<16}"
                )
                print(f"   Reason: {r['safety_reason']}")
                print(f"   Cmd   : {cmd_prev}")
                print("-" * 90)
        sys.exit(0)
