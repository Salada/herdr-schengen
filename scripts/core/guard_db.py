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
import threading
import time
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
            shadow_mode INTEGER DEFAULT 0, -- 0: false, 1: true
            scope_context TEXT DEFAULT 'SESSION_TRANSIENT' -- 'GLOBAL_RULE' | 'SESSION_TRANSIENT' | 'REPO_LOCAL'
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
            cwd TEXT, -- workspace cwd at interception (issue #7207 auto-promotion)
            origin TEXT, -- command author origin (A/H/I/E) at interception (INV-WS-3 promotion gate)
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

        CREATE TABLE IF NOT EXISTS guard_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS adjudication_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            escalation_id INTEGER,
            pane_id TEXT,
            agent_kind TEXT,
            action TEXT NOT NULL, -- 'APPROVE' | 'REJECT'
            feedback TEXT,
            created_at TEXT NOT NULL
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
        if "scope_context" not in columns:
            cursor.execute(
                "ALTER TABLE audit_logs ADD COLUMN scope_context TEXT DEFAULT 'SESSION_TRANSIENT'"
            )

        # Migration: Ensure session_id column exists in pending_escalations
        cursor.execute("PRAGMA table_info(pending_escalations)")
        p_columns = [c[1] for c in cursor.fetchall()]
        if "session_id" not in p_columns:
            cursor.execute("ALTER TABLE pending_escalations ADD COLUMN session_id TEXT")
        if "dialog_snapshot" not in p_columns:
            cursor.execute("ALTER TABLE pending_escalations ADD COLUMN dialog_snapshot TEXT")
        if "resolution" not in p_columns:
            cursor.execute("ALTER TABLE pending_escalations ADD COLUMN resolution TEXT")
        if "approver" not in p_columns:
            cursor.execute("ALTER TABLE pending_escalations ADD COLUMN approver TEXT")
        if "cwd" not in p_columns:
            cursor.execute("ALTER TABLE pending_escalations ADD COLUMN cwd TEXT")
        if "origin" not in p_columns:
            cursor.execute("ALTER TABLE pending_escalations ADD COLUMN origin TEXT")

        # Create indices after ensuring columns exist
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_layer ON audit_logs(decision_layer);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_origin ON audit_logs(origin);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_consequence ON audit_logs(consequence);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pending_session ON pending_escalations(session_id);")
        conn.commit()


# In-memory true LRU evaluation cache: cache_key -> (is_safe, safety_reason, decision_layer, taxonomy, expiry_timestamp)
_IN_MEMORY_EVAL_CACHE: OrderedDict[str, tuple[bool, str, str, dict[str, Any], float]] = OrderedDict()
_EVAL_CACHE_LOCK = threading.RLock()
_MAX_MEMORY_CACHE_SIZE = 1000


def clear_in_memory_cache():
    """Clear all entries from in-memory cache."""
    with _EVAL_CACHE_LOCK:
        _IN_MEMORY_EVAL_CACHE.clear()


def get_cached_evaluation(cache_key: str) -> Optional[dict[str, Any]]:
    """Retrieve cached security evaluation result by cache_key with true LRU ordering."""
    import json

    now_ts = datetime.now(timezone.utc).timestamp()

    # 1. Check in-memory cache first (<0.1ms)
    with _EVAL_CACHE_LOCK:
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

                with _EVAL_CACHE_LOCK:
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
    with _EVAL_CACHE_LOCK:
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


# INV-7: fold version specifiers to a canonical <VER> token (npm/cargo/gem `@ver`, pip `==ver`)
_VERSION_AT_RE = re.compile(r"@(?:[0-9][0-9A-Za-z.+-]*|latest|next|beta|alpha|rc[0-9]*|canary|dev|stable)\b")
_VERSION_EQ_RE = re.compile(r"(==|>=|<=|~=|!=)\s*[0-9][0-9A-Za-z.+-]*")


def normalize_command(cmd_str: str) -> str:
    """Normalize specific arguments (hashes, commit msgs, file names) into reusable patterns.

    Example:
    'git commit -m "feat: add doc"' -> 'git commit -m <STRING>'
    '/Users/kyjbusan/foo/bar.py'    -> '<PATH>'
    'pkg@2.45.0' / 'pkg==2.45.0'    -> 'pkg@<VER>' / 'pkg==<VER>' (INV-7)
    """
    norm = cmd_str.strip()
    # Normalize quoted strings
    norm = re.sub(r'["\'][^"\']*["\']', "<STRING>", norm)
    # Normalize absolute paths
    norm = re.sub(r"/(Users|home)/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_.-]+)+", "<PATH>", norm)
    # Normalize hex hashes
    norm = re.sub(r"\b[0-9a-f]{7,40}\b", "<HASH>", norm)
    # INV-7: fold version specifiers to a canonical <VER> token (npm/cargo/gem `@ver`,
    # pip `==ver`). Bare `@main` (git branch) is NOT folded: not in the tag list and
    # does not start with a digit. Applied BEFORE the final whitespace collapse so
    # `pkg== 2.31.0` and `pkg==2.31.1` both become `pkg==<VER>`.
    norm = _VERSION_AT_RE.sub("@<VER>", norm)
    norm = _VERSION_EQ_RE.sub(r"\1<VER>", norm)
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
    scope_context: str = "SESSION_TRANSIENT",
):
    """Record an audit entry with 2D Taxonomy and update pattern frequency statistics.

    scope_context: 'GLOBAL_RULE' | 'SESSION_TRANSIENT' | 'REPO_LOCAL' (issue
    #7207 — REPO_LOCAL marks workspace .schengen/ allowlist auto-promotions).
    """
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
                mechanism, gate_state, shadow_mode, scope_context
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                scope_context,
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
    """Retrieve recent audit events from SQLite3 database with flexible filtering.

    Each row also carries the escalation ``resolution`` (APPROVED / REJECTED /
    UNANSWERED / None) via a LEFT JOIN on pending_escalations (pane_id + raw_command),
    so the TUI can display the post-escalation processing status for ESCALATED records.
    """
    init_db()
    query = """
        SELECT a.id, a.timestamp, a.pane_id, a.agent_kind, a.raw_command, a.normalized_pattern,
               a.decision, a.safety_reason, COALESCE(a.decision_layer, 'FAST_TRACK_AST') AS decision_layer,
               pe.resolution AS resolution,
               pe.approver AS approver
        FROM audit_logs a
        LEFT JOIN pending_escalations pe ON pe.pane_id = a.pane_id AND pe.raw_command = a.raw_command
        WHERE 1=1
    """
    params = []

    if decision:
        query += " AND a.decision = ?"
        params.append(decision.upper())
    if pane_id:
        query += " AND a.pane_id = ?"
        params.append(pane_id)
    if layer:
        query += " AND UPPER(a.decision_layer) = ?"
        params.append(layer.upper())

    query += " ORDER BY a.id DESC LIMIT ?"
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


def get_audit_log_by_id(audit_id: int) -> Optional[dict]:
    """Fetch the full audit record by its ID."""
    init_db()
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM audit_logs WHERE id = ?", (audit_id,)).fetchone()
    return dict(row) if row else None


def get_escalation_resolution(pane_id: str, raw_command: str) -> Optional[str]:
    """Return the post-escalation resolution (APPROVED/REJECTED/UNANSWERED) for a command."""
    init_db()
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT resolution FROM pending_escalations WHERE pane_id = ? AND raw_command = ? ORDER BY id DESC LIMIT 1",
            (pane_id, raw_command),
        ).fetchone()
    return row["resolution"] if row else None


def get_escalation_approver(pane_id: str, raw_command: str) -> Optional[str]:
    """Return the approver (machine/human-tui/other) for a command's escalation."""
    init_db()
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT approver FROM pending_escalations WHERE pane_id = ? AND raw_command = ? ORDER BY id DESC LIMIT 1",
            (pane_id, raw_command),
        ).fetchone()
    return row["approver"] if row else None


def record_human_approval_pattern(canonical_pattern: str, scope: str = "default") -> None:
    """Record a canonical command pattern that a HUMAN explicitly approved (INV-3).

    Stores a row in `evaluation_cache` keyed by `human_approved:{scope}:{pattern}`
    (M7: the cwd dimension is dropped — the novelty gate previously seeded with
    cwd="" but queried with the real cwd, so the keys never matched and the
    HUMAN_APPROVED fast-path was dead). TTL is configurable via
    human_approval_ttl_seconds (default 3600s, clamp [60, 86400]). INV-4 is
    satisfied by construction: the `human_approved:` prefix has no legacy rows,
    so the learned-safe set starts EMPTY.
    """
    init_db()
    norm_scope = str(scope).strip() or "default"
    cache_key = f"human_approved:{norm_scope}:{canonical_pattern}"
    ttl = int(get_batch_approval_config().get("human_approval_ttl_seconds", 3600))
    now = time.time()
    expires_at = int(now + ttl)

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO evaluation_cache (
                cache_key, raw_command, is_safe, safety_reason, decision_layer,
                taxonomy_json, cwd, scope, agent_id, origin, ruleset_version,
                created_at, expires_at
            ) VALUES (?, ?, 1, 'human-approved-pattern', 'HUMAN_APPROVED', '{}', ?, ?, 'default', 'H', 'novelty-gate', datetime('now'), datetime(?, 'unixepoch'))
            ON CONFLICT(cache_key) DO UPDATE SET
                is_safe=1,
                expires_at=excluded.expires_at
            """,
            (cache_key, canonical_pattern, "", norm_scope, expires_at),
        )
        conn.commit()


def has_human_approval_pattern(canonical_pattern: str, scope: str = "default") -> bool:
    """Return True if the canonical pattern has a valid (unexpired) human approval in scope."""
    init_db()
    norm_scope = str(scope).strip() or "default"
    cache_key = f"human_approved:{norm_scope}:{canonical_pattern}"
    now = time.time()

    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT strftime('%s', expires_at) AS exp FROM evaluation_cache WHERE cache_key = ? AND is_safe = 1",
            (cache_key,),
        ).fetchone()
    if row is None or row["exp"] is None:
        return False
    return int(row["exp"]) > now


def get_adjudications_for_audit(
    pane_id: str,
    raw_command: str,
    limit: int = 20,
) -> list[dict]:
    """Return past adjudication opinions (feedback) joined to an audit record.

    Joins `adjudication_log` -> `pending_escalations` (via escalation_id) -> the
    audit record (via pane_id + raw_command) so the TUI detail view can show the
    gatekeeper's past approve/reject opinions for a specific intercepted command.
    """
    init_db()
    query = """
        SELECT al.id, al.escalation_id, al.pane_id, al.agent_kind, al.action, al.feedback, al.created_at
        FROM adjudication_log al
        JOIN pending_escalations pe ON pe.id = al.escalation_id
        WHERE pe.pane_id = ? AND pe.raw_command = ?
        ORDER BY al.id DESC
        LIMIT ?
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, (pane_id, raw_command, max(1, limit)))
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


_INSTRUCTION_CONFIG_DEFAULTS = {
    "send_approve_instruction": False,
    "send_reject_instruction": True,
}


def _parse_bool(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def get_instruction_delivery_config() -> dict[str, bool]:
    """Return the instruction-delivery config: whether to send the gatekeeper
    feedback (instruction) to the target pane on approve/reject.

    Defaults: send_approve_instruction=False (do NOT pollute the agent prompt on
    approve), send_reject_instruction=True (explain why a command was rejected).
    Backed by the `guard_config` table; missing keys fall back to the defaults.
    """
    init_db()
    config = dict(_INSTRUCTION_CONFIG_DEFAULTS)
    with get_db_connection() as conn:
        rows = conn.execute("SELECT key, value FROM guard_config").fetchall()
        for row in rows:
            if row["key"] in config:
                config[row["key"]] = _parse_bool(row["value"])
    return config


def set_instruction_delivery_config(
    send_approve_instruction: Optional[bool] = None,
    send_reject_instruction: Optional[bool] = None,
) -> dict[str, bool]:
    """Update instruction-delivery config keys (None = leave unchanged). Returns the new config."""
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    updates = {}
    if send_approve_instruction is not None:
        updates["send_approve_instruction"] = "true" if send_approve_instruction else "false"
    if send_reject_instruction is not None:
        updates["send_reject_instruction"] = "true" if send_reject_instruction else "false"
    if updates:
        with get_db_connection() as conn:
            for key, value in updates.items():
                conn.execute(
                    """
                    INSERT INTO guard_config (key, value, updated_at) VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                    """,
                    (key, value, now_iso),
                )
            conn.commit()
    return get_instruction_delivery_config()


_ANSWER_LANGUAGE_DEFAULT = "korean"
_ANSWER_LANGUAGE_OPTIONS = ("english", "korean", "japanese")


def get_answer_language() -> str:
    """Return the configured answer language for the TUI chat (english/korean/japanese)."""
    init_db()
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT value FROM guard_config WHERE key = 'answer_language'"
        ).fetchone()
    if row and str(row["value"]).strip().lower() in _ANSWER_LANGUAGE_OPTIONS:
        return str(row["value"]).strip().lower()
    return _ANSWER_LANGUAGE_DEFAULT


def set_answer_language(language: str) -> str:
    """Persist the answer language (english/korean/japanese). Returns the normalized value."""
    init_db()
    lang = str(language).strip().lower()
    if lang not in _ANSWER_LANGUAGE_OPTIONS:
        lang = _ANSWER_LANGUAGE_DEFAULT
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO guard_config (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            ("answer_language", lang, now_iso),
        )
        conn.commit()
    return lang


_CHANNEL_APPROVE_DEFAULT = False


def get_channel_approve_config() -> bool:
    """Return whether programmatic permission.reply approval (channel_approve) is enabled.

    When True, the watcher writes an approve/reject decision bound to the exact
    permission_id and the opencode host plugin replies via client.permission
    (issue #57 full closure). When False, the watcher falls back to keystroke
    injection (send-keys enter). Backed by the `guard_config` table — no longer a
    transient env var (issue #114), so the TUI is the single toggle surface and
    the daemon reads a consistent value regardless of spawn path.
    """
    init_db()
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT value FROM guard_config WHERE key = 'channel_approve'"
        ).fetchone()
    if row is not None:
        return _parse_bool(row["value"])
    return _CHANNEL_APPROVE_DEFAULT


def set_channel_approve_config(enabled: bool) -> bool:
    """Persist the channel_approve (permission.reply) opt-in. Returns the new value."""
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO guard_config (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            ("channel_approve", "true" if enabled else "false", now_iso),
        )
        conn.commit()
    return bool(enabled)


_COMPLEXITY_TAX_DEFAULTS = {
    "complexity_tax_enabled": True,
    "complexity_threshold": 6,
    "complexity_mode": "escalate",  # "escalate" | "judge" (judge reserved for M6)
}


def get_complexity_tax_config() -> dict[str, Any]:
    """Complexity-tax knobs, backed by guard_config. Missing keys -> defaults.
    threshold stored as string; coerce to int, clamp to [1, 10000]."""
    init_db()
    cfg = dict(_COMPLEXITY_TAX_DEFAULTS)
    with get_db_connection() as conn:
        for row in conn.execute("SELECT key, value FROM guard_config").fetchall():
            k, v = row["key"], row["value"]
            if k == "complexity_tax_enabled":
                cfg[k] = _parse_bool(v)
            elif k == "complexity_threshold":
                try:
                    cfg[k] = max(1, min(10000, int(v)))
                except (TypeError, ValueError):
                    pass
            elif k == "complexity_mode":
                if str(v).strip().lower() in ("escalate", "judge"):
                    cfg[k] = str(v).strip().lower()
    return cfg


def set_complexity_tax_config(enabled=None, threshold=None, mode=None) -> dict[str, Any]:
    """Human-only write path (TUI settings modal); returns the new config.
    Mirror the set_answer_language / set_channel_approve_config upsert pattern."""
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection() as conn:
        if enabled is not None:
            conn.execute(
                """
                INSERT INTO guard_config (key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                ("complexity_tax_enabled", "true" if _parse_bool(enabled) else "false", now_iso),
            )
        if threshold is not None:
            try:
                clamped = max(1, min(10000, int(threshold)))
            except (TypeError, ValueError):
                clamped = int(_COMPLEXITY_TAX_DEFAULTS["complexity_threshold"])
            conn.execute(
                """
                INSERT INTO guard_config (key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                ("complexity_threshold", str(clamped), now_iso),
            )
        if mode is not None:
            m = str(mode).strip().lower()
            if m in ("escalate", "judge"):
                conn.execute(
                    """
                    INSERT INTO guard_config (key, value, updated_at) VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                    """,
                    ("complexity_mode", m, now_iso),
                )
        conn.commit()
    return get_complexity_tax_config()


_ORIGIN_WEIGHTING_DEFAULTS = {"origin_weighting_enabled": True}


def get_origin_weighting_config() -> dict[str, bool]:
    """M5 origin-weighting toggle. Controls ONLY the HUMAN trust concession
    (skip complexity tax). The INJECTED/EMERGENT hard-escalate is unconditional
    and NOT gated by this knob."""
    init_db()
    cfg = dict(_ORIGIN_WEIGHTING_DEFAULTS)
    with get_db_connection() as conn:
        for row in conn.execute("SELECT key, value FROM guard_config").fetchall():
            if row["key"] == "origin_weighting_enabled":
                cfg["origin_weighting_enabled"] = _parse_bool(row["value"])
    return cfg


def set_origin_weighting_config(enabled: Optional[bool] = None) -> dict[str, bool]:
    """Human-only write path; mirror set_channel_approve_config upsert."""
    init_db()
    if enabled is not None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            conn.execute(
                "INSERT INTO guard_config (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                ("origin_weighting_enabled", "true" if _parse_bool(enabled) else "false", now_iso),
            )
            conn.commit()
    return get_origin_weighting_config()


_CLOUD_JUDGE_DEFAULTS = {"cloud_judge_min_confidence": 0.9}


def get_cloud_judge_config() -> dict[str, float]:
    """M6 cloud-judge confidence knob, backed by guard_config. Missing keys ->
    defaults. Stored as string; coerce to float and clamp to [0.5, 1.0]."""
    init_db()
    cfg = dict(_CLOUD_JUDGE_DEFAULTS)
    with get_db_connection() as conn:
        for row in conn.execute("SELECT key, value FROM guard_config").fetchall():
            if row["key"] == "cloud_judge_min_confidence":
                try:
                    cfg["cloud_judge_min_confidence"] = max(0.5, min(1.0, float(row["value"])))
                except (TypeError, ValueError):
                    pass
    return cfg


def set_cloud_judge_config(min_confidence: Optional[float] = None) -> dict[str, float]:
    """Human-only write; clamp [0.5, 1.0]; upsert guard_config (mirror set_channel_approve_config)."""
    init_db()
    if min_confidence is not None:
        now_iso = datetime.now(timezone.utc).isoformat()
        clamped = max(0.5, min(1.0, float(min_confidence)))
        with get_db_connection() as conn:
            conn.execute(
                "INSERT INTO guard_config (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                ("cloud_judge_min_confidence", str(clamped), now_iso),
            )
            conn.commit()
    return get_cloud_judge_config()


_BATCH_APPROVAL_DEFAULTS = {"batch_approval_enabled": True, "human_approval_ttl_seconds": 3600}


def get_batch_approval_config() -> dict:
    """M7 anti-fatigue knobs, backed by guard_config. Missing keys -> defaults.

    batch_approval_enabled: _parse_bool. human_approval_ttl_seconds: int clamp
    [60, 86400] (used by the novelty gate in record_human_approval_pattern).
    """
    init_db()
    cfg = dict(_BATCH_APPROVAL_DEFAULTS)
    with get_db_connection() as conn:
        for row in conn.execute("SELECT key, value FROM guard_config").fetchall():
            k, v = row["key"], row["value"]
            if k == "batch_approval_enabled":
                cfg[k] = _parse_bool(v)
            elif k == "human_approval_ttl_seconds":
                try:
                    cfg[k] = max(60, min(86400, int(float(v))))
                except (TypeError, ValueError):
                    pass
    return cfg


def set_batch_approval_config(enabled=None, ttl_seconds=None) -> dict:
    """Human-only write path; upsert guard_config (mirror set_channel_approve_config)."""
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection() as conn:
        if enabled is not None:
            conn.execute(
                "INSERT INTO guard_config (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                ("batch_approval_enabled", "true" if _parse_bool(enabled) else "false", now_iso),
            )
        if ttl_seconds is not None:
            clamped = max(60, min(86400, int(float(ttl_seconds))))
            conn.execute(
                "INSERT INTO guard_config (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                ("human_approval_ttl_seconds", str(clamped), now_iso),
            )
        conn.commit()
    return get_batch_approval_config()


_PANE_DIRECT_DEFAULTS = {"pane_direct_eviction_enabled": True, "pane_direct_confirm_polls": 2}


def get_pane_direct_config() -> dict:
    """Pane-direct auto-eviction knobs, backed by guard_config. Missing keys -> defaults.

    pane_direct_eviction_enabled: _parse_bool. pane_direct_confirm_polls: int
    clamp [1, 5] (consecutive not-live polls required before a PD-C debounced
    eviction self-approves a stale escalation).
    """
    init_db()
    cfg = dict(_PANE_DIRECT_DEFAULTS)
    with get_db_connection() as conn:
        for row in conn.execute("SELECT key, value FROM guard_config").fetchall():
            k, v = row["key"], row["value"]
            if k == "pane_direct_eviction_enabled":
                cfg[k] = _parse_bool(v)
            elif k == "pane_direct_confirm_polls":
                try:
                    cfg[k] = max(1, min(5, int(float(v))))
                except (TypeError, ValueError):
                    pass
    return cfg


def set_pane_direct_config(enabled=None, confirm_polls=None) -> dict:
    """Human-only write path; upsert guard_config (mirror set_batch_approval_config)."""
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection() as conn:
        if enabled is not None:
            conn.execute(
                "INSERT INTO guard_config (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                ("pane_direct_eviction_enabled", "true" if _parse_bool(enabled) else "false", now_iso),
            )
        if confirm_polls is not None:
            clamped = max(1, min(5, int(float(confirm_polls))))
            conn.execute(
                "INSERT INTO guard_config (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                ("pane_direct_confirm_polls", str(clamped), now_iso),
            )
        conn.commit()
    return get_pane_direct_config()


def record_adjudication(
    escalation_id: int,
    pane_id: str,
    agent_kind: str,
    action: str,
    feedback: str,
    origin: str = "A",
) -> None:
    """Persist an approve/deny adjudication and its instruction for auditability.

    A human APPROVE also seeds the novelty gate (INV-3): the escalation's canonical
    pattern is recorded with a TTL so subsequent identical commands (same pane scope)
    auto-approve via the HUMAN_APPROVED fast path instead of re-escalating.
    REJECT never seeds the gate.

    issue #7207: on APPROVE with a human/gatekeeper approver and AGENT/HUMAN
    origin, the workspace .schengen/ allowlist auto-promotion hook runs
    (skipped when no policy exists or the INV-WS-2 denylist re-assertion refuses).
    """
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    resolution = "APPROVED" if action == "APPROVE" else "REJECTED"
    raw_command = None
    esc_cwd = None
    esc_layer = None
    esc_origin = None
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO adjudication_log (escalation_id, pane_id, agent_kind, action, feedback, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (escalation_id, pane_id, agent_kind, action, feedback, now_iso),
        )
        if escalation_id:
            conn.execute(
                "UPDATE pending_escalations SET resolution = ?, approver = 'human-tui' WHERE id = ?",
                (resolution, escalation_id),
            )
            row = conn.execute(
                "SELECT raw_command, cwd, decision_layer, origin FROM pending_escalations WHERE id = ?", (escalation_id,)
            ).fetchone()
            if row:
                raw_command = row["raw_command"]
                esc_cwd = row["cwd"]
                esc_layer = row["decision_layer"]
                esc_origin = row["origin"]
        conn.commit()

    if action == "APPROVE" and raw_command:
        record_human_approval_pattern(normalize_command(raw_command), scope=pane_id)
        # issue #7207: workspace allowlist auto-promotion (human/gatekeeper
        # approval, AGENT/HUMAN origin only; fail-safe — never breaks adjudication).
        # Fix 4: the escalation row's intercepted origin is authoritative —
        # INJECTED/EMERGENT never promote even on a human approve.
        effective_origin = (esc_origin or origin or "A")
        try:
            _maybe_promote_workspace_rule(
                escalation_id=escalation_id,
                pane_id=pane_id,
                agent_kind=agent_kind,
                raw_command=raw_command,
                decision_layer=esc_layer,
                cwd=esc_cwd,
                origin=effective_origin,
                now_iso=now_iso,
            )
        except Exception:
            pass


def _derive_workspace_rule(raw_command: str, decision_layer: Optional[str]) -> Optional[dict]:
    """Derive a canonical (action_type, match_type, pattern) rule for promotion.

    Dialog types -> canonical (realpath) target path. exec -> the ORIGINAL raw
    command (exact string) — NOT normalize_command — so the INV-WS-2 denylist
    re-assertion (inside promote_rule) sees sensitive paths and absolute-path
    tokens on the RAW text before anything is persisted (reviewer fix).
    Returns None for unparseable dialog commands / question dialogs.
    """
    cmd = (raw_command or "").strip()
    if cmd.startswith("access_directory "):
        target = cmd[len("access_directory "):].strip()
        canon = os.path.realpath(os.path.expanduser(target))
        return {"action_type": "access_directory", "match_type": "prefix", "pattern": canon}
    if cmd.startswith("edit_file ") or cmd.startswith("create_file "):
        target = cmd.split(" ", 1)[1].strip()
        canon = os.path.realpath(os.path.expanduser(target))
        return {"action_type": "edit_file", "match_type": "exact", "pattern": canon}
    if cmd.startswith("read_file "):
        target = cmd[len("read_file "):].strip()
        canon = os.path.realpath(os.path.expanduser(target))
        return {"action_type": "read_file", "match_type": "exact", "pattern": canon}
    if decision_layer in ("QUESTION", "unhandled_dialog", None):
        return None
    return {"action_type": "exec", "match_type": "exact", "pattern": cmd}


def _maybe_promote_workspace_rule(
    escalation_id: int,
    pane_id: str,
    agent_kind: str,
    raw_command: str,
    decision_layer: Optional[str],
    cwd: Optional[str],
    origin: str,
    now_iso: str,
) -> None:
    """Auto-promote an approved escalation into the workspace .schengen/ allowlist.

    Only human-tui/gatekeeper approvals with AGENT/HUMAN origin promote (the
    approver is set to 'human-tui' by record_adjudication itself). Skips when:
    no workspace policy, unparseable rule, or the INV-WS-2 denylist re-assertion
    (inside promote_rule) refuses. Records a REPO_LOCAL audit row on success.
    """
    import os as _os
    import uuid as _uuid

    from core.workspace_allowlist import discover_workspace_policy, promote_rule

    if origin not in ("A", "H"):
        return  # INV-WS-3: INJECTED/EMERGENT never promote
    if not cwd:
        return
    rule_base = _derive_workspace_rule(raw_command, decision_layer)
    if rule_base is None:
        return
    policy_path = discover_workspace_policy(cwd)
    if policy_path is None:
        return
    rule = {
        "id": f"auto-{_uuid.uuid4().hex[:12]}",
        "action_type": rule_base["action_type"],
        "match_type": rule_base["match_type"],
        "pattern": rule_base["pattern"],
        "agent_scope": ["*"],
        "created_by": "human-tui",
        "created_at": now_iso,
        "reason": f"Auto-promoted from {decision_layer or 'unknown'} approval (escalation #{escalation_id})",
    }
    promoted = promote_rule(policy_path, rule)
    if promoted:
        record_audit_log(
            pane_id=pane_id,
            raw_command=raw_command,
            decision="ALLOWLIST_BYPASS",
            safety_reason=f"Auto-promoted workspace rule: {rule['action_type']} {rule['pattern']}",
            agent_kind=agent_kind,
            decision_layer=decision_layer or "FAST_TRACK_AST",
            origin=origin,
            consequence="NONE",
            mechanism="workspace-allowlist-promote",
            scope_context="REPO_LOCAL",
        )


def enqueue_pending_escalation(
    pane_id: str,
    raw_command: str,
    safety_reason: str,
    decision_layer: str,
    agent_kind: str = "unknown",
    session_id: Optional[str] = None,
    dialog_snapshot: Optional[str] = None,
    cwd: Optional[str] = None,
    origin: Optional[str] = None,
) -> int:
    """Enqueue a blocked dangerous command into persistent escalations queue (At-Least-Once).

    cwd: the workspace cwd at interception (issue #7207) — enables the
    auto-promotion hook on later human approval.
    origin: the command author origin (A/H/I/E) at interception — the
    auto-promotion gate (INV-WS-3) reads it so INJECTED/EMERGENT never promote
    even on a human approve.
    """
    import hashlib

    init_db()
    cmd_hash = hashlib.sha256(raw_command.encode("utf-8")).hexdigest()[:16]
    now_iso = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO pending_escalations (
                pane_id, session_id, agent_kind, raw_command, command_hash, safety_reason, decision_layer, dialog_snapshot, status, started_at, last_transitioned_at, cwd, origin
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?)
            ON CONFLICT(pane_id, command_hash) DO UPDATE SET
                session_id = excluded.session_id,
                status = 'PENDING',
                safety_reason = excluded.safety_reason,
                decision_layer = excluded.decision_layer,
                dialog_snapshot = excluded.dialog_snapshot,
                cwd = excluded.cwd,
                origin = excluded.origin,
                last_transitioned_at = excluded.last_transitioned_at
        """,
            (pane_id, session_id, agent_kind, raw_command, cmd_hash, safety_reason, decision_layer, dialog_snapshot, now_iso, now_iso, cwd, origin),
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
    query = f"SELECT id, pane_id, session_id, agent_kind, raw_command, command_hash, safety_reason, decision_layer, dialog_snapshot, status, started_at, delivered_at, last_transitioned_at, cwd, origin FROM pending_escalations WHERE status IN {statuses}"
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


def group_pending_escalations(escalations: list[dict]) -> list[dict]:
    """Group pending rows into (decision_layer, canonical_pattern) batches, FIFO order."""
    groups = {}
    order = []
    for e in escalations:  # already id ASC (FIFO)
        key = (e["decision_layer"], normalize_command(e["raw_command"]))
        if key not in groups:
            groups[key] = {
                "group_key": key,
                "decision_layer": e["decision_layer"],
                "canonical_pattern": normalize_command(e["raw_command"]),
                "count": 0,
                "items": [],
                "sample_raw_command": e["raw_command"],
            }
            order.append(key)
        groups[key]["items"].append(e)
        groups[key]["count"] += 1
    return [groups[k] for k in order]


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
    approver: Optional[str] = None,
    resolution: Optional[str] = None,
):
    """Mark escalation(s) as resolved or cancelled after user/agent action (ACK).

    `resolution` (optional, COALESCE-semantics) records the post-escalation
    disposition (APPROVED/REJECTED) WITHOUT overwriting an existing value when
    left None — pane-direct auto-eviction uses it to stamp APPROVED provenance
    without clobbering a prior human/gatekeeper disposition.
    """
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
                SET status = ?, last_transitioned_at = ?, approver = COALESCE(?, approver),
                    resolution = COALESCE(?, resolution)
                WHERE id = ?
            """,
                (resolution_status, now_iso, approver, resolution, escalation_id),
            )
        elif command_hash:
            cursor.execute(
                """
                UPDATE pending_escalations
                SET status = ?, last_transitioned_at = ?, approver = COALESCE(?, approver),
                    resolution = COALESCE(?, resolution)
                WHERE pane_id = ? AND command_hash = ? AND status IN ('PENDING', 'DELIVERED')
            """,
                (resolution_status, now_iso, approver, resolution, pane_id, command_hash),
            )
        else:
            cursor.execute(
                """
                UPDATE pending_escalations
                SET status = ?, last_transitioned_at = ?, approver = COALESCE(?, approver),
                    resolution = COALESCE(?, resolution)
                WHERE pane_id = ? AND status IN ('PENDING', 'DELIVERED')
            """,
                (resolution_status, now_iso, approver, resolution, pane_id),
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
                SET status = ?, last_transitioned_at = ?, resolution = COALESCE(resolution, 'UNANSWERED'), approver = COALESCE(approver, 'other')
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
                SET status = ?, last_transitioned_at = ?, resolution = COALESCE(resolution, 'UNANSWERED'), approver = COALESCE(approver, 'other')
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
                SET status = ?, last_transitioned_at = ?, resolution = COALESCE(resolution, 'UNANSWERED'), approver = COALESCE(approver, 'other')
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
