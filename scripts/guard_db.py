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
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DB_DIR = Path.home() / ".local" / "state" / "herdr-schengen"
DB_PATH = DB_DIR / "schengen_history.db"


def get_db_connection() -> sqlite3.Connection:
    """Initialize DB directory and connect to SQLite3 database."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
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
            decision TEXT NOT NULL, -- 'AUTO_APPROVED' | 'MANUAL_DELEGATED' | 'ALLOWLIST_BYPASS'
            safety_reason TEXT NOT NULL,
            decision_layer TEXT DEFAULT 'FAST_TRACK_AST'
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

        CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_pattern ON audit_logs(normalized_pattern);
        """)
        # Migration: Ensure decision_layer column exists in older schemas
        cursor.execute("PRAGMA table_info(audit_logs)")
        columns = [c[1] for c in cursor.fetchall()]
        if "decision_layer" not in columns:
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN decision_layer TEXT DEFAULT 'FAST_TRACK_AST'")

        # Create layer index after ensuring column exists
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_layer ON audit_logs(decision_layer);")
        conn.commit()


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
):
    """Record an audit entry and update pattern frequency statistics."""
    init_db()
    norm_pattern = normalize_command(raw_command)
    now_iso = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        # 1. Insert audit log
        cursor.execute(
            """
            INSERT INTO audit_logs (timestamp, pane_id, agent_kind, raw_command, normalized_pattern, decision, safety_reason, decision_layer)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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


def get_pattern_analysis() -> List[Dict]:
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


def check_persisted_allowlist(cmd_str: str) -> Tuple[bool, Optional[str]]:
    """Check if command matches any human-persisted allowlist regex."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT pattern_regex, description FROM user_allowlist WHERE"
            " is_active = 1"
        )
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
) -> List[Dict]:
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


def search_audit_logs(keyword: str, limit: int = 20) -> List[Dict]:
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


def get_state_file_paths() -> Dict[str, str]:
    """Return dictionary of all SmartGate / Schengen state and database paths."""
    return {
        "state_dir": str(DB_DIR),
        "db_path": str(DB_PATH),
        "lock_file": str(DB_DIR / "schengen.lock"),
        "log_file": str(DB_DIR / "schengen.log"),
    }


def tail_state_log(lines: int = 20) -> List[str]:
    """Safely retrieve the last N lines of the schengen log file without spawning shell subshells."""
    log_file = DB_DIR / "schengen.log"
    if not log_file.exists():
        return []
    try:
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
            return all_lines[-max(1, lines):]
    except Exception as e:
        return [f"Error reading log file: {e}\n"]


if __name__ == "__main__":
    import argparse
    import json
    import sys

    init_db()
    parser = argparse.ArgumentParser(description="Herdr SmartGate / Schengen Audit DB CLI")
    parser.add_argument("--recent", "-n", type=int, nargs="?", const=10, default=None, help="Display recent audit logs (default: 10)")
    parser.add_argument("--search", "-s", type=str, help="Search audit logs by keyword")
    parser.add_argument("--tail", "-t", type=int, nargs="?", const=20, default=None, help="Tail schengen.log file (default: 20 lines)")
    parser.add_argument("--paths", "--find-state", action="store_true", help="Print SmartGate state file paths")
    parser.add_argument("--stats", action="store_true", help="Display pattern analysis stats from DB and exit")
    parser.add_argument("--layer", type=str, help="Filter by decision layer (e.g. SECRET_GUARD, SHELL_CRITICAL)")
    parser.add_argument("--decision", type=str, help="Filter by decision (AUTO_APPROVED, MANUAL_DELEGATED, ALLOWLIST_BYPASS)")
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
                print(f"{symbol} [{r['timestamp'][:19]}] #{r['id']} {r['pane_id']} - {r['decision']} [Layer: {r['decision_layer']}] ({r['safety_reason']})")
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
                print(f"{symbol} [{r['timestamp'][:19]}] #{r['id']:<3} {r['pane_id']:<6} | {r['decision']:<16} | Layer: {r['decision_layer']:<16}")
                print(f"   Reason: {r['safety_reason']}")
                print(f"   Cmd   : {cmd_prev}")
                print("-" * 90)
        sys.exit(0)
