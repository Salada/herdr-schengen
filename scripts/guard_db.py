"""SQLite3 persistence and pattern analysis module for Herdr Agent Guard.

Stores:
1. audit_logs: Every detected permission request, decision, safety check, and timestamp.
2. pattern_stats: Aggregated frequency and approval count per normalized command template.
3. user_allowlist: Persisted custom approval rules reviewed by human engineers.

Database location: ~/.local/state/herdr-agent-guard/guard_history.db (XDG compliant, no skill pollution)
"""

import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DB_DIR = Path.home() / ".local" / "state" / "herdr-agent-guard"
DB_PATH = DB_DIR / "guard_history.db"


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
            decision TEXT NOT NULL, -- 'AUTO_APPROVED' | 'MANUAL_DELEGATED'
            safety_reason TEXT NOT NULL
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
            INSERT INTO audit_logs (timestamp, pane_id, agent_kind, raw_command, normalized_pattern, decision, safety_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                now_iso,
                pane_id,
                agent_kind,
                raw_command,
                norm_pattern,
                decision,
                safety_reason,
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
                1 if decision == "AUTO_APPROVED" else 0,
                1 if decision == "MANUAL_DELEGATED" else 0,
                now_iso,
                1 if decision == "AUTO_APPROVED" else 0,
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
    """Add a verified pattern to the persistent allowlist."""
    init_db()
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


if __name__ == "__main__":
    import sys

    init_db()
    if len(sys.argv) > 1 and sys.argv[1] == "--stats":
        stats = get_pattern_analysis()
        print("\n📊 Herdr Agent Guard - Pattern Analysis & Review Board")
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
    else:
        print(f"Database initialized at: {DB_PATH}")
