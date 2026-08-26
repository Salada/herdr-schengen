#!/usr/bin/env python3
"""Feature Request Backlog DB with FTS5 CJK (Trigram) Similarity Search.

Manages autonomous self-improvement backlog tasks in an independent SQLite DB:
~/.local/state/herdr-schengen/feature_requests.db

Key Capabilities:
1. Independent SQLite storage separate from guard_audit.db.
2. Full-Text Search via FTS5 with 'trigram' tokenizer for high-precision CJK/Korean n-gram matching.
3. Automatic sync triggers (INSERT, UPDATE, DELETE) between base table and FTS index.
4. Non-blocking queue operations for live TUI command interception & agent tool execution.
5. Self-improvement task lifecycle: PENDING -> IN_PROGRESS -> RESOLVED / REJECTED.
"""

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_DIR = Path.home() / ".local" / "state" / "herdr-schengen"
FEATURE_DB_PATH = DB_DIR / "feature_requests.db"


def get_feature_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Connect to the feature request SQLite database and ensure schema is initialized."""
    target_path = db_path or FEATURE_DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(target_path), timeout=10.0)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode = WAL;")
    con.execute("PRAGMA synchronous = NORMAL;")
    init_feature_db(con)
    return con


def init_feature_db(con: sqlite3.Connection) -> None:
    """Initialize base table, FTS5 virtual table (trigram tokenizer), and sync triggers."""
    with con:
        # 1. Base Table
        con.execute("""
            CREATE TABLE IF NOT EXISTS feature_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                source TEXT NOT NULL,
                requester TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                priority TEXT DEFAULT 'NORMAL',
                category TEXT DEFAULT 'GENERAL',
                status TEXT DEFAULT 'PENDING',
                assigned_to TEXT,
                resolved_at TEXT,
                resolution_note TEXT
            );
        """)

        # 2. FTS5 Virtual Table for CJK / Trigram n-gram similarity search
        con.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS feature_requests_fts USING fts5(
                title,
                description,
                category,
                content='feature_requests',
                content_rowid='id',
                tokenize='trigram'
            );
        """)

        # 3. Synchronization Triggers
        con.execute("""
            CREATE TRIGGER IF NOT EXISTS feature_requests_ai AFTER INSERT ON feature_requests BEGIN
                INSERT INTO feature_requests_fts(rowid, title, description, category)
                VALUES (new.id, new.title, coalesce(new.description, ''), coalesce(new.category, ''));
            END;
        """)
        con.execute("""
            CREATE TRIGGER IF NOT EXISTS feature_requests_ad AFTER DELETE ON feature_requests BEGIN
                INSERT INTO feature_requests_fts(feature_requests_fts, rowid, title, description, category)
                VALUES ('delete', old.id, old.title, coalesce(old.description, ''), coalesce(old.category, ''));
            END;
        """)
        con.execute("""
            CREATE TRIGGER IF NOT EXISTS feature_requests_au AFTER UPDATE ON feature_requests BEGIN
                INSERT INTO feature_requests_fts(feature_requests_fts, rowid, title, description, category)
                VALUES ('delete', old.id, old.title, coalesce(old.description, ''), coalesce(old.category, ''));
                INSERT INTO feature_requests_fts(rowid, title, description, category)
                VALUES (new.id, new.title, coalesce(new.description, ''), coalesce(new.category, ''));
            END;
        """)


def add_feature_request(
    title: str,
    description: str = "",
    requester: str = "user",
    priority: str = "NORMAL",
    category: str = "GENERAL",
    source: str = "tui_command",
    db_path: Optional[Path] = None,
) -> int:
    """Insert a new feature request into the backlog queue."""
    con = get_feature_db_connection(db_path)
    now_utc = datetime.now(timezone.utc).isoformat()
    with con:
        cur = con.execute(
            """
            INSERT INTO feature_requests (
                created_at, source, requester, title, description, priority, category, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING')
            """,
            (now_utc, source, requester, title.strip(), description.strip(), priority.upper(), category.upper()),
        )
        return int(cur.lastrowid or 0)


def search_similar_feature_requests(
    query: str,
    limit: int = 5,
    status: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Search similar feature requests using FTS5 trigram MATCH query and BM25 score ranking."""
    query_clean = query.strip()
    if not query_clean:
        return []

    con = get_feature_db_connection(db_path)
    safe_query = f'"{query_clean}"' if '"' not in query_clean else query_clean
    try:
        if status:
            cur = con.execute(
                """
                SELECT f.id, f.created_at, f.source, f.requester, f.title, f.description,
                       f.priority, f.category, f.status, f.assigned_to, f.resolved_at, f.resolution_note,
                       bm25(feature_requests_fts) AS rank_score
                FROM feature_requests_fts fts
                JOIN feature_requests f ON f.id = fts.rowid
                WHERE feature_requests_fts MATCH ? AND f.status = ?
                ORDER BY rank_score ASC
                LIMIT ?
                """,
                (safe_query, status.upper(), limit),
            )
        else:
            cur = con.execute(
                """
                SELECT f.id, f.created_at, f.source, f.requester, f.title, f.description,
                       f.priority, f.category, f.status, f.assigned_to, f.resolved_at, f.resolution_note,
                       bm25(feature_requests_fts) AS rank_score
                FROM feature_requests_fts fts
                JOIN feature_requests f ON f.id = fts.rowid
                WHERE feature_requests_fts MATCH ?
                ORDER BY rank_score ASC
                LIMIT ?
                """,
                (safe_query, limit),
            )
        return [dict(row) for row in cur.fetchall()]
    except sqlite3.OperationalError:
        like_pattern = f"%{query_clean}%"
        cur = con.execute(
            """
            SELECT id, created_at, source, requester, title, description,
                   priority, category, status, assigned_to, resolved_at, resolution_note,
                   0.0 AS rank_score
            FROM feature_requests
            WHERE title LIKE ? OR description LIKE ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (like_pattern, like_pattern, limit),
        )
        return [dict(row) for row in cur.fetchall()]


def get_feature_request_by_id(
    request_id: int,
    db_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve a single feature request by its primary key ID."""
    con = get_feature_db_connection(db_path)
    cur = con.execute(
        """
        SELECT id, created_at, source, requester, title, description,
               priority, category, status, assigned_to, resolved_at, resolution_note
        FROM feature_requests
        WHERE id = ?
        """,
        (request_id,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def list_feature_requests(
    status: Optional[str] = None,
    limit: int = 50,
    db_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """List recent feature requests with optional status filter."""
    con = get_feature_db_connection(db_path)
    if status:
        cur = con.execute(
            """
            SELECT id, created_at, source, requester, title, description,
                   priority, category, status, assigned_to, resolved_at, resolution_note
            FROM feature_requests
            WHERE status = ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (status.upper(), limit),
        )
    else:
        cur = con.execute(
            """
            SELECT id, created_at, source, requester, title, description,
                   priority, category, status, assigned_to, resolved_at, resolution_note
            FROM feature_requests
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
    return [dict(row) for row in cur.fetchall()]


def pull_next_feature_request(
    worker_name: str = "dev-agent",
    db_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Strict FIFO lock: claim and return the oldest PENDING feature request for self-improvement job."""
    con = get_feature_db_connection(db_path)
    with con:
        cur = con.execute(
            """
            SELECT id, created_at, source, requester, title, description,
                   priority, category, status, assigned_to, resolved_at, resolution_note
            FROM feature_requests
            WHERE status = 'PENDING'
            ORDER BY id ASC
            LIMIT 1
            """
        )
        row = cur.fetchone()
        if not row:
            return None
        req = dict(row)
        req_id = req["id"]
        con.execute(
            """
            UPDATE feature_requests
            SET status = 'IN_PROGRESS', assigned_to = ?
            WHERE id = ?
            """,
            (worker_name, req_id),
        )
        req["status"] = "IN_PROGRESS"
        req["assigned_to"] = worker_name
        return req


def update_feature_request_status(
    request_id: int,
    status: str,
    resolution_note: str = "",
    db_path: Optional[Path] = None,
) -> bool:
    """Update feature request status and set resolution note/timestamp if resolved."""
    con = get_feature_db_connection(db_path)
    now_utc = datetime.now(timezone.utc).isoformat()
    status_upper = status.upper()
    with con:
        if status_upper in ("RESOLVED", "REJECTED"):
            cur = con.execute(
                """
                UPDATE feature_requests
                SET status = ?, resolution_note = ?, resolved_at = ?
                WHERE id = ?
                """,
                (status_upper, resolution_note.strip(), now_utc, request_id),
            )
        else:
            cur = con.execute(
                """
                UPDATE feature_requests
                SET status = ?, resolution_note = ?
                WHERE id = ?
                """,
                (status_upper, resolution_note.strip(), request_id),
            )
        return cur.rowcount > 0
