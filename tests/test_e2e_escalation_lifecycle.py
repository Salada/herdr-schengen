#!/usr/bin/env python3
"""E2E Lifecycle Test for Schengen Guardian & TUI.

Simulates:
1. Multi-pending escalation ingestion in SQLite DB.
2. Strict FIFO single-item active window.
3. AGY Tab-Amend resolution protocol (tab -> security note -> enter).
4. Queue progression and final clean-slate state.
"""

import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import guard_db
from guard_db import (
    get_pending_escalations,
    resolve_escalation,
    get_recent_audit_logs,
)
from schengen_agent_llm import execute_tool_call


class TestE2EEscalationLifecycle(unittest.TestCase):
    """End-to-end simulation of multi-agent escalation queueing and adjudication."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"

        # Patch DB path in guard_db
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()

        # Initialize schema
        guard_db.init_db()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def _insert_escalation(self, pane_id: str, agent_kind: str, cmd: str, reason: str) -> int:
        conn = guard_db.get_db_connection()
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO pending_escalations
            (pane_id, agent_kind, raw_command, command_hash, safety_reason, decision_layer, status, started_at, last_transitioned_at)
            VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)
            """,
            (pane_id, agent_kind, cmd, f"hash_{pane_id}", reason, "GRAY_ZONE", now, now),
        )
        esc_id = cur.lastrowid
        conn.commit()
        conn.close()
        return esc_id

    def test_multi_escalation_fifo_progression(self):
        # 1. Insert 3 escalations from different panes
        id1 = self._insert_escalation("w1D:p5", "agy", "rm -rf /tmp/test_dir1", "Deletion test 1")
        id2 = self._insert_escalation("w1D:p1", "agy", "rm -rf /tmp/test_dir2", "Deletion test 2")
        id3 = self._insert_escalation("w1A:p1", "opencode", "pip install untrusted-pkg", "Package install")

        # 2. Check pending list count
        pending = get_pending_escalations(include_delivered=False)
        self.assertEqual(len(pending), 3)
        self.assertEqual(pending[0]["id"], id1)
        self.assertEqual(pending[1]["id"], id2)
        self.assertEqual(pending[2]["id"], id3)

        # 3. Simulate Tab Amend approval on #id1 (AGY)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            res = execute_tool_call("approve_escalation", {
                "escalation_id": id1,
                "english_feedback": "Approved. Test target path verified non-existent.",
            })
            self.assertIn("approved", res.lower())

            # Verify AGY-specific tab-amend command calls: tab -> send-text -> enter
            called_cmds = [call_args[0][0] for call_args in mock_run.call_args_list if len(call_args[0]) > 0]
            # Must contain herdr pane send-keys with tab and enter, and send-text with security gatekeeper header
            flat_calls = " ".join([" ".join(c) if isinstance(c, list) else str(c) for c in called_cmds])
            self.assertIn("tab", flat_calls)
            self.assertIn("enter", flat_calls)
            self.assertIn("[SECURITY GATEKEEPER]", flat_calls)

        # 4. Check that queue has 2 items left, next is #id2
        remaining = get_pending_escalations(include_delivered=False)
        self.assertEqual(len(remaining), 2)
        self.assertEqual(remaining[0]["id"], id2)

        # 5. Resolve #id2
        with patch("subprocess.run"):
            execute_tool_call("approve_escalation", {
                "escalation_id": id2,
                "english_feedback": "Approved. Clean VCS commit verified.",
            })

        # 6. Check that queue has 1 item left, next is #id3 (OpenCode)
        remaining = get_pending_escalations(include_delivered=False)
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["id"], id3)

        # 7. Reject #id3
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            res = execute_tool_call("reject_escalation", {
                "escalation_id": id3,
                "english_feedback": "Untrusted package prohibited.",
            })
            self.assertIn("rejected", res.lower())
            called_cmds = [call_args[0][0] for call_args in mock_run.call_args_list if len(call_args[0]) > 0]
            flat_calls = " ".join([" ".join(c) if isinstance(c, list) else str(c) for c in called_cmds])
            self.assertIn("escape", flat_calls)
            self.assertIn("Untrusted package prohibited.", flat_calls)

        # 8. Queue is now completely clear (clean slate)
        final_pending = get_pending_escalations(include_delivered=False)
        self.assertEqual(len(final_pending), 0)


if __name__ == "__main__":
    unittest.main()
