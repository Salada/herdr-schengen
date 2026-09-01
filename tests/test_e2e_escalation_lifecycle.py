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

import core.guard_db as guard_db
from core.guard_db import (
    enqueue_pending_escalation,
    get_pending_escalations,
    resolve_escalation,
    get_recent_audit_logs,
    set_instruction_delivery_config,
)
from tools.schengen_agent_llm import execute_tool_call


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

    def test_re_enqueue_resets_resolution_approver(self):
        """#3159: re-enqueuing the SAME command for the SAME pane (ON CONFLICT)
        must reset the prior resolution/approver/delivered_at to NULL — a
        re-escalated row must never show "PENDING but already APPROVED"."""
        pane_id = "w1D:p3159"
        cmd = "rm -rf /tmp/reconflict"
        esc_id = enqueue_pending_escalation(
            pane_id=pane_id, raw_command=cmd, safety_reason="test",
            decision_layer="GRAY_ZONE", agent_kind="agy",
        )
        resolve_escalation(
            pane_id=pane_id, escalation_id=esc_id,
            resolution_status="RESOLVED", is_approval=True,
            approver="pane-direct", resolution="APPROVED",
        )
        conn = guard_db.get_db_connection()
        try:
            row = conn.execute(
                "SELECT resolution, approver FROM pending_escalations WHERE id = ?", (esc_id,)
            ).fetchone()
            self.assertEqual(row["resolution"], "APPROVED")
            self.assertEqual(row["approver"], "pane-direct")
        finally:
            conn.close()

        # Re-enqueue the SAME command -> ON CONFLICT must reset the disposition.
        esc_id2 = enqueue_pending_escalation(
            pane_id=pane_id, raw_command=cmd, safety_reason="test2",
            decision_layer="GRAY_ZONE", agent_kind="agy",
        )
        self.assertEqual(esc_id2, esc_id)  # same row reused via ON CONFLICT

        conn = guard_db.get_db_connection()
        try:
            row = conn.execute(
                "SELECT status, resolution, approver, delivered_at FROM pending_escalations WHERE id = ?",
                (esc_id,),
            ).fetchone()
            self.assertEqual(row["status"], "PENDING")
            self.assertIsNone(row["resolution"])
            self.assertIsNone(row["approver"])
            self.assertIsNone(row["delivered_at"])
        finally:
            conn.close()

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
            # Enable approve-instruction delivery so the AGY tab-amend flow is exercised.
            set_instruction_delivery_config(send_approve_instruction=True)
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


class TestInstructionDeliveryConfig(unittest.TestCase):
    """Instruction-delivery config (approve/reject feedback gating) + adjudication log."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_default_config_approve_off_reject_on(self):
        cfg = guard_db.get_instruction_delivery_config()
        self.assertFalse(cfg["send_approve_instruction"])
        self.assertTrue(cfg["send_reject_instruction"])

    def test_set_config_persists(self):
        guard_db.set_instruction_delivery_config(send_approve_instruction=True, send_reject_instruction=False)
        cfg = guard_db.get_instruction_delivery_config()
        self.assertTrue(cfg["send_approve_instruction"])
        self.assertFalse(cfg["send_reject_instruction"])

    def test_default_answer_language_korean(self):
        self.assertEqual(guard_db.get_answer_language(), "korean")

    def test_set_answer_language_persists(self):
        self.assertEqual(guard_db.set_answer_language("english"), "english")
        self.assertEqual(guard_db.get_answer_language(), "english")
        self.assertEqual(guard_db.set_answer_language("japanese"), "japanese")
        self.assertEqual(guard_db.get_answer_language(), "japanese")
        # Invalid value falls back to the korean default.
        self.assertEqual(guard_db.set_answer_language("gibberish"), "korean")
        self.assertEqual(guard_db.get_answer_language(), "korean")

    def test_default_channel_approve_off(self):
        # permission.reply approval is opt-in; default is keystroke injection.
        self.assertFalse(guard_db.get_channel_approve_config())

    def test_set_channel_approve_persists(self):
        self.assertTrue(guard_db.set_channel_approve_config(True))
        self.assertTrue(guard_db.get_channel_approve_config())
        self.assertFalse(guard_db.set_channel_approve_config(False))
        self.assertFalse(guard_db.get_channel_approve_config())

    def test_get_audit_log_by_id_roundtrip(self):
        guard_db.record_audit_log(
            "w1D:p1", "git status", "AUTO_APPROVED", "safe git query",
            agent_kind="opencode", decision_layer="FAST_TRACK_AST",
        )
        logs = guard_db.get_recent_audit_logs(limit=1)
        self.assertEqual(len(logs), 1)
        full = guard_db.get_audit_log_by_id(logs[0]["id"])
        self.assertIsNotNone(full)
        self.assertEqual(full["raw_command"], "git status")
        self.assertEqual(full["agent_kind"], "opencode")
        self.assertIn("consequence", full)
        self.assertIn("gate_state", full)

    def test_get_adjudications_for_audit_join(self):
        conn = guard_db.get_db_connection()
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO pending_escalations
            (pane_id, agent_kind, raw_command, command_hash, safety_reason, decision_layer, status, started_at, last_transitioned_at)
            VALUES (?, ?, ?, ?, ?, ?, 'RESOLVED', ?, ?)
            """,
            ("w1D:p1", "opencode", "rm -rf /tmp/x", "hash1", "destructive", "GRAY_ZONE", now, now),
        )
        esc_id = cur.lastrowid
        conn.commit()
        conn.close()
        guard_db.record_adjudication(esc_id, "w1D:p1", "opencode", "APPROVE", "Approved. Safe.", approver="human-tui")

        adj = guard_db.get_adjudications_for_audit("w1D:p1", "rm -rf /tmp/x")
        self.assertEqual(len(adj), 1)
        self.assertEqual(adj[0]["action"], "APPROVE")
        self.assertEqual(adj[0]["feedback"], "Approved. Safe.")
        self.assertEqual(adj[0]["escalation_id"], esc_id)

        # A different command on the same pane must not match.
        self.assertEqual(guard_db.get_adjudications_for_audit("w1D:p1", "echo hello"), [])

    def test_record_adjudication_inserts_row(self):
        guard_db.record_adjudication(123, "w1D:p1", "opencode", "APPROVE", "Approved. Safe.", approver="human-tui")
        conn = guard_db.get_db_connection()
        rows = conn.execute("SELECT id, escalation_id, pane_id, action, feedback FROM adjudication_log").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["escalation_id"], 123)
        self.assertEqual(rows[0]["pane_id"], "w1D:p1")
        self.assertEqual(rows[0]["action"], "APPROVE")
        self.assertEqual(rows[0]["feedback"], "Approved. Safe.")

    def test_adjudication_sets_resolution(self):
        esc_id = guard_db.enqueue_pending_escalation(
            "w1D:p1", "rm -rf /tmp/x", "destructive", "GRAY_ZONE", agent_kind="opencode"
        )
        self.assertIsNone(guard_db.get_escalation_resolution("w1D:p1", "rm -rf /tmp/x"))
        guard_db.record_adjudication(esc_id, "w1D:p1", "opencode", "APPROVE", "Approved.", approver="human-tui")
        self.assertEqual(guard_db.get_escalation_resolution("w1D:p1", "rm -rf /tmp/x"), "APPROVED")

    def test_question_escalation_roundtrip(self):
        # A human question is enqueued with decision_layer="QUESTION" and stays
        # PENDING until the pane's dialog clears (the user answers).
        esc_id = guard_db.enqueue_pending_escalation(
            "w1D:p1K", "question: 어떤 브랜치를 머지할까요?",
            "Agent asked the user a question: 어떤 브랜치를 머지할까요?",
            "QUESTION", agent_kind="codex",
        )
        pending = guard_db.get_pending_escalations(include_delivered=False)
        q = next((e for e in pending if e["id"] == esc_id), None)
        self.assertIsNotNone(q)
        self.assertEqual(q["decision_layer"], "QUESTION")

        # Resolving the pane clears the question escalation.
        guard_db.resolve_escalation(pane_id="w1D:p1K")
        remaining = guard_db.get_pending_escalations(include_delivered=False)
        self.assertNotIn(esc_id, [e["id"] for e in remaining])

    def test_cleanup_sets_unanswered_resolution(self):
        esc_id = guard_db.enqueue_pending_escalation(
            "w1D:p1", "rm -rf /tmp/y", "destructive", "GRAY_ZONE", agent_kind="opencode"
        )
        guard_db.cleanup_escalations(escalation_ids=[esc_id], new_status="STALE_EXPIRED")
        self.assertEqual(guard_db.get_escalation_resolution("w1D:p1", "rm -rf /tmp/y"), "UNANSWERED")

    def test_recent_audit_logs_includes_resolution(self):
        guard_db.record_audit_log(
            "w1D:p1", "rm -rf /tmp/x", "MANUAL_DELEGATED", "destructive",
            agent_kind="opencode", decision_layer="GRAY_ZONE",
        )
        esc_id = guard_db.enqueue_pending_escalation(
            "w1D:p1", "rm -rf /tmp/x", "destructive", "GRAY_ZONE", agent_kind="opencode"
        )
        guard_db.record_adjudication(esc_id, "w1D:p1", "opencode", "APPROVE", "Approved.", approver="human-tui")
        logs = guard_db.get_recent_audit_logs(limit=5)
        matching = [l for l in logs if l["raw_command"] == "rm -rf /tmp/x"]
        self.assertTrue(matching)
        self.assertEqual(matching[0].get("resolution"), "APPROVED")


if __name__ == "__main__":
    unittest.main()
