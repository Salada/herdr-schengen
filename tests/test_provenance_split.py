#!/usr/bin/env python3
"""Provenance split tests (INV-HO-1..6): human opinion vs gatekeeper adjudication.

The human's `/approve <id> [reason]` / `/reject <id> [reason]` raw text is
persisted as an `action='HUMAN_OPINION'` row (`approver='human-tui'`,
`human_note=<raw text>`) BEFORE the gatekeeper LLM call — the raw reason is
never lost (INV-HO-1). approver / human_note / feedback stay independent
(INV-HO-2); an opinion NEVER seeds novelty gate / workspace promotion /
session memory — only a final disposition with approver="human-tui" grants
trust (INV-HO-3); record_human_opinion never mutates the escalation's final
resolution/approver (INV-HO-4); the schema migration is additive and legacy
rows keep NULLs (INV-HO-5); human_note is sanitized (INV-HO-6).

Uses a clean temp DB (patch guard_db.DB_PATH + init_db) — same harness pattern
as tests/test_question_eviction.py.
"""

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import core.guard_db as guard_db
from core.guard_db import (
    enqueue_pending_escalation,
    get_adjudications_for_audit,
    has_human_approval_pattern,
    has_human_opinion,
    normalize_command,
    record_adjudication,
    record_human_opinion,
)


class TestProvenanceSplit(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def _get_row(self, table: str, row_id: int) -> dict:
        conn = guard_db.get_db_connection()
        try:
            row = conn.execute(f"SELECT * FROM {table} WHERE id = ?", (row_id,)).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()

    def _columns(self, table: str) -> list[str]:
        conn = sqlite3.connect(self.db_path)
        try:
            return [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        finally:
            conn.close()

    def _enqueue(self, pane_id="w1D:p1", cmd="rm -rf /tmp/foo", origin="A"):
        return enqueue_pending_escalation(
            pane_id=pane_id,
            raw_command=cmd,
            safety_reason="Destructive command intercepted",
            decision_layer="NOT_ALLOWLISTED",
            agent_kind="codex",
            origin=origin,
        )

    # ---- INV-HO-5: additive, idempotent migration -------------------------

    def test_legacy_schema_migrated_additively(self):
        # Build a LEGACY adjudication_log (no approver / human_note columns)
        # with one existing row, then run init_db().
        conn = sqlite3.connect(self.db_path)
        try:
            conn.executescript(
                """
                CREATE TABLE adjudication_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    escalation_id INTEGER,
                    pane_id TEXT,
                    agent_kind TEXT,
                    action TEXT NOT NULL,
                    feedback TEXT,
                    created_at TEXT NOT NULL
                );
                INSERT INTO adjudication_log (escalation_id, pane_id, agent_kind, action, feedback, created_at)
                VALUES (1, 'w1D:p1', 'codex', 'APPROVE', 'legacy feedback', '2026-08-01T00:00:00+00:00');
                """
            )
            conn.commit()
        finally:
            conn.close()

        guard_db.init_db()

        cols = self._columns("adjudication_log")
        self.assertIn("approver", cols)
        self.assertIn("human_note", cols)
        # Legacy row intact with NULL new columns (INV-HO-5: no backfill).
        row = self._get_row("adjudication_log", 1)
        self.assertEqual(row["action"], "APPROVE")
        self.assertEqual(row["feedback"], "legacy feedback")
        self.assertIsNone(row["approver"])
        self.assertIsNone(row["human_note"])

    def test_fresh_schema_has_both_columns(self):
        guard_db.init_db()
        cols = self._columns("adjudication_log")
        self.assertIn("approver", cols)
        self.assertIn("human_note", cols)

    # ---- INV-HO-1/4: record_human_opinion --------------------------------

    def test_record_human_opinion_row_and_no_final_mutation(self):
        guard_db.init_db()
        esc_id = self._enqueue()
        record_human_opinion(esc_id, "user said it is fine to clean /tmp")

        # The opinion row is a HUMAN_OPINION with the raw note, no feedback.
        rows = guard_db.get_adjudication_exchange(esc_id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["action"], "HUMAN_OPINION")
        self.assertEqual(rows[0]["approver"], "human-tui")
        self.assertEqual(rows[0]["human_note"], "user said it is fine to clean /tmp")
        self.assertIsNone(rows[0]["feedback"])

        # INV-HO-4: pending_escalations resolution/approver are untouched.
        esc = self._get_row("pending_escalations", esc_id)
        self.assertIsNone(esc.get("resolution"))
        self.assertIsNone(esc.get("approver"))
        self.assertEqual(esc["status"], "PENDING")

    def test_record_human_opinion_unknown_escalation_is_noop(self):
        guard_db.init_db()
        # Must not raise and must not create any row.
        record_human_opinion(99999, "ghost opinion")
        conn = sqlite3.connect(self.db_path)
        try:
            n = conn.execute("SELECT COUNT(*) FROM adjudication_log").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(n, 0)

    # ---- has_human_opinion ------------------------------------------------

    def test_has_human_opinion_true_after_opinion_write(self):
        guard_db.init_db()
        esc_id = self._enqueue()
        self.assertFalse(has_human_opinion(esc_id))
        record_human_opinion(esc_id, "ok")
        self.assertTrue(has_human_opinion(esc_id))

    def test_has_human_opinion_false_for_gatekeeper_only_row(self):
        guard_db.init_db()
        esc_id = self._enqueue()
        record_adjudication(esc_id, "w1D:p1", "codex", "APPROVE", "gatekeeper feedback", approver="gatekeeper")
        self.assertFalse(has_human_opinion(esc_id))

    # ---- INV-HO-2: record_adjudication compatibility ----------------------

    def test_record_adjudication_human_note_compat(self):
        guard_db.init_db()
        # Without human_note (gatekeeper path) -> NULL human_note.
        esc1 = self._enqueue(pane_id="w1D:p1")
        record_adjudication(esc1, "w1D:p1", "codex", "APPROVE", "gk feedback", approver="gatekeeper")
        row1 = self._get_row("adjudication_log", 1)
        self.assertIsNone(row1["human_note"])
        self.assertEqual(row1["approver"], "gatekeeper")
        self.assertEqual(row1["feedback"], "gk feedback")

        # With human_note (batch human path) -> set; pending approver updated.
        esc2 = self._enqueue(pane_id="w1D:p2")
        record_adjudication(esc2, "w1D:p2", "codex", "REJECT", "batch feedback", approver="human-tui", human_note="batch note")
        row2 = self._get_row("adjudication_log", 2)
        self.assertEqual(row2["human_note"], "batch note")
        self.assertEqual(row2["approver"], "human-tui")
        self.assertEqual(row2["feedback"], "batch feedback")
        esc2_row = self._get_row("pending_escalations", esc2)
        self.assertEqual(esc2_row["resolution"], "REJECTED")
        self.assertEqual(esc2_row["approver"], "human-tui")

    # ---- INV-HO-3: opinion never grants trust -----------------------------

    def test_gatekeeper_final_disposition_after_opinion_grants_no_trust(self):
        guard_db.init_db()
        esc_id = self._enqueue()
        record_human_opinion(esc_id, "human said go ahead")
        with patch.object(guard_db, "_maybe_promote_workspace_rule") as mock_promote:
            record_adjudication(esc_id, "w1D:p1", "codex", "APPROVE", "gatekeeper feedback", approver="gatekeeper")
        # No novelty-gate seed (has_human_approval_pattern False).
        self.assertFalse(has_human_approval_pattern(normalize_command("rm -rf /tmp/foo"), scope="w1D:p1"))
        # No workspace promotion.
        mock_promote.assert_not_called()
        # Final disposition stays gatekeeper.
        esc = self._get_row("pending_escalations", esc_id)
        self.assertEqual(esc["resolution"], "APPROVED")
        self.assertEqual(esc["approver"], "gatekeeper")
        # The opinion row itself is still there and NOT conflated with feedback.
        rows = guard_db.get_adjudication_exchange(esc_id)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["action"], "HUMAN_OPINION")
        self.assertEqual(rows[0]["human_note"], "human said go ahead")
        self.assertEqual(rows[1]["action"], "APPROVE")
        self.assertEqual(rows[1]["approver"], "gatekeeper")
        self.assertEqual(rows[1]["feedback"], "gatekeeper feedback")
        self.assertIsNone(rows[1]["human_note"])

    def test_explicit_human_tui_adjudication_still_seeds(self):
        guard_db.init_db()
        esc_id = self._enqueue()
        record_human_opinion(esc_id, "human said go ahead")
        with patch.object(guard_db, "_maybe_promote_workspace_rule") as mock_promote:
            record_adjudication(esc_id, "w1D:p1", "codex", "APPROVE", "human feedback", approver="human-tui")
        # INV-HO-3 converse: approver="human-tui" still seeds the novelty gate.
        self.assertTrue(has_human_approval_pattern(normalize_command("rm -rf /tmp/foo"), scope="w1D:p1"))
        mock_promote.assert_called_once()
        esc = self._get_row("pending_escalations", esc_id)
        self.assertEqual(esc["approver"], "human-tui")

    # ---- get_adjudications_for_audit --------------------------------------

    def test_get_adjudications_for_audit_returns_approver_and_human_note(self):
        guard_db.init_db()
        esc_id = self._enqueue(pane_id="w1D:p1", cmd="rm -rf /tmp/foo")
        record_human_opinion(esc_id, "raw human note")
        record_adjudication(esc_id, "w1D:p1", "codex", "APPROVE", "gk feedback", approver="human-tui", human_note="raw human note")
        rows = get_adjudications_for_audit("w1D:p1", "rm -rf /tmp/foo")
        self.assertEqual(len(rows), 2)
        by_action = {r["action"]: r for r in rows}
        opinion = by_action["HUMAN_OPINION"]
        self.assertEqual(opinion["approver"], "human-tui")
        self.assertEqual(opinion["human_note"], "raw human note")
        decision = by_action["APPROVE"]
        self.assertEqual(decision["approver"], "human-tui")
        self.assertEqual(decision["human_note"], "raw human note")

    # ---- INV-HO-6: sanitization --------------------------------------------

    def test_human_note_sanitized(self):
        guard_db.init_db()
        esc_id = self._enqueue()
        dirty = "line1\nline2\r\n\x00\x1b\x07control   spaced\ttext"
        record_human_opinion(esc_id, dirty)
        row = self._get_row("adjudication_log", 1)
        note = row["human_note"]
        self.assertNotIn("\n", note)
        self.assertNotIn("\r", note)
        self.assertNotIn("\x00", note)
        self.assertNotIn("\x1b", note)
        self.assertNotIn("\t", note)
        self.assertEqual(note, "line1 line2 control spaced text")
        self.assertLessEqual(len(note), 256)

    def test_human_note_truncated_to_256(self):
        guard_db.init_db()
        esc_id = self._enqueue()
        record_human_opinion(esc_id, "x" * 500)
        row = self._get_row("adjudication_log", 1)
        self.assertEqual(len(row["human_note"]), 256)


if __name__ == "__main__":
    unittest.main()
