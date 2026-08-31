#!/usr/bin/env python3
"""Question 분리 (non-blocking) tests (#160 / INV-QN-1..5).

A PENDING QUESTION must not occupy the Command Approval slot (strict FIFO):
- get_pending_command_escalations / get_current_command_escalation EXCLUDE
  QUESTION rows (INV-QN-1) — the command head proceeds while the question
  stays PENDING (INV-QN-2).
- get_oldest_question_escalation surfaces the question for the sidebar hint
  (INV-QN-3); the #2800 ANSWERED sweep still fires for non-head questions.
- approve_escalation's head check uses the command slot (INV-QN-4/5).

Uses a clean temp DB (patch guard_db.DB_PATH + init_db) and mocked injection /
herdr primitives so no Herdr CLI or terminal is required.
"""

import json
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
from cmd.schengen_watcher import _question_not_live_streak, sweep_answered_questions
from tools.schengen_agent_llm import (
    approve_batch_escalations,
    execute_tool_call,
    get_current_active_escalation,
    get_current_command_escalation,
    get_oldest_question_escalation,
    reject_batch_escalations,
)


class TestQuestionNonBlocking(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()
        _question_not_live_streak.clear()

    def tearDown(self):
        _question_not_live_streak.clear()
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def _enqueue(self, pane_id, cmd, layer, agent_kind="agy"):
        return guard_db.enqueue_pending_escalation(
            pane_id=pane_id,
            raw_command=cmd,
            safety_reason="test",
            decision_layer=layer,
            agent_kind=agent_kind,
        )

    def _get_row(self, escalation_id: int) -> dict:
        conn = guard_db.get_db_connection()
        try:
            row = conn.execute(
                "SELECT id, pane_id, raw_command, status, resolution, approver, decision_layer "
                "FROM pending_escalations WHERE id = ?",
                (escalation_id,),
            ).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()

    # ---- INV-QN-1/2: command slot excludes questions ----------------------

    def test_get_current_command_escalation_excludes_questions(self):
        q_id = self._enqueue("w1D:q1", "question: proceed?", "QUESTION")
        c_id = self._enqueue("w1D:c1", "rm -rf /tmp/x", "GRAY_ZONE")
        head = get_current_command_escalation()
        self.assertIsNotNone(head)
        self.assertEqual(head["id"], c_id)      # QUESTION(id1) skipped -> COMMAND(id2)
        self.assertEqual(head["decision_layer"], "GRAY_ZONE")

    def test_get_oldest_question_escalation_returns_question(self):
        q_id = self._enqueue("w1D:q2", "question: deploy?", "QUESTION")
        self._enqueue("w1D:c2", "git push --force", "GRAY_ZONE")
        q = get_oldest_question_escalation()
        self.assertIsNotNone(q)
        self.assertEqual(q["id"], q_id)
        self.assertEqual(q["decision_layer"], "QUESTION")

    def test_get_current_active_escalation_still_includes_questions(self):
        q_id = self._enqueue("w1D:q3", "question: hold?", "QUESTION")
        self._enqueue("w1D:c3", "sudo rm -rf /tmp/y", "GRAY_ZONE")
        head = get_current_active_escalation()  # backward-compat: FIFO including questions
        self.assertIsNotNone(head)
        self.assertEqual(head["id"], q_id)      # oldest row IS the question

    def test_command_slot_empty_when_only_question_pending(self):
        self._enqueue("w1D:q4", "question: only?", "QUESTION")
        self.assertIsNone(get_current_command_escalation())  # no command -> no head
        self.assertIsNotNone(get_oldest_question_escalation())

    # ---- INV-QN-4: approve skips a QUESTION head --------------------------

    def test_llm_approve_skips_question_head(self):
        # QUESTION is the OLDEST row, but approve_escalation targets the COMMAND
        # head (command slot excludes questions) -> succeeds.
        self._enqueue("w1D:q5", "question: block me?", "QUESTION")
        c_id = self._enqueue("w1D:c5", "brew install untrusted-pkg", "GRAY_ZONE")
        with patch("tools.schengen_agent_llm._inject_approval", return_value=(True, "ok")) as mock_inject, patch(
            "subprocess.run", return_value=None
        ):
            resp = execute_tool_call("approve_escalation", {"escalation_id": str(c_id), "english_feedback": "ok"})
        data = json.loads(resp)
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["escalation_id"], c_id)
        mock_inject.assert_called_once()
        row = self._get_row(c_id)
        self.assertEqual(row["status"], "RESOLVED")

    def test_llm_approve_still_rejects_non_head_command(self):
        # A non-head COMMAND (behind another command) is still rejected — strict
        # command FIFO preserved (INV-QN-5).
        c1 = self._enqueue("w1D:c6", "git push --force", "GRAY_ZONE")
        c2 = self._enqueue("w1D:c6", "sudo reboot", "SHELL_CRITICAL")
        with patch("tools.schengen_agent_llm._inject_approval", return_value=(True, "ok")):
            resp = execute_tool_call("approve_escalation", {"escalation_id": str(c2), "english_feedback": "ok"})
        data = json.loads(resp)
        self.assertEqual(data["status"], "error")
        self.assertIn("not the current active FIFO head", data["error"])
        self.assertEqual(self._get_row(c2)["status"], "PENDING")

    # ---- INV-QN-4: batch approve/reject exclude questions -----------------

    def test_approve_batch_skips_question_head(self):
        # A QUESTION is the OLDEST row, but the batch head must be the oldest
        # COMMAND group — the question is never injected/resolved/adjudicated.
        q_id = self._enqueue("w1D:q8", "question: batch me?", "QUESTION")
        c_id = self._enqueue("w1D:c8", "brew install untrusted-pkg", "GRAY_ZONE")
        with patch("tools.schengen_agent_llm._inject_approval", return_value=(True, "ok")), patch(
            "tools.schengen_agent_llm.record_adjudication"
        ) as mock_adjudicate:
            result = approve_batch_escalations(feedback="ok")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["resolved"], [c_id])  # only the COMMAND resolved
        q_row = self._get_row(q_id)
        self.assertEqual(q_row["status"], "PENDING")  # question untouched
        self.assertIsNone(q_row["resolution"])
        c_row = self._get_row(c_id)
        self.assertEqual(c_row["status"], "RESOLVED")
        self.assertEqual(c_row["approver"], "human-tui")
        # record_adjudication never saw the QUESTION escalation id
        adjudicated_ids = [c.args[0] for c in mock_adjudicate.call_args_list]
        self.assertNotIn(q_id, adjudicated_ids)
        self.assertIn(c_id, adjudicated_ids)

    def test_reject_batch_skips_question_head(self):
        q_id = self._enqueue("w1D:q9", "question: reject me?", "QUESTION")
        c_id = self._enqueue("w1D:c9", "sudo rm -rf /tmp/x", "GRAY_ZONE")
        with patch("subprocess.run", return_value=None), patch(
            "tools.schengen_agent_llm.record_adjudication"
        ) as mock_adjudicate:
            result = reject_batch_escalations(feedback="no")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["resolved"], [c_id])  # only the COMMAND resolved
        q_row = self._get_row(q_id)
        self.assertEqual(q_row["status"], "PENDING")  # question untouched
        c_row = self._get_row(c_id)
        self.assertEqual(c_row["status"], "CANCELLED")
        adjudicated_ids = [c.args[0] for c in mock_adjudicate.call_args_list]
        self.assertNotIn(q_id, adjudicated_ids)
        self.assertIn(c_id, adjudicated_ids)

    # ---- INV-QN-3: sweep still resolves a non-head question ---------------

    def test_sweep_answered_questions_still_fires_when_not_head(self):
        # QUESTION + COMMAND both pending; the command occupies the slot but the
        # #2800 sweep still resolves the (non-head) answered question.
        q_id = self._enqueue("w1D:q7", "question: clean up?", "QUESTION")
        c_id = self._enqueue("w1D:c7", "rm -rf /tmp/z", "GRAY_ZONE")
        with patch(
            "cmd.schengen_watcher.get_pane_info",
            return_value={"pane_id": "w1D:q7", "agent": "agy", "agent_status": "working"},
        ), patch("cmd.schengen_watcher.get_pane_text", return_value="cleaned ok\nnext output"):
            sweep_answered_questions(confirm_polls=2)  # 1st: debounced
            sweep_answered_questions(confirm_polls=2)  # 2nd: resolved
        q_row = self._get_row(q_id)
        self.assertEqual(q_row["resolution"], "ANSWERED")
        self.assertEqual(q_row["approver"], "pane-direct")
        c_row = self._get_row(c_id)
        self.assertEqual(c_row["status"], "PENDING")  # command untouched


if __name__ == "__main__":
    unittest.main()
