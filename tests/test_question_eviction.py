#!/usr/bin/env python3
"""QUESTION escalation residual-eviction tests (#2800).

A QUESTION escalation (opencode/codex/AGY human-question dialog) must not stay
PENDING forever after the user answers it in the pane. It is resolved as
ANSWERED (pane-direct) — NEVER APPROVED (INV-Q-1) and never seeding the novelty
gate / workspace allowlist (INV-Q-2). Liveness is footer-keyed via the new
adapter.question_is_live (INV-Q-3); blocked panes are never evicted (INV-Q-4);
eviction is debounced by pane_direct_confirm_polls (INV-Q-5).

Uses a clean temp DB (patch guard_db.DB_PATH + init_db) and patched
herdr primitives / resolve_escalation so no Herdr CLI or terminal is required.
"""

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
from adapters.agent_adapters.agy import AgyAdapter
from adapters.agent_adapters.codex import CodexAdapter
from adapters.agent_adapters.opencode import OpenCodeAdapter
from core.guard_db import (
    enqueue_pending_escalation,
    get_escalation_approver,
    get_escalation_resolution,
    has_human_approval_pattern,
    normalize_command,
)
from cmd.schengen_watcher import (
    _question_not_live_streak,
    resolve_cleared_dialog,
    sweep_answered_questions,
)

try:
    from cmd.schengen_tui import SchengenTUIApp
    HAS_TEXTUAL = True
except Exception:  # pragma: no cover - Textual missing in bare envs
    SchengenTUIApp = None  # type: ignore
    HAS_TEXTUAL = False


def _make_app():
    """Bare SchengenTUIApp instance with just the guard state initialized."""
    app = SchengenTUIApp.__new__(SchengenTUIApp)  # type: ignore[attr-defined]
    app._pane_direct_polls = {}
    app._pane_direct_head = None
    return app


class TestQuestionEviction(unittest.TestCase):
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

    def _get_row(self, escalation_id: int) -> dict:
        conn = guard_db.get_db_connection()
        try:
            row = conn.execute(
                "SELECT id, pane_id, raw_command, status, resolution, approver FROM pending_escalations WHERE id = ?",
                (escalation_id,),
            ).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()

    def _enqueue_question(self, pane_id, cmd="question: proceed?"):
        return enqueue_pending_escalation(
            pane_id=pane_id,
            raw_command=cmd,
            safety_reason="Agent asked the user a question",
            decision_layer="QUESTION",
            agent_kind="agy",
        )

    def _question_esc(self, esc_id=21, pane_id="w1D:q1"):
        return {
            "id": esc_id,
            "pane_id": pane_id,
            "agent_kind": "agy",
            "decision_layer": "QUESTION",
            "raw_command": "question: proceed?",
            "safety_reason": "Agent asked the user a question",
        }

    # ---- INV-Q-3: adapter question_is_live (footer-keyed) -----------------

    def test_question_is_live_per_adapter(self):
        # AGY: "Question N/M:" header + "esc Skip" footer -> live.
        agy_text = (
            "Question 1/1: proceed with the install?\n"
            "> 1. Yes\n"
            "> 2. No\n"
            "↑/↓ Navigate · enter Select · esc Skip"
        )
        self.assertTrue(AgyAdapter().question_is_live(agy_text))

        # Codex: "enter to submit answer" footer -> live; dialog_is_live
        # (approval footer) must be FALSE for a question (INV-Q-3 separation).
        codex_text = (
            "Question 1/1 (1 unanswered)\n"
            "Which environment?\n"
            "› 1. prod\n"
            "  2. staging\n"
            "tab to add notes | enter to submit answer | esc to interrupt"
        )
        self.assertTrue(CodexAdapter().question_is_live(codex_text))
        self.assertFalse(CodexAdapter().dialog_is_live(codex_text))

        # OpenCode: "esc dismiss" footer -> live.
        oc_text = "↑↓ select  enter submit  esc dismiss\nWhich stack should I use?"
        self.assertTrue(OpenCodeAdapter().question_is_live(oc_text))

    def test_question_cleared_not_live(self):
        # Footers gone -> NOT live per adapter.
        self.assertFalse(AgyAdapter().question_is_live("Question 1/1: proceed?\nanswered ok\nnext output"))
        self.assertFalse(
            CodexAdapter().question_is_live("Question 1/1 (1 unanswered)\nWhich env?\n› 1. prod\n  2. staging")
        )
        self.assertFalse(OpenCodeAdapter().question_is_live("Which stack?\nanswered ok\nnext output"))

    # ---- INV-Q-1/4/5: TUI guard resolves answered questions as ANSWERED ----

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_tui_evicts_answered_question(self):
        # QUESTION + working + question_is_live False for 2 renders -> resolve
        # ANSWERED (never APPROVED), approver=pane-direct (INV-Q-1/5).
        app = _make_app()
        esc = self._question_esc()
        with patch(
            "cmd.schengen_tui.get_pane_info",
            return_value={"pane_id": "w1D:q1", "agent_status": "working"},
        ), patch("cmd.schengen_tui.get_pane_text", return_value="Question answered in pane\nnext output"), patch(
            "cmd.schengen_tui.resolve_escalation"
        ) as mock_resolve:
            app._pane_direct_liveness_guard(esc, confirm_polls=2)  # 1st not-live: debounced
            evicted2 = app._pane_direct_liveness_guard(esc, confirm_polls=2)  # 2nd: evict
        self.assertTrue(evicted2)
        mock_resolve.assert_called_once_with(
            pane_id="w1D:q1", resolution="ANSWERED", approver="pane-direct"
        )

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_tui_does_not_evict_blocked_question(self):
        # INV-Q-4: blocked question pane -> NEVER evict.
        app = _make_app()
        esc = self._question_esc()
        with patch(
            "cmd.schengen_tui.get_pane_info",
            return_value={"pane_id": "w1D:q1", "agent_status": "blocked"},
        ), patch("cmd.schengen_tui.get_pane_text", return_value=""), patch(
            "cmd.schengen_tui.resolve_escalation"
        ) as mock_resolve:
            for _ in range(3):
                self.assertFalse(app._pane_direct_liveness_guard(esc, confirm_polls=2))
        mock_resolve.assert_not_called()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_tui_single_false_question_no_evict(self):
        # INV-Q-5: a single transient not-live question render is debounced.
        app = _make_app()
        esc = self._question_esc()
        with patch(
            "cmd.schengen_tui.get_pane_info",
            return_value={"pane_id": "w1D:q1", "agent_status": "working"},
        ), patch("cmd.schengen_tui.get_pane_text", return_value="Question answered in pane"), patch(
            "cmd.schengen_tui.resolve_escalation"
        ) as mock_resolve:
            evicted = app._pane_direct_liveness_guard(esc, confirm_polls=2)
        self.assertFalse(evicted)
        mock_resolve.assert_not_called()
        self.assertEqual(app._pane_direct_polls.get(21), 1)

    # ---- watcher: cleared-question resolution + cross-workspace sweep ------

    def test_watcher_resolves_cleared_question_answered(self):
        # The `not req_cmd` cleared-dialog path resolves a QUESTION cache entry
        # as ANSWERED/pane-direct (never APPROVED).
        pane_id = "w1D:q2"
        esc_id = self._enqueue_question(pane_id, cmd="question: deploy now?")
        cached = {"cmd": "question: deploy now?", "seq": 1, "status": "blocked", "is_safe": True, "last_alert_time": 0}
        resolve_cleared_dialog(pane_id, cached)
        row = self._get_row(esc_id)
        self.assertEqual(row["status"], "RESOLVED")
        self.assertEqual(row["resolution"], "ANSWERED")
        self.assertEqual(row["approver"], "pane-direct")

    def test_watcher_resolves_cleared_unsafe_approved(self):
        # Non-question UNSAFE cache entry keeps APPROVED/pane-direct (unchanged).
        pane_id = "w1D:q2b"
        esc_id = enqueue_pending_escalation(
            pane_id=pane_id,
            raw_command="rm -rf /tmp/x",
            safety_reason="test",
            decision_layer="GRAY_ZONE",
            agent_kind="agy",
        )
        cached = {"cmd": "rm -rf /tmp/x", "seq": 1, "status": "blocked", "is_safe": False}
        resolve_cleared_dialog(pane_id, cached)
        row = self._get_row(esc_id)
        self.assertEqual(row["resolution"], "APPROVED")
        self.assertEqual(row["approver"], "pane-direct")

    def test_watcher_question_sweep_cross_workspace(self):
        # PENDING QUESTION on a WORKING pane (find_blocked_panes would skip it)
        # whose dialog is not live -> resolved ANSWERED after confirm_polls.
        pane_id = "w1D:q3"
        esc_id = self._enqueue_question(pane_id, cmd="question: clean up?")
        with patch(
            "cmd.schengen_watcher.get_pane_info",
            return_value={"pane_id": pane_id, "agent": "agy", "agent_status": "working"},
        ), patch("cmd.schengen_watcher.get_pane_text", return_value="cleanup done\nnext output"):
            r1 = sweep_answered_questions(confirm_polls=2)
            self.assertEqual(r1, 0)  # 1st not-live read: debounced (INV-Q-5)
            r2 = sweep_answered_questions(confirm_polls=2)
            self.assertEqual(r2, 1)  # 2nd consecutive: resolved
        row = self._get_row(esc_id)
        self.assertEqual(row["status"], "RESOLVED")
        self.assertEqual(row["resolution"], "ANSWERED")
        self.assertEqual(row["approver"], "pane-direct")

    def test_watcher_question_sweep_skips_blocked_and_live(self):
        # INV-Q-4/3: blocked pane and live question never resolve.
        pane_id = "w1D:q3b"
        esc_id = self._enqueue_question(pane_id, cmd="question: hold on?")
        live_text = "Question 1/1: hold on?\n↑/↓ Navigate · enter Select · esc Skip"
        with patch(
            "cmd.schengen_watcher.get_pane_info",
            side_effect=[
                {"pane_id": pane_id, "agent": "agy", "agent_status": "blocked"},  # 1st sweep: blocked
            ] + [
                {"pane_id": pane_id, "agent": "agy", "agent_status": "working"},  # live question after
            ] * 10,
        ), patch("cmd.schengen_watcher.get_pane_text", return_value=live_text):
            for _ in range(4):
                sweep_answered_questions(confirm_polls=2)
        row = self._get_row(esc_id)
        self.assertEqual(row["status"], "PENDING")  # never resolved

    def test_question_never_seeds_novelty(self):
        # INV-Q-2: an ANSWERED question must NOT seed the human-approved novelty
        # gate (and no workspace promotion happens — resolve_escalation never
        # calls record_human_approval_pattern).
        pane_id = "w1D:q4"
        cmd = "question: wipe tmp?"
        esc_id = self._enqueue_question(pane_id, cmd=cmd)
        with patch(
            "cmd.schengen_watcher.get_pane_info",
            return_value={"pane_id": pane_id, "agent": "agy", "agent_status": "working"},
        ), patch("cmd.schengen_watcher.get_pane_text", return_value="wiped ok"):
            sweep_answered_questions(confirm_polls=1)  # resolve immediately
        row = self._get_row(esc_id)
        self.assertEqual(row["resolution"], "ANSWERED")
        self.assertFalse(has_human_approval_pattern(normalize_command(cmd), scope=pane_id))


if __name__ == "__main__":
    unittest.main()
