#!/usr/bin/env python3
"""TUI pane-direct liveness guard tests (INV-PD-4/5, #7771).

The TUI pre-render slot validation must NEVER fake-approve a live dialog:
- INV-PD-4: while the pane agent_status is 'blocked' the escalation is NEVER
  evicted (a blocked agent is still waiting on the user).
- INV-PD-5: a not-live dialog is only evicted after `confirm_polls` (default 2)
  CONSECUTIVE not-live renders — a single transient read is debounced.
- The per-escalation counter resets when the FIFO head escalation id changes.

Uses `SchengenTUIApp.__new__` (bypasses the Textual constructor) + patched
module-level get_pane_info / get_pane_text / resolve_escalation so no terminal
or Herdr CLI is required.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

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


class TestTUIPaneDirectGuard(unittest.TestCase):
    def setUp(self):
        self.esc = {
            "id": 7,
            "pane_id": "w1D:pA",
            "agent_kind": "agy",
            "decision_layer": "GRAY_ZONE",
            "raw_command": "rm -rf /tmp/x",
            "safety_reason": "test escalation",
        }

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_tui_does_not_evict_blocked_agy(self):
        # INV-PD-4: pane status blocked -> NEVER evict, even if the dialog
        # liveness read would say not-live (no pane read is even issued).
        app = _make_app()
        with patch(
            "cmd.schengen_tui.get_pane_info",
            return_value={"pane_id": "w1D:pA", "agent_status": "blocked"},
        ) as mock_info, patch("cmd.schengen_tui.get_pane_text", return_value="") as mock_read, patch(
            "cmd.schengen_tui.resolve_escalation"
        ) as mock_resolve:
            evicted = app._pane_direct_liveness_guard(self.esc, confirm_polls=2)
        self.assertFalse(evicted)
        mock_resolve.assert_not_called()
        mock_read.assert_not_called()  # blocked -> no pane text read at all
        self.assertEqual(app._pane_direct_polls.get(7), 0)
        mock_info.assert_called()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_tui_single_false_does_not_evict(self):
        # INV-PD-5: one transient not-live render is debounced — no eviction.
        app = _make_app()
        with patch(
            "cmd.schengen_tui.get_pane_info",
            return_value={"pane_id": "w1D:pA", "agent_status": "working"},
        ), patch("cmd.schengen_tui.get_pane_text", return_value="cleared pane text"), patch(
            "cmd.schengen_tui.resolve_escalation"
        ) as mock_resolve:
            evicted = app._pane_direct_liveness_guard(self.esc, confirm_polls=2)
        self.assertFalse(evicted)
        mock_resolve.assert_not_called()
        self.assertEqual(app._pane_direct_polls.get(7), 1)

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_tui_evicts_after_confirm_polls(self):
        # INV-PD-5: two CONSECUTIVE not-live renders (working status) evict on
        # the second, with pane-direct provenance.
        app = _make_app()
        with patch(
            "cmd.schengen_tui.get_pane_info",
            return_value={"pane_id": "w1D:pA", "agent_status": "working"},
        ), patch("cmd.schengen_tui.get_pane_text", return_value="cleared pane text"), patch(
            "cmd.schengen_tui.resolve_escalation"
        ) as mock_resolve:
            app._pane_direct_liveness_guard(self.esc, confirm_polls=2)  # poll 1: debounced
            evicted2 = app._pane_direct_liveness_guard(self.esc, confirm_polls=2)  # poll 2: evict
        self.assertTrue(evicted2)
        mock_resolve.assert_called_once_with(
            pane_id="w1D:pA", resolution="APPROVED", approver="pane-direct"
        )

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_tui_resets_counter_on_new_head(self):
        # The per-escalation counter dict resets when the FIFO head changes.
        app = _make_app()
        with patch(
            "cmd.schengen_tui.get_pane_info",
            return_value={"pane_id": "w1D:pA", "agent_status": "working"},
        ), patch("cmd.schengen_tui.get_pane_text", return_value="cleared"), patch(
            "cmd.schengen_tui.resolve_escalation"
        ):
            app._pane_direct_liveness_guard(self.esc, confirm_polls=2)
            self.assertEqual(app._pane_direct_polls.get(7), 1)
            new_esc = dict(self.esc, id=8, pane_id="w1D:pB", raw_command="rm -rf /tmp/y")
            app._pane_direct_liveness_guard(new_esc, confirm_polls=2)
        self.assertIsNone(app._pane_direct_polls.get(7))  # old head counter cleared
        self.assertIn(8, app._pane_direct_polls)          # new head tracked
        self.assertEqual(app._pane_direct_head, 8)

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_tui_get_pane_info_error_never_evicts(self):
        # INV-PD-4 fail-closed: a get_pane_info EXCEPTION must never reach the
        # debounce/eviction path — unknown status -> never evict, even across
        # many renders.
        app = _make_app()
        with patch(
            "cmd.schengen_tui.get_pane_info", side_effect=RuntimeError("herdr CLI unavailable")
        ), patch("cmd.schengen_tui.get_pane_text", return_value="cleared pane text"), patch(
            "cmd.schengen_tui.resolve_escalation"
        ) as mock_resolve:
            for _ in range(3):  # well beyond confirm_polls=2
                evicted = app._pane_direct_liveness_guard(self.esc, confirm_polls=2)
                self.assertFalse(evicted)
        mock_resolve.assert_not_called()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_tui_get_pane_info_empty_never_evicts(self):
        # INV-PD-4 fail-closed: get_pane_info returning no/empty agent_status
        # ({} or None) must never evict.
        app = _make_app()
        for empty_info in ({}, None):
            with patch(
                "cmd.schengen_tui.get_pane_info", return_value=empty_info
            ), patch("cmd.schengen_tui.get_pane_text", return_value="cleared pane text"), patch(
                "cmd.schengen_tui.resolve_escalation"
            ) as mock_resolve:
                for _ in range(3):
                    evicted = app._pane_direct_liveness_guard(self.esc, confirm_polls=2)
                    self.assertFalse(evicted)
            mock_resolve.assert_not_called()

    @unittest.skipUnless(HAS_TEXTUAL, "Textual required")
    def test_tui_live_dialog_resets_counter(self):
        # A live read resets the not-live counter (no eviction on recovery).
        app = _make_app()
        live_text = "Requesting permission for: rm -rf /tmp/x\nDo you want to proceed?\n> 1. Yes"
        with patch(
            "cmd.schengen_tui.get_pane_info",
            return_value={"pane_id": "w1D:pA", "agent_status": "working"},
        ), patch("cmd.schengen_tui.get_pane_text", return_value="cleared") as mock_read, patch(
            "cmd.schengen_tui.resolve_escalation"
        ) as mock_resolve:
            app._pane_direct_liveness_guard(self.esc, confirm_polls=2)  # not-live -> counter 1
            self.assertEqual(app._pane_direct_polls.get(7), 1)
            mock_read.return_value = live_text  # dialog comes back live
            evicted = app._pane_direct_liveness_guard(self.esc, confirm_polls=2)
        self.assertFalse(evicted)
        mock_resolve.assert_not_called()
        self.assertEqual(app._pane_direct_polls.get(7), 0)  # counter reset


if __name__ == "__main__":
    unittest.main()
