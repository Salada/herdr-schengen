"""Gatekeeper approve_escalation adapter-injection tests (issue #23).

Verifies that approve_escalation uses the agent-kind adapter's channel approve
(opencode permission.reply) then keystroke inject_approval (codex 'y', opencode
enter+self-correction) instead of a bare `enter`, and returns an error when the
injection fails.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import core.guard_db as guard_db
from core.guard_db import enqueue_pending_escalation
from tools.schengen_agent_llm import execute_tool_call, reject_batch_escalations
from adapters.agent_adapters.base import INJECT_REJECT_NOT_IMPLEMENTED
from adapters.agent_adapters import INJECT_SKIP_CHANGED


class _FakeAdapter:
    """Minimal AgentAdapter double with configurable channel/inject outcomes."""

    def __init__(self, ch_ok=False, ch_reason="no channel permission", inj_ok=True, inj_reason="ok",
                 rej_ok=True, rej_reason="rejected"):
        self.ch_ok = ch_ok
        self.ch_reason = ch_reason
        self.inj_ok = inj_ok
        self.inj_reason = inj_reason
        self.rej_ok = rej_ok
        self.rej_reason = rej_reason
        self.channel_calls = []
        self.inject_calls = []
        self.reject_calls = []

    def channel_approve(self, pane_id, req_cmd):
        self.channel_calls.append((pane_id, req_cmd))
        return self.ch_ok, self.ch_reason

    def inject_approval(self, pane_id, req_cmd):
        self.inject_calls.append((pane_id, req_cmd))
        return self.inj_ok, self.inj_reason

    def inject_reject(self, pane_id, req_cmd):
        self.reject_calls.append((pane_id, req_cmd))
        return self.rej_ok, self.rej_reason


class TestGatekeeperApproveAdapter(unittest.TestCase):
    """approve_escalation uses adapter-based approval (issue #23)."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def _seed_escalation(self, pane_id="w1D:p1", agent_kind="opencode", raw_cmd="curl example.com") -> int:
        # Seed a real PENDING row so the FIFO-head validation passes.
        return enqueue_pending_escalation(
            pane_id=pane_id,
            raw_command=raw_cmd,
            safety_reason="Network access",
            decision_layer="NOT_ALLOWLISTED",
            agent_kind=agent_kind,
        )

    def _esc_row(self, pane_id="w1D:p1", agent_kind="opencode", raw_cmd="curl example.com"):
        return {"pane_id": pane_id, "agent_kind": agent_kind, "raw_command": raw_cmd}

    def test_approve_falls_back_to_adapter_inject_approval(self):
        esc_id = self._seed_escalation()
        fake = _FakeAdapter(ch_ok=False, ch_reason="no channel permission", inj_ok=True, inj_reason="ok")
        with patch("tools.schengen_agent_llm.resolve_escalation") as mock_resolve, patch(
            "tools.schengen_agent_llm.record_adjudication"
        ) as mock_rec, patch("tools.schengen_agent_llm._get_escalation_row", return_value=self._esc_row()), patch(
            "tools.schengen_agent_llm.get_adapter", return_value=fake
        ):
            res = execute_tool_call("approve_escalation", {"escalation_id": esc_id, "english_feedback": "x"})
        out = json.loads(res)
        self.assertEqual(out["status"], "success")
        # channel_approve failed -> keystroke inject_approval was used with (pane, cmd).
        self.assertEqual(fake.channel_calls, [("w1D:p1", "curl example.com")])
        self.assertEqual(fake.inject_calls, [("w1D:p1", "curl example.com")])
        # FIX 1: a verified injection success DOES record the adjudication.
        mock_resolve.assert_called_once()
        mock_rec.assert_called_once()

    def test_approve_error_when_injection_fails(self):
        esc_id = self._seed_escalation()
        fake_fail = _FakeAdapter(ch_ok=False, inj_ok=False, inj_reason="keyboard inject failed")
        with patch("tools.schengen_agent_llm.resolve_escalation") as mock_resolve, patch(
            "tools.schengen_agent_llm.record_adjudication"
        ) as mock_rec, patch("tools.schengen_agent_llm._get_escalation_row", return_value=self._esc_row()), patch(
            "tools.schengen_agent_llm.get_adapter", return_value=fake_fail
        ):
            res = execute_tool_call("approve_escalation", {"escalation_id": esc_id, "english_feedback": "x"})
        out = json.loads(res)
        self.assertEqual(out["status"], "error")
        self.assertIn("approval injection failed", out["error"])
        self.assertIn("keyboard inject failed", out["error"])
        # FIX 1: on injection failure the adjudication is NOT recorded — the
        # escalation stays PENDING so a retry is possible.
        mock_resolve.assert_not_called()
        mock_rec.assert_not_called()
        pending = guard_db.get_pending_escalations(include_delivered=False)
        self.assertTrue(any(e["id"] == esc_id for e in pending), "escalation must stay PENDING after failure")

    def test_approve_deferred_when_dialog_changed(self):
        # FIX 4: an INJECT_SKIP_CHANGED reason (dialog trampolined to a different
        # request) is surfaced distinctly from a hard delivery failure, and is
        # also NOT recorded as APPROVED.
        esc_id = self._seed_escalation()
        from adapters.agent_adapters import INJECT_SKIP_CHANGED

        fake = _FakeAdapter(ch_ok=False, inj_ok=False, inj_reason=INJECT_SKIP_CHANGED)
        with patch("tools.schengen_agent_llm.resolve_escalation") as mock_resolve, patch(
            "tools.schengen_agent_llm.record_adjudication"
        ) as mock_rec, patch("tools.schengen_agent_llm._get_escalation_row", return_value=self._esc_row()), patch(
            "tools.schengen_agent_llm.get_adapter", return_value=fake
        ):
            res = execute_tool_call("approve_escalation", {"escalation_id": esc_id, "english_feedback": "x"})
        out = json.loads(res)
        self.assertEqual(out["status"], "error")
        self.assertIn("approval deferred", out["error"])
        self.assertIn("dialog changed", out["error"])
        mock_resolve.assert_not_called()
        mock_rec.assert_not_called()

    def test_approve_channel_approve_success_skips_keystroke(self):
        esc_id = self._seed_escalation()
        fake_ch = _FakeAdapter(ch_ok=True, ch_reason="permission.reply decision written")
        with patch("tools.schengen_agent_llm.resolve_escalation"), patch(
            "tools.schengen_agent_llm.record_adjudication"
        ), patch("tools.schengen_agent_llm._get_escalation_row", return_value=self._esc_row()), patch(
            "tools.schengen_agent_llm.get_adapter", return_value=fake_ch
        ):
            res = execute_tool_call("approve_escalation", {"escalation_id": esc_id, "english_feedback": "x"})
        out = json.loads(res)
        self.assertEqual(out["status"], "success")
        self.assertEqual(fake_ch.channel_calls, [("w1D:p1", "curl example.com")])
        self.assertEqual(fake_ch.inject_calls, [])  # no keystroke fallback after channel approve

    def test_approve_no_adapter_uses_legacy_enter(self):
        esc_id = self._seed_escalation()
        with patch("tools.schengen_agent_llm.resolve_escalation"), patch(
            "tools.schengen_agent_llm.record_adjudication"
        ), patch("tools.schengen_agent_llm._get_escalation_row", return_value=self._esc_row()), patch(
            "tools.schengen_agent_llm.get_adapter", return_value=None
        ), patch("subprocess.run") as mock_run:
            mock_run.return_value = None
            res = execute_tool_call("approve_escalation", {"escalation_id": esc_id, "english_feedback": "x"})
        out = json.loads(res)
        self.assertEqual(out["status"], "success")
        called = [c.args[0] for c in mock_run.call_args_list]
        self.assertTrue(any("enter" in c for c in called), f"expected legacy bare enter, got {called}")

    def test_approve_directive_true_records_human_tui_provenance(self):
        """directive=true (explicit human /approve or free-text directive)
        records approver='human-tui' + human_note — the human is the final
        decision authority and their approval seeds the novelty gate."""
        esc_id = self._seed_escalation()
        fake = _FakeAdapter(ch_ok=True, ch_reason="permission.reply decision written")
        with patch("tools.schengen_agent_llm.resolve_escalation"), patch(
            "tools.schengen_agent_llm.record_adjudication"
        ) as mock_rec, patch("tools.schengen_agent_llm._get_escalation_row", return_value=self._esc_row()), patch(
            "tools.schengen_agent_llm.get_adapter", return_value=fake
        ):
            res = execute_tool_call("approve_escalation", {
                "escalation_id": esc_id,
                "english_feedback": "Executed human approval. Segments: mutation=rm -rf /tmp/foo.",
                "directive": True,
            })
        out = json.loads(res)
        self.assertEqual(out["status"], "success")
        mock_rec.assert_called_once()
        kwargs = mock_rec.call_args.kwargs
        self.assertEqual(kwargs["approver"], "human-tui")
        self.assertEqual(kwargs["human_note"], "Executed human approval. Segments: mutation=rm -rf /tmp/foo.")

    def test_approve_directive_false_records_gatekeeper_provenance(self):
        """directive omitted/false (autonomous obvious-safe approve) records
        approver='gatekeeper' and NO human_note — least-privileged provenance
        that never seeds the novelty gate."""
        esc_id = self._seed_escalation()
        fake = _FakeAdapter(ch_ok=True, ch_reason="permission.reply decision written")
        with patch("tools.schengen_agent_llm.resolve_escalation"), patch(
            "tools.schengen_agent_llm.record_adjudication"
        ) as mock_rec, patch("tools.schengen_agent_llm._get_escalation_row", return_value=self._esc_row()), patch(
            "tools.schengen_agent_llm.get_adapter", return_value=fake
        ):
            res = execute_tool_call("approve_escalation", {
                "escalation_id": esc_id,
                "english_feedback": "Approved. Segments: chained=none, mutation=none.",
            })
        out = json.loads(res)
        self.assertEqual(out["status"], "success")
        mock_rec.assert_called_once()
        kwargs = mock_rec.call_args.kwargs
        self.assertEqual(kwargs["approver"], "gatekeeper")
        self.assertIsNone(kwargs.get("human_note"))

    def test_reject_directive_true_records_human_tui_provenance(self):
        """directive=true on reject_escalation (explicit human /reject) records
        approver='human-tui' + human_note."""
        esc_id = self._seed_escalation()
        with patch("tools.schengen_agent_llm.resolve_escalation"), patch(
            "tools.schengen_agent_llm.record_adjudication"
        ) as mock_rec, patch("tools.schengen_agent_llm._get_escalation_row", return_value=self._esc_row()), patch(
            "subprocess.run"
        ) as mock_run:
            mock_run.return_value = None
            res = execute_tool_call("reject_escalation", {
                "escalation_id": esc_id,
                "english_feedback": "Executed human rejection. Segments: mutation=rm -rf /.",
                "directive": True,
            })
        out = json.loads(res)
        self.assertEqual(out["status"], "success")
        mock_rec.assert_called_once()
        kwargs = mock_rec.call_args.kwargs
        self.assertEqual(kwargs["approver"], "human-tui")
        self.assertEqual(kwargs["human_note"], "Executed human rejection. Segments: mutation=rm -rf /.")

    def test_reject_directive_false_records_gatekeeper_provenance(self):
        """directive omitted/false (autonomous Tier A critical reject) records
        approver='gatekeeper' and NO human_note."""
        esc_id = self._seed_escalation()
        with patch("tools.schengen_agent_llm.resolve_escalation"), patch(
            "tools.schengen_agent_llm.record_adjudication"
        ) as mock_rec, patch("tools.schengen_agent_llm._get_escalation_row", return_value=self._esc_row()), patch(
            "subprocess.run"
        ) as mock_run:
            mock_run.return_value = None
            res = execute_tool_call("reject_escalation", {
                "escalation_id": esc_id,
                "english_feedback": "Rejected. Segments: mutation=rm -rf /.",
            })
        out = json.loads(res)
        self.assertEqual(out["status"], "success")
        mock_rec.assert_called_once()
        kwargs = mock_rec.call_args.kwargs
        self.assertEqual(kwargs["approver"], "gatekeeper")
        self.assertIsNone(kwargs.get("human_note"))

    def test_reject_batch_delegates_to_adapter_inject_reject(self):
        """M7 item 4: reject_batch uses the agent-aware adapter inject_reject
        (opencode permission.reply 'reject' channel / codex esc / agy esc) —
        NO bare escape keystroke is sent to the pane."""
        esc_id = self._seed_escalation()
        fake = _FakeAdapter(rej_ok=True, rej_reason="permission.reply reject decision written")
        with patch("tools.schengen_agent_llm.get_adapter", return_value=fake), patch(
            "tools.schengen_agent_llm.resolve_escalation"
        ) as mock_resolve, patch("tools.schengen_agent_llm.record_adjudication") as mock_rec, patch(
            "tools.schengen_agent_llm.subprocess.run"
        ) as mock_run:
            result = reject_batch_escalations("batch no")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["resolved"], [esc_id])
        self.assertEqual(fake.reject_calls, [("w1D:p1", "curl example.com")])
        mock_run.assert_not_called()  # adapter handled the reject — no bare escape
        mock_resolve.assert_called_once()
        mock_rec.assert_called_once()

    def test_reject_batch_falls_back_to_bare_escape_when_adapter_not_implemented(self):
        """M7 item 4: an adapter without inject_reject (not-implemented) keeps
        the legacy bare-escape dismiss — reject_escalation parity."""
        esc_id = self._seed_escalation()
        fake = _FakeAdapter(rej_ok=False, rej_reason=INJECT_REJECT_NOT_IMPLEMENTED)
        with patch("tools.schengen_agent_llm.get_adapter", return_value=fake), patch(
            "tools.schengen_agent_llm.resolve_escalation"
        ), patch("tools.schengen_agent_llm.record_adjudication"), patch(
            "tools.schengen_agent_llm.subprocess.run"
        ) as mock_run:
            mock_run.return_value = None
            result = reject_batch_escalations("batch no")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["resolved"], [esc_id])
        called = [c.args[0] for c in mock_run.call_args_list]
        self.assertTrue(any("escape" in c for c in called), f"expected bare escape, got {called}")

    def test_reject_batch_no_adapter_uses_legacy_bare_escape(self):
        """M7 item 4: with no registered adapter (adapter is None) reject_batch
        falls back to the legacy bare-escape dismiss."""
        esc_id = self._seed_escalation()
        with patch("tools.schengen_agent_llm.get_adapter", return_value=None), patch(
            "tools.schengen_agent_llm.resolve_escalation"
        ), patch("tools.schengen_agent_llm.record_adjudication"), patch(
            "tools.schengen_agent_llm.subprocess.run"
        ) as mock_run:
            mock_run.return_value = None
            result = reject_batch_escalations("batch no")
        self.assertEqual(result["resolved"], [esc_id])
        called = [c.args[0] for c in mock_run.call_args_list]
        self.assertTrue(any("escape" in c for c in called), f"expected bare escape, got {called}")

    def test_reject_batch_real_failure_defers_fail_closed(self):
        """M7 item 4: a REAL inject_reject failure (dialog changed / CLI error,
        NOT 'not implemented') defers the item — no bare escape, no CANCELLED,
        the escalation stays PENDING (fail-closed)."""
        esc_id = self._seed_escalation()
        fake = _FakeAdapter(rej_ok=False, rej_reason=INJECT_SKIP_CHANGED)
        with patch("tools.schengen_agent_llm.get_adapter", return_value=fake), patch(
            "tools.schengen_agent_llm.resolve_escalation"
        ) as mock_resolve, patch("tools.schengen_agent_llm.record_adjudication") as mock_rec, patch(
            "tools.schengen_agent_llm.subprocess.run"
        ) as mock_run:
            result = reject_batch_escalations("batch no")
        self.assertEqual(result["resolved"], [])
        self.assertEqual(result["deferred"], [esc_id])
        mock_run.assert_not_called()
        mock_resolve.assert_not_called()
        mock_rec.assert_not_called()
        pending = guard_db.get_pending_escalations(include_delivered=False)
        self.assertTrue(any(e["id"] == esc_id for e in pending), "escalation must stay PENDING on real reject failure")


if __name__ == "__main__":
    unittest.main()
