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
from tools.schengen_agent_llm import execute_tool_call


class _FakeAdapter:
    """Minimal AgentAdapter double with configurable channel/inject outcomes."""

    def __init__(self, ch_ok=False, ch_reason="no channel permission", inj_ok=True, inj_reason="ok"):
        self.ch_ok = ch_ok
        self.ch_reason = ch_reason
        self.inj_ok = inj_ok
        self.inj_reason = inj_reason
        self.channel_calls = []
        self.inject_calls = []

    def channel_approve(self, pane_id, req_cmd):
        self.channel_calls.append((pane_id, req_cmd))
        return self.ch_ok, self.ch_reason

    def inject_approval(self, pane_id, req_cmd):
        self.inject_calls.append((pane_id, req_cmd))
        return self.inj_ok, self.inj_reason


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
        with patch("tools.schengen_agent_llm.resolve_escalation"), patch(
            "tools.schengen_agent_llm.record_adjudication"
        ), patch("tools.schengen_agent_llm._get_escalation_row", return_value=self._esc_row()), patch(
            "tools.schengen_agent_llm.get_adapter", return_value=fake
        ):
            res = execute_tool_call("approve_escalation", {"escalation_id": esc_id, "english_feedback": "x"})
        out = json.loads(res)
        self.assertEqual(out["status"], "success")
        # channel_approve failed -> keystroke inject_approval was used with (pane, cmd).
        self.assertEqual(fake.channel_calls, [("w1D:p1", "curl example.com")])
        self.assertEqual(fake.inject_calls, [("w1D:p1", "curl example.com")])

    def test_approve_error_when_injection_fails(self):
        esc_id = self._seed_escalation()
        fake_fail = _FakeAdapter(ch_ok=False, inj_ok=False, inj_reason="keyboard inject failed")
        with patch("tools.schengen_agent_llm.resolve_escalation"), patch(
            "tools.schengen_agent_llm.record_adjudication"
        ), patch("tools.schengen_agent_llm._get_escalation_row", return_value=self._esc_row()), patch(
            "tools.schengen_agent_llm.get_adapter", return_value=fake_fail
        ):
            res = execute_tool_call("approve_escalation", {"escalation_id": esc_id, "english_feedback": "x"})
        out = json.loads(res)
        self.assertEqual(out["status"], "error")
        self.assertIn("approval injection failed", out["error"])
        self.assertIn("keyboard inject failed", out["error"])

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


if __name__ == "__main__":
    unittest.main()
