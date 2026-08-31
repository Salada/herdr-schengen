"""Sprint 1c Auto-Advance tests (P0 dialog-trampoline fix, Refs #3689).

Covers the coordinator (adapters/auto_advance.py), the gatekeeper wiring
(tools/schengen_agent_llm.py approve_escalation / approve_batch_escalations),
the watcher audit-truth fix (INV-AA-8), and provenance isolation (INV-AA-6/9).

Harness mirrors tests/test_gatekeeper_approve_adapter.py (FakeAdapter, clean
temp DB, patch tools.schengen_agent_llm._inject_approval) — no subprocess, no
live pane.
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
from core.guard_db import (
    enqueue_pending_escalation,
    get_db_connection,
    get_pending_escalations,
    get_recent_audit_logs,
)
from core.security_evaluator import DecisionLayer, Origin
from tools.schengen_agent_llm import approve_batch_escalations, execute_tool_call
from adapters.agent_adapters import INJECT_SKIP_CHANGED
from adapters.auto_advance import AutoAdvanceResult, auto_advance_once, run_auto_advance
from cmd.schengen_watcher import drain_completed_inspections

A_CMD = "access_directory /tmp"


def _verdict(is_safe, reason="reason", layer=DecisionLayer.FAST_TRACK_AST, **tax):
    tax = {
        "origin": "A", "consequence": "NONE", "mechanism": "fast-track-verified",
        "gate_state": "ENFORCE", "shadow_mode": False, **tax,
    }
    return (is_safe, reason, layer, tax)


def _audit_rows(decision=None):
    rows = get_recent_audit_logs(limit=50)
    if decision:
        return [r for r in rows if r["decision"] == decision]
    return rows


def _mechanism_of(raw_command, decision):
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT mechanism FROM audit_logs WHERE raw_command = ? AND decision = ? ORDER BY id DESC LIMIT 1",
            (raw_command, decision),
        ).fetchone()
    return row["mechanism"] if row else None


class _FakeAdapter:
    """AgentAdapter double with a scripted pending-request queue + inject capture.

    pending: None (always None) | callable(pane_id, text) | list (pop front).
    """

    def __init__(self, pending=None, ch_ok=False, ch_reason="no channel permission",
                 inj_ok=True, inj_reason="ok"):
        self._pending = pending
        self.ch_ok = ch_ok
        self.ch_reason = ch_reason
        self.inj_ok = inj_ok
        self.inj_reason = inj_reason
        self.inject_calls = []
        self.channel_calls = []

    def get_pending_request(self, pane_id, text):
        if self._pending is None:
            return None
        if callable(self._pending):
            return self._pending(pane_id, text)
        if isinstance(self._pending, list):
            return self._pending.pop(0) if self._pending else None
        return self._pending

    def channel_approve(self, pane_id, req_cmd):
        self.channel_calls.append((pane_id, req_cmd))
        return self.ch_ok, self.ch_reason

    def inject_approval(self, pane_id, req_cmd):
        self.inject_calls.append((pane_id, req_cmd))
        return self.inj_ok, self.inj_reason


class TestAutoAdvanceCoordinator(unittest.TestCase):
    """Direct coordinator tests (no DB, no gatekeeper)."""

    def setUp(self):
        self.adapter = _FakeAdapter(pending=lambda pane_id, text: "echo safe")
        self.pane_text = "Permission required\n\n$ echo safe\n\nAllow once  Allow always  Reject"
        patchers = [
            patch("adapters.auto_advance.get_pane_text", return_value=self.pane_text),
            patch("adapters.auto_advance.get_adapter", return_value=self.adapter),
            patch("adapters.auto_advance.audit_shell_command_with_taxonomy", return_value=_verdict(True)),
            patch("adapters.auto_advance.MAX_AUTO_ADVANCE_HOPS", 3),
            patch("adapters.auto_advance.AUTO_ADVANCE_DEADLINE_SECONDS", 10.0),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)

    def _run(self, prev=A_CMD):
        return run_auto_advance(
            "w1D:p1", "opencode", prev,
            cwd="/tmp", scope="w1D:p1", agent_id="opencode",
            use_llm_judge=False, reasoning_effort="low",
        )

    def test_safe_trampoline_auto_injects_b(self):
        # Test 1: the pane trampolined A->B; B evaluates SAFE -> B is injected
        # via the verified-inject path (INV-AA-1/2).
        res = self._run()
        self.assertEqual(res.outcome, "advanced_safe")
        self.assertEqual(res.new_req_cmd, "echo safe")
        self.assertTrue(res.is_safe)
        self.assertEqual(self.adapter.inject_calls, [("w1D:p1", "echo safe")])

    def test_same_request_returns_not_trampolined(self):
        # No real trampoline: the live dialog still shows A -> not_trampolined,
        # caller re-delegates normally (never injects a second copy of A).
        self.adapter._pending = lambda pane_id, text: A_CMD
        res = self._run()
        self.assertEqual(res.outcome, "not_trampolined")
        self.assertEqual(self.adapter.inject_calls, [])

    def test_no_pending_request_fail_closed(self):
        # INV-AA-5: get_pending_request -> None -> not_trampolined (no new
        # dialog) — never inject.
        self.adapter._pending = None
        res = self._run()
        self.assertEqual(res.outcome, "not_trampolined")
        self.assertEqual(self.adapter.inject_calls, [])

    def test_unsafe_b_not_injected(self):
        # INV-AA-1: B = rm -rf / must NOT be auto-approved regardless of A.
        self.adapter._pending = lambda pane_id, text: "rm -rf /"
        with patch("adapters.auto_advance.audit_shell_command_with_taxonomy",
                   return_value=_verdict(False, "destructive", DecisionLayer.SHELL_CRITICAL)):
            res = self._run()
        self.assertEqual(res.outcome, "advanced_unsafe")
        self.assertEqual(res.new_req_cmd, "rm -rf /")
        self.assertFalse(res.is_safe)
        self.assertEqual(res.layer, DecisionLayer.SHELL_CRITICAL)
        self.assertEqual(self.adapter.inject_calls, [])

    def test_b_full_pipeline_re_evaluation_no_inheritance(self):
        # INV-AA-1: the evaluator is re-invoked for B (never A) with a fresh
        # origin=AGENT — B never inherits A's verdict/provenance.
        audit_calls = []

        def spy(*args, **kwargs):
            audit_calls.append((args, kwargs))
            return _verdict(True)

        with patch("adapters.auto_advance.audit_shell_command_with_taxonomy", side_effect=spy):
            res = self._run()
        self.assertEqual(res.outcome, "advanced_safe")
        self.assertEqual(len(audit_calls), 1)
        (cmd,), kwargs = audit_calls[0]
        self.assertEqual(cmd, "echo safe")  # B, not A
        self.assertEqual(kwargs["origin"], Origin.AGENT)  # re-derived, never inherited
        self.assertEqual(kwargs["cwd"], "/tmp")  # A's cwd inherited (INV-AA-2)
        self.assertEqual(kwargs["scope"], "w1D:p1")  # A's scope inherited

    def test_hop_budget_stops_at_boundary_escalates_d(self):
        # INV-AA-3: A->B->C->D with MAX=3 — B and C are auto-injected; the dialog
        # at the budget boundary (D, the 4th dialog) is returned as
        # budget_exhausted WITHOUT injection so the caller escalates D.
        self.adapter._pending = ["B", "C", "D"]
        res = self._run()
        self.assertEqual(res.outcome, "budget_exhausted")
        self.assertEqual(res.new_req_cmd, "D")
        self.assertFalse(res.is_safe)
        self.assertEqual([c[1] for c in self.adapter.inject_calls], ["B", "C"])
        self.assertNotIn("D", [c[1] for c in self.adapter.inject_calls])

    def test_deadline_expiry_never_injects(self):
        # INV-AA-4: a slow evaluator crosses the deadline mid-evaluation ->
        # budget_exhausted; the safe-but-late B is escalated and NEVER injected.
        with patch("adapters.auto_advance.AUTO_ADVANCE_DEADLINE_SECONDS", 1.0), \
             patch("adapters.auto_advance.time.monotonic", side_effect=[100.0, 100.5, 200.0]):
            res = self._run()
        self.assertEqual(res.outcome, "budget_exhausted")
        self.assertEqual(res.new_req_cmd, "echo safe")
        self.assertEqual(self.adapter.inject_calls, [])

    def test_evaluator_exception_fail_closed(self):
        # INV-AA-5: an evaluator exception -> parse_failed (is_safe=False),
        # never inject; the caller escalates B.
        def boom(*args, **kwargs):
            raise RuntimeError("evaluator exploded")

        with patch("adapters.auto_advance.audit_shell_command_with_taxonomy", side_effect=boom):
            res = self._run()
        self.assertEqual(res.outcome, "parse_failed")
        self.assertFalse(res.is_safe)
        self.assertEqual(res.new_req_cmd, "echo safe")
        self.assertEqual(self.adapter.inject_calls, [])

    def test_auto_advance_once_signature_and_hop_context(self):
        # auto_advance_once is the single-hop primitive; it accepts the run
        # loop's budget context (remaining_hops/deadline) and performs one
        # re-parse + one fresh full-pipeline evaluation.
        res = auto_advance_once(
            "w1D:p1", "opencode", A_CMD,
            cwd="/tmp", scope="w1D:p1", agent_id="opencode",
            use_llm_judge=False, reasoning_effort="low",
            remaining_hops=3, deadline=9999.0,
        )
        self.assertEqual(res.outcome, "advanced_safe")
        self.assertEqual(res.new_req_cmd, "echo safe")


class TestAutoAdvanceGatekeeper(unittest.TestCase):
    """Gatekeeper wiring: approve_escalation + approve_batch_escalations."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()
        self.adapter = _FakeAdapter(pending=lambda pane_id, text: "echo safe")

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def _seed_a(self, raw_cmd=A_CMD, pane="w1D:p1", kind="opencode", cwd="/repo"):
        return enqueue_pending_escalation(
            pane_id=pane, raw_command=raw_cmd, safety_reason="External dir",
            decision_layer="NOT_ALLOWLISTED", agent_kind=kind, cwd=cwd,
        )

    def _esc_state(self, esc_id):
        with get_db_connection() as conn:
            row = conn.execute(
                "SELECT status, resolution, approver FROM pending_escalations WHERE id = ?",
                (esc_id,),
            ).fetchone()
        return dict(row) if row else None

    def _approve(self, esc_id, b_cmd="echo safe", b_verdict=None, pane="w1D:p1"):
        if b_verdict is None:
            b_verdict = _verdict(True)
        self.adapter._pending = lambda pane_id, text: b_cmd
        with patch("tools.schengen_agent_llm._inject_approval", return_value=(False, INJECT_SKIP_CHANGED)), \
             patch("adapters.auto_advance.get_pane_text", return_value=f"Permission required\n\n$ {b_cmd}\n\nAllow once"), \
             patch("adapters.auto_advance.get_adapter", return_value=self.adapter), \
             patch("adapters.auto_advance.audit_shell_command_with_taxonomy", return_value=b_verdict):
            return json.loads(execute_tool_call(
                "approve_escalation", {"escalation_id": esc_id, "english_feedback": "x"}
            ))

    def test_gatekeeper_auto_advances_safe_b(self):
        # Test 1: inject A returns INJECT_SKIP_CHANGED; pane re-read yields B;
        # B evaluates safe -> B injected with approver="machine" provenance and
        # mechanism="auto-advance"; A reconciled SUPERSEDED (INV-AA-7).
        esc_id = self._seed_a()
        out = self._approve(esc_id)
        self.assertEqual(out["status"], "success")
        self.assertEqual(out["action"], "AUTO_ADVANCED")
        self.assertEqual(out["new_escalation"], "echo safe")
        self.assertEqual(self.adapter.inject_calls, [("w1D:p1", "echo safe")])
        state = self._esc_state(esc_id)
        self.assertEqual(state["status"], "CANCELLED")  # A never APPROVED
        self.assertEqual(state["resolution"], "SUPERSEDED")
        self.assertEqual(state["approver"], "other")
        # INV-AA-6: B recorded with decision=AUTO_APPROVED, mechanism=auto-advance,
        # decision_layer = the actual evaluator layer.
        auto = _audit_rows("AUTO_APPROVED")
        self.assertEqual(len(auto), 1)
        self.assertEqual(auto[0]["raw_command"], "echo safe")
        self.assertEqual(_mechanism_of("echo safe", "AUTO_APPROVED"), "auto-advance")
        self.assertEqual(auto[0]["decision_layer"], "FAST_TRACK_AST")

    def test_gatekeeper_unsafe_b_escalates_no_inject(self):
        # Test 2: B = rm -rf / evaluates unsafe -> B enqueued fresh, NEVER
        # injected; A reconciled SUPERSEDED (never APPROVED).
        esc_id = self._seed_a()
        out = self._approve(
            esc_id, b_cmd="rm -rf /",
            b_verdict=_verdict(False, "destructive", DecisionLayer.SHELL_CRITICAL),
        )
        self.assertEqual(out["status"], "advanced_unsafe")
        self.assertEqual(out["new_escalation"], "rm -rf /")
        self.assertEqual(self.adapter.inject_calls, [])
        pending = get_pending_escalations(include_delivered=False)
        self.assertTrue(
            any(e["raw_command"] == "rm -rf /" for e in pending),
            "B must be enqueued fresh (do NOT stall)",
        )
        state = self._esc_state(esc_id)
        self.assertEqual(state["status"], "CANCELLED")
        self.assertEqual(state["resolution"], "SUPERSEDED")

    def test_gatekeeper_no_inheritance_full_re_eval_for_b(self):
        # Test 3 / INV-AA-1: A was safe+approved, but B = sudo rm -rf / must
        # NOT auto-approve — the FULL evaluator is re-invoked for B.
        esc_id = self._seed_a()
        self.adapter._pending = lambda pane_id, text: "sudo rm -rf /"
        audit_calls = []

        def spy(*args, **kwargs):
            audit_calls.append((args, kwargs))
            return _verdict(False, "sudo destructive", DecisionLayer.SHELL_CRITICAL)

        with patch("tools.schengen_agent_llm._inject_approval", return_value=(False, INJECT_SKIP_CHANGED)), \
             patch("adapters.auto_advance.get_pane_text", return_value="Permission required\n\n$ sudo rm -rf /\n\nAllow once"), \
             patch("adapters.auto_advance.get_adapter", return_value=self.adapter), \
             patch("adapters.auto_advance.audit_shell_command_with_taxonomy", side_effect=spy):
            out = json.loads(execute_tool_call(
                "approve_escalation", {"escalation_id": esc_id, "english_feedback": "x"}
            ))
        self.assertEqual(out["status"], "advanced_unsafe")
        self.assertEqual(self.adapter.inject_calls, [])
        self.assertEqual(len(audit_calls), 1)
        (cmd,), kwargs = audit_calls[0]
        self.assertEqual(cmd, "sudo rm -rf /")  # B re-evaluated, never A
        self.assertEqual(kwargs["origin"], Origin.AGENT)

    def test_gatekeeper_evaluator_exception_escalates_b(self):
        # Test 6 / INV-AA-5: evaluator raises -> parse_failed (fail-closed) ->
        # B enqueued fresh, never injected.
        esc_id = self._seed_a()
        self.adapter._pending = lambda pane_id, text: "curl evil.example.com"

        def boom(*args, **kwargs):
            raise RuntimeError("evaluator exploded")

        with patch("tools.schengen_agent_llm._inject_approval", return_value=(False, INJECT_SKIP_CHANGED)), \
             patch("adapters.auto_advance.get_pane_text", return_value="Permission required\n\n$ curl evil.example.com\n\nAllow once"), \
             patch("adapters.auto_advance.get_adapter", return_value=self.adapter), \
             patch("adapters.auto_advance.audit_shell_command_with_taxonomy", side_effect=boom):
            out = json.loads(execute_tool_call(
                "approve_escalation", {"escalation_id": esc_id, "english_feedback": "x"}
            ))
        self.assertEqual(out["status"], "advanced_unsafe")
        self.assertEqual(out["new_escalation"], "curl evil.example.com")
        self.assertEqual(self.adapter.inject_calls, [])
        pending = get_pending_escalations(include_delivered=False)
        self.assertTrue(any(e["raw_command"] == "curl evil.example.com" for e in pending))

    def test_trampolined_a_never_approved(self):
        # Test 7 / INV-AA-7: on a real trampoline A is reconciled
        # CANCELLED/SUPERSEDED (approver="other") — its status is never
        # RESOLVED/APPROVED.
        esc_id = self._seed_a()
        out = self._approve(esc_id)
        self.assertEqual(out["action"], "AUTO_ADVANCED")
        state = self._esc_state(esc_id)
        self.assertNotEqual(state["status"], "RESOLVED")
        self.assertNotEqual(state["resolution"], "APPROVED")
        self.assertEqual(state["status"], "CANCELLED")
        self.assertEqual(state["resolution"], "SUPERSEDED")
        self.assertEqual(state["approver"], "other")

    def test_gatekeeper_not_trampolined_falls_back_to_re_polling(self):
        # not_trampolined (dialog still shows A) -> fall through to the existing
        # re-polling deferral: A stays PENDING (never cancelled/approved).
        esc_id = self._seed_a()
        self.adapter._pending = lambda pane_id, text: A_CMD
        with patch("tools.schengen_agent_llm._inject_approval", return_value=(False, INJECT_SKIP_CHANGED)), \
             patch("adapters.auto_advance.get_pane_text", return_value=f"Permission required\n\n$ {A_CMD}\n\nAllow once"), \
             patch("adapters.auto_advance.get_adapter", return_value=self.adapter), \
             patch("adapters.auto_advance.audit_shell_command_with_taxonomy", return_value=_verdict(True)):
            out = json.loads(execute_tool_call(
                "approve_escalation", {"escalation_id": esc_id, "english_feedback": "x"}
            ))
        self.assertEqual(out["status"], "error")
        self.assertIn("re-polling", out["error"])
        state = self._esc_state(esc_id)
        self.assertEqual(state["status"], "PENDING")
        self.assertEqual(self.adapter.inject_calls, [])

    def test_batch_auto_advances_on_skip_changed(self):
        # approve_batch_escalations: per-item INJECT_SKIP_CHANGED -> reconcile A
        # SUPERSEDED + auto-advance B through the full evaluator.
        ids = []
        for i, pane in enumerate(("wB1", "wB2")):
            ids.append(self._seed_a(pane=pane, cwd="/repo"))
        with patch("tools.schengen_agent_llm._inject_approval", return_value=(False, INJECT_SKIP_CHANGED)), \
             patch("adapters.auto_advance.get_pane_text", return_value="Permission required\n\n$ echo safe\n\nAllow once"), \
             patch("adapters.auto_advance.get_adapter", return_value=self.adapter), \
             patch("adapters.auto_advance.audit_shell_command_with_taxonomy", return_value=_verdict(True)):
            result = approve_batch_escalations("batch ok")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(sorted(result["resolved"]), sorted(ids))
        self.assertEqual(len(self.adapter.inject_calls), 2)
        for esc_id in ids:
            state = self._esc_state(esc_id)
            self.assertEqual(state["status"], "CANCELLED")
            self.assertEqual(state["resolution"], "SUPERSEDED")
            self.assertEqual(state["approver"], "other")

    def test_auto_advance_never_seeds_novelty_or_promotes(self):
        # INV-AA-6: the AUTO_ADVANCED path records B with approver="machine" but
        # NEVER seeds the novelty gate (record_human_approval_pattern) and NEVER
        # calls workspace promote_rule.
        esc_id = self._seed_a()
        with patch("tools.schengen_agent_llm._inject_approval", return_value=(False, INJECT_SKIP_CHANGED)), \
             patch("adapters.auto_advance.get_pane_text", return_value="Permission required\n\n$ echo safe\n\nAllow once"), \
             patch("adapters.auto_advance.get_adapter", return_value=self.adapter), \
             patch("adapters.auto_advance.audit_shell_command_with_taxonomy", return_value=_verdict(True)), \
             patch("core.guard_db.record_human_approval_pattern") as mock_seed, \
             patch("core.guard_db._maybe_promote_workspace_rule") as mock_promote:
            out = json.loads(execute_tool_call(
                "approve_escalation", {"escalation_id": esc_id, "english_feedback": "x"}
            ))
        self.assertEqual(out["action"], "AUTO_ADVANCED")
        mock_seed.assert_not_called()
        mock_promote.assert_not_called()


class _FakeCompletedInspector:
    """Minimal InspectorCoordinator double exposing the completed() drain."""

    def __init__(self, items):
        self._items = list(items)
        self.released = []
        self.human_queue = []

    def completed(self):
        for item in self._items:
            yield item
        self._items = []

    def release(self, pane_id, request=None):
        self.released.append((pane_id, request))

    def set_state(self, pane_id, request, state):
        pass


class TestWatcherAuditTruth(unittest.TestCase):
    """INV-AA-8: watcher writes AUTO_APPROVED only after a verified inject."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()
        self.pane_info = {"agent": "opencode", "pane_id": "w1D:p1"}
        self.request = ("echo safe", 1, "blocked", self.pane_info, "dialog text")
        self.result = _verdict(True)

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def _drain(self, inspector, adapter):
        with patch("cmd.schengen_watcher.get_pane_info", return_value=self.pane_info), \
             patch("cmd.schengen_watcher.get_adapter", return_value=adapter), \
             patch("cmd.schengen_watcher.get_pane_text", return_value="dialog text"), \
             patch("cmd.schengen_watcher.guard_db.get_channel_approve_config", return_value=False), \
             patch("cmd.schengen_watcher.resolve_escalation") as mock_resolve:
            drain_completed_inspections(inspector, {}, dry_run=False)
        return mock_resolve

    def test_skip_changed_writes_defer_not_auto_approved(self):
        # Test 8 / INV-AA-8: INJECT_SKIP_CHANGED -> the approval was NOT
        # delivered -> NO AUTO_APPROVED row for A; a corrective AUTO_DEFERRED
        # entry is written instead.
        adapter = _FakeAdapter(pending=lambda pane_id, text: "echo safe",
                               inj_ok=False, inj_reason=INJECT_SKIP_CHANGED)
        inspector = _FakeCompletedInspector([("w1D:p1", self.request, self.result)])
        self._drain(inspector, adapter)
        self.assertEqual(_audit_rows("AUTO_APPROVED"), [])
        defer = _audit_rows("AUTO_DEFERRED")
        self.assertEqual(len(defer), 1)
        self.assertEqual(defer[0]["raw_command"], "echo safe")
        self.assertEqual(inspector.released, [("w1D:p1", self.request)])

    def test_verified_inject_writes_auto_approved_after_delivery(self):
        # Verified inject success -> AUTO_APPROVED row + machine resolution
        # (INV-AA-8 positive path).
        adapter = _FakeAdapter(pending=lambda pane_id, text: "echo safe",
                               inj_ok=True, inj_reason="ok")
        inspector = _FakeCompletedInspector([("w1D:p1", self.request, self.result)])
        mock_resolve = self._drain(inspector, adapter)
        auto = _audit_rows("AUTO_APPROVED")
        self.assertEqual(len(auto), 1)
        self.assertEqual(auto[0]["raw_command"], "echo safe")
        mock_resolve.assert_called_once_with(pane_id="w1D:p1", approver="machine")
        self.assertEqual(adapter.inject_calls, [("w1D:p1", "echo safe")])
        self.assertEqual(inspector.released, [("w1D:p1", self.request)])

    def test_unsafe_keeps_manual_delegated_audit(self):
        # The MANUAL_DELEGATED audit path is unchanged (unsafe -> human queue).
        # The live dialog must still match the evaluated request (live_cmd ==
        # req_cmd) for the drain to apply the result.
        adapter = _FakeAdapter(pending=lambda pane_id, text: "echo safe")
        result = _verdict(False, "destructive", DecisionLayer.SHELL_CRITICAL)
        inspector = _FakeCompletedInspector([("w1D:p1", self.request, result)])
        self._drain(inspector, adapter)
        delegated = _audit_rows("MANUAL_DELEGATED")
        self.assertEqual(len(delegated), 1)
        self.assertEqual(delegated[0]["raw_command"], "echo safe")
        self.assertEqual(len(inspector.human_queue), 1)
        self.assertEqual(adapter.inject_calls, [])


class TestProvenanceIsolation(unittest.TestCase):
    """INV-AA-6/9 static + behavioral isolation assertions."""

    def test_opencode_adapter_never_imports_evaluator(self):
        # INV-AA-9: the adapter layer must NEVER import the evaluator — the
        # coordinator does the re-parse + re-evaluate.
        import ast

        src = Path(SCRIPT_DIR / "adapters" / "agent_adapters" / "opencode.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
        self.assertFalse(
            any("security_evaluator" in m for m in imports),
            f"opencode adapter must never import the evaluator: {imports}",
        )

    def test_auto_advance_module_never_seeds_memory_or_promotes(self):
        # INV-AA-6: the coordinator module never CALLS the novelty-gate seeder /
        # workspace promoter — recording provenance is the caller's job. AST-based
        # so the invariant docstring (which mentions the names) does not trip it.
        import ast

        src = Path(SCRIPT_DIR / "adapters" / "auto_advance.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        called = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name):
                    called.add(fn.id)
                elif isinstance(fn, ast.Attribute):
                    called.add(fn.attr)
        for forbidden in ("record_pane_approval", "record_human_approval_pattern", "promote_rule"):
            self.assertNotIn(forbidden, called,
                             f"auto_advance coordinator must never call {forbidden} (INV-AA-6)")


if __name__ == "__main__":
    unittest.main()
