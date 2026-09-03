"""M6 cloud-judge confidence tests: confidence-threshold gating + complexity_mode='judge'.

Covers:
1. High-confidence safe verdict -> auto-approve (confidence >= threshold).
2. Low-confidence safe verdict -> defer to human (fail-closed).
3. Missing confidence -> defer; parse_json_verdict returns a 3-tuple.
4. complexity_mode='judge' + NON-mutating over-threshold chain -> routed to the
   cloud judge (direct + end-to-end layer == CLOUD_JUDGE on high-confidence safe).
5. judge-mode low-confidence -> defers with COMPLEXITY_TAX.
6. INJECTED origin -> ORIGIN_GUARD fires BEFORE any cloud judge call (INV-23),
   even with mode='judge'.
7. Default mode='escalate': MUTATING over-threshold -> COMPLEXITY_TAX, cloud
   judge NOT called.
8. (issue #4027 tiered routing, fail-closed) MUTATING over-threshold chains
   NEVER auto-approve via the cloud judge — hard COMPLEXITY_TAX deferral in
   BOTH complexity_mode values; only read-only/diagnostic/VCS chains are
   absorbed by the judge (again in both modes).

Uses a clean temp DB (patch guard_db.DB_PATH + init_db) so defaults apply, and
wipes the global in-memory pane-approval / eval caches to avoid cross-test leaks.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Add scripts directory to path
SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
import sys

sys.path.insert(0, str(SCRIPT_DIR))

from core.cloud_judge import parse_json_verdict
from core.guard_db import (
    get_cloud_judge_config,
    get_complexity_tax_config,
    set_cloud_judge_config,
    set_complexity_tax_config,
)
from core.security_evaluator import (
    DecisionLayer,
    Origin,
    audit_shell_command,
    audit_shell_command_with_taxonomy,
    audit_with_cloud_judge,
)

import core.guard_db as guard_db

# MUTATING chain (mkdir -> MUTATING_LOW) over the default threshold of 6.
COMPLEX_CHAIN = "mkdir a1; mkdir a2; mkdir a3; mkdir a4; mkdir a5; mkdir a6; mkdir a7"
# NON-mutating chains (read-only verbs only, structural = 7 > 6) — distinct
# commands so cloud-judge verdicts can never cross-pollute via the cache.
READONLY_CHAIN_A = "true && true && true && true && true && true && true"
READONLY_CHAIN_B = "wait && wait && wait && wait && wait && wait && wait"


def _canned(content_str: str) -> dict:
    """Wrap a verdict JSON string into the post_cloud_judge response shape."""
    return {"choices": [{"message": {"content": content_str}}]}


class TestCloudJudgeConfidence(unittest.TestCase):
    """M6: cloud-judge confidence threshold + complexity_mode='judge'."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()
        # Cloud-judge transport needs a resolvable endpoint; patch env so
        # resolve_guard_llm_config() returns a truthy config at call time.
        self.env_patch = patch.dict(
            os.environ,
            {
                "GUARD_LLM_ENDPOINT": "https://example.com/v1/chat/completions",
                "GUARD_LLM_MODEL": "test-model",
                "GUARD_LLM_API_KEY": "test-key",
            },
        )
        self.env_patch.start()
        # Wipe global in-memory pane approvals + eval LRU so prior tests do not
        # leak cached approvals/verdicts across test methods in this process.
        from core.session_memory import clear_pane_approval_memory

        clear_pane_approval_memory()
        guard_db.clear_in_memory_cache()
        # Live module refs (immune to any importlib.reload ordering).
        import core.security_evaluator as se

        self.audit_with_cloud_judge = se.audit_with_cloud_judge
        self.audit_shell_command = se.audit_shell_command
        self.asct = se.audit_shell_command_with_taxonomy
        self.apply_tax = se._apply_complexity_tax
        self.Origin = se.Origin
        self.DecisionLayer = se.DecisionLayer

    def tearDown(self):
        self.env_patch.stop()
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_high_confidence_safe_approves(self):
        verdict = '{"is_safe": true, "confidence": 0.95, "reason": "benign"}'
        with patch("core.security_evaluator.post_cloud_judge", return_value=_canned(verdict)):
            safe, reason = self.audit_with_cloud_judge("echo hi", confidence_threshold=0.9)
        self.assertTrue(safe, f"high-confidence safe verdict must approve: {reason}")
        self.assertIn("benign", reason)

    def test_low_confidence_safe_defers(self):
        verdict = '{"is_safe": true, "confidence": 0.6, "reason": "probably benign"}'
        with patch("core.security_evaluator.post_cloud_judge", return_value=_canned(verdict)):
            safe, reason = self.audit_with_cloud_judge("echo hi2", confidence_threshold=0.9)
        self.assertFalse(safe, "low-confidence safe verdict must defer (fail-closed)")
        self.assertIn("confidence=0.6", reason)

    def test_missing_confidence_defers(self):
        verdict = '{"is_safe": true, "reason": "benign"}'
        with patch("core.security_evaluator.post_cloud_judge", return_value=_canned(verdict)):
            safe, reason = self.audit_with_cloud_judge("echo hi3", confidence_threshold=0.9)
        self.assertFalse(safe, "missing-confidence verdict must defer (fail-closed)")
        # parse_json_verdict now returns a 3-tuple with confidence=None when absent
        parsed = parse_json_verdict('{"is_safe": true, "reason": "x"}')
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed[0])
        self.assertIsNone(parsed[1])
        self.assertIn("x", parsed[2])

    def test_judge_mode_readonly_chain_routes_to_cloud_judge(self):
        # (issue #4027) judge mode: a NON-mutating over-threshold chain is
        # absorbed by the cloud judge (direct + end-to-end == CLOUD_JUDGE).
        set_complexity_tax_config(mode="judge")
        cfg = get_complexity_tax_config()
        verdict = '{"is_safe": true, "confidence": 0.95, "reason": "complex but benign"}'
        with patch("core.security_evaluator.post_cloud_judge", return_value=_canned(verdict)):
            # direct _apply_complexity_tax
            res = self.apply_tax(
                READONLY_CHAIN_A, cfg, self.Origin.AGENT, cwd="", scope="default", agent_id="default"
            )
            self.assertIsNotNone(res)
            safe, reason, layer = res
            self.assertTrue(safe, f"judge-mode high-confidence must clear: {reason}")
            self.assertEqual(layer, self.DecisionLayer.CLOUD_JUDGE)
            # end-to-end audit_shell_command
            e_safe, e_reason, e_layer = self.audit_shell_command(READONLY_CHAIN_A)
            self.assertTrue(e_safe, f"end-to-end judge-mode must clear: {e_reason}")
            self.assertEqual(e_layer, self.DecisionLayer.CLOUD_JUDGE)

    def test_judge_mode_mutating_chain_never_routes_to_cloud_judge(self):
        # (issue #4027 fail-closed decision) even in judge mode a MUTATING chain
        # (mkdir) must NOT be auto-approved by the cloud judge — hard deferral.
        set_complexity_tax_config(mode="judge")
        cfg = get_complexity_tax_config()
        calls = []

        def _recording(*args, **kwargs):
            calls.append(args)
            return _canned('{"is_safe": true, "confidence": 0.99, "reason": "benign"}')

        with patch("core.security_evaluator.post_cloud_judge", side_effect=_recording):
            res = self.apply_tax(
                COMPLEX_CHAIN, cfg, self.Origin.AGENT, cwd="", scope="default", agent_id="default"
            )
            self.assertIsNotNone(res)
            safe, reason, layer = res
            self.assertFalse(safe, "mutating chain must NEVER cloud-approve, even in judge mode")
            self.assertEqual(layer, self.DecisionLayer.COMPLEXITY_TAX)
            # end-to-end stays fail-closed too
            e_safe, e_reason, e_layer = self.audit_shell_command(COMPLEX_CHAIN)
            self.assertFalse(e_safe, f"end-to-end mutating chain must defer: {e_reason}")
            self.assertEqual(e_layer, self.DecisionLayer.COMPLEXITY_TAX)
        self.assertEqual(calls, [], "post_cloud_judge must NOT be called for a mutating chain in judge mode")

    def test_judge_mode_low_confidence_defers(self):
        set_complexity_tax_config(mode="judge")
        cfg = get_complexity_tax_config()
        verdict = '{"is_safe": true, "confidence": 0.5, "reason": "ambiguous"}'
        with patch("core.security_evaluator.post_cloud_judge", return_value=_canned(verdict)):
            res = self.apply_tax(
                READONLY_CHAIN_B, cfg, self.Origin.AGENT, cwd="", scope="default", agent_id="default"
            )
            self.assertIsNotNone(res)
            safe, reason, layer = res
            self.assertFalse(safe, "judge-mode low-confidence must defer to human")
            self.assertEqual(layer, self.DecisionLayer.COMPLEXITY_TAX)

    def test_injected_origin_blocks_before_cloud_judge(self):
        set_complexity_tax_config(mode="judge")
        calls = []

        def _recording(*args, **kwargs):
            calls.append(args)
            return _canned('{"is_safe": true, "confidence": 0.99, "reason": "benign"}')

        with patch("core.security_evaluator.post_cloud_judge", side_effect=_recording):
            safe, reason, layer, tax = self.asct(COMPLEX_CHAIN, origin=self.Origin.INJECTED)
        self.assertFalse(safe, f"INJECTED must hard-escalate before cloud judge: {reason}")
        self.assertEqual(layer, self.DecisionLayer.ORIGIN_GUARD)
        self.assertEqual(calls, [], "post_cloud_judge must NOT be called for INJECTED origin")

    def test_default_mode_escalate_mutating_skips_cloud_judge(self):
        # Clean temp DB -> default complexity_mode='escalate'
        calls = []

        def _recording(*args, **kwargs):
            calls.append(args)
            return _canned('{"is_safe": true, "confidence": 0.99, "reason": "benign"}')

        with patch("core.security_evaluator.post_cloud_judge", side_effect=_recording):
            res = self.apply_tax(
                COMPLEX_CHAIN, get_complexity_tax_config(), self.Origin.AGENT,
                cwd="", scope="default", agent_id="default",
            )
            self.assertIsNotNone(res)
            safe, reason, layer = res
            self.assertFalse(safe, "escalate mode must defer to human")
            self.assertEqual(layer, self.DecisionLayer.COMPLEXITY_TAX)
            # end-to-end
            e_safe, e_reason, e_layer = self.audit_shell_command(COMPLEX_CHAIN)
            self.assertFalse(e_safe, "escalate mode end-to-end must defer")
            self.assertEqual(e_layer, self.DecisionLayer.COMPLEXITY_TAX)
        self.assertEqual(calls, [], "post_cloud_judge must NOT be called for a mutating chain in escalate mode")

    def test_default_mode_escalate_readonly_chain_absorbed_by_cloud_judge(self):
        # (issue #4027 tiered routing) in the DEFAULT escalate mode a NON-mutating
        # over-threshold chain is ALSO absorbed by the cloud judge — high-confidence
        # safe -> CLOUD_JUDGE approve, unsafe -> COMPLEXITY_TAX deferral.
        calls = []

        def _recording(*args, **kwargs):
            calls.append(args)
            return _canned('{"is_safe": true, "confidence": 0.99, "reason": "benign"}')

        with patch("core.security_evaluator.post_cloud_judge", side_effect=_recording):
            res = self.apply_tax(
                READONLY_CHAIN_A, get_complexity_tax_config(), self.Origin.AGENT,
                cwd="", scope="default", agent_id="default",
            )
            self.assertIsNotNone(res)
            safe, reason, layer = res
            self.assertTrue(safe, f"read-only chain cleared by cloud judge in escalate mode: {reason}")
            self.assertEqual(layer, self.DecisionLayer.CLOUD_JUDGE)
        self.assertEqual(len(calls), 1, "cloud judge must be called exactly once for the read-only chain")

    def test_default_mode_escalate_readonly_chain_low_confidence_defers(self):
        calls = []

        def _recording(*args, **kwargs):
            calls.append(args)
            return _canned('{"is_safe": true, "confidence": 0.4, "reason": "uncertain"}')

        with patch("core.security_evaluator.post_cloud_judge", side_effect=_recording):
            res = self.apply_tax(
                READONLY_CHAIN_B, get_complexity_tax_config(), self.Origin.AGENT,
                cwd="", scope="default", agent_id="default",
            )
            self.assertIsNotNone(res)
            safe, reason, layer = res
            self.assertFalse(safe, "low-confidence read-only chain must defer (fail-closed)")
            self.assertEqual(layer, self.DecisionLayer.COMPLEXITY_TAX)

    def test_cloud_judge_config_clamp_lower_bound_07(self):
        # M6-3: the clamp floor is 0.7, not 0.5 — a 0.5-0.7 gate is too weak to
        # be a meaningful auto-approve confidence.
        cfg = set_cloud_judge_config(min_confidence=0.4)
        self.assertEqual(cfg["cloud_judge_min_confidence"], 0.7)
        cfg2 = set_cloud_judge_config(min_confidence=0.95)
        self.assertEqual(cfg2["cloud_judge_min_confidence"], 0.95)
        cfg3 = set_cloud_judge_config(min_confidence=1.5)
        self.assertEqual(cfg3["cloud_judge_min_confidence"], 1.0)
        # getter applies the same floor
        self.assertGreaterEqual(get_cloud_judge_config()["cloud_judge_min_confidence"], 0.7)

    def test_threshold_change_not_served_stale_verdict(self):
        # M6-2 regression: the cloud-judge cache key MUST include the effective
        # confidence_threshold. A runtime threshold change must re-audit instead
        # of serving the previously-cached (unsafe) verdict within the TTL window.
        from core.session_cache import clear_session_cache
        from core.session_memory import clear_pane_approval_memory

        calls = []

        def _recording(*args, **kwargs):
            calls.append(1)
            return _canned('{"is_safe": true, "confidence": 0.6, "reason": "probably benign"}')

        with patch("core.security_evaluator.post_cloud_judge", side_effect=_recording):
            safe1, reason1 = self.audit_with_cloud_judge("echo cache-thr", confidence_threshold=0.9)
            self.assertFalse(safe1, "0.6 < 0.9 must defer")
            self.assertIn("threshold=0.9", reason1)
            # isolate caches so the second call must go back to the LLM if the
            # key really is threshold-scoped (SQLite backing persists across the
            # in-memory clear — that is what the stale-verdict bug relied on).
            clear_pane_approval_memory()
            clear_session_cache()
            safe2, reason2 = self.audit_with_cloud_judge("echo cache-thr", confidence_threshold=0.99)
            self.assertFalse(safe2, "0.6 < 0.99 must still defer")
            self.assertIn("threshold=0.99", reason2, "threshold change must re-audit, not replay stale cache")
        self.assertEqual(len(calls), 2, "threshold change must re-invoke the cloud judge")


if __name__ == "__main__":
    unittest.main()
