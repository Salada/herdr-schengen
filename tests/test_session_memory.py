"""Unit tests for Pane-Scoped Session Memory and Fast-Path Approval Bypass (ADR-010)."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from guard_db import enqueue_pending_escalation, init_db, resolve_escalation
from security_evaluator import audit_dynamic_substitution_with_llm, audit_with_cloud_judge
from session_memory import (
    PaneSessionMemory,
    check_pane_approval,
    clear_pane_memory,
    record_pane_approval,
)


class TestPaneSessionMemory(unittest.TestCase):
    """Test suite for PaneSessionMemory isolation, persistence, and fast-path bypass."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_guard_audit.db"
        os.environ["GUARD_AUDIT_DB_PATH"] = str(self.db_path)
        init_db()
        clear_pane_memory()

    def tearDown(self):
        clear_pane_memory()
        self.tmp_dir.cleanup()
        os.environ.pop("GUARD_AUDIT_DB_PATH", None)

    def test_pane_isolation_strict(self):
        """Verify approvals in Pane A do not leak into Pane B."""
        cmd = "echo $(cat /tmp/data.txt)"
        # Record approval in pane-A
        record_pane_approval(
            pane_id="w1D:p1",
            raw_cmd=cmd,
            decision_layer="LLM_INSPECTOR",
            reason="Verified safe in pane 1",
            db_path=self.db_path,
        )

        # Check pane-A: must match
        res_a = check_pane_approval("w1D:p1", cmd, db_path=self.db_path)
        self.assertIsNotNone(res_a)
        assert res_a is not None
        self.assertTrue(res_a[0])
        self.assertIn("Verified safe in pane 1", res_a[1])

        # Check pane-B: must NOT match (strict isolation)
        res_b = check_pane_approval("w1D:p2", cmd, db_path=self.db_path)
        self.assertIsNone(res_b)

    def test_inspector_fast_path_bypass_llm(self):
        """Verify audit_dynamic_substitution_with_llm bypasses LLM call when pane memory exists."""
        cmd = "curl -d @<(cat /tmp/safe.json) http://example.com"
        scope = "w1D:p1"

        # 1. Pre-seed approval in pane memory
        record_pane_approval(
            pane_id=scope,
            raw_cmd=cmd,
            decision_layer="LLM_INSPECTOR",
            reason="File content verified safe",
            db_path=self.db_path,
        )

        # 2. Call audit_dynamic_substitution_with_llm with mocked post_cloud_judge
        with patch("security_evaluator.post_cloud_judge") as mock_post:
            is_safe, reason = audit_dynamic_substitution_with_llm(
                cmd_str=cmd,
                scope=scope,
                endpoint="http://dummy:1234/v1",
                model="dummy",
                api_key="sk-test",
            )
            # Must be safe and LLM must NOT have been called
            self.assertTrue(is_safe)
            self.assertIn("File content verified safe", reason)
            mock_post.assert_not_called()

    def test_cloud_judge_fast_path_bypass_llm(self):
        """Verify audit_with_cloud_judge bypasses LLM call when pane memory exists."""
        cmd = "python3 scripts/benchmark.py"
        scope = "w1D:p1"

        # 1. Pre-seed approval in pane memory
        record_pane_approval(
            pane_id=scope,
            raw_cmd=cmd,
            decision_layer="CLOUD_JUDGE",
            reason="Safe benchmark script",
            db_path=self.db_path,
        )

        # 2. Call audit_with_cloud_judge
        with patch("security_evaluator.post_cloud_judge") as mock_post:
            is_safe, reason = audit_with_cloud_judge(
                cmd_str=cmd,
                scope=scope,
                endpoint="http://dummy:1234/v1",
                model="dummy",
                api_key="sk-test",
            )
            self.assertTrue(is_safe)
            self.assertIn("Safe benchmark script", reason)
            mock_post.assert_not_called()

    def test_human_escalation_approval_populates_pane_memory(self):
        """Verify human operator approval in resolve_escalation populates pane session memory."""
        cmd = "pip install --upgrade custom-package"
        pane_id = "w1D:p1"

        # 1. Enqueue escalation
        esc_id = enqueue_pending_escalation(
            pane_id=pane_id,
            raw_command=cmd,
            safety_reason="Unverified package installation",
            decision_layer="GRAY_ZONE",
        )
        self.assertGreater(esc_id, 0)

        # Memory must not exist before human approval
        self.assertIsNone(check_pane_approval(pane_id, cmd, db_path=self.db_path))

        # 2. Human operator resolves/approves escalation
        resolve_escalation(pane_id=pane_id, escalation_id=esc_id, resolution_status="RESOLVED", is_approval=True)

        # 3. Check pane memory: must now be populated
        res = check_pane_approval(pane_id, cmd, db_path=self.db_path)
        self.assertIsNotNone(res)
        assert res is not None
        self.assertTrue(res[0])
        self.assertIn("Approved by human operator", res[1])

    def test_reset_dismiss_path_does_not_populate_memory(self):
        """Verify non-approval reset path (is_approval=False) defends against fail-open memory leaks."""
        cmd = "npm install -g malicious-pkg"
        pane_id = "w1D:p1"
        esc_id = enqueue_pending_escalation(
            pane_id=pane_id,
            raw_command=cmd,
            safety_reason="Malicious package",
            decision_layer="GRAY_ZONE",
        )
        # Dismiss/reset without approval
        resolve_escalation(pane_id=pane_id, escalation_id=esc_id, resolution_status="RESOLVED", is_approval=False)
        # Must remain None
        self.assertIsNone(check_pane_approval(pane_id, cmd, db_path=self.db_path))

    def test_clear_pane_memory_isolated(self):
        """Verify clearing pane memory for one pane leaves other panes intact."""
        cmd1 = "echo 1"
        cmd2 = "echo 2"
        record_pane_approval("pane-1", cmd1, db_path=self.db_path)
        record_pane_approval("pane-2", cmd2, db_path=self.db_path)

        clear_pane_memory("pane-1")
        self.assertIsNone(check_pane_approval("pane-1", cmd1, db_path=self.db_path))
        self.assertIsNotNone(check_pane_approval("pane-2", cmd2, db_path=self.db_path))

    def test_safe_pattern_template_matching(self):
        """Verify similar command with different search arguments matches session pattern template."""
        cmd1 = "python3 scripts/schengen_feature.py --search '모드'"
        cmd2 = "python3 scripts/schengen_feature.py --search '테마'"
        pane_id = "w1D:p1"

        # Record approval for cmd1
        record_pane_approval(
            pane_id=pane_id,
            raw_cmd=cmd1,
            decision_layer="LLM_INSPECTOR",
            reason="Safe query script",
            db_path=self.db_path,
        )

        # Check cmd2 (different arg): must match template in the same pane
        res = check_pane_approval(pane_id, cmd2, db_path=self.db_path)
        self.assertIsNotNone(res)
        assert res is not None
        self.assertTrue(res[0])
        self.assertIn("Matches previously approved template", res[1])

    def test_git_read_template_matching_and_isolation(self):
        """Verify git show hash variations match template in the same pane but do not leak across panes."""
        cmd1 = "git show a1b2c3d"
        cmd2 = "git show e4f5g6h"
        pane_a = "w1D:p1"
        pane_b = "w1D:p2"

        # Record approval in pane A
        record_pane_approval(pane_id=pane_a, raw_cmd=cmd1, decision_layer="LLM_INSPECTOR", reason="Safe git show")

        # Check in pane A: matches template
        res_a = check_pane_approval(pane_a, cmd2)
        self.assertIsNotNone(res_a)
        assert res_a is not None
        self.assertTrue(res_a[0])
        self.assertIn("Matches previously approved template", res_a[1])

        # Check in pane B: must NOT match (pane isolation)
        res_b = check_pane_approval(pane_b, cmd2)
        self.assertIsNone(res_b)


if __name__ == "__main__":
    unittest.main()
