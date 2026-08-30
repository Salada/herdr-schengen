"""Novelty Gate tests (INV-3, INV-4, INV-7).

Verifies that a canonical command pattern with prior HUMAN approval (scoped to
pane, with a TTL — the cwd dimension was dropped in M7 so the seed/query keys
match) auto-approves via the HUMAN_APPROVED fast path instead of re-escalating
— while remaining fail-closed everywhere else.
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
from core.guard_db import (
    enqueue_pending_escalation,
    has_human_approval_pattern,
    normalize_command,
    record_adjudication,
    record_human_approval_pattern,
)
from core.security_evaluator import DecisionLayer, audit_shell_command


class TestNoveltyGate(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    # --- INV-7: normalization (pure function, no DB) ---

    def test_inv7_version_specifiers_fold_to_ver(self):
        self.assertEqual(normalize_command("foo==2.31.0"), normalize_command("foo==2.31.1"))
        self.assertEqual(normalize_command("pkg@2.45.0"), "pkg@<VER>")
        self.assertEqual(normalize_command("pkg==2.45.0"), "pkg==<VER>")

    def test_inv7_distinct_packages_stay_distinct(self):
        self.assertNotEqual(normalize_command("brew install foo"), normalize_command("brew install bar"))

    def test_inv7_bare_command_is_own_key(self):
        self.assertEqual(normalize_command("brew upgrade"), "brew upgrade")

    def test_inv7_git_branch_not_folded(self):
        # `@main` (git branch) is NOT a version tag: not in the tag list and does
        # not start with a digit.
        self.assertNotIn("<VER>", normalize_command("pkg@main"))

    # --- INV-3/4: novelty gate DB primitives ---

    def test_novelty_gate_auto_approve(self):
        pat = normalize_command("git push origin feat/novelty-test")
        record_human_approval_pattern(pat, scope="w1D:p1")
        self.assertTrue(has_human_approval_pattern(pat, scope="w1D:p1"))

    def test_novelty_gate_scope_isolation(self):
        pat = normalize_command("git push origin feat/novelty-test")
        record_human_approval_pattern(pat, scope="w1D:p1")
        self.assertFalse(has_human_approval_pattern(pat, scope="w1D:p2"))

    def test_novelty_gate_cwd_dimension_dropped(self):
        # M7 fix: the novelty gate previously seeded its cache with cwd="" but
        # queried with the real cwd, so the keys never matched and the
        # HUMAN_APPROVED fast-path was dead. The cwd dimension is deliberately
        # dropped — scope (pane) is the only partition, so a recorded approval
        # must be found regardless of the cwd used at query time.
        pat = normalize_command("git push origin feat/novelty-test")
        record_human_approval_pattern(pat, scope="w1D:p1")
        self.assertTrue(has_human_approval_pattern(pat, scope="w1D:p1"))

    def test_novelty_gate_inv4_starts_empty(self):
        # INV-4: the human_approved: prefix must never inherit legacy rows — a
        # never-recorded pattern is always False even though pattern_stats may
        # carry auto_approved_count for other prefixes.
        self.assertFalse(has_human_approval_pattern("rm -rf /tmp/foo", scope="w1D:p1"))

    # --- E2E: evaluator integration ---

    def test_e2e_human_approved_layer(self):
        cmd = "git push origin feat/novelty-test"
        record_human_approval_pattern(normalize_command(cmd), scope="w1D:p1")

        safe, reason, layer = audit_shell_command(cmd, cwd="/repo", scope="w1D:p1")
        self.assertTrue(safe, f"Expected human-approved command to be safe: {reason}")
        self.assertEqual(layer, DecisionLayer.HUMAN_APPROVED)

        # Different scope -> fail-closed escalation.
        safe2, reason2, layer2 = audit_shell_command(cmd, cwd="/repo", scope="w1D:pOther")
        self.assertFalse(safe2, f"Expected different-scope command to escalate: {reason2}")
        self.assertEqual(layer2, DecisionLayer.NOT_ALLOWLISTED)

    def test_e2e_human_approved_taxonomy(self):
        from core.security_evaluator import audit_shell_command_with_taxonomy

        cmd = "git push origin feat/novelty-test"
        record_human_approval_pattern(normalize_command(cmd), scope="w1D:p1")
        safe, reason, layer, tax = audit_shell_command_with_taxonomy(cmd, cwd="/repo", scope="w1D:p1")
        self.assertTrue(safe)
        self.assertEqual(layer, DecisionLayer.HUMAN_APPROVED)
        self.assertEqual(tax["mechanism"], "human-approved-history")

    # --- record_adjudication seeds the gate ---

    def test_adjudication_approve_seeds_gate(self):
        pane_id = "w1D:pA"
        raw_cmd = "pip install requests"
        esc_id = enqueue_pending_escalation(
            pane_id=pane_id,
            raw_command=raw_cmd,
            safety_reason="Package install",
            decision_layer="NOT_ALLOWLISTED",
            agent_kind="agy",
        )
        record_adjudication(escalation_id=esc_id, pane_id=pane_id, agent_kind="agy", action="APPROVE", feedback="ok")
        self.assertTrue(has_human_approval_pattern(normalize_command(raw_cmd), scope=pane_id))

    def test_adjudication_reject_does_not_seed_gate(self):
        pane_id = "w1D:pB"
        raw_cmd = "npm install -g foo"
        esc_id = enqueue_pending_escalation(
            pane_id=pane_id,
            raw_command=raw_cmd,
            safety_reason="Package install",
            decision_layer="NOT_ALLOWLISTED",
            agent_kind="agy",
        )
        record_adjudication(escalation_id=esc_id, pane_id=pane_id, agent_kind="agy", action="REJECT", feedback="no")
        self.assertFalse(has_human_approval_pattern(normalize_command(raw_cmd), scope=pane_id))

    # --- TTL expiry ---

    def test_ttl_expiry_invalidates_approval(self):
        pat = normalize_command("brew install git")
        record_human_approval_pattern(pat, scope="w1D:pC")
        self.assertTrue(has_human_approval_pattern(pat, scope="w1D:pC"))

        # Force expiry directly in SQLite (epoch 0 < now).
        conn = guard_db.get_db_connection()
        conn.execute(
            "UPDATE evaluation_cache SET expires_at = datetime(0, 'unixepoch') "
            "WHERE cache_key LIKE 'human_approved:w1D:pC:%'"
        )
        conn.commit()
        conn.close()

        self.assertFalse(has_human_approval_pattern(pat, scope="w1D:pC"))


if __name__ == "__main__":
    unittest.main()
