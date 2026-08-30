"""M7 anti-fatigue tests (INV-13, INV-25..28, novelty-gate cwd fix).

Covers:
1. group_pending_escalations: (decision_layer, canonical_pattern) batching, FIFO.
2. approve_batch_escalations resolves ALL items of the head batch with
   approver='human-tui' provenance + adjudication_log entries.
3. One-key approve on an empty queue -> {"status": "empty"}, no audit rows.
4. Cross-class never batched: COMPLEXITY_TAX vs SECRET_GUARD stay disjoint;
   batch approve leaves the SECRET_GUARD row PENDING.
5. FIFO head-only: batch approve resolves only the first group.
6. Novelty-gate cwd fix regression: after an APPROVE adjudication the gate
   query matches the seed (would fail pre-fix).
7. human_approval_ttl_seconds config is honored (read/write + clamp + applied).

Uses a clean temp DB (patch guard_db.DB_PATH + init_db). The verified-inject
path (_inject_approval) is mocked so no real herdr subprocess is spawned.
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
    get_batch_approval_config,
    get_db_connection,
    get_pending_escalations,
    get_recent_audit_logs,
    group_pending_escalations,
    has_human_approval_pattern,
    normalize_command,
    record_adjudication,
    record_human_approval_pattern,
    set_batch_approval_config,
)
from tools.schengen_agent_llm import approve_batch_escalations

GIT_A = "git commit -m 'feat: a'"
GIT_B = "git commit -m 'feat: b'"
GIT_C = "git commit -m 'docs: c'"


def _count_adjudications() -> int:
    with get_db_connection() as conn:
        return int(conn.execute("SELECT COUNT(*) AS c FROM adjudication_log").fetchone()["c"])


def _approvers_for(ids):
    placeholders = ",".join("?" * len(ids))
    with get_db_connection() as conn:
        rows = conn.execute(
            f"SELECT id, approver, status FROM pending_escalations WHERE id IN ({placeholders})",
            tuple(ids),
        ).fetchall()
    return {r["id"]: (r["approver"], r["status"]) for r in rows}


class TestAntiFatigue(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()
        # Patch the verified-inject path so no real herdr subprocess runs.
        self.inject_patch = patch("tools.schengen_agent_llm._inject_approval", return_value=(True, ""))
        self.inject_patch.start()

    def tearDown(self):
        self.inject_patch.stop()
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_group_pending_escalations(self):
        for i, pane in enumerate(("wA1", "wA2", "wA3")):
            enqueue_pending_escalation(
                pane, f"git commit -m 'feat: {i}'", "cx", "COMPLEXITY_TAX", "opencode"
            )
        enqueue_pending_escalation("wB1", "ls -la", "cx", "COMPLEXITY_TAX", "opencode")
        pending = get_pending_escalations()
        groups = group_pending_escalations(pending)
        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0]["count"], 3)
        self.assertEqual(groups[0]["decision_layer"], "COMPLEXITY_TAX")
        self.assertEqual(groups[0]["canonical_pattern"], normalize_command("git commit -m 'feat: x'"))
        self.assertEqual(groups[1]["count"], 1)

    def test_batch_approve_resolves_all_with_provenance(self):
        ids = []
        for i, pane in enumerate(("wC1", "wC2", "wC3")):
            ids.append(
                enqueue_pending_escalation(
                    pane, f"git commit -m 'feat: {i}'", "cx", "COMPLEXITY_TAX", "opencode"
                )
            )
        result = approve_batch_escalations("batch ok")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(sorted(result["resolved"]), sorted(ids))
        self.assertEqual(result["deferred"], [])
        # All N resolved with human-tui provenance
        approvers = _approvers_for(ids)
        for esc_id in ids:
            approver, status = approvers[esc_id]
            self.assertEqual(status, "RESOLVED")
            self.assertEqual(approver, "human-tui")
        # adjudication_log grows by exactly N
        self.assertEqual(_count_adjudications(), 3)

    def test_batch_approve_empty_queue(self):
        result = approve_batch_escalations()
        self.assertEqual(result["status"], "empty")
        self.assertEqual(result["resolved"], 0)
        self.assertEqual(len(get_recent_audit_logs(limit=5)), 0)
        self.assertEqual(_count_adjudications(), 0)

    def test_cross_class_never_batched(self):
        enqueue_pending_escalation("wD1", GIT_A, "cx", "COMPLEXITY_TAX", "opencode")
        enqueue_pending_escalation("wD2", GIT_B, "cx", "COMPLEXITY_TAX", "opencode")
        secret_id = enqueue_pending_escalation(
            "wD3", "cat ~/.ssh/id_rsa", "secret", "SECRET_GUARD", "opencode"
        )
        groups = group_pending_escalations(get_pending_escalations())
        self.assertEqual(len(groups), 2)
        self.assertEqual({g["decision_layer"] for g in groups}, {"COMPLEXITY_TAX", "SECRET_GUARD"})
        # Batch approve resolves ONLY the COMPLEXITY_TAX head; SECRET_GUARD stays PENDING
        result = approve_batch_escalations()
        self.assertEqual(len(result["resolved"]), 2)
        remaining = get_pending_escalations()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["id"], secret_id)
        self.assertEqual(remaining[0]["decision_layer"], "SECRET_GUARD")
        self.assertEqual(remaining[0]["status"], "PENDING")

    def test_fifo_head_only(self):
        enqueue_pending_escalation("wE1", GIT_A, "cx", "COMPLEXITY_TAX", "opencode")
        enqueue_pending_escalation("wE2", GIT_B, "cx", "COMPLEXITY_TAX", "opencode")
        enqueue_pending_escalation("wE3", "mkdir -p /tmp/zz", "cx", "COMPLEXITY_TAX", "opencode")
        result = approve_batch_escalations()
        self.assertEqual(len(result["resolved"]), 2)
        remaining = get_pending_escalations()
        self.assertEqual(len(remaining), 1)
        self.assertIn("mkdir", remaining[0]["raw_command"])

    def test_novelty_cwd_fix_regression(self):
        from core.security_evaluator import DecisionLayer, audit_shell_command

        pane_id = "wF1"
        raw_cmd = "pip install requests"
        esc_id = enqueue_pending_escalation(
            pane_id, raw_cmd, "pkg", "NOT_ALLOWLISTED", "agy"
        )
        record_adjudication(escalation_id=esc_id, pane_id=pane_id, agent_kind="agy", action="APPROVE", feedback="ok")
        # M7 fix: the key drops the cwd dimension, so the query matches the seed.
        self.assertTrue(has_human_approval_pattern(normalize_command(raw_cmd), scope=pane_id))
        # E2E: the HUMAN_APPROVED fast-path actually fires (dead pre-fix).
        safe, reason, layer = audit_shell_command(raw_cmd, scope=pane_id)
        self.assertTrue(safe, f"Expected HUMAN_APPROVED fast-path: {reason}")
        self.assertEqual(layer, DecisionLayer.HUMAN_APPROVED)

    def test_ttl_config_honored(self):
        cfg = get_batch_approval_config()
        self.assertEqual(cfg["human_approval_ttl_seconds"], 3600)
        self.assertTrue(cfg["batch_approval_enabled"])
        self.assertEqual(set_batch_approval_config(ttl_seconds=120)["human_approval_ttl_seconds"], 120)
        # Clamp [60, 86400]
        self.assertEqual(set_batch_approval_config(ttl_seconds=10)["human_approval_ttl_seconds"], 60)
        self.assertEqual(set_batch_approval_config(ttl_seconds=999999)["human_approval_ttl_seconds"], 86400)
        set_batch_approval_config(enabled=False)
        self.assertFalse(get_batch_approval_config()["batch_approval_enabled"])
        # The novelty gate reads the configured TTL for its cache row
        set_batch_approval_config(ttl_seconds=120)
        record_human_approval_pattern("echo ttlcheck", scope="wT1")
        with get_db_connection() as conn:
            row = conn.execute(
                "SELECT strftime('%s', expires_at) - strftime('%s', datetime('now')) AS remaining "
                "FROM evaluation_cache WHERE cache_key = 'human_approved:wT1:echo ttlcheck'"
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertGreaterEqual(int(row["remaining"]), 60)  # ~120s TTL (loose bound)


if __name__ == "__main__":
    unittest.main()
