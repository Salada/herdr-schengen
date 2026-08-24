"""Unit & Scenario Test Suite for Non-VCS Irreversible Mutation & Gray-Zone Matrix (ADR-004 / SOP-12).

Tests:
1. Resource Tier Classification (T0 ~ T4) with canonicalization & sub-scoping
2. Operation Classification (R, A, W, T, D, M, X, E)
3. Full Matrix Evaluation (5 Tiers x 8 Operations = 40+ Combinations)
4. /var/folders/ internal heterogeneity (Temp vs Cache vs Unix Socket)
5. Clean Git Tree (T2) vs Uncommitted Git Tree (T3)
6. 7-field Structured Decision Guidance Document formatting
"""

import sys
import unittest
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from gray_zone_evaluator import (
    BASE_GOVERNANCE_MATRIX,
    OperationType,
    ResourceTier,
    Verdict,
    classify_operation,
    classify_resource_tier,
    evaluate_gray_zone_operation,
    format_decision_guidance,
)


class TestResourceTierClassification(unittest.TestCase):
    """Test dynamic classification of filesystem paths and URIs into T0 ~ T4."""

    def test_t0_ephemeral_paths(self):
        self.assertEqual(classify_resource_tier("/tmp/test.txt"), ResourceTier.T0_EPHEMERAL)
        self.assertEqual(classify_resource_tier("/private/tmp/test.txt"), ResourceTier.T0_EPHEMERAL)
        self.assertEqual(classify_resource_tier("/var/tmp/scratch.log"), ResourceTier.T0_EPHEMERAL)
        self.assertEqual(classify_resource_tier("/var/folders/ab/cd/T/temp_file.txt"), ResourceTier.T0_EPHEMERAL)

    def test_t1_regenerable_caches(self):
        self.assertEqual(
            classify_resource_tier("/var/folders/ab/cd/C/com.apple.app/cache.db"), ResourceTier.T1_REGENERABLE
        )
        self.assertEqual(
            classify_resource_tier("/Users/test/Library/Developer/Xcode/DerivedData/Build"), ResourceTier.T1_REGENERABLE
        )
        self.assertEqual(classify_resource_tier("/Users/test/.cache/pip/wheels"), ResourceTier.T1_REGENERABLE)
        self.assertEqual(classify_resource_tier("/Users/test/.npm/_cacache/content-v2"), ResourceTier.T1_REGENERABLE)

    def test_t2_chezmoi_source(self):
        self.assertEqual(
            classify_resource_tier("/Users/kyjbusan/.local/share/chezmoi/dot_zshrc.tmpl"),
            ResourceTier.T2_VERSION_CONTROLLED,
        )

    def test_t3_durable_gray_zone(self):
        self.assertEqual(
            classify_resource_tier("/Users/test/.local/state/package_history/brew.log"), ResourceTier.T3_DURABLE_GRAY
        )
        self.assertEqual(
            classify_resource_tier("/Users/test/.config/custom_app/config.json"), ResourceTier.T3_DURABLE_GRAY
        )
        self.assertEqual(classify_resource_tier("/Users/test/data/app.sqlite3"), ResourceTier.T3_DURABLE_GRAY)
        self.assertEqual(
            classify_resource_tier("/Users/test/.hermes/memories/session.json"), ResourceTier.T3_DURABLE_GRAY
        )

    def test_t4_critical_assets(self):
        self.assertEqual(classify_resource_tier("/Users/test/.ssh/id_ed25519"), ResourceTier.T4_CRITICAL)
        self.assertEqual(classify_resource_tier("/Users/test/.ssh/deploy_key.pem"), ResourceTier.T4_CRITICAL)
        self.assertEqual(
            classify_resource_tier("/Users/test/Library/Keychains/login.keychain-db"), ResourceTier.T4_CRITICAL
        )
        self.assertEqual(classify_resource_tier("/etc/hosts"), ResourceTier.T4_CRITICAL)
        self.assertEqual(classify_resource_tier("/System/Library/CoreServices"), ResourceTier.T4_CRITICAL)
        self.assertEqual(
            classify_resource_tier("http://192.168.10.102:3000/api/v1/admin/users/bot/emails"), ResourceTier.T4_CRITICAL
        )


class TestOperationClassification(unittest.TestCase):
    """Test classification of shell commands into R, A, W, T, D, M, X, E operations."""

    def test_read_operations(self):
        op, target = classify_operation("cat /tmp/test.txt")
        self.assertEqual(op, OperationType.READ)
        self.assertEqual(target, "/tmp/test.txt")

        op, target = classify_operation("grep 'pattern' ~/.local/state/app.log")
        self.assertEqual(op, OperationType.READ)

    def test_append_operations(self):
        op, target = classify_operation("echo 'log entry' >> ~/.local/state/history.log")
        self.assertEqual(op, OperationType.APPEND)
        self.assertEqual(target, "~/.local/state/history.log")

    def test_truncate_operations(self):
        op, target = classify_operation("echo '' > ~/.local/state/history.log")
        self.assertEqual(op, OperationType.TRUNCATE)
        self.assertEqual(target, "~/.local/state/history.log")

        op, target = classify_operation("> /var/folders/xx/yy/C/cache.db")
        self.assertEqual(op, OperationType.TRUNCATE)

    def test_delete_operations(self):
        op, target = classify_operation("rm -rf /tmp/build_dir")
        self.assertEqual(op, OperationType.DELETE)
        self.assertEqual(target, "/tmp/build_dir")

        op, target = classify_operation("unlink ~/.local/state/temp.sock")
        self.assertEqual(op, OperationType.DELETE)

    def test_move_operations(self):
        op, target = classify_operation("mv ~/.local/state/log.txt ~/.local/state/log.txt.bak")
        self.assertEqual(op, OperationType.MOVE)
        self.assertEqual(target, "~/.local/state/log.txt")

    def test_overwrite_operations(self):
        op, target = classify_operation("cp /tmp/new_config.json ~/.config/app/config.json")
        self.assertEqual(op, OperationType.OVERWRITE)
        self.assertEqual(target, "~/.config/app/config.json")

    def test_mutating_api_operations(self):
        op, target = classify_operation("defaults write com.apple.finder ShowAllFiles YES")
        self.assertEqual(op, OperationType.MUTATING_API)

        op, target = classify_operation("tccutil reset All com.apple.Terminal")
        self.assertEqual(op, OperationType.MUTATING_API)

        op, target = classify_operation("curl -X POST http://192.168.10.102:3000/api/v1/admin/users")
        self.assertEqual(op, OperationType.MUTATING_API)

    def test_heavy_exec_operations(self):
        op, target = classify_operation("cargo build --release")
        self.assertEqual(op, OperationType.HEAVY_EXEC)


class TestFullGovernanceMatrixScenarios(unittest.TestCase):
    """Test all 40 Matrix Combinations (5 Tiers x 8 Operations)."""

    def test_t0_ephemeral_all_allowed(self):
        for op in OperationType:
            verdict = BASE_GOVERNANCE_MATRIX[(ResourceTier.T0_EPHEMERAL, op)]
            self.assertEqual(verdict, Verdict.ALLOW, f"Expected ALLOW for T0 op {op}")

    def test_t1_caches_matrix(self):
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T1_REGENERABLE, OperationType.READ)], Verdict.ALLOW)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T1_REGENERABLE, OperationType.APPEND)], Verdict.ALLOW)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T1_REGENERABLE, OperationType.OVERWRITE)], Verdict.PROMPT)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T1_REGENERABLE, OperationType.TRUNCATE)], Verdict.ALLOW)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T1_REGENERABLE, OperationType.DELETE)], Verdict.ALLOW)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T1_REGENERABLE, OperationType.MOVE)], Verdict.ALLOW)
        self.assertEqual(
            BASE_GOVERNANCE_MATRIX[(ResourceTier.T1_REGENERABLE, OperationType.MUTATING_API)], Verdict.PROMPT
        )
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T1_REGENERABLE, OperationType.HEAVY_EXEC)], Verdict.ALLOW)

    def test_t2_clean_git_matrix(self):
        self.assertEqual(
            BASE_GOVERNANCE_MATRIX[(ResourceTier.T2_VERSION_CONTROLLED, OperationType.READ)], Verdict.ALLOW
        )
        self.assertEqual(
            BASE_GOVERNANCE_MATRIX[(ResourceTier.T2_VERSION_CONTROLLED, OperationType.APPEND)], Verdict.ALLOW
        )
        self.assertEqual(
            BASE_GOVERNANCE_MATRIX[(ResourceTier.T2_VERSION_CONTROLLED, OperationType.OVERWRITE)], Verdict.ALLOW
        )
        self.assertEqual(
            BASE_GOVERNANCE_MATRIX[(ResourceTier.T2_VERSION_CONTROLLED, OperationType.TRUNCATE)], Verdict.ALLOW
        )
        self.assertEqual(
            BASE_GOVERNANCE_MATRIX[(ResourceTier.T2_VERSION_CONTROLLED, OperationType.DELETE)], Verdict.PROMPT
        )
        self.assertEqual(
            BASE_GOVERNANCE_MATRIX[(ResourceTier.T2_VERSION_CONTROLLED, OperationType.MOVE)], Verdict.ALLOW
        )
        self.assertEqual(
            BASE_GOVERNANCE_MATRIX[(ResourceTier.T2_VERSION_CONTROLLED, OperationType.MUTATING_API)], Verdict.PROMPT
        )

    def test_t3_durable_gray_zone_matrix(self):
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T3_DURABLE_GRAY, OperationType.READ)], Verdict.ALLOW)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T3_DURABLE_GRAY, OperationType.APPEND)], Verdict.ALLOW)
        self.assertEqual(
            BASE_GOVERNANCE_MATRIX[(ResourceTier.T3_DURABLE_GRAY, OperationType.OVERWRITE)], Verdict.PROMPT
        )
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T3_DURABLE_GRAY, OperationType.TRUNCATE)], Verdict.BLOCK)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T3_DURABLE_GRAY, OperationType.DELETE)], Verdict.PROMPT)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T3_DURABLE_GRAY, OperationType.MOVE)], Verdict.PROMPT)
        self.assertEqual(
            BASE_GOVERNANCE_MATRIX[(ResourceTier.T3_DURABLE_GRAY, OperationType.MUTATING_API)], Verdict.PROMPT
        )
        self.assertEqual(
            BASE_GOVERNANCE_MATRIX[(ResourceTier.T3_DURABLE_GRAY, OperationType.HEAVY_EXEC)], Verdict.PROMPT
        )

    def test_t4_critical_matrix(self):
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T4_CRITICAL, OperationType.READ)], Verdict.PROMPT)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T4_CRITICAL, OperationType.APPEND)], Verdict.PROMPT)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T4_CRITICAL, OperationType.OVERWRITE)], Verdict.BLOCK)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T4_CRITICAL, OperationType.TRUNCATE)], Verdict.BLOCK)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T4_CRITICAL, OperationType.DELETE)], Verdict.BLOCK)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T4_CRITICAL, OperationType.MOVE)], Verdict.BLOCK)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T4_CRITICAL, OperationType.MUTATING_API)], Verdict.PROMPT)
        self.assertEqual(BASE_GOVERNANCE_MATRIX[(ResourceTier.T4_CRITICAL, OperationType.HEAVY_EXEC)], Verdict.BLOCK)


class TestSpecialEdgeCasesAndGuidance(unittest.TestCase):
    """Test specialized edge cases: /var/folders sockets, log truncates, and 7-field template."""

    def test_truncate_t3_log_is_blocked(self):
        verdict, reason, payload = evaluate_gray_zone_operation(
            "echo '' > ~/.local/state/package_history/brew_dump.json"
        )
        self.assertEqual(verdict, Verdict.BLOCK)
        self.assertIn("TRUNCATE", reason)

    def test_append_t3_log_is_allowed(self):
        verdict, reason, payload = evaluate_gray_zone_operation(
            "echo '2026-08-18 install pkg' >> ~/.local/state/package_history/history.log"
        )
        self.assertEqual(verdict, Verdict.ALLOW)

    def test_delete_t3_sqlite_prompts_with_7_fields(self):
        verdict, reason, payload = evaluate_gray_zone_operation("rm ~/.local/state/herdr-schengen/schengen_history.db")
        self.assertEqual(verdict, Verdict.PROMPT)
        self.assertIsNotNone(payload)

        doc = format_decision_guidance(payload)
        self.assertIn("[1] Target", doc)
        self.assertIn("[2] Operation", doc)
        self.assertIn("[3] Tier & Irreversibility", doc)
        self.assertIn("[4] Blast Radius", doc)
        self.assertIn("[5] Pre-Alternative", doc)
        self.assertIn("[6] Recovery Path", doc)
        self.assertIn("[7] Structured Choices", doc)
        self.assertIn("Create pre-backup", doc)

    def test_var_folders_socket_is_t4(self):
        # Even if in /T/, .sock is recognized as T4 critical
        tier = classify_resource_tier("/var/folders/ab/cd/T/agent_daemon.sock")
        self.assertEqual(tier, ResourceTier.T4_CRITICAL)

        verdict, reason, payload = evaluate_gray_zone_operation("rm /var/folders/ab/cd/T/agent_daemon.sock")
        self.assertEqual(verdict, Verdict.BLOCK)


if __name__ == "__main__":
    unittest.main()
