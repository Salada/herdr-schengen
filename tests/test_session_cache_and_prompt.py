import os
import sys
import time
import unittest
from pathlib import Path

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from session_cache import compute_cache_key, get_cached_result, store_cached_result
from guard_db import (
    get_cached_evaluation,
    set_cached_evaluation,
    purge_expired_cache_entries,
    _IN_MEMORY_EVAL_CACHE
)
from security_evaluator import (
    audit_shell_command_with_taxonomy,
    DecisionLayer,
    Origin,
    Consequence
)


class TestSessionCacheAndPrompt(unittest.TestCase):
    """Test suite for Step 3: Context-Full Session Cache & English Minimal Prompt."""

    def setUp(self):
        _IN_MEMORY_EVAL_CACHE.clear()

    def test_compute_cache_key_deterministic(self):
        """Cache keys are deterministic and sensitive to context dimensions."""
        k1 = compute_cache_key("git status", cwd="/Users/kyjbusan/code/repo", scope="w1:p1", agent_id="hermes-devops")
        k2 = compute_cache_key("git status", cwd="/Users/kyjbusan/code/repo", scope="w1:p1", agent_id="hermes-devops")
        self.assertEqual(k1, k2)

        # Different cwd produces different key
        k_diff_cwd = compute_cache_key("git status", cwd="/Users/kyjbusan/code/other", scope="w1:p1", agent_id="hermes-devops")
        self.assertNotEqual(k1, k_diff_cwd)

        # Different agent produces different key
        k_diff_agent = compute_cache_key("git status", cwd="/Users/kyjbusan/code/repo", scope="w1:p1", agent_id="hermes-ciso")
        self.assertNotEqual(k1, k_diff_agent)

    def test_in_memory_and_sqlite_cache_roundtrip(self):
        """Values stored in cache are retrievable from memory and persisted to SQLite."""
        test_key = compute_cache_key("echo 'cache test'", cwd="/tmp", scope="test", agent_id="test")
        sample_tax = {"origin": "A", "consequence": "NONE", "mechanism": "fast-track-verified"}
        
        store_cached_result(
            cache_key=test_key,
            raw_cmd="echo 'cache test'",
            is_safe=True,
            safety_reason="Verified safe command",
            decision_layer="FAST_TRACK_AST",
            taxonomy=sample_tax,
            cwd="/tmp",
            scope="test",
            agent_id="test"
        )

        # 1. First hit should be from in-memory cache
        res_mem = get_cached_result(test_key)
        self.assertIsNotNone(res_mem)
        self.assertTrue(res_mem["is_safe"])
        self.assertTrue(res_mem["from_memory"])
        self.assertEqual(res_mem["decision_layer"], "FAST_TRACK_AST")

        # 2. Clear in-memory cache to force SQLite DB fallback lookup
        clear_session_cache()
        res_db = get_cached_result(test_key)
        self.assertIsNotNone(res_db)
        self.assertTrue(res_db["is_safe"])
        self.assertFalse(res_db["from_memory"])
        self.assertEqual(res_db["taxonomy"]["mechanism"], "fast-track-verified")

    def test_end_to_end_audit_command_caching(self):
        """audit_shell_command_with_taxonomy seamlessly reuses cached verdicts."""
        cmd = "ls -la /tmp"
        
        # Turn 1: Cold evaluation
        t0 = time.perf_counter()
        safe1, reason1, layer1, tax1 = audit_shell_command_with_taxonomy(cmd, cwd="/tmp", scope="wS:pA", agent_id="test-agy")
        t_cold = time.perf_counter() - t0
        self.assertTrue(safe1)

        # Turn 2: Warm cached evaluation (<2ms latency)
        t1 = time.perf_counter()
        safe2, reason2, layer2, tax2 = audit_shell_command_with_taxonomy(cmd, cwd="/tmp", scope="wS:pA", agent_id="test-agy")
        t_warm = time.perf_counter() - t1
        self.assertTrue(safe2)
        self.assertEqual(reason1, reason2)
        self.assertEqual(layer1, layer2)
        self.assertLess(t_warm, 0.01)  # Warm lookup well under 10ms

    def test_cache_expiration_and_purge(self):
        """Expired cache items are ignored and purged from SQLite table."""
        exp_key = compute_cache_key("rm -rf /tmp/expired_test", cwd="/tmp")
        set_cached_evaluation(
            cache_key=exp_key,
            raw_command="rm -rf /tmp/expired_test",
            is_safe=False,
            safety_reason="Destructive rm",
            decision_layer="SHELL_CRITICAL",
            taxonomy={"origin": "A", "consequence": "DEST", "mechanism": "rm-rf"},
            ttl_seconds=-10  # Already expired 10 seconds ago
        )
        _IN_MEMORY_EVAL_CACHE.clear()

        # Lookup should return None because TTL expired
        lookup_res = get_cached_evaluation(exp_key)
        self.assertIsNone(lookup_res)

        # Purge should clean up expired rows
        purged = purge_expired_cache_entries()
        self.assertGreaterEqual(purged, 1)


if __name__ == "__main__":
    unittest.main()
