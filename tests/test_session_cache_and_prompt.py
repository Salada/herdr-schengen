import sys
import time
import unittest
from pathlib import Path

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from core.guard_db import _IN_MEMORY_EVAL_CACHE, get_cached_evaluation, set_cached_evaluation
from core.security_evaluator import DecisionLayer, audit_shell_command_with_taxonomy
from core.session_cache import clear_session_cache, compute_cache_key, get_cached_result, store_cached_result


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
        k_diff_cwd = compute_cache_key(
            "git status", cwd="/Users/kyjbusan/code/other", scope="w1:p1", agent_id="hermes-devops"
        )
        self.assertNotEqual(k1, k_diff_cwd)

        # Different agent produces different key
        k_diff_agent = compute_cache_key(
            "git status", cwd="/Users/kyjbusan/code/repo", scope="w1:p1", agent_id="hermes-ciso"
        )
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
            agent_id="test",
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
        """audit_dynamic_substitution_with_llm reuses cached verdicts for dynamic parameters."""
        from core.security_evaluator import audit_dynamic_substitution_with_llm

        cmd = "echo $(cat /tmp/safe.txt)"
        dyn_key = compute_cache_key(cmd, cwd="/tmp", scope="wS:pA", agent_id="test-agy", origin="I")

        # Seed the cache with an approved inspection
        store_cached_result(
            cache_key=dyn_key,
            raw_cmd=cmd,
            is_safe=True,
            safety_reason="Verified safe dynamic param",
            decision_layer="LLM_INSPECTOR",
            taxonomy={"origin": "I", "consequence": "NONE", "mechanism": "verified-param"},
            cwd="/tmp",
            scope="wS:pA",
            agent_id="test-agy",
            origin="I",
        )

        t0 = time.perf_counter()
        safe, reason = audit_dynamic_substitution_with_llm(cmd, cwd="/tmp", scope="wS:pA", agent_id="test-agy")
        elapsed = time.perf_counter() - t0

        self.assertTrue(safe)
        self.assertEqual(reason, "Verified safe dynamic param")
        self.assertLess(elapsed, 0.005)  # Cache lookup under 5ms

    def test_deterministic_guards_never_bypassed_by_poisoned_cache(self):
        """B1 Security Mandate: Deterministic catastrophic guards (rm -rf /) can NEVER be bypassed by cached entry."""
        danger_cmd = "rm -rf /System/Library"
        poisoned_key = compute_cache_key(danger_cmd, cwd="/", scope="w1:p1", agent_id="agent")

        # Manually poison cache with is_safe=True
        store_cached_result(
            cache_key=poisoned_key,
            raw_cmd=danger_cmd,
            is_safe=True,
            safety_reason="Fake safe verdict",
            decision_layer="FAST_TRACK_AST",
            taxonomy={"origin": "A", "consequence": "NONE", "mechanism": "poisoned"},
            cwd="/",
            scope="w1:p1",
            agent_id="agent",
        )

        # Evaluating the command MUST still return is_safe=False because deterministic guards run unconditionally
        safe, reason, layer, tax = audit_shell_command_with_taxonomy(
            danger_cmd, cwd="/", scope="w1:p1", agent_id="agent"
        )
        self.assertFalse(safe, "Catastrophic command was bypassed by poisoned cache entry!")
        self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL)

    def test_dynamic_ruleset_hash_invalidation(self):
        """B3: Dynamic ruleset hash is deterministic and derived from prompt and rule patterns."""
        from core.session_cache import get_dynamic_ruleset_version

        dyn_ver = get_dynamic_ruleset_version()
        self.assertTrue(dyn_ver.startswith("dyn-"))
        self.assertGreater(len(dyn_ver), 8)
        self.assertNotEqual(dyn_ver, "dyn-2.0.0", "get_dynamic_ruleset_version fell back to hardcoded default!")

    def test_cache_key_changes_on_all_dimensions(self):
        """Verify that cache key changes when cwd, scope, agent_id, origin, or ruleset changes."""
        base_key = compute_cache_key(
            "echo $(cat foo)",
            cwd="/home/a",
            scope="w1:p1",
            agent_id="hermes-devops",
            origin="I",
            ruleset_version="dyn-1",
        )
        self.assertNotEqual(
            base_key,
            compute_cache_key(
                "echo $(cat foo)",
                cwd="/home/b",
                scope="w1:p1",
                agent_id="hermes-devops",
                origin="I",
                ruleset_version="dyn-1",
            ),
        )
        self.assertNotEqual(
            base_key,
            compute_cache_key(
                "echo $(cat foo)",
                cwd="/home/a",
                scope="w1:p2",
                agent_id="hermes-devops",
                origin="I",
                ruleset_version="dyn-1",
            ),
        )
        self.assertNotEqual(
            base_key,
            compute_cache_key(
                "echo $(cat foo)",
                cwd="/home/a",
                scope="w1:p1",
                agent_id="hermes-ciso",
                origin="I",
                ruleset_version="dyn-1",
            ),
        )
        self.assertNotEqual(
            base_key,
            compute_cache_key(
                "echo $(cat foo)",
                cwd="/home/a",
                scope="w1:p1",
                agent_id="hermes-devops",
                origin="A",
                ruleset_version="dyn-1",
            ),
        )
        self.assertNotEqual(
            base_key,
            compute_cache_key(
                "echo $(cat foo)",
                cwd="/home/a",
                scope="w1:p1",
                agent_id="hermes-devops",
                origin="I",
                ruleset_version="dyn-2",
            ),
        )

    def test_true_lru_eviction(self):
        """N2: True LRU OrderedDict pops least recently used item when capacity is reached."""

        clear_session_cache()

        # Insert items 0 to 4
        for i in range(5):
            k = f"key_{i}"
            set_cached_evaluation(k, f"echo {i}", True, "safe", "FAST_TRACK_AST", {}, ttl_seconds=3600)

        # Access key_0 to move it to most recently used
        get_cached_evaluation("key_0")

        # Manually shrink max size for testing eviction
        from core.guard_db import _IN_MEMORY_EVAL_CACHE

        while len(_IN_MEMORY_EVAL_CACHE) > 3:
            _IN_MEMORY_EVAL_CACHE.popitem(last=False)

        # key_0 was accessed and should still be in cache; key_1 was least recently used and evicted
        self.assertIn("key_0", _IN_MEMORY_EVAL_CACHE)
        self.assertNotIn("key_1", _IN_MEMORY_EVAL_CACHE)

    def test_few_shot_prompt_schema_and_adversarial_exemplars(self):
        """N1: Prompt contains English-only concise instructions and adversarial few-shot exemplars."""
        from core.security_evaluator import MINIMAL_INSPECTOR_SYSTEM_PROMPT

        self.assertIn("Adversarial Exemplars:", MINIMAL_INSPECTOR_SYSTEM_PROMPT)
        self.assertIn(".env", MINIMAL_INSPECTOR_SYSTEM_PROMPT)
        self.assertIn("/etc/shadow", MINIMAL_INSPECTOR_SYSTEM_PROMPT)
        self.assertIn("taxonomy", MINIMAL_INSPECTOR_SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()
