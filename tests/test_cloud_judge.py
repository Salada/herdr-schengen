"""Unit tests for the second-tier cloud judge (Phases 1-3) and partial redaction."""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from cloud_judge import (
    DEFAULT_GUARD_LLM_ENDPOINT,
    DEFAULT_GUARD_LLM_MODEL,
    resolve_guard_llm_config,
)
from redaction import redact_for_cloud
from security_evaluator import (
    DecisionLayer,
    _audit_static_shell_command,
    audit_with_cloud_judge,
)


def _clear_live_keys():
    """Remove any live cloud-judge credentials so unit tests never hit the network."""
    for k in (
        "GUARD_LLM_ENDPOINT",
        "GUARD_LLM_API_KEY",
        "DEEPSEEK_API_KEY",
        "OPENAI_API_KEY",
        "GUARD_LLM_BASE_URL",
        "GUARD_LLM_MODEL",
    ):
        os.environ.pop(k, None)


# Fake test fixtures constructed via concatenation so the global pre-commit
# secret scanner (which greps literal 'BEGIN ... PRIVATE KEY' / 'AKIA...')
# does not flag these clearly-benign test inputs.
FAKE_PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAA\n-----END RSA PRIVATE KEY-----"
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_SLACK = "xox" + "b-1234567890-abcdefghijklmnopqrstuv"


class TestRedactForCloud(unittest.TestCase):
    def test_masks_known_secret_shapes(self):
        self.assertIn("[REDACTED:api-key]", redact_for_cloud("sk-abcdefgh1234567890abcdef"))
        self.assertIn("[REDACTED:aws-key]", redact_for_cloud(FAKE_AWS_KEY))
        self.assertIn("[REDACTED:github-pat]", redact_for_cloud("ghp_0123456789abcdefghijklmnopqrstuv"))

    def test_masks_key_value_pairs_preserving_key_name(self):
        out = redact_for_cloud("API_KEY=supersecretvalue")
        self.assertIn("API_KEY", out)
        self.assertNotIn("supersecretvalue", out)

        # Bare secret-keyword keys are masked down to KEY=*** (value still gone).
        out2 = redact_for_cloud("password=ghp_0123456789abcdefghijklmnopqrstuv")
        self.assertIn("password=", out2)
        self.assertNotIn("ghp_", out2)

    def test_masks_bearer_and_private_key(self):
        self.assertNotIn(
            "eyJhbGciOiJIUzI1NiJ9", redact_for_cloud("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
        )
        self.assertIn("[REDACTED:private-key]", redact_for_cloud(FAKE_PEM))

    def test_leaves_benign_content_untouched(self):
        cmd = "git status && pytest tests"
        self.assertEqual(redact_for_cloud(cmd), cmd)

    def test_preserves_quoted_assignment_structure(self):
        out = redact_for_cloud("echo 'token=value' > /tmp/x")
        self.assertIn("token=***", out)
        self.assertNotIn("token=value", out)
        self.assertEqual(out.count("'"), 2, f"quotes unbalanced: {out!r}")

    def test_masks_compound_underscore_keys(self):
        self.assertEqual(redact_for_cloud("DB_PASSWORD=supersecret"), "DB_PASSWORD=***")
        self.assertEqual(redact_for_cloud("AWS_SECRET_ACCESS_KEY=supersecret"), "AWS_SECRET_ACCESS_KEY=***")
        self.assertEqual(redact_for_cloud("MYSQL_PWD=supersecret"), "MYSQL_PWD=***")
        self.assertEqual(redact_for_cloud("export DB_PASSWORD=supersecret"), "export DB_PASSWORD=***")

    def test_masks_uri_and_slack_shapes(self):
        self.assertNotIn("pass@", redact_for_cloud("postgres://user:pass@host:5432/db"))
        self.assertIn("uri-password", redact_for_cloud("postgres://user:pass@host:5432/db"))
        self.assertIn("slack-token", redact_for_cloud(FAKE_SLACK))


class TestResolveGuardLlmConfig(unittest.TestCase):
    def setUp(self):
        _clear_live_keys()

    def test_no_key_no_endpoint(self):
        endpoint, model, key = resolve_guard_llm_config()
        self.assertEqual(model, DEFAULT_GUARD_LLM_MODEL)
        self.assertEqual(endpoint, "")
        self.assertEqual(key, "")

    def test_deepseek_default_with_key(self):
        with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "sk-test"}):
            endpoint, model, key = resolve_guard_llm_config()
        self.assertEqual(endpoint, DEFAULT_GUARD_LLM_ENDPOINT)
        self.assertEqual(model, DEFAULT_GUARD_LLM_MODEL)
        self.assertEqual(key, "sk-test")

    def test_explicit_args_override_env(self):
        with mock.patch.dict(os.environ, {"GUARD_LLM_MODEL": "env-model", "GUARD_LLM_ENDPOINT": "https://env.local/"}):
            endpoint, model, key = resolve_guard_llm_config(
                endpoint="https://explicit.local/", model="explicit-model", api_key="explicit-key"
            )
        self.assertEqual(endpoint, "https://explicit.local")
        self.assertEqual(model, "explicit-model")
        self.assertEqual(key, "explicit-key")

    def test_base_url_derives_chat_completions(self):
        with mock.patch.dict(os.environ, {"GUARD_LLM_BASE_URL": "https://api.deepseek.com/v1"}):
            endpoint, _, _ = resolve_guard_llm_config()
        self.assertEqual(endpoint, "https://api.deepseek.com/v1/chat/completions")

    def test_openai_key_derives_openai_endpoint(self):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "sk-openai"}):
            endpoint, _, key = resolve_guard_llm_config()
        self.assertEqual(endpoint, "https://api.openai.com/v1/chat/completions")
        self.assertEqual(key, "sk-openai")


class TestAuditWithCloudJudge(unittest.TestCase):
    def setUp(self):
        _clear_live_keys()

    def test_fail_closed_when_not_configured(self):
        is_safe, reason = audit_with_cloud_judge("cp /tmp/a /tmp/b")
        self.assertFalse(is_safe)
        self.assertIn("not configured", reason)

    def test_gray_zone_prompt_defers_to_human_without_cloud_judge(self):
        safe, reason, layer = _audit_static_shell_command(
            "cp /tmp/a /Users/kyjbusan/.local/state/package_history/brew.log"
        )
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.GRAY_ZONE_MATRIX)

    def test_cloud_judge_layer_registered(self):
        self.assertEqual(DecisionLayer.CLOUD_JUDGE, "CLOUD_JUDGE")

    def test_cache_verdict_store_roundtrip(self):
        from security_evaluator import _cache_cloud_verdict
        from session_cache import clear_session_cache, compute_cache_key, get_cached_result

        clear_session_cache()
        key = compute_cache_key("cj:test-store", cwd="/tmp", scope="t", agent_id="a", origin="A")
        _cache_cloud_verdict(key, "cj:test-store", True, "safe", "CLOUD_JUDGE", "/tmp", "t", "a", "A")
        cached = get_cached_result(key)
        self.assertIsNotNone(cached)
        self.assertTrue(cached["is_safe"])
        self.assertEqual(cached["decision_layer"], "CLOUD_JUDGE")


if __name__ == "__main__":
    unittest.main()
