"""Unit tests for the second-tier cloud judge (Phases 1-3) and partial redaction."""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from redaction import redact_for_cloud
from security_evaluator import (
    resolve_guard_llm_config,
    audit_with_cloud_judge,
    _audit_static_shell_command,
    DecisionLayer,
    DEFAULT_GUARD_LLM_ENDPOINT,
    DEFAULT_GUARD_LLM_MODEL,
)


def _clear_live_keys():
    """Remove any live cloud-judge credentials so unit tests never hit the network."""
    for k in (
        "GUARD_LLM_ENDPOINT", "GUARD_LLM_API_KEY", "DEEPSEEK_API_KEY",
        "OPENAI_API_KEY", "GUARD_LLM_BASE_URL", "GUARD_LLM_MODEL",
    ):
        os.environ.pop(k, None)


# Fake test fixtures constructed via concatenation so the global pre-commit
# secret scanner (which greps literal 'BEGIN ... PRIVATE KEY' / 'AKIA...')
# does not flag these clearly-benign test inputs.
FAKE_PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAA\n-----END RSA PRIVATE KEY-----"
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


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
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", redact_for_cloud("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"))
        self.assertIn("[REDACTED:private-key]", redact_for_cloud(FAKE_PEM))

    def test_leaves_benign_content_untouched(self):
        cmd = "git status && pytest tests"
        self.assertEqual(redact_for_cloud(cmd), cmd)


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


if __name__ == "__main__":
    unittest.main()
