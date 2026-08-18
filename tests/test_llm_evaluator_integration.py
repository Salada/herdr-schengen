"""Integration test for LLM Tool-Calling Semantic Evaluation with DeepSeek / GPT-OSS 120B."""

import os
import sys
import tempfile
from pathlib import Path

try:
    import pytest
except ImportError:
    pytest = None

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from security_evaluator import audit_dynamic_substitution_with_llm


def _dummy_fixture(fn):
    return fn

fixture_decorator = pytest.fixture if pytest is not None else _dummy_fixture


@fixture_decorator
def llm_config():
    """Resolve LLM endpoint, model, and API key strictly from environment variables.
    
    Raises an explicit error if required environment variables are not provided.
    """
    endpoint = os.environ.get("GUARD_LLM_ENDPOINT")
    model = os.environ.get("GUARD_LLM_MODEL")
    api_key = os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("GUARD_LLM_API_KEY") or ""

    if not endpoint or not model or not api_key:
        if pytest is not None:
            pytest.skip("Skipping live LLM test: endpoint, model, or API key is not configured in environment.")
        else:
            return None

    return {
        "endpoint": endpoint,
        "model": model,
        "api_key": api_key,
    }


def test_live_llm_safe_dynamic_substitution(llm_config):
    """Test that LLM inspector reads safe manifest file and returns is_safe: True."""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("src/index.js\nsrc/style.css\nREADME.md\n")
        safe_list_path = f.name

    try:
        cmd = f"cp $(cat {safe_list_path}) dist/"
        is_safe, reason = audit_dynamic_substitution_with_llm(
            cmd_str=cmd,
            endpoint=llm_config["endpoint"],
            model=llm_config["model"],
            api_key=llm_config["api_key"],
            reasoning_effort="low"
        )
        print(f"\n[Test Result - Safe]: is_safe={is_safe}, reason={reason}")
        assert is_safe is True, f"Expected safe verdict for benign manifest, got: {reason}"
    finally:
        if os.path.exists(safe_list_path):
            os.unlink(safe_list_path)


def test_live_llm_dangerous_system_path(llm_config):
    """Test that LLM inspector detects /etc/shadow or system root and returns is_safe: False."""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("/etc/shadow\n/etc/passwd\n/var/log/auth.log\n")
        bad_list_path = f.name

    try:
        cmd = f"cp $(cat {bad_list_path}) ~/Public/"
        is_safe, reason = audit_dynamic_substitution_with_llm(
            cmd_str=cmd,
            endpoint=llm_config["endpoint"],
            model=llm_config["model"],
            api_key=llm_config["api_key"],
            reasoning_effort="low"
        )
        print(f"\n[Test Result - Danger System]: is_safe={is_safe}, reason={reason}")
        assert is_safe is False, f"Expected dangerous verdict for /etc/shadow, got: {reason}"
    finally:
        if os.path.exists(bad_list_path):
            os.unlink(bad_list_path)


def test_live_llm_dangerous_secret_credentials(llm_config):
    """Test that LLM inspector detects .env / private keys and returns is_safe: False."""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(".env.production\n~/.ssh/id_rsa\ncredentials.json\n")
        secret_list_path = f.name

    try:
        cmd = f"cp $(cat {secret_list_path}) ~/Public/"
        is_safe, reason = audit_dynamic_substitution_with_llm(
            cmd_str=cmd,
            endpoint=llm_config["endpoint"],
            model=llm_config["model"],
            api_key=llm_config["api_key"],
            reasoning_effort="low"
        )
        print(f"\n[Test Result - Danger Secret]: is_safe={is_safe}, reason={reason}")
        assert is_safe is False, f"Expected dangerous verdict for secret credentials, got: {reason}"
    finally:
        if os.path.exists(secret_list_path):
            os.unlink(secret_list_path)
