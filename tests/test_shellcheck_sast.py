import os
import sys
import unittest
from pathlib import Path

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from shellcheck_evaluator import audit_shell_with_shellcheck, is_shellcheck_available
from security_evaluator import (
    audit_shell_command,
    audit_shell_command_with_taxonomy,
    DecisionLayer,
    Origin,
    Consequence,
)


class TestShellCheckSAST(unittest.TestCase):
    """Test suite for Step 2 (Phase 1): Scoped ShellCheck SAST pre-filter."""

    def test_static_command_fast_path(self):
        """Static commands without variables bypass ShellCheck subprocess invocation."""
        safe, reason, details = audit_shell_with_shellcheck("git status")
        self.assertTrue(safe)
        self.assertIn("Static command", reason)

    def test_sc2115_catastrophic_root_wipe(self):
        """SC2115: Use of unassigned/unprotected variable expanding to /* is blocked."""
        if not is_shellcheck_available():
            self.skipTest("shellcheck binary not installed on runner")

        cmd = 'rm -rf "$TARGET/*"'
        safe, reason, layer, tax = audit_shell_command_with_taxonomy(cmd)
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SAST_SHELLCHECK)
        self.assertEqual(tax["origin"], Origin.EMERGENT.value)
        self.assertEqual(tax["consequence"], Consequence.DESTRUCTION.value)
        self.assertEqual(tax["mechanism"], "unbound-variable-sc2115")

    def test_sc2154_unbound_variable_destructive(self):
        """SC2154: Unbound variable in destructive rm command is blocked."""
        if not is_shellcheck_available():
            self.skipTest("shellcheck binary not installed on runner")

        cmd = 'rm -rf "$COMPLETELY_UNDEFINED_PROJECT_DIR_XYZ"'
        safe, reason, layer, tax = audit_shell_command_with_taxonomy(cmd)
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SAST_SHELLCHECK)
        self.assertEqual(tax["origin"], Origin.EMERGENT.value)
        self.assertEqual(tax["consequence"], Consequence.DESTRUCTION.value)

    def test_env_whitelist_allows_runtime_variables(self):
        """Runtime environment variables in whitelist (HOME, TMPDIR) are not blocked."""
        if not is_shellcheck_available():
            self.skipTest("shellcheck binary not installed on runner")

        # Echoing HOME is benign and HOME is in whitelist
        safe, reason, layer, tax = audit_shell_command_with_taxonomy('echo "User home is $HOME"')
        self.assertTrue(safe)

    def test_assigned_variable_passes_sast(self):
        """Variables defined and assigned within the same script block pass SAST."""
        if not is_shellcheck_available():
            self.skipTest("shellcheck binary not installed on runner")

        cmd = 'BUILD_DIR=/tmp/my_test_build && echo "Building in $BUILD_DIR"'
        safe, reason, layer, tax = audit_shell_command_with_taxonomy(cmd)
        self.assertTrue(safe)

    def test_secret_variables_are_not_whitelisted_from_scrutiny(self):
        """Secret tokens (FORGEJO_TOKEN, BW_SESSION) are not in whitelist and are scrutinized."""
        if not is_shellcheck_available():
            self.skipTest("shellcheck binary not installed on runner")

        cmd = 'rm -rf "$FORGEJO_TOKEN_XYZ"'
        safe, reason, layer, tax = audit_shell_command_with_taxonomy(cmd)
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SAST_SHELLCHECK)
        self.assertEqual(tax["origin"], Origin.EMERGENT.value)

    def test_degraded_state_reported_when_binary_absent(self):
        """When shellcheck is unavailable, destructive commands with vars emit DEGRADED telemetry."""
        from unittest.mock import patch
        with patch("shellcheck_evaluator.is_shellcheck_available", return_value=False):
            safe, reason, details = audit_shell_with_shellcheck('rm -rf "$TARGET_DIR"')
            self.assertTrue(safe)  # Fails open to Layer 2 pattern guards
            self.assertIsNotNone(details)
            self.assertTrue(details.get("degraded"))
            self.assertEqual(details.get("reason"), "BINARY_ABSENT")
            self.assertIn("DEGRADED_UNAVAILABLE", reason)


if __name__ == "__main__":
    unittest.main()
