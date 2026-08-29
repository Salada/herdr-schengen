"""Package-manager 3-tuple classifier tests (INV-8..11).

Verifies that package-manager READ_ONLY queries fast-track via PACKAGE_GUARD
while MUTATING commands escalate via PACKAGE_GUARD — and that non-package or
unknown-action commands fall through to their normal paths (fail-closed).
"""

import sys
import unittest
from pathlib import Path

# Add scripts directory to path
SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from core.security_evaluator import DecisionLayer, audit_shell_command


class TestPackageManagerClassifier(unittest.TestCase):
    """INV-8..11: 3-tuple (manager, action_class, packages) classification."""

    def test_read_only_queries_fast_track(self):
        read_only = (
            "brew list",
            "brew info git",
            "pip show requests",
            "npm view react",
            "npm outdated",
            "brew leaves",
            "apt list --installed",
            "cargo search serde",
        )
        for cmd in read_only:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertTrue(safe, f"Expected read-only package query '{cmd}' safe, got: {reason}")
            self.assertEqual(layer, DecisionLayer.PACKAGE_GUARD)

    def test_mutating_commands_escalate(self):
        mutating = (
            "brew install git",
            "brew uninstall git",
            "npm install -g typescript",
            "npm ci",
            "pip install requests",
            "pip uninstall requests",
            "apt-get upgrade",
            "brew upgrade",  # bare no-package mutation must escalate
            "brew bundle",
            "cargo install ripgrep",
            "brew cleanup",
            "npm install",  # bare no-package mutation must escalate
        )
        for cmd in mutating:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected package mutation '{cmd}' to escalate, got safe=True: {reason}")
            self.assertEqual(layer, DecisionLayer.PACKAGE_GUARD)

    def test_blocked_earlier_not_package_guard(self):
        # sudo denylist fires BEFORE the package classifier -> SHELL_CRITICAL.
        safe, reason, layer = audit_shell_command("sudo pip install x")
        self.assertFalse(safe, f"Expected 'sudo pip install x' to escalate, got safe=True: {reason}")
        self.assertNotEqual(layer, DecisionLayer.PACKAGE_GUARD)

    def test_non_package_commands_still_fast_track(self):
        # classifier returns None for non-package managers -> FAST_TRACK_AST.
        for cmd in ("git status", "ls -la"):
            safe, reason, layer = audit_shell_command(cmd)
            self.assertTrue(safe, f"Expected '{cmd}' fast-track safe, got: {reason}")
            self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_unknown_action_fail_closed(self):
        # Unknown action (not in MUTATING/READ_ONLY) -> unclassified -> fail-closed.
        safe, reason, layer = audit_shell_command("brew foo")
        self.assertFalse(safe, f"Expected unknown action 'brew foo' to escalate, got safe=True: {reason}")

    def test_config_subcommand_escalates(self):
        # Reviewer finding 1: `config` is MUTATING (writes config files, can
        # redirect the registry — supply-chain vector). ALL config subcommands
        # escalate, conservatively (set/get/list/debug/delete/edit).
        for cmd in (
            "npm config set registry https://evil.example.com",
            "pip config set global.index-url https://evil.example.com",
            "cargo config set build.jobs 1",
            "brew config",
            "npm config get registry",
        ):
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' to escalate, got safe=True: {reason}")
            self.assertEqual(layer, DecisionLayer.PACKAGE_GUARD)

    def test_readonly_metachar_pipeline_escalates(self):
        # Reviewer finding 2: READ_ONLY fast-track must not apply when the command
        # contains shell metacharacters (pipe) — falls through to fail-closed.
        for cmd in ("brew list | bash", "brew list | sh"):
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' to escalate, got safe=True: {reason}")
            self.assertNotEqual(layer, DecisionLayer.PACKAGE_GUARD)

    def test_readonly_redirection_escalates(self):
        # Reviewer finding 2: redirection on a READ_ONLY query must not auto-approve.
        for cmd in (
            "brew list >> ~/.bash_profile",
            "pip list >> ~/.zshrc",
            "npm view react > /tmp/out",
        ):
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' to escalate, got safe=True: {reason}")
            self.assertNotEqual(layer, DecisionLayer.PACKAGE_GUARD)

    def test_taxonomy_mechanism(self):
        from core.security_evaluator import Consequence, audit_shell_command_with_taxonomy

        # READ_ONLY -> package-read-query, consequence NONE
        safe, reason, layer, tax = audit_shell_command_with_taxonomy("brew list")
        self.assertTrue(safe)
        self.assertEqual(layer, DecisionLayer.PACKAGE_GUARD)
        self.assertEqual(tax["mechanism"], "package-read-query")
        self.assertEqual(tax["consequence"], Consequence.NONE.value)

        # MUTATING -> package-mutation, consequence INTEGRITY
        safe, reason, layer, tax = audit_shell_command_with_taxonomy("brew install git")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.PACKAGE_GUARD)
        self.assertEqual(tax["mechanism"], "package-mutation")
        self.assertEqual(tax["consequence"], Consequence.INTEGRITY.value)


if __name__ == "__main__":
    unittest.main()
