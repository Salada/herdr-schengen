"""Obvious-safe version/help fast-track tests.

Trivially-safe, side-effect-free version/help queries (`node --version`,
`python3 --version`, `git --version`, ...) must fast-track (FAST_TRACK_AST)
instead of reaching the LLM — while anything with a script argument, a pipe,
chaining, mutation, egress, or a sensitive target stays blocked exactly as
before:
  * `node -e "rm -rf /"`        -> SHELL_CRITICAL (script arg, not a flag)
  * `cat ~/.ssh/id_rsa`         -> SECRET_GUARD   (sensitive read)
  * `node --version | grep x`   -> NOT_ALLOWLISTED (pipeline, not a single cmd)
"""

import sys
import unittest
from pathlib import Path

# Add scripts directory to path
SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from core.security_evaluator import (
    DecisionLayer,
    _is_fast_track_allowlisted,
    _is_obvious_safe_version_help,
    audit_shell_command,
)

FAST_TRACK = DecisionLayer.FAST_TRACK_AST
SECRET_GUARD = DecisionLayer.SECRET_GUARD
SHELL_CRITICAL = DecisionLayer.SHELL_CRITICAL


class TestObviousSafeRecognizer(unittest.TestCase):
    """Direct _is_obvious_safe_version_help gate checks."""

    def test_version_help_flags_recognized(self):
        for cmd in (
            "node --version",
            "python --version",
            "python3 --version",
            "python3 -V",
            "pip --version",
            "pip3 --version",
            "npm --version",
            "npm -v",
            "ruby -v",
            "rustc --version",
            "rustc -V",
            "cargo --version",
            "docker --version",
            "brew --version",
            "git --version",
            "git -v",
            "git --help",
            "node --help",
            "python3 -h",
        ):
            self.assertTrue(
                _is_obvious_safe_version_help(cmd), f"expected recognizer True for '{cmd}'"
            )

    def test_non_flag_args_not_recognized(self):
        # A script / extra argument means this is NOT a bare version/help query.
        for cmd in (
            'node -e "rm -rf /"',
            "node -e \"console.log('x')\"",
            "python3 -c \"import os\"",
            "python3 script.py",
            "npm install",
            "docker ps",
            "brew install git",
            "git status",
            "python3 -m unittest",
            "pip3 install requests",
            "ruby script.rb",
            "cargo build",
            "go run main.go",
        ):
            self.assertFalse(
                _is_obvious_safe_version_help(cmd), f"expected recognizer False for '{cmd}'"
            )

    def test_chained_piped_or_redirected_not_recognized(self):
        for cmd in (
            "node --version | grep x",
            "python3 --version; ls",
            "python3 --version && git status",
            "node --version > /tmp/out",
            "docker --version 2>&1",
            "npm --version\nls",
            "git --version $(date)",
        ):
            self.assertFalse(
                _is_obvious_safe_version_help(cmd), f"expected recognizer False for '{cmd}'"
            )

    def test_sensitive_or_mutating_shapes_not_recognized(self):
        for cmd in (
            "cat ~/.ssh/id_rsa",
            "python3 --version && rm -rf /",
            "node -v ~/.ssh/id_rsa",
        ):
            self.assertFalse(
                _is_obvious_safe_version_help(cmd), f"expected recognizer False for '{cmd}'"
            )

    def test_closed_interpreter_set_only(self):
        # Binaries OUTSIDE the closed set must never obvious-safe fast-track.
        for cmd in (
            "curl --version",
            "wget --version",
            "nc -h",
            "sh --version",
            "bash --version",
            "zsh --version",
            "python3.12 --version",
            "nodejs --version",
            "npx --version",
        ):
            self.assertFalse(
                _is_obvious_safe_version_help(cmd), f"expected recognizer False for '{cmd}'"
            )


class TestObviousSafeFastTrackDirect(unittest.TestCase):
    """_is_fast_track_allowlisted honors the recognizer as a LAST-resort layer."""

    def test_version_queries_allowlisted(self):
        for cmd in (
            "node --version",
            "python3 --version",
            "git --version",
            "docker --version",
            "npm -v",
        ):
            self.assertTrue(_is_fast_track_allowlisted(cmd), cmd)

    def test_script_arg_never_allowlisted(self):
        # CRITICAL: node -e with a destructive payload must NOT fast-track.
        self.assertFalse(_is_fast_track_allowlisted('node -e "rm -rf /"'))
        self.assertFalse(_is_fast_track_allowlisted('python3 -c "import os"'))

    def test_pipe_never_allowlisted(self):
        self.assertFalse(_is_fast_track_allowlisted("node --version | grep x"))
        self.assertFalse(_is_fast_track_allowlisted("python3 --version && git status"))


class TestObviousSafeFastTrackEndToEnd(unittest.TestCase):
    """End-to-end audit_shell_command layers keep their precedence."""

    def test_version_queries_fast_track(self):
        for cmd in (
            "node --version",
            "python --version",
            "python3 --version",
            "git --version",
            "git -v",
            "git --help",
            "docker --version",
            "brew --version",
            "rustc --version",
            "npm -v",
            "ruby -v",
            "pip3 --version",
        ):
            safe, reason, layer = audit_shell_command(cmd)
            self.assertTrue(safe, f"Expected '{cmd}' fast-track safe, got: {reason}")
            self.assertEqual(layer, FAST_TRACK, f"layer for '{cmd}' was {layer}: {reason}")

    def test_node_script_arg_still_shell_critical(self):
        # `node -e "rm -rf /"` runs a destructive script: CRITICAL patterns fire
        # on the raw string BEFORE any fast-track layer.
        safe, reason, layer = audit_shell_command('node -e "rm -rf /"')
        self.assertFalse(safe, f"Expected '{reason}' fail-closed, got safe=True")
        self.assertEqual(layer, SHELL_CRITICAL)

    def test_sensitive_read_still_secret_guard(self):
        safe, reason, layer = audit_shell_command("cat ~/.ssh/id_rsa")
        self.assertFalse(safe, f"Expected '{reason}' fail-closed, got safe=True")
        self.assertEqual(layer, SECRET_GUARD)

    def test_version_query_with_pipe_not_obvious_safe(self):
        # A pipe means two segments — the version query alone is obvious-safe,
        # but the CHAIN is not (not provably-benign as a unit).
        safe, reason, layer = audit_shell_command("node --version | grep x")
        self.assertFalse(safe, f"Expected '{reason}' fail-closed, got safe=True")
        self.assertNotEqual(layer, FAST_TRACK)

    def test_chain_with_mutation_not_obvious_safe(self):
        safe, reason, layer = audit_shell_command("python3 --version && rm -rf /")
        self.assertFalse(safe, f"Expected '{reason}' fail-closed, got safe=True")
        self.assertEqual(layer, SHELL_CRITICAL)

    def test_non_closed_binary_not_fast_tracked(self):
        # curl is forensic/network + outside the closed set: must escalate.
        safe, reason, layer = audit_shell_command("curl --version")
        self.assertFalse(safe, f"Expected '{reason}' fail-closed, got safe=True")
        self.assertNotEqual(layer, FAST_TRACK)


if __name__ == "__main__":
    unittest.main()
