"""Issue #197 read-only Docker and diagnostic target policy."""

import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from core.security_evaluator import DecisionLayer, audit_shell_command


class TestReadonlyDockerPolicy(unittest.TestCase):
    def assert_fast_track(self, command: str) -> None:
        safe, reason, layer = audit_shell_command(command)
        self.assertTrue(safe, reason)
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def assert_denied(self, command: str) -> None:
        safe, _reason, _layer = audit_shell_command(command)
        self.assertFalse(safe)

    def test_readonly_docker_exec_fast_tracks(self):
        for command in (
            "docker exec agentsview sh -c 'test -f /data/config.toml'",
            "docker exec -it agentsview cat /data/config.toml",
            "docker exec agentsview sh -c 'test -f /data/config.toml && sed -E \"s/^([A-Za-z0-9_]+)=.*/\\1=<redacted>/\" /data/config.toml || true'",
            "echo __CONFIG__ && docker exec agentsview sh -c 'test -f /data/config.toml' && git status --short",
        ):
            with self.subTest(command=command):
                self.assert_fast_track(command)

    def test_docker_payload_mutation_egress_and_dynamic_forms_stay_closed(self):
        for command in (
            "docker exec agentsview sh -c 'rm -rf /data/cache'",
            "docker exec agentsview sh -c 'cat /data/config.toml > /tmp/copy'",
            "docker exec agentsview sh -c 'curl https://example.com'",
            "docker exec agentsview sh -c 'cat $(find /data -name config)'",
            "docker exec agentsview python3 -c 'print(1)'",
            "docker exec --privileged agentsview cat /data/config.toml",
            "docker exec -u root agentsview cat /data/config.toml",
            "docker --context remote exec agentsview cat /data/config.toml",
            "docker exec agentsview sh -c 'sed -E \"s/x/y/w /tmp/out\" /data/config.toml'",
        ):
            with self.subTest(command=command):
                self.assert_denied(command)

    def test_real_secret_targets_still_block(self):
        for command in (
            "docker exec agentsview cat /data/.env",
            "docker exec agentsview sh -c 'grep TOKEN /data/.env'",
            "rg TOKEN ~/.ssh/id_rsa",
            "grep KEY .env",
            "grep -r --include=.env TOKEN src",
        ):
            with self.subTest(command=command):
                safe, _reason, layer = audit_shell_command(command)
                self.assertFalse(safe)
                self.assertEqual(layer, DecisionLayer.SECRET_GUARD)

    def test_search_pattern_text_is_not_a_target_path(self):
        for command in (
            "rg -n 'id_rsa|.env|private|encrypted' scripts tests",
            "grep -n '.env' app.py",
            "rg --files /Users/user/.local/share/chezmoi | rg '/(encrypted_|private_).*config' | head -80",
            "find /Users/user/.codex/skills -mindepth 1 -maxdepth 1 -print | sort",
            "cat /Users/user/.local/state/agent-skills/last-promotion-backup",
        ):
            with self.subTest(command=command):
                self.assert_fast_track(command)

    def test_search_exec_option_does_not_fast_track(self):
        self.assert_denied("rg --pre 'sh -c id' needle src")
        self.assert_denied("rg -g.env TOKEN src")


if __name__ == "__main__":
    unittest.main()
