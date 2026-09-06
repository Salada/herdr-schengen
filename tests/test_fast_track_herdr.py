"""Closed Herdr 0.8.2 read-only query fast-track regression tests."""

import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from core.security_evaluator import DecisionLayer, audit_shell_command


class TestHerdrQueryFastTrack(unittest.TestCase):
    def assertFastTrack(self, command):
        safe, reason, layer = audit_shell_command(command)
        self.assertTrue(safe, f"Expected fast-track for {command!r}: {reason}")
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)
        self.assertEqual(reason, "Fast-track verified safe Herdr CLI query")

    def assertNotFastTrack(self, command):
        safe, reason, layer = audit_shell_command(command)
        self.assertFalse(safe, f"Expected fail-closed for {command!r}: {reason}")
        self.assertNotEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_exact_readonly_queries_fast_track(self):
        for command in (
            "herdr --version",
            "herdr\t--help",
            "herdr -V",
            "herdr --help",
            "herdr -h",
            "herdr agent list",
            "herdr agent get reviewer",
            "herdr agent get w1D:pED",
            "herdr pane list",
            "herdr pane list --workspace w1D",
            "herdr pane get w1D:p5X",
        ):
            with self.subTest(command=command):
                self.assertFastTrack(command)

    def test_agent_wait_closed_options_fast_track(self):
        for command in (
            "herdr agent wait reviewer",
            "herdr agent wait w1D:pED --until idle",
            "herdr agent wait reviewer --until blocked --until done",
            "herdr agent wait reviewer --timeout 1",
            "herdr agent wait reviewer --timeout 1800000",
            "herdr agent wait reviewer --timeout 5000 --until working",
            "herdr agent wait reviewer --until unknown --timeout 5000 --until done",
        ):
            with self.subTest(command=command):
                self.assertFastTrack(command)

    def test_identifiers_are_closed(self):
        for command in (
            "herdr agent get ''",
            "herdr agent get AGY",
            "herdr agent get --purge",
            "herdr agent get reviewer.name",
            "herdr agent get w:p1",
            "herdr agent get w1D:p",
            "herdr agent get w1D:pED:extra",
            "herdr pane get reviewer",
            "herdr pane get w1D:pED:extra",
            "herdr pane list --workspace ''",
            "herdr pane list --workspace workspace-1",
            "herdr pane list --workspace --purge",
        ):
            with self.subTest(command=command):
                self.assertNotFastTrack(command)

    def test_wait_rejects_malformed_or_unknown_options(self):
        for command in (
            "herdr agent wait reviewer --until",
            "herdr agent wait reviewer --until=idle",
            "herdr agent wait reviewer --until IDLE",
            "herdr agent wait reviewer --until ready",
            "herdr agent wait reviewer --timeout",
            "herdr agent wait reviewer --timeout=5000",
            "herdr agent wait reviewer --timeout 0",
            "herdr agent wait reviewer --timeout 1800001",
            "herdr agent wait reviewer --timeout +1",
            "herdr agent wait reviewer --timeout 1.0",
            "herdr agent wait reviewer --timeout ١",
            "herdr agent wait reviewer --timeout 5 --timeout 6",
            "herdr agent wait reviewer --future value",
            "herdr agent wait reviewer extra",
        ):
            with self.subTest(command=command):
                self.assertNotFastTrack(command)

    def test_unknown_mutating_and_output_commands_stay_closed(self):
        for command in (
            "herdr list",
            "herdr agent list --json",
            "herdr agent read reviewer",
            "herdr agent prompt reviewer hello",
            "herdr agent send-keys reviewer enter",
            "herdr agent start reviewer",
            "herdr agent focus reviewer",
            "herdr agent rename reviewer next",
            "herdr pane read w1D:pED",
            "herdr pane wait-output w1D:pED --match done",
            "herdr pane wait w1D:pED",
            "herdr pane run w1D:pED ls",
            "herdr pane send-text w1D:pED hello",
            "herdr pane send-keys w1D:pED enter",
            "herdr pane close w1D:pED",
            "herdr pane rename w1D:pED next",
            "herdr pane focus right",
            "herdr server stop",
            "herdr server reload-config",
            "herdr update",
            "herdr workspace create",
            "herdr --version extra",
            "herdr pane list --workspace=w1D",
            "herdr pane list --workspace w1D --workspace w2",
        ):
            with self.subTest(command=command):
                self.assertNotFastTrack(command)

    def test_shell_syntax_never_expands_the_grammar(self):
        for command in (
            "herdr agent list; rm -rf /",
            "herdr agent list && echo pwn",
            "herdr agent list | grep reviewer",
            "herdr agent get $(whoami)",
            "herdr pane list > panes.txt",
            "herdr agent get 'reviewer;rm'",
            "herdr agent get 'reviewer",
        ):
            with self.subTest(command=command):
                self.assertNotFastTrack(command)


if __name__ == "__main__":
    unittest.main()
