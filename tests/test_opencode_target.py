"""Unit tests for multi-agent target support (agy + opencode)."""

import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from schengen_watcher import (
    parse_agent_filter,
    agent_matches,
    strip_ansi,
    classify_opencode_dialog_stage,
    parse_opencode_permission_request,
    parse_permission_request_for_agent,
)


class TestAgentFilterParsing(unittest.TestCase):
    def test_default_agy_only(self):
        f = parse_agent_filter("agy")
        self.assertIsNotNone(f)
        self.assertIn("agy", f)
        self.assertNotIn("opencode", f)

    def test_comma_separated_list(self):
        f = parse_agent_filter("agy,opencode")
        self.assertIn("agy", f)
        self.assertIn("opencode", f)
        self.assertEqual(len(f), 2)

    def test_all_sentinel_returns_none(self):
        self.assertIsNone(parse_agent_filter("all"))
        self.assertIsNone(parse_agent_filter("ALL"))

    def test_empty_and_whitespace_tokens(self):
        f = parse_agent_filter(" agy , opencode ")
        self.assertIn("agy", f)
        self.assertIn("opencode", f)

    def test_agent_matches(self):
        f = frozenset({"agy", "opencode"})
        self.assertTrue(agent_matches("agy", f))
        self.assertTrue(agent_matches("opencode", f))
        self.assertFalse(agent_matches("hermes", f))
        # None = match all
        self.assertTrue(agent_matches("hermes", None))


class TestOpenCodeDialogParsing(unittest.TestCase):
    def test_strip_ansi(self):
        self.assertEqual(strip_ansi("\x1b[1;32mPermission required\x1b[0m"), "Permission required")

    def test_stage_permission(self):
        text = "Permission required\n\n$ git status\n\nAllow once  Allow always  Reject"
        self.assertEqual(classify_opencode_dialog_stage(text), "permission")

    def test_stage_always_confirm(self):
        text = "Always allow\nuntil OpenCode is restarted"
        self.assertEqual(classify_opencode_dialog_stage(text), "always_confirm")

    def test_stage_reject(self):
        text = "Reject permission\nTell OpenCode what to do differently"
        self.assertEqual(classify_opencode_dialog_stage(text), "reject")

    def test_stage_unknown(self):
        self.assertEqual(classify_opencode_dialog_stage("random terminal output"), "unknown")

    def test_parse_bash_command(self):
        text = "Permission required\n\n  $ git status --porcelain\n\nAllow once  Allow always  Reject"
        self.assertEqual(parse_opencode_permission_request(text), "git status --porcelain")

    def test_parse_returns_none_for_always_confirm(self):
        text = "Always allow\nuntil OpenCode is restarted\n$ git status"
        self.assertIsNone(parse_opencode_permission_request(text))

    def test_parse_edit_file(self):
        text = "Permission required\n\nEdit file /tmp/example.txt\n\nAllow once"
        self.assertEqual(parse_opencode_permission_request(text), "edit_file /tmp/example.txt")

    def test_dispatch_by_agent_kind(self):
        agy_text = "Requesting permission for:\ngit status\nDo you want to proceed?"
        self.assertEqual(parse_permission_request_for_agent(agy_text, "agy"), "git status")

        oc_text = "Permission required\n\n$ ls -la\n\nAllow once"
        self.assertEqual(parse_permission_request_for_agent(oc_text, "opencode"), "ls -la")


if __name__ == "__main__":
    unittest.main()
