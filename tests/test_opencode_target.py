"""Unit tests for multi-agent target support (agy + opencode)."""

import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from schengen_watcher import parse_agent_filter, agent_matches
from agent_adapters import get_adapter, target_agent_kinds
from agent_adapters.opencode import strip_ansi, decide_opencode_injection, resolve_opencode_injection


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

    def test_all_sentinel_maps_to_target_kinds(self):
        self.assertEqual(parse_agent_filter("all"), frozenset({"agy", "opencode"}))
        self.assertEqual(parse_agent_filter("ALL"), frozenset({"agy", "opencode"}))

    def test_empty_falls_back_to_agy(self):
        self.assertEqual(parse_agent_filter(""), frozenset({"agy"}))
        self.assertEqual(parse_agent_filter("   "), frozenset({"agy"}))

    def test_empty_and_whitespace_tokens(self):
        f = parse_agent_filter(" agy , opencode ")
        self.assertIn("agy", f)
        self.assertIn("opencode", f)

    def test_agent_matches(self):
        f = frozenset({"agy", "opencode"})
        self.assertTrue(agent_matches("agy", f))
        self.assertTrue(agent_matches("opencode", f))
        self.assertFalse(agent_matches("hermes", f))
        # None matches nothing (safe default, never match-all)
        self.assertFalse(agent_matches("hermes", None))
        # A bare string is treated as a single kind (no substring degradation)
        self.assertTrue(agent_matches("agy", "agy"))
        self.assertFalse(agent_matches("agyx", "agy"))


class TestAdapterRegistry(unittest.TestCase):
    def test_target_kinds_registered(self):
        kinds = set(target_agent_kinds())
        self.assertEqual(kinds, {"agy", "opencode"})

    def test_get_adapter(self):
        self.assertIsNotNone(get_adapter("agy"))
        self.assertIsNotNone(get_adapter("opencode"))
        self.assertIsNone(get_adapter("hermes"))


class TestOpenCodeDialogParsing(unittest.TestCase):
    def setUp(self):
        self.adapter = get_adapter("opencode")

    def test_strip_ansi(self):
        self.assertEqual(strip_ansi("\x1b[1;32mPermission required\x1b[0m"), "Permission required")

    def test_stage_permission(self):
        text = "Permission required\n\n$ git status\n\nAllow once  Allow always  Reject"
        self.assertEqual(self.adapter.classify_dialog_stage(text), "permission")

    def test_stage_always_confirm(self):
        text = "Always allow\nuntil OpenCode is restarted"
        self.assertEqual(self.adapter.classify_dialog_stage(text), "always_confirm")

    def test_stage_reject(self):
        text = "Reject permission\nTell OpenCode what to do differently"
        self.assertEqual(self.adapter.classify_dialog_stage(text), "reject")

    def test_stage_unknown(self):
        self.assertEqual(self.adapter.classify_dialog_stage("random terminal output"), "unknown")

    def test_parse_bash_command(self):
        text = "Permission required\n\n  $ git status --porcelain\n\nAllow once  Allow always  Reject"
        self.assertEqual(self.adapter.parse_permission_request(text), "git status --porcelain")

    def test_parse_returns_none_for_always_confirm(self):
        text = "Always allow\nuntil OpenCode is restarted\n$ git status"
        self.assertIsNone(self.adapter.parse_permission_request(text))

    def test_parse_edit_file(self):
        text = "Permission required\n\nEdit file /tmp/example.txt\n\nAllow once"
        self.assertEqual(self.adapter.parse_permission_request(text), "edit_file /tmp/example.txt")

    def test_parse_edit_file_home_tilde(self):
        text = "Permission required\n\nEdit ~/src/foo.py\n\nAllow once"
        self.assertEqual(self.adapter.parse_permission_request(text), "edit_file ~/src/foo.py")

    def test_parse_bash_ignores_sidebar_cost_even_if_first(self):
        # Regression: the TUI sidebar renders "$0.93 spent" (cost metadata, no whitespace
        # after '$'). Even if it appears before the dialog command, it must be skipped.
        text = (
            "Permission required\n"
            "$0.93 spent\n"
            "$ echo schengen-live-probe\n"
            "Allow once  Allow always  Reject\n"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "echo schengen-live-probe")

    def test_parse_bash_anchored_to_dialog_ignores_past_command(self):
        # Regression: the chat timeline renders past commands ("$ git status") ABOVE the
        # dialog. Extraction must anchor to the dialog, never match the first "$ " viewport-wide.
        text = (
            "$ git status\n"
            "$ ls -la\n"
            "Permission required\n"
            "  # Shell command\n"
            "$ rm -rf /some/dir\n"
            "Allow once  Allow always  Reject\n"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "rm -rf /some/dir")

    def test_parse_returns_none_when_only_cost_metadata(self):
        text = "Permission required\n$0.93 spent\n422,651 tokens\nAllow once"
        self.assertIsNone(self.adapter.parse_permission_request(text))

    def test_parse_external_directory(self):
        text = (
            "Permission required\n"
            "  Access external directory /tmp\n"
            "Patterns\n"
            "- /tmp/*\n"
            "Allow once  Allow always  Reject\n"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "access_directory /tmp")

    def test_parse_external_directory_strips_literal_newline_body(self):
        # The TUI renders the multi-line "Patterns" body with literal "\n" (backslash-n).
        # The extraction must stop at the backslash so only the directory is captured.
        text = (
            "Permission required\n"
            "  Access external directory /tmp\\nPatterns\\n- /tmp/*\n"
            "Allow once  Allow always  Reject\n"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "access_directory /tmp")


class TestOpenCodeInjectionDecision(unittest.TestCase):
    def test_decide_always_abort(self):
        self.assertEqual(decide_opencode_injection("always_confirm"), "always_abort")

    def test_decide_not_registered(self):
        self.assertEqual(decide_opencode_injection("permission"), "not_registered")

    def test_decide_dialogue_gone(self):
        self.assertEqual(decide_opencode_injection("unknown"), "dialogue_gone")

    def test_resolve_success_when_dialog_clears(self):
        verdict, _ = resolve_opencode_injection(["unknown", "unknown"])
        self.assertEqual(verdict, "success")

    def test_resolve_always_abort_even_if_later_unknown(self):
        verdict, _ = resolve_opencode_injection(["unknown", "always_confirm", "unknown"])
        self.assertEqual(verdict, "always_abort")

    def test_resolve_reject_abort(self):
        verdict, _ = resolve_opencode_injection(["reject", "reject"])
        self.assertEqual(verdict, "reject_abort")

    def test_resolve_reject_abort_even_if_later_unknown(self):
        verdict, _ = resolve_opencode_injection(["unknown", "reject", "unknown"])
        self.assertEqual(verdict, "reject_abort")

    def test_resolve_not_registered_when_still_permission(self):
        verdict, _ = resolve_opencode_injection(["permission", "permission"])
        self.assertEqual(verdict, "not_registered")

    def test_resolve_not_registered_when_empty(self):
        verdict, _ = resolve_opencode_injection([])
        self.assertEqual(verdict, "not_registered")


class TestAgentDispatch(unittest.TestCase):
    def test_agy_adapter_parses_agy_dialog(self):
        agy_text = "Requesting permission for:\ngit status\nDo you want to proceed?"
        self.assertEqual(get_adapter("agy").parse_permission_request(agy_text), "git status")

    def test_opencode_adapter_parses_opencode_dialog(self):
        oc_text = "Permission required\n\n$ ls -la\n\nAllow once"
        self.assertEqual(get_adapter("opencode").parse_permission_request(oc_text), "ls -la")


if __name__ == "__main__":
    unittest.main()
