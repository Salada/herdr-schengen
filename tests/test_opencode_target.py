"""Unit tests for multi-agent target support (agy + opencode)."""

import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from agent_adapters import get_adapter, target_agent_kinds
from agent_adapters.opencode import decide_opencode_injection, resolve_opencode_injection, strip_ansi, strip_tui
from schengen_watcher import agent_matches, parse_agent_filter


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

    def test_strip_tui_box_drawing(self):
        self.assertEqual(strip_tui("┃ Permission required ┃"), " Permission required ")
        self.assertEqual(strip_tui("│ $ git status │"), " $ git status ")

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

    def test_stage_anchored_to_latest_dialog_ignores_history_marker(self):
        # Regression: a stale "Always allow" string in the transcript history (e.g. a
        # code diff printing the marker) must not misclassify the live permission dialog.
        text = (
            'ALWAYS_CONFIRM_MARKERS = ("Always allow", "until OpenCode is restarted")\n'
            "some diff line\n"
            "Permission required\n"
            "$ git status\n"
            "Allow once  Allow always  Reject\n"
        )
        self.assertEqual(self.adapter.classify_dialog_stage(text), "permission")

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
            "Permission required\n" "$0.93 spent\n" "$ echo schengen-live-probe\n" "Allow once  Allow always  Reject\n"
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

    def test_parse_bash_joins_wrapped_multiline_command(self):
        # Regression: a long command soft-wrapped by the TUI renders with real newlines.
        # A first-line-only capture would drop the "rm -rf /" suffix -> fail-open.
        text = (
            "Permission required\n"
            "  # Shell command\n"
            "$ git status; rm -rf\n"
            "/some/dir\n"
            "Allow once  Allow always  Reject\n"
        )
        self.assertEqual(
            self.adapter.parse_permission_request(text),
            "git status; rm -rf /some/dir",
        )

    def test_parse_bash_normalizes_literal_newline_command(self):
        # Multi-line command bodies render with literal backslash-n (see the
        # external-directory "Patterns" case). Normalize to a separator space so
        # word-boundary evaluator patterns still match the trailing dangerous token.
        text = "Permission required\n" "$ git status\\nrm -rf /tmp/foo\n" "Allow once  Allow always  Reject\n"
        self.assertEqual(
            self.adapter.parse_permission_request(text),
            "git status rm -rf /tmp/foo",
        )

    def test_parse_anchors_to_latest_dialog_not_history(self):
        # Regression: the transcript history above may contain the literal
        # "Permission required"/"Allow once" strings. Extraction must anchor to the
        # LATEST (bottom) dialog via rfind, not the first (top) history occurrence.
        text = (
            "Permission required\n"  # stale string in transcript history
            "past discussion about Allow once\n"
            "more history\n"
            "Permission required\n"  # actual dialog header (bottom)
            "  # Shell command\n"
            "$ rm -rf /some/dir\n"
            "Allow once  Allow always  Reject\n"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "rm -rf /some/dir")

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

    def test_parse_external_directory_with_space_in_path(self):
        # Regression: a directory path containing spaces must be captured in full; a
        # whitespace-bounded capture would truncate "/Volumes/My Drive/.ssh" to
        # "/Volumes/My" and drop the sensitive ".ssh" tail (fail-open).
        text = (
            "Permission required\n"
            "  Access external directory /Volumes/My Drive/.ssh\n"
            "Patterns\n"
            "- /Volumes/My Drive/.ssh/*\n"
            "Allow once  Allow always  Reject\n"
        )
        self.assertEqual(
            self.adapter.parse_permission_request(text),
            "access_directory /Volumes/My Drive/.ssh",
        )

    def test_parse_edit_file_with_space_in_path(self):
        # Regression: same space-in-path concern for edit/write paths.
        text = (
            "Permission required\n"
            "Edit file /Volumes/My Drive/project notes.md\n"
            "Allow once  Allow always  Reject\n"
        )
        self.assertEqual(
            self.adapter.parse_permission_request(text),
            "edit_file /Volumes/My Drive/project notes.md",
        )

    def test_parse_external_directory_wrapped_path(self):
        # Regression: a long directory path soft-wrapped by the TUI renders with real
        # newlines. A first-line-only capture would drop the ".ssh" tail (fail-open).
        text = (
            "Permission required\n"
            "  Access external directory /very/long/path/that/wraps\n"
            "/onto/second/.ssh\n"
            "Patterns\n"
            "- /very/long/path/that/wraps/onto/second/.ssh/*\n"
            "Allow once  Allow always  Reject\n"
        )
        self.assertEqual(
            self.adapter.parse_permission_request(text),
            "access_directory /very/long/path/that/wraps /onto/second/.ssh",
        )

    def test_parse_external_directory_patterns_substring_not_truncated(self):
        # Regression: the "Patterns" boundary must anchor to LINE START, so a path that
        # itself contains the substring "Patterns" is not truncated mid-path (which would
        # drop the ".ssh" tail and fail-open).
        text = (
            "Permission required\n"
            "  Access external directory /home/Patterns-dir/.ssh\n"
            "Patterns\n"
            "- /home/Patterns-dir/.ssh/*\n"
            "Allow once  Allow always  Reject\n"
        )
        self.assertEqual(
            self.adapter.parse_permission_request(text),
            "access_directory /home/Patterns-dir/.ssh",
        )

    def test_parse_edit_file_does_not_swallow_diff_body(self):
        # Regression: the edit dialog renders an EditBody diff after the title; the parser
        # must capture only the title path, not the diff lines below it.
        text = (
            "Permission required\n"
            "Edit file /tmp/example.txt\n"
            "@@ -1,2 +1,2 @@\n"
            "-rm -rf /some/dir\n"
            "+echo safe\n"
            "Allow once  Allow always  Reject\n"
        )
        self.assertEqual(
            self.adapter.parse_permission_request(text),
            "edit_file /tmp/example.txt",
        )

    def test_parse_bash_strips_tui_border_glyphs(self):
        # Regression: the TUI panel border wraps each visual line with box-drawing glyphs
        # (e.g. '┃' U+2503). A multi-line capture must not leak them into the command,
        # which would make the AST evaluator fail with "invalid character".
        text = (
            "Permission required\n"
            "┃ $ python3 -c 'import sys\n"
            "┃   print(1)' ┃\n"
            "Allow once  Allow always  Reject\n"
        )
        cmd = self.adapter.parse_permission_request(text)
        self.assertNotIn("\u2503", cmd)
        self.assertIn("python3 -c", cmd)

    def test_parse_read_file(self):
        text = "Permission required\n\nRead /tmp/notes.txt\n\nAllow once"
        self.assertEqual(self.adapter.parse_permission_request(text), "read_file /tmp/notes.txt")

    def test_parse_read_file_sensitive(self):
        text = "Permission required\n\nRead file /app/.env\n\nAllow once"
        self.assertEqual(self.adapter.parse_permission_request(text), "read_file /app/.env")

    def test_parse_doom_loop(self):
        text = "Permission required\n\nDoom loop detected\n\nAllow once  Allow always  Reject"
        self.assertEqual(self.adapter.parse_permission_request(text), "doom_loop")

    def test_parse_fallback_unhandled_dialog(self):
        # Glob/grep/list/task/websearch and any unknown permission type must escalate
        # with the title rather than return None (silent skip).
        text = "Permission required\n\nGlob /tmp/**\n\nAllow once  Allow always  Reject"
        self.assertEqual(self.adapter.parse_permission_request(text), "unhandled_dialog Glob /tmp/**")


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
