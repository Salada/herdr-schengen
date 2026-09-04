"""Unit tests for multi-agent target support (agy + opencode)."""

import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from adapters.agent_adapters import INJECT_SKIP_CHANGED, get_adapter, target_agent_kinds
from adapters.agent_adapters.opencode import (
    _norm_req_cmd,
    channel_event_to_req_cmd,
    decide_opencode_injection,
    read_channel_event,
    resolve_opencode_injection,
    strip_ansi,
    strip_leaked_text,
    strip_tui,
)
from cmd.schengen_watcher import agent_matches


class TestAgentMatches(unittest.TestCase):
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
        self.assertEqual(kinds, {"agy", "codex", "opencode"})

    def test_get_adapter(self):
        self.assertIsNotNone(get_adapter("agy"))
        self.assertIsNotNone(get_adapter("codex"))
        self.assertIsNotNone(get_adapter("opencode"))
        self.assertIsNone(get_adapter("hermes"))


class TestCodexAdapter(unittest.TestCase):
    """Test the Codex CLI adapter (ratatui approval modal parsing + key injection)."""

    def setUp(self):
        self.adapter = get_adapter("codex")

    def test_parse_exec_command(self):
        text = (
            "  Would you like to run the following command?\n\n"
            "  Environment: local\n\n"
            "  $ ls -la /tmp\n\n"
            "› 1. Yes, proceed (y)\n"
            "  2. Yes, and don't ask again for commands that start with `ls -la /tmp` (p)\n"
            "  3. No, and tell Codex what to do differently (esc)\n\n"
            "  Press enter to confirm or esc to cancel"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "ls -la /tmp")

    def test_parse_exec_command_wrapped(self):
        text = (
            "  Would you like to run the following command?\n"
            "  $ echo a && echo b &&\n"
            "  echo c\n\n"
            "› 1. Yes, proceed (y)\n"
            "  Press enter to confirm or esc to cancel"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "echo a && echo b &&\necho c")

    def test_parse_network_access(self):
        text = (
            'Do you want to approve network access to "api.example.com"?\n\n'
            "› 1. Yes, just this once (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "network_access api.example.com")

    def test_parse_file_edit(self):
        text = (
            "Would you like to make the following edits?\n\n"
            "› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "edit_file")

    def test_parse_file_edit_preserves_single_patch_target(self):
        text = (
            "Would you like to make the following edits?\n\n"
            "*** Add File: TODO_codex.md\n+draft\n"
            "*** End Patch\n\n› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "edit_file TODO_codex.md")

    def test_parse_file_edit_with_delete_stays_fail_closed(self):
        text = (
            "Would you like to make the following edits?\n\n"
            "*** Delete File: TODO_codex.md\n"
            "*** End Patch\n\n› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "edit_file")

    def test_parse_file_edit_destination_line_preserves_target(self):
        # Issue #52: current Codex CLI emits `Destination: <path>` (no legacy
        # `*** Add/Update/Delete File:` header) — the path must be preserved so
        # the evaluator's secret/sandbox/gray-zone checks apply.
        text = (
            "Would you like to make the following edits?\n\n"
            "Description: Apply proposed file edits\n"
            "Destination: /repo/scripts/core/session_memory.py\n\n"
            "› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(
            self.adapter.parse_permission_request(text), "edit_file /repo/scripts/core/session_memory.py"
        )

    def test_parse_file_edit_file_line_preserves_target(self):
        # `File: <path>` label form (same current-CLI family as Destination:).
        text = (
            "Would you like to make the following edits?\n\n"
            "File: /repo/scripts/core/session_memory.py\n\n"
            "› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(
            self.adapter.parse_permission_request(text), "edit_file /repo/scripts/core/session_memory.py"
        )

    def test_parse_file_edit_pathless_stays_fail_closed(self):
        # No Destination/File line -> pathless -> bare edit_file (fail-closed).
        text = (
            "Would you like to make the following edits?\n\n"
            "Description: Apply proposed file edits\n\n"
            "› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "edit_file")

    def test_parse_file_edit_multi_destination_returns_all_paths(self):
        # #7759: multiple Destination lines (multi-file edit) -> newline-
        # delimited paths so the evaluator validates EVERY target (INV-EF-2).
        text = (
            "Would you like to make the following edits?\n\n"
            "Destination: /repo/a.py\n"
            "Destination: /repo/b.py\n\n"
            "› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(
            self.adapter.parse_permission_request(text), "edit_file /repo/a.py\n/repo/b.py"
        )

    def test_parse_file_edit_leading_indent_destination(self):
        # #7759: leading-indent `  Destination: <path>` still parses.
        text = (
            "Would you like to make the following edits?\n\n"
            "  Destination: /repo/a.py\n\n"
            "› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "edit_file /repo/a.py")

    def test_parse_file_edit_framed_destination(self):
        # #7759: ratatui frame border `│ Destination: /path │` — the frame
        # chars must NOT be captured into the path.
        text = (
            "Would you like to make the following edits?\n\n"
            "│ Destination: /repo/a.py │\n\n"
            "› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "edit_file /repo/a.py")

    def test_parse_file_edit_lowercase_destination(self):
        # #7759: lowercase `destination:` / `file:` labels parse (IGNORECASE).
        text = (
            "Would you like to make the following edits?\n\n"
            "destination: /repo/a.py\n"
            "file: /repo/b.py\n\n"
            "› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(
            self.adapter.parse_permission_request(text), "edit_file /repo/a.py\n/repo/b.py"
        )

    def test_parse_file_edit_regression_pathless_and_spaces(self):
        # Regression: pathless -> bare edit_file (fail-closed, INV-EF-1).
        text = (
            "Would you like to make the following edits?\n\n"
            "Description: Apply proposed file edits\n\n"
            "› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "edit_file")
        # Regression: a single path containing spaces is preserved verbatim.
        text2 = (
            "Would you like to make the following edits?\n\n"
            "Destination: /repo/My Folder/x.py\n\n"
            "› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(self.adapter.parse_permission_request(text2), "edit_file /repo/My Folder/x.py")

    def test_parse_file_edit_legacy_update_still_works(self):
        # Legacy `*** Update File:` header must keep working (single Update -> path).
        text = (
            "Would you like to make the following edits?\n\n"
            "*** Update File: TODO_codex.md\n-foo\n+bar\n"
            "*** End Patch\n\n› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "edit_file TODO_codex.md")

    def test_parse_edit_dialog_live_footer_returns_target(self):
        # Issue #17: a LIVE edit dialog (footer present in the tail) still parses.
        text = (
            "Would you like to make the following edits?\n\n"
            "Destination: /repo/x.py\n\n"
            "› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel"
        )
        self.assertEqual(self.adapter.parse_permission_request(text), "edit_file /repo/x.py")

    def test_parse_edit_dialog_stale_returns_none(self):
        # Issue #17: a cleared edit dialog lingering in scrollback (the footer has
        # scrolled ABOVE the last 8 lines) must NOT be re-parsed as a pending edit.
        text = (
            "Would you like to make the following edits?\n"
            "Destination: /repo/x.py\n"
            "Press enter to confirm or esc to cancel\n"
            + "".join(f"out: new pane output line {i}\n" for i in range(12))
        )
        self.assertIsNone(self.adapter.parse_permission_request(text))

    def test_parse_exec_dialog_stale_returns_none(self):
        # Issue #17: a cleared exec dialog ("$ <cmd>" still in scrollback, footer
        # absent from the tail) must NOT be re-parsed as a pending command.
        text = (
            "Would you like to run the following command?\n\n"
            "  $ ls -la /tmp\n\n"
            "› 1. Yes, proceed (y)\n"
            "Press enter to confirm or esc to cancel\n"
            + "".join(f"out: new pane output line {i}\n" for i in range(12))
        )
        self.assertIsNone(self.adapter.parse_permission_request(text))

    def test_parse_none_when_no_dialog(self):
        self.assertIsNone(self.adapter.parse_permission_request("random terminal output"))

    def test_parse_question_dialog(self):
        text = (
            "  Question 1/1 (1 unanswered)\n"
            "  입력요청도구 테스트로 무엇을 선택할까요?\n\n"
            "  › 1. 첫 번째 선택       간단한 기본 동작을 테스트합니다.\n"
            "    2. 두 번째 선택       다른 선택지 응답을 테스트합니다.\n"
            "    3. 직접 입력          사용자 지정 응답 흐름을 테스트합니다.\n"
            "    4. None of the above  Optionally, add details in notes (tab).\n\n"
            "  tab to add notes | enter to submit answer | esc to interrupt"
        )
        self.assertEqual(
            self.adapter.parse_permission_request(text),
            "question: 입력요청도구 테스트로 무엇을 선택할까요?",
        )

    def test_parse_question_dialog_no_header_falls_back(self):
        # Footer marker present but no "Question N/M" header -> bare sentinel.
        self.assertEqual(self.adapter.parse_permission_request("enter to submit answer"), "question")

    def test_inject_approval_sends_y(self):
        with patch("adapters.agent_adapters.codex.run_cmd") as rc:
            approved, reason = self.adapter.inject_approval("w1D:p1K", "ls -la /tmp")
            self.assertTrue(approved)
            rc.assert_called_once_with(["herdr", "agent", "send-keys", "w1D:p1K", "y"])


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

    def test_parse_bash_preserves_multiline_command(self):
        # The parser preserves newlines. Herdr recent-unwrapped removes only
        # terminal soft wraps before this parser sees canonical input.
        text = (
            "Permission required\n"
            "  # Shell command\n"
            "$ git status; rm -rf\n"
            "/some/dir\n"
            "Allow once  Allow always  Reject\n"
        )
        self.assertEqual(
            self.adapter.parse_permission_request(text),
            "git status; rm -rf\n/some/dir",
        )

    def test_parse_bash_preserves_literal_backslash_n(self):
        # A literal backslash-n may be quoted executable data; do not rewrite it.
        text = "Permission required\n" "$ git status\\nrm -rf /tmp/foo\n" "Allow once  Allow always  Reject\n"
        self.assertEqual(
            self.adapter.parse_permission_request(text),
            "git status\\nrm -rf /tmp/foo",
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

    def test_resolve_single_unknown_is_not_success(self):
        # A single transient 'unknown' (mid-redraw flicker) must not be read as success.
        verdict, _ = resolve_opencode_injection(["unknown"])
        self.assertEqual(verdict, "not_registered")

    def test_resolve_permission_then_unknown_is_not_success(self):
        # Dialog still at 'permission' then a flicker to 'unknown' — not a confirmed clear.
        verdict, _ = resolve_opencode_injection(["permission", "unknown"])
        self.assertEqual(verdict, "not_registered")


class TestAgentDispatch(unittest.TestCase):
    def test_agy_adapter_parses_agy_dialog(self):
        agy_text = "Requesting permission for:\ngit status\nDo you want to proceed?"
        self.assertEqual(get_adapter("agy").parse_permission_request(agy_text), "git status")

    def test_agy_question_dialog(self):
        q_text = (
            "? 진행 방식을 선택해 주세요.\n\n"
            "Question\n"
            "──────────────────────────\n"
            "Question 1/1: 진행 방식을 선택해 주세요.\n\n"
            "> 1. 첫 번째 선택지: 빠른 처리 (Standard Mode)\n"
            "  2. 두 번째 선택지: 정밀 분석 및 검증 (Deep Mode)\n"
            "  4. Write-in...\n\n"
            "  ↑/↓ Navigate · enter Select · esc Skip"
        )
        self.assertEqual(
            get_adapter("agy").parse_permission_request(q_text),
            "question: 진행 방식을 선택해 주세요.",
        )

    def test_question_marker_in_scrollback_not_live(self):
        # A question marker lingering in OLD scrollback (not in the live bottom
        # region) must NOT be detected as a live question dialog — this is the
        # false-positive that made pending questions "keep queueing".
        opencode_text = "esc dismiss (mentioned in prose)\n" + "plain line\n" * 10
        self.assertIsNone(get_adapter("opencode").parse_permission_request(opencode_text))

        codex_text = "enter to submit answer (mentioned in prose)\n" + "plain line\n" * 10
        self.assertIsNone(get_adapter("codex").parse_permission_request(codex_text))

        agy_text = "Question 1/1: 어떤 선택을 할까요?\n" + "plain line\n" * 10
        self.assertIsNone(get_adapter("agy").parse_permission_request(agy_text))

    def test_opencode_adapter_parses_opencode_dialog(self):
        oc_text = "Permission required\n\n$ ls -la\n\nAllow once"
        self.assertEqual(get_adapter("opencode").parse_permission_request(oc_text), "ls -la")

    def test_strip_leaked_text_removes_tui_fragments(self):
        garbled = (
            "cd ~/x && git commit -m \"msg\" 133,841 tokens 13% used "
            "MCP • salada-nas Connected LSP LSPs will activate as files are read "
            "• pyright ~/code/herdr-schengen:main QUEUED Build · DeepSeek V4 Pro "
            "esc interrupt ctrl+p commands OpenCode 1.18.21"
        )
        cleaned = strip_leaked_text(garbled)
        self.assertIn("git commit", cleaned)
        for frag in ("133,841", "13% used", "salada-nas", "LSP", "pyright", "~/code", "QUEUED", "DeepSeek"):
            self.assertNotIn(frag, cleaned)

    def test_question_dialog_detected(self):
        adapter = get_adapter("opencode")
        q_text = (
            "┃\n"
            "┃  Which deployment target should I use?\n"
            "┃\n"
            "┃  1. Production\n"
            "┃     Recommended for stable releases\n"
            "┃  2. Staging\n"
            "┃  3. Type your own answer\n"
            "┃\n"
            "┃  ↑↓ select  enter submit  esc dismiss"
        )
        self.assertEqual(
            adapter.parse_permission_request(q_text),
            "question: Which deployment target should I use?",
        )

    def test_question_dialog_multi_select_text(self):
        adapter = get_adapter("opencode")
        q_text = (
            "┃\n"
            "┃  Which features do you want? (select all that apply)\n"
            "┃\n"
            "┃  1. [ ] Auth\n"
            "┃  2. [✓] Billing\n"
            "┃  3. Type your own answer\n"
            "┃\n"
            "┃  ↑↓ select  enter toggle  esc dismiss"
        )
        self.assertEqual(
            adapter.parse_permission_request(q_text),
            "question: Which features do you want? (select all that apply)",
        )

    def test_question_dialog_no_text_falls_back_to_sentinel(self):
        adapter = get_adapter("opencode")
        # Detection marker present but no extractable body above it -> bare sentinel.
        self.assertEqual(adapter.parse_permission_request("esc dismiss"), "question")

    def test_permission_dialog_not_question(self):
        adapter = get_adapter("opencode")
        oc_text = "Permission required\n\n$ ls -la\n\nAllow once  Allow always  Reject  ⇆ select  enter confirm"
        self.assertEqual(adapter.parse_permission_request(oc_text), "ls -la")


class TestOpenCodeInjectSkip(unittest.TestCase):
    """inject_approval must SKIP (not escalate) when the dialog trampolines to a
    different permission request mid-evaluation (e.g. access_directory -> shell)."""

    def setUp(self):
        self.adapter = get_adapter("opencode")

    def test_inject_skips_when_dialog_command_changed(self):
        # req_cmd is the stale access_directory request; the live dialog has already
        # advanced to a "Shell command" request (the classic two-dialogs-in-sequence
        # trampoline). inject_approval must NOT escalate the stale command.
        shell_dialog = "Permission required\n\n  $ git status --porcelain\n\nAllow once  Allow always  Reject"
        with patch("adapters.agent_adapters.opencode.get_pane_text", return_value=shell_dialog):
            approved, reason = self.adapter.inject_approval("w1D:p1", "access_directory /tmp")
        self.assertFalse(approved)
        self.assertEqual(reason, INJECT_SKIP_CHANGED)

    def test_inject_skips_when_dialog_moved_to_shell_command(self):
        # Same trampoline but with a wrapped command body, ensuring the skip is based
        # on command identity mismatch rather than a transient parse failure.
        shell_dialog = (
            "Permission required\n"
            "Shell command\n\n"
            "$ cp a b && cp c d\n"
            "Allow once  Allow always  Reject"
        )
        with patch("adapters.agent_adapters.opencode.get_pane_text", return_value=shell_dialog):
            approved, reason = self.adapter.inject_approval("w1D:p1", "access_directory ~/.config/herdr")
        self.assertFalse(approved)
        self.assertEqual(reason, INJECT_SKIP_CHANGED)

    def test_inject_unknown_read_does_not_claim_success(self):
        # Issue #23/#1910 FIX 2: a single 'unknown' stage read is NOT evidence the
        # dialog cleared. inject_approval must not return True without an actual
        # enter + two-consecutive-cleared-polls evidence — it retries, then fails
        # closed once the retry budget is exhausted.
        with patch("adapters.agent_adapters.opencode.get_pane_text", return_value="random terminal output"), patch.dict(
            os.environ, {"SCHENGEN_OPENCODE_MAX_INJECT": "1"}
        ):
            approved, reason = self.adapter.inject_approval("w1D:p1", "access_directory /tmp")
        self.assertFalse(approved)
        self.assertIn("dialog stage unknown", reason)

    def test_inject_success_via_two_consecutive_cleared_polls(self):
        # FIX 2: a genuinely-cleared dialog is confirmed by TWO consecutive
        # 'unknown' polls AFTER the enter (resolve_opencode_injection evidence),
        # not by a single pre-inject unknown read.
        dialog = "Permission required\n\n  $ ls -la\n\nAllow once  Allow always  Reject"
        with patch("adapters.agent_adapters.opencode.get_pane_text", return_value=dialog), patch(
            "adapters.agent_adapters.opencode.run_cmd", return_value=True
        ), patch("adapters.agent_adapters.opencode.read_channel_event", return_value=None), patch.object(
            self.adapter,
            "classify_dialog_stage",
            # TOCTOU pre-inject + get_pending_request stage gate + parse gate,
            # then two post-inject cleared polls.
            side_effect=["permission", "permission", "permission", "unknown", "unknown"],
        ), patch.dict(os.environ, {"SCHENGEN_OPENCODE_REPOLL_SECONDS": "1.0"}):
            approved, reason = self.adapter.inject_approval("w1D:p1", "ls -la")
        self.assertTrue(approved)
        self.assertIn("cleared", reason)

    def test_inject_matches_normalized_command_with_prompt_prefix(self):
        # Issue #23/#1910 FIX 3: a channel-sourced req_cmd and the pane-text
        # re-parse of the SAME dialog can differ by a leading '$ ' prompt / extra
        # whitespace; normalization must make them MATCH (no INJECT_SKIP_CHANGED).
        dialog = (
            "Permission required\n\n  $ python3 -m unittest discover -s tests\n\n"
            "Allow once  Allow always  Reject"
        )
        with patch("adapters.agent_adapters.opencode.get_pane_text", return_value=dialog), patch(
            "adapters.agent_adapters.opencode.run_cmd", return_value=True
        ), patch(
            "adapters.agent_adapters.opencode.resolve_opencode_injection", return_value=("success", "once approved")
        ), patch.object(self.adapter, "classify_dialog_stage", return_value="permission"), patch.object(
            self.adapter, "get_pending_request", return_value="$ python3 -m unittest discover -s tests"
        ), patch.dict(os.environ, {"SCHENGEN_OPENCODE_REPOLL_SECONDS": "0"}):
            approved, reason = self.adapter.inject_approval("w1D:p1", "python3 -m unittest discover -s tests")
        self.assertTrue(approved)

    def test_inject_accepts_truncated_prefix(self):
        # Issue #3143/#3219 FIX: the live pane-text re-parse can be a viewport-
        # soft-wrap TRUNCATED prefix of the approved req_cmd (cut at a word
        # boundary). same_request must treat it as the SAME request — the enter
        # is still injected, no INJECT_SKIP_CHANGED (no key-injection drop).
        full = "python3 -m unittest discover -s tests"
        truncated = "python3 -m unittest discover"
        dialog = "Permission required\n\n  $ python3 -m unittest discover -s tests\n\nAllow once  Allow always  Reject"
        with patch("adapters.agent_adapters.opencode.get_pane_text", return_value=dialog), patch(
            "adapters.agent_adapters.opencode.run_cmd", return_value=True
        ), patch(
            "adapters.agent_adapters.opencode.resolve_opencode_injection", return_value=("success", "once approved")
        ), patch.object(self.adapter, "classify_dialog_stage", return_value="permission"), patch.object(
            self.adapter, "get_pending_request", return_value=truncated
        ), patch.dict(os.environ, {"SCHENGEN_OPENCODE_REPOLL_SECONDS": "0"}):
            approved, reason = self.adapter.inject_approval("w1D:p1", full)
        self.assertTrue(approved)

    def test_inject_still_skips_superset(self):
        # Security invariant (directionality): a live re-parse that GREW beyond
        # the approved req_cmd (agent appended '&& rm -rf /') must NEVER match —
        # same_request is not symmetric and the inject must SKIP fail-closed.
        dialog = (
            "Permission required\n\n  $ git status --porcelain && rm -rf /\n\n"
            "Allow once  Allow always  Reject"
        )
        with patch("adapters.agent_adapters.opencode.get_pane_text", return_value=dialog), patch(
            "adapters.agent_adapters.opencode.run_cmd", return_value=True
        ) as rc, patch.object(
            self.adapter, "classify_dialog_stage", return_value="permission"
        ), patch.object(
            self.adapter, "get_pending_request", return_value="git status --porcelain && rm -rf /"
        ):
            approved, reason = self.adapter.inject_approval("w1D:p1", "git status")
        self.assertFalse(approved)
        self.assertEqual(reason, INJECT_SKIP_CHANGED)
        rc.assert_not_called()  # the dangerous superset must never receive an enter

    def test_inject_accepts_access_dir_parent(self):
        # Issue #3143/#3219: the approved access_directory grant referenced a
        # concrete file path; the live dialog re-parses to the PARENT directory
        # (same directory grant). Path-variance tolerance must still inject.
        dialog = (
            "Permission required\n\n  Access external directory /tmp/work/proj/src\n"
            "Patterns\n- /tmp/work/proj/src/*\n"
            "Allow once  Allow always  Reject"
        )
        with patch("adapters.agent_adapters.opencode.get_pane_text", return_value=dialog), patch(
            "adapters.agent_adapters.opencode.run_cmd", return_value=True
        ), patch(
            "adapters.agent_adapters.opencode.resolve_opencode_injection", return_value=("success", "once approved")
        ), patch.object(self.adapter, "classify_dialog_stage", return_value="permission"), patch.object(
            self.adapter, "get_pending_request", return_value="access_directory /tmp/work/proj/src"
        ), patch.dict(os.environ, {"SCHENGEN_OPENCODE_REPOLL_SECONDS": "0"}):
            approved, reason = self.adapter.inject_approval("w1D:p1", "access_directory /tmp/work/proj/src/tui.py")
        self.assertTrue(approved)


class TestNormReqCmd(unittest.TestCase):
    """_norm_req_cmd must be SURGICAL (prompt + whitespace only), not a
    security-collapsing normalization (reviewer round 2 on issue #1910)."""

    def test_different_paths_do_not_normalize_equal(self):
        # A dialog that changed to a DIFFERENT path must NOT be treated as the
        # same command: quoted payloads / absolute paths must stay distinct.
        self.assertNotEqual(
            _norm_req_cmd("edit_file /Users/alice/foo.txt"),
            _norm_req_cmd("edit_file /Users/alice/.ssh/id_rsa"),
        )
        self.assertNotEqual(
            _norm_req_cmd("cat /home/bob/a.txt"),
            _norm_req_cmd("cat /home/bob/.aws/credentials"),
        )

    def test_prompt_prefix_and_whitespace_still_match(self):
        # The intended-match behavior is preserved: leading '$ ' prompt and
        # whitespace differences of the SAME command still match.
        self.assertEqual(
            _norm_req_cmd("$ python3 -m unittest discover -s tests"),
            _norm_req_cmd("python3 -m unittest discover -s tests"),
        )
        self.assertEqual(_norm_req_cmd("  ls   -la  "), _norm_req_cmd("ls -la"))

    def test_quoted_payloads_do_not_normalize_equal(self):
        # Quoted -c/-d/-m payloads must stay distinct (no <STRING> collapsing).
        self.assertNotEqual(
            _norm_req_cmd('python3 -c "print(1)"'),
            _norm_req_cmd('python3 -c "print(2)"'),
        )


class TestStructuredPermissionChannel(unittest.TestCase):
    """Test the structured permission channel (issue #57) mapping + gating."""

    def setUp(self):
        self.adapter = get_adapter("opencode")

    # --- channel_event_to_req_cmd ---

    def test_channel_bash_uses_metadata_command(self):
        ev = {"permission": "bash", "patterns": ["git push", "rm x"], "metadata": {"command": "git push && rm x"}}
        self.assertEqual(channel_event_to_req_cmd(ev), "git push && rm x")

    def test_channel_bash_falls_back_to_joined_patterns(self):
        ev = {"permission": "bash", "patterns": ["git status"], "metadata": {}}
        self.assertEqual(channel_event_to_req_cmd(ev), "git status")

    def test_channel_external_directory_prefers_filepath(self):
        ev = {"permission": "external_directory", "patterns": ["/tmp/*"], "metadata": {"filepath": "/tmp", "parentDir": "/"}}
        self.assertEqual(channel_event_to_req_cmd(ev), "access_directory /tmp")

    def test_channel_external_directory_uses_parentdir(self):
        ev = {"permission": "external_directory", "patterns": ["/tmp/*"], "metadata": {"parentDir": "/tmp"}}
        self.assertEqual(channel_event_to_req_cmd(ev), "access_directory /tmp")

    def test_channel_external_directory_shell_directories(self):
        ev = {"permission": "external_directory", "patterns": ["/tmp/*"], "metadata": {"command": "mkdir -p /tmp/x", "directories": ["/tmp/outside"]}}
        self.assertEqual(channel_event_to_req_cmd(ev), "access_directory /tmp/outside")

    def test_channel_edit_prefers_filepath(self):
        ev = {"permission": "edit", "patterns": ["rel/path.py"], "metadata": {"filepath": "/abs/path.py"}}
        self.assertEqual(channel_event_to_req_cmd(ev), "edit_file /abs/path.py")

    def test_channel_read_uses_patterns(self):
        ev = {"permission": "read", "patterns": ["/etc/passwd"], "metadata": {}}
        self.assertEqual(channel_event_to_req_cmd(ev), "read_file /etc/passwd")

    def test_channel_webfetch(self):
        ev = {"permission": "webfetch", "patterns": ["https://example.com"], "metadata": {}}
        self.assertEqual(channel_event_to_req_cmd(ev), "webfetch https://example.com")

    def test_channel_unhandled_permission(self):
        ev = {"permission": "mcp:foo", "patterns": ["mcp:foo:bar"], "metadata": {}}
        self.assertEqual(channel_event_to_req_cmd(ev), "unhandled_dialog mcp:foo")

    def test_channel_empty_permission_returns_none(self):
        self.assertIsNone(channel_event_to_req_cmd({"permission": "", "metadata": {}, "patterns": []}))

    # --- read_channel_event ---

    def test_read_channel_event_missing_file_returns_none(self):
        with patch("adapters.agent_adapters.opencode._channel_file") as cf:
            cf.return_value = Path("/nonexistent/schengen_chan_missing.json")
            self.assertIsNone(read_channel_event("w1D:p1"))

    def test_read_channel_event_stale_returns_none(self):
        tmp = Path("/tmp/schengen_chan_test_stale.json")
        tmp.write_text(json.dumps({"permission": "bash", "ts": 0}))
        with patch("adapters.agent_adapters.opencode._channel_file", return_value=tmp):
            self.assertIsNone(read_channel_event("w1D:p1"))
        tmp.unlink(missing_ok=True)

    def test_read_channel_event_fresh_returns_event(self):
        tmp = Path("/tmp/schengen_chan_test_fresh.json")
        tmp.write_text(json.dumps({"permission": "bash", "metadata": {"command": "ls"}, "ts": time.time()}))
        with patch("adapters.agent_adapters.opencode._channel_file", return_value=tmp):
            ev = read_channel_event("w1D:p1")
            self.assertIsNotNone(ev)
            self.assertEqual(ev["permission"], "bash")
        tmp.unlink(missing_ok=True)

    def test_read_channel_event_parse_error_returns_none(self):
        tmp = Path("/tmp/schengen_chan_test_bad.json")
        tmp.write_text("{not valid json")
        with patch("adapters.agent_adapters.opencode._channel_file", return_value=tmp):
            self.assertIsNone(read_channel_event("w1D:p1"))
        tmp.unlink(missing_ok=True)

    # --- get_pending_request ---

    def test_get_pending_request_uses_channel_when_permission_stage(self):
        ev = {"permission": "bash", "patterns": ["echo clean"], "metadata": {"command": "echo clean"}}
        with patch("adapters.agent_adapters.opencode.read_channel_event", return_value=ev):
            text = "Permission required\n$ echo clean\nAllow once  Allow always  Reject"
            self.assertEqual(self.adapter.get_pending_request("w1D:p1", text), "echo clean")

    def test_get_pending_request_falls_back_when_no_channel_event(self):
        with patch("adapters.agent_adapters.opencode.read_channel_event", return_value=None):
            text = "Permission required\n$ git status --porcelain\nAllow once  Allow always  Reject"
            self.assertEqual(self.adapter.get_pending_request("w1D:p1", text), "git status --porcelain")

    def test_get_pending_request_ignores_channel_without_live_dialog(self):
        ev = {"permission": "bash", "patterns": ["stale cmd"], "metadata": {"command": "stale cmd"}}
        with patch("adapters.agent_adapters.opencode.read_channel_event", return_value=ev):
            # No "Permission required" marker -> stage unknown -> channel ignored -> fallback None
            self.assertIsNone(self.adapter.get_pending_request("w1D:p1", "random terminal output"))


class TestChannelApproval(unittest.TestCase):
    """Test channel-based approval (issue #57 full closure)."""

    def setUp(self):
        self.adapter = get_adapter("opencode")

    def test_channel_approve_writes_decision(self):
        ev = {"permission_id": "per_123", "permission": "bash", "patterns": ["echo ok"], "metadata": {"command": "echo ok"}}
        with patch("adapters.agent_adapters.opencode.read_channel_event", return_value=ev), \
             patch("adapters.agent_adapters.opencode.write_decision") as wd:
            approved, reason = self.adapter.channel_approve("w1D:p1", "echo ok")
            self.assertTrue(approved)
            self.assertIn("permission.reply", reason)
            wd.assert_called_once_with("w1D:p1", "per_123", "once")

    def test_channel_approve_skips_when_command_changed(self):
        ev = {"permission_id": "per_123", "permission": "bash", "patterns": ["rm -rf /"], "metadata": {"command": "rm -rf /"}}
        with patch("adapters.agent_adapters.opencode.read_channel_event", return_value=ev):
            approved, reason = self.adapter.channel_approve("w1D:p1", "echo ok")
            self.assertFalse(approved)
            self.assertEqual(reason, INJECT_SKIP_CHANGED)

    def test_channel_approve_matches_normalized_command(self):
        # Issue #23/#1910 FIX 3: req_cmd with a leading '$ ' prompt / extra
        # whitespace must match the channel-sourced command after normalization
        # (no spurious INJECT_SKIP_CHANGED from a stale gatekeeper-approved cmd).
        ev = {
            "permission_id": "per_789",
            "permission": "bash",
            "patterns": ["python3 -m unittest discover -s tests"],
            "metadata": {"command": "python3 -m unittest discover -s tests"},
        }
        with patch("adapters.agent_adapters.opencode.read_channel_event", return_value=ev), patch(
            "adapters.agent_adapters.opencode.write_decision"
        ) as wd:
            approved, reason = self.adapter.channel_approve("w1D:p1", "$ python3 -m unittest discover -s tests")
            self.assertTrue(approved)
            wd.assert_called_once_with("w1D:p1", "per_789", "once")

    def test_channel_approve_falls_back_without_channel(self):
        with patch("adapters.agent_adapters.opencode.read_channel_event", return_value=None):
            approved, reason = self.adapter.channel_approve("w1D:p1", "echo ok")
            self.assertFalse(approved)
            self.assertEqual(reason, "no channel permission")

    def test_base_channel_approve_not_supported(self):
        from adapters.agent_adapters.base import AgentAdapter
        approved, reason = AgentAdapter().channel_approve("w1D:p1", "echo ok")
        self.assertFalse(approved)
        self.assertEqual(reason, "not supported")

    def test_write_decision_writes_file(self):
        import tempfile
        from adapters.agent_adapters.opencode import _decision_file, write_decision
        with tempfile.TemporaryDirectory() as td:
            with patch("adapters.agent_adapters.opencode.DECISION_DIR", Path(td)):
                write_decision("w1D:p1", "per_456", "once")
                content = json.loads(_decision_file("w1D:p1").read_text())
                self.assertEqual(content["permission_id"], "per_456")
                self.assertEqual(content["response"], "once")
                self.assertEqual(content["pane_id"], "w1D:p1")


if __name__ == "__main__":
    unittest.main()
