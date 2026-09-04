"""Executable payload whitespace is data unless Herdr marks it as a soft wrap."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from adapters.agent_adapters.agy import AgyAdapter
from adapters.agent_adapters.codex import CodexAdapter
from adapters.agent_adapters.opencode import OpenCodeAdapter


def codex_dialog(command):
    rendered = command.replace("\n", "\n  ")
    return (
        "  Would you like to run the following command?\n"
        f"  $ {rendered}\n"
        "› 1. Yes, proceed (y)\n"
        "  Press enter to confirm or esc to cancel"
    )


def opencode_dialog(command):
    rendered = command.replace("\n", "\n  ")
    return (
        "Permission required\n"
        "  # Shell command\n"
        f"  $ {rendered}\n"
        "Allow once  Allow always  Reject"
    )


def agy_dialog(command):
    rendered = command.replace("\n", "\n  ")
    return f"Requesting permission for:\n  {rendered}\nDo you want to proceed?"


class TestCanonicalSoftWrap(unittest.TestCase):
    def _assert_unwrapped(self, adapter, visible, unwrapped, expected):
        patches = [
            patch("adapters.agent_adapters.base.get_pane_text", return_value=unwrapped),
            patch("adapters.agent_adapters.opencode.read_channel_event", return_value=None),
        ]
        with patches[0], patches[1]:
            request, source = adapter.get_canonical_request("w1D:p1", visible)
        self.assertEqual(request, expected)
        self.assertEqual(source, "recent-unwrapped")

    def test_codex_soft_wrap_rejoins(self):
        self._assert_unwrapped(
            CodexAdapter(),
            codex_dialog("echo alpha &&\necho omega"),
            codex_dialog("echo alpha && echo omega"),
            "echo alpha && echo omega",
        )

    def test_opencode_soft_wrap_rejoins(self):
        self._assert_unwrapped(
            OpenCodeAdapter(),
            opencode_dialog("echo alpha &&\necho omega"),
            opencode_dialog("echo alpha && echo omega"),
            "echo alpha && echo omega",
        )

    def test_agy_soft_wrap_rejoins(self):
        self._assert_unwrapped(
            AgyAdapter(),
            agy_dialog("echo alpha &&\necho omega"),
            agy_dialog("echo alpha && echo omega"),
            "echo alpha && echo omega",
        )


class TestSemanticWhitespace(unittest.TestCase):
    def test_explicit_newline_is_preserved_by_all_adapters(self):
        command = "printf first\nprintf second"
        for adapter, dialog in (
            (CodexAdapter(), codex_dialog),
            (OpenCodeAdapter(), opencode_dialog),
            (AgyAdapter(), agy_dialog),
        ):
            with self.subTest(adapter=adapter.kind), patch(
                "adapters.agent_adapters.opencode.read_channel_event", return_value=None
            ):
                self.assertEqual(adapter.parse_permission_request(dialog(command)), command)

    def test_python_heredoc_indentation_is_preserved_by_all_adapters(self):
        command = "python3 - <<'PY'\nif True:\n    print('ok')\nPY"
        for adapter, dialog in (
            (CodexAdapter(), codex_dialog),
            (OpenCodeAdapter(), opencode_dialog),
            (AgyAdapter(), agy_dialog),
        ):
            with self.subTest(adapter=adapter.kind), patch(
                "adapters.agent_adapters.opencode.read_channel_event", return_value=None
            ):
                self.assertEqual(adapter.parse_permission_request(dialog(command)), command)


if __name__ == "__main__":
    unittest.main()
