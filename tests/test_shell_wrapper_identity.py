"""Regressions for the corroborated, removable AGY shell-wrapper fallback."""

import copy
import importlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


SCRIPTS_ROOT = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_ROOT))

from adapters import shell_wrapper_identity
from adapters.agent_adapters import get_adapter
from cmd import schengen_watcher


AGY_DIALOG = (
    "Requesting permission for:\n"
    "touch /tmp/hybrid && rm /tmp/hybrid\n"
    "Do you want to proceed?\n"
    "> 1. Yes\n"
    "  2. No\n"
)


def hybrid_pane(**changes):
    pane = {
        "pane_id": "w1D:pGX",
        "agent": "shell",
        "display_agent": "agy",
        "agent_status": "working",
        "agent_session": {
            "agent": "agy",
            "source": "herdr:antigravity_cli",
            "value": "agy-session",
        },
    }
    pane.update(changes)
    return pane


def agy_process_info(executable="/Users/example/.local/bin/agy"):
    return {
        "pane_id": "w1D:pGX",
        "shell_pid": 100,
        "foreground_processes": [
            {
                "pid": 101,
                "name": "agy",
                "argv0": executable,
                "argv": [executable],
                "cmdline": f"{executable} --resume",
            }
        ],
    }


class TestPureIdentityResolver(unittest.TestCase):
    def test_live_hybrid_requires_all_correlated_evidence(self):
        pane = hybrid_pane()
        original = copy.deepcopy(pane)
        self.assertEqual(
            shell_wrapper_identity.resolve_agent_kind(pane, True, agy_process_info()),
            "agy",
        )
        self.assertEqual(pane, original, "the workaround must not rewrite raw metadata")

    def test_only_supported_fallback_top_level_shapes_can_qualify(self):
        panes = [hybrid_pane(agent=value) for value in ("shell", "unknown", "")]
        missing = hybrid_pane()
        missing.pop("agent")
        panes.append(missing)
        for pane in panes:
            with self.subTest(top_level=pane.get("agent", "<missing>")):
                self.assertEqual(
                    shell_wrapper_identity.resolve_agent_kind(
                        pane, True, agy_process_info()
                    ),
                    "agy",
                )

    def test_stale_zsh_only_process_is_rejected(self):
        self.assertIsNone(
            shell_wrapper_identity.resolve_agent_kind(
                hybrid_pane(),
                True,
                agy_process_info("/bin/zsh"),
            )
        )

    def test_display_and_session_mismatches_are_rejected(self):
        display_mismatch = hybrid_pane(display_agent="shell")
        session_mismatch = hybrid_pane()
        session_mismatch["agent_session"]["agent"] = "codex"
        for pane in (display_mismatch, session_mismatch):
            with self.subTest(pane=pane):
                self.assertIsNone(
                    shell_wrapper_identity.resolve_agent_kind(
                        pane, True, agy_process_info()
                    )
                )

    def test_untrusted_or_missing_source_is_rejected(self):
        for source in (None, "plugin:quota", "herdr:unknown"):
            pane = hybrid_pane()
            if source is None:
                pane["agent_session"].pop("source")
            else:
                pane["agent_session"]["source"] = source
            with self.subTest(source=source):
                self.assertIsNone(
                    shell_wrapper_identity.resolve_agent_kind(
                        pane, True, agy_process_info()
                    )
                )

    def test_no_dialog_never_qualifies(self):
        self.assertIsNone(
            shell_wrapper_identity.resolve_agent_kind(
                hybrid_pane(), False, agy_process_info()
            )
        )

    def test_name_title_or_cmdline_text_is_not_executable_evidence(self):
        process_info = {
            "foreground_processes": [
                {
                    "name": "agy",
                    "argv0": "/bin/zsh",
                    "argv": ["/bin/zsh"],
                    "cmdline": "zsh -c /Users/example/.local/bin/agy",
                    "title": "agy",
                }
            ]
        }
        self.assertIsNone(
            shell_wrapper_identity.resolve_agent_kind(
                hybrid_pane(), True, process_info
            )
        )

    def test_argv_basename_without_matching_process_name_is_rejected(self):
        process_info = agy_process_info()
        process_info["foreground_processes"][0]["name"] = "zsh"
        self.assertIsNone(
            shell_wrapper_identity.resolve_agent_kind(
                hybrid_pane(), True, process_info
            )
        )

    def test_malformed_process_shapes_fail_closed(self):
        malformed = (
            None,
            [],
            {},
            {"foreground_processes": "agy"},
            {"foreground_processes": ["agy"]},
            {"foreground_processes": [{"argv0": []}]},
            {"foreground_processes": [{"argv": {"0": "agy"}}]},
            {"foreground_processes": [{"argv": [7]}]},
            {
                "foreground_processes": [
                    {"argv0": "/usr/local/bin/agy"},
                    "malformed-after-valid",
                ]
            },
        )
        for process_info in malformed:
            with self.subTest(process_info=process_info):
                self.assertIsNone(
                    shell_wrapper_identity.resolve_agent_kind(
                        hybrid_pane(), True, process_info
                    )
                )

    def test_direct_or_unrelated_top_level_is_not_a_candidate(self):
        for top_level in ("agy", "codex", "opencode", "hermes", "bash"):
            with self.subTest(top_level=top_level):
                self.assertFalse(
                    shell_wrapper_identity.is_agy_shell_wrapper_candidate(
                        hybrid_pane(agent=top_level)
                    )
                )


class TestProcessInfoReader(unittest.TestCase):
    def test_fixed_argv_and_envelope_parsing(self):
        payload = {
            "id": "cli:pane:process-info",
            "result": {
                "type": "pane_process_info",
                "process_info": agy_process_info(),
            },
        }
        with patch.object(
            shell_wrapper_identity, "run_cmd", return_value=json.dumps(payload)
        ) as run:
            self.assertEqual(
                shell_wrapper_identity.get_pane_process_info("w1D:pGX"),
                agy_process_info(),
            )
        run.assert_called_once_with(
            ["herdr", "pane", "process-info", "--pane", "w1D:pGX"]
        )

    def test_cli_failure_malformed_and_oversize_fail_closed(self):
        values = (
            None,
            "not-json",
            "[]",
            json.dumps({"result": {}}),
            "x" * (shell_wrapper_identity.PROCESS_INFO_MAX_CHARS + 1),
        )
        for value in values:
            with self.subTest(value_type=type(value).__name__), patch.object(
                shell_wrapper_identity, "run_cmd", return_value=value
            ):
                self.assertIsNone(
                    shell_wrapper_identity.get_pane_process_info("w1D:pGX")
                )

    def test_invalid_pane_id_performs_no_subprocess(self):
        with patch.object(shell_wrapper_identity, "run_cmd") as run:
            self.assertIsNone(shell_wrapper_identity.get_pane_process_info(None))
            self.assertIsNone(shell_wrapper_identity.get_pane_process_info("bad\x00id"))
        run.assert_not_called()


class TestWatcherIsolationAndRouting(unittest.TestCase):
    def test_live_hybrid_dialog_reaches_normal_agy_path_in_order(self):
        calls = []
        real_adapter = get_adapter("agy")
        adapter = Mock(wraps=real_adapter)

        def process_info(_pane_id):
            calls.append("process-info")
            return agy_process_info()

        def parse(text):
            calls.append("dialog-parse")
            return real_adapter.parse_permission_request(text)

        adapter.parse_permission_request.side_effect = parse
        with patch.object(schengen_watcher, "get_adapter", return_value=adapter), patch.object(
            shell_wrapper_identity,
            "get_pane_process_info",
            side_effect=process_info,
        ):
            kind = schengen_watcher.resolve_watcher_agent_kind(
                hybrid_pane(), frozenset({"agy", "codex", "opencode"}), AGY_DIALOG
            )
        self.assertEqual(kind, "agy")
        self.assertLess(calls.index("dialog-parse"), calls.index("process-info"))
        self.assertEqual(adapter.parse_permission_request(AGY_DIALOG), "touch /tmp/hybrid && rm /tmp/hybrid")

    def test_non_dialog_candidate_never_calls_process_info(self):
        with patch.object(shell_wrapper_identity, "get_pane_process_info") as process:
            self.assertIsNone(
                schengen_watcher.resolve_watcher_agent_kind(
                    hybrid_pane(), frozenset({"agy"}), "ordinary shell output"
                )
            )
        process.assert_not_called()

    def test_metadata_mismatch_never_calls_process_info(self):
        pane = hybrid_pane(display_agent="shell")
        with patch.object(shell_wrapper_identity, "get_pane_process_info") as process:
            self.assertIsNone(
                schengen_watcher.resolve_watcher_agent_kind(
                    pane, frozenset({"agy"}), AGY_DIALOG
                )
            )
        process.assert_not_called()

    def test_direct_agents_never_load_helper_or_process_info(self):
        filters = frozenset({"agy", "codex", "opencode"})
        with patch.object(schengen_watcher, "_load_shell_wrapper_identity") as load, patch.object(
            shell_wrapper_identity, "get_pane_process_info"
        ) as process:
            for kind in filters:
                with self.subTest(kind=kind):
                    self.assertEqual(
                        schengen_watcher.resolve_watcher_agent_kind(
                            {"pane_id": "p", "agent": kind}, filters, AGY_DIALOG
                        ),
                        kind,
                    )
        load.assert_not_called()
        process.assert_not_called()

    def test_direct_agent_excluded_by_filter_cannot_fall_back(self):
        with patch.object(schengen_watcher, "_load_shell_wrapper_identity") as load:
            self.assertIsNone(
                schengen_watcher.resolve_watcher_agent_kind(
                    hybrid_pane(agent="codex"), frozenset({"agy"}), AGY_DIALOG
                )
            )
        load.assert_not_called()

    def test_malformed_top_level_agent_skips_without_loading_helper(self):
        for malformed in ([], {}):
            with self.subTest(malformed=malformed), patch.object(
                schengen_watcher, "_load_shell_wrapper_identity"
            ) as load:
                self.assertIsNone(
                    schengen_watcher.resolve_watcher_agent_kind(
                        hybrid_pane(agent=malformed), frozenset({"agy"}), AGY_DIALOG
                    )
                )
                load.assert_not_called()

    def test_missing_helper_disables_only_hybrid_fallback(self):
        missing = ModuleNotFoundError("optional helper absent")
        missing.name = schengen_watcher._SHELL_WRAPPER_IDENTITY_MODULE
        filters = frozenset({"agy", "codex"})
        with patch.object(importlib, "import_module", side_effect=missing):
            self.assertIsNone(
                schengen_watcher.resolve_watcher_agent_kind(
                    hybrid_pane(), filters, AGY_DIALOG
                )
            )
            self.assertEqual(
                schengen_watcher.resolve_watcher_agent_kind(
                    {"pane_id": "direct", "agent": "agy"}, filters, AGY_DIALOG
                ),
                "agy",
            )

    def test_missing_helper_keeps_direct_discovery_operational(self):
        missing = ModuleNotFoundError("optional helper absent")
        missing.name = schengen_watcher._SHELL_WRAPPER_IDENTITY_MODULE
        panes = [
            {"pane_id": "direct", "agent": "agy", "agent_status": "blocked"},
            hybrid_pane(agent_status="blocked"),
        ]
        with patch.object(importlib, "import_module", side_effect=missing), patch.object(
            schengen_watcher, "get_all_panes", return_value=panes
        ), patch.object(schengen_watcher, "get_pane_text", return_value=AGY_DIALOG):
            self.assertEqual(
                schengen_watcher.find_blocked_panes(
                    agent_filter=frozenset({"agy", "codex", "opencode"})
                ),
                ["direct"],
            )

    def test_nested_import_failure_is_not_hidden_as_optional_absence(self):
        nested = ModuleNotFoundError("nested dependency missing")
        nested.name = "nested_dependency"
        with patch.object(importlib, "import_module", side_effect=nested):
            with self.assertRaises(ModuleNotFoundError):
                schengen_watcher.resolve_watcher_agent_kind(
                    hybrid_pane(), frozenset({"agy"}), AGY_DIALOG
                )

    def test_process_info_exception_skips_without_escalation(self):
        with patch.object(
            shell_wrapper_identity,
            "get_pane_process_info",
            side_effect=RuntimeError("lookup failed"),
        ):
            self.assertIsNone(
                schengen_watcher.resolve_watcher_agent_kind(
                    hybrid_pane(), frozenset({"agy"}), AGY_DIALOG
                )
            )

    def test_find_blocked_panes_captures_live_hybrid_dialog(self):
        pane = hybrid_pane(agent_status="working")
        with patch.object(schengen_watcher, "get_all_panes", return_value=[pane]), patch.object(
            schengen_watcher, "get_pane_text", return_value=AGY_DIALOG
        ), patch.object(
            shell_wrapper_identity,
            "get_pane_process_info",
            return_value=agy_process_info(),
        ):
            self.assertEqual(
                schengen_watcher.find_blocked_panes(
                    agent_filter=frozenset({"agy", "codex", "opencode"})
                ),
                ["w1D:pGX"],
            )

    def test_ordinary_shell_does_not_reach_process_info(self):
        pane = {"pane_id": "shell", "agent": "shell", "agent_status": "working"}
        with patch.object(schengen_watcher, "get_all_panes", return_value=[pane]), patch.object(
            schengen_watcher, "get_pane_text", return_value=AGY_DIALOG
        ), patch.object(shell_wrapper_identity, "get_pane_process_info") as process:
            self.assertEqual(
                schengen_watcher.find_blocked_panes(
                    agent_filter=frozenset({"agy"})
                ),
                [],
            )
        process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
