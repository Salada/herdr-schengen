#!/usr/bin/env python3
"""Deterministic tests for repository-confined Inspector investigation tools."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from tools.schengen_agent_llm import (  # noqa: E402
    GUARD_TOOLS,
    build_system_prompt,
    execute_tool_call,
)


def _completed(argv, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def _match(path: Path | str, line: int, text: str) -> str:
    return json.dumps({
        "type": "match",
        "data": {
            "path": {"text": str(path)},
            "lines": {"text": text + "\n"},
            "line_number": line,
        },
    })


class TestGrepSearch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        (self.root / "src").mkdir()
        (self.root / "src" / "app.py").write_text("needle\n", encoding="utf-8")
        self.context = {"cwd": str(self.root / "src")}

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, args, *, search_stdout="", search_returncode=0, search_stderr=""):
        root = _completed([], stdout=str(self.root) + "\n")
        search = _completed([], returncode=search_returncode, stdout=search_stdout, stderr=search_stderr)
        with patch("tools.schengen_agent_llm.shutil.which", return_value="/usr/bin/rg"), \
             patch("tools.schengen_agent_llm.subprocess.run", side_effect=[root, search]) as run:
            result = json.loads(execute_tool_call("grep_search", args, context=self.context))
        return result, run.call_args_list

    def test_schema_exposes_no_repository_root(self):
        tool = next(t for t in GUARD_TOOLS if t["function"]["name"] == "grep_search")
        params = tool["function"]["parameters"]
        self.assertEqual(set(params["properties"]), {
            "query", "relative_path", "case_sensitive", "max_results",
        })
        self.assertEqual(params["required"], ["query"])

    def test_formats_matches_and_uses_server_derived_root(self):
        stdout = _match(self.root / "src" / "app.py", 7, "Needle")
        result, calls = self._run({"query": "needle", "relative_path": "src"}, search_stdout=stdout)

        self.assertEqual(result["matches"], ["src/app.py:7:Needle"])
        self.assertEqual(result["match_count"], 1)
        root_call, search_call = calls
        self.assertEqual(root_call.args[0], [
            "git", "-C", str((self.root / "src").resolve()), "rev-parse", "--show-toplevel",
        ])
        argv = search_call.args[0]
        self.assertIn("--ignore-case", argv)
        self.assertIn("--no-messages", argv)
        self.assertEqual(argv[argv.index("--") + 1:], ["needle", str(self.root / "src")])
        self.assertIs(search_call.kwargs["shell"], False)
        self.assertEqual(search_call.kwargs["timeout"], 5.0)

    def test_case_sensitive_omits_ignore_case_flag(self):
        _, calls = self._run({"query": "Needle", "case_sensitive": True})
        self.assertNotIn("--ignore-case", calls[1].args[0])

    def test_exit_one_is_normal_empty_result(self):
        result, _ = self._run({"query": "absent"}, search_returncode=1)
        self.assertEqual(result["matches"], [])
        self.assertEqual(result["match_count"], 0)
        self.assertNotIn("error", result)

    def test_invalid_regex_is_structured_error(self):
        result, _ = self._run(
            {"query": "["}, search_returncode=2,
            search_stderr="regex parse error: unclosed character class",
        )
        self.assertIn("regex parse error", result["error"])

    def test_missing_rg_and_timeout_are_structured_errors(self):
        root = _completed([], stdout=str(self.root) + "\n")
        with patch("tools.schengen_agent_llm.shutil.which", return_value=None), \
             patch("tools.schengen_agent_llm.subprocess.run", return_value=root):
            missing = json.loads(execute_tool_call("grep_search", {"query": "x"}, context=self.context))
        self.assertEqual(missing["error"], "rg unavailable")

        with patch("tools.schengen_agent_llm.shutil.which", return_value="/usr/bin/rg"), \
             patch(
                 "tools.schengen_agent_llm.subprocess.run",
                 side_effect=[root, subprocess.TimeoutExpired(["rg"], 5.0)],
             ):
            timed_out = json.loads(execute_tool_call("grep_search", {"query": "x"}, context=self.context))
        self.assertEqual(timed_out["error"], "grep_search timed out")

    def test_missing_context_and_non_git_cwd_fail_closed(self):
        missing = json.loads(execute_tool_call("grep_search", {"query": "x"}))
        self.assertIn("working directory unavailable", missing["error"])

        non_git = _completed([], returncode=128, stderr="not a git repository")
        with patch("tools.schengen_agent_llm.subprocess.run", return_value=non_git):
            result = json.loads(execute_tool_call("grep_search", {"query": "x"}, context=self.context))
        self.assertIn("not inside a Git worktree", result["error"])

    def test_rejects_absolute_tilde_parent_and_sensitive_paths_before_search(self):
        paths = [
            "/tmp", "~/code", "src/../outside", ".env", ".ssh",
            ".git/config", ".github/workflows", "credentials.json",
        ]
        for relative_path in paths:
            with self.subTest(relative_path=relative_path), \
                 patch("tools.schengen_agent_llm.subprocess.run") as run:
                result = json.loads(execute_tool_call(
                    "grep_search", {"query": "x", "relative_path": relative_path}, context=self.context,
                ))
                self.assertIn("error", result)
                run.assert_not_called()

    def test_rejects_symlink_escape_and_flag_like_path_is_argv_safe(self):
        with tempfile.TemporaryDirectory() as outside:
            (self.root / "escape").symlink_to(outside, target_is_directory=True)
            root = _completed([], stdout=str(self.root) + "\n")
            with patch("tools.schengen_agent_llm.subprocess.run", return_value=root):
                escaped = json.loads(execute_tool_call(
                    "grep_search", {"query": "x", "relative_path": "escape"}, context=self.context,
                ))
            self.assertIn("external access forbidden", escaped["error"])

        (self.root / "-flag").mkdir()
        result, calls = self._run({"query": "x", "relative_path": "-flag"}, search_returncode=1)
        self.assertNotIn("error", result)
        argv = calls[1].args[0]
        self.assertEqual(argv[argv.index("--") + 2], str(self.root / "-flag"))

    def test_filters_sensitive_match_paths_and_redacts_match_text(self):
        stdout = "\n".join([
            _match(self.root / "credentials.json", 1, "TOKEN=do-not-return"),
            _match(self.root / "src" / "app.py", 2, "DB_PASSWORD=SuperSecretPass123"),
        ])
        result, _ = self._run({"query": "secret"}, search_stdout=stdout)
        encoded = json.dumps(result)
        self.assertEqual(result["sensitive_matches_omitted"], 1)
        self.assertNotIn("do-not-return", encoded)
        self.assertNotIn("SuperSecretPass123", encoded)
        self.assertIn("DB_PASSWORD=***", encoded)

    def test_global_result_and_character_caps(self):
        many = "\n".join(
            _match(self.root / "src" / "app.py", i, "x") for i in range(1, 56)
        )
        result, _ = self._run({"query": "x", "max_results": 500}, search_stdout=many)
        self.assertEqual(len(result["matches"]), 50)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(json.dumps(result, ensure_ascii=False)), 4000)

        long_output = "\n".join(
            _match(self.root / "src" / "app.py", i, "z" * 1900) for i in range(1, 10)
        )
        bounded, _ = self._run({"query": "z"}, search_stdout=long_output)
        self.assertTrue(bounded["truncated"])
        self.assertLessEqual(len(json.dumps(bounded, ensure_ascii=False)), 4000)

    def test_malformed_or_outside_rg_output_fails_closed(self):
        malformed, _ = self._run({"query": "x"}, search_stdout="not-json")
        self.assertEqual(malformed["error"], "Malformed rg output")

        outside, _ = self._run({"query": "x"}, search_stdout=_match("/tmp/outside.py", 1, "x"))
        self.assertIn("outside the active Git worktree", outside["error"])

        sibling = Path(str(self.root) + "2") / "sibling.py"
        sibling_result, _ = self._run({"query": "x"}, search_stdout=_match(sibling, 1, "x"))
        self.assertIn("outside the active Git worktree", sibling_result["error"])

    def test_prompt_confines_search_to_named_red_flags(self):
        escalation = {
            "id": 1,
            "pane_id": "w1D:p1",
            "agent_kind": "codex",
            "raw_command": "git add src",
            "safety_reason": "requires review",
            "decision_layer": "NOT_ALLOWLISTED",
        }
        with patch(
            "tools.schengen_agent_llm.get_current_command_escalation",
            return_value=escalation,
        ):
            prompt = build_system_prompt()
        self.assertIn("specific, named, unresolved red flag", prompt)
        self.assertIn("Broad or exploratory searches are forbidden", prompt)
        self.assertIn("require EVIDENCE OF DANGER", prompt)


if __name__ == "__main__":
    unittest.main()
