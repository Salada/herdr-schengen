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
    format_tool_call_beautified,
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


class TestViewFileSlice(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        (self.root / "src").mkdir()
        self.target = self.root / "src" / "app.py"
        self.target.write_text("one\ntwo\nthree\n", encoding="utf-8")
        self.context = {"cwd": str(self.root / "src")}

    def tearDown(self):
        self.tmp.cleanup()

    def _view(self, args):
        root = _completed([], stdout=str(self.root) + "\n")
        with patch("tools.schengen_agent_llm.subprocess.run", return_value=root):
            return json.loads(execute_tool_call("view_file_slice", args, context=self.context))

    def test_schema_exposes_only_repository_relative_range(self):
        tool = next(t for t in GUARD_TOOLS if t["function"]["name"] == "view_file_slice")
        params = tool["function"]["parameters"]
        self.assertEqual(set(params["properties"]), {"relative_path", "start_line", "end_line"})
        self.assertEqual(params["required"], ["relative_path"])

    def test_reads_one_based_inclusive_range_and_defaults(self):
        result = self._view({"relative_path": "src/app.py", "start_line": 2, "end_line": 3})
        self.assertEqual(result["content"], ["   2 | two", "   3 | three"])
        self.assertFalse(result["truncated"])

        defaulted = self._view({"relative_path": "src/app.py"})
        self.assertEqual(defaulted["content"], ["   1 | one", "   2 | two", "   3 | three"])

    def test_strict_integer_and_range_validation(self):
        invalid = [
            {"start_line": True},
            {"start_line": 1.0},
            {"start_line": "1"},
            {"start_line": 0},
            {"end_line": 1_000_001},
            {"start_line": 3, "end_line": 2},
            {"start_line": 1, "end_line": 101},
        ]
        for extra in invalid:
            with self.subTest(extra=extra):
                result = self._view({"relative_path": "src/app.py", **extra})
                self.assertIn("error", result)

    def test_exact_hundred_lines_eof_and_beyond_eof(self):
        self.target.write_text("".join(f"line-{i}\n" for i in range(1, 101)), encoding="utf-8")
        exact = self._view({"relative_path": "src/app.py", "start_line": 1, "end_line": 100})
        self.assertEqual(len(exact["content"]), 100)
        self.assertFalse(exact["truncated"])

        eof = self._view({"relative_path": "src/app.py", "start_line": 99, "end_line": 100})
        self.assertEqual(eof["content"], ["  99 | line-99", " 100 | line-100"])

        beyond = self._view({"relative_path": "src/app.py", "start_line": 101, "end_line": 101})
        self.assertEqual(beyond["content"], [])
        self.assertFalse(beyond["truncated"])

    def test_reuses_repository_boundary_rejections(self):
        for relative_path in ["/tmp/x", "~/x", "src/../x", ".env", ".git/config", "credentials.json"]:
            with self.subTest(relative_path=relative_path), \
                 patch("tools.schengen_agent_llm.subprocess.run") as run:
                result = json.loads(execute_tool_call(
                    "view_file_slice", {"relative_path": relative_path}, context=self.context,
                ))
                self.assertIn("error", result)
                run.assert_not_called()

        with tempfile.TemporaryDirectory() as outside:
            external = Path(outside) / "outside.txt"
            external.write_text("secret\n", encoding="utf-8")
            (self.root / "escape").symlink_to(external)
            escaped = self._view({"relative_path": "escape"})
            self.assertIn("external access forbidden", escaped["error"])

    def test_binary_invalid_utf8_and_directory_are_rejected(self):
        self.target.write_bytes(b"text\x00binary")
        self.assertIn("Binary file", self._view({"relative_path": "src/app.py"})["error"])

        self.target.write_bytes(b"\xff\xfe")
        self.assertIn("non-UTF-8", self._view({"relative_path": "src/app.py"})["error"])

        directory = self._view({"relative_path": "src"})
        self.assertIn("not a regular file", directory["error"])

    def test_final_component_swap_fails_closed(self):
        with patch("tools.schengen_agent_llm.os.open", side_effect=OSError("Too many levels of symbolic links")):
            result = self._view({"relative_path": "src/app.py"})
        self.assertIn("Unable to open repository file safely", result["error"])

    def test_large_line_redaction_and_output_cap_are_explicit(self):
        self.target.write_text("DB_PASSWORD=SuperSecretPass123" + "x" * 10000 + "\n", encoding="utf-8")
        result = self._view({"relative_path": "src/app.py", "start_line": 1, "end_line": 1})
        encoded = json.dumps(result, ensure_ascii=False)
        self.assertTrue(result["truncated"])
        self.assertIn("[TRUNCATED]", encoded)
        self.assertNotIn("SuperSecretPass123", encoded)
        self.assertLessEqual(len(encoded), 4000)

    def test_prompt_confines_slice_to_search_hits(self):
        escalation = {
            "id": 1,
            "pane_id": "w1D:p1",
            "agent_kind": "codex",
            "raw_command": "git add src",
            "safety_reason": "requires review",
            "decision_layer": "NOT_ALLOWLISTED",
        }
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=escalation):
            prompt = build_system_prompt()
        self.assertIn("specific file and line range returned by `grep_search`", prompt)
        self.assertIn("not a general file browser", prompt)


class TestFindByName(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        (self.root / "src" / "nested").mkdir(parents=True)
        (self.root / "build").mkdir()
        (self.root / "src" / "target.bin").write_text("one", encoding="utf-8")
        (self.root / "src" / "nested" / "target.bin").write_text("two", encoding="utf-8")
        (self.root / "build" / "target.bin").write_text("ignored-by-git", encoding="utf-8")
        self.context = {"cwd": str(self.root / "src")}

    def tearDown(self):
        self.tmp.cleanup()

    def _find(self, args):
        root = _completed([], stdout=str(self.root) + "\n")
        with patch("tools.schengen_agent_llm.subprocess.run", return_value=root):
            return json.loads(execute_tool_call("find_by_name", args, context=self.context))

    def test_schema_is_exact_name_only_and_has_no_enumeration_knobs(self):
        tool = next(t for t in GUARD_TOOLS if t["function"]["name"] == "find_by_name")
        params = tool["function"]["parameters"]
        self.assertEqual(set(params["properties"]), {"name", "relative_path", "entry_type"})
        self.assertEqual(params["required"], ["name"])
        self.assertFalse(params["additionalProperties"])
        self.assertEqual(params["properties"]["entry_type"]["enum"], ["any", "file", "directory"])
        serialized = json.dumps(params)
        for forbidden in ("glob", "regex", "max_results", "max_depth", "repository_root", "command"):
            self.assertNotIn(f'"{forbidden}"', serialized)
        self.assertIn("unsupported argument", self._find({"name": "target.bin", "max_depth": 2})["error"])

    def test_exact_case_sensitive_matches_are_sorted_and_include_ignored_directories(self):
        result = self._find({"name": "target.bin"})
        self.assertEqual(result["matches"], [
            {"path": "build/target.bin", "entry_type": "file"},
            {"path": "src/nested/target.bin", "entry_type": "file"},
            {"path": "src/target.bin", "entry_type": "file"},
        ])
        self.assertEqual(result["completion_state"], "complete")

        self.assertEqual(self._find({"name": "*.bin"})["matches"], [])
        self.assertEqual(self._find({"name": "TARGET.BIN"})["matches"], [])

    def test_start_path_and_closed_entry_type_are_enforced(self):
        result = self._find({"name": "nested", "relative_path": "src", "entry_type": "directory"})
        self.assertEqual(result["matches"], [{"path": "src/nested", "entry_type": "directory"}])
        self.assertEqual(self._find({"name": "nested", "entry_type": "file"})["matches"], [])

        invalid_type = self._find({"name": "target.bin", "entry_type": "symlink"})
        self.assertIn("entry_type", invalid_type["error"])
        file_start = self._find({"name": "target.bin", "relative_path": "src/target.bin"})
        self.assertIn("without following symlinks", file_start["error"])

    def test_rejects_invalid_hidden_sensitive_and_external_inputs(self):
        invalid_names = ["", ".", "..", "a/b", ".hidden", "credentials.json", "x" * 256]
        for name in invalid_names:
            with self.subTest(name=name):
                result = self._find({"name": name})
                self.assertIn("error", result)

        for relative_path in ["/tmp", "~/code", "src/../outside", ".git", "credentials.json"]:
            with self.subTest(relative_path=relative_path), patch(
                "tools.schengen_agent_llm.subprocess.run"
            ) as run:
                result = json.loads(execute_tool_call(
                    "find_by_name", {"name": "target.bin", "relative_path": relative_path}, context=self.context,
                ))
                self.assertIn("error", result)
                run.assert_not_called()

    def test_hidden_sensitive_and_symlink_subtrees_are_omitted_without_following(self):
        (self.root / ".hidden").mkdir()
        (self.root / ".hidden" / "target.bin").write_text("hidden", encoding="utf-8")
        (self.root / "credentials.json").mkdir()
        (self.root / "credentials.json" / "target.bin").write_text("sensitive", encoding="utf-8")
        with tempfile.TemporaryDirectory() as outside:
            (Path(outside) / "target.bin").write_text("outside", encoding="utf-8")
            (self.root / "linked").symlink_to(outside, target_is_directory=True)
            result = self._find({"name": "target.bin"})

        self.assertEqual(len(result["matches"]), 3)
        self.assertEqual(result["hidden_paths_omitted"], 1)
        self.assertEqual(result["sensitive_paths_omitted"], 1)
        self.assertEqual(result["symlinks_omitted"], 1)
        encoded = json.dumps(result)
        self.assertNotIn(".hidden/target.bin", encoded)
        self.assertNotIn("credentials.json/target.bin", encoded)
        self.assertNotIn("linked/target.bin", encoded)

    def test_symlink_start_and_concurrent_swap_fail_closed(self):
        (self.root / "alias").symlink_to(self.root / "src", target_is_directory=True)
        self.assertIn(
            "without following symlinks",
            self._find({"name": "target.bin", "relative_path": "alias"})["error"],
        )
        with patch("tools.schengen_agent_llm.os.open", side_effect=OSError("swapped")):
            result = self._find({"name": "target.bin"})
        self.assertIn("without following symlinks", result["error"])

    def test_fixed_bounds_and_character_cap_are_explicit(self):
        with patch("tools.schengen_agent_llm.FIND_BY_NAME_MAX_ENTRIES", 1):
            bounded = self._find({"name": "target.bin"})
        self.assertTrue(bounded["truncated"])
        self.assertEqual(bounded["completion_state"], "truncated")
        self.assertLessEqual(len(json.dumps(bounded, ensure_ascii=False)), 4000)

        with patch("tools.schengen_agent_llm.time.monotonic", side_effect=[0.0, 6.0]):
            timed = self._find({"name": "target.bin"})
        self.assertTrue(timed["truncated"])

    def test_badge_and_prompt_keep_single_target_advisory_boundary(self):
        badge = format_tool_call_beautified("find_by_name", {"name": "target.bin", "relative_path": "build"})
        self.assertIn("[Repository Find]", badge)
        self.assertIn("target.bin", badge)
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value={"id": 1}):
            prompt = build_system_prompt()
        self.assertIn("one exact, specifically named, unresolved repository target", prompt)
        self.assertIn("Glob, regex, and broad enumeration are forbidden", prompt)


class TestGitDiffStat(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.context = {"cwd": str(self.root)}

    def tearDown(self):
        self.tmp.cleanup()

    def _stat(self, *, status=b"", diff=b"", status_code=0, diff_code=0, stderr=b""):
        root = _completed([], stdout=str(self.root) + "\n")
        status_result = _completed([], returncode=status_code, stdout=status, stderr=stderr)
        diff_result = _completed([], returncode=diff_code, stdout=diff, stderr=stderr)
        with patch(
            "tools.schengen_agent_llm.subprocess.run", side_effect=[root, status_result, diff_result]
        ) as run:
            result = json.loads(execute_tool_call("git_diff_stat", {}, context=self.context))
        return result, run.call_args_list

    def test_schema_and_runtime_accept_no_arguments(self):
        tool = next(t for t in GUARD_TOOLS if t["function"]["name"] == "git_diff_stat")
        params = tool["function"]["parameters"]
        self.assertEqual(params["properties"], {})
        self.assertEqual(params["required"], [])
        self.assertFalse(params["additionalProperties"])
        with patch("tools.schengen_agent_llm.subprocess.run") as run:
            result = json.loads(execute_tool_call("git_diff_stat", {"ref": "main"}, context=self.context))
        self.assertIn("accepts no arguments", result["error"])
        run.assert_not_called()

    def test_structured_counts_use_fixed_git_argv_and_no_raw_diff(self):
        status = b" M src/app.py\x00A  staged.py\x00 M image.bin\x00?? new.txt\x00"
        diff = b"2\t1\tsrc/app.py\x003\t0\tstaged.py\x00-\t-\timage.bin\x00"
        result, calls = self._stat(status=status, diff=diff)

        self.assertFalse(result["clean"])
        self.assertEqual(result["changed_file_count"], 4)
        self.assertEqual(result["staged_entry_count"], 1)
        self.assertEqual(result["unstaged_entry_count"], 2)
        self.assertEqual(result["untracked_entry_count"], 1)
        self.assertEqual((result["additions"], result["deletions"], result["binary_file_count"]), (5, 1, 1))
        encoded = json.dumps(result)
        self.assertNotIn("source content", encoded)

        self.assertEqual(calls[0].args[0], [
            "git", "-C", str(self.root), "rev-parse", "--show-toplevel",
        ])
        for call in calls[1:]:
            argv = call.args[0]
            self.assertEqual(argv[:7], [
                "git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "submodule.recurse=false", "-C",
            ])
            self.assertEqual(argv[7], str(self.root))
            self.assertIs(call.kwargs["shell"], False)
            self.assertEqual(call.kwargs["timeout"], 5.0)
            self.assertEqual(call.kwargs["env"]["GIT_OPTIONAL_LOCKS"], "0")
            self.assertEqual(call.kwargs["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertIn("--no-ext-diff", calls[2].args[0])
        self.assertIn("--no-textconv", calls[2].args[0])
        self.assertEqual(calls[2].args[0][-2:], ["HEAD", "--"])

    def test_clean_and_sensitive_paths_are_structured_and_redacted(self):
        clean, _ = self._stat()
        self.assertTrue(clean["clean"])
        self.assertEqual(clean["files"], [])

        status = b" M .env\x00 M src/app.py\x00"
        diff = b"9\t2\t.env\x001\t1\tsrc/app.py\x00"
        result, _ = self._stat(status=status, diff=diff)
        self.assertEqual(result["changed_file_count"], 2)
        self.assertEqual(result["sensitive_paths_omitted"], 1)
        self.assertEqual((result["additions"], result["deletions"]), (10, 3))
        self.assertNotIn(".env", json.dumps(result))

    def test_timeout_git_failure_and_malformed_output_are_structured(self):
        root = _completed([], stdout=str(self.root) + "\n")
        with patch(
            "tools.schengen_agent_llm.subprocess.run",
            side_effect=[root, subprocess.TimeoutExpired(["git"], 5.0)],
        ):
            timed = json.loads(execute_tool_call("git_diff_stat", {}, context=self.context))
        self.assertEqual(timed["error"], "git_diff_stat timed out")

        failed, _ = self._stat(status_code=128, stderr=b"fatal: repository unavailable")
        self.assertIn("repository unavailable", failed["error"])
        malformed, _ = self._stat(status=b" M missing-nul")
        self.assertEqual(malformed["error"], "Malformed Git metadata output")
        malformed_diff, _ = self._stat(diff=b"not-numstat\0")
        self.assertEqual(malformed_diff["error"], "Malformed git diff output")

    def test_result_count_and_character_caps_are_explicit(self):
        status = b"".join(f"?? path-{index:03d}.txt\0".encode() for index in range(80))
        result, _ = self._stat(status=status)
        self.assertEqual(result["changed_file_count"], 80)
        self.assertEqual(len(result["files"]), 50)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["completion_state"], "truncated")
        self.assertLessEqual(len(json.dumps(result, ensure_ascii=False)), 4000)

    def test_badge_and_prompt_make_metadata_non_proof_explicit(self):
        self.assertIn("[Git Diff Stat]", format_tool_call_beautified("git_diff_stat", {}))
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value={"id": 1}):
            prompt = build_system_prompt()
        self.assertIn("concrete unexpected-scope or mass-change red flag", prompt)
        self.assertIn("never proves payload safety", prompt)


if __name__ == "__main__":
    unittest.main()
