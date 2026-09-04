"""Deterministic policy for issue #200 routine Git workflows."""

import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from core.security_evaluator import DecisionLayer, audit_shell_command


class TestRoutineGitPolicy(unittest.TestCase):
    def assert_fast_track(self, command: str) -> None:
        safe, reason, layer = audit_shell_command(command)
        self.assertTrue(safe, reason)
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def assert_human_gated(self, command: str) -> None:
        safe, reason, layer = audit_shell_command(command)
        self.assertFalse(safe, reason)
        self.assertEqual(layer, DecisionLayer.NOT_ALLOWLISTED)

    def assert_critical(self, command: str) -> None:
        safe, reason, layer = audit_shell_command(command)
        self.assertFalse(safe, reason)
        self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL)

    def test_git_dash_c_read_queries_fast_track(self):
        for command in (
            "git -C /Users/user/Documents/iwe-base status --short",
            "git -C /Users/user/.local/share/chezmoi diff --check",
            "git -C repo log -3 --oneline --decorate",
            "git -C repo show --stat HEAD",
            "git -C repo branch --show-current",
            "git -C repo tag --list",
            "git -C repo remote -v",
            "git -C repo remote get-url origin",
        ):
            with self.subTest(command=command):
                self.assert_fast_track(command)

    def test_routine_commit_and_push_chain_fast_tracks(self):
        self.assert_fast_track(
            "git diff --check && git add BACKLOG.md && "
            "git commit -m 'docs: back up local backlog' && "
            "git push origin mac && git status --short --branch"
        )
        self.assert_fast_track("git add scripts/core/evaluator.py tests/test_policy.py")
        self.assert_fast_track("git commit --message='fix: routine policy'")
        self.assert_fast_track("git push -u origin feat/routine-git")
        self.assert_fast_track("git push origin HEAD:fix/routine-git")

    def test_broad_add_and_history_rewrite_stay_human_gated(self):
        for command in (
            "git add .",
            "git add -A",
            "git add ../outside",
            "git add '*.py'",
            "git add .env",
            "git commit",
            "git commit --amend -m fix",
            "git commit --no-verify -m fix",
            "git push",
            "git push origin HEAD",
            "git push https://example.com/repo.git feat/x",
            "git push --force-with-lease origin feat/x",
            "git push --force-if-includes origin feat/x",
            "git branch new-branch",
            "git tag v1.0.0",
            "git branch new-branch | head -1",
            "git tag v1.0.0 | cat",
        ):
            with self.subTest(command=command):
                self.assert_human_gated(command)

    def test_dangerous_pushes_are_critical_with_or_without_dash_c(self):
        for command in (
            "git push --force origin feat/x",
            "git push -uf origin feat/x",
            "git -C repo push -f origin feat/x",
            "git -C repo push --delete origin feat/x",
            "git -C repo push --mirror origin",
            "git -C repo push --all origin",
            "git -C repo push --tags origin",
            "git -C repo push origin +feat/x",
            "git -C repo push origin :feat/x",
            "git -C repo push origin main",
            "git -C repo push origin feat/x:refs/heads/main",
            "git -C repo push origin refs/tags/v1.0.0",
        ):
            with self.subTest(command=command):
                self.assert_critical(command)

    def test_exec_and_write_capable_read_options_do_not_fast_track(self):
        for command in (
            "git -C repo diff --no-index a b",
            "git -C repo diff --ext-diff HEAD",
            "git -C repo show --textconv HEAD:file",
            "git -C repo log --output=log.txt",
            "git -C repo grep --open-files-in-pager=vim needle",
            "git -C repo diff --ext HEAD",
            "git -c diff.external=evil diff",
            "/tmp/git -C repo status",
        ):
            with self.subTest(command=command):
                self.assert_human_gated(command)

    def test_mixed_or_unbounded_chains_do_not_fast_track(self):
        self.assert_human_gated("git add file && echo done")
        self.assert_human_gated("git -C one status && git -C two status")
        self.assert_human_gated("git commit -m one && git commit -m two")
        self.assert_human_gated("git push origin feat/a && git push origin feat/b")
        self.assert_human_gated("git status; git add file")


if __name__ == "__main__":
    unittest.main()
