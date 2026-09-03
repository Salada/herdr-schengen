"""Semantic complexity + tiered complexity-tax tests (issue #4027).

Covers:
1. Heredoc payload isolation: terminated heredocs collapse to '<<' so body
   lines never inflate the segment count; quoted bodies isolate substitutions,
   unquoted bodies keep them (extra_subst), here-strings (`<<<`) and
   unterminated heredocs are never mistaken for openers.
 2. compute_semantic_complexity: per-segment first-verb mutating
    classification, pipe-tail exemptions (tee NOT exempt), fail-closed UNKNOWN,
    structural parity with compute_complexity.
 3. _apply_complexity_tax tiered routing: read-only/diagnostic/VCS chains over
    threshold are absorbed via the cloud judge; mutating chains NEVER
    auto-approve via the cloud judge (hard COMPLEXITY_TAX deferral to human).

Uses a clean temp DB + patched guard LLM env; post_cloud_judge is mocked.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import core.guard_db as guard_db
from core.guard_db import get_complexity_tax_config
from core.security_evaluator import (
    DecisionLayer,
    Origin,
    _apply_complexity_tax,
    _isolate_heredocs,
    _mask_heredocs,
    _mask_quotes,
    audit_shell_command,
    compute_complexity,
    compute_semantic_complexity,
)

MUTATING_CHAIN = "mkdir a1; mkdir a2; mkdir a3; mkdir a4; mkdir a5; mkdir a6; mkdir a7"


def _heredoc(body_lines: int, prefix: str = "", quoted: bool = True) -> str:
    """Build a terminated heredoc with `body_lines` content lines."""
    q = "'" if quoted else ""
    delim = "EOF"
    opener = f"cat <<{q}{delim}{q}"
    return prefix + opener + "\n" + "\n".join(f"body{i}" for i in range(1, body_lines + 1)) + f"\n{delim}"


def _canned(content_str: str) -> dict:
    return {"choices": [{"message": {"content": content_str}}]}


class TestHeredocMasking(unittest.TestCase):
    """_mask_heredocs / compute_complexity heredoc isolation."""

    def test_16_line_quoted_heredoc_scores_two(self):
        # Before issue #4027: ~19 (16 body lines scored as phantom segments).
        heredoc = _heredoc(16)
        masked, extra = _mask_heredocs(heredoc)
        self.assertEqual(masked, "cat <<")
        self.assertEqual(extra, 0)
        self.assertEqual(compute_complexity(heredoc), 2)

    def test_quoted_heredoc_with_commit_push_chain_scores_low(self):
        # Body lines + terminator must not inflate: 'git commit -F -' + heredoc
        # + '&& git push' collapses to ~3 (was ~21 pre-masking).
        heredoc = (
            "git commit -F - <<'MSG'\n"
            + "\n".join(f"body{i}" for i in range(1, 18))
            + "\nMSG\n&& git push"
        )
        self.assertEqual(compute_complexity(heredoc), 3)

    def test_quoted_heredoc_isolates_substitutions(self):
        # A QUOTED heredoc body expands nothing — $(...) / backticks inside it
        # are inert payload text and must NOT score.
        heredoc = "cat <<'EOF'\n" + "echo $(date) `whoami`\n" * 8 + "EOF"
        masked, extra = _mask_heredocs(heredoc)
        self.assertEqual(masked, "cat <<")
        self.assertEqual(extra, 0)
        self.assertEqual(compute_complexity(heredoc), 2)

    def test_unquoted_heredoc_substitutions_survive(self):
        # An UNQUOTED heredoc body is shell-expanded: $(...) and backticks in it
        # still count (returned as extra_subst) after the payload is masked.
        heredoc = "cat <<EOF\n" + "a $(date)\nb `whoami`\nc $(pwd)\nd end\n" + "EOF"
        masked, extra = _mask_heredocs(heredoc)
        self.assertEqual(masked, "cat <<")
        self.assertEqual(extra, 4)  # 2x $(...) + 2 backticks
        # 1 segment + 4 surviving substitutions + 1 redirection
        self.assertEqual(compute_complexity(heredoc), 6)

    def test_double_quoted_delimiter_suppresses_expansion(self):
        # `<<"EOF"` quotes the delimiter, so shell suppresses body expansion
        # exactly like `<<'EOF'` (regression: double-quoted delimiters were
        # previously misclassified as unquoted and $(...) over-counted).
        for opener in ('<<"EOF"', "<<'EOF'"):
            with self.subTest(opener=opener):
                heredoc = f"cat {opener}\n$(date)\nEOF"
                masked, extra = _mask_heredocs(heredoc)
                self.assertEqual(masked, "cat <<")
                self.assertEqual(extra, 0)
                self.assertEqual(compute_complexity(heredoc), 2)
        # UNQUOTED delimiter still shell-expands the body: $(date) survives.
        heredoc = "cat <<EOF\n$(date)\nEOF"
        masked, extra = _mask_heredocs(heredoc)
        self.assertEqual(masked, "cat <<")
        self.assertEqual(extra, 1)
        self.assertEqual(compute_complexity(heredoc), 3)

    def test_dash_heredoc_with_indented_terminator_masks(self):
        # `<<-` terminators may be indented with leading tabs.
        heredoc = "cat <<-DATA\n\tcontent line\n\tDATA"
        masked, extra = _mask_heredocs(heredoc)
        self.assertEqual(masked, "cat <<")
        self.assertEqual(extra, 0)
        self.assertEqual(compute_complexity(heredoc), 2)

    def test_herestring_never_mistaken_for_heredoc(self):
        masked, extra = _mask_heredocs("cat <<< hello")
        self.assertEqual(masked, "cat <<< hello")
        self.assertEqual(extra, 0)
        self.assertEqual(compute_complexity("cat <<< hello"), 2)

    def test_unterminated_heredoc_left_untouched(self):
        # No terminator -> fail-closed: nothing masked, counts unchanged.
        raw = "cat << EOF\nbody line\n"
        masked, extra = _mask_heredocs(raw)
        self.assertEqual(masked, raw)
        self.assertEqual(extra, 0)
        self.assertEqual(compute_complexity(raw), 3)

    def test_heredoc_opener_without_body_untouched(self):
        # `cat << EOF` with no body/terminator must stay a plain redirection.
        masked, extra = _mask_heredocs("cat << EOF")
        self.assertEqual(masked, "cat << EOF")
        self.assertEqual(extra, 0)
        self.assertEqual(compute_complexity("cat << EOF"), 2)


class TestQuoteMasking(unittest.TestCase):
    """_mask_quotes / compute_complexity quoted-region isolation.

    Newlines / separators INSIDE a quoted shell word (multi-line
    `python3 -c "..."`, `echo "a\\nb"`) are one literal argument — they must
    never inflate the segment count — while newlines BETWEEN top-level
    commands remain separators. Double-quoted bodies are shell-expanded so
    their `$(...)`/backticks still count (extra_subst); single-quoted bodies
    expand nothing; unterminated quotes stay untouched (fail-closed).
    """

    def test_multiline_double_quoted_python3_does_not_inflate(self):
        # Actual newline characters inside the double-quoted `-c` payload.
        cmd = 'python3 -c "import os\nprint(os.getcwd())\nprint(1)"'
        self.assertEqual(compute_complexity(cmd), 1)

    def test_multiline_echo_quotes_do_not_inflate(self):
        self.assertEqual(compute_complexity('echo "a\nb\nc"'), 1)

    def test_single_quoted_multiline_does_not_inflate(self):
        self.assertEqual(compute_complexity("echo 'a\nb\nc'"), 1)

    def test_separators_inside_quotes_are_not_control_separators(self):
        # `;` / `|` / `&` inside quotes are literal word content, not chaining.
        cmd = 'echo "a; b | c" && echo \'d & e\''
        self.assertEqual(compute_complexity(cmd), 2)

    def test_top_level_newline_separated_commands_still_count(self):
        # Two top-level commands on separate lines = 2 segments (quotes do not
        # swallow text between commands).
        self.assertEqual(compute_complexity("git add a\ngit add b"), 2)
        self.assertEqual(compute_complexity("echo hi\necho there\necho now"), 3)

    def test_unterminated_quote_left_untouched(self):
        # Fail-closed: no closing quote -> no masking -> newlines still split.
        self.assertEqual(compute_complexity('python3 -c "a\nb\nc'), 3)

    def test_double_quoted_substitution_still_counts(self):
        # A DOUBLE-quoted body is shell-expanded: $(...) inside it executes and
        # must still score (masked text + extra_subst = parity with the old
        # global count).
        self.assertEqual(compute_complexity('echo "$(date)"'), 2)

    def test_single_quoted_substitution_is_inert(self):
        # A single-quoted body expands nothing: $(...) is literal text and must
        # NOT score as a substitution.
        self.assertEqual(compute_complexity("echo '$(date)'"), 1)

    def test_masked_quote_is_not_a_redirection(self):
        # The placeholder must not be misread as a redirection / separator.
        masked, extra = _mask_quotes('echo "x < y > z"')
        self.assertEqual(masked, "echo Q")
        self.assertEqual(extra, 0)
        self.assertEqual(compute_complexity('echo "x < y > z"'), 1)

    def test_quote_masking_after_heredoc_masking(self):
        # Ordering invariant: heredoc payloads collapse FIRST; quote masking
        # must not disturb them (a quoted heredoc opener is consumed whole).
        heredoc = "cat <<'EOF'\nbody line\nEOF"
        s, extra = _isolate_heredocs(heredoc)
        self.assertEqual(s, "cat <<")
        self.assertEqual(extra, 0)
        self.assertEqual(compute_complexity(heredoc), 2)

    def test_structural_parity_multi_command_quoted(self):
        # compute_complexity and compute_semantic_complexity share the same
        # masked structural value.
        cmd = 'python3 -c "import os\nprint(1)" | tail -5'
        prof = compute_semantic_complexity(cmd)
        self.assertEqual(prof.structural, compute_complexity(cmd))
        self.assertEqual(prof.structural, 2)


class TestSemanticComplexity(unittest.TestCase):
    """compute_semantic_complexity classification."""

    def test_readonly_chain_not_mutating(self):
        prof = compute_semantic_complexity("git status --short && echo '===' && git diff --stat")
        self.assertFalse(prof.has_mutation)
        self.assertEqual(prof.mutating_segments, ())
        self.assertEqual(prof.structural, compute_complexity("git status --short && echo '===' && git diff --stat"))

    def test_git_push_marks_mutating(self):
        prof = compute_semantic_complexity("git commit -m 'x' && git push")
        self.assertTrue(prof.has_mutation)
        self.assertEqual(prof.mutating_segments, ("git push",))

    def test_tee_not_exempt_as_pipe_tail(self):
        # `tee` writes — even as a pipe tail it must be UNKNOWN/mutating.
        prof = compute_semantic_complexity("git status | grep x | tee /tmp/o")
        self.assertTrue(prof.has_mutation)
        self.assertIn("tee /tmp/o", prof.mutating_segments)

    def test_readonly_pipe_tail_exempt(self):
        # tail/head/grep/rg/sort/uniq/wc/sed/cut/tr/column as immediate pipe
        # tails are read-only filters (non-mutating).
        for cmd in (
            "git status | grep x | wc -l",
            "git diff | head -20",
            "echo hi | sort | uniq | wc -l",
            "printf 'x\\n' | cut -c1 | tr a-z A-Z | tail -1",
        ):
            prof = compute_semantic_complexity(cmd)
            self.assertFalse(prof.has_mutation, f"expected read-only for '{cmd}': {prof.mutating_segments}")

    def test_pipe_tail_exemption_requires_pipe(self):
        # A filter verb NOT in pipe-tail position is not exempt (fail-closed
        # UNKNOWN) — only an immediate `| verb` tail gets the read-only filter pass.
        prof = compute_semantic_complexity("grep x file && git status")
        self.assertTrue(prof.has_mutation)
        self.assertIn("grep x file", prof.mutating_segments)

    def test_substitution_in_segment_is_control_flow(self):
        prof = compute_semantic_complexity("echo $(pwd) && git status")
        self.assertTrue(prof.has_mutation)
        self.assertEqual(prof.mutating_segments, ("echo $(pwd)",))

    def test_fd_redirects_stripped_before_split(self):
        prof = compute_semantic_complexity("python3 -m unittest discover -s tests 2>&1 | tail -30")
        self.assertFalse(prof.has_mutation)
        self.assertEqual(prof.n_segments, 2)

    def test_unknown_verb_fail_closed_mutating(self):
        prof = compute_semantic_complexity("some_random_tool --flag && git status")
        self.assertTrue(prof.has_mutation)
        self.assertIn("some_random_tool --flag", prof.mutating_segments)

    def test_structural_parity_with_compute_complexity(self):
        for cmd in (
            "git status --short && echo '===' && git diff --stat",
            "git commit -m 'x' && git push",
            "git status | grep x | tee /tmp/o",
            _heredoc(16),
            "cat <<EOF\n" + "a $(date)\nb `whoami`\n" + "EOF",
            "ls 2>&1 & wait",
            "python3 -m unittest discover -s tests 2>&1 | tail -30",
        ):
            prof = compute_semantic_complexity(cmd)
            self.assertEqual(prof.structural, compute_complexity(cmd), cmd)

    def test_heredoc_body_never_mutating_payload(self):
        # A QUOTED heredoc body is inert payload — masked before classification,
        # expands nothing, so it must not flag the chain as mutating.
        heredoc = "git commit -F - <<'MSG'\nrm -rf /\nMSG"
        prof = compute_semantic_complexity(heredoc)
        self.assertFalse(prof.has_mutation)
        self.assertEqual(prof.mutating_segments, ())

    def test_unquoted_heredoc_substitutions_mark_mutating(self):
        # PR #186 review (BLOCKING 1): an UNQUOTED heredoc body is shell-expanded
        # at run time — $(...) / backticks inside it EXECUTE and must force
        # has_mutation=True even though the payload is masked before segment
        # classification (CONTROL_FLOW-equivalent mutation).
        for body_line, label, expected in (
            ("$(touch /tmp/a)", "command substitution", 3),  # 1 seg + 1 subst + 1 redir
            ("`touch /tmp/a`", "backtick substitution", 4),  # 2 backticks survive
        ):
            heredoc = "git commit -F - <<EOF\n" + body_line + "\nEOF"
            with self.subTest(label=label):
                prof = compute_semantic_complexity(heredoc)
                self.assertTrue(prof.has_mutation, f"unquoted-heredoc {label} must mark mutating")
                self.assertIn("(unquoted heredoc substitution)", prof.mutating_segments)
                # compute_complexity still counts the surviving substitutions
                self.assertEqual(compute_complexity(heredoc), expected)

    def test_unquoted_heredoc_substitutions_over_threshold_poc(self):
        # The exact PR #186 PoC shape: 3 x $(touch ...) in an unquoted heredoc.
        poc = "git commit -F - <<EOF\n$(touch /tmp/a)\n$(touch /tmp/b)\n$(touch /tmp/c)\nEOF"
        prof = compute_semantic_complexity(poc)
        self.assertTrue(prof.has_mutation)
        self.assertIn("(unquoted heredoc substitution)", prof.mutating_segments)

    def test_double_quoted_heredoc_delimiter_body_remains_inert(self):
        # A quoted delimiter — double (`<<"EOF"`) OR single (`<<'EOF'`) —
        # suppresses body expansion: $(...) payload is inert text and must NOT
        # mark the chain mutating (regression for double-quoted delimiters).
        for opener in ('<<"EOF"', "<<'EOF'"):
            with self.subTest(opener=opener):
                heredoc = f"echo {opener}\n$(touch /tmp/q)\nEOF"
                prof = compute_semantic_complexity(heredoc)
                self.assertFalse(prof.has_mutation, f"{opener} body must be inert: {prof.mutating_segments}")
                self.assertEqual(prof.mutating_segments, ())
                self.assertEqual(prof.structural, 2)  # 1 seg + 1 redir, no surviving subst
        # Contrast: an UNQUOTED delimiter shell-expands the body at run time.
        heredoc = "echo <<EOF\n$(touch /tmp/q)\nEOF"
        prof = compute_semantic_complexity(heredoc)
        self.assertTrue(prof.has_mutation)
        self.assertIn("(unquoted heredoc substitution)", prof.mutating_segments)

    def test_quoted_heredoc_with_substitutions_remains_inert(self):
        # Quoted heredoc bodies expand nothing — even $(touch ...) payload is
        # inert text and must NOT mark the chain mutating.
        heredoc = "git commit -F - <<'MSG'\n" + "\n".join(
            f"$(touch /tmp/q{i})" for i in range(6)
        ) + "\nMSG"
        prof = compute_semantic_complexity(heredoc)
        self.assertFalse(prof.has_mutation)
        self.assertEqual(prof.mutating_segments, ())
        self.assertEqual(prof.structural, 2)  # body fully masked, no surviving subst


class TestComplexityTaxRouting(unittest.TestCase):
    """_apply_complexity_tax tiered routing (issue #4027)."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()
        self.env_patch = patch.dict(
            os.environ,
            {
                "GUARD_LLM_ENDPOINT": "https://example.com/v1/chat/completions",
                "GUARD_LLM_MODEL": "test-model",
                "GUARD_LLM_API_KEY": "test-key",
            },
        )
        self.env_patch.start()
        from core.session_memory import clear_pane_approval_memory

        clear_pane_approval_memory()
        guard_db.clear_in_memory_cache()
        import core.security_evaluator as se

        self.apply_tax = se._apply_complexity_tax
        self.Origin = se.Origin
        self.DecisionLayer = se.DecisionLayer

    def tearDown(self):
        self.env_patch.stop()
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def _apply(self, cmd):
        return self.apply_tax(cmd, get_complexity_tax_config(), self.Origin.AGENT,
                              cwd="", scope="default", agent_id="default")

    def test_mutating_chain_hard_defers_no_cloud(self):
        calls = []

        def _recording(*args, **kwargs):
            calls.append(args)
            return _canned('{"is_safe": true, "confidence": 0.99, "reason": "benign"}')

        with patch("core.security_evaluator.post_cloud_judge", side_effect=_recording):
            res = self._apply(MUTATING_CHAIN)
            self.assertIsNotNone(res)
            safe, reason, layer = res
            self.assertFalse(safe, f"mutating chain must defer: {reason}")
            self.assertEqual(layer, self.DecisionLayer.COMPLEXITY_TAX)
            self.assertIn("complexity", reason)
        self.assertEqual(calls, [], "cloud judge must NEVER be called for a mutating chain")

    def test_unquoted_heredoc_chain_never_routes_to_cloud_judge(self):
        # PR #186 review (BLOCKING 1): an over-threshold chain whose only
        # mutation is executable $(...) inside an UNQUOTED heredoc body must
        # hard-defer (COMPLEXITY_TAX) — NEVER be absorbed by the cloud judge
        # (structural = 1 masked segment + 6 surviving substitutions + 1
        # redirection = 8 > default threshold 6).
        unquoted = "git commit -F - <<EOF\n" + "\n".join(
            f"$(touch /tmp/a{i})" for i in range(6)
        ) + "\nEOF"
        prof = compute_semantic_complexity(unquoted)
        self.assertEqual(prof.structural, 8)
        self.assertTrue(prof.has_mutation)
        calls = []

        def _recording(*args, **kwargs):
            calls.append(args)
            return _canned('{"is_safe": true, "confidence": 0.99, "reason": "benign"}')

        with patch("core.security_evaluator.post_cloud_judge", side_effect=_recording):
            res = self._apply(unquoted)
            self.assertIsNotNone(res)
            safe, reason, layer = res
            self.assertFalse(safe, f"unquoted-heredoc chain must defer: {reason}")
            self.assertEqual(layer, self.DecisionLayer.COMPLEXITY_TAX)
        self.assertEqual(calls, [], "cloud judge must NEVER be called for an unquoted-heredoc chain")

    def test_quoted_heredoc_chain_over_threshold_absorbed_by_cloud_judge(self):
        # Contrast: a QUOTED heredoc body is inert, so an over-threshold chain
        # carrying one is non-mutating and MAY still be absorbed by the cloud
        # judge (structural = 7 masked segments + 1 redirection = 8 > threshold).
        quoted = (
            "git commit -F - <<'MSG'\n"
            + "\n".join(f"body{i}" for i in range(6))
            + "\nMSG\n&& echo a && echo b && echo c && echo d && echo e && echo f"
        )
        prof = compute_semantic_complexity(quoted)
        self.assertEqual(prof.structural, 8)
        self.assertFalse(prof.has_mutation)
        verdict = '{"is_safe": true, "confidence": 0.95, "reason": "quoted heredoc ok"}'
        with patch("core.security_evaluator.post_cloud_judge", return_value=_canned(verdict)):
            res = self._apply(quoted)
        self.assertIsNotNone(res)
        self.assertTrue(res[0], res[1])
        self.assertEqual(res[2], self.DecisionLayer.CLOUD_JUDGE)

    def test_readonly_chain_absorbed_by_cloud_judge(self):
        readonly = "true && true && true && true && true && true && true"
        verdict = '{"is_safe": true, "confidence": 0.95, "reason": "read-only ok"}'
        with patch(
            "core.security_evaluator.post_cloud_judge", return_value=_canned(verdict)
        ):
            res = self._apply(readonly)
            self.assertIsNotNone(res)
            safe, reason, layer = res
            self.assertTrue(safe, f"read-only chain must clear via cloud judge: {reason}")
            self.assertEqual(layer, self.DecisionLayer.CLOUD_JUDGE)

    def test_readonly_chain_cloud_judge_unsafe_defers(self):
        readonly = "wait && wait && wait && wait && wait && wait && wait"
        verdict = '{"is_safe": false, "confidence": 0.95, "reason": "uncertain"}'
        with patch(
            "core.security_evaluator.post_cloud_judge", return_value=_canned(verdict)
        ):
            res = self._apply(readonly)
            self.assertIsNotNone(res)
            safe, reason, layer = res
            self.assertFalse(safe, f"unsafe verdict must defer: {reason}")
            self.assertEqual(layer, self.DecisionLayer.COMPLEXITY_TAX)

    def test_under_threshold_passes_through(self):
        # Below/at threshold -> None regardless of cloud judge availability.
        for cmd in ("git status", "mkdir a1; mkdir a2; mkdir a3", "ls -la"):
            with patch("core.security_evaluator.post_cloud_judge") as pj:
                self.assertIsNone(self._apply(cmd))
                pj.assert_not_called()

    def test_diagnostic_chain_absorbed_not_mutating(self):
        # `python3 -m unittest ...` repeated segments are DIAGNOSTIC (0.5 each,
        # non-mutating): over-threshold absorbs via the cloud judge.
        cmd = " && ".join("python3 -m unittest discover -s tests" for _ in range(7))
        prof = compute_semantic_complexity(cmd)
        self.assertFalse(prof.has_mutation)
        self.assertEqual(prof.structural, 7)
        verdict = '{"is_safe": true, "confidence": 0.95, "reason": "test run ok"}'
        with patch("core.security_evaluator.post_cloud_judge", return_value=_canned(verdict)):
            res = self._apply(cmd)
        self.assertIsNotNone(res)
        self.assertTrue(res[0], res[1])
        self.assertEqual(res[2], self.DecisionLayer.CLOUD_JUDGE)

    def test_heredoc_chain_threshold_gate_uses_masked_structural(self):
        # A long quoted heredoc is structurally cheap AFTER masking: the tax
        # gate must use the masked structural value (not raw body lines).
        heredoc = _heredoc(16)
        self.assertEqual(compute_complexity(heredoc), 2)
        with patch("core.security_evaluator.post_cloud_judge") as pj:
            self.assertIsNone(self._apply(heredoc))
            pj.assert_not_called()


class TestComplexityTaxEndToEnd(unittest.TestCase):
    """End-to-end audit_shell_command regression guards."""

    def test_mutating_chain_end_to_end_complexity_tax(self):
        safe, reason, layer = audit_shell_command(MUTATING_CHAIN)
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.COMPLEXITY_TAX)


if __name__ == "__main__":
    unittest.main()
