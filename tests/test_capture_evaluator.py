"""Raw/canonical evaluation is monotonic: normalization never hides danger."""

import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from adapters.capture_evaluator import evaluate_capture_pair
from core.security_evaluator import DecisionLayer


def verdicts(mapping):
    def audit(command, **_kwargs):
        safe, layer = mapping[command]
        return safe, f"verdict for {command}", layer, {"mechanism": "test"}

    return audit


class TestCapturePairMonotonicity(unittest.TestCase):
    kwargs = {"reasoning_effort": "none"}

    def test_canonical_danger_blocks_even_when_rendered_is_safe(self):
        raw = "rm -\n  rf /tmp/example"
        canonical = "rm -rf /tmp/example"
        result = evaluate_capture_pair(
            raw,
            canonical,
            "recent-unwrapped",
            audit_func=verdicts(
                {
                    raw: (True, DecisionLayer.FAST_TRACK_AST),
                    canonical: (False, DecisionLayer.SHELL_CRITICAL),
                }
            ),
            **self.kwargs,
        )
        self.assertFalse(result[0])
        self.assertEqual(result[2], DecisionLayer.SHELL_CRITICAL)
        self.assertEqual(result[3]["normalization_relation"], "same")

    def test_rendered_danger_blocks_even_when_canonical_is_safe(self):
        raw = "cat /repo/.env"
        canonical = "cat /repo/notes.txt"
        result = evaluate_capture_pair(
            raw,
            canonical,
            "recent-unwrapped",
            audit_func=verdicts(
                {
                    raw: (False, DecisionLayer.SECRET_GUARD),
                    canonical: (True, DecisionLayer.FAST_TRACK_AST),
                }
            ),
            **self.kwargs,
        )
        self.assertFalse(result[0])
        self.assertEqual(result[2], DecisionLayer.SECRET_GUARD)

    def test_benign_identity_mismatch_is_ambiguous_not_approved(self):
        raw = "git status"
        canonical = "git diff --check"
        result = evaluate_capture_pair(
            raw,
            canonical,
            "recent-unwrapped",
            audit_func=verdicts(
                {
                    raw: (True, DecisionLayer.FAST_TRACK_AST),
                    canonical: (True, DecisionLayer.FAST_TRACK_AST),
                }
            ),
            **self.kwargs,
        )
        self.assertFalse(result[0])
        self.assertEqual(result[2], DecisionLayer.NORMALIZATION_AMBIGUOUS)
        self.assertTrue(result[3]["raw_capture_evaluated"])
        self.assertEqual(result[3]["mechanism"], "normalization-ambiguous")

    def test_unavailable_representation_is_ambiguous_without_audit(self):
        def unexpected(*_args, **_kwargs):
            self.fail("audit must not run without both representations")

        result = evaluate_capture_pair(
            None,
            "git status",
            "visible-unparsed",
            audit_func=unexpected,
            **self.kwargs,
        )
        self.assertFalse(result[0])
        self.assertEqual(result[2], DecisionLayer.NORMALIZATION_AMBIGUOUS)
        self.assertFalse(result[3]["raw_capture_evaluated"])

    def test_soft_wrap_uses_canonical_safe_verdict(self):
        raw = "git status --\n  short"
        canonical = "git status --short"
        result = evaluate_capture_pair(
            raw,
            canonical,
            "recent-unwrapped",
            audit_func=verdicts(
                {
                    raw: (False, DecisionLayer.NOT_ALLOWLISTED),
                    canonical: (True, DecisionLayer.FAST_TRACK_AST),
                }
            ),
            **self.kwargs,
        )
        self.assertTrue(result[0])
        self.assertEqual(result[2], DecisionLayer.FAST_TRACK_AST)

    def test_visible_mismatch_never_auto_approves(self):
        command = "git status"
        result = evaluate_capture_pair(
            command,
            command,
            "visible-mismatch",
            audit_func=verdicts({command: (True, DecisionLayer.FAST_TRACK_AST)}),
            **self.kwargs,
        )
        self.assertFalse(result[0])
        self.assertEqual(result[2], DecisionLayer.NORMALIZATION_AMBIGUOUS)


if __name__ == "__main__":
    unittest.main()
