"""Explicit human directives are deterministic and deliberately narrow."""

import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from core.human_directives import parse_human_directive


class TestHumanDirectiveParser(unittest.TestCase):
    def test_slash_approve_and_reject(self):
        approve = parse_human_directive("/approve 908 routine read", 1)
        self.assertEqual((approve.action, approve.escalation_id), ("approve", 908))
        self.assertEqual(approve.feedback, "routine read")
        reject = parse_human_directive("/reject", 910)
        self.assertEqual((reject.action, reject.escalation_id), ("reject", 910))

    def test_explicit_english_and_korean_use_active_command(self):
        for text in ("approve", "yes, do it", "go ahead", "승인", "승인해주세요", "진행하자", "실행해"):
            with self.subTest(text=text):
                directive = parse_human_directive(text, 42)
                self.assertEqual((directive.action, directive.escalation_id), ("approve", 42))
        for text in ("reject", "do not run it", "거절", "차단해주세요", "승인하지 마"):
            with self.subTest(text=text):
                directive = parse_human_directive(text, 43)
                self.assertEqual((directive.action, directive.escalation_id), ("reject", 43))

    def test_explicit_comma_note_is_preserved(self):
        directive = parse_human_directive("approve it, that's fine", 44)
        self.assertEqual(directive.action, "approve")
        self.assertEqual(directive.feedback, "approve it, that's fine")

    def test_ambiguous_or_broad_chat_is_not_adjudicated(self):
        for text in (
            "should I approve?",
            "승인해야 하나?",
            "승인됐어야 한다",
            "developers.openai.com 전체 승인",
            "전체 승인",
            "/approve-batch",
            "/allow-url developers.openai.com",
            "please investigate why approval failed",
            "승인, 하지마",
            "승인, 아니야",
            "yes, but actually no",
        ):
            with self.subTest(text=text):
                self.assertIsNone(parse_human_directive(text, 45))

    def test_no_active_command_keeps_directive_unbound(self):
        directive = parse_human_directive("승인")
        self.assertIsNone(directive.escalation_id)


if __name__ == "__main__":
    unittest.main()
