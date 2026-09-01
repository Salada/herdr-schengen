#!/usr/bin/env python3
"""Tests for Sprint 2a: Gatekeeper prompt restructuring (#3864).

Verifies:
1. Adjudication protocol mandates a STEP 0 pre-complexity/risk briefing before any verdict.
2. Anti-rubber-stamp adjudication rules (fail-closed, human note is advisory only).
3. Disagree & Commit stance (equal expert, never defer to the human).
4. Read-only interpretation mode (allow_adjudication=False) is untouched and disjoint.
5. GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT decomposition + anti-rubber-stamp JSON contract.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from core.cloud_judge import GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT
from tools.schengen_agent_llm import build_system_prompt

_ACTIVE_ESC = {
    "id": 123,
    "pane_id": "w1D:p1",
    "agent_kind": "agy",
    "raw_command": "rm -rf /tmp/test_dir",
    "safety_reason": "Destructive deletion",
}


class TestGatekeeperPromptAdjudicationBriefing(unittest.TestCase):
    """INV-GK-1: briefing-before-verdict — STEP 0 risk-segment decomposition."""

    def test_protocol_mandates_step0_briefing(self):
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=_ACTIVE_ESC):
            prompt = build_system_prompt()
        self.assertIn("PRE-COMPLEXITY/RISK BRIEFING", prompt)
        self.assertIn("FORBIDDEN from approving", prompt)
        self.assertIn("CHAINED SEGMENTS", prompt)
        self.assertIn("MUTATIONS", prompt)
        self.assertIn("NETWORK EGRESS", prompt)
        self.assertIn("SENSITIVE PATHS", prompt)
        self.assertIn("SUBSTITUTIONS", prompt)
        self.assertIn("Only AFTER this briefing may you proceed to a verdict", prompt)


class TestGatekeeperPromptAntiRubberStamp(unittest.TestCase):
    """INV-GK-2/4: anti-rubber-stamp adjudication, fail-closed."""

    def test_protocol_contains_anti_rubber_stamp_rules(self):
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=_ACTIVE_ESC):
            prompt = build_system_prompt()
        self.assertIn("NEVER approve", prompt)
        self.assertIn("ADVISORY OPINION", prompt)
        self.assertIn("never a directive", prompt)
        # Exact prompt text renders "NOT a valid skip reason" (capitalized); compare case-insensitively.
        self.assertIn("not a valid skip reason", prompt.lower())
        self.assertIn("When in doubt, fail closed", prompt)


class TestGatekeeperPromptDisagreeAndCommit(unittest.TestCase):
    """INV-GK-3: disagree & commit — equal expert, never defer to the human."""

    def test_protocol_contains_disagree_and_commit(self):
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=_ACTIVE_ESC):
            prompt = build_system_prompt()
        self.assertIn("DISAGREE & COMMIT", prompt)
        self.assertIn("EQUAL expert", prompt)
        self.assertIn("never defer to the human", prompt)
        self.assertIn("The human does not outrank your risk assessment", prompt)

    def test_protocol_removes_no_autonomous_reject(self):
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=_ACTIVE_ESC):
            prompt = build_system_prompt()
        self.assertNotIn("NO Autonomous Reject", prompt)
        self.assertNotIn("wait for explicit human instructions", prompt)


class TestGatekeeperPromptReadOnlyMode(unittest.TestCase):
    """INV-GK-6/7: question non-adjudication — else-branch untouched and disjoint."""

    def test_no_adjudication_mode_preserved(self):
        with patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=_ACTIVE_ESC):
            prompt = build_system_prompt(allow_adjudication=False)
        self.assertIn("NO ADJUDICATION", prompt)
        self.assertNotIn("DISAGREE & COMMIT", prompt)
        self.assertNotIn("PRE-COMPLEXITY/RISK BRIEFING", prompt)


class TestCloudJudgeSystemPrompt(unittest.TestCase):
    """Cloud-judge prompt decomposition + anti-rubber-stamp JSON contract."""

    def test_prompt_contains_decomposition_and_json_contract(self):
        self.assertIn("DECOMPOSE", GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)
        self.assertIn("network egress", GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)
        self.assertIn("command substitutions", GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)
        self.assertIn("is_safe", GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)
        self.assertIn("confidence", GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)

    def test_prompt_contains_anti_rubber_stamp_rule(self):
        self.assertIn("NEVER emit is_safe=true merely because", GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)
        self.assertIn("Run the decomposition first, always", GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)
        self.assertIn("defer to human", GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()
