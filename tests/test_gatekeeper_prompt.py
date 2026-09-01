#!/usr/bin/env python3
"""Tests for Sprint 2a: Gatekeeper prompt restructuring (#3864) + approve_advisory option.

Verifies:
1. Adjudication protocol mandates a STEP 0 pre-complexity/risk briefing before any verdict.
2. Anti-rubber-stamp adjudication rules (fail-closed) — STEP 2 unconditional.
3. STEP 3 branches on approve_advisory:
   - default (False): HUMAN DIRECTIVE — execute, no second-guessing.
   - opt-in (True): Disagree & Commit (equal expert, advisory opinion).
4. Read-only interpretation mode (allow_adjudication=False) is untouched and disjoint.
5. approve_advisory config roundtrip (default False, set/get, set False).
6. GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT decomposition + anti-rubber-stamp JSON contract
   (unaffected by the new markers).
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import core.guard_db as guard_db
from core.cloud_judge import GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT
from core.guard_db import get_approve_advisory_config, set_approve_advisory_config
from tools.schengen_agent_llm import build_system_prompt

_ACTIVE_ESC = {
    "id": 123,
    "pane_id": "w1D:p1",
    "agent_kind": "agy",
    "raw_command": "rm -rf /tmp/test_dir",
    "safety_reason": "Destructive deletion",
}

# New markers introduced by the approve_advisory split (INV-ADV). None of them
# may leak into the cloud-judge prompt or the read-only branch.
_ADVISORY_MARKERS = ("DISAGREE & COMMIT", "ADVISORY OPINION", "HUMAN DIRECTIVE", "approve_advisory")


def _patch_esc(esc=_ACTIVE_ESC):
    return patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=esc)


def _patch_advisory(enabled: bool):
    return patch("tools.schengen_agent_llm.get_approve_advisory_config", return_value=enabled)


class TestGatekeeperPromptAdjudicationBriefing(unittest.TestCase):
    """INV-GK-1 / INV-ADV-2: briefing-before-verdict — STEP 0 decomposition,
    unconditional in BOTH approve_advisory branches."""

    def test_protocol_mandates_step0_briefing(self):
        with _patch_esc():
            prompt = build_system_prompt()
        self.assertIn("PRE-COMPLEXITY/RISK BRIEFING", prompt)
        self.assertIn("FORBIDDEN from approving", prompt)
        self.assertIn("CHAINED SEGMENTS", prompt)
        self.assertIn("MUTATIONS", prompt)
        self.assertIn("NETWORK EGRESS", prompt)
        self.assertIn("SENSITIVE PATHS", prompt)
        self.assertIn("SUBSTITUTIONS", prompt)
        self.assertIn("Only AFTER this briefing may you proceed to a verdict", prompt)

    def test_step0_briefing_unconditional_in_advisory_branch(self):
        with _patch_esc(), _patch_advisory(True):
            prompt = build_system_prompt()
        self.assertIn("PRE-COMPLEXITY/RISK BRIEFING", prompt)
        self.assertIn("Only AFTER this briefing may you proceed to a verdict", prompt)

    def test_step0_briefing_unconditional_in_directive_branch(self):
        with _patch_esc(), _patch_advisory(False):
            prompt = build_system_prompt()
        self.assertIn("PRE-COMPLEXITY/RISK BRIEFING", prompt)
        self.assertIn("Only AFTER this briefing may you proceed to a verdict", prompt)


class TestGatekeeperPromptAntiRubberStamp(unittest.TestCase):
    """INV-GK-2/4 / INV-ADV-5: anti-rubber-stamp STEP 2 is unconditional and
    fail-closed in both branches."""

    def test_protocol_contains_anti_rubber_stamp_rules(self):
        # STEP 2 (unconditional) is exercised via the Disagree & Commit branch;
        # the ADVISORY OPINION marker lives in the advisory STEP 3.
        with _patch_esc(), _patch_advisory(True):
            prompt = build_system_prompt()
        self.assertIn("NEVER auto-approve", prompt)
        self.assertIn("ADVISORY OPINION", prompt)
        self.assertIn("never a directive", prompt)
        # Exact prompt text renders "NOT a valid skip reason" (capitalized); compare case-insensitively.
        self.assertIn("not a valid skip reason", prompt.lower())
        self.assertIn("When in doubt, fail closed", prompt)

    def test_anti_rubber_stamp_step2_present_in_directive_branch(self):
        # INV-ADV-5: STEP 2 stays even in the directive branch (autonomous
        # judgment only — never rubber-stamps autonomous approvals).
        with _patch_esc(), _patch_advisory(False):
            prompt = build_system_prompt()
        self.assertIn("ANTI-RUBBER-STAMP", prompt)
        self.assertIn("NEVER auto-approve", prompt)
        self.assertIn("When in doubt, fail closed", prompt)


class TestGatekeeperPromptDisagreeAndCommit(unittest.TestCase):
    """INV-GK-3 / INV-ADV-4: Disagree & Commit — advisory STEP 3 (equal expert,
    never defer to the human). Requires approve_advisory=True."""

    def test_protocol_contains_disagree_and_commit(self):
        with _patch_esc(), _patch_advisory(True):
            prompt = build_system_prompt()
        self.assertIn("DISAGREE & COMMIT", prompt)
        self.assertIn("equal expert", prompt)
        self.assertIn("never defer to the human", prompt)
        self.assertIn("The human does not outrank your risk assessment", prompt)

    def test_protocol_removes_no_autonomous_reject(self):
        with _patch_esc(), _patch_advisory(True):
            prompt = build_system_prompt()
        self.assertNotIn("NO Autonomous Reject", prompt)
        self.assertNotIn("wait for explicit human instructions", prompt)


class TestApproveAdvisoryDirectiveBranch(unittest.TestCase):
    """INV-ADV-1/3: default (approve_advisory=False) — the human /approve|/reject
    is a binding DIRECTIVE: execute, no second-guessing, no advisory markers."""

    def test_default_directive_semantics(self):
        with _patch_esc(), _patch_advisory(False):
            prompt = build_system_prompt()
        self.assertIn("HUMAN DIRECTIVE", prompt)
        self.assertIn("EXECUTE it", prompt)
        self.assertIn("Do NOT second-guess", prompt)
        self.assertIn("INDEPENDENT confirmation", prompt)
        self.assertIn("call `approve_escalation`", prompt)
        self.assertIn("call `reject_escalation`", prompt)

    def test_default_has_no_advisory_markers(self):
        with _patch_esc(), _patch_advisory(False):
            prompt = build_system_prompt()
        self.assertNotIn("DISAGREE & COMMIT", prompt)
        self.assertNotIn("ADVISORY OPINION", prompt)


class TestApproveAdvisoryAdvisoryBranch(unittest.TestCase):
    """INV-ADV-4: approve_advisory=True — Disagree & Commit (advisory opinion);
    the directive markers must be absent."""

    def test_advisory_semantics(self):
        with _patch_esc(), _patch_advisory(True):
            prompt = build_system_prompt()
        self.assertIn("DISAGREE & COMMIT", prompt)
        self.assertIn("ADVISORY OPINION", prompt)
        self.assertIn("never a directive", prompt)

    def test_advisory_has_no_directive_markers(self):
        with _patch_esc(), _patch_advisory(True):
            prompt = build_system_prompt()
        self.assertNotIn("HUMAN DIRECTIVE", prompt)


class TestApproveAdvisoryConfigRoundtrip(unittest.TestCase):
    """INV-ADV-1: persisted guard_config key `approve_advisory` — default False,
    set True -> get True, set False -> get False."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_approve_advisory_config_roundtrip(self):
        # default False (missing key -> _APPROVE_ADVISORY_DEFAULT)
        self.assertFalse(get_approve_advisory_config())
        # set True -> get True
        self.assertTrue(set_approve_advisory_config(True))
        self.assertTrue(get_approve_advisory_config())
        # set False -> get False
        self.assertFalse(set_approve_advisory_config(False))
        self.assertFalse(get_approve_advisory_config())


class TestGatekeeperPromptReadOnlyMode(unittest.TestCase):
    """INV-GK-6/7 / INV-ADV-7: question non-adjudication — else-branch untouched
    and disjoint (no new markers)."""

    def test_no_adjudication_mode_preserved(self):
        with _patch_esc():
            prompt = build_system_prompt(allow_adjudication=False)
        self.assertIn("NO ADJUDICATION", prompt)
        self.assertNotIn("DISAGREE & COMMIT", prompt)
        self.assertNotIn("HUMAN DIRECTIVE", prompt)
        self.assertNotIn("PRE-COMPLEXITY/RISK BRIEFING", prompt)


class TestCloudJudgeSystemPrompt(unittest.TestCase):
    """Cloud-judge prompt decomposition + anti-rubber-stamp JSON contract.
    INV-ADV-5: unaffected — none of the new gatekeeper markers may leak."""

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

    def test_cloud_judge_unaffected_by_advisory_markers(self):
        for marker in _ADVISORY_MARKERS:
            self.assertNotIn(marker, GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()
