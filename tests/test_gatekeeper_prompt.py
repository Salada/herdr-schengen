#!/usr/bin/env python3
"""Tests for the advisory-only gatekeeper prompt redesign.

Verifies:
1. The adjudication protocol is the single unconditional ADVISORY SECURITY
   REVIEW PROTOCOL: STEP 0 risk briefing, STEP 1 investigation, STEP 2 triage
   (Tier A / B / C + OBVIOUS-SAFE FORM), STEP 3 HUMAN DIRECTIVE (always
   binding, never override), STEP 4 feedback format.
2. `decision_layer` is surfaced in the CURRENT ACTIVE ESCALATION TARGET block.
3. Multi-line `raw_command` renders in a fenced code block (single-line stays
   in an inline backtick span).
4. Old protocol phrases are absent: `Defer or reject`, `The human does not
   outrank`, Disagree & Commit markers, approve_advisory config references.
5. Read-only interpretation mode (allow_adjudication=False) is untouched and
   disjoint (no new markers).
6. Cloud-judge prompt unaffected (none of the new markers leak).
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
    "decision_layer": "GRAY_ZONE",
}

# Markers introduced by the advisory-only redesign. None of them may leak into
# the cloud-judge prompt or the read-only branch.
_ADVISORY_MARKERS = (
    "ADVISORY SECURITY REVIEW",
    "TRIAGE",
    "Tier A",
    "OBVIOUS-SAFE FORM",
    "NO AUTONOMOUS REJECT",
    "never override",
)

# Old protocol phrases that must be GONE from the adjudication prompt.
_OLD_MARKERS = (
    "Defer or reject",
    "The human does not outrank",
    "DISAGREE & COMMIT",
    "ADVISORY OPINION",
    "approve_advisory",
    "PRE-COMPLEXITY/RISK BRIEFING",
    "ANTI-RUBBER-STAMP",
)


def _patch_esc(esc=_ACTIVE_ESC):
    return patch("tools.schengen_agent_llm.get_current_command_escalation", return_value=esc)


class TestGatekeeperAdvisoryProtocol(unittest.TestCase):
    """The adjudication prompt is the single unconditional advisory protocol."""

    def test_protocol_contains_advisory_markers(self):
        with _patch_esc():
            prompt = build_system_prompt()
        for marker in (
            "ADVISORY SECURITY REVIEW",
            "STEP 0 — RISK BRIEFING",
            "CHAINED SEGMENTS",
            "MUTATIONS",
            "NETWORK EGRESS",
            "SENSITIVE PATHS",
            "SUBSTITUTIONS",
            "STEP 1 — INVESTIGATION",
            "STEP 2 — TRIAGE",
            "STEP 3 — HUMAN DIRECTIVE",
            "STEP 4 — FEEDBACK FORMAT",
        ):
            self.assertIn(marker, prompt)

    def test_protocol_contains_tier_a_b_c(self):
        with _patch_esc():
            prompt = build_system_prompt()
        self.assertIn("Tier A — UNAMBIGUOUS CRITICAL", prompt)
        self.assertIn("Tier B — OBVIOUS-SAFE", prompt)
        self.assertIn("Tier C — GRAY-ZONE / AMBIGUOUS / COMPLEX", prompt)
        self.assertIn("reject_escalation", prompt)
        self.assertIn("approve_escalation", prompt)

    def test_protocol_contains_obvious_safe_form(self):
        with _patch_esc():
            prompt = build_system_prompt()
        self.assertIn("OBVIOUS-SAFE FORM (Tier B) — closed, never weakens the denylist", prompt)
        self.assertIn("NOT_ALLOWLISTED", prompt)
        self.assertIn("git status|log|diff|show|branch|tag|remote -v", prompt)
        self.assertIn("denylist layer ALWAYS wins over obvious-safe", prompt)

    def test_protocol_human_directive_binding(self):
        with _patch_esc():
            prompt = build_system_prompt()
        self.assertIn("HUMAN DIRECTIVE (always binding — never override)", prompt)
        self.assertIn("never override", prompt)
        self.assertIn("Their expressed decision ALWAYS wins over your Tier A/B/C assessment", prompt)
        self.assertIn("ALWAYS wins", prompt)
        self.assertIn("free-text", prompt)
        self.assertIn("directive=true", prompt)
        self.assertIn("You do NOT override the human", prompt)
        self.assertIn("NO AUTONOMOUS REJECT", prompt)
        self.assertIn("Autonomous reject is permitted ONLY for Tier A", prompt)

    def test_protocol_no_autonomous_reject_tier_c(self):
        with _patch_esc():
            prompt = build_system_prompt()
        self.assertIn("do NOT call `reject_escalation` on your own judgment for any Tier-C command", prompt)
        self.assertIn("Autonomous APPROVAL of a proven-safe Tier-C command is permitted and encouraged", prompt)

    def test_protocol_approval_bias_tier_c(self):
        with _patch_esc():
            prompt = build_system_prompt()
        self.assertIn("Bias toward APPROVAL", prompt)
        self.assertIn("MAY autonomously call `approve_escalation`", prompt)
        self.assertIn("NEVER call `reject_escalation` on your own judgment", prompt)

    def test_protocol_advisory_report_not_a_gate(self):
        with _patch_esc():
            prompt = build_system_prompt()
        self.assertIn("It is NOT itself a verdict and NOT a gate", prompt)
        self.assertIn("do not use it to force a rejection", prompt)

    def test_protocol_step0_segments(self):
        with _patch_esc():
            prompt = build_system_prompt()
        self.assertIn("NONE | EXFIL | DEST | INT | AVAIL | PERS", prompt)
        self.assertIn("env-var expansion, dynamic payload injection", prompt)

    def test_old_phrases_absent(self):
        with _patch_esc():
            prompt = build_system_prompt()
        for marker in _OLD_MARKERS:
            self.assertNotIn(marker, prompt)


class TestGatekeeperTargetBlock(unittest.TestCase):
    """decision_layer surfaced; multiline raw_command fenced."""

    def test_decision_layer_surfaced(self):
        esc = dict(_ACTIVE_ESC, decision_layer="SHELL_CRITICAL")
        with _patch_esc(esc):
            prompt = build_system_prompt()
        self.assertIn("- Decision Layer: SHELL_CRITICAL", prompt)

    def test_decision_layer_unknown_when_missing(self):
        esc = {k: v for k, v in _ACTIVE_ESC.items() if k != "decision_layer"}
        with _patch_esc(esc):
            prompt = build_system_prompt()
        self.assertIn("- Decision Layer: UNKNOWN", prompt)

    def test_multiline_raw_command_renders_fenced(self):
        esc = dict(_ACTIVE_ESC, raw_command="echo a\nrm -rf /tmp/x\necho b")
        with _patch_esc(esc):
            prompt = build_system_prompt()
        self.assertIn("- Raw Command:\n```bash\n", prompt)
        self.assertIn("rm -rf /tmp/x", prompt)
        self.assertIn("\n```", prompt)
        self.assertNotIn("- Raw Command: `echo a", prompt)

    def test_singleline_raw_command_renders_inline(self):
        with _patch_esc():
            prompt = build_system_prompt()
        self.assertIn("- Raw Command: `rm -rf /tmp/test_dir`", prompt)

    def test_decision_layer_drives_triage_text(self):
        # Tier A layers are enumerated in the prompt (SHELL_CRITICAL etc.).
        with _patch_esc():
            prompt = build_system_prompt()
        for layer in ("SHELL_CRITICAL", "SECRET_GUARD", "SANDBOX_GUARD", "PYTHON_AST", "ORIGIN_GUARD"):
            self.assertIn(layer, prompt)


class TestGatekeeperHumanOpinionSurface(unittest.TestCase):
    """has_human_opinion is surfaced in the ACTIVE ESCALATION TARGET block so
    the gatekeeper can distinguish a genuine human directive from a
    hallucinated one (edge-case-7 / INV-HO-1 free-text parity)."""

    def test_human_opinion_recorded_true_surfaced(self):
        with _patch_esc(), patch(
            "tools.schengen_agent_llm.has_human_opinion", return_value=True
        ) as mock_ho:
            prompt = build_system_prompt()
        self.assertIn("- Human Opinion Recorded: True", prompt)
        mock_ho.assert_called_once_with(_ACTIVE_ESC["id"])

    def test_human_opinion_recorded_false_surfaced(self):
        with _patch_esc(), patch(
            "tools.schengen_agent_llm.has_human_opinion", return_value=False
        ) as mock_ho:
            prompt = build_system_prompt()
        self.assertIn("- Human Opinion Recorded: False", prompt)
        mock_ho.assert_called_once_with(_ACTIVE_ESC["id"])

    def test_human_opinion_surfaced_in_read_only_mode(self):
        # Question interpretation mode keeps the target block — the hint must
        # surface there too (adjudication capability is removed, not the info).
        with _patch_esc(), patch(
            "tools.schengen_agent_llm.has_human_opinion", return_value=True
        ):
            prompt = build_system_prompt(allow_adjudication=False)
        self.assertIn("- Human Opinion Recorded: True", prompt)

    def test_no_active_escalation_returns_without_human_opinion_line(self):
        # Early-return branch (no active escalation) must not call has_human_opinion.
        with _patch_esc(None), patch(
            "tools.schengen_agent_llm.has_human_opinion", return_value=True
        ) as mock_ho:
            prompt = build_system_prompt()
        self.assertNotIn("Human Opinion Recorded", prompt)
        mock_ho.assert_not_called()


class TestGatekeeperPromptReadOnlyMode(unittest.TestCase):
    """Question non-adjudication: else-branch untouched and disjoint."""

    def test_no_adjudication_mode_preserved(self):
        with _patch_esc():
            prompt = build_system_prompt(allow_adjudication=False)
        self.assertIn("NO ADJUDICATION", prompt)
        self.assertIn("HUMAN QUESTION dialog", prompt)
        # None of the new advisory markers may leak into the read-only branch.
        for marker in _ADVISORY_MARKERS:
            self.assertNotIn(marker, prompt)
        # Old markers are gone everywhere.
        for marker in _OLD_MARKERS:
            self.assertNotIn(marker, prompt)


class TestCloudJudgeSystemPrompt(unittest.TestCase):
    """Cloud-judge prompt decomposition + JSON contract.
    Unaffected — none of the new gatekeeper markers may leak."""

    def test_prompt_contains_decomposition_and_json_contract(self):
        self.assertIn("DECOMPOSE", GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)
        self.assertIn("network egress", GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)
        self.assertIn("command substitutions", GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)
        self.assertIn("is_safe", GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)
        self.assertIn("confidence", GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)

    def test_cloud_judge_unaffected_by_advisory_markers(self):
        for marker in _ADVISORY_MARKERS:
            self.assertNotIn(marker, GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()
