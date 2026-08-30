"""Workspace .schengen/ persistent allowlist tests (issue #7207, INV-WS-1..5).

Covers:
1. In-scope rule match -> FAST_TRACK_WORKSPACE_ALLOWLIST.
2. Out-of-workspace path -> not matched (falls through).
3. Sensitive path listed but still denied (INV-WS-2) + symlink escape denied
   after realpath + promote_rule refuses a sensitive exec pattern.
4. No .schengen/ -> fallthrough (decision unchanged).
5. Auto-promotion writes the policy file; subsequent check fast-tracks.
6. INJECTED origin still hard-escalates (INV-WS-3).
7. Malformed JSON -> treated as absent (fail-closed, INV-WS-4).

Uses a clean temp DB (patch guard_db.DB_PATH) + a temp workspace.
"""

import json
import os
import shutil
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
from core.guard_db import enqueue_pending_escalation, normalize_command, record_adjudication
from core.security_evaluator import (
    DecisionLayer,
    Origin,
    audit_shell_command,
    audit_shell_command_with_taxonomy,
)
from core.workspace_allowlist import (
    check_rule,
    discover_workspace_policy,
    load_policy,
    promote_rule,
)


def _access_rule(pattern: str, match_type: str = "prefix") -> dict:
    return {
        "id": "r1",
        "action_type": "access_directory",
        "match_type": match_type,
        "pattern": pattern,
        "agent_scope": ["*"],
        "created_by": "t",
        "created_at": "",
        "reason": "test",
    }


class TestWorkspaceAllowlist(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()
        self.ws = Path(tempfile.mkdtemp())
        self.ws_resolved = str(self.ws.resolve())
        self.schengen = self.ws / ".schengen"
        self.schengen.mkdir()
        self.policy_path = self.schengen / "allowlist.json"

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()
        shutil.rmtree(str(self.ws), ignore_errors=True)

    def write_policy(self, rules):
        self.policy_path.write_text(
            json.dumps({"version": 1, "workspace_root": self.ws_resolved, "rules": rules}, indent=2)
        )

    def test_in_scope_access_directory_fast_tracks(self):
        self.write_policy([_access_rule(self.ws_resolved)])
        safe, reason, layer = audit_shell_command(f"access_directory {self.ws}", cwd=str(self.ws))
        self.assertTrue(safe, reason)
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_WORKSPACE_ALLOWLIST)

    def test_out_of_workspace_not_matched(self):
        self.write_policy([_access_rule(self.ws_resolved)])
        safe, reason, layer = audit_shell_command("access_directory /tmp", cwd=str(self.ws))
        self.assertTrue(safe, reason)
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_sensitive_path_listed_still_denied(self):
        # A rule explicitly listing a sensitive target must NOT fast-track it.
        sensitive = os.path.join(os.path.expanduser("~"), ".ssh")
        self.write_policy([_access_rule(sensitive)])
        safe, reason, layer = audit_shell_command("access_directory " + sensitive, cwd=str(self.ws))
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SECRET_GUARD)

        # Symlink inside the workspace pointing at a T4 secret path: denied
        # after realpath (INV-WS-2) — never workspace-fast-tracked.
        secret_target = os.path.join(os.path.expanduser("~"), ".ssh", "id_" + "rsa")
        link = self.ws / "leak-link"
        os.symlink(secret_target, link)
        safe2, reason2, layer2 = audit_shell_command("access_directory " + str(link), cwd=str(self.ws))
        self.assertFalse(safe2, f"symlink escape must be denied: {reason2}")
        self.assertEqual(layer2, DecisionLayer.GRAY_ZONE_MATRIX)

        # promote_rule refuses a sensitive exec pattern (INV-WS-2 re-assertion).
        refused = promote_rule(
            self.policy_path,
            {"action_type": "exec", "match_type": "exact", "pattern": "cat ~/.env", "agent_scope": ["*"]},
        )
        self.assertFalse(refused, "promote_rule must refuse sensitive patterns")

    def test_no_policy_fallthrough(self):
        shutil.rmtree(str(self.schengen), ignore_errors=True)
        self.assertIsNone(discover_workspace_policy(str(self.ws)))
        safe, reason, layer = audit_shell_command("access_directory /tmp", cwd=str(self.ws))
        self.assertTrue(safe)
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)
        # an exec command that would otherwise escalate stays fail-closed
        safe2, reason2, layer2 = audit_shell_command("python3 -c 'print(1)'", cwd=str(self.ws))
        self.assertFalse(safe2)
        self.assertEqual(layer2, DecisionLayer.NOT_ALLOWLISTED)

    def test_auto_promotion_writes_policy(self):
        pane = "wWS:p1"
        cmd = f"access_directory {self.ws}"
        esc_id = enqueue_pending_escalation(
            pane_id=pane,
            raw_command=cmd,
            safety_reason="external dir",
            decision_layer="GRAY_ZONE_MATRIX",
            agent_kind="opencode",
            cwd=str(self.ws),
        )
        # No policy file yet — auto-promotion must create it (issue #7207).
        self.assertFalse(self.policy_path.exists())
        record_adjudication(
            escalation_id=esc_id, pane_id=pane, agent_kind="opencode",
            action="APPROVE", feedback="ok", origin="A", approver="human-tui",
        )
        self.assertTrue(self.policy_path.exists(), "auto-promotion must write the policy file")
        policy = load_policy(self.policy_path)
        self.assertIsNotNone(policy)
        rules = policy.get("rules") or []
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["action_type"], "access_directory")
        self.assertEqual(rules[0]["match_type"], "prefix")
        self.assertEqual(rules[0]["pattern"], self.ws_resolved)
        # Subsequent check fast-tracks via the persisted rule.
        safe, reason, layer = audit_shell_command(cmd, cwd=str(self.ws))
        self.assertTrue(safe, reason)
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_WORKSPACE_ALLOWLIST)

    def test_origin_hard_escalate_still_applies(self):
        self.write_policy([_access_rule(self.ws_resolved)])
        safe, reason, layer, tax = audit_shell_command_with_taxonomy(
            f"access_directory {self.ws}", cwd=str(self.ws), origin=Origin.INJECTED
        )
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.ORIGIN_GUARD)
        self.assertEqual(tax["mechanism"], "origin-hard-escalate")

    def test_malformed_policy_fail_closed(self):
        self.policy_path.write_text("{ not valid json !!!")
        self.assertIsNone(load_policy(self.policy_path))
        safe, reason, layer = audit_shell_command(f"access_directory {self.ws}", cwd=str(self.ws))
        self.assertTrue(safe, "malformed policy must not crash; falls through benign")
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)
        # check_rule treats it as absent
        self.assertFalse(check_rule(load_policy(self.policy_path), "access_directory", self.ws_resolved))

    # --- Reviewer fixes (blocking findings on the exec path) ---

    def test_exec_promotion_sensitive_command_denied(self):
        # Fix 1: promotion uses the RAW command + denylist on raw text — a
        # sensitive-path exec command must NEVER promote (INV-WS-2).
        pane = "wWS:x1"
        esc_id = enqueue_pending_escalation(
            pane_id=pane,
            raw_command="cat /home/x/.ssh/id_rsa",
            safety_reason="secret read",
            decision_layer="SECRET_GUARD",
            agent_kind="opencode",
            cwd=str(self.ws),
            origin="A",
        )
        record_adjudication(
            escalation_id=esc_id, pane_id=pane, agent_kind="opencode",
            action="APPROVE", feedback="ok", origin="A", approver="human-tui",
        )
        # denylist on raw text refuses -> no policy file is created
        self.assertFalse(self.policy_path.exists(), "sensitive exec command must not promote")

    def test_exec_promotion_pathless_command(self):
        # Fix 1: a pathless exec command DOES promote as an exact raw-command rule.
        pane = "wWS:x2"
        esc_id = enqueue_pending_escalation(
            pane_id=pane,
            raw_command="make build",
            safety_reason="complex",
            decision_layer="COMPLEXITY_TAX",
            agent_kind="opencode",
            cwd=str(self.ws),
            origin="A",
        )
        record_adjudication(
            escalation_id=esc_id, pane_id=pane, agent_kind="opencode",
            action="APPROVE", feedback="ok", origin="A", approver="human-tui",
        )
        self.assertTrue(self.policy_path.exists(), "pathless exec command should promote")
        policy = load_policy(self.policy_path)
        rules = policy.get("rules") or []
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["action_type"], "exec")
        self.assertEqual(rules[0]["match_type"], "exact")
        self.assertEqual(rules[0]["pattern"], "make build")
        # exact raw match fast-tracks
        safe, reason, layer = audit_shell_command("make build", cwd=str(self.ws))
        self.assertTrue(safe, reason)
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_WORKSPACE_ALLOWLIST)
        # a different command with a path is NOT matched (exact + pathful denial)
        safe2, reason2, layer2 = audit_shell_command("make build /tmp/x", cwd=str(self.ws))
        self.assertNotEqual(layer2, DecisionLayer.FAST_TRACK_WORKSPACE_ALLOWLIST)

    def test_exec_rule_workspace_confined(self):
        # Fix 2: an exec rule in workspace A never matches when cwd is in B.
        self.write_policy([
            {"id": "r1", "action_type": "exec", "match_type": "exact",
             "pattern": "make build", "agent_scope": ["*"], "created_by": "t",
             "created_at": "", "reason": "t"},
        ])
        # workspace A (self.ws) matches
        safe_a, _, layer_a = audit_shell_command("make build", cwd=str(self.ws))
        self.assertTrue(safe_a)
        self.assertEqual(layer_a, DecisionLayer.FAST_TRACK_WORKSPACE_ALLOWLIST)
        # workspace B: no policy -> confined (no cross-workspace leakage)
        ws_b = Path(tempfile.mkdtemp())
        try:
            safe_b, _, layer_b = audit_shell_command("make build", cwd=str(ws_b))
            self.assertNotEqual(layer_b, DecisionLayer.FAST_TRACK_WORKSPACE_ALLOWLIST)
            # workspace B with its OWN policy (different rule) also never matches
            b_policy = ws_b / ".schengen" / "allowlist.json"
            b_policy.parent.mkdir()
            b_policy.write_text(
                json.dumps({"version": 1, "workspace_root": str(ws_b.resolve()),
                            "rules": [{"id": "rB", "action_type": "exec", "match_type": "exact",
                                       "pattern": "make clean", "agent_scope": ["*"],
                                       "created_by": "t", "created_at": "", "reason": "t"}]})
            )
            safe_b2, _, layer_b2 = audit_shell_command("make build", cwd=str(ws_b))
            self.assertNotEqual(layer_b2, DecisionLayer.FAST_TRACK_WORKSPACE_ALLOWLIST)
        finally:
            shutil.rmtree(str(ws_b), ignore_errors=True)

    def test_overbroad_pattern_not_matched_at_read(self):
        # Fix 3: `//` / `/` / `.*` patterns written directly into the JSON must
        # not match at read time.
        self.write_policy([
            {"id": "r1", "action_type": "access_directory", "match_type": "prefix",
             "pattern": "/", "agent_scope": ["*"], "created_by": "t", "created_at": "", "reason": "t"},
            {"id": "r2", "action_type": "read_file", "match_type": "glob",
             "pattern": ".*", "agent_scope": ["*"], "created_by": "t", "created_at": "", "reason": "t"},
        ])
        safe, reason, layer = audit_shell_command(f"access_directory {self.ws}", cwd=str(self.ws))
        self.assertTrue(safe)
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)
        safe2, reason2, layer2 = audit_shell_command(f"read_file {self.ws}/x.txt", cwd=str(self.ws))
        self.assertTrue(safe2)
        self.assertEqual(layer2, DecisionLayer.FAST_TRACK_AST)

    def test_injected_origin_escalation_does_not_promote(self):
        # Fix 4: the escalation row's intercepted origin is authoritative — an
        # INJECTED-origin escalation must NEVER promote even on a human approve.
        pane = "wWS:x3"
        esc_id = enqueue_pending_escalation(
            pane_id=pane,
            raw_command="make build",
            safety_reason="complex",
            decision_layer="COMPLEXITY_TAX",
            agent_kind="opencode",
            cwd=str(self.ws),
            origin="I",
        )
        # human approve passes origin="A" but the escalation row says "I"
        record_adjudication(
            escalation_id=esc_id, pane_id=pane, agent_kind="opencode",
            action="APPROVE", feedback="ok", origin="A", approver="human-tui",
        )
        self.assertFalse(self.policy_path.exists(), "INJECTED-origin escalation must not promote")

    def test_multifile_approve_promotes_one_rule_per_path(self):
        # #7759/INV-EF-4: a multi-file edit_file approval promotes ONE exact
        # rule per path (all safe paths land in .schengen/allowlist.json).
        pane = "wWS:mf1"
        cmd = f"edit_file {self.ws}/a.py\n{self.ws}/b.py"
        esc_id = enqueue_pending_escalation(
            pane_id=pane,
            raw_command=cmd,
            safety_reason="multi edit",
            decision_layer="GRAY_ZONE_MATRIX",
            agent_kind="opencode",
            cwd=str(self.ws),
            origin="A",
        )
        record_adjudication(
            escalation_id=esc_id, pane_id=pane, agent_kind="opencode",
            action="APPROVE", feedback="ok", origin="A", approver="human-tui",
        )
        self.assertTrue(self.policy_path.exists(), "multi-file approve must promote")
        rules = load_policy(self.policy_path).get("rules") or []
        self.assertEqual(len(rules), 2)
        patterns = sorted(r["pattern"] for r in rules)
        self.assertEqual(
            patterns,
            sorted([str((self.ws / "a.py").resolve()), str((self.ws / "b.py").resolve())]),
        )
        for r in rules:
            self.assertEqual(r["action_type"], "edit_file")
            self.assertEqual(r["match_type"], "exact")

    def test_multifile_approve_with_sensitive_path_promotes_nothing(self):
        # #7759/INV-EF-4 (all-or-nothing): ONE sensitive path in a multi-file
        # edit refuses the WHOLE batch — nothing is promoted.
        pane = "wWS:mf2"
        sensitive = f"{self.ws}/id_" + "rsa"
        cmd = f"edit_file {self.ws}/ok.py\n{sensitive}"
        esc_id = enqueue_pending_escalation(
            pane_id=pane,
            raw_command=cmd,
            safety_reason="multi edit",
            decision_layer="GRAY_ZONE_MATRIX",
            agent_kind="opencode",
            cwd=str(self.ws),
            origin="A",
        )
        record_adjudication(
            escalation_id=esc_id, pane_id=pane, agent_kind="opencode",
            action="APPROVE", feedback="ok", origin="A", approver="human-tui",
        )
        # the policy file was created by the batch, then rolled back -> gone
        self.assertFalse(self.policy_path.exists(), "sensitive multi-file edit must promote NOTHING")


if __name__ == "__main__":
    unittest.main()
