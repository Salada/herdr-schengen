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
            action="APPROVE", feedback="ok", origin="A",
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


if __name__ == "__main__":
    unittest.main()
