"""Unit tests for Herdr Schengen Decision Layer Attribution and History CLI."""

import json
import os
import sys
import unittest
from pathlib import Path

# Add scripts directory to path
SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from security_evaluator import audit_shell_command, DecisionLayer
from guard_db import (
    init_db,
    record_audit_log,
    get_recent_audit_logs,
    search_audit_logs,
    get_state_file_paths,
    tail_state_log,
)


class TestDecisionLayers(unittest.TestCase):
    def setUp(self):
        init_db()

    def test_fast_track_layer(self):
        safe, reason, layer = audit_shell_command("ls -la /tmp")
        self.assertTrue(safe)
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

        safe, reason, layer = audit_shell_command("git status")
        self.assertTrue(safe)
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_shell_critical_layer(self):
        safe, reason, layer = audit_shell_command("rm -rf /")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL)

        safe, reason, layer = audit_shell_command("sudo su")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL)

        # macOS Disk & Partition destruction
        critical_macos_cmds = [
            "diskutil eraseVolume APFS Untitled disk3s1",
            "diskutil eraseDisk JHFS+ Backup /dev/disk4",
            "diskutil partitionDisk disk2 GPT APFS Data 0b",
            "diskutil apfs deleteVolume disk3s5",
            "diskutil apfs deleteContainer disk3",
            "diskutil zeroDisk disk2",
            "newfs_apfs -v Test /dev/rdisk3s2",
            "newfs_hfs -v Macintosh /dev/rdisk2s1",
            "gpt destroy /dev/disk3",
            "asr restore --source /tmp/img.dmg --target /Volumes/Untitled --erase",
            "tmutil deletelocalsnapshots 2026-08-19-120000",
            "csrutil disable",
            "spctl --master-disable",
            "bputil -k",
            "nvram -c",
            "bless --mount /Volumes/OS --setBoot",
            "dscl . -delete /Users/testuser",
            "sysadminctl -deleteUser admin2",
            "security delete-keychain login.keychain",
            "security delete-generic-password -s myapp",
            "pfctl -d",
            "networksetup -removeallnetworkservices",
        ]
        for cmd in critical_macos_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' to be blocked as critical, but got safe={safe}")
            self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL, f"Expected SHELL_CRITICAL layer for '{cmd}'")

    def test_macos_safe_commands_allowed(self):
        safe_macos_cmds = [
            "diskutil list",
            "diskutil info /dev/disk1s1",
            "diskutil rename disk3s1 BackupDrive",
            "tmutil listlocalsnapshots /",
            "csrutil status",
            "spctl --status",
            "nvram -p",
            "defaults read com.apple.finder",
            "feedback_survey_skip",
            "edit_file /Users/kyjbusan/.local/share/chezmoi/dot_zshenv.tmpl",
            "create_file /Users/kyjbusan/.local/share/chezmoi/docs/adr/ADR-003-destructive-intent.md",
            'git -C ~/.local/share/chezmoi commit -m "fix(zshenv): fix template whitespace newline rendering for secrets"',
        ]
        for cmd in safe_macos_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertTrue(safe, f"Expected '{cmd}' to be allowed, but got blocked: {reason}")
            self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_sandbox_guard_layer(self):
        safe, reason, layer = audit_shell_command("echo 'hack' > ~/.hermes/sandboxes/docker/default/home/exploit.sh")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SANDBOX_GUARD)

        safe, reason, layer = audit_shell_command("cp malware.sh ~/.hermes/sandboxes/docker/default/home/")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SANDBOX_GUARD)

    def test_secret_guard_layer(self):
        safe, reason, layer = audit_shell_command("cat ~/.ssh/id_rsa")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SECRET_GUARD)

        safe, reason, layer = audit_shell_command("grep AWS_KEY .env")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SECRET_GUARD)

    def test_python_ast_layer(self):
        safe, reason, layer = audit_shell_command("python3 -c \"eval('__import__(\\'os\\')')\"")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.PYTHON_AST)

        safe, reason, layer = audit_shell_command("python3 -c \"import socket; s = socket.socket()\"")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.PYTHON_AST)

    def test_gray_zone_layer(self):
        # Truncate unversioned file in gray zone
        safe, reason, layer = audit_shell_command("> ~/.local/state/important.db")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.GRAY_ZONE_MATRIX)

    def test_managed_git_guard_layer(self):
        # 1. Forgejo GET is allowed, DELETE is blocked
        safe, reason, layer = audit_shell_command("curl http://192.168.10.102:3000/api/v1/repos/Org/repo/issues")
        self.assertTrue(safe)
        self.assertEqual(layer, DecisionLayer.MANAGED_GIT_GUARD)

        safe, reason, layer = audit_shell_command("curl -X DELETE http://192.168.10.102:3000/api/v1/repos/Org/repo")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.MANAGED_GIT_GUARD)

        # 2. GitHub API GET is allowed, DELETE is blocked
        safe, reason, layer = audit_shell_command("curl https://api.github.com/repos/owner/repo/issues")
        self.assertTrue(safe)
        self.assertEqual(layer, DecisionLayer.MANAGED_GIT_GUARD)

        safe, reason, layer = audit_shell_command("curl -X DELETE https://api.github.com/repos/owner/repo")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.MANAGED_GIT_GUARD)

        # 3. GitLab API GET is allowed, DELETE is blocked
        safe, reason, layer = audit_shell_command("curl https://gitlab.com/api/v4/projects/123/issues")
        self.assertTrue(safe)
        self.assertEqual(layer, DecisionLayer.MANAGED_GIT_GUARD)

        safe, reason, layer = audit_shell_command("curl -X DELETE https://gitlab.com/api/v4/projects/123/issues/45")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.MANAGED_GIT_GUARD)

        # 4. Gitea API GET is allowed, DELETE is blocked
        safe, reason, layer = audit_shell_command("curl https://gitea.example.com/api/v1/repos/org/repo/issues")
        self.assertTrue(safe)
        self.assertEqual(layer, DecisionLayer.MANAGED_GIT_GUARD)

        safe, reason, layer = audit_shell_command("curl -X DELETE https://gitea.example.com/api/v1/repos/org/repo/issues/45")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.MANAGED_GIT_GUARD)


class TestHistoryAndDiagnostics(unittest.TestCase):
    def setUp(self):
        init_db()

    def test_record_and_retrieve_audit_logs(self):
        test_cmd = "echo 'testing schengen layer tracking'"
        record_audit_log(
            pane_id="wT:p9",
            raw_command=test_cmd,
            decision="AUTO_APPROVED",
            safety_reason="Unit test pass",
            agent_kind="agy",
            decision_layer=DecisionLayer.FAST_TRACK_AST,
        )

        logs = get_recent_audit_logs(limit=5, pane_id="wT:p9")
        self.assertTrue(len(logs) > 0)
        self.assertEqual(logs[0]["raw_command"], test_cmd)
        self.assertEqual(logs[0]["decision_layer"], DecisionLayer.FAST_TRACK_AST)

    def test_search_audit_logs(self):
        unique_marker = "unique_unit_test_probe_xyz_123"
        record_audit_log(
            pane_id="wT:p9",
            raw_command=f"echo '{unique_marker}'",
            decision="AUTO_APPROVED",
            safety_reason="Search test",
            agent_kind="agy",
            decision_layer=DecisionLayer.FAST_TRACK_AST,
        )

        results = search_audit_logs(unique_marker, limit=5)
        self.assertTrue(len(results) >= 1)
        self.assertIn(unique_marker, results[0]["raw_command"])

    def test_get_state_file_paths(self):
        paths = get_state_file_paths()
        self.assertIn("db_path", paths)
        self.assertIn("state_dir", paths)
        self.assertIn("lock_file", paths)
        self.assertIn("log_file", paths)

    def test_tail_state_log(self):
        # Should return a list without error
        lines = tail_state_log(lines=5)
        self.assertIsInstance(lines, list)

    def test_scoped_lock_naming_and_path(self):
        from schengen_watcher import get_lock_file_path, sanitize_target_name
        self.assertEqual(sanitize_target_name("wS:pF"), "wS_pF")
        self.assertEqual(sanitize_target_name("auto"), "auto")
        self.assertEqual(sanitize_target_name("tab/pane-1"), "tab_pane-1")

        lock_auto = get_lock_file_path("auto")
        self.assertTrue(str(lock_auto).endswith("schengen_auto.lock"))

        lock_pane = get_lock_file_path("wS:pF")
        self.assertTrue(str(lock_pane).endswith("schengen_wS_pF.lock"))

    def test_graceful_reload_execution(self):
        from schengen_watcher import execute_graceful_reload
        # Calling execute_graceful_reload() should succeed without throwing exceptions
        try:
            execute_graceful_reload()
            reloaded = True
        except Exception as e:
            reloaded = False
        self.assertTrue(reloaded)

    def test_new_file_creation_in_git_repo_fast_track(self):
        """Verify that creating a new file in a git repo via redirection (cat << 'EOF' > new_file) is classified as T2 Fast-Track."""
        repo_root = Path(__file__).resolve().parent.parent
        target_file = repo_root / "docs" / "adr-999-unit-test-creation.md"
        cmd = f"cat << 'EOF' > {target_file}\n# Test ADR\nEOF"
        safe, reason, layer = audit_shell_command(cmd)
        self.assertTrue(safe, f"Expected safe for git repo file creation, got: {reason}")
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_escalation_queue_lifecycle_and_cleanup(self):
        from guard_db import (
            enqueue_pending_escalation,
            get_pending_escalations,
            mark_escalation_delivered,
            resolve_escalation,
            cleanup_escalations,
        )
        test_pane = "wTest:p1"
        test_cmd = "rm -rf /untrusted/test/danger"

        # 1. Enqueue with session_id
        test_session_uuid = "test-session-uuid-12345"
        esc_id = enqueue_pending_escalation(
            pane_id=test_pane,
            raw_command=test_cmd,
            safety_reason="Unit test risk detection",
            decision_layer="SHELL_CRITICAL",
            agent_kind="agy",
            session_id=test_session_uuid,
        )
        self.assertIsInstance(esc_id, int)

        # 2. Query pending with matching active_session_map
        active_map_matching = {test_pane: test_session_uuid}
        pending = get_pending_escalations(pane_id=test_pane, active_session_map=active_map_matching)
        self.assertTrue(len(pending) >= 1)
        target_item = next((item for item in pending if item["pane_id"] == test_pane), None)
        self.assertIsNotNone(target_item)
        self.assertEqual(target_item["status"], "PENDING")
        self.assertEqual(target_item.get("session_id"), test_session_uuid)
        self.assertIn("started_at", target_item)
        self.assertIn("last_transitioned_at", target_item)

        # 2b. Test Recycled Pane (Mismatched session UUID -> auto-filtered as SESSION_MISMATCH)
        active_map_recycled = {test_pane: "different-new-session-uuid-9999"}
        pending_recycled = get_pending_escalations(pane_id=test_pane, active_session_map=active_map_recycled)
        self.assertEqual(len(pending_recycled), 0)

        # 3. Re-enqueue for delivery test
        esc_id2 = enqueue_pending_escalation(
            pane_id=test_pane,
            raw_command=test_cmd,
            safety_reason="Unit test risk detection 2",
            decision_layer="SHELL_CRITICAL",
            agent_kind="agy",
            session_id=test_session_uuid,
        )
        delivered_list = get_pending_escalations(pane_id=test_pane, include_delivered=True, active_session_map=active_map_matching)
        target_item2 = next((item for item in delivered_list if item["id"] == esc_id2), None)
        self.assertIsNotNone(target_item2)

        # 4. Mark delivered
        mark_escalation_delivered(target_item2["id"])
        del_list = get_pending_escalations(pane_id=test_pane, include_delivered=True, active_session_map=active_map_matching)
        del_item = next((item for item in del_list if item["id"] == target_item2["id"]), None)
        self.assertIsNotNone(del_item)
        self.assertEqual(del_item["status"], "DELIVERED")
        self.assertIsNotNone(del_item["delivered_at"])

        # 5. Resolve / ACK
        resolve_escalation(pane_id=test_pane, escalation_id=target_item2["id"])
        pending_after_res = get_pending_escalations(pane_id=test_pane, active_session_map=active_map_matching)
        self.assertFalse(any(item["id"] == target_item2["id"] for item in pending_after_res))

        # 6. Cleanup / Purge
        cleaned = cleanup_escalations(pane_id=test_pane, new_status="CANCELLED")
        self.assertIsInstance(cleaned, int)

    def test_2d_taxonomy_emission(self):
        """Verify that audit_shell_command_with_taxonomy correctly extracts 2D taxonomy."""
        from security_evaluator import (
            audit_shell_command_with_taxonomy,
            Origin,
            Consequence,
            GateState,
        )

        # 1. Critical destructive command -> Consequence.DESTRUCTION
        safe_crit, reason_crit, layer_crit, tax_crit = audit_shell_command_with_taxonomy("rm -rf /")
        self.assertFalse(safe_crit)
        self.assertEqual(tax_crit["origin"], Origin.AGENT.value)
        self.assertEqual(tax_crit["consequence"], Consequence.DESTRUCTION.value)
        self.assertEqual(tax_crit["mechanism"], "rm-rf")
        self.assertEqual(tax_crit["gate_state"], GateState.ENFORCE.value)
        self.assertFalse(tax_crit["shadow_mode"])

        # 2. Secret reading -> Consequence.EXFILTRATION
        safe_sec, reason_sec, layer_sec, tax_sec = audit_shell_command_with_taxonomy("cat .env")
        self.assertFalse(safe_sec)
        self.assertEqual(tax_sec["consequence"], Consequence.EXFILTRATION.value)
        self.assertEqual(tax_sec["mechanism"], "secret-path")

        # 3. Benign command -> Consequence.NONE
        safe_ok, reason_ok, layer_ok, tax_ok = audit_shell_command_with_taxonomy("git status")
        self.assertTrue(safe_ok)
        self.assertEqual(tax_ok["consequence"], Consequence.NONE.value)
        self.assertEqual(tax_ok["mechanism"], "fast-track-verified")

    def test_shadow_mode_kill_switch(self):
        """Verify that SCHENGEN_SHADOW_MODE=1 allows execution while logging counterfactual block."""
        from security_evaluator import audit_shell_command_with_taxonomy, GateState

        old_env = os.environ.get("SCHENGEN_SHADOW_MODE")
        try:
            os.environ["SCHENGEN_SHADOW_MODE"] = "1"
            safe_shadow, reason_shadow, layer_shadow, tax_shadow = audit_shell_command_with_taxonomy("rm -rf /")
            # In shadow mode, dangerous command must return is_safe=True to allow pass-through
            self.assertTrue(safe_shadow)
            self.assertIn("Counterfactual BLOCK", reason_shadow)
            self.assertEqual(tax_shadow["gate_state"], GateState.OBSERVE.value)
            self.assertTrue(tax_shadow["shadow_mode"])
            self.assertTrue(tax_shadow["counterfactual_block"])
        finally:
            if old_env is not None:
                os.environ["SCHENGEN_SHADOW_MODE"] = old_env
            else:
                os.environ.pop("SCHENGEN_SHADOW_MODE", None)

    def test_guard_db_taxonomy_columns_and_idempotency(self):
        """Verify SQLite3 schema includes 2D taxonomy and record_audit_log stores it."""
        from guard_db import record_audit_log, get_recent_audit_logs, get_db_connection

        test_pane = "wTest:pTax"
        test_cmd = "rm -rf /tmp/test_taxonomy_target"
        record_audit_log(
            pane_id=test_pane,
            raw_command=test_cmd,
            decision="SHADOW_BLOCKED",
            safety_reason="Unit test counterfactual shadow block",
            agent_kind="agy",
            decision_layer="SHELL_CRITICAL",
            origin="A",
            consequence="DEST",
            mechanism="rm-rf",
            gate_state="OBSERVE",
            shadow_mode=True,
        )

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT origin, consequence, mechanism, gate_state, shadow_mode FROM audit_logs WHERE pane_id = ? ORDER BY id DESC LIMIT 1", (test_pane,))
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["origin"], "A")
            self.assertEqual(row["consequence"], "DEST")
            self.assertEqual(row["mechanism"], "rm-rf")
            self.assertEqual(row["gate_state"], "OBSERVE")
            self.assertEqual(row["shadow_mode"], 1)


if __name__ == "__main__":
    unittest.main()
