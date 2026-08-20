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


if __name__ == "__main__":
    unittest.main()
