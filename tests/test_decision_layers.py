"""Unit tests for Herdr Schengen Decision Layer Attribution and History CLI."""

import ast
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

# Add scripts directory to path
SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from core.security_evaluator import (
    DecisionLayer,
    Origin,
    _python_normalization_candidates,
    audit_python_code,
    audit_shell_command,
    audit_shell_command_with_taxonomy,
    compute_complexity,
)


def _try_parse(code: str) -> bool:
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


from core.guard_db import (
    get_recent_audit_logs,
    get_state_file_paths,
    init_db,
    record_audit_log,
    search_audit_logs,
    tail_state_log,
)

import core.guard_db as guard_db


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

        # Process listing that exposes environment variables (secret leakage)
        for ps_cmd in ("ps e", "ps auxe", "ps eww", "ps -wwE", "ps axeww"):
            safe, reason, layer = audit_shell_command(ps_cmd)
            self.assertFalse(safe, f"Expected '{ps_cmd}' to be blocked (env var leakage)")
            self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL)
        # Safe process listing (no env flag) — provably benign, but NOT in the
        # closed fast-track allowlist -> escalates (fail-closed) instead of
        # auto-approving via the removed catch-all (INV-1).
        for ps_cmd in ("ps -e", "ps aux", "ps auxww"):
            safe, reason, layer = audit_shell_command(ps_cmd)
            self.assertFalse(safe, f"Expected '{ps_cmd}' to escalate (fail-closed), got safe=True")
            self.assertEqual(layer, DecisionLayer.NOT_ALLOWLISTED)
        # Process environment file reads (Linux) and launchd env read
        for env_cmd in ("cat /proc/1234/environ", "strings /proc/*/environ", "launchctl getenv"):
            safe, reason, layer = audit_shell_command(env_cmd)
            self.assertFalse(safe, f"Expected '{env_cmd}' to be blocked (env var read)")
            self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL)

    def test_process_env_dump_denylist(self):
        # Genuine env-dump variants (Issue #51 gap) — must be blocked.
        blocked = [
            "ps e",
            "ps eww",
            "ps auxe",
            "ps axeww",
            "ps -wwE",
            "ps -wwE 1234",
            "ps -p 1234 eww",
            "launchctl getenv PATH",
            "launchctl getenv",
            "cat /proc/1234/environ",
            "strings /proc/*/environ",
            "cat /proc/$PPID/environ",
        ]
        for cmd in blocked:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' to be blocked (env dump), got safe=True")
            self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL, f"Expected SHELL_CRITICAL for '{cmd}'")

    def test_process_env_dump_no_false_positive(self):
        # Literal mentions of `ps eww` in non-command contexts must NOT trigger
        # the env-dump denylist (SHELL_CRITICAL). Commands that are still
        # provably benign (allowlisted) stay fast-tracked; everything else
        # escalates via NOT_ALLOWLISTED (fail-closed) instead of auto-approving
        # via the removed catch-all — but never via a denylist false positive.
        fast_track_allowed = [
            'echo "use ps eww to dump env vars"',
        ]
        escalated_not_denylisted = [
            "ps -e",
            "ps aux",
            "ps auxww",
            "ps -ef",
            # The `|` inside the quoted grep pattern is a literal alternation, not a
            # pipe; the naive INV-6 metachar check still escalates it (fail-closed,
            # conservative) — but never as an env-dump denylist false positive.
            "grep -rn 'auxe|eww|wwE|axeww|launchctl|/proc/|getenv|ps e' tests/",
            "git commit -m 'fix ps eww false positive in heredoc'",
            "cat > /tmp/handoff.txt <<'EOF'\n## Issue #51 — ps eww 프로세스 env 키 노출 수정\nEOF",
        ]
        for cmd in fast_track_allowed:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertTrue(safe, f"Expected '{cmd}' to be allowed (false positive), got: {reason}")
            self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)
        for cmd in escalated_not_denylisted:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' to escalate (fail-closed), got safe=True: {reason}")
            # M3 COMPLEXITY_TAX may intercept structurally-complex commands (e.g. the
            # quoted `|` alternation inflates the segment count) — still fail-closed,
            # still never an env-dump denylist false positive.
            self.assertIn(
                layer,
                (DecisionLayer.NOT_ALLOWLISTED, DecisionLayer.COMPLEXITY_TAX),
                f"Expected NOT_ALLOWLISTED/COMPLEXITY_TAX for '{cmd}', got {layer}",
            )

    def test_gpt_model_name_not_disk_command(self):
        # Regression: "gpt-4o-mini" (OpenAI model name) must not match the `gpt`
        # disk-partitioning tool. `git commit` is a write op, so it is no longer
        # auto-approved — it escalates via NOT_ALLOWLISTED (fail-closed), but
        # must NOT be flagged as SHELL_CRITICAL (no disk-tool false positive).
        safe, reason, layer = audit_shell_command('git commit -m "use gpt-4o-mini model"')
        self.assertFalse(safe, f"Expected git commit to escalate (fail-closed): {reason}")
        self.assertEqual(layer, DecisionLayer.NOT_ALLOWLISTED)
        safe, reason, layer = audit_shell_command("gpt destroy /dev/disk0")
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
            # Bitwarden CLI mass secret dump & irreversible vault destruction
            "bw list items",
            "bw list items --session $BW_SESSION",
            "bw --session $BW_SESSION list items",
            "bw --pretty list items",
            "bw --raw list items",
            "bw delete item 12345",
            "bw --session $BW_SESSION delete item abc-uuid",
            "bw delete item --permanent 12345",
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
            "git push -u origin feat/context-cache-and-minimal-prompt",
            "git push origin feat/allow-feature-branch-push",
            "git push origin fix/sc2154-unbound-var",
            "git push -u origin chore/update-deps",
            "git push origin refactor/security-evaluator",
            "git push origin test/feature-push",
            "git push origin docs/update-readme",
            "git push origin ci/runner-optimization",
            "git push origin wip/experiment-1",
            # Safe Bitwarden non-mass-dump operations
            "bw list folders",
            "bw list collections",
            "bw get item 12345",
            "bw sync",
            "bw unlock",
            "bw delete item-attachment 12345",
        ]
        # Under the fail-closed bias shift (INV-1/5), only commands on the
        # explicit closed allowlist are auto-approved (FAST_TRACK_AST). The
        # remaining commands are NOT denylisted (no false positive from the
        # critical/secret/sandbox guards) but escalate via NOT_ALLOWLISTED
        # instead of the removed fail-open catch-all.
        for cmd in safe_macos_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertIn(
                layer,
                (DecisionLayer.FAST_TRACK_AST, DecisionLayer.NOT_ALLOWLISTED),
                f"Expected no denylist false positive for '{cmd}', got layer={layer}: {reason}",
            )
            self.assertEqual(safe, layer == DecisionLayer.FAST_TRACK_AST, f"Safe flag mismatch for '{cmd}': {reason}")

    def test_git_push_safeguards(self):
        # 1. Safe Feature branch pushes -> FAST_TRACK_AST
        safe_pushes = [
            "git push -u origin feat/context-cache-and-minimal-prompt",
            "cd /Users/kyjbusan/code/herdr-schengen-worktrees/context-cache && git push origin feat/context-cache-and-minimal-prompt",
            "git push origin fix/test-bug",
            "git push -u origin chore/cleanup",
            "git push origin refactor/evaluator",
            "git push origin test/audit-suite",
            "git push origin docs/architecture",
            "git push origin custom-branch-123",
            # Regression: leaked opencode status bar (~/path:branch) must not match
            # the `:branch` remote-delete refspec, so a normal push stays safe.
            "cd ~/x && git push -u origin fix/27-28-cloud-judge-config-cache 2>&1 | tail -15 ~/code/herdr-schengen:main",
        ]
        # 1. Safe Feature branch pushes: NOT blocked by the push denylist, but
        #    `git push` is a write op absent from the read-only closed allowlist
        #    -> escalates via NOT_ALLOWLISTED (fail-closed), never SHELL_CRITICAL.
        for cmd in safe_pushes:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' to escalate (fail-closed), got safe=True: {reason}")
            self.assertEqual(layer, DecisionLayer.NOT_ALLOWLISTED, f"Expected NOT_ALLOWLISTED for '{cmd}', got {layer}")

        # 2. Blocked Dangerous Git Push scenarios -> SHELL_CRITICAL
        blocked_pushes = [
            ("git push --force origin feat/test", "force push"),
            ("git push -f origin feat/test", "force push"),
            ("git push origin +feat/test", "plus force refspec"),
            ("git push origin --delete feat/test", "remote delete flag"),
            ("git push origin :feat/test", "colon remote delete refspec"),
            ("git push --all origin", "all branches push"),
            ("git push --mirror origin", "mirror push"),
            ("git push --tags origin", "tags push"),
            ("git push origin main", "protected main branch"),
            ("git push -u origin master", "protected master branch"),
            ("git push origin develop", "protected develop branch"),
            ("git push origin release/v1.0", "protected release branch"),
            ("git push origin prod", "protected prod branch"),
            ("git push origin production", "protected production branch"),
            ("git push origin HEAD:main", "protected HEAD:main refspec"),
        ]
        for cmd, label in blocked_pushes:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' ({label}) to be blocked as critical, but got safe={safe}")
            self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL)

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

        safe, reason, layer = audit_shell_command('python3 -c "import socket; s = socket.socket()"')
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.PYTHON_AST)

    def test_python_ast_normalization_dedent_issue22(self):
        # Issue #22 regression: leading whitespace indentation on multi-line
        # inline python (TUI/AGY captured) must not fail-closed as SyntaxError.
        code = (
            "\n import json\n"
            " d=json.load(open('/Users/kyjbusan/.local/share/chezmoi/dot_agents/dot_skill-lock.json'))\n"
            " print('source hash:', d.get('skillFolderHash'))\n"
        )
        safe, reason = audit_python_code(code)
        self.assertTrue(safe, f"Expected dedent-normalized safe code, got blocked: {reason}")

    def test_python_ast_normalization_candidates(self):
        # _python_normalization_candidates must include dedent and a parseable variant
        code = "\n import json\n d = {}\n print(d)\n"
        cands = _python_normalization_candidates(code)
        self.assertIn(textwrap.dedent(code), cands)
        parsed = any(True for c in cands if _try_parse(c))
        self.assertTrue(parsed, "No normalization candidate parsed the indented python")

    def test_python_heredoc_variants_captured(self):
        # Bypass regressions: heredoc forms that were previously not AST-audited.
        # Dangerous inline python via no-dash heredoc must now be blocked.
        for cmd in (
            "python3 <<EOF\nimport socket; s=socket.socket()\nEOF",
            "python3 <<-EOF\n\timport socket; s=socket.socket()\n\tEOF",
            "python3 - <<EOF\nimport socket; s=socket.socket()\nEOF",
        ):
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' blocked, got safe={safe}: {reason}")
            self.assertEqual(layer, DecisionLayer.PYTHON_AST, f"Expected PYTHON_AST for '{cmd}'")

    def test_python_dash_c_no_space_captured(self):
        # python3 -c"..." (no space) previously bypassed the -c capture.
        safe, reason, layer = audit_shell_command('python3 -c"import socket; s=socket.socket()"')
        self.assertFalse(safe, f'Expected -c"..." blocked, got safe={safe}: {reason}')
        self.assertEqual(layer, DecisionLayer.PYTHON_AST)

    def test_python_dash_c_escaped_quote_not_truncated(self):
        # python3 -c "print(\"hi\")" previously truncated the capture at the escaped
        # quote (fail-closed SyntaxError); the AST guard must NOT block it. Under
        # the fail-closed bias shift it escalates via NOT_ALLOWLISTED (python3 not
        # on the closed allowlist) instead of auto-approving via the catch-all.
        safe, reason, layer = audit_shell_command('python3 -c "print(\\"hi\\")"')
        self.assertFalse(safe, f"Expected escaped-quote python to escalate (fail-closed), got safe=True: {reason}")
        self.assertEqual(layer, DecisionLayer.NOT_ALLOWLISTED)

    def test_python_split_token_normalization_fail_closed(self):
        # Split-token evasions: a dangerous identifier fragmented across a newline
        # must remain fail-closed (blocked), not reconstructed into a benign AST by
        # a normalization candidate (per_line_stripped regression / dedent variant).
        for cmd in (
            'python3 <<EOF\n    __impor\nt__("os").system("id")\nEOF',
            'python3 <<EOF\n    ex\nec("import os; os.system(\\"id\\")")\nEOF',
            'python3 <<EOF\n    __impor\n    t__("os").system("id")\nEOF',
            "python3 <<EOF\n    import sock\n    et\nEOF",
        ):
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected split-token '{cmd}' blocked, got safe={safe}: {reason}")
            self.assertEqual(layer, DecisionLayer.PYTHON_AST, f"Expected PYTHON_AST for split-token '{cmd}'")

    def test_python_compact_guard_no_false_positive(self):
        # The whitespace-insensitive dangerous-token guard must NOT block benign
        # code: string/comment literals mentioning dangerous terms, and module
        # names with a dangerous prefix (socketio, urllib3, httpclient).
        # `python3` is not in the closed fast-track allowlist, so benign inline
        # python now escalates via NOT_ALLOWLISTED (fail-closed) — but never as
        # a PYTHON_AST false positive.
        for cmd in (
            'python3 -c "print(\\"import socket\\")"',
            'python3 -c "s = \\"exec(\\""',
            'python3 -c "import socketio"',
            'python3 -c "import urllib3"',
            'python3 -c "import httpclient"',
        ):
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected benign '{cmd}' to escalate (fail-closed), got safe=True: {reason}")
            self.assertEqual(layer, DecisionLayer.NOT_ALLOWLISTED)

    def test_dialog_leading_whitespace_normalized(self):
        # Cross-layer: leading whitespace on dialog commands must still dispatch.
        safe, reason, layer = audit_shell_command("   edit_file /tmp/notes.txt")
        self.assertTrue(safe, f"Expected leading-space edit_file allowed, got blocked: {reason}")

        safe, reason, layer = audit_shell_command("   read_file ~/.ssh/id_rsa")
        self.assertFalse(safe, f"Expected leading-space read_file of secrets blocked, got safe: {reason}")
        self.assertEqual(layer, DecisionLayer.SECRET_GUARD)

    def test_gray_zone_layer(self):
        # Truncate unversioned file in gray zone
        safe, reason, layer = audit_shell_command("> ~/.local/state/important.db")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.GRAY_ZONE_MATRIX)

    def test_external_directory_access_layer(self):
        # Safe ephemeral directory -> allowed
        safe, reason, layer = audit_shell_command("access_directory /tmp")
        self.assertTrue(safe, f"Expected /tmp access allowed, got: {reason}")
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

        # Sensitive directory -> SECRET_GUARD
        safe, reason, layer = audit_shell_command("access_directory ~/.ssh")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SECRET_GUARD)

        safe, reason, layer = audit_shell_command("access_directory ~/.aws")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SECRET_GUARD)

        safe, reason, layer = audit_shell_command("access_directory ~/.config/gh")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SECRET_GUARD)

        # OpenCode config/plugin dir is NOT a secret store -> allowed (issue #54)
        safe, reason, layer = audit_shell_command("access_directory ~/.config/opencode/plugins")
        self.assertTrue(safe, f"Expected ~/.config/opencode/plugins allowed, got: {reason}")
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

        safe, reason, layer = audit_shell_command("access_directory ~/.config/opencode")
        self.assertTrue(safe, f"Expected ~/.config/opencode allowed, got: {reason}")
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

        # Hermes sandbox -> SANDBOX_GUARD
        safe, reason, layer = audit_shell_command("access_directory ~/.hermes/sandboxes/default")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SANDBOX_GUARD)

        # Literal "\n" suffix (as captured from the TUI "Patterns" body) must not
        # break the sensitive-directory boundary -> still SECRET_GUARD (fail-closed).
        literal_n = "access_directory ~/.ssh\\nPatterns\\n-"
        safe, reason, layer = audit_shell_command(literal_n)
        self.assertFalse(safe, f"Expected literal-\\n ~/.ssh blocked, got safe: {reason}")
        self.assertEqual(layer, DecisionLayer.SECRET_GUARD)

    def test_read_file_layer(self):
        # Safe read -> allowed
        safe, reason, layer = audit_shell_command("read_file /tmp/notes.txt")
        self.assertTrue(safe, f"Expected /tmp read allowed, got: {reason}")
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

        # Sensitive file read -> SECRET_GUARD
        safe, reason, layer = audit_shell_command("read_file ~/.ssh/id_rsa")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SECRET_GUARD)

        safe, reason, layer = audit_shell_command("read_file /app/.env")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SECRET_GUARD)

    def test_unhandled_dialog_and_doom_loop_layer(self):
        # Unhandled / doom-loop dialogs must never be auto-approved.
        safe, reason, layer = audit_shell_command("doom_loop")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL)

        # Human question dialogs (with or without extracted text) must never be
        # auto-approved either.
        safe, reason, layer = audit_shell_command("question")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL)

        safe, reason, layer = audit_shell_command("question: Which branch should I merge?")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL)

        # Mock the cloud judge so the unhandled-dialog path is deterministic:
        # the real LLM judge may classify a read-only glob as safe (correct in
        # isolation, but it makes this assertion flaky). A mocked "defer to
        # human" verdict is what the test actually cares about.
        with patch("core.security_evaluator.audit_with_cloud_judge", return_value=(False, "mocked: deferred to human")):
            safe, reason, layer = audit_shell_command("unhandled_dialog Glob /tmp/**")
            self.assertFalse(safe)
            self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL)

            safe, reason, layer = audit_shell_command("unhandled_dialog WebSearch foo")
            self.assertFalse(safe)
            self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL)

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

        safe, reason, layer = audit_shell_command(
            "curl -X DELETE https://gitea.example.com/api/v1/repos/org/repo/issues/45"
        )
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
        from cmd.schengen_watcher import get_lock_file_path, sanitize_target_name

        self.assertEqual(sanitize_target_name("wS:pF"), "wS_pF")
        self.assertEqual(sanitize_target_name("auto"), "auto")
        self.assertEqual(sanitize_target_name("tab/pane-1"), "tab_pane-1")

        lock_auto = get_lock_file_path("auto")
        self.assertTrue(str(lock_auto).endswith("schengen_auto.lock"))

        lock_pane = get_lock_file_path("wS:pF")
        self.assertTrue(str(lock_pane).endswith("schengen_wS_pF.lock"))

    def test_graceful_reload_execution(self):
        from cmd.schengen_watcher import execute_graceful_reload

        # Calling execute_graceful_reload() should succeed without throwing exceptions
        success = execute_graceful_reload()
        self.assertTrue(success)

    def test_graceful_reload_aborts_on_tampered_module(self):
        """Verify that verify_module_integrity rejects tampered modules, untracked files, and corrupted syntax."""
        import tempfile
        import types

        from cmd.schengen_watcher import verify_module_integrity

        # 1. Untracked / Null-stubbed module (outside SCM) -> rejected
        fake_mod = types.ModuleType("core.security_evaluator")
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(
                "class DecisionLayer: ALLOWLIST = 'ALLOWLIST'\ndef audit_shell_command(*args, **kwargs): return True, 'approved', 'ALLOWLIST'\n"
            )
            fake_path = f.name

        try:
            fake_mod.__file__ = fake_path
            self.assertFalse(verify_module_integrity(fake_mod))
        finally:
            if os.path.exists(fake_path):
                os.unlink(fake_path)

        # 2. Syntax corrupted module -> rejected
        bad_syntax_mod = types.ModuleType("core.guard_db")
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("def broken syntax (:::\n")
            bad_path = f.name

        try:
            bad_syntax_mod.__file__ = bad_path
            self.assertFalse(verify_module_integrity(bad_syntax_mod))
        finally:
            if os.path.exists(bad_path):
                os.unlink(bad_path)

    def test_find_git_repo_ssot_fallback_preserves_subdirectory(self):
        """The SSOT fallback must reconstruct scripts/<subdir>/<name> for mirror modules (issue #98)."""
        from cmd.schengen_watcher import find_git_repo_and_rel_path

        ssot = Path.home() / "code" / "herdr-schengen"
        if not (ssot / ".git").exists() or not (ssot / "scripts" / "core" / "security_evaluator.py").exists():
            self.skipTest("SSOT repo not available")

        # A module loaded from a non-git mirror, nested under scripts/core/.
        mirror_path = Path("/tmp") / "fake-mirror" / "scripts" / "core" / "security_evaluator.py"
        repo_dir, rel_path = find_git_repo_and_rel_path(mirror_path)
        self.assertEqual(repo_dir, ssot)
        self.assertEqual(rel_path, "scripts/core/security_evaluator.py")

    def test_new_file_creation_in_git_repo_fast_track(self):
        """File creation via redirection (cat << 'EOF' > new_file) is no longer auto-approved:
        the `>` metacharacter disqualifies it from the closed fast-track allowlist (INV-6),
        so it escalates via NOT_ALLOWLISTED instead of the removed catch-all."""
        repo_root = Path(__file__).resolve().parent.parent
        target_file = repo_root / "docs" / "adr-999-unit-test-creation.md"
        cmd = f"cat << 'EOF' > {target_file}\n# Test ADR\nEOF"
        safe, reason, layer = audit_shell_command(cmd)
        self.assertFalse(safe, f"Expected redirection file creation to escalate (fail-closed), got safe=True: {reason}")
        self.assertEqual(layer, DecisionLayer.NOT_ALLOWLISTED)

    def test_escalation_queue_lifecycle_and_cleanup(self):
        from core.guard_db import (
            cleanup_escalations,
            enqueue_pending_escalation,
            get_pending_escalations,
            mark_escalation_delivered,
            resolve_escalation,
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
        delivered_list = get_pending_escalations(
            pane_id=test_pane, include_delivered=True, active_session_map=active_map_matching
        )
        target_item2 = next((item for item in delivered_list if item["id"] == esc_id2), None)
        self.assertIsNotNone(target_item2)

        # 4. Mark delivered
        mark_escalation_delivered(target_item2["id"])
        del_list = get_pending_escalations(
            pane_id=test_pane, include_delivered=True, active_session_map=active_map_matching
        )
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
        from core.security_evaluator import (
            Consequence,
            GateState,
            Origin,
            audit_shell_command_with_taxonomy,
        )

        # 1. Critical destructive command -> Consequence.DESTRUCTION
        safe_crit, reason_crit, layer_crit, tax_crit = audit_shell_command_with_taxonomy("rm -rf /")
        self.assertFalse(safe_crit)
        self.assertEqual(tax_crit["origin"], Origin.AGENT.value)
        self.assertEqual(tax_crit["consequence"], Consequence.DESTRUCTION.value)
        self.assertEqual(tax_crit["mechanism"], "rm-rf")
        self.assertEqual(tax_crit["gate_state"], GateState.ENFORCE.value)
        self.assertFalse(tax_crit["shadow_mode"])

        # 1b. Destructive git rm -> Consequence.DESTRUCTION
        safe_grm, reason_grm, layer_grm, tax_grm = audit_shell_command_with_taxonomy("git rm -rf src/")
        self.assertFalse(safe_grm)
        self.assertEqual(tax_grm["consequence"], Consequence.DESTRUCTION.value)
        self.assertEqual(tax_grm["mechanism"], "git-destructive")

        # 2. Secret reading -> Consequence.EXFILTRATION
        safe_sec, reason_sec, layer_sec, tax_sec = audit_shell_command_with_taxonomy("cat .env")
        self.assertFalse(safe_sec)
        self.assertEqual(tax_sec["consequence"], Consequence.EXFILTRATION.value)
        self.assertEqual(tax_sec["mechanism"], "secret-path")

        # 3. Privilege escalation -> Consequence.PERSISTENCE
        safe_sudo, reason_sudo, layer_sudo, tax_sudo = audit_shell_command_with_taxonomy("sudo whoami")
        self.assertFalse(safe_sudo)
        self.assertEqual(tax_sudo["consequence"], Consequence.PERSISTENCE.value)
        self.assertEqual(tax_sudo["mechanism"], "privilege-escalation")

        # 4. Permission mutation -> Consequence.INTEGRITY
        safe_chmod, reason_chmod, layer_chmod, tax_chmod = audit_shell_command_with_taxonomy("chmod 777 /tmp/script.sh")
        self.assertFalse(safe_chmod)
        self.assertEqual(tax_chmod["consequence"], Consequence.INTEGRITY.value)
        self.assertEqual(tax_chmod["mechanism"], "perm-mutation")

        # 5. Fork bomb / DoS -> Consequence.AVAILABILITY
        safe_dos, reason_dos, layer_dos, tax_dos = audit_shell_command_with_taxonomy(":(){ :|:& };:")
        self.assertFalse(safe_dos)
        self.assertEqual(tax_dos["consequence"], Consequence.AVAILABILITY.value)
        self.assertEqual(tax_dos["mechanism"], "dos-fork-bomb")

        # 6. Benign command -> Consequence.NONE
        safe_ok, reason_ok, layer_ok, tax_ok = audit_shell_command_with_taxonomy("git status")
        self.assertTrue(safe_ok)
        self.assertEqual(tax_ok["consequence"], Consequence.NONE.value)
        self.assertEqual(tax_ok["mechanism"], "fast-track-verified")

    def test_shadow_mode_kill_switch(self):
        """Verify that SCHENGEN_SHADOW_MODE=1 allows execution while logging counterfactual block."""
        from core.security_evaluator import GateState, audit_shell_command_with_taxonomy

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
        from core.guard_db import get_db_connection, record_audit_log

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
            cursor.execute(
                "SELECT origin, consequence, mechanism, gate_state, shadow_mode FROM audit_logs WHERE pane_id = ? ORDER BY id DESC LIMIT 1",
                (test_pane,),
            )
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["origin"], "A")
            self.assertEqual(row["consequence"], "DEST")
            self.assertEqual(row["mechanism"], "rm-rf")
            self.assertEqual(row["gate_state"], "OBSERVE")
            self.assertEqual(row["shadow_mode"], 1)


class TestFastTrackTestRunner(unittest.TestCase):
    """INV-TEST-1: narrow test-runner fast-track (documented code-execution exception).

    Only the gatekeeper's own test-suite shape auto-approves: `python3 -m unittest`
    scoped to `tests/` (or a `tests.*` unit) and `pytest` scoped to `tests/...`
    (or bare `pytest`). Everything else (`-c`, script paths, other -m modules,
    sudo, metacharacters/redirection, unscoped discovery) stays fail-closed.
    NOTE: the documented HOLE (arbitrary code inside a tests/ module executes)
    is intentionally NOT test-enforced — see the docstring in
    `_is_fast_track_test_runner`.
    """

    def test_test_runner_forms_fast_track(self):
        safe_cmds = (
            "HERDR_ENV=1 ~/.local/share/herdr-schengen-tui-venv/bin/python3 -m unittest discover -s tests",
            "python3 -m unittest discover -s tests",
            "python3 -m unittest discover -s ./tests -v",
            "python3 -m unittest tests.test_decision_layers",
            "pytest tests/test_decision_layers.py",
            "pytest",
        )
        for cmd in safe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertTrue(safe, f"Expected '{cmd}' fast-track safe, got: {reason}")
            self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_non_test_runner_forms_stay_fail_closed(self):
        unsafe_cmds = (
            'python3 -c "print(1)"',  # -c payload
            "python3 some_script.py",  # bare script path
            "python3 -m pip install requests",  # other -m module
            "python3 -m unittest discover -s /etc",  # unscoped discovery dir
            "sudo python3 -m unittest discover -s tests",  # sudo
            "python3 -m unittest discover -s tests > /tmp/out",  # redirection
            "python3 -m unittest discover -s tests && rm -rf /",  # metachar + mutation
            "python3 -m unittest discover",  # no -s tests scope
        )
        for cmd in unsafe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' fail-closed, got safe=True: {reason}")

    def test_fd_redirect_symmetry(self):
        # #2555: pure fd-to-fd redirects (never a file write) must not over-block
        # the test-runner fast-track — '2>&1' (legacy), '1>&2', the spaced
        # '2 >&1' variant, and the '/dev/null' discard must all strip cleanly.
        safe_cmds = (
            "python3 -m unittest discover -s tests 2>&1",
            "python3 -m unittest discover -s tests 1>&2",
            "python3 -m unittest discover -s tests 2 >&1",
            "python3 -m unittest discover -s tests 2>&1 | tail -5",
            "python3 -m unittest discover -s tests &> /dev/null",
        )
        for cmd in safe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertTrue(safe, f"Expected '{cmd}' fast-track safe, got: {reason}")
            self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_fd_redirect_file_target_stays_fail_closed(self):
        # #2555: '&>' with a REAL file target is a file write (== '> file 2>&1')
        # and must stay fail-closed, like the plain '> file' redirection.
        unsafe_cmds = (
            "python3 -m unittest discover -s tests &> /tmp/out.log",
            "python3 -m unittest discover -s tests > /tmp/out",
        )
        for cmd in unsafe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' fail-closed, got safe=True: {reason}")

    def test_separator_after_redirect_stays_fail_closed(self):
        # #2555 hardening (INV-5/6): a trailing '&&'/'||'/';' separator after the
        # fd-redirect strip must NOT slip a second segment into the narrow
        # test-runner fast-track.
        unsafe_cmds = (
            "python3 -m unittest discover -s tests 2>&1 && rm -rf x",
            "python3 -m unittest discover -s tests && rm -rf x",
            "python3 -m unittest discover -s tests || echo fail",
        )
        for cmd in unsafe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' fail-closed, got safe=True: {reason}")

    def test_cd_safe_dir_prefix_test_runner_fast_tracks(self):
        # (issue #3670) a single leading `cd <safe-dir> &&` may prefix the narrow
        # test-runner fast-track.
        safe_cmds = (
            "cd ~/code/herdr-schengen && python3 -m unittest discover -s tests 2>&1 | tail -30",
            "cd ~/code/herdr-schengen && pytest",
            "cd /Users/kyjbusan/code/herdr-schengen && python3 -m unittest tests.test_decision_layers",
        )
        for cmd in safe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertTrue(safe, f"Expected '{cmd}' fast-track safe, got: {reason}")
            self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_cd_unsafe_dir_prefix_stays_fail_closed(self):
        # (issue #3670) the cd-prefix strip is fail-closed: an unsafe/navigation
        # dir keeps the raw command, whose '&&' then rejects the fast-track.
        unsafe_cmds = (
            "cd ~/.ssh && python3 -m unittest discover -s tests",
            "cd ~ && python3 -m unittest discover -s tests",
            "cd .. && python3 -m unittest discover -s tests",
            "cd / && python3 -m unittest discover -s tests",
        )
        for cmd in unsafe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' fail-closed, got safe=True: {reason}")


class TestComplexityTax(unittest.TestCase):
    """M3 COMPLEXITY_TAX (INV-16): structural-complexity deferral layer.

    The tax must ONLY escalate (never auto-approve): chained/nested aggregate
    shape above the threshold defers to human review, while provably-benign
    fast-track / test-runner / read-only-pipeline commands and already-blocked
    commands are unaffected. Uses a clean temp DB so the default threshold (6)
    applies — no pre-seeded guard_config rows.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def _audit(self, cmd):
        return audit_shell_command_with_taxonomy(cmd, origin=Origin.AGENT)

    def test_complex_chain_escalates_complexity_tax(self):
        cmd = "mkdir a1; mkdir a2; mkdir a3; mkdir a4; mkdir a5; mkdir a6; mkdir a7"
        safe, reason, layer, tax = self._audit(cmd)
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.COMPLEXITY_TAX)
        self.assertIn("complexity", reason)
        self.assertEqual(tax["mechanism"], "complexity-tax")

    def test_simple_commands_unaffected(self):
        for cmd in ("ls -la", "git status"):
            safe, reason, layer, tax = self._audit(cmd)
            self.assertNotEqual(layer, DecisionLayer.COMPLEXITY_TAX)
            self.assertTrue(safe)

    def test_compute_complexity_boundary(self):
        self.assertEqual(compute_complexity(";".join(f"mkdir a{i}" for i in range(6))), 6)
        self.assertEqual(compute_complexity(";".join(f"mkdir a{i}" for i in range(7))), 7)

    def test_fd_redirect_no_over_count(self):
        # #139-1: 'n>&m' fd-redirects must not be split into extra segments by the
        # '&' separator — `ls 2>&1` is 1 segment + 1 redirection = 2, NOT 3.
        self.assertEqual(compute_complexity("ls 2>&1"), 2)
        self.assertEqual(compute_complexity("ls 1>&2"), 2)
        self.assertEqual(compute_complexity("ls &> /tmp/out"), 2)
        # sanity: a genuine '&' separator still splits segments
        self.assertEqual(compute_complexity("ls 2>&1 & wait"), 3)

    def test_herestring_counts_as_redirection(self):
        # #139-2: `<<<` (herestring) previously matched NOTHING on
        # _COMPLEXITY_REDIR_RE (greedy backtrack + lookahead both fail), so
        # `cat <<< hello` under-scored as 1. It must count as a redirection.
        self.assertEqual(compute_complexity("cat <<< hello"), 2)
        # heredoc `<< EOF` still counts exactly one redirection
        self.assertEqual(compute_complexity("cat << EOF"), 2)
        self.assertEqual(compute_complexity("cat <<< a < b"), 3)

    def test_arithmetic_expansion_not_command_substitution(self):
        # #139-3: `$((...))` is arithmetic expansion, NOT command substitution —
        # previously `count("$(")` scored it as a substitution (over-count).
        self.assertEqual(compute_complexity("echo $((1+2))"), 1)
        # genuine `$(...)` substitution still scores
        self.assertEqual(compute_complexity("echo $(date)"), 2)
        self.assertEqual(compute_complexity("echo $((1+2)) $(date)"), 2)
        # nested arithmetic+substitution counts only the inner substitution
        self.assertEqual(compute_complexity("echo $(($(date)))"), 2)

    def test_separator_agnostic(self):
        # INV-16: |/&/; and surrounding whitespace/newlines are equivalent separators.
        self.assertEqual(compute_complexity("a && b"), 2)
        self.assertEqual(compute_complexity("a&&b"), 2)
        self.assertEqual(compute_complexity("a\n&&\nb"), 2)
        self.assertEqual(compute_complexity("a   &&   b"), 2)

    def test_already_blocked_unaffected(self):
        safe, reason, layer, tax = self._audit("rm -rf /tmp/x && sudo id")
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.SHELL_CRITICAL)
        self.assertNotEqual(layer, DecisionLayer.COMPLEXITY_TAX)

    def test_readonly_pipelines_not_gated(self):
        for cmd in ("git status && git log --oneline -3", "cat a.txt | sort | uniq"):
            safe, reason, layer, tax = self._audit(cmd)
            self.assertTrue(safe, f"Expected '{cmd}' fast-track safe, got: {reason}")
            self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_test_runner_not_gated(self):
        # INV-TEST-1: the gatekeeper's own suite must stay fast-tracked.
        safe, reason, layer, tax = self._audit("python3 -m unittest discover -s tests")
        self.assertTrue(safe, f"Expected test runner fast-track safe, got: {reason}")
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_substitution_terms_escalate_complexity_tax(self):
        cmd = "echo " + " ".join("$(pwd)" for _ in range(7))
        safe, reason, layer, tax = self._audit(cmd)
        self.assertFalse(safe)
        self.assertEqual(layer, DecisionLayer.COMPLEXITY_TAX)

    def test_heredoc_body_lines_do_not_inflate_complexity(self):
        # (issue #4027) a terminated heredoc collapses to a single '<<' marker —
        # 16 body lines previously scored ~19 as phantom segments; now ~2.
        heredoc = "cat <<'EOF'\n" + "\n".join(f"line{i}" for i in range(1, 17)) + "\nEOF"
        self.assertEqual(compute_complexity(heredoc), 2)

    def test_quoted_heredoc_substitutions_isolated(self):
        # (issue #4027) a QUOTED heredoc body expands nothing: $(...) inside it
        # must NOT count as a substitution, and body lines must not inflate.
        heredoc = "cat <<'EOF'\n" + "echo $(date) `whoami`\n" * 8 + "EOF"
        self.assertEqual(compute_complexity(heredoc), 2)

    def test_unquoted_heredoc_substitutions_survive(self):
        # (issue #4027) an UNQUOTED heredoc body IS shell-expanded: count its
        # $(...) / backticks even though the body lines themselves are masked.
        heredoc = "cat <<EOF\n" + "a $(date)\nb `whoami`\nc $(pwd)\nd end\n" + "EOF"
        # 1 segment + (2 '$(' + 2 backticks) + 1 redirection = 6
        self.assertEqual(compute_complexity(heredoc), 6)

    def test_herestring_and_unterminated_heredoc_unchanged(self):
        # `<<<` must never be mistaken for a heredoc opener; an unterminated
        # heredoc is left untouched (fail-closed: no masking without a bound).
        self.assertEqual(compute_complexity("cat <<< hello"), 2)
        self.assertEqual(compute_complexity("cat << EOF\nbody line\n"), 3)


class TestOriginWeighting(unittest.TestCase):
    """M5 ORIGIN_GUARD (INV-17): origin-based hard-escalate + HUMAN trust concession.

    INJECTED/EMERGENT origins hard-escalate at the TOP of `audit_shell_command`
    — BEFORE every auto-approve path (dialogs, Managed Git, fast-track,
    test-runner, novelty, package READ_ONLY, gray-zone->cloud-judge,
    dynamic-substitution LLM inspector). HUMAN origin skips the structural
    complexity tax (gated by the origin_weighting_enabled knob, default True).
    Uses a clean temp DB so origin_weighting_enabled defaults True.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()
        # Re-fetch LIVE module references: test_graceful_reload_execution (earlier
        # alphabetically) runs execute_graceful_reload(), which importlib.reload()s
        # security_evaluator/guard_db — creating NEW Origin/DecisionLayer classes.
        # Module-level `from ... import Origin` would then hold stale classes whose
        # members fail the reloaded derive_taxonomy isinstance() check. Fetching
        # via module attributes here makes this class immune to reload ordering.
        import core.security_evaluator as security_evaluator

        self.Origin = security_evaluator.Origin
        self.DecisionLayer = security_evaluator.DecisionLayer
        self.audit = security_evaluator.audit_shell_command_with_taxonomy

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_injected_emergent_hard_escalate(self):
        cmd = "mkdir a1; mkdir a2; mkdir a3; mkdir a4; mkdir a5; mkdir a6; mkdir a7"
        for origin in (self.Origin.INJECTED, self.Origin.EMERGENT):
            safe, reason, layer, tax = self.audit(cmd, origin=origin)
            self.assertFalse(safe, f"Origin {origin.value} must hard-escalate, got safe={safe}: {reason}")
            self.assertEqual(layer, self.DecisionLayer.ORIGIN_GUARD)
            self.assertEqual(tax["mechanism"], "origin-hard-escalate")

    def test_emergent_bypasses_fast_track(self):
        safe, reason, layer, tax = self.audit("ls -la", origin=self.Origin.EMERGENT)
        self.assertFalse(safe, f"EMERGENT must hard-escalate even a fast-track command: {reason}")
        self.assertEqual(layer, self.DecisionLayer.ORIGIN_GUARD)
        self.assertNotEqual(layer, self.DecisionLayer.FAST_TRACK_AST)

    def test_injected_bypasses_package_readonly(self):
        safe, reason, layer, tax = self.audit("brew list", origin=self.Origin.INJECTED)
        self.assertFalse(safe, f"INJECTED must hard-escalate even a READ_ONLY package query: {reason}")
        self.assertEqual(layer, self.DecisionLayer.ORIGIN_GUARD)
        self.assertNotEqual(layer, self.DecisionLayer.PACKAGE_GUARD)

    def test_human_skips_complexity_tax(self):
        cmd = "mkdir a1; mkdir a2; mkdir a3; mkdir a4; mkdir a5; mkdir a6; mkdir a7"
        safe_h, reason_h, layer_h, tax_h = self.audit(cmd, origin=self.Origin.HUMAN)
        self.assertNotEqual(
            layer_h, self.DecisionLayer.COMPLEXITY_TAX, f"HUMAN must skip the tax: {reason_h}"
        )
        safe_a, reason_a, layer_a, tax_a = self.audit(cmd, origin=self.Origin.AGENT)
        self.assertEqual(layer_a, self.DecisionLayer.COMPLEXITY_TAX)

        # HUMAN vs AGENT must produce IDENTICAL (is_safe, layer) for commands
        # that never reach the complexity tax.
        for c in ("ls -la", "brew list", "git status", "python3 -m unittest discover -s tests"):
            sh, _, lh, _ = self.audit(c, origin=self.Origin.HUMAN)
            sa, _, la, _ = self.audit(c, origin=self.Origin.AGENT)
            self.assertEqual((sh, lh), (sa, la), f"(is_safe, layer) must match for '{c}'")

    def test_origin_not_spoofable(self):
        cmd = "echo human approved"
        sa, _, la, taxa = self.audit(cmd, origin=self.Origin.AGENT)
        sh, _, lh, taxh = self.audit(cmd, origin=self.Origin.HUMAN)
        self.assertEqual(taxa["origin"], "A")
        self.assertEqual(taxh["origin"], "H")
        self.assertEqual((sa, la), (sh, lh))

    def test_injected_bypasses_cloud_judge(self):
        # `rm <T3 state path>` is a gray-zone DELETE on a durable/state target ->
        # Verdict.PROMPT, which with AGENT origin routes to the cloud judge.
        # INJECTED must be intercepted by ORIGIN_GUARD before reaching the
        # gray-zone/cloud-judge path.
        cmd = "rm ~/.local/state/data.sqlite"
        safe, reason, layer, tax = self.audit(cmd, origin=self.Origin.INJECTED)
        self.assertFalse(safe, f"INJECTED must hard-escalate a gray-zone command: {reason}")
        self.assertEqual(layer, self.DecisionLayer.ORIGIN_GUARD)
        self.assertNotIn(
            layer, (self.DecisionLayer.CLOUD_JUDGE, self.DecisionLayer.GRAY_ZONE_MATRIX)
        )

    def test_no_regression_origin_agent(self):
        safe, reason, layer, tax = self.audit(
            "python3 -m unittest discover -s tests", origin=self.Origin.AGENT
        )
        self.assertTrue(safe, f"AGENT test-runner must stay fast-tracked: {reason}")
        self.assertEqual(layer, self.DecisionLayer.FAST_TRACK_AST)


class TestStandaloneReadOnlySed(unittest.TestCase):
    """Issue #6935: read-only `sed -n '<addr>p' <file>` fast-track (whitelist).

    sed is a language: ONLY `sed -n` with a script that is exactly a numeric /
    range / `$` address + optional `!` + `p` (print) fast-tracks. Anything else
    (e, w, s///w, r, i/a/c, d, -i/-i.suffix) and sensitive/broad targets stay
    fail-closed, in both the standalone and pipeline paths.
    """

    def test_readonly_sed_n_fast_tracks(self):
        safe_cmds = (
            "sed -n '1,260p' /Users/kyjbusan/code/herdr-schengen/scripts/core/security_evaluator.py",
            "sed -n '1,10p' docs/guides/setup.md",
            "sed -n '10p' docs/guides/setup.md",
            "sed -n '1,10!p' file.txt",
        )
        for cmd in safe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertTrue(safe, f"Expected '{cmd}' fast-track safe, got: {reason}")
            self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_sed_script_language_forms_stay_fail_closed(self):
        # sed is a mini-language: execute / write / delete / substitute / no -n
        # must all reject (whitelist is the closed set above).
        unsafe_cmds = (
            "sed -n '1e touch /tmp/pwned' file.txt",  # GNU sed `e` executes shell
            "sed -n '1,10w ~/.bashrc' file.txt",  # adjacent `w` write
            "sed -n 's/x/y/w /tmp/out' file.txt",  # s///w write flag
            "sed -n '1,10d' file.txt",  # delete
            "sed 's/foo/bar/' file.txt",  # no -n (not matched)
        )
        for cmd in unsafe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' fail-closed, got safe=True: {reason}")

    def test_sed_inplace_forms_stay_fail_closed(self):
        unsafe_cmds = (
            "sed -i 's/foo/bar/' file.txt",  # in-place write-back
            "sed -n '1,10p' file.txt -i",  # -i flag anywhere
            "sed -n -i.bak 's/foo/bar/' file.txt",  # -i with attached suffix
            "sed -n '1,10p' file.txt > /tmp/out",  # redirection
        )
        for cmd in unsafe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' fail-closed, got safe=True: {reason}")

    def test_sed_extra_script_sources_stay_fail_closed(self):
        # Reviewer round 3: additional script sources (-e/-f/--expression/--file,
        # attached or space-separated) must reject — the whitelist only validates
        # the FIRST quoted script, so extra sources could smuggle e/w/s///w.
        unsafe_cmds = (
            "sed -n '1,10p' -e '1e touch /tmp/pwned' file.txt",  # execute via -e
            "sed -n '1,10p' -f /tmp/evil.sed file.txt",  # script file
            "sed -n --expression='1e id' '1,10p' file.txt",  # long form (attached)
            "sed -n --file=/tmp/evil.sed '1,10p' file.txt",  # long form (attached)
        )
        for cmd in unsafe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' fail-closed, got safe=True: {reason}")

    def test_sed_extra_script_sources_no_false_positive(self):
        # A filename-like token starting with -e/-f must NOT be rejected
        # (the \b boundary after the flag ensures only the bare flag token matches).
        safe, reason, layer = audit_shell_command("sed -n '1,10p' -example.txt")
        self.assertTrue(safe, f"Expected '-example.txt' fast-track safe, got: {reason}")
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_sed_n_sensitive_targets_stay_fail_closed(self):
        # INV-SENS-1: sensitive paths must never fast-track (SECRET_GUARD or fail-closed).
        ssh_key = "~/.ss" + "h/id_r" + "sa"
        env_file = "~/.e" + "nv"
        for cmd in (
            "sed -n '1,10p' " + ssh_key,
            "sed -n '1,10p' " + env_file,
        ):
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' fail-closed (sensitive), got safe=True: {reason}")

    def test_sed_pipeline_path_hardened(self):
        # The pipeline path must use the same strict whitelist (reviewer finding):
        # execute/write sed forms in a pipeline never fast-track, while the safe
        # print form still does.
        unsafe_cmds = (
            "cat a.txt | sed '1e id'",  # execute in pipeline
            "cat a.txt | sed 's/x/y/w out.txt'",  # write in pipeline
        )
        for cmd in unsafe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' fail-closed, got safe=True: {reason}")
        safe, reason, layer = audit_shell_command("sed -n '1,260p' file.txt | head -5")
        self.assertTrue(safe, f"Expected whitelist pipeline fast-track safe, got: {reason}")
        self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)


class TestTestRunnerStderrRedirect(unittest.TestCase):
    """Issue #2555: the gatekeeper's own test command with `2>&1 | grep` fast-tracks.

    Fix A: `2>&1` is a file-descriptor redirect, NOT a command separator — the
    complexity metric must not inflate the segment count.
    Fix B: `python3 -m unittest ... 2>&1` plus AT MOST ONE read-only filter pipe
    fast-tracks; multi-pipe, file redirection, and non-filter pipes stay fail-closed.
    """

    def test_test_runner_with_2and1_and_filter_pipe_fast_tracks(self):
        safe_cmds = (
            "python3 -m unittest discover -s tests 2>&1 | grep -E 'FAIL|ERROR'",
            "python3 -m unittest discover -s tests 2>&1 | grep FAIL",
            "python3 -m unittest discover -s tests 2>&1 | head -20",
            "python3 -m unittest discover -s tests",  # bare regression
        )
        for cmd in safe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertTrue(safe, f"Expected '{cmd}' fast-track safe, got: {reason}")
            self.assertEqual(layer, DecisionLayer.FAST_TRACK_AST)

    def test_test_runner_unsafe_pipes_stay_fail_closed(self):
        unsafe_cmds = (
            "python3 -m unittest discover -s tests 2>&1 | grep FAIL | tee /tmp/out",  # multi-pipe
            "python3 -m unittest discover -s tests 2>&1 > /tmp/out",  # file redirection
            "python3 -m unittest discover -s tests | sh",  # non-filter pipe
        )
        for cmd in unsafe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' fail-closed, got safe=True: {reason}")

    def test_test_runner_filter_tail_redirection_stays_fail_closed(self):
        # Round-2 finding: the redirection reject must run on the FULL command
        # (head AND filter tail) — '> file' / '>> file' on the filter tail must
        # not bypass it.
        unsafe_cmds = (
            "python3 -m unittest discover -s tests | grep FAIL > /tmp/out",  # filter-tail file redirect
            "python3 -m unittest discover -s tests | grep FAIL >> /tmp/out",  # filter-tail append
        )
        for cmd in unsafe_cmds:
            safe, reason, layer = audit_shell_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' fail-closed, got safe=True: {reason}")

    def test_compute_complexity_2and1_not_a_separator(self):
        # Fix A metric: '2>&1' counts as 1 segment + 1 redirection (was 2 segments + 1).
        self.assertEqual(compute_complexity("ls 2>&1"), 2)
        self.assertEqual(compute_complexity("a 2>&1 | b"), 3)
        # Round-2: the combined '&>' stdout+stderr redirect is also not a separator.
        self.assertEqual(compute_complexity("cmd &> file"), 2)


if __name__ == "__main__":
    unittest.main()
