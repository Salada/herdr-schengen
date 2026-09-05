"""Security evaluation module for Herdr Schengen (SmartGate) across 9 Decision Layers.

Combines:
1. Shell command parsing & blacklist inspection (with PATH exception)
2. Python AST static analysis (with Managed Git SCM API whitelist rules)
3. Sensitive file and secret pattern matching
4. Hermes sandbox write-protection policy
5. Multi-turn Tool-Calling Semantic Inspector for dynamic substitutions $(cat ...)
6. Output sanitization & exfiltration inspection
7. Gray-zone Non-VCS irreversible mutation matrix
"""

import ast
import dataclasses
import io
import json
import os
import re
import shlex
import stat
import textwrap
import threading
import tokenize as _tokenize
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from core.cloud_judge import (
    DEFAULT_REASONING_EFFORT,
    GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT,
    parse_json_verdict,
    post_cloud_judge,
    resolve_guard_llm_config,
)
from core.gray_zone_evaluator import (
    ResourceTier,
    Verdict,
    classify_resource_tier,
    evaluate_gray_zone_operation,
    format_decision_guidance,
)
from core.guard_db import (
    get_cloud_judge_config,
    get_complexity_tax_config,
    get_origin_weighting_config,
    has_human_approval_pattern,
    normalize_command,
)
from core.redaction import redact_for_cloud
from core.semgrep_evaluator import audit_script_with_semgrep
from core.shellcheck_evaluator import audit_shell_with_shellcheck

# ── Phase-1 in-flight phase hook (INV-PH1-6) ────────────────────────────────
# Per-thread callback so the watcher's InspectorCoordinator can observe the
# inspector ("deterministic AST, ms") vs gatekeeper ("LLM/cloud-judge, seconds")
# sub-phases WITHOUT touching the hot path. The hook is invoked ONLY around
# post_cloud_judge calls (never for cache hits / short-circuits), resets via
# finally even on exception, and is thread-local (no cross-pane stomping).
_phase_hooks = threading.local()


def set_phase_hook(hook):
    """Per-thread phase callback; invoked only by LLM tiers (never the hot path)."""
    _phase_hooks.hook = hook


def _emit_phase(phase: str) -> None:
    hook = getattr(_phase_hooks, "hook", None)
    if hook is not None:
        try:
            hook(phase)
        except Exception:
            pass

# 1. Sensitive file patterns (Secrets & Credentials)
SEP = r"(^|[\s/\"'@:=])"
END_SEP = r"([\s/\"'@:=]|$)"

SENSITIVE_FILE_PATTERN = re.compile(
    rf"""(
        {SEP}\.env(\.[a-zA-Z0-9_-]+)?{END_SEP}|
        id_[a-zA-Z0-9_-]+|
        {SEP}credentials(\.json|\.ya?ml|\.ini|\.toml|\.txt)?{END_SEP}|
        {SEP}\.?secrets?(\.json|\.ya?ml|\.toml|\.ini|\.env|\.txt){END_SEP}|
        {SEP}\.secrets(/|{END_SEP})|
        \.(pem|key|pfx|pkcs12){END_SEP}|
        hosts\.ya?ml|
        \.netrc|
        \.aws/|
        \.kube/config|
        {SEP}\.(zsh|bash)_history{END_SEP}|
        \.kdbx{END_SEP}|
        \.keychain{END_SEP}|
        {SEP}\.npmrc{END_SEP}|
        {SEP}\.pypirc{END_SEP}|
        {SEP}authorized_keys{END_SEP}|
        {SEP}known_hosts{END_SEP}
        |/(?:private/)?etc/shadow{END_SEP}
    )""",
    re.VERBOSE | re.IGNORECASE,
)

# 2. Hermes Sandbox path pattern
HERMES_SANDBOX_PATTERN = re.compile(r"(\.hermes/sandboxes|hermes_sandbox)", re.IGNORECASE)

# 2b. Sensitive directory pattern (for external-directory access screening)
# NOTE: `.config/opencode` is deliberately NOT listed. It holds OpenCode's config,
# plugins/, and skills/ (not secrets) — the agent legitimately writes its own
# plugin folder there (issue #54). OpenCode's actual auth state lives elsewhere
# (~/.local/share/opencode/auth.json), not under `.config/opencode`.
SENSITIVE_DIRECTORY_PATTERN = re.compile(
    r"(^|/)\.(ssh|aws|gnupg|kube|docker|hermes|config/gh)(/|\\|$)",
    re.IGNORECASE,
)

# 3. Managed Git SCM (Forgejo, Gitea, GitHub, GitLab) allowed endpoint patterns
MANAGED_GIT_HOST_PATTERN = re.compile(
    r"https?://(192\.168\.10\.102:3000|api\.github\.com|gitlab\.com/api|[^/]*gitea[^/]*/api)"
)
MANAGED_GIT_ISSUES_PATTERN = re.compile(
    r"https?://(192\.168\.10\.102:3000/api/v1/repos/[^/]+/[^/]+/issues|"
    r"api\.github\.com/repos/[^/]+/[^/]+/(issues|pulls)|"
    r"gitlab\.com/api/v4/projects/[^/]+/issues|"
    r"[^/]*gitea[^/]*/api/v1/repos/[^/]+/[^/]+/issues)"
)
# Backward-compatibility alias
FORGEJO_HOST_PATTERN = MANAGED_GIT_HOST_PATTERN
FORGEJO_ISSUES_PATTERN = MANAGED_GIT_ISSUES_PATTERN

# 4. Critical Dangerous Shell Commands (Destructive / Elevation / macOS System Guard)
CRITICAL_SHELL_PATTERNS = [
    (r"(?<!\bgit\s)\brm\s+(-[rfRF]+\s+|[^\s]*[rfRF])", "Destructive file deletion (rm -rf)"),
    (r"\bgit\s+rm\s+(?!.*--cached)(-[rfRF]+\s+|[^\s]*[rfRF])", "Destructive Git rm on working tree"),
    (r"\bsudo\b", "Privilege escalation (sudo)"),
    (r"\bsu\b", "User switching (su)"),
    (r"\bchmod\s+[0-7x+rw-]+", "Permission modification (chmod)"),
    (r"\bchown\b", "Ownership modification (chown)"),
    # Git Remote Push Safeguards (Allows non-force feature branch pushes, blocks force/delete/mirror/protected branch push)
    (r"\bgit\s+push\b.*(--force(?!-)\b|-f\b|\+[\w/.-]+)", "Destructive Git force push / overwrite (--force / -f / +ref)"),
    (r"\bgit\s+push\b.*(--delete\b|(?<!\S):\w+)", "Destructive Git remote branch deletion (--delete)"),
    (
        r"\bgit\s+push\b.*(--all\b|--mirror\b|--tags\b)",
        "Dangerous global or mirror Git push (--all / --mirror / --tags)",
    ),
    (
        r"\bgit\s+push\b.*(?:\borigin\s+|\s+|HEAD:)(main\b|master\b|develop\b|release[/_-][^\s]+|prod\b|production\b)",
        "Direct Git push to protected branch (main/master/develop/release/prod)",
    ),
    (r"\bgit\s+reset\s+--hard\b", "Destructive Git reset"),
    (r"\bgit\s+clean\s+-[fF]", "Destructive Git clean"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "Denial of Service / Fork bomb"),
    # Disk, Volume, & Filesystem Manipulation (Linux & macOS)
    (
        r"\bdiskutil\s+(eraseVolume|eraseDisk|partitionDisk|reformat|zeroDisk|randomDisk|secureErase|splitPartition|mergePartitions|apfs\s+(deleteVolume|deleteContainer|deleteSnapshot|eraseVolume)|cs\s+delete|appleRAID\s+delete)\b|"
        r"\b(mkfs|newfs_[a-z0-9_]+|dd|fdisk|pdisk|parted|gpt\s+[a-z]+)\b|"
        r"\basr\s+restore\b.*(--erase|-erase)|"
        r"\btmutil\s+(delete|deletelocalsnapshots|deleteappliancesnapshot)\b",
        "Destructive disk / volume formatting and partitioning",
    ),
    # macOS System Security, Integrity, & Firmware (SIP, NVRAM, Gatekeeper, Bootloader)
    (
        r"\bcsrutil\s+(disable|clear|authenticated-root\s+disable)\b|"
        r"\bspctl\s+(--master-disable|--disable)\b|"
        r"\bbputil\s+(-k|-s|-p)\b|"
        r"\bnvram\s+(-c|-d\b|[a-zA-Z0-9_-]+=[^\s]+)|"
        r"\bbless\s+(--mount|--setBoot|--folder)\b",
        "macOS System security / firmware integrity mutation",
    ),
    # macOS Directory Services & User Account Deletion / Password Mutation
    (
        r"\bdscl\s+[\w\./-]+\s+(-delete|-passwd|-create)\b|" r"\bsysadminctl\s+-(deleteUser|resetPasswordFor)\b",
        "macOS User account / Directory Services mutation",
    ),
    # macOS Keychain & Certificate Deletion
    (
        r"\bsecurity\s+(delete-keychain|delete-generic-password|delete-internet-password|delete-certificate|delete-identity|remove-identity-preference|create-keychain)\b",
        "macOS Keychain & credentials deletion",
    ),
    # macOS Firewall & Network Disruption
    (
        r"\bpfctl\s+(-f|-F\s+all|-d\b)|"
        r"\bnetworksetup\s+(-setdnsservers|-setsearchdomains|-setmanual|-removeallnetworkservices|-ordernetworkservices)\b",
        "macOS Firewall / Network disruption",
    ),
    # Bitwarden CLI: mass secret dump & irreversible vault destruction (Rule 17 + Rule 9)
    (
        r"\bbw\b.*?\blist\s+items\b",
        "Bitwarden mass secret dump (bw list items) - violates Secret Redacted-Read Mandate (Rule 17)",
    ),
    (
        r"\bbw\b.*?\bdelete\s+item\b(?!-)",
        "Bitwarden irreversible vault item deletion (bw delete item) - Non-VCS T4 irreversible mutation (Rule 9)",
    ),
]

# 4b. Process-environment-dump denylist (separate from CRITICAL_SHELL_PATTERNS because it
#     needs command-boundary anchoring AND quote-stripping that the generic loop must not
#     apply globally — globally stripping quotes would fail-open on e.g. `bash -c "rm -rf /"`).
#
#     The macOS/GNU/Linux `ps` env-dump vector is: `ps e` / `ps eww` / `ps axeww` /
#     `ps auxe` (BSD bare lowercase `e` flag), `ps -wwE` (macOS uppercase `E`), plus
#     `launchctl getenv` and `/proc/*/environ`. A bare lowercase `e` flag is the BSD env
#     marker; `ps -e` (GNU "select all processes") has a dash prefix and is NOT env-dump,
#     so it is deliberately excluded.
_CMD_BOUNDARY = r"(?:^|[\n;&|()]\s*|&&\s*|\|\|\s*)"


def _strip_quoted(text: str) -> str:
    """Remove single/double-quoted contents so literal text (grep patterns, commit
    messages, heredoc-less echo bodies) that merely MENTIONS a dangerous term is not
    matched by the process-env-dump denylist. Quoted shell strings are literal
    arguments, never an executed `ps` invocation."""
    return re.sub(r"'[^']*'", "''", re.sub(r'"[^"]*"', '""', text))


def check_process_env_dump(cmd_str: str):
    """Return (is_dangerous, reason) for process-environment-dump commands.

    Matched against a quote-stripped command and anchored to a shell command boundary,
    so `ps eww` / `ps -wwE` / `launchctl getenv` / `/proc/*/environ` are flagged ONLY
    when they are an actual command invocation — not when the substring appears inside a
    heredoc body, a grep pattern, or a commit-message literal.
    """
    # /proc/<pid>/environ is a direct file read; match against the raw command (not the
    # quote-stripped one) since the path is not a quoted string. Covers numeric pids
    # (123, ${123}, $123, * wildcard) and named shell vars ($PPID, $PID).
    if re.search(r"/proc/(?:\$[A-Za-z_][A-Za-z0-9_]*|\$?\{?[0-9*]+\}?|[0-9*]+)/environ\b", cmd_str):
        return True, "Process environment file read (/proc/*/environ) — secret exposure"
    scan = _strip_quoted(cmd_str)
    if re.search(_CMD_BOUNDARY + r"launchctl\s+getenv\b", scan):
        return True, "launchd environment read (launchctl getenv) — secret exposure"
    # BSD env flag: a bare (no dash) alphabetic token containing lowercase `e`
    # (e, eww, axeww, auxe). `ps -e` (dash prefix) is GNU "all processes" -> allowed.
    if re.search(_CMD_BOUNDARY + r"ps\s+(?:-\S+\s+|\d+\s+)*[a-z]*e[a-z]*(?=\s|$|[;&|])", scan):
        return True, "Process listing exposing environment variables (ps e/eww/axeww) — secret leakage risk"
    # macOS env flag: `-wwE` (uppercase E distinguishes it from GNU `ps -e`).
    if re.search(_CMD_BOUNDARY + r"ps\s+(?:-\S+\s+|\d+\s+)*-[a-zA-Z]*E(?=\s|$|[;&|])", scan):
        return True, "Process listing exposing environment variables (ps -wwE) — secret leakage risk"
    return False, None


# 5. Commands that READ or EXFILTRATE files
READ_COMMANDS = {
    "cat",
    "head",
    "tail",
    "grep",
    "rg",
    "less",
    "more",
    "awk",
    "sed",
    "strings",
    "base64",
    "xxd",
    "jq",
    "source",
}
NETWORK_EXFIL_COMMANDS = {"curl", "wget", "nc", "ncat", "socat", "scp", "rsync", "ssh"}

# 6. Shell file write commands targeting Hermes sandbox
SHELL_WRITE_COMMANDS = {"cp", "mv", "touch", "mkdir", "rsync", "tar", "unzip", "tee", "wget", "curl", "dd"}

# 7. Dynamic Substitution Patterns $(cat ...) or `cat ...`
DYNAMIC_SUBSTITUTION_PATTERN = re.compile(
    r"""(
        \$\(\s*(cat|head|tail|grep|find|awk|sed|<)\b|
        `\s*(cat|head|tail|grep|find|awk|sed|<)\b
    )""",
    re.VERBOSE | re.IGNORECASE,
)

# 7b. Resolvable Static Dynamic Substitution Patterns $(cat ...), $(< ...), `cat ...`
STATIC_RESOLVABLE_SUBSTITUTION_PATTERN = re.compile(
    r"""(
        \$\(\s*(?:cat|<)\s+([^)$|;&`]+?)\s*\)|
        `\s*cat\s+([^`$|;&]+?)\s*`
    )""",
    re.VERBOSE | re.IGNORECASE,
)

# Shell redirection tokens (fd + operator + target, e.g. '2>/dev/null', '>/dev/null',
# '2>&1', '<input', '2>>log') are not file arguments and must not be treated as paths.
REDIRECT_ARG_RE = re.compile(r"^[0-9]*[<>]")

# 8. Dangerous Python AST modules & functions
DANGEROUS_PY_MODULES = {"socket", "requests", "urllib", "http.client", "ftplib", "smtplib"}
DANGEROUS_PY_CALLS = {"eval", "exec", "__import__", "compile"}

# 8b. Whitespace-insensitive dangerous-token guard. Normalization candidates
# (dedent/flatten) can reconstruct a benign-looking AST from a split dangerous
# token (e.g. "__impor\nt__(...)" or "import sock\net"), turning a fail-closed
# SyntaxError into a fail-open SAFE. Compacting all whitespace before matching
# defeats that evasion regardless of the candidate that ultimately parses.
# Trailing (?![a-zA-Z0-9_]) boundaries avoid false-positives on benign module
# prefixes (socketio, httpclient, urllib3).
_DANGEROUS_COMPACT_PATTERN = re.compile(
    r"__import__(?![a-zA-Z0-9_])|eval\(|exec\(|compile\(|"
    r"(?:import|from)(?:socket|requests|urllib|ftplib|smtplib|http)(?![a-zA-Z0-9_])",
    re.IGNORECASE,
)


def _strip_strings_and_comments(code_str: str) -> str:
    """Remove STRING and COMMENT tokens so literals/comments that merely mention a
    dangerous term do not trigger the compact dangerous-token guard."""
    try:
        tokens = list(_tokenize.generate_tokens(io.StringIO(code_str).readline))
    except Exception:
        return code_str  # untokenizable (e.g. split token) -> scan raw text
    return "".join(tok.string for tok in tokens if tok.type not in (_tokenize.STRING, _tokenize.COMMENT))


def _compact_dangerous_token(code_str: str) -> Optional[str]:
    """Return the matched dangerous token after whitespace-compacting the code with
    string/comment literals removed, or None if no dangerous token is present."""
    # Unescape first so '-c' captures that carry \" / \' escapes tokenize cleanly
    # (otherwise a string literal like print(\"import socket\") cannot be recognized
    # as a STRING token and would false-positive).
    unescaped = code_str.replace('\\"', '"').replace("\\'", "'")
    compact_raw = re.sub(r"\s+", "", unescaped)
    if not _DANGEROUS_COMPACT_PATTERN.search(compact_raw):
        return None  # fast path: nothing dangerous even before stripping literals
    compact_clean = re.sub(r"\s+", "", _strip_strings_and_comments(unescaped))
    m = _DANGEROUS_COMPACT_PATTERN.search(compact_clean)
    return m.group(0) if m else None


# Tool Definition for Tool-Calling Semantic Inspector
INSPECTOR_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file_content",
            "description": "Read content of a regular local text file to inspect dynamic parameters before command execution. Returns up to 8KB.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to the file to inspect (e.g. 'safe_list.txt')"}
                },
                "required": ["file_path"],
            },
        },
    }
]


def safe_read_file_content(file_path: str, max_bytes: int = 8192) -> tuple[bool, str]:
    """Safely read text file content with 5 defensive guardrails:
    1. Canonical realpath resolution (prevents symlink loops)
    2. S_ISREG check (prevents FIFOs, sockets, character/block devices)
    3. Sensitive file exclusion (refuses direct read of .env / id_rsa)
    4. Max byte limit (8KB max to prevent memory exhaustion)
    5. Python native direct I/O (prevents shell subshell re-entrancy)
    """
    try:
        clean_path = Path(file_path.strip().strip("'\"")).expanduser().resolve()
        path_str = str(clean_path)

        # Guard: Never read secrets
        if SENSITIVE_FILE_PATTERN.search(path_str):
            return False, f"Refused read: Path contains sensitive credentials '{path_str}'"

        # Guard: Never read system root directories (including macOS /private/etc, /private/var logs)
        if re.search(
            r"^/(?:etc|System|Library|dev|proc|sys|private/etc|var/(?!folders/|tmp/)|private/var/(?!folders/|tmp/))",
            path_str,
            re.IGNORECASE,
        ):
            return False, f"Refused read: System/device directory path '{path_str}'"

        if not clean_path.exists():
            return False, f"File does not exist: '{path_str}'"

        st = clean_path.stat()
        if not stat.S_ISREG(st.st_mode):
            return False, f"Refused read: Target is not a regular file (FIFO/socket/device): '{path_str}'"

        with open(clean_path, encoding="utf-8", errors="replace") as f:
            content = f.read(max_bytes)
            return True, content
    except Exception as e:
        return False, f"Safe read error: {e}"


def resolve_dynamic_substitutions_locally(
    cmd_str: str, max_hops: int = 2
) -> tuple[bool, str, Optional[str], Optional[str]]:
    """Deterministically resolve static local dynamic substitutions (e.g. $(cat file), `cat file`, $(< file))
    using safe_read_file_content with 5 Anti-Loop Guardrails.

    Returns:
        (is_resolved: bool, resulting_cmd_or_error: str, layer_if_error: Optional[str], error_reason: Optional[str])
    """
    current_cmd = cmd_str
    visited_files = set()

    for _hop in range(max_hops):
        matches = list(STATIC_RESOLVABLE_SUBSTITUTION_PATTERN.finditer(current_cmd))
        if not matches:
            break

        # Process matches right-to-left to preserve slice indices
        for match in reversed(matches):
            full_sub = match.group(0)
            raw_arg = (match.group(2) or match.group(3) or "").strip()
            if not raw_arg:
                return (
                    False,
                    current_cmd,
                    DecisionLayer.LLM_INSPECTOR,
                    f"Empty file argument in dynamic substitution '{full_sub}'",
                )

            try:
                sub_files = shlex.split(raw_arg)
            except Exception:
                sub_files = raw_arg.split()

            # Drop shell redirection tokens (e.g. '2>/dev/null', '>/dev/null',
            # '2>&1', '<input') — they are not file arguments to read.
            sub_files = [f for f in sub_files if not REDIRECT_ARG_RE.match(f)]

            combined_chunks = []
            for fpath in sub_files:
                norm_path = str(Path(fpath.strip().strip("'\"")).expanduser().resolve())
                if norm_path in visited_files:
                    return (
                        False,
                        current_cmd,
                        DecisionLayer.LLM_INSPECTOR,
                        f"Circular reference loop detected for '{fpath}'",
                    )
                visited_files.add(norm_path)

                success, content = safe_read_file_content(fpath)
                if not success:
                    if (
                        SENSITIVE_FILE_PATTERN.search(fpath)
                        or "sensitive" in content.lower()
                        or "secret" in content.lower()
                    ):
                        err_layer = DecisionLayer.SECRET_GUARD
                    elif (
                        re.search(r"^/(etc|var|System|Library|dev|proc|sys|private/(etc|var))/", fpath)
                        or "system" in content.lower()
                    ):
                        err_layer = DecisionLayer.SHELL_CRITICAL
                    else:
                        err_layer = DecisionLayer.LLM_INSPECTOR
                    return False, current_cmd, err_layer, f"Dynamic substitution blocked on '{fpath}': {content}"

                clean_lines = " ".join(content.strip().splitlines())
                combined_chunks.append(clean_lines)

            replacement = " ".join(combined_chunks)
            current_cmd = current_cmd[: match.start()] + replacement + current_cmd[match.end() :]

    return True, current_cmd, None, None


class PythonASTAuditor(ast.NodeVisitor):
    """AST visitor to audit Python code safety before execution with Forgejo exceptions."""

    def __init__(self, raw_code: str = ""):
        self.raw_code = raw_code
        self.is_safe = True
        self.reasons: list[str] = []
        self.imported_net_modules = set()
        self.has_non_forgejo_net = False

    def visit_Import(self, node):
        for alias in node.names:
            base_mod = alias.name.split(".")[0]
            if base_mod in DANGEROUS_PY_MODULES:
                self.imported_net_modules.add(base_mod)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            base_mod = node.module.split(".")[0]
            if base_mod in DANGEROUS_PY_MODULES:
                self.imported_net_modules.add(base_mod)
        self.generic_visit(node)

    def visit_Call(self, node):
        # eval / exec check
        if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_PY_CALLS:
            self.is_safe = False
            self.reasons.append(f"Dynamic code execution call: {node.func.id}()")

        # open('...') check
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            if node.args and isinstance(node.args[0], ast.Constant):
                path_str = str(node.args[0].value)
                if SENSITIVE_FILE_PATTERN.search(path_str) and ".zshenv.local" not in path_str:
                    self.is_safe = False
                    self.reasons.append(f"Attempting to open sensitive file: '{path_str}'")

                # Check write mode into Hermes Sandbox
                if HERMES_SANDBOX_PATTERN.search(path_str):
                    mode = "r"
                    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                        mode = str(node.args[1].value)
                    for kw in node.keywords:
                        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                            mode = str(kw.value.value)
                    if any(m in mode for m in ("w", "a", "x", "+")):
                        self.is_safe = False
                        self.reasons.append(
                            f"Forbidden write operation to Hermes Sandbox: '{path_str}' (mode='{mode}')"
                        )

        # subprocess / os.system check
        if isinstance(node.func, ast.Attribute) and node.func.attr in (
            "run",
            "Popen",
            "system",
            "call",
            "check_output",
        ):
            for arg in node.args:
                if isinstance(arg, ast.Constant):
                    val_str = str(arg.value)
                    if HERMES_SANDBOX_PATTERN.search(val_str) and any(
                        w in val_str for w in (">", "cp ", "mv ", "touch ", "rm ")
                    ):
                        self.is_safe = False
                        self.reasons.append(f"Process call attempting write/mutation to Hermes Sandbox: '{val_str}'")

        self.generic_visit(node)

    def evaluate_network_calls(self):
        """Evaluate imported network modules against Forgejo whitelist rules."""
        if not self.imported_net_modules:
            return

        urls = re.findall(r"https?://[a-zA-Z0-9_.:/-]+", self.raw_code)
        if not urls:
            self.is_safe = False
            self.reasons.append(
                f"Network module imported without identifiable URL literal: {self.imported_net_modules}"
            )
            return

        for url in urls:
            if not FORGEJO_HOST_PATTERN.match(url):
                self.is_safe = False
                self.reasons.append(f"Network call to external (non-Forgejo) target: '{url}'")
                return

            if re.search(r"method\s*=\s*['\"]DELETE['\"]", self.raw_code, re.IGNORECASE) or re.search(
                r"requests\.delete\(", self.raw_code, re.IGNORECASE
            ):
                self.is_safe = False
                self.reasons.append(f"Forbidden HTTP DELETE request to Forgejo: '{url}'")
                return

            is_issues = bool(FORGEJO_ISSUES_PATTERN.search(url))
            has_post_patch = bool(
                re.search(
                    r"(method\s*=\s*['\"](POST|PATCH|PUT)['\"]|data\s*=|requests\.(post|patch|put)\()", self.raw_code
                )
            )

            if has_post_patch and not is_issues:
                if not re.search(r"/api/v1/(user|users)", url):
                    self.is_safe = False
                    self.reasons.append(f"Non-GET request to non-issues Forgejo endpoint: '{url}'")


def _python_normalization_candidates(code_str: str) -> list[str]:
    """Generate ordered parseable normalization candidates for inline Python source.

    Handles formatting artifacts captured from TUI/agent dialogs:
    1. Common leading indentation across all lines (textwrap.dedent).
    2. Tab/space mixing (expandtabs before dedent).
    3. Escaped quotes (unescape candidates).
    4. TUI soft-wrap flattening a single logical line onto multiple screen rows.

    Candidates are ordered most-preserving -> most-normalized so semantic
    fidelity is preferred whenever a variant parses. Per-line lstrip is
    deliberately NOT included: it is semantic-changing and can reconstruct a
    benign-but-different AST from a split+indented dangerous token (fail-open).
    """
    raw = code_str
    unescaped = raw.replace('\\"', '"').replace("\\'", "'")
    dedented = textwrap.dedent(raw)
    dedented_unescaped = textwrap.dedent(unescaped)
    tabs_expanded = textwrap.dedent(raw.expandtabs(4))
    flattened = " ".join(line.strip() for line in raw.splitlines())

    candidates: list[str] = []
    for cand in (
        raw,
        dedented,
        unescaped,
        dedented_unescaped,
        tabs_expanded,
        flattened,
    ):
        if cand and cand not in candidates:
            candidates.append(cand)
    return candidates


def audit_python_code(code_str: str) -> tuple[bool, str]:
    """Parse and audit Python source code with Forgejo whitelist."""
    # Whitespace-insensitive dangerous-token guard (defeats split-token evasions
    # that a normalization candidate could otherwise reconstruct as benign).
    compact_hit = _compact_dangerous_token(code_str)
    if compact_hit:
        return False, f"Python AST: dangerous token detected '{compact_hit}'"

    tree = None
    effective_code = code_str
    syntax_err = None

    for cand in _python_normalization_candidates(code_str):
        try:
            tree = ast.parse(cand)
            effective_code = cand
            break
        except SyntaxError as e:
            syntax_err = e

    if tree is None:
        return False, f"Python SyntaxError during AST audit: {syntax_err}"

    auditor = PythonASTAuditor(raw_code=effective_code)
    auditor.visit(tree)
    auditor.evaluate_network_calls()
    if not auditor.is_safe:
        return False, "; ".join(auditor.reasons)
    return True, "Python AST: Safe"


MINIMAL_INSPECTOR_SYSTEM_PROMPT = (
    "You are a strict security inspector subagent for Herdr SmartGate. "
    "A command contains dynamic command substitution (e.g. $(cat ...), <(cat ...), $(git ...)). "
    "Use `read_file_content` to inspect referenced files only when necessary. "
    "Auto-Approve Safe Patterns:\n"
    "- Target file is in safe workspace/tmp and contains benign parameters, configuration, or tests.\n"
    "- Read-only dynamic substitutions (e.g. $(git rev-parse ...), $(git log ...), $(cat /tmp/safe_param.txt)).\n"
    "Block if content contains:\n"
    "1) Secrets (.env, id_rsa, tokens, credentials, keys),\n"
    "2) System root paths (/etc, /System, /var, /usr, /dev),\n"
    "3) Destructive commands or dangerous payloads.\n"
    "Respond ONLY in JSON format: "
    '{"is_safe": true|false, "reason": "<concise explanation>", "taxonomy": {"origin": "I", "consequence": "NONE"|"EXFIL"|"DEST"|"INT"|"AVAIL"|"PERS", "mechanism": "string"}}\n'
    "Adversarial Exemplars:\n"
    '- Target `/tmp/safe.txt` (\'hello world\'): {"is_safe": true, "reason": "File content verified safe", "taxonomy": {"origin": "I", "consequence": "NONE", "mechanism": "verified-param"}}\n'
    '- Target `$(git rev-parse HEAD)`: {"is_safe": true, "reason": "Read-only git metadata substitution", "taxonomy": {"origin": "I", "consequence": "NONE", "mechanism": "git-meta-read"}}\n'
    '- Target `.env` (\'API_KEY=xyz\'): {"is_safe": false, "reason": "Detected API key credentials", "taxonomy": {"origin": "I", "consequence": "EXFIL", "mechanism": "env-leak-attempt"}}\n'
    '- Target `/etc/shadow` (\'root:...\'): {"is_safe": false, "reason": "Access to system sensitive shadow database", "taxonomy": {"origin": "I", "consequence": "DEST", "mechanism": "system-root-access"}}'
)


def _cache_cloud_verdict(cache_key, cmd_str, is_safe, reason, decision_layer, cwd, scope, agent_id, origin):
    """Best-effort store of a resolved cloud-judge verdict into the scoped cache (B1).

    Only unsafe/defers (is_safe=False) are cached. A 'safe' verdict is NOT cached:
    a correct 'safe' judgment could be replayed after the underlying file/context
    changed (dynamic-substitution TOCTOU), silently auto-approving a now-dangerous
    command. Unsafe verdicts remain safe to replay (they still defer to a human).
    """
    if not cache_key:
        return
    if is_safe:
        return
    try:
        from core.session_cache import store_cached_result

        try:
            layer = DecisionLayer(decision_layer)
        except (ValueError, TypeError):
            layer = DecisionLayer.CLOUD_JUDGE
        try:
            origin_enum = Origin(origin)
        except (ValueError, TypeError):
            origin_enum = Origin.AGENT
        taxonomy = derive_taxonomy(cmd_str, layer, is_safe, reason, origin=origin_enum)

        store_cached_result(
            cache_key=cache_key,
            raw_cmd=cmd_str,
            is_safe=is_safe,
            safety_reason=reason,
            decision_layer=decision_layer,
            taxonomy=taxonomy,
            cwd=cwd,
            scope=scope,
            agent_id=agent_id,
            origin=origin,
        )
    except Exception:
        pass


def audit_with_cloud_judge(
    cmd_str: str,
    context: str = "",
    endpoint: Optional[str] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    reasoning_effort: str = DEFAULT_REASONING_EFFORT,
    cwd: str = "",
    scope: str = "default",
    agent_id: str = "default",
    origin: str = "A",
    raise_on_error: bool = False,
    confidence_threshold: Optional[float] = None,
) -> tuple[bool, str]:
    """Second-tier cloud judge for uncertain cases (gray-zone PROMPT, unhandled dialogs).

    Returns (is_safe, reason). Fail-closed: any error / unparseable / uncertain
    / below-threshold verdict returns is_safe=False so the caller defers to human
    review. M6: an auto-approve requires BOTH is_safe=true AND confidence >=
    confidence_threshold (default from get_cloud_judge_config() = 0.9).
    """
    if confidence_threshold is None:
        confidence_threshold = get_cloud_judge_config().get("cloud_judge_min_confidence", 0.9)
    # 0. Check Pane-scoped Session Memory BEFORE expensive LLM call (ADR-010)
    try:
        from core.session_memory import check_pane_approval, record_pane_approval
        pane_cached = check_pane_approval(scope, cmd_str, cwd=cwd)
        if pane_cached:
            return pane_cached[0], pane_cached[1]
    except Exception:
        pass

    # Scoped cache (mirrors the dynamic-substitution inspector; key is namespaced 'cj:').
    cache_key = None
    if not is_shadow_mode():
        try:
            from core.session_cache import compute_cache_key, get_cached_result

            # M6: the effective confidence_threshold is part of the verdict
            # semantics — omitting it would serve a stale cached auto-approve for
            # the TTL window after a runtime threshold change. Include it so a
            # threshold change re-audits.
            cache_key = compute_cache_key(
                f"cj:{cmd_str}||{context}||conf:{confidence_threshold}",
                cwd=cwd,
                scope=scope,
                agent_id=agent_id,
                origin=origin,
            )
            cached = get_cached_result(cache_key)
            if cached:
                return cached["is_safe"], cached["safety_reason"]
        except Exception:
            pass

    target_endpoint, target_model, target_key = resolve_guard_llm_config(endpoint, model, api_key)
    if not target_endpoint:
        return False, "Cloud judge not configured; deferred to human review"

    user_content = f"Inspect and decide whether to auto-approve this command:\n```\n{redact_for_cloud(cmd_str)}\n```"
    if context:
        user_content += f"\n\nContext:\n{redact_for_cloud(context)}"

    messages = [
        {"role": "system", "content": GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]

    try:
        # INV-PH1-6: flip to "gatekeeper" ONLY around the LLM call; reset via
        # finally even on exception; cache hits / short-circuits never flip.
        _emit_phase("gatekeeper")
        try:
            data = post_cloud_judge(messages, target_endpoint, target_model, target_key, reasoning_effort)
        finally:
            _emit_phase("inspector")
        content_str = data["choices"][0].get("message", {}).get("content", "")
        parsed = parse_json_verdict(content_str)
        if parsed is not None:
            is_safe, conf, reason = parsed
            approved = bool(is_safe) and conf is not None and conf >= confidence_threshold
            if not approved:
                reason = f"{reason} (confidence={conf}, threshold={confidence_threshold})"
            _cache_cloud_verdict(cache_key, cmd_str, approved, reason, "CLOUD_JUDGE", cwd, scope, agent_id, origin)
            if approved:
                try:
                    from core.session_memory import record_pane_approval
                    record_pane_approval(scope, cmd_str, decision_layer="CLOUD_JUDGE", reason=reason, cwd=cwd)
                except Exception:
                    pass
            return approved, reason
        if raise_on_error:
            raise RuntimeError(f"Unparseable cloud judge output: {content_str}")
        return False, f"[Cloud Judge] Uncertain verdict: {content_str[:80]}; deferred to human"
    except Exception as e:
        if raise_on_error:
            raise
        return False, f"Cloud judge offline ({e}); deferred to human"


def audit_dynamic_substitution_with_llm(
    cmd_str: str,
    endpoint: Optional[str] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    reasoning_effort: str = DEFAULT_REASONING_EFFORT,
    max_hops: int = 2,
    raise_on_error: bool = False,
    cwd: str = "",
    scope: str = "default",
    agent_id: str = "default",
    origin: str = "I",
) -> tuple[bool, str]:
    """Semantic inspection of dynamic parameters with 5 Anti-Loop Guardrails and scoped LLM caching.

    Routes to the configured OpenAI-compatible cloud judge (OpenAI default; DeepSeek
    available via OPENAI_BASE_URL). If no endpoint is configured, or the judge is
    unreachable / uncertain, fails closed to human review.

    M6 (deliberate, comment-only scope): this inspector path applies NO confidence
    threshold. It is a fail-closed semantic DETECTION gate, not an auto-approve
    lever — unlike `audit_with_cloud_judge`, a positive verdict here is NOT
    sufficient for key injection: the caller must still pass a downstream
    auto-approve gate (e.g. the cloud-judge confidence gate or a session-memory /
    human approval). An unsafe / uncertain / unreachable verdict always defers to
    human review. Gating this path by confidence would be redundant with
    `audit_with_cloud_judge` AND would weaken detection: a low-confidence-but-real
    substitution must never be silently dropped from the audit trail.
    """
    # 0. Check Pane-scoped Session Memory BEFORE expensive LLM call (ADR-010)
    try:
        from core.session_memory import check_pane_approval, record_pane_approval
        pane_cached = check_pane_approval(scope, cmd_str, cwd=cwd)
        if pane_cached:
            return pane_cached[0], pane_cached[1]
    except Exception:
        pass

    # Check scoped LLM cache (B1: cache strictly scoped to expensive LLM tier)
    cache_key = None
    if not is_shadow_mode():
        try:
            from core.session_cache import compute_cache_key, get_cached_result

            cache_key = compute_cache_key(cmd_str, cwd=cwd, scope=scope, agent_id=agent_id, origin=origin)
            cached = get_cached_result(cache_key)
            if cached:
                return cached["is_safe"], cached["safety_reason"]
        except Exception:
            pass

    target_endpoint, target_model, target_key = resolve_guard_llm_config(endpoint, model, api_key)
    if not target_endpoint:
        return (
            False,
            "Dynamic command substitution $(cat ...) detected; cloud judge not configured; deferred to human review",
        )

    messages = [
        {"role": "system", "content": MINIMAL_INSPECTOR_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"Inspect the dynamic parameters of this command before approval:\n```\n{redact_for_cloud(cmd_str)}\n```",
        },
    ]

    visited_paths = set()

    # INV-PH1-6: flip to "gatekeeper" around the WHOLE multi-hop LLM loop (one
    # flip, not per hop); reset via finally on every exit path (verdict, error,
    # max-hops exhaustion).
    _emit_phase("gatekeeper")
    try:
        for _hop in range(max_hops):
            try:
                data = post_cloud_judge(
                    messages, target_endpoint, target_model, target_key, reasoning_effort, tools=INSPECTOR_TOOLS
                )
                choice = data["choices"][0]
                message = choice.get("message", {})
                tool_calls = message.get("tool_calls", [])

                if tool_calls:
                    messages.append(message)
                    for tc in tool_calls:
                        fn_name = tc.get("function", {}).get("name")
                        fn_args_raw = tc.get("function", {}).get("arguments", "{}")
                        try:
                            fn_args = json.loads(fn_args_raw)
                        except Exception:
                            fn_args = {}

                        if fn_name == "read_file_content":
                            target_file = fn_args.get("file_path", "")
                            norm_path = str(Path(target_file).expanduser().resolve())

                            if norm_path in visited_paths:
                                tool_result = f"Error: Circular reference loop detected for '{norm_path}'"
                            else:
                                visited_paths.add(norm_path)
                                success, content = safe_read_file_content(target_file)
                                tool_result = content if success else f"Error: {content}"

                            messages.append(
                                {
                                    "role": "tool",
                                    "tool_call_id": tc.get("id", "call_1"),
                                    "content": redact_for_cloud(tool_result),
                                }
                            )
                    continue  # Next turn in loop

                # Final text response
                content_str = message.get("content", "")
                parsed = parse_json_verdict(content_str)
                if parsed is not None:
                    is_safe, _conf, reason = parsed  # M6: inspector keeps binary behavior (confidence discarded)
                    _cache_cloud_verdict(
                        cache_key, cmd_str, is_safe, reason, "LLM_INSPECTOR", cwd, scope, agent_id, origin
                    )
                    if is_safe:
                        try:
                            from core.session_memory import record_pane_approval
                            record_pane_approval(scope, cmd_str, decision_layer="LLM_INSPECTOR", reason=reason, cwd=cwd)
                        except Exception:
                            pass
                    return is_safe, reason
                if raise_on_error:
                    raise RuntimeError(f"Unparseable LLM inspector output: {content_str}")
                return False, f"[Cloud Judge] Uncertain verdict: {content_str[:80]}; delegating to human"

            except Exception as e:
                if raise_on_error:
                    raise
                # Fail-Safe to Human Review when the cloud inspector is unreachable
                return False, f"Dynamic substitution detected & cloud judge offline ({e}); requires human review"

        if raise_on_error:
            raise RuntimeError("Dynamic substitution inspection could not be completed within max hops")
        return False, "Dynamic substitution inspection could not be completed; requires human review"
    finally:
        _emit_phase("inspector")


def is_managed_git_safe_command(cmd_str: str) -> tuple[bool, Optional[str]]:
    """Check if curl/shell command is a safe Managed Git SCM (Forgejo, Gitea, GitHub, GitLab) operation."""
    if not MANAGED_GIT_HOST_PATTERN.search(cmd_str):
        return False, None

    if re.search(r"-X\s*DELETE\b", cmd_str, re.IGNORECASE):
        return False, "Managed Git HTTP DELETE is forbidden without human review"

    if MANAGED_GIT_ISSUES_PATTERN.search(cmd_str):
        return True, "Allowed Managed Git issues/pulls interaction"

    if not re.search(r"(-X\s*(POST|PUT|PATCH)|-d\s+|--data)", cmd_str, re.IGNORECASE):
        return True, "Allowed Managed Git GET request"

    if re.search(r"/(api/v1|api/v4|repos)/", cmd_str) and not re.search(r"(-X\s*DELETE)", cmd_str):
        return True, "Allowed Managed Git read API query"

    return False, "Unrecognized mutating request to Managed Git endpoint"


# Backward compatibility alias
is_forgejo_safe_command = is_managed_git_safe_command


class Origin(str, Enum):
    """Origin axis of 2D Taxonomy: who authored/triggered the command."""

    HUMAN = "H"  # Explicit human user direction
    AGENT = "A"  # Autonomous agent reasoning
    INJECTED = "I"  # Prompt injection / untrusted third-party payload
    EMERGENT = "E"  # Latent / unbound variable disaster


class Consequence(str, Enum):
    """Consequence axis of 2D Taxonomy: what security boundary is threatened."""

    NONE = "NONE"  # Benign operation without harmful side-effects
    DESTRUCTION = "DEST"  # Data loss / filesystem deletion / disk wipe
    EXFILTRATION = "EXFIL"  # Confidentiality breach / credential egress
    INTEGRITY = "INT"  # Silent tampering / config pollution / corruption
    AVAILABILITY = "AVAIL"  # DoS / resource exhaustion / fork bombs
    PERSISTENCE = "PERS"  # Privilege escalation / backdoor / unauthorized ssh key


class GateState(str, Enum):
    """Schengen Gate operation posture."""

    ENFORCE = "ENFORCE"  # Active blocking & gatekeeping
    OBSERVE = "OBSERVE"  # Shadow mode: counterfactual evaluation without blocking
    DEGRADED = "DEGRADED"  # Fail-open for local safe reads, fail-closed for egress/mutations


def is_shadow_mode() -> bool:
    """Check if SCHENGEN_SHADOW_MODE kill-switch environment variable is active."""
    val = os.environ.get("SCHENGEN_SHADOW_MODE", "0").strip().lower()
    return val in ("1", "true", "yes", "on", "shadow", "observe")


class DecisionLayer(str, Enum):
    """Standard inspection layers for Herdr Schengen (SmartGate)."""

    ALLOWLIST = "ALLOWLIST"  # Layer 0: User-persisted allowlist regex
    MANAGED_GIT_GUARD = "MANAGED_GIT_GUARD"  # Layer 1: Managed Git SCM (Forgejo, Gitea, GitHub, GitLab) policy
    FORGEJO_GUARD = "MANAGED_GIT_GUARD"  # Layer 1 (Alias for backward compatibility)
    SAST_SHELLCHECK = "SAST_SHELLCHECK"  # Layer 2a: SAST ShellCheck variable hazard pre-filter (SC2115, SC2154)
    SAST_SEMGREP = "SAST_SEMGREP"  # Layer 2b: SAST Semgrep remote pipe & reverse shell pre-filter
    SHELL_CRITICAL = "SHELL_CRITICAL"  # Layer 2: Critical destructive shell operations (rm -rf, sudo, git reset --hard)
    SANDBOX_GUARD = "SANDBOX_GUARD"  # Layer 3: Hermes Docker/microVM Sandbox write isolation
    PYTHON_AST = "PYTHON_AST"  # Layer 4: Python static AST analysis (eval/exec, opens, subprocess writes)
    SECRET_GUARD = "SECRET_GUARD"  # Layer 5: Sensitive file & secret pattern matching (.env, id_rsa, hosts.yml)
    LLM_INSPECTOR = "LLM_INSPECTOR"  # Layer 6: L2 Tool-Calling LLM Dynamic Parameter Semantic Inspector
    CLOUD_JUDGE = (
        "CLOUD_JUDGE"  # Layer 6b: Second-tier OpenAI-compatible cloud judge (gray-zone PROMPT, unhandled dialogs)
    )
    GRAY_ZONE_MATRIX = "GRAY_ZONE_MATRIX"  # Layer 7: Non-VCS Irreversible Mutation Matrix (ADR-004 / SOP-12)
    FAST_TRACK_AST = "FAST_TRACK_AST"  # Layer 8: Fast-track static safe development operations
    NOT_ALLOWLISTED = "NOT_ALLOWLISTED"  # Fail-closed default: not in fast-track allowlist, requires human review
    HUMAN_APPROVED = "HUMAN_APPROVED"  # Novelty gate: canonical pattern has prior human approval (scope+TTL)
    PACKAGE_GUARD = "PACKAGE_GUARD"  # Package-manager 3-tuple classifier (MUTATING vs READ_ONLY)
    COMPLEXITY_TAX = "COMPLEXITY_TAX"  # Structural complexity deferral (never auto-approves)
    ORIGIN_GUARD = "ORIGIN_GUARD"  # Origin-based hard-escalate (INJECTED/EMERGENT never auto-approve)
    NORMALIZATION_AMBIGUOUS = "NORMALIZATION_AMBIGUOUS"  # Rendered/canonical identity is unavailable or lossy
    FAST_TRACK_WORKSPACE_ALLOWLIST = "FAST_TRACK_WORKSPACE_ALLOWLIST"  # Repo-local .schengen/ allowlist fast-track (issue #7207)


# INV-6: forensic / network primitives must NEVER fast-track (binary inspection / egress)
_FORENSIC_NETWORK_BIN_RE = re.compile(
    r"\b(strings|xxd|hexdump|od|base64|objdump|otool|curl|wget|ssh|scp|sftp|rsync|nc|ncat|socat|npx)\b",
    re.IGNORECASE,
)

# Issue #6935: sed is a language — enumerate SAFE forms as a closed whitelist.
_SED_INPLACE_RE = re.compile(r"(^|\s)-i(?:[A-Za-z0-9.]*)?(\s|$)|--in-place")
_SED_SAFE_SCRIPT_RE = re.compile(r"^\s*(\d+|\d+\s*,\s*\d+|\$)?\s*!?\s*p\s*$")

# INV-5: explicit closed enumeration of provably-benign read-only commands
FAST_TRACK_SAFE_COMMANDS = {
    "pwd", "echo", "date", "uname", "whoami", "id", "env", "printenv",
    "which", "type", "true", "false", "hostname", "uptime",
    "ls", "tree", "du", "df", "stat", "file", "readlink", "realpath",
    "dirname", "basename", "wc", "sort", "uniq",
    "cat", "head", "tail", "less", "more", "grep", "rg", "find",
}

# INV-5: safe (read-only) git subcommands, matched as anchored patterns
FAST_TRACK_SAFE_GIT_PATTERNS = (
    r"^git\s+status(?:\s|$)",
    r"^git\s+log(?:\s|$)",
    r"^git\s+diff(?:\s|$)",
    r"^git\s+show(?:\s|$)",
    r"^git\s+rev-parse(?:\s|$)",
    r"^git\s+rev-list(?:\s|$)",
    r"^git\s+describe(?:\s|$)",
    r"^git\s+ls-files(?:\s|$)",
    r"^git\s+blame(?:\s|$)",
    r"^git\s+shortlog(?:\s|$)",
    r"^git\s+grep(?:\s|$)",
    r"^git\s+remote(?:\s+(-v|--verbose))?(?:\s|$)",
    r"^git\s+stash\s+list(?:\s|$)",
    r"^git\s+branch(?:\s+(-a|-r|--all|--remote|--list|-l))?(?:\s|$)",
    r"^git\s+tag(?:\s+(-l|--list))?(?:\s|$)",
    r"^git\s+config\s+(--get|--list|--get-regexp)(?:\s|$)",
    # closed, side-effect-free version/help queries (obvious-safe)
    r"^git\s+--version(?:\s|$)",
    r"^git\s+-v(?:\s|$)",
    r"^git\s+--help(?:\s|$)",
)

# Read-only commands permitted inside a pure read-only pipeline (segments joined by | && ;)
READONLY_PIPELINE_COMMANDS = {
    "ls", "find", "tree", "du", "df", "stat", "file", "wc", "sort", "uniq",
    "pwd", "echo", "printf", "date", "uname", "whoami", "id", "env", "printenv",
    "which", "type", "hostname", "uptime", "dirname", "basename", "readlink", "realpath",
    "cat", "head", "tail", "less", "more", "grep", "rg", "sed", "awk", "jq",
    "cut", "tr", "column", "xargs",
}
# INV-SENS-2: broad/root-level targets that could sweep sensitive paths -> hard-escalate
_BROAD_WILDCARD_RE = re.compile(r"(^|\s)(~|~/|/(?:\s|$)|\.\*|\.\.(?:\s|$)|(?<!\S)\*(?!\S))(?:\s|$)")

# Pipeline separators that join a (possibly) multi-segment command
_PIPELINE_SEP_RE = re.compile(r"[|&;]")

# CLOSED set of interpreters / package CLIs for which a bare version/help query
# is provably side-effect-free. Deliberately NOT extended to arbitrary binaries —
# only these enumerated commands may ever be obvious-safe fast-tracked.
_OBVIOUS_SAFE_VERSION_BINS = (
    "node", "python", "python3", "pip", "pip3", "npm", "ruby", "go",
    "rustc", "cargo", "docker", "brew", "git",
)
# Anchored: `<bin> <flag>` with the version/help flag as the SOLE argument.
# Longer bins first so e.g. `pip3`/`python3` cannot be shadowed by shorter
# alternatives inside a non-backtracking engine; `\s` after the bin guarantees
# a real token boundary (never `python3.12 --version`, `nodejs -v`, ...).
_OBVIOUS_SAFE_VERSION_HELP_RE = re.compile(
    r"^\s*(?:python3|pip3|node|python|pip|npm|ruby|go|rustc|cargo|docker|brew|git)"
    r"\s+(?:--version|-v|-V|--help|-h)\s*$"
)


def _is_obvious_safe_version_help(cmd_str: str) -> bool:
    """True iff cmd_str is a CLOSED, trivially-safe version/help query.

    Recognizes exactly `<bin> <--version|-v|-V|--help|-h>` for the enumerated
    `_OBVIOUS_SAFE_VERSION_BINS`, with the flag as the SOLE argument. Hard
    gates (defense in depth, mirroring `_is_fast_track_allowlisted`):
      * NO command substitution (`$(` / backtick) — nothing dynamic;
      * NO redirection (`>` / `<` / `>>` / `<<` ...) — no write/egress shape;
      * NO pipeline / chaining separator (`|`, `&`, `;`, newline) — a single
        segment only.
    Everything else (scripts as arguments, extra args, pipes, mutation,
    egress, sensitive targets) fails closed and falls through to the normal
    gate layers. `node -e "rm -rf /"` carries a script argument, so it never
    matches; `cat ~/.ssh/id_rsa` is not a version/help shape at all.
    """
    if re.search(r"\$\(|`", cmd_str):
        return False
    if re.search(r">>?|<<?", cmd_str):
        return False
    if re.search(r"[|&;\n\r]", cmd_str):
        return False
    return _OBVIOUS_SAFE_VERSION_HELP_RE.match(cmd_str) is not None


def _is_safe_cd_target(directory: str) -> bool:
    """True iff `directory` is a concrete, non-escaping cd target (issue #3670).

    Accepts ONLY a concrete specific directory (e.g. `~/code/herdr-schengen`,
    `/Users/x/code/herdr-schengen`, relative `scripts/...`). Trailing slashes
    are normalized away FIRST so `../`, `~/`, `./` cannot slip past literal
    checks (PR #186 review finding), then rejects:
      * `..` path components anywhere (`..`, `../`, `../..`, `a/../b`);
      * bare/home/root anchors (`.`, `./`, `~`, `~/`, `~/.`, `/`, `//...`);
      * any target tripping the sensitive-file / sensitive-directory /
        broad-wildcard backstops.
    """
    if not directory:
        return False
    t = directory.rstrip("/")
    if not t:  # "/" / "//" ... -> pure root
        return False
    if t in (".", "..", "-", "~"):
        return False
    if t.startswith("//"):
        return False
    if t.endswith("/."):
        return False  # "~/.", "a/." -> anchor/dot-dir, not a concrete dir
    if any(comp == ".." for comp in t.split("/")):
        return False  # "..", "../..", "a/../b", "x/.."
    # Backstops (INV-SENS-1/2): never cd into a sensitive or broad/root target.
    if SENSITIVE_FILE_PATTERN.search(directory) or SENSITIVE_DIRECTORY_PATTERN.search(directory):
        return False
    if _BROAD_WILDCARD_RE.search(directory):
        return False
    return True


def _is_safe_cd_segment(seg: str) -> bool:
    """True iff seg is a `cd <specific-safe-dir>` (narrow carve-out, issue #3670).

    Primary regex accepts exactly ONE concrete dir token (`cd <dir>`); a quoted
    dir (e.g. `cd 'dir with spaces'`) is handled via the shlex fallback. Bare
    `cd`, `cd -/.`/`..`, home/root shorthand and sensitive/broad targets all
    fail closed. Used ONLY inside pure read-only chains — a mutating segment
    anywhere in the chain is still rejected by the surrounding guards.
    """
    if not seg or not seg.strip():
        return False
    m = re.match(r"^\s*cd\s+(\S+)\s*$", seg)
    if m:
        return _is_safe_cd_target(m.group(1))
    # shlex fallback: quoted directory token
    try:
        parts = shlex.split(seg)
    except ValueError:
        return False
    if len(parts) == 2 and parts[0] == "cd":
        return _is_safe_cd_target(parts[1])
    return False


_GIT_READ_SUBCOMMANDS = {
    "status", "diff", "log", "show", "rev-parse", "rev-list", "describe",
    "ls-files", "blame", "shortlog", "grep",
}
_GIT_PROTECTED_BRANCH_RE = re.compile(
    r"^(?:(?:refs/)?heads/)?(?:main|master|develop|prod|production|release(?:[/_-].*)?)$",
    re.IGNORECASE,
)
_GIT_REF_RE = re.compile(r"(?:HEAD|[A-Za-z0-9][A-Za-z0-9._/-]*)$")


def _parse_git_invocation(tokens: list[str]) -> Optional[tuple[Optional[str], str, list[str]]]:
    """Parse the closed global-option prefix used by routine Git workflows."""
    if not tokens or tokens[0] != "git":
        return None
    index, repo = 1, None
    if index < len(tokens) and tokens[index] == "-C":
        if index + 1 >= len(tokens) or not _is_safe_cd_target(tokens[index + 1]):
            return None
        repo = tokens[index + 1]
        index += 2
    if index >= len(tokens) or tokens[index].startswith("-"):
        return None
    return repo, tokens[index].lower(), tokens[index + 1:]


def _is_safe_git_ref(value: str) -> bool:
    return bool(
        _GIT_REF_RE.fullmatch(value)
        and ".." not in value
        and "//" not in value
        and "@{" not in value
        and not value.endswith(("/", ".", ".lock"))
    )


def _is_scoped_git_path(value: str) -> bool:
    if not value or value in {".", "./", ":/"} or value.startswith(("/", "~", ":")):
        return False
    if any(part == ".." for part in Path(value).parts) or any(ch in value for ch in "*?["):
        return False
    return not (SENSITIVE_FILE_PATTERN.search(value) or SENSITIVE_DIRECTORY_PATTERN.search(value))


def _classify_git_read(subcommand: str, args: list[str]) -> bool:
    if subcommand in _GIT_READ_SUBCOMMANDS:
        forbidden = {
            "--no-index", "--ext-diff", "--textconv", "--exec", "--output",
            "--paginate", "--exec-path", "--html-path", "--man-path", "--info-path",
            "--open-files-in-pager",
        }
        return not any(
            arg in forbidden
            or any(arg.startswith(f"{flag}=") for flag in forbidden)
            or (arg.startswith("--") and any(flag.startswith(arg) for flag in forbidden))
            for arg in args
        )
    if subcommand == "remote":
        return not args or args == ["-v"] or args == ["--verbose"] or (
            len(args) == 2 and args[0] == "get-url" and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", args[1]))
        )
    if subcommand == "branch":
        return not args or all(arg in {"-a", "--all", "-r", "--remotes", "--show-current"} for arg in args)
    if subcommand == "tag":
        return not args or args in (["-l"], ["--list"])
    return False


def _classify_git_add(args: list[str]) -> bool:
    if not args:
        return False
    paths = args[1:] if args[0] == "--" else args
    return bool(paths) and all(not path.startswith("-") and _is_scoped_git_path(path) for path in paths)


def _classify_git_commit(args: list[str]) -> bool:
    """Allow a new local commit only when its message is explicit."""
    if not args:
        return False
    index, has_message = 0, False
    while index < len(args):
        arg = args[index]
        if arg in {"-q", "--quiet", "--no-gpg-sign"}:
            index += 1
        elif arg in {"-m", "--message"}:
            if index + 1 >= len(args) or not args[index + 1]:
                return False
            has_message = True
            index += 2
        elif arg.startswith("--message=") and len(arg) > len("--message="):
            has_message = True
            index += 1
        elif arg.startswith("-m") and len(arg) > 2:
            has_message = True
            index += 1
        else:
            return False
    return has_message


def _push_target(refspec: str) -> Optional[str]:
    if refspec.startswith("+") or refspec.startswith(":") or refspec.count(":") > 1:
        return None
    if ":" in refspec:
        source, target = refspec.split(":", 1)
        if not source or not target or not _is_safe_git_ref(source) or not _is_safe_git_ref(target):
            return None
        return target
    return refspec if _is_safe_git_ref(refspec) else None


def _classify_git_push(args: list[str]) -> tuple[str, str]:
    """Classify one explicit remote/ref push without consulting network state."""
    if any(arg in {"--force", "-f", "--delete", "--all", "--mirror", "--tags"} for arg in args) or any(
        re.fullmatch(r"-[A-Za-z]*f[A-Za-z]*", arg) for arg in args
    ):
        return "DANGEROUS", "destructive push option"
    if any(arg.startswith("+") for arg in args):
        return "DANGEROUS", "force refspec"
    if any(arg.startswith("--force-") for arg in args):
        return "GATED", "lease/conditional force push requires human review"

    positional = []
    for arg in args:
        if arg in {"-u", "--set-upstream", "-q", "--quiet", "-v", "--verbose", "--porcelain", "--dry-run"}:
            continue
        if arg.startswith("-"):
            return "GATED", "unrecognized push option"
        positional.append(arg)
    if len(positional) != 2 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", positional[0]):
        return "GATED", "push requires one named remote and one explicit ref"
    target = _push_target(positional[1])
    if target is None:
        return "DANGEROUS", "destructive or malformed push refspec"
    if target == "HEAD":
        return "GATED", "push target must name the remote branch explicitly"
    if target.startswith(("refs/tags/", "tags/")):
        return "DANGEROUS", "remote tag push"
    if _GIT_PROTECTED_BRANCH_RE.fullmatch(target):
        return "DANGEROUS", f"protected branch push: {target}"
    return "SAFE", "ordinary explicit non-protected branch push"


def _classify_routine_git_workflow(cmd_str: str) -> tuple[str, str]:
    """Classify a bounded && chain of closed, routine Git operations."""
    if any(char in cmd_str for char in ("$", "`", "\n", "\r")):
        return "GATED", "dynamic or multiline Git command"
    try:
        lexer = shlex.shlex(cmd_str, posix=True, punctuation_chars="|;&<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return "GATED", "unparseable Git command"
    if not tokens or tokens[0] != "git":
        return "NOT_GIT", ""

    segments, current = [], []
    for token in tokens:
        if token == "&&":
            if not current:
                return "GATED", "empty Git workflow segment"
            segments.append(current)
            current = []
        elif token in {"|", "||", ";", "&", "<", ">", ">>", "<<"}:
            return "GATED", "unsupported shell control in Git workflow"
        else:
            current.append(token)
    if not current:
        return "GATED", "empty Git workflow segment"
    segments.append(current)
    if len(segments) > 8:
        return "GATED", "Git workflow exceeds eight segments"

    repos, commits, pushes = set(), 0, 0
    for segment in segments:
        parsed = _parse_git_invocation(segment)
        if parsed is None:
            return "GATED", "unsupported Git global options or mixed command chain"
        repo, subcommand, args = parsed
        repos.add(repo or "")
        if _classify_git_read(subcommand, args):
            continue
        if subcommand == "add" and _classify_git_add(args):
            continue
        if subcommand == "commit" and _classify_git_commit(args):
            commits += 1
            continue
        if subcommand == "push":
            pushes += 1
            verdict, reason = _classify_git_push(args)
            if verdict != "SAFE":
                return verdict, reason
            continue
        return "GATED", f"unsupported Git operation: {subcommand}"
    if len(repos) > 1 or commits > 1 or pushes > 1:
        return "GATED", "Git workflow must stay in one repository with at most one commit and push"
    return "SAFE", "bounded routine Git workflow"


def _shell_structure_view(cmd_str: str) -> str:
    """Mask quoted or escaped argument data while preserving character offsets.

    Shell controls in quotes are data, not syntax.  This deliberately limited
    view is only for finding controls; callers still inspect the original text.
    Dynamic substitutions are handled before the fast-track path.

    An UNTERMINATED quote is left untouched (fail-closed): a malformed quote
    must not hide a substitution/redirection from the control scan, so its
    content is restored verbatim rather than masked away.
    """
    chars = list(cmd_str)
    quote = None
    quote_start = -1
    index = 0
    while index < len(chars):
        char = chars[index]
        if char == "\\" and quote != "'":
            chars[index] = " "
            if index + 1 < len(chars):
                chars[index + 1] = " "
            index += 2
            continue
        if quote is None:
            if char in ("'", '"'):
                quote = char
                quote_start = index
                chars[index] = " "
        else:
            chars[index] = " "
            if char == quote:
                quote = None
                quote_start = -1
        index += 1
    if quote is not None and quote_start >= 0:
        for j in range(quote_start, len(chars)):
            chars[j] = cmd_str[j]
    return "".join(chars)


def _split_shell_control_segments(cmd_str: str) -> list[str]:
    """Split on unquoted shell controls while returning original segments."""
    structure = _shell_structure_view(cmd_str)
    segments = []
    start = 0
    for match in re.finditer(r"[|&;]+", structure):
        segments.append(cmd_str[start:match.start()])
        start = match.end()
    segments.append(cmd_str[start:])
    return segments


def _search_target_tokens(tokens: list[str]) -> list[str]:
    """Return grep/rg target operands, excluding pattern text and option values."""
    if not tokens or Path(tokens[0]).name not in {"grep", "rg"}:
        return tokens[1:]
    executable = Path(tokens[0]).name
    value_options = {
        "-e", "--regexp", "-f", "--file", "-g", "--glob", "-t", "--type",
        "-T", "--type-not", "-m", "--max-count", "--max-depth", "-A", "-B", "-C",
        "--after-context", "--before-context", "--context", "--sort", "--sortr",
        "--iglob", "--include", "--exclude", "--exclude-from",
    }
    pattern_from_option = False
    positional, selectors = [], []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            positional.extend(tokens[index + 1:])
            break
        if token in value_options:
            if index + 1 >= len(tokens):
                return tokens[1:]
            value = tokens[index + 1]
            if token in {"-e", "--regexp"}:
                pattern_from_option = True
            elif token in {"-f", "--file", "-g", "--glob", "--iglob", "--include", "--exclude", "--exclude-from"}:
                selectors.append(value)
            index += 2
            continue
        if len(token) > 2 and token[:2] in {"-e", "-f", "-g"}:
            if token[:2] == "-e":
                pattern_from_option = True
            else:
                selectors.append(token[2:])
            index += 1
            continue
        if any(token.startswith(f"{option}=") for option in value_options if option.startswith("--")):
            option, value = token.split("=", 1)
            if option == "--regexp":
                pattern_from_option = True
            elif option in {"--file", "--glob", "--iglob", "--include", "--exclude", "--exclude-from"}:
                selectors.append(value)
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        positional.append(token)
        index += 1
    if executable == "rg" and "--files" in tokens:
        return selectors + positional
    if executable == "grep" and any(flag in tokens for flag in {"-r", "-R", "--recursive"}) and len(positional) == 1:
        return selectors + positional
    return selectors + (positional if pattern_from_option else positional[1:])


def _is_sensitive_target(value: str) -> bool:
    """Check a path or glob selector after making glob boundaries explicit."""
    glob_normalized = re.sub(r"[*?\[\]{}!,]+", "/", value)
    return bool(
        SENSITIVE_FILE_PATTERN.search(value)
        or SENSITIVE_DIRECTORY_PATTERN.search(value)
        or SENSITIVE_FILE_PATTERN.search(glob_normalized)
        or SENSITIVE_DIRECTORY_PATTERN.search(glob_normalized)
    )


def _search_has_sensitive_target(seg: str) -> bool:
    try:
        tokens = shlex.split(seg)
    except ValueError:
        return True
    targets = _search_target_tokens(tokens)
    return any(_is_sensitive_target(target) for target in targets)


def _is_readonly_substitution_script(script: str) -> bool:
    """Accept one sed s/// print transformation, never e/w or extra commands."""
    if len(script) < 4 or script[0] != "s" or script[1].isalnum() or script[1] in {"\\", "\n", "\r"}:
        return False
    delimiter, separators, escaped = script[1], 0, False
    for index, char in enumerate(script[2:], start=2):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
        elif char == delimiter:
            separators += 1
            if separators == 2:
                return bool(re.fullmatch(r"[gIp0-9]*", script[index + 1:]))
    return False


def _is_readonly_diagnostic_sed(tokens: list[str]) -> bool:
    index = 1
    while index < len(tokens) and tokens[index] in {"-E", "-r", "-n", "-En", "-nE", "-rn", "-nr"}:
        index += 1
    if index >= len(tokens) or not _is_readonly_substitution_script(tokens[index]):
        return False
    targets = tokens[index + 1:]
    return bool(targets) and all(
        not target.startswith("-")
        and not _is_sensitive_target(target)
        and not _BROAD_WILDCARD_RE.search(target)
        for target in targets
    )


def _is_readonly_diagnostic_segment(seg: str, depth: int = 0) -> bool:
    try:
        tokens = shlex.split(seg)
    except ValueError:
        return False
    if not tokens:
        return False
    executable = Path(tokens[0]).name
    if executable == "docker":
        return _is_readonly_docker_exec(seg, depth=depth + 1)
    if executable in {"true", "false"}:
        return len(tokens) == 1
    if executable == "test":
        return len(tokens) == 3 and tokens[1] in {"-e", "-f", "-d", "-r", "-s", "-L"} and not _is_sensitive_target(tokens[2])
    if executable == "sed" and _is_readonly_diagnostic_sed(tokens):
        return True
    return _is_readonly_pipeline_segment(seg)


def _is_readonly_docker_exec(cmd_str: str, depth: int = 0) -> bool:
    """Recursively verify a local docker exec payload as a read-only diagnostic."""
    if depth >= 2 or any(char in cmd_str for char in ("$", "`", "\n", "\r")):
        return False
    structure = _shell_structure_view(cmd_str)
    if re.search(r">>?|<<?", structure) or _FORENSIC_NETWORK_BIN_RE.search(cmd_str):
        return False
    try:
        tokens = shlex.split(cmd_str)
    except ValueError:
        return False
    if len(tokens) < 4 or tokens[:2] != ["docker", "exec"]:
        return False
    index = 2
    while index < len(tokens) and re.fullmatch(r"-[it]+", tokens[index]):
        index += 1
    if index >= len(tokens) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", tokens[index]):
        return False
    payload = tokens[index + 1:]
    if not payload:
        return False
    if Path(payload[0]).name in {"sh", "bash"}:
        if len(payload) != 3 or payload[1] not in {"-c", "-lc"}:
            return False
        inner = payload[2]
        inner_structure = _shell_structure_view(inner)
        if re.search(r"\$\(|`|>>?|<<?", inner_structure) or _FORENSIC_NETWORK_BIN_RE.search(inner):
            return False
        segments = [segment.strip() for segment in _split_shell_control_segments(inner) if segment.strip()]
        return bool(segments) and len(segments) <= 8 and all(
            _is_readonly_diagnostic_segment(segment, depth=depth) for segment in segments
        )
    return _is_readonly_diagnostic_segment(shlex.join(payload), depth=depth)


def _is_readonly_pipeline_segment(seg: str) -> bool:
    """True if a single pipeline segment is a pure read-only command with no sensitive target."""
    seg = seg.strip()
    if not seg:
        return False
    try:
        tokens = shlex.split(seg)
    except ValueError:
        return False
    if not tokens:
        return False
    cmd = tokens[0]
    if cmd == "docker":
        return _is_readonly_docker_exec(seg)
    # git: parse -C and accept only closed read-only subcommands.
    if cmd == "git":
        parsed = _parse_git_invocation(tokens)
        if parsed is None or not _classify_git_read(parsed[1], parsed[2]):
            return False
        if SENSITIVE_FILE_PATTERN.search(seg) or SENSITIVE_DIRECTORY_PATTERN.search(seg):
            return False
        return not _BROAD_WILDCARD_RE.search(seg)
    # (issue #3670) `cd <specific-safe-dir>` is a read-only navigation segment —
    # allowed BEFORE the membership check so it can head a read-only chain, but
    # NEVER added to READONLY_PIPELINE_COMMANDS (bare `cd` stays fail-closed).
    if cmd == "cd":
        return _is_safe_cd_segment(seg)
    if cmd not in READONLY_PIPELINE_COMMANDS:
        return False
    if cmd in {"grep", "rg"}:
        if cmd == "rg" and any(token == "--pre" or token.startswith("--pre=") for token in tokens[1:]):
            return False
        targets = _search_target_tokens(tokens)
        return not any(
            _is_sensitive_target(target)
            or _BROAD_WILDCARD_RE.search(target)
            for target in targets
        )
    # sed is a language: override the loose READONLY membership with the strict
    # read-only whitelist (_is_readonly_sed) so e/w/s///w/-i forms in a pipeline
    # never fast-track.
    if cmd == "sed":
        return _is_readonly_sed(seg)
    # sensitive path in any argument -> fail-closed
    if SENSITIVE_FILE_PATTERN.search(seg) or SENSITIVE_DIRECTORY_PATTERN.search(seg):
        return False
    # broad/root-level target (INV-SENS-2) -> fail-closed
    if _BROAD_WILDCARD_RE.search(seg):
        return False
    return True


def _is_safe_readonly_pipeline(cmd_str: str) -> bool:
    """True if cmd_str is a pure read-only pipeline (segments joined by | && ;)."""
    segments = _split_shell_control_segments(cmd_str)
    nonempty = [s.strip() for s in segments if s.strip()]
    if not nonempty:
        return False
    return all(_is_readonly_pipeline_segment(s) for s in nonempty)


def _is_fast_track_allowlisted(cmd_str: str) -> bool:
    """INV-5/6: True only if cmd_str is provably-benign per the closed allowlist.

    Hard-rejects command substitution, redirection/heredoc, and forensic/network
    binaries; then fast-tracks either a pure read-only pipeline (segments joined
    by | && ;) or a single read-only command — always refusing sensitive paths,
    broad/root-level wildcard targets, and destructive git flags.
    """
    structure = _shell_structure_view(cmd_str)
    # Hard rejects — never fast-track mutation/execution/dynamic constructs
    if re.search(r"\$\(|`", structure):
        return False          # command substitution
    if re.search(r">>?|<<?", structure):
        return False          # redirection / heredoc (write)
    if _FORENSIC_NETWORK_BIN_RE.search(cmd_str):
        return False          # forensic / network egress primitives

    # Obvious-safe closed recognizer: bare `<bin> --version|-v|-V|--help|-h`.
    if _is_obvious_safe_version_help(cmd_str):
        return True

    if cmd_str.lstrip().startswith("docker "):
        return _is_readonly_docker_exec(cmd_str)

    # A single or all-Git chain uses the closed parser exclusively. This prevents
    # prefix regexes from treating mutations such as `git branch new-name` or
    # `git tag v1` as read-only while preserving mixed read pipelines/chains.
    if cmd_str.lstrip().startswith("git "):
        try:
            git_segments = [shlex.split(segment) for segment in _split_shell_control_segments(cmd_str) if segment.strip()]
        except ValueError:
            return False
        if git_segments and all(tokens and tokens[0] == "git" for tokens in git_segments):
            return _classify_routine_git_workflow(cmd_str)[0] == "SAFE"

    # Pure read-only pipeline (segments joined by | && ;)
    if _PIPELINE_SEP_RE.search(structure):
        return _is_safe_readonly_pipeline(cmd_str)

    # Single-command allowlist (no pipeline separators)
    for pat in FAST_TRACK_SAFE_GIT_PATTERNS:
        m = re.match(pat, cmd_str)
        if not m:
            continue
        # Fail-closed guard: `re.match` is prefix-anchored, so a destructive flag
        # AFTER the matched prefix (e.g. `git branch -d foo`, `git branch -D x`,
        # `git branch -m x`) must disqualify the command even though the pattern's
        # optional flag group did not consume it (INV-5 closed enumeration).
        rest = cmd_str[m.end():]
        if re.search(r"(^|\s)-[dDfFmM]{1,2}(\s|$)|--(delete|force|set|add|unset|move|copy|tag)\b", rest):
            return False
        # INV-SENS-2: sensitive path or broad/root-level target -> fail-closed
        if SENSITIVE_FILE_PATTERN.search(cmd_str) or SENSITIVE_DIRECTORY_PATTERN.search(cmd_str):
            return False
        if _BROAD_WILDCARD_RE.search(cmd_str):
            return False
        return True

    # Standalone read-only sed (issue #6935): `sed -n '<addr>p' <file>`
    if cmd_str.startswith("sed "):
        return _is_readonly_sed(cmd_str)

    tokens = cmd_str.split()
    if not tokens or tokens[0] not in FAST_TRACK_SAFE_COMMANDS:
        return False
    if tokens[0] in {"grep", "rg"}:
        try:
            search_tokens = shlex.split(cmd_str)
        except ValueError:
            return False
        if tokens[0] == "rg" and any(
            token == "--pre" or token.startswith("--pre=") for token in search_tokens[1:]
        ):
            return False
        targets = _search_target_tokens(search_tokens)
        return not any(
            _is_sensitive_target(target)
            or _BROAD_WILDCARD_RE.search(target)
            for target in targets
        )
    # INV-SENS-2: single-command broad/root-level or sensitive targets -> fail-closed
    if SENSITIVE_FILE_PATTERN.search(cmd_str) or SENSITIVE_DIRECTORY_PATTERN.search(cmd_str):
        return False
    if _BROAD_WILDCARD_RE.search(cmd_str):
        return False
    return True


def _is_readonly_sed(seg: str) -> bool:
    """Read-only sed whitelist (issue #6935): ONLY `sed -n '<addr>p' <file>`.

    A blacklist (reject -i/w) is incomplete: sed scripts can EXECUTE (e), WRITE
    files (w, s///w), READ files (r), and edit in place (-i, -i.suffix). Whitelist
    instead — require the `-n` flag and a script that is exactly a numeric /
    range / `$` address with an optional `!` negate and a single `p` (print).
    Anything else (e, w, s, r, i/a/c insert-append-change, d, =, y, n, ...) rejects.
    INV-SENS-1/2: sensitive targets and broad/root wildcards fail closed.
    """
    if not re.match(r"^sed\s+-n\b", seg):
        return False
    if _SED_INPLACE_RE.search(seg):
        return False
    # reject additional script sources (sed -e / -f / --expression / --file) —
    # they add scripts the whitelist would otherwise not validate (e/w/s///w bypass)
    if re.search(r"(^|\s)(-e|-f|--expression|--file)\b", seg):
        return False
    m = re.search(r"-n\s+(['\"])([^'\"]*)\1", seg)
    if not m:
        return False
    if not _SED_SAFE_SCRIPT_RE.match(m.group(2)):
        return False
    if SENSITIVE_FILE_PATTERN.search(seg) or SENSITIVE_DIRECTORY_PATTERN.search(seg):
        return False
    if _BROAD_WILDCARD_RE.search(seg):
        return False
    return True


# M3 COMPLEXITY_TAX (INV-16): structural complexity metric + deferral helper.
_COMPLEXITY_CONTROL_RE = re.compile(r"[|&;\n\r]+")
# (#139-2) `<<<` (herestring) is a single redirection: the generic lookaround
# pattern `(?<![<>])[<>]{1,2}(?![<>])` matches NOTHING on `<<<` (greedy backtrack
# and lookahead both fail), under-scoring `cat <<< x`. The explicit `<<<`
# alternative must come FIRST so it is counted once, not as `<<` + `<`. `<<`
# (heredoc) still counts as one redirection.
_COMPLEXITY_REDIR_RE = re.compile(r"<<<|(?<![<>])[<>]{1,2}(?![<>])")

# (issue #4027) heredoc opener: `<<EOF`, `<<-EOF`, `<<'EOF'`, `<<"EOF"` (also
# `<< EOF`). `<<<` (here-string) can NEVER match: after `<<` the regex demands
# an optional dash then a bare/quote-wrapped [A-Za-z_] delimiter — `<` is not
# one, so `cat <<< hello` is never mistaken for a heredoc opener.
_HEREDOC_OPENER_RE = re.compile(r"<<(?P<dash>-)?\s*(?P<q>['\"]?)(?P<delim>[A-Za-z_][A-Za-z0-9_]*)(?P=q)")


def _mask_heredocs(s: str) -> "tuple[str, int]":
    """Isolate terminated heredoc payloads (issue #4027) for complexity scoring.

    Each TERMINATED heredoc (opener ... terminator line) collapses to the
    literal `<<` marker, so body lines (and any `|`/`&`/newline inside them)
    no longer inflate the segment count. For an UNQUOTED heredoc the body is
    shell-expanded, so `$(...)` / backtick substitutions inside it are counted
    and returned as `extra_subst`. A QUOTED delimiter — single (`<<'EOF'`) OR
    double (`<<"EOF"`) — suppresses expansion, so bodies expand nothing.

    Unterminated/truncated heredocs and here-strings (`<<<`) are left
    UNTOUCHED (fail-closed: never mask what we cannot fully bound).
    """
    out = []
    extra_subst = 0
    cursor = 0
    for m in _HEREDOC_OPENER_RE.finditer(s):
        if m.start() < cursor:
            continue  # inside an already-masked region
        delim = m.group("delim")
        quoted = m.group("q") in ("'", '"')
        # `<<-` terminators may be indented with leading tabs; otherwise the
        # terminator must start at column 0 (leading whitespace tolerated).
        lead = r"\t*" if m.group("dash") is not None else r"[ \t]*"
        term = re.compile(rf"^{lead}{re.escape(delim)}\s*$", re.MULTILINE).search(s, m.end())
        if term is None:
            continue  # unterminated / truncated -> leave untouched (fail-closed)
        if not quoted:
            body = s[m.end():term.start()]
            extra_subst += body.count("$(") - body.count("$((") + body.count("`")
        out.append(s[cursor:m.start()])
        out.append("<<")
        cursor = term.end()
    out.append(s[cursor:])
    return "".join(out), extra_subst


# Quoted shell regions that must never inflate the structural complexity
# metric. Single-quoted bodies expand NOTHING; double-quoted bodies are
# shell-expanded (counted as extra_subst, mirroring unquoted-heredoc
# handling); ANSI-C `$'...'` bodies expand escapes only. Backslash escapes are
# honored inside "..." and $'...' so an escaped quote never truncates a
# region; plain single quotes have no escapes in shell, so `'[^']*'` is exact.
_QUOTED_REGION_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'      # double-quoted (\" / \\ ...)
    r"'[^']*'|"                # single-quoted (no escapes)
    r"\$'(?:[^'\\]|\\.)*'"     # ANSI-C $'...' ( \' allowed )
)


def _mask_quotes(s: str) -> "tuple[str, int]":
    """Collapse TERMINATED '...' / "..." / $'...' regions to one placeholder.

    Interior newlines / `|` / `&` / `;` (and inert `$(`/backticks) inside a
    quoted shell word must not be misread as top-level control separators: a
    multi-line `python3 -c "..."` or `echo "a\\nb"` is ONE command, not one per
    embedded line. Newlines BETWEEN top-level commands (outside any quotes)
    remain separators.

    Mirrors `_mask_heredocs`'s design:
      * each fully-terminated quoted region collapses to the literal `Q`
        placeholder (never a separator / redirection / substitution char);
      * a DOUBLE-quoted body is shell-expanded at runtime, so `$(...)` /
        backtick substitutions inside it are counted and returned as
        `extra_subst` (never silently dropped — fail-closed);
      * single-quoted and `$'...'` bodies expand nothing -> no extra_subst;
      * UNTERMINATED quotes are left UNTOUCHED (fail-closed: never mask what
        we cannot fully bound).
    """
    out = []
    extra_subst = 0
    cursor = 0
    for m in _QUOTED_REGION_RE.finditer(s):
        if m.start() < cursor:
            continue  # inside an already-masked region
        body = m.group(0)
        if body.startswith('"'):
            inner = body[1:-1]
            extra_subst += inner.count("$(") - inner.count("$((") + inner.count("`")
        out.append(s[cursor:m.start()])
        out.append("Q")
        cursor = m.end()
    out.append(s[cursor:])
    return "".join(out), extra_subst


def _isolate_heredocs(cmd_str: str) -> "tuple[str, int]":
    """CRLF-normalize, fd-normalize, collapse terminated heredocs AND quotes.

    Shared front-end for compute_complexity / compute_semantic_complexity so
    the structural metric is byte-identical across both.

    Heredocs are masked FIRST (`_mask_heredocs`): quote-masking before heredoc
    masking would destroy `<<'EOF'` / `<<"EOF"` opener quotes and leave the
    body unmasked (inflating every heredoc body line back into segments).
    After heredoc payloads are gone, `_mask_quotes` collapses any remaining
    terminated quoted regions so newlines/separators inside a quoted word
    (e.g. multi-line `python3 -c "..."`) never inflate the count. Both
    functions return surviving shell-expanded substitutions as extra_subst.
    """
    s = cmd_str.replace("\r\n", "\n").replace("\r", "\n")
    # INV-16 fix (issue #2555): '2>&1' / '1>&2' / '&>' are file-descriptor
    # redirections, not command separators — strip the '&' so it is not
    # misread as a segment split. The '>' is still counted as a redirection.
    s = re.sub(r">&|&>", ">", s)
    masked, extra_heredoc = _mask_heredocs(s)
    masked, extra_quotes = _mask_quotes(masked)
    # Quote-aware shell controls (PR #188): mask backslash-escaped characters
    # (`\|`, `\;`, `\&`, ...) so they are not misread as separators/substitutions.
    masked = _shell_structure_view(masked)
    return masked, extra_heredoc + extra_quotes


def compute_complexity(cmd_str: str) -> int:
    """Structural complexity score (INV-16: separator-agnostic, pure, never semantic).

    Structural-chain complexity only — NOT argument-length, NOT aliasing. Single
    commands with many args score low (handled by the fail-closed default + other
    layers). This tax targets chained/nested aggregate shape, which is the shape
    that "individually-passes-narrow-gates but hides risk." Aliasing/semantic
    obfuscation is out of scope (caught by SHELL_CRITICAL/SAST earlier).
    """
    s, extra_subst = _isolate_heredocs(cmd_str)
    n_segments = len([seg for seg in _COMPLEXITY_CONTROL_RE.split(s) if seg.strip()])
    # (#139-3) arithmetic expansion `$((...))` is NOT command substitution —
    # `$(` inside `$((` must not score a substitution. `count("$(") - count("$((")`
    # scores only genuine `$(...)` substitutions; a nested `$(( $(cmd) ))` still
    # counts the inner `$(cmd)` exactly once. (issue #4027 / quote-masking)
    # substitutions that survived heredoc masking (unquoted bodies) or live
    # inside a shell-expanded DOUBLE-quoted region are added via `extra_subst`.
    n_subst = s.count("$(") - s.count("$((") + s.count("`") + extra_subst
    n_redir = len(_COMPLEXITY_REDIR_RE.findall(s))
    return n_segments + n_subst + n_redir


# (issue #4027) semantic per-segment classification tables.
_SEM_READ_ONLY_VERBS = {"cd", "echo", "printf", "pwd", "shasum", "true", "false", "wait", "sleep"}
_SEM_GIT_READ_ONLY_SUBS = {"status", "log", "diff", "shortlog", "show"}
_SEM_GIT_VCS_SYNC_SUBS = {"checkout", "commit", "fetch", "add", "stash"}
_SEM_MUTATING_LOW = {"mkdir", "touch"}
_SEM_MUTATING_MID = {"cp", "mv", "make", "kubectl", "magick"}
_SEM_MUTATING_HIGH = {"rsync", "scp", "kill", "pkill", "killall"}
_SEM_DESTRUCTIVE = {"rm", "rmdir", "chmod", "chown", "chgrp"}
_SEM_CONTROL_FLOW_VERBS = {"eval", "xargs", "for", "while"}
# read-only filters that are exempt ONLY as an immediate pipe tail (`| verb`);
# `tee` is deliberately absent (it writes).
_SEM_PIPE_TAIL_EXEMPT = {"tail", "head", "grep", "rg", "sort", "uniq", "wc", "sed", "cut", "tr", "column"}


def _classify_semantic_segment(seg: str, pipe_tail: bool) -> bool:
    """Classify one (heredoc-masked, fd-stripped) segment by its first verb.

    Returns True when the segment is mutating. Fail-closed: an unknown first
    verb is mutating (True) — only the closed tables below ever classify as
    non-mutating (READ_ONLY / VCS_SYNC / DIAGNOSTIC / PIPE_TAIL).
    """
    seg = seg.strip()
    if not seg:
        return False
    # CONTROL_FLOW: substitution constructs in the segment override everything
    if re.search(r"\$\(|`", seg):
        return True
    tokens = seg.split()
    verb = tokens[0].strip("\"'").lower()
    if verb == "git":
        sub = tokens[1].strip("\"'").lower() if len(tokens) > 1 else ""
        if sub in _SEM_GIT_READ_ONLY_SUBS:
            return False
        if sub in _SEM_GIT_VCS_SYNC_SUBS:
            return False
        if sub in ("pull", "merge"):
            # only the fast-forward form is non-mutating; anything else can
            # create merge commits / rewrite history -> fail-closed UNKNOWN
            return "--ff-only" not in tokens
        # push or any other git subcommand -> mutating (fail-closed)
        return True
    if verb in ("python3",) or verb.endswith("/bin/python3"):
        if len(tokens) >= 3 and tokens[1] == "-m" and tokens[2] == "unittest":
            return False
        return True
    if verb == "pytest" or verb.endswith("/bin/pytest"):
        return False
    if verb in _SEM_READ_ONLY_VERBS:
        return False
    if verb in _SEM_MUTATING_LOW:
        return True
    if verb in _SEM_MUTATING_MID:
        return True
    if verb in _SEM_MUTATING_HIGH:
        return True
    if verb in _SEM_DESTRUCTIVE:
        return True
    if verb in _SEM_CONTROL_FLOW_VERBS:
        return True
    if pipe_tail and verb in _SEM_PIPE_TAIL_EXEMPT:
        return False
    return True


@dataclasses.dataclass
class SemanticComplexity:
    """Semantic complexity profile of a shell command (issue #4027).

    `structural` mirrors `compute_complexity` (heredoc payload isolated) and is
    the threshold gate. `has_mutation` is fail-closed: ANY MUTATING /
    DESTRUCTIVE / CONTROL_FLOW / UNKNOWN segment (or `$()`/backtick
    substitution) marks the chain mutating — mutating chains NEVER auto-approve
    via the cloud judge. Routing keys off `structural` + `has_mutation` only.
    """

    structural: int
    n_segments: int
    n_substitutions: int
    n_redirections: int
    mutating_segments: tuple
    has_mutation: bool


def compute_semantic_complexity(cmd_str: str) -> SemanticComplexity:
    """Semantic complexity with heredoc + quoted-region isolation (#4027, quotes).

    Splits on command separators after masking heredocs, collapsing quoted
    regions, and stripping pure fd-redirects; classifies each segment by its
    first verb (see `_classify_semantic_segment`) as mutating or not, and flags
    mutating chains fail-closed. Substitutions surviving in shell-expanded
    regions (unquoted heredoc bodies, double-quoted bodies) force
    `has_mutation`.
    """
    s, extra_subst = _isolate_heredocs(cmd_str)
    # structural component — byte-identical arithmetic to compute_complexity
    n_segments_structural = len([seg for seg in _COMPLEXITY_CONTROL_RE.split(s) if seg.strip()])
    n_subst = s.count("$(") - s.count("$((") + s.count("`") + extra_subst
    n_redir = len(_COMPLEXITY_REDIR_RE.findall(s))
    structural = n_segments_structural + n_subst + n_redir
    # semantic classification over the fd-redirect-stripped masked command
    stripped = _strip_fd_redirections(s)
    n_segments = 0
    mutating: list = []
    has_mutation = False
    prev_sep = ""
    for piece in re.split(r"([|&;\n\r]+)", stripped):
        if not piece:
            continue
        if re.fullmatch(r"[|&;\n\r]+", piece):
            prev_sep = piece
            continue
        pipe_tail = prev_sep.endswith("|")
        n_segments += 1
        if _classify_semantic_segment(piece, pipe_tail):
            has_mutation = True
            mutating.append(piece.strip())
        prev_sep = ""
    if extra_subst > 0:
        # (PR #186 review) an UNQUOTED heredoc body is shell-EXPANDED at run
        # time, so its $(...) / backtick substitutions EXECUTE code. Even though
        # the payload is masked away before segment classification, those
        # surviving substitutions are CONTROL_FLOW-equivalent mutations and must
        # force has_mutation=True (never absorb an unquoted-heredoc chain via
        # the cloud judge). Quoted heredoc bodies expand nothing -> extra_subst
        # stays 0 and remain inert. The same applies to substitutions inside a
        # DOUBLE-quoted region (shell-expanded; _mask_quotes counts them into
        # the same extra_subst).
        has_mutation = True
        mutating.append("(unquoted heredoc substitution)")
    return SemanticComplexity(
        structural=structural,
        n_segments=n_segments,
        n_substitutions=n_subst,
        n_redirections=n_redir,
        mutating_segments=tuple(mutating),
        has_mutation=has_mutation,
    )


def _apply_complexity_tax(
    cmd_str: str,
    cfg: dict,
    origin: Origin,
    cwd: str = "",
    scope: str = "default",
    agent_id: str = "default",
) -> "Optional[tuple[bool, str, str]]":
    """Return an escalation tuple if the command exceeds the complexity threshold,
    else None (pass through). Never returns is_safe=True for a mutating chain.

    M5 threads `origin`; HUMAN origin skips the structural-complexity deferral
    (trust concession gated by the origin_weighting_enabled knob). (issue #4027)
    over-threshold chains are routed by their mutation profile:

      * threshold gate = `structural` (heredoc payload isolated, see
        compute_semantic_complexity);
      * an over-threshold chain with NO mutating segments (pure read-only /
        diagnostic / VCS chain) is absorbed via the cloud judge
        (CLOUD_JUDGE on high-confidence safe, else COMPLEXITY_TAX deferral);
      * an over-threshold chain WITH a mutating segment NEVER auto-approves via
        the cloud judge — hard COMPLEXITY_TAX deferral to the human
        (fail-closed decision).
    """
    if not cfg.get("complexity_tax_enabled", True):
        return None
    if origin == Origin.HUMAN and get_origin_weighting_config().get("origin_weighting_enabled", True):
        return None   # M5: HUMAN trust concession — skip structural complexity deferral
    thr = cfg.get("complexity_threshold", 6)
    prof = compute_semantic_complexity(cmd_str)
    cx = prof.structural
    if cx <= thr:
        return None
    if not prof.has_mutation:
        # Read-only / diagnostic / VCS chain over threshold: absorb via the
        # cloud judge (issue #4027).
        origin_str = origin.value if isinstance(origin, Origin) else str(origin)
        cloud_safe, cloud_reason = audit_with_cloud_judge(
            cmd_str,
            context="Read-only diagnostic chain; no mutating segments",
            cwd=cwd,
            scope=scope,
            agent_id=agent_id,
            origin=origin_str,
        )
        if cloud_safe:
            return True, f"Complex read-only chain cleared by cloud judge: {cloud_reason}", DecisionLayer.CLOUD_JUDGE
        return False, f"Complex read-only chain deferred to human ({cloud_reason})", DecisionLayer.COMPLEXITY_TAX
    # Mutating chain over threshold: NEVER auto-approve via cloud judge —
    # apply the tighter hard-deferral behavior (deferral to the human).
    return (
        False,
        f"Complex mutating compound command requires human review (complexity={cx} > threshold={thr})",
        DecisionLayer.COMPLEXITY_TAX,
    )


def _strip_fd_redirections(s: str) -> str:
    """Strip side-effect-free fd redirections (issue #2555).

    Pure fd-to-fd redirects ('2>&1' / '1>&2' / spaced '2 >&1') never write a
    file, and '&> /dev/null' discards — strip them before separator/token
    checks. '&> file' with a REAL target keeps its '>' (a file write) and is
    NOT stripped. Shared by _is_fast_track_test_runner and
    compute_semantic_complexity.
    """
    s = re.sub(r"\s+[12]\s*>&[12]\b", " ", s)
    s = re.sub(r"\s*&>\s*/dev/null\b", " ", s)
    return s.strip()


def _strip_leading_cd_prefix(cmd_str: str) -> Optional[str]:
    """Strip a SINGLE leading `cd <safe-dir> && ...` prefix (issue #3670).

    Matches a leading `cd <dir> &&` (single '&&'; ';'/'||'/second-'&&' are NOT
    part of the prefix), validates the dir via `_is_safe_cd_segment`, and
    returns the substring AFTER the '&&' — else None (fail-closed). The
    caller's own separator guard then guarantees at most ONE `cd ... &&`
    prefix is consumed.
    """
    m = re.match(r"^\s*cd\s+(\S+)\s*&&\s*", cmd_str)
    if not m:
        return None
    if not _is_safe_cd_segment("cd " + m.group(1)):
        return None
    return cmd_str[m.end():]


# INV-TEST-1: Narrow test-runner fast-track (documented code-execution exception).
# A test runner EXECUTES code (unittest/pytest import and run test modules),
# unlike the read-only commands in the allowlist above. It is fast-tracked ONLY
# under this tight scope so the gatekeeper's own test suite can run without
# escalating, while `python3`/`pytest` remain non-general:
#   * binary: `python3 -m unittest` (optionally a venv `bin/python3`) or `pytest`
#     (optionally `bin/pytest`)
#   * target: discovery scoped to this repo's `tests/` dir (`discover -s tests`),
#     a specific `tests.<module>` unit, or `pytest` with `tests/...` (or bare `pytest`)
#   * hard-rejects: `-c`, bare script paths, `-m <other>` modules, sudo/su, shell
#     metacharacters, redirection/heredoc, command substitution, and the
#     forensic/network primitives in _FORENSIC_NETWORK_BIN_RE.
# HOLE (documented, intentionally NOT test-enforced): `python3 -m unittest` runs
# arbitrary code inside the test modules under tests/. The narrow scope confines
# execution to this repo's own test suite; it does NOT make `python3`/`pytest` a
# general safe command, and an edited/malicious test module under tests/ would
# still execute. Human review remains the backstop for anything outside this
# exact shape.
def _is_fast_track_test_runner(cmd_str: str) -> bool:
    if re.search(r"\$\(|`", cmd_str):
        return False
    if _FORENSIC_NETWORK_BIN_RE.search(cmd_str):
        return False
    if re.search(r"(^|\s)(sudo|su)(\s|$)", cmd_str):
        return False
    rest = re.sub(r"^(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)+", "", cmd_str).strip()
    # (issue #3670) a single leading `cd <safe-dir> && ...` prefix is allowed —
    # attempt the strip AFTER env assignments and BEFORE fd-redirect handling;
    # the separator guard below still rejects any SECOND '&&'/'||'/'; segment.
    cd_remainder = _strip_leading_cd_prefix(rest)
    if cd_remainder is not None:
        rest = cd_remainder
    # (issue #2555) fd-redirect strip symmetry: pure fd-to-fd redirects never
    # write a file, so strip '2>&1' / '1>&2' (and the spaced '2 >&1' variant)
    # before the token/shape checks. '&>' is a combined redirect that ALSO names
    # a file target: only the side-effect-free '/dev/null' discard is stripped —
    # any other '&> file' target keeps its '>' and stays fail-closed below.
    rest = _strip_fd_redirections(rest)
    # (round 2) reject any remaining file redirection / heredoc in the FULL
    # command (head AND filter tail) — '> file' / '>> file' / '< file' / '<<'.
    if re.search(r">>?|<<?", rest):
        return False
    # (#2555 hardening, INV-5/6): the fd-redirect strip above can leave a
    # trailing '&&' / '||' / ';' separator visible — a second segment would
    # execute beyond the narrow test-runner scope. Reject ANY remaining
    # command separator or embedded newline here (the pipe branch below already
    # rejects separators inside a filter tail).
    if re.search(r"\s*(?:&&|\|\||;)\s*|\n|\r", rest):
        return False
    # allow AT MOST ONE pipe whose tail is a single read-only filter
    if "|" in rest:
        head, tail = rest.split("|", 1)
        # strip quoted content to detect any hidden separator in the filter tail
        tail_clean = re.sub(r"'[^']*'|\"[^\"]*\"", "", tail)
        if re.search(r"[|&;]", tail_clean):
            return False
        tok = tail.strip().split()
        if not tok or tok[0] not in ("grep", "head", "tail", "sort", "uniq", "rg"):
            return False
        rest = head.strip()
    tokens = rest.split()
    if not tokens:
        return False
    binary = tokens[0]
    if binary == "pytest" or binary.endswith("/bin/pytest"):
        return len(tokens) == 1 or all(t == "tests" or t.startswith("tests/") for t in tokens[1:])
    if binary != "python3" and not binary.endswith("/bin/python3"):
        return False
    if len(tokens) < 3 or tokens[1] != "-m" or tokens[2] != "unittest":
        return False
    args = tokens[3:]
    if not args:
        return False
    if args[0] == "discover":
        for i, a in enumerate(args):
            if a in ("-s", "--start-directory"):
                if i + 1 < len(args):
                    return args[i + 1].rstrip("/") in ("tests", "./tests")
                return False
        return False
    return args[0] == "tests" or args[0].startswith("tests.")


# INV-8..11: package-manager 3-tuple classifier (MUTATING vs READ_ONLY)
PACKAGE_MANAGERS = {"brew", "npm", "pip", "pip3", "cargo", "apt", "apt-get", "pnpm", "yarn"}

PACKAGE_MUTATING_ACTIONS = {
    "install", "i", "uninstall", "remove", "rm", "upgrade", "update",
    "reinstall", "ci", "bundle", "add", "purge", "clean", "cleanup", "autoclean",
    "link", "unlink", "pin", "unpin", "config",
}

PACKAGE_READONLY_ACTIONS = {
    "list", "ls", "info", "search", "view", "show", "outdated", "leaves",
    "doctor", "desc", "deps", "why",
}


def classify_package_command(cmd_str: str) -> Optional[tuple[str, str, list[str]]]:
    """Classify a package-manager command as (manager, action_class, packages), or None.

    action_class is 'MUTATING' or 'READ_ONLY'. Returns None for non-package commands
    or unknown actions (so they fall through to the fail-closed default).
    """
    # Metacharacter / redirection / command-substitution guard: any command
    # containing these MUST NOT auto-approve via the READ_ONLY path (e.g.
    # `brew list | bash`, `npm view react > /tmp/out`, `pip list >> ~/.zshrc`,
    # `brew list\nbash -c id` — newline/carriage-return are shell separators too).
    # Returning None falls through to the fail-closed default for BOTH paths.
    if re.search(r"[|&;<>\n\r]|\$\(|`", cmd_str):
        return None  # metacharacter / redirection / substitution -> fail-closed default
    tokens = cmd_str.split()
    if not tokens or tokens[0] not in PACKAGE_MANAGERS:
        return None
    manager = tokens[0]
    # find the action: first non-flag token after the manager
    action = None
    idx = 1
    while idx < len(tokens):
        t = tokens[idx]
        if t.startswith("-"):
            idx += 1
            continue
        action = t
        idx += 1
        break
    if action is None:
        return (manager, "MUTATING", [])  # bare manager (e.g. `npm`, `brew`) — treat as unsafe
    if action in PACKAGE_MUTATING_ACTIONS:
        action_class = "MUTATING"
    elif action in PACKAGE_READONLY_ACTIONS:
        action_class = "READ_ONLY"
    else:
        return None  # unknown action -> not classified -> fail-closed default
    packages = [t for t in tokens[idx:] if not t.startswith("-")]
    return (manager, action_class, packages)


def _check_workspace_allowlist(cmd_str: str, cwd: str = "", action_type: Optional[str] = None):
    """Check the workspace `.schengen/` allowlist (issue #7207, INV-WS-1..5).

    Returns (True, reason) on a rule match for `action_type`, else None.
    exec -> match on normalize_command(cmd_str); dialog types -> the canonical
    target path. Runs AFTER the global denylist layers (INV-WS-2 by ordering:
    sensitive/sandbox/SHELL_CRITICAL/gray-zone-BLOCK all return first).
    """
    try:
        from core.workspace_allowlist import check_rule, discover_workspace_policy, load_policy

        policy_path = discover_workspace_policy(cwd)
        if policy_path is None:
            return None
        policy = load_policy(policy_path)
        if policy is None:
            return None
        if action_type is None:
            return None
        if action_type == "exec":
            # Fix 1 (reviewer): match the RAW command text (exact), not a
            # normalized form — promoted exec rules store the original command.
            target = cmd_str.strip()
        elif action_type == "edit_file":
            if cmd_str.startswith("edit_file "):
                target = cmd_str.split(" ", 1)[1].strip()
            elif cmd_str.startswith("create_file "):
                target = cmd_str.split(" ", 1)[1].strip()
            else:
                return None
        else:
            prefix = action_type + " "
            if cmd_str.startswith(prefix):
                target = cmd_str[len(prefix):].strip()
            else:
                return None
        if check_rule(policy, action_type, target):
            return True, f"Workspace allowlist ({action_type}): '{target}'"
        return None
    except Exception:
        return None


def _audit_static_shell_command(
    cmd_str: str,
    use_llm_judge: bool = False,
    reasoning_effort: str = DEFAULT_REASONING_EFFORT,
    cwd: str = "",
    scope: str = "default",
    agent_id: str = "default",
    origin: Origin = Origin.AGENT,
) -> tuple[bool, str, str]:
    """Audit static shell command line with PATH, Managed Git rules, and AST judge."""
    # Normalize leading/trailing whitespace so dialog dispatch (startswith / ==)
    # and pattern matching are robust against TUI-captured indentation.
    cmd_str = cmd_str.strip()
    if not cmd_str:
        return True, "Safe", DecisionLayer.FAST_TRACK_AST

    # 0. Check CLI feedback survey skip
    if cmd_str == "feedback_survey_skip":
        return True, "Auto-skipping CLI feedback survey ([0] Skip)", DecisionLayer.FAST_TRACK_AST

    # 0a. Check AGY File Edit / Creation dialog commands (edit_file <path>,
    #     create_file <path>). #7759: the payload may be newline-delimited for
    #     multi-file edits — collect ALL paths, validate EACH against the
    #     denylist (all-or-nothing, INV-EF-2), and only then fast-track.
    if cmd_str.startswith("edit_file ") or cmd_str.startswith("create_file "):
        op_type = "creation" if cmd_str.startswith("create_file ") else "edit"
        raw = cmd_str.split(" ", 1)[1]
        paths = [p.strip() for p in raw.split("\n") if p.strip()]
        if not paths:
            return False, f"File {op_type} request with no target path", DecisionLayer.NOT_ALLOWLISTED
        for target_path in paths:
            if HERMES_SANDBOX_PATTERN.search(target_path):
                return False, f"Forbidden file {op_type} targeting Hermes Sandbox: '{target_path}'", DecisionLayer.SANDBOX_GUARD
            if (
                SENSITIVE_FILE_PATTERN.search(target_path)
                and "dot_zshenv.tmpl" not in target_path
                and ".zshenv.local" not in target_path
            ):
                return False, f"Attempting to perform file {op_type} on sensitive credential file: '{target_path}'", DecisionLayer.SECRET_GUARD
            # Check gray zone classification for the target path
            if classify_resource_tier(target_path) == ResourceTier.T4_CRITICAL:
                return False, f"Critical OS/Secret resource {op_type} blocked: '{target_path}'", DecisionLayer.GRAY_ZONE_MATRIX
        # issue #7207: workspace .schengen/ allowlist fast-track (after denylists)
        # — single-file only (INV-EF-3 parity; multi-file stays explicit).
        if len(paths) == 1:
            ws_hit = _check_workspace_allowlist(cmd_str, cwd=cwd, action_type="edit_file")
            if ws_hit is not None:
                return True, ws_hit[1], DecisionLayer.FAST_TRACK_WORKSPACE_ALLOWLIST
        return True, f"Verified safe file {op_type}: '{', '.join(paths)}'", DecisionLayer.FAST_TRACK_AST

    # 0a-2. Check opencode external-directory access dialog (access_directory <path>)
    if cmd_str.startswith("access_directory "):
        target = cmd_str.split(" ", 1)[1].strip()
        if HERMES_SANDBOX_PATTERN.search(target):
            return (
                False,
                f"Forbidden external directory access to Hermes Sandbox: '{target}'",
                DecisionLayer.SANDBOX_GUARD,
            )
        if SENSITIVE_FILE_PATTERN.search(target) or SENSITIVE_DIRECTORY_PATTERN.search(target):
            return (
                False,
                f"Forbidden external directory access to sensitive location: '{target}'",
                DecisionLayer.SECRET_GUARD,
            )
        gz_tier = classify_resource_tier(target)
        if gz_tier == ResourceTier.T4_CRITICAL:
            return (
                False,
                f"Critical OS/Secret resource directory access blocked: '{target}'",
                DecisionLayer.GRAY_ZONE_MATRIX,
            )
        # issue #7207: workspace .schengen/ allowlist fast-track (after denylists)
        ws_hit = _check_workspace_allowlist(cmd_str, cwd=cwd, action_type="access_directory")
        if ws_hit is not None:
            return True, ws_hit[1], DecisionLayer.FAST_TRACK_WORKSPACE_ALLOWLIST
        return True, f"Verified safe external directory access: '{target}'", DecisionLayer.FAST_TRACK_AST

    # 0a-3. Check opencode file-read dialog (read_file <path>)
    if cmd_str.startswith("read_file "):
        target_path = cmd_str.split(" ", 1)[1].strip()
        if (
            SENSITIVE_FILE_PATTERN.search(target_path)
            and "dot_zshenv.tmpl" not in target_path
            and ".zshenv.local" not in target_path
        ):
            return False, f"Attempting to READ sensitive credential file: '{target_path}'", DecisionLayer.SECRET_GUARD
        gz_tier = classify_resource_tier(target_path)
        if gz_tier == ResourceTier.T4_CRITICAL:
            return False, f"Critical OS/Secret resource read blocked: '{target_path}'", DecisionLayer.GRAY_ZONE_MATRIX
        # issue #7207: workspace .schengen/ allowlist fast-track (after denylists)
        ws_hit = _check_workspace_allowlist(cmd_str, cwd=cwd, action_type="read_file")
        if ws_hit is not None:
            return True, ws_hit[1], DecisionLayer.FAST_TRACK_WORKSPACE_ALLOWLIST
        return True, f"Verified safe file read: '{target_path}'", DecisionLayer.FAST_TRACK_AST

    # 0a-4. opencode doom-loop dialogs must NEVER be auto-approved.
    if cmd_str == "doom_loop":
        return False, "Doom loop detected; requires human review", DecisionLayer.SHELL_CRITICAL

    # 0a-4b. opencode human question dialogs must NEVER be auto-approved.
    if cmd_str.startswith("question"):
        return False, "Agent asked the user a question; requires human input", DecisionLayer.SHELL_CRITICAL

    # 0a-5. Unhandled opencode dialogs: route to the second-tier cloud judge (fail-closed to human).
    if cmd_str.startswith("unhandled_dialog "):
        cloud_safe, cloud_reason = audit_with_cloud_judge(
            cmd_str,
            context="An opencode permission dialog of an unrecognized type was intercepted. Only auto-approve if it is obviously read-only and safe.",
            reasoning_effort=reasoning_effort,
            cwd=cwd,
            scope=scope,
            agent_id=agent_id,
            origin=origin,
        )
        if cloud_safe:
            return True, f"Unhandled dialog cleared by cloud judge: {cloud_reason}", DecisionLayer.CLOUD_JUDGE
        return (
            False,
            f"Unhandled opencode permission type deferred to human ({cloud_reason})",
            DecisionLayer.SHELL_CRITICAL,
        )

    # 0b. Check Managed Git command rules if targeting Managed Git host
    if MANAGED_GIT_HOST_PATTERN.search(cmd_str):
        mg_safe, mg_reason = is_managed_git_safe_command(cmd_str)
        if not mg_safe and mg_reason:
            return False, f"Managed Git security guard: {mg_reason}", DecisionLayer.MANAGED_GIT_GUARD
        if mg_safe and mg_reason:
            return True, f"Managed Git security guard: {mg_reason}", DecisionLayer.MANAGED_GIT_GUARD

    # 1. Check for inline python execution (Here-doc or -c)
    #    Heredoc allows optional '-' (python3 - <<EOF), no '-' (python3 <<EOF),
    #    and tab-stripping '<<-' (python3 <<-EOF). Escaped-quote truncation is
    #    avoided in -c via a negative lookbehind on the closing quote.
    heredoc_match = re.search(
        r"python[0-9.]*\s+(?:-\s*)?<<-?\s*['\"]?([A-Za-z0-9_]+)['\"]?\s*\n([\s\S]*?)\n\s*\1", cmd_str
    )
    if heredoc_match:
        py_code = heredoc_match.group(2)
        safe, reason = audit_python_code(py_code)
        if not safe:
            return False, f"Inline Python risk: {reason}", DecisionLayer.PYTHON_AST

    dash_c_match = re.search(r"python[0-9.]*\s+-c\s*(['\"])([\s\S]*?)(?<!\\)\1", cmd_str)
    if dash_c_match:
        py_code = dash_c_match.group(2)
        safe, reason = audit_python_code(py_code)
        if not safe:
            return False, f"Python -c inline risk: {reason}", DecisionLayer.PYTHON_AST

    # 1b. Check ShellCheck SAST for variable hazards (SC2115, SC2154)
    sc_safe, sc_reason, sc_details = audit_shell_with_shellcheck(cmd_str)
    if not sc_safe:
        return False, sc_reason, DecisionLayer.SAST_SHELLCHECK

    # 1c. Check Semgrep SAST for remote piping / reverse shells
    sem_safe, sem_reason, sem_details = audit_script_with_semgrep(cmd_str)
    if not sem_safe:
        return False, sem_reason, DecisionLayer.SAST_SEMGREP

    git_workflow, git_reason = _classify_routine_git_workflow(cmd_str)
    if git_workflow == "DANGEROUS":
        return False, f"Critical Git risk detected: {git_reason}", DecisionLayer.SHELL_CRITICAL

    # 2. Check critical destructive patterns
    for pat, desc in CRITICAL_SHELL_PATTERNS:
        if re.search(pat, cmd_str, re.IGNORECASE):
            return False, f"Critical risk detected: {desc}", DecisionLayer.SHELL_CRITICAL

    # 2b. Check process-environment-dump commands (ps e/eww/-wwE, launchctl getenv,
    #     /proc/*/environ). Anchored to a command boundary + quote-stripped so literal
    #     mentions in heredocs/grep-patterns/commit-messages are not flagged.
    env_dump, env_dump_reason = check_process_env_dump(cmd_str)
    if env_dump:
        return False, f"Critical risk detected: {env_dump_reason}", DecisionLayer.SHELL_CRITICAL

    # Check system directory access (exclude PATH=... variable assignments)
    cleaned_cmd = re.sub(r'PATH=["\']?[^"\';\s]+["\']?', "", cmd_str)
    if re.search(
        r"\b(cd|ls|cat|rm|cp|mv)\s+/(?:etc|usr|bin|sbin|Library|System|private/etc|var/(?!folders/|tmp/)|private/var/(?!folders/|tmp/))\b",
        cleaned_cmd,
        re.IGNORECASE,
    ):
        return False, "System directory direct mutation/access", DecisionLayer.SHELL_CRITICAL

    # 3. Check Hermes Sandbox WRITE attempts
    if HERMES_SANDBOX_PATTERN.search(cmd_str):
        if re.search(r">>?[^|;&\n]*(\.hermes/sandboxes|hermes_sandbox)", cmd_str, re.IGNORECASE):
            return (
                False,
                f"Forbidden shell redirection WRITE to Hermes Sandbox: '{cmd_str}'",
                DecisionLayer.SANDBOX_GUARD,
            )
        sub_commands = _split_shell_control_segments(cmd_str)
        for sub_cmd in sub_commands:
            sub_cmd = sub_cmd.strip()
            for write_bin in SHELL_WRITE_COMMANDS:
                if re.search(rf"\b{write_bin}\b.*(\.hermes/sandboxes|hermes_sandbox)", sub_cmd, re.IGNORECASE):
                    return (
                        False,
                        f"Forbidden WRITE command ({write_bin}) targeting Hermes Sandbox: '{sub_cmd}'",
                        DecisionLayer.SANDBOX_GUARD,
                    )

    # 4. Check sensitive file reading or network exfiltration
    for sub_cmd in _split_shell_control_segments(cmd_str):
        try:
            executable = Path(shlex.split(sub_cmd)[0]).name
        except (ValueError, IndexError):
            continue
        if executable in {"grep", "rg"} and _search_has_sensitive_target(sub_cmd):
            return False, f"Attempting to READ sensitive file: '{sub_cmd.strip()}'", DecisionLayer.SECRET_GUARD
    if SENSITIVE_FILE_PATTERN.search(cmd_str) and not FORGEJO_HOST_PATTERN.search(cmd_str):
        sub_commands = _split_shell_control_segments(cmd_str)
        for sub_cmd in sub_commands:
            sub_cmd = sub_cmd.strip()
            for read_bin in READ_COMMANDS:
                if re.search(rf"\b{read_bin}\b", sub_cmd, re.IGNORECASE) and SENSITIVE_FILE_PATTERN.search(sub_cmd):
                    try:
                        executable = Path(shlex.split(sub_cmd)[0]).name
                    except (ValueError, IndexError):
                        executable = ""
                    if executable in {"grep", "rg"} and not _search_has_sensitive_target(sub_cmd):
                        continue
                    if executable == "docker" and _is_readonly_docker_exec(sub_cmd):
                        continue
                    return False, f"Attempting to READ sensitive file: '{sub_cmd}'", DecisionLayer.SECRET_GUARD
            for net_bin in NETWORK_EXFIL_COMMANDS:
                if re.search(rf"\b{net_bin}\b", sub_cmd, re.IGNORECASE) and SENSITIVE_FILE_PATTERN.search(sub_cmd):
                    return False, f"Network command touching sensitive path: '{sub_cmd}'", DecisionLayer.SECRET_GUARD

    # 6. Check Non-VCS Irreversible Mutation & Gray Zone Matrix (ADR-004 / SOP-12)
    gz_verdict, gz_reason, gz_payload = evaluate_gray_zone_operation(cmd_str)
    if gz_verdict == Verdict.BLOCK:
        return False, f"Non-VCS Gray-Zone Guard [BLOCK]: {gz_reason}", DecisionLayer.GRAY_ZONE_MATRIX
    if gz_verdict == Verdict.PROMPT and gz_payload:
        tax = _apply_complexity_tax(cmd_str, get_complexity_tax_config(), origin, cwd=cwd, scope=scope, agent_id=agent_id)
        if tax is not None:
            return tax
        guidance = format_decision_guidance(gz_payload)
        cloud_safe, cloud_reason = audit_with_cloud_judge(
            cmd_str,
            context=guidance,
            reasoning_effort=reasoning_effort,
            cwd=cwd,
            scope=scope,
            agent_id=agent_id,
            origin=origin,
        )
        if cloud_safe:
            return True, f"Gray-zone cleared by cloud judge: {cloud_reason}", DecisionLayer.CLOUD_JUDGE
        return False, f"Gray-zone deferred to human ({cloud_reason}):\n{guidance}", DecisionLayer.GRAY_ZONE_MATRIX

    if git_workflow == "SAFE":
        return True, f"Fast-track verified {git_reason}: '{cmd_str}'", DecisionLayer.FAST_TRACK_AST

    # issue #7207: workspace .schengen/ allowlist — persistent repo-local
    # fast-track. Runs AFTER the gray-zone BLOCK (and every denylist layer
    # above) and BEFORE the closed fast-track/novelty/package/slow paths, so
    # INV-WS-2 holds by construction: sensitive/sandbox/SHELL_CRITICAL/
    # gray-zone-BLOCK all return first.
    ws_hit = _check_workspace_allowlist(cmd_str, cwd=cwd, action_type="exec")
    if ws_hit is not None:
        return True, ws_hit[1], DecisionLayer.FAST_TRACK_WORKSPACE_ALLOWLIST

    is_degraded = (isinstance(sc_details, dict) and sc_details.get("degraded")) or (
        isinstance(sem_details, dict) and sem_details.get("degraded")
    )

    # INV-5/6: fast-track auto-approve is now an explicit closed allowlist of
    # provably-benign commands (no metacharacters, no forensic/network binaries).
    if _is_fast_track_allowlisted(cmd_str):
        return True, f"Fast-track verified safe: '{cmd_str}'", DecisionLayer.FAST_TRACK_AST

    # INV-TEST-1: narrow test-runner fast-track (documented code-execution exception)
    if _is_fast_track_test_runner(cmd_str):
        return True, f"Fast-track test runner (narrow): '{cmd_str}'", DecisionLayer.FAST_TRACK_AST

    # M3 COMPLEXITY_TAX: gate the UNPROVEN auto-approve paths (novelty recall,
    # package READ_ONLY). Runs AFTER the provably-benign fast-track + test-runner.
    tax = _apply_complexity_tax(cmd_str, get_complexity_tax_config(), origin, cwd=cwd, scope=scope, agent_id=agent_id)
    if tax is not None:
        return tax

    # INV-3: novelty/history gate — a canonical pattern with prior HUMAN approval
    # (scoped to pane, within TTL) auto-approves, instead of re-escalating.
    # M7: the gate key dropped the cwd dimension — seed and query now match.
    canonical = normalize_command(cmd_str)
    if has_human_approval_pattern(canonical, scope=scope):
        return True, f"Human-approved pattern (session): '{canonical}'", DecisionLayer.HUMAN_APPROVED

    # INV-8..11: package-manager 3-tuple classifier (READ_ONLY fast-track, MUTATING escalate)
    pkg = classify_package_command(cmd_str)
    if pkg is not None:
        manager, action_class, packages = pkg
        if action_class == "READ_ONLY":
            return True, f"Read-only package query ({manager})", DecisionLayer.PACKAGE_GUARD
        return False, f"Package mutation requires human review ({manager})", DecisionLayer.PACKAGE_GUARD

    # INV-2: degraded SAST can no longer auto-approve — fail-closed.
    if is_degraded:
        return False, "SAST tools unavailable; requires human review (fail-closed)", DecisionLayer.NOT_ALLOWLISTED

    # INV-1: the fail-open catch-all is REMOVED. Default is escalate (fail-closed).
    return False, "Not in fast-track allowlist; requires human review (fail-closed)", DecisionLayer.NOT_ALLOWLISTED


def audit_shell_command(
    cmd_str: str,
    use_llm_judge: bool = False,
    reasoning_effort: str = DEFAULT_REASONING_EFFORT,
    cwd: str = "",
    scope: str = "default",
    agent_id: str = "default",
    origin: Origin = Origin.AGENT,
) -> tuple[bool, str, str]:
    """Audit shell command line with PATH, Managed Git rules, dynamic substitution inspection, and AST judge.

    Returns:
        (is_safe: bool, reason: str, layer: str)
    """
    # M5 INV-17: INJECTED/EMERGENT hard-escalate BEFORE every auto-approve path
    # (dialogs, Managed Git, fast-track, test-runner, novelty, package READ_ONLY,
    # gray-zone->cloud-judge, dynamic-substitution LLM inspector).
    if origin in (Origin.INJECTED, Origin.EMERGENT):
        return (
            False,
            f"Origin {origin.value} hard-escalates; requires human review",
            DecisionLayer.ORIGIN_GUARD,
        )

    if not cmd_str or not cmd_str.strip():
        return True, "Safe", DecisionLayer.FAST_TRACK_AST

    # 5. Check dynamic command substitution $(cat ...) or `cat ...`
    if DYNAMIC_SUBSTITUTION_PATTERN.search(cmd_str):
        # 5a. Attempt deterministic local resolution with 5 Anti-Loop Guardrails
        resolved, res_cmd, err_layer, err_reason = resolve_dynamic_substitutions_locally(cmd_str)
        if not resolved:
            return (
                False,
                err_reason or "Dynamic substitution security guard triggered",
                err_layer or DecisionLayer.LLM_INSPECTOR,
            )

        # 5b. If dynamic substitutions still remain (complex expressions like $(find ...), $(awk ...))
        if DYNAMIC_SUBSTITUTION_PATTERN.search(res_cmd):
            is_safe, reason = audit_dynamic_substitution_with_llm(
                res_cmd, reasoning_effort=reasoning_effort, cwd=cwd, scope=scope, agent_id=agent_id
            )
            return is_safe, reason, DecisionLayer.LLM_INSPECTOR

        # 5c. All substitutions resolved -> audit resulting static command
        exp_safe, exp_reason, exp_layer = _audit_static_shell_command(
            res_cmd,
            use_llm_judge=use_llm_judge,
            reasoning_effort=reasoning_effort,
            cwd=cwd,
            scope=scope,
            agent_id=agent_id,
            origin=origin,
        )
        if exp_safe:
            return (
                True,
                f"Dynamic substitution verified safe ({sanitize_output(res_cmd)[:60]}): {exp_reason}",
                DecisionLayer.FAST_TRACK_AST,
            )
        else:
            return False, f"Dynamic substitution expanded to unsafe command: {exp_reason}", exp_layer

    return _audit_static_shell_command(
        cmd_str,
        use_llm_judge=use_llm_judge,
        reasoning_effort=reasoning_effort,
        cwd=cwd,
        scope=scope,
        agent_id=agent_id,
        origin=origin,
    )


def derive_taxonomy(
    cmd_str: str, layer: DecisionLayer, is_safe: bool, reason: str, origin: Origin = Origin.AGENT
) -> dict[str, Any]:
    """Derive 2D Taxonomy (Origin x Consequence + Mechanism) from evaluation result.

    Origin:
      - 'H' (Human): User-persisted allowlist bypass or explicit human prompt
      - 'A' (Agent): Default autonomous agent execution in terminal
      - 'I' (Injected): Reserved for Layer 6 LLM Inspector & adversarial prompt injection
      - 'E' (Emergent): Reserved for Phase 1 SAST Scoped ShellCheck (unbound variables)

    Consequence:
      - 'NONE': Safe benign operations
      - 'DEST': File/directory deletion, disk formatting, git reset --hard
      - 'EXFIL': Credential egress, sensitive file reading, unauthorized network push
      - 'INT': Permission modification (chmod/chown), SIP mutation, sandbox tampering
      - 'AVAIL': Fork bomb, network disruption, system process termination
      - 'PERS': Sudo elevation, user account creation/deletion
    """
    shadow = is_shadow_mode()
    gate_state = GateState.OBSERVE if shadow else GateState.ENFORCE

    # Determine Consequence and Mechanism with pattern-level precision
    if is_safe:
        consequence = Consequence.NONE
        if layer == DecisionLayer.ALLOWLIST:
            mechanism = "user-allowlist"
            origin = Origin.HUMAN
        elif layer == DecisionLayer.HUMAN_APPROVED:
            mechanism = "human-approved-history"
            origin = Origin.HUMAN
        elif layer == DecisionLayer.PACKAGE_GUARD:
            mechanism = "package-read-query"
        elif layer == DecisionLayer.CLOUD_JUDGE:
            mechanism = "cloud-judge-verified"
        elif layer == DecisionLayer.FAST_TRACK_WORKSPACE_ALLOWLIST:
            # origin stays the command author (NOT forced to HUMAN).
            mechanism = "workspace-allowlist"
        else:
            mechanism = "fast-track-verified"
    elif cmd_str == "doom_loop" or cmd_str.startswith("question") or cmd_str.startswith("unhandled_dialog "):
        consequence = Consequence.INTEGRITY
        mechanism = "doom-loop" if cmd_str == "doom_loop" else ("question" if cmd_str.startswith("question") else "unhandled-dialog")
    elif layer == DecisionLayer.SECRET_GUARD:
        consequence = Consequence.EXFILTRATION
        mechanism = "secret-path"
    elif layer == DecisionLayer.SANDBOX_GUARD:
        consequence = Consequence.INTEGRITY
        mechanism = "sandbox-write"
    elif layer == DecisionLayer.PYTHON_AST:
        if "external" in reason.lower() or "network" in reason.lower():
            consequence = Consequence.EXFILTRATION
            mechanism = "python-network"
        else:
            consequence = Consequence.INTEGRITY
            mechanism = "python-ast"
    elif layer == DecisionLayer.GRAY_ZONE_MATRIX:
        if "DELETE" in reason or "rm " in cmd_str:
            consequence = Consequence.DESTRUCTION
            mechanism = "gray-zone-delete"
        elif "TRUNCATE" in reason:
            consequence = Consequence.DESTRUCTION
            mechanism = "gray-zone-truncate"
        elif "READ" in reason:
            consequence = Consequence.EXFILTRATION
            mechanism = "gray-zone-read"
        elif "MUTATING_API" in reason:
            consequence = Consequence.INTEGRITY
            mechanism = "gray-zone-api"
        elif "HEAVY_EXEC" in reason:
            consequence = Consequence.AVAILABILITY
            mechanism = "gray-zone-exec"
        else:
            consequence = Consequence.DESTRUCTION
            mechanism = "non-vcs-gray-zone"
    elif layer == DecisionLayer.MANAGED_GIT_GUARD:
        if "DELETE" in reason or "DELETE" in cmd_str:
            consequence = Consequence.DESTRUCTION
            mechanism = "git-api-delete"
        else:
            consequence = Consequence.INTEGRITY
            mechanism = "git-api-mutation"
    elif layer == DecisionLayer.SAST_SHELLCHECK:
        consequence = Consequence.DESTRUCTION
        origin = Origin.EMERGENT
        if "SC2115" in reason or "2115" in reason:
            mechanism = "unbound-variable-sc2115"
        else:
            mechanism = "unbound-variable-sc2154"
    elif layer == DecisionLayer.SAST_SEMGREP:
        consequence = (
            Consequence.PERSISTENCE
            if ("piped" in reason.lower() or "reverse" in reason.lower())
            else Consequence.INTEGRITY
        )
        origin = Origin.INJECTED if ("piped" in reason.lower() or "reverse" in reason.lower()) else Origin.EMERGENT
        mechanism = (
            "piped-remote-script-execution"
            if "piped" in reason.lower()
            else ("reverse-shell" if "reverse" in reason.lower() else "semgrep-sast-rule")
        )
    elif layer == DecisionLayer.SHELL_CRITICAL:
        if re.search(r"\b(sudo|su)\b", cmd_str, re.IGNORECASE):
            consequence = Consequence.PERSISTENCE
            mechanism = "privilege-escalation"
        elif re.search(r"\b(chmod|chown)\b", cmd_str, re.IGNORECASE):
            consequence = Consequence.INTEGRITY
            mechanism = "perm-mutation"
        elif re.search(r"\b(csrutil|spctl|bputil|nvram|bless)\b", cmd_str, re.IGNORECASE):
            consequence = Consequence.INTEGRITY
            mechanism = "firmware-sip-mutation"
        elif re.search(r"\b(dscl|sysadminctl)\b", cmd_str, re.IGNORECASE):
            consequence = Consequence.PERSISTENCE
            mechanism = "user-account-mutation"
        elif re.search(r"\b(pfctl|networksetup)\b", cmd_str, re.IGNORECASE):
            consequence = Consequence.AVAILABILITY
            mechanism = "network-disruption"
        elif re.search(r"\b(ps|launchctl)\b", cmd_str, re.IGNORECASE) or "/proc/" in cmd_str:
            consequence = Consequence.EXFILTRATION
            mechanism = "process-env-dump"
        elif re.search(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", cmd_str) or re.search(
            r"\b(killall|pkill)\s+-9\s+(launchd|init|systemd|Dock|Finder)", cmd_str
        ):
            consequence = Consequence.AVAILABILITY
            mechanism = "dos-fork-bomb"
        elif re.search(r"\bgit\s+(push\b|reset\s+--hard|clean\s+-[fF]|rm\s+-[rfRF]+)", cmd_str):
            consequence = Consequence.DESTRUCTION
            mechanism = "git-destructive"
        elif re.search(
            r"\b(diskutil\s+(erase|partition|zero)|mkfs|dd|gpt\s+destroy|asr\s+restore|tmutil\s+delete)", cmd_str
        ):
            consequence = Consequence.DESTRUCTION
            mechanism = "disk-format-wipe"
        else:
            consequence = Consequence.DESTRUCTION
            mechanism = "rm-rf"
    elif layer == DecisionLayer.NOT_ALLOWLISTED:
        consequence = Consequence.NONE
        mechanism = "fail-closed-not-allowlisted"
    elif layer == DecisionLayer.HUMAN_APPROVED:
        consequence = Consequence.NONE
        mechanism = "human-approved-history"
    elif layer == DecisionLayer.PACKAGE_GUARD:
        consequence = Consequence.INTEGRITY
        mechanism = "package-mutation"
    elif layer == DecisionLayer.ORIGIN_GUARD:
        consequence = Consequence.NONE
        mechanism = "origin-hard-escalate"
    elif layer == DecisionLayer.NORMALIZATION_AMBIGUOUS:
        consequence = Consequence.NONE
        mechanism = "normalization-ambiguous"
    elif layer == DecisionLayer.COMPLEXITY_TAX:
        consequence = Consequence.NONE
        mechanism = "complexity-tax"
    elif layer == DecisionLayer.CLOUD_JUDGE:
        consequence = Consequence.DESTRUCTION
        mechanism = "cloud-judge-defer"
    elif layer == DecisionLayer.LLM_INSPECTOR:
        consequence = Consequence.DESTRUCTION
        mechanism = "subshell-substitution"
    else:
        consequence = Consequence.DESTRUCTION
        mechanism = "none"

    if "DEGRADED" in reason or "degraded" in reason.lower() or "binary absent" in reason.lower():
        gate_state = GateState.DEGRADED
        mechanism = "sast-degraded"

    return {
        "origin": origin.value if isinstance(origin, Origin) else str(origin),
        "consequence": consequence.value if isinstance(consequence, Consequence) else str(consequence),
        "mechanism": mechanism,
        "gate_state": gate_state.value if isinstance(gate_state, GateState) else str(gate_state),
        "shadow_mode": shadow,
        "counterfactual_block": (not is_safe) and shadow,
    }


def audit_shell_command_with_taxonomy(
    cmd_str: str,
    use_llm_judge: bool = False,
    reasoning_effort: str = DEFAULT_REASONING_EFFORT,
    origin: Origin = Origin.AGENT,
    cwd: str = "",
    scope: str = "default",
    agent_id: str = "default",
) -> tuple[bool, str, DecisionLayer, dict[str, Any]]:
    """Audit shell command and return safety, reason, layer, and 2D taxonomy metadata.

    Deterministic guards (Fast-Track AST, ShellCheck SAST, Critical Regex, Gray-Zone)
    run unconditionally on every invocation. Dynamic parameter evaluations use the scoped LLM cache.

    If SCHENGEN_SHADOW_MODE=1 is active, dangerous commands return is_safe=True with
    counterfactual logging metadata.
    """
    is_safe, reason, raw_layer = audit_shell_command(
        cmd_str,
        use_llm_judge=use_llm_judge,
        reasoning_effort=reasoning_effort,
        cwd=cwd,
        scope=scope,
        agent_id=agent_id,
        origin=origin,
    )
    try:
        layer = DecisionLayer(raw_layer) if not isinstance(raw_layer, DecisionLayer) else raw_layer
    except (ValueError, TypeError):
        layer = DecisionLayer.FAST_TRACK_AST

    taxonomy = derive_taxonomy(cmd_str, layer, is_safe, reason, origin=origin)

    # Shadow Mode Handling
    if is_shadow_mode() and not is_safe:
        shadow_reason = f"[SHADOW_OBSERVE: Counterfactual BLOCK] {reason}"
        return True, shadow_reason, layer, taxonomy

    return is_safe, reason, layer, taxonomy


def sanitize_output(output_str: str) -> str:
    """Sanitize secrets from command output/logs."""
    masked = re.sub(
        r"(token|secret|key|password|api[_-]?key)\s*[:=]\s*['\"][^'\"]+['\"]",
        r"\1: '***MASKED***'",
        output_str,
        flags=re.IGNORECASE,
    )
    return masked
