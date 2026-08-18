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
from enum import Enum
import json
import os
import re
import shlex
import stat
import urllib.request
import urllib.error
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional

from gray_zone_evaluator import (
    evaluate_gray_zone_operation,
    Verdict,
    format_decision_guidance,
    ResourceTier,
    OperationType,
)

# 1. Sensitive file patterns (Secrets & Credentials)
SEP = r"(^|[\s/\"'@:=])"
END_SEP = r"([\s/\"'@:=]|$)"

SENSITIVE_FILE_PATTERN = re.compile(
    rf"""(
        {SEP}\.env(\.[a-zA-Z0-9_-]+)?{END_SEP}|
        id_[a-zA-Z0-9_-]+|
        {SEP}credentials(\.json|\.yml|\.ini)?{END_SEP}|
        {SEP}secrets?(\.json|\.yml|\.toml)?{END_SEP}|
        \.(pem|key|pfx|pkcs12){END_SEP}|
        hosts\.yml|
        \.netrc|
        \.aws/credentials|
        \.kube/config
    )""",
    re.VERBOSE | re.IGNORECASE,
)

# 2. Hermes Sandbox path pattern
HERMES_SANDBOX_PATTERN = re.compile(r"(\.hermes/sandboxes|hermes_sandbox)", re.IGNORECASE)

# 3. Managed Git SCM (Forgejo, Gitea, GitHub, GitLab) allowed endpoint patterns
MANAGED_GIT_HOST_PATTERN = re.compile(r"https?://(192\.168\.10\.102:3000|api\.github\.com|gitlab\.com/api|[^/]*gitea[^/]*/api)")
MANAGED_GIT_ISSUES_PATTERN = re.compile(
    r"https?://(192\.168\.10\.102:3000/api/v1/repos/[^/]+/[^/]+/issues|"
    r"api\.github\.com/repos/[^/]+/[^/]+/(issues|pulls)|"
    r"gitlab\.com/api/v4/projects/[^/]+/issues|"
    r"[^/]*gitea[^/]*/api/v1/repos/[^/]+/[^/]+/issues)"
)
# Backward-compatibility alias
FORGEJO_HOST_PATTERN = MANAGED_GIT_HOST_PATTERN
FORGEJO_ISSUES_PATTERN = MANAGED_GIT_ISSUES_PATTERN

# 4. Critical Dangerous Shell Commands (Destructive / Elevation)
CRITICAL_SHELL_PATTERNS = [
    (r"\brm\s+(-[rfRF]+\s+|[^\s]*[rfRF])", "Destructive file deletion (rm -rf)"),
    (r"\bsudo\b", "Privilege escalation (sudo)"),
    (r"\bsu\b", "User switching (su)"),
    (r"\bchmod\s+[0-7x+rw-]+", "Permission modification (chmod)"),
    (r"\bchown\b", "Ownership modification (chown)"),
    (r"\bgit\s+push(\s+--force|\s+-f)?\b", "Remote Git push / overwrite"),
    (r"\bgit\s+reset\s+--hard\b", "Destructive Git reset"),
    (r"\bgit\s+clean\s+-[fF]", "Destructive Git clean"),
    (r"\b(mkfs|dd|fdisk|parted)\b", "Disk / Partition manipulation"),
]

# 5. Commands that READ or EXFILTRATE files
READ_COMMANDS = {
    "cat", "head", "tail", "grep", "less", "more", "awk", "sed",
    "strings", "base64", "xxd", "jq", "source", "."
}
NETWORK_EXFIL_COMMANDS = {"curl", "wget", "nc", "ncat", "socat", "scp", "rsync", "ssh"}

# 6. Shell file write commands targeting Hermes sandbox
SHELL_WRITE_COMMANDS = {
    "cp", "mv", "touch", "mkdir", "rsync", "tar", "unzip", "tee", "wget", "curl", "dd"
}

# 7. Dynamic Substitution Patterns $(cat ...) or `cat ...`
DYNAMIC_SUBSTITUTION_PATTERN = re.compile(
    r"""(
        \$\(\s*(cat|head|tail|grep|find|awk|sed|<)\b|
        `\s*(cat|head|tail|grep|find|awk|sed|<)\b
    )""",
    re.VERBOSE | re.IGNORECASE
)

# 8. Dangerous Python AST modules & functions
DANGEROUS_PY_MODULES = {"socket", "requests", "urllib", "http.client", "ftplib", "smtplib"}
DANGEROUS_PY_CALLS = {"eval", "exec", "__import__", "compile"}

# 9. LLM / GPT-OSS 120B / DeepSeek Model Configuration
DEFAULT_GPT_OSS_MODEL = os.environ.get("GUARD_LLM_MODEL", "gpt-oss:120b")
DEFAULT_GPT_OSS_ENDPOINT = os.environ.get("GUARD_LLM_ENDPOINT", "http://192.168.10.102:8000/v1/chat/completions")
DEFAULT_GPT_OSS_API_KEY = os.environ.get("GUARD_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("OPENAI_API_KEY") or ""
DEFAULT_REASONING_EFFORT = os.environ.get("GUARD_REASONING_EFFORT", "low")

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
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to inspect (e.g. 'safe_list.txt')"
                    }
                },
                "required": ["file_path"]
            }
        }
    }
]


def safe_read_file_content(file_path: str, max_bytes: int = 8192) -> Tuple[bool, str]:
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

        # Guard: Never read system root directories
        if re.search(r"^/(etc|var|System|Library|dev|proc|sys)/", path_str):
            return False, f"Refused read: System/device directory path '{path_str}'"

        if not clean_path.exists():
            return False, f"File does not exist: '{path_str}'"

        st = clean_path.stat()
        if not stat.S_ISREG(st.st_mode):
            return False, f"Refused read: Target is not a regular file (FIFO/socket/device): '{path_str}'"

        with open(clean_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(max_bytes)
            return True, content
    except Exception as e:
        return False, f"Safe read error: {e}"


class PythonASTAuditor(ast.NodeVisitor):
    """AST visitor to audit Python code safety before execution with Forgejo exceptions."""

    def __init__(self, raw_code: str = ""):
        self.raw_code = raw_code
        self.is_safe = True
        self.reasons: List[str] = []
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
                        self.reasons.append(f"Forbidden write operation to Hermes Sandbox: '{path_str}' (mode='{mode}')")

        # subprocess / os.system check
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("run", "Popen", "system", "call", "check_output"):
            for arg in node.args:
                if isinstance(arg, ast.Constant):
                    val_str = str(arg.value)
                    if HERMES_SANDBOX_PATTERN.search(val_str) and any(w in val_str for w in (">", "cp ", "mv ", "touch ", "rm ")):
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
            self.reasons.append(f"Network module imported without identifiable URL literal: {self.imported_net_modules}")
            return

        for url in urls:
            if not FORGEJO_HOST_PATTERN.match(url):
                self.is_safe = False
                self.reasons.append(f"Network call to external (non-Forgejo) target: '{url}'")
                return

            if re.search(r"method\s*=\s*['\"]DELETE['\"]", self.raw_code, re.IGNORECASE) or \
               re.search(r"requests\.delete\(", self.raw_code, re.IGNORECASE):
                self.is_safe = False
                self.reasons.append(f"Forbidden HTTP DELETE request to Forgejo: '{url}'")
                return

            is_issues = bool(FORGEJO_ISSUES_PATTERN.search(url))
            has_post_patch = bool(re.search(r"(method\s*=\s*['\"](POST|PATCH|PUT)['\"]|data\s*=|requests\.(post|patch|put)\()", self.raw_code))
            
            if has_post_patch and not is_issues:
                if not re.search(r"/api/v1/(user|users)", url):
                    self.is_safe = False
                    self.reasons.append(f"Non-GET request to non-issues Forgejo endpoint: '{url}'")


def audit_python_code(code_str: str) -> Tuple[bool, str]:
    """Parse and audit Python source code with Forgejo whitelist."""
    try:
        tree = ast.parse(code_str)
        auditor = PythonASTAuditor(raw_code=code_str)
        auditor.visit(tree)
        auditor.evaluate_network_calls()
        if not auditor.is_safe:
            return False, "; ".join(auditor.reasons)
        return True, "Python AST: Safe"
    except SyntaxError as e:
        return False, f"Python SyntaxError during AST audit: {e}"


def audit_dynamic_substitution_with_llm(
    cmd_str: str,
    endpoint: str = DEFAULT_GPT_OSS_ENDPOINT,
    model: str = DEFAULT_GPT_OSS_MODEL,
    api_key: Optional[str] = None,
    reasoning_effort: str = DEFAULT_REASONING_EFFORT,
    max_hops: int = 2
) -> Tuple[bool, str]:
    """Multi-turn Tool-Calling security inspector using private GPT-OSS 120B or DeepSeek.
    
    Guards against indirect command substitution attacks by reading referenced files
    and verifying whether runtime expanded arguments contain sensitive/system paths.
    Enforces Max Hops = 2 to prevent infinite tool loops.
    """
    system_prompt = (
        "You are an uncompromising security inspector subagent for Herdr SmartGate. "
        "A command contains dynamic command substitution (e.g. $(cat ...)). "
        "Use the `read_file_content` tool to inspect the referenced file(s). "
        "Check if the file content contains: "
        "1) Sensitive secrets (.env, id_rsa, tokens, credentials, passwords), "
        "2) System root paths (/etc, /System, /var, /usr, /dev), "
        "3) Destructive shell flags or commands. "
        "If safe, respond ONLY with JSON: {\"is_safe\": true, \"reason\": \"File content verified safe: <summary>\"}. "
        "If dangerous or uncertain, respond ONLY with JSON: {\"is_safe\": false, \"reason\": \"<danger explanation>\"}."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Inspect the dynamic parameters of this command before approval:\n```\n{cmd_str}\n```"}
    ]

    visited_paths = set()

    for hop in range(max_hops):
        req_body: Dict[str, Any] = {
            "model": model,
            "temperature": 0.0,
            "max_tokens": 300,
            "messages": messages,
            "tools": INSPECTOR_TOOLS,
            "tool_choice": "auto"
        }
        # Only inject reasoning_effort if explicitly configured and targeting a reasoning model
        if reasoning_effort and reasoning_effort.lower() not in ("off", "none", "") and ("reason" in model.lower() or "gpt-oss" in model.lower()):
            req_body["reasoning_effort"] = reasoning_effort.lower()

        payload = json.dumps(req_body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        effective_key = api_key if api_key is not None else DEFAULT_GPT_OSS_API_KEY
        if effective_key:
            headers["Authorization"] = f"Bearer {effective_key}"

        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers=headers
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.load(resp)
                choice = data["choices"][0]
                message = choice.get("message", {})
                tool_calls = message.get("tool_calls", [])

                if tool_calls:
                    if hop >= max_hops:
                        return False, f"Dynamic substitution inspection hop limit exceeded (Max Hops: {max_hops}); requires human review"

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

                            messages.append({
                                "role": "tool",
                                "tool_call_id": tc.get("id", "call_1"),
                                "content": tool_result
                            })
                    continue  # Next turn in loop

                # Final text response
                content_str = message.get("content", "")
                # Try parsing JSON response
                try:
                    # Clean json fences if present
                    clean_json = re.sub(r"^```json\s*", "", content_str.strip(), flags=re.IGNORECASE)
                    clean_json = re.sub(r"\s*```$", "", clean_json)
                    res = json.loads(clean_json)
                    is_safe = bool(res.get("is_safe", False))
                    reason = f"[GPT-OSS 120B Inspector] {res.get('reason', 'Inspected dynamic parameters')}"
                    return is_safe, reason
                except Exception:
                    if "true" in content_str.lower() and "safe" in content_str.lower() and "not" not in content_str.lower():
                        return True, f"[GPT-OSS 120B Inspector] Safe: {content_str[:80]}"
                    return False, f"[GPT-OSS 120B Inspector] Uncertain verdict: {content_str[:80]}; delegating to human"

        except Exception as e:
            # Fail-Safe to Human Review when private LLM inspector is unreachable
            return False, f"Dynamic substitution detected & LLM Inspector offline ({e}); requires human review"

    return False, "Dynamic substitution inspection could not be completed; requires human review"


def is_managed_git_safe_command(cmd_str: str) -> Tuple[bool, Optional[str]]:
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


class DecisionLayer(str, Enum):
    """Standard 9 inspection layers for Herdr Schengen (SmartGate)."""
    ALLOWLIST = "ALLOWLIST"                   # Layer 0: User-persisted allowlist regex
    MANAGED_GIT_GUARD = "MANAGED_GIT_GUARD"   # Layer 1: Managed Git SCM (Forgejo, Gitea, GitHub, GitLab) policy
    FORGEJO_GUARD = "MANAGED_GIT_GUARD"       # Layer 1 (Alias for backward compatibility)
    SHELL_CRITICAL = "SHELL_CRITICAL"         # Layer 2: Critical destructive shell operations (rm -rf, sudo, git reset --hard)
    SANDBOX_GUARD = "SANDBOX_GUARD"           # Layer 3: Hermes Docker/microVM Sandbox write isolation
    PYTHON_AST = "PYTHON_AST"                 # Layer 4: Python static AST analysis (eval/exec, opens, subprocess writes)
    SECRET_GUARD = "SECRET_GUARD"             # Layer 5: Sensitive file & secret pattern matching (.env, id_rsa, hosts.yml)
    LLM_INSPECTOR = "LLM_INSPECTOR"           # Layer 6: L2 Tool-Calling LLM Dynamic Parameter Semantic Inspector
    GRAY_ZONE_MATRIX = "GRAY_ZONE_MATRIX"     # Layer 7: Non-VCS Irreversible Mutation Matrix (ADR-004 / SOP-12)
    FAST_TRACK_AST = "FAST_TRACK_AST"         # Layer 8: Fast-track static safe development operations


def audit_shell_command(
    cmd_str: str,
    use_llm_judge: bool = False,
    reasoning_effort: str = DEFAULT_REASONING_EFFORT
) -> Tuple[bool, str, str]:
    """Audit shell command line with PATH, Managed Git rules, dynamic substitution inspection, and AST judge.
    
    Returns:
        (is_safe: bool, reason: str, layer: str)
    """
    if not cmd_str or not cmd_str.strip():
        return True, "Safe", DecisionLayer.FAST_TRACK_AST

    # 0. Check Managed Git command rules if targeting Managed Git host
    if MANAGED_GIT_HOST_PATTERN.search(cmd_str):
        mg_safe, mg_reason = is_managed_git_safe_command(cmd_str)
        if not mg_safe and mg_reason:
            return False, f"Managed Git security guard: {mg_reason}", DecisionLayer.MANAGED_GIT_GUARD
        if mg_safe and mg_reason:
            return True, f"Managed Git security guard: {mg_reason}", DecisionLayer.MANAGED_GIT_GUARD

    # 1. Check for inline python execution (Here-doc or -c)
    heredoc_match = re.search(r"python[0-9.]*\s+-\s*<<\s*['\"]?([A-Za-z0-9_]+)['\"]?\s*\n([\s\S]*?)\n\s*\1", cmd_str)
    if heredoc_match:
        py_code = heredoc_match.group(2)
        safe, reason = audit_python_code(py_code)
        if not safe:
            return False, f"Inline Python risk: {reason}", DecisionLayer.PYTHON_AST

    dash_c_match = re.search(r"python[0-9.]*\s+-c\s+(['\"])([\s\S]*?)\1", cmd_str)
    if dash_c_match:
        py_code = dash_c_match.group(2)
        safe, reason = audit_python_code(py_code)
        if not safe:
            return False, f"Python -c inline risk: {reason}", DecisionLayer.PYTHON_AST

    # 2. Check critical destructive patterns
    for pat, desc in CRITICAL_SHELL_PATTERNS:
        if re.search(pat, cmd_str, re.IGNORECASE):
            return False, f"Critical risk detected: {desc}", DecisionLayer.SHELL_CRITICAL

    # Check system directory access (exclude PATH=... variable assignments)
    cleaned_cmd = re.sub(r'PATH=["\']?[^"\';\s]+["\']?', '', cmd_str)
    if re.search(r"\b(cd|ls|cat|rm|cp|mv)\s+/(etc|var|usr|bin|sbin|Library|System)/", cleaned_cmd, re.IGNORECASE):
        return False, "System directory direct mutation/access", DecisionLayer.SHELL_CRITICAL

    # 3. Check Hermes Sandbox WRITE attempts
    if HERMES_SANDBOX_PATTERN.search(cmd_str):
        if re.search(r">>?[^|;&\n]*(\.hermes/sandboxes|hermes_sandbox)", cmd_str, re.IGNORECASE):
            return False, f"Forbidden shell redirection WRITE to Hermes Sandbox: '{cmd_str}'", DecisionLayer.SANDBOX_GUARD
        sub_commands = re.split(r"[;&|]+", cmd_str)
        for sub_cmd in sub_commands:
            sub_cmd = sub_cmd.strip()
            for write_bin in SHELL_WRITE_COMMANDS:
                if re.search(rf"\b{write_bin}\b.*(\.hermes/sandboxes|hermes_sandbox)", sub_cmd, re.IGNORECASE):
                    return False, f"Forbidden WRITE command ({write_bin}) targeting Hermes Sandbox: '{sub_cmd}'", DecisionLayer.SANDBOX_GUARD

    # 4. Check sensitive file reading or network exfiltration
    if SENSITIVE_FILE_PATTERN.search(cmd_str) and not FORGEJO_HOST_PATTERN.search(cmd_str):
        sub_commands = re.split(r"[;&|]+", cmd_str)
        for sub_cmd in sub_commands:
            sub_cmd = sub_cmd.strip()
            for read_bin in READ_COMMANDS:
                if re.search(rf"\b{read_bin}\b", sub_cmd, re.IGNORECASE) and SENSITIVE_FILE_PATTERN.search(sub_cmd):
                    return False, f"Attempting to READ sensitive file: '{sub_cmd}'", DecisionLayer.SECRET_GUARD
            for net_bin in NETWORK_EXFIL_COMMANDS:
                if re.search(rf"\b{net_bin}\b", sub_cmd, re.IGNORECASE) and SENSITIVE_FILE_PATTERN.search(sub_cmd):
                    return False, f"Network command touching sensitive path: '{sub_cmd}'", DecisionLayer.SECRET_GUARD

    # 5. Check dynamic command substitution $(cat ...) or `cat ...`
    if DYNAMIC_SUBSTITUTION_PATTERN.search(cmd_str):
        # Trigger L2 Multi-turn Tool-Calling Semantic Inspector with 5 Guardrails
        is_safe, reason = audit_dynamic_substitution_with_llm(cmd_str, reasoning_effort=reasoning_effort)
        return is_safe, reason, DecisionLayer.LLM_INSPECTOR

    # 6. Check Non-VCS Irreversible Mutation & Gray Zone Matrix (ADR-004 / SOP-12)
    gz_verdict, gz_reason, gz_payload = evaluate_gray_zone_operation(cmd_str)
    if gz_verdict == Verdict.BLOCK:
        return False, f"Non-VCS Gray-Zone Guard [BLOCK]: {gz_reason}", DecisionLayer.GRAY_ZONE_MATRIX
    if gz_verdict == Verdict.PROMPT and gz_payload:
        return False, format_decision_guidance(gz_payload), DecisionLayer.GRAY_ZONE_MATRIX

    return True, "Safe", DecisionLayer.FAST_TRACK_AST


def sanitize_output(output_str: str) -> str:
    """Sanitize secrets from command output/logs."""
    masked = re.sub(r"(token|secret|key|password|api[_-]?key)\s*[:=]\s*['\"][^'\"]+['\"]", r"\1: '***MASKED***'", output_str, flags=re.IGNORECASE)
    return masked
