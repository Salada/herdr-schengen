"""Security evaluation module for Herdr Agent Guard.

Combines:
1. Shell command parsing & blacklist inspection
2. Python AST static analysis (for inline / script files)
3. Sensitive file and secret pattern matching
4. Hermes sandbox write-protection policy
5. Output sanitization & exfiltration inspection
"""

import ast
import re
import shlex
from typing import Tuple, List, Dict, Any

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

# 3. Critical Dangerous Shell Commands (Destructive / Elevation)
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
    (r"/(etc|var|usr|bin|sbin|Library|System)/", "System directory access"),
]

# 4. Commands that READ or EXFILTRATE files
READ_COMMANDS = {
    "cat", "head", "tail", "grep", "less", "more", "awk", "sed",
    "strings", "base64", "xxd", "jq", "source", "."
}
NETWORK_EXFIL_COMMANDS = {"curl", "wget", "nc", "ncat", "socat", "scp", "rsync", "ssh"}

# 5. Shell file write commands targeting Hermes sandbox
SHELL_WRITE_COMMANDS = {
    "cp", "mv", "touch", "mkdir", "rsync", "tar", "unzip", "tee", "wget", "curl", "dd"
}

# 6. Dangerous Python AST modules & functions
DANGEROUS_PY_MODULES = {"socket", "requests", "urllib", "http.client", "ftplib", "smtplib"}
DANGEROUS_PY_CALLS = {"eval", "exec", "__import__", "compile"}


class PythonASTAuditor(ast.NodeVisitor):
    """AST visitor to audit Python code safety before execution."""

    def __init__(self):
        self.is_safe = True
        self.reasons: List[str] = []

    def visit_Import(self, node):
        for alias in node.names:
            base_mod = alias.name.split(".")[0]
            if base_mod in DANGEROUS_PY_MODULES:
                self.is_safe = False
                self.reasons.append(f"Forbidden network module imported: {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            base_mod = node.module.split(".")[0]
            if base_mod in DANGEROUS_PY_MODULES:
                self.is_safe = False
                self.reasons.append(f"Forbidden network module imported: {node.module}")
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
                if SENSITIVE_FILE_PATTERN.search(path_str):
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

        # Path.write_text / write_bytes check
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("write_text", "write_bytes"):
            self.is_safe = False
            self.reasons.append(f"File write method '{node.func.attr}' called")

        # subprocess / os.system check
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("run", "Popen", "system", "call", "check_output"):
            for arg in node.args:
                if isinstance(arg, ast.Constant):
                    val_str = str(arg.value)
                    if SENSITIVE_FILE_PATTERN.search(val_str):
                        self.is_safe = False
                        self.reasons.append(f"Process call targeting sensitive target: '{val_str}'")
                    if HERMES_SANDBOX_PATTERN.search(val_str) and any(w in val_str for w in (">", "cp ", "mv ", "touch ", "rm ")):
                        self.is_safe = False
                        self.reasons.append(f"Process call attempting write/mutation to Hermes Sandbox: '{val_str}'")

        self.generic_visit(node)


def audit_python_code(code_str: str) -> Tuple[bool, str]:
    """Parse and audit Python source code."""
    try:
        tree = ast.parse(code_str)
        auditor = PythonASTAuditor()
        auditor.visit(tree)
        if not auditor.is_safe:
            return False, "; ".join(auditor.reasons)
        return True, "Python AST: Safe"
    except SyntaxError as e:
        return False, f"Python SyntaxError during AST audit: {e}"


def audit_shell_command(cmd_str: str) -> Tuple[bool, str]:
    """Audit shell command line for dangerous patterns, secret reads, and sandbox writes."""
    # 1. Check critical destructive patterns
    for pat, desc in CRITICAL_SHELL_PATTERNS:
        if re.search(pat, cmd_str, re.IGNORECASE):
            return False, f"Critical risk detected: {desc}"

    # 2. Check Hermes Sandbox WRITE attempts
    if HERMES_SANDBOX_PATTERN.search(cmd_str):
        # Check redirection write (> or >>)
        if re.search(r">>?[^|;&\n]*(\.hermes/sandboxes|hermes_sandbox)", cmd_str, re.IGNORECASE):
            return False, f"Forbidden shell redirection WRITE to Hermes Sandbox: '{cmd_str}'"
        # Check write commands
        sub_commands = re.split(r"[;&|]+", cmd_str)
        for sub_cmd in sub_commands:
            sub_cmd = sub_cmd.strip()
            for write_bin in SHELL_WRITE_COMMANDS:
                if re.search(rf"\b{write_bin}\b.*(\.hermes/sandboxes|hermes_sandbox)", sub_cmd, re.IGNORECASE):
                    return False, f"Forbidden WRITE command ({write_bin}) targeting Hermes Sandbox: '{sub_cmd}'"

    # 3. Check for inline python execution (Here-doc or -c)
    heredoc_match = re.search(r"python[0-9.]*\s+-\s*<<\s*['\"]?([A-Za-z0-9_]+)['\"]?\s*\n([\s\S]*?)\n\s*\1", cmd_str)
    if heredoc_match:
        py_code = heredoc_match.group(2)
        safe, reason = audit_python_code(py_code)
        if not safe:
            return False, f"Inline Python risk: {reason}"

    dash_c_match = re.search(r"python[0-9.]*\s+-c\s+(['\"])([\s\S]*?)\1", cmd_str)
    if dash_c_match:
        py_code = dash_c_match.group(2)
        safe, reason = audit_python_code(py_code)
        if not safe:
            return False, f"Python -c inline risk: {reason}"

    # 4. Check sensitive file reading or network exfiltration
    if SENSITIVE_FILE_PATTERN.search(cmd_str):
        sub_commands = re.split(r"[;&|]+", cmd_str)
        for sub_cmd in sub_commands:
            sub_cmd = sub_cmd.strip()
            for read_bin in READ_COMMANDS:
                if re.search(rf"\b{read_bin}\b", sub_cmd, re.IGNORECASE) and SENSITIVE_FILE_PATTERN.search(sub_cmd):
                    return False, f"Attempting to READ sensitive file: '{sub_cmd}'"
            for net_bin in NETWORK_EXFIL_COMMANDS:
                if re.search(rf"\b{net_bin}\b", sub_cmd, re.IGNORECASE) and SENSITIVE_FILE_PATTERN.search(sub_cmd):
                    return False, f"Network command touching sensitive path: '{sub_cmd}'"

    return True, "Safe"


def sanitize_output(output_str: str) -> str:
    """Sanitize secrets from command output/logs."""
    masked = re.sub(r"(token|secret|key|password|api[_-]?key)\s*[:=]\s*['\"][^'\"]+['\"]", r"\1: '***MASKED***'", output_str, flags=re.IGNORECASE)
    return masked
