"""ShellCheck SAST pre-filter module for Herdr Schengen (SmartGate).

Inspects shell scripts, multi-line payloads, and command strings for latent/emergent
variable hazards before execution:
1. SC2115: Use "${var:?}" to ensure variable never expands to '/' or '/*' (Catastrophic root wipe)
2. SC2154: Variable referenced but not assigned (Unbound variable disaster)
3. Environment Whitelist: Injects runtime environment variables to eliminate false positives.

Latency SLA: <80ms, non-blocking fallback if binary is absent.
"""

import json
import re
import shutil
import subprocess
from typing import Any, Optional

# Standard runtime environment variable whitelist to prevent false-positives
# Note: Sensitive tokens/keys (e.g. FORGEJO_TOKEN, BW_SESSION) are excluded to ensure full scrutiny
STANDARD_ENV_WHITELIST: set[str] = {
    "HOME",
    "USER",
    "LOGNAME",
    "PATH",
    "PWD",
    "OLDPWD",
    "SHELL",
    "TERM",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "UID",
    "GID",
    "EUID",
    "OSTYPE",
    "MACHTYPE",
    "HOSTTYPE",
    "HOSTNAME",
    "SHLVL",
    "RANDOM",
    "SECONDS",
    "LINENO",
    "IFS",
    # Safe Agent & Tooling runtime flags (non-secret)
    "ANTIGRAVITY_AGENT",
    "HERDR_ENV",
    "HERMES_HOME",
    "SCHENGEN_SHADOW_MODE",
    "CI",
    "NODE_ENV",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "CARGO_HOME",
    "RUSTUP_HOME",
}

# Critical shell operations where unbound variables are catastrophic (E x DEST)
DESTRUCTIVE_VARIABLE_COMMANDS = re.compile(r"\b(rm|unlink|mkfs|dd|chmod|chown|mv|truncate|cp)\b", re.IGNORECASE)


def get_runtime_env_whitelist() -> set[str]:
    """Return standard non-secret environment whitelist."""
    return set(STANDARD_ENV_WHITELIST)


def is_shellcheck_available() -> bool:
    """Check if shellcheck binary is installed and executable in PATH."""
    return shutil.which("shellcheck") is not None


def audit_shell_with_shellcheck(
    cmd_str: str, custom_env_whitelist: Optional[set[str]] = None, timeout: float = 0.2
) -> tuple[bool, str, Optional[dict[str, Any]]]:
    """Audit shell command line or script block with ShellCheck AST analyzer.

    Latency SLA: <80ms typical, hard timeout at 200ms.

    Returns:
        (is_safe: bool, reason: str, details: Optional[dict[str, Any]])
    """
    if not cmd_str or not cmd_str.strip():
        return True, "Safe: Empty command", None

    # Only run ShellCheck if variable substitutions or script structures are present
    if not re.search(r"(\$|`|<<|\n|;|\band\b|\bor\b)", cmd_str):
        return True, "Safe: Static command without variable expansion", None

    if not is_shellcheck_available():
        # If binary is absent and command has destructive variable usage, emit visible DEGRADED marker
        if DESTRUCTIVE_VARIABLE_COMMANDS.search(cmd_str) and re.search(r"(\$|`)", cmd_str):
            return (
                True,
                "ShellCheck SAST: [DEGRADED_UNAVAILABLE] shellcheck binary not installed; pass-through to Layer 2 pattern guards",
                {"degraded": True, "reason": "BINARY_ABSENT"},
            )
        return True, "ShellCheck binary not available; skipped SAST pre-filter", None

    try:
        # Run shellcheck in JSON mode with all optional warnings enabled (including SC2154)
        proc = subprocess.run(
            ["shellcheck", "-s", "bash", "--enable=all", "-f", "json", "-"],
            input=cmd_str.encode("utf-8"),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if not proc.stdout.strip():
            return True, "ShellCheck SAST: No issues found", None

        findings = json.loads(proc.stdout.decode("utf-8"))
        if not findings:
            return True, "ShellCheck SAST: Clean", None

        whitelist = custom_env_whitelist or get_runtime_env_whitelist()

        for f in findings:
            code = f.get("code")
            msg = f.get("message", "")

            # 1. SC2115: Catastrophic empty variable expanding to '/' or '/*'
            if code == 2115:
                return (
                    False,
                    f"Catastrophic variable wipe risk (SC2115): {msg}",
                    {
                        "code": 2115,
                        "finding": f,
                        "hazard": "CATASTROPHIC_ROOT_WIPE",
                        "origin": "E",
                        "consequence": "DEST",
                        "mechanism": "unbound-variable-sc2115",
                    },
                )

            # 2. SC2154: Variable referenced but not assigned
            if code == 2154:
                # Extract variable name from message: "var is referenced but not assigned."
                var_match = re.match(r"^([a-zA-Z0-9_]+)\s+is referenced", msg)
                var_name = var_match.group(1) if var_match else ""

                # If variable is in the environment whitelist, it is a valid runtime variable -> ignore
                if var_name and var_name in whitelist:
                    continue

                # If the unassigned variable is used in a destructive command context -> BLOCK
                if DESTRUCTIVE_VARIABLE_COMMANDS.search(cmd_str):
                    return (
                        False,
                        f"Unbound variable in destructive command (SC2154: '${var_name}'): {msg}",
                        {
                            "code": 2154,
                            "var_name": var_name,
                            "finding": f,
                            "hazard": "UNBOUND_VARIABLE_DESTRUCTION",
                            "origin": "E",
                            "consequence": "DEST",
                            "mechanism": "unbound-variable-sc2154",
                        },
                    )

        return True, "ShellCheck SAST: Verified safe", None

    except subprocess.TimeoutExpired:
        # Fast fail-open with explicit degradation note if timeout exceeded (>200ms)
        return (
            True,
            "ShellCheck SAST: [DEGRADED_TIMEOUT] timeout exceeded (>200ms); pass-through to Layer 2",
            {"degraded": True, "reason": "TIMEOUT_EXCEEDED"},
        )
    except Exception as e:
        return True, f"ShellCheck SAST execution error ({e}); pass-through to Layer 2", None
