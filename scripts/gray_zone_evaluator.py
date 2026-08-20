#!/usr/bin/env python3
"""Gray Zone & Non-VCS Irreversible Mutation Evaluator (ADR-004 / SOP-12).

Implements the Dynamic Decision Function:
Decision = f(Resource Tier x Operation Type x Irreversibility Spectrum x Execution Context)
"""

import enum
import os
import re
import shlex
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class ResourceTier(str, enum.Enum):
    T0_EPHEMERAL = "T0_EPHEMERAL"              # /tmp, /var/tmp, /var/folders/**/T/ (non-socket)
    T1_REGENERABLE = "T1_REGENERABLE"          # /var/folders/**/C/, DerivedData, package caches
    T2_VERSION_CONTROLLED = "T2_VERSION_CONTROLLED" # Chezmoi source, Git clean & committed
    T3_DURABLE_GRAY = "T3_DURABLE_GRAY"        # ~/.local/state, SQLite DB, uncommitted git tree
    T4_CRITICAL = "T4_CRITICAL"                # Keychains, TCC, SSH keys, active sockets, Forgejo/DSM deletes


class OperationType(str, enum.Enum):
    READ = "R"               # Read / Inspect (cat, ls, grep)
    APPEND = "A"             # Append / Insert (>>, INSERT INTO)
    OVERWRITE = "W"          # Overwrite / Modify in-place (cp, nano, echo > existing)
    TRUNCATE = "T"           # Truncate / 0-byte (> existing, truncate)
    DELETE = "D"             # Delete / Remove (rm, unlink)
    MOVE = "M"               # Move / Rename (mv)
    MUTATING_API = "X"       # Mutating API / System CLI (tccutil, defaults, curl POST/DELETE)
    HEAVY_EXEC = "E"         # Heavy build / migration / execution


class IrreversibilityGrade(str, enum.Enum):
    R0_NONE = "R0"           # Trivial re-generation, near zero cost
    R1_BACKUP_VCS = "R1"     # Fully recoverable from backup or clean VCS
    R2_RECONSTRUCT = "R2"    # Recoverable only via re-running work (hours/CPU/network loss)
    R3_OS_APP_RELOAD = "R3"  # Requires app re-login, daemon reload, or OS re-permissioning
    R4_IRREVERSIBLE = "R4"   # True permanent loss (secrets, external server delete)


class Verdict(str, enum.Enum):
    ALLOW = "ALLOW"          # 0.1s Fast-Track automated approval
    PROMPT = "PROMPT"        # Intercept & present 7-field Structured Decision Guidance
    BLOCK = "BLOCK"          # Hard block with alternative remediation advice


# Base Matrix: Tier x Operation -> Verdict
BASE_GOVERNANCE_MATRIX: Dict[Tuple[ResourceTier, OperationType], Verdict] = {
    # T0 (Ephemeral)
    (ResourceTier.T0_EPHEMERAL, OperationType.READ): Verdict.ALLOW,
    (ResourceTier.T0_EPHEMERAL, OperationType.APPEND): Verdict.ALLOW,
    (ResourceTier.T0_EPHEMERAL, OperationType.OVERWRITE): Verdict.ALLOW,
    (ResourceTier.T0_EPHEMERAL, OperationType.TRUNCATE): Verdict.ALLOW,
    (ResourceTier.T0_EPHEMERAL, OperationType.DELETE): Verdict.ALLOW,
    (ResourceTier.T0_EPHEMERAL, OperationType.MOVE): Verdict.ALLOW,
    (ResourceTier.T0_EPHEMERAL, OperationType.MUTATING_API): Verdict.ALLOW,
    (ResourceTier.T0_EPHEMERAL, OperationType.HEAVY_EXEC): Verdict.ALLOW,

    # T1 (Regenerable with Cost)
    (ResourceTier.T1_REGENERABLE, OperationType.READ): Verdict.ALLOW,
    (ResourceTier.T1_REGENERABLE, OperationType.APPEND): Verdict.ALLOW,
    (ResourceTier.T1_REGENERABLE, OperationType.OVERWRITE): Verdict.PROMPT,
    (ResourceTier.T1_REGENERABLE, OperationType.TRUNCATE): Verdict.ALLOW,
    (ResourceTier.T1_REGENERABLE, OperationType.DELETE): Verdict.ALLOW,
    (ResourceTier.T1_REGENERABLE, OperationType.MOVE): Verdict.ALLOW,
    (ResourceTier.T1_REGENERABLE, OperationType.MUTATING_API): Verdict.PROMPT,
    (ResourceTier.T1_REGENERABLE, OperationType.HEAVY_EXEC): Verdict.ALLOW,

    # T2 (Clean & Committed Version-Controlled)
    (ResourceTier.T2_VERSION_CONTROLLED, OperationType.READ): Verdict.ALLOW,
    (ResourceTier.T2_VERSION_CONTROLLED, OperationType.APPEND): Verdict.ALLOW,
    (ResourceTier.T2_VERSION_CONTROLLED, OperationType.OVERWRITE): Verdict.ALLOW,
    (ResourceTier.T2_VERSION_CONTROLLED, OperationType.TRUNCATE): Verdict.ALLOW,
    (ResourceTier.T2_VERSION_CONTROLLED, OperationType.DELETE): Verdict.PROMPT,
    (ResourceTier.T2_VERSION_CONTROLLED, OperationType.MOVE): Verdict.ALLOW,
    (ResourceTier.T2_VERSION_CONTROLLED, OperationType.MUTATING_API): Verdict.PROMPT,
    (ResourceTier.T2_VERSION_CONTROLLED, OperationType.HEAVY_EXEC): Verdict.ALLOW,

    # T3 (Durable Gray Zone: Logs, State, DBs, Uncommitted Git Trees)
    (ResourceTier.T3_DURABLE_GRAY, OperationType.READ): Verdict.ALLOW,
    (ResourceTier.T3_DURABLE_GRAY, OperationType.APPEND): Verdict.ALLOW,
    (ResourceTier.T3_DURABLE_GRAY, OperationType.OVERWRITE): Verdict.PROMPT,
    (ResourceTier.T3_DURABLE_GRAY, OperationType.TRUNCATE): Verdict.BLOCK,
    (ResourceTier.T3_DURABLE_GRAY, OperationType.DELETE): Verdict.PROMPT,
    (ResourceTier.T3_DURABLE_GRAY, OperationType.MOVE): Verdict.PROMPT,
    (ResourceTier.T3_DURABLE_GRAY, OperationType.MUTATING_API): Verdict.PROMPT,
    (ResourceTier.T3_DURABLE_GRAY, OperationType.HEAVY_EXEC): Verdict.PROMPT,

    # T4 (Irreversible & Critical: Secrets, OS State, Sockets, Admin APIs)
    (ResourceTier.T4_CRITICAL, OperationType.READ): Verdict.PROMPT,
    (ResourceTier.T4_CRITICAL, OperationType.APPEND): Verdict.PROMPT,
    (ResourceTier.T4_CRITICAL, OperationType.OVERWRITE): Verdict.BLOCK,
    (ResourceTier.T4_CRITICAL, OperationType.TRUNCATE): Verdict.BLOCK,
    (ResourceTier.T4_CRITICAL, OperationType.DELETE): Verdict.BLOCK,
    (ResourceTier.T4_CRITICAL, OperationType.MOVE): Verdict.BLOCK,
    (ResourceTier.T4_CRITICAL, OperationType.MUTATING_API): Verdict.PROMPT,
    (ResourceTier.T4_CRITICAL, OperationType.HEAVY_EXEC): Verdict.BLOCK,
}


@dataclass
class DecisionGuidancePayload:
    target: str
    operation: OperationType
    tier: ResourceTier
    irreversibility: IrreversibilityGrade
    blast_radius: str
    pre_alternative: str
    recovery_path: str
    choices: List[str]
    verdict: Verdict
    reason: str


def is_git_clean_and_committed(path: Path) -> bool:
    """Check if the path resides in a git repository and has a clean, committed working tree."""
    try:
        target_dir = path if path.is_dir() else path.parent
        if not target_dir.exists():
            return False
        
        # Check if inside git work tree
        is_git = subprocess.run(
            ["git", "-C", str(target_dir), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, check=False
        )
        if is_git.returncode != 0 or is_git.stdout.strip() != "true":
            return False

        # Check working tree status for the target path
        status = subprocess.run(
            ["git", "-C", str(target_dir), "status", "--porcelain", str(path)],
            capture_output=True, text=True, check=False
        )
        # If porcelain status is empty, it is clean and committed
        return len(status.stdout.strip()) == 0
    except Exception:
        return False


def is_unix_socket(path: Path) -> bool:
    """Check if the given path exists and is a Unix Domain Socket."""
    try:
        if path.exists() or path.is_socket():
            return stat.S_ISSOCK(path.lstat().st_mode)
    except Exception:
        pass
    return False


def canonicalize_path(raw_path_str: str) -> Path:
    """Resolve symlinks (/var -> /private/var, /tmp -> /private/tmp) and canonicalize path."""
    expanded = os.path.expanduser(os.path.expandvars(raw_path_str.strip()))
    p = Path(expanded)
    try:
        return p.resolve()
    except Exception:
        return p.absolute()


def classify_resource_tier(target_str: str, context: Optional[Dict] = None) -> ResourceTier:
    """Dynamically classify a filesystem path or URI into T0 ~ T4 tiers."""
    target_clean = target_str.strip()
    
    # 1. External REST API Endpoints
    if target_clean.startswith("http://") or target_clean.startswith("https://"):
        if re.search(r"/(admin/users|repos/[^/]+/[^/]+/archive|volumes|storagepools)", target_clean):
            return ResourceTier.T4_CRITICAL
        return ResourceTier.T3_DURABLE_GRAY

    canon = canonicalize_path(target_clean)
    canon_str = str(canon)

    # 2. Critical OS & Secret Targets (T4)
    # Check for Unix socket in any directory (especially /var/folders/.../T/)
    if is_unix_socket(canon) or (re.search(r"/var/folders/.*/T/", canon_str) and canon_str.endswith(".sock")):
        return ResourceTier.T4_CRITICAL

    t4_patterns = [
        r"/\.ssh/(id_|.*\.pem|.*\.key)",
        r"/Library/Keychains",
        r"/\.gnupg/(secring|private-keys-v1\.d)",
        r"/com\.apple\.TCC/TCC\.db",
        r"/LaunchServices/.*\.csstore",
        r"^/(private/)?(etc|System|usr|bin|sbin|var/root)",
    ]
    for pat in t4_patterns:
        if re.search(pat, canon_str):
            return ResourceTier.T4_CRITICAL

    # 3. macOS /var/folders Sub-Scoping
    if "/var/folders/" in canon_str:
        if re.search(r"/var/folders/.*/T(/.*)?$", canon_str):
            # /T/ is Ephemeral T0 (unless it was a socket caught above)
            return ResourceTier.T0_EPHEMERAL
        if re.search(r"/var/folders/.*/C(/.*)?$", canon_str):
            # /C/ is Regenerable Cache T1
            return ResourceTier.T1_REGENERABLE
        if re.search(r"/var/folders/.*/0(/.*)?$", canon_str):
            # /0/ is OS Darwin Core state T4
            return ResourceTier.T4_CRITICAL

    # 4. Standard Ephemeral Roots (T0)
    if canon_str.startswith("/tmp") or canon_str.startswith("/private/tmp") or canon_str.startswith("/var/tmp") or canon_str.startswith("/private/var/tmp"):
        return ResourceTier.T0_EPHEMERAL

    # 5. Caches & DerivedData (T1)
    t1_patterns = [
        r"/Library/Developer/Xcode/DerivedData",
        r"/\.cache/",
        r"/\.npm/_cacache",
        r"/\.cargo/registry/cache",
        r"/Library/Caches/",
    ]
    for pat in t1_patterns:
        if re.search(pat, canon_str):
            return ResourceTier.T1_REGENERABLE

    # 6. Version Controlled Assets (T2 vs T3 Clean Tree Verification)
    if "/.local/share/chezmoi" in canon_str:
        return ResourceTier.T2_VERSION_CONTROLLED

    if canon.exists() and is_git_clean_and_committed(canon):
        return ResourceTier.T2_VERSION_CONTROLLED

    # 7. Durable Gray Zone Assets (T3)
    t3_patterns = [
        r"/\.local/state/",
        r"/\.local/share/(?!chezmoi)",
        r"/\.config/",
        r"/\.hermes/(memories|sessions|logs)",
        r".*\.(db|sqlite|sqlite3|wal|shm)$",
    ]
    for pat in t3_patterns:
        if re.search(pat, canon_str):
            return ResourceTier.T3_DURABLE_GRAY

    # Default fallback: If it is a user repo with uncommitted changes -> T3, otherwise T3
    return ResourceTier.T3_DURABLE_GRAY


def classify_operation(cmd_str: str) -> Tuple[OperationType, Optional[str]]:
    """Parse shell command string to determine OperationType (R, A, W, T, D, M, X, E) and primary target."""
    clean_cmd = cmd_str.strip()

    # Strip quoted strings to avoid false-positive redirection matching on email brackets (<...>) or string literals
    unquoted_cmd = re.sub(r'([\'"])(?:(?!\1)[^\\]|\\.)*\1', '""', clean_cmd)

    # 1. Truncate (> file.ext without >>)
    if re.search(r"(?<![>12&])>\s*[^>&]+", unquoted_cmd):
        match = re.search(r"(?<![>12&])>\s*([^\s>&|]+)", unquoted_cmd)
        target = match.group(1) if match else None
        return OperationType.TRUNCATE, target

    # 2. Append (>> file.ext)
    if ">>" in unquoted_cmd:
        match = re.search(r">>\s*([^\s>&|]+)", unquoted_cmd)
        target = match.group(1) if match else None
        return OperationType.APPEND, target

    # 3. Mutating System API / CLI / REST
    if re.search(r"\b(tccutil|defaults\s+(write|delete)|launchctl\s+(bootstrap|bootout|load|unload|kill|disable|enable)|security\s+(add|delete|set|import)|scselect|systemsetup|pmset|networksetup|plutil\s+(-replace|-remove)|scutil\s+--set)\b", clean_cmd):
        return OperationType.MUTATING_API, clean_cmd.split()[0]

    if re.search(r"\bcurl\b.*-X\s*(POST|PUT|DELETE|PATCH)", clean_cmd):
        url_match = re.search(r"https?://[^\s\"']+", clean_cmd)
        url_str = url_match.group(0) if url_match else ""
        # Local LLM Inference endpoints (OpenAI-compatible) are stateless inference requests
        if re.search(r"https?://(127\.0\.0\.1|localhost)(:\d+)?/v1/(chat/completions|completions|embeddings)", url_str):
            return OperationType.READ, url_str
        target = url_str if url_str else "REST_API"
        return OperationType.MUTATING_API, target

    # 4. Standard File Commands
    try:
        tokens = shlex.split(clean_cmd)
    except Exception:
        tokens = clean_cmd.split()

    if not tokens:
        return OperationType.READ, None

    cmd_verb = tokens[0]

    if cmd_verb in ("rm", "unlink", "shred", "trash"):
        # Delete
        targets = [t for t in tokens[1:] if not t.startswith("-")]
        return OperationType.DELETE, (targets[-1] if targets else None)

    if cmd_verb in ("mv",):
        # Move / Rename
        targets = [t for t in tokens[1:] if not t.startswith("-")]
        return OperationType.MOVE, (targets[0] if targets else None)

    if cmd_verb in ("cp", "install", "rsync"):
        # Overwrite / Write
        targets = [t for t in tokens[1:] if not t.startswith("-")]
        return OperationType.OVERWRITE, (targets[-1] if targets else None)

    if cmd_verb in ("cat", "head", "tail", "grep", "rg", "find", "ls", "less", "file", "stat", "git"):
        # Read
        targets = [t for t in tokens[1:] if not t.startswith("-")]
        return OperationType.READ, (targets[0] if targets else None)

    # 5. Heavy Execution
    if cmd_verb in ("make", "cargo", "pytest", "npm", "pnpm", "bun", "docker", "mise"):
        return OperationType.HEAVY_EXEC, cmd_verb

    return OperationType.READ, (tokens[1] if len(tokens) > 1 else None)


def evaluate_gray_zone_operation(
    cmd_str: str,
    target_override: Optional[str] = None,
    context: Optional[Dict] = None
) -> Tuple[Verdict, str, Optional[DecisionGuidancePayload]]:
    """Evaluate dynamic decision function and generate Structured Decision Guidance if needed."""
    op, detected_target = classify_operation(cmd_str)
    target = target_override or detected_target or "unknown_target"
    tier = classify_resource_tier(target, context)

    # Lookup Base Verdict
    base_verdict = BASE_GOVERNANCE_MATRIX.get((tier, op), Verdict.PROMPT)

    # Irreversibility Grading
    if tier == ResourceTier.T0_EPHEMERAL:
        irrev = IrreversibilityGrade.R0_NONE
    elif tier == ResourceTier.T1_REGENERABLE:
        irrev = IrreversibilityGrade.R2_RECONSTRUCT
    elif tier == ResourceTier.T2_VERSION_CONTROLLED:
        irrev = IrreversibilityGrade.R1_BACKUP_VCS
    elif tier == ResourceTier.T3_DURABLE_GRAY:
        irrev = IrreversibilityGrade.R2_RECONSTRUCT if op in (OperationType.OVERWRITE, OperationType.DELETE, OperationType.TRUNCATE) else IrreversibilityGrade.R1_BACKUP_VCS
    else:  # T4
        irrev = IrreversibilityGrade.R4_IRREVERSIBLE

    reason = f"Dynamic Gate: Tier={tier.value}, Op={op.value} ({op.name}), Irreversibility={irrev.value} ({irrev.name}) -> Verdict={base_verdict.value}"

    if base_verdict == Verdict.ALLOW:
        return Verdict.ALLOW, reason, None

    # Construct 7-field Structured Decision Guidance Document
    canonical_target = str(canonicalize_path(target)) if not target.startswith("http") else target
    blast_radius = f"{tier.value} resource impact: "
    if tier == ResourceTier.T4_CRITICAL:
        blast_radius += "System security, active daemon socket, or critical server configuration."
    elif tier == ResourceTier.T3_DURABLE_GRAY:
        blast_radius += "Stateful local data, uncommitted working tree changes, or SQLite database records."
    elif tier == ResourceTier.T1_REGENERABLE:
        blast_radius += "Re-download / re-compilation cost (bandwidth and CPU time)."
    else:
        blast_radius += "Local file modifications."

    if op == OperationType.TRUNCATE:
        pre_alt = f"Rotate file before truncate: mv {target} {target}.$(date +%Y%m%d_%H%M%S).bak"
    elif op == OperationType.DELETE:
        pre_alt = f"Archive or stage backup: cp -a {target} {target}.bak"
    elif op == OperationType.MUTATING_API:
        pre_alt = "Use dedicated non-destructive API or query token permissions first."
    else:
        pre_alt = f"Stage shadow copy: cp -a {target} {target}.bak"

    recovery_path = f"Restore from backup copy (.bak) or rerun official state provisioning script."

    choices = [
        "A) Create pre-backup and proceed safely (Recommended)",
        "B) Proceed without backup (Explicit risk acceptance)",
        "C) Execute non-destructive alternative (Move to trash / rotate)",
        "D) Skip operation"
    ]

    payload = DecisionGuidancePayload(
        target=canonical_target,
        operation=op,
        tier=tier,
        irreversibility=irrev,
        blast_radius=blast_radius,
        pre_alternative=pre_alt,
        recovery_path=recovery_path,
        choices=choices,
        verdict=base_verdict,
        reason=reason
    )

    return base_verdict, reason, payload


def format_decision_guidance(payload: DecisionGuidancePayload) -> str:
    """Format DecisionGuidancePayload into standardized 7-field text block."""
    lines = [
        "🚨 [BORDER_CONTROL_INTERCEPT] Non-VCS Irreversible Mutation Gate",
        "────────────────────────────────────────────────────────────────────────",
        f"[1] Target (대상)        : {payload.target}",
        f"[2] Operation (연산)     : {payload.operation.value} ({payload.operation.name})",
        f"[3] Tier & Irreversibility: {payload.tier.value} | {payload.irreversibility.value} ({payload.irreversibility.name})",
        f"[4] Blast Radius (파급)  : {payload.blast_radius}",
        f"[5] Pre-Alternative (대안): {payload.pre_alternative}",
        f"[6] Recovery Path (복원) : {payload.recovery_path}",
        "[7] Structured Choices (선택지):",
    ]
    for ch in payload.choices:
        lines.append(f"    {ch}")
    lines.append(f"Verdict: {payload.verdict.value} ({payload.reason})")
    lines.append("────────────────────────────────────────────────────────────────────────")
    return "\n".join(lines)
