"""Workspace-scoped persistent allowlist (issue #7207, INV-WS-1..5).

A repo-local `.schengen/allowlist.json` policy file lets a workspace declare
persistent allowlist rules (dialog target paths or exec commands) that
fast-track without re-escalation — while:

- INV-WS-1: path rules only apply to targets under the policy's workspace_root.
- INV-WS-2: the global denylist ALWAYS wins (sensitive paths, sandbox, broad
  wildcards, T4-critical, root '/'), even when a rule lists the target.
- INV-WS-3: INJECTED/EMERGENT origins still hard-escalate (enforced by the
  ORIGIN_GUARD at the top of audit_shell_command, not here).
- INV-WS-4: malformed/oversized policy JSON is treated as absent (fail-closed).
- INV-WS-5: discovery never looks above the git toplevel (or $HOME) bound.

Rule schema:
    {"id", "action_type"("access_directory"|"edit_file"|"read_file"|"exec"),
     "match_type"("exact"|"prefix"|"glob"), "pattern", "agent_scope"(["*"]|[...]),
     "created_by", "created_at", "reason"}
"""

import fnmatch
import json
import os
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Optional

# Oversized policy files are treated as absent (INV-WS-4, fail-closed).
_MAX_POLICY_BYTES = 256 * 1024

# path -> (mtime, parsed_or_None); mtime-invalidated, no reload churn.
_policy_cache: dict[str, tuple[float, Optional[dict]]] = {}


def discover_workspace_policy(cwd: str) -> Optional[Path]:
    """Walk upward from cwd (inclusive) for the first `.schengen/allowlist.json`.

    The walk is bounded: it never ascends above the git toplevel (via
    `git rev-parse --show-toplevel`) or, when not in a git repo, above $HOME
    (INV-WS-5). Returns the policy file path or None.
    """
    if not cwd:
        return None
    try:
        start = Path(os.path.realpath(os.path.expanduser(str(cwd).strip())))
        if not start.is_dir():
            if start.exists():
                start = start.parent
    except Exception:
        return None

    # Upper bound: git toplevel else $HOME.
    bound: Optional[Path] = None
    try:
        out = subprocess.run(
            ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        if out.returncode == 0 and out.stdout.strip():
            bound = Path(os.path.realpath(out.stdout.strip()))
    except Exception:
        bound = None
    if bound is None:
        try:
            bound = Path.home().resolve()
        except Exception:
            bound = None

    cur = start
    while True:
        try:
            # Detect the .schengen/ DIRECTORY (allowlist.json need not exist yet)
            # so auto-promotion can create the file on first human approval.
            if (cur / ".schengen").is_dir():
                return cur / ".schengen" / "allowlist.json"
        except Exception:
            pass
        if bound is not None:
            real_cur = os.path.realpath(str(cur))
            real_bound = os.path.realpath(str(bound))
            if real_cur == real_bound:
                break  # bound checked inclusively; never ascend above it
        if cur.parent == cur:
            break
        cur = cur.parent
        if bound is not None:
            real_cur = os.path.realpath(str(cur))
            real_bound = os.path.realpath(str(bound))
            if real_cur != real_bound and not real_cur.startswith(real_bound + os.sep):
                break  # moved above the bound
    return None


def load_policy(path) -> Optional[dict]:
    """Parse + memoize the policy file (mtime-invalidated).

    Malformed or oversized JSON -> None (fail-closed, INV-WS-4). The None
    result is memoized too, so a broken file is not re-parsed on every call.
    """
    try:
        p = Path(path)
        st = p.stat()
        cache_key = str(p)
        cached = _policy_cache.get(cache_key)
        if cached is not None and cached[0] == st.st_mtime:
            return cached[1]
        if st.st_size > _MAX_POLICY_BYTES:
            _policy_cache[cache_key] = (st.st_mtime, None)
            return None
        raw = p.read_text(encoding="utf-8")
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            parsed = None
        if not isinstance(parsed, dict):
            parsed = None
        _policy_cache[cache_key] = (st.st_mtime, parsed)
        return parsed
    except Exception:
        return None


def _denylist_blocks(action_type: str, canon: str) -> bool:
    """INV-WS-2 re-assertion: sensitive paths, broad wildcards, T4, root '/'.

    Lazy imports avoid a circular import (security_evaluator imports this
    module). Returns True when the target must be denied even if listed.

    Reviewer fix: for `exec` the check runs on the RAW command text (so
    sensitive paths stay visible to the regexes) and ANY absolute-path token
    (`/...` or `~/...`) refuses the rule fail-closed — a pathful exec command
    can never promote or match, even if the sensitive path was otherwise
    invisible (e.g. after normalization collapsed it to `<PATH>`).
    """
    try:
        from core.security_evaluator import (
            SENSITIVE_DIRECTORY_PATTERN,
            SENSITIVE_FILE_PATTERN,
            _BROAD_WILDCARD_RE,
        )
    except Exception:
        # Fail-closed: if the denylist cannot be evaluated, refuse to allow.
        return True
    if SENSITIVE_FILE_PATTERN.search(canon) or SENSITIVE_DIRECTORY_PATTERN.search(canon):
        return True
    if _BROAD_WILDCARD_RE.search(canon):
        return True
    if action_type == "exec":
        # Fix 1: exec rules must be pathless — any absolute path token is
        # refused (fail-closed), so a sensitive-path command can never
        # promote or match.
        for tok in str(canon).split():
            if tok.startswith("/") or tok.startswith("~/"):
                return True
        return False
    if canon == "/" or canon == "//":
        return True
    try:
        from core.gray_zone_evaluator import ResourceTier, classify_resource_tier

        if classify_resource_tier(canon) == ResourceTier.T4_CRITICAL:
            return True
    except Exception:
        pass
    return False


def _is_overbroad_pattern(pattern: str) -> bool:
    """Reject catch-all / over-broad patterns before they can be persisted."""
    p = (pattern or "").strip()
    if not p:
        return True
    lowered = p.lower()
    if lowered in ("**", "/", "//", "/*", "*", ".*", "~", "~/", "/**", ".", ".."):
        return True
    if p.endswith("/**") or p.endswith("/*") or p.endswith("/.*"):
        return True
    if lowered.startswith("**"):
        return True
    return False


def check_rule(policy, action_type: str, target: str) -> bool:
    """Return True if `target` matches a rule for `action_type`.

    INV-WS-2 denylist re-assertion runs FIRST — sensitive paths, broad
    wildcards, T4-critical targets and root '/' always deny, even when a rule
    lists them (for `exec` on the RAW command text, with absolute-path tokens
    refused). INV-WS-1: the policy must declare a valid, non-overbroad
    workspace_root and path targets must live under it — applied uniformly to
    ALL action_types (exec rules are confined by discovery: the policy only
    surfaces for a cwd inside that workspace). Over-broad patterns (Fix 3)
    never match at read time.
    """
    rules = (policy or {}).get("rules") or []
    if not rules:
        return False
    if action_type == "exec":
        # Fix 1: match on the RAW command (exact), not a normalized form, so
        # promoted exact rules stay consistent and sensitive paths are visible.
        canon = str(target).strip()
    else:
        try:
            canon = os.path.realpath(os.path.expanduser(str(target)))
        except Exception:
            canon = str(target)

    # INV-WS-2: denylist first (fail-closed even for listed targets).
    if _denylist_blocks(action_type, canon):
        return False

    # INV-WS-1 (uniform): the policy must declare a valid, non-overbroad
    # workspace_root. Path targets must also live under it; exec rules are
    # confined by discovery (the policy only surfaces for cwd under its root).
    ws_root = str((policy or {}).get("workspace_root") or "").rstrip("/")
    if not ws_root or _is_overbroad_pattern(ws_root):
        return False
    if action_type != "exec":
        if canon != ws_root and not canon.startswith(ws_root + "/"):
            return False

    for r in rules:
        if r.get("action_type") != action_type:
            continue
        mt = r.get("match_type")
        pat = r.get("pattern")
        if not pat:
            continue
        # Fix 3: over-broad catch-all patterns never match at read time.
        if _is_overbroad_pattern(pat):
            continue
        if mt == "exact":
            if canon == pat:
                return True
        elif mt == "prefix":
            base = str(pat).rstrip("/")
            if canon == str(pat) or canon == base or canon.startswith(base + "/"):
                return True
        elif mt == "glob":
            if fnmatch.fnmatch(canon, pat):
                return True
    return False


def _atomic_write(path: Path, policy: dict) -> None:
    """Write the policy atomically: tmp + fsync + os.replace + fsync dir."""
    data = json.dumps(policy, indent=2, ensure_ascii=False).encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".allowlist-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, str(path))
        try:
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception:
            pass
    finally:
        try:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        except Exception:
            pass


def _policy_root(policy_path: Path) -> str:
    """Derive workspace_root from a policy path (<ws>/.schengen/allowlist.json)."""
    return str(policy_path.parent.parent.resolve())


def promote_rule(policy_path, rule: dict) -> bool:
    """Atomically add a rule to the workspace policy file (issue #7207).

    Dedupes by (action_type, match_type, pattern, agent_scope); re-asserts the
    INV-WS-2 denylist and rejects over-broad catch-all patterns before writing.
    Returns True on success.
    """
    try:
        policy_path = Path(policy_path)
        if not policy_path.parent.is_dir():
            return False
        existing = load_policy(policy_path) or {"version": 1, "workspace_root": "", "rules": []}
        rules = list(existing.get("rules") or [])
        at = rule.get("action_type")
        mt = rule.get("match_type")
        pat = rule.get("pattern")
        if not at or not mt or not pat:
            return False
        # INV-WS-2 re-assertion + over-broad rejection before write.
        if _denylist_blocks(at, pat):
            return False
        if _is_overbroad_pattern(pat):
            return False
        scope = sorted(rule.get("agent_scope") or ["*"])
        for r in rules:
            if (
                r.get("action_type") == at
                and r.get("match_type") == mt
                and r.get("pattern") == pat
                and sorted(r.get("agent_scope") or ["*"]) == scope
            ):
                return True  # already present (idempotent)
        new_rule = dict(rule)
        new_rule.setdefault("id", f"auto-{uuid.uuid4().hex[:12]}")
        new_rule.setdefault("agent_scope", ["*"])
        new_rule.setdefault("created_at", "")
        rules.append(new_rule)
        new_policy = {
            "version": 1,
            "workspace_root": existing.get("workspace_root") or _policy_root(policy_path),
            "rules": rules,
        }
        _atomic_write(policy_path, new_policy)
        _policy_cache.pop(str(policy_path), None)  # invalidate memo
        return True
    except Exception:
        return False


def revoke_rule(policy_path, rule: dict) -> bool:
    """Atomically remove a matching rule from the workspace policy file."""
    try:
        policy_path = Path(policy_path)
        existing = load_policy(policy_path)
        if existing is None:
            return False
        rules = existing.get("rules") or []
        at = rule.get("action_type")
        mt = rule.get("match_type")
        pat = rule.get("pattern")
        scope = sorted(rule.get("agent_scope") or ["*"])
        kept = [
            r
            for r in rules
            if not (
                r.get("action_type") == at
                and r.get("match_type") == mt
                and r.get("pattern") == pat
                and sorted(r.get("agent_scope") or ["*"]) == scope
            )
        ]
        if len(kept) == len(rules):
            return False  # nothing to revoke
        new_policy = {
            "version": 1,
            "workspace_root": existing.get("workspace_root") or _policy_root(policy_path),
            "rules": kept,
        }
        _atomic_write(policy_path, new_policy)
        _policy_cache.pop(str(policy_path), None)
        return True
    except Exception:
        return False
