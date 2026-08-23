#!/usr/bin/env python3
"""Herdr Schengen / SmartGate Trusted Clearance Watcher Daemon.

Monitors Herdr pane(s) at configurable intervals, performs AST static
analysis and security evaluation on requested commands/scripts, logs every
event into SQLite3 database (~/.local/state/herdr-schengen/schengen_history.db),
and auto-approves safe commands (SmartGate flow) while delegating risky commands to human review.

Key Architecture:
- MULTI-AGENT TARGET SCOPE: Auto-approves designated coding agents (agy, opencode) while excluding Hermes, bare shells, and the caller pane. Default target is 'agy'; opencode is opt-in via --agent-filter agy,opencode.
- CONTINUOUS DISCOVERY: Dynamically polls all active and newly added Herdr panes in real-time.
- STRICT SINGLETON FILELOCK (fcntl.flock): Prevents race conditions & duplicate key injection.
- DAEMON & STATUS MANAGEMENT: Built-in --daemon, --status, and --stop lifecycle management.
- FAST 1ms AST + PRIVATELY HOSTED 120B LOW REASONING: Zero Google One quota consumption.
"""

import argparse
import ast
import fcntl
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add script directory to sys.path for local imports
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import importlib
import guard_db
import gray_zone_evaluator
import security_evaluator

from guard_db import (
    record_audit_log,
    check_persisted_allowlist,
    get_pattern_analysis,
    get_recent_audit_logs,
    search_audit_logs,
    get_state_file_paths,
    tail_state_log,
    init_db,
    enqueue_pending_escalation,
    get_pending_escalations,
    mark_escalation_delivered,
    resolve_escalation,
    cleanup_escalations,
    DB_DIR,
    DB_PATH
)
from security_evaluator import (
    audit_shell_command,
    audit_shell_command_with_taxonomy,
    derive_taxonomy,
    audit_python_code,
    sanitize_output,
    DecisionLayer,
    Origin,
    Consequence,
    GateState,
    is_shadow_mode,
    DEFAULT_GPT_OSS_MODEL,
    DEFAULT_GPT_OSS_ENDPOINT,
    DEFAULT_REASONING_EFFORT
)
from herdr_client import (
    run_cmd,
    get_all_panes,
    get_pane_info,
    get_pane_text,
    detect_self_pane_id,
)
from agent_adapters import get_adapter, target_agent_kinds

LOCK_FILE = DB_DIR / "schengen.lock"
LOG_FILE = DB_DIR / "schengen.log"

# Global reload trigger flag
_RELOAD_REQUESTED = False


def sanitize_target_name(target: str) -> str:
    """Normalize target string for safe lockfile naming (e.g. 'wS:pF' -> 'wS_pF')."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", target.strip())


def get_lock_file_path(target: str = "auto") -> Path:
    """Return target-specific scoped lockfile path."""
    sanitized = sanitize_target_name(target)
    return DB_DIR / f"schengen_{sanitized}.lock"


def get_legacy_lock_file_path() -> Path:
    """Return legacy global lockfile path for backward compatibility."""
    return DB_DIR / "schengen.lock"


def list_active_guard_locks() -> list:
    """Discover all active guard lockfiles and their running PIDs."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    active = []

    lock_files = list(DB_DIR.glob("schengen_*.lock"))
    legacy = get_legacy_lock_file_path()
    if legacy.exists() and legacy not in lock_files:
        lock_files.append(legacy)

    for lf in lock_files:
        if lf.name == "schengen.lock":
            target_label = "legacy_global"
        else:
            target_label = lf.stem.replace("schengen_", "", 1)

        pid = None
        try:
            with open(lf, "r") as f:
                content = f.read().strip()
                if content and content.isdigit():
                    cand_pid = int(content)
                    os.kill(cand_pid, 0)
                    pid = cand_pid
        except Exception:
            pid = None

        if pid is not None:
            active.append((target_label, lf, pid))
        else:
            try:
                lf.unlink(missing_ok=True)
            except Exception:
                pass

    return active


def acquire_scoped_lock(target: str = "auto"):
    """Acquire strict scoped singleton lock using fcntl.flock to prevent concurrent instances on the same target."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    lock_file = get_lock_file_path(target)
    try:
        lock_fd = open(lock_file, "a+")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_fd.seek(0)
        lock_fd.truncate()
        lock_fd.write(f"{os.getpid()}\n")
        lock_fd.flush()
        return lock_fd, lock_file
    except (IOError, BlockingIOError):
        running_pid = "unknown"
        try:
            with open(lock_file, "r") as f:
                running_pid = f.read().strip()
        except Exception:
            pass
        print(f"⚠️  Another SmartGate / Herdr Schengen watcher is already running for target '{target}' (PID: {running_pid}). Exiting.")
        sys.exit(0)


def get_running_guard_pid(target: str = "auto"):
    """Return PID of running guard for specific target if active and alive, else None."""
    lock_file = get_lock_file_path(target)
    if not lock_file.exists():
        if target == "auto":
            legacy = get_legacy_lock_file_path()
            if legacy.exists():
                lock_file = legacy
            else:
                return None
        else:
            return None
    try:
        with open(lock_file, "r") as f:
            pid_str = f.read().strip()
        if pid_str and pid_str.isdigit():
            pid = int(pid_str)
            os.kill(pid, 0)
            return pid
    except (ProcessLookupError, OSError):
        return None
    except Exception:
        return None
    return None


def show_guard_status():
    """Display live daemon state for all scopes, Herdr pane classification, and recent SmartGate events."""
    init_db()
    active_daemons = list_active_guard_locks()

    print("=" * 70)
    print("🛡️  Herdr SmartGate / Schengen Status Report")
    print("=" * 70)
    if active_daemons:
        print(f"● Status: ACTIVE ({len(active_daemons)} daemon(s) running)")
        for tgt, lpath, dpid in active_daemons:
            print(f"   • Target: [{tgt:<12}] | PID: {dpid:<7} | Lock: {lpath.name}")
    else:
        print("○ Status: INACTIVE (No active Schengen daemons)")

    # Active Herdr Panes
    all_panes = get_all_panes()
    self_pane = detect_self_pane_id()
    print(f"\n🖥️  Discovered Herdr Panes ({len(all_panes)} active, Self-Caller: {self_pane or 'None'}):")
    if not all_panes:
        print("   (No active Herdr panes detected or Herdr not running)")
    for p in all_panes:
        pane_id = p.get("pane_id", "")
        agent = p.get("agent", "none")
        agent_status = p.get("agent_status", "")
        cwd = p.get("foreground_cwd") or p.get("cwd", "")
        if self_pane and pane_id == self_pane:
            guard_label = " [🚫 EXCLUDED: Self-Caller Pane (No Self-Approval)]"
        elif agent in target_agent_kinds():
            guard_label = f" [🎯 Guard Target: {agent.upper()} Sibling/Child Pane]"
        else:
            guard_label = f" [⚪ Ignored: Non-Target ({agent})]"
        print(f"   • Pane {pane_id:<6} | Agent: {agent:<8} | Status: {agent_status:<8} | CWD: {cwd}{guard_label}")

    # Recent Audit Log Entries
    print(f"\n📜 Recent SmartGate Audit Events (from SQLite3):")
    try:
        rows = get_recent_audit_logs(limit=5)
        if not rows:
            print("   (No audit events recorded yet)")
        for r in rows:
            symbol = "✅" if r["decision"] in ("AUTO_APPROVED", "ALLOWLIST_BYPASS") else "🚨"
            cmd_preview = (r["raw_command"][:60] + "...") if len(r["raw_command"]) > 60 else r["raw_command"]
            print(f"   {symbol} [{r['timestamp'][:19]}] #{r['id']} {r['pane_id']} - {r['decision']} [Layer: {r['decision_layer']}] ({r['safety_reason']})")
            print(f"      Cmd: {cmd_preview}")
    except Exception as e:
        print(f"   (Failed to read audit logs: {e})")
    print("=" * 70)


def stop_running_guard(target=None):
    """Stop running guard process for a specific target, or all guards if target is 'all' or None."""
    active_daemons = list_active_guard_locks()
    if not active_daemons:
        print("ℹ️  No running SmartGate / Herdr Schengen process found.")
        return

    targets_to_stop = []
    if target and target not in ("all", "*"):
        norm_target = sanitize_target_name(target)
        for tgt, lpath, dpid in active_daemons:
            if tgt == norm_target or (target == "auto" and tgt in ("auto", "legacy_global")):
                targets_to_stop.append((tgt, lpath, dpid))
        if not targets_to_stop:
            print(f"ℹ️  No running Schengen daemon found for target '{target}'.")
            return
    else:
        targets_to_stop = active_daemons

    for tgt, lpath, dpid in targets_to_stop:
        try:
            os.kill(dpid, signal.SIGTERM)
            print(f"🛑 Terminated SmartGate daemon for target '{tgt}' (PID: {dpid}).")
            lpath.unlink(missing_ok=True)
        except ProcessLookupError:
            print(f"ℹ️  Daemon for '{tgt}' (PID: {dpid}) was already terminated. Removing stale lock.")
            lpath.unlink(missing_ok=True)
        except Exception as e:
            print(f"❌ Failed to stop daemon for '{tgt}' (PID: {dpid}): {e}")


def reload_running_guard(target=None):
    """Send SIGHUP signal to trigger graceful in-process module reloading without killing the daemon."""
    active_daemons = list_active_guard_locks()
    if not active_daemons:
        print("ℹ️  No running SmartGate / Herdr Schengen daemon found to reload.")
        return

    targets_to_reload = []
    if target and target not in ("all", "*"):
        norm_target = sanitize_target_name(target)
        for tgt, lpath, dpid in active_daemons:
            if tgt == norm_target or (target == "auto" and tgt in ("auto", "legacy_global")):
                targets_to_reload.append((tgt, lpath, dpid))
        if not targets_to_reload:
            print(f"ℹ️  No running Schengen daemon found for target '{target}'.")
            return
    else:
        targets_to_reload = active_daemons

    for tgt, lpath, dpid in targets_to_reload:
        try:
            os.kill(dpid, signal.SIGHUP)
            print(f"🔄 Sent SIGHUP dynamic reload signal to daemon '{tgt}' (PID: {dpid}). Modules will reload instantly.")
        except Exception as e:
            print(f"❌ Failed to signal reload for '{tgt}' (PID: {dpid}): {e}")


def handle_sighup(signum, frame):
    """Signal handler for SIGHUP: sets flag to trigger dynamic in-process reload on next iteration."""
    global _RELOAD_REQUESTED
    _RELOAD_REQUESTED = True


def find_git_repo_and_rel_path(mod_path: Path):
    """Find git repository and relative path for module file, checking parent directory tree and SSOT repo."""
    parent_dir = mod_path.parent
    try:
        res = subprocess.run(
            ["git", "-C", str(parent_dir), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, check=False, timeout=1.0
        )
        if res.returncode == 0 and res.stdout.strip() == "true":
            rel_res = subprocess.run(
                ["git", "-C", str(parent_dir), "ls-files", "--full-name", str(mod_path)],
                capture_output=True, text=True, check=False, timeout=1.0
            )
            rel_path = rel_res.stdout.strip()
            if rel_path:
                return parent_dir, rel_path
    except Exception:
        pass

    # Fallback to SSOT repository at ~/code/herdr-schengen
    ssot_repo = Path.home() / "code" / "herdr-schengen"
    if (ssot_repo / ".git").exists():
        rel_candidate = f"scripts/{mod_path.name}"
        try:
            rel_res = subprocess.run(
                ["git", "-C", str(ssot_repo), "ls-files", "--error-unmatch", rel_candidate],
                capture_output=True, text=True, check=False, timeout=1.0
            )
            if rel_res.returncode == 0 and rel_res.stdout.strip():
                return ssot_repo, rel_candidate
        except Exception:
            pass

    return None, None


def verify_module_integrity(module_obj) -> bool:
    """Verify that Python source file exists, parses to valid AST, is tracked by Git, and matches committed Git HEAD blob hash."""
    try:
        mod_file = getattr(module_obj, "__file__", None)
        if not mod_file:
            return False
        mod_path = Path(mod_file).resolve()
        if mod_path.suffix == ".pyc":
            mod_path = mod_path.with_suffix(".py")
        if not mod_path.is_file():
            return False
        content = mod_path.read_text(encoding="utf-8")
        if not content.strip():
            return False
        
        # 1. Syntax check
        ast.parse(content)

        # 2. Cryptographic SCM Git Blob Verification against committed HEAD
        repo_dir, rel_path = find_git_repo_and_rel_path(mod_path)
        if not repo_dir or not rel_path:
            return False

        head_blob_res = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", f"HEAD:{rel_path}"],
            capture_output=True, text=True, check=False, timeout=1.0
        )
        if head_blob_res.returncode != 0:
            return False
        head_blob_hash = head_blob_res.stdout.strip()

        file_blob_res = subprocess.run(
            ["git", "-C", str(repo_dir), "hash-object", str(mod_path)],
            capture_output=True, text=True, check=False, timeout=1.0
        )
        if file_blob_res.returncode != 0:
            return False
        file_blob_hash = file_blob_res.stdout.strip()

        # If file has uncommitted tampering / does not match HEAD blob, reject reload
        if head_blob_hash != file_blob_hash:
            return False

        return True
    except Exception:
        return False


def execute_graceful_reload():
    """Dynamically reload evaluator modules and rulesets in-place with AST integrity verification."""
    global gray_zone_evaluator, security_evaluator
    global audit_shell_command, audit_shell_command_with_taxonomy, derive_taxonomy, audit_python_code, sanitize_output, DecisionLayer
    try:
        # Pre-reload AST integrity verification
        for mod in (guard_db, gray_zone_evaluator, security_evaluator):
            if not verify_module_integrity(mod):
                print(f"🛑 [GRACEFUL_RELOAD_ABORTED] Module integrity/AST verification failed for {getattr(mod, '__name__', str(mod))}. Rejecting reload.", flush=True)
                return False

        importlib.reload(guard_db)
        importlib.reload(gray_zone_evaluator)
        importlib.reload(security_evaluator)
        from security_evaluator import (
            audit_shell_command as _asc,
            audit_shell_command_with_taxonomy as _asct,
            derive_taxonomy as _dt,
            audit_python_code as _apc,
            sanitize_output as _so,
            DecisionLayer as _dl
        )
        audit_shell_command = _asc
        audit_shell_command_with_taxonomy = _asct
        derive_taxonomy = _dt
        audit_python_code = _apc
        sanitize_output = _so
        DecisionLayer = _dl
        print(f"✨ [GRACEFUL_RELOAD] Successfully reloaded guard modules and rulesets in-process at {datetime.now(timezone.utc).isoformat()}.", flush=True)
        return True
    except Exception as e:
        print(f"⚠️  [GRACEFUL_RELOAD_ERROR] Failed to reload modules: {e}", flush=True)
        return False


def verify_agy_runtime_environment():
    """Ensure Schengen watcher is executing strictly within an Antigravity agent runtime."""
    is_agy = (
        os.environ.get("ANTIGRAVITY_AGENT") == "1"
        or os.environ.get("AI_AGENT") == "antigravity"
        or bool(os.environ.get("ANTIGRAVITY_CONVERSATION_ID"))
    )
    if not is_agy:
        sys.stderr.write(
            "❌ [SCHENGEN_FATAL] Execution rejected: Herdr Schengen (SmartGate) must run exclusively\n"
            "   within an active Antigravity (AGY) agent session (ANTIGRAVITY_AGENT=1 or AI_AGENT=antigravity).\n"
            "   Standalone terminal execution or detached background daemons are forbidden by ADR-003 governance.\n"
        )
        sys.exit(1)


def is_parent_alive(initial_ppid: int) -> bool:
    """Check if the parent process or Herdr multiplexer environment is still alive."""
    if initial_ppid > 1:
        try:
            os.kill(initial_ppid, 0)
            return True
        except (ProcessLookupError, OSError):
            pass
    # Fallback: verify Herdr environment is responsive
    try:
        res = subprocess.run(["herdr", "pane", "list"], capture_output=True, timeout=5)
        return res.returncode == 0
    except Exception:
        return False


AGENT_FILTER_ALL = "all"


def parse_agent_filter(raw: str):
    """Normalize --agent-filter into a frozenset of agent kinds.

    Accepts a comma-separated list (e.g. 'agy,opencode') or the 'all' sentinel.
    'all' expands to the registered target agent kinds; it does NOT match
    non-target agents (hermes, bare shells, human). Empty input falls back to
    the default {'agy'}.
    """
    raw = (raw or "").strip()
    if raw.lower() == AGENT_FILTER_ALL:
        return frozenset(target_agent_kinds())
    kinds = frozenset(k.strip() for k in raw.split(",") if k.strip())
    return kinds or frozenset({"agy"})


def agent_matches(agent_kind: str, agent_filter) -> bool:
    """Return True if agent_kind passes the parsed agent filter.

    agent_filter is expected to be a frozenset of agent kinds (from
    parse_agent_filter). A bare string is treated as a single agent kind for
    backward compatibility; None matches nothing (safe default, never match-all).
    """
    if isinstance(agent_filter, str):
        return agent_kind == agent_filter
    if agent_filter is None:
        return False
    return agent_kind in agent_filter


def escalate_request(pane_id, pane_info, req_cmd, safety_reason, decision_layer, agent_kind):
    """Enqueue a persistent escalation and emit intercept notifications. Returns escalation id."""
    session_uuid = pane_info.get("agent_session", {}).get("value") if isinstance(pane_info.get("agent_session"), dict) else None
    esc_id = enqueue_pending_escalation(
        pane_id=pane_id,
        raw_command=req_cmd,
        safety_reason=safety_reason,
        decision_layer=decision_layer,
        agent_kind=agent_kind,
        session_id=session_uuid,
    )
    print(f"🚨 [BORDER_CONTROL_INTERCEPT] Pre-execution HALTED for safety. Escalating to AGY / Human Review (Escalation #{esc_id}, Session: {session_uuid or 'unknown'}).", flush=True)
    print(f"   • Pane: {pane_id} ({agent_kind})", flush=True)
    print(f"   • Layer: {decision_layer}", flush=True)
    print(f"   • Reason: {safety_reason}", flush=True)
    print(f"   • Intercepted Command:\n     {req_cmd}", flush=True)
    # Herdr notification popup
    run_cmd(["herdr", "notification", "show", "SmartGate Alert", "--body", f"Manual approval required on {pane_id} [Layer: {decision_layer}]: {safety_reason}", "--sound", "request"])
    return esc_id


def find_blocked_panes(agent_filter=frozenset(), exclude_panes=None):
    """Find panes currently waiting on approval, strictly filtered by agent type and excluding excluded panes."""
    if exclude_panes is None:
        exclude_panes = set()
    else:
        exclude_panes = set(exclude_panes)

    blocked = []
    for pane in get_all_panes():
        pane_id = pane.get("pane_id", "")
        if pane_id in exclude_panes:
            continue

        agent_kind = pane.get("agent", "")
        if not agent_matches(agent_kind, agent_filter):
            continue

        status = pane.get("agent_status", "")
        if status == "blocked":
            blocked.append(pane_id)
        else:
            adapter = get_adapter(agent_kind)
            text = get_pane_text(pane_id, lines=50)
            if adapter and any(p in text for p in adapter.blocked_markers):
                blocked.append(pane_id)
    return list(set(blocked))


def main():
    global _RELOAD_REQUESTED
    parser = argparse.ArgumentParser(description="Herdr SmartGate / Schengen Trusted Clearance Watcher (AGY Exclusive)")
    parser.add_argument("--target", default="auto", help="Target pane ID (e.g. wP:p2) or 'auto' (default: auto - monitors all active & future panes)")
    parser.add_argument("--agent-filter", default="agy", help="Target agent filter, comma-separated (e.g. 'agy,opencode') or 'all' (default: agy only)")
    parser.add_argument("--exclude-pane", action="append", default=[], help="Pane ID to exclude from auto-approval")
    parser.add_argument("--interval", type=int, default=3, help="Polling interval in seconds (default: 3)")
    parser.add_argument("--auto-exit", action="store_true", default=False, help="Automatically exit after idle timeout (default: False, runs continuously)")
    parser.add_argument("--dry-run", action="store_true", help="Log decisions without injecting keys")
    parser.add_argument("--recent", "-n", type=int, nargs="?", const=10, default=None, help="Display recent audit logs (default: 10)")
    parser.add_argument("--search", "-s", type=str, help="Search audit logs by keyword")
    parser.add_argument("--tail", "-t", type=int, nargs="?", const=20, default=None, help="Tail schengen.log file (default: 20 lines)")
    parser.add_argument("--paths", "--find-state", action="store_true", help="Print SmartGate state file paths")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format for agent parsing")
    parser.add_argument("--stats", action="store_true", help="Display pattern analysis stats from DB and exit")
    parser.add_argument("--status", action="store_true", help="Display status of SmartGate daemon and monitored panes")
    parser.add_argument("--use-gpt-oss", action="store_true", default=False, help="Enable private GPT-OSS 120B semantic judge")
    parser.add_argument("--reasoning", choices=["off", "low", "medium", "high"], default=DEFAULT_REASONING_EFFORT, help="Reasoning effort for guard watcher (default: low)")
    parser.add_argument("--stop", action="store_true", help="Stop running guard process for target (or all) and exit")
    parser.add_argument("--reload", action="store_true", help="Gracefully reload modules/rulesets on running guard without restarting process")
    args = parser.parse_args()

    if args.stop:
        stop_running_guard(target=args.target if args.target != "auto" else None)
        return

    if args.reload:
        reload_running_guard(target=args.target if args.target != "auto" else None)
        return

    if args.status:
        show_guard_status()
        return

    init_db()

    if args.paths:
        paths = get_state_file_paths()
        paths["scoped_lock_file"] = str(get_lock_file_path(args.target))
        if args.json:
            print(json.dumps(paths, indent=2))
        else:
            print("🗂️  SmartGate / Herdr Schengen State Paths:")
            for k, v in paths.items():
                print(f"  • {k:<18}: {v}")
        return

    if args.tail is not None:
        log_lines = tail_state_log(args.tail)
        if args.json:
            print(json.dumps({"lines": log_lines}, indent=2))
        else:
            print(f"📜 Last {len(log_lines)} lines of schengen.log:")
            print("".join(log_lines), end="")
        return

    if args.search:
        results = search_audit_logs(args.search)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(f"🔍 Search results for '{args.search}' ({len(results)} found):")
            for r in results:
                symbol = "✅" if r["decision"] in ("AUTO_APPROVED", "ALLOWLIST_BYPASS") else "🚨"
                print(f"{symbol} [{r['timestamp'][:19]}] #{r['id']} {r['pane_id']} - {r['decision']} [Layer: {r['decision_layer']}] ({r['safety_reason']})")
                print(f"   Cmd: {r['raw_command']}")
        return

    if args.recent is not None:
        limit = args.recent
        logs = get_recent_audit_logs(limit=limit)
        if args.json:
            print(json.dumps(logs, indent=2))
        else:
            print(f"📜 Recent SmartGate Audit Events (Limit: {limit}):")
            print("=" * 90)
            if not logs:
                print("   (No audit events found)")
            for r in logs:
                symbol = "✅" if r["decision"] in ("AUTO_APPROVED", "ALLOWLIST_BYPASS") else "🚨"
                cmd_prev = (r["raw_command"][:70] + "...") if len(r["raw_command"]) > 70 else r["raw_command"]
                print(f"{symbol} [{r['timestamp'][:19]}] #{r['id']:<3} {r['pane_id']:<6} | {r['decision']:<16} | Layer: {r['decision_layer']:<16}")
                print(f"   Reason: {r['safety_reason']}")
                print(f"   Cmd   : {cmd_prev}")
                print("-" * 90)
        return

    if args.stats:
        stats = get_pattern_analysis()
        print("\n📊 Herdr SmartGate / Schengen - Pattern Analysis & Review Board")
        print("=" * 80)
        if not stats:
            print("No command patterns recorded yet in DB.")
        for row in stats:
            print(f"• Frequency: {row['total_occurrences']} (Approved: {row['auto_approved_count']}, Delegated: {row['delegated_count']})")
            print(f"  Pattern: {row['pattern']}")
            print(f"  Last Seen: {row['last_seen']}")
            print("-" * 80)
        return

    # Strictly verify AGY runtime environment (ADR-003 mandate)
    verify_agy_runtime_environment()

    # Normalize the target agent filter into a set (None = match all).
    agent_filter_set = parse_agent_filter(args.agent_filter)

    # Track parent PID for orphan prevention
    initial_ppid = os.getppid()

    # Register SIGHUP for graceful dynamic in-process reload
    signal.signal(signal.SIGHUP, handle_sighup)

    # Acquire scoped singleton lock
    lock_fd, lock_file_path = acquire_scoped_lock(args.target)

    # Auto-detect self pane for strict exclusion (prevents self-recursive approval)
    self_pane = detect_self_pane_id()
    excluded = set(args.exclude_pane)
    if self_pane:
        excluded.add(self_pane)
    print(f"🛡️  SmartGate / Herdr Schengen started (PID: {os.getpid()}, PPID: {initial_ppid}, target={args.target}, agent_filter={args.agent_filter}, self_pane={self_pane or 'None'}, excluded={list(excluded)}, interval={args.interval}s, reasoning={args.reasoning}, lock={lock_file_path.name})", flush=True)

    last_processed_prompt = {}
    idle_count = 0

    try:
        while True:
            # Check for dynamic reload trigger (SIGHUP)
            if _RELOAD_REQUESTED:
                _RELOAD_REQUESTED = False
                execute_graceful_reload()

            # P1 Guard against orphan process: verify parent AGY session is alive
            if not is_parent_alive(initial_ppid):
                print(f"🛑 [SCHENGEN_LIFECYCLE] Parent AGY session (PID {initial_ppid}) terminated. Exiting SmartGate watcher to prevent orphan auto-approval.", flush=True)
                break

            target_panes = []
            all_p = get_all_panes()

            if args.target == "auto":
                target_panes = find_blocked_panes(agent_filter=agent_filter_set, exclude_panes=excluded)
                if not target_panes:
                    active = [p["pane_id"] for p in all_p if agent_matches(p.get("agent"), agent_filter_set) and p["pane_id"] not in excluded]
                    target_panes = active
            else:
                if args.target in excluded:
                    target_panes = []
                else:
                    pane_info = get_pane_info(args.target)
                    if pane_info:
                        agent_kind = pane_info.get("agent", "")
                        if not agent_matches(agent_kind, agent_filter_set):
                            target_panes = []
                        else:
                            target_panes = [args.target]
                    else:
                        target_panes = [args.target]

            if not target_panes:
                idle_count += 1
                if args.auto_exit and idle_count > 10:
                    print("🏁 No active target AGY agent found. SmartGate exiting gracefully.", flush=True)
                    break
                time.sleep(args.interval)
                continue

            idle_count = 0

            for pane_id in target_panes:
                pane_info = get_pane_info(pane_id)
                if not pane_info:
                    continue

                agent_kind = pane_info.get("agent", "unknown")
                if not agent_matches(agent_kind, agent_filter_set):
                    continue

                adapter = get_adapter(agent_kind)
                if adapter is None:
                    continue

                state_seq = pane_info.get("state_change_seq", 0)
                agent_status = pane_info.get("agent_status", "")

                visible_text = get_pane_text(pane_id, lines=80)
                req_cmd = adapter.parse_permission_request(visible_text)

                if not req_cmd:
                    # Prompt is no longer active; reset last_processed_prompt for this pane
                    if pane_id in last_processed_prompt:
                        resolve_escalation(pane_id=pane_id)
                        last_processed_prompt.pop(pane_id, None)
                    continue

                cached = last_processed_prompt.get(pane_id)
                now = time.time()

                # If same command is pending review on this pane in the EXACT same turn state
                if cached and cached.get("cmd") == req_cmd and cached.get("seq") == state_seq and cached.get("status") == agent_status:
                    if not cached.get("is_safe", True):
                        if now - cached.get("last_alert_time", 0) > 30.0:
                            cached["last_alert_time"] = now
                            print(f"⏳ [ESCALATION_REMINDER] Pane {pane_id} ({agent_kind}) is STILL waiting for approval: {req_cmd[:70]}", flush=True)
                    continue

                print(f"\n🔍 [Target: {pane_id} ({agent_kind})] Detected Script/Command Pre-Approval Request:\n----------------------------------------\n{req_cmd}\n----------------------------------------", flush=True)

                target_cwd = pane_info.get("foreground_cwd") or pane_info.get("cwd") or os.getcwd()

                # 1. Check user persisted allowlist
                is_whitelisted, wl_reason = check_persisted_allowlist(req_cmd)
                if is_whitelisted:
                    is_safe = True
                    reason = wl_reason
                    decision = "ALLOWLIST_BYPASS"
                    layer = DecisionLayer.ALLOWLIST
                    tax = derive_taxonomy(req_cmd, layer, is_safe, reason, origin=Origin.HUMAN)
                else:
                    is_safe, reason, layer, tax = audit_shell_command_with_taxonomy(
                        req_cmd,
                        use_llm_judge=args.use_gpt_oss,
                        reasoning_effort=args.reasoning,
                        origin=Origin.AGENT if agent_kind != "human" else Origin.HUMAN,
                        cwd=target_cwd,
                        scope=pane_id,
                        agent_id=agent_kind
                    )
                    if tax.get("counterfactual_block"):
                        decision = "SHADOW_BLOCKED"
                    else:
                        decision = "AUTO_APPROVED" if is_safe else "MANUAL_DELEGATED"

                state_tag = f"[{tax.get('gate_state', 'ENFORCE')}]"
                print(f"⚖️  Safety Evaluation {state_tag}: {'✅ SAFE' if is_safe else '🚨 DANGEROUS / REVIEW NEEDED'} ({reason}) [Decision: {decision}, Layer: {layer}, Origin: {tax.get('origin')}, Conseq: {tax.get('consequence')}]", flush=True)

                # 2. Record to SQLite3 DB
                record_audit_log(
                    pane_id=pane_id,
                    raw_command=req_cmd,
                    decision=decision,
                    safety_reason=reason,
                    agent_kind=agent_kind,
                    decision_layer=layer,
                    origin=tax.get("origin", "A"),
                    consequence=tax.get("consequence", "NONE"),
                    mechanism=tax.get("mechanism", "none"),
                    gate_state=tax.get("gate_state", "ENFORCE"),
                    shadow_mode=tax.get("shadow_mode", False),
                )

                # 3. Action
                if is_safe:
                    if not args.dry_run:
                        # P0 TOCTOU Guard: Re-read pane immediately before sending enter to ensure prompt has not changed
                        current_text = get_pane_text(pane_id, lines=80)
                        current_req = adapter.parse_permission_request(current_text)
                        if current_req != req_cmd:
                            print(f"⚠️  [TOCTOU_ABORT] Pane {pane_id} prompt modified during safety evaluation. Aborting key injection.", flush=True)
                            continue

                        approved, inject_reason = adapter.inject_approval(pane_id, req_cmd)
                        if not approved:
                            print(f"🚨 [{agent_kind}] {inject_reason} on {pane_id}", flush=True)
                            # 'OPENCODE_FAILSAFE' is a watcher-level escalation marker, deliberately
                            # outside the command-classification DecisionLayer enum.
                            escalate_request(pane_id, pane_info, req_cmd, inject_reason, "OPENCODE_FAILSAFE", agent_kind)
                            last_processed_prompt[pane_id] = {
                                "cmd": req_cmd,
                                "seq": state_seq,
                                "status": agent_status,
                                "is_safe": False,
                                "last_alert_time": now
                            }
                            continue
                    else:
                        print(f"🧪 [Dry-Run] Would send Enter to {pane_id}", flush=True)
                    last_processed_prompt[pane_id] = {
                        "cmd": req_cmd,
                        "seq": state_seq,
                        "status": agent_status,
                        "is_safe": True,
                        "last_alert_time": now
                    }
                    resolve_escalation(pane_id=pane_id)
                else:
                    # Enqueue persistent escalation into SQLite3 (At-least-once guarantee)
                    escalate_request(pane_id, pane_info, req_cmd, reason, layer, agent_kind)
                    last_processed_prompt[pane_id] = {
                        "cmd": req_cmd,
                        "seq": state_seq,
                        "status": agent_status,
                        "is_safe": False,
                        "last_alert_time": now
                    }

            time.sleep(args.interval)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()
            if lock_file_path.exists():
                lock_file_path.unlink()
        except Exception:
            pass


if __name__ == "__main__":
    main()
