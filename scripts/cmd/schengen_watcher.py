#!/usr/bin/env python3
"""Herdr Schengen / SmartGate Trusted Clearance Watcher Daemon.

Monitors Herdr pane(s) at configurable intervals, performs AST static
analysis and security evaluation on requested commands/scripts, logs every
event into SQLite3 database (~/.local/state/herdr-schengen/schengen_history.db),
and auto-approves safe commands (SmartGate flow) while delegating risky commands to human review.

Key Architecture:
- MULTI-AGENT TARGET SCOPE: Auto-approves all registered target agent kinds (agy, opencode) while excluding Hermes, bare shells, and the caller pane.
- CONTINUOUS DISCOVERY: Dynamically polls all active and newly added Herdr panes in real-time.
- STRICT SINGLETON FILELOCK (fcntl.flock): Prevents race conditions & duplicate key injection.
- DAEMON & STATUS MANAGEMENT: Built-in --daemon, --status, and --stop lifecycle management.
- FAST 1ms AST + PRIVATELY HOSTED 120B LOW REASONING: Zero Google One quota consumption.
"""

import argparse
import ast
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Add script directory to sys.path for local imports
SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parent
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import importlib

import core.gray_zone_evaluator as gray_zone_evaluator
import core.guard_db as guard_db
import core.security_evaluator as security_evaluator
from adapters.agent_adapters import INJECT_SKIP_CHANGED, canonical_request, get_adapter, target_agent_kinds
from core.cloud_judge import DEFAULT_REASONING_EFFORT
from core.redaction import redact_for_cloud
from core.guard_db import (
    DB_DIR,
    IN_FLIGHT_STATE_PATH,
    IN_FLIGHT_TTL,
    LOG_DIR,
    check_persisted_allowlist,
    enqueue_pending_escalation,
    get_pattern_analysis,
    get_pane_direct_config,
    get_pending_escalations,
    get_recent_audit_logs,
    get_state_file_paths,
    init_db,
    record_audit_log,
    resolve_escalation,
    search_audit_logs,
    tail_state_log,
)
from adapters.herdr_client import (
    detect_self_pane_id,
    get_all_panes,
    get_pane_info,
    get_pane_text,
    run_cmd,
)
from core.security_evaluator import (
    DecisionLayer,
    Origin,
    audit_shell_command_with_taxonomy,
    derive_taxonomy,
)

LOCK_FILE = DB_DIR / "schengen.lock"
LOG_FILE = LOG_DIR / "schengen.log"
WATCHER_CONFIG_PATH = SCRIPTS_ROOT.parent / "config" / "schengen_watcher.json"
WATCHER_DEFAULTS = {"max_workers": 10, "interval_seconds": 3, "auto_exit_idle_cycles": 10}
WATCHER_LIMITS = {"max_workers": (1, 10), "interval_seconds": (1, 3600), "auto_exit_idle_cycles": (1, 10000)}

# Global reload trigger flag
_RELOAD_REQUESTED = False

# Pane-direct PD-C debounce counter: consecutive not-live polls per pane_id.
# Module-scope so the pure decision helper and the poll loop share one counter.
_not_live_streak: dict[str, int] = {}

# QUESTION residual sweep (issue #2800): consecutive not-live question reads per
# pane_id. A QUESTION escalation whose dialog cleared (user answered in the
# pane) is resolved ANSWERED after pane_direct_confirm_polls consecutive
# not-live reads; a live question read resets the counter.
_question_not_live_streak: dict[str, int] = {}

# Host binary dirs that may be missing from the daemon's inherited PATH (e.g.
# launched from a bare shell) but are required for SAST tools (shellcheck /
# semgrep) to be discoverable. Issue #45: without them shutil.which() returns
# None -> SAST degraded -> fail-closed escalates every non-allowlist command.
#
# Declared in HIGHEST-PRIORITY-FIRST order: _inject_runtime_path() iterates in
# reverse so the FIRST tuple entry ends up FIRST in the resulting PATH.
if sys.platform.startswith("linux"):
    # Linuxbrew (Homebrew on Linux) installs to /home/linuxbrew/.linuxbrew/bin.
    _RUNTIME_BIN_DIRS = ("/home/linuxbrew/.linuxbrew/bin", "/usr/local/bin", os.path.expanduser("~/.local/bin"))
else:
    # macOS: Apple Silicon Homebrew (/opt/homebrew/bin) > Intel (/usr/local/bin)
    # > user-local binaries. (Issue #45: identical to the pre-guard macOS set.)
    _RUNTIME_BIN_DIRS = ("/opt/homebrew/bin", "/usr/local/bin", os.path.expanduser("~/.local/bin"))


def load_watcher_config(path=WATCHER_CONFIG_PATH):
    """Load watcher tunables; malformed or missing config fails safely to defaults."""
    try:
        with Path(path).open(encoding="utf-8") as handle:
            loaded = json.load(handle)
        if not isinstance(loaded, dict):
            raise ValueError("top-level value must be an object")
    except (OSError, ValueError, json.JSONDecodeError):
        return dict(WATCHER_DEFAULTS)
    config = dict(WATCHER_DEFAULTS)
    for key, default in WATCHER_DEFAULTS.items():
        value = loaded.get(key, default)
        low, high = WATCHER_LIMITS[key]
        if type(value) is int and low <= value <= high:
            config[key] = value
    return config


class InspectorCoordinator:
    """Bounded silent inspection with per-pane in-flight ownership.

    Evaluations run concurrently; pane polling and all UI/key actions remain on
    the watcher thread. Evaluator-owned shared caches must synchronize their
    own access.
    """

    def __init__(self, max_workers=10):
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="schengen-inspector")
        self.in_flight = {}
        self.owned = {}
        self.human_queue = deque()
        self.active_human = None

    def submit(self, pane_id, request, evaluate):
        if pane_id in self.owned:  # INV-CONC-1: ownership survives completion
            return False
        self.owned[pane_id] = (request, "in_flight")
        # Phase-1 IPC (INV-PH1-6): phase_box starts at "inspector"; the worker
        # thread's phase hook flips it to "gatekeeper" only around LLM calls.
        phase_box = {"phase": "inspector", "ts": time.time()}
        self.in_flight[pane_id] = (request, phase_box, self.executor.submit(self._evaluate, evaluate, phase_box))
        return True

    def _evaluate(self, evaluate, phase_box):
        security_evaluator.set_phase_hook(lambda p: phase_box.update(phase=p))
        try:
            return evaluate()
        finally:
            security_evaluator.set_phase_hook(None)

    def completed(self):
        for pane_id, (request, _phase_box, future) in list(self.in_flight.items()):
            if not future.done():
                continue
            del self.in_flight[pane_id]
            try:
                yield pane_id, request, future.result()
            except Exception as exc:
                yield pane_id, request, (False, f"Inspector failed closed: {exc}", DecisionLayer.SHELL_CRITICAL, {})

    def set_state(self, pane_id, request, state):
        if self.owned.get(pane_id, (None,))[0] == request:
            self.owned[pane_id] = (request, state)

    def release(self, pane_id, request=None):
        owned = self.owned.get(pane_id)
        if owned and (request is None or owned[0] == request):
            self.owned.pop(pane_id, None)

    def evict_stale_human_requests(self, is_live):
        """Drop stale active/queued requests and return the cancelled active slot."""
        cancelled = None
        if self.active_human and not is_live(*self.active_human):
            cancelled = self.active_human
            self.release(cancelled[0])
            self.active_human = None
        kept = deque()
        while self.human_queue:
            queued = self.human_queue.popleft()
            if is_live(queued[0], queued[2]):
                kept.append(queued)
            else:
                self.release(queued[0])
        self.human_queue = kept
        return cancelled

    def close(self):
        self.executor.shutdown(wait=False, cancel_futures=True)


def sync_in_flight_state(inspector) -> None:
    """Publish the inspector's in-flight state to the shared JSON IPC file.

    Single-writer (the watcher), atomic tmp+os.replace (INV-PH1-3/5). Each
    entry carries the pane, agent kind, a short command fingerprint + preview,
    the started_at timestamp, and the live phase ("inspector" | "gatekeeper").
    Entries older than IN_FLIGHT_TTL are dropped so a stale snapshot can never
    pin a perpetual "Checking" banner (INV-PH1-2). Called AT MOST once per poll
    cycle — never per command.
    """
    now = time.time()
    entries = []
    for pane_id, (request, phase_box, _future) in list(inspector.in_flight.items()):
        try:
            command = request[0] if isinstance(request, (tuple, list)) and request else None
            if not isinstance(command, str) or not command.strip():
                continue  # skip entries whose command can't be derived safely
            pane_info = request[3] if len(request) >= 4 and isinstance(request[3], dict) else {}
            started_at = float(phase_box.get("ts", now))
        except Exception:
            continue  # skip entries that cannot be derived safely
        if now - started_at > IN_FLIGHT_TTL:
            continue
        entries.append({
            "pane_id": str(pane_id),
            "agent_kind": str(pane_info.get("agent", "unknown")),
            "command_fp": hashlib.sha256(command.encode("utf-8")).hexdigest()[:12],
            "command_preview": redact_for_cloud(command[:80]),
            "started_at": started_at,
            "phase": phase_box.get("phase", "inspector"),
        })
    try:
        IN_FLIGHT_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = IN_FLIGHT_STATE_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"ts": now, "entries": entries}, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, IN_FLIGHT_STATE_PATH)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


def cancel_stale_human_escalation(pane_id, command):
    """Persist cancellation for a human slot invalidated by live-pane revalidation."""
    resolve_escalation(
        pane_id=pane_id,
        command_hash=hashlib.sha256(command.encode("utf-8")).hexdigest()[:16],
        resolution_status="CANCELLED",
        approver="other",
    )


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


def is_process_smartgate_watcher(pid: int) -> bool:
    """Verify if a running PID is actually an active schengen_watcher daemon."""
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, OSError):
        return False

    # Deep verification via ps command to prevent false positives from recycled PIDs
    try:
        res = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        if res.returncode == 0 and res.stdout:
            cmd = res.stdout.strip()
            # Must match watcher or python script invocation
            if "schengen_watcher" in cmd or "schengen" in cmd or "python" in cmd:
                return True
            return False
    except Exception:
        # If ps fails, fallback to alive check from os.kill
        return True
    return False


def list_active_guard_locks() -> list:
    """Discover all active guard lockfiles and their running PIDs with stale-lock auto-cleanup."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    active = []

    lock_files = [f for f in DB_DIR.glob("schengen_*.lock") if f.name != "schengen_tui.lock"]
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
            with open(lf) as f:
                content = f.read().strip()
                if content and content.isdigit():
                    cand_pid = int(content)
                    if is_process_smartgate_watcher(cand_pid):
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
    except (OSError, BlockingIOError):
        running_pid = "unknown"
        try:
            with open(lock_file) as f:
                running_pid = f.read().strip()
        except Exception:
            pass
        print(
            f"⚠️  Another SmartGate / Herdr Schengen watcher is already running for target '{target}' (PID: {running_pid}). Exiting."
        )
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
        with open(lock_file) as f:
            pid_str = f.read().strip()
        if pid_str and pid_str.isdigit():
            pid = int(pid_str)
            if is_process_smartgate_watcher(pid):
                return pid
            else:
                try:
                    lock_file.unlink(missing_ok=True)
                except Exception:
                    pass
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
    print("\n📜 Recent SmartGate Audit Events (from SQLite3):")
    try:
        rows = get_recent_audit_logs(limit=5)
        if not rows:
            print("   (No audit events recorded yet)")
        for r in rows:
            symbol = "✅" if r["decision"] in ("AUTO_APPROVED", "ALLOWLIST_BYPASS") else "🚨"
            cmd_preview = (r["raw_command"][:60] + "...") if len(r["raw_command"]) > 60 else r["raw_command"]
            print(
                f"   {symbol} [{r['timestamp'][:19]}] #{r['id']} {r['pane_id']} - {r['decision']} [Layer: {r['decision_layer']}] ({r['safety_reason']})"
            )
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

    for tgt, _lpath, dpid in targets_to_reload:
        try:
            os.kill(dpid, signal.SIGHUP)
            print(
                f"🔄 Sent SIGHUP dynamic reload signal to daemon '{tgt}' (PID: {dpid}). Modules will reload instantly."
            )
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
            capture_output=True,
            text=True,
            check=False,
            timeout=1.0,
        )
        if res.returncode == 0 and res.stdout.strip() == "true":
            rel_res = subprocess.run(
                ["git", "-C", str(parent_dir), "ls-files", "--full-name", str(mod_path)],
                capture_output=True,
                text=True,
                check=False,
                timeout=1.0,
            )
            rel_path = rel_res.stdout.strip()
            if rel_path:
                return parent_dir, rel_path
    except Exception:
        pass

    # Fallback to SSOT repository at ~/code/herdr-schengen
    ssot_repo = Path.home() / "code" / "herdr-schengen"
    if (ssot_repo / ".git").exists():
        # Reconstruct the module's path relative to its "scripts" root so
        # subdirectory modules (core/, tools/, adapters/, cmd/) resolve to the
        # correct SSOT path. The runtime mirror (~/.agents/skills/herdr-schengen)
        # is not a git work tree, so a bare `scripts/{mod_path.name}` misses
        # every module nested below scripts/ (issue #98).
        parts = mod_path.parts
        rel_candidate = f"scripts/{mod_path.name}"
        if "scripts" in parts:
            rel_candidate = "/".join(parts[parts.index("scripts"):])
        try:
            rel_res = subprocess.run(
                ["git", "-C", str(ssot_repo), "ls-files", "--error-unmatch", rel_candidate],
                capture_output=True,
                text=True,
                check=False,
                timeout=1.0,
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
            capture_output=True,
            text=True,
            check=False,
            timeout=1.0,
        )
        if head_blob_res.returncode != 0:
            return False
        head_blob_hash = head_blob_res.stdout.strip()

        file_blob_res = subprocess.run(
            ["git", "-C", str(repo_dir), "hash-object", str(mod_path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=1.0,
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
                print(
                    f"🛑 [GRACEFUL_RELOAD_ABORTED] Module integrity/AST verification failed for {getattr(mod, '__name__', str(mod))}. Rejecting reload.",
                    flush=True,
                )
                return False

        importlib.reload(guard_db)
        importlib.reload(gray_zone_evaluator)
        importlib.reload(security_evaluator)
        from core.security_evaluator import (
            DecisionLayer as _dl,
        )
        from core.security_evaluator import (
            audit_python_code as _apc,
        )
        from core.security_evaluator import (
            audit_shell_command as _asc,
        )
        from core.security_evaluator import (
            audit_shell_command_with_taxonomy as _asct,
        )
        from core.security_evaluator import (
            derive_taxonomy as _dt,
        )
        from core.security_evaluator import (
            sanitize_output as _so,
        )

        audit_shell_command = _asc
        audit_shell_command_with_taxonomy = _asct
        derive_taxonomy = _dt
        audit_python_code = _apc
        sanitize_output = _so
        DecisionLayer = _dl
        print(
            f"✨ [GRACEFUL_RELOAD] Successfully reloaded guard modules and rulesets in-process at {datetime.now(timezone.utc).isoformat()}.",
            flush=True,
        )
        return True
    except Exception as e:
        print(f"⚠️  [GRACEFUL_RELOAD_ERROR] Failed to reload modules: {e}", flush=True)
        return False


def _inject_runtime_path() -> None:
    """Prepend common host binary dirs to PATH so shellcheck/semgrep are discoverable.

    Idempotent: only prepends a dir that EXISTS on disk and is not already in PATH.

    Priority note (issue #45): `_RUNTIME_BIN_DIRS` is declared in
    highest-priority-first order. Because each existing dir is `insert(0, ...)`-ed,
    we iterate in REVERSE so the FIRST tuple entry (/opt/homebrew/bin on macOS)
    ends up FIRST (highest precedence) in the resulting PATH — the previous
    forward iteration left the LAST entry (~/.local/bin) shadowing Homebrew.
    """
    path = os.environ.get("PATH", "")
    # Empty path entries (consecutive colons / leading/trailing colon) are
    # dropped. A literal "." entry is deliberately KEPT: it is not an empty
    # entry but an explicit relative current-directory marker with real PATH
    # semantics (POSIX shell searches the CWD), so removing it would silently
    # change command resolution. (Issue #45: documented, no behavior change.)
    parts = [p for p in path.split(os.pathsep) if p]
    for d in reversed(_RUNTIME_BIN_DIRS):
        if os.path.isdir(d) and d not in parts:
            parts.insert(0, d)
    os.environ["PATH"] = os.pathsep.join(parts)


NON_BLOCKED_STATUSES = ("working", "idle", "done")


def _norm_agent_status(status) -> str:
    """Normalize a Herdr agent status for token comparison (issue #33).

    Herdr pane statuses may differ in casing across versions/adapters (e.g.
    "Working" vs "working", "Blocked" vs "blocked"). Normalizing to lowercase
    (stripped) before comparison ensures a casing difference can never cause a
    stale-escalation eviction miss — or, conversely, an unexpected-casing status
    being treated as non-blocked when it should not be.
    """
    return str(status or "").strip().lower()

# Fail-closed reason when a truncated dialog could not be expanded (INV-EX-3).
TRUNCATED_DIALOG_REASON = "Truncated dialog could not be expanded; requires human review"


def maybe_expand_truncated_dialog(adapter, pane_id, visible_text, req_cmd):
    """Expand a truncated/folded dialog so the AST sees the FULL request (#2099).

    Returns (visible_text, req_cmd, truncated_unrecoverable):
    - on successful expansion: (expanded_text, expanded_req, False) — the caller
      substitutes these into the request tuple and the evaluate closure
      (INV-EX-2: a truncated req_cmd never reaches the AST).
    - on failure (expand returned nothing, still truncated, or the expanded text
      parses no request): (visible_text, req_cmd, True) — the caller evaluates
      fail-closed (INV-EX-3).

    Single bounded attempt per poll — NO retry loop (INV-EX-4). Only invoked
    after the pane-direct liveness / question checks (INV-EX-5).
    """
    if not adapter.is_truncated(visible_text):
        return visible_text, req_cmd, False  # INV-EX-1: nothing truncated
    expanded_text = adapter.expand_dialog(pane_id)
    if expanded_text and not adapter.is_truncated(expanded_text):
        expanded_req = adapter.get_pending_request(pane_id, expanded_text)
        if expanded_req:
            return expanded_text, expanded_req, False
    return visible_text, req_cmd, True


def resolve_cleared_dialog(pane_id: str, cached_clear: Optional[dict]) -> None:
    """Resolve a cleared-dialog cache entry with correct provenance (#2800).

    - UNSAFE entry: the user answered the permission dialog directly in the
      pane -> pane-direct APPROVED.
    - QUESTION entry (cached cmd startswith "question"): the user answered the
      question in the pane -> pane-direct ANSWERED (INV-Q-1: never APPROVED).
    - Safe non-question entry: plain dialog-clear resolution (approver=other).
    """
    if not cached_clear:
        return
    is_q = str(cached_clear.get("cmd", "")).startswith("question")
    if is_q:
        # INV-Q-1: a question is ANSWERED regardless of its safety flag — check
        # is_q FIRST so a future change to the question cache entry's is_safe
        # cannot silently regress a question to APPROVED.
        resolve_escalation(pane_id=pane_id, resolution="ANSWERED", approver="pane-direct")
    elif not cached_clear.get("is_safe", True):
        resolve_escalation(pane_id=pane_id, resolution="APPROVED", approver="pane-direct")
    else:
        resolve_escalation(pane_id=pane_id, approver="other")


def sweep_answered_questions(confirm_polls: int = 2) -> int:
    """Debounced QUESTION residual sweep — resolve questions answered in-pane.

    A QUESTION escalation whose dialog cleared (the user answered it directly
    in the agent pane) must not stay PENDING forever (#2800). Runs once per
    poll cycle, INDEPENDENT of target_panes (a question dialog may sit on a
    pane that find_blocked_panes would skip). Per-pane debounce:
    - agent_status == "blocked" -> skip, reset counter (INV-Q-4).
    - adapter None -> skip (fail-closed, never evict).
    - question_is_live(text) -> reset counter (still live, INV-Q-3).
    - otherwise increment `_question_not_live_streak`; on reaching
      confirm_polls resolve escalation_id as ANSWERED/pane-direct (INV-Q-5).
    Returns the number of escalations resolved this sweep.
    """
    confirm_polls = max(1, int(confirm_polls))
    resolved = 0
    for q_esc in get_pending_escalations():
        if q_esc.get("decision_layer") != "QUESTION":
            continue
        q_pane = q_esc.get("pane_id")
        if not q_pane:
            continue
        try:
            q_info = get_pane_info(q_pane)
        except Exception:
            continue  # fail-closed: unknown status -> keep pending
        if not q_info:
            continue
        if q_info.get("agent_status") == "blocked":
            _question_not_live_streak.pop(q_pane, None)
            continue  # INV-Q-4: blocked -> never evict
        q_adapter = get_adapter(q_info.get("agent", ""))
        if q_adapter is None:
            continue
        try:
            q_text = get_pane_text(q_pane, lines=80)
        except Exception:
            continue  # fail-closed: unknown -> keep pending
        if q_adapter.question_is_live(q_text):
            _question_not_live_streak.pop(q_pane, None)
            continue  # INV-Q-3: still live
        streak = _question_not_live_streak.get(q_pane, 0) + 1
        _question_not_live_streak[q_pane] = streak
        if streak >= confirm_polls:  # INV-Q-5: debounced
            resolve_escalation(
                pane_id=q_pane,
                escalation_id=q_esc.get("id"),
                resolution="ANSWERED",
                approver="pane-direct",
            )
            _question_not_live_streak.pop(q_pane, None)
            resolved += 1
            print(
                f"♻️ [QUESTION-ANSWERED] Pane {q_pane}: question dialog cleared; resolved ANSWERED (escalation #{q_esc.get('id')}).",
                flush=True,
            )
    return resolved


def truncated_evaluate_result():
    """Fail-closed evaluate result for an unexpandable truncated dialog.

    Short-circuits BEFORE check_persisted_allowlist / audit_shell_command_with_
    taxonomy so a partial/truncated command is never AST-evaluated (INV-EX-2/3).
    """
    return False, TRUNCATED_DIALOG_REASON, DecisionLayer.NOT_ALLOWLISTED


def should_evict_pane_direct(cached, pane_info, visible_text, req_cmd, adapter):
    """Returns (evict: bool, reason: str). cached is the last_processed_prompt entry
    or None; pane_info is get_pane_info(); req_cmd is adapter.get_pending_request(...)
    (already computed) or None; adapter is the registered AgentAdapter or None."""
    if not cached or cached.get("is_safe", True):
        return False, "no unsafe escalation"
    if adapter is None:
        return False, "no adapter"
    # INV-PD-CMD (issue #33): this eviction path keys on pane_id alone, but the
    # dialog/liveness state observed below belongs to the CURRENT req_cmd. If a
    # DIFFERENT (not-yet-approved) command's dialog is now live, never evict the
    # cached escalation based on it — fail-closed: keep the cached escalation
    # pending and let the new command escalate fresh on its own.
    cached_cmd = cached.get("cmd")
    if req_cmd and cached_cmd and req_cmd != cached_cmd:
        return False, "command changed"
    dialog_live = adapter.dialog_is_live(visible_text)
    seq_changed = pane_info.get("state_change_seq", 0) != cached.get("seq", -1)
    status = _norm_agent_status(pane_info.get("agent_status", ""))
    cached_status = _norm_agent_status(cached.get("status", ""))
    status_changed = status != cached_status
    if not dialog_live and not req_cmd:
        return True, "dialog gone"           # PD-A
    if cached_status == "blocked" and status in NON_BLOCKED_STATUSES and not dialog_live:
        return True, "agent left blocked"    # PD-B
    if seq_changed and not dialog_live:
        return True, "state changed, dialog not live"  # PD-C (debounced by caller)
    return False, "still live"


def pane_direct_maybe_evict(pane_id, cached, pane_info, visible_text, req_cmd, adapter, confirm_polls=2):
    """Single-poll pane-direct eviction decision INCLUDING the PD-C debounce.

    Pure decision helper (module-scope `_not_live_streak` counter): PD-A (dialog
    gone) and PD-B (agent left blocked) evict immediately; PD-C (state changed +
    dialog not live) requires `confirm_polls` CONSECUTIVE not-live polls so a
    transient dialog redraw never self-approves a stale escalation.

    Returns (evict: bool, reason: str). On a debounced PD-C the caller must keep
    the cached entry untouched and re-poll.
    """
    evict, reason = should_evict_pane_direct(cached, pane_info, visible_text, req_cmd, adapter)
    if not evict:
        _not_live_streak.pop(pane_id, None)
        return False, reason
    if reason == "state changed, dialog not live":
        streak = _not_live_streak.get(pane_id, 0) + 1
        _not_live_streak[pane_id] = streak
        if streak < max(1, int(confirm_polls)):
            return False, f"debounced (not-live poll {streak}/{int(confirm_polls)})"
    _not_live_streak.pop(pane_id, None)
    return True, reason


def _should_evict_stale_escalation(cached: Optional[dict], agent_status: str) -> bool:
    """Backward-compatible predicate wrapper (issue #33), superseded in the poll
    loop by should_evict_pane_direct (the single pane-direct eviction path).

    Old semantics: a cached UNSAFE escalation whose agent was `blocked` at cache
    time is evicted once the agent transitions to a non-blocked state (the user
    answered the dialog directly in the pane). Retained for tests/back-compat.

    Status comparison is case-insensitive (see _norm_agent_status): Herdr
    statuses may differ in casing ("Working" vs "working"), which must never
    cause an eviction miss (issue #33).
    """
    if not cached or cached.get("is_safe", True):
        return False
    if _norm_agent_status(cached.get("status", "")) != "blocked":
        return False
    return _norm_agent_status(agent_status) in NON_BLOCKED_STATUSES


def verify_host_runtime_environment():
    """Ensure the watcher runs within a supported agent runtime (Antigravity or OpenCode) under Herdr.

    ADR-003's session-bound mandate is extended by ADR-008 to permit OpenCode as
    an alternative host. The watcher must never run detached/orphaned, and must
    run under the Herdr multiplexer (HERDR_ENV=1) — it is meaningless without it.
    """
    # Issue #45: make SAST tools (shellcheck/semgrep) discoverable before the
    # evaluator probes them, so the daemon does not run SAST-degraded merely
    # because /opt/homebrew/bin etc. are absent from the inherited PATH.
    _inject_runtime_path()

    is_host = (
        os.environ.get("ANTIGRAVITY_AGENT") == "1"
        or os.environ.get("AI_AGENT") == "antigravity"
        or bool(os.environ.get("ANTIGRAVITY_CONVERSATION_ID"))
        or os.environ.get("OPENCODE") == "1"
    )
    # DECISION (ADR-008): HERDR_ENV=1 is REQUIRED. This daemon is a Herdr-pane
    # watcher — it reads pane text (`herdr pane read`) and injects keystrokes
    # (`herdr agent send-keys`), both Herdr-specific. A headless `opencode serve`
    # has no panes, so it is intentionally OUT OF SCOPE here; guarding it would
    # require a separate SDK-level `permission.ask` hook integration, not this
    # pane watcher. If headless support is ever wanted, revisit this guard (and
    # the OpenCode plugin) rather than weakening it.
    in_herdr = os.environ.get("HERDR_ENV") == "1"
    if not is_host or not in_herdr:
        sys.stderr.write(
            "❌ [SCHENGEN_FATAL] Execution rejected: Herdr Schengen (SmartGate) must run\n"
            "   within an active agent session under the Herdr multiplexer\n"
            "   (Antigravity: ANTIGRAVITY_AGENT=1 / AI_AGENT=antigravity; OpenCode: OPENCODE=1;\n"
            "   Herdr: HERDR_ENV=1).\n"
            "   Standalone terminal execution or detached background daemons are forbidden (ADR-003 / ADR-008).\n"
        )
        sys.exit(1)

    # SAST availability telemetry — printed ONLY after the host-runtime gate
    # passes, so a rejected/non-Herdr invocation does not emit a misleading
    # "SAST READY" line before the fatal exit (issue #45).
    #
    # DECISION (INV-2 fail-closed, TODO_phase3 "[Task/Dependency]"): semgrep is a
    # DECLARED required dependency (pyproject.toml `semgrep>=1.70.0`) and the
    # SAST pre-filter core. A missing semgrep hard-fails startup with an
    # actionable install guide — degraded SAST must not silently auto-allow.
    # shellcheck keeps the pre-existing DEGRADED warning (non-fatal), matching
    # its legacy evaluator fallback path and test-skip behavior.
    if shutil.which("semgrep") is None:
        sys.stderr.write(
            "❌ [SCHENGEN_FATAL] Required SAST dependency 'semgrep' not found on PATH.\n"
            "   semgrep is a declared required dependency of herdr-schengen (SAST pre-filter core).\n"
            "   Install it, then restart the daemon from the TUI (Ctrl+T):\n"
            "     - Python venv : ~/.local/share/herdr-schengen-tui-venv/bin/pip install 'semgrep>=1.70.0'\n"
            "     - Homebrew    : brew install semgrep\n"
            "   Refusing to start: degraded SAST must not silently auto-allow (INV-2 fail-closed).\n"
        )
        sys.exit(1)
    if shutil.which("shellcheck") is None:
        print("⚠️  [SAST] DEGRADED — missing binary: shellcheck", flush=True)
    else:
        print("✅ [SAST] READY (shellcheck + semgrep)", flush=True)


# Backward-compatible alias (pre-opencode-host naming)
verify_agy_runtime_environment = verify_host_runtime_environment


def is_parent_alive(initial_ppid: int) -> bool:
    """Check if the parent process or Herdr multiplexer environment is still alive."""
    if initial_ppid > 1:
        try:
            os.kill(initial_ppid, 0)
            return True
        except (ProcessLookupError, OSError):
            pass
    # Strict die-with-parent (OpenCode host, ADR-008): no Herdr fallback — the
    # daemon must exit when its parent process dies, regardless of Herdr.
    if os.environ.get("SCHENGEN_STRICT_PARENT") == "1":
        return False
    # Fallback: verify Herdr environment is responsive
    try:
        res = subprocess.run(["herdr", "pane", "list"], capture_output=True, timeout=5)
        return res.returncode == 0
    except Exception:
        return False


def agent_matches(agent_kind: str, agent_filter) -> bool:
    """Return True if agent_kind passes the agent filter.

    agent_filter is a frozenset of agent kinds (or a bare string treated as a
    single kind for backward compatibility); None matches nothing (safe default,
    never match-all).
    """
    if isinstance(agent_filter, str):
        return agent_kind == agent_filter
    if agent_filter is None:
        return False
    return agent_kind in agent_filter


def escalate_request(pane_id, pane_info, req_cmd, safety_reason, decision_layer, agent_kind, visible_text=None):
    """Enqueue a persistent escalation and emit intercept notifications. Returns escalation id."""
    session_uuid = (
        pane_info.get("agent_session", {}).get("value") if isinstance(pane_info.get("agent_session"), dict) else None
    )
    # issue #7207: thread the pane's workspace cwd so auto-promotion can resolve
    # the repo-local .schengen/ policy on a later human approval. Also thread the
    # author origin (INV-WS-3): INJECTED/EMERGENT must never auto-promote.
    esc_cwd = pane_info.get("foreground_cwd") or pane_info.get("cwd") or ""
    esc_origin = "H" if agent_kind == "human" else "A"
    # Capture the raw dialog/situation (tail-most 8K chars) so the host LLM can
    # later inspect exactly what was on screen without re-deriving it (ADR-008).
    snapshot = (visible_text or "").strip()[-8000:] or None
    esc_id = enqueue_pending_escalation(
        pane_id=pane_id,
        raw_command=req_cmd,
        safety_reason=safety_reason,
        decision_layer=decision_layer,
        agent_kind=agent_kind,
        session_id=session_uuid,
        dialog_snapshot=snapshot,
        cwd=esc_cwd,
        origin=esc_origin,
    )
    print(
        f"🚨 [BORDER_CONTROL_INTERCEPT] Pre-execution HALTED for safety. Escalating to AGY / Human Review (Escalation #{esc_id}, Session: {session_uuid or 'unknown'}).",
        flush=True,
    )
    print(f"   • Pane: {pane_id} ({agent_kind})", flush=True)
    print(f"   • Layer: {decision_layer}", flush=True)
    print(f"   • Reason: {safety_reason}", flush=True)
    print(f"   • Intercepted Command:\n     {req_cmd}", flush=True)
    # Herdr notification popup
    run_cmd(
        [
            "herdr",
            "notification",
            "show",
            "SmartGate Alert",
            "--body",
            f"Manual approval required on {pane_id} [Layer: {decision_layer}]: {safety_reason}",
            "--sound",
            "request",
        ]
    )
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


def drain_completed_inspections(inspector, last_processed_prompt, dry_run=False):
    """Apply completed silent-inspection results for one poll cycle.

    Completed inspections are applied only after the live dialog is re-read
    (INV-CONC-4); worker threads never touch panes, SQLite, or UI.

    INV-AA-8 (audit-truth): an AUTO_APPROVED audit row is written ONLY after a
    VERIFIED inject success (or dry-run simulation). When the dialog changed
    mid-evaluation (INJECT_SKIP_CHANGED), the approval was NOT delivered, so
    the audit records an honest AUTO_DEFERRED entry instead — never
    AUTO_APPROVED. MANUAL_DELEGATED rows (unsafe -> human queue) are unchanged.
    """
    for pane_id, request, result in inspector.completed():
        req_cmd, state_seq, agent_status, pane_info, visible_text = request
        live_info = get_pane_info(pane_id)
        adapter = get_adapter(live_info.get("agent", "")) if live_info else None
        if adapter:
            live_text = get_pane_text(pane_id, lines=80)
            live_cmd, _ = canonical_request(adapter, pane_id, live_text)
        else:
            live_cmd = None
        if not live_info or live_cmd != req_cmd:
            inspector.release(pane_id, request)
            continue
        is_safe, reason, layer, tax = result
        if not is_safe:
            # Unsafe -> delegated to the human queue. The audit row documents the
            # delegation (unchanged behavior).
            record_audit_log(pane_id=pane_id, raw_command=req_cmd, decision="MANUAL_DELEGATED",
                safety_reason=reason or "", agent_kind=live_info.get("agent", "unknown"), decision_layer=layer,
                origin=tax.get("origin", "A"), consequence=tax.get("consequence", "NONE"),
                mechanism=tax.get("mechanism", "none"), gate_state=tax.get("gate_state", "ENFORCE"),
                shadow_mode=tax.get("shadow_mode", False))
            inspector.human_queue.append((pane_id, live_info, req_cmd, reason, layer, visible_text, state_seq, agent_status))
            inspector.set_state(pane_id, request, "queued")
            continue
        # Safe -> verified-inject path. The AUTO_APPROVED audit row is written
        # ONLY after the inject is verified (INV-AA-8).
        deferred = False
        approval_failed_reason = None
        if not dry_run:
            # Channel approval is an explicit OpenCode opt-in.  Keep
            # its verified permission.reply path ahead of the
            # keystroke fallback used by every other adapter.
            if guard_db.get_channel_approve_config():
                ch_approved, ch_reason = adapter.channel_approve(pane_id, req_cmd)
                if ch_approved:
                    deadline = time.monotonic() + 2.5
                    while time.monotonic() < deadline:
                        time.sleep(0.5)
                        current_text = get_pane_text(pane_id, lines=80)
                        current_req, _ = canonical_request(adapter, pane_id, current_text)
                        if current_req is None:
                            break
                    else:
                        print(
                            f"⚠️  [CHANNEL_FALLBACK] Pane {pane_id}: permission.reply not confirmed; falling back to keystroke injection.",
                            flush=True,
                        )
                    current_text = get_pane_text(pane_id, lines=80)
                    current_req, _ = canonical_request(adapter, pane_id, current_text)
                    if current_req is None:
                        print(f"🚀 Auto-approving {live_info.get('agent', 'unknown')} via permission.reply for {pane_id}...", flush=True)
                if ch_reason == INJECT_SKIP_CHANGED:
                    deferred = True
                    print(f"⏭️  [SKIP] Pane {pane_id} channel request changed during evaluation; deferring to next poll.", flush=True)
            if not deferred:
                current_text = get_pane_text(pane_id, lines=80)
                current_req, _ = canonical_request(adapter, pane_id, current_text)
                if current_req == req_cmd:
                    approved, inject_reason = adapter.inject_approval(pane_id, req_cmd)
                    if not approved and inject_reason == INJECT_SKIP_CHANGED:
                        deferred = True
                        print(f"⏭️  [SKIP] Pane {pane_id} dialog changed during evaluation; deferring to next poll.", flush=True)
                    elif not approved:
                        approval_failed_reason = inject_reason
                        print(f"🚨 [{live_info.get('agent', 'unknown')}] {inject_reason} on {pane_id}", flush=True)
                elif current_req is not None:
                    deferred = True
                    print(f"⏭️  [SKIP] Pane {pane_id} prompt changed during evaluation; deferring to next poll.", flush=True)
        if deferred:
            # INV-AA-8: the approval was NOT delivered — write an honest
            # AUTO_DEFERRED entry, never AUTO_APPROVED.
            record_audit_log(pane_id=pane_id, raw_command=req_cmd, decision="AUTO_DEFERRED",
                safety_reason=f"dialog changed mid-evaluation; approval not delivered: {reason or ''}".strip(),
                agent_kind=live_info.get("agent", "unknown"), decision_layer=layer,
                origin=tax.get("origin", "A"), consequence=tax.get("consequence", "NONE"),
                mechanism=tax.get("mechanism", "none"), gate_state=tax.get("gate_state", "ENFORCE"),
                shadow_mode=tax.get("shadow_mode", False))
            inspector.release(pane_id, request)
            continue
        if approval_failed_reason:
            # Real inject failure (not a dialog change): escalate; NO
            # AUTO_APPROVED row is written (the approval was not delivered).
            escalate_request(
                pane_id, live_info, req_cmd, approval_failed_reason,
                "OPENCODE_FAILSAFE", live_info.get("agent", "unknown"), visible_text=visible_text,
            )
            last_processed_prompt[pane_id] = {"cmd": req_cmd, "seq": state_seq, "status": agent_status, "is_safe": False, "last_alert_time": time.time()}
            inspector.release(pane_id, request)
            continue
        # VERIFIED inject success (or dry-run simulation): AUTO_APPROVED audit
        # row written ONLY now (INV-AA-8).
        record_audit_log(pane_id=pane_id, raw_command=req_cmd, decision="AUTO_APPROVED",
            safety_reason=reason or "", agent_kind=live_info.get("agent", "unknown"), decision_layer=layer,
            origin=tax.get("origin", "A"), consequence=tax.get("consequence", "NONE"),
            mechanism=tax.get("mechanism", "none"), gate_state=tax.get("gate_state", "ENFORCE"),
            shadow_mode=tax.get("shadow_mode", False))
        last_processed_prompt[pane_id] = {"cmd": req_cmd, "seq": state_seq, "status": agent_status, "is_safe": True, "last_alert_time": time.time()}
        resolve_escalation(pane_id=pane_id, approver="machine")
        inspector.release(pane_id, request)


def main():
    global _RELOAD_REQUESTED
    config = load_watcher_config()
    parser = argparse.ArgumentParser(description="Herdr SmartGate / Schengen Trusted Clearance Watcher (AGY Exclusive)")
    parser.add_argument(
        "--target",
        default="auto",
        help="Target pane ID (e.g. wP:p2) or 'auto' (default: auto - monitors all active & future panes)",
    )
    parser.add_argument("--exclude-pane", action="append", default=[], help="Pane ID to exclude from auto-approval")
    parser.add_argument("--interval", type=int, default=config["interval_seconds"], help="Polling interval in seconds")
    parser.add_argument(
        "--auto-exit",
        action="store_true",
        default=False,
        help="Automatically exit after idle timeout (default: False, runs continuously)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Log decisions without injecting keys")
    parser.add_argument(
        "--recent", "-n", type=int, nargs="?", const=10, default=None, help="Display recent audit logs (default: 10)"
    )
    parser.add_argument("--search", "-s", type=str, help="Search audit logs by keyword")
    parser.add_argument(
        "--tail", "-t", type=int, nargs="?", const=20, default=None, help="Tail schengen.log file (default: 20 lines)"
    )
    parser.add_argument("--paths", "--find-state", action="store_true", help="Print SmartGate state file paths")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format for agent parsing")
    parser.add_argument("--stats", action="store_true", help="Display pattern analysis stats from DB and exit")
    parser.add_argument("--status", action="store_true", help="Display status of SmartGate daemon and monitored panes")
    parser.add_argument(
        "--use-gpt-oss", action="store_true", default=False, help="Enable private GPT-OSS 120B semantic judge"
    )
    parser.add_argument(
        "--reasoning",
        choices=["off", "low", "medium", "high"],
        default=DEFAULT_REASONING_EFFORT,
        help="Reasoning effort for guard watcher (default: low)",
    )
    parser.add_argument("--stop", action="store_true", help="Stop running guard process for target (or all) and exit")
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Gracefully reload modules/rulesets on running guard without restarting process",
    )
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
                print(
                    f"{symbol} [{r['timestamp'][:19]}] #{r['id']} {r['pane_id']} - {r['decision']} [Layer: {r['decision_layer']}] ({r['safety_reason']})"
                )
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
                print(
                    f"{symbol} [{r['timestamp'][:19]}] #{r['id']:<3} {r['pane_id']:<6} | {r['decision']:<16} | Layer: {r['decision_layer']:<16}"
                )
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
            print(
                f"• Frequency: {row['total_occurrences']} (Approved: {row['auto_approved_count']}, Delegated: {row['delegated_count']})"
            )
            print(f"  Pattern: {row['pattern']}")
            print(f"  Last Seen: {row['last_seen']}")
            print("-" * 80)
        return

    # Strictly verify host runtime environment (ADR-003 / ADR-008 mandate)
    verify_host_runtime_environment()

    # Guard all registered target agent kinds (agy, opencode).
    agent_filter_set = frozenset(target_agent_kinds())

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

    # Resolve stale PENDING/DELIVERED escalations for excluded panes. These are
    # leftover false-positives from a previous daemon run (e.g. the host pane's
    # conversation text that mentioned a question marker). The pane is now
    # excluded and will never be processed, so without this startup cleanup the
    # stale escalations would linger in the pending queue after a restart.
    for exc_pane in excluded:
        resolve_escalation(pane_id=exc_pane, resolution_status="CANCELLED")

    print(
        f"🛡️  SmartGate / Herdr Schengen started (PID: {os.getpid()}, PPID: {initial_ppid}, target={args.target}, agent_filter=all, self_pane={self_pane or 'None'}, excluded={list(excluded)}, interval={args.interval}s, reasoning={args.reasoning}, lock={lock_file_path.name})",
        flush=True,
    )

    last_processed_prompt = {}
    inspector = InspectorCoordinator(max_workers=config["max_workers"])
    idle_count = 0

    try:
        while True:
            # Completed inspections are applied only after the live dialog is
            # re-read (INV-CONC-4); worker threads never touch panes, SQLite, or UI.
            drain_completed_inspections(inspector, last_processed_prompt, dry_run=args.dry_run)

            # INV-CONC-3: publish exactly one unsafe result at a time. The rest
            # remain silent in memory until its dialog clears.
            def human_request_is_live(pane_id, command):
                info = get_pane_info(pane_id)
                adapter = get_adapter(info.get("agent", "")) if info else None
                if not adapter:
                    return False
                visible = get_pane_text(pane_id, lines=80)
                request, _ = canonical_request(adapter, pane_id, visible)
                return request == command

            cancelled = inspector.evict_stale_human_requests(human_request_is_live)
            if cancelled:
                active_pane, active_cmd = cancelled
                cancel_stale_human_escalation(active_pane, active_cmd)
            if inspector.active_human is None and inspector.human_queue:
                queued = inspector.human_queue.popleft()
                pane_id, pane_info, req_cmd, reason, layer, visible_text, state_seq, agent_status = queued
                adapter = get_adapter(pane_info.get("agent", ""))
                visible = get_pane_text(pane_id, lines=80)
                canonical, _ = canonical_request(adapter, pane_id, visible) if adapter else (None, "")
                if adapter and canonical == req_cmd:
                    escalate_request(pane_id, pane_info, req_cmd, reason, layer, pane_info.get("agent", "unknown"), visible_text)
                    inspector.active_human = (pane_id, req_cmd)
                    inspector.set_state(pane_id, (req_cmd, state_seq, agent_status, pane_info, visible_text), "active")
                    last_processed_prompt[pane_id] = {"cmd": req_cmd, "seq": state_seq, "status": agent_status, "is_safe": False, "last_alert_time": time.time()}

            # Check for dynamic reload trigger (SIGHUP)
            if _RELOAD_REQUESTED:
                _RELOAD_REQUESTED = False
                execute_graceful_reload()

            # P1 Guard against orphan process: verify parent AGY session is alive
            if not is_parent_alive(initial_ppid):
                print(
                    f"🛑 [SCHENGEN_LIFECYCLE] Parent AGY session (PID {initial_ppid}) terminated. Exiting SmartGate watcher to prevent orphan auto-approval.",
                    flush=True,
                )
                break

            target_panes = []
            all_p = get_all_panes()

            if args.target == "auto":
                target_panes = find_blocked_panes(agent_filter=agent_filter_set, exclude_panes=excluded)
                if not target_panes:
                    active = [
                        p["pane_id"]
                        for p in all_p
                        if agent_matches(p.get("agent"), agent_filter_set) and p["pane_id"] not in excluded
                    ]
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

            # QUESTION residual sweep (#2800): resolve QUESTION escalations whose
            # dialog cleared (answered in-pane) as ANSWERED. Runs once per loop,
            # INDEPENDENT of target_panes — a question dialog may sit on a pane
            # that find_blocked_panes would not report. Debounced with the same
            # pane_direct_confirm_polls knob (INV-Q-5); blocked panes are never
            # evicted (INV-Q-4); live question reads reset the counter.
            try:
                sweep_confirm_polls = int(get_pane_direct_config().get("pane_direct_confirm_polls", 2))
            except Exception:
                sweep_confirm_polls = 2
            sweep_answered_questions(confirm_polls=sweep_confirm_polls)

            if not target_panes:
                idle_count += 1
                if args.auto_exit and idle_count > config["auto_exit_idle_cycles"]:
                    print("🏁 No active target AGY agent found. SmartGate exiting gracefully.", flush=True)
                    break
                time.sleep(args.interval)
                continue

            idle_count = 0

            # Pane-direct auto-eviction knobs (one config read per poll cycle).
            pane_direct_cfg = get_pane_direct_config()
            pane_direct_enabled = bool(pane_direct_cfg.get("pane_direct_eviction_enabled", True))
            pane_direct_confirm_polls = max(1, int(pane_direct_cfg.get("pane_direct_confirm_polls", 2)))

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
                req_cmd, _capture_source = canonical_request(adapter, pane_id, visible_text)

                if not req_cmd:
                    # Prompt is no longer active; reset last_processed_prompt for this pane
                    cached_clear = last_processed_prompt.get(pane_id)
                    if cached_clear:
                        # UNSAFE -> APPROVED pane-direct; QUESTION -> ANSWERED
                        # pane-direct (#2800); safe non-question -> other.
                        resolve_cleared_dialog(pane_id, cached_clear)
                        last_processed_prompt.pop(pane_id, None)
                        _not_live_streak.pop(pane_id, None)
                    if inspector.active_human and inspector.active_human[0] == pane_id:
                        inspector.active_human = None
                    inspector.release(pane_id)
                    continue

                # Pane-direct adjudication auto-eviction (PD-A/PD-B/PD-C): a cached
                # UNSAFE escalation is auto-resolved (approver=pane-direct,
                # resolution=APPROVED) when the live dialog is no longer present —
                # the user answered it DIRECTLY in the pane (y/n/enter). PD-C is
                # debounced (confirm_polls consecutive not-live polls) so a
                # transient dialog redraw never self-approves a stale escalation.
                if pane_direct_enabled:
                    cached_esc = last_processed_prompt.get(pane_id)
                    evict, evict_reason = pane_direct_maybe_evict(
                        pane_id, cached_esc, pane_info, visible_text, req_cmd, adapter,
                        confirm_polls=pane_direct_confirm_polls,
                    )
                    if evict:
                        resolve_escalation(pane_id=pane_id, resolution="APPROVED", approver="pane-direct")
                        last_processed_prompt.pop(pane_id, None)
                        _not_live_streak.pop(pane_id, None)
                        if inspector.active_human and inspector.active_human[0] == pane_id:
                            inspector.active_human = None
                        inspector.release(pane_id)
                        print(
                            f"♻️ [PANE-DIRECT] Pane {pane_id}: {evict_reason}; resolved stale escalation (approver=pane-direct).",
                            flush=True,
                        )
                        continue
                    if evict_reason.startswith("debounced"):
                        # PD-C debounce: hold processing (no re-evaluation/re-escalation)
                        # until confirm_polls consecutive not-live polls observed.
                        continue

                if req_cmd.startswith("question"):
                    # Human question dialog (subjective). Never send a keystroke,
                    # never approve/reject. Surface it as a PENDING escalation so
                    # the user is guided to answer it in the pane; it stays pending
                    # until the dialog clears (the user answers), at which point the
                    # `not req_cmd` branch above auto-resolves it.
                    question_text = req_cmd[len("question:"):].strip() if req_cmd.startswith("question:") else ""
                    summary = question_text or "(no text extracted)"
                    cached = last_processed_prompt.get(pane_id)
                    if (
                        cached
                        and cached.get("cmd") == req_cmd
                        and cached.get("seq") == state_seq
                        and cached.get("status") == agent_status
                    ):
                        continue  # already surfaced; wait for the dialog to clear
                    session_uuid = (
                        pane_info.get("agent_session", {}).get("value")
                        if isinstance(pane_info.get("agent_session"), dict)
                        else None
                    )
                    esc_id = enqueue_pending_escalation(
                        pane_id=pane_id,
                        raw_command=req_cmd,
                        safety_reason=f"Agent asked the user a question: {summary}",
                        decision_layer="QUESTION",
                        agent_kind=agent_kind,
                        session_id=session_uuid,
                        dialog_snapshot=visible_text,
                        cwd=pane_info.get("foreground_cwd") or pane_info.get("cwd") or "",
                        origin="H" if agent_kind == "human" else "A",
                    )
                    last_processed_prompt[pane_id] = {
                        "cmd": req_cmd,
                        "seq": state_seq,
                        "status": agent_status,
                        "is_safe": True,
                        "last_alert_time": 0,
                    }
                    print(
                        f"❓ [QUESTION] Pane {pane_id} ({agent_kind}) asked: {summary} — surfaced as pending (Escalation #{esc_id}); awaiting manual answer.",
                        flush=True,
                    )
                    continue

                cached = last_processed_prompt.get(pane_id)
                now = time.time()

                # If same command is pending review on this pane in the EXACT same turn state
                if (
                    cached
                    and cached.get("cmd") == req_cmd
                    and cached.get("seq") == state_seq
                    and cached.get("status") == agent_status
                ):
                    if not cached.get("is_safe", True):
                        if now - cached.get("last_alert_time", 0) > 30.0:
                            cached["last_alert_time"] = now
                            print(
                                f"⏳ [ESCALATION_REMINDER] Pane {pane_id} ({agent_kind}) is STILL waiting for approval: {req_cmd[:70]}",
                                flush=True,
                            )
                    continue

                print(
                    f"\n🔍 [Target: {pane_id} ({agent_kind})] Detected Script/Command Pre-Approval Request:\n----------------------------------------\n{req_cmd}\n----------------------------------------",
                    flush=True,
                )

                target_cwd = pane_info.get("foreground_cwd") or pane_info.get("cwd") or os.getcwd()

                # Dialog expansion (issue #2099): a truncated/folded dialog must be
                # expanded so the AST evaluator sees the FULL request (INV-EX-2).
                # Single bounded attempt per poll (INV-EX-4). Runs only after the
                # pane-direct liveness and question checks (INV-EX-5); a failed or
                # still-truncated expansion evaluates fail-closed (INV-EX-3).
                visible_text, req_cmd, truncated_unrecoverable = maybe_expand_truncated_dialog(
                    adapter, pane_id, visible_text, req_cmd
                )

                # INV-CONC-1/2: submit silently; approval/escalation is handled
                # only from the completion drain at the next poll.
                def evaluate(req=req_cmd, cwd=target_cwd, kind=agent_kind, scope=pane_id):
                    if truncated_unrecoverable:
                        return truncated_evaluate_result()  # INV-EX-3: fail-closed
                    is_whitelisted, wl_reason = check_persisted_allowlist(req)
                    if is_whitelisted:
                        tax = derive_taxonomy(req, DecisionLayer.ALLOWLIST, True, wl_reason or "", origin=Origin.HUMAN)
                        return True, wl_reason, DecisionLayer.ALLOWLIST, tax
                    return audit_shell_command_with_taxonomy(req, use_llm_judge=args.use_gpt_oss,
                        reasoning_effort=args.reasoning, origin=Origin.AGENT if kind != "human" else Origin.HUMAN,
                        cwd=cwd, scope=scope, agent_id=kind)
                inspector.submit(pane_id, (req_cmd, state_seq, agent_status, pane_info, visible_text), evaluate)
                continue

            # Phase-1 IPC (INV-PH1-3): publish the in-flight snapshot once per
            # poll cycle, AFTER the pane loop + any submits, BEFORE the sleep.
            sync_in_flight_state(inspector)

            time.sleep(args.interval)
    finally:
        inspector.close()
        try:
            # Dead-watcher cleanup (INV-PH1-2/5): leave NO stale "Checking" —
            # publish an empty snapshot so the TUI reader clears immediately.
            IN_FLIGHT_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            IN_FLIGHT_STATE_PATH.write_text(
                json.dumps({"ts": time.time(), "entries": []}, ensure_ascii=False), encoding="utf-8"
            )
        except Exception:
            pass
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()
            if lock_file_path.exists():
                lock_file_path.unlink()
        except Exception:
            pass


if __name__ == "__main__":
    main()
