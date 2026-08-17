#!/usr/bin/env python3
"""Herdr Agent Guard Watcher Daemon with SQLite3 Persistence & GPT-OSS 120B Subagent support.

Monitors Herdr pane(s) at configurable intervals, performs AST static
analysis and security evaluation on requested commands/scripts, logs every
event into SQLite3 database (~/.local/state/herdr-agent-guard/guard_history.db),
and auto-approves safe commands while delegating risky commands to the user.
Zero Google One quota consumption by leveraging private GPT-OSS 120B Subagent.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# Add script directory to sys.path for local imports
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from guard_db import (
    record_audit_log,
    check_persisted_allowlist,
    get_pattern_analysis,
    init_db,
    DB_PATH
)
from security_evaluator import audit_shell_command, audit_python_code, sanitize_output, DEFAULT_GPT_OSS_MODEL, DEFAULT_GPT_OSS_ENDPOINT


def run_cmd(args):
    """Run a subprocess command and return stdout."""
    try:
        res = subprocess.run(args, capture_output=True, text=True, check=True)
        return res.stdout
    except subprocess.CalledProcessError:
        return None


def get_all_panes():
    """Retrieve all active Herdr panes."""
    out = run_cmd(["herdr", "pane", "list"])
    if not out:
        return []
    try:
        data = json.loads(out)
        return data.get("result", {}).get("panes", [])
    except Exception:
        return []


def get_pane_info(pane_id):
    """Retrieve specific pane metadata."""
    for pane in get_all_panes():
        if pane.get("pane_id") == pane_id:
            return pane
    return None


def get_pane_text(pane_id, lines=60):
    """Read visible terminal buffer from pane."""
    out = run_cmd(["herdr", "pane", "read", pane_id, "--source", "visible", "--lines", str(lines)])
    return out or ""


def find_blocked_panes():
    """Find all panes currently waiting on approval/blocked status."""
    blocked = []
    for pane in get_all_panes():
        status = pane.get("agent_status", "")
        pane_id = pane.get("pane_id", "")
        if status == "blocked":
            blocked.append(pane_id)
        else:
            text = get_pane_text(pane_id, lines=40)
            if "Requesting permission for:" in text or "Do you want to proceed?" in text:
                blocked.append(pane_id)
    return list(set(blocked))


def parse_permission_request(visible_text):
    """Extract command from Herdr/AGY approval dialog."""
    match = re.search(r"Requesting permission for:\s*\n([\s\S]*?)\n\s*Do you want to proceed\?", visible_text)
    if match:
        return match.group(1).strip()
    return None


def main():
    parser = argparse.ArgumentParser(description="Herdr Agent Guard Watcher with GPT-OSS 120B Subagent Support")
    parser.add_argument("--target", default="auto", help="Target pane ID (e.g. wP:p2) or 'auto'")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds (default: 5)")
    parser.add_argument("--auto-exit", action="store_true", default=True, help="Automatically exit when agent finishes session")
    parser.add_argument("--dry-run", action="store_true", help="Log decisions without injecting keys")
    parser.add_argument("--stats", action="store_true", help="Display pattern analysis stats from DB and exit")
    parser.add_argument("--use-gpt-oss", action="store_true", default=False, help="Enable private GPT-OSS 120B semantic judge (Zero Google One quota)")
    args = parser.parse_args()

    init_db()

    if args.stats:
        stats = get_pattern_analysis()
        print("\n📊 Herdr Agent Guard - Pattern Analysis & Review Board")
        print("=" * 80)
        if not stats:
            print("No command patterns recorded yet in DB.")
        for row in stats:
            print(f"• Frequency: {row['total_occurrences']} (Approved: {row['auto_approved_count']}, Delegated: {row['delegated_count']})")
            print(f"  Pattern: {row['pattern']}")
            print(f"  Last Seen: {row['last_seen']}")
            print("-" * 80)
        return

    print(f"🛡️  Herdr Agent Guard started (target={args.target}, interval={args.interval}s, gpt_oss={args.use_gpt_oss}, db={DB_PATH})", flush=True)

    last_approved_cmd = {}
    idle_count = 0

    while True:
        target_panes = []
        if args.target == "auto":
            target_panes = find_blocked_panes()
            if not target_panes:
                all_p = get_all_panes()
                active = [p["pane_id"] for p in all_p if p.get("agent") in ("agy", "hermes", "codex")]
                target_panes = active
        else:
            target_panes = [args.target]

        if not target_panes:
            idle_count += 1
            if args.auto_exit and idle_count > 6:
                print("🏁 No active agent target found. Guard watcher exiting gracefully.", flush=True)
                break
            time.sleep(args.interval)
            continue

        for pane_id in target_panes:
            pane_info = get_pane_info(pane_id)
            if not pane_info:
                continue

            agent_kind = pane_info.get("agent", "unknown")
            visible_text = get_pane_text(pane_id, lines=60)
            req_cmd = parse_permission_request(visible_text)

            if req_cmd and last_approved_cmd.get(pane_id) != req_cmd:
                print(f"\n🔍 [Target: {pane_id} ({agent_kind})] Detected Permission Request:\n----------------------------------------\n{req_cmd}\n----------------------------------------", flush=True)

                # 1. Check user persisted allowlist
                is_whitelisted, wl_reason = check_persisted_allowlist(req_cmd)
                if is_whitelisted:
                    is_safe = True
                    reason = wl_reason
                else:
                    is_safe, reason = audit_shell_command(req_cmd, use_llm_judge=args.use_gpt_oss)

                print(f"⚖️  Safety Evaluation: {'✅ SAFE' if is_safe else '🚨 DANGEROUS / REVIEW NEEDED'} ({reason})", flush=True)

                # 2. Record to SQLite3 DB
                decision = "AUTO_APPROVED" if is_safe else "MANUAL_DELEGATED"
                record_audit_log(
                    pane_id=pane_id,
                    raw_command=req_cmd,
                    decision=decision,
                    safety_reason=reason,
                    agent_kind=agent_kind
                )

                # 3. Action
                if is_safe:
                    if not args.dry_run:
                        print(f"🚀 Auto-approving for {pane_id} (sending Enter)...", flush=True)
                        run_cmd(["herdr", "agent", "send-keys", pane_id, "enter"])
                    else:
                        print(f"🧪 [Dry-Run] Would send Enter to {pane_id}", flush=True)
                    last_approved_cmd[pane_id] = req_cmd
                else:
                    print(f"🛑 Execution HALTED for safety. Awaiting human review on pane {pane_id}.", flush=True)
                    run_cmd(["herdr", "notification", "send", "--title", "Agent Guard Alert", "--body", f"Manual approval required on {pane_id}: {reason}"])
                    last_approved_cmd[pane_id] = req_cmd

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
