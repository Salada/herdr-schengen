#!/usr/bin/env python3
"""Herdr Schengen / SmartGate History & Diagnostics CLI.

Provides standardized query, log tailing, path discovery, and layer-aware
audit inspection for AI coding agents and human engineers.
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Add scripts directory to path
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from guard_db import (
    get_recent_audit_logs,
    search_audit_logs,
    get_pattern_analysis,
    get_state_file_paths,
    tail_state_log,
    init_db,
    get_pending_escalations,
    resolve_escalation,
    cleanup_escalations,
)
from security_evaluator import DecisionLayer


def main():
    parser = argparse.ArgumentParser(
        description="Herdr Schengen / SmartGate History & Diagnostics CLI"
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version="Herdr Schengen (SmartGate) v1.2.0",
        help="Show program version and exit",
    )
    parser.add_argument(
        "--list-layers",
        action="store_true",
        help="List all 9 standard Decision Layers and exit",
    )
    parser.add_argument(
        "--list-decisions",
        action="store_true",
        help="List all standard decision types and exit",
    )
    parser.add_argument(
        "--recent",
        "-n",
        type=int,
        nargs="?",
        const=10,
        default=None,
        help="Display recent audit logs (default: 10)",
    )
    parser.add_argument(
        "--limit",
        "-l",
        type=int,
        default=10,
        help="Limit number of logs to display (default: 10)",
    )
    parser.add_argument(
        "--search",
        "-s",
        type=str,
        help="Search audit logs by keyword across commands, patterns, and reasons",
    )
    parser.add_argument(
        "--tail",
        "-t",
        type=int,
        nargs="?",
        const=20,
        default=None,
        help="Tail schengen.log file (default: 20 lines)",
    )
    parser.add_argument(
        "--paths",
        "--find-state",
        action="store_true",
        help="Print SmartGate state file paths (DB, lockfile, logs)",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Display pattern analysis stats from DB and exit",
    )
    parser.add_argument(
        "--layer",
        type=str,
        help="Filter by decision layer (e.g. SECRET_GUARD, SHELL_CRITICAL, FAST_TRACK_AST)",
    )
    parser.add_argument(
        "--decision",
        type=str,
        help="Filter by decision (AUTO_APPROVED, MANUAL_DELEGATED, ALLOWLIST_BYPASS)",
    )
    parser.add_argument(
        "--pane",
        type=str,
        help="Filter by Herdr pane ID (e.g. wP:p2)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output structured JSON results for agent parsing",
    )
    parser.add_argument(
        "--pending",
        action="store_true",
        help="Display active pending escalations requiring human/agent review",
    )
    parser.add_argument(
        "--cleanup-pending",
        action="store_true",
        help="Clean up stale pending escalations (marks expired/stale entries)",
    )
    parser.add_argument(
        "--purge-old",
        action="store_true",
        help="Purge resolved/cancelled/expired escalations older than 7 days from DB",
    )

    args = parser.parse_args()

    # 0. Discovery & Metadata Flags (Side-effect free)
    if args.list_layers:
        layers = [layer.value for layer in DecisionLayer]
        if args.json:
            print(json.dumps(layers, indent=2))
        else:
            print("🛡️  Herdr Schengen Standard Decision Layers (9 Layers):")
            for idx, layer in enumerate(layers):
                print(f"  • Layer {idx}: {layer}")
        return

    if args.list_decisions:
        decisions = ["AUTO_APPROVED", "MANUAL_DELEGATED", "ALLOWLIST_BYPASS"]
        if args.json:
            print(json.dumps(decisions, indent=2))
        else:
            print("📋 Herdr Schengen Persisted Audit Decision Types:")
            for d in decisions:
                print(f"  • {d}")
        return

    # Pending Escalations Management
    if args.cleanup_pending:
        count = cleanup_escalations(pane_id=args.pane, older_than_hours=24.0, new_status="STALE_EXPIRED")
        if args.json:
            print(json.dumps({"cleaned_count": count, "status": "ok"}))
        else:
            print(f"🧹 Cleaned up {count} stale pending escalation(s) -> STALE_EXPIRED.")
        return

    if args.purge_old:
        purged = cleanup_escalations(purge_deleted=True)
        if args.json:
            print(json.dumps({"purged_count": purged, "status": "ok"}))
        else:
            print(f"🗑️  Purged {purged} old resolved/stale escalation record(s) older than 7 days.")
        return

    if args.pending:
        # Query active Herdr session map for dynamic liveness validation
        active_map = {}
        try:
            res = subprocess.run(["herdr", "pane", "list"], capture_output=True, text=True, check=False)
            if res.returncode == 0:
                p_data = json.loads(res.stdout)
                for p in p_data.get("result", {}).get("panes", []):
                    pid = p.get("pane_id")
                    sess_uuid = p.get("agent_session", {}).get("value") if isinstance(p.get("agent_session"), dict) else None
                    if pid:
                        active_map[pid] = sess_uuid
        except Exception:
            active_map = None

        pending = get_pending_escalations(pane_id=args.pane, include_delivered=True, active_session_map=active_map)
        if args.json:
            print(json.dumps(pending, indent=2))
        else:
            print(f"🚨 Active Pending Escalations Queue ({len(pending)} pending):")
            print("=" * 90)
            if not pending:
                print("   (No active pending escalations)")
            for item in pending:
                sess_info = f"Session: {item.get('session_id', 'unknown')}"
                print(f"• Escalation #{item['id']} [Pane: {item['pane_id']} | {sess_info}] Status: {item['status']}")
                print(f"  Layer  : {item['decision_layer']}")
                print(f"  Reason : {item['safety_reason']}")
                print(f"  Started: {item['started_at']}")
                print(f"  Command: {item['raw_command']}")
                print("-" * 90)
        return

    # 1. State File Paths
    if args.paths:
        paths = get_state_file_paths()
        if args.json:
            print(json.dumps(paths, indent=2))
        else:
            print("🗂️  SmartGate / Herdr Schengen State Paths:")
            for k, v in paths.items():
                print(f"  • {k:<12}: {v}")
        return

    # 2. Tail Log
    if args.tail is not None:
        log_lines = tail_state_log(args.tail)
        if args.json:
            print(json.dumps({"lines": log_lines, "count": len(log_lines)}, indent=2))
        else:
            print(f"📜 Last {len(log_lines)} lines of schengen.log:")
            print("".join(log_lines), end="")
        return

    # 3. Pattern Frequency Stats
    if args.stats:
        stats = get_pattern_analysis()
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            print("\n📊 Herdr SmartGate / Schengen - Pattern Analysis & Review Board")
            print("=" * 80)
            if not stats:
                print("No command patterns recorded yet in DB.")
            for row in stats:
                print(
                    f"• Frequency: {row['total_occurrences']} (Approved:"
                    f" {row['auto_approved_count']}, Delegated:"
                    f" {row['delegated_count']})"
                )
                print(f"  Pattern: {row['pattern']}")
                print(f"  Last Seen: {row['last_seen']}")
                print("-" * 80)
        return

    # 4. Search Audit Logs
    if args.search:
        results = search_audit_logs(args.search, limit=args.limit)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(f"🔍 Search results for '{args.search}' ({len(results)} found, limit: {args.limit}):")
            print("=" * 90)
            if not results:
                print("   (No matching audit events found)")
            for r in results:
                symbol = "✅" if r["decision"] in ("AUTO_APPROVED", "ALLOWLIST_BYPASS") else "🚨"
                cmd_prev = (r["raw_command"][:70] + "...") if len(r["raw_command"]) > 70 else r["raw_command"]
                print(f"{symbol} [{r['timestamp'][:19]}] #{r['id']:<3} {r['pane_id']:<6} | {r['decision']:<16} | Layer: {r['decision_layer']:<16}")
                print(f"   Reason: {r['safety_reason']}")
                print(f"   Cmd   : {cmd_prev}")
                print("-" * 90)
        return

    # 5. Default / Recent Audit Logs
    effective_limit = args.recent if args.recent is not None else args.limit
    logs = get_recent_audit_logs(
        limit=effective_limit,
        decision=args.decision,
        pane_id=args.pane,
        layer=args.layer,
    )

    if args.json:
        print(json.dumps(logs, indent=2))
    else:
        filter_info = []
        if args.decision:
            filter_info.append(f"Decision: {args.decision}")
        if args.layer:
            filter_info.append(f"Layer: {args.layer}")
        if args.pane:
            filter_info.append(f"Pane: {args.pane}")
        filter_str = f" [{', '.join(filter_info)}]" if filter_info else ""

        print(f"📜 Recent SmartGate Audit Events (Limit: {effective_limit}){filter_str}:")
        print("=" * 90)
        if not logs:
            print("   (No audit events found matching criteria)")
        for r in logs:
            symbol = "✅" if r["decision"] in ("AUTO_APPROVED", "ALLOWLIST_BYPASS") else "🚨"
            cmd_prev = (r["raw_command"][:70] + "...") if len(r["raw_command"]) > 70 else r["raw_command"]
            print(f"{symbol} [{r['timestamp'][:19]}] #{r['id']:<3} {r['pane_id']:<6} | {r['decision']:<16} | Layer: {r['decision_layer']:<16}")
            print(f"   Reason: {r['safety_reason']}")
            print(f"   Cmd   : {cmd_prev}")
            print("-" * 90)


if __name__ == "__main__":
    main()
