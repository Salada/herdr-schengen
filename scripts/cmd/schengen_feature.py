#!/usr/bin/env python3
"""CLI utility for managing Feature Requests & Self-Improvement Backlog.

Usage:
  # 1. Add feature request
  python3 scripts/schengen_feature.py --add "TUI Dark Mode" --desc "Add monokai dark theme toggle" --priority HIGH

  # 2. Search similar feature requests (FTS5 CJK trigram matching)
  python3 scripts/schengen_feature.py --search "마크다운"

  # 3. List backlog items
  python3 scripts/schengen_feature.py --list
  python3 scripts/schengen_feature.py --list --status PENDING

  # 4. Pull next task (for autonomous dev agent self-improvement job)
  python3 scripts/schengen_feature.py --pull --worker "bot-agy"

  # 5. Resolve task
  python3 scripts/schengen_feature.py --resolve 1 --note "Implemented in PR #62"
"""

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parent
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from core.feature_db import (
    add_feature_request,
    create_feature_request_with_similars,
    get_feature_request_by_id,
    list_feature_requests,
    pull_next_feature_request,
    search_similar_feature_requests,
    update_feature_request_status,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Herdr-Schengen Feature Request Backlog & Self-Improvement CLI")
    parser.add_argument("--add", metavar="TITLE", help="Add a new feature request title")
    parser.add_argument("--desc", default="", help="Detailed description of the feature request")
    parser.add_argument("--priority", choices=["LOW", "NORMAL", "HIGH", "CRITICAL"], default="NORMAL", help="Priority level")
    parser.add_argument("--category", default="GENERAL", help="Category tag (e.g. UI, SECURITY, LLM, WORKFLOW)")
    parser.add_argument("--requester", default="user", help="Requester identity (default: user)")
    parser.add_argument("--source", default="cli", help="Submission source (default: cli)")

    parser.add_argument("--search", metavar="QUERY", help="Search similar feature requests using FTS5 CJK trigram")
    parser.add_argument("--list", action="store_true", help="List recent feature requests")
    parser.add_argument("--status", choices=["PENDING", "IN_PROGRESS", "RESOLVED", "REJECTED"], help="Filter by status")
    parser.add_argument("--limit", type=int, default=20, help="Maximum number of items to return")

    parser.add_argument("--pull", action="store_true", help="Claim and pull the oldest PENDING feature request for self-improvement")
    parser.add_argument("--worker", default="dev-agent", help="Worker name when pulling a task")

    parser.add_argument("--resolve", type=int, metavar="ID", help="Mark feature request as RESOLVED")
    parser.add_argument("--reject", type=int, metavar="ID", help="Mark feature request as REJECTED")
    parser.add_argument("--note", default="", help="Resolution note or rejection reason")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    # 1. Add
    if args.add:
        created = create_feature_request_with_similars(
            title=args.add,
            description=args.desc,
            requester=args.requester,
            priority=args.priority,
            category=args.category,
            source=args.source,
            similars_limit=3,
        )
        req_id = created["id"]
        similars = created["similar_items"]

        if args.json:
            print(json.dumps({"status": "created", "id": req_id, "similar_items": similars}, indent=2, ensure_ascii=False))
        else:
            print(f"✅ Feature Request #{req_id} queued successfully: {args.add} (Priority: {args.priority})")
            if similars:
                print(f"🔍 Found {len(similars)} similar existing request(s):")
                for sim in similars:
                    print(f"   • #{sim['id']} [{sim['status']}] {sim['title']} (Rank: {sim['rank_score']:.2f})")
        return 0

    # 2. Search
    if args.search:
        results = search_similar_feature_requests(args.search, limit=args.limit, status=args.status)
        if args.json:
            print(json.dumps(results, indent=2, ensure_ascii=False))
        else:
            if not results:
                print(f"🔍 No feature requests matching query: '{args.search}'")
            else:
                print(f"🔍 Found {len(results)} matching feature request(s) for '{args.search}':")
                for r in results:
                    print(f"  • #{r['id']} [{r['status']}] ({r['priority']}) {r['title']} — {r.get('description', '')[:50]}")
        return 0

    # 3. Pull
    if args.pull:
        task = pull_next_feature_request(worker_name=args.worker)
        if not task:
            if args.json:
                print(json.dumps({"status": "empty", "task": None}))
            else:
                print("🏁 No pending feature requests in backlog queue.")
            return 0
        if args.json:
            print(json.dumps({"status": "claimed", "task": task}, indent=2, ensure_ascii=False))
        else:
            print(f"🚀 Claimed Feature Request #{task['id']} for self-improvement job:")
            print(f"   • Title: {task['title']}")
            print(f"   • Priority: {task['priority']} | Category: {task['category']}")
            print(f"   • Description: {task.get('description', '')}")
            print(f"   • Assigned to: {task['assigned_to']}")
        return 0

    # 4. Resolve
    if args.resolve:
        success = update_feature_request_status(args.resolve, "RESOLVED", resolution_note=args.note)
        if success:
            print(f"✅ Feature Request #{args.resolve} marked as RESOLVED.")
        else:
            print(f"❌ Feature Request #{args.resolve} not found or update failed.", file=sys.stderr)
            return 1
        return 0

    # 5. Reject
    if args.reject:
        success = update_feature_request_status(args.reject, "REJECTED", resolution_note=args.note)
        if success:
            print(f"🚫 Feature Request #{args.reject} marked as REJECTED.")
        else:
            print(f"❌ Feature Request #{args.reject} not found or update failed.", file=sys.stderr)
            return 1
        return 0

    # 6. List
    if args.list or len(sys.argv) == 1:
        items = list_feature_requests(status=args.status, limit=args.limit)
        if args.json:
            print(json.dumps(items, indent=2, ensure_ascii=False))
        else:
            if not items:
                print("📋 Backlog is empty.")
            else:
                print(f"📋 Feature Requests Backlog ({len(items)} items):")
                for it in items:
                    badge = f"[{it['status']}]"
                    print(f"  • #{it['id']:<3} {badge:<13} ({it['priority']:<8}) {it['title']}")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
