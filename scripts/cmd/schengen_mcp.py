#!/usr/bin/env python3
"""Lightweight stdio MCP Server for Herdr Schengen (SmartGate).

Strict Daemon Liveness Binding:
The MCP server monitors the live existence of the Schengen guard daemon (PID & flock).
If no active guard daemon is running (stop schengen / daemon killed), this MCP server
closes its connection and exits immediately (sys.exit(1)).
This forces OpenCode's TUI sidebar to transition MCP status from 'connected' to 'failed / disconnected'.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Add herdr-schengen scripts directory to path
SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parent
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from core.guard_db import (
    get_pending_escalations,
    get_recent_audit_logs,
    get_session_dashboard_summary,
    get_state_file_paths,
    resolve_escalation,
)
from cmd.schengen_watcher import list_active_guard_locks


def check_daemon_liveness():
    active = list_active_guard_locks()
    if active:
        tgt, lpath, pid = active[0]
        return {
            "status": "ACTIVE",
            "running": True,
            "pid": pid,
            "target": tgt,
            "color": "green",
            "lock_file": str(lpath.name),
        }
    return {
        "status": "INACTIVE",
        "running": False,
        "pid": None,
        "target": None,
        "color": "red",
        "lock_file": None,
    }


async def liveness_watchdog():
    """Background watchdog: If no daemon is running, exit immediately so OpenCode TUI shows Failed/Red."""
    # Allow 3 seconds grace period on initial startup
    await asyncio.sleep(3.0)
    while True:
        live = check_daemon_liveness()
        if not live["running"]:
            # Daemon is stopped or died -> exit immediately to drop stdio pipe
            sys.exit(1)
        await asyncio.sleep(1.0)


async def handle_request(req):
    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                },
                "serverInfo": {
                    "name": "schengen-gate",
                    "version": "1.2.0",
                },
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "schengen_status",
                        "description": "Get live Schengen (SmartGate) daemon process status, PID, and target pane.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                        },
                    },
                    {
                        "name": "schengen_summary",
                        "description": "Get complete Schengen timeline dashboard: daemon health, 10 recent audits, and 5 escalations with approval states.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "pane_id": {
                                    "type": "string",
                                    "description": "Optional Herdr pane ID filter (e.g. w1D:p1). Omit for all panes.",
                                },
                            },
                        },
                    },
                    {
                        "name": "schengen_pending",
                        "description": "List all active pending escalations awaiting human supervisor clearance.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "pane_id": {
                                    "type": "string",
                                    "description": "Optional Herdr pane ID filter.",
                                },
                            },
                        },
                    },
                    {
                        "name": "schengen_resolve",
                        "description": "Resolve or cancel an active escalation by ID or command hash.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "escalation_id": {
                                    "type": "integer",
                                    "description": "Escalation ID to resolve/cancel.",
                                },
                                "resolution": {
                                    "type": "string",
                                    "enum": ["RESOLVED", "CANCELLED"],
                                    "description": "Resolution status: RESOLVED (approve) or CANCELLED (reject).",
                                    "default": "RESOLVED",
                                },
                            },
                            "required": ["escalation_id"],
                        },
                    },
                ],
            },
        }

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})

        if name == "schengen_status":
            live = check_daemon_liveness()
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(live, indent=2),
                        }
                    ]
                },
            }

        if name == "schengen_summary":
            pane_id = args.get("pane_id")
            live = check_daemon_liveness()
            summary = get_session_dashboard_summary(pane_id=pane_id, audit_limit=10, escalation_limit=5)
            payload = {
                "daemon": live,
                "summary": summary,
            }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(payload, indent=2),
                        }
                    ]
                },
            }

        if name == "schengen_pending":
            pane_id = args.get("pane_id")
            pending = get_pending_escalations(pane_id=pane_id, include_delivered=True)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(pending, indent=2),
                        }
                    ]
                },
            }

        if name == "schengen_resolve":
            esc_id = args.get("escalation_id")
            res_status = args.get("resolution", "RESOLVED")
            resolve_escalation(pane_id="", escalation_id=esc_id, resolution_status=res_status)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({"status": "success", "escalation_id": esc_id, "resolution": res_status}),
                        }
                    ]
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {name}"},
        }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Unhandled method: {method}"},
    }


async def main():
    # Run active watchdog task concurrently
    asyncio.create_task(liveness_watchdog())

    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        line = await reader.readline()
        if not line:
            break
        try:
            req_text = line.decode("utf-8").strip()
            if not req_text:
                continue
            req = json.loads(req_text)
            resp = await handle_request(req)
            if resp is not None:
                resp_bytes = (json.dumps(resp) + "\n").encode("utf-8")
                sys.stdout.buffer.write(resp_bytes)
                sys.stdout.buffer.flush()
        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": f"Internal error: {str(e)}"},
            }
            sys.stdout.buffer.write((json.dumps(err_resp) + "\n").encode("utf-8"))
            sys.stdout.buffer.flush()


if __name__ == "__main__":
    asyncio.run(main())
