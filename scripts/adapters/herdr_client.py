#!/usr/bin/env python3
"""Herdr CLI I/O primitives shared by the watcher core and agent adapters.

Isolated from cmd.schengen_watcher.py so that agent adapters can import the raw
Herdr primitives without creating a circular dependency.
"""

import json
import os
import subprocess


AGENT_THREAD_READ_STATUSES = frozenset({"working", "idle", "done", "blocked"})


def run_cmd(args):
    """Run a subprocess command and return stdout (None on failure)."""
    try:
        res = subprocess.run(args, capture_output=True, text=True, check=True)
        return res.stdout
    except subprocess.CalledProcessError:
        return None


def get_all_panes():
    """Retrieve all active Herdr panes enriched with live agent metadata and state_change_seq."""
    out = run_cmd(["herdr", "agent", "list"])
    if out:
        try:
            data = json.loads(out)
            agents = data.get("result", {}).get("agents", [])
            if agents:
                return agents
        except Exception:
            pass

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


def get_pane_text(pane_id, lines=80, full_dump=False, source=None):
    """Read terminal text from the requested Herdr buffer source."""
    source = source or ("scrollback" if (full_dump or lines > 100) else "visible")
    out = run_cmd(["herdr", "pane", "read", pane_id, "--source", source, "--lines", str(lines)])
    return out or ""


def get_agent_or_pane_text(pane_id, lines=80, full_dump=False, source=None):
    """Prefer a registered agent thread for advisory context investigations.

    This intentionally costs one metadata subprocess before the read. Explicit
    pane sources and full scrollback dumps bypass agent routing because those
    are terminal-buffer concepts used by safety-critical callers.
    """
    pane_source = source or ("scrollback" if (full_dump or lines > 100) else "visible")

    if source is None and not full_dump:
        pane = get_pane_info(pane_id)
        session = pane.get("agent_session") if isinstance(pane, dict) else None
        status = str(pane.get("agent_status") or "").strip().lower() if isinstance(pane, dict) else ""
        if (
            isinstance(session, dict)
            and bool(session.get("value"))
            and status in AGENT_THREAD_READ_STATUSES
        ):
            out = run_cmd(
                [
                    "herdr",
                    "agent",
                    "read",
                    pane_id,
                    "--source",
                    "recent-unwrapped",
                    "--lines",
                    str(lines),
                ]
            )
            if out and out.strip():
                return out, "agent:recent-unwrapped"

    return get_pane_text(
        pane_id,
        lines=lines,
        full_dump=full_dump,
        source=source,
    ), f"pane:{pane_source}"


def detect_self_pane_id():
    """Detect the current pane ID running this guard watcher process."""
    env_pane = os.environ.get("HERDR_PANE") or os.environ.get("HERDR_PANE_ID")
    if env_pane:
        return env_pane.strip()
    return None
