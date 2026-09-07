"""Isolated AGY shell-wrapper identity workaround.

Herdr can briefly expose a live AGY process as top-level ``agent=shell`` while
its independently sourced display/session metadata still identifies AGY.  The
watcher may consult this module only after the normal AGY adapter has proved a
live permission dialog.  Removing this file therefore removes only the narrow
fallback; direct registered-agent discovery remains in the watcher.

The resolver is intentionally pure.  Process lookup is a separate fixed-argv,
bounded adapter so tests can prove that dialog recognition happens first.
"""

import json
import os

from adapters.herdr_client import run_cmd


TRUSTED_AGY_SESSION_SOURCE = "herdr:antigravity_cli"
PROCESS_INFO_MAX_CHARS = 65_536


def is_agy_shell_wrapper_candidate(pane_info):
    """Return whether raw metadata is the one supported hybrid AGY shape."""
    if not isinstance(pane_info, dict):
        return False
    top_level = pane_info.get("agent")
    if top_level not in (None, "", "shell", "unknown"):
        return False
    session = pane_info.get("agent_session")
    return (
        pane_info.get("display_agent") == "agy"
        and isinstance(session, dict)
        and session.get("agent") == "agy"
        and session.get("source") == TRUSTED_AGY_SESSION_SOURCE
    )


def get_pane_process_info(pane_id):
    """Read one bounded Herdr process-info envelope using fixed argv."""
    if not isinstance(pane_id, str) or not pane_id or "\x00" in pane_id:
        return None
    out = run_cmd(["herdr", "pane", "process-info", "--pane", pane_id])
    if not out or len(out) > PROCESS_INFO_MAX_CHARS:
        return None
    try:
        envelope = json.loads(out)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(envelope, dict):
        return None
    result = envelope.get("result")
    if not isinstance(result, dict) or result.get("type") != "pane_process_info":
        return None
    process_info = result.get("process_info")
    return process_info if isinstance(process_info, dict) else None


def _foreground_has_agy_executable(process_info):
    """Require an exact foreground argv executable basename, never display text."""
    if not isinstance(process_info, dict):
        return False
    processes = process_info.get("foreground_processes")
    if not isinstance(processes, list) or not processes:
        return False
    executable_candidates = []
    for process in processes:
        if not isinstance(process, dict):
            return False
        name = process.get("name")
        argv0 = process.get("argv0")
        argv = process.get("argv")
        if name is not None and not isinstance(name, str):
            return False
        if argv0 is not None and not isinstance(argv0, str):
            return False
        if argv is not None and not isinstance(argv, list):
            return False
        if isinstance(argv, list) and argv and not isinstance(argv[0], str):
            return False
        if name != "agy":
            continue
        if isinstance(argv0, str):
            executable_candidates.append(argv0)
        if isinstance(argv, list) and argv:
            executable_candidates.append(argv[0])
    return any(
        candidate
        and "\x00" not in candidate
        and os.path.basename(candidate) == "agy"
        for candidate in executable_candidates
    )


def resolve_agent_kind(pane_info, permission_dialog_live, process_info):
    """Resolve the supported hybrid payload to ``agy`` or fail closed to None."""
    if not permission_dialog_live or not is_agy_shell_wrapper_candidate(pane_info):
        return None
    return "agy" if _foreground_has_agy_executable(process_info) else None
