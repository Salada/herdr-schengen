#!/usr/bin/env python3
"""Stage-1 private parser-shadow helper.

This process intentionally does not import or execute a native parser.  It
only validates the bounded transport envelope and reports that the parser is
unavailable/not qualified.  A later research package must explicitly provide
and qualify the parser runtime before this helper can emit COMPLETE results.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import threading
import time
from typing import Any


PROTOCOL_VERSION = 1
MAX_COMMAND_BYTES = 64 * 1024
MAX_FRAME_BYTES = MAX_COMMAND_BYTES + 4096
_COUNT_FIELDS = (
    "command_count",
    "chain_count",
    "pipeline_count",
    "redirection_count",
    "substitution_count",
    "heredoc_count",
    "unknown_count",
)


def _valid_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(char in "0123456789abcdef" for char in value)


def handle_request(request: Any) -> dict[str, Any]:
    """Validate one frame and return metadata without loading native code."""
    if not isinstance(request, dict) or set(request) != {
        "schema_version",
        "request_id",
        "raw_sha256",
        "raw_byte_length",
        "raw_command",
    }:
        raise ValueError("invalid request envelope")
    if request["schema_version"] != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol")
    if not _valid_hex(request["request_id"], 32) or not _valid_hex(request["raw_sha256"], 64):
        raise ValueError("invalid binding")
    raw_command = request["raw_command"]
    if not isinstance(raw_command, str) or type(request["raw_byte_length"]) is not int:
        raise ValueError("invalid command shape")
    raw_bytes = raw_command.encode("utf-8")
    if len(raw_bytes) > MAX_COMMAND_BYTES:
        raise ValueError("command too large")
    if len(raw_bytes) != request["raw_byte_length"] or hashlib.sha256(raw_bytes).hexdigest() != request["raw_sha256"]:
        raise ValueError("binding mismatch")

    # find_spec is intentionally the strongest Stage-1 probe: native modules
    # are never imported into this child until a later qualification decision.
    available = (
        importlib.util.find_spec("tree_sitter") is not None
        and importlib.util.find_spec("tree_sitter_bash") is not None
    )
    diagnostic = "PARSER_STAGE1_NOT_QUALIFIED" if available else "PARSER_UNAVAILABLE"
    return {
        "schema_version": PROTOCOL_VERSION,
        "request_id": request["request_id"],
        "raw_sha256": request["raw_sha256"],
        "raw_byte_length": request["raw_byte_length"],
        "status": "UNMODELED_OR_INVALID",
        "completion_state": "unavailable",
        "diagnostic_codes": [diagnostic],
        "parser_engine": "none",
        "parser_version": "unavailable",
        "structural_counts": {name: 0 for name in _COUNT_FIELDS},
        "diagnostic_spans": [],
    }


def _error_response(request: Any) -> dict[str, Any]:
    request = request if isinstance(request, dict) else {}
    request_id = request.get("request_id", "")
    raw_sha256 = request.get("raw_sha256", "")
    raw_byte_length = request.get("raw_byte_length", 0)
    return {
        "schema_version": PROTOCOL_VERSION,
        "request_id": request_id if _valid_hex(request_id, 32) else "",
        "raw_sha256": raw_sha256 if _valid_hex(raw_sha256, 64) else "",
        "raw_byte_length": raw_byte_length
        if type(raw_byte_length) is int and 0 <= raw_byte_length <= MAX_COMMAND_BYTES
        else 0,
        "status": "UNMODELED_OR_INVALID",
        "completion_state": "malformed",
        "diagnostic_codes": ["PROTOCOL_MISMATCH"],
        "parser_engine": "none",
        "parser_version": "unavailable",
        "structural_counts": {name: 0 for name in _COUNT_FIELDS},
        "diagnostic_spans": [],
    }


def _exit_when_parent_changes(initial_ppid: int) -> None:
    """Prevent a wedged future parser from surviving its Gatekeeper parent."""
    while True:
        time.sleep(0.1)
        if os.getppid() != initial_ppid:
            os._exit(0)


def main() -> int:
    watchdog = threading.Thread(
        target=_exit_when_parent_changes,
        args=(os.getppid(),),
        name="schengen-parser-parent-watchdog",
        daemon=True,
    )
    watchdog.start()
    while True:
        frame = sys.stdin.buffer.readline(MAX_FRAME_BYTES + 1)
        if not frame:
            return 0
        request: Any = None
        try:
            if len(frame) > MAX_FRAME_BYTES or not frame.endswith(b"\n"):
                raise ValueError("oversized frame")
            request = json.loads(frame.decode("utf-8"))
            response = handle_request(request)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            response = _error_response(request)
        payload = json.dumps(response, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
        try:
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.flush()
        except BrokenPipeError:
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
