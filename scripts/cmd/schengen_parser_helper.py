#!/usr/bin/env python3
"""Stage-1 private parser-shadow helper and isolated qualification route.

The default Stage-1 path intentionally does not import or execute a native
parser. It only validates the bounded transport envelope and reports that the
parser is unavailable/not qualified. The explicit ``--qualification`` route
is for the offline, hash-pinned research harness only; the installed watcher
never uses it.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
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
MAX_NODES = 4096
MAX_DEPTH = 64
MAX_DIAGNOSTICS = 32
MAX_IR_BYTES = 16 * 1024
PARSE_BUDGET_NS = 5_000_000
TRAVERSAL_BUDGET_NS = 5_000_000
_COUNT_FIELDS = (
    "command_count",
    "chain_count",
    "pipeline_count",
    "redirection_count",
    "substitution_count",
    "heredoc_count",
    "unknown_count",
)

_NODE_CLASSIFICATIONS = {
    "program": "root",
    "command": "command",
    "declaration_command": "command",
    "unset_command": "command",
    "negated_command": "command",
    "test_command": "command",
    "list": "chain",
    "pipeline": "pipeline",
    "redirected_statement": "redirection",
    "file_redirect": "redirection",
    "heredoc_redirect": "redirection",
    "herestring_redirect": "redirection",
    "command_substitution": "substitution",
    "process_substitution": "substitution",
    "arithmetic_expansion": "substitution",
    "simple_expansion": "dynamic",
    "expansion": "dynamic",
    "variable_assignment": "dynamic",
    "variable_assignments": "dynamic",
    "subscript": "dynamic",
    "brace_expression": "dynamic",
    "extglob_pattern": "dynamic",
    "array": "dynamic",
    "for_statement": "compound",
    "c_style_for_statement": "compound",
    "while_statement": "compound",
    "do_group": "compound",
    "if_statement": "compound",
    "elif_clause": "compound",
    "else_clause": "compound",
    "case_statement": "compound",
    "case_item": "compound",
    "function_definition": "compound",
    "compound_statement": "compound",
    "subshell": "compound",
    "unary_expression": "compound",
    "binary_expression": "compound",
    "postfix_expression": "compound",
    "parenthesized_expression": "compound",
    "ternary_expression": "compound",
    "concatenation": "compound",
    "word": "literal",
    "number": "literal",
    "string_content": "literal",
    "raw_string": "literal",
    "ansi_c_string": "literal",
    "regex": "literal",
    "comment": "literal",
    "variable_name": "literal",
    "special_variable_name": "literal",
    "heredoc_start": "literal",
    "heredoc_body": "literal",
    "heredoc_content": "literal",
    "heredoc_end": "literal",
    "file_descriptor": "literal",
    "test_operator": "literal",
    "command_name": "literal",
    "string": "literal",
    "translated_string": "literal",
}
_DYNAMIC_CLASSIFICATIONS = {"dynamic", "substitution"}


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
    response = {
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
    return response


def _validated_request(request: Any) -> tuple[str, bytes]:
    """Reuse the Stage-1 envelope checks without changing its response."""
    handle_request(request)
    return request["raw_command"], request["raw_command"].encode("utf-8")


def _diagnostic(code: str, node: Any | None = None) -> dict[str, Any]:
    item = {"code": code}
    if node is not None:
        item.update({"start_byte": node.start_byte, "end_byte": node.end_byte})
    return item


def _bounded_ir(root: Any, raw_byte_length: int) -> tuple[dict[str, Any], list[dict[str, Any]], bool, bool]:
    """Create a text-free, deterministic IR from named tree-sitter nodes."""
    started = time.monotonic_ns()
    stack = [(root, 0)]
    nodes = []
    diagnostics = []
    counts = {name: 0 for name in _COUNT_FIELDS}
    visited = 0
    dynamic = False
    bounded = False

    while stack:
        if time.monotonic_ns() - started > TRAVERSAL_BUDGET_NS:
            diagnostics.append(_diagnostic("TRAVERSAL_BUDGET_EXCEEDED"))
            bounded = True
            break
        node, depth = stack.pop()
        visited += 1
        if visited > MAX_NODES:
            diagnostics.append(_diagnostic("NODE_LIMIT_EXCEEDED", node))
            bounded = True
            break
        if depth > MAX_DEPTH:
            diagnostics.append(_diagnostic("DEPTH_LIMIT_EXCEEDED", node))
            bounded = True
            break
        if node.start_byte < 0 or node.end_byte < node.start_byte or node.end_byte > raw_byte_length:
            diagnostics.append(_diagnostic("INVALID_SOURCE_SPAN"))
            bounded = True
            break
        invalid_node = node.type == "ERROR" or node.is_missing
        if invalid_node:
            diagnostics.append(_diagnostic("PARSE_ERROR" if node.type == "ERROR" else "MISSING_NODE", node))
        if node.is_named and not invalid_node:
            classification = _NODE_CLASSIFICATIONS.get(node.type)
            if classification is None:
                classification = "unknown"
                counts["unknown_count"] += 1
                diagnostics.append(_diagnostic("UNKNOWN_NODE", node))
            nodes.append({"classification": classification, "start_byte": node.start_byte, "end_byte": node.end_byte})
            dynamic = dynamic or classification in _DYNAMIC_CLASSIFICATIONS
            if classification == "command":
                counts["command_count"] += 1
            elif classification == "chain":
                counts["chain_count"] += 1
            elif classification == "pipeline":
                counts["pipeline_count"] += 1
            elif classification == "redirection":
                counts["redirection_count"] += 1
            elif classification == "substitution":
                counts["substitution_count"] += 1
            if node.type == "heredoc_redirect":
                counts["heredoc_count"] += 1
        if len(diagnostics) >= MAX_DIAGNOSTICS:
            diagnostics = diagnostics[:MAX_DIAGNOSTICS]
            bounded = True
            break
        children = node.children
        stack.extend((child, depth + 1) for child in reversed(children))

    ir = {"schema_version": 1, "nodes": nodes, "node_count": visited}
    if len(json.dumps(ir, sort_keys=True, separators=(",", ":")).encode("ascii")) > MAX_IR_BYTES:
        diagnostics.append(_diagnostic("IR_SERIALIZED_LIMIT_EXCEEDED"))
        ir = {"schema_version": 1, "nodes": [], "node_count": visited}
        bounded = True
    return (
        {"ir": ir, "structural_counts": counts, "traversal_ns": time.monotonic_ns() - started},
        diagnostics,
        dynamic,
        bounded,
    )


_QUALIFICATION_PARSER: tuple[Any, str] | None = None


def _qualification_parser() -> tuple[Any, str]:
    global _QUALIFICATION_PARSER
    if _QUALIFICATION_PARSER is None:
        from tree_sitter import Language, Parser  # pyright: ignore[reportMissingImports]

        import tree_sitter_bash  # pyright: ignore[reportMissingImports]

        _QUALIFICATION_PARSER = (
            Parser(Language(tree_sitter_bash.language())),
            importlib.metadata.version("tree-sitter-bash"),
        )
    return _QUALIFICATION_PARSER


def _qualification_startup_response() -> dict[str, Any]:
    """Construct the native parser before declaring the research child ready."""
    try:
        _, parser_version = _qualification_parser()
    except ImportError:
        return {
            "schema_version": PROTOCOL_VERSION,
            "ready": False,
            "parser_engine": "tree-sitter-bash",
            "parser_version": "unavailable",
            "diagnostic_code": "PARSER_RUNTIME_UNAVAILABLE",
        }
    except Exception:
        return {
            "schema_version": PROTOCOL_VERSION,
            "ready": False,
            "parser_engine": "tree-sitter-bash",
            "parser_version": "unavailable",
            "diagnostic_code": "PARSER_EXCEPTION",
        }
    return {
        "schema_version": PROTOCOL_VERSION,
        "ready": True,
        "parser_engine": "tree-sitter-bash",
        "parser_version": parser_version,
    }


def handle_qualification_request(
    request: Any,
    parser: Any | None = None,
    parser_version: str | None = None,
) -> dict[str, Any]:
    """Parse one synthetic research input; never called by the live watcher."""
    _, raw_bytes = _validated_request(request)
    if parser is None:
        parser, parser_version = _qualification_parser()
    assert parser is not None

    parse_started = time.monotonic_ns()
    tree = parser.parse(raw_bytes)
    parse_ns = time.monotonic_ns() - parse_started
    built, diagnostics, dynamic, bounded = _bounded_ir(tree.root_node, len(raw_bytes))
    if parse_ns > PARSE_BUDGET_NS:
        diagnostics.append(_diagnostic("PARSE_BUDGET_EXCEEDED"))
    if tree.root_node.start_byte != 0 or tree.root_node.end_byte != len(raw_bytes):
        diagnostics.append(_diagnostic("INCOMPLETE_CONSUMPTION", tree.root_node))
    if tree.root_node.has_error and not any(item["code"] in {"PARSE_ERROR", "MISSING_NODE"} for item in diagnostics):
        diagnostics.append(_diagnostic("PARSE_ERROR", tree.root_node))
    if dynamic:
        diagnostics.append(_diagnostic("DYNAMIC_SYNTAX"))
    codes = [item["code"] for item in diagnostics]
    invalid = bool(codes) or tree.root_node.has_error or bounded
    response = {
        "schema_version": PROTOCOL_VERSION,
        "request_id": request["request_id"],
        "raw_sha256": request["raw_sha256"],
        "raw_byte_length": request["raw_byte_length"],
        "status": "UNMODELED_OR_INVALID" if invalid else "COMPLETE",
        "completion_state": "invalid" if invalid else "complete",
        "diagnostic_codes": codes[:MAX_DIAGNOSTICS],
        "parser_engine": "tree-sitter-bash",
        "parser_version": parser_version or "unknown",
        "structural_counts": built["structural_counts"],
        "diagnostic_spans": [
            {"start_byte": item["start_byte"], "end_byte": item["end_byte"]}
            for item in diagnostics[:MAX_DIAGNOSTICS]
            if "start_byte" in item
        ],
        "parse_ns": parse_ns,
        "traversal_ns": built["traversal_ns"],
        "ir": built["ir"],
    }
    try:
        import resource

        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        response["rss_kib"] = int(rss / 1024) if sys.platform == "darwin" else int(rss)
    except (ImportError, OSError):
        pass
    return response


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


def _qualification_error_response(request: Any, code: str) -> dict[str, Any]:
    response = _error_response(request)
    response.update(
        {
            "completion_state": "invalid",
            "diagnostic_codes": [code],
            "parser_engine": "tree-sitter-bash",
            "ir": {"schema_version": 1, "nodes": [], "node_count": 0},
        }
    )
    return response


def _exit_when_parent_changes(initial_ppid: int) -> None:
    """Prevent a wedged future parser from surviving its Gatekeeper parent."""
    while True:
        time.sleep(0.1)
        if os.getppid() != initial_ppid:
            os._exit(0)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv not in ([], ["--qualification"]):
        return 2
    handler = handle_qualification_request if argv else handle_request
    watchdog = threading.Thread(
        target=_exit_when_parent_changes,
        args=(os.getppid(),),
        name="schengen-parser-parent-watchdog",
        daemon=True,
    )
    watchdog.start()
    if argv:
        startup = _qualification_startup_response()
        payload = json.dumps(startup, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
        try:
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.flush()
        except BrokenPipeError:
            return 0
        if not startup["ready"]:
            return 0
    while True:
        frame = sys.stdin.buffer.readline(MAX_FRAME_BYTES + 1)
        if not frame:
            return 0
        request: Any = None
        try:
            if len(frame) > MAX_FRAME_BYTES or not frame.endswith(b"\n"):
                raise ValueError("oversized frame")
            request = json.loads(frame.decode("utf-8"))
            response = handler(request)
        except ImportError:
            response = (
                _qualification_error_response(request, "PARSER_RUNTIME_UNAVAILABLE")
                if argv
                else _error_response(request)
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            response = _error_response(request)
        except Exception:
            if not argv:
                raise
            response = _qualification_error_response(request, "PARSER_EXCEPTION")
        payload = json.dumps(response, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
        try:
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.flush()
        except BrokenPipeError:
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
