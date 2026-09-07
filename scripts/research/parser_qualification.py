#!/usr/bin/env python3
"""Run isolated tree-sitter-bash qualification and unbash differential evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import secrets
import select
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MAX_COMMAND_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 20 * 1024
REQUEST_TIMEOUT_SECONDS = 1.0
PRIMARY_REQUEST_TIMEOUT_SECONDS = 0.005
STARTUP_TIMEOUT_SECONDS = 1.0
REAPER_TERM_GRACE_SECONDS = 0.05
FORBIDDEN_RESPONSE_KEYS = {
    "raw_command",
    "argv",
    "literal",
    "source",
    "environment",
    "cwd",
    "pane",
    "model",
    "tool",
    "output",
}
FAILURE_CODES = {
    "HELPER_START_FAILED",
    "HELPER_TIMEOUT",
    "HELPER_CRASHED",
    "HELPER_PROTOCOL_FAILURE",
    "PARSER_EXCEPTION",
    "PARSER_RUNTIME_UNAVAILABLE",
    "PARSER_TIMEOUT",
    "ORACLE_EXCEPTION",
}
COUNT_FIELDS = {
    "command_count",
    "chain_count",
    "pipeline_count",
    "redirection_count",
    "substitution_count",
    "heredoc_count",
    "unknown_count",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_and_verify_lock(
    lock_path: Path,
    artifact_dir: Path,
    platform_id: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("schema_version") != 1 or not isinstance(lock.get("artifacts"), list):
        raise ValueError("invalid environment lock")
    if any(not isinstance(item, dict) for item in lock["artifacts"]):
        raise ValueError("invalid artifact record")
    selected = [item for item in lock["artifacts"] if item.get("platform") in {platform_id, "any"}]
    kinds = {item.get("kind") for item in selected}
    if kinds != {"python", "tree-sitter", "tree-sitter-bash", "node", "unbash"}:
        raise ValueError(f"incomplete artifact set for {platform_id}")
    verified = []
    for item in selected:
        if not isinstance(item, dict) or set(item) != {
            "kind", "version", "platform", "filename", "url", "sha256", "license", "provenance"
        }:
            raise ValueError("invalid artifact record")
        if (
            Path(item["filename"]).name != item["filename"]
            or len(item["sha256"]) != 64
            or any(char not in "0123456789abcdef" for char in item["sha256"])
            or not item["url"].startswith("https://")
        ):
            raise ValueError("unsafe artifact record")
        path = artifact_dir / item["filename"]
        if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
            raise ValueError(f"missing or unsafe artifact: {item['filename']}")
        actual = _sha256(path)
        if actual != item["sha256"]:
            raise ValueError(f"artifact hash mismatch: {item['filename']}")
        verified.append({key: item[key] for key in item if key != "url"} | {"hash_verified": True})
    return lock, verified


def _fixed_failure(request: dict[str, Any], engine: str, code: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "request_id": request["request_id"],
        "raw_sha256": request["raw_sha256"],
        "raw_byte_length": request["raw_byte_length"],
        "status": "UNMODELED_OR_INVALID",
        "completion_state": "invalid",
        "diagnostic_codes": [code],
        "parser_engine": engine,
        "parser_version": "unavailable",
        "structural_counts": {name: 0 for name in COUNT_FIELDS},
        "diagnostic_spans": [],
        "ir": {"schema_version": 1, "nodes": [], "node_count": 0},
    }


def _forbidden_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(key.lower() in FORBIDDEN_RESPONSE_KEYS or _forbidden_key(child) for key, child in value.items())
    if isinstance(value, list):
        return any(_forbidden_key(child) for child in value)
    return False


def validate_response(response: Any, request: dict[str, Any], engine: str) -> dict[str, Any]:
    if not isinstance(response, dict) or _forbidden_key(response):
        raise ValueError("unsafe response")
    required = {
        "schema_version", "request_id", "raw_sha256", "raw_byte_length", "status", "completion_state",
        "diagnostic_codes", "parser_engine", "parser_version", "structural_counts", "diagnostic_spans", "ir",
    }
    if not required <= set(response) or set(response) - required - {"parse_ns", "traversal_ns", "rss_kib"}:
        raise ValueError("invalid response fields")
    for key in ("request_id", "raw_sha256", "raw_byte_length"):
        if response.get(key) != request[key]:
            raise ValueError("response binding mismatch")
    if (
        response.get("schema_version") != 1
        or response.get("parser_engine") != engine
        or response.get("status") not in {"COMPLETE", "UNMODELED_OR_INVALID"}
        or response.get("completion_state") not in {"complete", "invalid"}
        or not isinstance(response.get("parser_version"), str)
    ):
        raise ValueError("invalid parser response")
    codes = response.get("diagnostic_codes")
    if (
        not isinstance(codes, list)
        or len(codes) > 32
        or any(
            not isinstance(code, str) or not code or len(code) > 64 or not code.replace("_", "").isalnum()
            for code in codes
        )
    ):
        raise ValueError("invalid diagnostics")
    counts = response.get("structural_counts")
    if (
        not isinstance(counts, dict)
        or set(counts) != COUNT_FIELDS
        or any(type(value) is not int or value < 0 for value in counts.values())
    ):
        raise ValueError("invalid structural counts")
    spans = response.get("diagnostic_spans")
    if not isinstance(spans, list) or len(spans) > 32:
        raise ValueError("invalid diagnostic spans")
    for span in spans:
        if not isinstance(span, dict) or set(span) != {"start_byte", "end_byte"}:
            raise ValueError("invalid diagnostic span")
        if not (type(span["start_byte"]) is int and type(span["end_byte"]) is int):
            raise ValueError("invalid diagnostic span")
        if not 0 <= span["start_byte"] <= span["end_byte"] <= request["raw_byte_length"]:
            raise ValueError("invalid diagnostic span")
    ir = response.get("ir")
    serialized_ir = (
        json.dumps(ir, sort_keys=True, separators=(",", ":")).encode("utf-8") if isinstance(ir, dict) else b""
    )
    if not isinstance(ir, dict) or len(serialized_ir) > 16 * 1024:
        raise ValueError("invalid IR envelope")
    nodes = ir.get("nodes")
    if (
        not isinstance(nodes, list)
        or len(nodes) > 4096
        or type(ir.get("node_count")) is not int
        or not 0 <= ir["node_count"] <= 4097
    ):
        raise ValueError("invalid IR nodes")
    for node in nodes:
        if not isinstance(node, dict) or set(node) != {"classification", "start_byte", "end_byte"}:
            raise ValueError("invalid IR node")
        if node["classification"] not in {
            "root",
            "command",
            "chain",
            "pipeline",
            "redirection",
            "substitution",
            "dynamic",
            "compound",
            "literal",
            "unknown",
        }:
            raise ValueError("open IR classification")
        if not (type(node["start_byte"]) is int and type(node["end_byte"]) is int):
            raise ValueError("invalid IR span")
        if not 0 <= node["start_byte"] <= node["end_byte"] <= request["raw_byte_length"]:
            raise ValueError("out-of-range IR span")
    return response


def _read_frame(stream: Any, deadline: float) -> bytes:
    """Read one bounded newline frame without letting partial output block."""
    frame = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("helper frame timeout")
        ready, _, _ = select.select([stream], [], [], remaining)
        if not ready:
            raise TimeoutError("helper frame timeout")
        chunk = os.read(stream.fileno(), MAX_RESPONSE_BYTES + 1 - len(frame))
        if not chunk:
            return bytes(frame)
        frame.extend(chunk)
        newline = frame.find(b"\n")
        if newline >= 0:
            if newline != len(frame) - 1:
                raise ValueError("multiple helper frames")
            return bytes(frame)
        if len(frame) > MAX_RESPONSE_BYTES:
            raise ValueError("oversized helper frame")


def _write_frame(stream: Any, frame: bytes, deadline: float) -> None:
    """Write one frame under the same deadline used for its response."""
    written = 0
    while written < len(frame):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("helper frame timeout")
        _, ready, _ = select.select([], [stream], [], remaining)
        if not ready:
            raise TimeoutError("helper frame timeout")
        written += os.write(stream.fileno(), frame[written:])


class FramedParser:
    """Persistent private child; a failed request is recorded and never retried."""

    def __init__(
        self,
        command: list[str],
        engine: str,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
        *,
        eager_ready: bool = False,
        startup_timeout: float = STARTUP_TIMEOUT_SECONDS,
        timeout_code: str = "HELPER_TIMEOUT",
    ):
        self.command = command
        self.engine = engine
        self.timeout = timeout
        self.eager_ready = eager_ready
        self.startup_timeout = startup_timeout
        self.timeout_code = timeout_code
        self.process: subprocess.Popen[bytes] | None = None
        self.cold_start_ms: float | None = None
        self._reapers: list[threading.Thread] = []

    @staticmethod
    def _environment() -> dict[str, str]:
        return {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONHASHSEED": "0", "PYTHONNOUSERSITE": "1"}

    def _start(self) -> None:
        started = time.monotonic_ns()
        self.process = subprocess.Popen(
            self.command,
            cwd=REPO_ROOT,
            env=self._environment(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            bufsize=0,
        )
        assert self.process.stdin is not None
        os.set_blocking(self.process.stdin.fileno(), False)
        if self.eager_ready:
            assert self.process.stdout is not None
            frame = _read_frame(self.process.stdout, time.monotonic() + self.startup_timeout)
            if len(frame) > MAX_RESPONSE_BYTES or not frame.endswith(b"\n"):
                raise ValueError("invalid helper readiness frame")
            startup = json.loads(frame)
            required = {"schema_version", "ready", "parser_engine", "parser_version"}
            if (
                not isinstance(startup, dict)
                or not required <= set(startup)
                or set(startup) - required - {"diagnostic_code"}
                or startup.get("schema_version") != 1
                or startup.get("parser_engine") != self.engine
                or type(startup.get("ready")) is not bool
                or not isinstance(startup.get("parser_version"), str)
            ):
                raise ValueError("invalid helper readiness envelope")
            if not startup["ready"]:
                code = startup.get("diagnostic_code")
                if code not in {"PARSER_RUNTIME_UNAVAILABLE", "PARSER_EXCEPTION"}:
                    raise ValueError("invalid helper startup diagnostic")
                raise ParserStartupError(code)
        if self.cold_start_ms is None:
            self.cold_start_ms = (time.monotonic_ns() - started) / 1_000_000

    @staticmethod
    def _kill_and_reap(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            # Every research helper starts a new session, so signalling pid as
            # pgid reaps only the exact helper and any descendants it created.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=REAPER_TERM_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def _stop(self) -> None:
        process, self.process = self.process, None
        if process is not None:
            self._kill_and_reap(process)

    def _detach_timed_out_process(self) -> None:
        """Return deadline outcomes without waiting for TERM-resistant code."""
        process, self.process = self.process, None
        if process is None:
            return
        self._reapers = [thread for thread in self._reapers if thread.is_alive()]
        reaper = threading.Thread(
            target=self._kill_and_reap,
            args=(process,),
            name="schengen-parser-reaper",
            daemon=True,
        )
        self._reapers.append(reaper)
        reaper.start()

    def wait_for_reapers(self) -> None:
        for reaper in self._reapers:
            reaper.join()
        self._reapers.clear()

    def close(self) -> None:
        self._stop()
        self.wait_for_reapers()

    def request(self, raw_command: str) -> dict[str, Any]:
        raw = raw_command.encode("utf-8")
        request = {
            "schema_version": 1,
            "request_id": secrets.token_hex(16),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "raw_byte_length": len(raw),
            "raw_command": raw_command,
        }
        if len(raw) > MAX_COMMAND_BYTES:
            return _fixed_failure(request, self.engine, "INPUT_TOO_LARGE")
        was_cold = self.process is None
        if was_cold:
            try:
                self._start()
            except ParserStartupError as error:
                self._stop()
                return _fixed_failure(request, self.engine, error.code)
            except (OSError, TimeoutError, ValueError, json.JSONDecodeError):
                self._stop()
                return _fixed_failure(request, self.engine, "HELPER_START_FAILED")
        try:
            assert self.process is not None and self.process.stdin is not None and self.process.stdout is not None
            deadline = time.monotonic() + self.timeout
            frame = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
            try:
                _write_frame(self.process.stdin, frame, deadline)
                response_frame = _read_frame(self.process.stdout, deadline)
            except TimeoutError:
                self._detach_timed_out_process()
                return _fixed_failure(request, self.engine, self.timeout_code)
            if not response_frame:
                self._stop()
                return _fixed_failure(request, self.engine, "HELPER_CRASHED")
            if len(response_frame) > MAX_RESPONSE_BYTES or not response_frame.endswith(b"\n"):
                raise ValueError("oversized response")
            response = validate_response(json.loads(response_frame), request, self.engine)
        except (BrokenPipeError, UnicodeDecodeError, json.JSONDecodeError, OSError, ValueError):
            self._stop()
            return _fixed_failure(request, self.engine, "HELPER_PROTOCOL_FAILURE")
        return response


class ParserStartupError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def materialize_case(case: dict[str, Any]) -> str:
    if "command" in case:
        return case["command"]
    generator = case.get("generator", {})
    kind = generator.get("kind")
    size = generator.get("value")
    if kind == "utf8_bytes":
        prefix = "printf "
        return prefix + "x" * (size - len(prefix.encode("utf-8")))
    if kind == "nested_substitution":
        return "$(" * size + "printf x" + ")" * size
    raise ValueError(f"unknown corpus generator for {case.get('id')}")


def _summary(response: dict[str, Any]) -> dict[str, Any]:
    return {
        key: response.get(key)
        for key in (
            "status", "completion_state", "diagnostic_codes", "parser_engine", "parser_version",
            "structural_counts", "diagnostic_spans", "parse_ns", "traversal_ns", "ir",
        )
    }


def _without_timing(response: dict[str, Any]) -> dict[str, Any]:
    result = _summary(response)
    result.pop("parse_ns", None)
    result.pop("traversal_ns", None)
    return result


def compare_results(primary: dict[str, Any], oracle: dict[str, Any]) -> list[str]:
    disagreements = []
    if primary.get("completion_state") != oracle.get("completion_state"):
        disagreements.append("completion")
    primary_errors = any("ERROR" in code or "FAILURE" in code for code in primary.get("diagnostic_codes", []))
    oracle_errors = any("ERROR" in code or "FAILURE" in code for code in oracle.get("diagnostic_codes", []))
    if primary_errors != oracle_errors:
        disagreements.append("error")
    primary_spans = [
        (node.get("start_byte"), node.get("end_byte")) for node in primary.get("ir", {}).get("nodes", [])
    ]
    oracle_spans = [
        (node.get("start_byte"), node.get("end_byte")) for node in oracle.get("ir", {}).get("nodes", [])
    ]
    if primary_spans != oracle_spans or primary.get("diagnostic_spans") != oracle.get("diagnostic_spans"):
        disagreements.append("span")
    if ("DYNAMIC_SYNTAX" in primary.get("diagnostic_codes", [])) != (
        "DYNAMIC_SYNTAX" in oracle.get("diagnostic_codes", [])
    ):
        disagreements.append("dynamic")
    if primary.get("status") != oracle.get("status"):
        disagreements.append("status")
    if primary.get("structural_counts") != oracle.get("structural_counts") or primary.get("ir") != oracle.get("ir"):
        disagreements.append("ir")
    for label, result in (("primary", primary), ("oracle", oracle)):
        codes = result.get("diagnostic_codes", [])
        if any(code in {"HELPER_TIMEOUT", "HELPER_CRASHED"} for code in codes):
            disagreements.append(f"{label}_timeout_or_crash")
        parser_failures = {
            "HELPER_PROTOCOL_FAILURE",
            "HELPER_START_FAILED",
            "PARSER_EXCEPTION",
            "PARSER_RUNTIME_UNAVAILABLE",
            "PARSER_TIMEOUT",
            "ORACLE_EXCEPTION",
        }
        if any(code in parser_failures for code in codes):
            disagreements.append(f"{label}_parser_or_protocol_failure")
    return disagreements


def compare_expected(expected: dict[str, Any], result: dict[str, Any], label: str) -> list[str]:
    findings = []
    codes = result.get("diagnostic_codes", [])
    syntax_valid = not any(
        code in {"PARSE_ERROR", "MISSING_NODE", "INCOMPLETE_CONSUMPTION", "UNKNOWN_NODE"} for code in codes
    )
    if "valid" in expected and syntax_valid != expected["valid"]:
        findings.append(f"{label}_expected_validity")
    if "dynamic" in expected and ("DYNAMIC_SYNTAX" in codes) != expected["dynamic"]:
        findings.append(f"{label}_expected_dynamic")
    if expected.get("over_input_cap") and "INPUT_TOO_LARGE" not in codes:
        findings.append(f"{label}_expected_input_cap")
    return findings


def percentile(values: list[int], quantile: float) -> int:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(quantile * len(ordered)) - 1)]


def _is_parse_budget_miss(response: dict[str, Any]) -> bool:
    return any(
        code in {"PARSE_BUDGET_EXCEEDED", "PARSER_TIMEOUT"}
        for code in response.get("diagnostic_codes", [])
    )


def _failure_report_counts(failures: dict[str, int]) -> dict[str, int]:
    return {
        "failure_count": sum(failures.values()),
        "crash_or_timeout_count": sum(
            count
            for code, count in failures.items()
            if code in {"HELPER_CRASHED", "HELPER_TIMEOUT", "PARSER_TIMEOUT"}
        ),
    }


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
        stream.write("\n")


def run_qualification(args: argparse.Namespace) -> dict[str, Path]:
    lock, verified = load_and_verify_lock(args.lock, args.artifact_dir, args.platform)
    corpus = json.loads(args.corpus.read_text(encoding="utf-8"))
    if corpus.get("schema_version") != 1 or not isinstance(corpus.get("cases"), list):
        raise ValueError("invalid corpus")
    primary = FramedParser(
        [str(args.python), "-I", str(REPO_ROOT / "scripts/cmd/schengen_parser_helper.py"), "--qualification"],
        "tree-sitter-bash",
        timeout=PRIMARY_REQUEST_TIMEOUT_SECONDS,
        eager_ready=True,
        timeout_code="PARSER_TIMEOUT",
    )
    oracle = FramedParser(
        [str(args.node), str(REPO_ROOT / "scripts/research/unbash_oracle.mjs"), "--module", str(args.unbash_module)],
        "unbash",
    )
    case_results = []
    corpus_failures: dict[str, int] = {}
    threshold_misses = 0
    try:
        for case in corpus["cases"]:
            command = materialize_case(case)
            first = primary.request(command)
            threshold_misses += int(_is_parse_budget_miss(first))
            for code in first.get("diagnostic_codes", []):
                if code in FAILURE_CODES:
                    corpus_failures[code] = corpus_failures.get(code, 0) + 1
            deterministic = False
            if not any(code in FAILURE_CODES for code in first["diagnostic_codes"]):
                second = primary.request(command)
                threshold_misses += int(_is_parse_budget_miss(second))
                for code in second.get("diagnostic_codes", []):
                    if code in FAILURE_CODES:
                        corpus_failures[code] = corpus_failures.get(code, 0) + 1
                deterministic = _without_timing(first) == _without_timing(second)
            oracle_result = oracle.request(command)
            for code in oracle_result.get("diagnostic_codes", []):
                if code in FAILURE_CODES:
                    corpus_failures[code] = corpus_failures.get(code, 0) + 1
            marker_results = []
            for marker in case.get("span_markers", []):
                raw = command.encode("utf-8")
                marker_raw = marker.encode("utf-8")
                start = raw.find(marker_raw)
                spans = {(node["start_byte"], node["end_byte"]) for node in first.get("ir", {}).get("nodes", [])}
                marker_results.append(start >= 0 and (start, start + len(marker_raw)) in spans)
            disagreements = compare_results(first, oracle_result)
            disagreements.extend(compare_expected(case.get("expected", {}), first, "primary"))
            disagreements.extend(compare_expected(case.get("expected", {}), oracle_result, "oracle"))
            case_results.append({
                "case_id": case["id"],
                "expected": case.get("expected", {}),
                "deterministic": deterministic,
                "span_markers_round_trip": marker_results,
                "primary": _summary(first),
                "oracle": _summary(oracle_result),
                "disagreements": disagreements,
            })

        benchmark_command = materialize_case(next(case for case in corpus["cases"] if case["id"] == "benchmark_static"))
        parse_samples = []
        traversal_samples = []
        benchmark_failures: dict[str, int] = {}
        rss_start = None
        rss_end = None
        for _ in range(args.iterations):
            response = primary.request(benchmark_command)
            for code in response.get("diagnostic_codes", []):
                if code in FAILURE_CODES:
                    benchmark_failures[code] = benchmark_failures.get(code, 0) + 1
            if type(response.get("parse_ns")) is int:
                parse_samples.append(response["parse_ns"])
            if type(response.get("traversal_ns")) is int:
                traversal_samples.append(response["traversal_ns"])
            threshold_misses += int(_is_parse_budget_miss(response))
            if type(response.get("rss_kib")) is int:
                rss_start = response["rss_kib"] if rss_start is None else rss_start
                rss_end = response["rss_kib"]
    finally:
        primary.close()
        oracle.close()

    def metrics(values: list[int]) -> dict[str, Any]:
        return {
            "samples": len(values),
            "p50_ns": percentile(values, 0.50) if values else None,
            "p95_ns": percentile(values, 0.95) if values else None,
            "p99_ns": percentile(values, 0.99) if values else None,
            "max_ns": max(values) if values else None,
        }

    failures = dict(corpus_failures)
    for code, count in benchmark_failures.items():
        failures[code] = failures.get(code, 0) + count
    platform_report = {
        "schema_version": 1,
        "platform": args.platform,
        "observed_system": platform.system(),
        "observed_machine": platform.machine(),
        "iterations": args.iterations,
        "cold_start_ms": primary.cold_start_ms,
        "deadline": {
            "mode": "eager-ready-parent-supervised",
            "detection_ms": int(PRIMARY_REQUEST_TIMEOUT_SECONDS * 1000),
            "includes": "framing-and-ipc",
            "cleanup_wait_before_outcome": False,
            "reaper_term_grace_ms": int(REAPER_TERM_GRACE_SECONDS * 1000),
            "native_progress_callback_used": False,
        },
        "parse": metrics(parse_samples),
        "traversal": metrics(traversal_samples),
        "threshold_misses": threshold_misses,
        "helper_failures": failures,
        "rss_delta_kib": None if rss_start is None or rss_end is None else max(0, rss_end - rss_start),
    }
    corpus_report = {"schema_version": 1, "platform": args.platform, "cases": case_results}
    provenance_report = {
        "schema_version": 1,
        "lock_sha256": _sha256(args.lock),
        "verified_platform_artifacts": verified,
        "inventory": [{key: item[key] for key in item if key != "url"} for item in lock["artifacts"]],
        "known_native_timeout_findings": [
            {
                "platform": "macos-arm64",
                "tree_sitter_version": "0.26.0",
                "mechanism": "progress_callback",
                "result": "SIGSEGV_EXIT_139",
                "adoption": "forbidden-for-pinned-pair",
            }
        ],
    }
    findings = sorted({finding for case in case_results for finding in case["disagreements"]})
    findings.append("native_progress_callback_sigsegv_macos_arm64")
    failure_counts = _failure_report_counts(failures)
    decision_report = {
        "schema_version": 1,
        "platform": args.platform,
        "evidence_state": "COMPLETE" if len(parse_samples) == args.iterations else "INCOMPLETE",
        "adoption_authorized": False,
        "live_shadow_authorized": False,
        "policy_effect": "none",
        "findings": findings,
        "all_ir_deterministic": all(case["deterministic"] for case in case_results),
        "all_marked_spans_round_trip": all(
            all(case["span_markers_round_trip"]) for case in case_results if case["span_markers_round_trip"]
        ),
        "parse_budget_met": threshold_misses == 0,
        "traversal_budget_met": all(value <= 5_000_000 for value in traversal_samples),
        **failure_counts,
    }
    outputs = {
        "platform": args.output_dir / f"{args.platform}.platform.json",
        "corpus": args.output_dir / f"{args.platform}.corpus.json",
        "provenance": args.output_dir / f"{args.platform}.provenance.json",
        "decision": args.output_dir / f"{args.platform}.decision.json",
    }
    for name, report in (
        ("platform", platform_report), ("corpus", corpus_report),
        ("provenance", provenance_report), ("decision", decision_report),
    ):
        _write_json(outputs[name], report)
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=REPO_ROOT / "research/parser-qualification/environment.lock.json")
    parser.add_argument("--corpus", type=Path, default=REPO_ROOT / "tests/fixtures/parser_qualification_cases.json")
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--platform", choices=("macos-arm64", "linux-x86_64"), required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--unbash-module", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=10_000)
    args = parser.parse_args(argv)
    if args.iterations < 10_000:
        parser.error("--iterations must be at least 10000")
    outputs = run_qualification(args)
    for name, path in outputs.items():
        print(f"{name}_report={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
