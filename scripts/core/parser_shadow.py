"""Default-off, metadata-only structural parser shadow transport.

Stage 1 deliberately contains no native parser.  It proves that a private,
parent-owned helper can be supervised and observed without changing the raw
command decision path.  Parser output is never an execution or approval
target, and full structural IR is never persisted.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import select
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

from core.runtime_provenance import get_source_revision


FLAG_NAME = "SCHENGEN_PARSER_SHADOW"
PROTOCOL_VERSION = 1
RECORD_SCHEMA_VERSION = 1
MAX_COMMAND_BYTES = 64 * 1024
MAX_FRAME_BYTES = MAX_COMMAND_BYTES + 4096
MAX_RESPONSE_BYTES = 16 * 1024
MAX_RECORD_BYTES = 4096
DEFAULT_TIMEOUT_SECONDS = 0.25
DEFAULT_QUEUE_SIZE = 128
DEFAULT_LOG_BYTES = 10 * 1024 * 1024
DEFAULT_LOG_FILES = 5
DEFAULT_LOG_PATH = (
    Path.home() / ".local" / "state" / "herdr-schengen" / "parser-shadow" / "events.jsonl"
)

_STATUS = frozenset({"COMPLETE", "UNMODELED_OR_INVALID"})
_DIAGNOSTICS = frozenset(
    {
        "PARSER_UNAVAILABLE",
        "PARSER_STAGE1_NOT_QUALIFIED",
        "INPUT_TOO_LARGE",
        "INPUT_TRUNCATED",
        "HELPER_START_FAILED",
        "HELPER_TIMEOUT",
        "HELPER_CRASHED",
        "HELPER_IO_ERROR",
        "HELPER_MALFORMED_RESPONSE",
        "PROTOCOL_MISMATCH",
    }
)
_COMPLETION_STATES = frozenset(
    {"complete", "unavailable", "truncated", "timeout", "crashed", "malformed", "io_error"}
)
_DECISION_LAYERS = frozenset(
    {
        "ALLOWLIST",
        "MANAGED_GIT_GUARD",
        "SAST_SHELLCHECK",
        "SAST_SEMGREP",
        "SHELL_CRITICAL",
        "SANDBOX_GUARD",
        "PYTHON_AST",
        "SECRET_GUARD",
        "LLM_INSPECTOR",
        "CLOUD_JUDGE",
        "GRAY_ZONE_MATRIX",
        "FAST_TRACK_AST",
        "NOT_ALLOWLISTED",
        "HUMAN_APPROVED",
        "PACKAGE_GUARD",
        "COMPLEXITY_TAX",
        "ORIGIN_GUARD",
        "NORMALIZATION_AMBIGUOUS",
        "FAST_TRACK_WORKSPACE_ALLOWLIST",
        "OPENCODE_FAILSAFE",
    }
)
_COUNT_FIELDS = (
    "command_count",
    "chain_count",
    "pipeline_count",
    "redirection_count",
    "substitution_count",
    "heredoc_count",
    "unknown_count",
)


def parser_shadow_enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    """Return true only for the exact trusted-operator startup value ``1``."""
    source = os.environ if env is None else env
    return source.get(FLAG_NAME) == "1"


def _safe_revision(value: Any) -> str:
    candidate = str(value or "")
    if 7 <= len(candidate) <= 64 and all(char in "0123456789abcdef" for char in candidate.lower()):
        return candidate.lower()
    return "unknown"


def _safe_layer(value: Any) -> str:
    candidate = value.value if hasattr(value, "value") else str(value or "")
    if not isinstance(candidate, str):
        return "unknown"
    return candidate if candidate in _DECISION_LAYERS else "unknown"


def _failure(code: str, completion_state: str, duration_ms: float = 0.0) -> dict[str, Any]:
    return {
        "status": "UNMODELED_OR_INVALID",
        "completion_state": completion_state if completion_state in _COMPLETION_STATES else "malformed",
        "diagnostic_codes": [code if code in _DIAGNOSTICS else "HELPER_MALFORMED_RESPONSE"],
        "parser_engine": "none",
        "parser_version": "unavailable",
        "duration_ms": max(0.0, round(float(duration_ms), 3)),
        "structural_counts": {name: 0 for name in _COUNT_FIELDS},
        "diagnostic_spans": [],
    }


def _validate_response(response: Any, request: Mapping[str, Any], duration_ms: float) -> dict[str, Any]:
    if not isinstance(response, dict):
        return _failure("HELPER_MALFORMED_RESPONSE", "malformed", duration_ms)
    if response.get("schema_version") != PROTOCOL_VERSION:
        return _failure("PROTOCOL_MISMATCH", "malformed", duration_ms)
    for name in ("request_id", "raw_sha256", "raw_byte_length"):
        if response.get(name) != request.get(name):
            return _failure("PROTOCOL_MISMATCH", "malformed", duration_ms)

    status = response.get("status")
    completion_state = response.get("completion_state")
    codes = response.get("diagnostic_codes")
    counts = response.get("structural_counts")
    spans = response.get("diagnostic_spans")
    if not isinstance(status, str) or status not in _STATUS:
        return _failure("HELPER_MALFORMED_RESPONSE", "malformed", duration_ms)
    if not isinstance(completion_state, str) or completion_state not in _COMPLETION_STATES:
        return _failure("HELPER_MALFORMED_RESPONSE", "malformed", duration_ms)
    if not isinstance(codes, list) or any(
        not isinstance(code, str) or code not in _DIAGNOSTICS for code in codes
    ):
        return _failure("HELPER_MALFORMED_RESPONSE", "malformed", duration_ms)
    if status == "UNMODELED_OR_INVALID" and not codes:
        return _failure("HELPER_MALFORMED_RESPONSE", "malformed", duration_ms)
    if not isinstance(counts, dict) or set(counts) != set(_COUNT_FIELDS):
        return _failure("HELPER_MALFORMED_RESPONSE", "malformed", duration_ms)
    if spans != []:
        # Stage 1 has no parser and therefore cannot truthfully emit spans.
        return _failure("HELPER_MALFORMED_RESPONSE", "malformed", duration_ms)
    if any(type(counts[name]) is not int or counts[name] < 0 for name in _COUNT_FIELDS):
        return _failure("HELPER_MALFORMED_RESPONSE", "malformed", duration_ms)
    engine = response.get("parser_engine")
    version = response.get("parser_version")
    if not isinstance(engine, str) or engine not in {"none", "tree-sitter-bash"}:
        return _failure("HELPER_MALFORMED_RESPONSE", "malformed", duration_ms)
    if not isinstance(version, str) or len(version) > 64:
        return _failure("HELPER_MALFORMED_RESPONSE", "malformed", duration_ms)
    return {
        "status": status,
        "completion_state": completion_state,
        "diagnostic_codes": list(codes[:8]),
        "parser_engine": engine,
        "parser_version": version,
        "duration_ms": max(0.0, round(float(duration_ms), 3)),
        "structural_counts": {name: counts[name] for name in _COUNT_FIELDS},
        "diagnostic_spans": [],
    }


class ParserHelperClient:
    """One bounded line-framed client for a lazily spawned private child."""

    def __init__(
        self,
        command: Optional[Sequence[str]] = None,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        popen_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
    ) -> None:
        helper = Path(__file__).resolve().parents[1] / "cmd" / "schengen_parser_helper.py"
        self.command = list(command or (sys.executable, "-I", str(helper)))
        self.timeout_seconds = max(0.01, float(timeout_seconds))
        self._popen_factory = popen_factory
        self._process: Optional[subprocess.Popen] = None
        self._read_buffer = b""

    @staticmethod
    def _minimal_environment() -> dict[str, str]:
        return {"LANG": "C", "LC_ALL": "C", "PYTHONHASHSEED": "0", "PYTHONNOUSERSITE": "1"}

    def _start(self) -> bool:
        if self._process is not None and self._process.poll() is None:
            return True
        self.close()
        try:
            self._process = self._popen_factory(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self._minimal_environment(),
                bufsize=0,
                close_fds=True,
            )
        except (OSError, ValueError):
            self._process = None
            return False
        if self._process.stdin is None or self._process.stdout is None:
            self.close()
            return False
        return True

    def _write_all(self, payload: bytes, deadline: float) -> None:
        if self._process is None or self._process.stdin is None:
            raise BrokenPipeError
        fd = self._process.stdin.fileno()
        view = memoryview(payload)
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            _, writable, _ = select.select([], [fd], [], remaining)
            if not writable:
                raise TimeoutError
            written = os.write(fd, view[:4096])
            if written <= 0:
                raise BrokenPipeError
            view = view[written:]

    def _read_line(self, deadline: float) -> bytes:
        if self._process is None or self._process.stdout is None:
            raise BrokenPipeError
        fd = self._process.stdout.fileno()
        while b"\n" not in self._read_buffer:
            if len(self._read_buffer) > MAX_RESPONSE_BYTES:
                raise ValueError("oversized response")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                raise TimeoutError
            chunk = os.read(fd, 4096)
            if not chunk:
                raise BrokenPipeError
            self._read_buffer += chunk
        line, self._read_buffer = self._read_buffer.split(b"\n", 1)
        if len(line) > MAX_RESPONSE_BYTES:
            raise ValueError("oversized response")
        return line

    def request(self, raw_command: str, raw_sha256: str, raw_byte_length: int) -> dict[str, Any]:
        request = {
            "schema_version": PROTOCOL_VERSION,
            "request_id": uuid.uuid4().hex,
            "raw_sha256": raw_sha256,
            "raw_byte_length": raw_byte_length,
            "raw_command": raw_command,
        }
        payload = (json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        if raw_byte_length > MAX_COMMAND_BYTES or len(payload) > MAX_FRAME_BYTES:
            return _failure("INPUT_TOO_LARGE", "truncated")
        started = time.monotonic()
        if not self._start():
            return _failure("HELPER_START_FAILED", "crashed")
        deadline = started + self.timeout_seconds
        try:
            self._write_all(payload, deadline)
            line = self._read_line(deadline)
            response = json.loads(line.decode("utf-8"))
        except TimeoutError:
            self.close()
            return _failure("HELPER_TIMEOUT", "timeout", (time.monotonic() - started) * 1000)
        except (BrokenPipeError, OSError):
            self.close()
            return _failure("HELPER_CRASHED", "crashed", (time.monotonic() - started) * 1000)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self.close()
            return _failure("HELPER_MALFORMED_RESPONSE", "malformed", (time.monotonic() - started) * 1000)
        return _validate_response(response, request, (time.monotonic() - started) * 1000)

    def close(self) -> None:
        process, self._process = self._process, None
        self._read_buffer = b""
        if process is None:
            return
        if process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=0.1)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                    process.wait(timeout=0.1)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        for stream in (process.stdin, process.stdout):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass


def _validate_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise OSError("unsafe log directory")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
        raise OSError("unsafe log directory")


def _validate_existing_file(path: Path) -> Optional[os.stat_result]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise OSError("unsafe log file")
    if before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600:
        raise OSError("unsafe log file")
    return before


class RotatingShadowWriter:
    """Process-local locked, fail-to-no-record JSONL writer."""

    def __init__(
        self,
        path: Path = DEFAULT_LOG_PATH,
        *,
        max_bytes: int = DEFAULT_LOG_BYTES,
        max_files: int = DEFAULT_LOG_FILES,
    ) -> None:
        self.path = Path(path)
        self.max_bytes = max(1, int(max_bytes))
        self.max_files = max(1, int(max_files))
        self._lock = threading.Lock()

    def _rotated(self, index: int) -> Path:
        return self.path.with_name(f"{self.path.name}.{index}")

    def _rotate(self) -> None:
        candidates = [self.path] + [self._rotated(index) for index in range(1, self.max_files)]
        for candidate in candidates:
            _validate_existing_file(candidate)
        oldest = self._rotated(self.max_files - 1)
        if self.max_files > 1 and oldest.exists():
            oldest.unlink()
        for index in range(self.max_files - 2, 0, -1):
            source = self._rotated(index)
            if source.exists():
                os.replace(source, self._rotated(index + 1))
        if self.max_files > 1 and self.path.exists():
            os.replace(self.path, self._rotated(1))
        elif self.max_files == 1 and self.path.exists():
            self.path.unlink()

    def _open_append(self) -> int:
        before = _validate_existing_file(self.path)
        flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        if before is None:
            fd = os.open(self.path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            os.fchmod(fd, 0o600)
        else:
            fd = os.open(self.path, flags)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) != 0o600:
            os.close(fd)
            raise OSError("unsafe log file")
        if before is not None and (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            os.close(fd)
            raise OSError("log file changed while opening")
        return fd

    def write(self, record: Mapping[str, Any]) -> bool:
        try:
            line = (json.dumps(dict(record), sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode(
                "ascii"
            )
        except (TypeError, ValueError, UnicodeEncodeError):
            return False
        if len(line) > MAX_RECORD_BYTES or len(line) > self.max_bytes:
            return False
        with self._lock:
            try:
                _validate_directory(self.path.parent)
                current = _validate_existing_file(self.path)
                if current is not None and current.st_size + len(line) > self.max_bytes:
                    self._rotate()
                fd = self._open_append()
                try:
                    original_size = os.fstat(fd).st_size
                    try:
                        written = os.write(fd, line)
                    except OSError:
                        try:
                            os.ftruncate(fd, original_size)
                        except OSError:
                            pass
                        raise
                    if written != len(line):
                        os.ftruncate(fd, original_size)
                        return False
                finally:
                    os.close(fd)
            except OSError:
                return False
        return True


@dataclass(frozen=True)
class _ShadowTask:
    raw_command: str
    raw_sha256: str
    raw_byte_length: int
    decision: str
    decision_layer: str
    input_truncated: bool


class ParserShadow:
    """Non-blocking observer that owns one helper for the Gatekeeper parent."""

    def __init__(
        self,
        enabled: bool,
        *,
        writer: Optional[RotatingShadowWriter] = None,
        client_factory: Callable[[], ParserHelperClient] = ParserHelperClient,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        source_revision: Optional[str] = None,
    ) -> None:
        self.enabled = bool(enabled)
        self.writer = writer or RotatingShadowWriter()
        self._client_factory = client_factory
        self._queue: queue.Queue = queue.Queue(maxsize=max(1, int(queue_size)))
        self._source_revision = (
            _safe_revision(source_revision or get_source_revision()) if self.enabled else "unknown"
        )
        self._start_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.dropped_records = 0

    @classmethod
    def from_environment(cls, env: Optional[Mapping[str, str]] = None, **kwargs: Any) -> "ParserShadow":
        return cls(parser_shadow_enabled(env), **kwargs)

    @property
    def worker_started(self) -> bool:
        return self._thread is not None

    def _ensure_worker(self) -> None:
        if self._thread is not None:
            return
        with self._start_lock:
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name="schengen-parser-shadow", daemon=True)
                self._thread.start()

    def observe(
        self,
        raw_command: str,
        *,
        is_safe: bool,
        decision_layer: Any,
        input_truncated: bool = False,
    ) -> None:
        if not self.enabled or self._stop.is_set() or not isinstance(raw_command, str):
            return
        raw_bytes = raw_command.encode("utf-8")
        task = _ShadowTask(
            raw_command=raw_command,
            raw_sha256=hashlib.sha256(raw_bytes).hexdigest(),
            raw_byte_length=len(raw_bytes),
            decision="SAFE" if is_safe else "UNSAFE",
            decision_layer=_safe_layer(decision_layer),
            input_truncated=bool(input_truncated),
        )
        self._ensure_worker()
        try:
            self._queue.put_nowait(task)
        except queue.Full:
            self.dropped_records += 1

    def _record(self, task: _ShadowTask, result: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema_version": RECORD_SCHEMA_VERSION,
            "event": "parser_shadow",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "source_revision": self._source_revision,
            "raw_sha256": task.raw_sha256,
            "raw_byte_length": task.raw_byte_length,
            "raw_decision": task.decision,
            "raw_decision_layer": task.decision_layer,
            "status": result["status"],
            "completion_state": result["completion_state"],
            "diagnostic_codes": list(result["diagnostic_codes"]),
            "parser_engine": result["parser_engine"],
            "parser_version": result["parser_version"],
            "helper_protocol_version": PROTOCOL_VERSION,
            "duration_ms": result["duration_ms"],
            "structural_counts": dict(result["structural_counts"]),
            "diagnostic_spans": list(result["diagnostic_spans"]),
            "input_truncated": task.input_truncated or result["completion_state"] == "truncated",
            "helper_failed": any(code.startswith("HELPER_") for code in result["diagnostic_codes"]),
        }

    def _run(self) -> None:
        client: Optional[ParserHelperClient] = None
        try:
            while not self._stop.is_set():
                try:
                    task = self._queue.get(timeout=0.05)
                except queue.Empty:
                    continue
                try:
                    if task.input_truncated:
                        result = _failure("INPUT_TRUNCATED", "truncated")
                    elif task.raw_byte_length > MAX_COMMAND_BYTES:
                        result = _failure("INPUT_TOO_LARGE", "truncated")
                    else:
                        result = _failure("HELPER_START_FAILED", "crashed")
                        if client is None:
                            try:
                                client = self._client_factory()
                            except Exception:
                                client = None
                        if client is not None:
                            try:
                                result = client.request(
                                    task.raw_command,
                                    task.raw_sha256,
                                    task.raw_byte_length,
                                )
                            except Exception:
                                result = _failure("HELPER_IO_ERROR", "io_error")
                                try:
                                    client.close()
                                except Exception:
                                    pass
                                client = None
                    self.writer.write(self._record(task, result))
                except Exception:
                    # Shadow work is deliberately unable to affect adjudication.
                    pass
                finally:
                    self._queue.task_done()
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass

    def close(self, timeout: float = 1.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=max(0.0, float(timeout)))
