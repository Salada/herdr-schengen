import hashlib
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from cmd.schengen_parser_helper import handle_request
from cmd.schengen_watcher import observe_parser_shadow
from core.parser_shadow import (
    DEFAULT_LOG_BYTES,
    DEFAULT_LOG_FILES,
    MAX_COMMAND_BYTES,
    ParserHelperClient,
    ParserShadow,
    RotatingShadowWriter,
    parser_shadow_enabled,
)


class _CapturingWriter:
    def __init__(self):
        self.records = []
        self.condition = threading.Condition()

    def write(self, record):
        with self.condition:
            self.records.append(dict(record))
            self.condition.notify_all()
        return True

    def wait_for_count(self, count, timeout=1.0):
        with self.condition:
            return self.condition.wait_for(lambda: len(self.records) >= count, timeout)


class _UnavailableClient:
    def __init__(self):
        self.calls = []
        self.closed = False

    def request(self, raw_command, raw_sha256, raw_byte_length):
        self.calls.append((raw_command, raw_sha256, raw_byte_length))
        return {
            "status": "UNMODELED_OR_INVALID",
            "completion_state": "unavailable",
            "diagnostic_codes": ["PARSER_UNAVAILABLE"],
            "parser_engine": "none",
            "parser_version": "unavailable",
            "duration_ms": 0.125,
            "diagnostic_spans": [],
            "structural_counts": {
                "command_count": 0,
                "chain_count": 0,
                "pipeline_count": 0,
                "redirection_count": 0,
                "substitution_count": 0,
                "heredoc_count": 0,
                "unknown_count": 0,
            },
        }

    def close(self):
        self.closed = True


class ParserShadowFlagTests(unittest.TestCase):
    def test_only_exact_ascii_one_enables(self):
        self.assertTrue(parser_shadow_enabled({"SCHENGEN_PARSER_SHADOW": "1"}))
        for value in (None, "", "0", "true", "TRUE", " 1", "1 ", "01", "１"):
            env = {} if value is None else {"SCHENGEN_PARSER_SHADOW": value}
            self.assertFalse(parser_shadow_enabled(env), value)

    def test_off_performs_zero_worker_client_or_write(self):
        calls = []
        writer = _CapturingWriter()

        def factory():
            calls.append("spawn")
            return _UnavailableClient()

        shadow = ParserShadow.from_environment({}, writer=writer, client_factory=factory)
        shadow.observe("echo should-not-run", is_safe=True, decision_layer="FAST_TRACK_AST")
        shadow.close()
        self.assertFalse(shadow.worker_started)
        self.assertEqual(calls, [])
        self.assertEqual(writer.records, [])


class ParserHelperProtocolTests(unittest.TestCase):
    @staticmethod
    def _request(command="printf ok"):
        raw = command.encode("utf-8")
        return {
            "schema_version": 1,
            "request_id": "a" * 32,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "raw_byte_length": len(raw),
            "raw_command": command,
        }

    def test_stage1_helper_binds_hash_and_length_without_returning_raw(self):
        request = self._request("printf super-secret-marker")
        response = handle_request(request)
        self.assertEqual(response["request_id"], request["request_id"])
        self.assertEqual(response["raw_sha256"], request["raw_sha256"])
        self.assertEqual(response["raw_byte_length"], request["raw_byte_length"])
        self.assertEqual(response["status"], "UNMODELED_OR_INVALID")
        self.assertEqual(response["diagnostic_spans"], [])
        self.assertIn(
            response["diagnostic_codes"][0],
            {"PARSER_UNAVAILABLE", "PARSER_STAGE1_NOT_QUALIFIED"},
        )
        self.assertNotIn("raw_command", response)
        self.assertNotIn("super-secret-marker", json.dumps(response))

    def test_absent_native_modules_report_parser_unavailable(self):
        with patch("cmd.schengen_parser_helper.importlib.util.find_spec", return_value=None):
            response = handle_request(self._request())
        self.assertEqual(response["diagnostic_codes"], ["PARSER_UNAVAILABLE"])
        self.assertEqual(response["parser_engine"], "none")

    def test_stage1_helper_rejects_bad_binding_and_oversize(self):
        mismatched = self._request()
        mismatched["raw_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            handle_request(mismatched)
        with self.assertRaises(ValueError):
            handle_request(self._request("x" * (MAX_COMMAND_BYTES + 1)))

    def test_real_private_child_is_persistent_and_unqualified(self):
        client = ParserHelperClient(timeout_seconds=1.0)
        process = None
        try:
            first_raw = b"echo one"
            first = client.request("echo one", hashlib.sha256(first_raw).hexdigest(), len(first_raw))
            self.assertEqual(first["status"], "UNMODELED_OR_INVALID")
            self.assertIn(
                first["diagnostic_codes"][0],
                {"PARSER_UNAVAILABLE", "PARSER_STAGE1_NOT_QUALIFIED"},
            )
            pid = client._process.pid
            process = client._process
            second_raw = b"echo two"
            second = client.request("echo two", hashlib.sha256(second_raw).hexdigest(), len(second_raw))
            self.assertEqual(second["status"], "UNMODELED_OR_INVALID")
            self.assertEqual(client._process.pid, pid)
        finally:
            client.close()
        self.assertIsNotNone(process)
        self.assertIsNotNone(process.poll())

    def test_timeout_crash_and_malformed_output_are_structured(self):
        cases = (
            ([sys.executable, "-c", "import time; time.sleep(2)"], "HELPER_TIMEOUT"),
            ([sys.executable, "-c", "import os; os._exit(3)"], "HELPER_CRASHED"),
            ([sys.executable, "-c", "print('not-json', flush=True)"], "HELPER_MALFORMED_RESPONSE"),
            (
                [
                    sys.executable,
                    "-c",
                    "import sys,json;r=json.loads(sys.stdin.readline());r.pop('raw_command');r['status']=[];print(json.dumps(r),flush=True)",
                ],
                "HELPER_MALFORMED_RESPONSE",
            ),
        )
        raw = b"echo bounded"
        for command, expected in cases:
            with self.subTest(expected=expected):
                client = ParserHelperClient(command, timeout_seconds=0.1)
                try:
                    result = client.request("echo bounded", hashlib.sha256(raw).hexdigest(), len(raw))
                finally:
                    client.close()
                self.assertEqual(result["status"], "UNMODELED_OR_INVALID")
                self.assertEqual(result["diagnostic_codes"], [expected])

    def test_dead_helper_is_restarted_on_next_request(self):
        starts = []

        def tracked_popen(*args, **kwargs):
            import subprocess

            starts.append(True)
            return subprocess.Popen(*args, **kwargs)

        client = ParserHelperClient(
            [sys.executable, "-c", "import os; os._exit(3)"],
            timeout_seconds=0.2,
            popen_factory=tracked_popen,
        )
        raw = b"echo bounded"
        try:
            for _ in range(2):
                result = client.request("echo bounded", hashlib.sha256(raw).hexdigest(), len(raw))
                self.assertEqual(result["diagnostic_codes"], ["HELPER_CRASHED"])
        finally:
            client.close()
        self.assertEqual(len(starts), 2)

    def test_child_receives_minimal_scrubbed_environment(self):
        environment = ParserHelperClient._minimal_environment()
        self.assertEqual(set(environment), {"LANG", "LC_ALL", "PYTHONHASHSEED", "PYTHONNOUSERSITE"})
        for forbidden in ("HOME", "PATH", "OPENAI_API_KEY", "HTTP_PROXY", "AWS_SECRET_ACCESS_KEY"):
            self.assertNotIn(forbidden, environment)


class ParserShadowObserverTests(unittest.TestCase):
    def test_on_records_only_bounded_metadata_after_decision(self):
        writer = _CapturingWriter()
        clients = []

        def factory():
            client = _UnavailableClient()
            clients.append(client)
            return client

        raw_command = "printf super-secret-marker"
        shadow = ParserShadow(
            True,
            writer=writer,
            client_factory=factory,
            source_revision="89f14d207c8ef91a9dd4e96eb959dd5a55c1e27e",
        )
        shadow.observe(raw_command, is_safe=False, decision_layer="NOT_ALLOWLISTED")
        self.assertTrue(writer.wait_for_count(1))
        shadow.close()

        self.assertEqual(len(clients), 1)
        self.assertTrue(clients[0].closed)
        self.assertEqual(len(writer.records), 1)
        record = writer.records[0]
        self.assertEqual(
            set(record),
            {
                "schema_version",
                "event",
                "recorded_at",
                "source_revision",
                "raw_sha256",
                "raw_byte_length",
                "raw_decision",
                "raw_decision_layer",
                "status",
                "completion_state",
                "diagnostic_codes",
                "parser_engine",
                "parser_version",
                "helper_protocol_version",
                "duration_ms",
                "structural_counts",
                "diagnostic_spans",
                "input_truncated",
                "helper_failed",
            },
        )
        self.assertEqual(record["raw_sha256"], hashlib.sha256(raw_command.encode()).hexdigest())
        self.assertEqual(record["raw_byte_length"], len(raw_command.encode()))
        self.assertEqual(record["raw_decision"], "UNSAFE")
        self.assertEqual(record["raw_decision_layer"], "NOT_ALLOWLISTED")
        self.assertEqual(record["diagnostic_codes"], ["PARSER_UNAVAILABLE"])
        serialized = json.dumps(record, sort_keys=True)
        for forbidden in ("super-secret-marker", "raw_command", "argv", "cwd", "pane", "model", "tool"):
            self.assertNotIn(forbidden, serialized)

    def test_truncated_and_oversize_inputs_do_not_start_helper(self):
        writer = _CapturingWriter()
        calls = []

        def factory():
            calls.append("client")
            return _UnavailableClient()

        shadow = ParserShadow(True, writer=writer, client_factory=factory, source_revision="a" * 40)
        shadow.observe("partial", is_safe=False, decision_layer="NORMALIZATION_AMBIGUOUS", input_truncated=True)
        shadow.observe("x" * (MAX_COMMAND_BYTES + 1), is_safe=False, decision_layer="NOT_ALLOWLISTED")
        self.assertTrue(writer.wait_for_count(2))
        shadow.close()
        self.assertEqual(calls, [])
        self.assertEqual(len(writer.records), 2)
        codes = {record["diagnostic_codes"][0] for record in writer.records}
        self.assertEqual(codes, {"INPUT_TRUNCATED", "INPUT_TOO_LARGE"})

    def test_watcher_wrapper_returns_exact_raw_result_when_observer_fails(self):
        class BrokenObserver:
            def observe(self, *args, **kwargs):
                raise RuntimeError("shadow failure must be ignored")

        result = (False, "unchanged reason", "NOT_ALLOWLISTED", {"origin": "A"})
        returned = observe_parser_shadow(BrokenObserver(), "echo hi", result)
        self.assertIs(returned, result)

    def test_client_factory_failure_is_recorded_without_escaping(self):
        writer = _CapturingWriter()

        def broken_factory():
            raise OSError("no helper")

        shadow = ParserShadow(
            True,
            writer=writer,
            client_factory=broken_factory,
            source_revision="a" * 40,
        )
        shadow.observe("echo hi", is_safe=True, decision_layer="FAST_TRACK_AST")
        self.assertTrue(writer.wait_for_count(1))
        shadow.close()
        self.assertEqual(writer.records[0]["diagnostic_codes"], ["HELPER_START_FAILED"])
        self.assertTrue(writer.records[0]["helper_failed"])


class RotatingShadowWriterTests(unittest.TestCase):
    def test_defaults_are_ten_mibibytes_times_five(self):
        self.assertEqual(DEFAULT_LOG_BYTES, 10 * 1024 * 1024)
        self.assertEqual(DEFAULT_LOG_FILES, 5)

    def test_rotates_bounded_mode_0600_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "shadow" / "events.jsonl"
            writer = RotatingShadowWriter(path, max_bytes=128, max_files=3)
            for number in range(8):
                self.assertTrue(writer.write({"number": number, "padding": "x" * 72}))
            files = sorted(path.parent.glob("events.jsonl*"))
            self.assertEqual(len(files), 3)
            for candidate in files:
                self.assertLessEqual(candidate.stat().st_size, 128)
                self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o600)

    def test_process_local_lock_keeps_concurrent_records_one_line(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "shadow" / "events.jsonl"
            writer = RotatingShadowWriter(path, max_bytes=64 * 1024, max_files=2)
            results = []
            result_lock = threading.Lock()

            def write(number):
                outcome = writer.write({"number": number, "event": "parser_shadow"})
                with result_lock:
                    results.append(outcome)

            threads = [threading.Thread(target=write, args=(number,)) for number in range(32)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(results, [True] * 32)
            lines = path.read_text(encoding="ascii").splitlines()
            self.assertEqual(len(lines), 32)
            self.assertEqual({json.loads(line)["number"] for line in lines}, set(range(32)))

    def test_symlink_and_peer_writable_file_fail_to_no_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            target = directory / "target"
            target.write_text("unchanged", encoding="utf-8")
            link = directory / "events.jsonl"
            link.symlink_to(target)
            self.assertFalse(RotatingShadowWriter(link).write({"event": "parser_shadow"}))
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")

            unsafe = directory / "unsafe.jsonl"
            unsafe.write_text("unchanged", encoding="utf-8")
            unsafe.chmod(0o666)
            self.assertFalse(RotatingShadowWriter(unsafe).write({"event": "parser_shadow"}))
            self.assertEqual(unsafe.read_text(encoding="utf-8"), "unchanged")

    def test_wrong_owner_and_peer_writable_directory_fail_to_no_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "shadow"
            directory.mkdir()
            path = directory / "events.jsonl"
            with patch("core.parser_shadow.os.getuid", return_value=os.getuid() + 1):
                self.assertFalse(RotatingShadowWriter(path).write({"event": "parser_shadow"}))
            self.assertFalse(path.exists())

            directory.chmod(0o777)
            self.assertFalse(RotatingShadowWriter(path).write({"event": "parser_shadow"}))
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
