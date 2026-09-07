import hashlib
import json
import os
import select
import signal
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from cmd.schengen_parser_helper import (  # pyright: ignore[reportMissingImports]
    MAX_DEPTH,
    MAX_NODES,
    _qualification_startup_response,
    handle_qualification_request,
    handle_request,
    main,
)
from research.parser_qualification import (  # pyright: ignore[reportMissingImports]
    FORBIDDEN_RESPONSE_KEYS,
    FAILURE_CODES,
    FramedParser,
    _failure_report_counts,
    _is_parse_budget_miss,
    _write_json,
    compare_results,
    load_and_verify_lock,
    materialize_case,
    validate_response,
)


def request(command="printf x"):
    raw = command.encode("utf-8")
    return {
        "schema_version": 1,
        "request_id": "a" * 32,
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_byte_length": len(raw),
        "raw_command": command,
    }


class FakeNode:
    def __init__(self, kind, start, end, children=(), *, named=True, missing=False, error=False):
        self.type = kind
        self.start_byte = start
        self.end_byte = end
        self.children = list(children)
        self.is_named = named
        self.is_missing = missing
        self.has_error = error or any(child.has_error for child in self.children)


class FakeTree:
    def __init__(self, root):
        self.root_node = root


class FakeParser:
    def __init__(self, root):
        self.root = root
        self.inputs = []

    def parse(self, raw, **_kwargs):
        if callable(raw):
            raw = raw(0, None)
        self.inputs.append(raw)
        return FakeTree(self.root)


class QualificationHelperTests(unittest.TestCase):
    def test_default_stage1_stays_unqualified_and_cli_is_explicit(self):
        with patch("cmd.schengen_parser_helper.importlib.util.find_spec", return_value=None):
            response = handle_request(request())
        self.assertEqual(response["diagnostic_codes"], ["PARSER_UNAVAILABLE"])
        self.assertEqual(response["parser_engine"], "none")
        self.assertEqual(main(["--not-qualified"]), 2)

    def test_readiness_is_emitted_only_after_parser_construction(self):
        parser = object()
        with patch("cmd.schengen_parser_helper._qualification_parser", return_value=(parser, "test")):
            self.assertEqual(
                _qualification_startup_response(),
                {
                    "schema_version": 1,
                    "ready": True,
                    "parser_engine": "tree-sitter-bash",
                    "parser_version": "test",
                },
            )
        with patch("cmd.schengen_parser_helper._qualification_parser", side_effect=ImportError):
            unavailable = _qualification_startup_response()
        self.assertFalse(unavailable["ready"])
        self.assertEqual(unavailable["diagnostic_code"], "PARSER_RUNTIME_UNAVAILABLE")

    def test_static_ir_is_bounded_source_mapped_and_contains_no_text(self):
        raw = "printf 한글"
        raw_bytes = raw.encode("utf-8")
        marker_start = raw_bytes.index("한글".encode("utf-8"))
        marker = FakeNode("word", marker_start, len(raw_bytes))
        command = FakeNode("command", 0, len(raw_bytes), [marker])
        parser = FakeParser(FakeNode("program", 0, len(raw_bytes), [command]))
        response = handle_qualification_request(request(raw), parser=parser, parser_version="test")
        self.assertEqual(response["status"], "COMPLETE")
        self.assertEqual(parser.inputs, [raw_bytes])
        self.assertIn(
            {"classification": "literal", "start_byte": marker_start, "end_byte": len(raw_bytes)},
            response["ir"]["nodes"],
        )
        serialized = json.dumps(response, sort_keys=True)
        self.assertNotIn("한글", serialized)
        self.assertNotIn("raw_command", serialized)

    def test_dynamic_unknown_error_and_incomplete_inputs_never_complete(self):
        cases = (
            (FakeNode("simple_expansion", 0, 1), "DYNAMIC_SYNTAX"),
            (FakeNode("future_grammar_node", 0, 1), "UNKNOWN_NODE"),
            (FakeNode("ERROR", 0, 1, error=True), "PARSE_ERROR"),
            (FakeNode("program", 0, 0), "INCOMPLETE_CONSUMPTION"),
        )
        for root, code in cases:
            with self.subTest(code=code):
                response = handle_qualification_request(request("x"), parser=FakeParser(root), parser_version="test")
                self.assertEqual(response["status"], "UNMODELED_OR_INVALID")
                self.assertIn(code, response["diagnostic_codes"])

    def test_depth_and_node_caps_fail_closed(self):
        root = FakeNode("program", 0, 1)
        current = root
        for _ in range(MAX_DEPTH + 1):
            child = FakeNode("program", 0, 1)
            current.children = [child]
            current = child
        with patch("cmd.schengen_parser_helper.time.monotonic_ns", return_value=0):
            response = handle_qualification_request(request("x"), parser=FakeParser(root), parser_version="test")
        self.assertIn("DEPTH_LIMIT_EXCEEDED", response["diagnostic_codes"])

        many = [FakeNode("word", 0, 1) for _ in range(MAX_NODES)]
        with patch("cmd.schengen_parser_helper.time.monotonic_ns", return_value=0):
            response = handle_qualification_request(
                request("x"), parser=FakeParser(FakeNode("program", 0, 1, many)), parser_version="test"
            )
        self.assertIn("NODE_LIMIT_EXCEEDED", response["diagnostic_codes"])


class QualificationHarnessTests(unittest.TestCase):
    def test_lock_requires_complete_hash_verified_platform_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = []
            for kind in ("python", "tree-sitter", "tree-sitter-bash", "node", "unbash"):
                path = root / f"{kind}.bin"
                path.write_bytes(kind.encode("ascii"))
                artifacts.append(
                    {
                        "kind": kind,
                        "version": "1",
                        "platform": "any" if kind == "unbash" else "macos-arm64",
                        "filename": path.name,
                        "url": f"https://example.invalid/{path.name}",
                        "sha256": hashlib.sha256(kind.encode("ascii")).hexdigest(),
                        "license": "test",
                        "provenance": "test fixture",
                    }
                )
            lock = root / "lock.json"
            lock.write_text(json.dumps({"schema_version": 1, "artifacts": artifacts}), encoding="utf-8")
            _, verified = load_and_verify_lock(lock, root, "macos-arm64")
            self.assertEqual(len(verified), 5)
            self.assertTrue(all(item["hash_verified"] for item in verified))
            (root / "node.bin").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                load_and_verify_lock(lock, root, "macos-arm64")
            artifacts[0]["filename"] = "../outside"
            lock.write_text(json.dumps({"schema_version": 1, "artifacts": artifacts}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsafe artifact"):
                load_and_verify_lock(lock, root, "macos-arm64")

    def test_response_validation_rejects_text_and_binding_changes(self):
        envelope = request()
        base = {
            "schema_version": 1,
            "request_id": envelope["request_id"],
            "raw_sha256": envelope["raw_sha256"],
            "raw_byte_length": envelope["raw_byte_length"],
            "status": "COMPLETE",
            "completion_state": "complete",
            "diagnostic_codes": [],
            "parser_engine": "tree-sitter-bash",
            "parser_version": "test",
            "structural_counts": {
                "command_count": 0,
                "chain_count": 0,
                "pipeline_count": 0,
                "redirection_count": 0,
                "substitution_count": 0,
                "heredoc_count": 0,
                "unknown_count": 0,
            },
            "diagnostic_spans": [],
            "ir": {"schema_version": 1, "nodes": [], "node_count": 0},
        }
        self.assertIs(validate_response(base, envelope, "tree-sitter-bash"), base)
        for forbidden in FORBIDDEN_RESPONSE_KEYS:
            with self.subTest(forbidden=forbidden):
                invalid = dict(base)
                invalid[forbidden] = "secret"
                with self.assertRaisesRegex(ValueError, "unsafe response"):
                    validate_response(invalid, envelope, "tree-sitter-bash")
        invalid = dict(base, raw_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            validate_response(invalid, envelope, "tree-sitter-bash")

    def test_oversize_input_returns_without_spawning(self):
        parser = FramedParser(["must-not-run"], "tree-sitter-bash")
        with patch.object(parser, "_start", side_effect=AssertionError("spawned")):
            response = parser.request("x" * (64 * 1024 + 1))
        self.assertEqual(response["diagnostic_codes"], ["INPUT_TOO_LARGE"])

    def test_helper_start_failure_is_structured(self):
        for error in (FileNotFoundError(), PermissionError()):
            with self.subTest(error=type(error).__name__):
                parser = FramedParser(["must-not-run"], "tree-sitter-bash")
                with patch.object(parser, "_start", side_effect=error):
                    response = parser.request("printf x")
                self.assertEqual(response["diagnostic_codes"], ["HELPER_START_FAILED"])
                self.assertEqual(set(response["structural_counts"]), {
                    "command_count", "chain_count", "pipeline_count", "redirection_count",
                    "substitution_count", "heredoc_count", "unknown_count",
                })

    def test_qualification_route_without_research_modules_is_structured(self):
        parser = FramedParser(
            [sys.executable, "-I", "-S", str(REPO_ROOT / "scripts/cmd/schengen_parser_helper.py"), "--qualification"],
            "tree-sitter-bash",
            eager_ready=True,
        )
        try:
            response = parser.request("printf x")
        finally:
            parser.close()
        self.assertEqual(response["status"], "UNMODELED_OR_INVALID")
        self.assertEqual(response["diagnostic_codes"], ["PARSER_RUNTIME_UNAVAILABLE"])

    def test_eager_ready_deadline_kills_and_restarts_without_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = root / "child.py"
            state = root / "state"
            received = root / "received"
            child.write_text(
                "import hashlib,json,os,signal,sys\n"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                "print(json.dumps({'schema_version':1,'ready':True,'parser_engine':'tree-sitter-bash',"
                "'parser_version':'test'}),flush=True)\n"
                "r=json.loads(sys.stdin.readline())\n"
                "with open(sys.argv[2],'a') as f: f.write(r['request_id']+'\\n')\n"
                "if not os.path.exists(sys.argv[1]):\n"
                " open(sys.argv[1],'w').write('timed-out')\n"
                " signal.pause()\n"
                "raw=r.pop('raw_command').encode()\n"
                "r.update(status='COMPLETE',completion_state='complete',diagnostic_codes=[],"
                "parser_engine='tree-sitter-bash',parser_version='test',"
                "structural_counts={k:0 for k in ('command_count','chain_count','pipeline_count',"
                "'redirection_count','substitution_count','heredoc_count','unknown_count')},"
                "diagnostic_spans=[],ir={'schema_version':1,'nodes':[],'node_count':0})\n"
                "print(json.dumps(r),flush=True)\n",
                encoding="utf-8",
            )
            parser = FramedParser(
                [sys.executable, str(child), str(state), str(received)],
                "tree-sitter-bash",
                timeout=0.05,
                eager_ready=True,
                startup_timeout=1.0,
                timeout_code="PARSER_TIMEOUT",
            )
            starts = []
            real_start = parser._start

            def tracked_start():
                real_start()
                starts.append(parser.process.pid)

            real_select = select.select
            select_timeouts = []

            def tracked_select(reads, writes, errors, timeout):
                select_timeouts.append(timeout)
                return real_select(reads, writes, errors, timeout)

            real_killpg = os.killpg
            killed = []

            def tracked_killpg(process_group, sig):
                killed.append((process_group, sig))
                return real_killpg(process_group, sig)

            with (
                patch.object(parser, "_start", side_effect=tracked_start),
                patch("research.parser_qualification.select.select", side_effect=tracked_select),
                patch("research.parser_qualification.os.killpg", side_effect=tracked_killpg),
            ):
                request_started = time.monotonic()
                first = parser.request("printf first")
                timeout_delivery_seconds = time.monotonic() - request_started
                self.assertEqual(first["diagnostic_codes"], ["PARSER_TIMEOUT"])
                self.assertLess(timeout_delivery_seconds, 0.25)
                self.assertIsNone(parser.process)
                self.assertEqual(len(starts), 1)
                self.assertIn((starts[0], signal.SIGTERM), killed)
                self.assertEqual(received.read_text().splitlines(), [first["request_id"]])

                second = parser.request("printf second")
                self.assertEqual(second["status"], "COMPLETE")
                self.assertEqual(len(starts), 2)
                self.assertNotEqual(starts[0], starts[1])
                self.assertEqual(len(received.read_text().splitlines()), 2)
                parser.close()
                self.assertIn((starts[0], signal.SIGKILL), killed)
                with self.assertRaises(ProcessLookupError):
                    os.kill(starts[0], 0)
            self.assertEqual(len(select_timeouts), 6)
            self.assertGreater(select_timeouts[0], 0.9)
            self.assertLessEqual(select_timeouts[1], 0.05)
            self.assertLessEqual(select_timeouts[2], 0.05)
            self.assertGreater(select_timeouts[3], 0.9)
            self.assertLessEqual(select_timeouts[4], 0.05)
            self.assertLessEqual(select_timeouts[5], 0.05)

    def test_parser_timeout_is_accounted_as_budget_failure_and_timeout(self):
        response = {"diagnostic_codes": ["PARSER_TIMEOUT"]}
        self.assertTrue(_is_parse_budget_miss(response))
        self.assertIn("PARSER_TIMEOUT", FAILURE_CODES)
        self.assertEqual(
            _failure_report_counts({"PARSER_TIMEOUT": 2, "HELPER_PROTOCOL_FAILURE": 1}),
            {"failure_count": 3, "crash_or_timeout_count": 2},
        )

    def test_timeout_crash_and_malformed_child_are_explicit_and_not_retried(self):
        cases = (
            ([sys.executable, "-c", "import time; time.sleep(2)"], "HELPER_TIMEOUT"),
            ([sys.executable, "-c", "import os; os._exit(3)"], "HELPER_CRASHED"),
            ([sys.executable, "-c", "print('not-json', flush=True)"], "HELPER_PROTOCOL_FAILURE"),
            (
                [sys.executable, "-c", "import sys,time;sys.stdout.write('{');sys.stdout.flush();time.sleep(2)"],
                "HELPER_TIMEOUT",
            ),
        )
        for command, expected in cases:
            with self.subTest(expected=expected):
                parser = FramedParser(command, "tree-sitter-bash", timeout=0.05)
                starts = []
                real_start = parser._start

                def tracked_start():
                    starts.append(True)
                    real_start()

                with patch.object(parser, "_start", side_effect=tracked_start):
                    result = parser.request("printf x")
                parser.close()
                self.assertEqual(result["diagnostic_codes"], [expected])
                self.assertEqual(len(starts), 1)

    def test_synthetic_command_is_transported_but_never_executed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "must-not-exist"
            child = root / "child.py"
            child.write_text(
                "import hashlib,json,sys\n"
                "r=json.loads(sys.stdin.readline()); raw=r.pop('raw_command').encode()\n"
                "r.update(status='COMPLETE',completion_state='complete',diagnostic_codes=[],"
                "parser_engine='tree-sitter-bash',parser_version='test',"
                "structural_counts={k:0 for k in ('command_count','chain_count','pipeline_count',"
                "'redirection_count','substitution_count','heredoc_count','unknown_count')},"
                "diagnostic_spans=[],ir={'schema_version':1,'nodes':[],'node_count':0})\n"
                "print(json.dumps(r),flush=True)\n",
                encoding="utf-8",
            )
            parser = FramedParser([sys.executable, str(child)], "tree-sitter-bash")
            try:
                response = parser.request(f"touch {marker}")
            finally:
                parser.close()
            self.assertEqual(response["status"], "COMPLETE")
            self.assertFalse(marker.exists())

    def test_corpus_locks_required_adversarial_families_and_boundaries(self):
        corpus = json.loads((REPO_ROOT / "tests/fixtures/parser_qualification_cases.json").read_text(encoding="utf-8"))
        ids = {case["id"] for case in corpus["cases"]}
        required = {
            "quoted_controls", "escaped_control", "nested_command_substitution", "legacy_backticks",
            "parameter_expansion", "arithmetic_expansion", "process_substitution", "heredoc_expandable",
            "heredoc_quoted", "heredoc_tab_stripping", "here_string", "redirection_order", "and_chain",
            "or_chain", "sequence_chain", "pipeline", "background_chain", "bash_c_wrapper",
            "malformed_quote", "malformed_substitution", "malformed_heredoc", "malformed_conditional",
            "malformed_loop", "valid_prefix_malformed_suffix", "known_astral_crash_seed",
            "input_64k_boundary", "input_64k_over", "depth_63", "depth_64", "depth_65",
        }
        self.assertTrue(required <= ids)
        by_id = {case["id"]: case for case in corpus["cases"]}
        self.assertEqual(len(materialize_case(by_id["input_64k_boundary"]).encode()), 64 * 1024)
        self.assertEqual(len(materialize_case(by_id["input_64k_over"]).encode()), 64 * 1024 + 1)
        self.assertEqual(materialize_case(by_id["known_astral_crash_seed"]), "{𱡀")

    def test_differential_disagreements_are_explicit(self):
        primary = {
            "completion_state": "complete", "status": "COMPLETE", "diagnostic_codes": [],
            "diagnostic_spans": [], "structural_counts": {"command_count": 1},
        }
        oracle = {
            "completion_state": "invalid", "status": "UNMODELED_OR_INVALID",
            "diagnostic_codes": ["PARSE_ERROR", "DYNAMIC_SYNTAX"],
            "diagnostic_spans": [{"start_byte": 0, "end_byte": 1}],
            "structural_counts": {"command_count": 0},
        }
        self.assertEqual(compare_results(primary, oracle), ["completion", "error", "span", "dynamic", "status", "ir"])

    def test_reports_are_private_and_watcher_never_selects_qualification_route(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            _write_json(output, {"schema_version": 1, "synthetic": True})
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        watcher = (REPO_ROOT / "scripts/cmd/schengen_watcher.py").read_text(encoding="utf-8")
        self.assertNotIn("--qualification", watcher)


if __name__ == "__main__":
    unittest.main()
