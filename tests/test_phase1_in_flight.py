#!/usr/bin/env python3
"""Phase-1 in-flight inspection IPC tests (INV-PH1-1..6).

The watcher publishes its inspector in-flight state (sub-phases "inspector"
vs "gatekeeper") to a shared JSON file; the TUI reads it read-only. Covers
the writer (sync_in_flight_state), the reader (read_in_flight_state), the
phase_box lifecycle in InspectorCoordinator, and the TUI badge formatter.
"""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from cmd.schengen_watcher import InspectorCoordinator, sync_in_flight_state
from core import guard_db


class _FakeInspector:
    def __init__(self, in_flight):
        self.in_flight = in_flight


class TestPhase1InFlightIPC(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_path = Path(self.temp_dir.name) / "in_flight_state.json"
        # Patch BOTH namespaces: the watcher's imported name and guard_db's
        # module global (read_in_flight_state reads via guard_db).
        self.p_watcher = mock.patch("cmd.schengen_watcher.IN_FLIGHT_STATE_PATH", self.state_path)
        self.p_guard = mock.patch("core.guard_db.IN_FLIGHT_STATE_PATH", self.state_path)
        self.p_watcher.start()
        self.p_guard.start()

    def tearDown(self):
        self.p_watcher.stop()
        self.p_guard.stop()
        self.temp_dir.cleanup()

    def _request(self, cmd="rm -rf /tmp/x", agent="agy"):
        return (cmd, 1, "blocked", {"agent": agent}, "visible text")

    # ---- writer: sync_in_flight_state ------------------------------------

    def test_sync_writes_entries(self):
        phase_box = {"phase": "gatekeeper", "ts": time.time()}
        inspector = _FakeInspector({"w1D:p1": (self._request("echo hello && rm -rf /tmp/x"), phase_box, object())})
        sync_in_flight_state(inspector)
        self.assertTrue(self.state_path.exists())
        data = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(len(data["entries"]), 1)
        entry = data["entries"][0]
        self.assertEqual(entry["pane_id"], "w1D:p1")
        self.assertEqual(entry["agent_kind"], "agy")
        self.assertEqual(entry["phase"], "gatekeeper")
        self.assertEqual(entry["command_preview"], "echo hello && rm -rf /tmp/x")
        self.assertEqual(entry["command_fp"], __import__("hashlib").sha256(b"echo hello && rm -rf /tmp/x").hexdigest()[:12])
        self.assertAlmostEqual(entry["started_at"], phase_box["ts"], delta=1.0)

    def test_sync_clears_when_idle(self):
        sync_in_flight_state(_FakeInspector({}))
        data = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(data["entries"], [])

    def test_sync_skips_unsafe_entries(self):
        # Non-string / empty command cannot be derived safely -> skipped.
        inspector = _FakeInspector({
            "pane-a": ((None,), {"phase": "inspector", "ts": time.time()}, object()),
            "pane-b": (("",), {"phase": "inspector", "ts": time.time()}, object()),
            "pane-c": (self._request("valid cmd"), {"phase": "inspector", "ts": time.time()}, object()),
        })
        sync_in_flight_state(inspector)
        data = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual([e["pane_id"] for e in data["entries"]], ["pane-c"])

    def test_sync_drops_stale_entries(self):
        old_ts = time.time() - 100  # > IN_FLIGHT_TTL (30s)
        inspector = _FakeInspector({
            "pane-a": (self._request("old cmd"), {"phase": "gatekeeper", "ts": old_ts}, object()),
        })
        sync_in_flight_state(inspector)
        data = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(data["entries"], [])

    # ---- coordinator: phase_box lifecycle (INV-PH1-6) --------------------

    def test_submit_records_started_at_and_phase_box(self):
        coordinator = InspectorCoordinator(max_workers=1)
        try:
            before = time.time()
            self.assertTrue(coordinator.submit("w1D:p1", self._request("echo hi"), lambda: (True, "ok", "AST", {})))
            # 3-tuple shape: (request, phase_box, future) — phase defaults to
            # "inspector" at submit (INV-PH1-6).
            request, phase_box, future = coordinator.in_flight["w1D:p1"]
            self.assertIsNotNone(future)
            self.assertEqual(phase_box["phase"], "inspector")  # defaults at submit
            self.assertGreaterEqual(phase_box["ts"], before)
            self.assertLessEqual(phase_box["ts"], time.time())
        finally:
            coordinator.close()

    # ---- reader: read_in_flight_state -------------------------------------

    def test_read_returns_empty_when_stale(self):
        self.state_path.write_text(
            json.dumps({"ts": time.time() - 100, "entries": [{"pane_id": "x", "phase": "inspector"}]}),
            encoding="utf-8",
        )
        self.assertEqual(guard_db.read_in_flight_state(), [])

    def test_read_returns_empty_on_malformed_json(self):
        self.state_path.write_text("{ not json !!!", encoding="utf-8")
        self.assertEqual(guard_db.read_in_flight_state(), [])
        self.state_path.write_text('{"ts": "nope", "entries": []}', encoding="utf-8")
        self.assertEqual(guard_db.read_in_flight_state(), [])
        self.state_path.write_text('{"ts": 123, "entries": "not-a-list"}', encoding="utf-8")
        self.assertEqual(guard_db.read_in_flight_state(), [])

    def test_read_returns_entries_when_fresh(self):
        self.state_path.write_text(
            json.dumps({"ts": time.time(), "entries": [{"pane_id": "w1D:p1", "phase": "gatekeeper"}]}),
            encoding="utf-8",
        )
        entries = guard_db.read_in_flight_state()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["phase"], "gatekeeper")

    # ---- TUI badge formatter (INV-PH1-1) ----------------------------------

    def test_inflight_phase_badge_rendering(self):
        from cmd.schengen_tui import format_inflight_phase_badge

        self.assertIn("Gatekeeper: judging", format_inflight_phase_badge("gatekeeper"))
        self.assertIn("🤖", format_inflight_phase_badge("gatekeeper"))
        self.assertIn("Inspector: checking", format_inflight_phase_badge("inspector"))
        self.assertIn("🔍", format_inflight_phase_badge("inspector"))
        # unknown phase defaults to the inspector badge (conservative)
        self.assertIn("Inspector: checking", format_inflight_phase_badge("weird"))


if __name__ == "__main__":
    unittest.main()
