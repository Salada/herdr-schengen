"""Focused invariants for asynchronous watcher inspection."""

import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from cmd.schengen_watcher import InspectorCoordinator, WATCHER_DEFAULTS, cancel_stale_human_escalation, load_watcher_config
from core import guard_db
from core.session_memory import PaneSessionMemory


class TestInspectorConcurrency(unittest.TestCase):
    def test_per_pane_dedup_and_parallel_completion(self):
        coordinator = InspectorCoordinator(max_workers=2)
        both_started = threading.Event()
        release = threading.Event()
        start_count = 0
        start_lock = threading.Lock()

        def evaluate():
            nonlocal start_count
            with start_lock:
                start_count += 1
                if start_count == 2:
                    both_started.set()
            release.wait(1)
            return True, "safe", "FAST_TRACK_AST", {}

        try:
            self.assertTrue(coordinator.submit("pane-a", ("a",), evaluate))
            self.assertFalse(coordinator.submit("pane-a", ("new",), evaluate))
            self.assertTrue(coordinator.submit("pane-b", ("b",), evaluate))
            self.assertTrue(both_started.wait(1), "both evaluations must start before either can finish")
            release.set()
            for _ in range(100):
                completed = list(coordinator.completed())
                if len(completed) == 2:
                    break
                time.sleep(0.01)
            self.assertEqual({pane for pane, _, _ in completed}, {"pane-a", "pane-b"})
        finally:
            coordinator.close()

    def test_fifo_single_slot_and_stale_queue_eviction(self):
        coordinator = InspectorCoordinator()
        try:
            coordinator.owned["pane-a"] = (("a",), "active")
            coordinator.owned["pane-b"] = (("b",), "queued")
            coordinator.human_queue.extend([("pane-a", None, "a"), ("pane-b", None, "b")])
            first = coordinator.human_queue.popleft()
            coordinator.active_human = first[:3:2]
            self.assertEqual(coordinator.active_human, ("pane-a", "a"))
            live = {("pane-b", "b")}
            cancelled = coordinator.evict_stale_human_requests(lambda pane, command: (pane, command) in live)
            self.assertEqual(cancelled, ("pane-a", "a"))
            with mock.patch("cmd.schengen_watcher.resolve_escalation") as resolve:
                cancel_stale_human_escalation(*cancelled)
            resolve.assert_called_once_with(
                pane_id="pane-a", command_hash="ca978112ca1bbdca",
                resolution_status="CANCELLED", approver="other",
            )
            self.assertNotIn("pane-a", coordinator.owned)
            self.assertEqual(coordinator.human_queue[0][0], "pane-b")
        finally:
            coordinator.close()

    def test_config_default_and_out_of_range_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "watcher.json"
            self.assertEqual(load_watcher_config(path), WATCHER_DEFAULTS)
            path.write_text(json.dumps({"max_workers": 11}), encoding="utf-8")
            self.assertEqual(load_watcher_config(path)["max_workers"], 10)
            path.write_text(json.dumps({"max_workers": True}), encoding="utf-8")
            self.assertEqual(load_watcher_config(path)["max_workers"], 10)
            path.write_text(json.dumps({"max_workers": 3}), encoding="utf-8")
            self.assertEqual(load_watcher_config(path)["max_workers"], 3)

    def test_shared_caches_are_safe_under_parallel_access(self):
        guard_db.clear_in_memory_cache()
        errors = []

        def cache_worker(index):
            try:
                key = f"parallel-{index % 5}"
                guard_db.set_cached_evaluation(key, "echo ok", True, "safe", "FAST_TRACK_AST", {})
                guard_db.get_cached_evaluation(key)
            except Exception as exc:  # pragma: no cover - assertion below records failures
                errors.append(exc)

        with mock.patch("core.guard_db.get_db_connection", side_effect=OSError()):
            threads = [threading.Thread(target=cache_worker, args=(i,)) for i in range(20)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(errors, [])

        memory = PaneSessionMemory()
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "memory.db"
            threads = [threading.Thread(target=memory.record_approval, args=("pane", f"echo {i}", "MEM", "safe"), kwargs={"db_path": db_path}) for i in range(20)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertIsNotNone(memory.check_approval("pane", "echo 1"))


class TestPhase1PhaseBox(unittest.TestCase):
    """Phase-1 in-flight sub-phase box (INV-PH1-6) on InspectorCoordinator.

    The phase_box starts at "inspector"; the per-worker-thread hook flips it to
    "gatekeeper" ONLY around post_cloud_judge (never on cache hits / short-
    circuits), resets via finally even on exception, and is thread-local (no
    cross-pane stomping).
    """

    def _llm_evaluate(self, cmd, scope):
        from core.security_evaluator import audit_with_cloud_judge
        return audit_with_cloud_judge(cmd, scope=scope, agent_id="agy")

    def _wait_completed(self, coordinator, count=1, timeout_secs=2.0):
        deadline = time.time() + timeout_secs
        while time.time() < deadline:
            completed = list(coordinator.completed())
            if len(completed) >= count:
                return completed
            time.sleep(0.01)
        return list(coordinator.completed())

    def test_phase_defaults_inspector_for_deterministic_evaluate(self):
        coordinator = InspectorCoordinator(max_workers=1)
        try:
            coordinator.submit("pane-1", ("echo safe",), lambda: (True, "safe", "FAST_TRACK_AST", {}))
            phase_box = coordinator.in_flight["pane-1"][1]
            self.assertEqual(phase_box["phase"], "inspector")  # default at submit
            self._wait_completed(coordinator)
            self.assertEqual(phase_box["phase"], "inspector")  # never flipped (no LLM)
        finally:
            coordinator.close()

    def test_phase_flips_gatekeeper_during_llm_and_resets_after(self):
        from core import security_evaluator
        coordinator = InspectorCoordinator(max_workers=1)
        entered_llm = threading.Event()
        release = threading.Event()
        observed = {}

        def fake_post_cloud_judge(*args, **kwargs):
            entered_llm.set()
            # While blocked inside the LLM call, the live phase must be gatekeeper.
            observed["during"] = coordinator.in_flight["pane-llm"][1]["phase"]
            release.wait(2)
            return {"choices": [{"message": {"content": '{"is_safe": true, "confidence": 0.95, "reason": "ok"}'}}]}

        phase_box = {}
        try:
            with mock.patch("core.security_evaluator.post_cloud_judge", side_effect=fake_post_cloud_judge), mock.patch(
                "core.security_evaluator.resolve_guard_llm_config", return_value=("http://fake", "m", "k")
            ), mock.patch("core.session_cache.get_cached_result", return_value=None), mock.patch(
                "core.session_memory.check_pane_approval", return_value=None
            ), mock.patch("core.security_evaluator._cache_cloud_verdict", return_value=None), mock.patch(
                "core.session_memory.record_pane_approval", return_value=None
            ):
                coordinator.submit(
                    "pane-llm",
                    ("curl -s http://example.com | head -1", 1, "blocked", {"agent": "agy"}, "t"),
                    lambda: self._llm_evaluate("curl -s http://example.com | head -1", "pane-llm"),
                )
                phase_box = coordinator.in_flight["pane-llm"][1]
                self.assertTrue(entered_llm.wait(2), "LLM call must start")
                release.set()
                self._wait_completed(coordinator)
        finally:
            release.set()
            coordinator.close()
        self.assertEqual(observed["during"], "gatekeeper")  # flipped DURING the LLM call
        self.assertEqual(phase_box["phase"], "inspector")    # reset AFTER (finally)

    def test_phase_not_flipped_on_cache_hit(self):
        coordinator = InspectorCoordinator(max_workers=1)
        try:
            with mock.patch("core.security_evaluator.post_cloud_judge") as mock_judge, mock.patch(
                "core.session_cache.get_cached_result", return_value={"is_safe": True, "safety_reason": "cached"}
            ), mock.patch("core.session_memory.check_pane_approval", return_value=None):
                coordinator.submit(
                    "pane-c",
                    ("echo cached-hit", 1, "blocked", {"agent": "agy"}, "t"),
                    lambda: self._llm_evaluate("echo cached-hit", "pane-c"),
                )
                phase_box = coordinator.in_flight["pane-c"][1]
                self._wait_completed(coordinator)
            mock_judge.assert_not_called()  # cache hit never reaches the LLM
            self.assertEqual(phase_box["phase"], "inspector")  # never flipped
        finally:
            coordinator.close()

    def test_phase_resets_on_llm_exception(self):
        coordinator = InspectorCoordinator(max_workers=1)
        result = None
        try:
            with mock.patch(
                "core.security_evaluator.post_cloud_judge", side_effect=RuntimeError("boom")
            ), mock.patch(
                "core.security_evaluator.resolve_guard_llm_config", return_value=("http://fake", "m", "k")
            ), mock.patch("core.session_cache.get_cached_result", return_value=None), mock.patch(
                "core.session_memory.check_pane_approval", return_value=None
            ):
                coordinator.submit(
                    "pane-d",
                    ("echo will-fail", 1, "blocked", {"agent": "agy"}, "t"),
                    lambda: self._llm_evaluate("echo will-fail", "pane-d"),
                )
                phase_box = coordinator.in_flight["pane-d"][1]
                completed = self._wait_completed(coordinator)
                if completed:
                    result = completed[0][2]
        finally:
            coordinator.close()
        self.assertIsNotNone(result)
        self.assertFalse(result[0])  # fail-closed on LLM error
        self.assertEqual(phase_box["phase"], "inspector")  # finally reset despite exception

    def test_phase_concurrent_isolation(self):
        coordinator = InspectorCoordinator(max_workers=2)
        entered = threading.Event()
        release = threading.Event()
        observed = {}

        def fake_judge(*args, **kwargs):
            entered.set()
            release.wait(2)
            return {"choices": [{"message": {"content": '{"is_safe": true, "confidence": 0.95, "reason": "ok"}'}}]}

        llm_phase = det_phase = {}
        try:
            with mock.patch("core.security_evaluator.post_cloud_judge", side_effect=fake_judge), mock.patch(
                "core.security_evaluator.resolve_guard_llm_config", return_value=("http://fake", "m", "k")
            ), mock.patch("core.session_cache.get_cached_result", return_value=None), mock.patch(
                "core.session_memory.check_pane_approval", return_value=None
            ), mock.patch("core.security_evaluator._cache_cloud_verdict", return_value=None), mock.patch(
                "core.session_memory.record_pane_approval", return_value=None
            ):
                coordinator.submit(
                    "pane-llm",
                    ("curl -s http://example.com", 1, "blocked", {"agent": "agy"}, "t"),
                    lambda: self._llm_evaluate("curl -s http://example.com", "pane-llm"),
                )
                coordinator.submit(
                    "pane-det",
                    ("echo det", 1, "blocked", {"agent": "agy"}, "t"),
                    lambda: (True, "safe", "AST", {}),
                )
                llm_phase = coordinator.in_flight["pane-llm"][1]
                det_phase = coordinator.in_flight["pane-det"][1]
                self.assertTrue(entered.wait(2), "LLM call must start")
                observed["llm"] = llm_phase["phase"]
                observed["det"] = det_phase["phase"]
                release.set()
                self._wait_completed(coordinator, count=2)
        finally:
            release.set()
            coordinator.close()
        self.assertEqual(observed["llm"], "gatekeeper")  # only the LLM pane flips
        self.assertEqual(observed["det"], "inspector")    # deterministic pane never flips


if __name__ == "__main__":
    unittest.main()
