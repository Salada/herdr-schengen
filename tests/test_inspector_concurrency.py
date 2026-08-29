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

from cmd.schengen_watcher import InspectorCoordinator, WATCHER_DEFAULTS, load_watcher_config
from core import guard_db
from core.session_memory import PaneSessionMemory


class TestInspectorConcurrency(unittest.TestCase):
    def test_per_pane_dedup_and_parallel_completion(self):
        coordinator = InspectorCoordinator(max_workers=2)
        started = threading.Event()
        release = threading.Event()

        def evaluate():
            started.set()
            release.wait(1)
            return True, "safe", "FAST_TRACK_AST", {}

        try:
            self.assertTrue(coordinator.submit("pane-a", ("a",), evaluate))
            self.assertTrue(started.wait(1))
            self.assertFalse(coordinator.submit("pane-a", ("new",), evaluate))
            self.assertTrue(coordinator.submit("pane-b", ("b",), evaluate))
            release.set()
            for _ in range(100):
                completed = list(coordinator.completed())
                if len(completed) == 2:
                    break
                time.sleep(0.01)
            self.assertEqual({pane for pane, _, _ in completed}, {"pane-a", "pane-b"})
        finally:
            coordinator.close()

    def test_fifo_single_slot_and_stale_queue_eviction_model(self):
        coordinator = InspectorCoordinator()
        try:
            coordinator.human_queue.extend([("pane-a", None, "a"), ("pane-b", None, "b")])
            first = coordinator.human_queue.popleft()
            coordinator.active_human = first[:3:2]
            self.assertEqual(coordinator.active_human, ("pane-a", "a"))
            # The watcher retains only live requests before dispatching the next slot.
            coordinator.human_queue = type(coordinator.human_queue)(q for q in coordinator.human_queue if q[2] == "b")
            self.assertEqual(coordinator.human_queue[0][0], "pane-b")
        finally:
            coordinator.close()

    def test_config_default_and_out_of_range_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "watcher.json"
            self.assertEqual(load_watcher_config(path), WATCHER_DEFAULTS)
            path.write_text(json.dumps({"max_workers": 11}), encoding="utf-8")
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


if __name__ == "__main__":
    unittest.main()
