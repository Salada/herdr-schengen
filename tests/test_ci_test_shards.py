import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from cmd.schengen_test_shards import (
    LIVE_ONLY_MODULES,
    SHARDS,
    _validate_home_root,
    manifest_errors,
    run_parallel,
    shard_environment,
)


class TestCITestShards(unittest.TestCase):
    def test_manifest_covers_each_module_exactly_once(self):
        self.assertEqual(manifest_errors(), [])
        assigned = [module for modules in SHARDS.values() for module in modules]
        self.assertEqual(len(assigned), len(set(assigned)))
        self.assertTrue(set(LIVE_ONLY_MODULES).isdisjoint(assigned))

    def test_shards_are_purpose_based_not_count_balanced(self):
        self.assertEqual(set(SHARDS), {"policy", "protocol", "runtime"})
        self.assertGreater(len(SHARDS["runtime"]), len(SHARDS["protocol"]))
        self.assertIn("tests.test_schengen_tui_and_agent", SHARDS["runtime"])
        self.assertIn("tests.test_decision_layers", SHARDS["runtime"])

    def test_shard_environment_isolates_home_and_mutable_roots(self):
        with tempfile.TemporaryDirectory() as state_root:
            with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as home_root:
                policy = shard_environment(state_root, home_root, "policy")
                runtime = shard_environment(state_root, home_root, "runtime")
        for key in (
            "HOME",
            "TMPDIR",
            "SCHENGEN_LOG_DIR",
            "PYTHONPYCACHEPREFIX",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
        ):
            self.assertNotEqual(policy[key], runtime[key])
        self.assertEqual(policy["PYTHONNOUSERSITE"], "1")
        self.assertEqual(runtime["PYTHONNOUSERSITE"], "1")

    def test_home_root_rejects_paths_that_change_security_semantics(self):
        for path in ("/tmp/ci-home", "/private/tmp/ci-home", Path(__file__).resolve().parents[1] / ".ci-home"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    _validate_home_root(path)

    def test_home_creation_failure_cleans_temporary_state_root(self):
        with tempfile.TemporaryDirectory() as runner_temp:
            with patch.dict(os.environ, {"RUNNER_TEMP": runner_temp}):
                with patch(
                    "cmd.schengen_test_shards.create_isolated_home_root",
                    side_effect=RuntimeError("unavailable"),
                ):
                    with self.assertRaisesRegex(RuntimeError, "unavailable"):
                        run_parallel()
            self.assertEqual(list(Path(runner_temp).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
