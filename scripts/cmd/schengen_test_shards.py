#!/usr/bin/env python3
"""Run the unit suite in isolated, purpose-based process shards."""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from collections import Counter
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_ROOT = REPO_ROOT / "scripts"

# These groups are intentionally uneven.  The boundary is responsibility and
# isolation risk, not an equal test count.
SHARDS = {
    "policy": (
        "tests.test_adapter_whitespace",
        "tests.test_approval_bias_corpus",
        "tests.test_ci_test_shards",
        "tests.test_codex_edit_file",
        "tests.test_dynamic_substitution",
        "tests.test_fail_closed_bias_shift",
        "tests.test_fast_track_herdr",
        "tests.test_fast_track_pipelines",
        "tests.test_gray_zone_matrix",
        "tests.test_normalization_incident_corpus",
        "tests.test_obvious_safe",
        "tests.test_package_manager",
        "tests.test_readonly_docker_policy",
        "tests.test_request_match",
        "tests.test_routine_git_policy",
        "tests.test_sast_path_injection",
        "tests.test_semgrep_sast_and_hardening",
        "tests.test_shellcheck_sast",
    ),
    "protocol": (
        "tests.test_agent_llm_max_tokens",
        "tests.test_canonical_pane_capture",
        "tests.test_capture_evaluator",
        "tests.test_cloud_judge",
        "tests.test_context_compaction",
        "tests.test_gatekeeper_investigation_tools",
        "tests.test_gatekeeper_prompt",
        "tests.test_gatekeeper_turn_telemetry",
        "tests.test_herdr_agent_read_routing",
        "tests.test_herdr_client_timeouts",
        "tests.test_herdr_multiplexer_live_e2e",
        "tests.test_human_directives",
        "tests.test_inspector_concurrency",
        "tests.test_network_retry",
        "tests.test_opencode_host",
        "tests.test_opencode_target",
        "tests.test_prompt_cache_alignment",
        "tests.test_schengen_bias_harness",
    ),
    "runtime": (
        "tests.test_anti_fatigue",
        "tests.test_approver_provenance",
        "tests.test_auto_advance",
        "tests.test_cloud_judge_confidence",
        "tests.test_complexity_tax",
        "tests.test_daemon_kill_sync",
        "tests.test_decision_layers",
        "tests.test_e2e_escalation_lifecycle",
        "tests.test_feature_requests",
        "tests.test_gatekeeper_approve_adapter",
        "tests.test_installer_crash_recovery",
        "tests.test_judge_observability",
        "tests.test_novelty_gate",
        "tests.test_pane_direct_eviction",
        "tests.test_persistent_allowlist_cud",
        "tests.test_phase1_in_flight",
        "tests.test_provenance_split",
        "tests.test_question_eviction",
        "tests.test_question_non_blocking",
        "tests.test_schengen_tui_and_agent",
        "tests.test_session_cache_and_prompt",
        "tests.test_session_memory",
        "tests.test_settings_config",
        "tests.test_stale_escalation_eviction",
        "tests.test_tui_deterministic_directives",
        "tests.test_tui_pane_direct_guard",
        "tests.test_url_allowlist",
        "tests.test_workspace_allowlist",
    ),
}

LIVE_ONLY_MODULES = ("tests.test_llm_evaluator_integration",)


class TimedTextTestResult(unittest.TextTestResult):
    """Emit one machine-readable duration line for every completed test case."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._started_at = {}

    def startTest(self, test):
        self._started_at[id(test)] = time.perf_counter()
        super().startTest(test)

    def stopTest(self, test):
        started_at = self._started_at.pop(id(test), None)
        super().stopTest(test)
        if started_at is not None:
            elapsed = time.perf_counter() - started_at
            self.stream.writeln(f"duration_seconds={elapsed:.6f} test={test.id()}")


def discover_test_modules(repo_root=REPO_ROOT):
    return {
        f"tests.{path.stem}"
        for path in (Path(repo_root) / "tests").glob("test_*.py")
    }


def manifest_errors(repo_root=REPO_ROOT):
    assigned = [module for modules in SHARDS.values() for module in modules]
    counts = Counter(assigned + list(LIVE_ONLY_MODULES))
    duplicates = sorted(module for module, count in counts.items() if count != 1)
    discovered = discover_test_modules(repo_root)
    declared = set(counts)
    errors = []
    if duplicates:
        errors.append(f"duplicate modules: {', '.join(duplicates)}")
    if discovered - declared:
        errors.append(f"unassigned modules: {', '.join(sorted(discovered - declared))}")
    if declared - discovered:
        errors.append(f"missing modules: {', '.join(sorted(declared - discovered))}")
    return errors


def _is_within(path, parent):
    try:
        Path(path).resolve().relative_to(Path(parent).resolve())
        return True
    except ValueError:
        return False


def _validate_home_root(home_root):
    home_root = Path(home_root).resolve()
    ephemeral_roots = (Path("/tmp"), Path("/private/tmp"), Path("/var/tmp"))
    if any(_is_within(home_root, root) for root in ephemeral_roots):
        raise ValueError(f"CI HOME must not be under an ephemeral security tier: {home_root}")
    if _is_within(home_root, REPO_ROOT):
        raise ValueError(f"CI HOME must not be inside the repository: {home_root}")
    return home_root


def create_isolated_home_root():
    configured = os.environ.get("SCHENGEN_CI_HOME_PARENT")
    candidates = [Path(configured)] if configured else [
        Path("/data/.ci-runs/herdr-schengen"),
        REPO_ROOT.parent / ".herdr-schengen-ci-homes",
    ]
    failures = []
    for candidate in candidates:
        try:
            candidate = _validate_home_root(candidate)
            candidate.mkdir(parents=True, exist_ok=True)
            return Path(tempfile.mkdtemp(prefix="run-", dir=candidate))
        except (OSError, ValueError) as exc:
            failures.append(f"{candidate}: {exc}")
            if configured:
                break
    raise RuntimeError("could not create isolated CI HOME: " + "; ".join(failures))


def shard_environment(state_root, home_root, shard):
    root = Path(state_root) / shard
    home = Path(home_root) / shard
    paths = {
        "log": root / "log",
        "tmp": root / "tmp",
        "pycache": root / "pycache",
        "xdg_cache": home / ".cache",
        "xdg_data": home / ".local" / "share",
        "xdg_state": home / ".local" / "state",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(
        {
            "HERDR_ENV": "1",
            "HOME": str(home),
            "TMPDIR": str(paths["tmp"]),
            "SCHENGEN_LOG_DIR": str(paths["log"]),
            "PYTHONPYCACHEPREFIX": str(paths["pycache"]),
            "PYTHONNOUSERSITE": "1",
            "XDG_CACHE_HOME": str(paths["xdg_cache"]),
            "XDG_DATA_HOME": str(paths["xdg_data"]),
            "XDG_STATE_HOME": str(paths["xdg_state"]),
        }
    )
    return env


def run_worker(shard):
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    if str(SCRIPTS_ROOT) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_ROOT))
    suite = unittest.defaultTestLoader.loadTestsFromNames(SHARDS[shard])
    result = unittest.TextTestRunner(verbosity=2, resultclass=TimedTextTestResult).run(suite)
    return 0 if result.wasSuccessful() else 1


def run_live():
    if os.environ.get("RUN_LIVE_LLM_TESTS") != "1":
        print("live tests require RUN_LIVE_LLM_TESTS=1", file=sys.stderr)
        return 2
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    if str(SCRIPTS_ROOT) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_ROOT))
    suite = unittest.defaultTestLoader.loadTestsFromNames(LIVE_ONLY_MODULES)
    result = unittest.TextTestRunner(verbosity=2, resultclass=TimedTextTestResult).run(suite)
    if result.skipped:
        print("live test contract violation: configured tests were skipped", file=sys.stderr)
        return 1
    return 0 if result.wasSuccessful() else 1


def run_parallel():
    errors = manifest_errors()
    if errors:
        for error in errors:
            print(f"manifest error: {error}", file=sys.stderr)
        return 2

    parent = os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()
    state_root = None
    home_root = None
    processes = []
    try:
        state_root = Path(tempfile.mkdtemp(prefix="herdr-schengen-ci-", dir=parent))
        home_root = create_isolated_home_root()
        for shard in SHARDS:
            log_path = state_root / f"{shard}.log"
            log_file = log_path.open("w", encoding="utf-8")
            process = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--worker", shard],
                cwd=REPO_ROOT,
                env=shard_environment(state_root, home_root, shard),
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
            )
            processes.append((shard, process, log_file, log_path))

        failed = False
        for shard, process, log_file, log_path in processes:
            return_code = process.wait()
            log_file.close()
            print(f"\n===== {shard} shard (exit {return_code}) =====")
            print(log_path.read_text(encoding="utf-8"), end="")
            failed = failed or return_code != 0
        return 1 if failed else 0
    finally:
        for _, process, log_file, _ in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            if not log_file.closed:
                log_file.close()
        if state_root is not None:
            shutil.rmtree(state_root, ignore_errors=True)
        if home_root is not None:
            shutil.rmtree(home_root, ignore_errors=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="validate the shard manifest")
    parser.add_argument("--run", action="store_true", help="run all non-live shards in parallel")
    parser.add_argument("--live", action="store_true", help="run the explicit live-only shard serially")
    parser.add_argument("--worker", choices=tuple(SHARDS), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.worker:
        return run_worker(args.worker)
    if args.verify:
        errors = manifest_errors()
        if errors:
            for error in errors:
                print(f"manifest error: {error}", file=sys.stderr)
            return 1
        print(f"manifest ok: {sum(map(len, SHARDS.values()))} non-live modules, {len(LIVE_ONLY_MODULES)} live-only")
        return 0
    if args.run:
        return run_parallel()
    if args.live:
        return run_live()
    parser.error("one of --verify, --run, or --live is required")


if __name__ == "__main__":
    raise SystemExit(main())
