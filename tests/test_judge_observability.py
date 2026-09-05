#!/usr/bin/env python3
"""Judge no-tool-call, decision-source, and runtime provenance regressions."""

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import core.guard_db as guard_db
import cmd.schengen_install as schengen_install
from tools.schengen_agent_llm import record_model_no_tool_call
from tools.schengen_agent_llm import SchengenAgentChat


class TestJudgeObservability(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_pending_capture_context_round_trip(self):
        guard_db.enqueue_pending_escalation(
            pane_id="w1D:p1",
            raw_command="git status --short",
            safety_reason="probe",
            decision_layer="NORMALIZATION_AMBIGUOUS",
            capture_source="recent-unwrapped",
            normalization_relation="different",
            normalization_ambiguous=True,
            raw_capture_evaluated=True,
        )
        row = guard_db.get_pending_escalations()[0]
        self.assertEqual(row["capture_source"], "recent-unwrapped")
        self.assertEqual(row["normalization_relation"], "different")
        self.assertEqual(row["normalization_ambiguous"], 1)
        self.assertEqual(row["raw_capture_evaluated"], 1)

    def test_model_no_tool_call_is_explicit_llm_audit(self):
        esc = {
            "pane_id": "w1D:p1",
            "raw_command": "git commit",
            "agent_kind": "codex",
            "decision_layer": "NOT_ALLOWLISTED",
            "origin": "A",
            "started_at": "2000-01-01T00:00:00+00:00",
        }
        reason = record_model_no_tool_call(esc, "Judge")
        record_model_no_tool_call(esc, "Judge")
        self.assertIn("remains pending", reason)
        row = guard_db.get_recent_audit_logs(limit=1)[0]
        self.assertEqual(row["decision"], "MODEL_NO_TOOL_CALL")
        self.assertEqual(row["decision_source"], "LLM")
        self.assertEqual(row["decision_layer"], "NOT_ALLOWLISTED")
        self.assertTrue(row["source_revision"])
        with guard_db.get_db_connection() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM audit_logs WHERE decision = 'MODEL_NO_TOOL_CALL'"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_legacy_tables_gain_observability_columns(self):
        conn = sqlite3.connect(self.db_path)
        conn.executescript(
            """
            CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, timestamp TEXT, pane_id TEXT,
              agent_kind TEXT, raw_command TEXT, normalized_pattern TEXT, decision TEXT,
              safety_reason TEXT, decision_layer TEXT);
            CREATE TABLE pending_escalations (id INTEGER PRIMARY KEY, pane_id TEXT,
              raw_command TEXT, command_hash TEXT, safety_reason TEXT, decision_layer TEXT,
              status TEXT, started_at TEXT, last_transitioned_at TEXT);
            """
        )
        conn.close()
        guard_db.init_db()
        with sqlite3.connect(self.db_path) as migrated:
            audit_cols = {r[1] for r in migrated.execute("PRAGMA table_info(audit_logs)")}
            pending_cols = {r[1] for r in migrated.execute("PRAGMA table_info(pending_escalations)")}
        self.assertTrue({"decision_source", "source_revision"} <= audit_cols)
        self.assertTrue(
            {"capture_source", "normalization_relation", "normalization_ambiguous", "raw_capture_evaluated"}
            <= pending_cols
        )

    def test_installer_stamps_exact_revision(self):
        target = Path(self.temp_dir.name).resolve() / "herdr-schengen"
        with patch.object(schengen_install, "CANONICAL_TARGETS", frozenset({target.absolute()})), patch.object(
            schengen_install, "source_is_clean", return_value=True
        ):
            manifest = schengen_install.install(target)
        stamped = json.loads((target / ".schengen-source.json").read_text(encoding="utf-8"))
        self.assertEqual(stamped["revision"], manifest["revision"])
        self.assertTrue((target / "scripts/core/security_evaluator.py").is_file())
        self.assertTrue((target / "AGENTS.md").is_file())

    def test_installer_rejects_noncanonical_and_dirty_targets(self):
        target = Path(self.temp_dir.name).resolve() / "herdr-schengen"
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            schengen_install.install(target)
        with patch.object(schengen_install, "CANONICAL_TARGETS", frozenset({target.absolute()})), patch.object(
            schengen_install, "source_is_clean", return_value=False
        ), self.assertRaisesRegex(ValueError, "dirty"):
            schengen_install.install(target)

    def test_installer_prunes_stale_managed_files(self):
        target = Path(self.temp_dir.name).resolve() / "herdr-schengen"
        stale = target / "scripts/stale.py"
        stale.parent.mkdir(parents=True)
        stale.write_text("stale", encoding="utf-8")
        with patch.object(schengen_install, "CANONICAL_TARGETS", frozenset({target.absolute()})), patch.object(
            schengen_install, "source_is_clean", return_value=True
        ):
            schengen_install.install(target)
        self.assertFalse(stale.exists())

    def test_installer_rejects_symlinked_runtime_root(self):
        temp_root = Path(self.temp_dir.name).resolve()
        broad = temp_root / "broad"
        broad.mkdir()
        target = temp_root / "herdr-schengen"
        target.symlink_to(broad, target_is_directory=True)
        with patch.object(
            schengen_install, "CANONICAL_TARGETS", frozenset({target.absolute()})
        ), self.assertRaisesRegex(ValueError, "contains a symlink"):
            schengen_install.install(target)

    def test_installer_copies_only_tracked_files(self):
        tracked = schengen_install.tracked_files()
        self.assertTrue(tracked)
        self.assertTrue(all((REPO_ROOT / path).is_file() for path in tracked))
        self.assertFalse(any("__pycache__" in path.parts or path.suffix == ".pyc" for path in tracked))

    def test_installer_rejects_tracked_source_symlink(self):
        source_root = Path(self.temp_dir.name).resolve() / "source"
        target = Path(self.temp_dir.name).resolve() / "herdr-schengen"
        link = source_root / "scripts/link.py"
        link.parent.mkdir(parents=True)
        link.symlink_to(Path(__file__))
        with patch.object(schengen_install, "REPO_ROOT", source_root), patch.object(
            schengen_install, "CANONICAL_TARGETS", frozenset({target.absolute()})
        ), patch.object(schengen_install, "source_is_clean", return_value=True), patch.object(
            schengen_install, "tracked_files", return_value=(Path("scripts/link.py"),)
        ), self.assertRaisesRegex(ValueError, "not a regular file"):
            schengen_install.install(target)
        self.assertFalse(target.exists())

    def test_installer_copy_failure_preserves_previous_runtime(self):
        target = Path(self.temp_dir.name).resolve() / "herdr-schengen"
        sentinel = target / "scripts/previous.py"
        sentinel.parent.mkdir(parents=True)
        sentinel.write_text("previous", encoding="utf-8")
        with patch.object(
            schengen_install, "CANONICAL_TARGETS", frozenset({target.absolute()})
        ), patch.object(schengen_install, "source_is_clean", return_value=True), patch.object(
            schengen_install.shutil, "copy2", side_effect=OSError("copy failed")
        ), self.assertRaisesRegex(OSError, "copy failed"):
            schengen_install.install(target)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "previous")
        self.assertFalse(any(target.parent.glob(f".{target.name}.stage-*")))

    def test_installer_activation_failure_rolls_back_previous_runtime(self):
        target = Path(self.temp_dir.name).resolve() / "herdr-schengen"
        sentinel = target / "scripts/previous.py"
        sentinel.parent.mkdir(parents=True)
        sentinel.write_text("previous", encoding="utf-8")
        real_replace = os.replace

        def fail_stage_activation(source, destination):
            if Path(source).name.startswith(f".{target.name}.stage-"):
                raise OSError("activation failed")
            return real_replace(source, destination)

        with patch.object(
            schengen_install, "CANONICAL_TARGETS", frozenset({target.absolute()})
        ), patch.object(schengen_install, "source_is_clean", return_value=True), patch.object(
            schengen_install.os, "replace", side_effect=fail_stage_activation
        ), self.assertRaisesRegex(OSError, "activation failed"):
            schengen_install.install(target)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "previous")
        self.assertFalse(any(target.parent.glob(f".{target.name}.backup-*")))


class _Response:
    status_code = 200

    def json(self):
        return {
            "choices": [{"message": {"content": "Risk briefing only."}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2},
        }


class _Client:
    async def post(self, *args, **kwargs):
        return _Response()

    async def aclose(self):
        return None


class TestNoToolCallRoundTrip(unittest.IsolatedAsyncioTestCase):
    async def test_text_only_model_turn_is_visible_and_audited(self):
        temp_dir = tempfile.TemporaryDirectory()
        db_path = Path(temp_dir.name) / "guard.db"
        esc = {
            "id": 7,
            "pane_id": "w1D:p1",
            "raw_command": "git commit",
            "agent_kind": "codex",
            "decision_layer": "NOT_ALLOWLISTED",
            "safety_reason": "manual review",
            "origin": "A",
            "started_at": "2000-01-01T00:00:00+00:00",
        }
        try:
            with patch.object(guard_db, "DB_PATH", db_path), patch(
                "tools.schengen_agent_llm.get_current_command_escalation", return_value=esc
            ), patch("tools.schengen_agent_llm.has_human_opinion", return_value=False), patch(
                "tools.schengen_agent_llm.httpx.AsyncClient", return_value=_Client()
            ):
                chat = SchengenAgentChat(api_key="test-key")
                chat.inspector_model = chat.judge_model = "gpt-5.6-luna"
                chat.inspector_base_url = chat.judge_base_url = "https://example.invalid/v1"
                chat.inspector_api_key = chat.judge_api_key = "test-key"
                response = await chat.send_message("review")
                self.assertIn("[MODEL_NO_TOOL_CALL]", response)
                self.assertIn("remains pending", response)
                row = guard_db.get_recent_audit_logs(limit=1)[0]
                self.assertEqual(row["decision"], "MODEL_NO_TOOL_CALL")
                self.assertEqual(row["decision_source"], "LLM")
        finally:
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
