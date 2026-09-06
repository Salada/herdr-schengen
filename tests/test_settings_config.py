#!/usr/bin/env python3
"""Tests for the canonical schema-v1 Settings 1B resolver."""

import json
import math
import os
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock, patch


SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import core.guard_db as guard_db
import core.settings_config as settings_config
from core.settings_config import (
    DEFAULT_SETTINGS,
    SETTINGS_KEYS,
    SettingsConflictError,
    SettingsError,
    SettingsResolver,
    atomic_write,
    read_trusted,
    validate_settings,
)


class ResolverTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.settings_path = root / "config" / "settings.json"
        self.recovery_path = root / "state" / "settings.last-good.json"

    def tearDown(self):
        self.temporary.cleanup()

    def resolver(self, **kwargs):
        return SettingsResolver(self.settings_path, self.recovery_path, **kwargs)

    def write_raw(self, path, value, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
        path.chmod(mode)


class TestSettingsSchema(ResolverTestCase):
    def test_default_document_has_exact_schema_and_twelve_values(self):
        document = DEFAULT_SETTINGS.to_dict()
        self.assertEqual(len(document), 13)
        self.assertEqual(set(document), SETTINGS_KEYS)
        self.assertEqual(document["schema_version"], 1)

    def test_missing_unknown_and_wrong_types_reject_whole_document(self):
        valid = DEFAULT_SETTINGS.to_dict()
        cases = []
        missing = dict(valid)
        missing.pop("channel_approve")
        cases.append(missing)
        cases.append({**valid, "unknown": True})
        cases.append({**valid, "send_approve_instruction": 1})
        cases.append({**valid, "complexity_threshold": True})
        cases.append({**valid, "human_approval_ttl_seconds": 60.0})
        cases.append({**valid, "schema_version": True})
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(SettingsError):
                validate_settings(candidate)

    def test_ranges_and_non_finite_numbers_reject(self):
        valid = DEFAULT_SETTINGS.to_dict()
        invalid = (
            {**valid, "complexity_threshold": 0},
            {**valid, "cloud_judge_min_confidence": 0.69},
            {**valid, "cloud_judge_min_confidence": math.nan},
            {**valid, "cloud_judge_min_confidence": math.inf},
            {**valid, "human_approval_ttl_seconds": 59},
            {**valid, "pane_direct_confirm_polls": 6},
        )
        for candidate in invalid:
            with self.subTest(candidate=candidate), self.assertRaises(SettingsError):
                validate_settings(candidate)

        self.write_raw(
            self.settings_path,
            json.dumps(valid).replace("0.9", "NaN", 1),
        )
        with self.assertRaises(SettingsError):
            read_trusted(self.settings_path)

        duplicate = json.dumps(valid).replace(
            '"schema_version": 1',
            '"schema_version": 1, "schema_version": 1',
            1,
        )
        self.write_raw(self.settings_path, duplicate)
        with self.assertRaises(SettingsError):
            read_trusted(self.settings_path)


class TestSettingsLifecycle(ResolverTestCase):
    def test_absent_file_migrates_once_and_writes_trusted_complete_snapshots(self):
        migrated = {**DEFAULT_SETTINGS.to_dict(), "complexity_threshold": 17}
        factory = Mock(return_value=migrated)
        snapshot = self.resolver().get(factory)

        self.assertEqual(snapshot.complexity_threshold, 17)
        factory.assert_called_once_with()
        self.assertEqual(read_trusted(self.settings_path), snapshot)
        self.assertEqual(read_trusted(self.recovery_path), snapshot)
        self.assertEqual(self.settings_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.recovery_path.stat().st_mode & 0o777, 0o600)

    def test_valid_canonical_is_live_authority_and_skips_migration(self):
        expected = validate_settings({**DEFAULT_SETTINGS.to_dict(), "complexity_threshold": 21})
        atomic_write(self.settings_path, expected)
        factory = Mock(side_effect=AssertionError("SQLite must not be read"))
        self.assertEqual(self.resolver().get(factory), expected)
        factory.assert_not_called()

    def test_invalid_canonical_cold_start_uses_recovery_without_repair_or_sqlite(self):
        original = b'{"schema_version": 1, "broken": true}\n'
        self.settings_path.parent.mkdir(parents=True)
        self.settings_path.write_bytes(original)
        self.settings_path.chmod(0o600)
        recovered = validate_settings({**DEFAULT_SETTINGS.to_dict(), "answer_language": "english"})
        atomic_write(self.recovery_path, recovered)
        factory = Mock(side_effect=AssertionError("stale SQLite must not be read"))

        resolver = self.resolver()
        self.assertEqual(resolver.get(factory), recovered)
        self.assertEqual(self.settings_path.read_bytes(), original)
        self.assertIn("canonical settings rejected", resolver.last_diagnostic)
        factory.assert_not_called()

    def test_invalid_canonical_and_recovery_use_defaults_without_repair(self):
        original = b"not-json\n"
        self.write_raw(self.settings_path, original.decode())
        self.write_raw(self.recovery_path, "also-not-json\n")
        factory = Mock(side_effect=AssertionError("stale SQLite must not be read"))

        resolver = self.resolver()
        self.assertEqual(resolver.get(factory), DEFAULT_SETTINGS)
        self.assertEqual(self.settings_path.read_bytes(), original)
        self.assertIn("using defaults", resolver.last_diagnostic)
        factory.assert_not_called()

    def test_reload_is_bounded_whole_document_lkg_and_recovers_after_repair(self):
        now = [0.0]
        first = validate_settings({**DEFAULT_SETTINGS.to_dict(), "complexity_threshold": 10})
        second = validate_settings({**DEFAULT_SETTINGS.to_dict(), "complexity_threshold": 20})
        atomic_write(self.settings_path, first)
        resolver = self.resolver(clock=lambda: now[0])
        factory = Mock(side_effect=AssertionError("SQLite must not be read"))

        self.assertEqual(resolver.get(factory), first)
        atomic_write(self.settings_path, second)
        now[0] = 4.999
        self.assertEqual(resolver.get(factory), first)
        now[0] = 5.0
        self.assertEqual(resolver.get(factory), second)

        original_invalid = b"{\"schema_version\": 1}\n"
        self.settings_path.write_bytes(original_invalid)
        self.settings_path.chmod(0o600)
        now[0] = 10.0
        self.assertEqual(resolver.get(factory), second)
        self.assertEqual(self.settings_path.read_bytes(), original_invalid)

        repaired = validate_settings({**DEFAULT_SETTINGS.to_dict(), "complexity_threshold": 30})
        atomic_write(self.settings_path, repaired)
        now[0] = 15.0
        self.assertEqual(resolver.get(factory), repaired)

    def test_invalid_canonical_blocks_update_and_preserves_bytes(self):
        original = b"invalid\n"
        self.settings_path.parent.mkdir(parents=True)
        self.settings_path.write_bytes(original)
        self.settings_path.chmod(0o600)
        with self.assertRaises(SettingsError):
            self.resolver().update(
                {"channel_approve": True},
                lambda: DEFAULT_SETTINGS.to_dict(),
            )
        self.assertEqual(self.settings_path.read_bytes(), original)

    def test_replace_failure_preserves_prior_canonical_bytes(self):
        initial = validate_settings(DEFAULT_SETTINGS.to_dict())
        atomic_write(self.settings_path, initial)
        before = self.settings_path.read_bytes()
        resolver = self.resolver()
        with patch("core.settings_config.os.replace", side_effect=OSError("simulated")):
            with self.assertRaisesRegex(OSError, "simulated"):
                resolver.update(
                    {"channel_approve": True},
                    lambda: DEFAULT_SETTINGS.to_dict(),
                )
        self.assertEqual(self.settings_path.read_bytes(), before)

    def test_concurrent_writers_preserve_independent_fields(self):
        atomic_write(self.settings_path, DEFAULT_SETTINGS)
        barrier = threading.Barrier(2)

        def update(changes):
            barrier.wait()
            return self.resolver().update(changes, lambda: DEFAULT_SETTINGS.to_dict())

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (
                pool.submit(update, {"channel_approve": True}),
                pool.submit(update, {"complexity_threshold": 42}),
            )
            for future in futures:
                future.result(timeout=5)
        final = read_trusted(self.settings_path)
        self.assertTrue(final.channel_approve)
        self.assertEqual(final.complexity_threshold, 42)

    def test_compare_and_update_conflict_is_zero_write_and_reports_current(self):
        initial = validate_settings({**DEFAULT_SETTINGS.to_dict(), "complexity_threshold": 10})
        external = validate_settings({
            **initial.to_dict(),
            "complexity_threshold": 11,
            "channel_approve": True,
        })
        atomic_write(self.settings_path, external)
        resolver = self.resolver()
        before = self.settings_path.read_bytes()

        with self.assertRaises(SettingsConflictError) as raised:
            resolver.compare_and_update(
                {"complexity_threshold": 12},
                {"complexity_threshold": 10},
                lambda: DEFAULT_SETTINGS.to_dict(),
            )

        self.assertEqual(raised.exception.fields, ("complexity_threshold",))
        self.assertEqual(raised.exception.current, external)
        self.assertEqual(self.settings_path.read_bytes(), before)

    def test_compare_and_update_rejects_invalid_or_unsafe_canonical_without_repair(self):
        cases = (
            ("malformed", "{broken", 0o600),
            ("peer-writable", json.dumps(DEFAULT_SETTINGS.to_dict()), 0o660),
        )
        for label, document, mode in cases:
            with self.subTest(label=label):
                self.write_raw(self.settings_path, document, mode=mode)
                before = self.settings_path.read_bytes()
                before_mode = self.settings_path.stat().st_mode & 0o777

                with self.assertRaises(SettingsError):
                    self.resolver().compare_and_update(
                        {"complexity_threshold": 12},
                        {"complexity_threshold": 6},
                        lambda: DEFAULT_SETTINGS.to_dict(),
                    )

                self.assertEqual(self.settings_path.read_bytes(), before)
                self.assertEqual(self.settings_path.stat().st_mode & 0o777, before_mode)
                self.assertFalse(self.recovery_path.exists())

    def test_compare_and_update_force_uses_latest_document(self):
        current = validate_settings({
            **DEFAULT_SETTINGS.to_dict(),
            "complexity_threshold": 11,
            "channel_approve": True,
        })
        atomic_write(self.settings_path, current)

        updated = self.resolver().compare_and_update(
            {"complexity_threshold": 12},
            {"complexity_threshold": 10},
            lambda: DEFAULT_SETTINGS.to_dict(),
            force=True,
        )

        self.assertEqual(updated.complexity_threshold, 12)
        self.assertTrue(updated.channel_approve)
        self.assertEqual(read_trusted(self.settings_path), updated)

    def test_compare_and_update_requires_matching_expected_fields(self):
        atomic_write(self.settings_path, DEFAULT_SETTINGS)
        with self.assertRaises(SettingsError):
            self.resolver().compare_and_update(
                {"complexity_threshold": 12},
                {},
                lambda: DEFAULT_SETTINGS.to_dict(),
            )


class TestSettingsTrust(ResolverTestCase):
    def test_symlink_nonregular_wrong_owner_and_peer_writable_are_rejected(self):
        valid = DEFAULT_SETTINGS.to_dict()
        for case in ("symlink", "directory", "owner", "mode"):
            with self.subTest(case=case):
                root = Path(self.temporary.name) / case
                canonical = root / "settings.json"
                recovery = root / "recovery.json"
                root.mkdir()
                resolver = SettingsResolver(canonical, recovery)
                if case == "symlink":
                    target = root / "target.json"
                    atomic_write(target, DEFAULT_SETTINGS)
                    canonical.symlink_to(target)
                elif case == "directory":
                    canonical.mkdir()
                else:
                    atomic_write(canonical, DEFAULT_SETTINGS)
                    if case == "mode":
                        canonical.chmod(0o620)
                if case == "owner":
                    with patch("core.settings_config.os.getuid", return_value=os.getuid() + 1):
                        with self.assertRaises(SettingsError):
                            read_trusted(canonical)
                else:
                    self.assertEqual(resolver.get(lambda: valid), DEFAULT_SETTINGS)

    def test_unsafe_recovery_is_never_loaded_or_replaced(self):
        self.write_raw(self.settings_path, "invalid\n")
        target = Path(self.temporary.name) / "recovery-target.json"
        recovered = validate_settings({**DEFAULT_SETTINGS.to_dict(), "channel_approve": True})
        atomic_write(target, recovered)
        self.recovery_path.parent.mkdir(parents=True)
        self.recovery_path.symlink_to(target)

        resolver = self.resolver()
        self.assertEqual(resolver.get(lambda: recovered.to_dict()), DEFAULT_SETTINGS)
        self.assertTrue(self.recovery_path.is_symlink())
        self.assertEqual(read_trusted(target), recovered)


class TestGuardDbSettingsCompatibility(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary.name) / "guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db._reset_settings_resolver_cache()
        guard_db.init_db()

    def tearDown(self):
        guard_db._reset_settings_resolver_cache()
        self.db_patch.stop()
        self.temporary.cleanup()

    def test_legacy_sqlite_migration_is_complete_and_then_ceases_authority(self):
        values = {
            "send_approve_instruction": "true",
            "send_reject_instruction": "not-a-boolean",
            "answer_language": "japanese",
            "complexity_threshold": "19",
            "cloud_judge_min_confidence": "0.8",
            "human_approval_ttl_seconds": "120",
            "pane_direct_confirm_polls": "4",
        }
        with guard_db.get_db_connection() as conn:
            conn.executemany(
                "INSERT INTO guard_config (key, value, updated_at) VALUES (?, ?, ?)",
                [(key, value, "2026-09-07T00:00:00+00:00") for key, value in values.items()],
            )
            conn.commit()

        self.assertEqual(guard_db.get_complexity_tax_config()["complexity_threshold"], 19)
        settings_path, recovery_path = guard_db._settings_storage_paths()
        document = read_trusted(settings_path)
        self.assertEqual(len(document.to_dict()), 13)
        self.assertEqual(document.answer_language, "japanese")
        self.assertTrue(document.send_reject_instruction)
        self.assertEqual(document.human_approval_ttl_seconds, 120)
        self.assertEqual(read_trusted(recovery_path), document)

        with guard_db.get_db_connection() as conn:
            conn.execute(
                "UPDATE guard_config SET value = '99' WHERE key = 'complexity_threshold'"
            )
            conn.commit()
        guard_db._reset_settings_resolver_cache()
        self.assertEqual(guard_db.get_complexity_tax_config()["complexity_threshold"], 19)

    def test_numeric_file_values_resolve_through_existing_getters(self):
        settings_path, _ = guard_db._settings_storage_paths()
        expected = validate_settings({
            **DEFAULT_SETTINGS.to_dict(),
            "complexity_threshold": 88,
            "cloud_judge_min_confidence": 0.75,
            "human_approval_ttl_seconds": 7200,
            "pane_direct_confirm_polls": 5,
        })
        atomic_write(settings_path, expected)
        self.assertEqual(guard_db.get_complexity_tax_config()["complexity_threshold"], 88)
        self.assertEqual(guard_db.get_cloud_judge_config()["cloud_judge_min_confidence"], 0.75)
        self.assertEqual(guard_db.get_batch_approval_config()["human_approval_ttl_seconds"], 7200)
        self.assertEqual(guard_db.get_pane_direct_config()["pane_direct_confirm_polls"], 5)

    def test_numeric_tuning_bulk_update_detects_conflict_and_preserves_unrelated(self):
        settings_path, _ = guard_db._settings_storage_paths()
        baseline = {
            "complexity_threshold": 6,
            "cloud_judge_min_confidence": 0.9,
            "human_approval_ttl_seconds": 3600,
            "pane_direct_confirm_polls": 2,
        }
        guard_db.get_complexity_tax_config()
        guard_db.set_channel_approve_config(True)
        guard_db.set_complexity_tax_config(threshold=7)

        with self.assertRaises(SettingsConflictError):
            guard_db.set_numeric_tuning_config(
                complexity_threshold=8,
                cloud_judge_min_confidence=0.8,
                human_approval_ttl_seconds=7200,
                pane_direct_confirm_polls=3,
                expected=baseline,
            )
        self.assertEqual(read_trusted(settings_path).complexity_threshold, 7)

        result = guard_db.set_numeric_tuning_config(
            complexity_threshold=8,
            cloud_judge_min_confidence=0.8,
            human_approval_ttl_seconds=7200,
            pane_direct_confirm_polls=3,
            expected=baseline,
            force=True,
        )
        self.assertEqual(result["complexity_threshold"], 8)
        document = read_trusted(settings_path)
        self.assertTrue(document.channel_approve)
        self.assertEqual(document.pane_direct_confirm_polls, 3)

    def test_patched_database_uses_injected_storage_not_operator_home(self):
        with patch.object(
            guard_db,
            "default_settings_path",
            side_effect=AssertionError("operator home must not be resolved"),
        ):
            guard_db.get_instruction_delivery_config()
        settings_path, _ = guard_db._settings_storage_paths()
        self.assertEqual(settings_path.parent, self.db_path.parent)
        self.assertTrue(settings_path.exists())


if __name__ == "__main__":
    unittest.main()
