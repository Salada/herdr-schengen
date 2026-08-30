"""Persistent Allowlist CUD tests (issue #91, INV-PL-1..5).

Covers the full Create/Update/Revoke lifecycle of the global `user_allowlist`:
1. create -> is_active=1, created_by/created_at set; check_persisted_allowlist matches.
2. revoke by id -> is_active=0, revoked_at/revoked_by set; no longer matches (INV-PL-2).
3. update by id changes pattern_regex; created_at/created_by preserved, updated_at set.
4. re-add a revoked pattern -> reactivated, id preserved (INV-PL-5, UPSERT not REPLACE).
5. catch-all rejection raises ValueError in add AND update (INV-PL-4).
6. each CUD writes one audit_log row with the correct mechanism (INV-PL-3).
7. migration backfill: pre-#91 rows get created_by='human-tui', is_active unchanged.
8. revoke/update by unknown id -> 0 / no-op (idempotent).
"""

import json
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
from core.guard_db import (
    add_to_allowlist,
    check_persisted_allowlist,
    list_allowlist_rules,
    revoke_allowlist_rule,
    update_allowlist_rule,
)


def _audit_rows() -> list[dict]:
    with guard_db.get_db_connection() as conn:
        rows = conn.execute(
            "SELECT mechanism, origin, decision_layer, scope_context, decision FROM audit_logs ORDER BY id ASC"
        ).fetchall()
        return [dict(r) for r in rows]


class TestPersistentAllowlistCud(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guard.db"
        self.db_patch = patch.object(guard_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        guard_db.init_db()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_create_sets_provenance_and_matches(self):
        add_to_allowlist("^git status$", description="status check", created_by="human-tui")
        rules = list_allowlist_rules()
        self.assertEqual(len(rules), 1)
        r = rules[0]
        self.assertEqual(r["is_active"], 1)
        self.assertEqual(r["created_by"], "human-tui")
        self.assertTrue(r["created_at"])
        self.assertIsNone(r["revoked_at"])
        self.assertIsNone(r["revoked_by"])
        ok, reason = check_persisted_allowlist("git status")
        self.assertTrue(ok)
        self.assertIn("status check", reason)

    def test_revoke_by_id_deactivates_and_stops_matching(self):
        add_to_allowlist("^brew list$", description="read-only brew")
        rule_id = list_allowlist_rules()[0]["id"]
        affected = revoke_allowlist_rule(rule_id, revoked_by="human-tui")
        self.assertEqual(affected, 1)
        rules = list_allowlist_rules(include_revoked=True)
        r = next(x for x in rules if x["id"] == rule_id)
        self.assertEqual(r["is_active"], 0)
        self.assertTrue(r["revoked_at"])
        self.assertEqual(r["revoked_by"], "human-tui")
        # INV-PL-2: revocation is immediate — the read path filters is_active=1.
        ok, _ = check_persisted_allowlist("brew list")
        self.assertFalse(ok)
        self.assertEqual(list_allowlist_rules(), [])

    def test_update_changes_pattern_preserves_provenance(self):
        add_to_allowlist("^git status$", description="status")
        rule_id = list_allowlist_rules()[0]["id"]
        orig_created_at = list_allowlist_rules()[0]["created_at"]
        affected = update_allowlist_rule(rule_id, pattern_regex="^git log$", description="log")
        self.assertEqual(affected, 1)
        r = list_allowlist_rules()[0]
        self.assertEqual(r["pattern_regex"], "^git log$")
        self.assertEqual(r["description"], "log")
        self.assertEqual(r["created_at"], orig_created_at)  # preserved
        self.assertEqual(r["created_by"], "human-tui")  # preserved
        self.assertTrue(r["updated_at"])  # stamped
        # old pattern stops matching, new matches
        ok_old, _ = check_persisted_allowlist("git status")
        self.assertFalse(ok_old)
        ok_new, _ = check_persisted_allowlist("git log")
        self.assertTrue(ok_new)

    def test_readd_revoked_reactivates_preserving_id(self):
        add_to_allowlist("^git diff$", description="diff")
        rule_id = list_allowlist_rules()[0]["id"]
        revoke_allowlist_rule(rule_id)
        # Re-add the SAME pattern -> reactivated, SAME id (UPSERT, not REPLACE).
        add_to_allowlist("^git diff$", description="diff v2")
        rules = list_allowlist_rules()
        self.assertEqual(len(rules), 1)
        r = rules[0]
        self.assertEqual(r["id"], rule_id)
        self.assertEqual(r["is_active"], 1)
        self.assertIsNone(r["revoked_at"])
        self.assertIsNone(r["revoked_by"])
        self.assertEqual(r["description"], "diff v2")
        ok, _ = check_persisted_allowlist("git diff")
        self.assertTrue(ok)

    def test_catch_all_rejected_in_add_and_update(self):
        add_to_allowlist("^git show$")
        rule_id = list_allowlist_rules()[0]["id"]
        for bad in (".*", ".+", "^.*$", "ab"):
            with self.assertRaises(ValueError):
                add_to_allowlist(bad)
        with self.assertRaises(ValueError):
            update_allowlist_rule(rule_id, pattern_regex=".*")
        with self.assertRaises(ValueError):
            update_allowlist_rule(rule_id, pattern_regex="ab")

    def test_each_cud_writes_one_audit_row(self):
        add_to_allowlist("^git fetch$", description="fetch", created_by="human-tui")
        rule_id = list_allowlist_rules()[0]["id"]
        update_allowlist_rule(rule_id, description="fetch v2", created_by="human-tui")
        revoke_allowlist_rule(rule_id, revoked_by="human-tui")
        rows = _audit_rows()
        self.assertEqual(len(rows), 3)
        self.assertEqual([r["mechanism"] for r in rows], ["allowlist-create", "allowlist-update", "allowlist-revoke"])
        for r in rows:
            self.assertEqual(r["origin"], "H")
            self.assertEqual(r["decision_layer"], "ALLOWLIST")
            self.assertEqual(r["scope_context"], "GLOBAL_RULE")

    def test_migration_backfills_created_by(self):
        # Simulate a pre-#91 schema: build a legacy user_allowlist (no CUD
        # columns), insert a raw row, then run init_db() to migrate.
        legacy_db = Path(self.temp_dir.name) / "legacy.db"
        conn = sqlite3.connect(str(legacy_db))
        conn.executescript(
            """
            CREATE TABLE user_allowlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_regex TEXT NOT NULL UNIQUE,
                description TEXT,
                created_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1
            );
            """
        )
        conn.execute(
            "INSERT INTO user_allowlist (pattern_regex, description, created_at, is_active) VALUES (?, ?, ?, 1)",
            ("^git stash$", "legacy", "2026-01-01T00:00:00+00:00"),
        )
        conn.commit()
        conn.close()
        with patch.object(guard_db, "DB_PATH", Path(legacy_db)):
            guard_db.init_db()  # idempotent ALTER TABLE migration + backfill
            rules = guard_db.list_allowlist_rules(include_revoked=True)
        target = next(r for r in rules if r["pattern_regex"] == "^git stash$")
        self.assertEqual(target["created_by"], "human-tui")
        self.assertEqual(target["is_active"], 1)  # untouched
        self.assertIsNone(target["revoked_at"])
        self.assertIsNone(target["updated_at"])

    def test_unknown_id_ops_are_idempotent_noops(self):
        add_to_allowlist("^git tag$")
        rule_id = list_allowlist_rules()[0]["id"]
        # unknown id -> 0, no audit row
        self.assertEqual(revoke_allowlist_rule(99999), 0)
        self.assertEqual(update_allowlist_rule(99999, pattern_regex="^git x$"), 0)
        self.assertEqual(len(_audit_rows()), 1)  # only the create row
        # revoke then update on the revoked rule -> 0 (is_active=1 filter)
        revoke_allowlist_rule(rule_id)
        self.assertEqual(update_allowlist_rule(rule_id, description="nope"), 0)
        self.assertEqual(revoke_allowlist_rule(rule_id), 0)  # already revoked
        rows = _audit_rows()
        self.assertEqual([r["mechanism"] for r in rows], ["allowlist-create", "allowlist-revoke"])


if __name__ == "__main__":
    unittest.main()
