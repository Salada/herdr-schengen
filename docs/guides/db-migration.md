# DB Schema Migration Runbook — Additive Provenance Columns

> **Scope**: additive provenance migrations for `audit_logs`,
> `pending_escalations`, and `adjudication_log`. `guard_db.init_db()` applies all
> migrations idempotently at startup; the SQL below is for inspection and manual
> recovery only.

## 1. Why

The current `adjudication_log` records `action` + `feedback` but **not who** made
each entry, and it conflates the human's typed reason with the gatekeeper's
re-interpretation. Two nullable columns are added so each entry carries its own
author (`approver`) and the human's raw text (`human_note`), independently of the
final disposition.

## 2. Existing schema (pre-migration)

```sql
CREATE TABLE adjudication_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    escalation_id INTEGER,
    pane_id       TEXT,
    agent_kind    TEXT,
    action        TEXT NOT NULL,   -- 'APPROVE' | 'REJECT' (later also 'HUMAN_OPINION')
    feedback      TEXT,
    created_at    TEXT NOT NULL
);
```

## 3. Target schema (post-migration)

```sql
-- ... unchanged columns, plus:
    approver   TEXT,   -- WHO authored this entry: machine / human-tui / gatekeeper / pane-direct / other
    human_note TEXT    -- raw human opinion (sanitized); NULL on non-human rows
```

## 4. Migration SQL (additive, nullable, idempotent)

```sql
ALTER TABLE adjudication_log ADD COLUMN approver TEXT;
ALTER TABLE adjudication_log ADD COLUMN human_note TEXT;
```

## 5. LLM judgment procedure

Do **not** run the `ALTER TABLE` until the checks below pass. Fail-closed: when in
doubt, stop and ask a human.

1. **Inspect** the live schema:
   ```bash
   sqlite3 ~/.local/state/herdr-schengen/schengen_history.db "PRAGMA table_info(adjudication_log);"
   ```
2. **Judge necessity (idempotency)**: if `approver` **and** `human_note` are both
   already listed in the output → the migration already ran → **skip**.
3. **Judge safety** — every condition must hold:
   - Statements are `ADD COLUMN` only (no `DROP`, no change to existing column types).
   - New columns are **nullable** (`notnull=0`, no default) → no table rewrite.
   - Existing rows are **untouched**; they read `NULL` for the new columns.
4. **Backup** (non-destructive belt-and-suspenders):
   ```bash
   cp ~/.local/state/herdr-schengen/schengen_history.db \
      ~/.local/state/herdr-schengen/schengen_history.db.bak.$(date +%s)
   ```
5. **Execute** the two `ALTER TABLE` statements (via `sqlite3` CLI, or the
   idempotent `guard_db.init_db()` code path).
6. **Verify**:
   ```bash
   sqlite3 ~/.local/state/herdr-schengen/schengen_history.db "PRAGMA table_info(adjudication_log);"
   sqlite3 ~/.local/state/herdr-schengen/schengen_history.db "SELECT COUNT(*) FROM adjudication_log;"
   ```
   Confirm `approver` and `human_note` appear with `notnull=0`, and the row count
   is unchanged.
7. **Report**: columns added, row count unchanged, no data loss.

## 6. Safety invariants (fail-closed)

- **Additive-only** — never `DROP COLUMN`, never alter existing column types.
- **Idempotent** — guard via `PRAGMA table_info`; skip if the column already exists.
- **No backfill** — legacy rows keep `NULL`; `NULL` grants no trust (every trust
  predicate is an explicit `approver == "human-tui"` string equality).
- **Opinion ≠ trust (INV-HO-3)** — presence of a human opinion never seeds the
  novelty gate / workspace promotion / pane session memory. Only a final
  disposition with `approver="human-tui"` grants trust.

## 7. Rollback

Restore the backup taken in step 4:
```bash
cp ~/.local/state/herdr-schengen/schengen_history.db.bak.<ts> \
   ~/.local/state/herdr-schengen/schengen_history.db
```
Because the change is additive and nullable, leaving it in place is also safe —
legacy rows simply read `NULL`.

## 8. In-code equivalent

`guard_db.init_db()` inspects each table with `PRAGMA table_info` and adds only
missing columns. It now covers:

- `adjudication_log.approver` and `human_note`;
- `audit_logs.decision_source` and `source_revision`;
- `pending_escalations.capture_source`, `normalization_relation`,
  `normalization_ambiguous`, and `raw_capture_evaluated`.

Legacy rows retain neutral defaults (`DETERMINISTIC`, `unknown`, `NULL`, or
false); migration never manufactures human or LLM provenance.
