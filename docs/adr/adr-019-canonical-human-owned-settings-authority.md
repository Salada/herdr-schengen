# ADR-019: Canonical Human-Owned Settings Authority

- **Status**: Active
- **Date**: 2026-09-08

## Context

Settings 1B made all twelve runtime settings file-configurable and exposed the
remaining tuning controls through SettingsModal. Several stores and actors
could otherwise appear capable of supplying the same value: the canonical JSON
document, legacy SQLite rows, a persisted recovery snapshot, compiled defaults,
external editors, the Modal, and runtime agents. Without an explicit precedence
and write boundary, an invalid edit could revive stale policy or an agent could
expand its own approval behavior.

## Decision

1. `~/.config/herdr-schengen/settings.json` is the sole live authority. Schema
   version 1 contains exactly `schema_version` plus all twelve typed settings.
   Missing, unknown, incorrectly typed, non-finite, or out-of-range fields
   reject the candidate as a whole.
2. The canonical file must be a current-user-owned regular non-symlink and must
   not be group- or world-writable. A malformed or unsafe live edit keeps the
   process's last validated snapshot and emits a bounded diagnostic; it is not
   partially applied or silently repaired.
3. Legacy SQLite configuration is migration-only. It may seed a complete
   canonical document once when that document is absent. After the canonical
   path exists—including when it is invalid—SQLite is not a competing source.
4. `~/.local/state/herdr-schengen/settings.last-good.json` is recovery-only. It
   is written atomically only from validated canonical JSON or the first
   migration and is consulted only when an existing canonical file is invalid
   at cold start. It never acts as a live authority and never repairs or
   replaces the canonical file. If it is unavailable or invalid, compiled
   defaults are used with a diagnostic.
5. SettingsModal is a human write surface. Each write takes the process and
   file lock, revalidates the newest trusted complete document, preserves
   unrelated concurrent fields, and atomically replaces the whole document.
   The four grouped numeric controls additionally compare their four baseline
   values while holding the same lock; a mismatch is a typed zero-write
   conflict resolved only by an explicit human Reload, Overwrite, or Cancel.
6. Runtime agents, Inspector, Gatekeeper, and other LLM personas receive no
   configuration setter or file-write tool. Any future natural-language policy
   control plane may produce a bounded proposal, but deterministic validation,
   an exact old/new diff, explicit human confirmation, and an auditable atomic
   commit remain mandatory.

## Consequences

- There is one normal-operation authority and no field-by-field mixture of
  canonical, legacy, recovery, and default values.
- Invalid human input remains visible for correction instead of being destroyed
  by automatic repair.
- Recovery improves cold-start availability without gaining policy authority.
- Concurrent human and external edits have explicit, testable conflict
  semantics.
- Approval-affecting configuration cannot be autonomously widened by the agents
  whose behavior it controls.

## References

- Forgejo Issues #247 and #249
- Forgejo PRs #248 and #250
- `docs/guides/configuration.md`, canonical user settings
- `scripts/core/settings_config.py`
- `scripts/cmd/schengen_tui.py`, SettingsModal
