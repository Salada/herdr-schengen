# ADR-018: Installer Crash Recovery

- **Status**: Active
- **Date**: 2026-09-05

## Context

The runtime installer activates an update by renaming the live target to a
backup and then renaming a staged copy to the target. A process or host failure
between those operations can leave the target absent. Concurrent installers
can also turn a recoverable state into ambiguous remnants.

## Decision

1. Each canonical target has an advisory, non-blocking `fcntl.flock` on the
   persistent `.{target.name}.install.lock` file in its own parent directory.
   The kernel releases the lock when the process exits; the file is never
   treated as an installation artifact or deleted.
2. Staging uses the deterministic `.{target.name}.stage` path while the lock is
   held. Legacy stages with the exact eight-alphanumeric `mkdtemp` suffix are
   reconstructable and may be removed under the lock. Stage-like near misses
   are warned about and preserved.
3. A single backup may be restored only when it is a real directory with a
   parseable provenance manifest containing a non-empty revision. Multiple or
   invalid backups fail closed. When target and backup both exist, target
   provenance is verified before the backup is deleted.
4. Discovery uses `os.scandir` and `lstat` semantics without following
   symlinks. Unsafe artifacts fail closed. Restoration precedes stage cleanup,
   and every recovery intermediate maps back to a classified state.
5. The two runtime targets are independent because discovery and locking are
   scoped by both `target.parent` and `target.name`. The installer never
   manages the TUI-owned daemon lifecycle.

## Consequences

- Re-running the installer heals an interruption after the first rename.
- Backups are treated as potentially irreplaceable state; stages are treated
  as reconstructable copies.
- Ambiguous or unsafe remnants require human inspection instead of automatic
  deletion.
