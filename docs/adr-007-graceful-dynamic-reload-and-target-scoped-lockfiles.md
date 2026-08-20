# ADR-007: Graceful Dynamic Reload (SIGHUP) & Target-Scoped Lockfile Architecture

- **Status**: Accepted
- **Date**: 2026-08-21
- **Deciders**: Antigravity/AGY (Orchestrator), Hermes (Reviewer), Human Engineer (SaladaQoo)
- **Consulted**: Herdr Schengen Core Team
- **Informed**: All AGY Worker Panes (`wS:pF`, `wS:pK`, `wZ:p1`)

---

## 🧭 1. Context & Problem Statement

In a multi-agent Herdr multiplexer environment, multiple AGY agent sessions operate concurrently across tabs and split panes. Previously:
1. **Singleton Contention (`schengen.lock`)**: A single global lockfile meant that whenever any agent or engineer ran `schengen_watcher.py --stop` to apply a patch or reconfigure parameters, all other active agent sessions lost their watcher daemon simultaneously.
2. **Hard Process Termination on Hotpatching**: Applying AST parser patches or updating gray-zone rule matrices required killing and restarting the Python process, introducing a downtime window where subsequent commands stalled at approval prompts.
3. **Repository Confusion / Dotfiles Over-coupling**: Agent sessions frequently mistook `herdr-schengen` specific ADRs for dotfiles chezmoi documentation due to broad global system prompt scopes.

---

## 🎯 2. Decision Drivers

- **Zero-Downtime Hot Reload**: Security rule updates and parser fixes must take effect in under 10ms without killing running daemon processes.
- **Scope-Isolated Concurrency**: Dedicated single-pane watchers (`--target wS:pF`) and global discovery watchers (`--target auto`) must co-exist without lockfile collision.
- **Explicit Repository Boundary**: Project-specific architecture decisions for Herdr Schengen must reside strictly within `~/code/herdr-schengen/docs/` and synchronize to `~/.agents/skills/herdr-schengen/docs/`, avoiding dotfiles chezmoi repository pollution.

---

## 🏗️ 3. Considered Options

- **Option A (Legacy Process Cycling)**: Use `pkill -f schengen_watcher` and re-spawn on every rule edit. *(Rejected: High race condition risk, lockfile orphan states, temporary security blind spots)*.
- **Option B (Unix Domain Socket RPC Server)**: Build an asynchronous IPC server inside the watcher for command configuration. *(Rejected: Over-engineered, adds complex networking dependencies)*.
- **Option C (POSIX SIGHUP + in-process `importlib.reload()` + Target-Scoped Lockfiles)**: Use POSIX signal `SIGHUP` to trigger in-place module reloads and isolate lockfiles by sanitized target identifiers (`schengen_auto.lock`, `schengen_wS_pF.lock`). *(Chosen)*.

---

## ⚖️ 4. Decision Outcome: Option C

### Key Architectural Invariants:
1. **In-Process Dynamic Reload**:
   - `signal.signal(signal.SIGHUP, handle_sighup)` sets `_RELOAD_REQUESTED = True`.
   - On the next poll cycle, `execute_graceful_reload()` invokes `importlib.reload()` across `guard_db`, `gray_zone_evaluator`, and `security_evaluator` in-place.
   - CLI trigger: `python3 schengen_watcher.py --reload [--target <pane_id>]`.
2. **Target-Scoped Lockfile Naming**:
   - Target names are sanitized via `re.sub(r"[^a-zA-Z0-9_-]", "_", target)` producing `schengen_<target>.lock`.
   - `auto` uses `schengen_auto.lock`, while pane-specific modes use `schengen_<pane_id>.lock`.
3. **Session-Bound Lifetime Governance**:
   - Daemons must run as direct background tasks (`task-<id>`) under the orchestrating AGY session.
   - If an unexpected termination occurs, the active AGY session is mandated to auto-recover the watcher immediately.

---

## 🛡️ 5. Consequences & Trade-offs

- **Positive**:
  - Hotfixes to regex parsers (e.g. quote masking, `git rm` lookbehinds) apply instantly across all running sessions.
  - Zero inter-agent lockfile interference.
  - Test suite coverage expanded to 43 unit tests including dynamic reload verification.
- **Negative**:
  - Global variable states in reloaded modules must be designed to reset cleanly upon `importlib.reload()`.

---

## 📜 6. References & Cross-Links

- [ADR-003: AGY Native Task Integration & Singleton Governance](file:///Users/kyjbusan/code/herdr-schengen/docs/adr-003-agy-native-task-integration-and-singleton-governance.md)
- [ADR-004: Non-VCS Irreversible Mutation Governance](file:///Users/kyjbusan/code/herdr-schengen/docs/adr-004-non-vcs-irreversible-mutation-governance.md)
- [ADR-006: Destructive Intent Taxonomy & Hybrid SAST Pre-Execution Gate](file:///Users/kyjbusan/code/herdr-schengen/docs/adr-006-destructive-intent-taxonomy-and-sast-pre-execution-gate.md)
- [Herdr Schengen SKILL.md](file:///Users/kyjbusan/.agents/skills/herdr-schengen/SKILL.md)
