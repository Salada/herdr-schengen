# 🤖 AGENTS.md — Herdr-Schengen (SmartGate) Autonomous Engineering Guide

> **Target Audience**: Autonomous Coding Agents (Antigravity/AGY, Hermes, Codex) & Security Engineers.  
> **Repository**: `InhouseOriented/herdr-schengen` (Self-contained Security Daemon & Skill).  
> **Source Directory**: `~/code/herdr-schengen/`  
> **Runtime Skill Mirrors**: `~/.agents/skills/herdr-schengen/`, `~/.gemini/skills/herdr-schengen/`

---

## 🧭 1. Core Operating Principles (Self-Contained Rules)

1. **Autonomous Repository Autonomy**:
   - `herdr-schengen` is a 100% self-contained codebase. All architectural specifications, evaluation matrices, and multi-agent protocols are fully defined within this repository's `docs/adr-*.md` series.
   - Do not create external documentation dependencies or hard-link assumptions to other repositories.

2. **Dual-Sync Contract with Runtime Skills**:
   - The source Git repository (`~/code/herdr-schengen/`) is the absolute SSOT.
   - When modifying files (scripts, docs, SKILL.md), always write, test, and commit them in `~/code/herdr-schengen/`, then mirror to `~/.agents/skills/herdr-schengen/` and `~/.gemini/skills/herdr-schengen/`.
   - **Ephemeral Runtime Testing**: Live debugging directly in `~/.agents/skills/` is permitted only for immediate hypothesis verification, but final code must be authored, tested, and committed inside `~/code/herdr-schengen/` (never blind reverse-copied).

3. **In-Process Graceful Reload via SIGHUP (0ms Downtime)**:
   - When modifying rule sets or evaluators, do NOT kill the daemon process. Use `python3 scripts/schengen_watcher.py --reload` to trigger an instant in-process hot reload via `importlib.reload()` and `SIGHUP`.

4. **100% Unit Test Baseline**:
   - Before committing any changes, verify all test suites pass without error:
     ```bash
     python3 -m unittest discover -s tests
     ```

5. **Bot Git Attribution Policy**:
   - Always commit using `bot-agy-macmini <bot-agy-macmini@noreply.localhost>` and include required trailers (`Co-authored-by`, `Agent`, `Op`, `Effort`).

6. **Mandatory Isolated Worktree & Reviewer Isolation Mandate**:
   - ❌ **Never** stack multiple concurrent tasks, feature branches, or peer reviews directly in the default `~/code/herdr-schengen/` working tree.
   - ✅ **Developer Agents**: Always spawn a dedicated worktree (`git worktree add -b feat/<name> ~/code/herdr-schengen-worktrees/<name> main`) for each new feature/PR.
   - ✅ **Reviewer Hermes Agents**: In shared container profiles, never execute bare `git checkout` in the root repository. Always allocate an isolated reviewer worktree (`git worktree add ~/code/herdr-schengen-worktrees/review-<role> origin/<branch>`) to prevent cross-reviewer race conditions and disk pollution.

7. **Proactive Escalation Polling & Idle Defense Mandate**:
   - ❌ **Never** remain passive when worker panes are actively executing long-running or potentially dangerous workflows.
   - ✅ **Always** arm a proactive wakeup heartbeat timer (`schedule DurationSeconds=120, TimerCondition="any"`) before entering idle state, and drain the SQLite queue (`schengen_history.py --pending`) upon every wake turn to ensure blocked escalations are surfaced immediately.
---

## 🗺️ 2. Architecture & Decision Records (ADR SSOT)

This repository serves as the single source of truth (SSOT) for the Schengen Security Gatekeeper:

| ADR File | Title & Core Scope |
| :--- | :--- |
| **[ADR-001](./docs/adr-001-runtime-architecture-python-vs-go.md)** | Runtime & Architecture Selection (Python In-Process AST vs Go Binary) |
| **[ADR-002](./docs/adr-002-dynamic-substitution-tool-calling-inspector.md)** | Dynamic Tool-Calling Semantic Inspector for Subshell Substitutions |
| **[ADR-003](./docs/adr-003-agy-native-task-integration-and-singleton-governance.md)** | AGY Native Streaming Task Integration & Proactive Watcher Recovery |
| **[ADR-004](./docs/adr-004-non-vcs-irreversible-mutation-governance.md)** | Non-VCS Irreversible Mutation Governance & Filesystem Gray-Zone Evaluation |
| **[ADR-005](./docs/adr-005-autonomous-orchestration-and-deadlock-defense.md)** | Autonomous Multi-Agent Orchestration & Deadlock Defense Protocol |
| **[ADR-006](./docs/adr-006-destructive-intent-taxonomy-and-sast-pre-execution-gate.md)** | Destructive Intent Taxonomy & Hybrid SAST Pre-Execution Security Gate |
| **[ADR-007](./docs/adr-007-graceful-dynamic-reload-and-target-scoped-lockfiles.md)** | Graceful Dynamic Reload (SIGHUP) & Target-Scoped Lockfile Architecture |
| **[ADR-008](./docs/adr-008-opencode-alternative-host-runtime.md)** | OpenCode as Alternative Host Runtime (Agent-Agnostic Session-Bound Governance) |
| **[ADR-009](./docs/adr-009-smartgate-tui-dual-model-and-fifo-governance.md)** | SmartGate TUI, Dual-Model Phase Routing, and Strict Sequential FIFO Escalation Governance |

---

## ⚡ 3. Everyday SOPs

### SOP-01: Updating Guard Rules & Hot-Reloading
```bash
# 1. Edit evaluator in source repo
nvim ~/code/herdr-schengen/scripts/security_evaluator.py
# 2. Run test suite
python3 -m unittest discover -s tests
# 3. Mirror to runtime skill
cp -r ~/code/herdr-schengen/scripts/ ~/.agents/skills/herdr-schengen/scripts/
# 4. Gracefully hot-reload running daemon via SIGHUP (0ms downtime)
python3 ~/.agents/skills/herdr-schengen/scripts/schengen_watcher.py --reload
```

### SOP-02: Documenting New Architectural Decisions
```bash
# 1. Create docs/adr-00X-<title>.md
# 2. Link only to internal ADRs using relative paths (./adr-00X-*.md)
# 3. Sync to skill docs
cp -r ~/code/herdr-schengen/docs/ ~/.agents/skills/herdr-schengen/docs/
```
