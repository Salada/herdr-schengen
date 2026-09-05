# 🤖 AGENTS.md — Herdr-Schengen (SmartGate) Autonomous Engineering Guide

> **Target Audience**: Autonomous Coding Agents (Antigravity/AGY, Hermes, Codex) & Security Engineers.  
> **Repository**: `InhouseOriented/herdr-schengen` (Self-contained Security Daemon & Skill).  
> **Source Directory**: `~/code/herdr-schengen/`  
> **Runtime Skill Mirrors**: `~/.agents/skills/herdr-schengen/`, `~/.gemini/skills/herdr-schengen/`

---

## 🧭 1. Core Operating Principles (Self-Contained Rules)

1. **Source SSOT & Runtime Mirroring**:
   - `herdr-schengen` is 100% self-contained: all architecture/evaluation specs live in this repo's `docs/adr/adr-*.md` — no external documentation dependencies.
   - The source Git repository (`~/code/herdr-schengen/`) is the absolute SSOT. Write, test, and commit there, then mirror to `~/.agents/skills/herdr-schengen/` and `~/.gemini/skills/herdr-schengen/`.
   - **Ephemeral Runtime Testing**: live debugging in `~/.agents/skills/` is permitted only for immediate hypothesis verification; final code must be authored, tested, and committed in the source repo (never blind reverse-copied).

2. **Single-Writer & TUI-Owned Daemon Lifecycle**:
   - Only **one** process owns each stateful resource: the TUI owns the daemon lifecycle and the FIFO escalation queue; the watcher is the single writer of audit/queue records; companion CLIs (`schengen_history.py`, `schengen_feature.py`, `schengen_mcp.py`) are read-only or operate on their own storage.
   - ❌ **Never** spawn, kill, or reload the daemon outside the TUI (`Ctrl+T`) — non-TUI daemon lifecycle is deprecated (ADR-008/009, Issue #114).
   - For rule/evaluator changes, hot-reload in-process via SIGHUP (0ms downtime, ADR-007) instead of restarting the daemon.

3. **100% Unit Test Baseline**:
   - Before committing any changes, verify all test suites pass without error:
     ```bash
     python3 -m unittest discover -s tests
     ```

4. **Bot Git Attribution Policy**:
   - Commit using the active agent's bot identity (per `agent-git-attribution-policy`; see `docs/agent-handoff.md`) with required trailers (`Co-authored-by`, `Agent`, `Op`, `Effort`).

5. **Mandatory Isolated Worktree & Reviewer Isolation Mandate**:
   - ❌ **Never** stack multiple concurrent tasks, feature branches, or peer reviews directly in the default `~/code/herdr-schengen/` working tree.
   - ✅ **Developer Agents**: always spawn a dedicated worktree (`git worktree add -b feat/<name> ~/code/herdr-schengen-worktrees/<name> main`) for each feature/PR.
   - ✅ **Reviewer Agents**: in shared container profiles, never bare `git checkout` in the root repo — allocate an isolated reviewer worktree to prevent cross-reviewer race conditions.

6. **Proactive Escalation Polling**:
   - Never idle passively while worker panes run long or risky workflows. Before idling, arm a wakeup heartbeat timer (`schedule DurationSeconds=120`); on every wake, drain the pending queue (`schengen_history.py --pending`) so blocked escalations surface immediately.

7. **Peer Review Output**:
   - Author all multi-agent peer reviews, persona evaluations (DBA, PdM, SOLID Architect), and audit critiques in concise, professional English.
   - Never leave reviewer opinions ephemeral in Herdr panes — post each persona's unabridged report to the Forgejo PR via the issue-comments API (`/api/v1/repos/.../issues/<id>/comments`) for immutable audit history.

8. **Question-Dialog Non-Adjudication Invariant**:
   - A target agent's human **question dialog** (opencode `esc dismiss`, codex `enter to submit answer`, AGY `Question N/M:`) is a *subjective request for the human*, NOT a command to approve.
   - ❌ **Never** auto-approve/reject/adjudicate a question. The gatekeeper may surface/interpret it **read-only** (`allow_adjudication=False` — adjudication tools removed) but never adjudicate; leave it pending until the user answers directly in the agent pane.

9. **Decision Bias: Human Final Authority & Fail-Closed**:
   - The human is the final decision authority (ADR-015 P1). The gatekeeper autonomously approves only what it can prove safe, and never autonomously rejects gray-zone/ambiguous commands (advisory-only; Tier-A denylist is the sole autonomous-reject case).
   - On analyzer error, cache miss, or LLM outage, defer ambiguous commands to the human — never auto-approve; fail-open only for provably side-effect-free local reads (`ls`, `git status`) with a visible `[GATE DEGRADED]` banner (ADR-006).

10. **One-Way GitHub Distribution Mirror**:
    - ❌ **Never** develop, open issues, merge, or commit directly on GitHub — all development and issue tracking happen exclusively on the private Forgejo (`salada-git`).
    - ✅ GitHub (`github.com/Salada/herdr-schengen`) is a **one-way distribution snapshot mirror only**: after a Forgejo `main` merge, push the snapshot (`git push github main:main`).

11. **TOCTOU Guard Fuzzy/Prefix Matching**:
    - Command-string guards that fire just before key injection must tolerate terminal viewport soft-wrap truncation and path-expression variance (`~` vs absolute, directory vs file).
    - ✅ Use prefix / upper-directory / semantic comparison, never exact `==` string equality (incidents #3143/#3219 key-injection drop).
---

## 🗺️ 2. Architecture & Decision Records (ADR SSOT)

This repository serves as the single source of truth (SSOT) for the Schengen Security Gatekeeper:

| ADR File | Status | Title & Core Scope |
| :--- | :--- | :--- |
| **[ADR-001](./docs/adr/adr-001-runtime-architecture-python-vs-go.md)** | Active | Runtime & Architecture Selection (Python In-Process AST vs Go Binary) |
| **[ADR-002](./docs/adr/adr-002-dynamic-substitution-tool-calling-inspector.md)** | Evolved | Dynamic Tool-Calling Semantic Inspector for Subshell Substitutions |
| **[ADR-003](./docs/adr/adr-003-agy-native-task-integration-and-singleton-governance.md)** | Superseded | AGY Native Streaming Task Integration & Proactive Watcher Recovery (superseded by ADR-008/009) |
| **[ADR-004](./docs/adr/adr-004-non-vcs-irreversible-mutation-governance.md)** | Active | Non-VCS Irreversible Mutation Governance & Filesystem Gray-Zone Evaluation |
| **[ADR-005](./docs/adr/adr-005-autonomous-orchestration-and-deadlock-defense.md)** | Evolved | Autonomous Multi-Agent Orchestration & Deadlock Defense Protocol |
| **[ADR-006](./docs/adr/adr-006-destructive-intent-taxonomy-and-sast-pre-execution-gate.md)** | Evolved | Destructive Intent Taxonomy & Hybrid SAST Pre-Execution Security Gate |
| **[ADR-007](./docs/adr/adr-007-graceful-dynamic-reload-and-target-scoped-lockfiles.md)** | Active | Graceful Dynamic Reload (SIGHUP) & Target-Scoped Lockfile Architecture |
| **[ADR-008](./docs/adr/adr-008-opencode-alternative-host-runtime.md)** | Superseded | OpenCode as Alternative Host Runtime (superseded by ADR-009/013) |
| **[ADR-009](./docs/adr/adr-009-smartgate-tui-dual-model-and-fifo-governance.md)** | Evolved | SmartGate TUI, Dual-Model Phase Routing, and Strict Sequential FIFO Escalation Governance |
| **[ADR-010](./docs/adr/adr-010-modular-architecture-core-tools-cmd-adapters.md)** | Active | Modular Architecture: Core, Tools, Cmd, and Adapters Separation |
| **[ADR-011](./docs/adr/adr-011-default-llm-provider-openai-deepseek-removal.md)** | Active | Default LLM Provider (OpenAI gpt-5.6-luna, DeepSeek opt-in) |
| **[ADR-012](./docs/adr/adr-012-high-contrast-text-selection.md)** | Active | High-Contrast Text-Selection Visibility in the TUI |
| **[ADR-013](./docs/adr/adr-013-opencode-structured-permission-channel.md)** | Active | OpenCode Structured Permission Channel & Programmatic Approval |
| **[ADR-014](./docs/adr/adr-014-escalation-phase-model-and-ephemeral-ipc.md)** | Active | Escalation Phase Model & Ephemeral Cross-Process IPC |
| **[ADR-015](./docs/adr/adr-015-gatekeeper-advisory-only-governance.md)** | Active | Gatekeeper Advisory-Only Governance (Human Final Authority, No Autonomous Reject) |
| **[ADR-016](./docs/adr/adr-016-judge-observability-and-runtime-provenance.md)** | Active | Explicit no-tool-call outcomes, decision-source audit, and installed revision provenance |
| **[ADR-017](./docs/adr/adr-017-canonical-capture-and-monotonic-normalization.md)** | Active | Canonical pane capture, monotonic normalization, and deterministic re-entry for LLM reconstruction |

---

## 📦 3. Setup, Dependencies & OpenCode Integration

For full setup, installation, and environment variable configuration, refer to **[docs/guides/setup.md](./docs/guides/setup.md)** and **[docs/guides/configuration.md](./docs/guides/configuration.md)**:

- **Dedicated Virtualenv**: `~/.local/share/herdr-schengen-tui-venv`
- **Core TUI Dependencies**: `textual`, `rich`, `httpx`
- **OpenCode Subagent Sync**: In `opencode.jsonc`, `agent.schengen.model` and `small_model` automatically synchronize to Schengen Inspector/Judge phases.
- **Key Files**:
  - `scripts/core/security_evaluator.py` — deterministic layers (fast-track / denylist / complexity / quote·escape masking)
  - `scripts/tools/schengen_agent_llm.py` — gatekeeper LLM (Tier A/B/C triage) + approve/reject dispatch
  - `scripts/adapters/agent_adapters/{agy,codex,opencode}.py` — per-agent key injection
  - `scripts/cmd/schengen_tui.py` — TUI
  - `docs/adr/` — ADR SSOT · `docs/todo/TODO_phase4.md` — active backlog

---

## ⚡ 4. Everyday SOPs

### SOP-01: Updating Guard Rules & Hot-Reloading
```bash
# 1. Edit evaluator in source repo
nvim ~/code/herdr-schengen/scripts/core/security_evaluator.py
# 2. Run test suite
HERDR_ENV=1 ~/.local/share/herdr-schengen-tui-venv/bin/python3 -m unittest discover -s tests
# 3. Install the tested source into both runtime mirrors (stamps source revision)
python3 scripts/cmd/schengen_install.py \
  --target ~/.agents/skills/herdr-schengen \
  --target ~/.gemini/skills/herdr-schengen
# 4. Restart the daemon via TUI (Ctrl+T) — non-TUI reload is deprecated (Rule 2 / ADR-009)
```

### SOP-02: Launching Interactive Gatekeeper TUI
```bash
~/.local/share/herdr-schengen-tui-venv/bin/python3 ~/code/herdr-schengen/scripts/cmd/schengen_tui.py
```

### SOP-03: Documenting New Architectural Decisions
```bash
# 1. Create docs/adr/adr-00X-<title>.md
# 2. Link only to internal ADRs using relative paths (./adr-00X-*.md)
# 3. Re-run the repository installer after tests pass
python3 scripts/cmd/schengen_install.py --target ~/.agents/skills/herdr-schengen
```
