# Herdr Schengen — Documentation Index

Machine- and LLM-friendly master index. Categories: **Architecture ADRs** / **Guides** /
**TODO** / **Issues & Archive**. Each entry lists a 1-line summary and the related
source-code path(s) under `scripts/`.

## 1. Architecture ADRs (`docs/adr/`)

| Doc | Status | Summary | Related source |
| :--- | :--- | :--- | :--- |
| [ADR-001](adr/adr-001-runtime-architecture-python-vs-go.md) | Active | Runtime choice: Python in-process AST vs Go binary (Python chosen). | `scripts/core/security_evaluator.py`, `scripts/cmd/schengen_watcher.py` |
| [ADR-002](adr/adr-002-dynamic-substitution-tool-calling-inspector.md) | Evolved | Dynamic-substitution tool-calling inspector for `$(cat ...)` payloads. | `scripts/core/security_evaluator.py` (LLM_INSPECTOR) |
| [ADR-003](adr/adr-003-agy-native-task-integration-and-singleton-governance.md) | Evolved | AGY-native task integration, singleton governance, watcher recovery. | `scripts/cmd/schengen_tui.py`, `opencode/plugins/schengen-host.js` |
| [ADR-004](adr/adr-004-non-vcs-irreversible-mutation-governance.md) | Active | Non-VCS irreversible-mutation governance & gray-zone matrix. | `scripts/core/gray_zone_evaluator.py`, `scripts/core/security_evaluator.py` (GRAY_ZONE_MATRIX) |
| [ADR-005](adr/adr-005-autonomous-orchestration-and-deadlock-defense.md) | Evolved | Multi-agent orchestration & deadlock-defense protocol. | `scripts/core/session_cache.py`, `scripts/cmd/schengen_watcher.py` |
| [ADR-006](adr/adr-006-destructive-intent-taxonomy-and-sast-pre-execution-gate.md) | Evolved | Destructive-intent taxonomy & hybrid SAST pre-execution gate. | `scripts/core/security_evaluator.py`, `scripts/core/shellcheck_evaluator.py`, `scripts/core/semgrep_evaluator.py` |
| [ADR-007](adr/adr-007-graceful-dynamic-reload-and-target-scoped-lockfiles.md) | Active | SIGHUP graceful reload & target-scoped lockfiles. | `scripts/cmd/schengen_watcher.py` (--reload) |
| [ADR-008](adr/adr-008-opencode-alternative-host-runtime.md) | Evolved | OpenCode as alternative host runtime (agent-agnostic governance). | `opencode/plugins/schengen-host.js`, `scripts/cmd/schengen_watcher.py` |
| [ADR-009](adr/adr-009-smartgate-tui-dual-model-and-fifo-governance.md) | Active | SmartGate TUI, dual-model phase routing, strict FIFO escalation. | `scripts/cmd/schengen_tui.py`, `scripts/tools/schengen_agent_llm.py`, `scripts/tools/schengen_inspector.py` |
| [ADR-010](adr/adr-010-modular-architecture-core-tools-cmd-adapters.md) | Active | Modular architecture: core / tools / cmd / adapters separation. | `scripts/{core,tools,cmd,adapters}/` layout |
| [ADR-011](adr/adr-011-default-llm-provider-openai-deepseek-removal.md) | Active | Default LLM provider: OpenAI (gpt-5.6-luna), DeepSeek opt-in only. | `scripts/core/cloud_judge.py`, `scripts/tools/schengen_agent_llm.py` |
| [ADR-012](adr/adr-012-high-contrast-text-selection.md) | Active | High-contrast text-selection visibility in the TUI. | `scripts/cmd/schengen_tui.py` |
| [ADR-013](adr/adr-013-opencode-structured-permission-channel.md) | Active | OpenCode structured permission channel & programmatic approval. | `opencode/plugins/schengen-host.js`, `scripts/adapters/agent_adapters/` |
| [ADR-014](adr/adr-014-escalation-phase-model-and-ephemeral-ipc.md) | Active | Escalation phase model (in-flight / judging / human-required) & ephemeral cross-process IPC. | `scripts/core/security_evaluator.py` (`_emit_phase`), `scripts/cmd/schengen_watcher.py`, `scripts/cmd/schengen_tui.py` |
| [ADR-015](adr/adr-015-gatekeeper-advisory-only-governance.md) | Active | Gatekeeper advisory-only governance: human final authority, no autonomous reject (Disagree & Commit regression fix). | `scripts/tools/schengen_agent_llm.py`, `scripts/core/security_evaluator.py` |

## 2. Guides (`docs/guides/`)

| Doc | Summary | Related source |
| :--- | :--- | :--- |
| [setup.md](guides/setup.md) | Full setup, dependencies & OpenCode integration. | `scripts/cmd/schengen_tui.py`, `opencode/plugins/schengen-host.js` |
| [setup-from-scratch.md](guides/setup-from-scratch.md) | Clean-machine bootstrap with portable `$SCHENGEN_HOME/.venv`. | `scripts/cmd/schengen_tui.py`, `scripts/cmd/schengen_watcher.py` |
| [configuration.md](guides/configuration.md) | Environment variables, `config/schengen_watcher.json`, runtime state. | `scripts/core/guard_db.py`, `scripts/tools/schengen_agent_llm.py`, `config/schengen_watcher.json` |
| [github-mirror.md](guides/github-mirror.md) | GitHub one-way distribution mirror policy. | `README.github.md` |
| [db-migration.md](guides/db-migration.md) | SQLite schema migration runbook (`adjudication_log` provenance columns). | `scripts/core/guard_db.py` (`init_db`) |

## 3. TODO (`docs/todo/`)

| Doc | Summary | Related source |
| :--- | :--- | :--- |
| [TODO_phase1.md](todo/TODO_phase1.md) | Phase-1 backlog (core gate, allowlist, audit) — Completed. | `scripts/core/security_evaluator.py` |
| [TODO_phase2.md](todo/TODO_phase2.md) | Phase-2 backlog (adapters, escalation, codex support) — Completed. | `scripts/adapters/`, `scripts/cmd/schengen_tui.py` |
| [TODO_phase3.md](todo/TODO_phase3.md) | Phase-3 backlog (Sprint 1/2/3, provenance split, settings modal) — Completed. | `scripts/cmd/schengen_tui.py`, `scripts/tools/` |
| [TODO_phase4.md](todo/TODO_phase4.md) | Phase-4 active backlog (Sprint 4 parallel concurrency, #3670 fast-track, #4027 heredoc). | `scripts/core/`, `scripts/cmd/`, `scripts/tools/` |


## 4. Issues & Archive

| Doc | Summary | Related source |
| :--- | :--- | :--- |
| [bloat_message_opencode.md](issues/bloat_message_opencode.md) | OpenCode approval-feedback bloat issue record. | `opencode/plugins/schengen-host.js` |
| [motivation.md](archive/motivation.md) | Archived background, design philosophy & maintenance commitment. | — (context) |
| [BENCHMARK_SLM_CHOICE.md](archive/BENCHMARK_SLM_CHOICE.md) | SLM choice benchmark notes. | `scripts/tools/schengen_agent_llm.py` |
| [diary.md](archive/diary.md) | Development diary. | — (context) |
| [handoff-2026-08-27.md](archive/handoff-2026-08-27.md) | Session handoff (2026-08-27). | — (context) |
| [handoff-2026-08-29.md](archive/handoff-2026-08-29.md) | Session handoff (2026-08-29). | — (context) |
| [json_data_beautify.md](archive/json_data_beautify.md) | JSON data beautify design note. | `scripts/tools/` (TUI rendering) |
