# ADR-010: Modular Architecture — Core, Tools, Cmd, and Adapters Separation

## Status
**Accepted**

## Context
Previously, all Python scripts in `herdr-schengen` resided directly in a flat `scripts/` directory. As the system expanded to include AST evaluators, SQLite backlogs, Textual TUI dashboards, Claude/DeepSeek dual-model chains, and terminal multiplexer adapters, maintaining all files in a single flat namespace compromised modularity, code organization, and architectural clarity.

## Decision
We refactored `scripts/` into a 4-tier domain-driven package hierarchy while maintaining 100% backward compatibility for all existing CLI commands, skills, and unit tests:

1. **`scripts/core/` (Core Governance & Persistence Engine)**:
   - `security_evaluator.py`: 1ms AST parsing, rule engine, session safe pattern template matching.
   - `gray_zone_evaluator.py`: Non-VCS filesystem gray-zone mutation risk classifier.
   - `guard_db.py`: SQLite audit ledger, sequential FIFO escalation queue state machine.
   - `session_memory.py`: Per-pane LRU session cache and fast-path approval bypass.
   - `cloud_judge.py`: Synchronous cloud judge retry loop with TCP timeouts.
   - `feature_db.py`: FTS5 CJK trigram feature request backlog.
   - `redaction.py`: Security redaction of sensitive credentials.

2. **`scripts/tools/` (Autonomous Inspectors & LLM Agents)**:
   - `schengen_agent_llm.py`: Dual-model Inspector/Judge reasoning pipeline and tool calling executor.
   - `schengen_inspector.py`: Standalone CLI semantic inspector.
   - `shellcheck_evaluator.py` & `semgrep_evaluator.py`: Static analysis analyzers.

3. **`scripts/cmd/` (CLI Application Entrypoints)**:
   - `schengen_watcher.py`: SmartGate background guard daemon with SIGHUP hot reload.
   - `schengen_tui.py`: Textual interactive dashboard (Leader-Observer controller pattern).
   - `schengen_history.py`: Audit history and queue management CLI.
   - `schengen_feature.py`: Feature backlog CLI.
   - `schengen_mcp.py`: Model Context Protocol server.

4. **`scripts/adapters/` (Multiplexer & Host Runtime Adapters)**:
   - `herdr_client.py`: Herdr terminal multiplexer CLI client.
   - `agent_adapters/`: OpenCode and Antigravity host runtime adapters.

## Backward Compatibility & Shims
To guarantee zero breaking changes for existing daemon invocations, runtime skills (`~/.agents/skills/`, `~/.gemini/skills/`), and automation scripts:
- Root files in `scripts/` remain as clean facade shims importing from their respective subpackages.
- Package `__init__.py` automatically resolves and exports module paths into `sys.path`.

## Consequences
- **High Cohesion & Low Coupling**: Clear boundaries between core AST engines, autonomous LLM tools, CLI entrypoints, and runtime adapters.
- **Zero Regression**: 219/219 unit tests passing with Pyright 0 errors.
