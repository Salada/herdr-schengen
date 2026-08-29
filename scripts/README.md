# scripts/ — Herdr Schengen (SmartGate) Modular Package Layout

This directory is the single source of truth (SSOT) for all SmartGate Python
code. It is organized into four domain-driven subpackages with **strict
dependency direction** (lower layers never import upper layers), so the module
graph remains a DAG with **no circular imports**.

## Dependency rule (the contract)

- `core/` — no imports from `tools/`, `cmd/`, or `adapters/`.
- `adapters/` — self-contained (runtime multiplexer client + agent adapters);
  imports only from `core/` where absolutely necessary (currently none).
- `tools/` — may import `core/` and `adapters/`.
- `cmd/` — may import `core/`, `tools/`, and `adapters/` (entry points).

Any new module must be placed in the lowest layer that satisfies its imports.
A module used by only one feature belongs next to that feature; a module used
widely belongs in `core/` (or `adapters/` for runtime clients).

## Layout

```
scripts/
├── __init__.py              # bootstrap: puts scripts/ on sys.path
├── README.md                # this file
├── core/                    # Core governance & persistence engine
│   ├── guard_db.py          # SQLite audit ledger + FIFO escalation queue
│   ├── security_evaluator.py# 1ms AST parser + deterministic rule engine
│   ├── gray_zone_evaluator.py # Non-VCS filesystem mutation risk classifier
│   ├── cloud_judge.py       # Cloud judge retry loop (OpenAI-compatible)
│   ├── session_memory.py    # Per-pane LRU session cache (fast-path approvals)
│   ├── session_cache.py     # Deterministic ruleset-version fingerprint cache
│   ├── feature_db.py        # FTS5 CJK feature-request backlog
│   ├── redaction.py         # Sensitive-credential redaction wrapper
│   ├── semgrep_evaluator.py # Semgrep SAST analyzer (used by security_evaluator)
│   └── shellcheck_evaluator.py # ShellCheck SAST analyzer (used by security_evaluator)
├── adapters/                # Multiplexer & host-runtime adapters
│   ├── herdr_client.py      # Herdr terminal multiplexer CLI client
│   └── agent_adapters/      # Strategy-pattern agent adapters (registry)
│       ├── base.py          # AgentAdapter interface + get_adapter registry
│       ├── agy.py           # Antigravity (AGY) dialog parser/injector
│       └── opencode.py      # OpenCode permission dialog parser/injector
├── tools/                   # Autonomous inspectors & LLM agents
│   ├── schengen_agent_llm.py # Dual-model Inspector/Judge pipeline + tool executor
│   └── schengen_inspector.py # Standalone semantic inspector CLI
└── cmd/                     # CLI entry points (runnable as `python scripts/cmd/…`)
    ├── schengen_watcher.py  # SmartGate guard daemon (SIGHUP hot reload)
    ├── schengen_tui.py      # Textual TUI (Controller/Observer)
    ├── schengen_history.py  # Audit history & queue CLI
    ├── schengen_feature.py  # Feature backlog CLI
    ├── schengen_mcp.py      # Model Context Protocol server
    ├── guard_watcher.py     # alias -> schengen_watcher.py (back-compat)
    ├── smartgate.py         # alias -> schengen_watcher.py (back-compat)
    └── trusted_clearance.py # alias -> schengen_watcher.py (back-compat)
```

## Import convention

- Always use **absolute subpackage imports**, never the flat module name:

  ```python
  from core.guard_db import DB_DIR, get_pending_escalations   # correct
  from tools.schengen_agent_llm import SchengenAgentChat      # correct
  from adapters.agent_adapters import get_adapter             # correct
  ```

- When a module needs to be referenced bare (e.g. `importlib.reload(guard_db)`),
  alias it: `import core.guard_db as guard_db`.

- Entry points (`cmd/*.py`) insert `scripts/` onto `sys.path` at import time so
  the absolute subpackage imports resolve when run directly
  (`python scripts/cmd/schengen_watcher.py`).

## Running

```bash
python3 scripts/cmd/schengen_tui.py                     # interactive TUI (single daemon lifecycle owner)
python3 scripts/cmd/schengen_watcher.py --status        # read-only diagnostics (spawn is deprecated, issue #114)
python3 scripts/cmd/schengen_history.py --pending       # escalation queue
python3 scripts/cmd/schengen_feature.py --list          # feature backlog
```

## Testing

```bash
HERDR_ENV=1 ~/.local/share/herdr-schengen-tui-venv/bin/python3 -m unittest discover -s tests
```
