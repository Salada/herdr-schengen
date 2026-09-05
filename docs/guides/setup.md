# 🛠️ Herdr-Schengen (SmartGate) Setup & Installation Guide

> **Target Audience**: Human Operators & Autonomous Coding Agents (Antigravity/AGY, OpenCode, Codex, Hermes).  
> **Repository**: `InhouseOriented/herdr-schengen`  
> **Source Directory**: `~/code/herdr-schengen/`  
> **Runtime Skill Mirrors**: `~/.agents/skills/herdr-schengen/`, `~/.gemini/skills/herdr-schengen/`

---

## 📋 1. Prerequisites

1. **Operating System**: macOS (Apple Silicon / Intel) or Linux (Ubuntu / Alpine).
2. **Python Runtime**: `python3` (>= 3.9) with standard `venv` and `sqlite3` modules.
3. **Herdr Multiplexer**: `herdr` CLI installed and active session (`HERDR_ENV=1`).
4. **ShellCheck**: `shellcheck` binary in `$PATH` (for SAST fast-track evaluation).
5. **Semgrep** (required): `semgrep` CLI in `$PATH` — declared dependency (`pyproject.toml`, `semgrep>=1.70.0`). Install into the TUI venv below (`pip install 'semgrep>=1.70.0'`) or via `brew install semgrep`. The daemon's host-runtime gate **hard-fails** at startup if `semgrep` is missing (INV-2 fail-closed).

---

## 📦 2. Virtual Environment & Dependencies

SmartGate TUI relies on modern terminal UI and asynchronous HTTP libraries. To prevent polluting the system Python environment, all TUI dependencies are isolated in a dedicated user-space virtual environment:

### Step 1: Create Dedicated Virtualenv
```bash
python3 -m venv ~/.local/share/herdr-schengen-tui-venv
```

### Step 2: Install Required Dependencies
```bash
~/.local/share/herdr-schengen-tui-venv/bin/pip install --upgrade pip
~/.local/share/herdr-schengen-tui-venv/bin/pip install textual rich httpx 'semgrep>=1.70.0'
```

### Dependency Reference Matrix

| Package | Minimum Version | Scope | Purpose |
|:---|:---:|:---:|:---|
| `textual` | `>= 0.80.0` | TUI | Reactive terminal user interface, layout containers, widgets, command palette |
| `rich` | `>= 13.0.0` | TUI / Logging | Styled markup rendering, ANSI escaping, text formatting |
| `httpx` | `>= 0.27.0` | Dual-Model Agent | Async HTTP client for Inspector and Judge OpenAI-compatible LLM endpoints |
| `semgrep` | `>= 1.70.0` | SAST (required) | SAST pre-filter core (declared dependency). Missing binary hard-fails daemon startup (INV-2) |

---

## 🔑 3. Environment Variables & Credentials

SmartGate supports unified credential loading from user profile (`~/.zshrc`) or Bitwarden secrets:

### 1) Standard Unified Fallback
```bash
export OPENAI_API_KEY="sk-..."           # OpenAI-standard (default provider)
export OPENAI_BASE_URL="https://api.openai.com/v1"
# Optional: keep using a self-hosted / alternate OpenAI-compatible endpoint
# (e.g. DeepSeek at home): export OPENAI_BASE_URL="https://api.deepseek.com/v1"
```

### 2) Dual-Model Phase Overrides (Optional / Advanced)
You can configure independent models and endpoints for Phase 1 (Inspector tool-calling) and Phase 2 (Judge adjudication):

```bash
# Phase 1: Fast Tool-Calling Inspector
export SCHENGEN_INSPECTOR_API_KEY="sk-..."
export SCHENGEN_INSPECTOR_BASE_URL="https://api.openai.com/v1"
export SCHENGEN_INSPECTOR_MODEL="gpt-5.6-luna"

# Phase 2: High-Precision Adjudication Judge
export SCHENGEN_JUDGE_API_KEY="sk-..."
export SCHENGEN_JUDGE_BASE_URL="https://api.openai.com/v1"
export SCHENGEN_JUDGE_MODEL="gpt-5.6-luna"
```

### 3) OpenCode Subagent Model Synchronization
When `SCHENGEN_INSPECTOR_MODEL` is not explicitly set, SmartGate automatically reads `~/.config/opencode/opencode.jsonc` and synchronizes with OpenCode's subagent / small model:
- `agent.schengen.model` (e.g. `gpt-5.6-luna`)
- `small_model` (e.g. `gpt-5.6-luna`)

---

## 🚀 4. How to Launch & Run

### Install or update runtime skill mirrors

Run the repository-owned installer from the tested source checkout. It copies
only Git-tracked files in the supported runtime surface, removes stale files
from its managed directories, and stamps the exact Git revision. It accepts
only the two runtime skill roots below, refuses a dirty source checkout, and
rejects symlinks in the destination path. It does not start, stop, or reload
the daemon.

```bash
cd ~/code/herdr-schengen
python3 scripts/cmd/schengen_install.py \
  --target ~/.agents/skills/herdr-schengen \
  --target ~/.gemini/skills/herdr-schengen
```

### Option A: Interactive Textual TUI (Recommended in Dedicated Herdr Pane)
In a dedicated Herdr pane (e.g. `w1D:p7`):

```bash
export SCHENGEN_HOME="${SCHENGEN_HOME:-$HOME/code/herdr-schengen}"
~/.local/share/herdr-schengen-tui-venv/bin/python3 "$SCHENGEN_HOME/scripts/cmd/schengen_tui.py"
```

### Option B: Standalone Background Watcher Daemon (deprecated — issue #114)

> The daemon lifecycle is owned exclusively by the TUI (`Ctrl+T`). Direct
> `schengen_watcher.py --target auto` is deprecated. The `--status`/`--reload`/
> `--stop` subcommands remain as read-only diagnostics / TUI-internal ops.

```bash
# Read-only diagnostics (NOT lifecycle — the TUI owns start/stop/reload)
python3 "$SCHENGEN_HOME/scripts/cmd/schengen_watcher.py" --status
```

---

## ⌨️ 5. TUI Keybindings & Command Reference

| Key / Command | Action | Description |
|:---|:---|:---|
| `Ctrl + T` (or `/toggle`) | **Toggle Daemon** | Starts or safely stops the background SmartGate watcher daemon |
| `Ctrl + Y` | **Copy Chat** | Copies the complete plain-text conversation & tool log to macOS clipboard (`pbcopy`) |
| `Ctrl + L` (or `/clear`) | **Clear Screen** | Clears the TUI chat viewport and resets the local clipboard buffer |
| `Ctrl + P` | **Command Palette** | Opens the centered 72ch modal palette for quick actions |
| `/approve <id> [note]` | **Approve** | Manually approves an escalation and injects Tab-Amend security feedback |
| `/reject <id> [reason]` | **Reject** | Manually rejects an escalation and cancels the worker prompt with feedback |

---

## 🧪 6. Self-Verification & Automated Tests

To ensure the environment is fully operational:

```bash
# 1. Run full unit and E2E test suite (100% PASS baseline)
HERDR_ENV=1 ~/.local/share/herdr-schengen-tui-venv/bin/python3 -m unittest discover -s tests

# 2. Run static type checker
pyright scripts/tools/schengen_agent_llm.py scripts/cmd/schengen_tui.py
```

---

## ❓ 7. Troubleshooting

1. **`ModuleNotFoundError: No module named 'textual'`**:
   - Ensure you are running the script using the dedicated virtualenv binary:
     `~/.local/share/herdr-schengen-tui-venv/bin/python3 scripts/cmd/schengen_tui.py`
2. **`[SCHENGEN_FATAL] Execution rejected: must run within an active agent session`**:
   - Schengen requires an active Herdr session (`HERDR_ENV=1`) and an agent session marker (`ANTIGRAVITY_AGENT=1` or `OPENCODE=1`).
3. **Clipboard copy (`Ctrl+Y`) shows error on Linux**:
   - macOS uses `pbcopy` by default. On Linux, ensure `xclip` or `wl-copy` is installed if running outside macOS.
