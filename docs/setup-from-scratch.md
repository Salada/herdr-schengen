# Setup from scratch

This guide is for a person or LLM setting up a fresh checkout. It assumes Herdr
and the coding agent to be guarded are already installed. It does not require
this checkout to live in a dotfiles directory.

## 1. Clone and prepare Python

Choose any local directory, then record the absolute checkout path for the
commands below.

```bash
git clone <repository-url> "$HOME/src/herdr-schengen"
cd "$HOME/src/herdr-schengen"
export SCHENGEN_HOME="$(pwd -P)"

python3 -m venv "$SCHENGEN_HOME/.venv"
"$SCHENGEN_HOME/.venv/bin/pip" install --upgrade pip
"$SCHENGEN_HOME/.venv/bin/pip" install textual rich httpx
```

Required host tools are Python 3.9 or newer, `git`, and `shellcheck` in
`PATH`. ShellCheck is used by the static security evaluation lane. Install it
through the operating system's normal package manager before running the
watcher.

## 2. Keep the runtime inside this checkout

The optional OpenCode plugin has a historical default path under
`~/.agents/skills`. Override it so the plugin always calls this checkout:

```bash
export SCHENGEN_HISTORY_PATH="$SCHENGEN_HOME/scripts/cmd/schengen_history.py"
```

Set this variable in the environment that launches OpenCode, not only in a
separate shell. If you use the plugin, install its repository copy and restart
OpenCode:

```bash
mkdir -p ~/.config/opencode/plugins
cp "$SCHENGEN_HOME/opencode/plugins/schengen-host.js" \
  ~/.config/opencode/plugins/schengen-host.js
```

The repository already contains its redaction logic in
`scripts/core/redaction.py`; no external dotfiles script needs to be copied.

## 3. Optional LLM configuration

Static, local decisions and the test suite do not require an API key. The
semantic Inspector/Judge lane uses OpenAI-compatible environment variables when
enabled. Keep real credentials in your own secret manager or launcher
configuration and never commit them:

```bash
export OPENAI_API_KEY="<your-secret>"
export OPENAI_BASE_URL="https://api.openai.com/v1"  # optional override
```

The default state directory is `~/.local/state/herdr-schengen`. It contains the
SQLite audit database and runtime channels; it is intentionally outside the
repository.

## 4. Verify and run

Run tests from the checkout:

```bash
HERDR_ENV=1 "$SCHENGEN_HOME/.venv/bin/python" -m unittest discover -s "$SCHENGEN_HOME/tests" -v
"$SCHENGEN_HOME/.venv/bin/python" "$SCHENGEN_HOME/scripts/cmd/schengen_watcher.py" --status
```

Launch the TUI in a dedicated Herdr pane:

```bash
"$SCHENGEN_HOME/.venv/bin/python" "$SCHENGEN_HOME/scripts/cmd/schengen_tui.py"
```

The TUI owns watcher lifecycle. Do not start the watcher directly with
`--target auto`; use `--status` only for diagnostics. For a useful live status,
run the command from an active Herdr environment with the intended agent pane
available.
