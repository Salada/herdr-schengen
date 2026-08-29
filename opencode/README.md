# OpenCode Host Plugin — Herdr Schengen (SmartGate)

This plugin provides the OpenCode-side of the **permission.reply pipeline**
(issue #57 full closure): it observes `permission.asked` events, writes them to
the per-pane channel (the watcher daemon's clean command source), then polls the
watcher's decision file and replies programmatically via `client.permission` —
approval bound to the exact `permission_id` (no bare `send-keys enter`).

The guard **daemon lifecycle** (start/stop/reload) is owned **exclusively by the
Schengen TUI** (`Ctrl+T`), NOT this plugin (issue #114). Escalation surfacing is
also the TUI's responsibility.

## Files

| File | Purpose |
| :--- | :--- |
| `plugins/schengen-host.js` | OpenCode permission.reply pipeline (channel emit + decision poller + `schengen_pending` query) |

## Installation

1. Copy (or symlink) the plugin into OpenCode's global plugin directory:

   ```bash
   mkdir -p ~/.config/opencode/plugins
   cp opencode/plugins/schengen-host.js ~/.config/opencode/plugins/schengen-host.js
   ```

2. **Restart OpenCode** (plugins are loaded once at startup, not hot-reloaded).

## Tools

- `schengen_pending` — list active pending SmartGate escalations (with dialog
  snapshots) as JSON. Read-only inspection; escalation surfacing/adjudication is
  handled by the TUI.

## Configuration (env vars)

| Env var | Default | Purpose |
| :--- | :--- | :--- |
| `SCHENGEN_LOG_PATH` | `~/.local/state/herdr-schengen/schengen-host.log` | Plugin error log |
| `SCHENGEN_DECISION_POLL_MS` | `1000` | Decision-file poll interval (permission.reply) |
| `SCHENGEN_HISTORY_PATH` | `~/.agents/skills/herdr-schengen/scripts/cmd/schengen_history.py` | History CLI for `schengen_pending` |

The programmatic-approval opt-in is the persistent `channel_approve` `guard_config`
setting (TUI toggle), no longer the transient `SCHENGEN_CHANNEL_APPROVE` env var.

## Permission allow rules

`schengen_pending` polls the pending-escalation queue via
`schengen_history.py --pending --json`, which is read-only and must never
trigger an interactive prompt. Add this allow rule to OpenCode's
`permission.bash` config (`~/.config/opencode/opencode.jsonc`):

```jsonc
"python3 *schengen_history.py --pending*": "allow"
```

Rule ordering follows "broad first, narrow last": it sits after `"*": "ask"`
and the `bw *` deny rules so it wins for this command.
