# OpenCode Host Plugin — Herdr Schengen (SmartGate)

On-demand guard activation inside a **specific OpenCode session**. This plugin
makes one OpenCode session the "host" that runs the Schengen watcher daemon
(which monitors *all* panes), mirroring the AGY host model from ADR-003/ADR-008.

## Files

| File | Purpose |
| :--- | :--- |
| `plugins/schengen-host.js` | The OpenCode host plugin (custom tools + cleanup) |

## Installation

1. Copy (or symlink) the plugin into OpenCode's global plugin directory:

   ```bash
   mkdir -p ~/.config/opencode/plugins
   cp opencode/plugins/schengen-host.js ~/.config/opencode/plugins/schengen-host.js
   ```

2. **Restart OpenCode** (plugins are loaded once at startup, not hot-reloaded).

## Usage

In the OpenCode session you want to be the **host**, ask the agent:

- `start the schengen guard` → calls `schengen_start` (spawns the daemon; this
  session becomes the host).
- `stop the schengen guard` → calls `schengen_stop`.
- `is the schengen guard running?` → calls `schengen_status`.

The daemon runs `--target auto`, so a single host guards **all** AGY + OpenCode
panes. Other OpenCode sessions do nothing unless the user starts it there too
(the daemon's `fcntl.flock` singleton ensures only one daemon survives).

## Lifecycle

- **die-with-parent**: the daemon is spawned as a child of the OpenCode process
  and is killed via the plugin `dispose` hook when this session closes.
  `SCHENGEN_STRICT_PARENT=1` additionally makes the daemon exit when the OpenCode
  **process** dies (even on crash) — this fires on process death, not on session
  close while the process stays alive.
- **watcher-of-the-watcher**: while `desired`, a poll re-spawns the daemon if it
  crashes (equivalent to the AGY `schedule()` auto-recovery role).

## Configuration (env vars)

| Env var | Default | Purpose |
| :--- | :--- | :--- |
| `SCHENGEN_WATCHER_PATH` | `~/.agents/skills/herdr-schengen/scripts/schengen_watcher.py` | Watcher daemon path |
| `SCHENGEN_LOG_PATH` | `~/.local/state/herdr-schengen/schengen-host.log` | Daemon stdout/stderr |
| `SCHENGEN_HOST_POLL_MS` | `15000` | Crash re-spawn delay |

## Multi-session behavior

- **N simultaneous**: every session's plugin exposes the tools, but only the
  session where the user invoked `schengen_start` becomes the host; the daemon's
  `fcntl.flock` (`schengen_auto.lock`) guarantees a single daemon.
- **N sequential**: the host role follows whichever session currently runs the
  daemon; on host close the daemon dies, and the user re-starts it in another
  session.

## Note

`--target auto` monitors all panes. To instead guard a *subset* while `auto`
covers the rest, run a second watcher with `--target <pane>` plus
`--exclude-pane <pane>` on the `auto` daemon — the per-target scoped locks
(`schengen_auto.lock` vs `schengen_<pane>.lock`) allow both to run concurrently
without the flock colliding (see `scripts/schengen_watcher.py`).
