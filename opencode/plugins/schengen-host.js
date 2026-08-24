// schengen-host.js — OpenCode host plugin for Herdr Schengen (SmartGate).
//
// On-demand activation: the user starts the guard in a SPECIFIC OpenCode session
// by asking the agent to "start the schengen guard" (which calls the
// `schengen_start` tool). Only that session becomes the host. The daemon is
// spawned as a child of the OpenCode process and is killed when this session
// closes (die-with-parent), matching ADR-003/ADR-008 session-bound governance.
//
// Install: copy this file to ~/.config/opencode/plugins/ and restart OpenCode.
//
// Die-with-parent has two layers:
//   1. `tui.lifecycle.onDispose` (the same hook the Herdr integration uses in
//      herdr-tui-session.js) kills the daemon on graceful session close.
//   2. The daemon runs with SCHENGEN_STRICT_PARENT=1, so its `is_parent_alive`
//      P1 guard exits when this OpenCode process dies (even on crash).

import { spawn } from "node:child_process"; // Bun implements node:* builtins
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const WATCHER_PATH =
  process.env.SCHENGEN_WATCHER_PATH ||
  path.join(os.homedir(), ".agents", "skills", "herdr-schengen", "scripts", "schengen_watcher.py");

const LOG_PATH =
  process.env.SCHENGEN_LOG_PATH ||
  path.join(os.homedir(), ".local", "state", "herdr-schengen", "schengen-host.log");

const POLL_MS = parseInt(process.env.SCHENGEN_HOST_POLL_MS || "15000", 10);

// Which agent kinds the daemon guards. The watcher defaults to 'agy' only, so
// we must pass this explicitly to also guard OpenCode panes.
const AGENT_FILTER = process.env.SCHENGEN_AGENT_FILTER || "agy,opencode";

let child = null; // the spawned process (may be exited), or null
let desired = false; // user asked for the guard to run
let rearm = null; // setTimeout handle for crash re-spawn

function inRuntime() {
  return process.env.HERDR_ENV === "1" && process.env.OPENCODE === "1";
}

function start() {
  if (!inRuntime()) {
    return "refusing to start: not running inside Herdr + OpenCode";
  }
  if (child && child.exitCode === null && child.signalCode === null) {
    return `already running (pid ${child.pid})`;
  }

  const logFd = fs.openSync(LOG_PATH, "a");
  const proc = spawn("python3", [WATCHER_PATH, "--target", "auto", "--agent-filter", AGENT_FILTER], {
    detached: false,
    stdio: ["ignore", logFd, logFd],
    env: { ...process.env, SCHENGEN_STRICT_PARENT: "1" },
  });
  fs.closeSync(logFd);

  child = proc;
  desired = true;

  proc.on("exit", (code) => {
    if (!desired) return; // stopped intentionally
    child = null;
    if (code === 0) {
      // Singleton yield: another host already holds the flock -> we are not
      // the host. Do NOT re-spawn (avoids a spawn/exit loop).
      desired = false;
      return;
    }
    // Unexpected death (crash) -> watcher-of-the-watcher re-spawn.
    rearm = setTimeout(() => {
      if (desired) start();
    }, POLL_MS);
  });

  return `started schengen guard (pid ${proc.pid}); this session is now the host`;
}

function stop() {
  desired = false;
  if (rearm) {
    clearTimeout(rearm);
    rearm = null;
  }
  if (child && child.exitCode === null) {
    child.kill("SIGTERM");
  }
  child = null;
  return "stopped";
}

function status() {
  if (child && child.exitCode === null) {
    return `running (pid ${child.pid})`;
  }
  return `stopped${desired ? " (restart pending)" : ""}`;
}

export default async () => {
  return {
    tool: {
      schengen_start: {
        description:
          "Start the Herdr Schengen (SmartGate) guard daemon in THIS OpenCode session, making it the host that monitors all panes. Only call when the user explicitly asks to start the guard.",
        args: {},
        async execute() {
          return start();
        },
      },
      schengen_stop: {
        description: "Stop the Herdr Schengen guard daemon in this session.",
        args: {},
        async execute() {
          return stop();
        },
      },
      schengen_status: {
        description: "Report whether the Herdr Schengen guard daemon is running in this session.",
        args: {},
        async execute() {
          return status();
        },
      },
    },
    tui: async (api) => {
      api.lifecycle.onDispose(() => {
        stop();
      });
    },
  };
};
