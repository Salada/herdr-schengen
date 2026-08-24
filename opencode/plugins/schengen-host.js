// schengen-host.js — OpenCode host plugin for Herdr Schengen (SmartGate).
//
// On-demand activation: the user starts the guard in a SPECIFIC OpenCode session
// by asking the agent to "start the schengen guard" (which calls the
// `schengen_start` tool). Only that session becomes the host. The daemon is
// spawned as a child of the OpenCode process and is killed when this session
// closes (die-with-parent), matching ADR-003/ADR-008 session-bound governance.
//
// Install: copy this file to ~/.config/opencode/plugins/ and restart OpenCode.

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Resolve the watcher daemon path (runtime skill mirror by default).
const WATCHER_PATH =
  process.env.SCHENGEN_WATCHER_PATH ||
  path.join(os.homedir(), ".agents", "skills", "herdr-schengen", "scripts", "schengen_watcher.py");

const LOG_PATH =
  process.env.SCHENGEN_LOG_PATH ||
  path.join(os.homedir(), ".local", "state", "herdr-schengen", "schengen-host.log");

const POLL_MS = parseInt(process.env.SCHENGEN_HOST_POLL_MS || "15000", 10);

let child = null; // { pid, proc } or null
let desired = false; // user has asked for the guard to run
let pollTimer = null;

function inRuntime() {
  return process.env.HERDR_ENV === "1" && process.env.OPENCODE === "1";
}

function start() {
  if (!inRuntime()) {
    return "not running inside Herdr + OpenCode; refusing to start";
  }
  if (child && child.proc.exitCode === null) {
    return `already running (pid ${child.pid})`;
  }

  const logFd = fs.openSync(LOG_PATH, "a");
  const proc = spawn("python3", [WATCHER_PATH, "--target", "auto"], {
    detached: false,
    stdio: ["ignore", logFd, logFd],
  });
  fs.closeSync(logFd);

  child = { pid: proc.pid, proc };
  desired = true;
  ensurePolling();

  return `started schengen guard (pid ${proc.pid}); this session is now the host`;
}

function stop() {
  desired = false;
  if (child && child.proc.exitCode === null) {
    child.proc.kill("SIGTERM");
  }
  child = null;
  return "stopped";
}

function status() {
  if (child && child.proc.exitCode === null) {
    return `running (pid ${child.pid})`;
  }
  return `stopped${desired ? " (restart pending)" : ""}`;
}

// Watcher-of-the-watcher: re-spawn only when the user has asked for it
// (desired) and the daemon died unexpectedly (crash / external kill).
function ensurePolling() {
  if (pollTimer) return;
  pollTimer = setInterval(() => {
    if (desired && (!child || child.proc.exitCode !== null)) {
      start();
    }
  }, POLL_MS);
  pollTimer.unref?.();
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
        if (pollTimer) clearInterval(pollTimer);
      });
    },
  };
};
