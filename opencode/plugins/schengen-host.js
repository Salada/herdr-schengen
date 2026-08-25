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
//   1. The `dispose` hook kills the daemon on graceful session close.
//   2. The daemon runs with SCHENGEN_STRICT_PARENT=1, so its `is_parent_alive`
//      P1 guard exits when this OpenCode process dies (even on crash).
//
// Escalation surfacing (ADR-008): the plugin polls the pending-escalations queue
// and injects new escalations into this session via
// `client.session.prompt({ body: { noReply: true } })` — a persistent, zero-token
// render that does NOT trigger an LLM turn, so a human can then interact.

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

const HISTORY_PATH =
  process.env.SCHENGEN_HISTORY_PATH ||
  path.join(path.dirname(WATCHER_PATH), "schengen_history.py");

const POLL_MS = parseInt(process.env.SCHENGEN_HOST_POLL_MS || "15000", 10);

// How often (ms) the host plugin re-polls the pending-escalations queue to
// surface new escalations into this OpenCode session via noReply prompt.
const ESC_POLL_MS = parseInt(process.env.SCHENGEN_ESC_POLL_MS || "15000", 10);

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

  fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });
  const logFd = fs.openSync(LOG_PATH, "a");
  const proc = spawn("python3", [WATCHER_PATH, "--target", "auto"], {
    detached: false,
    stdio: ["ignore", logFd, logFd],
    env: { ...process.env, SCHENGEN_STRICT_PARENT: "1" },
  });
  fs.closeSync(logFd);

  proc.on("error", (err) => {
    console.error(`[schengen-host] failed to spawn daemon: ${err.message}`);
    child = null;
    desired = false;
  });

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
      rearm = null;
      if (desired) start();
    }, POLL_MS);
    // Do not let the re-arm timer hold the event loop open on shutdown.
    if (typeof rearm.unref === "function") rearm.unref();
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

export default async ({ client }) => {
  let sessionID = null;
  const surfacedEscalationIds = new Set();
  let escPollTimer = null;

  function runHistoryPending() {
    return new Promise((resolve) => {
      const proc = spawn("python3", [HISTORY_PATH, "--pending", "--json"], {
        stdio: ["ignore", "pipe", "ignore"],
      });
      let out = "";
      proc.stdout.on("data", (chunk) => {
        out += chunk;
      });
      proc.on("close", () => resolve(out));
      proc.on("error", () => resolve(""));
    });
  }

  function formatEscalation(esc) {
    const snapshot = esc.dialog_snapshot
      ? `\n\n--- Dialog snapshot (last 20 lines) ---\n${esc.dialog_snapshot.split("\n").slice(-20).join("\n")}`
      : "";
    return (
      `🚨 [SmartGate] Escalation #${esc.id} requires review\n` +
      `Pane: ${esc.pane_id} (${esc.agent_kind || "unknown"}) | Session: ${esc.session_id || "unknown"}\n` +
      `Layer: ${esc.decision_layer}\n` +
      `Reason: ${esc.safety_reason}\n` +
      `Command: ${esc.raw_command}${snapshot}\n\n` +
      `Resolve with the schengen guard tools (or \`schengen_pending\` to re-list).`
    );
  }

  async function surfaceEscalations() {
    if (!sessionID) return;
    try {
      const raw = await runHistoryPending();
      const list = JSON.parse(raw);
      if (!Array.isArray(list)) return;
      for (const esc of list) {
        if (!esc || surfacedEscalationIds.has(esc.id)) continue;
        surfacedEscalationIds.add(esc.id);
        await client.session.prompt({
          path: { id: sessionID },
          body: { noReply: true, parts: [{ type: "text", text: formatEscalation(esc) }] },
        });
      }
    } catch (err) {
      try {
        fs.appendFileSync(LOG_PATH, `[schengen-host] surface escalation failed: ${err}\n`);
      } catch {}
    }
  }

  // Server plugin body runs on load; start the escalation surfacing poller now.
  escPollTimer = setInterval(surfaceEscalations, ESC_POLL_MS);

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
      schengen_pending: {
        description:
          "List active pending SmartGate escalations (with dialog snapshots) as JSON. Use to inspect what needs review.",
        args: {},
        async execute() {
          return (await runHistoryPending()) || "[]";
        },
      },
    },
    "chat.message": (input) => {
      sessionID = input.sessionID;
    },
    dispose: async () => {
      stop();
      if (escPollTimer) clearInterval(escPollTimer);
      escPollTimer = null;
    },
  };
};
