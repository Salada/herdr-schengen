// schengen-host.js — OpenCode host plugin for Herdr Schengen (SmartGate).
//
// This plugin provides the OpenCode-side of the permission.reply pipeline
// (issue #57 full closure): it observes `permission.asked` events and writes
// them to the per-pane channel (the watcher's clean command source), then polls
// the watcher's decision file and replies programmatically via client.permission
// — approval bound to the exact permission_id (no bare `send-keys enter`).
//
// The guard DAEMON lifecycle (start/stop/reload) is owned EXCLUSIVELY by the
// Schengen TUI (Ctrl+T), NOT this plugin (issue #114). Escalation surfacing is
// also the TUI's responsibility. This plugin no longer spawns the daemon nor
// injects escalation prompts.
//
// Install: copy this file to ~/.config/opencode/plugins/ and restart OpenCode.

import { spawn } from "node:child_process"; // Bun implements node:* builtins
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const LOG_PATH = (() => {
  const override = process.env.SCHENGEN_LOG_PATH;
  if (override) return override;
  // Unix convention: log under /var/log; fall back to the XDG state dir when
  // /var/log is not writable (e.g. macOS non-root).
  const candidates = [
    "/var/log/herdr-schengen/schengen-host.log",
    path.join(os.homedir(), ".local", "state", "herdr-schengen", "schengen-host.log"),
  ];
  for (const candidate of candidates) {
    try {
      fs.mkdirSync(path.dirname(candidate), { recursive: true });
      const fd = fs.openSync(candidate, "a");
      fs.closeSync(fd);
      return candidate;
    } catch (_) {
      // not writable; try the next candidate
    }
  }
  return candidates[candidates.length - 1];
})();

const HISTORY_PATH =
  process.env.SCHENGEN_HISTORY_PATH ||
  path.join(os.homedir(), ".agents", "skills", "herdr-schengen", "scripts", "cmd", "schengen_history.py");

function inRuntime() {
  return process.env.HERDR_ENV === "1" && process.env.OPENCODE === "1";
}

// Structured permission channel (issue #57, extraction-reliability improvement).
// Each guarded OpenCode pane's plugin observes `permission.asked` events on the
// internal bus and overwrites a per-pane JSON file with the CLEAN request — no
// terminal-text scraping. The watcher daemon reads this file as the primary
// command source (pane-text scraping remains the fallback).
const CHANNEL_DIR = path.join(
  os.homedir(),
  ".local",
  "state",
  "herdr-schengen",
  "opencode_permissions",
);

function channelFilePath(paneId) {
  const safe = String(paneId || "unknown").replace(/[^A-Za-z0-9._-]/g, "_");
  return path.join(CHANNEL_DIR, `${safe}.json`);
}

// Decision channel (issue #57 full closure): the watcher daemon writes an
// approve/reject decision (permission_id + response) to a per-pane JSON file;
// this plugin polls it and programmatically replies via client.permission.
const DECISION_DIR = path.join(
  os.homedir(),
  ".local",
  "state",
  "herdr-schengen",
  "opencode_decisions",
);

function decisionFilePath(paneId) {
  const safe = String(paneId || "unknown").replace(/[^A-Za-z0-9._-]/g, "_");
  return path.join(DECISION_DIR, `${safe}.json`);
}

// permission_ids this session has asked and is awaiting a guard decision for.
const pendingPermissions = new Set();

function emitPermissionAsked(event) {
  // Only emit for guarded panes: an OpenCode session running inside a Herdr pane.
  if (!inRuntime()) return;
  try {
    const p = (event && event.properties) || event || {};
    if (!p || !p.permission) return;
    fs.mkdirSync(CHANNEL_DIR, { recursive: true });
    const record = {
      pane_id: process.env.HERDR_PANE_ID || null,
      permission_id: p.id || null,
      permission: p.permission,
      patterns: Array.isArray(p.patterns) ? p.patterns : [],
      metadata: p.metadata || {},
      ts: Date.now() / 1000,
    };
    // Single-writer per pane, so overwrite (not append) bounds file growth.
    fs.writeFileSync(channelFilePath(process.env.HERDR_PANE_ID), JSON.stringify(record) + "\n");
    if (p.id) pendingPermissions.add(p.id);
  } catch (err) {
    try {
      fs.appendFileSync(LOG_PATH, `[schengen-host] emit permission failed: ${err}\n`);
    } catch {}
  }
}

export default async ({ client }) => {
  let sessionID = null;
  let decisionTimer = null;
  const DECISION_POLL_MS = parseInt(process.env.SCHENGEN_DECISION_POLL_MS || "1000", 10);

  function runHistoryPending() {
    return new Promise((resolve) => {
      const proc = spawn("python3", [HISTORY_PATH, "--pending", "--json"], {
        stdio: ["ignore", "pipe", "ignore"],
      });
      let out = "";
      proc.stdout.on("data", (chunk) => {
        out += chunk;
      });
      proc.on("close", (code) => {
        const trimmed = (out || "").trim();
        if (trimmed) {
          resolve(trimmed);
          return;
        }
        // Empty output: the history CLI failed or produced no JSON. Return a
        // valid empty list so the poller does not crash; log the exit code.
        if (code !== 0) {
          try {
            fs.appendFileSync(
              LOG_PATH,
              `[schengen-host] history --pending --json exited ${code} with empty output\n`,
            );
          } catch {}
        }
        resolve("[]");
      });
      proc.on("error", (err) => {
        try {
          fs.appendFileSync(LOG_PATH, `[schengen-host] failed to spawn history CLI: ${err.message}\n`);
        } catch {}
        resolve("[]");
      });
    });
  }

  async function pollDecisions() {
    // Programmatic approve/reject (issue #57 full closure): the watcher daemon
    // writes a decision (permission_id + response) to this pane's decision file;
    // reply via client.permission so approval is bound to the exact
    // permission_id — no bare enter on the live dialog.
    if (!inRuntime()) return;
    if (!sessionID) return;
    let decision;
    try {
      decision = JSON.parse(fs.readFileSync(decisionFilePath(process.env.HERDR_PANE_ID), "utf8"));
    } catch {
      return; // no decision yet
    }
    if (!decision || !decision.permission_id) return;
    if (!pendingPermissions.has(decision.permission_id)) return;
    const response = decision.response === "reject" ? "reject" : "once";
    try {
      await client.postSessionIdPermissionsPermissionId({
        path: { id: sessionID, permissionID: decision.permission_id },
        body: { response },
      });
      pendingPermissions.delete(decision.permission_id);
      try {
        fs.unlinkSync(decisionFilePath(process.env.HERDR_PANE_ID));
      } catch {}
    } catch (err) {
      try {
        fs.appendFileSync(LOG_PATH, `[schengen-host] permission reply failed: ${err}\n`);
      } catch {}
    }
  }

  // Start the decision poller now. The daemon lifecycle moved to the TUI
  // (issue #114), but the permission.reply decision poller stays here — it
  // needs the opencode session's client.permission API.
  decisionTimer = setInterval(pollDecisions, DECISION_POLL_MS);
  if (typeof decisionTimer.unref === "function") decisionTimer.unref();

  return {
    tool: {
      schengen_pending: {
        description:
          "List active pending SmartGate escalations (with dialog snapshots) as JSON. Use to inspect what needs review.",
        args: {},
        async execute() {
          return (await runHistoryPending()) || "[]";
        },
      },
    },
    event: ({ event }) => {
      if (event && event.type === "permission.asked") {
        emitPermissionAsked(event);
      }
    },
    "chat.message": (input) => {
      sessionID = input.sessionID;
    },
    dispose: async () => {
      if (decisionTimer) clearInterval(decisionTimer);
      decisionTimer = null;
    },
  };
};
