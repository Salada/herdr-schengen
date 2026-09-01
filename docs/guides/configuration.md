# Configuration Reference

Environment variables, the watcher config file, and the runtime state layout of Herdr
Schengen (SmartGate). All variables are optional unless noted; absent values fall back to
the documented defaults.

## 1. Core Environment Variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `HERDR_ENV` | unset | **Required for the daemon.** Must be `1`; the watcher refuses to start outside a Herdr session (ADR-008). |
| `HERDR_PANE_ID` | unset | Pane id of the caller. The watcher excludes this pane from interception to prevent self-recursive auto-approval. |
| `SCHENGEN_HOME` | repo root | Portable repo-root convention used by the bootstrap and companion CLIs (venv, history CLI paths). See `docs/guides/setup-from-scratch.md`. |
| `SCHENGEN_HISTORY_PATH` | `~/.agents/skills/herdr-schengen/scripts/cmd/schengen_history.py` | Path to the history CLI used by the opencode plugin (`schengen_pending`). |
| `SCHENGEN_LOG_DIR` | `/var/log/herdr-schengen` | Log directory honored by the persistence layer (falls back gracefully). |
| `SCHENGEN_DEBUG` | unset | Reserved debug toggle. **Note**: no code reads this variable today — mouse tracing uses `SCHENGEN_MOUSE_DEBUG` (read by the TUI). |
| `SCHENGEN_MOUSE_DEBUG` | unset | TUI mouse-event debug output. |
| `SCHENGEN_SHADOW_MODE` | unset | Kill-switch: run the gate in shadow mode (log-only, no interception). |
| `SCHENGEN_STRICT_PARENT` | unset | `1` = die-with-parent daemon lifecycle (set by the TUI when spawning; ADR-003/008). |

## 2. LLM Environment Variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `OPENAI_API_KEY` | unset | Shared API key for the cloud judge and the TUI Inspector/Judge phases (fallback when phase-specific keys are unset). |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible endpoint. Provider switching (e.g. DeepSeek at home) is done here per ADR-011. |
| `GUARD_LLM_MODEL` | `gpt-5.6-luna` | Cloud judge model (`scripts/core/cloud_judge.py`). |
| `GUARD_LLM_API_KEY` / `GUARD_LLM_BASE_URL` / `GUARD_LLM_ENDPOINT` | unset | Explicit cloud-judge overrides. |
| `GUARD_REASONING_EFFORT` | `low` | Reasoning-effort tier for the cloud judge. |
| `SCHENGEN_INSPECTOR_API_KEY` / `SCHENGEN_INSPECTOR_BASE_URL` / `SCHENGEN_INSPECTOR_MODEL` | shared key/url / `gpt-5.6-luna` | TUI Inspector phase (tool-calling subagent). |
| `SCHENGEN_JUDGE_API_KEY` / `SCHENGEN_JUDGE_BASE_URL` / `SCHENGEN_JUDGE_MODEL` | shared key/url / `gpt-5.6-luna` | TUI Judge phase (final adjudication). |
| `SCHENGEN_LLM_PROVIDER` | `openai` | Logical provider selector. **Note**: no code reads this variable today — provider routing is performed via `OPENAI_BASE_URL` (ADR-011). |
| `OPENCODE_MODEL` / `OPENCODE_SUBAGENT_MODEL` | unset | Model overrides for the OpenCode host runtime adapter. |

## 3. `config/schengen_watcher.json`

Read at daemon startup; absent or invalid values safely fall back to built-in defaults, and
command-line flags override file values. Built-in defaults:

```json
{
  "max_workers": 10,
  "interval_seconds": 3,
  "auto_exit_idle_cycles": 10
}
```

Add future watcher-wide tunables to this file and `WATCHER_DEFAULTS` in
`scripts/cmd/schengen_watcher.py`.

## 4. Runtime State: `~/.local/state/herdr-schengen/`

XDG-compliant state directory (no skill/repo pollution). Created lazily by the persistence
layer (`scripts/core/guard_db.py`, `scripts/core/feature_db.py`).

| Path | Purpose |
| :--- | :--- |
| `schengen_history.db` | Audit logs, pattern stats, user allowlist, evaluation cache, pending escalations (SQLite). |
| `feature_requests.db` | Feature-request / self-improvement backlog (SQLite, FTS5 trigram CJK search). |
| `in_flight_state.json` | Watcher-published in-flight inspector state; the TUI reads it read-only (INV-PH1-2/5). |

## 5. OpenCode Plugin Configuration

The plugin (`opencode/plugins/schengen-host.js`) forwards a minimal allowlist of
environment variables to spawned processes (ADR-008) and reads:

| Variable | Purpose |
| :--- | :--- |
| `SCHENGEN_OPENCODE_CHANNEL_TTL` | TTL for structured permission-channel decisions (ADR-013). |
| `SCHENGEN_OPENCODE_MAX_INJECT` | Max injection attempts for a permission dialog. |
| `SCHENGEN_OPENCODE_REPOLL_SECONDS` | Repoll interval for permission decisions. |

## 6. Approval Semantics & `approve_advisory`

Which command grants **unconditional** approval vs **gatekeeper-mediated**
approval:

| Command | Semantics | Provenance |
| :--- | :--- | :--- |
| `/approve <id> [reason]` / `/reject <id> [reason]` (single) | **Gatekeeper-mediated**. The gatekeeper LLM evaluates the command first; with `approve_advisory=false` (default) your note is a binding **DIRECTIVE** that it executes (approver stays `"gatekeeper"`). With `approve_advisory=true` the gatekeeper may **disagree** (Disagree & Commit) — the note is an advisory opinion, not a directive. | `approver="gatekeeper"` |
| `/approve-batch` / `/reject-batch` | **Deterministic, unconditional**. Resolves the FIFO head batch directly (verified-inject path, no LLM gate) and seeds the human-approval trust window. | `approver="human-tui"` |
| `/allow <pattern> [description]` (and `/allow-last`) | **Persistent allowlist**. A full-match regex rule reviewed by the human; applies from then on (revocable, never deleted). | `created_by="human-tui"` |

### `approve_advisory` config key (guard_config)

- **Default**: `false` — an explicit human `/approve`/`/reject` note is a binding
  directive; the gatekeeper executes it without second-guessing (recorded with
  `approver="gatekeeper"`). Its STEP 2 anti-rubber-stamp/fail-closed rules still
  apply to *autonomous* judgment (no explicit human directive present).
- **`true`** — opt-in "Disagree & Commit": the human note becomes an *advisory
  opinion*; the gatekeeper must weigh it as evidence and may reject/escalate
  when it conflicts with the STEP 0/1 risk assessment.
- **How to set**: `scripts/core/guard_db.py`
  (`set_approve_advisory_config(True|False)`, persisted in the `guard_config`
  table; read via `get_approve_advisory_config()`). A TUI toggle is planned.

### Session-pattern removal (INTENTIONAL)

The 2a gatekeeper-prompt rework removed the "Session Pattern Memory"
auto-approve: repetitive commands are **re-evaluated on every interception**
(fail-closed at the cost of latency). This is deliberate — no command
auto-approves merely because a similar one was approved earlier in the session
(STEP 2 anti-rubber-stamp), so patterns can never bypass the evaluator. |
