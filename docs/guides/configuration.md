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
| `SCHENGEN_PARSER_SHADOW` | unset | Research-only structural-shadow transport. Only the exact value `1` enables it at watcher startup; every other value is OFF. It never changes the enforced decision. |
| `SCHENGEN_STRICT_PARENT` | unset | `1` = die-with-parent daemon lifecycle (set by the TUI when spawning; ADR-003/008). |

`SCHENGEN_PARSER_SHADOW` and `SCHENGEN_SHADOW_MODE` are unrelated. The latter
changes enforcement, while parser shadow is metadata-only observation and must
never be used as an enforcement switch. When parser shadow is OFF, no helper is
spawned, no parse is requested, and no parser-shadow record is written. The
value is read only when the watcher parent starts; there is no agent, LLM,
SettingsModal, reload, or lifecycle-control path for changing it.

Stage 1 validates only the bounded subprocess transport and secure telemetry
writer. It does not install or load a native parser and therefore reports
`UNMODELED_OR_INVALID` with `PARSER_UNAVAILABLE` (or
`PARSER_STAGE1_NOT_QUALIFIED` if ambient modules are merely detected). These
statuses are expected research evidence, not production parser qualification
or a product fallback. The helper is a private, lazily spawned child owned by
the watcher parent. It has no network or lifecycle interface and receives a
minimal scrubbed environment.

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
| `SCHENGEN_INSPECTOR_MAX_TOKENS` | `4096` | Inspector completion ceiling. ASCII decimal integer `64..4096`; invalid values fall back to the default. |
| `SCHENGEN_JUDGE_MAX_TOKENS` | `4096` | Judge completion ceiling. ASCII decimal integer `64..4096`; invalid values fall back to the default. |
| `SCHENGEN_INSPECTOR_CONTEXT_WINDOW` | unset | Inspector provider context window. ASCII decimal integer with 4..10 digits and value `>=8192`; read once at chat-process startup. |
| `SCHENGEN_JUDGE_CONTEXT_WINDOW` | unset | Judge provider context window, with the same strict syntax; configured independently from Inspector. |
| `SCHENGEN_LLM_PROVIDER` | `openai` | Logical provider selector. **Note**: no code reads this variable today — provider routing is performed via `OPENAI_BASE_URL` (ADR-011). |
| `OPENCODE_MODEL` / `OPENCODE_SUBAGENT_MODEL` | unset | Model overrides for the OpenCode host runtime adapter. |

The TUI reads completion ceilings once when `SchengenAgentChat` is created; an
environment change therefore takes effect only in a new process. The current
DeepSeek Chat Completions endpoint uses `max_tokens`. Revalidate the payload
field before switching to a provider that requires `max_completion_tokens`
instead.

Each declared context window enables adaptive input budgeting only for its own
phase. The effective input cap is `min(262144, declared_window - 4096)`, where
4096 tokens are reserved for completion. A missing or invalid declaration
keeps that phase on the existing conservative 12,000-character compaction and
emits only `CONTEXT_WINDOW_MISSING` or `CONTEXT_WINDOW_INVALID`; it does not
guess an unknown provider limit.

Before a configured request, Schengen serializes Inspector `messages + tools`
or Judge `messages` as canonical compact UTF-8 JSON. It first compacts eligible
old tool results using the existing thresholds. If the estimated input plus
phase-local growth headroom still does not fit, it atomically compacts every
tool result in the latest complete round into source-bound records. System and
user context and assistant/tool-call relationships remain intact. A malformed
relationship or a request that still does not fit makes no API call and leaves
the escalation pending with `CONTEXT_CAP_EXCEEDED`; this is a human defer, not
an approval or rejection. Successful provider usage samples refine only the
same phase's in-memory estimate and are discarded on process restart.
`get_token_usage_stats()` exposes flat `inspector_...` and `judge_...` fields
for the declared window, effective cap, latest estimate, growth headroom,
budget state, and cumulative cap defers.

## 3. Canonical user settings

`~/.config/herdr-schengen/settings.json` is the sole live settings authority.
The schema-v1 document has exactly 13 top-level keys: `schema_version` plus all
12 settings below. Missing, unknown, incorrectly typed, non-finite, or
out-of-range values reject the whole candidate; values are never partially
applied.

```json
{
  "answer_language": "korean",
  "batch_approval_enabled": true,
  "channel_approve": false,
  "cloud_judge_min_confidence": 0.9,
  "complexity_tax_enabled": true,
  "complexity_threshold": 6,
  "human_approval_ttl_seconds": 3600,
  "origin_weighting_enabled": true,
  "pane_direct_confirm_polls": 2,
  "pane_direct_eviction_enabled": true,
  "schema_version": 1,
  "send_approve_instruction": false,
  "send_reject_instruction": true
}
```

| Setting | Type and accepted range |
| :--- | :--- |
| `send_approve_instruction`, `send_reject_instruction`, `channel_approve` | JSON boolean |
| `complexity_tax_enabled`, `origin_weighting_enabled`, `batch_approval_enabled`, `pane_direct_eviction_enabled` | JSON boolean |
| `answer_language` | `english`, `korean`, or `japanese` |
| `complexity_threshold` | integer `1..10000` |
| `cloud_judge_min_confidence` | finite number `0.7..1.0` |
| `human_approval_ttl_seconds` | integer `60..86400` |
| `pane_direct_confirm_polls` | integer `1..5` |

The file must be a regular non-symlink owned by the current user and must not
be group- or world-writable. Valid external edits become visible as one whole
snapshot within five seconds. On a malformed or unsafe update, processes keep
their last known-good snapshot and emit a local diagnostic; they resume from a
later valid repair without changing the invalid file.

On first use when the file is absent, legacy `guard_config` SQLite values are
validated, merged with compiled defaults, and exported once as a complete
mode-`0600` document. SQLite is not consulted after the canonical file exists.
SettingsModal exposes all 12 settings. Its eight boolean/language controls
apply immediately. The four numeric controls are validated as one draft group
and use one explicit **Apply numeric settings** action; an invalid field writes
nothing. The preview shows each old-to-new value and whether the change raises
or lowers scrutiny, the approval bar, the approval-memory window, or the
pane-direct liveness wait. Disabling Complexity Tax or Pane-Direct eviction
disables its dependent numeric input without discarding that draft.

Every SettingsModal write takes a cross-process lock and atomically replaces
the same complete document, so unrelated concurrent changes are preserved.
The grouped numeric write additionally compares its four baseline values while
holding that lock. A concurrent numeric change writes nothing and offers
**Reload**, **Overwrite**, or **Cancel**; overwrite applies all four visible
drafts to the newest trusted complete document. Closing a dirty Modal asks
before discarding numeric drafts, while already-applied immediate controls are
not reverted. Valid external changes refresh clean drafts automatically;
dirty drafts are retained and marked as externally changed.

The recovery-only snapshot is
`~/.local/state/herdr-schengen/settings.last-good.json`. It is atomically
written only from a validated canonical document or the first migration and
has the same file-trust requirements. It is consulted only when an existing
canonical file is invalid at cold start; if recovery is unavailable or invalid,
compiled defaults are used. Recovery never acts as a live authority and never
repairs or replaces the canonical file.

## 4. `config/schengen_watcher.json`

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

## 5. Runtime State: `~/.local/state/herdr-schengen/`

XDG-compliant state directory (no skill/repo pollution). Created lazily by the persistence
layer (`scripts/core/guard_db.py`, `scripts/core/feature_db.py`).

| Path | Purpose |
| :--- | :--- |
| `schengen_history.db` | Audit logs, pattern stats, user allowlist, evaluation cache, pending escalations (SQLite). |
| `feature_requests.db` | Feature-request / self-improvement backlog (SQLite, FTS5 trigram CJK search). |
| `in_flight_state.json` | Watcher-published in-flight inspector state; the TUI reads it read-only (INV-PH1-2/5). |
| `settings.last-good.json` | Recovery-only last validated schema-v1 settings snapshot; never a competing live authority. |
| `gatekeeper-timelines/escalation-<id>.json` | Metadata-only monotonic timing timeline for one escalation. It contains fixed stage/outcome labels and numeric durations, never commands, tool arguments/output, model text, paths, secrets, or exception text. Inspect it with `schengen_history.py --timeline <id>`. |
| `parser-shadow/events.jsonl` and `.1`…`.4` | Default-off Stage-1 parser-shadow metadata. Each mode-`0600` file is limited to 10 MiB (50 MiB total); rotation never uploads data. Records contain the raw SHA-256/byte length, existing final decision/layer, fixed parser status/counters, duration, and source revision—never raw commands, source fragments, argv/literals, full IR, reserialized shell, environment, cwd, pane/model/tool text, or output. |
| `sessions/session_*.jsonl` | Local raw Gatekeeper chat transcript, never reinjected or uploaded. Trusted mode-`0600` files are retained for 30 days; cleanup runs at startup and then at most once per 24 hours. |

Parser-shadow records are written only after the existing raw-command decision
is final. Helper timeout/crash/malformed output and unsafe log paths fail to no
record and cannot change evaluation, audit, adjudication, or delivery. Joining
the hash metadata to the existing raw-command audit is an explicit offline
operator action; Stage 1 provides no export tool and performs no automatic
upload.

The `sessions` directory must be a real current-UID directory with mode `0700`;
each transcript must be a real current-UID regular file with mode `0600`.
Symlinks, wrong ownership, permissive modes, unreadable entries, and unexpected
file names are rejected or skipped without repair. Transcript or retention I/O
failure never changes adjudication or delivery.

Each runtime skill root also contains `.schengen-source.json`, written by the
repository installer. New audit rows copy its exact Git revision into
`audit_logs.source_revision`. Source checkouts without a manifest fall back to
their current `git rev-parse HEAD`; `SCHENGEN_SOURCE_REVISION` is the explicit
fallback for packaged environments without Git metadata.

Audit `decision_source` values are `DETERMINISTIC`, `LLM`, `HUMAN`, `DEFERRED`,
or `NORMALIZATION_AMBIGUOUS`. A Judge briefing without an adjudication tool is
recorded as `MODEL_NO_TOOL_CALL`/`LLM` and leaves the escalation pending.
Each Gatekeeper timeline uses a random correlation ID and records detection,
queueing, deterministic evaluation, Inspector/Judge attempts, retry backoff,
tool-call duration, and terminal delivery/outcome without changing the SQLite
schema or decision behavior.

## 6. OpenCode Plugin Configuration

The plugin (`opencode/plugins/schengen-host.js`) forwards a minimal allowlist of
environment variables to spawned processes (ADR-008) and reads:

| Variable | Purpose |
| :--- | :--- |
| `SCHENGEN_OPENCODE_CHANNEL_TTL` | TTL for structured permission-channel decisions (ADR-013). |
| `SCHENGEN_OPENCODE_MAX_INJECT` | Max injection attempts for a permission dialog. |
| `SCHENGEN_OPENCODE_REPOLL_SECONDS` | Repoll interval for permission decisions. |

## 7. Approval Semantics

Which command grants **unconditional** approval vs **gatekeeper-mediated**
approval:

| Command | Semantics | Provenance |
| :--- | :--- | :--- |
| `/approve [id] [reason]` / `/reject [id] [reason]` (single), or an exact English/Korean directive such as `approve`, `go ahead`, `승인`, `진행해`, `reject`, `거절` | **Deterministic and binding** for the current command FIFO head. Uses the verified adapter injection path without an LLM call. Broad or ambiguous chat (including `전체 승인`) remains advisory. | `approver="human-tui"` |
| `/approve-batch` / `/reject-batch` | **Deterministic, unconditional**. Resolves the FIFO head batch directly (verified-inject path, no LLM gate) and seeds the human-approval trust window. | `approver="human-tui"` |
| `/allow <pattern> [description]` (and `/allow-last`) | **Persistent allowlist**. A full-match regex rule reviewed by the human; applies from then on (revocable, never deleted). | `created_by="human-tui"` |
| `/allow-url <hostname-or-origin> [description]` | **Persistent exact-host policy for read-only network access**. Applies to `network_access` and curl GET/stdout; upload/auth/output/redirect flags, mixed hosts, mutation, and non-read-only pipelines never match. Use `/allow-url-list` to inspect and `/revoke-url <id-or-host>` to revoke. | `created_by="human-tui"` |

For an exact recurring command such as `chezmoi status`, let it reach human
review once and use `/allow-last`; the stored rule is escaped and matched with
`re.fullmatch`. Global home-directory allowlist files are intentionally not a
supported configuration surface: agents share the human OS uid, so an
agent-writable global Fast-Track file would be a self-authorization path. Use
the TUI-managed SQLite rules for global policy and `<repo>/.schengen/allowlist.json`
for repository-scoped policy. The repo-local file is also writable by agents
sharing the OS uid; it is not a human-only trust store. Its authority is bounded
to that repository, denylist layers still take precedence, and automatic rule
promotion requires an explicit `human-tui` approval.

The former `approve_advisory` switch was removed by ADR-015. Ordinary prose is
still sent to the Gatekeeper as advice; only the closed directive grammar above
can mutate an escalation without an LLM round trip.

Routine Git approval is also deterministic and does not call an LLM. The closed
grammar accepts read queries with an optional `git -C <specific-directory>`,
explicit scoped paths for `git add`, an explicit `-m`/`--message` for
`git commit`, and one named remote plus one explicit non-protected branch for
`git push`. Force/delete/mirror/all/tags/protected-branch pushes are blocked;
`--force-with-lease`, implicit targets, broad adds, and unknown options remain
human-gated.

Local `docker exec` is likewise structural rather than keyword-scored. Schengen
parses the container command and, for `sh -c`/`bash -lc`, recursively checks up
to eight inner diagnostic segments. Reads, existence tests, filters, and a
single print-only redacting `sed s///` may fast-track. Docker exec options other
than interactive/TTY, credential paths, mutation, networking, substitution,
and redirection remain fail-closed. For `grep` and `rg`, pattern text is kept
separate from path operands, so names such as `private` or `encrypted` are not
credentials by themselves; actual sensitive targets and selector globs remain
blocked.

Read-only Herdr metadata queries also use a closed deterministic grammar. The
allowlist covers only help/version, `agent list|get|wait`, and `pane list|get`,
with validated agent names, opaque pane/workspace IDs, wait states, and a
30-minute maximum explicit timeout. Output-reading, input, focus, mutation,
lifecycle, shell-control, substitution, redirection, unknown-option, and nested
payload forms remain human-gated. This grammar was validated against Herdr
0.8.2 and must be revalidated before a Herdr CLI upgrade is adopted.

### Session-pattern removal (INTENTIONAL)

The 2a gatekeeper-prompt rework removed the "Session Pattern Memory"
auto-approve: repetitive commands are **re-evaluated on every interception**
(fail-closed at the cost of latency). This is deliberate — no command
auto-approves merely because a similar one was approved earlier in the session
(STEP 2 anti-rubber-stamp), so patterns can never bypass the evaluator. |
