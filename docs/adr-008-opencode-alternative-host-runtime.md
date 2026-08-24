# ADR-008: OpenCode as Alternative Host Runtime (Agent-Agnostic Session-Bound Governance)

- **Status**: Accepted
- **Date**: 2026-08-24
- **Context**: Herdr Schengen (SmartGate) watcher host runtime
- **Authors**: `bot-opencode-default <bot-opencode-default@salada.mail.home.arpa>`

---

## 🧭 1. Context

ADR-003 mandated that the Schengen watcher run **exclusively** inside an
Antigravity (AGY) session (`ANTIGRAVITY_AGENT=1` / `AI_AGENT=antigravity`),
streaming daemon output into the AGY session as a `run_command` background task
and using AGY-native `schedule()` heartbeats for escalation polling.

In practice, hosting the watcher in AGY accrues LLM token cost in two ways:

1. The watcher's verbose stdout streams into the AGY session context.
2. Escalation judgment + `schedule()` heartbeat wakeups consume AGY model turns.

OpenCode (running `deepseek-v4-pro`/`deepseek-v4-flash`) is a materially cheaper
host with a deterministic permission model, and its SDK exposes `noReply: true`
message injection that renders a persistent in-session escalation **without**
triggering an LLM turn.

## 🎯 2. Decision

Extend the host runtime gate from "AGY-only" to **agent-agnostic (AGY or OpenCode)**:

- `verify_agy_runtime_environment()` is superseded by
  `verify_host_runtime_environment()`, which accepts either the Antigravity
  markers (`ANTIGRAVITY_AGENT=1`, `AI_AGENT=antigravity`,
  `ANTIGRAVITY_CONVERSATION_ID`) or the OpenCode marker (`OPENCODE`).
- The **session-bound / no-orphan** invariant (ADR-003) is preserved: the daemon
  must still be a child of a living host (fork via an OpenCode plugin spawn) and
  self-terminates via the existing `is_parent_alive(initial_ppid)` P1 guard.
- Escalation surfacing under OpenCode uses `client.session.prompt(..., noReply:
  true)` (persistent, zero-token render) instead of AGY stream injection.

## 🛡️ 3. Cost Model

The daemon itself (`schengen_watcher.py`) already runs a `while True` poll loop
on any host (0 tokens); the 7-field guidance is generated deterministically by
`gray_zone_evaluator`, and the cloud judge (Phase 1-3) is host-agnostic. The
token-cost delta between hosts comes only from how the daemon is launched and
how escalations are drained/surfaced:

| Concern | AGY host | OpenCode host |
| :--- | :--- | :--- |
| Daemon launch | `run_command` streaming task — stdout into AGY context (tokens) | plugin `spawn` — stdout → log file (0 tokens) |
| Escalation drain | `schedule()` heartbeat wakes the AGY model (tokens) | daemon loop + `herdr notification` (0 tokens) |
| Escalation surfacing | AGY session stream prompt | `client.session.prompt(noReply: true)` render (0 tokens) |

## 📊 4. Consequences

- **Positives**: materially lower LLM cost; decouples the guard's lifecycle from
  any single agent vendor; deterministic permission model.
- **Negatives**: breaks ADR-003's "AGY-exclusive" wording (superseded here); the
  OpenCode host path (plugin spawn + `noReply` injection) adds an OpenCode-side
  component that lives outside this repository (OpenCode plugin config).

## 📚 5. External Contract References

- **OpenCode marker**: `OPENCODE=1` (set by the OpenCode runtime; verified in a
  live OpenCode session alongside `OPENCODE_PID`).
- **No-reply injection**: `client.session.prompt({ ..., body: { noReply: true,
  parts: [...] } })` — OpenCode SDK (`@opencode-ai/sdk`), "Inject context without
  triggering AI response".
