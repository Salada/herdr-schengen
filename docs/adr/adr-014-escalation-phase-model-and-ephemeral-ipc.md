# ADR-014: Escalation Phase Model & Ephemeral Cross-Process IPC

- **Status**: Active
- **Date**: 2026-08-31
- **Related**: ADR-009 (TUI dual-model FIFO), ADR-002 (dynamic-substitution inspector)

## Context

The SmartGate TUI conflated two distinct escalation states under a single
"PENDING" label: the inspector/judge was still *evaluating* a command, yet the
UI rendered "Human Authorization Required" immediately (incident #3363). This
caused cognitive fatigue and premature intervention. Separately, the daemon
(watcher) and TUI are separate processes sharing SQLite, with no cheap way for
the TUI to observe the daemon's transient in-flight state.

## Decision

Model the escalation lifecycle as distinct phases and surface them via an
ephemeral, single-writer IPC channel:

1. **Phase 1 — in-flight inspection** (pre-escalation): the inspector
   (`audit_shell_command_with_taxonomy`) evaluates the command. Sub-phases
   `inspector` (default, deterministic pre-LLM layers, ms) vs `gatekeeper`
   (LLM/cloud-judge, s) are distinguished by a **thread-local phase hook**
   (`set_phase_hook`/`_emit_phase` in `security_evaluator.py`), registered per
   worker in `_evaluate` and cleared in `finally`; it flips only around
   `post_cloud_judge` at two sites — `audit_with_cloud_judge` and the multi-hop
   `audit_dynamic_substitution_with_llm` loop — never on cache hits.
2. **Ephemeral IPC**: the watcher publishes Phase 1 to
   `~/.local/state/herdr-schengen/in_flight_state.json` — a JSON status file
   written atomically (`tmp + os.replace`) **once per poll**, single-writer
   (the flock-guarded watcher), read-only by the TUI. Staleness auto-clears via
   a 30s `IN_FLIGHT_TTL` heartbeat (wall-clock `time.time()` — not `monotonic`,
   since it crosses the watcher/TUI process boundary; a wall-clock jump can
   shorten/extend the window). On clean shutdown the watcher's `finally`
   publishes an empty snapshot, so the TTL is the crash-only fallback. The
   reader fails closed (missing/malformed/stale → empty list).
3. **Phase 2a — judge investigating** (post-escalation, TUI-local): the TUI
   tracks `_judging_escalation_id` (in-memory only, **no schema change**). The
   judge round-trip (`process_user_chat` → `send_message` → `build_system_prompt`)
   is wrapped in a `try/finally` at the `@work` wrapper level that clears the
   flag on **every** exit path (early returns included). Render `🔍 Gatekeeper
   Checking…` (dim).
4. **Phase 2b — human required** (final): only when the judge finishes AND the
   escalation is still PENDING does the TUI render the red
   `🚨 Human Authorization Required` card — exactly once, guarded by the
   `_decision_card_written` dedup set.
5. **Copy-paste-able decision card**: the card frames only the header badge;
   target/command/reason/action lines are flat, word-wrapped (never truncated),
   with no `│` box borders, so the command and reason select/copy as original
   text. The `[#id]` deep-link token lives in the framed header, decoupled from
   the copyable body.

## Consequences

- **Positive**: cognitive fatigue eliminated (red card only at the true
  human-required stage); zero DB contention (ephemeral state lives in a file,
  not SQLite); zero added latency (the phase hook is a thread-local `dict`
  read); copy-paste usability restored for the human adjudication artifact.
- **Invariants**: INV-PH1-1..6 (badge sourced only from the IPC file, staleness
  auto-clear, ≤1 write/poll, no regression of #157/#158/#160); INV-HR-1/2, 3, 6
  (judging ≠ human-required, judge prompt labeled system not "You:", command/
  reason copy-paste-able, clear-on-every-exit).
- **Negative / deferred**: the judge-investigating phase (2a) is TUI-local and
  not persisted (an observer can't see it); a configurable judge timeout is not
  yet implemented.
