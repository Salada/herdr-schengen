# ADR-016: Judge Observability and Runtime Provenance

- **Status**: Active
- **Date**: 2026-09-05

## Context

An Inspector or Judge can return a useful briefing without calling an
adjudication tool. Previously the TUI printed that text and left the escalation
pending without a durable explanation. Runtime skill mirrors also did not
identify the exact source revision that produced an audit decision.

## Decision

1. A text-only adjudication turn is recorded as `MODEL_NO_TOOL_CALL` with
   `decision_source=LLM`. It never resolves the escalation; the TUI visibly says
   that the response was advisory and the command remains pending.
2. The Judge receives the canonical command plus capture source, normalization
   relation, ambiguity state, and whether the rendered capture was evaluated.
   An LLM reconstruction is advisory only and must re-enter every deterministic
   guard before execution.
3. Audit records expose a decision source: `DETERMINISTIC`, `LLM`, `HUMAN`,
   `DEFERRED`, or `NORMALIZATION_AMBIGUOUS`. Final human/pane-direct resolutions
   override the displayed source without rewriting historical evaluation rows.
4. Runtime mirrors are installed with `schengen_install.py`. The installer
   accepts only the canonical agent/Gemini skill roots, refuses dirty source,
   prunes stale files from managed directories, and writes
   `.schengen-source.json`; every new audit row records that revision.

## Consequences

- A low-reasoning model cannot silently turn a no-tool response into an implied
  approval or an unexplained wait.
- Existing SQLite databases migrate additively and remain readable.
- Runtime synchronization is explicit, repeatable, and traceable to one commit.
