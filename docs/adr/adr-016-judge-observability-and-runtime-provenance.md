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
   rejects symlinked destination paths, copies only Git-tracked files, prunes
   stale files from managed directories, and writes `.schengen-source.json`;
   every new audit row records that revision.
5. Each persistent escalation has one metadata-only JSON timing timeline under
   `~/.local/state/herdr-schengen/gatekeeper-timelines/`. A random correlation
   ID links monotonic detection/queue, deterministic evaluation, every
   Inspector/Judge attempt and retry backoff, tool-call timing, and terminal
   delivery/outcome. The schema accepts only fixed labels and numeric values;
   command text, tool arguments/output, model text, paths, secrets, and
   exception strings cannot enter it. Timeline I/O is best-effort and never
   changes a Gatekeeper decision or delivery result.

## Consequences

- A low-reasoning model cannot silently turn a no-tool response into an implied
  approval or an unexplained wait.
- Existing SQLite databases migrate additively and remain readable.
- Per-turn latency bottlenecks are attributable without a SQLite migration or
  a second raw-content audit surface.
- Runtime synchronization is explicit, repeatable, and traceable to one commit.
