# ADR-015: Gatekeeper Advisory-Only Governance — Human Final Authority & No Autonomous Reject

- **Status**: Active
- **Date**: 2026-09-03
- **Related**: ADR-009 (TUI dual-model FIFO), ADR-006 (destructive intent taxonomy), PR #179/#3864 (regression), PR #189 + PR #190 (fix)

## Context

PR #179 ("pre-complexity briefing + Disagree & Commit prompting", #3864)
reframed the gatekeeper LLM as an *equal expert* who may "disagree and commit"
— i.e. override the human. It deleted a pre-existing rule ("NO Autonomous
Reject: do not call `reject_escalation` autonomously; report risks to the human
and wait for explicit human instructions") and replaced it with instructions to
"reject or escalate — never defer to the human merely because they asked" and
"The human does not outrank your risk assessment."

This produced two serious regressions reported by the operator:

1. The gatekeeper autonomously rejected gray-zone commands without asking the
   human — very frequently.
2. The gatekeeper overrode a human's strong approval expressed as free-text
   (not `/approve`) and still rejected.

The underlying model error: the gatekeeper believed it *owned* the
approve/reject decision, instead of being an advisor whose opinion the human
consumes.

## Decision

The gatekeeper becomes an **autonomous approver, advisory rejecter**: it
autonomously approves commands whose safety it can prove, but never rejects
gray-zone on its own (it defers to the human). Three governance principles are
hard invariants:

- **P1** — final decision and legal/security responsibility ALWAYS rest with the
  human.
- **P2** — the gatekeeper autonomously APPROVES commands whose safety it can
  prove (**approval-bias**); it only briefs a risk assessment and defers when it
  cannot prove safety.
- **P3** — autonomous reject is permitted ONLY for unambiguous denylist/critical
  risk; never skip the human for gray-zone/complexity.

Concretely (PR #189, `scripts/tools/schengen_agent_llm.py`):

1. **Three-tier triage** in `build_system_prompt`, driven by the surfaced
   `decision_layer`:
   - **Tier A — unambiguous critical** (`SHELL_CRITICAL`, `SECRET_GUARD`,
     `SANDBOX_GUARD`, `PYTHON_AST`, `ORIGIN_GUARD`) → may autonomously
     `reject_escalation`.
   - **Tier B — obvious-safe** (`NOT_ALLOWLISTED` + closed obvious-safe form) →
     may autonomously `approve_escalation` (no investigation loops).
    - **Tier C — gray-zone / ambiguous / complex** (everything else) → may
      autonomously `approve_escalation` when safety is proven (approval-bias);
      otherwise defer (never reject), wait for the human.
2. **"NO Autonomous Reject" restored** for Tier C (autonomous approval of a
   proven-safe Tier C command remains permitted and encouraged).
3. **Human directive always binding** — a directive may arrive as `/approve`,
   `/reject`, or free-text; the gatekeeper executes it (`directive=true`) and
   records an independent confirmation but never overrides it.
4. **`decision_layer` surfaced** into the prompt so the gatekeeper can
   distinguish a `SECRET_GUARD` escalation (`cat ~/.ssh/id_rsa`) from a plain
   `NOT_ALLOWLISTED` one (`node --version`) — without this, any obvious-safe rule
   would be fail-open on secrets.
5. **`approve_advisory` ("Disagree & Commit") config removed** (YAGNI; its sole
   purpose — permit overriding the human — violates P1). **Directive provenance**
   added: `approver="human-tui"` for directives, `"gatekeeper"` for autonomous.

Complementary (PR #190, `scripts/core/security_evaluator.py`):

- **Obvious-safe fast-track**: a closed interpreter version/help recognizer
  (`node`/`python`/`git`/… `--version|-v|-V|--help|-h`, sole arg, no
  substitution/redirection/separator) so trivially-safe queries never reach the
  LLM. Consulted only after all denylist layers.
- **Quote masking**: collapse terminated `'…'`/`"…"`/`$'…'` regions so interior
  newlines/separators do not inflate `compute_complexity`; double-quoted `$(…)`
  still counted (fail-closed); top-level newlines remain separators.

## Consequences

- **Positive**: over-rejection eliminated; human responsibility restored;
  trivially-safe commands fast-track (no fatigue); multi-line quoted payloads
  scored correctly; denylist non-regression (`node -e "rm -rf /"` still
  `SHELL_CRITICAL`, `cat ~/.ssh/id_rsa` still `SECRET_GUARD`).
- **Invariants**: `INV-GK-ADV` (advisory-only; autonomous reject restricted to
  denylist layers; autonomous approve restricted to obvious-safe
  `NOT_ALLOWLISTED`); `INV-GK-NL` (quoted/heredoc interior newlines never inflate
  structural complexity); `INV-HO-5` (human directive records
  `approver="human-tui"` via `directive=true`).
- **Negative / deferred**: free-text directive provenance still relies on the
  LLM setting `directive=true` (the TUI `record_human_opinion` persistence layer
  is not yet implemented — an LLM-outage survivability gap); `has_human_opinion`
  is not surfaced into the prompt as a confirmation hint; `<<\"EOF\"` heredocs are
  still treated as unquoted (pre-existing, fail-closed direction).
