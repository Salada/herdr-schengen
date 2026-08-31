# Governance Proposal — Session Retrospective (2026-08-31)

> **Status**: PROPOSAL-ONLY (not yet applied). A human reviews before any
> AGENTS.md / `.agents/rules/` edit. This document records the proposed rules,
> their rationale, and residual objections from the AGY↔Hermes retrospective.

## Summary

The session (Phase-1 IPC #161, human-required gating #167, queue badge #168,
docs restructure #169) surfaced reusable patterns and process failures. Two
independent reviewers (AGY, Hermes) converged on the following rule candidates.

## Proposed rules

### Global process rules (→ `~/.agents/rules/`)

1. **PR-based review for sandbox reviewers.** Reviewer subagents run in a Docker
   sandbox and cannot see host worktrees. Every peer review MUST target an
   `origin/<branch>` (pushed) or an open Forgejo PR; never reconstruct a diff
   from briefing prose. Verify `git ls-remote --heads origin` before starting.
   *(AGY + Hermes — this session wasted a full turn probing an unreachable
   host path.)*

2. **Tool-layer redaction false positives.** The redaction layer may flag `sk-`
   substrings inside ordinary identifiers (e.g. `...-task-...`). Treat such hits
   as false positives — do **not** rewrite them as `[REDACTED]` placeholders and
   do not report them as secret leaks unless a real credential is present.
   *(Hermes — the ADR-003 `task-integration` filename was mis-handled this way.)*

3. **Test mock-timing.** Async TUI tests that replace an `@work` method
   (`app.process_user_chat = MagicMock()`) must assign the mock **before**
   `app.run_test(...)`, otherwise `on_mount` invokes the real worker and mutates
   state before the first assertion (flaky, order-dependent). *(Hermes.)*

4. **Race severity by reachability.** A race is blocking only if reachable at
   realistic event timings; sub-tick races (human input interleaving with a
   scheduled `@work` worker) are theoretical → report non-blocking with the fix,
   do not DISPUTE on them. *(Hermes.)*

### Repo-specific rules (→ `herdr-schengen/AGENTS.md`)

5. **One-way GitHub mirror.** All development/issues happen only on the private
   Forgejo. GitHub is a one-way distribution snapshot; no reverse merge, no
   direct commit to GitHub, no external-contribution intake. *(AGY.)*

6. **TOCTOU guard matching must be fuzzy/prefix.** Command-string guards that
   fire just before key injection must tolerate viewport soft-wrap truncation
   and path-expression variance (`~` vs absolute, dir vs file) — use prefix/
   semantic matching, not exact `==`. *(AGY — #3143/#3219 key-injection drop.)*

7. **DB upsert clears prior columns.** On `ON CONFLICT`/re-enqueue, explicitly
   clear the previous resolution/approver columns, not just `status`. *(AGY —
   #3159/#2997 leftover APPROVED.)*

8. **Forgejo merge API backoff.** After updating a PR branch, wait a few seconds
   of async backoff before calling the merge API (HTTP 405 "Please try again
   later" during background mergeability check). *(AGY.)*

## Residual objections

- Rules 6–8 are repo-local and reference incident numbers (#3143/#3219/#3159/
  #2997) that predate this session; they are recorded here as candidates and
  should be validated against those incidents before promotion.

## Proposed diff targets

| Rule | File | Proposed edit |
| :--- | :--- | :--- |
| 1–4 | `~/.agents/rules/multi-agent-collaboration-and-handoff-policy.md` (or new `review-process.md`) | append review/redaction/mock-timing/race-reachability rules |
| 5–8 | `herdr-schengen/AGENTS.md` §1 Core Operating Principles | append mirror + guard + upsert + merge-backoff rules |
