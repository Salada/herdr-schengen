# Governance Proposal: Gatekeeper Advisory-Only (Human Final Authority)

- **Date**: 2026-09-03
- **Status**: Proposed (human sign-off required)
- **Related**: ADR-015

## Proposed Rule (for `AGENTS.md` §1 Core Operating Principles)

**15. Gatekeeper Advisory-Only.** The Security Gatekeeper LLM is an advisor, not
a decision-maker: it briefs a risk assessment and states its professional
opinion, but never autonomously approves/rejects on its own judgment except for
unambiguous denylist/critical risk. Final approval/rejection authority and
responsibility always rest with the human.

## Rationale

PR #179/#3864 reframed the gatekeeper as an "equal expert" who may override the
human ("Disagree & Commit"), removing the pre-existing "NO Autonomous Reject"
guard. This caused two regressions — autonomous over-rejection of gray-zone
commands, and overriding a human's free-text approval (ADR-015; fixed in PR
#189/#190).

## Residual Objections

None blocking.

## Proposed Diff

Append to `AGENTS.md` §1 (Core Operating Principles), after rule 14:

```markdown
15. **Gatekeeper Advisory-Only**: the gatekeeper LLM is an advisor, not a
    decision-maker. It briefs its risk assessment and opinion but never
    autonomously approves/rejects gray-zone commands; final decision authority
    and responsibility always rest with the human. Autonomous reject is limited
    to unambiguous denylist/critical risk (Tier A per ADR-015).
```
