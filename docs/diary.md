# Diary — Non-authoritative Log

> ⚠️ **Non-authoritative scratch pad.** Entries here are raw session lessons, NOT
> durable wiki knowledge and NOT decisions. A lesson is promoted to durable
> knowledge/ADR only after peer review. All dates are KST.

## 2026-09-03 — Gatekeeper "Disagree & Commit" over-rejection regression

**Mistake**: PR #179/#3864 reframed the gatekeeper LLM as an "equal expert" who
may *disagree and commit* (override the human), and deleted the pre-existing
"NO Autonomous Reject" guard. Result: (1) frequent autonomous reject of
gray-zone commands without asking the human; (2) overriding a human's strong
free-text approval.

**Root cause**: prompt reframing conflated "advisor" with "adjudicator" —
"your verdict is your own" + "the human does not outrank your risk assessment"
handed an LLM decision authority over the human operator.

**Fix**: PR #189 (advisory-only three-tier triage; "NO Autonomous Reject"
restored; human directive always binding; `approve_advisory` removed; directive
provenance) + PR #190 (obvious-safe fast-track + quote masking).

**Lesson**: in safety-critical human-in-the-loop governance, an LLM gatekeeper
must be ADVISORY, not decisive. Final authority and responsibility always rest
with the human; autonomous reject is limited to unambiguous denylist. A
"disagree & commit / override-the-human" framing is an anti-pattern here.
