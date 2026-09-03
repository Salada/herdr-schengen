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

## 2026-09-03 — Human-facing explanation should be plain-risk, not raw heuristics

**Principle (operator guidance)**: this project's purpose is to help human
judgment — give clear explanations, auto-approve low-risk commands as much as
possible, and surface only real risk. The internal risk-scoring machinery
(complexity scores, segment counts, weight tables) should be abstracted away;
the human-facing explanation must be a plain risk statement, not a
formula/score breakdown.

**Trigger**: the `complexity_mode` knob exposed an internal judge-vs-escalate
"calculation mode" to operators and then went dead (deprecated this session).
Broader direction: audit the gatekeeper's human-facing escalation reason for raw
heuristic leakage (e.g. "complexity=26 > threshold=6") and rephrase to
plain-risk wording.
