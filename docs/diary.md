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

## 2026-09-03 — Gatekeeper bias must lean toward APPROVAL, not deferral

**Correction**: the advisory-only redesign (ADR-015) over-corrected — it made
Tier C "never approve, never reject, always defer", which removed the gatekeeper's
autonomous approval for low-risk mutations (git add/commit) and pushed the system
toward hardcoded rulesets instead of LLM judgment.

**Principle**: the bias must be approval-bias — (1) expand the 1ms deterministic
allowlist only for unambiguously-safe commands; (2) for everything else, the
gatekeeper uses the LLM + tool calls to PROVE safety and autonomously APPROVE;
(3) only when safety cannot be proven does it defer (never reject). Avoid
hardcoded "allow add/commit, block push" rulesets — they only complexify the code.

**Fix**: revised Tier C prompt to "approve if proven safe, defer if not, never
reject"; discarded the deterministic safe-VCS-mutation ruleset.
