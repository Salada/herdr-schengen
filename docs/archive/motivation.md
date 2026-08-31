# Motivation & Design Philosophy (Archived Background)

> **Status**: Archived — historical context. The current, concise statement of purpose
> lives in the [README](../../README.md) (Core Purpose + 9 Decision Layers).

## Project Maintenance & Long-Term Support Commitment

This repository (`InhouseOriented/herdr-schengen`) is an **actively maintained, tier-1 core
developer asset**. It is **NOT** a one-off experimental script.

1. **Continuous Rule & Heuristic Refinement**: Security patterns, AST evaluators, and
   denylist boundaries are continually updated to adapt to evolving multi-agent behaviors
   and shell patterns.
2. **Automated Weekly Quality Assurance**: Weekly scheduled CI runs
   ([`.forgejo/workflows/llm_security_eval.yml`](../../.forgejo/workflows/llm_security_eval.yml))
   execute full unit and live integration tests against the OpenAI-compatible cloud judge
   to prevent regression.
3. **Active Issue-First Governance**: Bug reports, edge-case vulnerability disclosures, and
   feature proposals are actively triaged via the
   [Forgejo Issue Tracker](http://192.168.10.102:3000/InhouseOriented/herdr-schengen/issues).
4. **Long-Term Dotfiles Integration**: This repository serves as the definitive upstream
   source for all agent skill syncs (`npx skills`, Chezmoi dotfiles). It will remain
   maintained and backward-compatible.

## The Context: High-Velocity, Zero-Marginal-Cost AI Automation

As an active user of **Google Antigravity (AGY)** authenticated via **Google OAuth
(Google One)**, our engineering environment leverages subscription-backed model access to
achieve near-unlimited agent capabilities without incurring heavy per-token API bills from
commercial pay-as-you-go providers (such as Anthropic Claude or OpenAI Codex).

## The Trade-Off: Autonomous Velocity vs. YOLO Disasters

When orchestrating multi-agent workflows across terminal multiplexers like
[Herdr](https://github.com/michaellperry/herdr):

1. **The Friction Dilemma**: Standard interactive permission prompts require human
   intervention dozens of times per session, destroying autonomous agent velocity and
   cognitive flow.
2. **The "YOLO" Hazard**: Blindly granting unconditional auto-approval
   (`--dangerously-skip-permissions`) is a disaster waiting to happen. Autonomous coding
   agents can inadvertently run destructive commands (`rm -rf`, `git reset --hard`,
   `git push --force`), leak sensitive credentials (`.env`, `~/.ssh/id_rsa`,
   `.aws/credentials`), or mutate isolated sandboxes.

## The Solution: Herdr Schengen (SmartGate)

**Herdr Schengen** acts as an automated immigration border control for coding agents:
a deterministic 9-layer pre-execution gate that auto-approves safe operations, blocks
destructive ones, and delegates ambiguous cases to a human operator — see the
[9 Decision Layers Architecture](../../README.md#-9-decision-layers-architecture) in the README.
