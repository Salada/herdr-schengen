# Herdr Schengen (SmartGate) 🌍🛂🛃

> **Autonomous Multi-Agent Border Control & Trusted Clearance for Herdr Multiplexer**  
> *Balancing Cost-Effective Zero-Token Flow with Bulletproof Denylist Defense against YOLO Hazards.*

[![Maintenance](https://img.shields.io/badge/Status-Actively_Maintained-brightgreen.svg)](http://192.168.10.102:3000/InhouseOriented/herdr-schengen)
[![Governance](https://img.shields.io/badge/Governance-InhouseOriented_Tier_1-blue.svg)](http://192.168.10.102:3000/InhouseOriented)
[![CI](https://img.shields.io/badge/CI-Forgejo_Actions_Verified-success.svg)](http://192.168.10.102:3000/InhouseOriented/herdr-schengen/actions)

---

## 📌 Project Maintenance & Long-Term Support Commitment

> **Notice to Developers, AI Agents & Contributors**:  
> This repository (`InhouseOriented/herdr-schengen`) is an **actively maintained, tier-1 core developer asset**. It is **NOT** a one-off experimental script.
>
> 1. **Continuous Rule & Heuristic Refinement**: Security patterns, AST evaluators, and denylist boundaries are continually updated to adapt to evolving multi-agent behaviors and shell patterns.
> 2. **Automated Weekly Quality Assurance**: Weekly scheduled CI runs ([`.forgejo/workflows/llm_security_eval.yml`](file:///.forgejo/workflows/llm_security_eval.yml)) execute full unit and live integration tests against DeepSeek / GPT-OSS 120B to prevent regression.
> 3. **Active Issue-First Governance**: Bug reports, edge-case vulnerability disclosures, and feature proposals are actively triaged via the [Forgejo Issue Tracker](http://192.168.10.102:3000/InhouseOriented/herdr-schengen/issues).
> 4. **Long-Term Dotfiles Integration**: This repository serves as the definitive upstream source for all agent skill syncs (`npx skills`, Chezmoi dotfiles). It will remain maintained and backward-compatible.

---

## 🧭 The Motivation & Design Philosophy

### The Context: High-Velocity, Zero-Marginal-Cost AI Automation
As an active user of **Google Antigravity (AGY)** authenticated via **Google OAuth (Google One)**, our engineering environment leverages subscription-backed model access to achieve near-unlimited agent capabilities without incurring heavy per-token API bills from commercial pay-as-you-go providers (such as Anthropic Claude or OpenAI Codex).

### The Trade-Off: Autonomous Velocity vs. YOLO Disasters
When orchestrating multi-agent workflows across terminal multiplexers like [Herdr](https://github.com/michaellperry/herdr):
1. **The Friction Dilemma**: Standard interactive permission prompts require human intervention dozens of times per session, destroying autonomous agent velocity and cognitive flow.
2. **The "YOLO" Hazard**: Blindly granting unconditional auto-approval (`--dangerously-skip-permissions`) is a disaster waiting to happen. Autonomous coding agents can inadvertently run destructive commands (`rm -rf`, `git reset --hard`, `git push --force`), leak sensitive credentials (`.env`, `~/.ssh/id_rsa`, `.aws/credentials`), or mutate isolated sandboxes.

### The Solution: Herdr Schengen (SmartGate)
**Herdr Schengen** acts as an automated immigration border control for coding agents:
- **Fast-Track Schengen Zone (0.1s Fast-Path, Zero Token Cost)**: Common, verifiable safe operations (file edits, test executions, git commits, project builds) are validated via a 1ms local Python AST parser and auto-approved instantly with zero LLM API cost.
- **Dynamic Semantic Inspection (Private LLM Subagent)**: Indirect substitutions like `cp $(cat safe_list.txt) ~/dest/` are inspected in real time using private self-hosted models (GPT-OSS 120B on local NAS or DeepSeek-V3 via Tool-Calling) to inspect underlying file payloads.
- **5 Anti-Loop & Anti-Hang Guardrails**: Prevents HTTP-like redirect loops, symlink recursion, blocking FIFOs, and prompt re-entrancy.
- **Continuous Rule Evolution**: The rules and heuristics in this repository are continually refined to maintain the optimal equilibrium between **hyper cost-efficiency** and **rock-solid security**.

---

## 🏛️ 3-Tier Evaluation Architecture

```mermaid
flowchart TD
    CMD["Agent Command (e.g. cp $(cat manifest.txt) dist/)"] --> T1{"Tier 1: 1ms AST Static Audit<br>(Deterministic & Zero-Token)"}
    
    T1 -->|Static Safe Command| PASS["✅ Tier 1: Auto-Approve (0.1s Fast-Track)"]
    T1 -->|Critical Denylist Trigger| BLOCK["🚨 Blocked: Critical Risk (rm -rf, sudo, .env leak)"]
    T1 -->|Dynamic Substitution $(cat ...)| T2["Tier 2: Tool-Calling Semantic Inspector<br>(GPT-OSS 120B / DeepSeek-V3)"]
    
    subgraph T2_Inspection ["Tier 2: Real-time Payload Inspection"]
        T2 --> TC["Tool Call: read_file_content('manifest.txt')"]
        TC --> G5{"5 Anti-Loop Guardrails Check"}
        G5 -->|Verified Safe Payload| T2_PASS["✅ Tier 2: Auto-Approved with Audit Trail"]
        G5 -->|Sensitive / System Paths Found| T3["👤 Tier 3: Human Review & Delegation"]
    end

    BLOCK --> T3
```

---

## 🛡️ Key Features

1. **Deterministic 1ms Python AST & Shell Denylist**:
   - Blocks privilege escalation (`sudo`, `su`, `chmod`), destructive file mutations (`rm -rf`, `mkfs`, `dd`), and unreviewed remote pushes (`git push`).
   - Protects sensitive files (`.env`, `id_rsa`, `credentials.json`, `hosts.yml`, `.aws/credentials`).
   - Protects Hermes sandbox paths (`~/.hermes/sandboxes/`) from unauthorized writes.
2. **Multi-Turn Tool-Calling Semantic Inspection**:
   - Inspects dynamic command substitution (`$(cat ...)`, `` `cat ...` ``, `$(<...)`).
   - Subagent reads referenced files via native Python I/O up to 8KB without spawning shell subprocesses.
3. **5 Anti-Loop & Anti-Hang Guardrails**:
   - **Strict Max Hops (2)**: Mathematical bound to prevent infinite tool-call turns.
   - **Native Direct I/O**: Eliminates prompt re-entrancy / self-trigger loops.
   - **Regular File Check (`stat.S_ISREG`)**: Rejects blocking FIFOs, sockets, and character devices.
   - **Symlink Canonicalization**: Traverses realpaths with visited sets to eliminate circular loops.
   - **Fail-Safe to Human**: Graceful bail-out to manual approval on network timeout or ambiguity.
4. **Self-Exclusion & Agent Isolation**:
   - The caller pane running the watcher is automatically excluded (`HERDR_PANE_ID`) to prevent self-recursive auto-approval.
   - Strictly targets designated coding agents (`agent: "agy"`) while ignoring non-target agents (Hermes, bare shells).
5. **Auditing & SQLite3 Ledger**:
   - Every approval and manual delegation is permanently logged to SQLite with timestamps and safety rationales.

---

## 🚀 Getting Started

### Installation
```bash
# Global installation via npx skills
npx skills add ssh://git@salada-git:2222/InhouseOriented/herdr-schengen.git -g -y
```

### Quick Commands & Aliases
```bash
# 1. Start SmartGate daemon monitoring all active & future AGY panes
python3 scripts/schengen_watcher.py --target auto

# 2. Check live status and active Herdr panes
python3 scripts/schengen_watcher.py --status

# 3. View review board & audit stats
python3 scripts/schengen_watcher.py --stats

# 4. Stop the SmartGate daemon
python3 scripts/schengen_watcher.py --stop
```

### Shell Aliases (`alias.zsh`)
- `smartgate`: Start background SmartGate daemon.
- `smartgate-status`: Show daemon PID, monitored panes, and recent SQLite audit events.
- `smartgate-stop`: Terminate running SmartGate daemon.

---

## 🧪 Testing & CI Pipeline

Comprehensive unit tests and live integration tests run on Forgejo Actions:

```bash
# Run unit tests & guardrail verification
pytest -v tests/test_dynamic_substitution.py

# Run live LLM integration tests
GUARD_LLM_ENDPOINT="https://api.deepseek.com/v1/chat/completions" \
GUARD_LLM_MODEL="deepseek-chat" \
DEEPSEEK_API_KEY="sk-..." \
pytest -v tests/test_llm_evaluator_integration.py
```

### CI Triggers ([`.forgejo/workflows/llm_security_eval.yml`](file:///.forgejo/workflows/llm_security_eval.yml))
- **Weekly Schedule**: Automated run every Monday at 00:00 UTC.
- **Pull Requests**: Runs on any PR targeting `main`.
- **Manual Dispatch**: 1-click execution from Forgejo Web UI.

---

## 🤝 Contributing & Extensibility

Herdr Schengen is designed to be open-source ready and modular:
- **New AST Rules**: Extend [`scripts/security_evaluator.py`](file:///scripts/security_evaluator.py) to add language-specific parsers.
- **Custom LLM Providers**: Compatible with any OpenAI-compliant endpoint (vLLM, Ollama, DeepSeek, LocalAI).
- **Architecture Decision Records**: Consult [`docs/adr-001`](file:///docs/adr-001-runtime-architecture-python-vs-go.md) and [`docs/adr-002`](file:///docs/adr-002-dynamic-substitution-tool-calling-inspector.md) for technical trade-off details.

Pull requests, issues, and security rule proposals are warmly welcomed!
