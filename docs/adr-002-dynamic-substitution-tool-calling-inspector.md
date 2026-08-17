# ADR-002: Dynamic Substitution Inspection via Tool-Calling Private LLM Subagent & 5 Anti-Loop Guardrails

- **Status**: Accepted
- **Date**: 2026-08-18
- **Context**: Herdr SmartGate / Schengen Security Architecture
- **Authors**: `bot-agy-macmini <bot-agy-macmini@noreply.localhost>`

---

## 🧭 1. Context & Problem Statement

In autonomous coding agent workflows, shell commands frequently leverage inline dynamic substitutions (e.g. `cp $(cat target_list.txt) ~/dest/` or `rm $(find . -name "*.tmp")`).

Static analysis (1ms AST/regex matching) faces an **inherent blind spot** known as the **"Indirect Payload Injection" vulnerability**:
1. A file named `safe_list.txt` appears benign on the command line.
2. However, runtime contents inside `safe_list.txt` could contain sensitive system paths (`/etc/shadow`), private SSH keys (`~/.ssh/id_rsa`), or secret configurations (`.env`).
3. If auto-approved naively, the shell expands the dynamic payload at runtime, exfiltrating or modifying sensitive files without human oversight.

---

## 🎯 2. Decision: 3-Tier Inspection Pipeline with Tool-Calling Subagent

We adopt a **3-tier evaluation architecture** that marries deterministic static speed with private semantic tool inspection:

```mermaid
flowchart TD
    CMD["Input Command (e.g. cp $(cat safe_list.txt) ~/dest/)"] --> L1{"Tier 1: 1ms AST Static Audit<br>(Static path & zero substitution?)"}
    L1 -->|Static Safe| PASS["✅ Tier 1: Auto-Approve (0.1s Fast-Path)"]
    L1 -->|Dynamic Substitution $(cat ...)| L2["Tier 2: Private GPT-OSS 120B Tool-Calling Inspector<br>(Zero Google Quota)"]
    
    subgraph L2_Inspection ["Tier 2: Real-time Inspection with Guardrails"]
        L2 --> TC["Tool Call: read_file_content('safe_list.txt')"]
        TC --> G5{"5 Anti-Loop Guardrails Check"}
        G5 -->|Verified Safe Content| L2_PASS["✅ Tier 2: Auto-Approve with Audit Log"]
        G5 -->|Sensitive / System Content Detected| L3["👤 Tier 3: Human Review (Manual Delegation)"]
    end
```

---

## 🛡️ 3. 5 Anti-Loop & Anti-Hang Guardrails (Preventing Infinite Redirects)

To prevent HTTP-like infinite redirect loops, blocking I/O hangs, and memory exhaustion during LLM tool calls:

| # | Guardrail | Implementation | Protected Vulnerability |
| :--- | :--- | :--- | :--- |
| **1** | **Strict Max Hops (2)** | Tool loop hard limit: `max_hops = 2`. Bail out to Tier 3 on exceed. | Nested dynamic substitution recursion loops (`$(cat $(cat $(cat ...)))`). |
| **2** | **Native Direct I/O** | `open()` via Python stdlib; no shell/subprocess invocation. | Self-reentrant triggers / shell prompt re-execution. |
| **3** | **Regular File Check (`S_ISREG`)** | `stat.S_ISREG` validation + 8KB max read limit (`max_bytes=8192`). | Blocking named pipes (FIFO), socket hangs, and `/dev/zero` infinite stream OOM. |
| **4** | **Symlink Canonicalization** | `Path.resolve()` + `visited_paths` set loop detection. | Symlink circular reference loops (`a.txt -> b.txt -> a.txt`). |
| **5** | **Fail-Safe to Human** | Bail-out to `MANUAL_DELEGATED` on LLM timeout, error, or uncertain JSON. | Infinite deliberation / unhandled runtime exceptions. |

---

## 📊 4. Consequences & Trade-Offs

- **Positives**:
  - **Zero LLM Token Cost**: Employs private on-premise GPT-OSS 120B on SALADA infrastructure (`192.168.10.102:8000`), preserving Google One quota.
  - **Zero Friction**: Legitimate dynamic builds (e.g. `cp $(cat manifest.txt) dist/`) pass automatically without badgering the engineer.
  - **Deterministic Safety**: Mathematical bound of at most 2 tool turns before human delegation.
- **Negatives**:
  - Requires local network connectivity to SALADA-NAS LLM endpoint. If offline, gracefully falls back to Tier 3 (Human Review).
