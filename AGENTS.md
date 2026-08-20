# 🤖 AGENTS.md — Herdr-Schengen (SmartGate) Master Engineering Guide

> **Target Audience**: Autonomous Coding Agents (Antigravity/AGY, Hermes, Codex) & Human Engineers.  
> **Repository**: `InhouseOriented/herdr-schengen` (Hosted on **Forgejo** `salada-git:2222/InhouseOriented/herdr-schengen.git`).  
> **Source Directory**: `~/code/herdr-schengen/`  
> **Runtime Skill Mirrors**: `~/.agents/skills/herdr-schengen/`, `~/.gemini/skills/herdr-schengen/`

---

## 🧭 1. Core Operating Principles (Non-Negotiable Rules)

1. **Repository Identity & Boundary Isolation**:
   - ❌ **Never** commit `herdr-schengen` source files, tests, or ADRs into `OrgManaged/dotfiles` (`~/.local/share/chezmoi`).
   - ✅ **Always** commit changes directly inside `~/code/herdr-schengen/` and push to `origin` (`InhouseOriented/herdr-schengen.git`).

2. **Dual-Sync Contract with Runtime Skills**:
   - Any modifications made in `~/code/herdr-schengen/` (scripts, docs, SKILL.md) **MUST** be mirrored to `~/.agents/skills/herdr-schengen/` and `~/.gemini/skills/herdr-schengen/`.
   - Running daemons can be reloaded in 0.01s without downtime via `python3 scripts/schengen_watcher.py --reload`.

3. **Strict Cross-Repository Reference & Linking Standard**:
   - **Internal Links (Intra-Repo)**: Always use relative paths (e.g., `[ADR-001](./adr-001-runtime-architecture-python-vs-go.md)`).
   - **External Links (Cross-Repo)**: References to `dotfiles`, `common-llm-wiki`, or other org repos **MUST NOT** use bare filenames. They must use Org-qualified titles and canonical Forgejo URLs:
     - `[AGENTS.md (OrgManaged/dotfiles)](http://192.168.10.102:3000/OrgManaged/dotfiles/src/branch/main/AGENTS.md)`
     - `[SOP-11: Unbiased Peer Review Protocol (dotfiles)](http://192.168.10.102:3000/OrgManaged/dotfiles/src/branch/main/dot_agents/rules/sops/sop-11-unbiased-peer-review-protocol.md)`
     - `[SOP-12: Non-VCS Irreversible Mutation Governance (dotfiles)](http://192.168.10.102:3000/OrgManaged/dotfiles/src/branch/main/dot_agents/rules/sops/sop-12-non-vcs-gray-zone-governance.md)`

4. **Bot Git Attribution Policy**:
   - Always commit using `bot-agy-macmini <bot-agy-macmini@noreply.localhost>` and include required trailers (`Co-authored-by`, `Agent`, `Op`, `Effort`).

---

## 🗺️ 2. Repository Topology & Document Index

```text
~/code/herdr-schengen/
├── AGENTS.md                  # [THIS FILE] In-house Master Engineering Guide
├── README.md                  # Architecture & User Guide
├── SKILL.md                   # Agent Skill Manifest (Schengen Fast-Track)
├── scripts/                   # Core Security Daemon & Evaluators
│   ├── schengen_watcher.py    # Main PTY Watcher & Singleton Daemon
│   ├── security_evaluator.py  # 9-Layer Decision Matrix & AST Evaluator
│   ├── gray_zone_evaluator.py # Non-VCS Gray-Zone Dynamic Evaluator
│   ├── guard_db.py            # SQLite3 Audit Trail Storage
│   └── schengen_history.py    # CLI Diagnostic & Log Search Tool
├── tests/                     # Unit Test Suite (40+ Test Cases)
└── docs/                      # Official Architecture Decision Records (ADR)
    ├── adr-001-runtime-architecture-python-vs-go.md
    ├── adr-002-dynamic-substitution-tool-calling-inspector.md
    ├── adr-003-agy-native-task-integration-and-singleton-governance.md
    ├── adr-004-non-vcs-irreversible-mutation-governance.md
    ├── adr-005-autonomous-orchestration-and-deadlock-defense.md
    ├── adr-006-destructive-intent-taxonomy-and-sast-pre-execution-gate.md
    └── adr-007-graceful-dynamic-reload-and-target-scoped-lockfiles.md
```

---

## ⚡ 3. Everyday Engineering SOPs

### SOP-01: Updating Guard Rules & Hot-Reloading
```bash
# 1. Edit evaluator in source repo
nvim ~/code/herdr-schengen/scripts/security_evaluator.py
# 2. Run test suite
python3 -m unittest discover -s tests
# 3. Mirror to runtime skill
cp -r ~/code/herdr-schengen/scripts/ ~/.agents/skills/herdr-schengen/scripts/
# 4. Gracefully hot-reload running daemon via SIGHUP (0ms downtime)
python3 ~/.agents/skills/herdr-schengen/scripts/schengen_watcher.py --reload
```

### SOP-02: Writing a New ADR
```bash
# 1. Create adr-00X-*.md inside docs/
# 2. Ensure internal links use relative paths (./adr-00X-*.md)
# 3. Ensure external dotfiles/wiki links use Org-qualified URLs
# 4. Sync to skill docs
cp -r ~/code/herdr-schengen/docs/ ~/.agents/skills/herdr-schengen/docs/
```
