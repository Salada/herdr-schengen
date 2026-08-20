# ADR-005: Autonomous Multi-Agent Orchestration & Deadlock Defense Protocol

- **Status**: Accepted
- **Date**: 2026-08-19
- **Deciders**: SaladaQoo (Human Lead), Antigravity (AGY Commander), Hermes (Governance Reviewer)
- **Consulted**: `ciso-reviewer`, `devops-reviewer`, `english-reviewer`
- **Related Documents**:
  - [ADR-001: Runtime & Architecture Selection](./adr-001-runtime-architecture-python-vs-go.md)
  - [ADR-003: AGY Native Task Integration & Singleton Governance](./adr-003-agy-native-task-integration-and-singleton-governance.md)
  - [ADR-004: Non-VCS Irreversible Mutation Governance](./adr-004-non-vcs-irreversible-mutation-governance.md)

---

## 1. Context & Problem Statement

During multi-agent peer review sessions, a critical failure mode emerged: **"Deadlock of Mutual Silence (상호 침묵 교착 상태)"**.
When the orchestrator (AGY) committed a patch, it stopped and remained `idle` waiting for human intervention or an arbitrary timer. Meanwhile, reviewer agents in Herdr panes remained `idle` waiting for prompt directives. Because neither side sent a signal, the entire autonomous review pipeline froze indefinitely.

Additionally, multiple human friction points occurred:
1. **Sleep-based Busy-wait**: Shell `sleep` was invoked instead of event-driven polling.
2. **Hidden Background Spawning**: Agents were spawned invisibly (`hermes -z`).
3. **Infrastructure Exception Masking**: External API 401/timeouts were swallowed as `is_safe=False`, producing false-negative test failures in CI.
4. **PR Transparency Deficit**: Review summaries were posted to chat while omitting unedited CLI verification traces.

---

## 2. Decision & Architecture

We establish a **5-Pillar Autonomous Multi-Agent Orchestration Protocol**:

### Pillar 1: Event-Driven Zero-Stall Auto-Chaining
- The orchestrator operates as a **Finite State Machine (FSM)**:
  `OPEN` ➔ `BROADCASTING` ➔ `AWAIT_VERDICT` ➔ `CONSENSUS` ➔ `MERGE_READY` ➔ `TORN_DOWN` (or `ESCALATED`).
- State transitions are event-driven: pushing a commit automatically triggers `herdr agent prompt` to all active reviewers within 1 second.
- The orchestrator waits reactively using `herdr agent wait <name> --until idle --until done --timeout 120000`. Shell `sleep` is strictly forbidden.

### Pillar 2: Heartbeat Status Broadcast
- Whenever the orchestrator transitions state (e.g., executing CI, analyzing diffs, waiting on timers), it sends a 1-line status ping to reviewer panes (`[Commander Status: CI Running on SHA <sha>]`) preventing zombie waiting states.

### Pillar 3: Structured Verdict Contract
- Reviewers must conclude reviews with machine-parseable JSON:
  ```json
  {
    "reviewer": "ciso-reviewer",
    "verdict": "APPROVED",
    "reviewed_sha": "11756c1",
    "ci_verified": true,
    "blocking_findings": [],
    "non_blocking_recommendations": []
  }
  ```
- Allowed verdicts: `APPROVED`, `DISPUTED`, `REJECTED`, `ESCALATED`.

### Pillar 4: Infrastructure Exception Separation & CI Gating
- API transport and authentication failures must raise explicit `HTTPError`/`RuntimeError` exceptions rather than returning synthetic `is_safe=False` booleans.
- Flaky external dependencies must be gated in CI with `@unittest.skipIf` with explicit rationale.

### Pillar 5: Role Architecture Decoupling (Commander AGY vs Worker Hermes)
- **AGY Commander**: Plans roadmap, orchestrates Herdr panes, handles SCM/PR lifecycle, diagnoses CI, and monitors governance.
- **Hermes Worker**: Performs AST code refactors, executes test suites, and conducts domain-specific audits in visible Herdr panes.

---

## 3. Consequences

### Positive
- **Zero Human Chaperoning**: Eliminates the need for humans to remind agents to broadcast diffs or check review status.
- **100% SCM Transparency**: Unabridged raw CLI probes and structured verdicts are permanently recorded on Forgejo PR issue comments.
- **Ultra-Fast Deterministic CI**: Sub-0.05s CI execution without external network flakiness.

### Trade-offs & Mitigations
- **Runaway Loop Risk**: Mitigated by enforcing Max 3 Review Rounds and 30-minute total session budget caps before auto-escalating to humans.
- **Secret Leakage Risk**: Mitigated by applying mandatory credential/token redaction gates prior to PR comment submission.
