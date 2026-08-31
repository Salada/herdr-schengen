# Herdr Schengen Engineering Diary & Retrospective

> **Scope**: InhouseOriented/herdr-schengen  
> **Target Audience**: Core Maintainers, AGY Commanders, and Hermes Reviewers  
> **Status**: Living Document (Non-Authoritative Scratch Pad)

---

## 2026-08-21: ADR-006 4-Phase Rollout Post-Mortem & Multi-Agent Dialectic Lessons

### 1. Overview & Context
Completed the 4-step phased implementation of ADR-006 (9-Layer Hybrid SAST, 2D Threat Taxonomy, and Context-Full Session Cache) across PRs #5 through #8, governed by continuous dual-channel multi-agent peer review between AGY Commander, `devops-hermes` (Platform Lead), and `ciso-hermes` (Security Lead).

### 2. What Went Well
- **Socratic Peer Review Specialization**:
  - `devops-hermes` focused on latency budgets, CLI cold-starts (disqualifying Semgrep CLI from the <0.1s hot path), and parameter pipeline wiring.
  - `ciso-hermes` caught semantic taxonomy inconsistencies, L2 cache bypass vectors, and weak test assertions.
- **Fail-Safe SIGHUP Dynamic Reload**:
  - Module reload with cryptographic git blob verification allowed testing live fixes without terminating background Schengen daemons or breaking active agent sessions.
- **Reviewer Worktree Mandate**:
  - Both Hermes reviewers created dedicated worktrees (`/root/worktrees/review-*`) in their shared Docker container profile, completely eliminating checkout collisions during concurrent reviews.

### 3. Frictions & Mistakes Encountered
- **Changelog Claim ≠ Empirical Verification**:
  - Multiple PR submissions asserted "100% tests passing / 0 failures", but actual execution in reviewer worktrees revealed runner path hardcoding and regressions in existing taxonomy tests (`test_2d_taxonomy_emission`).
  - *Lesson*: PR claims are hypotheses until verified by test execution in an isolated worktree.
- **Silent No-Op Masking (Broad `except` Anti-Pattern)**:
  - `get_dynamic_ruleset_version()` imported an erroneous symbol name (`CRITICAL_PATTERNS`) wrapped in `except Exception: return 'dyn-2.0.0'`, masking the defect and disabling dynamic rule hash invalidation silently.
  - *Lesson*: Core security evaluation and hash calculation routines must fail loud or emit explicit degradation telemetry; never silently fall back to static constants.
- **Global Telemetry Contamination vs Domain Scoping**:
  - When surfacing `DEGRADED` state for absent SAST tools, the flag was initially applied globally to all commands, contaminating benign static commands (`git status`, `ls -la`) with `gate_state = DEGRADED`.
  - *Lesson*: Telemetry must be strictly scoped to the domain of the missing tool (e.g. script execution contexts `python -c`, `bash -c`).

### 4. Load-Bearing Invariants Cemented
1. **L2 Reducer Isolation**: LLM and cache are middle-tier reducers; deterministic guards (AST, ShellCheck, Regex, Sandbox) run unconditionally on every command.
2. **Context-Full State Binding**: Cache keys must bind `(raw_cmd, cwd, scope, agent_id, origin, ruleset_hash)`.
3. **Fail-Loud Cryptographic Invalidation**: Dynamic rule hashes must be computed from prompt and rule contents.

---

## 2026-08-29: OpenCode permission.reply + Codex adapter session — Frictions & Mistakes

### Frictions & Mistakes Encountered

- **Wrong plugin client API (PR #109)**:
  - The plugin called `client.permission.postSessionIdPermissionsPermissionId(...)`, but the plugin `client` is the **v1 flat SDK client** — it has no `client.permission` namespace. Runtime threw `TypeError: undefined is not an object`, silently stalling every approval (decisions written but never replied).
  - *Lesson*: verify the actual `client` object shape at runtime, not the SDK-generated type names; a namespaced method (`client.permission.X`) may only exist on the v2 client.
- **Self-pane exclusion from a bad daemon spawn**:
  - Restarting the watcher daemon from the opencode pane's own shell inherited `HERDR_PANE_ID=w1D:p1`, so `detect_self_pane_id()` marked the guarded pane as the daemon's own and **excluded it** from monitoring — approvals silently stopped for that pane.
  - *Lesson*: spawn the daemon with `HERDR_PANE_ID` unset (or from the TUI), and assert `self_pane`/`excluded` in the startup log.
- **`2>/dev/null` redirect mis-parsed as a file path (PR #110)**:
  - `resolve_dynamic_substitutions_locally` `shlex.split` the `$(cat …)` argument and treated the `2>/dev/null` redirect token as a file path → "File does not exist" false block.
  - *Lesson*: shell redirection tokens (`[0-9]*[<>]…`) are not file arguments; filter them before path resolution.
- **channel_approve had no fallback (PR #107/#108)**:
  - `channel_approve` wrote a decision and returned success immediately, so when the plugin did not reply (stale/not-restarted) the approval stalled with no fallback. Fixed with a ~2.5s cleared-dialog verification + `send-keys` fallback, and gated behind `SCHENGEN_CHANNEL_APPROVE=1`.

### Load-Bearing Invariants Cemented

1. **Permission_id binding**: programmatic approval must be a reply bound to the exact `permission_id` (never a bare `enter`).
2. **Opt-in gate**: an async, plugin-dependent approve path must default OFF (keystroke injection) and be enabled by an explicit env flag.
3. **Redirect-aware substitution**: dynamic-substitution file resolution must drop redirection tokens before treating tokens as paths.
