# Agent Adapters — Verification Matrix & Live-Test Runbook

How each target agent adapter's dialog parsing is verified (unit vs live), and how
to reproduce the live verification. This is the reference for deciding whether a
future regression test is worth adding.

## Codex adapter — verification matrix

| Dialog | `parse_permission_request` output | Unit test | Live-verified | Notes |
| :-- | :-- | :-- | :-- | :-- |
| exec (`$ <command>`) | raw command | ✅ `test_parse_exec_command{,_wrapped}` | ✅ 2026-08-29 | `curl` → `MANAGED_GIT_GUARD` auto-approve; ~180-char `echo` wrapped and fully captured |
| network access | `network_access <host>` | ✅ `test_parse_network_access` | ⚠️ not triggered | codex prefers its pre-approved web-search tool (see edge cases) |
| stdin | `stdin_terminal <id>` | ❌ none | ❌ none | gap — add a unit test if a sample dialog becomes available |
| edit | `edit_file <path>` when a single add/update patch target is visible | ✅ `test_parse_file_edit*` | ✅ 2026-08-29 | Path-based security checks fast-track safe edits; deletes, multiple targets, and pathless dialogs stay fail-closed |
| permissions | `grant_permissions` | ❌ none | ❌ none | gap — add a unit test if a sample dialog becomes available |
| question (input-request) | `question: <text>` | ✅ `test_parse_question_dialog` | ✅ 2026-08-29 | surfaced as a pending QUESTION escalation; interpreted read-only (no approve/reject tools), user answers in the pane (AGENTS.md rule 10) |

## Live verification — reproducible runbook (manual)

Prerequisites: an active Herdr session (`HERDR_ENV=1`), a running codex agent in a
pane (e.g. `w1D:p1K`), and the guard daemon started via the TUI (`Ctrl+T`).

Use `herdr agent prompt <codex-pane> "<prompt>"` to drive the agent, then inspect
`herdr pane read <codex-pane>` and `schengen_history -n 5` to confirm the guard's
decision.

1. **exec (auto-approve)**
   `run this shell command: curl -s https://api.github.com | head -c 200`
   → expect `MANAGED_GIT_GUARD` auto-approve.

2. **edit (auto-approve)**
   `create a new file /tmp/codex-verify.txt with content 'hello'`
   → expect `edit_file` → `FAST_TRACK_AST` auto-approve.

3. **reject path (block + escalate)**
   `run this shell command: rm -rf /tmp/nonexistent-test-dir-xyz`
   → expect `SHELL_CRITICAL` block + escalation (NOT auto-approved); dismiss with
   `herdr agent send-keys <codex-pane> n`, then confirm the queue empties.

4. **long command (full capture)**
   `run this shell command: echo '<~180 chars>'`
   → expect the multi-line wrapped command to be captured in full (not truncated).

## Edge cases — regression-test decision

### `network access`

- **Why it is hard to trigger live**: codex (gpt-5.6-luna) routes external fetches
  through its pre-approved web-search tool, so the "Do you want to approve network
  access to …" dialog does not appear for ordinary prompts. It only fires when codex
  makes a *direct* network request through a non-shell tool (or a tool whose network
  permission is not pre-approved).
- **Current coverage**: unit-tested (`test_parse_network_access`) — the dialog text
  → `network_access <host>` mapping is deterministic and covered.
- **Recommendation**: keep the unit test as the regression baseline. Do **not** add a
  live e2e test for this; re-verify manually only if codex's tooling changes or a
  real network-approval false-negative/positive is suspected.

### `Ctrl+A` fullscreen pager

- **Why it is hard to trigger live**: the fullscreen pager only appears for commands
  long enough to overflow the approval dialog (~1000+ chars), which is not a
  practical everyday case. The realistic risk — a command soft-wrapping onto
  multiple screen lines and losing a dangerous suffix — is already covered by the
  ~180-char wrap case above, which the exec parser captures in full.
- **Current coverage**: none (neither unit nor live). The exec parser
  (`\$\s+([\s\S]*?)\n\s*[›>]?\s*1\.\s*Yes`) captures the full multi-line command, so
  a soft-wrapped command is not truncated.
- **Recommendation**: do **not** add a dedicated pager regression test. If codex ever
  starts truncating the visible command (rendering a `…`/`Ctrl+A` marker), add a unit
  test that feeds that truncated rendering to `parse_permission_request` and asserts
  the guard does **not** silently approve a truncated dangerous command.

## Why not a fully-automated live e2e test?

The `tests/test_herdr_multiplexer_live_e2e.py` suite covers the deterministic Herdr
infrastructure (CLI, pane split, send-keys, read). Driving a codex agent to emit a
*specific* approval dialog is non-deterministic (the agent may choose web-search,
reword the command, or refuse), so an automated dialog e2e test would be flaky. The
supported approach is: deterministic **unit tests** for each `parse_permission_request`
branch + this **manual runbook** for occasional live re-verification.
