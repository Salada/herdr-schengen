# ADR-013: OpenCode Structured Permission Channel & Programmatic Approval

## Status
**Accepted**

## Context

The OpenCode adapter extracted commands by regex-scraping the pane terminal
buffer (`herdr pane read --source visible`). That buffer leaks sidebar/status-bar
and adjacent-pane text, so arbitrary user text could not be reliably stripped
(issue #57). Separately, approval was injected as a bare `send-keys enter` on the
live dialog — a keystroke with no binding to the specific permission request, so
a dialog that changed between evaluation and injection (e.g. `access_directory`
→ shell trampoline, or parallel tool calls) could be mis-approved (fail-open).

## Decision

1. **Structured permission channel (extraction).** The OpenCode host plugin
   (`opencode/plugins/schengen-host.js`) observes `permission.asked` on the
   internal event bus and overwrites a per-pane JSON file
   (`~/.local/state/herdr-schengen/opencode_permissions/<pane>.json`) with the
   clean request. The adapter reads it as the primary command source, stage-gated
   on a live permission dialog, and falls back to pane-text scraping (fail-closed).

2. **Programmatic approval (permission_id-bound).** The watcher writes an
   approve decision to `opencode_decisions/<pane>.json`; the plugin polls it and
   replies via `client.postSessionIdPermissionsPermissionId({ path:{id,permissionID},
   body:{response} })`. Approval is bound to an exact, still-unresolved
   permission_id — never a bare `enter`.

3. **Opt-in gating.** `channel_approve` is gated behind
   `SCHENGEN_CHANNEL_APPROVE=1`; by default the watcher uses the pre-existing
   `send-keys enter` (with TOCTOU re-verification) so the guard works regardless
   of plugin load state. The plugin's decision poller only loads on an OpenCode
   session restart.

## Consequences

- **Positive**: command extraction is clean (no TUI leak); approval is bound to
  a permission_id (bare-enter fail-open surface eliminated when enabled).
- **Negative**: the programmatic path has a deployment dependency — the plugin
  must be restarted to load the decision poller, and the plugin `client` is the
  v1 flat SDK client (its `postSessionIdPermissionsPermissionId` method has no
  `client.permission` namespace). Until enabled, `send-keys` remains the path.
- **Neutral**: AGY panes still use pane-text scraping (AGY has no plugin).

## Peer Review

Harvested via `session-harvest` (unbiased critic) on 2026-08-29. Agreed
invariants: the plugin overwrites a per-pane JSON file with the clean
`permission.asked` request; `read_channel_event` returns parsed JSON or `None`;
approval is a `postSessionIdPermissionsPermissionId` reply bound to the exact
permission_id. Residual objection: the extraction behavior is described but a
single observable end-to-end test (plugin reply → dialog cleared) should be
encoded as a regression test.
