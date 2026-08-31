# ADR-012: High-Contrast Text Selection Visibility in the TUI

## Status
**Active**

## Context

The SmartGate TUI (`scripts/cmd/schengen_tui.py`, Textual 8.x) renders command,
audit, and chat text over a dark, semi-transparent surface palette. Mouse-drag
text selection was difficult to distinguish from surrounding static content,
hurting the operator's ability to reliably copy command lines, pane IDs, and
audit details.

A design proposal (`select-style-suggestion.md`) requested three things:
(1) an opaque cyan selection background, (2) black inverted text, and (3) a
selection border.

## Decision

1. **Override the canonical Textual selection hook** — `Screen > .screen--selection` —
   with an opaque bright-cyan background (`#00FFFF`), black foreground
   (`#000000`), and bold text-style. This is the correct Textual mechanism; it
   applies globally to all selectable text (RichLog, Static, DataTable, etc.).
2. **Reject the proposal's `-selected-region` pseudo-classes** — they do not exist
   in Textual. Selection styling is controlled by the `screen--selection`
   component class, not per-widget pseudo-classes.
3. **Do not implement a selection border.** Textual selection spans support only
   text styles (background/color/text-style); borders are widget box
   decorations and cannot be applied per-selection-span. The opaque background
   block itself defines the selection boundary, which satisfies the proposal's
   underlying intent.

## Consequences

- **Positive**: drag-selection contrast is maximized (opaque cyan block + black
  text + bold), improving copy reliability.
- **Negative**: the requested selection border (proposal item 3) is not
  implementable via Textual selection spans and is intentionally omitted.
- **Neutral**: the change is CSS-only and has no effect on the selection data
  path or clipboard behavior.
