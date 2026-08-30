"""Base adapter interface (Strategy pattern) for agent-specific approval handling.

The core watcher only depends on this interface and the registry, so adding a new
agent kind (e.g. codex, cursor) means adding a new adapter module — no changes to
schengen_watcher.py (Open/Closed Principle).
"""

from typing import Optional

from adapters.herdr_client import get_pane_text

# Sentinel `reason` returned by `inject_approval` when the live permission dialog
# trampolined to a DIFFERENT request than `req_cmd` while the caller was evaluating
# (e.g. opencode's "Access external directory" prompt advances to the "Shell command"
# prompt). The stale `req_cmd` is gone and the new request will be re-parsed and
# evaluated on the next poll. The caller MUST skip (defer to the next poll) rather
# than escalate the stale command — escalating it would enqueue an un-resolvable
# escalation that deadlocks the strict FIFO escalation queue.
INJECT_SKIP_CHANGED = "SKIP_DIALOG_CHANGED"


def footer_is_live(text: str, marker: str, tail_lines: int = 8) -> bool:
    """True if `marker` appears within the last `tail_lines` lines of `text`.

    The pane read returns a scrollback window (the last ~80 lines); the live
    permission/question dialog sits at the BOTTOM. Requiring the dialog's footer
    marker to appear in the tail prevents matching stale/lingering scrollback or
    conversation text that merely mentions the marker (false positives that cause
    the escalation to "keep queueing" after the user already resolved it).
    """
    lines = text.splitlines()
    tail = lines[-tail_lines:] if len(lines) > tail_lines else lines
    return any(marker in ln for ln in tail)


class AgentAdapter:
    """Common interface implemented by each target agent adapter.

    Subclasses must set `kind`, `blocked_markers` and implement
    `parse_permission_request` and `inject_approval`.
    """

    kind = "base"

    # Plain-text markers used for blocked-pane fallback detection.
    blocked_markers = ()

    def parse_permission_request(self, visible_text: str):
        """Extract the command/action being requested, or None if none pending."""
        return None

    def get_pending_request(self, pane_id: str, visible_text: str):
        """Return the pending command/action for a pane, using any cleaner source
        available (e.g. a structured plugin channel), falling back to pane-text
        parsing. The default is the pane-text parser; adapters with a structured
        source override this."""
        return self.parse_permission_request(visible_text)

    def dialog_is_live(self, visible_text: str) -> bool:
        """True only if the ACTIVE (bottom/focused) dialog anchor is present in the
        tail of visible_text — genuinely open, not a historical prompt in scrollback.
        Stricter than get_pending_request. Conservative default: False."""
        return False

    def is_truncated(self, visible_text: str) -> bool:
        """True if the visible pane text shows a truncation/fold marker."""
        return False

    def expand_dialog(self, pane_id: str) -> Optional[str]:
        """Return the expanded full dialog text, or None on failure.

        Default: full-scrollback read (NO keystroke) — this protects opencode /
        codex from an unnecessary/disruptive ctrl+f / ctrl+a expansion.
        """
        text = get_pane_text(pane_id, lines=500, full_dump=True)
        return text or None

    def channel_approve(self, pane_id: str, req_cmd: str):
        """Try a structured-channel approval bound to an exact permission_id.

        Returns (approved: bool, reason: str). Adapters without a structured
        channel return (False, ...) so the caller falls back to keystroke
        injection. A reason of INJECT_SKIP_CHANGED means the channel request
        changed mid-evaluation and the caller must skip (defer to the next poll).
        """
        return False, "not supported"

    def inject_approval(self, pane_id: str, req_cmd: str):
        """Inject the approval keystroke(s).

        Returns (approved: bool, reason: str). approved=False means the caller
        MUST escalate (MANUAL_DELEGATED) instead of resolving.
        """
        return False, "not implemented"


_REGISTRY = {}


def register(adapter_cls):
    """Class decorator that registers an adapter by its `kind`."""
    _REGISTRY[adapter_cls.kind] = adapter_cls()
    return adapter_cls


def get_adapter(agent_kind: str):
    """Return the adapter instance for an agent kind, or None if not a target agent."""
    return _REGISTRY.get(agent_kind)


def target_agent_kinds():
    """Return the tuple of registered target agent kinds."""
    return tuple(_REGISTRY.keys())
