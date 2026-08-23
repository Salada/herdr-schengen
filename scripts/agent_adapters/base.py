"""Base adapter interface (Strategy pattern) for agent-specific approval handling.

The core watcher only depends on this interface and the registry, so adding a new
agent kind (e.g. codex, cursor) means adding a new adapter module — no changes to
schengen_watcher.py (Open/Closed Principle).
"""


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
