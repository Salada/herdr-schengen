"""Agent-specific adapters for SmartGate (Strategy pattern).

Each target agent kind (agy, opencode, codex) implements the AgentAdapter interface.
The core watcher depends only on this interface and the registry, so adding a
new agent kind means adding a new adapter module — no changes to
schengen_watcher.py (Open/Closed Principle).
"""

# Import adapter modules to trigger registration.
import adapters.agent_adapters.agy  # noqa: F401
import adapters.agent_adapters.codex  # noqa: F401
import adapters.agent_adapters.opencode  # noqa: F401
from adapters.agent_adapters.base import (
    AgentAdapter,
    INJECT_SKIP_CHANGED,
    canonical_request,
    get_adapter,
    target_agent_kinds,
)

__all__ = ["AgentAdapter", "get_adapter", "target_agent_kinds", "INJECT_SKIP_CHANGED", "canonical_request"]
