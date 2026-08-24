"""Agent-specific adapters for SmartGate (Strategy pattern).

Each target agent kind (agy, opencode) implements the AgentAdapter interface.
The core watcher depends only on this interface and the registry, so adding a
new agent kind means adding a new adapter module — no changes to
schengen_watcher.py (Open/Closed Principle).
"""

# Import adapter modules to trigger registration.
import agent_adapters.agy  # noqa: F401
import agent_adapters.opencode  # noqa: F401
from agent_adapters.base import AgentAdapter, get_adapter, target_agent_kinds

__all__ = ["AgentAdapter", "get_adapter", "target_agent_kinds"]
