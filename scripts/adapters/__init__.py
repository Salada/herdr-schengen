"""External agent and terminal multiplexer adapters (Herdr, OpenCode, Antigravity)."""

import sys
from pathlib import Path

_DIR = Path(__file__).resolve().parent.parent
if str(_DIR) not in sys.path:
    sys.path.insert(0, str(_DIR))
