"""External agent and terminal multiplexer adapters (Herdr, OpenCode, Antigravity)."""

import sys
from pathlib import Path

_DIR = Path(__file__).resolve().parent.parent
for _p in (_DIR, _DIR / "core", _DIR / "tools", _DIR / "cmd", _DIR / "adapters"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
