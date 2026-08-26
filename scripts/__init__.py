"""Herdr Schengen (SmartGate) Security Governance Package."""

import sys
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).resolve().parent
for _sub in (_SCRIPTS_DIR, _SCRIPTS_DIR / "core", _SCRIPTS_DIR / "tools", _SCRIPTS_DIR / "cmd", _SCRIPTS_DIR / "adapters"):
    if str(_sub) not in sys.path:
        sys.path.insert(0, str(_sub))
