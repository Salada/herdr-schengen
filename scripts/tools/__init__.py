"""LLM-based autonomous inspector, judge pipeline, and SAST tools."""

import sys
from pathlib import Path

_DIR = Path(__file__).resolve().parent.parent
if str(_DIR) not in sys.path:
    sys.path.insert(0, str(_DIR))
