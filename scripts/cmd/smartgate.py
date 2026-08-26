#!/usr/bin/env python3
"""SmartGate entry point (Alias of schengen_watcher.py)."""

import os
import sys
from pathlib import Path

if __name__ == "__main__":
    script_path = Path(__file__).resolve().parent / "schengen_watcher.py"
    os.execv(sys.executable, [sys.executable, str(script_path)] + sys.argv[1:])
