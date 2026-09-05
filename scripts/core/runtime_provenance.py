"""Installed-source provenance for audit records and the TUI."""

import json
import os
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional


PROVENANCE_FILE = ".schengen-source.json"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _git_revision(root: Path) -> Optional[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


@lru_cache(maxsize=1)
def get_runtime_provenance() -> Dict[str, Any]:
    """Return the installed manifest, falling back to the source checkout."""
    root = _repo_root()
    manifest = root / PROVENANCE_FILE
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("revision"):
            return data
    except (OSError, ValueError):
        pass
    return {
        "revision": os.environ.get("SCHENGEN_SOURCE_REVISION") or _git_revision(root) or "unknown",
        "source": str(root),
        "installed_at": None,
    }


def get_source_revision() -> str:
    return str(get_runtime_provenance().get("revision") or "unknown")
