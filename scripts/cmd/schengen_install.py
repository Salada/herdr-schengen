#!/usr/bin/env python3
"""Synchronize the repository into an explicit runtime skill directory."""

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DIRECTORIES = ("config", "docs", "opencode", "scripts")
FILES = ("AGENTS.md", "LICENSE", "README.md", "SKILL.md", "pyproject.toml")
PROVENANCE_FILE = ".schengen-source.json"
ALLOWED_TARGETS = frozenset(
    {
        (Path.home() / ".agents/skills/herdr-schengen").resolve(),
        (Path.home() / ".gemini/skills/herdr-schengen").resolve(),
    }
)


def source_revision() -> str:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def source_is_clean() -> bool:
    return not subprocess.run(
        ["git", "-C", str(REPO_ROOT), "status", "--porcelain", "--untracked-files=normal"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def install(target: Path) -> dict:
    """Copy the supported runtime surface and stamp its exact source revision."""
    target = target.expanduser().resolve()
    if target not in ALLOWED_TARGETS:
        allowed = ", ".join(str(path) for path in sorted(ALLOWED_TARGETS))
        raise ValueError(f"runtime target is not allowlisted; expected one of: {allowed}")
    if not source_is_clean():
        raise ValueError("source checkout is dirty; commit or remove changes before installing")
    target.mkdir(parents=True, exist_ok=True)
    for name in DIRECTORIES:
        managed_dir = target / name
        if managed_dir.exists():
            shutil.rmtree(managed_dir)
        shutil.copytree(REPO_ROOT / name, target / name, dirs_exist_ok=True)
    for name in FILES:
        shutil.copy2(REPO_ROOT / name, target / name)
    manifest = {
        "revision": source_revision(),
        "source": str(REPO_ROOT),
        "installed_at": datetime.now(timezone.utc).isoformat(),
    }
    (target / PROVENANCE_FILE).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", required=True, help="runtime skill directory (repeatable)")
    args = parser.parse_args()
    for raw_target in args.target:
        manifest = install(Path(raw_target))
        print(f"installed {manifest['revision']} -> {Path(raw_target).expanduser()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
