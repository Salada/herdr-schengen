#!/usr/bin/env python3
"""Synchronize the repository into an explicit runtime skill directory."""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


REPO_ROOT = Path(__file__).resolve().parents[2]
DIRECTORIES = ("config", "docs", "opencode", "scripts")
FILES = ("AGENTS.md", "LICENSE", "README.md", "SKILL.md", "pyproject.toml")
PROVENANCE_FILE = ".schengen-source.json"
CANONICAL_TARGETS = frozenset(
    {
        Path.home() / ".agents/skills/herdr-schengen",
        Path.home() / ".gemini/skills/herdr-schengen",
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


def tracked_files() -> tuple:
    selected = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "-z", "--", *DIRECTORIES, *FILES],
        check=True,
        capture_output=True,
    ).stdout
    return tuple(Path(raw.decode("utf-8")) for raw in selected.split(b"\0") if raw)


def _reject_symlinked_path(target: Path) -> None:
    current = Path(target.anchor)
    for part in target.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"runtime target path contains a symlink: {current}")


def _tracked_payload() -> tuple:
    payload = tracked_files()
    if not payload:
        raise ValueError("tracked runtime payload is empty")
    for relative in payload:
        source = REPO_ROOT / relative
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"tracked runtime path escapes source root: {relative}")
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"tracked runtime source is not a regular file: {relative}")
    return payload


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def install(target: Path) -> dict:
    """Copy the supported runtime surface and stamp its exact source revision."""
    target = target.expanduser().absolute()
    if target not in CANONICAL_TARGETS:
        allowed = ", ".join(str(path) for path in sorted(CANONICAL_TARGETS))
        raise ValueError(f"runtime target is not allowlisted; expected one of: {allowed}")
    _reject_symlinked_path(target)
    if not source_is_clean():
        raise ValueError("source checkout is dirty; commit or remove changes before installing")
    payload = _tracked_payload()
    manifest = {
        "revision": source_revision(),
        "source": str(REPO_ROOT),
        "installed_at": datetime.now(timezone.utc).isoformat(),
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{target.name}.stage-", dir=target.parent))
    backup = target.parent / f".{target.name}.backup-{uuid4().hex}"
    try:
        if target.exists():
            if not target.is_dir():
                raise ValueError(f"runtime target is not a directory: {target}")
            shutil.copytree(target, stage, dirs_exist_ok=True, symlinks=True)
        for name in DIRECTORIES:
            _remove_path(stage / name)
        for relative in payload:
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            _remove_path(destination)
            shutil.copy2(REPO_ROOT / relative, destination, follow_symlinks=False)
        (stage / PROVENANCE_FILE).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        had_target = target.exists()
        if had_target:
            os.replace(target, backup)
        try:
            os.replace(stage, target)
        except Exception:
            if had_target:
                os.replace(backup, target)
            raise
        if had_target:
            shutil.rmtree(backup, ignore_errors=True)
    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
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
