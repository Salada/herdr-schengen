#!/usr/bin/env python3
"""Synchronize the repository into an explicit runtime skill directory."""

import argparse
import errno
import fcntl
import json
import os
import re
import shutil
import stat
import subprocess
import warnings
from contextlib import contextmanager
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


def _path_kind(path: Path) -> str:
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return "absent"
    return "directory" if stat.S_ISDIR(mode) else "unsafe"


def _valid_provenance(root: Path) -> bool:
    manifest = root / PROVENANCE_FILE
    try:
        if not stat.S_ISREG(os.lstat(manifest).st_mode):
            return False
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        return False
    return isinstance(data.get("revision"), str) and bool(data["revision"].strip())


def _remove_real_directory(path: Path) -> None:
    if _path_kind(path) != "directory":
        raise ValueError(f"installer artifact is not a genuine directory: {path}")
    shutil.rmtree(path)


@contextmanager
def _target_lock(target: Path):
    lock_path = target.parent / f".{target.name}.install.lock"
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"installer lock path is a symlink: {lock_path}") from exc
        raise
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(f"installer lock held for {target}") from exc
        yield
    finally:
        os.close(fd)


def _discover_installer_artifacts(target: Path) -> tuple:
    backup_prefix = f".{target.name}.backup-"
    backup_pattern = re.compile(rf"{re.escape(backup_prefix)}[0-9a-f]{{32}}")
    fixed_stage_name = f".{target.name}.stage"
    legacy_stage_prefix = f"{fixed_stage_name}-"
    legacy_stage_pattern = re.compile(rf"{re.escape(legacy_stage_prefix)}[a-z0-9_]{{8}}")
    backups = []
    stages = []
    with os.scandir(target.parent) as entries:
        for entry in entries:
            name = entry.name
            is_backup = name.startswith(backup_prefix)
            is_stage = name == fixed_stage_name or name.startswith(legacy_stage_prefix)
            if not is_backup and not is_stage:
                continue
            if entry.is_symlink() or not stat.S_ISDIR(entry.stat(follow_symlinks=False).st_mode):
                raise ValueError(f"untrusted installer artifact: {entry.path}")
            if is_stage and name != fixed_stage_name and not legacy_stage_pattern.fullmatch(name):
                warnings.warn(f"leaving unrecognized stage-like entry untouched: {entry.path}", stacklevel=2)
                continue
            if is_backup and not backup_pattern.fullmatch(name):
                raise ValueError(f"unrecognized backup artifact: {entry.path}")
            (backups if is_backup else stages).append(Path(entry.path))
    return tuple(sorted(backups)), tuple(sorted(stages))


def _recover_interrupted_install(target: Path) -> None:
    target_kind = _path_kind(target)
    if target_kind == "unsafe":
        raise ValueError(f"runtime target is not a genuine directory: {target}")
    backups, stages = _discover_installer_artifacts(target)
    if len(backups) > 1:
        raise ValueError(f"multiple backup remnants require manual recovery: {', '.join(map(str, backups))}")
    if backups:
        backup = backups[0]
        if not _valid_provenance(backup):
            raise ValueError(f"backup provenance is missing or invalid: {backup}")
        if target_kind == "absent":
            os.replace(backup, target)
            target_kind = "directory"
        else:
            if not _valid_provenance(target):
                raise ValueError(f"target provenance is missing or invalid; preserving backup: {target}")
            _remove_real_directory(backup)
    for stage in stages:
        _remove_real_directory(stage)


def install(target: Path) -> dict:
    """Copy the supported runtime surface and stamp its exact source revision."""
    target = target.expanduser().absolute()
    if target not in CANONICAL_TARGETS:
        allowed = ", ".join(str(path) for path in sorted(CANONICAL_TARGETS))
        raise ValueError(f"runtime target is not allowlisted; expected one of: {allowed}")
    _reject_symlinked_path(target)
    if not source_is_clean():
        raise ValueError("source checkout is dirty; commit or remove changes before installing")
    target.parent.mkdir(parents=True, exist_ok=True)
    with _target_lock(target):
        _recover_interrupted_install(target)
        payload = _tracked_payload()
        manifest = {
            "revision": source_revision(),
            "source": str(REPO_ROOT),
            "installed_at": datetime.now(timezone.utc).isoformat(),
        }
        stage = target.parent / f".{target.name}.stage"
        backup = target.parent / f".{target.name}.backup-{uuid4().hex}"
        stage.mkdir()
        try:
            if target.exists():
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
            if _path_kind(stage) == "directory":
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
