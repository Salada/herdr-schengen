"""Canonical, typed JSON settings for Herdr Schengen.

The canonical user-owned document is the only live authority.  SQLite is
consulted by the caller only to create the document when it is absent; a
recovery snapshot is consulted only when an existing canonical document is
invalid.
"""

from __future__ import annotations

import fcntl
import json
import logging
import math
import os
import stat
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterator, Mapping


SCHEMA_VERSION = 1
RELOAD_INTERVAL_SECONDS = 5.0
MAX_DOCUMENT_BYTES = 64 * 1024


@dataclass(frozen=True)
class SettingsSnapshot:
    schema_version: int = SCHEMA_VERSION
    send_approve_instruction: bool = False
    send_reject_instruction: bool = True
    answer_language: str = "korean"
    channel_approve: bool = False
    complexity_tax_enabled: bool = True
    complexity_threshold: int = 6
    origin_weighting_enabled: bool = True
    cloud_judge_min_confidence: float = 0.9
    batch_approval_enabled: bool = True
    human_approval_ttl_seconds: int = 3600
    pane_direct_eviction_enabled: bool = True
    pane_direct_confirm_polls: int = 2

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


DEFAULT_SETTINGS = SettingsSnapshot()
SETTINGS_KEYS = frozenset(DEFAULT_SETTINGS.to_dict())


class SettingsError(ValueError):
    """A settings document or storage path failed validation."""


class SettingsConflictError(SettingsError):
    """A compare-and-update baseline no longer matches the canonical file."""

    def __init__(self, fields: tuple[str, ...], current: SettingsSnapshot) -> None:
        self.fields = fields
        self.current = current
        super().__init__(f"settings changed externally: {', '.join(fields)}")


def default_settings_path() -> Path:
    return Path.home() / ".config" / "herdr-schengen" / "settings.json"


def default_recovery_path() -> Path:
    return Path.home() / ".local" / "state" / "herdr-schengen" / "settings.last-good.json"


def _is_int(value: object) -> bool:
    return type(value) is int


def _is_number(value: object) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


def validate_settings(candidate: Mapping[str, object]) -> SettingsSnapshot:
    """Validate one complete schema-v1 document without coercion or clamping."""
    if not isinstance(candidate, dict):
        raise SettingsError("top-level settings value must be an object")
    actual = set(candidate)
    if actual != SETTINGS_KEYS:
        missing = sorted(SETTINGS_KEYS - actual)
        unknown = sorted(actual - SETTINGS_KEYS)
        raise SettingsError(f"settings keys mismatch (missing={missing}, unknown={unknown})")
    if not _is_int(candidate["schema_version"]) or candidate["schema_version"] != SCHEMA_VERSION:
        raise SettingsError("schema_version must be integer 1")

    bool_fields = (
        "send_approve_instruction",
        "send_reject_instruction",
        "channel_approve",
        "complexity_tax_enabled",
        "origin_weighting_enabled",
        "batch_approval_enabled",
        "pane_direct_eviction_enabled",
    )
    for name in bool_fields:
        if type(candidate[name]) is not bool:
            raise SettingsError(f"{name} must be boolean")

    language = candidate["answer_language"]
    if type(language) is not str or language not in ("english", "korean", "japanese"):
        raise SettingsError("answer_language must be english, korean, or japanese")

    threshold = candidate["complexity_threshold"]
    if not _is_int(threshold) or not 1 <= threshold <= 10000:
        raise SettingsError("complexity_threshold must be an integer in [1, 10000]")

    confidence = candidate["cloud_judge_min_confidence"]
    if not _is_number(confidence) or not 0.7 <= float(confidence) <= 1.0:
        raise SettingsError("cloud_judge_min_confidence must be a finite number in [0.7, 1.0]")

    ttl = candidate["human_approval_ttl_seconds"]
    if not _is_int(ttl) or not 60 <= ttl <= 86400:
        raise SettingsError("human_approval_ttl_seconds must be an integer in [60, 86400]")

    polls = candidate["pane_direct_confirm_polls"]
    if not _is_int(polls) or not 1 <= polls <= 5:
        raise SettingsError("pane_direct_confirm_polls must be an integer in [1, 5]")

    return SettingsSnapshot(**candidate)


def _json_bytes(snapshot: SettingsSnapshot) -> bytes:
    return (json.dumps(snapshot.to_dict(), indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def _validate_stat(info: os.stat_result, path: Path) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise SettingsError(f"settings path is not a regular file: {path}")
    if info.st_uid != os.getuid():
        raise SettingsError(f"settings file is not owned by the current user: {path}")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise SettingsError(f"settings file is group/world writable: {path}")


def _object_without_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SettingsError(f"duplicate settings key: {key}")
        result[key] = value
    return result


def read_trusted(path: Path) -> SettingsSnapshot:
    """Read and validate a regular, current-user-owned, non-writable-by-peers file."""
    path = Path(path)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode):
        raise SettingsError(f"settings path is a symlink: {path}")
    _validate_stat(before, path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        _validate_stat(opened, path)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise SettingsError(f"settings file changed while opening: {path}")
        chunks = []
        remaining = MAX_DOCUMENT_BYTES + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise SettingsError(f"settings document exceeds {MAX_DOCUMENT_BYTES} bytes")
    finally:
        os.close(fd)
    try:
        candidate = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                SettingsError(f"non-finite number is not allowed: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SettingsError(f"invalid settings JSON: {exc}") from exc
    return validate_settings(candidate)


def atomic_write(path: Path, snapshot: SettingsSnapshot) -> None:
    """Durably replace a complete document without exposing partial bytes."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        existing = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISLNK(existing.st_mode):
            raise SettingsError(f"refusing to replace settings symlink: {path}")
        _validate_stat(existing, path)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(_json_bytes(snapshot))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise


class SettingsResolver:
    """Process-local LKG cache around one canonical/recovery path pair."""

    def __init__(
        self,
        settings_path: Path,
        recovery_path: Path,
        *,
        reload_interval: float = RELOAD_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings_path = Path(settings_path)
        self.recovery_path = Path(recovery_path)
        self.reload_interval = reload_interval
        self._clock = clock
        self._lock = threading.RLock()
        self._last_good: SettingsSnapshot | None = None
        self._recovery_synced = False
        self._checked_at: float | None = None
        self.last_diagnostic: str | None = None

    def reset_cache(self) -> None:
        with self._lock:
            self._last_good = None
            self._recovery_synced = False
            self._checked_at = None
            self.last_diagnostic = None

    def get(self, migration_factory: Callable[[], Mapping[str, object]]) -> SettingsSnapshot:
        with self._lock:
            now = self._clock()
            if (
                self._last_good is not None
                and self._checked_at is not None
                and now - self._checked_at < self.reload_interval
            ):
                return self._last_good
            snapshot = self._load(migration_factory)
            self._checked_at = now
            return snapshot

    def _load(self, migration_factory: Callable[[], Mapping[str, object]]) -> SettingsSnapshot:
        if not self.settings_path.exists() and not self.settings_path.is_symlink():
            with self._write_lock():
                if not self.settings_path.exists() and not self.settings_path.is_symlink():
                    snapshot = validate_settings(dict(migration_factory()))
                    atomic_write(self.settings_path, snapshot)
                    self._accept(snapshot)
                    self._write_recovery(snapshot)
                    return snapshot
        try:
            with self._write_lock():
                snapshot = read_trusted(self.settings_path)
                changed = self._accept(snapshot)
                if changed or not self._recovery_synced:
                    self._write_recovery(snapshot)
        except (OSError, SettingsError) as exc:
            self._diagnose(f"canonical settings rejected: {exc}")
            if self._last_good is not None:
                return self._last_good
            try:
                snapshot = read_trusted(self.recovery_path)
            except (OSError, SettingsError) as recovery_exc:
                self._diagnose(f"canonical and recovery settings rejected; using defaults: {recovery_exc}")
                self._last_good = DEFAULT_SETTINGS
                return DEFAULT_SETTINGS
            self._last_good = snapshot
            self._recovery_synced = True
            return snapshot
        return snapshot

    def update(
        self,
        changes: Mapping[str, object],
        migration_factory: Callable[[], Mapping[str, object]],
    ) -> SettingsSnapshot:
        """Atomically apply fields to the newest complete canonical document."""
        if not changes or "schema_version" in changes or not set(changes) < SETTINGS_KEYS:
            raise SettingsError("updates must contain only known setting fields")
        with self._lock, self._write_lock():
            exists = self.settings_path.exists() or self.settings_path.is_symlink()
            if exists:
                base = read_trusted(self.settings_path)
            else:
                base = validate_settings(dict(migration_factory()))
            candidate = validate_settings({**base.to_dict(), **changes})
            atomic_write(self.settings_path, candidate)
            self._accept(candidate)
            self._write_recovery(candidate)
            self._checked_at = self._clock()
            return candidate

    def compare_and_update(
        self,
        changes: Mapping[str, object],
        expected: Mapping[str, object],
        migration_factory: Callable[[], Mapping[str, object]],
        *,
        force: bool = False,
    ) -> SettingsSnapshot:
        """Update fields only when their locked canonical values match ``expected``."""
        if (
            not changes
            or "schema_version" in changes
            or not set(changes) < SETTINGS_KEYS
            or set(expected) != set(changes)
        ):
            raise SettingsError("compare-and-update requires matching known setting fields")
        with self._lock, self._write_lock():
            exists = self.settings_path.exists() or self.settings_path.is_symlink()
            if exists:
                base = read_trusted(self.settings_path)
            else:
                base = validate_settings(dict(migration_factory()))
            validate_settings({**base.to_dict(), **expected})
            candidate = validate_settings({**base.to_dict(), **changes})
            conflicts = tuple(
                sorted(name for name, value in expected.items() if getattr(base, name) != value)
            )
            if conflicts and not force:
                raise SettingsConflictError(conflicts, base)
            atomic_write(self.settings_path, candidate)
            self._accept(candidate)
            self._write_recovery(candidate)
            self._checked_at = self._clock()
            return candidate

    def _accept(self, snapshot: SettingsSnapshot) -> bool:
        changed = snapshot != self._last_good
        self._last_good = snapshot
        self.last_diagnostic = None
        return changed

    def _write_recovery(self, snapshot: SettingsSnapshot) -> None:
        try:
            atomic_write(self.recovery_path, snapshot)
            self._recovery_synced = True
        except (OSError, SettingsError) as exc:
            self._recovery_synced = False
            self._diagnose(f"recovery settings write failed: {exc}")

    def _diagnose(self, message: str) -> None:
        self.last_diagnostic = message
        logging.getLogger(__name__).warning(message)

    @contextmanager
    def _write_lock(self) -> Iterator[None]:
        lock_path = self.settings_path.with_name(f".{self.settings_path.name}.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(lock_path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            _validate_stat(os.fstat(fd), lock_path)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
