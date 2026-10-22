"""Safe creation of an alternate Win11 configuration.

This module deliberately stops before activation. It creates a new same-directory
JSON candidate while leaving the explicit original configuration byte-identical.
Opening a recovery wizard, switching configurations, backups, and deletion remain
outside this module's authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Mapping, NoReturn

from .config import load_venue
from .win11_setup import build_initial_venue, write_initial_config


_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
_MAX_COLLISION_ATTEMPTS = 16
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class RecoveryError(RuntimeError):
    """Fixed-code failure; never include paths, inputs, or exception text."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RecoveryResult:
    candidate_path: Path
    original_sha256: str


def _token_hex() -> str:
    return secrets.token_hex(16)


def _is_reparse(info: os.stat_result) -> bool:
    return bool(
        stat.S_ISLNK(info.st_mode)
        or (getattr(info, "st_file_attributes", 0) & _REPARSE)
    )


def _raise(code: str) -> NoReturn:
    raise RecoveryError(code) from None


def _absolute_original(original_path: str | os.PathLike[str]) -> Path:
    try:
        path = Path(os.fspath(original_path))
    except (TypeError, ValueError):
        _raise("recovery_path_not_absolute")
    if not path.is_absolute():
        _raise("recovery_path_not_absolute")
    return path


def _check_original_shape(path: Path) -> os.stat_result:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        _raise("recovery_path_missing")
    except OSError:
        _raise("recovery_path_unreadable")
    if _is_reparse(info):
        _raise("recovery_path_reparse")
    if not stat.S_ISREG(info.st_mode):
        _raise("recovery_path_not_file")
    for ancestor in path.parents:
        try:
            ancestor_info = os.lstat(ancestor)
        except FileNotFoundError:
            _raise("recovery_path_missing")
        except OSError:
            _raise("recovery_path_unreadable")
        if _is_reparse(ancestor_info):
            _raise("recovery_path_reparse")
    return info


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    if left.st_ino and right.st_ino:
        return (
            left.st_dev == right.st_dev
            and left.st_ino == right.st_ino
            and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        )
    return (
        left.st_dev == right.st_dev
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        and left.st_ctime_ns == right.st_ctime_ns
        and left.st_size == right.st_size
    )


def _hash_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        block = os.read(fd, 1 << 20)
        if not block:
            break
        digest.update(block)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def _hash_original(path: Path, expected: os.stat_result | None = None) -> str:
    before = expected or _check_original_shape(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        _raise("recovery_path_missing")
    except OSError:
        _raise("recovery_path_unreadable")
    try:
        opened = os.fstat(fd)
        if _is_reparse(opened) or not stat.S_ISREG(opened.st_mode):
            _raise("recovery_path_not_file")
        if not _same_file(before, opened):
            _raise("recovery_original_changed")
        return _hash_fd(fd)
    except RecoveryError:
        raise
    except OSError:
        _raise("recovery_path_unreadable")
    finally:
        os.close(fd)


def _candidate_path(original: Path, token: str) -> Path:
    return original.with_name(
        f"{original.stem}.recovery-{token}.json"
    )


def _remove_owned(path: Path, created: os.stat_result) -> None:
    try:
        current = os.lstat(path)
    except OSError:
        return
    if not _same_file(created, current):
        return
    try:
        path.unlink()
    except OSError:
        pass


def _create_candidate(
    original: Path, payload: Mapping[str, Any]
) -> tuple[Path, os.stat_result]:
    try:
        venue = build_initial_venue(payload)
    except Exception:
        _raise("recovery_invalid_payload")

    for _ in range(_MAX_COLLISION_ATTEMPTS):
        try:
            token = _token_hex()
        except Exception:
            _raise("recovery_candidate_token_invalid")
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            _raise("recovery_candidate_token_invalid")
        candidate = _candidate_path(original, token)
        try:
            write_initial_config(candidate, venue)
        except FileExistsError:
            continue
        except (OSError, ValueError, TypeError):
            _raise("recovery_candidate_write_failed")
        try:
            info = os.lstat(candidate)
        except OSError:
            _raise("recovery_candidate_write_failed")
        if _is_reparse(info) or not stat.S_ISREG(info.st_mode):
            _raise("recovery_candidate_write_failed")
        return candidate, info

    _raise("recovery_candidate_collision")


def create_alternate_config(
    original_path: str | os.PathLike[str],
    payload: Mapping[str, Any] | None,
) -> RecoveryResult:
    """Create a validated alternate config without changing the original.

    ``payload=None`` represents an explicit cancellation and creates no file.
    The returned candidate path is intended only for the local caller; this
    module neither logs nor transmits it.
    """

    if payload is None:
        _raise("recovery_cancelled")
    if not isinstance(payload, Mapping):
        _raise("recovery_invalid_payload")

    original = _absolute_original(original_path)
    original_stat = _check_original_shape(original)
    original_sha256 = _hash_original(original, original_stat)
    candidate, candidate_stat = _create_candidate(original, payload)

    try:
        load_venue(candidate)
        after_sha256 = _hash_original(original, original_stat)
        if after_sha256 != original_sha256:
            _raise("recovery_original_changed")
    except RecoveryError as error:
        _remove_owned(candidate, candidate_stat)
        raise error
    except Exception:
        _remove_owned(candidate, candidate_stat)
        _raise("recovery_candidate_invalid")

    return RecoveryResult(
        candidate_path=candidate,
        original_sha256=original_sha256,
    )


__all__ = [
    "RecoveryError",
    "RecoveryResult",
    "create_alternate_config",
]
