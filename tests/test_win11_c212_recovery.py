"""C212 safe creation of an alternate Win11 configuration."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

import pytest

from scam import win11_recovery
from scam.config import load_venue


def _valid_payload():
    return {
        "camera_id": "front-door",
        "source_kind": "camera",
        "source": "0",
        "detector_model": "",
        "monitor_only": True,
    }


def _write_original(path: Path) -> bytes:
    payload = {
        "version": "0.3",
        "venue": "win11-workstation",
        "l3": {"enabled": False},
        "cameras": [{
            "id": "old-camera",
            "enabled": True,
            "source_kind": "camera",
            "source": "0",
            "detector": {"engine": "none"},
            "record_enabled": False,
            "zones": [],
        }],
    }
    body = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode()
    path.write_bytes(body)
    return body


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in root.iterdir()
        if path.is_file()
    }


def test_valid_payload_creates_alternate_json_without_touching_original(
    tmp_path, caplog
):
    original = tmp_path / "cameras.json"
    original_bytes = _write_original(original)
    original.chmod(0o444)

    result = win11_recovery.create_alternate_config(
        original, _valid_payload()
    )

    assert isinstance(result, win11_recovery.RecoveryResult)
    assert result.candidate_path.parent == original.parent
    assert result.candidate_path != original
    assert re.fullmatch(
        r"cameras\.recovery-[0-9a-f]{32}\.json",
        result.candidate_path.name,
    )
    assert result.original_sha256 == hashlib.sha256(
        original_bytes
    ).hexdigest()
    assert original.read_bytes() == original_bytes
    saved = load_venue(result.candidate_path)
    assert saved["l3"] == {"enabled": False}
    assert saved["cameras"][0]["id"] == "front-door"
    assert str(original) not in caplog.text
    assert str(result.candidate_path) not in caplog.text


def test_cancel_produces_no_file(tmp_path):
    original = tmp_path / "cameras.json"
    _write_original(original)
    before = _files(tmp_path)
    with pytest.raises(win11_recovery.RecoveryError) as excinfo:
        win11_recovery.create_alternate_config(original, None)
    assert excinfo.value.code == "recovery_cancelled"
    assert _files(tmp_path) == before


def test_invalid_payload_produces_no_file(tmp_path):
    original = tmp_path / "cameras.json"
    _write_original(original)
    before = _files(tmp_path)
    payload = _valid_payload()
    payload["source_kind"] = "rtsp"
    payload["source"] = "http://invalid"
    with pytest.raises(win11_recovery.RecoveryError) as excinfo:
        win11_recovery.create_alternate_config(original, payload)
    assert excinfo.value.code == "recovery_invalid_payload"
    assert _files(tmp_path) == before


@pytest.mark.parametrize(
    ("target_factory", "code"),
    [
        (lambda tmp: Path("."), "recovery_path_not_absolute"),
        (lambda tmp: tmp / "missing.json", "recovery_path_missing"),
        (lambda tmp: tmp / "directory", "recovery_path_not_file"),
    ],
)
def test_original_path_fails_closed(tmp_path, target_factory, code):
    target = target_factory(tmp_path)
    if code == "recovery_path_not_file":
        target.mkdir()
    with pytest.raises(win11_recovery.RecoveryError) as excinfo:
        win11_recovery.create_alternate_config(target, _valid_payload())
    assert excinfo.value.code == code


def test_reparse_ancestor_is_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    original = real / "cameras.json"
    _write_original(original)
    link = tmp_path / "junction"
    completed = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(link), str(real)],
        capture_output=True,
        text=True,
        shell=False,
    )
    if completed.returncode != 0:
        pytest.skip("directory junction creation unavailable")
    try:
        with pytest.raises(win11_recovery.RecoveryError) as excinfo:
            win11_recovery.create_alternate_config(
                link / "cameras.json", _valid_payload()
            )
        assert excinfo.value.code == "recovery_path_reparse"
        assert not list(real.glob("cameras.recovery-*.json"))
    finally:
        os.rmdir(link)


def test_candidate_collision_never_overwrites_existing_file(
    tmp_path, monkeypatch
):
    original = tmp_path / "cameras.json"
    _write_original(original)
    occupied = tmp_path / (
        "cameras.recovery-" + "a" * 32 + ".json"
    )
    occupied.write_bytes(b"pre-existing")
    values = iter(["a" * 32, "b" * 32])
    monkeypatch.setattr(
        win11_recovery,
        "_token_hex",
        lambda: next(values),
    )
    result = win11_recovery.create_alternate_config(
        original, _valid_payload()
    )
    assert occupied.read_bytes() == b"pre-existing"
    assert result.candidate_path.name.endswith("b" * 32 + ".json")


def test_exhausted_candidate_collisions_fail_without_writing(
    tmp_path, monkeypatch
):
    original = tmp_path / "cameras.json"
    _write_original(original)
    tokens = [format(number, "032x") for number in range(16)]
    occupied = []
    for token in tokens:
        path = tmp_path / ("cameras.recovery-" + token + ".json")
        path.write_bytes(("existing-" + token).encode())
        occupied.append(path)
    values = iter(tokens)
    monkeypatch.setattr(
        win11_recovery,
        "_token_hex",
        lambda: next(values),
    )
    with pytest.raises(win11_recovery.RecoveryError) as excinfo:
        win11_recovery.create_alternate_config(original, _valid_payload())
    assert excinfo.value.code == "recovery_candidate_collision"
    assert all(
        path.read_bytes() == ("existing-" + path.stem[-32:]).encode()
        for path in occupied
    )


def test_original_change_is_detected_and_candidate_is_removed(
    tmp_path, monkeypatch
):
    original = tmp_path / "cameras.json"
    _write_original(original)
    token = "c" * 32

    def change_original():
        original.write_bytes(original.read_bytes() + b" ")
        return token

    monkeypatch.setattr(win11_recovery, "_token_hex", change_original)
    with pytest.raises(win11_recovery.RecoveryError) as excinfo:
        win11_recovery.create_alternate_config(original, _valid_payload())
    assert excinfo.value.code == "recovery_original_changed"
    assert not (tmp_path / ("cameras.recovery-" + token + ".json")).exists()


def test_write_failure_keeps_original_and_unrelated_objects(
    tmp_path, monkeypatch
):
    original = tmp_path / "cameras.json"
    original_bytes = _write_original(original)
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_bytes(b"keep-me")

    def fail_fsync(fd):
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(win11_recovery.os, "fsync", fail_fsync)
    with pytest.raises(win11_recovery.RecoveryError) as excinfo:
        win11_recovery.create_alternate_config(original, _valid_payload())
    assert excinfo.value.code == "recovery_candidate_write_failed"
    assert original.read_bytes() == original_bytes
    assert unrelated.read_bytes() == b"keep-me"
    assert not list(tmp_path.glob("cameras.recovery-*.json"))
