"""Linux replay input fingerprint manifest.

Freezes the exact input set for a future offline replay: one video, one
config, one model, plus a software identifier.  Streaming SHA-256 over
read-only file access only -- this is the replay input freeze
prerequisite, NOT a replay executor.  No subprocess, no model runtime,
no OpenCV/video decoding, no network, no file writes.  Fingerprinting
inputs never implies replay was executed or any gate passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "scam.linux-replay-manifest/v1"
INPUT_ROLES = ("video", "config", "model")
_HEX64 = set("0123456789abcdef")


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and set(value) <= _HEX64)


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _check_regular_file(path, role, errors):
    try:
        info = os.lstat(path)
    except OSError:
        errors.append(f"{role}: missing")
        return None
    if stat.S_ISLNK(info.st_mode):
        errors.append(f"{role}: symlink is not accepted")
        return None
    if not stat.S_ISREG(info.st_mode):
        errors.append(f"{role}: not a regular file")
        return None
    return info


def _open_readonly_nofollow(path):
    """Read-only open; O_NOFOLLOW on platforms that have it (Linux) so a
    symlink swapped in after lstat is rejected by the kernel."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags)


def _snapshot(info):
    """Identity plus mutable metadata used to reject path replacement."""
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _hash_file_consistently(path, role, pre_info, errors, sha256_fn):
    """Hash one input and re-check the pre-hash snapshot afterwards; a
    file that changed while fingerprinting produces an error instead of
    an inconsistent manifest entry."""
    try:
        if sha256_fn is None:
            fd = _open_readonly_nofollow(path)
            try:
                digest = hashlib.sha256()
                for chunk in iter(lambda: os.read(fd, 1024 * 1024), b""):
                    digest.update(chunk)
                digest = digest.hexdigest()
            finally:
                os.close(fd)
        else:
            digest = sha256_fn(path)
    except OSError as exc:
        errors.append(f"{role}: unreadable ({type(exc).__name__})")
        return None
    try:
        post_info = os.lstat(path)
    except OSError as exc:
        errors.append(f"{role}: unreadable ({type(exc).__name__})")
        return None
    if _snapshot(pre_info) != _snapshot(post_info):
        errors.append(f"{role}: changed while fingerprinting")
        return None
    return digest


def _build_input_entry(path, role, errors, sha256_fn=None):
    info = _check_regular_file(path, role, errors)
    if info is None:
        return None
    digest = _hash_file_consistently(path, role, info, errors, sha256_fn)
    if digest is None:
        return None
    return {
        "role": role,
        "name": os.path.basename(path),
        "size_bytes": int(info.st_size),
        "sha256": digest,
    }


def _verify_config_is_json_object(path, errors):
    try:
        payload = json.loads(Path(path).read_bytes().decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        errors.append(
            f"config: not readable as UTF-8 JSON ({type(exc).__name__})")
        return
    if not isinstance(payload, dict):
        errors.append("config: JSON root is not an object")


def build_manifest(video, config, model, software_id, *, sha256_fn=None):
    """Build the manifest, or (None, errors) when any input is invalid."""
    errors = []
    if not isinstance(software_id, str) or not software_id.strip():
        errors.append("software_id: must be a non-empty string")
        software_id = None
    else:
        software_id = software_id.strip()

    entries = []
    for role, path in zip(INPUT_ROLES, (video, config, model)):
        entry = _build_input_entry(path, role, errors, sha256_fn=sha256_fn)
        if entry is not None:
            entries.append(entry)
    if not errors:
        _verify_config_is_json_object(config, errors)

    if errors:
        return None, errors
    return {
        "schema": SCHEMA,
        "kind": "replay_input_manifest",
        "created_at": _utc_now(),
        "software_id": software_id,
        "inputs": entries,
        "replay_executed": False,
        "quality_gate_passed": None,
        "release_gate_passed": None,
        "next_steps_note": (
            "Inputs frozen only; replay still requires real decoding, "
            "fixed detector execution, event comparison and quality "
            "statistics."),
    }, errors


def _error_payload(errors):
    return {
        "schema": SCHEMA,
        "kind": "replay_input_manifest_error",
        "errors": errors,
        "replay_executed": False,
        "quality_gate_passed": None,
        "release_gate_passed": None,
    }


def _validate_archived_payload(payload, errors):
    error_count = len(errors)
    if not isinstance(payload, dict):
        errors.append("archived_manifest: root is not an object")
        return None
    if payload.get("schema") != SCHEMA:
        errors.append("archived_manifest: unknown schema")
    if payload.get("kind") != "replay_input_manifest":
        errors.append("archived_manifest: kind must be replay_input_manifest")
    if not isinstance(payload.get("software_id"), str) \
            or not payload["software_id"].strip():
        errors.append("archived_manifest: software_id must be non-empty")
    inputs = payload.get("inputs")
    if not isinstance(inputs, list):
        errors.append("archived_manifest: inputs must be a list")
        return None
    roles = [entry.get("role") for entry in inputs
             if isinstance(entry, dict)]
    if (len(roles) != len(INPUT_ROLES)
            or any(not isinstance(role, str) for role in roles)
            or set(roles) != set(INPUT_ROLES)):
        errors.append(
            "archived_manifest: inputs must contain exactly one entry "
            "per role " + "/".join(INPUT_ROLES))
    for entry in inputs:
        if not isinstance(entry, dict):
            errors.append("archived_manifest: input entry is not an object")
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            errors.append(f"archived_manifest[{entry.get('role')}]: "
                          "name must be a non-empty string")
        elif os.path.basename(name) != name or name in (".", ".."):
            errors.append(f"archived_manifest[{entry.get('role')}]: "
                          "name must be a plain basename")
        size = entry.get("size_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            errors.append(f"archived_manifest[{entry.get('role')}]: "
                          "size_bytes must be a non-negative int")
        if not _is_hex64(entry.get("sha256")):
            errors.append(f"archived_manifest[{entry.get('role')}]: "
                          "sha256 must be 64 hex chars")
    return payload if len(errors) == error_count else None


def _load_archived_manifest(path, errors):
    """Strictly read and validate an archived manifest (regular file only)."""
    try:
        info = os.lstat(path)
    except OSError:
        errors.append("archived_manifest: missing")
        return None
    if stat.S_ISLNK(info.st_mode):
        errors.append("archived_manifest: symlink is not accepted")
        return None
    if not stat.S_ISREG(info.st_mode):
        errors.append("archived_manifest: not a regular file")
        return None
    try:
        fd = _open_readonly_nofollow(path)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) \
                    or _snapshot(opened) != _snapshot(info):
                errors.append("archived_manifest: changed while reading")
                return None
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(fd)
        post_info = os.lstat(path)
        if _snapshot(post_info) != _snapshot(info):
            errors.append("archived_manifest: changed while reading")
            return None
        payload = json.loads(b"".join(chunks).decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        errors.append(
            f"archived_manifest: not readable as UTF-8 JSON "
            f"({type(exc).__name__})")
        return None
    return _validate_archived_payload(payload, errors)


def verify_manifest_against_inputs(archived, video, config, model, *,
                                   sha256_fn=None):
    """Recompute current input fingerprints and compare an archived
    manifest item by item (name/size/hash per role).

    ``archived`` is either the manifest dict or a path to an archived
    manifest file.  Returns (result, errors).  ``inputs_match`` is true
    only when the archived manifest is structurally valid and every role
    matches.  Honest fields never change: no replay is executed and no
    gate is promoted.
    """
    errors = []
    if isinstance(archived, (str, os.PathLike)):
        archived = _load_archived_manifest(archived, errors)
    else:
        archived = _validate_archived_payload(archived, errors)
    valid_archived = archived is not None

    current_entries = []
    if valid_archived:
        for role, path in zip(INPUT_ROLES, (video, config, model)):
            entry = _build_input_entry(path, role, errors, sha256_fn=sha256_fn)
            if entry is not None:
                current_entries.append(entry)

    archived_by_role = {}
    if valid_archived and isinstance(archived.get("inputs"), list):
        for entry in archived["inputs"]:
            if isinstance(entry, dict):
                archived_by_role[entry.get("role")] = entry

    comparisons = []
    inputs_match = valid_archived and not errors
    for role in INPUT_ROLES:
        archived_entry = archived_by_role.get(role)
        current_entry = next(
            (e for e in current_entries if e["role"] == role), None)
        if archived_entry is None or current_entry is None:
            inputs_match = False
            comparisons.append({
                "role": role,
                "match": False,
                "archived": ({"name": archived_entry.get("name"),
                              "size_bytes": archived_entry.get("size_bytes"),
                              "sha256": archived_entry.get("sha256")}
                             if isinstance(archived_entry, dict) else None),
                "current": ({"name": current_entry["name"],
                             "size_bytes": current_entry["size_bytes"],
                             "sha256": current_entry["sha256"]}
                            if current_entry else None),
            })
            continue
        name_match = archived_entry["name"] == current_entry["name"]
        size_match = archived_entry["size_bytes"] == current_entry["size_bytes"]
        hash_match = archived_entry["sha256"] == current_entry["sha256"]
        role_match = name_match and size_match and hash_match
        inputs_match = inputs_match and role_match
        comparisons.append({
            "role": role,
            "match": role_match,
            "name_match": name_match,
            "size_match": size_match,
            "hash_match": hash_match,
            "archived": {"name": archived_entry["name"],
                         "size_bytes": archived_entry["size_bytes"],
                         "sha256": archived_entry["sha256"]},
            "current": {"name": current_entry["name"],
                        "size_bytes": current_entry["size_bytes"],
                        "sha256": current_entry["sha256"]},
        })

    software_id = (archived.get("software_id")
                   if valid_archived else None)
    result = {
        "schema": SCHEMA,
        "kind": "replay_input_verification",
        "created_at": _utc_now(),
        "software_id": software_id,
        "inputs_match": bool(inputs_match),
        "comparisons": comparisons,
        "errors": errors,
        "replay_executed": False,
        "quality_gate_passed": None,
        "release_gate_passed": None,
        "next_steps_note": (
            "Verification only compares fingerprints; replay still requires "
            "real decoding, fixed detector execution, event comparison and "
            "quality statistics."),
    }
    return result, errors


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="建立 replay 输入指纹清单（只读；不是 replay 执行器，"
                    "不代表任何门禁通过）。给定 --verify-manifest 时改为"
                    "离线复核归档清单与当前输入是否逐项一致。")
    parser.add_argument("--video", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--software-id", required=False)
    parser.add_argument("--verify-manifest", required=False,
                        help="归档清单路径；提供时进入复核模式")
    args = parser.parse_args(argv)

    if args.verify_manifest:
        load_errors = []
        archived = _load_archived_manifest(args.verify_manifest, load_errors)
        if archived is None:
            json.dump(_error_payload(load_errors), sys.stderr,
                      ensure_ascii=False)
            sys.stderr.write("\n")
            return 1
        result, errors = verify_manifest_against_inputs(
            archived, args.video, args.config, args.model)
        if errors:
            json.dump(_error_payload(errors), sys.stderr, ensure_ascii=False)
            sys.stderr.write("\n")
            return 1
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["inputs_match"] else 1

    if not args.software_id or not args.software_id.strip():
        errors = ["software_id: must be a non-empty string"]
        json.dump(_error_payload(errors), sys.stderr, ensure_ascii=False)
        sys.stderr.write("\n")
        return 1

    manifest, errors = build_manifest(
        args.video, args.config, args.model, args.software_id)
    if manifest is None:
        json.dump(_error_payload(errors), sys.stderr, ensure_ascii=False)
        sys.stderr.write("\n")
        return 1
    print(json.dumps(manifest, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
