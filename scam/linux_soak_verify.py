"""Linux NVR soak evidence package integrity verifier.

Offline verification of an evidence directory produced by
``scam.linux_soak``: manifest/summary contracts, streaming NDJSON hash
chain, and summary cross-checks.  The result only proves package
structure and hash integrity; it never evaluates release gates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys

SCHEMA = "scam.linux-soak/v1"
VERIFY_SCHEMA = "scam.linux-soak-verify/v1"
GENESIS_HASH = "0" * 64
_HEX64 = set("0123456789abcdef")
REQUIRED_FILES = ("manifest.json", "samples.ndjson", "summary.json")


def _canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":")).encode("utf-8")


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and set(value) <= _HEX64)


def _is_count(value):
    return isinstance(value, int) and not isinstance(value, bool)


class _Corrupt(Exception):
    """Internal: stop streaming on the first inconsistency."""


def _read_json_file(path, name, errors):
    with open(path, "rb") as handle:
        raw = handle.read()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        errors.append(f"{name}: invalid JSON ({type(exc).__name__})")
        return None
    if not isinstance(payload, dict):
        errors.append(f"{name}: root is not an object")
        return None
    return payload


def _check_regular_file(path, name, errors):
    """Reject missing files, symlinks and anything that is not a plain file."""
    try:
        info = os.lstat(path)
    except OSError:
        errors.append(f"{name}: missing")
        return False
    if stat.S_ISLNK(info.st_mode):
        errors.append(f"{name}: symlink is not accepted")
        return False
    if not stat.S_ISREG(info.st_mode):
        errors.append(f"{name}: not a regular file")
        return False
    return True


def _verify_manifest(payload, errors):
    if payload is None:
        return
    if payload.get("schema") != SCHEMA:
        errors.append("manifest.json: unknown schema")
    if payload.get("kind") != "manifest":
        errors.append("manifest.json: kind must be manifest")


def _verify_summary(payload, errors):
    if payload is None:
        return None
    if payload.get("schema") != SCHEMA:
        errors.append("summary.json: unknown schema")
    if payload.get("kind") != "summary":
        errors.append("summary.json: kind must be summary")
    count = payload.get("sample_count")
    if not _is_count(count) or count < 0:
        errors.append("summary.json: sample_count must be a non-negative int")
        count = None
    last = payload.get("last_record_sha256")
    if not _is_hex64(last):
        errors.append("summary.json: last_record_sha256 must be 64 hex chars")
        last = None
    return {"sample_count": count, "last_record_sha256": last}


def _iter_record_errors(handle, errors):
    """Stream the NDJSON chain; raise _Corrupt on the first inconsistency."""
    expected_sequence = 0
    previous = GENESIS_HASH
    count = 0
    last = None
    for number, line in enumerate(handle, start=1):
        line = line.rstrip("\r\n")
        if not line:
            raise _Corrupt(f"samples.ndjson:{number}: blank line")
        try:
            record = json.loads(line)
        except ValueError as exc:
            raise _Corrupt(
                f"samples.ndjson:{number}: invalid JSON "
                f"({type(exc).__name__})") from exc
        if not isinstance(record, dict):
            raise _Corrupt(f"samples.ndjson:{number}: record is not an object")
        if record.get("schema") != SCHEMA:
            raise _Corrupt(f"samples.ndjson:{number}: unknown schema")
        if record.get("kind") != "sample":
            raise _Corrupt(f"samples.ndjson:{number}: kind must be sample")
        sequence = record.get("sequence")
        if not _is_count(sequence):
            raise _Corrupt(f"samples.ndjson:{number}: sequence must be an int")
        if sequence != expected_sequence:
            raise _Corrupt(
                f"samples.ndjson:{number}: sequence {sequence} != "
                f"expected {expected_sequence}")
        if record.get("previous_sha256") != previous:
            raise _Corrupt(f"samples.ndjson:{number}: previous_sha256 mismatch")
        digest = record.get("record_sha256")
        if not _is_hex64(digest):
            raise _Corrupt(
                f"samples.ndjson:{number}: record_sha256 must be 64 hex chars")
        without_digest = dict(record)
        without_digest.pop("record_sha256", None)
        computed = hashlib.sha256(_canonical(without_digest)).hexdigest()
        if computed != digest:
            raise _Corrupt(f"samples.ndjson:{number}: record_sha256 mismatch")
        previous = digest
        last = digest
        expected_sequence = sequence + 1
        count += 1
    return count, last


def verify_soak_directory(output_dir):
    """Verify one soak evidence directory and return a machine-readable
    result.  ``release_gate_passed`` stays None by contract: structural
    integrity is not a release evaluation."""
    errors = []
    root = os.path.abspath(output_dir)
    try:
        root_info = os.lstat(root)
        if stat.S_ISLNK(root_info.st_mode):
            errors.append("output_dir: symlink is not accepted")
            # Do not continue through the link merely to collect more errors:
            # the contract forbids reading evidence outside the supplied root.
            return _result(root, errors, sample_count=None)
        if not stat.S_ISDIR(root_info.st_mode):
            errors.append("output_dir: not a directory")
            return _result(root, errors, sample_count=None)
    except OSError:
        errors.append(f"output_dir: missing: {root}")
        return _result(root, errors, sample_count=None)

    present = {
        name: _check_regular_file(os.path.join(root, name), name, errors)
        for name in REQUIRED_FILES}

    manifest = summary = None
    if present["manifest.json"]:
        manifest = _read_json_file(
            os.path.join(root, "manifest.json"), "manifest.json", errors)
        _verify_manifest(manifest, errors)
    summary_view = None
    if present["summary.json"]:
        summary = _read_json_file(
            os.path.join(root, "summary.json"), "summary.json", errors)
        summary_view = _verify_summary(summary, errors)

    sample_count = None
    if present["samples.ndjson"]:
        last = None
        try:
            with open(os.path.join(root, "samples.ndjson"),
                      "r", encoding="utf-8") as handle:
                sample_count, last = _iter_record_errors(handle, errors)
        except _Corrupt as exc:
            errors.append(str(exc))
        except (OSError, UnicodeError) as exc:
            errors.append(
                f"samples.ndjson: unreadable ({type(exc).__name__})")
        if summary_view is not None and sample_count is not None:
            if summary_view["sample_count"] is not None \
                    and summary_view["sample_count"] != sample_count:
                errors.append(
                    f"summary.json: sample_count "
                    f"{summary_view['sample_count']} != observed {sample_count}")
            if summary_view["last_record_sha256"] is not None:
                expected_last = last if sample_count else GENESIS_HASH
                if summary_view["last_record_sha256"] != expected_last:
                    errors.append("summary.json: last_record_sha256 mismatch")

    return _result(root, errors, sample_count=sample_count)


def _result(root, errors, *, sample_count):
    return {
        "schema": VERIFY_SCHEMA,
        "kind": "verify_result",
        "output_dir": root,
        "integrity_passed": not errors,
        "sample_count": sample_count,
        "errors": errors,
        "release_gate_passed": None,
        "release_gate_note": (
            "Structure and hash integrity only; host, RTSP, duration, "
            "resource plateau and failure thresholds are evaluated "
            "separately."),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="离线验证浸泡证据包结构与哈希完整性（不评估发布门禁）")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    result = verify_soak_directory(args.output_dir)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["integrity_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
