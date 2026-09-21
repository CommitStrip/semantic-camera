"""Linux semantic-event replay comparison.

Offline, deterministic multiset comparison of expected vs actual
``semantic_events`` fact records.  This module only compares facts that
already exist; it never executes video decoding, detectors or the event
chain, and it never promotes any quality or release gate.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import stat
import sys
from datetime import datetime, timezone

SCHEMA = "scam.linux-replay-compare/v1"
FACT_FIELDS = ("camera", "template", "zone_id", "cls", "state",
               "t_start", "t_end", "end_reason")
TEXT_FIELDS = ("camera", "template", "state")
NULLABLE_TEXT_FIELDS = ("zone_id", "cls", "end_reason")
# 运行期 ID 允许出现但绝不参与比较（事件身份随运行环境变化）
RUNTIME_ID_FIELDS = ("semantic_event_id", "event_id", "review_id",
                     "object_id")


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":")).encode("utf-8")


def _check_regular_file(path, role, errors):
    try:
        info = os.lstat(path)
    except OSError:
        errors.append(f"{role}: missing")
        return False
    if stat.S_ISLNK(info.st_mode):
        errors.append(f"{role}: symlink is not accepted")
        return False
    if not stat.S_ISREG(info.st_mode):
        errors.append(f"{role}: not a regular file")
        return False
    return True


def _snapshot(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _open_readonly_nofollow(path):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags)


def _load_event_list(path, role, errors):
    if not _check_regular_file(path, role, errors):
        return None
    try:
        before = os.lstat(path)
        fd = _open_readonly_nofollow(path)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) \
                    or _snapshot(opened) != _snapshot(before):
                errors.append(f"{role}: changed while reading")
                return None
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(fd)
        after = os.lstat(path)
        if _snapshot(after) != _snapshot(before):
            errors.append(f"{role}: changed while reading")
            return None
        payload = json.loads(b"".join(chunks).decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        errors.append(
            f"{role}: not readable as UTF-8 JSON ({type(exc).__name__})")
        return None
    if not isinstance(payload, list):
        errors.append(f"{role}: root must be a JSON array")
        return None
    return payload


def _normalize_event(item, role, index, errors):
    """校验并抽取事实字段；运行期 ID 忽略，未知/缺失/坏类型即拒绝。"""
    where = f"{role}[{index}]"
    if not isinstance(item, dict):
        errors.append(f"{where}: event is not an object")
        return None
    known = set(FACT_FIELDS) | set(RUNTIME_ID_FIELDS)
    unknown = sorted(set(item) - known)
    if unknown:
        errors.append(f"{where}: unknown fields {unknown}")
    missing = [field for field in FACT_FIELDS if field not in item]
    if missing:
        errors.append(f"{where}: missing fields {missing}")
    if unknown or missing:
        return None
    fact = {}
    for field in TEXT_FIELDS:
        if not isinstance(item[field], str):
            errors.append(f"{where}: {field} must be a string")
            return None
        fact[field] = item[field]
    for field in NULLABLE_TEXT_FIELDS:
        value = item[field]
        if value is not None and not isinstance(value, str):
            errors.append(f"{where}: {field} must be a string or null")
            return None
        fact[field] = value
    t_start = item["t_start"]
    if not isinstance(t_start, (int, float)) or isinstance(t_start, bool) \
            or not math.isfinite(t_start):
        errors.append(f"{where}: t_start must be a finite number")
        return None
    fact["t_start"] = t_start
    t_end = item["t_end"]
    if t_end is not None and (not isinstance(t_end, (int, float))
                              or isinstance(t_end, bool)
                              or not math.isfinite(t_end)):
        errors.append(f"{where}: t_end must be a finite number or null")
        return None
    fact["t_end"] = t_end
    return fact


def compare_event_lists(expected, actual):
    """Order-independent multiset comparison preserving duplicates."""
    from collections import Counter
    errors = []
    expected_keys = Counter()
    expected_facts = {}
    for index, item in enumerate(expected):
        fact = _normalize_event(item, "expected", index, errors)
        if fact is not None:
            key = _canonical(fact).decode("utf-8")
            expected_keys[key] += 1
            expected_facts[key] = fact
    actual_keys = Counter()
    actual_facts = {}
    for index, item in enumerate(actual):
        fact = _normalize_event(item, "actual", index, errors)
        if fact is not None:
            key = _canonical(fact).decode("utf-8")
            actual_keys[key] += 1
            actual_facts[key] = fact
    if errors:
        return None, errors

    missing_counts = expected_keys - actual_keys
    unexpected_counts = actual_keys - expected_keys
    missing = [expected_facts[key]
               for key in sorted(missing_counts)
               for _ in range(missing_counts[key])]
    unexpected = [actual_facts[key]
                  for key in sorted(unexpected_counts)
                  for _ in range(unexpected_counts[key])]
    matched = sum((expected_keys & actual_keys).values())
    return {
        "match": not missing and not unexpected,
        "missing": missing,
        "unexpected": unexpected,
        "matched_count": matched,
    }, errors


def compare_files(expected_path, actual_path):
    """Compare two event files; returns (result, errors)."""
    errors = []
    expected = _load_event_list(expected_path, "expected", errors)
    actual = _load_event_list(actual_path, "actual", errors)
    if errors or expected is None or actual is None:
        return None, errors
    outcome, errors = compare_event_lists(expected, actual)
    if outcome is None:
        return None, errors
    return {
        "schema": SCHEMA,
        "kind": "semantic_event_comparison",
        "created_at": _utc_now(),
        "expected_count": len(expected),
        "actual_count": len(actual),
        "match": outcome["match"],
        "missing": outcome["missing"],
        "unexpected": outcome["unexpected"],
        "counts": {
            "matched": outcome["matched_count"],
            "missing": len(outcome["missing"]),
            "unexpected": len(outcome["unexpected"]),
        },
        "replay_executed": False,
        "quality_gate_passed": None,
        "release_gate_passed": None,
        "comparison_note": (
            "Compares already-recorded facts only; no video decoding, "
            "detector execution or event chain is performed here."),
    }, errors


def _error_payload(errors):
    return {
        "schema": SCHEMA,
        "kind": "semantic_event_comparison_error",
        "errors": errors,
        "replay_executed": False,
        "quality_gate_passed": None,
        "release_gate_passed": None,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="离线比较预期/实际语义事件事实（多重集；不执行视频、"
                    "检测器或事件链，不代表任何门禁通过）")
    parser.add_argument("--expected", required=True)
    parser.add_argument("--actual", required=True)
    args = parser.parse_args(argv)

    result, errors = compare_files(args.expected, args.actual)
    if result is None:
        json.dump(_error_payload(errors), sys.stderr, ensure_ascii=False)
        sys.stderr.write("\n")
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["match"] else 1


if __name__ == "__main__":
    sys.exit(main())
