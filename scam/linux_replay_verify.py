"""Linux L4 one-shot replay fact verifier (queue N).

Chains the offline replay pipeline in one CLI: run M (deterministic
replay execution), export facts with L, compare with K.  Production path
calls the three stages directly in-process -- no subprocess, no network,
no fakes; tests may inject M's capture/detector/sink factories.  The
verifier itself writes no extra fact files; stage M writes only the
designated output database, which is preserved as evidence even when the
comparison mismatches.  A fact match never implies quality or release
approval: ``quality_gate_passed`` and ``release_gate_passed`` stay null
on every path.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

from scam.linux_replay_compare import compare_event_lists
from scam.linux_replay_export import export_events
from scam.linux_replay_run import run_replay

SCHEMA = "scam.linux-replay-verify/v1"


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _identity(path):
    try:
        info = os.lstat(path)
    except OSError:
        return None
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns)


def _read_fd_all(fd):
    chunks = []
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _lstat_now(path):
    """_load_expected 专用的路径身份采样点（测试经此注入确定性时序）。"""
    return os.lstat(path)


def _load_expected(path, errors, *, before=None):
    """Safely read the expected-events file (LC-031 严格 samestat 版)：
    lstat 身份快照（可注入）→ ``O_NOFOLLOW`` 打开 → ``samestat(before,
    opened)`` 不一致立即拒绝 → 只从持有 fd 读取 → 读取前后两次 fstat 比对
    size/mtime/ctime（防读取中途变化）→ 读后路径 lstat 须普通非链接且与
    opened samestat（防读取后换出/消失）。"""
    role = "expected"
    if before is None:
        try:
            before = _lstat_now(path)
        except OSError:
            errors.append(f"{role}: missing")
            return None
    if stat.S_ISLNK(before.st_mode):
        errors.append(f"{role}: symlink is not accepted")
        return None
    if not stat.S_ISREG(before.st_mode):
        errors.append(f"{role}: not a regular file")
        return None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)         | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        errors.append(
            f"{role}: open failed ({type(exc).__name__}: {exc})")
        return None
    try:
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                errors.append(
                    f"{role}: opened object is not a regular file")
                return None
            if not os.path.samestat(before, opened):
                errors.append(
                    f"{role}: identity changed between check and open")
                return None
            raw = _read_fd_all(fd)
            after_read_fd = os.fstat(fd)
        except OSError as exc:
            errors.append(
                f"{role}: read failed ({type(exc).__name__}: {exc})")
            return None
    finally:
        os.close(fd)
    if (after_read_fd.st_size, after_read_fd.st_mtime_ns,
            after_read_fd.st_ctime_ns) != (opened.st_size,
                                           opened.st_mtime_ns,
                                           opened.st_ctime_ns):
        errors.append(f"{role}: changed while reading")
        return None
    try:
        after = _lstat_now(path)
    except OSError as exc:
        errors.append(
            f"{role}: replaced while reading "
            f"({type(exc).__name__}: {exc})")
        return None
    if stat.S_ISLNK(after.st_mode) or not stat.S_ISREG(after.st_mode):
        errors.append(f"{role}: replaced while reading")
        return None
    if not os.path.samestat(opened, after):
        errors.append(f"{role}: replaced while reading")
        return None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        errors.append(f"{role}: invalid UTF-8 JSON ({type(exc).__name__})")
        return None
    if not isinstance(payload, list):
        errors.append(f"{role}: root must be a JSON array")
        return None
    return payload



def run_verify(manifest_path, video, config_path, model, camera_id,
               expected_path, output_db, *, capture_factory=None,
               detector_factory=None, sink_factory=None):
    """Run M -> L -> K once; returns (result, errors)."""
    errors = []
    result = {
        "schema": SCHEMA,
        "kind": "replay_verify_result",
        "created_at": _utc_now(),
        "camera_id": camera_id,
        "stages": {"replay": "skipped", "export": "skipped",
                   "compare": "skipped"},
        "replay_executed": False,
        "comparison_match": None,
        "expected_count": None,
        "actual_count": None,
        "missing": None,
        "unexpected": None,
        "errors": [],
        "quality_gate_passed": None,
        "release_gate_passed": None,
        "verify_note": (
            "Fact comparison only; no video decoding quality, detector "
            "accuracy or release gate is evaluated here."),
    }

    # 阶段 0：预期事件文件安全读取（输入错误在任何执行前拒绝）
    expected = _load_expected(expected_path, errors)
    if expected is None:
        result["errors"] = list(errors)
        return result, errors

    # 阶段 1：M —— 确定性 replay 执行
    replay_result, replay_errors = run_replay(
        manifest_path, video, config_path, model, camera_id, output_db,
        capture_factory=capture_factory, detector_factory=detector_factory,
        sink_factory=sink_factory)
    errors.extend(replay_errors)
    result["replay_executed"] = bool(replay_result.get("replay_executed"))
    if replay_errors or not result["replay_executed"]:
        result["stages"]["replay"] = "failed"
    else:
        result["stages"]["replay"] = "ok"
    if replay_errors or not result["replay_executed"]:
        result["errors"] = list(errors)
        return result, errors

    # 阶段 2：L —— 从正式 replay 库导出事实（库作为证据保留，绝不删除）
    try:
        export, export_errors = export_events(output_db)
    except Exception as exc:  # 导出层异常与错误返回同权：阶段失败，绝不炸穿
        export, export_errors = None, [f"export: {type(exc).__name__}: {exc}"]
    if export_errors or export is None:
        result["stages"]["export"] = "failed"
        result["stages"]["compare"] = "skipped"
        errors.extend(export_errors or ["export: unknown export failure"])
        result["errors"] = list(errors)
        return result, errors
    result["stages"]["export"] = "ok"
    result["actual_count"] = len(export)
    result["expected_count"] = len(expected)

    # 阶段 3：K —— 语义事件多重集比较
    try:
        outcome, compare_errors = compare_event_lists(expected, export)
    except Exception as exc:
        outcome, compare_errors = None, [f"compare: {type(exc).__name__}: {exc}"]
    if outcome is None or compare_errors:
        result["stages"]["compare"] = "failed"
        errors.extend(compare_errors)
        result["errors"] = list(errors)
        return result, errors
    result["stages"]["compare"] = "ok"
    result["comparison_match"] = outcome["match"]
    result["missing"] = outcome["missing"]
    result["unexpected"] = outcome["unexpected"]
    result["counts"] = {
        "matched": outcome["matched_count"],
        "missing": len(outcome["missing"]),
        "unexpected": len(outcome["unexpected"]),
    }
    result["errors"] = list(errors)
    return result, errors


def _error_payload(errors):
    return {
        "schema": SCHEMA,
        "kind": "replay_verify_error",
        "errors": errors,
        "replay_executed": False,
        "quality_gate_passed": None,
        "release_gate_passed": None,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="一键 replay 事实判定：顺序执行 M replay、L 导出、"
                    "K 比较（比较不匹配非零退出；不代表任何门禁通过）")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--video", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--camera-id", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--output-db", required=True)
    args = parser.parse_args(argv)

    result, errors = run_verify(
        args.manifest, args.video, args.config, args.model, args.camera_id,
        args.expected, args.output_db)
    if errors:
        result = dict(result)
        result["errors"] = list(errors)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    if errors or not result["replay_executed"]:
        return 1
    return 0 if result["comparison_match"] else 1


if __name__ == "__main__":
    sys.exit(main())
