"""Win11 发布前自动预检。

本模块只证明“本机入口具备启动条件”，不会把配置检查冒充真实 RTSP、
真实模型、进程重启或原生安装端到端证据。报告不保存摄像头地址或凭据。
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import sys

from .config import load_venue, validate_venue
from .editions import WIN11_WORKSTATION
from .platform import app_data_dir


SCHEMA = "scam.win11-preflight/v1"
DEPENDENCIES = ("numpy", "cv2", "onnxruntime", "PIL")


def _check(name, passed, detail, *, blocking=True):
    return {
        "name": name,
        "passed": bool(passed),
        "blocking": bool(blocking),
        "detail": str(detail),
    }


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _dependency_checks(find_spec=importlib.util.find_spec):
    checks = []
    for module in DEPENDENCIES:
        available = find_spec(module) is not None
        checks.append(_check(
            f"dependency:{module}", available,
            "available" if available else "missing"))
    return checks


def collect_preflight(config_path=None, *, current_platform=None,
                      find_spec=importlib.util.find_spec, ffmpeg_path=None):
    """收集可重复的自动预检结果；不打开摄像头、不加载模型。"""
    expected_config = Path(WIN11_WORKSTATION.default_config())
    config = Path(config_path or expected_config)
    current_platform = current_platform or sys.platform
    checks = [
        _check("native_windows", current_platform == "win32",
               current_platform),
        _check("per_user_config", _under(config, Path(app_data_dir())),
               "inside LOCALAPPDATA app directory" if _under(
                   config, Path(app_data_dir())) else
               "outside LOCALAPPDATA app directory"),
        _check("config_exists", config.is_file(),
               "present" if config.is_file() else "missing"),
    ]
    checks.extend(_dependency_checks(find_spec))
    ffmpeg = shutil.which("ffmpeg") if ffmpeg_path is None else ffmpeg_path
    checks.append(_check("ffmpeg", bool(ffmpeg),
                         "available" if ffmpeg else "missing"))

    cameras = []
    config_errors = []
    if config.is_file():
        try:
            venue = load_venue(config)
            config_errors = validate_venue(venue)
            for camera in venue.get("cameras", []) if isinstance(
                    venue, dict) else []:
                detector = camera.get("detector") or {}
                engine = detector.get("engine")
                model = detector.get("model") if engine == "onnx" else None
                cameras.append({
                    "id": camera.get("id"),
                    "source_kind": camera.get("source_kind", "unspecified"),
                    "mode": "alerting" if engine == "onnx" else "monitor_only",
                    "model_present": bool(model and Path(model).is_file()),
                    "recording_enabled": camera.get("record_enabled", False)
                    is True,
                })
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            config_errors = [f"配置读取失败: {type(exc).__name__}"]
    checks.append(_check("config_valid", not config_errors,
                         "; ".join(config_errors) if config_errors else "valid"))

    for camera in cameras:
        cid = camera["id"] or "unknown"
        if camera["mode"] == "alerting":
            checks.append(_check(
                f"camera:{cid}:model", camera["model_present"],
                "model present" if camera["model_present"] else
                "configured model missing"))
        else:
            checks.append(_check(
                f"camera:{cid}:honest_mode", True,
                "monitor_only; alerts are disabled", blocking=False))

    blocking_passed = all(item["passed"] for item in checks
                          if item["blocking"])
    alerting_ready = bool(cameras) and all(
        camera["mode"] == "alerting" and camera["model_present"]
        for camera in cameras)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_level": "automated_preflight",
        "host": {
            "platform": current_platform,
            "windows_release": platform.release() if current_platform == "win32"
            else None,
        },
        "config": {
            "path": str(config.resolve()),
            "expected_path": str(expected_config.resolve()),
            "camera_count": len(cameras),
        },
        "cameras": cameras,
        "checks": checks,
        "summary": {
            "launch_ready": blocking_passed,
            "alerting_ready": alerting_ready,
            "monitor_only": blocking_passed and bool(cameras) and
            not alerting_ready,
        },
        "not_verified": [
            "real_rtsp_stream",
            "real_detector_quality",
            "process_restart_persistence",
            "clean_non_admin_install",
            "installer_end_to_end",
            "long_running_stability",
        ],
    }


def write_report(path, report):
    """原子写入UTF-8报告；不覆盖时不会留下半文件。"""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(target.name + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, target)


def default_report_path():
    return os.path.join(app_data_dir(), "evidence", "win11-preflight.json")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Win11发布前自动预检（不替代真实摄像头/安装验收）")
    parser.add_argument("--config", default=WIN11_WORKSTATION.default_config())
    parser.add_argument("--report", default=default_report_path())
    args = parser.parse_args(argv)
    report = collect_preflight(args.config)
    write_report(args.report, report)
    summary = report["summary"]
    print("[OK] 自动预检通过" if summary["launch_ready"] else
          "[FAIL] 自动预检未通过")
    if summary["monitor_only"]:
        print("[提示] 当前为只预览不告警模式")
    print(f"[证据] {Path(args.report).resolve()}")
    print("[边界] 未验证真实RTSP、真实模型质量、进程重启、干净安装和长稳")
    return 0 if summary["launch_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
