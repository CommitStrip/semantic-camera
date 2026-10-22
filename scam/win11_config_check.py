"""Offline, redacted static configuration diagnostics for Win11.

This module validates configuration shape and local asset presence only. It
never starts the product, loads a model, contacts a network endpoint, reads a
cloud key value, or prints raw paths and configuration values.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

from .config import load_venue, resolve_venue_asset_paths, validate_venue
from .win11_diagnostic_text import format_summary


REPORT_SCHEMA = "scam.win11-config-check/v1"
KEY_ENV_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
MAX_CONFIG_BYTES = 4 * 1024 * 1024


class _UsageError(Exception):
    pass


class _RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError()


def _path_is_reparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except (OSError, ValueError):
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & marker) or Path(path).is_symlink()


def _identity(
    provided: bool,
    absolute: bool,
    existing: bool,
    role: str,
) -> dict[str, Any]:
    return {
        "role": role,
        "provided": bool(provided),
        "absolute": bool(absolute),
        "existing": bool(existing),
    }


def _issue(issues: list[dict[str, str]], code: str, role: str) -> None:
    entry = {"code": code, "role": role}
    if entry not in issues:
        issues.append(entry)


def _read_config_text(path: Path) -> tuple[str | None, str | None]:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_CONFIG_BYTES + 1)
    except OSError:
        return None, "config_invalid_json"
    if len(data) > MAX_CONFIG_BYTES:
        return None, "config_too_large"
    try:
        return data.decode("utf-8-sig"), None
    except UnicodeError:
        return None, "config_invalid_json"


def _enabled(section: Any, role: str, issues: list[dict[str, str]]) -> bool:
    if not isinstance(section, dict):
        return False
    if "enabled" in section and type(section["enabled"]) is not bool:
        _issue(issues, f"{role}_enabled_invalid", f"{role}_model")
        return False
    return section.get("enabled") is True


def _check_required_path(
    raw: Any,
    expected: str,
    code: str,
    role: str,
    issues: list[dict[str, str]],
) -> bool:
    if not isinstance(raw, str) or not raw:
        _issue(issues, f"{code}_missing", role)
        return False
    path = Path(raw)
    if not path.is_absolute():
        _issue(issues, f"{code}_not_absolute", role)
        return False
    if _path_is_reparse(path):
        _issue(issues, f"{code}_reparse_point", role)
        return False
    valid = path.is_dir() if expected == "directory" else path.is_file()
    if not valid:
        _issue(issues, f"{code}_missing", role)
        return False
    return True


def _asset_marker(value: Any) -> tuple[bool, str | None]:
    marker = value.get("asset_paths") if isinstance(value, dict) else None
    if not isinstance(marker, dict):
        return False, None
    root = marker.get("root")
    return True, root if isinstance(root, str) else None


def _load_config(
    config_path: Path,
    install_root: Path | None,
    issues: list[dict[str, str]],
) -> tuple[Any | None, str]:
    if not config_path.is_absolute():
        _issue(issues, "config_not_absolute", "external_config")
        return None, "rejected"
    if _path_is_reparse(config_path):
        _issue(issues, "config_reparse_point", "external_config")
        return None, "rejected"
    if not config_path.is_file():
        _issue(issues, "config_missing", "external_config")
        return None, "rejected"
    text, read_code = _read_config_text(config_path)
    if read_code is not None:
        _issue(issues, read_code, "external_config")
        return None, "rejected"
    try:
        raw = json.loads(text or "")
    except (OSError, UnicodeError, json.JSONDecodeError):
        _issue(issues, "config_invalid_json", "external_config")
        return None, "rejected"
    if not isinstance(raw, dict):
        _issue(issues, "config_structure_invalid", "external_config")
        _issue(issues, "venue_invalid", "venue")
        return None, "rejected"
    marker_present, marker_root = _asset_marker(raw)
    try:
        if marker_present and marker_root == "install":
            if install_root is None:
                _issue(issues, "install_root_required", "install_root")
                return None, "rejected"
            value = resolve_venue_asset_paths(
                raw, config_path, install_root=install_root
            )
            return value, "resolve_venue_asset_paths"
        marker_present, marker_root = _asset_marker(raw)
        if marker_present and marker_root == "config":
            value = resolve_venue_asset_paths(raw, config_path)
            return value, "resolve_venue_asset_paths"
        return raw, "utf8_sig_json"
    except Exception:
        _issue(issues, "config_resolution_failed", "external_config")
        return None, "rejected"


def _venue_checks(
    value: Any,
    issues: list[dict[str, str]],
) -> tuple[bool, dict[str, Any]]:
    errors = validate_venue(value) if isinstance(value, dict) else ["invalid"]
    valid = not errors
    if isinstance(value, dict) and "l2" in value and not isinstance(value["l2"], dict):
        _issue(issues, "l2_structure_invalid", "l2_model")
        valid = False
    if not valid:
        _issue(issues, "venue_invalid", "venue")
    l3 = value.get("l3") if isinstance(value, dict) else None
    if isinstance(l3, dict):
        if any("image_upload_consent" in error for error in errors):
            _issue(issues, "l3_consent_missing", "l3_model")
        if any("vision_capable" in error for error in errors):
            _issue(issues, "l3_vision_not_declared", "l3_model")
        if any("key_env" in error for error in errors):
            _issue(issues, "l3_key_env_invalid", "l3_model")
    return valid, {"role": "venue", "valid": valid}


def _l1_checks(
    value: Any,
    issues: list[dict[str, str]],
) -> dict[str, Any]:
    cameras = value.get("cameras") if isinstance(value, dict) else None
    enabled = False
    if isinstance(cameras, list):
        for camera in cameras:
            if isinstance(camera, dict) and "enabled" in camera:
                if type(camera["enabled"]) is not bool:
                    _issue(issues, "l1_enabled_invalid", "l1_model")
                elif camera["enabled"] is False:
                    continue
            detector = camera.get("detector") if isinstance(camera, dict) else None
            if not isinstance(detector, dict) or detector.get("engine") != "onnx":
                continue
            enabled = True
            _check_required_path(
                detector.get("model"), "file", "l1_model", "l1_model", issues
            )
    return {
        "role": "l1_model",
        "enabled": enabled,
        "status": "checked" if enabled else "disabled",
    }


def _l2_checks(
    value: Any,
    issues: list[dict[str, str]],
) -> dict[str, Any]:
    section = value.get("l2") if isinstance(value, dict) else None
    enabled = _enabled(section, "l2", issues)
    if enabled:
        _check_required_path(
            section.get("repo_path"), "directory", "l2_repo", "l2_model", issues
        )
        _check_required_path(
            section.get("checkpoint"), "file", "l2_checkpoint", "l2_model", issues
        )
    return {
        "role": "l2_model",
        "enabled": enabled,
        "status": "checked" if enabled else "disabled",
    }


def _l3_checks(
    value: Any,
    issues: list[dict[str, str]],
) -> dict[str, Any]:
    section = value.get("l3") if isinstance(value, dict) else None
    enabled = _enabled(section, "l3", issues)
    provider = section.get("provider", "local") if isinstance(section, dict) else None
    key_env = section.get("key_env") if isinstance(section, dict) else None
    key_name_valid = (
        isinstance(key_env, str) and KEY_ENV_RE.fullmatch(key_env) is not None
    )
    if enabled and provider == "local":
        _check_required_path(
            section.get("model_path"), "directory", "l3_model", "l3_model", issues
        )
    if enabled and provider == "cloud":
        if section.get("image_upload_consent") is not True:
            _issue(issues, "l3_consent_missing", "l3_model")
        if section.get("vision_capable") is not True:
            _issue(issues, "l3_vision_not_declared", "l3_model")
        if not key_name_valid:
            _issue(issues, "l3_key_env_invalid", "l3_model")
    return {
        "role": "l3_model",
        "enabled": enabled,
        "status": "checked" if enabled else "disabled",
        "provider": provider if enabled and provider in ("local", "cloud") else None,
        "consent": section.get("image_upload_consent") is True
        if enabled and provider == "cloud" else None,
        "vision_capable": section.get("vision_capable") is True
        if enabled and provider == "cloud" else None,
        "key_env_name_valid": key_name_valid if enabled and provider == "cloud" else None,
    }


def run_check(config: str, install_root: str | None = None) -> dict[str, Any]:
    issues: list[dict[str, str]] = []
    config_path = Path(config)
    install_path = Path(install_root) if install_root is not None else None
    install_identity = _identity(
        install_path is not None,
        install_path.is_absolute() if install_path is not None else False,
        install_path.is_dir() if install_path is not None else False,
        "install_root",
    )
    if install_path is not None:
        if not install_path.is_absolute():
            _issue(issues, "install_root_not_absolute", "install_root")
        elif _path_is_reparse(install_path):
            _issue(issues, "install_root_reparse_point", "install_root")
        elif not install_path.is_dir():
            _issue(issues, "install_root_missing", "install_root")

    value, loader = _load_config(config_path, install_path, issues)
    venue_valid = False
    venue_check = {"role": "venue", "valid": False}
    l1_check = {"role": "l1_model", "enabled": False, "status": "unavailable"}
    l2_check = {"role": "l2_model", "enabled": False, "status": "unavailable"}
    l3_check = {
        "role": "l3_model",
        "enabled": False,
        "status": "unavailable",
        "provider": None,
        "consent": None,
        "vision_capable": None,
        "key_env_name_valid": None,
    }
    marker_present, marker_root = _asset_marker(value)
    if value is not None:
        venue_valid, venue_check = _venue_checks(value, issues)
        l1_check = _l1_checks(value, issues)
        l2_check = _l2_checks(value, issues)
        l3_check = _l3_checks(value, issues)
    if value is None:
        loader = "unavailable"

    report = {
        "schema": REPORT_SCHEMA,
        "config": _identity(
            True,
            config_path.is_absolute(),
            config_path.is_file(),
            "external_config",
        ),
        "install_root": install_identity,
        "checks": {
            "venue": venue_check,
            "asset_resolution": {
                "role": "asset_paths",
                "marker_present": marker_present,
                "root": marker_root,
                "loader": loader,
            },
            "l1": l1_check,
            "l2": l2_check,
            "l3": l3_check,
        },
        "issues": sorted(
            issues,
            key=lambda item: (item["code"], item["role"]),
        ),
        "runtime_verified": False,
        "release_ready": False,
        "verdict": "static_config_pass" if not issues else "failed",
    }
    if not venue_valid and value is not None:
        report["checks"]["venue"] = venue_check
    return report


def main(argv: list[str] | None = None) -> int:
    parser = _RedactedArgumentParser(
        description="Offline redacted static Win11 configuration diagnostics."
    )
    parser.add_argument(
        "--config", required=True, type=Path,
        help="Explicit absolute JSON path",
    )
    parser.add_argument(
        "--install-root", type=Path,
        help="Explicit absolute install root",
    )
    parser.add_argument(
        "--text", action="store_true",
        help="Print redacted Chinese guidance instead of JSON",
    )
    try:
        args = parser.parse_args(argv)
    except _UsageError:
        requested = list(argv) if argv is not None else sys.argv[1:]
        if "--text" in requested:
            print("命令行参数无效，请使用完整诊断命令。")
            return 2
        print(json.dumps({
            "schema": REPORT_SCHEMA,
            "config": _identity(False, False, False, "external_config"),
            "install_root": _identity(False, False, False, "install_root"),
            "checks": {},
            "issues": [{"code": "usage_error", "role": "cli"}],
            "runtime_verified": False,
            "release_ready": False,
            "verdict": "failed",
        }, ensure_ascii=False, sort_keys=True))
        return 2
    if args.install_root is not None and not args.install_root.is_absolute():
        if args.text:
            print("安装根目录必须是绝对路径。")
            return 2
        print(json.dumps({
            "schema": REPORT_SCHEMA,
            "config": _identity(True, args.config.is_absolute(), False,
                                "external_config"),
            "install_root": _identity(True, False, False, "install_root"),
            "checks": {},
            "issues": [
                {"code": "install_root_not_absolute", "role": "install_root"}
            ],
            "runtime_verified": False,
            "release_ready": False,
            "verdict": "failed",
        }, ensure_ascii=False, sort_keys=True))
        return 2
    try:
        report = run_check(str(args.config),
                           str(args.install_root) if args.install_root else None)
    except Exception:
        report = {
            "schema": REPORT_SCHEMA,
            "config": _identity(True, Path(args.config).is_absolute(), False,
                                "external_config"),
            "install_root": _identity(
                args.install_root is not None,
                Path(args.install_root).is_absolute()
                if args.install_root is not None else False,
                False,
                "install_root",
            ),
            "checks": {},
            "issues": [{"code": "internal_error", "role": "tool"}],
            "runtime_verified": False,
            "release_ready": False,
            "verdict": "failed",
        }
    if args.text:
        print(format_summary(report))
    else:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report["verdict"] == "static_config_pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
