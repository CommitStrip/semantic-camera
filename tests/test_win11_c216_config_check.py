from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scam import win11_config_check


def _write_config(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _valid_config(model_path: str = "models/person-detector.onnx") -> dict:
    return {
        "cameras": [{
            "id": "front",
            "source": "rtsp://user:password@camera.local/stream",
            "detector": {
                "engine": "onnx",
                "model": model_path,
                "classes": ["person"],
            },
        }],
        "l2": {"enabled": False},
        "l3": {"enabled": False},
    }


def _candidate_assets(root: Path) -> None:
    (root / "models").mkdir(parents=True, exist_ok=True)
    (root / "models/person-detector.onnx").write_bytes(b"l1")
    (root / "l2-repo").mkdir(parents=True, exist_ok=True)
    (root / "l2-checkpoint.pth").write_bytes(b"l2")
    (root / "l3-model").mkdir(parents=True, exist_ok=True)


def _codes(report: dict) -> set[str]:
    return {item["code"] for item in report["issues"]}


def test_valid_local_config_passes_without_reading_key_values(tmp_path, capsys):
    root = tmp_path / "安装 根"
    root.mkdir()
    _candidate_assets(root)
    config = root / "配置 # &.json"
    _write_config(config, {
        "asset_paths": {"schema": "scam.package-assets/v1", "root": "install"},
        "cameras": [{
            "id": "front",
            "source": "rtsp://user:password@camera.local/stream",
            "detector": {
                "engine": "onnx",
                "model": "models/person-detector.onnx",
                "classes": ["person"],
            },
        }],
        "l2": {"enabled": True, "repo_path": "l2-repo",
               "checkpoint": "l2-checkpoint.pth"},
        "l3": {"enabled": True, "provider": "local",
               "model_path": "l3-model"},
    })
    code = win11_config_check.main([
        "--config", str(config), "--install-root", str(root)
    ])
    output = capsys.readouterr().out
    report = json.loads(output)
    assert code == 0
    assert report["verdict"] == "static_config_pass"
    assert report["runtime_verified"] is False
    assert report["release_ready"] is False
    assert report["checks"]["l1"]["enabled"] is True
    assert report["checks"]["l2"]["enabled"] is True
    assert report["checks"]["l3"]["enabled"] is True
    assert "password" not in output
    assert "camera.local" not in output


def test_missing_config_bad_json_and_bad_type_fail_without_raw_exception(
    tmp_path, capsys
):
    missing = tmp_path / "missing.json"
    code = win11_config_check.main(["--config", str(missing)])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert "config_missing" in _codes(report)

    bad = tmp_path / "bad.json"
    bad.write_text('{"source": "rtsp://secret', encoding="utf-8")
    code = win11_config_check.main(["--config", str(bad)])
    output = capsys.readouterr().out
    report = json.loads(output)
    assert code == 1
    assert "config_invalid_json" in _codes(report)
    assert "secret" not in output

    wrong = tmp_path / "wrong.json"
    _write_config(wrong, {"cameras": "not-a-list"})
    code = win11_config_check.main(["--config", str(wrong)])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert "venue_invalid" in _codes(report)


def test_disabled_model_paths_are_not_forced_missing(tmp_path, capsys):
    root = tmp_path / "root"
    root.mkdir()
    config = root / "disabled.json"
    value = _valid_config()
    value["cameras"][0]["detector"] = {"engine": "none"}
    _write_config(config, value)
    code = win11_config_check.main([
        "--config", str(config), "--install-root", str(root)
    ])
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["checks"]["l2"] == {"role": "l2_model", "enabled": False, "status": "disabled"}
    assert report["checks"]["l3"]["role"] == "l3_model"
    assert report["checks"]["l3"]["enabled"] is False
    assert report["checks"]["l3"]["status"] == "disabled"


def test_enabled_missing_l2_l3_paths_fail_with_role_codes(tmp_path, capsys):
    root = tmp_path / "root"
    root.mkdir()
    config = root / "enabled.json"
    _write_config(config, {
        "asset_paths": {"schema": "scam.package-assets/v1", "root": "install"},
        "cameras": [],
        "l2": {"enabled": True, "repo_path": "missing-repo",
               "checkpoint": "missing-checkpoint"},
        "l3": {"enabled": True, "provider": "local",
               "model_path": "missing-model"},
    })
    code = win11_config_check.main([
        "--config", str(config), "--install-root", str(root)
    ])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert {"l2_repo_missing", "l3_model_missing"} <= _codes(report)


def test_cloud_consent_vision_and_key_name_are_static_only(tmp_path, capsys):
    root = tmp_path / "root"
    root.mkdir()
    config = root / "cloud.json"
    _write_config(config, {
        "cameras": [{
            "id": "front",
            "source": "rtsp://camera.local/stream",
            "detector": {"engine": "none"},
        }],
        "l3": {
            "enabled": True,
            "provider": "cloud",
            "base_url": "https://api.example.test/v1",
            "model": "vision-model",
            "key_env": "C216_KEY",
            "image_upload_consent": True,
            "vision_capable": True,
        },
    })
    code = win11_config_check.main(["--config", str(config)])
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["checks"]["l3"]["key_env_name_valid"] is True
    assert report["checks"]["l3"]["consent"] is True
    assert report["checks"]["l3"]["vision_capable"] is True

    _write_config(config, {
        "cameras": [{
            "id": "front",
            "source": "rtsp://camera.local/stream",
            "detector": {"engine": "none"},
        }],
        "l3": {
            "enabled": True,
            "provider": "cloud",
            "base_url": "https://api.example.test/v1",
            "model": "vision-model",
            "key_env": "bad key",
            "image_upload_consent": False,
            "vision_capable": False,
        },
    })
    code = win11_config_check.main(["--config", str(config)])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert {"l3_consent_missing", "l3_vision_not_declared",
            "l3_key_env_invalid"} <= _codes(report)


def test_reparse_paths_fail_closed_and_usage_is_two(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    config = root / "config.json"
    _write_config(config, _valid_config())
    monkeypatch.setattr(
        win11_config_check, "_path_is_reparse",
        lambda path: path == config,
    )
    report = win11_config_check.run_check(str(config))
    assert report["verdict"] == "failed"
    assert "config_reparse_point" in _codes(report)

    assert win11_config_check.main([]) == 2


def test_install_root_relative_is_usage_error(tmp_path, capsys):
    config = tmp_path / "config.json"
    _write_config(config, _valid_config())
    assert win11_config_check.main([
        "--config", str(config), "--install-root", "relative-root"
    ]) == 2
