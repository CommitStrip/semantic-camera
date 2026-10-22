from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def _valid_config(path: Path) -> None:
    path.write_text(json.dumps({
        "cameras": [{
            "id": "front",
            "source": "rtsp://camera.local/stream",
            "detector": {"engine": "none"},
        }],
        "l2": {"enabled": False},
        "l3": {"enabled": False},
    }, ensure_ascii=False), encoding="utf-8")


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["PYTHONIOENCODING"] = "UTF-8"
    return subprocess.run(
        [sys.executable, "-m", "scam.win11_config_check", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        shell=False,
        check=False,
    )


def test_text_success_is_human_readable_and_not_json(tmp_path):
    config = tmp_path / "配置 # &.json"
    _valid_config(config)
    result = _run("--config", str(config), "--text")
    assert result.returncode == 0
    assert "配置静态检查通过" in result.stdout
    assert "不代表摄像头" in result.stdout
    assert result.stdout.lstrip().startswith("配置静态检查通过")
    assert "C:" not in result.stdout
    assert "camera.local" not in result.stdout


def test_default_json_contract_remains_unchanged(tmp_path):
    config = tmp_path / "config.json"
    _valid_config(config)
    result = _run("--config", str(config))
    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report["schema"] == "scam.win11-config-check/v1"
    assert report["verdict"] == "static_config_pass"
    assert report["runtime_verified"] is False
    assert report["release_ready"] is False


def test_text_failure_uses_constant_guidance_without_raw_values(tmp_path):
    config = tmp_path / "bad.json"
    config.write_text('{"source": "rtsp://secret', encoding="utf-8")
    result = _run("--config", str(config), "--text")
    assert result.returncode == 1
    assert "配置静态检查未通过" in result.stdout
    assert "配置文件不是有效 JSON" in result.stdout
    assert "secret" not in result.stdout
    assert "C:" not in result.stdout


def test_text_usage_error_is_redacted(tmp_path):
    secret = str(tmp_path / "用户 example-user" / "secret.json")
    result = _run("--unknown", secret, "--text")
    assert result.returncode == 2
    output = result.stdout + result.stderr
    assert "命令行参数无效" in output
    assert "example-user" not in output
    assert "unknown" not in output
