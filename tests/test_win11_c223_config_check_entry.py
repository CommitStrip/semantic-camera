from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scam import win11_config_check


ENTRY = ROOT / "packaging/win11_exe_entry.py"


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


def _run_entry(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    return subprocess.run(
        [sys.executable, str(ENTRY), "--check-config", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )


def test_real_entry_static_success_and_failure_exit_codes(tmp_path):
    config = tmp_path / "配置 # &.json"
    _valid_config(config)
    result = _run_entry("--config", str(config))
    report = json.loads(result.stdout)
    assert result.returncode == 0
    assert report["verdict"] == "static_config_pass"
    assert report["runtime_verified"] is False
    assert report["release_ready"] is False

    bad = tmp_path / "bad.json"
    bad.write_text('{"source": "rtsp://secret', encoding="utf-8")
    result = _run_entry("--config", str(bad))
    output = result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert result.returncode == 1
    assert "config_invalid_json" in {
        item["code"] for item in report["issues"]
    }
    assert "secret" not in output


def test_unknown_and_missing_arguments_exit_two_without_raw_path(tmp_path):
    secret = str(tmp_path / "用户 example-user" / "secret-path.json")
    result = _run_entry("--unknown-option", secret)
    output = result.stdout + result.stderr
    assert result.returncode == 2
    assert "usage_error" in output
    assert secret not in output
    assert "example-user" not in output

    result = _run_entry()
    output = result.stdout + result.stderr
    assert result.returncode == 2
    assert "usage_error" in output


def test_check_config_and_desktop_mix_never_starts_runtime(
    tmp_path, monkeypatch
):
    config = tmp_path / "config.json"
    _valid_config(config)
    import scam.win11_desktop as desktop
    import scam.win11_launcher as launcher

    def forbidden(*args, **kwargs):
        raise AssertionError("runtime must not start")

    monkeypatch.setattr(launcher, "main", forbidden)
    monkeypatch.setattr(desktop, "desktop_main", forbidden)
    monkeypatch.setattr(
        sys, "argv",
        [str(ENTRY), "--check-config", "--desktop", "--config", str(config)],
    )
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(ENTRY), run_name="__main__")
    assert exc.value.code == 2


def test_module_argparse_errors_are_redacted(capsys):
    secret = r"C:\Users\example\secret-path.json"
    code = win11_config_check.main(["--unknown", secret])
    output = capsys.readouterr().out
    report = json.loads(output)
    assert code == 2
    assert report["issues"][0]["code"] == "usage_error"
    assert secret not in output
    assert "example-user" not in output

    code = win11_config_check.main([None])
    output = capsys.readouterr().out
    report = json.loads(output)
    assert code == 2
    assert report["issues"][0]["code"] == "usage_error"


def test_pyinstaller_static_analysis_can_discover_config_check_import():
    tree = ast.parse(ENTRY.read_text(encoding="utf-8"))
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "scam.win11_config_check" in imported
