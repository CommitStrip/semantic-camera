"""ZW-003 Win11 部署契约守卫：入口、配置落点、首次启动、缺模型预览、录像默认关。

以文本契约固化部署脚本与 pyproject 入口声明，以行为契约固化 win11 入口与
首次接入向导；只读产品代码与脚本，不修改任何脚本、产品代码或上下文。
合成证据，非真实安装器/实机证据；发现契约破坏时只报告，由 Codex 修复。
"""

import os
import re
from pathlib import Path

import pytest

from scam.editions import WIN11_WORKSTATION
from scam.platform import app_data_dir
import scam.win11 as win11_entry
from scam.win11_setup import build_initial_venue, write_initial_config

REPO = Path(__file__).resolve().parents[1]


def _read(*parts, encoding="utf-8"):
    return (REPO.joinpath(*parts)).read_text(encoding=encoding)


# ---------- 1. 入口契约：bat 与 pyproject 都指向 scam.win11 ----------

def test_entry_contract_declares_win11_module_everywhere():
    bat = _read("deploy", "start-win11.bat")
    assert "-m scam.win11" in bat
    assert "-m scam.nvr" not in bat
    assert "LOCALAPPDATA" in bat  # 配置落点提示与契约一致

    pyproject = _read("pyproject.toml")
    assert 'scam-win11 = "scam.win11:main"' in pyproject
    assert 'scam-win11-preflight = "scam.win11_acceptance:main"' in pyproject
    assert 'scam-linux-nvr = "scam.linux_nvr:main"' in pyproject


# ---------- 2. 配置落点契约：每用户 LOCALAPPDATA，绝不落在仓库/进程 cwd ----------

def test_default_config_resolves_to_per_user_appdata():
    config = WIN11_WORKSTATION.default_config()
    assert os.path.isabs(config)
    assert os.path.basename(config) == "cameras.json"
    assert "semantic-camera" in config
    local = os.environ.get("LOCALAPPDATA")
    if local:
        assert config.startswith(local)
    # 与 Linux 版的 cwd 相对默认值划清界限：不受进程工作目录影响
    assert os.path.abspath(config) != os.path.join(
        os.getcwd(), "cameras.json")


# ---------- 3. 首次启动契约：缺配置走向导（cwd 无关），完成才进值守 ----------

def test_first_run_missing_config_opens_wizard_then_runtime(
        tmp_path, monkeypatch):
    calls = {}

    def _fake_wizard(config_path):
        calls["wizard"] = config_path
        return True

    def _fake_runtime(args, edition=None):
        calls["runtime"] = (list(args), edition)
        return 0

    monkeypatch.setattr(win11_entry, "run_first_use_setup", _fake_wizard)
    monkeypatch.setattr(win11_entry, "run_runtime", _fake_runtime)
    monkeypatch.chdir(tmp_path)  # 证明首次启动不依赖 cwd/仓库内 cameras.json

    assert win11_entry.main([]) == 0

    default_config = WIN11_WORKSTATION.default_config()
    assert calls["wizard"] == default_config  # 缺配置 → 向导，落点为用户目录
    args, edition = calls["runtime"]
    assert args[:2] == ["--config", default_config]
    assert edition == "win11"

    # 向导未完成 → 退出码 1，值守绝不启动
    calls.clear()
    monkeypatch.setattr(win11_entry, "run_first_use_setup",
                        lambda config_path: False)
    assert win11_entry.main([]) == 1
    assert "runtime" not in calls

    # 已有配置 → 不走向导直接值守
    calls.clear()
    existing = tmp_path / "existing.json"
    existing.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        win11_entry, "run_first_use_setup",
        lambda config_path: pytest.fail("已有配置不得进入向导"))
    assert win11_entry.main(["--config", str(existing)]) == 0
    assert "wizard" not in calls


# ---------- 4. 缺模型契约：必须明确选择“仅预览不告警” ----------

def test_missing_model_requires_explicit_monitor_only_choice():
    base = {"camera_id": "front", "source_kind": "camera", "source": "0"}

    with pytest.raises(ValueError):
        build_initial_venue({**base, "detector_model": ""})  # 未明确选择即拒绝

    venue = build_initial_venue(
        {**base, "detector_model": "", "monitor_only": True})
    camera = venue["cameras"][0]
    assert camera["detector"] == {"engine": "none"}  # 诚实降级：无检测能力

    venue = build_initial_venue({**base, "detector_model": " person.onnx "})
    camera = venue["cameras"][0]
    assert camera["detector"]["engine"] == "onnx"
    assert camera["detector"]["model"] == "person.onnx"


# ---------- 5. 录像默认关 + 既有配置绝不覆盖 ----------

def test_wizard_venue_recording_off_and_config_never_overwritten(tmp_path):
    venue = build_initial_venue(
        {"camera_id": "front", "source_kind": "camera", "source": "0",
         "detector_model": "", "monitor_only": True})
    assert venue["cameras"][0]["record_enabled"] is False

    target = tmp_path / "cameras.json"
    write_initial_config(target, venue)
    with pytest.raises(OSError):
        write_initial_config(target, venue)  # O_EXCL：既有配置绝不覆盖


# ---------- 6. 安装器契约：只建用户目录不写配置，不触碰录像开关 ----------

def test_installer_script_contract_localappdata_and_recording_untouched():
    ps1 = _read("deploy", "install-win11.ps1", encoding="utf-8-sig")

    assert "record" not in ps1.lower()  # 安装器完全不触碰录像开关
    assert "LOCALAPPDATA" in ps1 and "semantic-camera" in ps1
    for line in ps1.splitlines():
        if "cfgPath" in line:
            assert not re.search(
                r"Set-Content|Out-File|Add-Content|WriteAllText", line), line
    # 安装器生成的启动脚本同样必须指向 scam.win11 入口
    assert "-m scam.win11" in ps1
