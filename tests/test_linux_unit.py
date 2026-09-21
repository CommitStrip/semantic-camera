"""linux_unit 渲染器契约：键位必需 + 单一真值（静态模板/安装脚本不得各写一份 unit）。

公开测试（跨平台）：Windows 开发机与 Linux CI 都必须通过。
服务级行为冒烟见 test_linux_service_smoke.py（仅 Linux）。
"""

import sys
from pathlib import Path

import pytest

from scam.linux_unit import main, render_unit

ROOT = Path(__file__).resolve().parents[1]


def test_unit_contains_required_keys():
    unit = render_unit(user="nvr-admin", workdir="/opt/scam")
    assert "User=nvr-admin" in unit                      # 显式用户，禁止 %i 占位符
    assert "%i" not in unit
    assert "WorkingDirectory=/opt/scam" in unit          # 绝对工作目录
    assert "ExecStart=/opt/scam/.venv/bin/python -m scam.linux_nvr" in unit
    assert "Restart=always" in unit
    assert "RestartSec=5" in unit
    assert "Environment=PYTHONUNBUFFERED=1" in unit       # journalctl 实时可见
    assert "Wants=network-online.target" in unit          # 等待网络就绪
    assert "After=network-online.target" in unit
    assert "[Install]" in unit
    assert "WantedBy=multi-user.target" in unit


def test_unit_explicit_python_override_is_absolute():
    unit = render_unit(user="u", workdir="/opt/scam", python="/usr/bin/python3")
    assert "ExecStart=/usr/bin/python3 -m scam.linux_nvr" in unit


def test_unit_rejects_placeholder_or_empty_user():
    with pytest.raises(ValueError):
        render_unit(user="%i", workdir="/opt/scam")
    with pytest.raises(ValueError):
        render_unit(user="", workdir="/opt/scam")
    with pytest.raises(ValueError):
        render_unit(user="  ", workdir="/opt/scam")


def test_unit_rejects_relative_and_dotdot_workdir():
    with pytest.raises(ValueError):
        render_unit(user="u", workdir="scam")
    with pytest.raises(ValueError):
        render_unit(user="u", workdir="/opt/../etc")


def test_cli_renders_to_stdout(capsys):
    assert main(["render", "--user", "u1", "--workdir", "/opt/scam"]) == 0
    out = capsys.readouterr().out
    assert "User=u1" in out
    assert "-m scam.linux_nvr" in out


def test_cli_defaults_to_environment_user(monkeypatch, capsys):
    monkeypatch.setenv("USER", "service-owner")
    assert main(["render", "--workdir", "/opt/scam"]) == 0
    assert "User=service-owner" in capsys.readouterr().out


def test_single_truth_install_script_has_no_embedded_unit():
    text = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert "[Unit]" not in text, \
        "install.sh 不得内嵌第二份 unit（单一真值 = linux_unit 渲染器）"
    assert "scam.linux_unit render" in text, "install.sh 必须经渲染器取得 unit"


def test_legacy_static_template_is_deprecated_pointer():
    text = (ROOT / "deploy" / "scam-nvr.service").read_text(encoding="utf-8")
    assert "[Unit]" not in text, \
        "静态 unit 模板必须废弃，防止与渲染器形成双真值"
    assert "linux_unit" in text
