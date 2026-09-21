"""LC-011 主机预检证据清单测试：只读采集、字段固定、门禁恒 null、零子进程。

平台与工具发现性全部注入，不在测试中冒充 Linux 主机证据；本文件为合成
API 契约测试，不代表任何真实主机、RTSP 或发布结论。
"""

import json
import subprocess

import pytest

import scam.linux_host_probe as probe
from scam.linux_host_probe import SCHEMA, TOOLS, UNEVALUATED_GATES, main


def _fake_which(paths):
    def _which(name):
        return paths.get(name)

    return _which


def _assert_common_shape(observation, *, native_linux):
    assert observation["schema"] == SCHEMA
    assert observation["kind"] == "host_preflight"
    assert observation["observed_at"].endswith("Z")
    assert observation["native_linux"] is native_linux
    assert observation["host_gate_passed"] is None
    assert observation["release_gate_passed"] is None
    assert observation["unevaluated_gates"] == list(UNEVALUATED_GATES)
    assert len(observation["unevaluated_gates"]) == 6
    assert "availability does not" in observation["host_gate_note"]


def test_native_linux_observation_with_all_tools_discovered():
    observation = probe.collect_observation(
        system="linux",
        platform_platform="Linux-6.8-x86_64",
        python_version="3.12.1",
        python_executable="/usr/bin/python3",
        which_fn=_fake_which({"ffmpeg": "/usr/bin/ffmpeg",
                              "ffprobe": "/usr/bin/ffprobe",
                              "systemctl": "/usr/bin/systemctl"}))

    _assert_common_shape(observation, native_linux=True)
    assert observation["platform_system"] == "linux"
    assert observation["platform_platform"] == "Linux-6.8-x86_64"
    assert observation["python_version"] == "3.12.1"
    assert observation["python_executable"] == "/usr/bin/python3"
    assert [tool["name"] for tool in observation["tools"]] == list(TOOLS)
    assert all(tool["available"] for tool in observation["tools"])
    assert observation["tools"][0]["path"] == "/usr/bin/ffmpeg"


def test_non_linux_platform_reports_not_native(tmp_path, monkeypatch):
    # 当前测试在 Windows 本机运行：如实注入非 Linux 平台，不冒充主机证据
    monkeypatch.setattr(probe.shutil, "which", _fake_which({}))
    observation = probe.collect_observation(system="win32",
                                            platform_platform="Windows-11")
    _assert_common_shape(observation, native_linux=False)
    assert observation["platform_system"] == "win32"
    for tool in observation["tools"]:
        assert tool["available"] is False
        assert tool["path"] is None


def test_missing_tools_reported_unavailable_only(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.shutil, "which", _fake_which(
        {"ffmpeg": None, "ffprobe": "/usr/bin/ffprobe", "systemctl": None}))
    observation = probe.collect_observation(system="linux")
    tools = {tool["name"]: tool for tool in observation["tools"]}
    assert tools["ffmpeg"]["available"] is False
    assert tools["ffmpeg"]["path"] is None
    assert tools["ffprobe"]["available"] is True
    assert tools["systemctl"]["available"] is False
    # 工具缺失/存在都不改变门禁诚实边界
    assert observation["host_gate_passed"] is None
    assert observation["release_gate_passed"] is None


def test_gates_stay_null_across_platforms_and_tools():
    for system in ("linux", "win32", "darwin"):
        observation = probe.collect_observation(
            system=system, which_fn=_fake_which({}))
        assert observation["host_gate_passed"] is None
        assert observation["release_gate_passed"] is None


def test_zero_subprocess_during_collection_and_cli(tmp_path, monkeypatch,
                                                   capsys):
    def _forbidden(*args, **kwargs):
        raise AssertionError("预检采集不得创建子进程")

    for name in ("run", "Popen", "check_output", "call", "check_call"):
        monkeypatch.setattr(subprocess, name, _forbidden)
    monkeypatch.setattr(probe.shutil, "which", _fake_which({}))

    observation = probe.collect_observation(system="linux")
    assert observation["kind"] == "host_preflight"

    assert main([]) == 0
    payload = json.loads(capsys.readouterr().out)
    _assert_common_shape(payload, native_linux=(probe.sys.platform == "linux"))


def test_linux_lookalike_platform_is_not_native():
    observation = probe.collect_observation(
        system="linux-proxy", which_fn=_fake_which({}))
    _assert_common_shape(observation, native_linux=False)


def test_cli_rejects_unknown_parameters_nonzero():
    with pytest.raises(SystemExit) as excinfo:
        main(["--definitely-not-a-flag"])
    assert excinfo.value.code != 0


def test_cli_internal_error_reports_nonzero_without_gate_pass(
        tmp_path, monkeypatch, capsys):
    def _boom():
        raise RuntimeError("collector failed")

    monkeypatch.setattr(probe, "collect_observation", _boom)
    assert main([]) == 1
    stderr = capsys.readouterr().err
    payload = json.loads(stderr)
    assert payload["kind"] == "host_preflight_error"
    assert payload["host_gate_passed"] is None
    assert payload["release_gate_passed"] is None
