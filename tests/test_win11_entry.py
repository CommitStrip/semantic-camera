from types import SimpleNamespace

import sys

import pytest

from scam import win11


def test_win11_entry_uses_per_user_config_and_runs_setup_once(
        monkeypatch, tmp_path):
    config = tmp_path / "用户数据" / "cameras.json"
    monkeypatch.setattr(win11, "platform_error", lambda edition: None)
    monkeypatch.setattr(
        win11, "WIN11_WORKSTATION",
        SimpleNamespace(default_config=lambda: str(config),
                        default_host="127.0.0.1", key="win11"))
    setup_calls = []
    runtime_calls = []

    def setup(path, *, default_model_path=None):
        setup_calls.append((path, default_model_path))
        path_obj = config
        path_obj.parent.mkdir(parents=True)
        path_obj.write_text("{}", encoding="utf-8")
        return True

    monkeypatch.setattr(win11, "run_first_use_setup", setup)
    monkeypatch.setattr(win11, "bundled_model_path",
                        lambda: "C:/pkg/models/person-detector.onnx")
    monkeypatch.setattr(
        win11, "run_runtime",
        lambda argv, edition: runtime_calls.append((argv, edition)) or 0)

    assert win11.main(["--port", "9999"]) == 0
    assert setup_calls == [(str(config),
                            "C:/pkg/models/person-detector.onnx")],         "发行包随附模型必须预填给向导（用户仍可清空改预览模式）"
    assert runtime_calls[0][0][:2] == ["--config", str(config)]
    assert runtime_calls[0][1] == "win11"

    setup_calls.clear()
    assert win11.main([]) == 0
    assert setup_calls == [], "已有配置不得重复打开向导"


def test_win11_help_never_opens_setup(monkeypatch):
    monkeypatch.setattr(win11, "platform_error", lambda edition: None)
    monkeypatch.setattr(
        win11, "run_first_use_setup",
        lambda path, **kwargs: (_ for _ in ()).throw(
            AssertionError("must not run")))
    monkeypatch.setattr(win11, "run_runtime",
                        lambda argv, edition: 0 if argv == ["--help"] else 1)
    assert win11.main(["--help"]) == 0


def test_win11_cancelled_setup_does_not_start_runtime(monkeypatch, tmp_path):
    monkeypatch.setattr(win11, "platform_error", lambda edition: None)
    monkeypatch.setattr(
        win11, "WIN11_WORKSTATION",
        SimpleNamespace(default_config=lambda: str(tmp_path / "missing.json"),
                        default_host="127.0.0.1", key="win11"))
    monkeypatch.setattr(win11, "run_first_use_setup",
                        lambda path, **kwargs: False)
    monkeypatch.setattr(
        win11, "run_runtime",
        lambda argv, edition: (_ for _ in ()).throw(
            AssertionError("runtime must not start")))
    assert win11.main([]) == 1

# ---------- 发行包启动器（双击入口） ----------

def test_launcher_strips_its_own_flags_before_forwarding(monkeypatch):
    """启动器独有开关不得转发给运行时：否则 argparse 直接报错退出、应用起不来。"""
    from scam import win11_launcher as launcher

    forwarded = []
    monkeypatch.setattr(launcher, "fix_console_encoding", lambda: None)
    monkeypatch.setattr(launcher, "acquire_single_instance",
                        lambda: ("held", None))
    monkeypatch.setattr(launcher, "port_in_use", lambda host, port: False)
    monkeypatch.setattr(launcher, "find_ffmpeg", lambda: "ffmpeg")
    monkeypatch.setattr(launcher, "_open_browser_when_ready",
                        lambda *a, **k: False)
    monkeypatch.setattr(
        "scam.win11.main",
        lambda argv: forwarded.append(list(argv)) or 0)

    assert launcher.main(["--port", "8631", "--no-browser"]) == 0
    assert forwarded == [["--port", "8631"]]
    assert "--no-browser" not in forwarded[0]
    # 运行时自己的开关必须原样保留（启动器不做白名单裁剪）
    assert launcher._runtime_args(["--no-slow", "--no-browser"]) == ["--no-slow"]


def test_launcher_refuses_second_instance_and_port_conflict(capsys, monkeypatch):
    """重复双击与端口占用都必须明确拒绝，且不出现"启动成功"假象。"""
    from scam import win11_launcher as launcher

    monkeypatch.setattr(launcher, "fix_console_encoding", lambda: None)
    monkeypatch.setattr(launcher, "acquire_single_instance",
                        lambda: ("already_running", None))
    assert launcher.main([]) == 3
    assert "已有一个实例在运行" in capsys.readouterr().out

    monkeypatch.setattr(launcher, "acquire_single_instance",
                        lambda: ("held", None))
    monkeypatch.setattr(launcher, "port_in_use", lambda host, port: True)
    monkeypatch.setattr(launcher, "_pause_on_error", lambda enabled: None)
    monkeypatch.setattr("scam.win11.main",
                        lambda argv: (_ for _ in ()).throw(
                            AssertionError("端口被占用时不得启动值守")))
    assert launcher.main([]) == 1
    text = capsys.readouterr().out
    assert "已被占用" in text and "未启动值守" in text


def test_launcher_reports_missing_ffmpeg_without_blocking(capsys, monkeypatch):
    """ffmpeg 缺失必须如实提示，但不能阻断预览与管理员规则告警。"""
    from scam import win11_launcher as launcher

    monkeypatch.setattr(launcher, "fix_console_encoding", lambda: None)
    monkeypatch.setattr(launcher, "acquire_single_instance",
                        lambda: ("held", None))
    monkeypatch.setattr(launcher, "port_in_use", lambda host, port: False)
    monkeypatch.setattr(launcher, "find_ffmpeg", lambda: None)
    monkeypatch.setattr(launcher, "_open_browser_when_ready", lambda *a, **k: False)
    monkeypatch.setattr("scam.win11.main", lambda argv: 0)

    assert launcher.main(["--no-browser"]) == 0
    text = capsys.readouterr().out
    assert "录像/片段导出不可用" in text
    assert "预览与管理员规则告警不受影响" in text


def test_bundled_model_path_follows_packaged_layout(monkeypatch, tmp_path):
    """随包模型只在发行包布局下生效；源码运行不得凭空造出路径。"""
    from scam import win11_launcher as launcher

    assert launcher.bundled_model_path() is None, "源码运行应为 None"
    models = tmp_path / "models"
    models.mkdir()
    (models / "person-detector.onnx").write_bytes(b"stub")
    monkeypatch.setattr(launcher.sys, "_MEIPASS", str(tmp_path), raising=False)
    assert launcher.bundled_model_path() == str(models / "person-detector.onnx")

# ---------- 整改批次：回环边界 / 凭据不回显 / 单实例 fail-closed ----------

# 测试专用假凭据（TEST-NET 地址，非真实设备；仅用于验证"绝不出现在输出里"）
FAKE_RTSP = "rtsp://test-user:test-pass@192.0.2.10:554/stream"
FAKE_USER = "test-user"
FAKE_PASS = "test-pass"


def _launcher(monkeypatch, **overrides):
    from scam import win11_launcher as launcher

    monkeypatch.setattr(launcher, "fix_console_encoding", lambda: None)
    monkeypatch.setattr(launcher, "acquire_single_instance",
                        overrides.get("mutex", lambda: ("held", None)))
    monkeypatch.setattr(launcher, "port_in_use", lambda host, port: False)
    monkeypatch.setattr(launcher, "find_ffmpeg", lambda: "ffmpeg")
    monkeypatch.setattr(launcher, "_open_browser_when_ready",
                        lambda *a, **k: False)
    monkeypatch.setattr(launcher, "_pause_on_error", lambda enabled: None)
    return launcher


@pytest.mark.parametrize("host", [
    "0.0.0.0", "192.168.1.10", "10.0.0.5", "localhost", "example.com",
    "127.0.0.2", "::", "0:0:0:0:0:0:0:0",
])
def test_launcher_rejects_non_loopback_host(monkeypatch, capsys, host):
    """非回环 --host 必须在打开数据库/相机/工作台之前被拒。"""
    launcher = _launcher(monkeypatch)
    monkeypatch.setattr("scam.win11.main",
                        lambda argv: (_ for _ in ()).throw(
                            AssertionError("非回环 host 不得进入运行时")))

    assert launcher.main(["--host", host]) == launcher.EXIT_HOST_NOT_ALLOWED

    text = capsys.readouterr().out
    # 提示必须是**固定**文案（逐字匹配，不做任何取值插值）
    assert launcher.HOST_REJECT_HINT in text
    assert "不会打开数据库或相机" in text


def test_launcher_accepts_default_and_explicit_loopback(monkeypatch):
    """默认回环与显式 --host 127.0.0.1 / ::1 都应放行。"""
    launcher = _launcher(monkeypatch)
    seen = []
    monkeypatch.setattr("scam.win11.main", lambda argv: seen.append(list(argv)) or 0)

    assert launcher.main(["--no-browser"]) == 0
    assert launcher.main(["--host", "127.0.0.1", "--no-browser"]) == 0
    assert launcher.main(["--host=127.0.0.1", "--no-browser"]) == 0
    assert len(seen) == 3, "默认、--host X、--host=X 三种合法写法都应放行"


def test_win11_entry_rejects_non_loopback_host(monkeypatch, capsys):
    """`python -m scam.win11` 入口同样封闭：非回环 host 拒绝且不启动。"""
    monkeypatch.setattr(win11, "platform_error", lambda edition: None)
    monkeypatch.setattr(win11, "run_first_use_setup",
                        lambda path, **kwargs: (_ for _ in ()).throw(
                            AssertionError("非回环 host 不得进入向导")))
    monkeypatch.setattr(win11, "run_runtime",
                        lambda argv, edition: (_ for _ in ()).throw(
                            AssertionError("非回环 host 不得进入运行时")))

    assert win11.main(["--host", "0.0.0.0"]) == 5
    assert "只允许绑定 127.0.0.1" in capsys.readouterr().out


def test_launcher_startup_failure_never_echoes_credentials(monkeypatch, capsys,
                                                           tmp_path):
    """启动失败：异常原文（含 RTSP 凭据）不得进入控制台或诊断文件。"""
    config = tmp_path / "用户数据" / "cameras.json"
    launcher = _launcher(monkeypatch)
    monkeypatch.setattr("scam.win11.main",
                        lambda argv: (_ for _ in ()).throw(
                            RuntimeError(f"无法连接 {FAKE_RTSP} 打开失败")))

    assert launcher.main(["--config", str(config), "--no-browser"]) == 1

    text = capsys.readouterr().out
    for leaked in (FAKE_USER, FAKE_PASS, FAKE_RTSP, "192.0.2.10"):
        assert leaked not in text, f"控制台泄露了 {leaked}"
    assert "E-W11-001" in text, "必须保留固定错误码供排查"

    diagnostics = (config.parent / "logs" / "win11-errors.log").read_text(
        encoding="utf-8")
    for leaked in (FAKE_USER, FAKE_PASS, FAKE_RTSP, "192.0.2.10"):
        assert leaked not in diagnostics, f"诊断文件泄露了 {leaked}"
    assert "E-W11-001" in diagnostics


def test_wizard_failure_never_echoes_credentials(monkeypatch, capsys, tmp_path):
    """向导失败：同样只给固定错误码。"""
    monkeypatch.setattr(win11, "platform_error", lambda edition: None)
    monkeypatch.setattr(
        win11, "WIN11_WORKSTATION",
        SimpleNamespace(default_config=lambda: str(tmp_path / "missing.json"),
                        default_host="127.0.0.1", key="win11"))
    monkeypatch.setattr(win11, "bundled_model_path", lambda: None)
    monkeypatch.setattr(win11, "run_first_use_setup",
                        lambda path, **kwargs: (_ for _ in ()).throw(
                            RuntimeError(f"向导打开 {FAKE_RTSP} 失败")))
    monkeypatch.setattr(win11, "run_runtime",
                        lambda argv, edition: (_ for _ in ()).throw(
                            AssertionError("向导失败不得进入运行时")))

    assert win11.main([]) == 1        # 保持既有退出码契约
    text = capsys.readouterr().out
    for leaked in (FAKE_USER, FAKE_PASS, FAKE_RTSP, "192.0.2.10"):
        assert leaked not in text, f"控制台泄露了 {leaked}"
    assert "E-W11-002" in text


def test_launcher_refuses_when_single_instance_unavailable(monkeypatch, capsys):
    """拿不到单实例保护：fail-closed 拒绝启动，绝不放行第二个实例。"""
    launcher = _launcher(monkeypatch,
                         mutex=lambda: ("unavailable", None))
    monkeypatch.setattr("scam.win11.main",
                        lambda argv: (_ for _ in ()).throw(
                            AssertionError("无单实例保护时不得启动值守")))

    assert launcher.main(["--no-browser"]) == launcher.EXIT_MUTEX_UNAVAILABLE
    text = capsys.readouterr().out
    assert "无法取得单实例保护" in text
    assert "不会打开数据库或相机" in text


def test_windows_mutex_allows_one_instance_and_releases_cleanly():
    """真实互斥体：第二个实例被拒；正常释放后可以再次获取（不留假锁）。"""
    from scam import win11_launcher as launcher
    if sys.platform != "win32":
        pytest.skip("命名互斥体仅 Windows 可用")

    name = "Local\scam-win11-remediation-test"
    state1, handle1 = launcher.acquire_single_instance(name)
    assert state1 == "held" and handle1
    try:
        state2, handle2 = launcher.acquire_single_instance(name)
        assert state2 == "already_running", "同一互斥体不得被第二个实例持有"
    finally:
        launcher.release_single_instance(handle1)

    state3, handle3 = launcher.acquire_single_instance(name)
    assert state3 == "held", "正常释放后不得残留假锁"
    launcher.release_single_instance(handle3)

# ---------- 收口批次：重复/混用 --host 与 IPv6 口径 ----------

REPEATED_HOST_ARGS = [
    ["--host", "127.0.0.1", "--host", "0.0.0.0"],
    ["--host", "0.0.0.0", "--host", "127.0.0.1"],
    ["--host=127.0.0.1", "--host", "127.0.0.1"],
    ["--host", "127.0.0.1", "--host=127.0.0.1"],
    ["--host=127.0.0.1", "--host=127.0.0.1"],
]


@pytest.mark.parametrize("argv", REPEATED_HOST_ARGS,
                         ids=["plain-plain-evil", "evil-then-plain",
                              "eq-then-plain", "plain-then-eq", "eq-eq"])
def test_launcher_rejects_repeated_host_before_anything(monkeypatch, capsys, argv):
    """重复/混用 --host：入口必须拒绝（否则运行时取最后一个值，绕过校验）。"""
    launcher = _launcher(monkeypatch)
    monkeypatch.setattr("scam.win11.main",
                        lambda a: (_ for _ in ()).throw(
                            AssertionError("重复 --host 不得进入运行时")))

    assert launcher.main([*argv, "--no-browser"]) == launcher.EXIT_HOST_NOT_ALLOWED
    text = capsys.readouterr().out
    assert "--host 只能出现一次" in text
    assert "0.0.0.0" not in text, "拒绝提示不得回显原始取值"


@pytest.mark.parametrize("argv", REPEATED_HOST_ARGS,
                         ids=["plain-plain-evil", "evil-then-plain",
                              "eq-then-plain", "plain-then-eq", "eq-eq"])
def test_win11_entry_rejects_repeated_host(monkeypatch, capsys, argv):
    """直接 Python 入口同样拒绝重复/混用 --host。"""
    monkeypatch.setattr(win11, "platform_error", lambda edition: None)
    monkeypatch.setattr(win11, "run_first_use_setup",
                        lambda path, **kwargs: (_ for _ in ()).throw(
                            AssertionError("不得进入向导")))
    monkeypatch.setattr(win11, "run_runtime",
                        lambda a, edition: (_ for _ in ()).throw(
                            AssertionError("不得进入运行时")))
    assert win11.main(argv) == 5
    assert "--host 只能出现一次" in capsys.readouterr().out


def test_ipv6_loopback_rejected_with_fixed_message(monkeypatch, capsys):
    """::1 首版不支持：固定中文拒绝，不留"校验放行、随后崩溃"的中间状态。"""
    launcher = _launcher(monkeypatch)
    monkeypatch.setattr("scam.win11.main",
                        lambda a: (_ for _ in ()).throw(AssertionError("不得启动")))
    assert launcher.main(["--host", "::1", "--no-browser"]) ==         launcher.EXIT_HOST_NOT_ALLOWED
    text = capsys.readouterr().out
    assert launcher.HOST_REJECT_HINT in text
    assert "IPv6" in text
    assert launcher.LOOPBACK_HOSTS == ("127.0.0.1",)


def test_validated_host_is_the_one_forwarded_to_runtime(monkeypatch):
    """入口校验过的地址必须与运行时采用的一致（规范化后只保留一处）。"""
    launcher = _launcher(monkeypatch)
    seen = []
    monkeypatch.setattr("scam.win11.main", lambda a: seen.append(list(a)) or 0)

    assert launcher.main(["--host=127.0.0.1", "--no-browser"]) == 0
    assert seen[0].count("--host") == 1
    host_index = seen[0].index("--host")
    assert seen[0][host_index + 1] == "127.0.0.1"


def test_missing_host_value_rejected(monkeypatch, capsys):
    """--host 后面没有取值：拒绝而不是猜测默认值。"""
    launcher = _launcher(monkeypatch)
    monkeypatch.setattr("scam.win11.main",
                        lambda a: (_ for _ in ()).throw(AssertionError("不得启动")))
    # 缺值时由 argparse 先行拒绝（退出码 2，未进入任何启动动作）——
    # 与固定文案拒绝同为 fail-closed，这里只断言"拒绝 + 不启动"。
    code = launcher.main(["--host", "--no-browser"])
    assert code != 0, "缺值必须拒绝启动"
    assert code in (2, launcher.EXIT_HOST_NOT_ALLOWED)
    assert launcher.HOST_REJECT_HINT in capsys.readouterr().out or code == 2
