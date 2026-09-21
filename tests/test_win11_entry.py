from types import SimpleNamespace

from scam import win11


def test_win11_entry_uses_per_user_config_and_runs_setup_once(
        monkeypatch, tmp_path):
    config = tmp_path / "用户数据" / "cameras.json"
    monkeypatch.setattr(win11, "platform_error", lambda edition: None)
    monkeypatch.setattr(
        win11, "WIN11_WORKSTATION",
        SimpleNamespace(default_config=lambda: str(config), key="win11"))
    setup_calls = []
    runtime_calls = []

    def setup(path):
        setup_calls.append(path)
        path_obj = config
        path_obj.parent.mkdir(parents=True)
        path_obj.write_text("{}", encoding="utf-8")
        return True

    monkeypatch.setattr(win11, "run_first_use_setup", setup)
    monkeypatch.setattr(
        win11, "run_runtime",
        lambda argv, edition: runtime_calls.append((argv, edition)) or 0)

    assert win11.main(["--port", "9999"]) == 0
    assert setup_calls == [str(config)]
    assert runtime_calls[0][0][:2] == ["--config", str(config)]
    assert runtime_calls[0][1] == "win11"

    setup_calls.clear()
    assert win11.main([]) == 0
    assert setup_calls == [], "已有配置不得重复打开向导"


def test_win11_help_never_opens_setup(monkeypatch):
    monkeypatch.setattr(win11, "platform_error", lambda edition: None)
    monkeypatch.setattr(
        win11, "run_first_use_setup",
        lambda path: (_ for _ in ()).throw(AssertionError("must not run")))
    monkeypatch.setattr(win11, "run_runtime",
                        lambda argv, edition: 0 if argv == ["--help"] else 1)
    assert win11.main(["--help"]) == 0


def test_win11_cancelled_setup_does_not_start_runtime(monkeypatch, tmp_path):
    monkeypatch.setattr(win11, "platform_error", lambda edition: None)
    monkeypatch.setattr(
        win11, "WIN11_WORKSTATION",
        SimpleNamespace(default_config=lambda: str(tmp_path / "missing.json"),
                        key="win11"))
    monkeypatch.setattr(win11, "run_first_use_setup", lambda path: False)
    monkeypatch.setattr(
        win11, "run_runtime",
        lambda argv, edition: (_ for _ in ()).throw(
            AssertionError("runtime must not start")))
    assert win11.main([]) == 1
