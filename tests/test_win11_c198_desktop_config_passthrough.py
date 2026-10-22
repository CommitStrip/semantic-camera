from pathlib import Path

from scam import win11_desktop


class _Bridge:
    def watch_stdin(self, *_args, **_kwargs):
        return None

    def emit_navigate(self, *_args, **_kwargs):
        return None

    def _emit(self, *_args, **_kwargs):
        return None

    def hook(self, *_args, **_kwargs):
        return None


def test_default_config_is_forwarded_to_runtime_after_setup(tmp_path, monkeypatch):
    config = tmp_path / "cameras.json"
    seen = {}

    def setup_runner(path, **_kwargs):
        Path(path).write_text("{}", encoding="utf-8")
        return True

    def runtime_main(argv, **_kwargs):
        seen["argv"] = list(argv)
        return 0

    monkeypatch.setattr(
        win11_desktop,
        "DesktopBackendBridge",
        lambda *_args, **_kwargs: _Bridge(),
    )

    class Edition:
        @staticmethod
        def default_config():
            return str(config)

    import scam.editions as editions
    monkeypatch.setattr(editions, "WIN11_WORKSTATION", Edition())

    code = win11_desktop.desktop_main(
        [],
        edition="win11",
        runtime_main=runtime_main,
        setup_runner=setup_runner,
        stdin=None,
    )

    assert code == 0
    assert seen["argv"] == [
        "--config", str(config), "--host", "127.0.0.1", "--port", "8600",
    ]
    assert seen["argv"].count("--config") == 1


def test_explicit_config_is_not_duplicated(tmp_path, monkeypatch):
    config = tmp_path / "explicit.json"
    config.write_text("{}", encoding="utf-8")
    seen = {}

    def runtime_main(argv, **_kwargs):
        seen["argv"] = list(argv)
        return 0

    monkeypatch.setattr(
        win11_desktop,
        "DesktopBackendBridge",
        lambda *_args, **_kwargs: _Bridge(),
    )
    code = win11_desktop.desktop_main(
        ["--config", str(config)],
        edition="win11",
        runtime_main=runtime_main,
        setup_runner=lambda *_args, **_kwargs: True,
        stdin=None,
    )

    assert code == 0
    assert seen["argv"] == [
        "--config", str(config), "--host", "127.0.0.1", "--port", "8600",
    ]
    assert seen["argv"].count("--config") == 1
