import os

from scam.editions import (LINUX_NVR, WIN11_WORKSTATION, get_edition,
                           platform_error)


def test_editions_have_independent_identity_and_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert get_edition("linux-nvr") is LINUX_NVR
    assert get_edition("win11") is WIN11_WORKSTATION
    assert LINUX_NVR.key != WIN11_WORKSTATION.key
    assert LINUX_NVR.default_db() == os.path.join(".", "storage", "scam.db")
    assert WIN11_WORKSTATION.default_db() == os.path.join(
        str(tmp_path), "semantic-camera", "storage", "scam.db")
    assert WIN11_WORKSTATION.default_config() == os.path.join(
        str(tmp_path), "semantic-camera", "cameras.json")
    assert LINUX_NVR.default_config() == "cameras.json"


def test_edition_platform_guards():
    assert platform_error(LINUX_NVR, "linux") is None
    assert platform_error(WIN11_WORKSTATION, "win32") is None
    assert "Linux" in platform_error(LINUX_NVR, "win32")
    assert "Windows 11" in platform_error(WIN11_WORKSTATION, "linux")
