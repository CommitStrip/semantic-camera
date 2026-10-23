import importlib.util
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/package_release.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "test_windows_source_package", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_default_linux_profile_is_unchanged(tmp_path):
    module = load_module()
    module.REPO = str(tmp_path)
    (tmp_path / "scam").mkdir()
    (tmp_path / "scam/keep.py").write_text("keep = True\n", encoding="utf-8")
    files = module._collect()
    assert "scam/keep.py" in files
    assert "packaging/runtime_hook_deps.py" not in files
    assert "desktop/win11/MainWindow.cs" not in files


def test_windows_profile_requires_complete_source(tmp_path):
    module = load_module()
    module.REPO = str(tmp_path)
    (tmp_path / "scam").mkdir()
    (tmp_path / "scam/keep.py").write_text("keep = True\n", encoding="utf-8")
    try:
        module._collect("windows-source")
    except ValueError as exc:
        assert "windows_source_missing_required" in str(exc)
    else:
        raise AssertionError("missing Windows source must fail closed")


def test_windows_profile_accepts_complete_fixture(tmp_path):
    module = load_module()
    module.REPO = str(tmp_path)
    for rel in module.WINDOWS_REQUIRED_PATHS:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")
    for generated in ("desktop/bin", "desktop/obj", "desktop/publish"):
        path = tmp_path / generated / "generated.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"generated")
    files = module._collect("windows-source")
    assert set(module.WINDOWS_REQUIRED_PATHS).issubset(files)
    assert not any(path.startswith("desktop/bin/") for path in files)
    assert not any(path.startswith("desktop/obj/") for path in files)
    assert not any(path.startswith("desktop/publish/") for path in files)
    assert not any("__pycache__" in path for path in files)


def test_windows_profile_sensitive_gate_remains_fail_closed(tmp_path):
    module = load_module()
    module.REPO = str(tmp_path)
    for rel in module.WINDOWS_REQUIRED_PATHS:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")
    (tmp_path / "desktop/Cameras.json").write_text("sentinel", encoding="utf-8")
    try:
        module._collect("windows-source")
    except ValueError as exc:
        assert "敏感文件命中" in str(exc)
    else:
        raise AssertionError("sensitive file must be rejected")


def test_windows_profile_rejects_generated_binary_artifacts(tmp_path):
    module = load_module()
    module.REPO = str(tmp_path)
    for rel in module.WINDOWS_REQUIRED_PATHS:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")
    (tmp_path / "desktop/win11/fixture.exe").write_bytes(b"binary")
    try:
        module._collect("windows-source")
    except ValueError as exc:
        assert "windows_source_forbidden_artifact" in str(exc)
    else:
        raise AssertionError("generated binary must be rejected")


def test_windows_profile_rejects_mocked_reparse_file(tmp_path, monkeypatch):
    module = load_module()
    module.REPO = str(tmp_path)
    for rel in module.WINDOWS_REQUIRED_PATHS:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")
    target = tmp_path / "desktop/win11/MainWindow.cs"
    original_lstat = os.lstat

    def fake_lstat(path):
        info = original_lstat(path)
        if Path(path).name == "MainWindow.cs":
            attrs = getattr(info, "st_file_attributes", 0)
            reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            info = SimpleNamespace(
                st_mode=info.st_mode,
                st_file_attributes=attrs | reparse)
        return info

    monkeypatch.setattr(module.os, "lstat", fake_lstat)
    try:
        module._collect("windows-source")
    except ValueError as exc:
        assert "windows_source_reparse_point" in str(exc)
    else:
        raise AssertionError("mocked reparse file must be rejected")


def test_linux_profile_does_not_add_reparse_gate(tmp_path, monkeypatch):
    module = load_module()
    module.REPO = str(tmp_path)
    (tmp_path / "scam").mkdir()
    (tmp_path / "scam/keep.py").write_text("keep = True\n", encoding="utf-8")
    original_lstat = os.lstat

    def fake_lstat(path):
        info = original_lstat(path)
        attrs = getattr(info, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return SimpleNamespace(
            st_mode=info.st_mode,
            st_file_attributes=attrs | reparse)

    monkeypatch.setattr(module.os, "lstat", fake_lstat)
    assert "scam/keep.py" in module._collect()


def test_real_symlink_is_skipped_when_unavailable(tmp_path):
    module = load_module()
    module.REPO = str(tmp_path)
    for rel in module.WINDOWS_REQUIRED_PATHS:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")
    (tmp_path / "scam").mkdir()
    source = tmp_path / "scam/keep.py"
    source.write_text("keep = True\n", encoding="utf-8")
    link = tmp_path / "scam/reparse-link.txt"
    try:
        link.symlink_to(source, target_is_directory=False)
    except OSError:
        pytest.skip("symlink permission unavailable on this host")
    try:
        module._collect("windows-source")
    except ValueError as exc:
        assert "windows_source_reparse_point" in str(exc)
        assert "scam/reparse-link.txt" in str(exc)
    else:
        raise AssertionError("Windows source profile must reject real symlink")
