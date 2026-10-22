"""后端构建器公开合同：hook 随源码、敏感件默认拒发。

自包含（不依赖内部证据目录）：只 import 构建器的函数级 API，用 tmp_path
构造候选树。真实 PyInstaller 构建不在本测试范围。
"""
import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "packaging" / "build_win11_full_backend.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location("build_full_backend", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def builder():
    return _load_builder()


def test_hook_ships_with_source(builder):
    """运行 hook 必须在公开 packaging/ 目录内，构建链不依赖内部目录。"""
    assert builder.HOOK == ROOT / "packaging" / "runtime_hook_deps.py"
    assert builder.HOOK.is_file()
    assert "work" not in builder.HOOK.parts


def test_build_root_is_generic(builder):
    """构建产物根不得指向内部证据目录。"""
    assert "work" not in builder.WORK.parts
    assert builder.WORK.name == "win11-full-backend"


@pytest.mark.parametrize("rel", [
    "_deps/Cookies.log",
    "_deps/User Data/debug.log",
    "_deps/EBWebView/x.log",
    "app.log",
    "_deps/sub/TRACE.LOG",
    "_deps/.db-shm",
    "_deps/clip.mp4",
])
def test_sensitive_files_are_rejected(builder, tmp_path, rel):
    """隐私/日志/媒体件一律拒发（无后缀或目录豁免）。"""
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"x")
    hits = builder.scan_sensitive(tmp_path)
    assert hits, f"{rel} 必须被拒发"


def test_clean_tree_passes(builder, tmp_path):
    """无敏感件的树不产生误报。"""
    (tmp_path / "_deps" / "pkg").mkdir(parents=True)
    (tmp_path / "_deps" / "pkg" / "module.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "semantic-camera-backend.exe").write_bytes(b"MZ")
    assert builder.scan_sensitive(tmp_path) == []
