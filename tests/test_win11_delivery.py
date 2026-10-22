"""Win11 发行包交付测试：内容闸门、zip 成员校验、清单元数据、入口约定。

只测构建与交付契约（不触发真实 PyInstaller 构建；构建由
`python packaging/build_win11.py` 在原生 Windows 上执行并留清单）。
"""

import importlib.util
import json
import pathlib
import sys
import zipfile

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
PACKAGING = REPO / "packaging"


def _load_builder():
    """按文件路径加载构建脚本（packaging/ 不是包，不能 import）。"""
    spec = importlib.util.spec_from_file_location(
        "scam_win11_builder", PACKAGING / "build_win11.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def builder():
    return _load_builder()


# ---------- 内容闸门：私有/测试/用户数据绝不许入包 ----------

FORBIDDEN_SAMPLES = [
    ("ZCODE-LINUX-CONTEXT.md", "私有记录本"),
    ("docs/context/WORKLOG.md", "私有上下文目录"),
    ("AGENTS.md", "协作约定"),
    ("WIN11-CONTEXT.md", "产品记录本"),
    ("审查-2026-09-18.md", "内部审查"),
    ("设计稿-总集.md", "内部设计稿"),
    ("方案-新入口.md", "内部方案"),
    ("tests/test_db.py", "测试文件"),
    ("cameras.json", "用户配置（含 RTSP 凭据）"),
    ("storage/scam.db", "运行时数据库"),
    ("logs/run.log", "运行日志"),
    ("clips/sample.mp4", "测试视频"),
    ("models/person-detector.onnx", "模型权重（未声明来源时）"),
    (".codex/session.json", "工具本地目录"),
]


@pytest.mark.parametrize("relative,label", FORBIDDEN_SAMPLES,
                         ids=[label for _path, label in FORBIDDEN_SAMPLES])
def test_gate_rejects_forbidden_content(builder, tmp_path, relative, label):
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"x")
    hits = builder.scan_tree(tmp_path)
    assert any(relative.lower() in hit for hit in hits), \
        f"闸门必须拒绝{label}（{relative}）"


def test_gate_allows_clean_package_and_declared_model(builder, tmp_path):
    (tmp_path / "_internal").mkdir()
    (tmp_path / "语义摄像头.exe").write_bytes(b"MZ")
    (tmp_path / "使用说明.md").write_text("x", encoding="utf-8")
    (tmp_path / "THIRD-PARTY-NOTICES.txt").write_text("x", encoding="utf-8")
    assert builder.scan_tree(tmp_path) == []

    model = tmp_path / "models" / "person-detector.onnx"
    model.parent.mkdir()
    model.write_bytes(b"onnx")
    assert builder.scan_tree(tmp_path) != [], "未声明来源的模型不得入包"
    assert builder.scan_tree(tmp_path, allow_model=True) == [], \
        "有来源档案时模型允许随包"


# ---------- zip 成员名校验（外部输入，逐段白名单） ----------

@pytest.mark.parametrize("name", [
    "语义摄像头/使用说明.md",
    "语义摄像头/_internal/python3.dll",
    "语义摄像头/models/person-detector.onnx",
])
def test_safe_member_names_accepted(builder, name):
    assert builder.is_safe_member_name(name) is True


@pytest.mark.parametrize("name", [
    "", "/etc/passwd", "C:/Windows/system32/x.dll", "a\\b.txt",
    "语义摄像头/../../secrets.txt", "../evil.txt", "a/./b.txt",
    "语义摄像头//x.txt",
])
def test_unsafe_member_names_rejected(builder, name):
    assert builder.is_safe_member_name(name) is False


def test_extract_rejects_escaping_zip(builder, tmp_path):
    """外部 zip 带父目录段：必须拒绝，且不在目标目录外留下任何文件。"""
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("语义摄像头/x.txt", "ok")
        bundle.writestr("语义摄像头/../../../escaped.txt", "no")
    with pytest.raises(ValueError):
        builder.extract_zip_safely(archive, tmp_path / "out")
    assert not (tmp_path.parent / "escaped.txt").exists()


def test_extract_rejects_multi_top_level_zip(builder, tmp_path):
    archive = tmp_path / "two-tops.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("a/x.txt", "1")
        bundle.writestr("b/y.txt", "2")
    with pytest.raises(ValueError):
        builder.extract_zip_safely(archive, tmp_path / "out")


# ---------- 交付契约：入口命名、清单字段、文档随包 ----------

def test_entry_module_is_top_level_and_package_relative_imports_are_avoided():
    """exe 入口必须在包外：包内模块用相对导入，不能直接当顶层脚本。"""
    import ast

    source = (PACKAGING / "win11_exe_entry.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0, "入口脚本不得使用包内相对导入"
            imported.append(node.module)
        elif isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
    assert "scam.win11_launcher" in imported


def test_build_script_pins_versions_and_declares_app_name(builder):
    assert builder.APP_NAME == "语义摄像头"
    assert builder.PYINSTALLER_VERSION, "必须固定 PyInstaller 版本"
    assert builder.ENTRY.name == "win11_exe_entry.py"
    assert builder.ENTRY.is_file()


def test_packaged_docs_exist_and_have_no_credentials():
    """随包文档必须存在，且不得包含凭据样式的字面量。"""
    doc = (PACKAGING / "win11-上手说明.md").read_text(encoding="utf-8")
    notices = (PACKAGING / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
    assert "解压" in doc and "双击" in doc and "%LOCALAPPDATA%" in doc
    assert "本发行包内嵌以下第三方运行库" in notices
    for text in (doc, notices):
        assert "rtsp://admin:" not in text, "文档不得写入可用凭据字面量"
        assert "password" not in text.lower()


def test_model_is_not_bundled_without_provenance(builder):
    """默认不随包模型；缺少来源档案时 --with-model 必须拒绝。"""
    assert builder.load_model_provenance() is None
    assert builder.main(["--with-model"]) == 1
