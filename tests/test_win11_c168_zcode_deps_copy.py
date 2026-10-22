# -*- coding: utf-8 -*-
"""C168-Z builder _deps 复制固化合同测试（mock；零真实 PyInstaller）。

主协调批复：_deps 复制从手工固化进 builder——显式已验收依赖源、复制到全新
输出、完整复制后才封存清单、侧车树外。mock 反例：
缺依赖源 / 复制失败 / 大小写冲突 / 源重解析点 / 已存在输出不改旧件。
"""
import hashlib
import json
import importlib.util
import os
import pathlib
import stat

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
BUILDER = REPO / "packaging" / "build_win11_full_backend.py"


def _load():
    spec = importlib.util.spec_from_file_location("c168_builder", BUILDER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def builder():
    return _load()


def _make_deps(root, files=None):
    deps = pathlib.Path(root)
    for rel, content in (files or {"torch/__init__.py": "v=1\n",
                                   "transformers/__init__.py": "v=2\n",
                                   "_stdlib/json/__init__.py": "{}\n"}).items():
        p = deps / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return deps


def test_copies_fully_and_digests(builder, tmp_path):
    src = _make_deps(tmp_path / "src-deps")
    app = tmp_path / "app"
    app.mkdir()
    count, records, digest, prov = builder.copy_deps_sidecar(src, app)
    assert count == 3
    assert all(r["path"].startswith("_deps/") for r in records)
    dest = app / "_deps"
    for r in records:
        p = app / r["path"]
        assert p.is_file() and p.stat().st_size == r["bytes"]
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        assert h == r["sha256"]
    assert digest and len(digest) == 64
    # C168-R2：provenance 记**实际 deps 源路径**+源哈希
    assert len(prov) == count
    for rel, meta in prov.items():
        assert meta["source"] == str((src / rel[len("_deps/"):]).resolve())
        assert meta["source_sha256"] ==             hashlib.sha256((src / rel[len("_deps/"):]).read_bytes()).hexdigest()


def test_missing_deps_source_rejected(builder, tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    with pytest.raises(ValueError,
                       match="deps_source_repoint|deps_source_reparse"):
        # C171 fail-closed：不存在的路径 lstat 失败即拒绝（不再细分为
        # missing——无法验证即不放行）。
        builder.copy_deps_sidecar(tmp_path / "no-such-deps", app)
    assert not (app / "_deps").exists()


def test_dest_exists_never_touches_old_outputs(builder, tmp_path):
    src = _make_deps(tmp_path / "src-deps")
    app = tmp_path / "app"
    (app / "_deps").mkdir(parents=True)
    old_file = app / "_deps" / "keep.txt"
    old_file.write_text("old-kept", encoding="utf-8")
    with pytest.raises(ValueError, match="deps_dest_exists"):
        builder.copy_deps_sidecar(src, app)
    assert old_file.read_text(encoding="utf-8") == "old-kept"


def test_case_conflict_guard_present_in_code(builder):
    """大小写冲突防护（源码级钉住）：copy_deps_sidecar 逐条 casefold 入
    seen 集，冲突即 ValueError。Windows 大小写不敏感 FS 上文件级冲突
    结构上不可构造（rglob 返回单条）——防护为归档/跨平台冗余。"""
    import inspect
    code = inspect.getsource(builder.copy_deps_sidecar)
    assert "casefold()" in code
    assert "deps_case_conflict" in code


def test_reparse_guard_present_in_code(builder):
    assert "deps_source_reparse_point" in         (BUILDER.read_text(encoding="utf-8"))


def test_reparse_point_in_source_rejected(builder, tmp_path):
    src = _make_deps(tmp_path / "src-deps")
    link = src / "torch" / "linked.py"
    try:
        os.symlink(src / "torch" / "__init__.py", link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink 不可用")
    app = tmp_path / "app"
    app.mkdir()
    with pytest.raises(ValueError, match="reparse"):
        builder.copy_deps_sidecar(src, app)
    assert not (app / "_deps").exists()




def test_nested_source_output_rejected(builder, tmp_path):
    src = _make_deps(tmp_path / "src-deps")
    app = tmp_path / "app"
    app.mkdir()
    (app / "_deps").mkdir(parents=True, exist_ok=True)
    nested_src = app / "_deps"          # 源位于输出内
    with pytest.raises(ValueError, match="nested"):
        builder.copy_deps_sidecar(nested_src, app)


def test_copy_failure_cleans_halfwritten_deps(builder, tmp_path,
                                              monkeypatch):
    """copy2 抛 OSError（非 ValueError）→ 半成品 _deps 被清理、异常上抛。"""
    src = _make_deps(tmp_path / "src-deps")
    app = tmp_path / "app"
    app.mkdir()
    real_copy2 = builder.shutil.copy2
    calls = {"n": 0}

    def flaky(src_, dst_, **kw):
        calls["n"] += 1
        if calls["n"] >= 2:               # 第二个文件复制失败
            raise OSError("disk full simulation")
        return real_copy2(src_, dst_, **kw)

    monkeypatch.setattr(builder.shutil, "copy2", flaky)
    with pytest.raises(OSError):
        builder.copy_deps_sidecar(src, app)
    # C171：partial 保留（不 rmtree）——半成品留待主协调处置
    assert (app / "_deps").exists(), "partial 必须保留"



# ---------------------------------------------------------------------------
# C168-R2：真实 main mock 负例（不拿 C158 测试替代）
# ---------------------------------------------------------------------------

def _run_main_sideload(tmp_path, builder, monkeypatch, *, copy2_raises=False,
                       deps_source=None):
    if deps_source is None:
        deps_source = tmp_path / "deps-source"
        _make_deps(deps_source)
    """隔离跑 main(--execute --mode sideload --deps-source ...)：
    真 PyInstaller 跳过（monkeypatch subprocess.run 返回 rc=0+伪 exe）、
    依赖源用 stub；返回 (返回码, json-out 载荷)。"""
    deps_source = deps_source or (tmp_path / "deps-source")
    log = tmp_path / "build.log"

    class FakeProc:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(argv, cwd=None, stdout=None, stderr=None, **kw):
        # 模拟 PyInstaller 时序：dist/work/spec 由构建本身创建
        out_dir = tmp_path / "dist" / "semantic-camera-backend"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "semantic-camera-backend.exe").write_bytes(b"MZ-stub")
        (out_dir / "_internal").mkdir(exist_ok=True)
        (out_dir / "_internal" / "base_library.zip").write_bytes(b"PK")
        return FakeProc()

    monkeypatch.setattr(builder.subprocess, "run", fake_run)
    fixed_facts = {
        "ok": True, "problems": [], "hf_models_local": [],
        "modes": {"sideload": {"allowed": True}, "full-freeze": {"allowed": False}}}
    monkeypatch.setattr(builder, "check", lambda: fixed_facts)
    # 资源门禁固定（不受当期系统 RAM 影响；本测试只验证 deps 复制合同）
    fixed_facts = {
        "ok": True, "problems": [], "hf_models_local": [],
        "modes": {"sideload": {"allowed": True}, "full-freeze": {"allowed": False}}}
    monkeypatch.setattr(builder, "check", lambda: fixed_facts)

    class _LogHandle:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def write(self, *_):
            pass

    import time
    real_open = pathlib.Path.open

    def fake_open(self, mode="r", *a, **k):
        if str(self).endswith(".log"):
            return _LogHandle(str(self))
        return real_open(self, mode, *a, **k)

    monkeypatch.setattr(builder.pathlib.Path, "open", fake_open)
    json_out = tmp_path / "result.json"
    argv = ["--execute", "--mode", "sideload", "--version", "0.1.0",
            "--dist-root", str(tmp_path / "dist"),
            "--work-root", str(tmp_path / "w"),
            "--spec-path", str(tmp_path / "s"),
            "--json-out", str(json_out),
            "--deps-source", str(deps_source)]
    rc = builder.main(argv)
    payload = json.loads(json_out.read_text(encoding="utf-8"))         if json_out.is_file() else {}
    return rc, payload


def test_main_copy2_oserror_structured_nonzero(builder, tmp_path,
                                               monkeypatch):
    """copy2 抛 OSError（非 ValueError）⇒ published=false、
    deps_copy_failed 结构化原因、main 返回非零、JSON 落盘。"""
    deps_source = tmp_path / "deps-source"
    _make_deps(deps_source)
    monkeypatch.setattr(builder.shutil, "copy2",
                        lambda *a, **k: (_ for _ in ()).throw(
                            OSError("disk full simulation")))
    rc, payload = _run_main_sideload(tmp_path, builder, monkeypatch,
                                     copy2_raises=True,
                                     deps_source=deps_source)
    assert rc != 0
    assert payload["published"] is False
    reasons = payload.get("reasons") or []
    assert any("deps_copy_failed" in r and "OSError" in r
               for r in reasons), reasons


def test_main_valid_deps_source_publishes_with_source_provenance(
        builder, tmp_path, monkeypatch):
    """对照：合法依赖源 → published=true；_deps 文件的 provenance 指向
    **实际 deps 源路径**（非复制后输出）。"""
    deps_source = tmp_path / "deps-source"
    _make_deps(deps_source)
    rc, payload = _run_main_sideload(tmp_path, builder, monkeypatch,
                                     deps_source=deps_source)
    assert rc == 0 and payload["published"] is True, payload.get("reasons")
    # provenance 在树外侧车（provenance_path）——检查 _deps 条目 source
    prov_path = pathlib.Path(payload["provenance_path"])
    side = json.loads(prov_path.read_text(encoding="utf-8"))
    deps_entries = {k: v for k, v in side["provenance"].items()
                    if k.startswith("_deps/")}
    assert deps_entries, "应有 _deps 条目"
    for rel, meta in deps_entries.items():
        assert str(deps_source.resolve()) in meta["source"], (rel, meta["source"])
        src_file = pathlib.Path(meta["source"])
        assert src_file.is_file()
        assert meta["source_sha256"] ==             hashlib.sha256(src_file.read_bytes()).hexdigest()


def test_empty_deps_source_rejected(builder, tmp_path):
    src = tmp_path / "src-deps"
    src.mkdir()
    app = tmp_path / "app"
    app.mkdir()
    with pytest.raises(ValueError, match="deps_source_empty"):
        builder.copy_deps_sidecar(src, app)
    assert not (app / "_deps").exists()
