"""LZ-059 发布打包测试：白名单/敏感双闸/可复现哈希/既有包扫描。"""

import os
import tarfile

import pytest

import scripts.package_release as pr


def test_version_reads_from_pyproject():
    assert pr.version().count(".") >= 1


def test_collect_excludes_sensitive_faces():
    files = pr._collect()
    lows = [f.lower() for f in files]
    assert any(f.startswith("scam/") for f in files)
    assert "pyproject.toml" in files
    for forbidden in ("cameras.json", "win11-context", "zcode-context",
                      "linux-context", "agents.md", ".onnx", "storage/",
                      "设计稿"):
        assert not any(forbidden in low for low in lows), forbidden


def test_collect_blocks_when_sensitive_file_enters_whitelist(tmp_path,
                                                             monkeypatch):
    # 伪造：scam/ 下出现 cameras.json → 双闸必须拒绝
    evil = tmp_path / "scam" / "cameras.json"
    evil.parent.mkdir(parents=True)
    evil.write_text("{}")
    monkeypatch.setattr(pr, "REPO", str(tmp_path))
    (tmp_path / "pyproject.toml").write_text('[project]\nversion="9.9.9"\n')
    with pytest.raises(ValueError, match="敏感文件"):
        pr._collect()


def test_build_is_reproducible(tmp_path, monkeypatch):
    monkeypatch.setattr(pr, "REPO", str(tmp_path))
    (tmp_path / "pyproject.toml").write_text('[project]\nversion="1.2.3"\n')
    pkg = tmp_path / "scam" / "__init__.py"
    pkg.parent.mkdir()
    pkg.write_text("# core\n")

    out1, sha1, n1 = pr.build(str(tmp_path / "a.tar.gz"))
    out2, sha2, n2 = pr.build(str(tmp_path / "b.tar.gz"))

    assert n1 == n2 >= 1
    assert sha1 == sha2, "归一化元数据后同一工作树必须同哈希"
    with tarfile.open(out1) as tar:
        names = tar.getnames()
    assert "scam/scam/__init__.py" in names


def test_check_detects_sensitive_member(tmp_path):
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as tar:
        info = tarfile.TarInfo("scam/cameras.json")
        data = b'{"cameras":[{"source":"rtsp://u:p@x"}]}'
        info.size = len(data)
        tar.addfile(info, io_bytes(data))
    hits = pr.check(str(bad))
    assert hits == ["scam/cameras.json"]


def io_bytes(data):
    import io
    return io.BytesIO(data)


def test_check_clean_package(tmp_path):
    good = tmp_path / "good.tar.gz"
    with tarfile.open(good, "w:gz") as tar:
        info = tarfile.TarInfo("scam/scam/__init__.py")
        data = b"# core"
        info.size = len(data)
        tar.addfile(info, io_bytes(data))
    assert pr.check(str(good)) == []


def test_cli_dry_run_lists_without_writing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pr, "REPO", str(tmp_path))
    (tmp_path / "pyproject.toml").write_text('[project]\nversion="0.1"\n')
    pkg = tmp_path / "scam" / "__init__.py"
    pkg.parent.mkdir()
    pkg.write_text("")
    rc = pr.main(["--dry-run"])
    out = capsys.readouterr().out
    assert rc == 0 and "pyproject.toml" in out
    assert not (tmp_path / "dist").exists()
