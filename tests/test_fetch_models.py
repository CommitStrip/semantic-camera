"""LZ-055 模型交付脚本测试：白名单边界/哈希校验/原子入位/围栏（不真下载）。"""

import os
from pathlib import Path

import pytest

import scripts.fetch_models as fm


# ---------- URL 白名单边界 ----------

def test_url_must_be_in_frozen_registry(monkeypatch):
    with pytest.raises(ValueError, match="白名单"):
        fm._assert_safe_url("https://github.com/evil/other.onnx")


def test_http_rejected_even_if_whitelisted_host(monkeypatch):
    url = "http://github.com/RangiLyu/nanodet/releases/download/x/y.onnx"
    monkeypatch.setitem(fm.MODELS, "probe",
                        {"url": url, "sha256": None, "path": "models/p.onnx"})
    with pytest.raises(ValueError, match="HTTPS"):
        fm._assert_safe_url(url)


def test_non_public_ip_rejected(monkeypatch):
    url = "https://github.com/x/y.onnx"
    monkeypatch.setitem(fm.MODELS, "probe",
                        {"url": url, "sha256": None, "path": "models/p.onnx"})

    def fake_resolve(host, port):
        return [(2, 0, 0, "", ("192.168.1.5", port))]
    monkeypatch.setattr(fm.socket, "getaddrinfo", fake_resolve)
    with pytest.raises(ValueError, match="非公网"):
        fm._assert_safe_url(url)


def test_redirect_refused():
    handler = fm._NoRedirect()
    with pytest.raises(Exception, match="拒绝重定向"):
        handler.redirect_request(None, None, 302, "Found", {},
                                 "https://evil.example/x")


# ---------- fetch：未冻结拒绝下载 / 哈希不符不落位 / 成功原子入位 ----------

def test_fetch_refuses_unfrozen_sha(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(fm, "_download_to",
                        lambda *a, **k: called.append(1) or str(tmp_path))
    state, _ = fm.fetch("nanodet")
    assert state == "unfrozen" and not called


def test_fetch_mismatch_discards(tmp_path, monkeypatch):
    monkeypatch.setitem(fm.MODELS, "probe",
                        {"url": "https://github.com/a/b.onnx",
                         "sha256": "0" * 64, "path": "models/probe.onnx"})
    bad = tmp_path / "models" / "probe.onnx.download"
    bad.parent.mkdir(parents=True)
    bad.write_bytes(b"wrong-content")
    monkeypatch.setattr(fm, "_download_to", lambda *a, **k: str(bad))
    monkeypatch.setattr(fm, "_repo_root", lambda: str(tmp_path))

    state, detail = fm.fetch("probe")

    assert state == "mismatch"
    assert not bad.exists(), "哈希不符的下载物必须被删除"
    assert not (tmp_path / "models" / "probe.onnx").exists()


def test_fetch_success_atomic(tmp_path, monkeypatch):
    import hashlib
    content = b"model-bytes"
    digest = hashlib.sha256(content).hexdigest()
    monkeypatch.setitem(fm.MODELS, "probe",
                        {"url": "https://github.com/a/b.onnx",
                         "sha256": digest, "path": "models/probe.onnx"})
    good = tmp_path / "models" / "probe.onnx.download"
    good.parent.mkdir(parents=True)
    good.write_bytes(content)
    monkeypatch.setattr(fm, "_download_to", lambda *a, **k: str(good))
    monkeypatch.setattr(fm, "_repo_root", lambda: str(tmp_path))

    state, detail = fm.fetch("probe")

    assert state == "ok"
    assert (tmp_path / "models" / "probe.onnx").read_bytes() == content
    assert not good.exists(), "临时文件必须被原子改名消费"


def test_download_dir_outside_repo_rejected(tmp_path):
    with pytest.raises(ValueError, match="越出仓库根"):
        fm._download_to("https://github.com/a/b.onnx", str(tmp_path / "elsewhere"))


# ---------- verify_local 围栏 ----------

def test_verify_local_dotdot_rejected():
    state, _ = fm.verify_local("models/../../x.onnx")
    assert state == "invalid_path"


def test_verify_local_outside_repo_rejected(tmp_path):
    state, _ = fm.verify_local(str(tmp_path / "x.onnx"))
    assert state == "invalid_path"


def test_verify_local_roundtrip(tmp_path, monkeypatch):
    import hashlib
    content = b"local-export"
    digest = hashlib.sha256(content).hexdigest()
    target = Path(fm._repo_root()) / "models" / "verify-probe.onnx"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    try:
        state, _ = fm.verify_local(str(target), expect_sha256=digest)
        assert state == "ok"
        state, _ = fm.verify_local(str(target), expect_sha256="0" * 64)
        assert state == "mismatch"
        state, _ = fm.verify_local(str(target))
        assert state == "unfrozen"
    finally:
        target.unlink(missing_ok=True)


# ---------- 状态机与 CLI ----------

def test_status_states(tmp_path, monkeypatch):
    monkeypatch.setattr(fm, "_repo_root", lambda: str(tmp_path))
    rows = {r["model"]: r for r in fm.status()}
    assert rows["nanodet"]["state"] == "missing"

    target = tmp_path / "models" / "person-detector.onnx"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"x")
    rows = {r["model"]: r for r in fm.status()}
    assert rows["nanodet"]["state"] == "unfrozen", \
        "未冻结哈希时在位文件也只能是 unfrozen，不得冒充 ok"


def test_cli_list_exit_zero(monkeypatch):
    monkeypatch.setattr("sys.argv", ["fetch_models.py", "--list"])
    assert fm.main(["--list"]) == 0
