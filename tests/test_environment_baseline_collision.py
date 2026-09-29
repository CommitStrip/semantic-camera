"""A-R2 缺陷同构回归：同秒同画面复核的覆盖与误删阻塞。

场景与真实缺陷完全同构（**不换画面、不绕开碰撞**）：先建立 v1；同一秒、
同一帧触发复核并注入写库失败；断言 v1 文件字节与完整 SHA-256 不变、v1 可由
历史端点回看、当前指针仍为 v1、文件清单无孤立新文件。随后成功复核 v2：
两版各有独立画面引用，历史回看均正确。
另覆盖：同秒同帧两次尝试独立文件身份、目标预存在明确失败不覆盖、
清理所有权（令牌）与库内零引用双证、非 nonce 令牌拒删。
"""

import hashlib
import json
import os
import types

import numpy as np
import pytest

import scam.db as db
from scam.db import connect
from scam.evidence import EvidenceStore
from scam.server import WorkbenchState

from test_environment_baseline import (_H, _LocalProvider, _LiveMonitor,
                                       _get, _get_bytes, _post)

FROZEN_T = 1790500000.0
JPEG_HEAD = bytes([0xFF, 0xD8])
JPEG_TAIL = bytes([0xFF, 0xD9])


def _walk(root):
    found = set()
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            found.add(os.path.join(dirpath, name))
    return found


def _sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


@pytest.fixture()
def live(tmp_path, monkeypatch):
    """冻结时间（同秒条件）+ 恒定帧（同画面条件）的工作台状态。"""
    db_path = str(tmp_path / "wb.db")
    conn = connect(db_path)
    db.init_schema(conn)
    conn.close()
    state = WorkbenchState(db_path)
    state.evidence = EvidenceStore(str(tmp_path / "evidence"))
    state.environment_provider = _LocalProvider()
    monkeypatch.setattr("scam.server.time.time", lambda: FROZEN_T)
    return state


def _attach(state, camera="front"):
    state.save_zones(camera, [])
    state.monitors[camera] = _LiveMonitor()   # 恒定帧：全程同一画面
    return state.monitors[camera]


# ---------- 缺陷同构主回归（同秒同帧 + 写库失败） ----------

def test_same_second_same_frame_review_failure_keeps_v1_intact(
        live, monkeypatch):
    state = live
    _attach(state)
    assert _post(state, "/api/environment/baseline",
                 {"camera": "front", "mode": "first-use",
                  "cloud_confirmed": False})[0] == 200

    conn = connect(state.db_path)
    v1_row = db.get_environment_baseline(
        conn, db.environment_baseline_status(conn, "front")["baseline_id"])
    conn.close()
    v1_file = state.evidence.resolve(v1_row["evidence_path"])
    v1_bytes = open(v1_file, "rb").read()
    v1_sha = _sha(v1_file)
    before = _walk(state.evidence.root)

    # 同一秒（时间冻结）、同一帧（恒定帧）触发复核，注入写库失败
    def boom(*args, **kwargs):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(db, "establish_environment_baseline", boom)
    st, body = _post(state, "/api/environment/baseline",
                     {"camera": "front", "mode": "review",
                      "cloud_confirmed": False})
    assert st == 503, "写库失败必须如实失败"

    after = _walk(state.evidence.root)
    assert after == before, "失败清理后文件清单无孤立新文件、无残留"
    assert open(v1_file, "rb").read() == v1_bytes, "v1 字节不变（不得被覆盖）"
    assert _sha(v1_file) == v1_sha, "v1 完整 SHA-256 不变"

    st, body = _get(state, "/api/environment/front")
    assert body["baseline"]["state"] == "ready" and \
        body["baseline"]["version"] == 1, "当前指针仍为 v1"
    st, frame = _get_bytes(
        state, "/api/environment/front/baselines/"
        + v1_row["baseline_id"] + "/frame")
    assert st == 200 and hashlib.sha256(frame).hexdigest() == v1_sha, \
        "v1 可由历史端点回看且逐字节一致"

    # 成功复核 v2：仍是同秒同帧——两版独立画面引用、历史回看均正确
    monkeypatch.undo()
    st, body = _post(state, "/api/environment/baseline",
                     {"camera": "front", "mode": "review",
                      "cloud_confirmed": False})
    assert st == 200 and body["baseline"]["version"] == 2

    conn = connect(state.db_path)
    v2_row = db.get_environment_baseline(
        conn, db.environment_baseline_status(conn, "front")["baseline_id"])
    conn.close()
    assert v2_row["evidence_path"] != v1_row["evidence_path"], \
        "同秒同帧两版必须各有独立画面引用"
    v2_file = state.evidence.resolve(v2_row["evidence_path"])
    assert os.path.exists(v1_file) and os.path.exists(v2_file)
    assert open(v1_file, "rb").read() == v1_bytes, "v2 成功也绝不碰 v1"

    st, f1 = _get_bytes(state, "/api/environment/front/baselines/"
                        + v1_row["baseline_id"] + "/frame")
    st2, f2 = _get_bytes(state, "/api/environment/front/baselines/"
                         + v2_row["baseline_id"] + "/frame")
    assert st == 200 and st2 == 200
    assert hashlib.sha256(f1).hexdigest() == v1_sha
    assert hashlib.sha256(f2).hexdigest() == v2_row["evidence_sha256"]

    st, body = _get(state, "/api/environment/front/baselines")
    rows = body["baselines"]
    assert [(r["version"], r["status"]) for r in rows] == \
        [(2, "valid"), (1, "superseded")], "历史可辨识且 v1 保留"


# ---------- 同秒同帧独立文件身份 ----------

def test_same_second_same_frame_two_saves_get_independent_files(tmp_path):
    store = EvidenceStore(str(tmp_path / "evidence"))
    content = JPEG_HEAD + b"identical-frame" + JPEG_TAIL
    a = store.save_scene_frame(camera="cam", frame_bytes=content,
                               established_at=1234.5)
    b = store.save_scene_frame(camera="cam", frame_bytes=content,
                               established_at=1234.5)
    assert a["path"] != b["path"], "同相机同 JPEG 同秒不得共用路径"
    assert a["owner_token"] != b["owner_token"], "尝试令牌互相独立"
    assert store.read_scene_frame(a["path"], sha256=a["sha256"]) == content
    assert store.read_scene_frame(b["path"], sha256=b["sha256"]) == content


# ---------- 目标预存在：明确失败、不覆盖 ----------

def test_publish_never_overwrites_preexisting_target(tmp_path, monkeypatch):
    import scam.evidence as evmod
    store = EvidenceStore(str(tmp_path / "evidence"))
    content = JPEG_HEAD + b"victim-frame" + JPEG_TAIL
    fixed = "aabbccddeeff00112233445566778899"
    monkeypatch.setattr(evmod.uuid, "uuid4",
                        lambda: types.SimpleNamespace(hex=fixed))
    first = store.save_scene_frame(camera="cam", frame_bytes=content,
                                   established_at=1234.5)
    target = store.resolve(first["path"])
    with open(target, "r+b") as handle:      # 预先存在且内容不同
        handle.write(b"\x00\x00\x00\x00\x00")
    victim = open(target, "rb").read()

    with pytest.raises(ValueError, match="拒绝覆盖"):
        store.save_scene_frame(camera="cam", frame_bytes=content,
                               established_at=1234.5)
    assert open(target, "rb").read() == victim, "预存在目标一个字节都不动"
    leftovers = [name for name in os.listdir(os.path.dirname(target))
                 if name.endswith(".tmp")]
    assert leftovers == [], "失败不得残留临时文件"


def test_publish_fails_explicitly_when_link_unsupported(tmp_path, monkeypatch):
    """文件系统不支持安全发布操作时明确失败，绝不回退 os.replace。"""
    import scam.evidence as evmod
    store = EvidenceStore(str(tmp_path / "evidence"))
    content = JPEG_HEAD + b"fs-unsupported" + JPEG_TAIL

    def no_link(src, dst):
        raise OSError(1, "operation not supported")

    monkeypatch.setattr(evmod.os, "link", no_link)
    with pytest.raises(ValueError, match="不支持安全发布"):
        store.save_scene_frame(camera="cam", frame_bytes=content,
                               established_at=1234.5)
    monkeypatch.undo()
    leftovers = [name for _dir, _s, files in os.walk(store.root)
                 for name in files]
    assert leftovers == [], "明确失败路径同样零残留"


# ---------- 清理所有权双证 ----------

def test_discard_refuses_foreign_ownership(tmp_path):
    store = EvidenceStore(str(tmp_path / "evidence"))
    content = JPEG_HEAD + b"owned-by-attempt-a" + JPEG_TAIL
    a = store.save_scene_frame(camera="cam", frame_bytes=content,
                               established_at=1.0)
    with pytest.raises(ValueError, match="令牌不匹配"):
        store.discard_attempt_file(a["path"], "000000000000")
    with pytest.raises(ValueError, match="令牌非法"):
        store.discard_attempt_file(a["path"], "not-a-nonce")
    with pytest.raises(ValueError, match="令牌非法"):
        store.discard_attempt_file(a["path"], a["owner_token"].upper())
    assert os.path.exists(store.resolve(a["path"])), "误删防线必须生效"
    store.discard_attempt_file(a["path"], a["owner_token"])
    assert not os.path.exists(store.resolve(a["path"]))


def test_cleanup_refuses_file_referenced_by_version(live, monkeypatch):
    """库内引用核验：被任一版本引用的画面绝不清理（含无法核验时保守不删）。"""
    state = live
    _attach(state)
    assert _post(state, "/api/environment/baseline",
                 {"camera": "front", "mode": "first-use",
                  "cloud_confirmed": False})[0] == 200

    # 直接调用清理路径：路径恰是 v1 的证据 → 必须被"库内零引用"条件拒绝
    conn = connect(state.db_path)
    v1_row = db.get_environment_baseline(
        conn, db.environment_baseline_status(conn, "front")["baseline_id"])
    conn.close()

    class FakeStore:
        def __init__(self, real):
            self.real = real
            self.called = 0

        def __getattr__(self, name):
            return getattr(self.real, name)

        def discard_attempt_file(self, path, token):
            self.called += 1
            return self.real.discard_attempt_file(path, token)

    fake = FakeStore(state.evidence)
    state.evidence = fake
    state._discard_attempt_file({
        "path": v1_row["evidence_path"],
        "owner_token": "aabbccddeeff"})
    assert fake.called == 0, "被引用的证据绝不进入删除动作"
    assert os.path.exists(state.evidence.real.resolve(v1_row["evidence_path"]))

    # 引用核验不可用（连接失败）→ 保守不删
    def no_conn():
        raise RuntimeError("db down")

    state._conn = no_conn
    state._discard_attempt_file({
        "path": v1_row["evidence_path"],
        "owner_token": "aabbccddeeff"})
    assert os.path.exists(state.evidence.real.resolve(v1_row["evidence_path"])), \
        "无法核验引用时保守不删"
