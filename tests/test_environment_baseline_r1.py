"""环境基线整改回归（A-R1：五条验收阻塞）。

覆盖：占位输出拒收、证据失效重新锁定、逐版本可回看、旧版有效+当前损坏、
真实模型/配置标识、失败清理仅限本次新写文件、连接全路径关闭、重启状态。
合成证据；不含真实 RTSP/跨月规律/语义准确率/长稳声明。
"""

import hashlib
import json
import os
import sqlite3

import numpy as np
import pytest

import scam.db as db
from scam.db import connect, init_schema
from scam.environment import _validate_profile
from scam.evidence import EvidenceStore
from scam.server import WorkbenchState

from test_environment_baseline import (_H, _LocalProvider, _LiveMonitor,
                                       _get, _get_bytes, _post)


def _profile(**overrides):
    base = {"scene_type": "住宅门口", "elements": ["门"],
            "lighting": "白天", "risk_notes": "台阶湿滑",
            "suggested_zones": ["门前台阶"]}
    base.update(overrides)
    return base


@pytest.fixture()
def live(tmp_path):
    db_path = str(tmp_path / "wb.db")
    conn = connect(db_path)
    init_schema(conn)
    conn.close()
    state = WorkbenchState(db_path)
    state.evidence = EvidenceStore(str(tmp_path / "evidence"))
    provider = _LocalProvider()
    state.environment_provider = provider
    return state, provider


def _attach(state, camera="front", frame=None):
    state.save_zones(camera, [])
    state.monitors[camera] = _LiveMonitor(frame)
    return state.monitors[camera]


# ---------- 占位输出拒收（第二条） ----------

@pytest.mark.parametrize("field,value", [
    ("scene_type", "..."),
    ("scene_type", "…"),
    ("scene_type", "   "),
    ("scene_type", "．．．"),
    ("scene_type", "场景类型，≤64字"),
    ("scene_type", "画面要素"),
    ("lighting", "照明情况，≤64字"),
    ("risk_notes", "风险提示，≤500字"),
    ("lighting", "--"),
    ("scene_type", "scene_type"),
    ("scene_type", "～·—"),
])
def test_placeholder_outputs_are_rejected(field, value):
    raw = _profile(**{field: value})
    assert _validate_profile(raw) is None, f"占位内容不得通过：{value!r}"


@pytest.mark.parametrize("field,value", [
    ("scene_type", "住宅门口"),
    ("lighting", "白天"),
    ("risk_notes", "无"),
    ("risk_notes", "台阶湿滑"),
    ("scene_type", "仓库门口夜间灯光"),
])
def test_real_content_still_passes(field, value):
    raw = _profile(**{field: value})
    assert _validate_profile(raw) is not None


def test_placeholder_model_output_cannot_establish_and_keeps_old_version(
        live, monkeypatch):
    """占位输出判失败：不写新版本、不解锁、保留上一有效版本与证据。"""
    state, _ = live
    _attach(state)
    assert _post(state, "/api/environment/baseline",
                 {"camera": "front", "mode": "first-use",
                  "cloud_confirmed": False})[0] == 200

    class PlaceholderProvider:
        name = "local"
        model = "qwen3-vl:2b"
        base = "http://127.0.0.1:11434"

        def understand(self, prompt, frames_b64, context=None):
            return {"scene_type": "...", "elements": ["..."],
                    "lighting": "场景类型，≤64字", "risk_notes": "...",
                    "suggested_zones": []}

    state.environment_provider = PlaceholderProvider()
    _attach(state, frame=np.full((16, 24, 3), 130, dtype=np.uint8))
    st, body = _post(state, "/api/environment/baseline",
                     {"camera": "front", "mode": "review",
                      "cloud_confirmed": False})
    assert st == 503 and body["state"] == "invalid", \
        "占位输出必须判失败，不得写成有效基线"
    st, body = _get(state, "/api/environment/front")
    assert body["baseline"]["state"] == "ready", "失败不得毁旧版本"
    assert body["baseline"]["version"] == 1
    assert body["baseline"]["reason"] == "last_attempt_failed"
    st, body = _get(state, "/api/environment/front/baselines")
    assert [b["version"] for b in body["baselines"]] == [1], "不产生假版本"


# ---------- 证据失效重新锁定（第一条） ----------

def test_tampered_evidence_relocks_current_version(live):
    """内容篡改（哈希不符）→ evidence_broken 重新锁定，历史不删不改。"""
    state, _ = live
    _attach(state)
    _post(state, "/api/environment/baseline",
          {"camera": "front", "mode": "first-use", "cloud_confirmed": False})
    conn = connect(state.db_path)
    row = db.environment_baseline_status(conn, "front")
    conn.close()
    target = state.evidence.resolve(row["evidence_path"])
    with open(target, "r+b") as handle:      # 篡改一个字节
        handle.seek(0)
        handle.write(b"\xff\xd9")
    st, body = _get(state, "/api/environment/front")
    assert body["baseline"]["state"] == "evidence_broken"
    st, _content = _get_bytes(state, "/api/environment/front/baseline/frame")
    assert st == 404


def test_old_version_valid_current_broken_per_version_frames(live, tmp_path):
    """旧版有效、当前版损坏：旧版画面仍按其自身哈希可回看，不拿当前帧冒充。"""
    state, _ = live
    _attach(state, frame=np.full((16, 24, 3), 60, dtype=np.uint8))
    assert _post(state, "/api/environment/baseline",
                 {"camera": "front", "mode": "first-use",
                  "cloud_confirmed": False})[0] == 200
    _attach(state, frame=np.full((16, 24, 3), 180, dtype=np.uint8))
    assert _post(state, "/api/environment/baseline",
                 {"camera": "front", "mode": "review",
                  "cloud_confirmed": False})[0] == 200

    st, body = _get(state, "/api/environment/front/baselines")
    rows = body["baselines"]
    assert [r["version"] for r in rows] == [2, 1]
    assert rows[0]["is_current"] is True and rows[1]["is_current"] is False
    old_id = rows[1]["baseline_id"]
    new_id = rows[0]["baseline_id"]

    conn = connect(state.db_path)
    current = db.environment_baseline_status(conn, "front")
    conn.close()
    os.remove(state.evidence.resolve(current["evidence_path"]))   # 当前版损坏

    st, body = _get(state, "/api/environment/front")
    assert body["baseline"]["state"] == "evidence_broken"
    st, old_frame = _get_bytes(
        state, "/api/environment/front/baselines/" + old_id + "/frame")
    assert st == 200, "旧版按自身证据可回看"
    st, new_frame = _get_bytes(
        state, "/api/environment/front/baselines/" + new_id + "/frame")
    assert st == 404, "当前版损坏就是不可回看"
    assert old_frame != new_frame, "绝不以当前帧替代旧帧"

    st, body = _get(state, "/api/environment/front/baselines")
    rows = body["baselines"]
    assert rows[0]["evidence_available"] is False
    assert rows[1]["evidence_available"] is True

    state2 = WorkbenchState(state.db_path)
    state2.evidence = state.evidence
    st, body = _get(state2, "/api/environment/front")
    assert body["baseline"]["state"] == "evidence_broken", "重启后状态保持"


def test_per_version_frame_rejects_path_like_identity(live):
    state, _ = live
    _attach(state)
    _post(state, "/api/environment/baseline",
          {"camera": "front", "mode": "first-use", "cloud_confirmed": False})
    for bad in ("..%2Fetc", "a%2Fb"):
        st, body = _get(state, "/api/environment/front/baselines/"
                        + bad + "/frame")
        assert st in (404, 400), "受控版本身份之外的身份一律拒绝"
    st, body = _get(state, "/api/environment/front/baselines/ghost-id/frame")
    assert st == 404


# ---------- 真实模型/配置标识（第三条） ----------

def test_model_identity_is_real_not_channel_or_grid(live):
    state, _ = live
    state.environment_provider = type(
        "P", (), {"name": "local", "model": "qwen3-vl:2b",
                  "base": "http://127.0.0.1:11434",
                  "understand": lambda self, p, f, context=None: _profile()})()
    _attach(state)
    assert _post(state, "/api/environment/baseline",
                 {"camera": "front", "mode": "first-use",
                  "cloud_confirmed": False})[0] == 200
    st, body = _get(state, "/api/environment/front/baselines")
    row = body["baselines"][0]
    assert row["model_id"] == "qwen3-vl:2b", "不得用 channel 名冒充模型身份"
    assert "grid:" not in str(row["config_fingerprint"]), \
        "不得用网格尺寸冒充配置指纹"
    assert not row.get("comparison_insufficient")


def test_unknown_model_identity_marks_comparison_insufficient(live):
    state, _ = live
    state.environment_provider = type(
        "P", (), {"name": "local",
                  "understand": lambda self, p, f, context=None: _profile()})()
    _attach(state)
    assert _post(state, "/api/environment/baseline",
                 {"camera": "front", "mode": "first-use",
                  "cloud_confirmed": False})[0] == 200
    st, body = _get(state, "/api/environment/front")
    assert body["baseline"]["model_id"] == "unknown"
    assert body["baseline"]["comparison_insufficient"] is True
    st, body = _get(state, "/api/environment/front/baselines")
    assert body["baselines"][0].get("comparison_insufficient") is True


# ---------- 失败清理边界（第四条） ----------

def test_db_failure_cleans_only_new_file_and_keeps_old_evidence(
        live, monkeypatch):
    """写库失败：只删本次新写文件；旧版本证据与指针不变；重试可成功。"""
    state, _ = live
    _attach(state, frame=np.full((16, 24, 3), 60, dtype=np.uint8))
    assert _post(state, "/api/environment/baseline",
                 {"camera": "front", "mode": "first-use",
                  "cloud_confirmed": False})[0] == 200
    conn = connect(state.db_path)
    old = db.environment_baseline_status(conn, "front")
    conn.close()
    old_target = state.evidence.resolve(old["evidence_path"])
    before_files = set()
    root = state.evidence.root
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            before_files.add(os.path.join(dirpath, name))

    import scam.server as server_mod

    def boom(*args, **kwargs):
        raise RuntimeError("database is locked")

    import scam.db as db_mod
    monkeypatch.setattr(db_mod, "establish_environment_baseline", boom)
    _attach(state, frame=np.full((16, 24, 3), 190, dtype=np.uint8))
    st, body = _post(state, "/api/environment/baseline",
                     {"camera": "front", "mode": "review",
                      "cloud_confirmed": False})
    assert st == 503

    after_files = set()
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            after_files.add(os.path.join(dirpath, name))
    assert after_files == before_files, "只清理本次新写文件，不留孤立资产"
    assert os.path.exists(old_target), "旧版本证据绝不删"
    st, body = _get(state, "/api/environment/front")
    assert body["baseline"]["state"] == "ready" and \
        body["baseline"]["version"] == 1, "旧指针不变"

    # 重试成功
    monkeypatch.undo()
    st, body = _post(state, "/api/environment/baseline",
                     {"camera": "front", "mode": "review",
                      "cloud_confirmed": False})
    assert st == 200 and body["baseline"]["version"] == 2


def test_connections_closed_on_all_paths(live, monkeypatch):
    """成功/识别失败/写库失败/冲突各路径都不泄漏数据库连接。"""
    state, _ = live
    _attach(state)
    opened = []
    real_conn = WorkbenchState._conn

    def tracking_conn(self):
        conn = real_conn(self)
        opened.append(conn)
        return conn

    monkeypatch.setattr(WorkbenchState, "_conn", tracking_conn)
    _post(state, "/api/environment/baseline",
          {"camera": "front", "mode": "first-use", "cloud_confirmed": False})
    # 识别失败路径
    class BadProvider:
        name = "local"
        model = "m"

        def understand(self, prompt, frames_b64, context=None):
            raise RuntimeError("model down")

    state.environment_provider = BadProvider()
    _attach(state, frame=np.full((16, 24, 3), 200, dtype=np.uint8))
    _post(state, "/api/environment/baseline",
          {"camera": "front", "mode": "review", "cloud_confirmed": False})
    # 写库失败路径
    import scam.db as db_mod
    monkeypatch.setattr(db_mod, "establish_environment_baseline",
                        lambda *a, **k: (_ for _ in ()).throw(
                            RuntimeError("db down")))
    state.environment_provider = _LocalProvider()
    _attach(state, frame=np.full((16, 24, 3), 210, dtype=np.uint8))
    _post(state, "/api/environment/baseline",
          {"camera": "front", "mode": "review", "cloud_confirmed": False})
    monkeypatch.undo()
    for conn in opened:
        try:
            conn.execute("SELECT 1")
        except sqlite3.ProgrammingError:
            continue   # 已关闭：符合预期
        pytest.fail("存在未关闭连接")
