"""环境基线测试（工作包 A：值守前置 + 版本化可追溯）。

进程内驱动 Handler（零网络）。合成证据：不代表真实 RTSP / 真实模型准确率 /
跨月规律判断。覆盖任务书清单：首次建立、重复读取零模型调用、建立失败可重试
不毁旧版本、重启指针持久、多相机隔离、历史版本不覆盖、原始证据缺失/损坏、
云端未确认、建议不写 zones、旧 meta env 不伪造基线、v6 迁移保数据。
"""

import hashlib
import json
import os

import numpy as np
import pytest

import scam.db as db
from scam.db import (connect, establish_environment_baseline,
                     init_schema, record_environment_baseline_failure)
from scam.evidence import EvidenceStore
from scam.server import WorkbenchHandler, WorkbenchState


class _H(WorkbenchHandler):
    def __init__(self, method, path, obj=None, state=None):
        import io
        self.command = method
        self.path = path
        self.headers = {"Content-Length": str(len(json.dumps(obj)) if obj else 0)}
        self.rfile = io.BytesIO(json.dumps(obj).encode() if obj else b"")
        self.wfile = io.BytesIO()
        self.status = None
        self.response_headers = {}
        self._state = state

    @property
    def server(self):
        from types import SimpleNamespace
        return SimpleNamespace(state=self._state)

    def send_response(self, code, message=None):
        self.status = code

    def send_header(self, key, value):
        self.response_headers[key] = value

    def end_headers(self):
        pass

    def body_json(self):
        raw = self.wfile.getvalue()
        start = raw.find(b"{")
        return json.loads(raw[start:]) if start >= 0 else {}


def _get(state, path):
    h = _H("GET", path, None, state)
    h.do_GET()
    return h.status, h.body_json()


def _get_bytes(state, path):
    h = _H("GET", path, None, state)
    h.do_GET()
    return h.status, h.wfile.getvalue()


def _post(state, path, obj):
    h = _H("POST", path, obj, state)
    h.do_POST()
    return h.status, h.body_json()


class _LocalProvider:
    name = "local"

    def __init__(self, calls=None):
        self.calls = calls if calls is not None else []

    def understand(self, prompt, frames_b64, context=None):
        self.calls.append(1)
        return {"scene_type": "住宅门口", "elements": ["门"],
                "lighting": "白天", "risk_notes": "台阶湿滑",
                "suggested_zones": ["门前台阶"]}


class _LiveMonitor:
    def __init__(self, frame=None):
        self.latest_frame_bgr = (np.full((16, 24, 3), 90, dtype=np.uint8)
                                 if frame is None else frame)
        self.grid = _Grid()
        self.zone_revision = 0

    def request_zone_update(self, zones):
        self.zone_revision += 1
        return self.zone_revision


class _Grid:
    rows, cols = 18, 22


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


# ---------- 首次建立与解锁 ----------

def test_first_use_requires_then_establishes_then_ready(live):
    state, provider = live
    _attach(state)
    st, body = _get(state, "/api/environment/front")
    assert st == 200
    assert body["baseline"]["state"] == "baseline_required"
    assert body["baseline"]["legacy_profile"] is False

    st, body = _post(state, "/api/environment/baseline",
                     {"camera": "front", "mode": "first-use",
                      "cloud_confirmed": False})
    assert st == 200 and body["ok"] is True
    assert body["baseline"]["version"] == 1
    assert body["baseline"]["profile"]["scene_type"] == "住宅门口"
    assert len(provider.calls) == 1, "建立恰好调用一次模型"

    st, body = _get(state, "/api/environment/front")
    baseline = body["baseline"]
    assert baseline["state"] == "ready"
    assert baseline["version"] == 1
    assert baseline["evidence_available"] is True, "原始画面受控资产存在"
    assert baseline["established_via"] == "first-use"
    assert baseline["machine_state"] == "unknown", "无识别字段时标记未知"
    st, body = _get(state, "/api/environment/front/baselines")
    assert [b["version"] for b in body["baselines"]] == [1]


def test_repeated_status_reads_invoke_zero_model_calls(live):
    state, provider = live
    _attach(state)
    _post(state, "/api/environment/baseline",
          {"camera": "front", "mode": "first-use", "cloud_confirmed": False})
    before = len(provider.calls)
    for _ in range(5):
        _get(state, "/api/environment/front")
        _get(state, "/api/environment/front/baselines")
    assert len(provider.calls) == before, "重复读取不得调用模型"


def test_baseline_frame_read_is_integrity_checked(live):
    state, _ = live
    _attach(state)
    _post(state, "/api/environment/baseline",
          {"camera": "front", "mode": "first-use", "cloud_confirmed": False})
    st, content = _get_bytes(state, "/api/environment/front/baseline/frame")
    assert st == 200 and content.startswith(b"\xff\xd8")
    conn = connect(state.db_path)
    row = db.environment_baseline_status(conn, "front")
    conn.close()
    assert hashlib.sha256(content).hexdigest() == row["evidence_sha256"]
    # 响应体与状态接口都不得含本机路径
    st, body = _get(state, "/api/environment/front")
    assert "evidence_path" not in body["baseline"]


# ---------- 失败边界 ----------

def test_establishment_failure_retries_without_destroying_version(live):
    state, provider = live
    _attach(state)
    _post(state, "/api/environment/baseline",
          {"camera": "front", "mode": "first-use", "cloud_confirmed": False})
    state.monitors["front"].latest_frame_bgr = None   # 相机掉线
    st, body = _post(state, "/api/environment/baseline",
                     {"camera": "front", "mode": "review",
                      "cloud_confirmed": False})
    assert st == 503 and body["state"] == "frame_unavailable"
    st, body = _get(state, "/api/environment/front")
    assert body["baseline"]["state"] == "ready", "已建立版本仍是权威解锁"
    assert body["baseline"]["version"] == 1, "失败不得抹去上一有效版本"
    assert body["baseline"]["reason"] == "last_attempt_failed",         "失败摘要必须可见"

    _attach(state)   # 相机恢复 → 复核成功 → 版本 2
    st, body = _post(state, "/api/environment/baseline",
                     {"camera": "front", "mode": "review",
                      "cloud_confirmed": False})
    assert st == 200 and body["baseline"]["version"] == 2
    st, body = _get(state, "/api/environment/front")
    assert body["baseline"]["state"] == "ready"
    st, body = _get(state, "/api/environment/front/baselines")
    assert [(b["version"], b["status"]) for b in body["baselines"]] == \
        [(2, "valid"), (1, "superseded")], "历史不覆盖、只追加"


def test_legacy_profile_is_not_a_valid_baseline(live, tmp_path):
    state, _ = live
    _attach(state, camera="legacy")
    conn = connect(state.db_path)
    conn.execute(
        "INSERT INTO meta (key,value) VALUES (?,?)",
        ("env:legacy", json.dumps({
            "scene_type": "旧版场景", "elements": ["门"],
            "lighting": "白天", "risk_notes": "无",
            "suggested_zones": [], "provider": "local",
            "analyzed_at": 1.0, "frame_sha256": "ab" * 32})))
    conn.commit()
    conn.close()
    st, body = _get(state, "/api/environment/legacy")
    baseline = body["baseline"]
    assert baseline["state"] == "baseline_required"
    assert baseline["reason"] == "legacy_profile_without_evidence"
    assert baseline["legacy_profile"] is True


def test_cloud_requires_each_call_confirmation_for_baseline(live):
    class CloudProvider:
        name = "cloud"

        def __init__(self):
            self.calls = 0

        def understand(self, prompt, frames_b64, context=None):
            self.calls += 1
            return {"scene_type": "仓库", "elements": ["门"],
                    "lighting": "白天", "risk_notes": "无",
                    "suggested_zones": ["入口"]}

    cloud = CloudProvider()
    state, _ = live
    state.environment_provider = cloud
    _attach(state)
    st, body = _post(state, "/api/environment/baseline",
                     {"camera": "front", "mode": "first-use",
                      "cloud_confirmed": False})
    assert st == 428 and body["state"] == "confirmation_required"
    assert cloud.calls == 0, "未确认前不得外发任何画面"
    st, body = _post(state, "/api/environment/baseline",
                     {"camera": "front", "mode": "first-use",
                      "cloud_confirmed": True})
    assert st == 200 and cloud.calls == 1


def test_suggestions_never_write_zones(live):
    state, _ = live
    _attach(state, camera="front")
    _post(state, "/api/environment/baseline",
          {"camera": "front", "mode": "first-use", "cloud_confirmed": False})
    assert state.zones("front") == [], "识别建议绝不能自动写成区域"


# ---------- 多相机隔离与持久化 ----------

def test_multi_camera_baselines_do_not_unlock_each_other(live, tmp_path):
    state, provider = live
    _attach(state, camera="cam-a")
    _attach(state, camera="cam-b")
    _post(state, "/api/environment/baseline",
          {"camera": "cam-a", "mode": "first-use", "cloud_confirmed": False})
    st, a = _get(state, "/api/environment/cam-a")
    st2, b = _get(state, "/api/environment/cam-b")
    assert a["baseline"]["state"] == "ready"
    assert b["baseline"]["state"] == "baseline_required", \
        "一台相机的基线不得给另一台解锁"
    # 新建 WorkbenchState 模拟重启：指针持久
    state2 = WorkbenchState(state.db_path)
    st, a2 = _get(state2, "/api/environment/cam-a")
    st2, b2 = _get(state2, "/api/environment/cam-b")
    assert a2["baseline"]["state"] == "ready" and a2["baseline"]["version"] == 1
    assert b2["baseline"]["state"] == "baseline_required"


def test_restart_persists_pointer_and_history(tmp_path):
    db_path = str(tmp_path / "wb.db")
    conn = connect(db_path)
    init_schema(conn)
    store = EvidenceStore(str(tmp_path / "evidence"))
    content = bytes([0xFF, 0xD8]) + b"real-scene-frame" + bytes([0xFF, 0xD9])
    info = store.save_scene_frame(camera="front", frame_bytes=content,
                                  established_at=100.0)
    establish_environment_baseline(
        conn, camera="front", baseline_id="b1", established_at=100.0,
        established_via="first-use", scene_summary="门口",
        machine_state="fixed", profile={"scene_type": "门口"},
        model_id="qwen3-vl:2b", config_fingerprint="f",
        evidence_path=info["path"], evidence_sha256=info["sha256"],
        evidence_size=info["size_bytes"])
    conn.close()
    state = WorkbenchState(db_path)
    state.save_zones("front", [])
    st, body = _get(state, "/api/environment/front")
    assert body["baseline"]["state"] == "ready", "真实证据在位：重启后指针持久解锁"
    assert body["baseline"]["version"] == 1


# ---------- 证据缺失/损坏 ----------

def test_missing_or_corrupt_evidence_is_reported_not_faked(live, tmp_path):
    state, _ = live
    _attach(state)
    _post(state, "/api/environment/baseline",
          {"camera": "front", "mode": "first-use", "cloud_confirmed": False})
    conn = connect(state.db_path)
    row = db.environment_baseline_status(conn, "front")
    target = state.evidence.resolve(row["evidence_path"])
    conn.close()
    os.remove(target)   # 原始画面被移动/删除
    st, body = _get(state, "/api/environment/front")
    baseline = body["baseline"]
    assert baseline["state"] == "evidence_broken", "当前版本证据失效不得按 ready 解锁（需修复/复核）"
    assert baseline["evidence_available"] is False
    assert baseline["reason"] == "evidence_missing_or_corrupt"
    st, content = _get_bytes(state, "/api/environment/front/baseline/frame")
    assert st == 404, "画面不得用坏链接假装可回看"
    st, body = _get(state, "/api/environment/front/baselines")
    assert [b["version"] for b in body["baselines"]] == [1], "历史行不删不改"
    assert body["baselines"][0]["evidence_available"] is False


# ---------- 迁移 ----------

def test_v5_database_upgrades_and_keeps_event_truth(tmp_path):
    """既有 v5 候选库（事件事实+旧 evidence 资产）升级 v6 零丢失。"""
    path = str(tmp_path / "v5.db")
    conn = connect(path)
    init_schema(conn)
    conn.execute("PRAGMA user_version=5")
    db.open_tracked_object(conn, object_id="o1", camera="front",
                           t_start=1.0, cls="person")
    db.open_event_fact(conn, event_id="e1", camera="front",
                       object_id="o1", t_start=1.0, cls="person")
    content = b"\xff\xd8legacy-evidence\xff\xd9"
    digest = hashlib.sha256(content).hexdigest()
    conn.execute(
        "INSERT INTO evidence_assets (asset_id,owner_type,owner_id,camera,"
        " kind,path,state,mime,size_bytes,sha256,created_at,updated_at)"
        " VALUES (?,'tracked_object','o1','front','clean_best_frame',"
        " 'a/b.jpg','available','image/jpeg',?,?,1.0,1.0)",
        ("best:legacy", len(content), digest))
    conn.commit()
    conn.close()

    conn = connect(path)
    init_schema(conn)   # v5 库被 v6 程序打开
    assert conn.execute("PRAGMA user_version").fetchone()[0] == \
        db.SCHEMA_VERSION
    assert conn.execute(
        "SELECT object_id FROM event_facts WHERE event_id='e1'"
    ).fetchone()["object_id"] == "o1", "事件事实零丢失"
    row = conn.execute(
        "SELECT sha256 FROM evidence_assets WHERE asset_id='best:legacy'"
    ).fetchone()
    assert row["sha256"] == digest, "旧证据资产零丢失"


def test_establishment_db_failure_records_reason_and_keeps_state(live,
                                                                 monkeypatch):
    """建立落库失败：记固定中文摘要、状态 failed、旧版本不受影响。"""
    state, _ = live
    _attach(state)
    _post(state, "/api/environment/baseline",
          {"camera": "front", "mode": "first-use", "cloud_confirmed": False})

    def boom(*args, **kwargs):
        raise RuntimeError("database is locked")

    import scam.server as server_mod
    from scam import db as db_mod
    monkeypatch.setattr(db_mod, "establish_environment_baseline", boom)
    state.monitors["front"].latest_frame_bgr = np.full(
        (16, 24, 3), 120, dtype=np.uint8)
    st, body = _post(state, "/api/environment/baseline",
                     {"camera": "front", "mode": "review",
                      "cloud_confirmed": False})
    assert st == 503
    st, body = _get(state, "/api/environment/front")
    assert body["baseline"]["state"] == "ready", "失败不得改指针"
    assert body["baseline"]["version"] == 1
    assert body["baseline"]["reason"] == "last_attempt_failed"
    assert body["baseline"]["error"] == "基线写入失败"
    st, body = _get(state, "/api/environment/front/baselines")
    assert [b["version"] for b in body["baselines"]] == [1]
