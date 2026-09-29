"""语义更新第一切片测试（Win11「进行中事件的语义更新」）。

用可注入确定性 provider 验证状态机与合同 v1；生产入口默认真实本地模型，
注入 fake 仅限测试——本文件全部为合成证据，不宣称真实语义质量达标、
不代表真实 RTSP/提醒时延/长稳。
"""

import hashlib
import json
import threading
from pathlib import Path

import numpy as np
import pytest

import scam.db as db
from scam.db import (connect, get_event_fact, init_schema,
                     publish_semantic_update,
                     semantic_update_ledger_hit_prefix)
from scam.evidence import EvidenceStore
from scam.monitor import Monitor, to_gray
from scam.semantic_updater import (SemanticUpdater, compose_text,
                                   validate_semantic_profile)
from scam.server import WorkbenchState
from scam.sinks import SqliteSink

import cv2

from test_event_api import _H, _get, _post

W, H = 640, 360
JPEG = bytes([0xFF, 0xD8]) + b"frame" + bytes([0xFF, 0xD9])


def _flip_frame(present, flip):
    f = np.zeros((H, W, 3), np.uint8)
    f[:] = (30, 30, 30)
    if present:
        x0 = int(0.45 * W) + (8 if flip else 0)
        cv2.rectangle(f, (x0, int(0.45 * H)),
                      (x0 + 60, int(0.45 * H) + 80), (255, 255, 255), -1)
    return f


def _detect(frame):
    if frame[200, 330].mean() > 100:
        return [{"cls": "person", "conf": 0.9,
                 "bbox": [0.45, 0.45, 0.10, 0.22], "cx": 0.50, "cy": 0.56}]
    return []


def _evidence_root(db_path):
    return str(Path(db_path).parent / "evidence")


class FakeProvider:
    """确定性 provider（仅测试）：ok / raise / none / placeholder。"""

    name = "local"
    model = "fake-semantic:1b"
    base = "http://127.0.0.1:11434"

    def __init__(self, behavior="ok"):
        self.behavior = behavior
        self.calls = 0

    def understand(self, prompt, frames_b64, context=None):
        self.calls += 1
        if self.behavior == "raise":
            raise RuntimeError("model down")
        if self.behavior == "none":
            return None
        if self.behavior == "placeholder":
            return {"observed": ["..."], "inference": "...",
                    "uncertainty": "low"}
        return {"observed": ["门口有一人站立", "门处于关闭状态"],
                "inference": "疑似在等候进入，需结合后续画面判断",
                "uncertainty": "low"}


@pytest.fixture()
def served(tmp_path):
    """无规则（zones=[]）真实快路径：事件 + v1 + 受控最佳帧证据。"""
    db_path = str(tmp_path / "events.db")
    sink = SqliteSink(db_path)
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []}, detect_fn=_detect, sinks=[sink])
    t = 1000000.0
    for i in range(8):
        f = _flip_frame(True, i % 2)
        m.step(f, to_gray(f, Monitor.GRAY_W), t)
        t += 400.0
    conn = connect(db_path)
    row = conn.execute(
        "SELECT event_id,object_id FROM event_facts").fetchone()
    asset = conn.execute(
        "SELECT asset_id FROM evidence_assets WHERE owner_type="
        "'tracked_object' AND owner_id=? AND kind='clean_best_frame'"
        " AND state='available'", (row["object_id"],)).fetchone()
    conn.close()
    assert row is not None and asset is not None, \
        "无规则事件与受控证据必须已就绪"
    state = WorkbenchState(db_path)
    return {"db_path": db_path, "monitor": m, "state": state,
            "event_id": row["event_id"], "object_id": row["object_id"],
            "asset_id": asset["asset_id"]}


def _updater(env, behavior="ok", **kwargs):
    provider = FakeProvider(behavior)
    stop = threading.Event()
    updater = SemanticUpdater(env["db_path"], provider,
                              stop_event=stop, **kwargs)
    return updater, stop, provider


def _drain_once(updater):
    updater._scan()
    updater._drain()


def _vlm_rows(db_path, event_id):
    conn = connect(db_path)
    rows = [dict(r) for r in conn.execute(
        "SELECT version,source,text,uncertainty,evidence_refs,payload"
        " FROM event_descriptions WHERE event_id=? AND source='vlm'"
        " ORDER BY version", (event_id,)).fetchall()]
    conn.close()
    return rows


# ---------- 主线：无规则事件 v1 照常 + v2 追加 + 版本历史 ----------

def test_no_rule_event_v1_unchanged_then_v2_appended(served):
    env = served
    updater, _stop, _provider = _updater(env, "ok")
    _drain_once(updater)

    rows = _vlm_rows(env["db_path"], env["event_id"])
    assert len(rows) == 1 and rows[0]["version"] == 2, "v2 追加为版本 2"
    assert rows[0]["uncertainty"] in ("confirmed", "low", "high")
    payload = json.loads(rows[0]["payload"])
    assert payload["evidence_digest"], "描述必须绑定证据摘要"
    assert payload["observed"] and payload["inference"]

    state = WorkbenchState(env["db_path"])
    detail = state.event_fact_detail(env["event_id"])
    assert [d["version"] for d in detail["descriptions"]] == [1, 2], \
        "v1→v2 历史可见"
    assert detail["descriptions"][0]["source"] == "initial_observation"
    assert any(n["kind"] == "semantic_update"
               for n in detail["notifications"])
    assert not any(n["kind"] == "alert"
                   for n in detail["notifications"])


def test_v1_text_and_initial_notification_not_delayed_or_overwritten(served):
    env = served
    conn = connect(env["db_path"])
    v1_before = conn.execute(
        "SELECT text,payload FROM event_descriptions WHERE event_id=?"
        " AND version=1", (env["event_id"],)).fetchone()
    notif_before = conn.execute(
        "SELECT created_at FROM event_notifications WHERE event_id=?"
        " AND kind='initial_fact'", (env["event_id"],)).fetchone()
    conn.close()
    updater, _stop, _provider = _updater(env, "ok")
    _drain_once(updater)

    conn = connect(env["db_path"])
    v1_after = conn.execute(
        "SELECT text,payload FROM event_descriptions WHERE event_id=?"
        " AND version=1", (env["event_id"],)).fetchone()
    notif_after = conn.execute(
        "SELECT created_at FROM event_notifications WHERE event_id=?"
        " AND kind='initial_fact'", (env["event_id"],)).fetchone()
    v2 = conn.execute(
        "SELECT t_created FROM event_descriptions WHERE event_id=?"
        " AND version=2", (env["event_id"],)).fetchone()
    conn.close()
    assert v1_after["text"] == v1_before["text"]
    v1p_b = json.loads(v1_before["payload"]) if v1_before["payload"] else None; v1p_a = json.loads(v1_after["payload"]) if v1_after["payload"] else None; assert v1p_a == v1p_b, \
        "v1 不可变"
    assert notif_after["created_at"] == notif_before["created_at"], \
        "initial_fact 不被语义更新延迟或改写"
    assert v2["t_created"] >= notif_before["created_at"] - 1e-9


# ---------- 失败边界：模型/证据 ----------

def test_model_raise_leaves_v1_intact_and_failure_visible(served):
    env = served
    updater, _stop, _provider = _updater(env, "raise")
    _drain_once(updater)
    assert _vlm_rows(env["db_path"], env["event_id"]) == [], \
        "模型失败不得生成描述"
    snap = updater.snapshot()
    assert snap["waiting_retry"] >= 1 and snap["last_error"], "失败状态可观察"
    assert snap["published"] == 0
    conn = connect(env["db_path"])
    n = conn.execute("SELECT COUNT(*) c FROM event_notifications"
                     " WHERE event_id=? AND kind='initial_fact'",
                     (env["event_id"],)).fetchone()["c"]
    conn.close()
    assert n == 1, "v1 提醒照常工作"


def test_model_none_and_placeholder_marked_invalid(served):
    env = served
    for behavior in ("none", "placeholder"):
        updater, _stop, _provider = _updater(env, behavior)
        _drain_once(updater)
        state = updater.event_state(env["event_id"])
        assert state["state"] in ("waiting_retry", "failed_terminal")
        assert state["code"] in ("model_unavailable", "output_invalid"), \
            "占位/不可用都不得当作完成识别"
    assert _vlm_rows(env["db_path"], env["event_id"]) == []


def test_missing_evidence_skips_model_without_fabrication(tmp_path):
    db_path = str(tmp_path / "events.db")
    conn = connect(db_path)
    init_schema(conn)
    db.open_tracked_object(conn, object_id="o1", camera="front",
                           t_start=1.0, cls="person")
    db.open_event_fact(conn, event_id="e1", camera="front", object_id="o1",
                       t_start=1.0, cls="person")   # 无受控证据资产
    conn.close()
    provider = FakeProvider("ok")
    updater = SemanticUpdater(db_path, provider,
                              stop_event=threading.Event())
    updater._scan()
    updater._drain()
    assert provider.calls == 0, "缺证据不得调用模型、不得生成肯定式结论"
    conn = connect(db_path)
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_descriptions"
        " WHERE event_id='e1'").fetchone()["c"] == 0
    conn.close()


def test_unreadable_evidence_marks_failure(served, monkeypatch):
    """证据不可读（缺失/损坏在读取缝合点暴露）→ 失败可观察，不产描述。"""
    env = served

    updater, _stop, _provider = _updater(env, "ok")
    updater._scan()          # 入队（当时证据在位）
    conn = connect(env["db_path"])
    conn.execute(
        "UPDATE evidence_assets SET path='missing/dir/frame.jpg'"
        " WHERE owner_id=?", (env["object_id"],))
    conn.commit()
    conn.close()
    updater._drain()         # 处理：读取失败 → 保守失败
    state = updater.event_state(env["event_id"])
    assert state["state"] in ("waiting_retry", "failed_terminal")
    assert state["code"] in ("evidence_identity_mismatch",
                             "evidence_missing_or_corrupt"),         "路径中途变化与缺失都属于保守失败"
    assert _vlm_rows(env["db_path"], env["event_id"]) == []


# ---------- 幂等：重复调度 / 重启 / 并发 ----------

def test_duplicate_scheduling_restart_and_concurrency_no_duplicates(served):
    env = served
    updater, _stop, provider = _updater(env, "ok")
    _drain_once(updater)
    _drain_once(updater)   # 同进程重复调度
    rows = _vlm_rows(env["db_path"], env["event_id"])
    assert len(rows) == 1

    # 进程重启：新实例同库（同证据摘要、同指纹）→ 账本命中 → 零新增
    updater2, stop2, provider2 = _updater(env, "ok")
    updater2._scan()
    assert provider2.calls == 0, "同指纹已在账本，不得重复调用模型"
    assert updater2.queue.empty(), "不得重复入队"
    stop2.set()

    # 并发发布同一身份：恰一次
    digest = json.loads(rows[0]["payload"])["evidence_digest"]
    conn = connect(env["db_path"])
    v, created = publish_semantic_update(
        conn, event_id=env["event_id"],
        identity=f"{digest}:{updater.fingerprint}",
        text="dup", uncertainty="low", evidence_refs=[],
        t_created=9.0, model_id="x", event_open_at_write=False)
    conn.close()
    assert created is False and v is None
    assert len(_vlm_rows(env["db_path"], env["event_id"])) == 1


def test_event_closed_during_processing_conservative(served):
    """处理期间事件已关闭：按已捕获证据保守落库，不伪装成开放期间观察。"""
    env = served
    updater, _stop, _provider = _updater(env, "ok")
    updater._scan()          # 扫描入队时事件仍 open
    conn = connect(env["db_path"])
    db.close_event_fact(conn, env["event_id"], reason="track-lost")
    conn.close()
    updater._drain()         # 写出前事件已关闭 → 保守落库
    rows = _vlm_rows(env["db_path"], env["event_id"])
    assert len(rows) == 1
    payload = json.loads(rows[0]["payload"])
    assert payload["event_open_at_capture"] is False, \
        "关闭后不得伪装成开放期间观察"


# ---------- 预算：静态不重复调用 / 新证据推进版本 ----------

def test_static_frame_skips_model_new_evidence_advances_version(served,
                                                                 tmp_path):
    env = served
    updater, _stop, provider = _updater(env, "ok")
    _drain_once(updater)
    calls_after_v2 = provider.calls
    _drain_once(updater)   # 静态：同证据摘要 → 账本命中 → 不重复调用
    assert provider.calls == calls_after_v2
    assert len(_vlm_rows(env["db_path"], env["event_id"])) == 1

    # 新证据：经受控存储落一副新画面，资产行改指新证据 → 新摘要 → v3
    store = EvidenceStore(str(Path(env["db_path"]).parent / "evidence"))
    new_content = bytes([0xFF, 0xD8]) + b"new-evidence-frame" \
        + bytes([0xFF, 0xD9])
    info = store.save_scene_frame(camera="front-door",
                                  frame_bytes=new_content,
                                  established_at=1000.0)
    conn = connect(env["db_path"])
    conn.execute(
        "UPDATE evidence_assets SET path=?, sha256=?, size_bytes=?,"
        " state='available' WHERE owner_id=?",
        (info["path"], info["sha256"], info["size_bytes"],
         env["object_id"]))
    conn.commit()
    conn.close()
    _drain_once(updater)   # 自然推进：生产状态机自行识别新证据，无测试特权
    rows = _vlm_rows(env["db_path"], env["event_id"])
    assert [r["version"] for r in rows] == [2, 3], "确有新证据才允许新版本"


# ---------- 多相机积压 ----------

def test_two_cameras_backlog_both_processed_without_blocking(served):
    env = served
    conn = connect(env["db_path"])
    db.open_tracked_object(conn, object_id="back:run:track:1",
                           camera="back-door", t_start=5.0, cls="person")
    db.open_event_fact(conn, event_id="back:run:event:1", camera="back-door",
                       object_id="back:run:track:1", t_start=5.0,
                       cls="person")
    conn.commit()
    conn.close()
    store = EvidenceStore(str(Path(env["db_path"]).parent / "evidence"))
    frame = bytes([0xFF, 0xD8]) + b"back-door-frame" + bytes([0xFF, 0xD9])
    info = store.save_scene_frame(camera="back-door", frame_bytes=frame,
                                  established_at=5.0)
    conn = connect(env["db_path"])
    conn.execute(
        "INSERT INTO evidence_assets (asset_id,owner_type,owner_id,camera,"
        " kind,path,state,mime,size_bytes,sha256,created_at,updated_at)"
        " VALUES (?,'tracked_object','back:run:track:1','back-door',"
        " 'clean_best_frame',?, 'available','image/jpeg',?,?,?,?)",
        ("best:back:1", info["path"], info["size_bytes"], info["sha256"],
         5.0, 5.0))
    conn.commit()
    conn.close()
    updater, _stop, _provider = _updater(env, "ok")
    _drain_once(updater)
    _drain_once(updater)
    conn = connect(env["db_path"])
    cams = {r["camera"] for r in conn.execute(
        "SELECT f.camera AS camera FROM event_descriptions d"
        " JOIN event_facts f ON f.event_id=d.event_id"
        " WHERE d.source='vlm'").fetchall()}
    conn.close()
    assert cams == {"front-door", "back-door"}, "一台相机不得拖住另一台"


# ---------- 状态面与旧接口 ----------

def test_health_and_detail_surfaces_state_without_leaks(served):
    env = served
    stop = threading.Event()
    updater = SemanticUpdater(env["db_path"], FakeProvider("raise"),
                              stop_event=stop)
    state = WorkbenchState(env["db_path"])
    state.semantic = updater
    updater._scan()
    updater._drain()

    handler = _H("GET", "/api/health", None, state)
    handler.do_GET()
    health = handler.body_json()
    assert health["semantic"]["failed"] + health["semantic"]["waiting_retry"] >= 1
    assert health["semantic"]["provider"] == "fake-semantic:1b"
    detail = state.event_fact_detail(env["event_id"])
    assert detail["semantic"]["state"] in ("waiting_retry",
                                           "failed_terminal")
    assert detail["semantic_note"] == "暂未生成进一步理解"
    raw = json.dumps(detail, ensure_ascii=False)
    assert "evidence_path" not in raw and "rtsp://" not in raw


def test_worker_thread_lifecycle_start_stop(served):
    env = served
    updater, stop, _provider = _updater(env, "ok", scan_interval_s=0.2)
    updater.start()
    assert updater._thread is not None and updater._thread.is_alive()
    stop.set()
    updater.stop(timeout=3.0)
    assert not updater._thread.is_alive()


def test_old_events_api_semantic_events_unchanged(served):
    env = served
    updater, _stop, _provider = _updater(env, "ok")
    _drain_once(updater)
    conn = connect(env["db_path"])
    n = conn.execute("SELECT COUNT(*) c FROM semantic_events").fetchone()["c"]
    conn.close()
    assert n == 0, "语义更新不是管理员规则告警，旧接口语义不变"


# ---------- 纯校验器 ----------

def test_validate_semantic_profile_rejects_placeholder_and_missing():
    assert validate_semantic_profile({"observed": ["..."],
                                      "inference": "x",
                                      "uncertainty": "low"}) is None
    assert validate_semantic_profile({"observed": [], "inference": "x",
                                      "uncertainty": "low"}) is None
    assert validate_semantic_profile({"observed": ["门口有人"],
                                      "inference": "",
                                      "uncertainty": "low"}) is None
    ok = validate_semantic_profile({"observed": ["门口有人"],
                                    "inference": "疑似等候",
                                    "uncertainty": "nonsense"})
    assert ok["uncertainty"] == "low", "非法不确定性默认保守标记"


def test_compose_text_separates_observation_and_inference():
    text = compose_text({"observed": ["门口有人"], "inference": "疑似等候",
                         "uncertainty": "low"})
    assert "画面可直接确认" in text and "模型推断" in text
    assert "存在不确定性" in text


# ---------- R1-① 旧开放事件不饿死（扫描游标可推进可回绕） ----------

def _seed_open_event(state, camera, seq, *, with_evidence=True):
    conn = connect(state.db_path)
    event_id = f"{camera}:run:event:{seq}"
    object_id = f"{camera}:run:track:{seq}"
    t_start = 1000.0 + (seq % 900 if isinstance(seq, int) else 0.0)
    db.open_tracked_object(conn, object_id=object_id, camera=camera,
                           t_start=t_start, cls="person")
    db.open_event_fact(conn, event_id=event_id, camera=camera,
                       object_id=object_id, t_start=t_start, cls="person")
    conn.commit()
    conn.close()
    if with_evidence:
        store = EvidenceStore(_evidence_root(state.db_path))
        info = store.save_scene_frame(
            camera=camera, frame_bytes=bytes([0xFF, 0xD8])
            + b"frame-" + str(seq).encode() + bytes([0xFF, 0xD9]),
            established_at=t_start)
        conn = connect(state.db_path)
        conn.execute(
            "INSERT INTO evidence_assets (asset_id,owner_type,owner_id,"
            " camera,kind,path,state,mime,size_bytes,sha256,created_at,"
            " updated_at)"
            " VALUES (?,'tracked_object',?,?,'clean_best_frame',?,"
            " 'available','image/jpeg',?,?,?,?)",
            (f"best:{camera}:{seq}", object_id, camera, info["path"],
             info["size_bytes"], info["sha256"], t_start, t_start))
        conn.commit()
        conn.close()
    return event_id, object_id


def test_old_open_events_not_starved_under_continuous_insertion(served):
    env = served
    old_ids = [_seed_open_event(env["state"], "front-door",
                            "old-" + str(i).zfill(3))[0] for i in range(40)]
    updater, stop, _provider = _updater(env, "ok", scan_batch=32)
    processed = set()
    new_seq = 100
    for _round in range(8):
        _drain_once(updater)
        conn = connect(env["db_path"])
        rows = conn.execute(
            "SELECT event_id FROM event_descriptions"
            " WHERE source='vlm'").fetchall()
        conn.close()
        processed = {r["event_id"] for r in rows}
        for _k in range(2):   # 持续插入新事件
            _seed_open_event(env["state"], "front-door",
                             "new-" + str(new_seq).zfill(3))
            new_seq += 1
        if all(eid in processed for eid in old_ids):
            break
    stop.set()
    missing = [eid for eid in old_ids if eid not in processed]
    assert not missing, f"旧开放事件被饿死 {len(missing)} 条"
    assert len(processed) >= 40


def test_multi_camera_interleaved_no_starvation(served):
    env = served
    for i in range(12):
        _seed_open_event(env["state"], "cam-a", i)
        _seed_open_event(env["state"], "cam-b", i)
    updater, stop, _provider = _updater(env, "ok", scan_batch=8)
    for _round in range(8):
        _drain_once(updater)
    stop.set()
    conn = connect(env["db_path"])
    cams = {r["camera"] for r in conn.execute(
        "SELECT f.camera AS camera FROM event_descriptions d"
        " JOIN event_facts f ON f.event_id=d.event_id"
        " WHERE d.source='vlm'").fetchall()}
    conn.close()
    assert {"cam-a", "cam-b"} <= cams, "两台相机都必须被处理（不互相饿死）"


def test_scan_cursor_persists_across_restart(served):
    env = served
    for i in range(6):
        _seed_open_event(env["state"], "front-door", i)
    updater, stop, _provider = _updater(env, "ok", scan_batch=2)
    updater._scan()
    stop.set()
    conn = connect(env["db_path"])
    row = conn.execute(
        "SELECT value FROM meta WHERE key='semantic_scan_cursor'").fetchone()
    conn.close()
    assert row is not None and row[0], "扫描游标必须持久化（跨重启续跑）"


# ---------- R1-② 失败退避 → 终态 → 证据变化再激活 ----------

def test_recoverable_failure_backoff_then_terminal_then_evidence_change(
        served, monkeypatch):
    env = served
    updater, stop, provider = _updater(env, "raise")
    eid, _oid = _seed_open_event(env["state"], "front-door", 1)

    updater._scan()
    updater._drain()
    r1 = updater.records[eid]
    assert r1["state"] == "waiting_retry" and r1["attempts"] == 1

    r1["next_retry_mono"] = 0   # 模拟退避到期
    updater._scan()
    updater._drain()
    r2 = updater.records[eid]
    assert r2["state"] == "waiting_retry" and r2["attempts"] == 2

    r2["next_retry_mono"] = 0
    updater._scan()
    updater._drain()
    r3 = updater.records[eid]
    assert r3["state"] == "failed_terminal", "重试耗尽转终态"
    calls_at_terminal = provider.calls

    # 故障解除（模型恢复）+ 证据摘要变化 → 重新激活并发布
    updater.provider.behavior = "ok"
    store = EvidenceStore(_evidence_root(env["db_path"]))
    new_content = bytes([0xFF, 0xD8]) + b"changed-frame" + bytes([0xFF, 0xD9])
    info = store.save_scene_frame(camera="front-door",
                                  frame_bytes=new_content,
                                  established_at=1007.0)
    conn = connect(env["db_path"])
    conn.execute(
        "UPDATE evidence_assets SET path=?, sha256=?, size_bytes=?"
        " WHERE owner_id=?",
        (info["path"], info["sha256"], info["size_bytes"],
         eid.replace(":event:", ":track:")))
    conn.commit()
    conn.close()
    updater._scan()
    updater._drain()
    rows = _vlm_rows(env["db_path"], eid)
    assert len(rows) == 1 and rows[0]["source"] == "vlm"
    dig = json.loads(rows[0]["payload"])["evidence_digest"]
    assert dig == hashlib.sha256(new_content).hexdigest(), "摘要=新证据"
    assert updater.event_state(eid)["state"] == "published"
    assert provider.calls > calls_at_terminal


def test_restart_resets_retry_budget_but_never_duplicates(served):
    env = served
    _seed_open_event(env["state"], "front-door", 1)
    updater, stop, _provider = _updater(env, "raise")
    updater._scan()
    updater._drain()
    stop.set()
    # 进程重启：新实例内存记录清空 → 重试预算重置（账本兜底不重复）
    updater2, stop2, provider2 = _updater(env, "ok")
    updater2._scan()
    updater2._drain()
    stop2.set()
    rows = _vlm_rows(env["db_path"], "front-door:run:event:1")
    assert len(rows) == 1 and rows[0]["source"] == "vlm", \
        "重启后恰一次发布，零重复"


# ---------- R1-③ 证据身份与模型输入绑定 ----------

def _seed_with_evidence(env):
    eid, oid = _seed_open_event(env["state"], "front-door", 7,
                                with_evidence=False)
    store = EvidenceStore(_evidence_root(env["db_path"]))
    info = store.save_scene_frame(camera="front-door", frame_bytes=JPEG,
                                  established_at=1007.0)
    conn = connect(env["db_path"])
    conn.execute(
        "INSERT INTO evidence_assets (asset_id,owner_type,owner_id,camera,"
        " kind,path,state,mime,size_bytes,sha256,created_at,updated_at)"
        " VALUES (?,'tracked_object',?,'front-door',"
        " 'clean_best_frame',?, 'available','image/jpeg',?,?,?,?)",
        ("best:front:7", oid, info["path"], info["size_bytes"],
         info["sha256"], 1007.0, 1007.0))
    conn.commit()
    conn.close()
    return info


def test_content_changed_same_path_binds_actual_bytes(served):
    """路径不变、内容被替换（记录同步更新）：摘要取自实际送模字节。"""
    env = served
    _seed_with_evidence(env)
    updater, stop, _provider = _updater(env, "ok")
    updater._scan()
    store = EvidenceStore(_evidence_root(env["db_path"]))
    new_content = bytes([0xFF, 0xD8]) + b"changed-frame" + bytes([0xFF, 0xD9])
    info = store.save_scene_frame(camera="front-door",
                                  frame_bytes=new_content,
                                  established_at=1007.0)
    conn = connect(env["db_path"])
    conn.execute(
        "UPDATE evidence_assets SET path=?, sha256=?, size_bytes=?"
        " WHERE owner_id=?",
        (info["path"], info["sha256"], info["size_bytes"],
         "front-door:run:track:7"))
    conn.commit()
    conn.close()
    updater._scan()          # 重扫描：排队中的旧快照由处理时全量核验自愈
    updater._drain()
    rows = _vlm_rows(env["db_path"], "front-door:run:event:7")
    assert len(rows) == 1
    payload = json.loads(rows[0]["payload"])
    assert payload["evidence_digest"] == \
        hashlib.sha256(new_content).hexdigest(), \
        "摘要必须等于实际送模字节的哈希（不得混配旧摘要）"
    stop.set()


def test_asset_record_changed_midflight_conservative_fail(served):
    """入队后资产行指向另一文件但校验和保留旧值 → 读取核验失配，
    保守失败不产 v2；路径中途变化同样识别。"""
    env = served
    _seed_with_evidence(env)
    updater, stop, _provider = _updater(env, "ok")
    updater._scan()
    store = EvidenceStore(_evidence_root(env["db_path"]))
    decoy = store.save_scene_frame(camera="front-door",
                                   frame_bytes=bytes([0xFF, 0xD8])
                                   + b"decoy-frame" + bytes([0xFF, 0xD9]),
                                   established_at=1008.0)
    conn = connect(env["db_path"])
    conn.execute(
        "UPDATE evidence_assets SET path=?, sha256='outdated-sha',"
        " size_bytes=12345 WHERE owner_id='front-door:run:track:7'",
        (decoy["path"],))
    conn.commit()
    conn.close()
    updater._scan()          # 重扫描：当前记录指向 decoy，处理时核验失配
    updater._drain()
    state = updater.event_state("front-door:run:event:7")
    assert state["state"] in ("failed_terminal", "waiting_retry")
    assert state["code"] in ("evidence_identity_mismatch",
                             "evidence_missing_or_corrupt")
    assert _vlm_rows(env["db_path"], "front-door:run:event:7") == []
    stop.set()


# ---------- R1-④ semantic_update 工作台闭环 ----------

def test_semantic_update_independent_paginated_stream(served):
    env = served
    state = env["state"]
    conn = connect(state.db_path)
    for i in range(25):
        eid = f"front-door:run:event:{i}"
        oid = f"front-door:run:track:{i}"
        db.open_tracked_object(conn, object_id=oid, camera="front",
                               t_start=1000.0 + i, cls="person")
        db.open_event_fact(conn, event_id=eid, camera="front",
                           object_id=oid, t_start=1000.0 + i, cls="person")
        publish_semantic_update(
            conn, event_id=eid, identity=f"digest-{i}:fp",
            text=f"新增一版理解 {i}", uncertainty="low", evidence_refs=[],
            t_created=2000.0 + i, model_id="fake-semantic:1b",
            event_open_at_write=True)
    conn.close()
    collected = _walk_notifications(state, "semantic_update")
    assert len(collected) == 25 and len(set(collected)) == 25
    initial_ids = _walk_notifications(state, "initial_fact")
    assert set(collected).isdisjoint(set(initial_ids)), \
        "语义更新与初始事实提醒是两条独立流"


def _walk_notifications(state, kind, limit=10, max_pages=50):
    collected = []
    cursor = None
    for _guard in range(max_pages):
        path = f"/api/v2/notifications?limit={limit}&kind={kind}"
        if cursor:
            path += f"&cursor={cursor}"
        status, data = _get(state, path)
        assert status == 200
        collected.extend(n["notification_id"] for n in data["notifications"])
        if not data.get("next_cursor"):
            break
        cursor = data["next_cursor"]
    return collected


def test_semantic_update_ack_idempotent_via_page_flow(served):
    env = served
    state = env["state"]
    eid, _oid = _seed_open_event(state, "front-door", 5)
    conn = connect(state.db_path)
    publish_semantic_update(
        conn, event_id=eid, identity="d5:fp",
        text="新增理解 5", uncertainty="low", evidence_refs=[],
        t_created=3000.0, model_id="fake-semantic:1b",
        event_open_at_write=True)
    nid = conn.execute(
        "SELECT notification_id FROM event_notifications"
        " WHERE event_id=? AND kind='semantic_update'",
        (eid,)).fetchone()["notification_id"]
    conn.close()
    status, first = _post(state, "/api/v2/notifications/ack",
                          {"notification_id": nid})
    assert first["first_acknowledgement"] is True
    conn = connect(state.db_path)
    t1 = conn.execute(
        "SELECT acknowledged_at FROM event_notifications"
        " WHERE notification_id=?", (nid,)).fetchone()["acknowledged_at"]
    conn.close()
    status, second = _post(state, "/api/v2/notifications/ack",
                           {"notification_id": nid})
    assert second["first_acknowledgement"] is False
    conn = connect(state.db_path)
    t2 = conn.execute(
        "SELECT acknowledged_at FROM event_notifications"
        " WHERE notification_id=?", (nid,)).fetchone()["acknowledged_at"]
    conn.close()
    assert t1 == t2, "首次确认时间不被重复请求覆盖"


def test_workbench_page_contract_semantic_stream(served):
    env = served
    handler = _H("GET", "/", None, env["state"])
    handler.do_GET()
    html = handler.wfile.getvalue().decode("utf-8")
    assert "pollReminders('semantic_update'" in html, \
        "工作台必须有语义更新独立轮询流"
    assert "新增一版理解" in html
    assert "查看版本详情" in html, "语义更新横幅必须能打开版本详情"


def test_workbench_inline_js_real_syntax_check(served, tmp_path):
    """工作台内联 JS 真实语法检查（node --check）。

    背景：一处花括号失衡曾令整页初始化失效（横幅/时间线/健康全停摆），
    静态 200 与括号计数都无法可靠发现；本测试用真实工具链解析整段脚本。
    node 不可用时跳过并如实标注（本机与 CI 均预装 node）。
    """
    import re as _re
    import shutil
    import subprocess
    env = served
    handler = _H("GET", "/", None, env["state"])
    handler.do_GET()
    html = handler.wfile.getvalue().decode("utf-8")
    scripts = _re.findall(r"<script>(.*?)</script>", html, _re.S)
    assert scripts, "工作台必须带内联脚本"
    node = shutil.which("node")
    if node is None:
        pytest.skip("node 不可用：无法执行真实 JS 语法检查")
    page = tmp_path / "workbench-page.js"
    page.write_text(scripts[-1], encoding="utf-8")
    proc = subprocess.run([node, "--check", str(page)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, \
        "工作台内联 JS 语法错误（node --check）: " + proc.stderr[:800]


# ---------- R3 「已显示/已确认」事实链：API 级回归 ----------

def _detail(state, event_id):
    return _get(state, "/api/v2/events/" + event_id)


def _notif_row(db_path, notification_id):
    conn = connect(db_path)
    row = conn.execute(
        "SELECT user_confirmed_at, acknowledged_at, state FROM"
        " event_notifications WHERE notification_id=?",
        (notification_id,)).fetchone()
    conn.close()
    return row


def test_display_ack_does_not_write_user_confirmation(served):
    """初始事件被自动显示并提交 /ack 后：user_confirmed_at 仍为空，
    详情仍显示未人工确认（显示回执 ≠ 人工确认）。"""
    env = served
    state = env["state"]
    status, page = _get(state, "/api/v2/notifications?kind=initial_fact")
    assert status == 200 and page["notifications"]
    nid = page["notifications"][0]["notification_id"]
    assert page["notifications"][0]["user_confirmed"] is False
    status, ack = _post(state, "/api/v2/notifications/ack",
                        {"notification_id": nid})
    assert status == 200 and ack["first_acknowledgement"] is True
    status, detail = _detail(state, env["event_id"])
    assert status == 200
    notif = [n for n in detail["notifications"]
             if n["notification_id"] == nid][0]
    assert notif["state"] == "acknowledged", "已显示（自动回执）"
    assert notif["user_confirmed"] is False, "仍未经人工确认"
    assert notif["user_confirmed_at"] is None
    assert _notif_row(env["db_path"], nid)["user_confirmed_at"] is None


def test_manual_confirm_writes_user_confirmation_idempotent(served):
    """人工确认写 user_confirmed_at；重复请求幂等（首次时间不覆盖）；
    服务进程重启（同库新状态对象）后已确认事实保持。"""
    env = served
    state = env["state"]
    status, page = _get(state, "/api/v2/notifications?kind=initial_fact")
    nid = page["notifications"][0]["notification_id"]
    _post(state, "/api/v2/notifications/ack", {"notification_id": nid})
    status, first = _post(state, "/api/v2/notifications/user-confirm",
                          {"notification_id": nid})
    assert status == 200 and first["first_user_confirmation"] is True
    t1 = _notif_row(env["db_path"], nid)["user_confirmed_at"]
    assert t1 is not None
    status, second = _post(state, "/api/v2/notifications/user-confirm",
                           {"notification_id": nid})
    assert status == 200 and second["first_user_confirmation"] is False
    t2 = _notif_row(env["db_path"], nid)["user_confirmed_at"]
    assert t1 == t2, "重复确认不覆盖首次确认时间"
    status, detail = _detail(state, env["event_id"])
    notif = [n for n in detail["notifications"]
             if n["notification_id"] == nid][0]
    assert notif["user_confirmed"] is True
    state2 = WorkbenchState(env["db_path"])
    status, detail2 = _detail(state2, env["event_id"])
    notif2 = [n for n in detail2["notifications"]
              if n["notification_id"] == nid][0]
    assert notif2["user_confirmed"] is True, "重启后保持"
    assert notif2["user_confirmed_at"] == t1


# ---------- R6 语义呈现安全：模型文本不改变事实与告警 ----------

def test_semantic_text_cannot_mutate_events_or_alarms(served):
    """「无异常/安全/没有危险」类模型文本不得关闭事件、压制事实提醒、
    产生规则升级或改写 v1 事实——语义更新只追加描述与提醒。"""
    env = served
    eid = env["event_id"]     # 夹具事件：带 v1 初始事实与 initial_fact 提醒
    conn = connect(env["db_path"])
    v1_before = conn.execute(
        "SELECT text FROM event_descriptions WHERE event_id=? AND version=1",
        (eid,)).fetchone()["text"]
    state_before = conn.execute(
        "SELECT state, t_end FROM event_facts WHERE event_id=?",
        (eid,)).fetchone()
    publish_semantic_update(
        conn, event_id=eid, identity="safe:fp",
        text="观察到：无异常，一切安全，没有危险。",
        uncertainty="confirmed", evidence_refs=[], t_created=4000.0,
        model_id="fake-semantic:1b", event_open_at_write=True)
    conn.commit()
    state_after = conn.execute(
        "SELECT state, t_end FROM event_facts WHERE event_id=?",
        (eid,)).fetchone()
    v1_after = conn.execute(
        "SELECT text FROM event_descriptions WHERE event_id=? AND version=1",
        (eid,)).fetchone()["text"]
    notif = conn.execute(
        "SELECT COUNT(*) c FROM event_notifications WHERE event_id=?"
        " AND kind='initial_fact'", (eid,)).fetchone()["c"]
    escalation = conn.execute(
        "SELECT COUNT(*) c FROM event_escalations WHERE event_id=?",
        (eid,)).fetchone()["c"]
    conn.close()
    assert state_after["state"] == state_before["state"] == "open"
    assert state_after["t_end"] is None, "「无异常」文本不得关闭事件"
    assert v1_after == v1_before, "v1 初始事实不可变"
    assert notif == 1, "事实提醒不得被模型文本压制"
    assert escalation == 0, "模型文本不得产生规则升级"


def test_workbench_labels_model_versions_as_unverified(served):
    """工作台 v2+ 呈现合同：明确「模型补充描述，可能有误」+「模型自报」
    不确定性（未经系统核实）；v1 保持系统记录口径；模型原文保留可审查。"""
    import re as _re
    env = served
    eid, _oid = _seed_open_event(env["state"], "front-door", 7,
                                 with_evidence=False)
    conn = connect(env["db_path"])
    publish_semantic_update(
        conn, event_id=eid, identity="label:fp",
        text="观察到：无异常，一切安全。", uncertainty="confirmed",
        evidence_refs=[], t_created=5000.0, model_id="fake-semantic:1b",
        event_open_at_write=True)
    conn.close()
    handler = _H("GET", "/", None, env["state"])
    handler.do_GET()
    html = handler.wfile.getvalue().decode("utf-8")
    assert "模型补充描述（可能有误，待结合证据核对）" in html
    assert "模型自报不确定性：" in html and "未经系统核实" in html
    assert "不作为告警或事实依据" in html, "模型原文须附安全边界说明"
    assert "初始事实（系统记录）" in html, "v1 保持系统记录口径"
    # 横幅语义流同样带免责标注
    assert "（模型补充描述，可能有误）" in html
    # 脚本括号仍需平衡（防失衡回归叠加）
    scripts = _re.findall(r"<script>(.*?)</script>", html, _re.S)
    body = scripts[-1]
    assert body.count("{") == body.count("}")
    assert body.count("(") == body.count(")")


def test_semantic_banner_confirm_independent_from_initial_confirm(served):
    """语义更新横幅确认与初始事件确认互不混淆；各自幂等；未知 id 404。"""
    env = served
    state = env["state"]
    eid, _oid = _seed_open_event(state, "front-door", 5)
    conn = connect(state.db_path)
    publish_semantic_update(
        conn, event_id=eid, identity="d5:fp", text="新增理解 5",
        uncertainty="low", evidence_refs=[], t_created=3000.0,
        model_id="fake-semantic:1b", event_open_at_write=True)
    sem_nid = conn.execute(
        "SELECT notification_id FROM event_notifications"
        " WHERE event_id=? AND kind='semantic_update'",
        (eid,)).fetchone()["notification_id"]
    conn.close()
    status, page = _get(state, "/api/v2/notifications?kind=initial_fact")
    init_nid = [n for n in page["notifications"]
                if n["event_id"] == env["event_id"]][0]["notification_id"]
    assert _post(state, "/api/v2/notifications/user-confirm",
                 {"notification_id": sem_nid})[1] \
        ["first_user_confirmation"] is True
    assert _post(state, "/api/v2/notifications/user-confirm",
                 {"notification_id": init_nid})[1] \
        ["first_user_confirmation"] is True
    assert _notif_row(env["db_path"], sem_nid)["user_confirmed_at"] is not None
    assert _notif_row(env["db_path"],
                      init_nid)["user_confirmed_at"] is not None
    # 各自重复幂等
    assert _post(state, "/api/v2/notifications/user-confirm",
                 {"notification_id": sem_nid})[1] \
        ["first_user_confirmation"] is False
    assert _post(state, "/api/v2/notifications/user-confirm",
                 {"notification_id": init_nid})[1] \
        ["first_user_confirmation"] is False
    # 未知 id → 404（不得谎报成功）
    assert _post(state, "/api/v2/notifications/user-confirm",
                 {"notification_id": "notif:unknown"})[0] == 404


# ---------- R3 页面脚本可执行交互测试（node 运行时 + DOM/fetch 桩） ----------

_WORKBENCH_HARNESS_JS = r'''
const fs = require("fs");
const pagePath = process.argv[2];
const pageJs = fs.readFileSync(pagePath, "utf8");

const calls = [];            // {method, url, body}
let postMode = "ok";         // ok | 500 | reject —— 注入 POST /user-confirm
let verifyMode = "unconfirmed"; // unconfirmed | confirmed | missing | 500 | reject
                            // —— 注入 GET /api/v2/events/{id}（回读）
let postCount = 0;           // POST 成功次数（first_user_confirmation 语义）
const listSemConfirmed = { value: false };  // 通知列表里语义项的持久化事实

function el(tag) {
  return {
    tag: tag, children: [], textContent: "", className: "", hidden: false,
    disabled: false, onclick: null, href: "", target: "", value: "",
    classList: { add: function () {}, remove: function () {} },
    appendChild: function (c) { this.children.push(c); return c; },
    prepend: function (c) { this.children.unshift(c); },
    replaceChildren: function () { this.children = []; },
    addEventListener: function () {}, scrollIntoView: function () {},
    insertRow: function () {
      const r = el("tr");
      r.insertCell = function () { const c = el("td"); r.children.push(c); return c; };
      this.children.push(r); return r;
    },
    insertCell: function () { const c = el("td"); this.children.push(c); return c; },
  };
}
const byId = new Map();
function gid(id) {
  if (!byId.has(id)) byId.set(id, el("#" + id));
  return byId.get(id);
}
function resp(obj, status) {
  status = status || 200;
  return { ok: status >= 200 && status < 300, status: status,
           json: async function () { return obj; } };
}
const notifInitial = { notification_id: "nid-init-1", event_id: "e1",
  kind: "initial_fact", state: "acknowledged", created_at: 1,
  camera: "front-door", text: "v1", user_confirmed: false };
const notifSem = { notification_id: "nid-sem-1", event_id: "e1",
  kind: "semantic_update", state: "available", created_at: 2,
  camera: "front-door", text: "v2", user_confirmed: false };
function detailPayload(confirmedFlag) {
  // 真实合同：事件详情按事件返回**全部**通知（initial_fact 与 semantic_update
  // 都在，不分页）；回读按 notification_id 精确匹配。
  return { event_id: "e1", camera: "front-door", state: "open",
    t_start: 1, cls: "person", descriptions: [],
    notifications: confirmedFlag === null ? [] :
      [Object.assign({}, notifInitial,
        { user_confirmed: confirmedFlag,
          user_confirmed_at: confirmedFlag ? 123.0 : null }),
       Object.assign({}, notifSem,
        { user_confirmed: confirmedFlag,
          user_confirmed_at: confirmedFlag ? 456.0 : null })],
    semantic: { state: "none" } };
}
globalThis.window = { addEventListener: function () {} };
globalThis.document = {
  getElementById: gid,
  createElement: function (t) { return el(t); },
  createTextNode: function (t) { const n = el("#text"); n.textContent = t; return n; },
  querySelector: function () { return el("tbody"); },
  querySelectorAll: function () { return []; },
  addEventListener: function () {},
  body: el("body"),
};
globalThis.setInterval = function () { return 0; };
globalThis.clearInterval = function () {};
globalThis.fetch = async function (url, opts) {
  const method = (opts && opts.method) || "GET";
  calls.push({ method: method, url: url, body: opts && opts.body });
  if (method === "POST" && postMode === "reject") {
    throw new TypeError("network down");
  }
  if (method === "GET" && url.indexOf("/api/v2/events/") === 0) {
    if (verifyMode === "reject") throw new TypeError("verify network down");
    if (verifyMode === "500") return resp({ error: "boom" }, 500);
    if (verifyMode === "missing") return resp(detailPayload(null));
    return resp(detailPayload(verifyMode === "confirmed"));
  }
  if (url === "/api/cameras") return resp({ cameras: [] });
  if (url.indexOf("/api/health") === 0) return resp({ cameras: [] });
  if (url.indexOf("/api/v2/notifications?") === 0) {
    if (url.indexOf("kind=semantic_update") >= 0) {
      return resp({ notifications: [Object.assign({}, notifSem,
        { user_confirmed: listSemConfirmed.value })], next_cursor: null });
    }
    return resp({ notifications: [notifInitial], next_cursor: null });
  }
  if (url === "/api/v2/notifications/user-confirm" && method === "POST") {
    if (postMode === "500") return resp({ error: "boom" }, 500);
    postCount += 1;
    return resp({ ok: true, first_user_confirmation: postCount === 1 });
  }
  if (url === "/api/v2/notifications/ack") {
    return resp({ first_acknowledgement: true });
  }
  return resp({}, 404);
};

(async () => {
  const results = {};
  const tick = () => new Promise((r) => setImmediate(r));
  try {
    require("vm").runInThisContext(pageJs,
      { filename: "workbench-page.js" });   // 函数声明挂全局，可逐场景驱动
    await tick(); await tick(); await tick();
    const area = gid("confirm-area");
    const banner = gid("reminder-banner");
    const findBtn = (root, text) => root.children.find(
      (c) => c.tag === "button" && c.textContent.indexOf(text) >= 0);
    const hasBadge = (root) => root.children.some(
      (c) => c.textContent.indexOf("已人工确认") >= 0);
    const PENDING = "暂未核实";

    // ===== 详情：初始打开（未确认 → 按钮可点）=====
    await openEventDetail("e1"); await tick();
    const btnD = findBtn(area, "人工确认");
    results.detailOffersManualConfirm = !!btnD;

    // D1 POST 成功 + 回读 500 → 待核实：按钮恢复、无徽标、不停「正在…」
    postMode = "ok"; verifyMode = "500";
    btnD.onclick(); await tick(); await tick(); await tick();
    results.detailPostOkGet500Pending =
      btnD.disabled === false
      && btnD.textContent.indexOf("人工确认") >= 0
      && btnD.textContent.indexOf("正在") < 0
      && !hasBadge(area)
      && gid("zone-message").textContent.indexOf(PENDING) >= 0;

    // D2 POST 成功 + 回读断网 → 同上
    verifyMode = "reject";
    btnD.onclick(); await tick(); await tick(); await tick();
    results.detailPostOkGetRejectPending =
      btnD.disabled === false && !hasBadge(area)
      && btnD.textContent.indexOf("正在") < 0
      && gid("zone-message").textContent.indexOf(PENDING) >= 0;

    // D3 POST 成功 + 回读缺目标通知 → 同上（不得当作已核实）
    verifyMode = "missing";
    btnD.onclick(); await tick(); await tick(); await tick();
    results.detailPostOkGetMissingPending =
      btnD.disabled === false && !hasBadge(area)
      && gid("zone-message").textContent.indexOf(PENDING) >= 0;

    // D4 POST 成功 + 回读返回未确认 → 恢复未确认，无徽标
    verifyMode = "unconfirmed";
    btnD.onclick(); await tick(); await tick(); await tick();
    results.detailPostOkGetUnconfirmed =
      btnD.disabled === false && !hasBadge(area)
      && gid("zone-message").textContent.indexOf("尚未显示确认") >= 0;

    // D5 恢复服务（回读已确认）→ 重试核实成功 → 徽标 + 无按钮
    verifyMode = "confirmed";
    btnD.onclick(); await tick(); await tick(); await tick();
    results.detailVerifiedBadge =
      hasBadge(area) && !findBtn(area, "人工确认");
    results.detailBadgeBackedByGet = calls.some(
      (c) => c.method === "GET" && c.url.indexOf("/api/v2/events/") === 0);

    // D6 POST 失败（500）→ 不进入核实回读，无徽标，按钮恢复
    verifyMode = "unconfirmed";
    await openEventDetail("e1"); await tick();
    const btnD2 = findBtn(area, "人工确认");
    postMode = "500";
    const tailBefore = calls.length;
    btnD2.onclick(); await tick(); await tick();
    results.detailPost500Restores =
      btnD2.disabled === false && !hasBadge(area)
      && gid("zone-message").textContent.indexOf("未成功") >= 0;
    results.detailPost500NoVerifyRead = !calls.slice(tailBefore).some(
      (c) => c.method === "GET" && c.url.indexOf("/api/v2/events/") === 0);
    postMode = "ok";

    // ===== 横幅：语义更新确认按钮（初始未确认）=====
    let semBtn = null;
    for (const item of banner.children) {
      const b = item.children.find(
        (c) => c.tag === "button" && c.textContent.indexOf("确认已看到") >= 0);
      if (b) { semBtn = b; break; }
    }
    results.bannerOffersManualConfirm = !!semBtn;
    if (semBtn) {
      // B0 POST 失败（500）→ 按钮恢复原始文字与可点、提示错误、库未被假确认
      verifyMode = "unconfirmed"; postMode = "500";
      let postBefore = postCount;
      semBtn.onclick(); await tick(); await tick(); await tick();
      results.bannerPostFail500RestoresText =
        semBtn.disabled === false && semBtn.textContent === "确认已看到";
      results.bannerPostFail500Hint =
        gid("zone-message").textContent.indexOf("未成功") >= 0;
      results.bannerPostFail500NoDbWrite = postCount === postBefore;
      results.bannerPostFail500NoBadge = !semBtn.textContent.startsWith("正在");

      // B0b POST 失败（断网）→ 同上
      postMode = "reject";
      semBtn.onclick(); await tick(); await tick(); await tick();
      results.bannerPostFailRejectRestoresText =
        semBtn.disabled === false && semBtn.textContent === "确认已看到";
      results.bannerPostFailRejectHint =
        gid("zone-message").textContent.indexOf("网络异常") >= 0;
      results.bannerPostFailRejectNoDbWrite = postCount === postBefore;
      postMode = "ok";

      // B1 POST 成功 + 回读 500
      verifyMode = "500";
      semBtn.onclick(); await tick(); await tick(); await tick();
      results.bannerPostOkGet500Pending =
        semBtn.disabled === false
        && semBtn.textContent.indexOf("已人工确认") < 0
        && semBtn.textContent.indexOf("正在") < 0
        && gid("zone-message").textContent.indexOf(PENDING) >= 0;

      // B2 回读断网
      verifyMode = "reject";
      semBtn.onclick(); await tick(); await tick(); await tick();
      results.bannerPostOkGetRejectPending =
        semBtn.disabled === false
        && semBtn.textContent.indexOf("已人工确认") < 0;

      // B3 回读缺目标通知
      verifyMode = "missing";
      semBtn.onclick(); await tick(); await tick(); await tick();
      results.bannerPostOkGetMissingPending =
        semBtn.disabled === false
        && semBtn.textContent.indexOf("已人工确认") < 0;

      // B4 回读返回未确认
      verifyMode = "unconfirmed";
      semBtn.onclick(); await tick(); await tick(); await tick();
      results.bannerPostOkGetUnconfirmed =
        semBtn.disabled === false
        && semBtn.textContent.indexOf("已人工确认") < 0
        && gid("zone-message").textContent.indexOf("尚未显示确认") >= 0;

      // B5 恢复（回读已确认）→ 徽标
      verifyMode = "confirmed";
      semBtn.onclick(); await tick(); await tick(); await tick();
      results.bannerVerifiedBadge =
        semBtn.textContent.indexOf("已人工确认") >= 0 && semBtn.disabled;
    }

    // ===== 已核实项不再渲染确认按钮（刷新/重开后以服务端事实渲染）=====
    listSemConfirmed.value = true;
    await pollReminders("semantic_update", "semCursorX", new Map(), "x");
    await tick();
    const items = banner.children.filter(
      (c) => c.className === "reminder-item");
    const last = items[items.length - 1];
    results.confirmedItemHasNoButton = !last
      || !last.children.some((c) => c.tag === "button"
        && c.textContent.indexOf("确认已看到") >= 0);
  } catch (err) {
    results.harnessError = String(err && err.stack || err);
  }
  let ok = true;
  Object.keys(results).forEach((k) => { if (results[k] !== true) ok = false; });
  console.log(JSON.stringify({ ok: ok, results: results }));
  process.exit(ok ? 0 : 1);
})();
'''


def test_workbench_confirm_buttons_executable_behavior(served, tmp_path):
    """可执行交互测试：node 运行时执行页面脚本，验证人工确认按钮真实
    调用 /user-confirm（而非 /ack）、user_confirmed 门控、非 2xx/网络
    异常恢复可点击并提示、成功后重读服务端状态、已确认不重复提示。
    node 不可用时跳过并如实标注。"""
    import re as _re
    import shutil
    import subprocess
    env = served
    handler = _H("GET", "/", None, env["state"])
    handler.do_GET()
    html = handler.wfile.getvalue().decode("utf-8")
    scripts = _re.findall(r"<script>(.*?)</script>", html, _re.S)
    assert scripts, "工作台必须带内联脚本"
    node = shutil.which("node")
    if node is None:
        pytest.skip("node 不可用：无法执行页面脚本交互测试")
    page = tmp_path / "workbench-page.js"
    page.write_text(scripts[-1], encoding="utf-8")
    harness = tmp_path / "harness.js"
    harness.write_text(_WORKBENCH_HARNESS_JS, encoding="utf-8")
    proc = subprocess.run([node, str(harness), str(page)],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (
        "交互测试失败\nstdout: " + proc.stdout[-1500:]
        + "\nstderr: " + proc.stderr[-800:])
    data = json.loads(proc.stdout)
    assert data["ok"] is True, data["results"]


def test_detail_exposes_structured_semantic_fields(served):
    env = served
    _seed_with_evidence(env)
    updater, stop, _provider = _updater(env, "ok")
    _drain_once(updater)
    stop.set()
    state = WorkbenchState(env["db_path"])
    detail = state.event_fact_detail("front-door:run:event:7")
    vlm = [d for d in detail["descriptions"] if d["source"] == "vlm"]
    assert len(vlm) == 1, "恰一条 vlm 语义描述"
    v2 = vlm[0]
    assert v2["observed"] and v2["inference"]
    assert v2["uncertainty"] in ("confirmed", "low", "high")
    assert v2["evidence_digest"]
    assert v2["model_id"] == "fake-semantic:1b"
    assert "payload" not in v2, "内部 payload 不下发"
    raw = json.dumps(detail, ensure_ascii=False)
    assert "evidence_path" not in raw and "rtsp://" not in raw
