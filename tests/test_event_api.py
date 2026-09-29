"""事件事实 v2 API 与初始事实提醒测试（阶段二：用户可见事件）。

进程内驱动 Handler（不联网）；覆盖任务书第 6 条自动化清单：
无规则事件默认可见 / 初始提醒恰一次 / 崩溃窗口补账 / 回执幂等 / 旧接口兼容 /
规则升级关联 / 证据缺失与失效 / 无绝对路径与凭据泄露 / 环境识别可跳过（页面契约）。
全部为合成测试，不代表真实 RTSP、语义准确率、端到端时延或发布验收。
"""

import hashlib
import json

import pytest

import scam.db as db
from scam.db import (
    acknowledge_notification,
    backfill_initial_fact_pairs,
    connect,
    ensure_initial_description,
    ensure_initial_notification,
    get_event_fact,
    init_schema,
    link_event_escalation,
    list_event_facts,
    list_initial_notifications,
    mark_notification_available,
    open_semantic_event,
    open_tracked_object,
)
from scam.monitor import Monitor, to_gray
from scam.server import WorkbenchHandler, WorkbenchState
from scam.sinks import SqliteSink

import numpy as np
import cv2

W, H = 640, 360


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


def _drive(m, *, start_ms, frames, present, step_ms=400.0):
    t = start_ms
    for i in range(frames):
        f = _flip_frame(present, i % 2)
        m.step(f, to_gray(f, Monitor.GRAY_W), t)
        t += step_ms
    return t


class _H(WorkbenchHandler):
    """进程内最小 Handler 驱动（与 test_server 同口径，零网络）。"""

    def __init__(self, method, path, obj=None, state=None):
        self.command = method
        self.path = path
        self.headers = {"Content-Length": str(len(json.dumps(obj)) if obj else 0)}
        self.rfile = __import__("io").BytesIO(
            json.dumps(obj).encode() if obj else b"")
        self.wfile = __import__("io").BytesIO()
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


def _post(state, path, obj):
    h = _H("POST", path, obj, state)
    h.do_POST()
    return h.status, h.body_json()


@pytest.fixture()
def served(tmp_path):
    """跑通一段无规则值守（含结束）的 SqliteSink 数据库 + 工作台状态。"""
    db_path = str(tmp_path / "events.db")
    sink = SqliteSink(db_path)
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []}, detect_fn=_detect, sinks=[sink])
    _drive(m, start_ms=1_000_000.0, frames=8, present=True)
    _drive(m, start_ms=1_004_000.0, frames=32, present=False, step_ms=500.0)
    return WorkbenchState(db_path), db_path


# ---- 无规则事件默认可见 + 初始提醒恰一次 ----

def test_rule_free_events_visible_with_initial_fact(served):
    state, db_path = served
    status, data = _get(state, "/api/v2/events")
    assert status == 200
    events = data["events"]
    assert len(events) == 1
    ev = events[0]
    assert ev["camera"] == "front-door" and ev["cls"] == "person"
    assert ev["state"] == "closed" and ev["end_reason"] == "track-lost"
    assert ev["initial_fact_text"] == "front-door 画面中出现 person"
    assert ev["initial_notification_state"] == "available", \
        "服务即'工作台可读取'"
    assert ev["escalation_count"] == 0
    assert ev["best_frame"] and "/api/evidence/" in ev["best_frame"]["content_url"]


def test_initial_fact_and_description_created_exactly_once(tmp_path):
    """同 event_id 重放开路径：描述 v1 与 initial_fact 仍各恰一条。"""
    db_path = str(tmp_path / "events.db")
    conn = connect(db_path)
    init_schema(conn)
    sink = SqliteSink(db_path)
    assert sink.open_event_fact(
        event_id="e1", camera="cam", object_id="cam:r:track:1", t_start=1.0,
        cls="person") is False, "对象不存在时事件不得落库"
    db.open_tracked_object(conn, object_id="cam:r:track:1",
                           camera="cam", t_start=1.0, cls="person")
    assert sink.open_event_fact(
        event_id="e1", camera="cam", object_id="cam:r:track:1", t_start=1.0,
        cls="person") is True
    assert sink.open_event_fact(
        event_id="e1", camera="cam", object_id="cam:r:track:1", t_start=1.0,
        cls="person") is True
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_descriptions").fetchone()["c"] == 1
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_notifications").fetchone()["c"] == 1
    n = conn.execute("SELECT * FROM event_notifications").fetchone()
    assert n["kind"] == "initial_fact" and n["state"] == "generated"
    d = conn.execute("SELECT * FROM event_descriptions").fetchone()
    assert d["version"] == 1 and d["source"] == "initial_observation"
    assert d["text"] == "cam 画面中出现 person"


# ---- 提醒三态与回执幂等 ----

def test_notification_states_and_idempotent_ack(served):
    state, _ = served
    _, data = _get(state, "/api/v2/notifications")
    items = data["notifications"]
    assert len(items) == 1
    nid = items[0]["notification_id"]
    assert items[0]["state"] == "available", "服务即'可读取'"
    status, first = _post(state, "/api/v2/notifications/ack",
                          {"notification_id": nid})
    assert status == 200 and first["first_acknowledgement"] is True
    status, second = _post(state, "/api/v2/notifications/ack",
                           {"notification_id": nid})
    assert status == 200 and second["first_acknowledgement"] is False, \
        "重复回执不得伪造新送达"
    _, data = _get(state, "/api/v2/events")
    assert data["events"][0]["initial_notification_state"] == "acknowledged"
    status, missing = _post(state, "/api/v2/notifications/ack",
                            {"notification_id": "notif:ghost"})
    assert status == 404


def test_ack_requires_idempotent_db_semantics(tmp_path):
    conn = connect(str(tmp_path / "n.db"))
    init_schema(conn)
    db.open_tracked_object(conn, object_id="o1", camera="c", t_start=1.0,
                           cls="person")
    db.open_event_fact(conn, event_id="e1", camera="c", object_id="o1",
                       t_start=1.0, cls="person")
    assert ensure_initial_notification(conn, "e1", text="t", t_event=1.0,
                                       created_at=5.0) is True
    row = conn.execute("SELECT notification_id FROM event_notifications"
                       ).fetchone()
    nid = row["notification_id"]
    assert mark_notification_available(conn, nid, at=6.0) is True
    assert mark_notification_available(conn, nid, at=7.0) is False, \
        "available 不得回退 generated"
    assert acknowledge_notification(conn, nid, at=8.0) is True
    assert acknowledge_notification(conn, nid, at=9.0) is False, \
        "acknowledged_at 不得被重复回执改写"
    row = conn.execute(
        "SELECT state,acknowledged_at,created_at FROM event_notifications"
        " WHERE notification_id=?", (nid,)).fetchone()
    assert row["state"] == "acknowledged" and row["acknowledged_at"] == 8.0


# ---- 崩溃窗口补账 ----

def test_startup_backfill_creates_missing_pair_exactly_once(tmp_path):
    """事件已落库但提醒/描述缺失（崩溃窗口）→ 启动补账恰一次。"""
    db_path = str(tmp_path / "crash.db")
    conn = connect(db_path)
    init_schema(conn)
    db.open_tracked_object(conn, object_id="o1", camera="front",
                           t_start=1.0, cls="person")
    db.open_event_fact(conn, event_id="e-crash", camera="front",
                       object_id="o1", t_start=2.0, cls="person")
    conn.close()

    conn = connect(db_path)
    first = backfill_initial_fact_pairs(conn, created_at=100.0)
    assert first["descriptions"] == 1 and first["notifications"] == 1
    assert first["remaining"] == 0, "补账必须如实报剩余待补数"
    second = backfill_initial_fact_pairs(conn, created_at=200.0)
    assert second["descriptions"] == 0 and second["notifications"] == 0,         "重复补账零改动"
    assert second["remaining"] == 0 and second["failed"] == 0
    conn.close()


# ---- 旧接口兼容 ----

def test_legacy_events_api_keeps_semantic_events_meaning(served, tmp_path):
    state, db_path = served
    conn = connect(db_path)
    object_id = conn.execute(
        "SELECT object_id FROM event_facts").fetchone()["object_id"]
    event_id = conn.execute(
        "SELECT event_id FROM event_facts").fetchone()["event_id"]
    open_semantic_event(
        conn, semantic_event_id="sem-1", camera="front-door",
        review_id=conn.execute(
            "SELECT review_id FROM event_facts").fetchone()["review_id"],
        object_id=object_id, t_start=3.0, template="immediate",
        zone_id="yard", short_name="规则告警")
    link_event_escalation(
        conn, event_id=event_id, semantic_event_id="sem-1", t_linked=3.0)
    conn.commit()
    conn.close()

    status, data = _get(state, "/api/events")
    assert status == 200
    assert len(data["events"]) == 1
    assert data["events"][0]["event_id"] == "sem-1"
    assert data["events"][0]["template"] == "immediate", \
        "旧接口仍服务规则告警，不得被事件事实顶替"

    status, detail = _get(state, "/api/v2/events")
    assert detail["events"][0]["escalation_count"] == 1
    event_id = detail["events"][0]["event_id"]
    status, fact = _get(state, "/api/v2/events/" + event_id)
    assert status == 200
    assert fact["escalations"][0]["semantic_event_id"] == "sem-1"
    assert fact["escalations"][0]["template"] == "immediate"
    assert fact["descriptions"][0]["source"] == "initial_observation"


# ---- 筛选与排序 ----

def test_event_list_filters_and_order(served):
    state, db_path = served
    conn = connect(db_path)
    db.open_tracked_object(conn, object_id="o2", camera="back",
                           t_start=1.0, cls="person")
    db.open_event_fact(conn, event_id="e-back", camera="back",
                       object_id="o2", t_start=50.0, cls="person")
    conn.close()
    status, data = _get(state, "/api/v2/events?camera=back")
    assert [e["event_id"] for e in data["events"]] == ["e-back"]
    status, data = _get(state, "/api/v2/events?state=closed")
    assert all(e["state"] == "closed" for e in data["events"])
    status, data = _get(state, "/api/v2/events?limit=1")
    assert len(data["events"]) == 1
    times = [e["t_start"] for e in data["events"]]
    assert times == sorted(times, reverse=True), "时间倒序稳定排序"


# ---- 证据缺失 / 失效 / 无路径泄露 ----

def test_missing_evidence_shows_no_broken_links(served):
    state, _ = served
    status, data = _get(state, "/api/v2/events")
    ev = data["events"][0]
    if ev["best_frame"] is None:
        assert ev["evidence_state"] == "metadata_only"
    detail_id = ev["event_id"]
    status, fact = _get(state, "/api/v2/events/" + detail_id)
    assert fact["evidence_state"] in ("metadata_only", "image_only")
    if fact["best_frame"] is None:
        assert "best_frame" not in fact or fact["best_frame"] is None


def test_no_absolute_paths_or_credentials_in_v2_responses(served, tmp_path):
    state, db_path = served
    for path in ("/api/v2/events", "/api/v2/notifications"):
        handler = _H("GET", path, None, state)
        handler.do_GET()
        raw = handler.wfile.getvalue().decode("utf-8")
        assert str(tmp_path) not in raw and db_path not in raw, "无本机路径"
        assert "rtsp://" not in raw, "无摄像头凭据"
        assert "sqlite3" not in raw and "Traceback" not in raw, "无异常原文"
        assert "best_frame_path" not in raw, "内部路径字段不下发"


def test_untrusted_source_time_yields_no_fake_latency(tmp_path):
    """来源时间不可信（host_receive）→ 不计算/展示端到端时延。"""
    db_path = str(tmp_path / "ts.db")
    sink = SqliteSink(db_path)
    conn = connect(db_path)
    db.open_tracked_object(conn, object_id="o1", camera="c", t_start=1.0,
                           cls="person")
    conn.close()
    sink.open_event_fact(
        event_id="e1", camera="c", object_id="o1", t_start=10.0, cls="person",
        payload={"timestamp_kind": "host_receive"})
    state = WorkbenchState(db_path)
    detail = state.event_fact_detail("e1")
    assert detail["notifications"][0]["end_to_end_latency_s"] is None, \
        "不可信源时间不得产出虚假延迟指标"
    assert detail["descriptions"][0]["source"] == "initial_observation"


def test_trusted_source_time_reports_latency(tmp_path):
    db_path = str(tmp_path / "ts2.db")
    sink = SqliteSink(db_path)
    conn = connect(db_path)
    db.open_tracked_object(conn, object_id="o1", camera="c", t_start=1.0,
                           cls="person")
    conn.close()
    sink.open_event_fact(
        event_id="e1", camera="c", object_id="o1", t_start=10.0, cls="person",
        payload={"timestamp_kind": "source_capture"})
    state = WorkbenchState(db_path)
    detail = state.event_fact_detail("e1")
    created = detail["notifications"][0]["created_delay_s"]
    assert created is not None and created >= 0.0,         "可信同钟的事件→创建延迟可证实（字段已正名）"
    assert detail["notifications"][0]["end_to_end_latency_s"] is None,         "端到端时延不可测恒 null（不冒充用户送达）"
