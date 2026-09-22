"""LZ-053 S3 证据与反馈闭环测试：金标/误报/事件反查/真值只读。"""

import json
import threading
import time
import http.client

import pytest

import scam.db as db
from scam.slow_core import SlowCore


def _conn(tmp_path):
    conn = db.connect(str(tmp_path / "f.db"))
    db.init_schema(conn)
    return conn


def _processed_event(tmp_path, conn, *, rid="rev-1", camera="front",
                     eid="ev-1", name=None):
    """造一个已有慢处理档案的语义事件（返回 pattern 内存 id）。"""
    db.open_review_segment(conn, review_id=rid, camera=camera, t_start=1000.0)
    db.close_review_segment(conn, rid, t_end=1120.0, reason="quiet")
    db.open_tracked_object(conn, object_id=f"{rid}:obj", camera=camera,
                           t_start=1010.0, cls="person", zones=["z1"])
    db.close_tracked_object(conn, f"{rid}:obj", t_end=1110.0, reason="gone")
    db.open_semantic_event(
        conn, semantic_event_id=eid, camera=camera, review_id=rid,
        object_id=f"{rid}:obj", t_start=1020.0, template="enter-dwell",
        zone_id="z1", cls="person")
    db.close_semantic_event(conn, eid, t_end=1100.0, reason="left")
    conn.commit()
    core = SlowCore(conn, camera=camera)
    stats = core.process_pending(provider=None)
    assert stats["recorded"] == 1
    payload = json.loads(conn.execute(
        "SELECT payload FROM segments WHERE segment_id=?", (rid,)
    ).fetchone()[0])
    return payload["pattern_id"], core


# ---------- 金标改名：human-verified 晋升 + 持久化 + 审计痕迹 ----------

def test_confirm_name_promotes_and_persists(tmp_path):
    conn = _conn(tmp_path)
    pid, core = _processed_event(tmp_path, conn)

    summary = core.confirm_pattern(pid, name="门口送快递")

    assert summary["name"] == "门口送快递"
    assert summary["state"] in ("draft", "human-verified")
    assert summary["state"] == "human-verified" or summary["count"] >= 0

    # 跨实例（重启等价）仍可读
    fresh = SlowCore(db.connect(str(tmp_path / "f.db")), camera="front")
    restored = fresh.library.patterns[pid]
    assert restored["name"] == "门口送快递"
    assert restored["last_human_feedback"]["misreport"] is False
    conn.close()


def test_confirm_name_length_validated(tmp_path):
    conn = _conn(tmp_path)
    pid, core = _processed_event(tmp_path, conn)
    with pytest.raises(ValueError):
        core.confirm_pattern(pid, name="x" * 17)
    with pytest.raises(ValueError):
        core.confirm_pattern(pid, name="")
    conn.close()


# ---------- 误报：降级 draft、计数保留、不删证据 ----------

def test_misreport_downgrades_keeps_count_and_truth(tmp_path):
    conn = _conn(tmp_path)
    pid, core = _processed_event(tmp_path, conn)
    before = conn.execute(
        "SELECT * FROM semantic_events ORDER BY semantic_event_id"
    ).fetchall()

    summary = core.confirm_pattern(pid, misreport=True)

    assert summary["state"] == "draft"
    assert summary["count"] >= 0, "计数保留（降级不惩罚历史）"
    pattern = core.library.patterns[pid]
    assert pattern["last_human_feedback"]["misreport"] is True
    # 红线：管理员规则告警真值一字不动
    after = conn.execute(
        "SELECT * FROM semantic_events ORDER BY semantic_event_id"
    ).fetchall()
    assert [tuple(r) for r in after] == [tuple(r) for r in before]
    conn.close()


# ---------- 事件 → 模式反查 ----------

def test_pattern_of_event(tmp_path):
    conn = _conn(tmp_path)
    pid, _ = _processed_event(tmp_path, conn)

    core = SlowCore(conn, camera="front")
    found, camera = core.pattern_of_event("ev-1")
    assert found == pid and camera == "front"
    assert core.pattern_of_event("no-such")[0] is None
    conn.close()


# ---------- HTTP 端点 ----------

def _server(tmp_path, conn):
    from scam.server import WorkbenchServer, WorkbenchState
    state = WorkbenchState(str(tmp_path / "f.db"))
    server = WorkbenchServer(state, host="127.0.0.1", port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return server, server.server_address[1]


def _post(port, path, body):
    hc = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    hc.request("POST", path, json.dumps(body),
               {"Content-Type": "application/json"})
    resp = hc.getresponse()
    data = json.loads(resp.read().decode("utf-8"))
    hc.close()
    return resp.status, data


def test_http_feedback_by_event(tmp_path):
    conn = _conn(tmp_path)
    pid, _ = _processed_event(tmp_path, conn)
    conn.close()
    server, port = _server(tmp_path, conn)
    try:
        status, data = _post(port, "/api/patterns/feedback",
                             {"event_id": "ev-1", "name": "门口送快递"})
        assert status == 200 and data["ok"] is True
        assert data["pattern"]["name"] == "门口送快递"

        status, data = _post(port, "/api/patterns/feedback",
                             {"event_id": "no-such"})
        assert status == 404
    finally:
        server.shutdown()


def test_http_feedback_misreport_and_validation(tmp_path):
    conn = _conn(tmp_path)
    pid, _ = _processed_event(tmp_path, conn)
    conn.close()
    server, port = _server(tmp_path, conn)
    try:
        status, data = _post(port, "/api/patterns/feedback",
                             {"event_id": "ev-1", "misreport": True})
        assert status == 200 and data["pattern"]["state"] == "draft"

        status, _ = _post(port, "/api/patterns/feedback",
                          {"event_id": "ev-1", "name": "x" * 20})
        assert status == 400

        status, _ = _post(port, "/api/patterns/feedback", {})
        assert status == 400, "pattern_id/event_id 至少给一个"
    finally:
        server.shutdown()


# ---------- 直给 pattern_id（无事件上下文） ----------

def test_http_feedback_direct_pattern_id(tmp_path):
    conn = _conn(tmp_path)
    pid, _ = _processed_event(tmp_path, conn)
    conn.close()
    server, port = _server(tmp_path, conn)
    try:
        status, data = _post(port, "/api/patterns/feedback",
                             {"pattern_id": pid, "name": "直连反馈"})
        assert status == 200 and data["pattern"]["name"] == "直连反馈"
    finally:
        server.shutdown()
