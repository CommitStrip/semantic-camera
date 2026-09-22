"""LZ-057 通知出口测试：游标增量/双出口/降级/校验/观测（不真发网络）。"""

import json
import threading
import time

import pytest

import scam.db as db
from scam.notify import (NotificationHub, WebhookOutlet,
                         assert_webhook_target)


def _conn(tmp_path):
    conn = db.connect(str(tmp_path / "n.db"))
    db.init_schema(conn)
    return conn


def _event(conn, eid, camera="front", t_start=1000.0):
    db.open_review_segment(conn, review_id=f"{eid}:rev", camera=camera,
                           t_start=t_start - 2.0)
    db.close_review_segment(conn, f"{eid}:rev", t_end=t_start + 30.0,
                            reason="quiet")
    db.open_tracked_object(conn, object_id=f"{eid}:obj", camera=camera,
                           t_start=t_start, cls="person")
    db.close_tracked_object(conn, f"{eid}:obj", t_end=t_start + 20.0,
                            reason="gone")
    db.open_semantic_event(
        conn, semantic_event_id=eid, camera=camera, review_id=f"{eid}:rev",
        object_id=f"{eid}:obj", t_start=t_start, template="enter-dwell",
        zone_id="z1", cls="person")
    db.close_semantic_event(conn, eid, t_end=t_start + 5.0, reason="left")
    conn.commit()


def _wait_until(predicate, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


class SpyOutlet:
    """替身出口：记录发布，可注入失败。"""

    def __init__(self, fail=False):
        self.published = []
        self.fail = fail

    def publish(self, event):
        if self.fail:
            return False
        self.published.append(event)
        return True

    def stop(self):
        pass

    def status(self):
        return {"configured": True, "spy": True}


# ---------- 游标增量：只发新事件，重启窗口重发 ----------

def test_hub_publishes_incrementally(tmp_path):
    conn = _conn(tmp_path)
    _event(conn, "ev-1", t_start=time.time() - 60)
    conn.close()

    hub = NotificationHub(str(tmp_path / "n.db"), {})
    spy = SpyOutlet()
    hub.webhook = spy                       # 注入替身出口
    hub.start()
    try:
        assert _wait_until(lambda: hub.counters["events_seen"] >= 1)
        seen_ids = {e["event_id"] for e in spy.published}
        assert "ev-1" in seen_ids
        first_seen = hub.counters["events_seen"]

        # 新事件进来后被发；旧窗口事件允许重发（at-least-once）但游标推进
        writer = db.connect(str(tmp_path / "n.db"))
        _event(writer, "ev-2", t_start=time.time() - 1)
        writer.close()
        assert _wait_until(lambda: hub.counters["events_seen"] > first_seen)
        seen_ids = {e["event_id"] for e in spy.published}
        assert "ev-2" in seen_ids
        assert hub.counters["webhook_failed"] == 0
    finally:
        assert hub.stop(timeout=5.0) is True


# ---------- 出口失败只计数，不中断 ----------

def test_outlet_failure_is_counted_not_fatal(tmp_path):
    conn = _conn(tmp_path)
    _event(conn, "ev-x", t_start=time.time() - 10)
    conn.close()

    hub = NotificationHub(str(tmp_path / "n.db"), {})
    hub.webhook = SpyOutlet(fail=True)
    hub.start()
    try:
        assert _wait_until(lambda: hub.counters["webhook_failed"] >= 1)
        assert hub._thread.is_alive(), "出口失败不得终止通知线程"
        snap = hub.snapshot()
        assert snap["counters"]["webhook_failed"] >= 1
    finally:
        assert hub.stop(timeout=5.0) is True


# ---------- 未配置出口：零发布零失败 ----------

def test_no_outlets_configured_is_idle(tmp_path):
    conn = _conn(tmp_path)
    _event(conn, "ev-i", t_start=time.time() - 5)
    conn.close()

    hub = NotificationHub(str(tmp_path / "n.db"), {})
    hub.start()
    try:
        assert _wait_until(lambda: hub.counters["rounds"] >= 1)
        snap = hub.snapshot()
        assert snap["mqtt"] is None and snap["webhook"] is None
        assert snap["counters"]["events_seen"] >= 1, \
            "事件照常计数（可见），只是没有出口"
    finally:
        assert hub.stop(timeout=5.0) is True


# ---------- webhook 目标校验 ----------

def test_webhook_target_validation():
    assert assert_webhook_target("http://127.0.0.1:1880/hook") in \
        ("loopback", "loopback+private")
    with pytest.raises(ValueError):
        assert_webhook_target("ftp://x/hook")
    with pytest.raises(ValueError):
        assert_webhook_target("http://user:pass@host/hook")
    with pytest.raises(ValueError):
        assert_webhook_target("http:///no-host")


def test_webhook_outlet_rejects_bad_url_at_construction():
    outlet = WebhookOutlet({"url": "javascript:alert(1)"})
    assert outlet.error is not None
    assert outlet.publish({"x": 1}) is False


# ---------- MQTT 缺席降级 ----------

def test_mqtt_outlet_degrades_without_paho(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_paho(name, *a, **k):
        if name.startswith("paho"):
            raise ImportError(name)
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_paho)
    from scam.notify import MqttOutlet
    outlet = MqttOutlet({"host": "127.0.0.1"})
    assert outlet.client is None
    assert "paho" in (outlet.error or "")
    assert outlet.publish({"camera": "c"}) is False


# ---------- 载荷最小化 ----------

def test_payload_is_minimal_and_stable(tmp_path):
    conn = _conn(tmp_path)
    _event(conn, "ev-p", t_start=time.time() - 5)
    row = conn.execute(
        "SELECT * FROM semantic_events WHERE semantic_event_id='ev-p'"
    ).fetchone()
    conn.close()
    from scam.notify import _sanitize_event
    payload = _sanitize_event(row)
    assert set(payload) == {
        "schema", "event_id", "camera", "t_start", "t_end", "state",
        "cls", "conf", "zone_id", "template", "severity", "short_name"}
    assert payload["schema"] == "scam.notify/v1"
    json.dumps(payload)                     # 可序列化


# ---------- LZ-065 P0-2：运行期失败不丢（游标成败感知） ----------

def test_runtime_failure_keeps_event_for_redelivery(tmp_path):
    conn = _conn(tmp_path)
    _event(conn, "ev-keep", t_start=time.time() - 5)
    conn.close()
    db_path = str(tmp_path / "n.db")

    hub = NotificationHub(db_path, {})
    flaky = SpyOutlet()
    flaky.fail = True
    hub.webhook = flaky
    hub.start()
    try:
        assert _wait_until(lambda: hub.counters["webhook_failed"] >= 1)
        cursor_row = db.connect(db_path).execute(
            "SELECT value FROM meta WHERE key='notify:cursor'").fetchone()
        assert cursor_row is None or float(cursor_row[0]) <             time.time() - 4, "失败事件的游标不得越过它"

        flaky.fail = False                    # 出口恢复
        assert _wait_until(
            lambda: hub.counters["webhook_ok"] >= 1, timeout=15),             "恢复后必须重投该事件（运行期失败不永久丢）"
        delivered = {e["event_id"] for e in flaky.published}
        assert "ev-keep" in delivered
    finally:
        assert hub.stop(timeout=5.0) is True


def test_poison_event_dropped_after_attempt_limit(tmp_path):
    conn = _conn(tmp_path)
    _event(conn, "ev-poison", t_start=time.time() - 5)
    conn.close()
    db_path = str(tmp_path / "n.db")
    # 预置失败计数=上限：毒丸立即放弃
    pre = db.connect(db_path)
    pre.execute(
        "INSERT INTO meta (key,value) VALUES"
        " ('notify:fail:ev-poison','5')")
    pre.commit()
    pre.close()

    hub = NotificationHub(db_path, {})
    spy = SpyOutlet(fail=True)
    hub.webhook = spy
    hub.start()
    try:
        assert _wait_until(lambda: hub.counters.get("dropped", 0) >= 1),             "超限事件必须放弃（dropped），不得阻塞游标"
        assert hub.counters["webhook_ok"] == 0
    finally:
        assert hub.stop(timeout=5.0) is True


# ---------- LZ-065 P1-5：MQTT 构造不阻塞（后台连接） ----------

def test_mqtt_connect_is_nonblocking():
    import time as time_mod
    from scam.notify import MqttOutlet
    t0 = time_mod.monotonic()
    outlet = MqttOutlet({"host": "10.255.255.1", "port": 1883})
    elapsed = time_mod.monotonic() - t0
    assert elapsed < 1.0, f"构造必须立即返回（实测 {elapsed:.2f}s）"
    status = outlet.status()
    # 非阻塞即达标：三态任一（连接中/已连/异步失败）都证明构造未等待
    assert (status["connecting"] or status["connected"]
            or status["error"]), status
    outlet.stop()
