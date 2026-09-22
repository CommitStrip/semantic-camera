"""S2 慢系统有界后台接线测试（LZ-047 合同：消费/隔离/有界停机/披露/多相机）。"""

import json
import time

import pytest

import scam.db as db
from scam.slow_worker import SlowWorker


def _conn(tmp_path):
    conn = db.connect(str(tmp_path / "w.db"))
    db.init_schema(conn)
    return conn


def _seed_closed_segment(conn, rid, camera="front", t0=1000.0, t1=1120.0):
    db.open_review_segment(conn, review_id=rid, camera=camera, t_start=t0)
    db.close_review_segment(conn, rid, t_end=t1, reason="quiet")
    db.open_tracked_object(
        conn, object_id=f"{rid}:obj", camera=camera,
        t_start=t0 + 10, cls="person", zones=["z1"])
    db.close_tracked_object(conn, f"{rid}:obj", t_end=t1 - 10, reason="gone")
    conn.commit()


def _wait_until(predicate, timeout=15.0, interval=0.2):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


# ---------- 1. worker 消费闭合段：档案出现、水位归零 ----------

def test_worker_consumes_closed_segments(tmp_path):
    conn = _conn(tmp_path)
    _seed_closed_segment(conn, "rev-1")
    _seed_closed_segment(conn, "rev-2", camera="front")
    conn.close()
    db_path = str(tmp_path / "w.db")

    worker = SlowWorker(db_path, ["front"], interval_s=0.5)
    assert worker.start() is True
    try:
        assert _wait_until(lambda: worker.totals["processed"] >= 2), \
            "worker 必须在时限内消费闭合段"
    finally:
        assert worker.stop(timeout=5.0) is True

    check = _conn(tmp_path)
    rows = check.execute("SELECT COUNT(*) FROM segments").fetchone()[0]
    assert rows == 2
    check.close()


# ---------- 2. 快路径零等待：worker 运行中闭合段写入立即成功 ----------

def test_fast_path_never_blocks_on_worker(tmp_path):
    conn = _conn(tmp_path)
    _seed_closed_segment(conn, "rev-1")
    conn.close()
    db_path = str(tmp_path / "w.db")

    worker = SlowWorker(db_path, ["front"], interval_s=0.5)
    worker.start()
    try:
        assert _wait_until(lambda: worker.totals["runs"] >= 1)
        # 快路径（另一连接）在 worker 运行中写闭合段：必须立返成功
        writer = db.connect(db_path)
        db.init_schema(writer)
        t0 = time.time()
        db.open_review_segment(writer, review_id="rev-fast",
                               camera="front", t_start=2000.0)
        db.close_review_segment(writer, "rev-fast", t_end=2100.0,
                                reason="quiet")
        writer.commit()
        writer.close()
        assert time.time() - t0 < 2.0, "快路径写入被 worker 阻塞"
    finally:
        assert worker.stop(timeout=5.0) is True


# ---------- 3. 有界关机：批间退出、join 超时不吞事实 ----------

def test_bounded_stop_reports_timeout_not_swallow(tmp_path):
    conn = _conn(tmp_path)
    _seed_closed_segment(conn, "rev-1")
    conn.close()

    worker = SlowWorker(str(tmp_path / "w.db"), ["front"], interval_s=60.0)
    worker.start()
    time.sleep(0.3)                      # 进入长等待轮

    assert worker.stop(timeout=3.0) is True, "长等待轮也必须有界退出"


# ---------- 4. 异常隔离：轮内崩溃只记 last_error，worker 存活 ----------

def test_round_exception_isolated_and_visible(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    _seed_closed_segment(conn, "rev-1")
    conn.close()

    worker = SlowWorker(str(tmp_path / "w.db"), ["front"], interval_s=0.5)

    def boom(self, *a, **k):
        raise RuntimeError("注入崩溃")

    monkeypatch.setattr("scam.slow_core.SlowCore.process_pending", boom)
    worker.start()
    try:
        assert _wait_until(lambda: worker.last_error == "RuntimeError"), \
            "异常类型名必须进入 last_error"
        assert worker._thread.is_alive(), "worker 不得因单轮异常退出"
    finally:
        monkeypatch.undo()
        assert worker.stop(timeout=5.0) is True


# ---------- 5. 计数与水位披露（/api/health slow 段数据源） ----------

def test_snapshot_discloses_counters_and_waterlevel(tmp_path):
    conn = _conn(tmp_path)
    _seed_closed_segment(conn, "rev-1")
    conn.close()
    db_path = str(tmp_path / "w.db")

    worker = SlowWorker(db_path, ["front"], interval_s=0.5)
    worker.start()
    try:
        assert _wait_until(lambda: worker.totals["processed"] >= 1)
        snap = worker.snapshot()
        assert snap["enabled"] is True
        assert snap["totals"]["processed"] >= 1
        assert snap["totals"]["vlm_calls"] == 0     # provider 缺席零调用
        assert snap["last_error"] is None
        assert snap["pending_total"] == 0
        assert snap["backlogged"] is False
        assert snap["waterlevel"]["front"]["pending"] == 0
        assert snap["waterlevel"]["front"]["patterns"] >= 1
    finally:
        assert worker.stop(timeout=5.0) is True


# ---------- 6. 多相机隔离 ----------

def test_multi_camera_isolation(tmp_path):
    conn = _conn(tmp_path)
    _seed_closed_segment(conn, "rev-f", camera="front")
    _seed_closed_segment(conn, "rev-b", camera="back", t0=5000.0, t1=5100.0)
    conn.close()

    worker = SlowWorker(str(tmp_path / "w.db"), ["front", "back"],
                        interval_s=0.5)
    worker.start()
    try:
        assert _wait_until(lambda: worker.totals["processed"] >= 2)
        snap = worker.snapshot()
        assert set(snap["waterlevel"]) == {"front", "back"}
        for level in snap["waterlevel"].values():
            assert level["pending"] == 0 and level["patterns"] == 1
    finally:
        assert worker.stop(timeout=5.0) is True


# ---------- 7. health 端点 slow 段（接线级，进程内 Handler） ----------

def test_health_endpoint_discloses_slow_section(tmp_path):
    import http.client
    from scam.server import WorkbenchServer, WorkbenchState

    conn = _conn(tmp_path)
    _seed_closed_segment(conn, "rev-h")
    conn.close()

    state = WorkbenchState(str(tmp_path / "w.db"))
    worker = SlowWorker(str(tmp_path / "w.db"), ["front"], interval_s=0.5)
    state.slow_worker = worker
    server = WorkbenchServer(state, host="127.0.0.1", port=0)
    worker.start()
    try:
        import threading
        threading.Thread(target=server.serve_forever, daemon=True).start()
        time.sleep(0.2)
        port = server.server_address[1]
        hc = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        hc.request("GET", "/api/health")
        resp = hc.getresponse()
        body = json.loads(resp.read().decode("utf-8"))
        hc.close()
        assert resp.status == 200
        assert "slow" in body and body["slow"]["enabled"] is True
        assert "pending_total" in body["slow"]
    finally:
        assert worker.stop(timeout=5.0) is True
        server.shutdown()


# ---------- 8. 未接线时 health 保持既有形状（兼容） ----------

def test_health_without_slow_worker_keeps_shape(tmp_path):
    import http.client
    import threading
    from scam.server import WorkbenchServer, WorkbenchState

    conn = _conn(tmp_path)
    conn.execute(
        "INSERT OR IGNORE INTO zones (camera,data) VALUES ('front','[]')")
    conn.commit()
    conn.close()

    state = WorkbenchState(str(tmp_path / "w.db"))   # 不挂 slow_worker
    server = WorkbenchServer(state, host="127.0.0.1", port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        time.sleep(0.2)
        port = server.server_address[1]
        hc = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        hc.request("GET", "/api/health")
        body = json.loads(hc.getresponse().read().decode("utf-8"))
        hc.close()
        assert "slow" not in body, "未接线不得出现假 slow 段"
    finally:
        server.shutdown()


# ---------- SC-B：生产 worker 显式启用陈旧恢复 ----------

def test_worker_passes_recover_stale_true(tmp_path, monkeypatch):
    """生产调度必须显式 recover_stale=True（进程重启后需恢复陈旧工作）。"""
    conn = _conn(tmp_path)
    _seed_closed_segment(conn, "rev-rs")
    conn.close()
    seen = {}
    from scam.slow_core import SlowCore
    orig = SlowCore.process_pending

    def spy(self, **kwargs):
        seen.update(kwargs)
        return orig(self, **kwargs)

    monkeypatch.setattr(SlowCore, "process_pending", spy)
    worker = SlowWorker(str(tmp_path / "w.db"), ["front"], interval_s=0.5)
    worker.start()
    try:
        assert _wait_until(lambda: bool(seen), timeout=10)
        assert seen.get("recover_stale") is True, seen
    finally:
        monkeypatch.undo()
        assert worker.stop(timeout=5.0) is True
