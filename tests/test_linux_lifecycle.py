"""Linux L1：对象、审查段和管理员语义事件的默认主链契约。"""

import io
import json
from types import SimpleNamespace

import cv2
import numpy as np

from scam.db import connect, init_schema
from scam.monitor import Monitor, to_gray
from scam.nvr import _recover_event_truth
from scam.server import WorkbenchHandler, WorkbenchState
from scam.sinks import SqliteSink

W, H = 640, 360


def _frame(points, tick):
    frame = np.zeros((H, W, 3), np.uint8)
    frame[:] = (30, 30, 30)
    for cx, cy in points:
        x = int(cx * W) + (tick // 40 % 2) * 8
        y = int(cy * H)
        cv2.rectangle(frame, (x, y), (x + 50, y + 70),
                      (255, 255, 255), -1)
    return frame


class ScriptedDetector:
    def __init__(self, points):
        self.points = points

    def __call__(self, _frame_bgr):
        return [{"cls": "person", "conf": 0.9 - index * 0.05,
                 "bbox": [cx - 0.04, cy - 0.10, 0.08, 0.20],
                 "cx": cx, "cy": cy}
                for index, (cx, cy) in enumerate(self.points)]


def _config(cells=(231,)):
    return {
        "id": "front-door",
        "grid": {"rows": 18, "cols": 22},
        "zones": [{
            "id": "z1", "cells": list(cells),
            "rules": [{"cls": "person", "template": "immediate"}],
        }],
    }


def _step(monitor, detector, tick):
    frame = _frame(detector.points, tick)
    return monitor.step(frame, to_gray(frame, monitor.GRAY_W), tick)


def test_admin_event_leave_and_reenter_share_one_review(tmp_path):
    """离区闭合、重入新建事件；同一连续活动只形成一个审查段。"""
    db_path = str(tmp_path / "linux.db")
    detector = ScriptedDetector([(0.50, 0.56)])
    monitor = Monitor(_config(), detector, [SqliteSink(db_path)],
                      run_id="linux-run")

    _step(monitor, detector, 0)
    alarms = _step(monitor, detector, 5000)
    assert len(alarms) == 1

    detector.points = [(0.30, 0.35)]
    _step(monitor, detector, 10000)
    detector.points = [(0.50, 0.56)]
    _step(monitor, detector, 15000)
    _step(monitor, detector, 15500)

    conn = connect(db_path)
    events = conn.execute(
        "SELECT state,end_reason FROM semantic_events ORDER BY t_start"
    ).fetchall()
    reviews = conn.execute("SELECT * FROM review_segments").fetchall()
    conn.close()
    assert len(events) == 2, "离区后重入必须是新的管理员语义事件"
    assert events[0]["state"] == "closed"
    assert events[0]["end_reason"] == "zone-leave"
    assert events[1]["state"] == "open"
    assert len(reviews) == 1, "连续活动中的离区重入不应切碎审查段"
    assert reviews[0]["severity"] == "alert"


def test_overlapping_targets_are_aggregated_into_one_review(tmp_path):
    """两个同时出现的目标共享相机审查段，而不是一目标一张卡。"""
    db_path = str(tmp_path / "overlap.db")
    points = [(0.50, 0.56), (0.57, 0.56)]
    detector = ScriptedDetector(points)
    monitor = Monitor(_config(cells=(231, 232)), detector,
                      [SqliteSink(db_path)], run_id="overlap")
    _step(monitor, detector, 0)
    _step(monitor, detector, 5000)

    conn = connect(db_path)
    rows = conn.execute("SELECT object_ids FROM review_segments").fetchall()
    objects = conn.execute("SELECT object_id FROM tracked_objects").fetchall()
    conn.close()
    assert len(rows) == 1
    assert len(json.loads(rows[0]["object_ids"])) == 2
    assert len(objects) == 2


def test_track_loss_closes_event_object_and_review(tmp_path):
    """目标消失后语义事件与对象闭合，静默阈值后同一审查段闭合。"""
    db_path = str(tmp_path / "lost.db")
    detector = ScriptedDetector([(0.50, 0.56)])
    monitor = Monitor(_config(), detector, [SqliteSink(db_path)],
                      run_id="lost")
    _step(monitor, detector, 0)
    _step(monitor, detector, 5000)
    detector.points = []
    _step(monitor, detector, 18000)
    _step(monitor, detector, 31000)

    conn = connect(db_path)
    event = conn.execute(
        "SELECT state,end_reason FROM semantic_events").fetchone()
    obj = conn.execute(
        "SELECT t_end,end_reason FROM tracked_objects").fetchone()
    review = conn.execute(
        "SELECT t_end,end_reason FROM review_segments").fetchone()
    conn.close()
    assert event["state"] == "closed" and event["end_reason"] == "track-lost"
    assert obj["t_end"] is not None and obj["end_reason"] == "track-lost"
    assert review["t_end"] is not None
    assert review["end_reason"] == "idle-timeout"


class BrokenEvidenceSink:
    def __call__(self, _alarm):
        raise RuntimeError("recorder unavailable")

    def __getattr__(self, name):
        if name.startswith(("open_", "update_", "observe_", "close_")):
            def fail(*_args, **_kwargs):
                raise RuntimeError("recorder unavailable")
            return fail
        raise AttributeError(name)


def test_broken_evidence_sink_does_not_block_alarm_truth(tmp_path):
    """旁路证据失败时，后续 SQLite 出口仍保存管理员告警。"""
    db_path = str(tmp_path / "isolation.db")
    detector = ScriptedDetector([(0.50, 0.56)])
    monitor = Monitor(
        _config(), detector,
        [BrokenEvidenceSink(), SqliteSink(db_path)], run_id="isolation")
    _step(monitor, detector, 0)
    alarms = _step(monitor, detector, 5000)

    conn = connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM semantic_events").fetchone()[0]
    conn.close()
    assert len(alarms) == 1 and count == 1
    assert monitor.stats()["sink_failures"] > 0
    assert monitor.stats()["last_sink_error"]["error"] == \
        "recorder unavailable"


def test_linux_startup_recovery_closes_without_deleting(tmp_path):
    """Linux 单实例重启立即闭合旧开放记录，审查历史仍可查询。"""
    db_path = str(tmp_path / "recovery.db")
    detector = ScriptedDetector([(0.50, 0.56)])
    monitor = Monitor(_config(), detector, [SqliteSink(db_path)],
                      run_id="old-run")
    _step(monitor, detector, 0)
    _step(monitor, detector, 5000)

    conn = connect(db_path)
    counts = _recover_event_truth(conn, now=6.0, stale_after_s=0.0)
    event = conn.execute("SELECT state,end_reason FROM semantic_events").fetchone()
    review = conn.execute("SELECT t_end,end_reason FROM review_segments").fetchone()
    conn.close()
    assert counts == {"tracked_objects": 1, "review_segments": 1,
                      "semantic_events": 1}
    assert event["state"] == "closed"
    assert event["end_reason"] == "recovered_after_restart"
    assert review["t_end"] is not None
    assert review["end_reason"] == "recovered_after_restart"


class _Handler(WorkbenchHandler):
    def __init__(self, path, state):
        self.command = "GET"
        self.path = path
        self.headers = {"Content-Length": "0"}
        self.rfile = io.BytesIO()
        self.wfile = io.BytesIO()
        self.status = None
        self._state = state

    @property
    def server(self):
        return SimpleNamespace(state=self._state)

    def send_response(self, code, message=None):
        self.status = code

    def send_header(self, *_args):
        pass

    def end_headers(self):
        pass


def test_review_and_failure_status_are_readable_via_api(tmp_path):
    db_path = str(tmp_path / "api.db")
    conn = connect(db_path)
    init_schema(conn)
    conn.close()
    state = WorkbenchState(db_path)
    detector = ScriptedDetector([(0.50, 0.56)])
    monitor = Monitor(_config(), detector,
                      [BrokenEvidenceSink(), SqliteSink(db_path)],
                      run_id="api")
    _step(monitor, detector, 0)
    _step(monitor, detector, 5000)
    state.monitors["front-door"] = monitor

    stats = _Handler("/api/stats", state)
    stats.do_GET()
    stats_body = json.loads(stats.wfile.getvalue())
    review = _Handler("/api/review", state)
    review.do_GET()
    review_body = json.loads(review.wfile.getvalue())
    assert stats.status == 200
    assert stats_body["cameras"][0]["last_sink_error"]["error"] == \
        "recorder unavailable"
    assert review.status == 200 and len(review_body["segments"]) == 1
    assert review_body["segments"][0]["severity"] == "alert"
