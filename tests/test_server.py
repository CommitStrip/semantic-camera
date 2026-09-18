"""工作台服务测试：zones 持久化 / camera_id 白名单 / feedback 合并语义。

进程内驱动 Handler（不联网、不起端口）：SSRF 面为零，且能精确断言状态码。
"""

import io
import json
from types import SimpleNamespace

import pytest

from scam.db import connect, init_schema, insert_event
from scam.server import WorkbenchHandler, WorkbenchState


@pytest.fixture()
def state(tmp_path):
    db_path = str(tmp_path / "wb.db")
    conn = connect(db_path)
    init_schema(conn)
    conn.close()
    return WorkbenchState(db_path)


class _H(WorkbenchHandler):
    """绕过网络栈的最小 Handler 驱动：只走 do_GET/do_POST 业务逻辑。"""

    def __init__(self, method, path, obj=None, state=None):
        self.command = method
        self.path = path
        self.headers = {"Content-Length": str(len(json.dumps(obj)) if obj else 0)}
        self.rfile = io.BytesIO(json.dumps(obj).encode() if obj else b"")
        self.wfile = io.BytesIO()
        self.status = None
        self._state = state

    @property
    def server(self):
        return SimpleNamespace(state=self._state)

    def send_response(self, code, message=None):
        self.status = code

    def send_header(self, *a):
        pass

    def end_headers(self):
        pass

    def body_json(self):
        raw = self.wfile.getvalue()
        start = raw.find(b"{")
        return json.loads(raw[start:]) if start >= 0 else {}


def _post(state, path, obj):
    h = _H("POST", path, obj, state)
    h.do_POST()
    return h.status, h.body_json()


def _get(state, path):
    h = _H("GET", path, None, state)
    h.do_GET()
    return h.status, h.body_json()


def test_zones_save_roundtrip_and_cameras(state):
    st, body = _post(state, "/api/zones/save", {
        "camera": "front-door",
        "zones": [{"id": "z1", "cells": [1, 2],
                   "rules": [{"cls": "person", "template": "immediate"}]}]})
    assert st == 200 and body["ok"]
    st, body = _get(state, "/api/cameras")
    assert [c["id"] for c in body["cameras"]] == ["front-door"]
    assert state.zones("front-door")[0]["id"] == "z1"


def test_save_zones_rejects_bad_camera_id(state):
    for bad in ("a/b", "..", "c am", ""):
        st, body = _post(state, "/api/zones/save", {"camera": bad, "zones": []})
        assert st == 400, f"非法 camera_id {bad!r} 必须被拒绝"


def test_feedback_merges_not_overwrites(state):
    """反馈必须合并进原 payload——证据（缩略图等）不可丢。"""
    conn = state._conn()
    insert_event(conn, event_id="e1", camera="c", kind="alert",
                 t_processed="2026-09-18T10:00:00",
                 payload='{"thumb": "AAA", "dwell_s": 5}')
    conn.close()
    st, body = _post(state, "/api/events/feedback",
                     {"event_id": "e1", "feedback": "误报"})
    assert st == 200 and body["ok"]
    conn = state._conn()
    row = conn.execute(
        "SELECT payload FROM events WHERE event_id = ?", ("e1",)).fetchone()
    conn.close()
    p = json.loads(row["payload"])
    assert p["thumb"] == "AAA" and p["dwell_s"] == 5, "原证据字段必须保留"
    assert p["feedback"] == "误报"


def test_feedback_missing_event_is_404(state):
    st, _ = _post(state, "/api/events/feedback",
                  {"event_id": "nope", "feedback": "x"})
    assert st == 404


def test_state_save_zones_rejects_non_list(state):
    with pytest.raises(ValueError):
        state.save_zones("cam", "not-a-list")


def test_unknown_path_404(state):
    st, _ = _get(state, "/api/nothing")
    assert st == 404
