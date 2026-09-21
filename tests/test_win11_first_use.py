"""ZW-002 首次使用重启持久化入口测试：磨砂门 required→ready、建议只读、
档案与管理员 zones 跨状态对象重建持久化、离线无帧诚实 503。

进程内驱动 Handler（不联网、不起端口、不起子进程）；provider 为合成替身。
本文件是合成入口证据，不代表真实 Win11 / RTSP / 浏览器重启证据。
"""

import io
import json
from types import SimpleNamespace

import numpy as np

from scam.db import connect, init_schema
from scam.server import WorkbenchHandler, WorkbenchState
from scam.zones import Grid


GOOD = {
    "scene_type": "住宅门口",
    "elements": ["大门", "台阶", "绿植"],
    "lighting": "夜间红外，黑白画面",
    "risk_notes": "夜间光线弱，人物细节有限",
    "suggested_zones": ["大门台阶区域"],
}

ZONES = [{"id": "z1", "cells": [1, 2],
          "rules": [{"cls": "person", "template": "immediate"}]}]


class FakeProvider:
    """合成 provider：计数调用、返回预设结构（输出按不可信数据交校验层）。"""

    name = "local"

    def __init__(self):
        self.calls = 0

    def understand(self, prompt, frames_b64, context=None):
        self.calls += 1
        return json.dumps(GOOD)


class _Monitor:
    """在线相机替身：最新帧与 zones 运行时接口的最小面。"""

    def __init__(self, frame=None):
        self.latest_frame_bgr = frame
        self.grid = Grid()
        self.zone_revision = 0
        self._pending_zones = None

    def request_zone_update(self, zones):
        self._pending_zones = zones
        self.zone_revision += 1
        return self.zone_revision


class _H(WorkbenchHandler):
    """绕过网络栈的最小 Handler 驱动：只走 do_GET/do_POST 业务逻辑。"""

    def __init__(self, method, path, obj=None, state=None):
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


def _post(state, path, obj):
    h = _H("POST", path, obj, state)
    h.do_POST()
    return h.status, h.body_json()


def _get(state, path):
    h = _H("GET", path, None, state)
    h.do_GET()
    return h.status, h.body_json()


def _frame():
    return np.zeros((8, 8, 3), dtype=np.uint8)


def _db_path(tmp_path):
    db_path = str(tmp_path / "first_use.db")
    conn = connect(db_path)
    init_schema(conn)
    conn.close()
    return db_path


def _state(db_path, provider):
    return WorkbenchState(db_path, environment_provider=provider)


# ---------- 1. 未识别 required → 管理员识别 ready ----------

def test_first_use_gate_required_then_ready(tmp_path):
    provider = FakeProvider()
    state = _state(_db_path(tmp_path), provider)
    state.monitors["front"] = _Monitor(frame=_frame())

    st, body = _get(state, "/api/environment/front")
    assert st == 200
    assert body["state"] == "required" and body["profile"] is None
    assert body["channel"] == "local"
    assert provider.calls == 0  # 门禁状态读取不调模型

    st, body = _post(state, "/api/environment/analyze", {"camera": "front"})
    assert st == 200 and body["ok"] and body["state"] == "ok"
    assert body["profile"]["scene_type"] == GOOD["scene_type"]
    assert provider.calls == 1

    st, body = _get(state, "/api/environment/front")
    assert st == 200
    assert body["state"] == "ready" and body["profile"] is not None
    assert provider.calls == 1


# ---------- 2. 建议只是建议：识别后 zones 仍为空 ----------

def test_identify_keeps_zones_empty_suggestions_only(tmp_path):
    state = _state(_db_path(tmp_path), FakeProvider())
    state.monitors["front"] = _Monitor(frame=_frame())

    st, body = _post(state, "/api/environment/analyze", {"camera": "front"})
    assert st == 200
    assert body["profile"]["suggested_zones"] == GOOD["suggested_zones"]

    # zones 表零行：suggested_zones 绝不落 zones、更不生成规则
    st, _ = _get(state, "/api/zones/front")
    assert st == 404  # 无圈选真值，不伪造空配置
    assert state.cameras() == []
    assert state.zones("front") == []


# ---------- 3+4. 管理员 zones 与档案跨状态对象重建持久化 ----------

def test_rebuild_persists_archive_and_admin_zones_zero_model_calls(tmp_path):
    provider = FakeProvider()
    db_path = _db_path(tmp_path)
    state = _state(db_path, provider)
    state.monitors["front"] = _Monitor(frame=_frame())

    st, _ = _post(state, "/api/environment/analyze", {"camera": "front"})
    assert st == 200
    st, saved = _post(state, "/api/zones/save",
                      {"camera": "front", "zones": ZONES})
    assert st == 200 and saved["ok"]
    assert saved["runtime"] == "queued"  # 在线替身接收运行时更新

    # 销毁状态对象，用同一 DB 重建（新 provider 从零计数）
    del state
    provider2 = FakeProvider()
    reborn = _state(db_path, provider2)
    assert reborn.monitors == {}

    st, body = _get(reborn, "/api/environment/front")
    assert st == 200
    assert body["state"] == "ready"  # 档案自 SQLite 恢复
    assert body["profile"]["scene_type"] == GOOD["scene_type"]
    assert len(body["profile"]["frame_sha256"]) == 64
    assert provider2.calls == 0

    st, config = _get(reborn, "/api/zones/front")
    assert st == 200
    assert config["zones"] == saved["zones"]  # 管理员格子与规则原样可读
    assert config["runtime"] == "restart_required"  # 无在线相机，如实标注

    # 重复读取零模型调用
    _get(reborn, "/api/environment/front")
    _get(reborn, "/api/zones/front")
    assert provider2.calls == 0


# ---------- 5. 离线无帧：诚实 503 且不生成档案 ----------

def test_offline_no_frame_honest_503_without_profile(tmp_path):
    provider = FakeProvider()
    state = _state(_db_path(tmp_path), provider)
    state.monitors["front"] = _Monitor(frame=None)

    st, body = _post(state, "/api/environment/analyze", {"camera": "front"})
    assert st == 503 and body["state"] == "unavailable"
    assert provider.calls == 0  # 无帧不调模型

    st, body = _get(state, "/api/environment/front")
    assert st == 200
    assert body["state"] == "required" and body["profile"] is None
