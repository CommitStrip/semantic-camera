"""工作台服务测试：zones 持久化 / camera_id 白名单 / feedback 合并语义。

进程内驱动 Handler（不联网、不起端口）：SSRF 面为零，且能精确断言状态码。
"""

import io
import hashlib
import json
from types import SimpleNamespace

import numpy as np
import pytest

from scam.db import (connect, init_schema, insert_event, open_review_segment,
                     open_semantic_event, open_tracked_object)
from scam.server import WorkbenchHandler, WorkbenchState
from scam.zones import Grid


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


def _get_handler(state, path):
    h = _H("GET", path, None, state)
    h.do_GET()
    return h


def _seed_event_with_evidence(state, tmp_path):
    conn = state._conn()
    open_tracked_object(
        conn, object_id="obj-1", camera="front", t_start=1.0,
        cls="person", payload={"track": 7})
    open_review_segment(
        conn, review_id="review-1", camera="front", t_start=1.0,
        object_ids=["obj-1"], payload={"source": "test"})
    open_semantic_event(
        conn, semantic_event_id="event:1", camera="front",
        review_id="review-1", object_id="obj-1", t_start=2.0,
        template="immediate", zone_id="yard", short_name="人员进入院子",
        payload={"rule": "admin"})
    content = b"\xff\xd8clean-jpeg\xff\xd9"
    rel = "front/obj/frame.jpg"
    target = tmp_path / "evidence" / "front" / "obj" / "frame.jpg"
    target.parent.mkdir(parents=True)
    target.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    conn.execute(
        "INSERT INTO evidence_assets"
        " (asset_id,owner_type,owner_id,camera,kind,path,state,mime,"
        " t_start,score,size_bytes,sha256,created_at,updated_at,metadata)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("event-best:abc", "semantic_event", "event:1", "front",
         "clean_best_frame", rel, "available", "image/jpeg", 2.0, 1.5,
         len(content), digest, 2.0, 2.0,
         json.dumps({"bbox": [0.1, 0.2, 0.3, 0.4]})))
    conn.commit()
    conn.close()
    return content, target


def test_zones_save_roundtrip_and_cameras(state):
    st, body = _post(state, "/api/zones/save", {
        "camera": "front-door",
        "zones": [{"id": "z1", "cells": [1, 2],
                   "rules": [{"cls": "person", "template": "immediate"}]}]})
    assert st == 200 and body["ok"]
    st, body = _get(state, "/api/cameras")
    assert [c["id"] for c in body["cameras"]] == ["front-door"]
    assert state.zones("front-door")[0]["id"] == "z1"
    st, body = _get(state, "/api/zones/front-door")
    assert st == 200
    assert body["grid"] == {"rows": 18, "cols": 22}
    assert body["zones"][0]["cells"] == [1, 2]
    assert body["runtime"] == "restart_required"


def test_zone_save_validates_before_persisting(state):
    invalid = [
        [{"id": "bad/id", "cells": [1], "rules": []}],
        [{"id": "z1", "cells": [999], "rules": []}],
        [{"id": "z1", "cells": [1], "rules": [{"cls": ""}]}],
        [{"id": "z1", "cells": [1], "rules": "bad"}],
    ]
    for zones in invalid:
        st, body = _post(
            state, "/api/zones/save", {"camera": "front", "zones": zones})
        assert st == 400 and body["error"]
    assert state.cameras() == []


def test_zone_save_queues_live_monitor_at_frame_boundary(state):
    class LiveMonitor:
        grid = Grid(rows=10, cols=12)
        zone_revision = 4
        _pending_zones = None

        def request_zone_update(self, zones):
            self.queued = zones
            self._pending_zones = (5, zones)
            return 5

    live = LiveMonitor()
    state.monitors["front"] = live
    st, body = _post(state, "/api/zones/save", {
        "camera": "front",
        "zones": [{"id": "door", "name": "门口", "cells": [3, 2, 3],
                   "rules": [{"cls": "person", "template": "immediate"}]}],
    })
    assert st == 200 and body["runtime"] == "queued"
    assert body["revision"] == 5
    assert live.queued[0]["cells"] == [2, 3]
    st, body = _get(state, "/api/zones/front")
    assert st == 200 and body["pending"] is True
    assert body["grid"] == {"rows": 10, "cols": 12}


def test_unknown_zone_camera_is_404(state):
    st, body = _get(state, "/api/zones/missing")
    assert st == 404 and body["error"] == "camera not found"


def test_frame_endpoint_encodes_latest_frame_on_demand(state):
    class LiveMonitor:
        latest_frame_bgr = np.full((360, 1920, 3), 127, dtype=np.uint8)

    state.monitors["front"] = LiveMonitor()
    handler = _get_handler(state, "/api/frame/front")
    content = handler.wfile.getvalue()
    assert handler.status == 200
    assert handler.response_headers["Content-Type"] == "image/jpeg"
    assert content.startswith(b"\xff\xd8") and content.endswith(b"\xff\xd9")

    import cv2
    decoded = cv2.imdecode(np.frombuffer(content, dtype=np.uint8), cv2.IMREAD_COLOR)
    assert decoded.shape[1] == 1280, "工作台快照必须限制宽度，避免多路4K内存/带宽放大"


def test_frame_endpoint_reports_offline_empty_and_unknown(state):
    class EmptyMonitor:
        latest_frame_bgr = None

    state.monitors["empty"] = EmptyMonitor()
    st, body = _get(state, "/api/frame/empty")
    assert st == 503 and body["state"] == "empty"
    st, body = _get(state, "/api/frame/offline")
    assert st == 503 and body["state"] == "offline"
    st, body = _get(state, "/api/frame/bad%2Fid")
    assert st == 404 and body["state"] == "unknown"


def test_frame_endpoint_reports_encode_failure(state):
    class BrokenMonitor:
        latest_frame_bgr = object()

    state.monitors["broken"] = BrokenMonitor()
    st, body = _get(state, "/api/frame/broken")
    assert st == 500 and body["state"] == "encode_failed"


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


def test_index_exposes_admin_zone_editor_contract(state):
    """R3 页面必须把当前帧、网格和管理员显式保存连成可操作闭环。"""
    handler = _get_handler(state, "/")
    html = handler.wfile.getvalue().decode("utf-8")

    assert handler.status == 200
    assert handler.response_headers["Content-Type"] == \
        "text/html; charset=utf-8"
    assert handler.response_headers["Cache-Control"] == "private, no-store"
    assert handler.response_headers["X-Content-Type-Options"] == "nosniff"
    for marker in (
            'id="camera-select"', 'id="zone-frame"', 'id="zone-grid"',
            'id="environment-gate"', 'id="analyze-environment"',
            'id="zone-id"', 'id="rule-template"', 'id="save-zone"',
            'id="delete-zone"', "'/api/frame/'", "'/api/zones/'",
            "'/api/zones/save'", "'/api/environment/'",
            "'/api/environment/analyze'", "onpointerenter"):
        assert marker in html
    assert "保存并应用管理员规则" in html
    assert "模型建议不会自动成为告警" in html
    assert "必须完成" in html and "不会自动成为报警规则" in html
    assert "window.confirm" in html, "删除现有管理员区域必须有明确确认"


def test_environment_status_and_local_analysis_use_current_frame(state):
    class LocalProvider:
        name = "local"

        def __init__(self):
            self.calls = 0

        def understand(self, prompt, frames_b64, context=None):
            self.calls += 1
            return {"scene_type": "住宅门口", "elements": ["门"],
                    "lighting": "白天", "risk_notes": "台阶湿滑",
                    "suggested_zones": ["门前台阶"]}

    class LiveMonitor:
        latest_frame_bgr = np.zeros((16, 16, 3), dtype=np.uint8)

    provider = LocalProvider()
    state.environment_provider = provider
    state.save_zones("front", [])
    state.monitors["front"] = LiveMonitor()

    st, body = _get(state, "/api/environment/front")
    assert st == 200 and body["state"] == "required"
    assert body["channel"] == "local" and body["profile"] is None

    st, body = _post(state, "/api/environment/analyze",
                     {"camera": "front", "cloud_confirmed": False})
    assert st == 200 and body["profile"]["scene_type"] == "住宅门口"
    assert provider.calls == 1
    st, body = _get(state, "/api/environment/front")
    assert st == 200 and body["state"] == "ready"
    assert body["profile"]["suggested_zones"] == ["门前台阶"]
    assert state.zones("front") == [], "模型建议绝不能自动写成报警区域"


def test_environment_cloud_requires_each_call_confirmation(state):
    class CloudProvider:
        name = "cloud"

        def __init__(self):
            self.calls = 0

        def understand(self, prompt, frames_b64, context=None):
            self.calls += 1
            return {"scene_type": "仓库", "elements": ["门"],
                    "lighting": "白天", "risk_notes": "无",
                    "suggested_zones": ["入口"]}

    class LiveMonitor:
        latest_frame_bgr = np.zeros((8, 8, 3), dtype=np.uint8)

    cloud = CloudProvider()
    state.environment_provider = cloud
    state.save_zones("front", [])
    state.monitors["front"] = LiveMonitor()

    st, body = _post(state, "/api/environment/analyze",
                     {"camera": "front", "cloud_confirmed": False})
    assert st == 428 and body["state"] == "confirmation_required"
    assert cloud.calls == 0

    st, body = _post(state, "/api/environment/analyze",
                     {"camera": "front", "cloud_confirmed": True})
    assert st == 200 and body["profile"]["provider"] == "cloud"
    assert cloud.calls == 1


def test_environment_analysis_reports_offline_and_bad_confirmation(state):
    state.save_zones("front", [])
    st, body = _post(state, "/api/environment/analyze",
                     {"camera": "front", "cloud_confirmed": False})
    assert st == 503 and body["state"] == "unavailable"

    st, body = _post(state, "/api/environment/analyze",
                     {"camera": "front", "cloud_confirmed": "yes"})
    assert st == 400 and "boolean" in body["error"]

    st, body = _get(state, "/api/environment/missing")
    assert st == 404 and body["error"] == "camera not found"


def test_review_and_semantic_event_apis_read_three_layer_truth(state):
    conn = state._conn()
    open_tracked_object(
        conn, object_id="obj-1", camera="front", t_start=1.0, cls="person")
    open_review_segment(
        conn, review_id="review-1", camera="front", t_start=1.0,
        object_ids=["obj-1"])
    open_semantic_event(
        conn, semantic_event_id="event-1", camera="front",
        review_id="review-1", object_id="obj-1", t_start=2.0,
        template="immediate", zone_id="yard", short_name="人员进入院子")
    conn.close()

    st, body = _get(state, "/api/review")
    assert st == 200
    assert body["segments"][0]["review_id"] == "review-1"
    assert body["segments"][0]["object_ids"] == ["obj-1"]

    st, body = _get(state, "/api/events")
    assert st == 200
    assert body["events"][0]["event_id"] == "event-1"
    assert body["events"][0]["template"] == "immediate"


def test_reviewed_api_marks_existing_segment_and_reports_missing(state):
    conn = state._conn()
    open_review_segment(
        conn, review_id="review-1", camera="front", t_start=1.0)
    conn.close()

    st, body = _post(
        state, "/api/review/reviewed", {"review_id": "review-1"})
    assert st == 200 and body["ok"]
    st, body = _get(state, "/api/review")
    assert body["segments"][0]["reviewed"] == 1

    st, body = _post(
        state, "/api/review/reviewed", {"review_id": "missing"})
    assert st == 404 and body["error"] == "review segment not found"


def test_event_detail_returns_three_layers_and_safe_evidence_metadata(
        state, tmp_path):
    _seed_event_with_evidence(state, tmp_path)

    st, body = _get(state, "/api/events/event%3A1")
    assert st == 200
    assert body["event"]["semantic_event_id"] == "event:1"
    assert body["event"]["payload"] == {"rule": "admin"}
    assert "best_frame_path" not in body["event"]
    assert body["review"]["object_ids"] == ["obj-1"]
    assert body["object"]["payload"] == {"track": 7}
    assert "best_frame_path" not in body["object"]
    assert body["evidence"][0]["asset_id"] == "event-best:abc"
    assert body["evidence"][0]["metadata"]["bbox"] == [0.1, 0.2, 0.3, 0.4]
    assert "path" not in body["evidence"][0]
    assert body["evidence"][0]["content_url"] == \
        "/api/evidence/event-best%3Aabc"

    st, listing = _get(state, "/api/events")
    assert st == 200
    assert listing["events"][0]["best_frame_asset_id"] == "event-best:abc"

    st, body = _get(state, "/api/events/missing")
    assert st == 404 and body["error"] == "event not found"


def test_evidence_endpoint_serves_only_indexed_valid_jpeg(state, tmp_path):
    content, _ = _seed_event_with_evidence(state, tmp_path)
    h = _get_handler(state, "/api/evidence/event-best%3Aabc")
    assert h.status == 200
    assert h.wfile.getvalue() == content
    assert h.response_headers["Content-Type"] == "image/jpeg"
    assert int(h.response_headers["Content-Length"]) == len(content)
    assert h.response_headers["X-Content-Type-Options"] == "nosniff"

    st, body = _get(state, "/api/evidence/not-indexed")
    assert st == 404 and body["state"] == "unknown"


def test_evidence_endpoint_marks_missing_and_corrupt_honestly(state, tmp_path):
    _, target = _seed_event_with_evidence(state, tmp_path)
    target.unlink()
    st, body = _get(state, "/api/evidence/event-best:abc")
    assert st == 404 and body["state"] == "missing"
    conn = state._conn()
    assert conn.execute(
        "SELECT state FROM evidence_assets WHERE asset_id='event-best:abc'"
    ).fetchone()[0] == "missing"
    conn.close()

    target.write_bytes(b"not a jpeg")
    st, body = _get(state, "/api/evidence/event-best:abc")
    assert st == 422 and body["state"] == "corrupt"
    conn = state._conn()
    assert conn.execute(
        "SELECT state FROM evidence_assets WHERE asset_id='event-best:abc'"
    ).fetchone()[0] == "corrupt"
    conn.close()


def test_indexed_path_traversal_is_never_read(state, tmp_path):
    content, _ = _seed_event_with_evidence(state, tmp_path)
    outside = tmp_path / "outside.jpg"
    outside.write_bytes(content)
    conn = state._conn()
    conn.execute(
        "UPDATE evidence_assets SET path=? WHERE asset_id=?",
        ("../outside.jpg", "event-best:abc"))
    conn.commit()
    conn.close()

    st, body = _get(state, "/api/evidence/event-best:abc")
    assert st == 422 and body["state"] == "corrupt"


def test_non_jpeg_asset_is_not_served_or_reclassified(state):
    conn = state._conn()
    conn.execute(
        "INSERT INTO evidence_assets"
        " (asset_id,owner_type,owner_id,camera,kind,path,state,mime,"
        " size_bytes,sha256,created_at,updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("clip-1", "semantic_event", "event-1", "front", "event_clip",
         "clips/clip.mp4", "available", "video/mp4", 123, "deadbeef",
         1.0, 1.0))
    conn.commit()
    conn.close()

    st, body = _get(state, "/api/evidence/clip-1")
    assert st == 404 and body["state"] == "unsupported"
    conn = state._conn()
    assert conn.execute(
        "SELECT state FROM evidence_assets WHERE asset_id='clip-1'"
    ).fetchone()[0] == "available"
    conn.close()
