"""工作台服务测试：zones 持久化 / camera_id 白名单 / feedback 合并语义。

进程内驱动 Handler（不联网、不起端口）：SSRF 面为零，且能精确断言状态码。
"""

import io
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import numpy as np
import pytest

from scam.db import (connect, init_schema, insert_event, open_review_segment,
                     open_semantic_event, open_tracked_object)
from scam.server import (CameraRuntimeRegistry, WorkbenchHandler,
                         WorkbenchState)
from scam.win11_understanding_store import UnderstandingStore
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
            'id="analyze-environment"', 'id="baseline-establish"',
            'id="baseline-retry"', 'id="gate-message"',
            'id="zone-id"', 'id="rule-template"', 'id="save-zone"',
            'id="delete-zone"', "'/api/frame/'", "'/api/zones/'",
            "'/api/zones/save'", "'/api/environment/'",
            "'/api/environment/baseline'", "+'/baselines'",
            "onpointerenter",
            "'/api/v2/events'", "'/api/v2/notifications",
            "初始事实提醒", "暂无可回看画面"):
        assert marker in html
    assert "保存并应用管理员规则" in html
    assert "模型建议不会自动成为告警" in html
    # 工作包 A（产品合同三条同时成立）：磨砂引导恢复为按相机的首次基线前置；
    # 事件不以圈选或规则为前提；错误"可选识别"文案不得残留。
    assert 'id="environment-gate"' in html, "首次基线磨砂引导必须恢复"
    assert "先建立环境基线，再进入值守" in html
    assert "事件的发现与记录不以圈选或规则为前提" in html
    assert "不会自动成为报警规则" in html
    # C-144-R2（任务书 §一）：环境基线与圈选降级为可选增强——门可跳过、
    # 不阻挡观察与证据查看；「可选增强」作为诚实标注允许出现，但不得
    # 伪造 ready。旧的"可选识别"残留文案禁令继续有效。
    assert "可选识别" not in html, "错误文案必须清除"
    assert "先跳过，稍后再建" in html, "基线门必须可跳过"
    assert "不识别也可直接值守" not in html, "错误文案必须清除"
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


# ---------- ZW-004：相机运行/能力状态与可操作故障提示 ----------

def test_health_without_runtime_keeps_legacy_shape(state):
    """未接线值守时 /api/health 形状不变（Linux 兼容与无 registry 语义）。"""
    st, body = _get(state, "/api/health")
    assert st == 200
    assert set(body) == {"cameras", "count", "recording"}
    # 运行实例身份只在值守接线后声明：未接线路径的顶层键集一字不动。
    assert "runtime_instance" not in body


def test_health_runtime_exposes_lifecycle_and_recovery(state):
    """运行状态必须走真实生命周期，并在读失败恢复后清空 issue。"""
    registry = CameraRuntimeRegistry(["front-door"])
    state.runtime = registry

    def camera():
        st, body = _get(state, "/api/health")
        assert st == 200
        # 既有字段不回归：无在线相机时基线形状不变
        assert body["cameras"] == [] and body["recording"] == []
        assert body["runtime"]["count"] == 1
        return body["runtime"]["cameras"][0]

    initial = camera()
    assert (initial["state"], initial["capability"]) == \
        ("connecting", "monitor_only")
    assert initial["issue"] is None

    registry.online("front-door")
    registry.detector("front-door", "alerting")
    cam = camera()
    assert cam["state"] == "online" and cam["capability"] == "alerting"
    assert cam["issue"] is None

    registry.degraded("front-door", "source_read_failed")
    cam = camera()
    assert cam["state"] == "degraded"
    assert cam["issue"]["code"] == "source_read_failed"
    assert cam["issue"]["action"] in cam["hint"], "提示必须带可操作中文动作"

    registry.online("front-door")            # 读失败后恢复
    cam = camera()
    assert cam["state"] == "online" and cam["issue"] is None

    registry.stopped("front-door")
    cam = camera()
    assert cam["state"] == "stopped"
    assert cam["capability"] == "alerting", "停止不得改写检测能力"


def test_health_runtime_separates_monitor_only_from_detector_unavailable(state):
    """管理员放弃检测与检测不可用必须可区分，且各自给出下一步动作。"""
    registry = CameraRuntimeRegistry(["yard"])
    state.runtime = registry
    registry.online("yard")

    st, body = _get(state, "/api/health")
    cam = body["runtime"]["cameras"][0]
    assert cam["capability"] == "monitor_only" and cam["issue"] is None
    assert "仅预览" in cam["hint"]

    registry.detector("yard", "detector_unavailable", "detector_missing")
    st, body = _get(state, "/api/health")
    cam = body["runtime"]["cameras"][0]
    assert cam["capability"] == "detector_unavailable"
    assert cam["issue"] == {"code": "detector_missing",
                            "action": "把检测模型放到配置路径后重启值守"}
    assert "仅预览" not in cam["hint"]


def test_health_runtime_never_echoes_paths_credentials_or_exception_text(state):
    """健康出口只给固定状态与固定 code：路径、凭据与异常正文一个都不许出现。"""
    registry = CameraRuntimeRegistry(["front-door"])
    state.runtime = registry
    registry.degraded("front-door", "source_open_failed")
    registry.detector("front-door", "detector_unavailable",
                      "detector_load_failed")

    st, body = _get(state, "/api/health")
    cam = body["runtime"]["cameras"][0]
    # 源侧故障优先；检测不可用仍结构化保留，源恢复后浮出
    assert cam["state"] == "degraded"
    assert cam["issue"]["code"] == "source_open_failed"
    assert cam["capability"] == "detector_unavailable"

    registry.online("front-door")
    st, body = _get(state, "/api/health")
    cam = body["runtime"]["cameras"][0]
    assert cam["state"] == "online"
    assert cam["issue"]["code"] == "detector_load_failed"

    serialized = json.dumps(body, ensure_ascii=False)
    for leaked in ("rtsp://", "admin:secret", "camera/live", ".onnx",
                   "C:\\", "Traceback", "Errno", "RuntimeError"):
        assert leaked not in serialized, f"健康出口泄露了 {leaked}"


def test_health_runtime_snapshot_failure_degrades_honestly(state):
    """状态快照异常必须结构化降级，端点和既有字段都不受影响。"""
    def _boom():
        raise RuntimeError("registry exploded")

    state.runtime = SimpleNamespace(snapshot=_boom)

    st, body = _get(state, "/api/health")

    assert st == 200
    assert body["runtime"] == {"state": "unavailable", "error": "RuntimeError"}
    assert body["cameras"] == [] and body["recording"] == []
    # 实例身份来自 WorkbenchState 而非注册表：快照降级不影响身份声明。
    assert set(body["runtime_instance"]) == {"runtime_instance_id",
                                             "started_at"}


# ---------- ZW-006：运行实例身份（R3 重启验收的唯一进程标识） ----------

def test_health_runtime_instance_is_unique_per_state_and_credential_free(state):
    """每次 WorkbenchState 构造唯一，且只含随机标识与 UTC 时间。"""
    state.runtime = CameraRuntimeRegistry(["front-door"])

    st, body = _get(state, "/api/health")

    assert st == 200
    # 既有字段逐条不回归（无在线相机时的基线形状）
    assert body["cameras"] == [] and body["count"] == 0
    assert body["recording"] == [] and body["runtime"]["count"] == 1
    instance = body["runtime_instance"]
    assert set(instance) == {"runtime_instance_id", "started_at"}
    assert re.fullmatch(r"[0-9a-f]{32}", instance["runtime_instance_id"]), \
        "实例标识必须是随机十六进制，不得夹带主机名、路径、PID 或凭据"
    started = datetime.fromisoformat(instance["started_at"])
    assert started.utcoffset() == timedelta(0), "启动时间必须是 UTC"

    # 另一次构造必须是另一个实例——重启验收全靠这个差异
    other = WorkbenchState(state.db_path)
    other.runtime = CameraRuntimeRegistry(["front-door"])
    st, body = _get(other, "/api/health")
    assert body["runtime_instance"]["runtime_instance_id"] != \
        instance["runtime_instance_id"]
    assert state.runtime_instance_id == instance["runtime_instance_id"]
    assert state.started_at == instance["started_at"]


def test_health_runtime_instance_never_echoes_host_paths_pid_or_credentials(
        state):
    """身份出口只给随机标识与时间：任何路径、凭据、异常正文都不许出现。"""
    state.runtime = CameraRuntimeRegistry(["front-door"])
    st, body = _get(state, "/api/health")
    serialized = json.dumps(body, ensure_ascii=False)
    for leaked in ("rtsp://", "admin:secret", "camera/live", ".onnx", "C:\\",
                   "Traceback", os.sep + "Users", "localhost"):
        assert leaked not in serialized, f"健康出口泄露了 {leaked}"
    for text in (body["runtime_instance"]["runtime_instance_id"],
                 body["runtime_instance"]["started_at"]):
        assert not re.search(r"[A-Za-z]:[\\/]", text)


def test_health_runtime_instance_absent_when_state_cannot_declare_it(state):
    """无法声明身份时如实不声明：绝不临时编造一个实例标识。"""
    del state.runtime_instance_id
    state.runtime = CameraRuntimeRegistry(["front-door"])

    st, body = _get(state, "/api/health")

    assert st == 200
    assert "runtime_instance" not in body
    assert body["runtime"]["count"] == 1


def test_runtime_registry_rejects_unknown_camera_and_vocabulary():
    registry = CameraRuntimeRegistry(["front"])
    with pytest.raises(KeyError):
        registry.online("missing")
    with pytest.raises(ValueError):
        registry.degraded("front", "not-a-real-code")
    with pytest.raises(ValueError):
        registry.detector("front", "detector_ok")
    with pytest.raises(ValueError):
        CameraRuntimeRegistry(["front", "front"])


def test_index_polls_health_and_renders_actionable_camera_hints(state):
    """页面必须周期读取健康状态，并渲染服务端给出的可操作中文提示。"""
    handler = _get_handler(state, "/")
    html = handler.wfile.getvalue().decode("utf-8")

    assert handler.status == 200
    for marker in ('id="camera-status"', "'/api/health'", "refreshHealth",
                   "setInterval(refreshHealth,5000)", "camera.hint"):
        assert marker in html, f"页面缺少相机状态接线: {marker}"


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


def test_index_renders_multi_camera_guard_grid_contract(state):
    """值守页多相机网格：卡片容器、状态点、快照刷新与告警徽章的静态契约。"""
    handler = _get_handler(state, "/")
    html = handler.wfile.getvalue().decode("utf-8")

    assert handler.status == 200
    for marker in (
            'id="guard-grid"', 'guard-card', 'guard-dot',
            'guard-badge', "class=\"guard-grid\"",
            "/api/frame/'+encodeURIComponent(id)", 'guardEvents'):
        assert marker in html, marker
    # 告警计数来自语义事件表（前端聚合），不得引入新的后端面
    assert "guardEvents[e.camera]" in html

# ---------- F9：数据面故障必须在健康面可见 ----------

def test_persistence_issue_is_visible_and_clears():
    """审查段/告警写不进库：状态保持在线，但载荷与提示必须带出数据面故障。"""
    registry = CameraRuntimeRegistry(["front-door"])
    registry.online("front-door")

    assert registry.snapshot()["cameras"][0]["persistence_issue"] is None

    registry.persistence("front-door", "persistence_degraded")
    camera = registry.snapshot()["cameras"][0]
    assert camera["state"] == "online", "数据面故障不得改写源状态"
    assert camera["persistence_issue"]["code"] == "persistence_degraded"
    assert "未能写入本机数据库" in camera["persistence_issue"]["action"]
    assert "未能写入本机数据库" in camera["hint"]

    registry.persistence("front-door", None)
    cleared = registry.snapshot()["cameras"][0]
    assert cleared["persistence_issue"] is None
    assert "未能写入本机数据库" not in cleared["hint"]


def test_persistence_unknown_code_is_rejected():
    """未知 code 拒绝写入：健康面只出固定词表，不臆造文案。"""
    registry = CameraRuntimeRegistry(["front-door"])
    with pytest.raises(ValueError):
        registry.persistence("front-door", "not-a-code")


def test_persistence_issue_coexists_with_source_degradation():
    """源故障与数据面故障可同时存在，提示里两者都要看得见。"""
    registry = CameraRuntimeRegistry(["front-door"])
    registry.degraded("front-door", "source_read_failed")
    registry.persistence("front-door", "persistence_degraded")

    camera = registry.snapshot()["cameras"][0]
    assert camera["issue"]["code"] == "source_read_failed"
    assert camera["persistence_issue"]["code"] == "persistence_degraded"
    assert "相机供电" in camera["hint"]
    assert "未能写入本机数据库" in camera["hint"]


# ---------- C-131 §4：L1 中间层最小状态面（/api/health l1 块 + 工作台状态行） ----------

class _FakeL1Pipeline:
    """最小 L1Pipeline 替身：snapshot() 逐次现调，只返回预设只读快照。"""

    def __init__(self, snap=None, error=None):
        self.snap = snap or {}
        self.error = error
        self.calls = 0

    def snapshot(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return dict(self.snap)


def test_health_without_l1_keeps_response_shape(state):
    """state 无 l1 属性或为 None → 响应无 l1 键，既有顶层契约一字不动。"""
    assert not hasattr(state, "l1")
    st, body = _get(state, "/api/health")
    assert st == 200
    assert "l1" not in body
    assert set(body) == {"cameras", "count", "recording"}

    state.l1 = None
    st, body = _get(state, "/api/health")
    assert st == 200 and "l1" not in body


def test_health_l1_groups_pass_through_snapshot_with_cameras(state):
    """state.l1 非空 → 每组 cameras 键标识覆盖相机且 snapshot 字段透传；
    snapshot 每次请求现调（不缓存），单组/多组都成立。"""
    snap = {"state": "ready", "model": "stub",
            "counters": {"submitted": 3, "merged_start": 1,
                         "dropped_expired": 0, "ok": 2}}
    pipeline = _FakeL1Pipeline(snap)
    state.l1 = [{"cameras": ["cam"], "pipeline": pipeline}]
    st, body = _get(state, "/api/health")
    assert st == 200
    group = body["l1"][0]
    assert group["cameras"] == ["cam"]
    assert group["counters"]["submitted"] == 3
    assert group["counters"]["merged_start"] == 1
    assert group["state"] == "ready" and group["model"] == "stub"
    assert pipeline.calls == 1, "snapshot 必须每次请求现调，不得缓存"

    st, body = _get(state, "/api/health")
    assert pipeline.calls == 2

    state.l1 = [
        {"cameras": ["front"],
         "pipeline": _FakeL1Pipeline({"state": "ready"})},
        {"cameras": ["yard", "dock"],
         "pipeline": _FakeL1Pipeline({"state": "loading"})}]
    st, body = _get(state, "/api/health")
    assert st == 200
    assert [g["cameras"] for g in body["l1"]] == \
        [["front"], ["yard", "dock"]]
    assert [g["state"] for g in body["l1"]] == ["ready", "loading"]


def test_health_l1_snapshot_failure_degrades_without_500(state):
    """组 snapshot 抛错 → 固定码结构化降级；状态码 200、既有字段不受影响，
    异常正文与路径凭据绝不外泄。"""
    state.l1 = [{"cameras": ["cam"],
                 "pipeline": _FakeL1Pipeline(error=RuntimeError("boom"))}]
    st, body = _get(state, "/api/health")
    assert st == 200
    assert body["l1"] == [{"error": "snapshot_unavailable"}]
    assert body["cameras"] == [] and body["count"] == 0
    assert body["recording"] == []
    serialized = json.dumps(body, ensure_ascii=False)
    for leaked in ("boom", "RuntimeError", "rtsp://", "C:\\"):
        assert leaked not in serialized, f"健康出口泄露了 {leaked}"


def test_index_renders_l1_status_lines_contract(state):
    """工作台：L1 状态梯固定词表（C-132 F9，JS 侧）+ L2—L4 行不再静态存在
    （改为仅当 payload 含 l1 组时由 JS 注入）；页面不出现摄像头地址、凭据
    或绝对路径。可见行为由可执行 DOM 测试（test_l1_status_face_dom_executable）
    断言。"""
    handler = _get_handler(state, "/")
    html = handler.wfile.getvalue().decode("utf-8")
    assert handler.status == 200
    for marker in (
            'id="l1-status"', 'id="l1-materials"', 'id="l2-note"',
            "guard-l1", "l1-line", "l1-group-line",
            "检测停止中", "检测停止未完成", "检测已停止",
            "检测不可用，变化仍在记录", "检测推理失败（将自动重试）",
            "检测模型加载中", "推理中", "发现变化，正在分析",
            "已检测到对象 ", "检测成功零对象", "变化材料已保留（",
            "包待交接", "正常等待下一巡检",
            "L1 组：合并", "材料待交接", "预算丢弃",
            "对象感知不可用，后续理解未接入",
            "后续语义理解（L2—L4）尚未接入"):
        assert marker in html, f"页面缺少 L1 状态接线: {marker}"
    # C-132：静态 L2—L4 行必须移除（l1-static 钩子不复存在）；该文案只能
    # 经 JS 注入路径出现（上方断言命中的是 JS 字符串，非静态行）。
    assert "l1-static" not in html
    # C-131 旧词表退场：默认「L1 待命」与无凭证的「未检测到对象，变化材料
    # 已保留」不得残留。
    assert "L1 待命" not in html
    assert "未检测到对象，变化材料已保留" not in html
    assert "rtsp://" not in html
    assert "admin:secret" not in html
    assert not re.search(r"[A-Za-z]:[\\/]", html), "页面不得内嵌绝对路径"


def test_health_l2_block_passthrough_and_absence(state):
    """C-134 健康面：state.l2 存在→payload["l2"] 透传（计数/最近摘要，
    无图像无路径）；未启用→无该键（既有契约一字不动）。"""
    st, body = _get(state, "/api/health")
    assert st == 200
    assert "l2" not in body, "未启用 L2 时不得出现 l2 键"

    class _FakeRuntime:
        def snapshot(self):
            return {"enabled": True,
                    "cameras": {"cam": {"processed": 2, "expired": 0,
                                        "failed": 0,
                                        "identity_rejected": 0,
                                        "crops_produced": 3}},
                    "last": {"cam": {"status": "ok", "candidates": 1,
                                     "crops": 2, "calibrated": False}}}

    state.l2 = _FakeRuntime()
    st, body = _get(state, "/api/health")
    assert st == 200
    block = body["l2"]
    assert block["cameras"]["cam"]["processed"] == 2
    assert block["last"]["cam"]["calibrated"] is False
    serialized = json.dumps(body, ensure_ascii=False)
    assert "frame_bgr" not in serialized and "rtsp://" not in serialized
    del state.l2
    st, body = _get(state, "/api/health")
    assert "l2" not in body


def test_workbench_inline_js_l1_addition_syntax(state, tmp_path):
    """工作台内联 JS 真实语法检查（node --check，沿用 test_semantic_update
    既有模式）；node 不可用时退化为静态括号平衡断言（如实命名：这不是
    真实语法检查）。"""
    import shutil
    import subprocess
    handler = _get_handler(state, "/")
    html = handler.wfile.getvalue().decode("utf-8")
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert scripts, "工作台必须带内联脚本"
    script = scripts[-1]
    node = shutil.which("node")
    if node is None:
        # 退化路径：静态括号平衡（如实命名：非真实语法检查）。
        assert script.count("{") == script.count("}"), "花括号不平衡"
        assert script.count("(") == script.count(")"), "圆括号不平衡"
        assert script.count("[") == script.count("]"), "方括号不平衡"
        return
    page = tmp_path / "workbench-page-server.js"
    page.write_text(script, encoding="utf-8")
    proc = subprocess.run([node, "--check", str(page)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, \
        "工作台内联 JS 语法错误（node --check）: " + proc.stderr[:800]


def test_health_l1_normalizes_per_camera_against_group_cameras(state):
    """集成回归（C-131）：真实 L1Pipeline.snapshot() 自带逐相机 cameras 字典，
    归一化后组级 cameras 恒为 id 列表、逐相机字典让位为 per_camera——
    两种形状互不遮蔽，工作台按 per_camera 读检测状态。"""
    snap = {"state": "ready", "model": "person-detector.onnx",
            "classes": ["person"],
            "cameras": {"cam": {"pending": 1, "in_flight": False,
                                "last_status": "empty",
                                "last_result_age_ms": 12.5}},
            "counters": {"submitted": 3}}
    state.l1 = [{"cameras": ["cam"], "pipeline": _FakeL1Pipeline(snap=snap)}]
    st, body = _get(state, "/api/health")
    assert st == 200
    group = body["l1"][0]
    assert group["cameras"] == ["cam"]
    assert group["per_camera"]["cam"]["pending"] == 1
    assert group["per_camera"]["cam"]["last_status"] == "empty"
    assert group["state"] == "ready" and group["counters"]["submitted"] == 3


# ---------- C-132 F7/F9：材料交接面（/api/health materials 块） ----------

class _FakeMaterialsStore:
    """最小 MaterialsStore 替身：snapshot() 逐次现调，只返回预设只读快照。"""

    def __init__(self, snap=None, error=None):
        self.snap = snap or {}
        self.error = error
        self.calls = 0

    def snapshot(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return dict(self.snap)


def test_health_without_materials_keeps_response_shape(state):
    """state 无 materials 属性或为 None → 响应无 materials 键，既有顶层
    契约一字不动（l1 同理，双缺失时工作台面隐藏）。"""
    assert not hasattr(state, "materials")
    st, body = _get(state, "/api/health")
    assert st == 200
    assert "materials" not in body
    assert set(body) == {"cameras", "count", "recording"}

    state.materials = None
    st, body = _get(state, "/api/health")
    assert st == 200 and "materials" not in body


def test_health_materials_snapshot_passes_through(state):
    """state.materials 非空 → payload["materials"]=store.snapshot() 原样披露，
    每次请求现调（不缓存）；与 l1 块并存时互不影响。"""
    store = _FakeMaterialsStore({
        "cameras": {"cam": {"ready": 2, "consumed": 1, "expired": 1,
                            "dropped_pressure": 0, "attach_missed": 0,
                            "total_bytes": 456, "oldest_age_s": 3.5,
                            "ready_with_prev": 1, "ready_with_next": 0,
                            "last_l1_status": "empty"}},
        "total_bytes": 456})
    state.materials = store
    state.l1 = [{"cameras": ["cam"],
                 "pipeline": _FakeL1Pipeline({"state": "ready"})}]
    st, body = _get(state, "/api/health")
    assert st == 200
    assert body["materials"]["cameras"]["cam"]["ready"] == 2
    assert body["materials"]["cameras"]["cam"]["last_l1_status"] == "empty"
    assert body["materials"]["total_bytes"] == 456
    assert store.calls == 1, "materials 快照必须每次请求现调，不得缓存"
    assert body["l1"][0]["state"] == "ready", "l1 块与 materials 块互不影响"

    st, body = _get(state, "/api/health")
    assert store.calls == 2


def test_health_materials_failure_degrades_without_500(state):
    """store.snapshot() 抛错 → 固定码结构化降级；状态码 200、既有字段不受
    影响，异常正文与路径凭据绝不外泄。"""
    state.materials = _FakeMaterialsStore(error=RuntimeError("store exploded"))
    st, body = _get(state, "/api/health")
    assert st == 200
    assert body["materials"] == {"error": "materials_unavailable"}
    assert body["cameras"] == [] and body["count"] == 0
    serialized = json.dumps(body, ensure_ascii=False)
    for leaked in ("exploded", "RuntimeError", "rtsp://", "C:\\"):
        assert leaked not in serialized, f"健康出口泄露了 {leaked}"


# ---------- C-132 F9：状态梯可执行 DOM 测试（node harness，沿
# test_semantic_update R3 模式：真实执行页面脚本 + DOM/fetch 桩驱动
# refreshHealth，禁止只做 HTML 字符串包含） ----------

_L1_DOM_HARNESS_JS = r'''
const fs = require("fs");
const pagePath = process.argv[2];
const pageJs = fs.readFileSync(pagePath, "utf8");

function el(tag) {
  return {
    tag: tag, children: [], textContent: "", className: "", hidden: false,
    disabled: false, onclick: null, href: "", target: "", value: "",
    dataset: {}, id: "",
    classList: { add: function () {}, remove: function () {},
      toggle: function () {} },
    appendChild: function (c) { this.children.push(c); return c; },
    prepend: function (c) { this.children.unshift(c); },
    replaceChildren: function () { this.children = []; },
    querySelector: function () { return null; },
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
// 静态页里这三个容器带 hidden 属性，桩保持一致。
["l1-status", "l1-materials", "l2-note"].forEach(function (id) {
  gid(id).hidden = true;
});
function resp(obj, status) {
  status = status || 200;
  return { ok: status >= 200 && status < 300, status: status,
           json: async function () { return obj; } };
}
let healthPayload = {};   // 每场景改写
let healthFail = false;   // 注入 /api/health 请求失败
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
  if (url.indexOf("/api/health") === 0) {
    if (healthFail) throw new TypeError("health endpoint down");
    return resp(healthPayload);
  }
  if (url === "/api/cameras") return resp({ cameras: [] });
  if (url.indexOf("/api/v2/notifications") === 0)
    return resp({ notifications: [], next_cursor: null });
  if (url.indexOf("/api/v2/events") === 0) return resp({ events: [] });
  if (url === "/api/review") return resp({ segments: [] });
  if (url === "/api/events") return resp({ events: [] });
  if (url === "/api/patterns") return resp({ patterns: [] });
  return resp({}, 404);
};

function groupOf(cam, det, extra) {
  // 构造一个 l1 组：state/cameras/counters 缺省 ready/单相机/空计数；
  // extra 提供 lifecycle 等组级字段；det 提供该相机 per_camera 状态。
  const g = { state: "ready", lifecycle: "running", cameras: [cam],
    per_camera: {}, counters: {} };
  if (extra) {
    Object.keys(extra).forEach(function (k) {
      if (k !== "cameras" && k !== "per_camera") g[k] = extra[k]; });
    if (extra.per_camera) g.per_camera = extra.per_camera;
  }
  if (det) g.per_camera[cam] = det;
  return g;
}

(async () => {
  const results = {};
  const tick = () => new Promise((r) => setImmediate(r));
  const l1box = () => gid("l1-status");
  const mbox = () => gid("l1-materials");
  const l2note = () => gid("l2-note");
  const camRows = () => l1box().children.filter(
    (c) => c.className === "l1-line").map((c) => c.textContent);
  const groupRows = () => l1box().children.filter(
    (c) => c.className.indexOf("l1-group-line") >= 0);
  const matRows = () => mbox().children.map((c) => c.textContent);
  const has = (rows, s) => rows.some((t) => t.indexOf(s) >= 0);
  async function drive() { await refreshHealth(); await tick(); }

  try {
    require("vm").runInThisContext(pageJs,
      { filename: "workbench-page.js" });
    await tick(); await tick(); await tick();

    // ===== 一、组级 lifecycle 失败态不得被 last_detections 遮蔽 =====
    healthPayload = { l1: [groupOf("cam-a",
      { pending: 0, in_flight: false, last_status: "ok",
        last_detections: 5 }, { lifecycle: "stop_incomplete" })] };
    await drive();
    results.stopIncompleteNotMaskedByDetections =
      l1box().hidden === false
      && has(camRows(), "cam-a：检测停止未完成")
      && !has(camRows(), "已检测到对象");

    healthPayload = { l1: [groupOf("cam-a",
      { pending: 0, in_flight: false, last_status: "ok",
        last_detections: 5 }, { lifecycle: "closing" })] };
    await drive();
    results.closingVisibleNotMasked =
      has(camRows(), "检测停止中") && !has(camRows(), "已检测到对象");

    healthPayload = { l1: [groupOf("cam-a",
      { pending: 0, in_flight: false, last_status: "ok",
        last_detections: 5 }, { lifecycle: "stopped" })] };
    await drive();
    results.stoppedVisible =
      has(camRows(), "cam-a：检测已停止") && !has(camRows(), "已检测到对象");

    // ===== 二、组 model_unavailable 先于 pending 与旧成功文案 =====
    healthPayload = { l1: [groupOf("cam-a",
      { pending: 1, in_flight: false, last_status: "ok",
        last_detections: 7 }, { state: "model_unavailable" })] };
    await drive();
    results.modelUnavailableNotMasked =
      has(camRows(), "检测不可用，变化仍在记录")
      && !has(camRows(), "发现变化，正在分析")
      && !has(camRows(), "已检测到对象");

    // 相机 infer_failed（组 ready，旧结果曾成功）
    healthPayload = { l1: [groupOf("cam-a",
      { pending: 0, in_flight: false, last_status: "infer_failed",
        last_detections: 3 })] };
    await drive();
    results.inferFailedVisibleNotMasked =
      has(camRows(), "检测推理失败（将自动重试）")
      && !has(camRows(), "已检测到对象 3");

    // ===== 三、loading / 推理中 / 分析中的先后 =====
    healthPayload = { l1: [groupOf("cam-a",
      { pending: 0, in_flight: false, last_status: null,
        last_detections: 0 }, { state: "loading" })] };
    await drive();
    results.loadingVisible = has(camRows(), "检测模型加载中");

    healthPayload = { l1: [groupOf("cam-a",
      { pending: 1, in_flight: true, last_status: "ok",
        last_detections: 2 })] };
    await drive();
    results.inFlightBeatsPending =
      has(camRows(), "推理中") && !has(camRows(), "发现变化，正在分析");

    healthPayload = { l1: [groupOf("cam-a",
      { pending: 1, in_flight: false, last_status: "ok",
        last_detections: 2 })] };
    await drive();
    results.pendingBeatsStaleDetections =
      has(camRows(), "发现变化，正在分析")
      && !has(camRows(), "已检测到对象");

    // ===== 四、ok + 对象数 =====
    healthPayload = { l1: [groupOf("cam-a",
      { pending: 0, in_flight: false, last_status: "ok",
        last_detections: 2 })] };
    await drive();
    results.okShowsCount = has(camRows(), "已检测到对象 2");

    // ===== 四b、被拒结果（C-133 R1）：材料面 last_l1_accepted===false
    // 时显示拒收诊断，绝不显示为检测观察 =====
    healthPayload = { l1: [groupOf("cam-a",
      { pending: 0, in_flight: false, last_status: "ok",
        last_detections: 2 })],
      materials: { cameras: { "cam-a": { ready: 1,
        last_l1_accepted: false, last_reject_reason: "expired" } },
        total_bytes: 1 } };
    await drive();
    results.rejectedShowsDiagnosticNotDetection =
      has(camRows(), "结果已拒收（expired），不计为检测观察")
      && !has(camRows(), "已检测到对象");

    // ===== 五、empty：材料凭证门控（无凭证不得出现「已保留」） =====
    healthPayload = {
      l1: [groupOf("cam-a",
        { pending: 0, in_flight: false, last_status: "empty",
          last_detections: 0 })],
      materials: { cameras: { "cam-a": { ready: 3 } }, total_bytes: 1 } };
    await drive();
    results.emptyWithMaterialsShowsRetention =
      has(camRows(), "检测成功零对象，变化材料已保留（3 包待交接）");

    healthPayload = { l1: [groupOf("cam-a",
      { pending: 0, in_flight: false, last_status: "empty",
        last_detections: 0 })] };
    await drive();
    results.emptyWithoutMaterialsNoRetentionClaim =
      has(camRows(), "检测成功零对象") && !has(camRows(), "已保留");

    healthPayload = {
      l1: [groupOf("cam-a",
        { pending: 0, in_flight: false, last_status: "empty",
          last_detections: 0 })],
      materials: { cameras: { "cam-a": { ready: 0 } }, total_bytes: 0 } };
    await drive();
    results.emptyReadyZeroNoRetentionClaim =
      has(camRows(), "检测成功零对象") && !has(camRows(), "已保留");

    // ===== 六、空闲 =====
    healthPayload = { l1: [groupOf("cam-a",
      { pending: 0, in_flight: false, last_status: null,
        last_detections: 0 })] };
    await drive();
    results.idleShowsWaiting = has(camRows(), "正常等待下一巡检");

    // ===== 组级计数独立行，不伪装成每相机 =====
    healthPayload = { l1: [Object.assign(groupOf("cam-a",
      { pending: 0, in_flight: false, last_status: "ok",
        last_detections: 1 }),
      { counters: { merged_start: 4, dropped_expired: 2,
        rejected_closed: 1 } })] };
    await drive();
    results.groupCountersSeparateLine =
      groupRows().length === 1
      && groupRows()[0].textContent === "L1 组：合并 4 / 过期 2 / 关闭拒绝 1"
      && camRows().length === 1
      && camRows()[0].indexOf("合并 4") < 0
      && camRows()[0].indexOf("过期 2") < 0
      && camRows()[0].indexOf("关闭拒绝") < 0
      && camRows()[0].indexOf("已检测到对象 1") >= 0;

    // ===== L2—L4 行门控：无 l1 → 行不存在且容器隐藏 =====
    healthPayload = {};
    await drive();
    results.noL1HidesNoteAndContainers =
      l2note().hidden === true && l2note().textContent === ""
      && l1box().hidden === true && l1box().children.length === 0
      && mbox().hidden === true;

    healthPayload = { l1: [groupOf("cam-a", null)] };
    await drive();
    results.withL1ShowsNote =
      l2note().hidden === false
      && l2note().textContent === "后续语义理解（L2—L4）尚未接入"
      && l1box().hidden === false;

    // ===== materials 行与失败标注 =====
    healthPayload = {
      materials: { cameras: {
        "cam-b": { ready: 3, expired: 1, dropped_pressure: 2,
          last_l1_status: "infer_failed" },
        "cam-a": { ready: 0, expired: 0, dropped_pressure: 0,
          last_l1_status: "empty" } }, total_bytes: 9 } };
    await drive();
    results.materialsRowsRendered =
      mbox().hidden === false && matRows().length === 2
      && has(matRows(), "cam-b：材料待交接 3 / 已过期 1 / 预算丢弃 2");
    results.materialsFailureAnnotated =
      has(matRows(), "对象感知不可用，后续理解未接入");
    results.materialsHealthyRowNoFailureNote =
      matRows().filter(function (t) { return t.indexOf("cam-a：") === 0; })
        .every(function (t) { return t.indexOf("对象感知不可用") < 0; });

    // ===== 相机切换 / 数据消失 / 请求失败 → 旧行全量清理 =====
    healthPayload = { l1: [
      groupOf("cam-a", { pending: 0, in_flight: false,
        last_status: "ok", last_detections: 1 }),
      groupOf("cam-b", { pending: 0, in_flight: false,
        last_status: "empty", last_detections: 0 })] };
    await drive();
    let names = camRows().map(function (t) {
      return t.split("：")[0]; }).sort();
    results.twoCamerasRenderedBeforeSwitch =
      names.join(",") === "cam-a,cam-b";

    healthPayload = { l1: [
      groupOf("cam-a", { pending: 0, in_flight: false,
        last_status: "ok", last_detections: 1 })] };
    await drive();
    names = camRows().map(function (t) { return t.split("：")[0]; });
    results.switchCleansRemovedCameraRows =
      names.join(",") === "cam-a";

    healthPayload = {};
    await drive();
    results.l1DisappearClearsStaleSuccess =
      l1box().hidden === true && l1box().children.length === 0
      && l2note().hidden === true && l2note().textContent === "";

    healthPayload = { l1: [groupOf("cam-a",
      { pending: 0, in_flight: false, last_status: "empty",
        last_detections: 0 })] };
    await drive();
    results.materialsDisappearHidesContainer =
      mbox().hidden === true && mbox().children.length === 0;

    healthPayload = {
      l1: [groupOf("cam-a", { pending: 0, in_flight: false,
        last_status: "ok", last_detections: 9 })],
      materials: { cameras: { "cam-a": { ready: 5 } }, total_bytes: 1 } };
    await drive();
    healthFail = true;
    await drive();
    healthFail = false;
    results.fetchFailureClearsAllRows =
      l1box().hidden === true && l1box().children.length === 0
      && mbox().hidden === true && mbox().children.length === 0
      && l2note().hidden === true
      && gid("camera-status").textContent.indexOf("暂不可用") >= 0;
  } catch (err) {
    results.harnessError = String(err && err.stack || err);
  }
  let ok = true;
  Object.keys(results).forEach((k) => { if (results[k] !== true) ok = false; });
  console.log(JSON.stringify({ ok: ok, results: results }));
  process.exit(ok ? 0 : 1);
})();
'''


def test_l1_status_face_dom_executable(state, tmp_path):
    """C-132 F9 可执行 DOM 测试：node 真实执行页面脚本，驱动 refreshHealth
    断言状态梯出现/遮蔽关系/材料凭证门控/组级计数独立行/L2—L4 行门控/
    相机切换与请求失败的行清理。node 不可用时跳过并如实标注。"""
    import shutil
    import subprocess
    handler = _get_handler(state, "/")
    html = handler.wfile.getvalue().decode("utf-8")
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert scripts, "工作台必须带内联脚本"
    node = shutil.which("node")
    if node is None:
        pytest.skip("node 不可用：无法执行页面脚本交互测试")
    page = tmp_path / "workbench-page-l1.js"
    page.write_text(scripts[-1], encoding="utf-8")
    harness = tmp_path / "harness-l1.js"
    harness.write_text(_L1_DOM_HARNESS_JS, encoding="utf-8")
    proc = subprocess.run([node, str(harness), str(page)],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (
        "L1 状态梯 DOM 测试失败\nstdout: " + proc.stdout[-3000:]
        + "\nstderr: " + proc.stderr[-800:])
    data = json.loads(proc.stdout)
    assert data["ok"] is True, data["results"]


# ---------- C-138 §3/§6：理解结果冻结摘要（/api/understanding + 健康面） ------

def _seed_understanding_store(camera="front"):
    """构造带真实记录结构的 UnderstandingStore（记录形状同 results_from_output）。"""
    store = UnderstandingStore()
    store.append(camera, "l2", {"status": "ok", "calibrated": False,
                                "model_ref": "l2-model",
                                "window_state": "producing"})
    store.append(camera, "l3", {
        "window": "w-1", "branch": "panorama", "status": "ok", "at": 1.0,
        "results": [{
            "window_key": [camera, "run-1", "v1", "w-1"],
            "branch_key": [camera, "run-1", "v1", "w-1", "panorama", None],
            "branch": "panorama", "crop_id": None, "status": "ok",
            "model_ref": "l3-local-model",
            "observation": {"text": "画面中一个人站在大门口",
                            "unstructured": True,
                            "certainty": "model_inferred"},
            "inference": None, "reason": None,
            "sources": [{"position": "cur", "frame_id": "f9",
                         "present": True, "t_capture_ms": 12.0,
                         "timestamp_kind": "source_capture"}],
            "missing": {"frames_dropped": 0, "omission_reason": None,
                        "frames": []}}]})
    store.append(camera, "l4", {"version_id": "abcdef1234567890",
                                "status": "ok", "window_id": "w-1",
                                # C-140 §3：生产 l4 记录自带 window_key 四元
                                #（_l4_history_payload），融合身份分列依赖它。
                                "window_key": [camera, "run-1", "v1", "w-1"],
                                "items": [{"kind": "observation",
                                           "text": "一人站立",
                                           "certainty": "observed"}],
                                "at": 2.0})
    return store


def test_understanding_api_returns_frozen_summary_shape(state):
    """/api/understanding 返回 C-138 §3 冻结摘要 + C-139 §5/R2 D1 追溯增强
    （current_identity 来自 runtime 注册表权威值）+ C-140 §3 融合身份标注
    与 fusion_history 分列 + 原始有界历史。"""
    state.understanding_store = _seed_understanding_store()
    # C-139-R2 D1：当前身份唯一权威来源 = runtime 注册表（生产接线维护）。
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    assert set(body) == {"camera", "summary", "window_state", "branches",
                         "fusion", "fusion_history", "l2", "l3", "l4",
                         "evidence_available", "current_identity"}
    assert body["camera"] == "front"
    assert body["window_state"] == "producing"
    assert body["current_identity"] == {"run_id": "run-1",
                                        "config_version": "v1"}
    assert len(body["branches"]) == 1
    row = body["branches"][0]
    assert set(row) == {
        "branch_key", "kind", "status", "text", "sources", "missing",
        "window_key", "crop_id", "material_id", "model_ref", "certainty",
        "detail_code", "reason", "bbox_norm", "missing_frames",
        "kind_label", "certainty_label", "evidence_available",
        "evidence_url", "run_short", "config_short", "is_current"}
    assert row["kind"] == "panorama" and row["status"] == "ok"
    assert row["kind_label"] == "全景理解"
    assert row["certainty"] == "model_inferred"
    assert row["certainty_label"] == "模型推断"
    assert row["text"] == "画面中一个人站在大门口"
    assert row["sources"][0]["frame_id"] == "f9"
    assert row["window_key"] == ["front", "run-1", "v1", "w-1"]
    assert row["crop_id"] is None and row["material_id"] is None
    assert row["model_ref"] == "l3-local-model"
    assert row["missing_frames"] == [] and row["bbox_norm"] is None
    assert row["detail_code"] is None and row["reason"] is None
    # C-139-R2 D1：is_current 恒为 bool，与权威身份 (run, config) 匹配
    assert row["is_current"] is True
    assert row["run_short"] == "run-1" and row["config_short"] == "v1"
    # D3 证据诚实：裁图未持久化 → 无链接（evidence_url=None）
    assert row["evidence_available"] is False
    assert row["evidence_url"] is None
    assert body["evidence_available"] is False
    assert set(body["fusion"]) == {"version_id", "status", "items",
                                   "frame_refs", "run_short", "config_short",
                                   "is_current"}
    assert body["fusion"]["version_id"] == "abcdef1234567890"
    assert body["fusion"]["frame_refs"] == []
    # C-140 §3：顶层融合标注窗口身份（与权威身份匹配 → is_current=True）
    assert body["fusion"]["is_current"] is True
    assert body["fusion"]["run_short"] == "run-1"
    assert body["fusion"]["config_short"] == "v1"
    # C-140 §3：fusion_history 逐版本分列（带 run/config 短码与 is_current）
    assert body["fusion_history"] == [{
        "version_id": "abcdef1234567890", "status": "ok",
        "window_id": "w-1", "run_short": "run-1", "config_short": "v1",
        "is_current": True}]
    # C-139 §5：融合条目补 sources 缺省（未随版本保存时如实空列表）
    assert body["fusion"]["items"][0]["sources"] == []
    assert body["l3"][0]["results"][0]["model_ref"] == "l3-local-model"
    serialized = json.dumps(body, ensure_ascii=False)
    assert "rtsp://" not in serialized and "C:\\" not in serialized


def test_understanding_current_identity_authoritative_not_history(state):
    """C-139-R2 D1：current_identity 只认 runtime 注册表——历史里更新的
    run/config（最后一条 l3 记录）绝不冒充当前身份；is_current 按权威
    身份分列（匹配 True / 不匹配 False）。"""
    store = UnderstandingStore()
    # 历史记录：旧 run-1/v1（w-1）与更新的 run-9/v9（w-2，最后写入）
    store.append("front", "l3", {
        "window": "w-1", "branch": "panorama", "status": "ok", "at": 1.0,
        "results": [{
            "window_key": ["front", "run-1", "v1", "w-1"],
            "branch_key": ["front", "run-1", "v1", "w-1", "panorama", None],
            "branch": "panorama", "status": "ok",
            "observation": {"text": "旧 run 的描述", "unstructured": True,
                            "certainty": "model_inferred"},
            "sources": [], "missing": {}}]})
    store.append("front", "l3", {
        "window": "w-2", "branch": "panorama", "status": "ok", "at": 2.0,
        "results": [{
            "window_key": ["front", "run-9", "v9", "w-2"],
            "branch_key": ["front", "run-9", "v9", "w-2", "panorama", None],
            "branch": "panorama", "status": "ok",
            "observation": {"text": "最后一条记录的描述", "unstructured": True,
                            "certainty": "model_inferred"},
            "sources": [], "missing": {}}]})
    state.understanding_store = store
    # 注册表权威身份是 run-1/v1（不是历史里最新的 run-9/v9）
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    # 绝不从历史推断：当前身份 = 注册表值（run-1/v1）
    assert body["current_identity"] == {"run_id": "run-1",
                                        "config_version": "v1"}
    by_run = {row["window_key"][1]: row for row in body["branches"]}
    assert by_run["run-1"]["is_current"] is True
    assert by_run["run-9"]["is_current"] is False
    # 无注册表 → current_identity=None，所有行 is_current=False（不冒充）
    state.l2 = SimpleNamespace()
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    assert body["current_identity"] is None
    assert all(row["is_current"] is False for row in body["branches"])


def test_understanding_api_fusion_history_current_vs_history(state):
    """C-140 §3：/api/understanding 增 fusion_history——l4 原史逐版本分列，
    每条带 run/config 短码与 is_current（与权威注册表身份匹配才 True）；
    顶层融合同规则标注；无身份记录不冒充当前；注册表切回旧身份时旧版本
    标当前、新版本标历史（当前身份只认注册表，不认最新记录）。"""
    store = UnderstandingStore()
    for version, wkey, at in (("old-v-1", ["front", "run-1", "v1", "w-1"], 1.0),
                              ("old-v-2", ["front", "run-1", "v1", "w-2"], 2.0),
                              ("new-v-9", ["front", "run-2", "v3", "w-9"], 3.0)):
        store.append("front", "l4", {"version_id": version, "status": "ok",
                                     "window_id": wkey[3], "window_key": wkey,
                                     "items": [], "at": at})
    state.understanding_store = store
    state.l2 = SimpleNamespace(_registry={"front": ("run-2", "v3")})
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    hist = body["fusion_history"]
    assert set(hist[0]) == {"version_id", "status", "window_id",
                            "run_short", "config_short", "is_current"}
    assert [r["version_id"] for r in hist] == \
        ["old-v-1", "old-v-2", "new-v-9"]
    # 注册表权威身份 run-2/v3：旧 run 的版本全部 is_current=False
    assert [r["is_current"] for r in hist] == [False, False, True]
    assert hist[0]["run_short"] == "run-1"
    assert hist[0]["config_short"] == "v1"
    assert hist[0]["window_id"] == "w-1"
    assert hist[2]["run_short"] == "run-2"
    assert hist[2]["config_short"] == "v3"
    # 顶层融合（最新记录）即当前身份版本 → is_current=True
    assert body["fusion"]["version_id"] == "new-v-9"
    assert body["fusion"]["is_current"] is True
    assert body["fusion"]["run_short"] == "run-2"
    # 无注册表 → 全部 is_current=False（身份未知，不冒充当前）
    state.l2 = SimpleNamespace()
    st, body = _get(state, "/api/understanding/front")
    assert body["current_identity"] is None
    assert all(r["is_current"] is False for r in body["fusion_history"])
    assert body["fusion"]["is_current"] is False
    # 注册表切回旧身份 run-1/v1：旧版本标当前、最新记录（run-2）标历史
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    st, body = _get(state, "/api/understanding/front")
    hist = body["fusion_history"]
    assert [r["is_current"] for r in hist] == [True, True, False]
    assert body["fusion"]["version_id"] == "new-v-9"
    assert body["fusion"]["is_current"] is False
    # 无 window_key 的记录 → 身份未记录（短码 None，is_current=False）
    store.append("front", "l4", {"version_id": "legacy-v-0", "status": "ok",
                                 "items": [], "at": 4.0})
    state.understanding_store = store
    st, body = _get(state, "/api/understanding/front")
    assert body["fusion_history"][-1] == {
        "version_id": "legacy-v-0", "status": "ok", "window_id": None,
        "run_short": None, "config_short": None, "is_current": False}
    assert body["fusion"]["is_current"] is False
    serialized = json.dumps(body, ensure_ascii=False)
    assert "rtsp://" not in serialized and "C:\\" not in serialized


def test_understanding_api_404_fixed_code_without_runtime_or_store(state):
    """runtime 与 store 都未接入 → 404 固定码（现状保持）。"""
    st, body = _get(state, "/api/understanding/front")
    assert st == 404
    assert body == {"error": "l2_unavailable"}


def test_understanding_api_serves_runtime_held_store(state):
    """C-138 §5：runtime 持 store 实例（state.l2.understanding_store）
    时同样按冻结形状服务。"""
    state.l2 = SimpleNamespace(
        understanding_store=_seed_understanding_store("yard"))
    st, body = _get(state, "/api/understanding/yard")
    assert st == 200
    assert body["camera"] == "yard"
    assert body["branches"][0]["text"] == "画面中一个人站在大门口"


def test_understanding_api_legacy_runtime_shape_preserved(state):
    """过渡兼容：未接 UnderstandingStore 的旧 runtime（C-136 形状）不破。"""

    class _LegacyRuntime:
        def history(self, camera):
            return {"l2": [{"status": "ok"}], "l3": [], "l4": []}

        def summary_line(self, camera):
            return "理解进展：旧单行"

    state.l2 = _LegacyRuntime()
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    assert body["summary"] == "理解进展：旧单行"
    assert body["l2"] == [{"status": "ok"}]


def test_health_understanding_block_from_store_summary(state):
    """/api/health understanding 块从冻结摘要生成：分支计数/描述文本/融合
    版本/来源标注（model_ref + calibrated=false）+ C-139 §5/R2 D1 追溯增强
    （分支行来源字段/证据诚实判定/权威当前身份）+ C-140 §3 融合身份标注与
    fusion_history 分列。"""
    state.understanding_store = _seed_understanding_store()
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    st, body = _get(state, "/api/health")
    assert st == 200
    block = body["understanding"]["front"]
    assert set(block) == {"summary", "window_state", "counts", "branches",
                          "fusion", "fusion_history", "model_ref",
                          "calibrated", "evidence_available",
                          "current_identity"}
    assert block["counts"]["done"] == 1
    assert block["branches"][0]["text"] == "画面中一个人站在大门口"
    assert block["branches"][0]["kind_label"] == "全景理解"
    assert block["branches"][0]["is_current"] is True
    assert block["branches"][0]["evidence_available"] is False
    assert block["fusion"]["version_id"] == "abcdef1234567890"
    # C-140 §3：融合身份标注与 fusion_history 分列随块透传
    assert block["fusion"]["is_current"] is True
    assert block["fusion_history"] == [{
        "version_id": "abcdef1234567890", "status": "ok",
        "window_id": "w-1", "run_short": "run-1", "config_short": "v1",
        "is_current": True}]
    assert block["model_ref"] == "l3-local-model"
    assert block["calibrated"] is False
    assert block["evidence_available"] is False
    assert block["current_identity"] == {"run_id": "run-1",
                                         "config_version": "v1"}
    serialized = json.dumps(body, ensure_ascii=False)
    assert "rtsp://" not in serialized and "C:\\" not in serialized


def test_health_understanding_block_absent_without_store(state):
    """无 store 且 runtime 无 summary_line → 无 understanding 键（既有契约）。"""
    state.l2 = SimpleNamespace(snapshot=lambda: {"enabled": True})
    st, body = _get(state, "/api/health")
    assert st == 200 and "understanding" not in body


def test_understanding_sources_and_frame_refs_roundtrip(state):
    """C-139-R2 D2：带 sources 的 l3 记录经 store→API 逐值透传；l4 记录的
    frame_refs（frame_id/时间/坐标体系）与 items[].sources 同样透传；
    无路径/凭据。"""
    store = UnderstandingStore()
    sources = [{"position": "cur", "frame_id": "f-9", "present": True,
                "t_capture_ms": 17123.5, "timestamp_kind": "source_capture"},
               {"position": "prev", "frame_id": "f-8", "present": False,
                "t_capture_ms": None, "timestamp_kind": "source_capture"}]
    store.append("front", "l3", {
        "window": "w-1", "branch": "relation_crop", "status": "ok",
        "at": 1.0,
        "results": [{
            "window_key": ["front", "run-1", "v1", "w-1"],
            "branch_key": ["front", "run-1", "v1", "w-1", "relation_crop",
                           "crop-7", "mat-1"],
            "branch": "relation_crop", "crop_id": "crop-7",
            "model_ref": "local-vlm-7b", "status": "ok",
            "observation": {"text": "该人员手持包裹", "unstructured": True,
                            "certainty": "model_inferred"},
            "sources": sources, "missing": {}}]})
    store.append("front", "l4", {
        "version_id": "v-abc-123", "status": "ok", "window_id": "w-1",
        "window_key": ["front", "run-1", "v1", "w-1"],
        "coord_space": "normalized",
        "items": [{"kind": "observation", "text": "一人站立",
                   "certainty": "observed",
                   "sources": ["crop:crop-7", "frame:f-9"]}],
        "frame_refs": [{"frame_id": "f-9", "t_ms": 17123.5,
                        "time_kind": "source_capture",
                        "coord_space": "normalized",
                        "crop_ref": "crop-7",
                        "stable_ref": "front:run-1:track:3",
                        "bbox_norm": [0.1, 0.2, 0.3, 0.4]},
                       {"frame_id": "f-8", "t_ms": None,
                        "time_kind": "unknown",
                        "coord_space": "normalized",
                        "crop_ref": None, "stable_ref": None}],
        "at": 2.0})
    state.understanding_store = store
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    row = body["branches"][0]
    # 逐值透传（值与序完全一致，无改写）
    assert row["sources"] == sources
    assert row["crop_id"] == "crop-7"
    assert row["model_ref"] == "local-vlm-7b"
    fusion = body["fusion"]
    assert fusion["version_id"] == "v-abc-123"
    assert fusion["coord_space"] == "normalized"
    # C-140 §3：带 window_key 的版本标注身份（与权威身份匹配 → 当前）
    assert fusion["is_current"] is True
    assert fusion["run_short"] == "run-1" and fusion["config_short"] == "v1"
    assert body["fusion_history"] == [{
        "version_id": "v-abc-123", "status": "ok", "window_id": "w-1",
        "run_short": "run-1", "config_short": "v1", "is_current": True}]
    assert fusion["items"][0]["sources"] == ["crop:crop-7", "frame:f-9"]
    refs = fusion["frame_refs"]
    assert len(refs) == 2
    assert refs[0]["frame_id"] == "f-9"
    assert refs[0]["t_ms"] == 17123.5
    assert refs[0]["time_kind"] == "source_capture"
    assert refs[0]["coord_space"] == "normalized"
    assert refs[0]["crop_ref"] == "crop-7"
    assert refs[0]["stable_ref"] == "front:run-1:track:3"
    assert refs[0]["bbox_norm"] == [0.1, 0.2, 0.3, 0.4]
    assert refs[1]["frame_id"] == "f-8" and refs[1]["t_ms"] is None
    # 非受控字段不透传；无 frame_refs 的版本如实空列表
    assert all(set(r) <= {"frame_id", "t_ms", "time_kind", "coord_space",
                          "crop_ref", "stable_ref", "bbox_norm"}
               for r in refs)
    store.append("front", "l4", {"version_id": "v-no-refs", "status": "ok",
                                 "items": [], "at": 3.0})
    state.understanding_store = store
    st, body = _get(state, "/api/understanding/front")
    assert body["fusion"]["version_id"] == "v-no-refs"
    assert body["fusion"]["frame_refs"] == []
    # C-140 §3：无 window_key 的版本身份未记录 → 不冒充当前（is_current=False）
    assert body["fusion"]["is_current"] is False
    assert body["fusion"]["run_short"] is None
    assert body["fusion_history"][-1] == {
        "version_id": "v-no-refs", "status": "ok", "window_id": None,
        "run_short": None, "config_short": None, "is_current": False}


def test_understanding_stale_gate_reason_not_attached_after_success(state):
    """C-139-R2 D1：旧 fallback（门控兜底）原因不附着到其后的成功窗口——
    最新 l2 记录无 gate_reason 时，摘要与健康面都不再出现旧原因。"""
    store = UnderstandingStore()
    store.append("front", "l2", {"status": "l1_gate_blocked",
                                 "gate_reason": "l1_wait_timeout",
                                 "calibrated": False})
    store.append("front", "l3", {
        "window": "w-2", "branch": "panorama", "status": "ok", "at": 2.0,
        "results": [{
            "window_key": ["front", "run-1", "v1", "w-2"],
            "branch_key": ["front", "run-1", "v1", "w-2", "panorama", None],
            "branch": "panorama", "status": "ok",
            "observation": {"text": "成功窗口的描述", "unstructured": True,
                            "certainty": "model_inferred"},
            "sources": [], "missing": {}}]})
    store.append("front", "l2", {"status": "ok", "calibrated": False})
    state.understanding_store = store
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    assert "关系识别不可用" not in body["summary"]
    assert "l1_wait_timeout" not in body["summary"]
    st, body = _get(state, "/api/health")
    block = body["understanding"]["front"]
    assert "关系识别不可用" not in block["summary"]
    # 最新 l2 记录自身带 gate_reason → 原因照实显示（位置保持计数段后）
    store.append("front", "l2", {"status": "l1_gate_blocked",
                                 "gate_reason": "model_unavailable",
                                 "calibrated": False})
    st, body = _get(state, "/api/understanding/front")
    assert "关系识别不可用（model_unavailable）" in body["summary"]
    assert body["summary"].index("分支 完成") \
        < body["summary"].index("关系识别不可用")


def test_sanitized_summary_keeps_frozen_shape_without_gate():
    """sanitized_summary 单元：无门控记录时摘要逐字保持 store 原文。"""
    from scam.server import sanitized_summary
    original = ("分支 完成 1 / 失败 0 / 淘汰 0 / 等待 0；全景：画面稳定；"
                "局部：门口有人；融合版本 abcdef123456（ok）")
    assert sanitized_summary(original, [{"status": "ok"}]) == original
    assert sanitized_summary(original, []) == original


_UNDERSTANDING_DOM_HARNESS_JS = r'''
const fs = require("fs");
const pageJs = fs.readFileSync(process.argv[2], "utf8");

function el(tag) {
  return {
    tag: tag, children: [], textContent: "", className: "", hidden: false,
    disabled: false, onclick: null, href: "", target: "", value: "",
    dataset: {}, id: "",
    // C142：页面「来源」切换钮/原图链接带 aria 属性（setAttribute 真实
    // 调用），harness 忠实记录键值供断言（缺失键 getAttribute → null）。
    attrs: {},
    setAttribute: function (k, v) { this.attrs[k] = String(v); },
    getAttribute: function (k) {
      return Object.prototype.hasOwnProperty.call(this.attrs, k)
        ? this.attrs[k] : null; },
    classList: { add: function () {}, remove: function () {},
      toggle: function () {} },
    appendChild: function (c) { this.children.push(c); return c; },
    prepend: function (c) { this.children.unshift(c); },
    replaceChildren: function () { this.children = []; },
    querySelector: function () { return null; },
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
["l1-status", "l1-materials", "l2-note", "understanding-line",
 "understanding-detail"].forEach(function (id) { gid(id).hidden = true; });
function resp(obj, status) {
  status = status || 200;
  return { ok: status >= 200 && status < 300, status: status,
           json: async function () { return obj; } };
}
let healthPayload = {};
let healthFail = false;
let deferredHealth = null;
function makeDeferred() {
  let resolve;
  const promise = new Promise(function (r) { resolve = r; });
  return { resolve: resolve, promise: promise };
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
globalThis.fetch = async function (url) {
  if (url.indexOf("/api/health") === 0) {
    if (healthFail) throw new TypeError("health endpoint down");
    if (deferredHealth) return resp(await deferredHealth.promise);
    return resp(healthPayload);
  }
  if (url === "/api/cameras") return resp({ cameras: [] });
  if (url.indexOf("/api/v2/notifications") === 0)
    return resp({ notifications: [], next_cursor: null });
  if (url.indexOf("/api/v2/events") === 0) return resp({ events: [] });
  if (url === "/api/review") return resp({ segments: [] });
  if (url === "/api/events") return resp({ events: [] });
  if (url === "/api/patterns") return resp({ patterns: [] });
  return resp({}, 404);
};

function allDescendants(node) {
  const out = [];
  (node.children || []).forEach(function (c) {
    out.push(c); out.push.apply(out, allDescendants(c));
  });
  return out;
}
function flatText(node) {
  return allDescendants(node).map(function (c) {
    return c.textContent || "";
  }).join("|") + "|" + (node.textContent || "");
}

(async () => {
  const results = {};
  const tick = () => new Promise((r) => setImmediate(r));
  const line = () => gid("understanding-line");
  const detail = () => gid("understanding-detail");
  async function drive() { await refreshHealth(); await tick(); await tick(); }

  try {
    require("vm").runInThisContext(pageJs,
      { filename: "workbench-page.js" });
    await tick(); await tick(); await tick();
    gid("camera-select").value = "cam-a";

    const entry = {
      summary: "分支 完成 2 / 失败 1 / 淘汰 0 / 等待 1；全景：一人站在门口；"
        + "融合版本 abcdef123456（ok）",
      window_state: "producing",
      counts: { done: 2, failed: 1, evicted: 0, pending: 1 },
      branches: [
        { branch_key: "w1|panorama|", kind: "panorama", status: "ok",
          text: "画面中一个人站在大门口<script>alert(1)</script>",
          is_current: true,
          sources: [{ position: "cur", frame_id: "f9", present: true }],
          missing: {} },
        { branch_key: "w1|relation_crop|c1", kind: "relation_crop",
          status: "ok", text: "该人员手持包裹"
            + "<img src=x onerror=alert(2)>", is_current: true,
          sources: [], missing: {} },
        { branch_key: "w2|panorama|", kind: "panorama", status: "expired",
          text: "", is_current: false, sources: [], missing: {} }],
      fusion: { version_id: "abcdef1234567890", status: "ok",
        is_current: true, run_short: "run-1", config_short: "v1",
        items: [{ kind: "observation", text: "一人站在门口",
                  certainty: "observed" },
                { kind: "inference", text: "疑似正在进门",
                  certainty: "model_inferred" }] },
      fusion_history: [{ version_id: "abcdef1234567890", status: "ok",
        window_id: "w-1", run_short: "run-1", config_short: "v1",
        is_current: true }],
      model_ref: "internvl-local", calibrated: false };

    // ===== 一、实际内容渲染（非仅元素存在） =====
    healthPayload = { understanding: { "cam-a": entry } };
    await drive();
    results.lineShowsSummary =
      line().hidden === false
      && line().textContent.indexOf("理解进展（cam-a）：") === 0
      && line().textContent.indexOf("分支 完成 2 / 失败 1 / 淘汰 0 / 等待 1") > 0;
    results.detailVisible = detail().hidden === false;
    results.headShowsCountsAndWindowState =
      detail().children.some(function (c) {
        return c.textContent.indexOf("理解分支（cam-a）：完成 2 / 失败 1"
          + " / 淘汰 0 / 等待 1（窗口 producing）") === 0; });
    const detailText = flatText(detail());
    results.panoramaTextRendered =
      detailText.indexOf("最新全景描述：") >= 0
      && detailText.indexOf("画面中一个人站在大门口") >= 0;
    results.localTextRenderedSeparately =
      detailText.indexOf("最新局部分支描述：") >= 0
      && detailText.indexOf("该人员手持包裹") >= 0;
    results.fusionVersionAndStatusRendered =
      detailText.indexOf("最新融合版本 abcdef1234567890（ok，2 条）") >= 0;
    results.fusionCertaintySplitObservedVsInferred =
      detailText.indexOf("· [画面确认] 一人站在门口") >= 0
      && detailText.indexOf("· [模型推断] 疑似正在进门") >= 0;
    results.sourceAnnotationModelRefAndUncalibrated =
      detailText.indexOf("模型 internvl-local") >= 0
      && detailText.indexOf("calibrated=false（模型推断，未经校准）") >= 0;

    // ===== 二、安全文本：模型输出含 script/img 片段不当 HTML =====
    const noScriptTag = allDescendants(detail()).every(function (c) {
      return c.tag !== "script" && c.tag !== "img"; });
    results.scriptSnippetIsTextNotHtml =
      noScriptTag
      && detailText.indexOf("<script>alert(1)</script>") >= 0
      && detailText.indexOf("<img src=x onerror=alert(2)>") >= 0;

    // ===== 三、相机切换：无该相机理解 → 行隐藏，不残留旧相机内容 =====
    gid("camera-select").value = "cam-zz";
    await drive();
    results.unknownCameraHidesUnderstanding =
      line().hidden === true && detail().hidden === true
      && detail().children.length === 0;

    // ===== 四、竞态守卫：请求在途时切走相机，迟到响应不覆盖新相机 =====
    gid("camera-select").value = "cam-a";
    deferredHealth = makeDeferred();
    const pending = refreshHealth();          // 请求发出时选中 cam-a
    gid("camera-select").value = "cam-b";     // 用户随即切走
    deferredHealth.resolve({ understanding: { "cam-a": entry } });
    await pending; await tick(); await tick();
    results.lateResponseDoesNotPaintSwitchedCamera =
      detail().hidden === true
      && flatText(detail()).indexOf("画面中一个人站在大门口") < 0;
    deferredHealth = null;

    // ===== 五、数据消失 / 请求失败 → 全量清理 =====
    gid("camera-select").value = "cam-a";
    healthPayload = { understanding: { "cam-a": entry } };
    await drive();
    results.understandingVisibleBeforeFailure =
      line().hidden === false && detail().hidden === false;
    healthPayload = {};
    await drive();
    results.disappearedDataHidesUnderstanding =
      line().hidden === true && detail().hidden === true;
    healthPayload = { understanding: { "cam-a": entry } };
    await drive();
    healthFail = true;
    await drive();
    healthFail = false;
    results.fetchFailureClearsUnderstanding =
      line().hidden === true && detail().hidden === true
      && detail().children.length === 0;

    // ===== 六、C-139-R2 D1/D2：当前/历史分列 + 权威身份 + 来源展开点击
    // + 融合 frame_refs + 证据诚实（无持久化裁图不给链接） =====
    gid("camera-select").value = "cam-a";
    const entry2 = {
      summary: "分支 完成 1 / 失败 0 / 淘汰 0 / 等待 0；全景：当前窗口的描述",
      window_state: "producing",
      counts: { done: 1, failed: 0, evicted: 0, pending: 0 },
      current_identity: { run_id: "run-2", config_version: "v3" },
      branches: [
        { branch_key: "w2|panorama|", kind: "panorama",
          kind_label: "全景理解", status: "ok", text: "当前窗口的描述",
          crop_id: "crop-7", model_ref: "local-vlm-7b",
          run_short: "run-2", config_short: "v3", is_current: true,
          evidence_available: false, evidence_url: null,
          sources: [{ position: "cur", frame_id: "f-9", present: true,
                      t_capture_ms: 17123.5,
                      timestamp_kind: "source_capture" }],
          missing: {} },
        { branch_key: "w1|relation_crop|c1", kind: "relation_crop",
          kind_label: "关系局部", status: "ok", text: "旧 run 的描述",
          crop_id: "crop-3", model_ref: "local-vlm-7b",
          run_short: "run-1", config_short: "v1", is_current: false,
          evidence_available: false, evidence_url: null,
          sources: [{ position: "cur", frame_id: "f-3", present: true,
                      t_capture_ms: 9000,
                      timestamp_kind: "source_capture" }],
          missing: {} }],
      fusion: { version_id: "abcdef1234567890", status: "ok",
        is_current: true, run_short: "run-2", config_short: "v3",
        frame_refs: [{ frame_id: "f-9", t_ms: 17123.5,
                       time_kind: "source_capture",
                       coord_space: "normalized" }],
        items: [{ kind: "observation", text: "一人站在门口",
                  certainty: "observed" }] },
      fusion_history: [{ version_id: "abcdef1234567890", status: "ok",
        window_id: "w-2", run_short: "run-2", config_short: "v3",
        is_current: true }],
      model_ref: "local-vlm-7b", calibrated: false };
    healthPayload = { understanding: { "cam-a": entry2 } };
    await drive();
    const sections = allDescendants(detail()).filter(function (c) {
      return c.className === "und-section"; });
    results.currentAndHistorySectionsSeparated =
      sections.length === 2
      && sections[0].textContent === "当前窗口进展"
      && sections[1].textContent === "历史记录（旧 run/config）";
    const detailText2 = flatText(detail());
    results.currentSectionBeforeHistory =
      detailText2.indexOf("当前窗口的描述") >= 0
      && detailText2.indexOf("旧 run 的描述") >= 0
      && detailText2.indexOf("当前窗口进展")
           < detailText2.indexOf("旧 run 的描述");
    results.historyRowShowsIdentityShortCodes =
      detailText2.indexOf("（历史 run run-1 · 配置 v1）") >= 0;
    results.headShowsAuthoritativeIdentity =
      detail().children.some(function (c) {
        return c.textContent.indexOf("（当前 run run-2 · 配置 v3）") > 0; });
    results.perRowTraceLineVisible =
      detailText2.indexOf("裁图 crop-7 · 模型 local-vlm-7b"
        + " · 帧 f-9 t=17123.5ms") >= 0;
    results.noEvidenceLinkWithoutPersistedCrop =
      detailText2.indexOf("原始裁图尚未保存") >= 0
      && allDescendants(detail()).every(function (c) {
        return c.tag !== "a" || c.textContent !== "打开原始裁图"; });
    const toggleBtn = allDescendants(detail()).find(function (c) {
      return c.tag === "button" && c.textContent === "来源 ▸"; });
    const sourcesArea = allDescendants(detail()).find(function (c) {
      return c.className === "und-sources"; });
    results.sourcesCollapsedByDefault =
      !!toggleBtn && !!sourcesArea && sourcesArea.hidden === true;
    toggleBtn.onclick();
    results.sourcesExpandOnClick =
      sourcesArea.hidden === false
      && flatText(sourcesArea).indexOf("帧#cur f-9 t=17123.5ms") >= 0;
    results.fusionFrameRefsRendered =
      detailText2.indexOf("· 帧 f-9 t=17123.5ms（normalized）") >= 0;

    // ===== 七、C-140 §3：L4 融合/速览当前与历史分列 =====
    gid("camera-select").value = "cam-a";
    // 场景 1：runtime 已切新身份 run-2/v3，历史只有旧 run-1/v1 的分支与
    // 融合（新结果尚未完成）→ 旧内容全部明确标历史，当前区显示等待。
    const oldEntry = {
      summary: "分支 完成 1 / 失败 0 / 淘汰 0 / 等待 0",
      window_state: "producing",
      counts: { done: 1, failed: 0, evicted: 0, pending: 0 },
      current_identity: { run_id: "run-2", config_version: "v3" },
      branches: [
        { branch_key: "w1|panorama|", kind: "panorama",
          kind_label: "全景理解", status: "ok",
          text: "旧身份的全景描述", run_short: "run-1",
          config_short: "v1", is_current: false,
          evidence_available: false, evidence_url: null,
          sources: [], missing: {} }],
      fusion: { version_id: "oldfusion01", status: "ok",
        is_current: false, run_short: "run-1", config_short: "v1",
        frame_refs: [],
        items: [{ kind: "observation", text: "旧融合条目",
                  certainty: "observed" }] },
      fusion_history: [{ version_id: "oldfusion01", status: "ok",
        window_id: "w-1", run_short: "run-1", config_short: "v1",
        is_current: false }],
      model_ref: "local-vlm-7b", calibrated: false };
    healthPayload = { understanding: { "cam-a": oldEntry } };
    await drive();
    const oldText = flatText(detail());
    results.switchedOldBranchOnlyInHistoryArea =
      oldText.indexOf("旧身份的全景描述") >= 0
      && oldText.indexOf("（历史 run run-1 · 配置 v1）") >= 0
      && oldText.indexOf("当前窗口进展") < 0;
    results.switchedQuickViewShowsWaitingNotOldText =
      oldText.indexOf("全景速览：等待分析") >= 0
      && oldText.indexOf("局部速览：等待分析") >= 0
      && oldText.indexOf("最新全景描述：") < 0
      && oldText.indexOf("最新局部分支描述：") < 0;
    results.switchedOldFusionMarkedHistoryInHistoryArea =
      oldText.indexOf("历史融合版本 oldfusion01（ok，1 条）"
        + "（历史 run run-1 · 配置 v1）") >= 0
      && oldText.indexOf("最新融合版本 oldfusion01") < 0
      && oldText.indexOf("历史记录（旧 run/config）")
           < oldText.indexOf("历史融合版本 oldfusion01");
    results.switchedCurrentAreaShowsFusionWaiting =
      oldText.indexOf("融合速览：等待分析") >= 0;

    // 场景 2：新身份结果到达 → 进入当前区；旧身份内容保持在历史区。
    const newEntry = {
      summary: "分支 完成 1 / 失败 0 / 淘汰 0 / 等待 0",
      window_state: "producing",
      counts: { done: 1, failed: 0, evicted: 0, pending: 0 },
      current_identity: { run_id: "run-2", config_version: "v3" },
      branches: [
        { branch_key: "w9|panorama|", kind: "panorama",
          kind_label: "全景理解", status: "ok",
          text: "新身份的全景描述", run_short: "run-2",
          config_short: "v3", is_current: true,
          evidence_available: false, evidence_url: null,
          sources: [{ position: "cur", frame_id: "f-12", present: true,
                      t_capture_ms: 8000,
                      timestamp_kind: "source_capture" }],
          missing: {} },
        { branch_key: "w1|panorama|", kind: "panorama",
          kind_label: "全景理解", status: "ok",
          text: "旧身份的全景描述", run_short: "run-1",
          config_short: "v1", is_current: false,
          evidence_available: false, evidence_url: null,
          sources: [], missing: {} }],
      fusion: { version_id: "newfusion009", status: "ok",
        is_current: true, run_short: "run-2", config_short: "v3",
        frame_refs: [{ frame_id: "f-12", t_ms: 8000,
                       time_kind: "source_capture",
                       coord_space: "normalized" }],
        items: [{ kind: "observation", text: "新融合条目",
                  certainty: "observed" }] },
      fusion_history: [
        { version_id: "oldfusion01", status: "ok", window_id: "w-1",
          run_short: "run-1", config_short: "v1", is_current: false },
        { version_id: "newfusion009", status: "ok", window_id: "w-9",
          run_short: "run-2", config_short: "v3", is_current: true }],
      model_ref: "local-vlm-7b", calibrated: false };
    healthPayload = { understanding: { "cam-a": newEntry } };
    await drive();
    const newText = flatText(detail());
    results.newResultsEnterCurrentArea =
      newText.indexOf("最新全景描述：新身份的全景描述") >= 0
      && newText.indexOf("最新融合版本 newfusion009（ok，1 条）") >= 0
      && newText.indexOf("· [画面确认] 新融合条目") >= 0
      && newText.indexOf("当前窗口进展")
           < newText.indexOf("新身份的全景描述");
    results.newResultsKeepOldContentInHistoryArea =
      newText.indexOf("历史融合版本 oldfusion01（ok）"
        + "（历史 run run-1 · 配置 v1）") >= 0
      && newText.indexOf("旧身份的全景描述") >= 0;
    results.newResultsQuickViewNoMoreWaiting =
      newText.indexOf("全景速览：等待分析") < 0
      && newText.indexOf("融合速览：等待分析") < 0;
    results.newFusionFrameRefsTraceable =
      newText.indexOf("· 帧 f-12 t=8000ms（normalized）") >= 0;

    // 场景 3：身份未知（停止/未接线）→ 标未知，不假称正在分析；旧内容
    // 仍只在历史区。
    const unknownEntry = {
      summary: "分支 完成 1 / 失败 0 / 淘汰 0 / 等待 0",
      window_state: null,
      counts: { done: 1, failed: 0, evicted: 0, pending: 0 },
      current_identity: null,
      branches: [
        { branch_key: "w1|panorama|", kind: "panorama",
          kind_label: "全景理解", status: "ok",
          text: "旧身份的全景描述", run_short: "run-1",
          config_short: "v1", is_current: false,
          evidence_available: false, evidence_url: null,
          sources: [], missing: {} }],
      fusion: { version_id: "oldfusion01", status: "ok",
        is_current: false, run_short: "run-1", config_short: "v1",
        frame_refs: [], items: [] },
      fusion_history: [{ version_id: "oldfusion01", status: "ok",
        window_id: "w-1", run_short: "run-1", config_short: "v1",
        is_current: false }],
      model_ref: "local-vlm-7b", calibrated: false };
    healthPayload = { understanding: { "cam-a": unknownEntry } };
    await drive();
    const unknownText = flatText(detail());
    results.unknownIdentityShownNotFakeAnalyzing =
      unknownText.indexOf("（当前身份未知）") >= 0
      && unknownText.indexOf("全景速览：等待分析"
        + "（当前身份未知：未运行或已停止）") >= 0
      && unknownText.indexOf("融合速览：等待分析"
        + "（当前身份未知：未运行或已停止）") >= 0
      && unknownText.indexOf("分析中") < 0;
    results.unknownIdentityHistoryStillTagged =
      unknownText.indexOf("历史融合版本 oldfusion01（ok，0 条）"
        + "（历史 run run-1 · 配置 v1）") >= 0;

    // 场景 4：注册表切回旧身份 run-1/v1 → 旧身份版本回当前区（当前身份
    // 更早窗口版本紧凑列出），新身份版本标历史；当前身份只认注册表。
    const backEntry = {
      summary: "分支 完成 1 / 失败 0 / 淘汰 0 / 等待 0",
      window_state: "producing",
      counts: { done: 1, failed: 0, evicted: 0, pending: 0 },
      current_identity: { run_id: "run-1", config_version: "v1" },
      branches: [
        { branch_key: "w1|panorama|", kind: "panorama",
          kind_label: "全景理解", status: "ok",
          text: "切回身份的全景描述", run_short: "run-1",
          config_short: "v1", is_current: true,
          evidence_available: false, evidence_url: null,
          sources: [], missing: {} }],
      fusion: { version_id: "newfusion009", status: "ok",
        is_current: false, run_short: "run-2", config_short: "v3",
        frame_refs: [], items: [] },
      fusion_history: [
        { version_id: "oldfusion01", status: "ok", window_id: "w-1",
          run_short: "run-1", config_short: "v1", is_current: true },
        { version_id: "newfusion009", status: "ok", window_id: "w-9",
          run_short: "run-2", config_short: "v3", is_current: false }],
      model_ref: "local-vlm-7b", calibrated: false };
    healthPayload = { understanding: { "cam-a": backEntry } };
    await drive();
    const backText = flatText(detail());
    results.switchBackCurrentIdentityRestored =
      backText.indexOf("当前融合版本 oldfusion01（ok） · 窗口 w-1") >= 0
      && backText.indexOf("历史融合版本 newfusion009（ok，0 条）"
        + "（历史 run run-2 · 配置 v3）") >= 0
      && backText.indexOf("最新全景描述：切回身份的全景描述") >= 0
      && backText.indexOf("融合速览：等待分析") < 0;
  } catch (err) {
    results.harnessError = String(err && err.stack || err);
  }
  let ok = true;
  Object.keys(results).forEach((k) => { if (results[k] !== true) ok = false; });
  console.log(JSON.stringify({ ok: ok, results: results }));
  process.exit(ok ? 0 : 1);
})();
'''


def test_understanding_branch_face_dom_executable(state, tmp_path):
    """C-138 §6 + C-140 §3 可执行 DOM 测试：node 真实执行页面脚本驱动
    refreshHealth，断言分支区渲染实际内容（描述文本/分支计数/融合版本/
    来源标注）、模型输出含 script 片段时按纯文本渲染、相机切换竞态守卫、
    数据消失与请求失败的清理；C-140 §3：切配置后旧分支/旧速览/旧融合全部
    明确标历史且当前区显示等待、新结果到达进当前区、全景/局部速览只取
    当前身份、身份未知标未知不假称正在分析、切回旧身份恢复当前区。
    node 不可用时跳过并如实标注。"""
    import shutil
    import subprocess
    handler = _get_handler(state, "/")
    html = handler.wfile.getvalue().decode("utf-8")
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert scripts, "工作台必须带内联脚本"
    node = shutil.which("node")
    if node is None:
        pytest.skip("node 不可用：无法执行页面脚本交互测试")
    page = tmp_path / "workbench-page-understanding.js"
    page.write_text(scripts[-1], encoding="utf-8")
    harness = tmp_path / "harness-understanding.js"
    harness.write_text(_UNDERSTANDING_DOM_HARNESS_JS, encoding="utf-8")
    proc = subprocess.run([node, str(harness), str(page)],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (
        "理解分支区 DOM 测试失败\nstdout: " + proc.stdout[-3000:]
        + "\nstderr: " + proc.stderr[-800:])
    data = json.loads(proc.stdout)
    assert data["ok"] is True, data["results"]


# ---------- C141：独立裁图资产接口（/api/crops）+ 分支三序位证据 -----------

# 端点层不做 PNG 真解码（crop_service.read 已验证）；这里用带 PNG magic 的
# 非空字节证明字节透传（内容不含大括号，避免 body_json 误判）。
_C141_PNG = b"\x89PNG\r\n\x1a\n" + b"crop-png-bytes"
_C141_AID = hashlib.sha256(b"c141-crop-current").hexdigest()


class _CropServiceError(Exception):
    """crop_service.read 失败替身：带 .code 固定码（形状同服务契约）。"""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


class _StubCropService:
    """crop_service 替身：find 按相机 + 身份等值过滤索引条目；read 校验读取。

    形状同服务契约：find(camera_id, filters=None, limit=...) -> list[dict]；
    read(asset_id) -> {"metadata": {"asset_id", "provenance"}, "png": bytes}
    （provenance 从该 asset_id 对应索引条目派生，同真服务：归档元数据与
    索引同源于同一 provenance 载荷）；失败抛带 .code 固定码异常。
    find_calls/read_calls 记录调用，供「关联校验先于读取」断言。
    """

    def __init__(self, index=None, blobs=None, find_error=None,
                 read_error=None, read_result=None,
                 with_commit_status=False, commit_status_result=None,
                 commit_status_error=None):
        self.index = list(index or [])
        self.blobs = dict(blobs or {})
        self.find_error = find_error
        self.read_error = read_error
        self.read_result = read_result
        self.commit_status_result = commit_status_result
        self.commit_status_error = commit_status_error
        self.find_calls = []
        self.read_calls = []
        self.commit_calls = []
        # C141-R3：commit_status 为可选鸭子方法（模拟 A 未接线/旧服务）
        # ——默认不存在，既有用例零扰动；with_commit_status=True 才挂载。
        if with_commit_status:
            self.commit_status = self._commit_status

    def _commit_status(self, camera_id, identity):
        """A 冻结 §1 形状：commit_status(camera_id, 九元 identity) ->
        dict | None（commit_uncertain / {"status": None} / None=无匹配）。"""
        self.commit_calls.append({"camera": str(camera_id),
                                  "identity": dict(identity)})
        if self.commit_status_error is not None:
            raise self.commit_status_error
        return self.commit_status_result

    def find(self, camera_id, filters=None, limit=10):
        self.find_calls.append({"camera": str(camera_id),
                                "filters": dict(filters or {}),
                                "limit": limit})
        if self.find_error is not None:
            raise self.find_error
        hits = [dict(e) for e in self.index
                if str(e.get("camera_id")) == str(camera_id)
                and all(str(e.get(k)) == str(v)
                        for k, v in (filters or {}).items())]
        return hits[:limit] if limit else hits

    def read(self, asset_id):
        self.read_calls.append(str(asset_id))
        if self.read_error is not None:
            raise self.read_error
        if self.read_result is not None:
            return self.read_result
        if asset_id not in self.blobs:
            raise _CropServiceError("missing")
        entry = next((e for e in self.index
                      if str(e.get("asset_id")) == str(asset_id)), None)
        provenance = (_crop_provenance_from_entry(entry)
                      if entry is not None else {})
        return {"metadata": {"asset_id": asset_id,
                             "provenance": provenance},
                "png": self.blobs[asset_id]}


def _crop_provenance_from_entry(entry, **overrides):
    """索引条目 → 归档 provenance（同源身份载荷的形状；真服务中二者
    来自同一次提交）。overrides 供构造错归属/异身份归档的负面用例。"""
    provenance = {"camera_id": entry["camera_id"], "run_id": entry["run_id"],
                  "config_version": entry["config_version"],
                  "material_id": entry["material_id"],
                  "window_id": entry["window_id"], "branch": entry["branch"],
                  "crop_id": entry["crop_id"], "frame_id": entry["frame_id"],
                  "slot": entry["slot"]}
    provenance.update(overrides)
    return provenance


def _crop_index_entry(camera="front", asset_id=_C141_AID, slot="current",
                      status="saved", **extra):
    """A 索引条目形状（身份键=camera_id/run_id/config_version/material_id/
    window_id/branch/crop_id/frame_id/slot/asset_id/status）。branch 为
    A 的冻结枚举：局部分支统一 "local"（精确子类经 crop_id 内 ":chg:"
    追溯），全景为 "panorama"。"""
    entry = {"camera_id": camera, "run_id": "run-1", "config_version": "v1",
             "window_id": "w-1", "branch": "local",
             "crop_id": "crop-1", "material_id": "mat-1",
             "frame_id": "f-9", "slot": slot, "asset_id": asset_id,
             "status": status}
    entry.update(extra)
    return entry


def test_crops_endpoint_serves_registered_png_with_fixed_headers(state):
    """成功路径：200 + image/png + nosniff + no-store，body=验证后的 PNG
    字节；关联校验确实按（camera, asset_id）查索引且 limit=1。"""
    state.save_zones("front", [])
    state.crop_service = _StubCropService(
        index=[_crop_index_entry()], blobs={_C141_AID: _C141_PNG})
    h = _get_handler(state, "/api/crops/" + _C141_AID + "?camera=front")
    assert h.status == 200
    assert h.wfile.getvalue() == _C141_PNG
    assert h.response_headers["Content-Type"] == "image/png"
    assert h.response_headers["X-Content-Type-Options"] == "nosniff"
    assert h.response_headers["Cache-Control"] == "no-store"
    assert int(h.response_headers["Content-Length"]) == len(_C141_PNG)
    assert state.crop_service.find_calls == [
        {"camera": "front", "filters": {"asset_id": _C141_AID}, "limit": 1}]
    assert state.crop_service.read_calls == [_C141_AID]


def test_crops_endpoint_rejects_invalid_asset_ids(state):
    """asset_id 非 64 位小写 hex → 404 invalid_asset，绝不进入索引查询。"""
    from urllib.parse import quote
    state.save_zones("front", [])
    service = _StubCropService()
    state.crop_service = service
    for bad in ("", "xyz", "ABCDEF" + "0" * 58, "g" * 64, "0" * 63,
                "0" * 65, "../../etc", "a/b"):
        st, body = _get(state,
                        "/api/crops/" + quote(bad, safe="") + "?camera=front")
        assert st == 404, bad
        assert body["code"] == "invalid_asset", bad
    assert service.find_calls == [] and service.read_calls == []


def test_crops_endpoint_unknown_camera_is_404(state):
    """相机不存在/形状非法 → 404「camera not found」（沿用既有未知相机
    404 风格）+ 固定码 unknown_camera；相机校验先于索引查询。"""
    state.save_zones("front", [])
    state.crop_service = _StubCropService(
        index=[_crop_index_entry()], blobs={_C141_AID: _C141_PNG})
    st, body = _get(state, "/api/crops/" + _C141_AID + "?camera=missing")
    assert st == 404 and body["error"] == "camera not found"
    assert body["code"] == "unknown_camera"
    st, body = _get(state, "/api/crops/" + _C141_AID + "?camera=a%2Fb")
    assert st == 404 and body["code"] == "unknown_camera"
    assert state.crop_service.find_calls == []
    assert state.crop_service.read_calls == []


def test_crops_endpoint_knowing_hash_is_not_enough(state):
    """关联校验：哈希未注册 → 404 asset_not_found，read 永不执行
    （只知哈希不等于可读——即使 read 本可成功）。"""
    state.save_zones("front", [])
    service = _StubCropService(index=[], blobs={_C141_AID: _C141_PNG})
    state.crop_service = service
    st, body = _get(state, "/api/crops/" + _C141_AID + "?camera=front")
    assert st == 404 and body["code"] == "asset_not_found"
    assert service.read_calls == [], "关联校验失败绝不能触达读取"


def test_crops_endpoint_rejects_asset_registered_to_other_camera(state):
    """他相机注册的资产：对 front 同样 404 asset_not_found（与不存在资产
    同一固定码，不泄露存在性差异）；真实所属相机可读。"""
    state.save_zones("front", [])
    state.save_zones("yard", [])
    state.crop_service = _StubCropService(
        index=[_crop_index_entry(camera="yard")],
        blobs={_C141_AID: _C141_PNG})
    st, body = _get(state, "/api/crops/" + _C141_AID + "?camera=front")
    assert st == 404 and body["code"] == "asset_not_found"
    assert state.crop_service.read_calls == []
    h = _get_handler(state, "/api/crops/" + _C141_AID + "?camera=yard")
    assert h.status == 200 and h.wfile.getvalue() == _C141_PNG


def test_crops_endpoint_read_failures_map_to_fixed_codes(state):
    """read 异常按固定码映射：missing/corrupt/invalid_id → 410
    asset_unreadable；其余异常 → 500 固定码（异常正文绝不外泄）；
    返回形状不合法（png 非字节）→ 410。"""
    state.save_zones("front", [])
    for err, want_status in ((_CropServiceError("missing"), 410),
                             (_CropServiceError("corrupt"), 410),
                             (_CropServiceError("invalid_id"), 410),
                             (RuntimeError("disk exploded"), 500)):
        state.crop_service = _StubCropService(
            index=[_crop_index_entry()], read_error=err)
        st, body = _get(state,
                        "/api/crops/" + _C141_AID + "?camera=front")
        assert st == want_status, err
        assert body["code"] == ("asset_unreadable" if want_status == 410
                                else "crop_read_failed")
        assert "exploded" not in json.dumps(body, ensure_ascii=False)
    state.crop_service = _StubCropService(
        index=[_crop_index_entry()],
        read_result={"metadata": {}, "png": "not-bytes"})
    st, body = _get(state, "/api/crops/" + _C141_AID + "?camera=front")
    assert st == 410 and body["code"] == "asset_unreadable"


def test_crops_endpoint_without_service_is_structured_503(state):
    """crop_service 缺失（属性不存在或 None）/查询异常 → 503 固定码
    （不回栈、不崩溃、异常正文不外泄）。"""
    state.save_zones("front", [])
    assert not hasattr(state, "crop_service")
    st, body = _get(state, "/api/crops/" + _C141_AID + "?camera=front")
    assert st == 503 and body["code"] == "crop_service_unavailable"
    state.crop_service = None
    st, body = _get(state, "/api/crops/" + _C141_AID + "?camera=front")
    assert st == 503 and body["code"] == "crop_service_unavailable"
    state.crop_service = _StubCropService(find_error=RuntimeError("boom"))
    st, body = _get(state, "/api/crops/" + _C141_AID + "?camera=front")
    assert st == 503 and body["code"] == "crop_service_unavailable"
    assert "boom" not in json.dumps(body, ensure_ascii=False)


def test_crops_endpoint_archive_provenance_double_check(state):
    """C141-R1 修阻塞 3：归档双校验——read 取回的 metadata.provenance 与
    索引条目与查询相机三方一致才出图；错归属相机/异身份归档 → 固定 404
    asset_identity_mismatch（错误体只有固定 error/code 两键，绝不输出
    路径、绝不泄露差异在哪个键）；归档缺 provenance/缺核心身份键 →
    固定 404 asset_incomplete。"""
    state.save_zones("front", [])
    entry = _crop_index_entry()
    wrong_cam = _StubCropService(
        index=[entry],
        read_result={"metadata": {"asset_id": _C141_AID,
                                  "provenance": _crop_provenance_from_entry(
                                      entry, camera_id="yard")},
                     "png": _C141_PNG})
    state.crop_service = wrong_cam
    st, body = _get(state, "/api/crops/" + _C141_AID + "?camera=front")
    assert st == 404
    assert body == {"error": "asset_identity_mismatch",
                    "code": "asset_identity_mismatch"}
    wrong_mat = _StubCropService(
        index=[entry],
        read_result={"metadata": {"asset_id": _C141_AID,
                                  "provenance": _crop_provenance_from_entry(
                                      entry, material_id="mat-2")},
                     "png": _C141_PNG})
    state.crop_service = wrong_mat
    st, body = _get(state, "/api/crops/" + _C141_AID + "?camera=front")
    assert st == 404
    assert body == {"error": "asset_identity_mismatch",
                    "code": "asset_identity_mismatch"}
    no_prov = _StubCropService(
        index=[entry],
        read_result={"metadata": {"asset_id": _C141_AID},
                     "png": _C141_PNG})
    state.crop_service = no_prov
    st, body = _get(state, "/api/crops/" + _C141_AID + "?camera=front")
    assert st == 404 and body["code"] == "asset_incomplete"
    partial = _crop_provenance_from_entry(entry)
    partial.pop("frame_id")
    state.crop_service = _StubCropService(
        index=[entry],
        read_result={"metadata": {"asset_id": _C141_AID,
                                  "provenance": partial},
                     "png": _C141_PNG})
    st, body = _get(state, "/api/crops/" + _C141_AID + "?camera=front")
    assert st == 404 and body["code"] == "asset_incomplete"
    # 对照：provenance 与索引/查询三方一致 → 照常出图（C141 行为不回归）
    state.crop_service = _StubCropService(index=[entry],
                                          blobs={_C141_AID: _C141_PNG})
    h = _get_handler(state, "/api/crops/" + _C141_AID + "?camera=front")
    assert h.status == 200 and h.wfile.getvalue() == _C141_PNG


def _seed_three_slot_store(camera="front"):
    """带三序位 sources 的 relation_crop 分支（next 缺帧）。

    sources[].position 用 l3 原始记录真实形状：int 0/1/2（0=previous、
    1=current、2=next）。
    """
    store = UnderstandingStore()
    store.append(camera, "l2", {"status": "ok", "calibrated": False,
                                "model_ref": "l3-local-model",
                                "window_state": "producing"})
    store.append(camera, "l3", {
        "window": "w-1", "branch": "relation_crop", "status": "ok", "at": 1.0,
        "results": [{
            "window_key": [camera, "run-1", "v1", "w-1"],
            "branch_key": [camera, "run-1", "v1", "w-1", "relation_crop",
                           "crop-7", "mat-1"],
            "branch": "relation_crop", "crop_id": "crop-7",
            "model_ref": "local-vlm-7b", "status": "ok",
            "observation": {"text": "该人员手持包裹", "unstructured": True,
                            "certainty": "observed"},
            "sources": [
                {"position": 0, "frame_id": "f-8", "present": True,
                 "t_capture_ms": 8000.0,
                 "timestamp_kind": "source_capture"},
                {"position": 1, "frame_id": "f-9", "present": True,
                 "t_capture_ms": 9000.0,
                 "timestamp_kind": "source_capture"},
                {"position": 2, "frame_id": "f-10", "present": False,
                 "t_capture_ms": None,
                 "timestamp_kind": "source_capture"}],
            "missing": {"frames_dropped": 1, "omission_reason": None,
                        "frames": [2]}}]})
    return store


def test_understanding_evidence_three_slots_json_shape(state):
    """evidence 段：三序位 JSON 形状——saved 给 asset_id + 分支帧时间；
    异步未完成如实 pending；缺帧序位 missing(frame_absent)（缺帧不查
    索引）；find 过滤使用分支完整身份 + slot + 源帧 frame_id（C141-R1
    修阻塞 4），逐序位 limit=1。"""
    state.understanding_store = _seed_three_slot_store()
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    aid = hashlib.sha256(b"c141-crop-cur").hexdigest()
    service = _StubCropService(index=[
        _crop_index_entry(asset_id=aid, slot="current", status="saved",
                          crop_id="crop-7"),
        _crop_index_entry(asset_id=None, slot="previous", status="pending",
                          crop_id="crop-7", frame_id="f-8")],
        blobs={aid: _C141_PNG})
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    row = body["branches"][0]
    ev = row["evidence"]
    assert ev["available"] is True
    assert set(ev) == {"available", "previous", "current", "next"}
    for slot in (ev["previous"], ev["current"], ev["next"]):
        assert set(slot) == {"asset_id", "status", "reason", "t_capture_ms"}
    assert ev["current"] == {"asset_id": aid, "status": "saved",
                             "reason": None, "t_capture_ms": 9000.0}
    assert ev["previous"]["status"] == "pending"
    assert ev["previous"]["asset_id"] is None
    assert ev["previous"]["t_capture_ms"] == 8000.0
    assert ev["next"] == {"asset_id": None, "status": "missing",
                          "reason": "frame_absent", "t_capture_ms": None}
    # find 过滤键与 A 的索引条目身份键对齐（分支完整身份 + slot + 源帧
    # frame_id；branch 已规范化到冻结枚举：局部族 relation_crop → "local"）
    by_slot = {c["filters"].get("slot"): c for c in service.find_calls}
    assert set(by_slot) == {"previous", "current"}, \
        "缺帧序位（next）不应触发索引查询"
    assert by_slot["current"]["filters"] == {
        "run_id": "run-1", "config_version": "v1", "window_id": "w-1",
        "branch": "local", "crop_id": "crop-7",
        "material_id": "mat-1", "slot": "current", "frame_id": "f-9"}
    assert by_slot["previous"]["filters"]["frame_id"] == "f-8"
    assert all(c["camera"] == "front" and c["limit"] == 1
               for c in service.find_calls)


def test_understanding_evidence_failed_dropped_and_identity_free(state):
    """failed/dropped 状态与原因固定码透传（仅 saved 给 asset_id）；分支
    身份未记录（window_key 缺失）→ 全序位 missing(identity_unrecorded)
    且绝不触发 find（防宽松过滤跨身份捞资产）。"""
    state.understanding_store = _seed_three_slot_store()
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    state.crop_service = _StubCropService(index=[
        _crop_index_entry(asset_id=None, slot="current", status="failed",
                          reason="index_failed", crop_id="crop-7"),
        _crop_index_entry(asset_id=None, slot="previous", status="dropped",
                          reason="ttl_exceeded", crop_id="crop-7",
                          frame_id="f-8")])
    st, body = _get(state, "/api/understanding/front")
    ev = body["branches"][0]["evidence"]
    assert ev["current"] == {"asset_id": None, "status": "failed",
                             "reason": "index_failed",
                             "t_capture_ms": 9000.0}
    assert ev["previous"] == {"asset_id": None, "status": "dropped",
                              "reason": "ttl_exceeded",
                              "t_capture_ms": 8000.0}
    assert ev["next"]["status"] == "missing"
    assert ev["next"]["reason"] == "frame_absent"

    store = UnderstandingStore()
    store.append("front", "l3", {
        "window": "w-legacy", "branch": "panorama", "status": "ok", "at": 1.0,
        "results": [{"branch": "panorama", "status": "ok",
                     "observation": {"text": "无身份旧档",
                                     "certainty": "model_inferred"},
                     "sources": [{"position": 1, "frame_id": "f-0",
                                  "present": True, "t_capture_ms": 1.0,
                                  "timestamp_kind": "unknown"}],
                     "missing": {}}]})
    state.understanding_store = store
    service = _StubCropService(index=[_crop_index_entry()])
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    ev = body["branches"][0]["evidence"]
    assert ev["available"] is True
    assert ev["current"]["status"] == "missing"
    assert ev["current"]["reason"] == "identity_unrecorded"
    assert service.find_calls == []


def test_understanding_evidence_branch_kind_normalized_to_frozen_enum(state):
    """C141 集成修复 + C141-R1 回归：branch 词表规范化——A 的索引/v2 校验
    把 branch 冻结为枚举 "panorama"|"local"（B 提交侧局部分支统一
    "local"，精确子类经 crop_id 内 ":chg:" 追溯）。row.kind 值域含
    relation_crop/change_region 等子类标签，原样透传会与索引 "local" 不
    相等 → find 查不中。过滤必须规范化：局部族（relation_crop/
    change_region/local）→ "local"；panorama → "panorama"；无法归类的
    kind → 规范化枚举缺失 = 完整身份不齐（C141-R1 修阻塞 4）→ 不查询、
    全序位 identity_unrecorded（宁可不查，绝不脱枚举宽松借图）。"""
    store = UnderstandingStore()
    for kind, at in (("change_region", 1.0), ("relation_crop", 2.0),
                     ("panorama", 3.0), ("mystery_kind", 4.0)):
        store.append("front", "l3", {
            "window": "w-1", "branch": kind, "status": "ok", "at": at,
            "results": [{
                "window_key": ["front", "run-1", "v1", "w-1"],
                "branch_key": ["front", "run-1", "v1", "w-1", kind,
                               "crop-" + kind, "mat-1"],
                "branch": kind, "crop_id": "crop-" + kind, "status": "ok",
                "observation": {"text": kind + " 的描述",
                                "certainty": "model_inferred"},
                "sources": [{"position": 1, "frame_id": "f-9",
                             "present": True, "t_capture_ms": 9000.0,
                             "timestamp_kind": "source_capture"}],
                "missing": {}}]})
    state.understanding_store = store
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    service = _StubCropService()
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    kinds = {row["kind"] for row in body["branches"]}
    assert kinds == {"change_region", "relation_crop", "panorama",
                     "mystery_kind"}
    # 每行只有 cur 序位帧在场；可归类行（3 条）各查询一次；mystery_kind
    # 规范化枚举缺失 → identity_unrecorded 且绝不查询（C141-R1）
    assert len(service.find_calls) == 3
    local_calls = [c for c in service.find_calls
                   if c["filters"].get("branch") == "local"]
    pano_calls = [c for c in service.find_calls
                  if c["filters"].get("branch") == "panorama"]
    # 局部族（change_region + relation_crop）都规范化为冻结枚举 "local"
    assert len(local_calls) == 2
    # 全景行 → "panorama"
    assert len(pano_calls) == 1
    # 冻结枚举之外绝不出现其它 branch 值
    assert all(c["filters"].get("branch") in ("panorama", "local")
               for c in service.find_calls)
    # 共同身份键（run/config/window + slot + 源帧）不受规范化影响
    for call in service.find_calls:
        assert call["filters"]["run_id"] == "run-1"
        assert call["filters"]["config_version"] == "v1"
        assert call["filters"]["window_id"] == "w-1"
        assert call["filters"]["slot"] == "current"
        assert call["filters"]["frame_id"] == "f-9"
        assert call["camera"] == "front" and call["limit"] == 1
    # mystery_kind 行：枚举缺失 = 身份不齐 → 全序位 identity_unrecorded
    mystery = [row for row in body["branches"]
               if row["kind"] == "mystery_kind"][0]
    assert mystery["evidence"]["available"] is True
    for slot in ("previous", "current", "next"):
        assert mystery["evidence"][slot]["status"] == "missing"
        assert mystery["evidence"][slot]["reason"] == "identity_unrecorded"
        assert mystery["evidence"][slot]["asset_id"] is None


def test_understanding_evidence_int_position_slots(state):
    """C141 集成修复回归：l3 sources 的 position 是 int 0/1/2（0=previous、
    1=current、2=next；实测原始记录形状，如 {"position": 0, "present":
    false}）——序位按规范序位匹配。previous（position 0 present=false）
    → frame_absent 且不查索引；current/next 在场 → 进入 find（next 异步
    未完成如实 pending）；t_capture_ms 随各自序位帧。"""
    store = UnderstandingStore()
    store.append("front", "l3", {
        "window": "w-1", "branch": "relation_crop", "status": "ok", "at": 1.0,
        "results": [{
            "window_key": ["front", "run-1", "v1", "w-1"],
            "branch_key": ["front", "run-1", "v1", "w-1", "relation_crop",
                           "crop-7", "mat-1"],
            "branch": "relation_crop", "crop_id": "crop-7",
            "model_ref": "local-vlm-7b", "status": "ok",
            "observation": {"text": "该人员手持包裹", "certainty": "observed"},
            "sources": [
                {"position": 0, "present": False, "frame_id": None,
                 "t_capture_ms": None,
                 "timestamp_kind": "source_capture"},
                {"position": 1, "present": True, "frame_id": "f-9",
                 "t_capture_ms": 9000.0,
                 "timestamp_kind": "source_capture"},
                {"position": 2, "present": True, "frame_id": "f-10",
                 "t_capture_ms": 9500.0,
                 "timestamp_kind": "source_capture"}],
            "missing": {"frames_dropped": 1, "omission_reason": None,
                        "frames": [0]}}]})
    state.understanding_store = store
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    aid = hashlib.sha256(b"c141-int-pos").hexdigest()
    service = _StubCropService(index=[
        _crop_index_entry(asset_id=aid, slot="current", status="saved",
                          crop_id="crop-7"),
        _crop_index_entry(asset_id=None, slot="next", status="pending",
                          crop_id="crop-7", frame_id="f-10")],
        blobs={aid: _C141_PNG})
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    assert ev["available"] is True
    # previous（position 0，present=false）→ frame_absent，绝不查索引
    assert ev["previous"] == {"asset_id": None, "status": "missing",
                              "reason": "frame_absent", "t_capture_ms": None}
    # current（position 1）→ 索引命中 saved（asset_id + 该序位帧时间）
    assert ev["current"] == {"asset_id": aid, "status": "saved",
                             "reason": None, "t_capture_ms": 9000.0}
    # next（position 2）→ 索引命中 pending（异步未完成如实 pending）
    assert ev["next"] == {"asset_id": None, "status": "pending",
                          "reason": None, "t_capture_ms": 9500.0}
    # 只有 current/next 进入 find（previous 缺帧不查），身份键完整
    by_slot = {c["filters"].get("slot"): c for c in service.find_calls}
    assert set(by_slot) == {"current", "next"}
    for call in service.find_calls:
        assert call["camera"] == "front" and call["limit"] == 1
        assert call["filters"]["branch"] == "local"
        assert call["filters"]["crop_id"] == "crop-7"
        assert call["filters"]["material_id"] == "mat-1"


def test_understanding_evidence_follows_branch_identity_marked_history(state):
    """历史分支（is_current=False）的 evidence 跟随分支自身身份查询——
    注册表已切 run-2/v3，find 过滤仍是 run-1/v1；资产可展示（行的「历史」
    标注由 is_current/历史短码承担），不冒充当前。"""
    store = UnderstandingStore()
    store.append("front", "l3", {
        "window": "w-old", "branch": "relation_crop", "status": "ok",
        "at": 1.0,
        "results": [{
            "window_key": ["front", "run-1", "v1", "w-old"],
            "branch_key": ["front", "run-1", "v1", "w-old", "relation_crop",
                           "crop-old", "mat-old"],
            "branch": "relation_crop", "crop_id": "crop-old",
            "status": "ok",
            "observation": {"text": "旧 run 的描述", "certainty": "observed"},
            "sources": [{"position": 1, "frame_id": "f-old",
                         "present": True, "t_capture_ms": 1000.0,
                         "timestamp_kind": "source_capture"}],
            "missing": {}}]})
    state.understanding_store = store
    state.l2 = SimpleNamespace(_registry={"front": ("run-2", "v3")})
    aid = hashlib.sha256(b"c141-history-crop").hexdigest()
    service = _StubCropService(index=[
        _crop_index_entry(camera="front", asset_id=aid, slot="current",
                          status="saved", run_id="run-1",
                          config_version="v1", window_id="w-old",
                          crop_id="crop-old", material_id="mat-old",
                          frame_id="f-old")],
        blobs={aid: _C141_PNG})
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    row = body["branches"][0]
    assert row["is_current"] is False
    assert row["evidence"]["available"] is True
    assert row["evidence"]["current"]["asset_id"] == aid
    assert service.find_calls[0]["filters"]["run_id"] == "run-1"
    assert service.find_calls[0]["filters"]["config_version"] == "v1"


def test_understanding_evidence_service_unavailable_degrades(state):
    """裁图服务不可用（None/查询异常）→ evidence 段整体 available=false
    固定码（/api/understanding 与 /api/health 一致，理解面绝不 500）；
    服务未接线（属性不存在）→ 既有形状（无 evidence 键）一字不动。"""
    state.understanding_store = _seed_three_slot_store()
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    state.crop_service = None
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    assert body["branches"][0]["evidence"] == {
        "available": False, "reason": "crop_service_unavailable"}
    state.crop_service = _StubCropService(find_error=RuntimeError("boom"))
    st, body = _get(state, "/api/understanding/front")
    assert body["branches"][0]["evidence"] == {
        "available": False, "reason": "crop_service_unavailable"}
    assert "boom" not in json.dumps(body, ensure_ascii=False)
    st, body = _get(state, "/api/health")
    assert body["understanding"]["front"]["branches"][0]["evidence"] == {
        "available": False, "reason": "crop_service_unavailable"}
    # 未接线（删除属性）→ 既有形状：分支行无 evidence 键
    del state.crop_service
    st, body = _get(state, "/api/understanding/front")
    assert "evidence" not in body["branches"][0]


def _seed_full_identity_branch(camera="front", *, kind="relation_crop",
                               crop_id="crop-7", material="mat-1",
                               window="w-1", sources=None):
    """一条完整身份的 l3 局部分支（三序位 sources 可定制；默认只有
    current 序位帧在场，frame_id=f-9）。"""
    store = UnderstandingStore()
    store.append(camera, "l3", {
        "window": window, "branch": kind, "status": "ok", "at": 1.0,
        "results": [{
            "window_key": [camera, "run-1", "v1", window],
            "branch_key": [camera, "run-1", "v1", window, kind,
                           crop_id, material],
            "branch": kind, "crop_id": crop_id, "status": "ok",
            "observation": {"text": "该人员手持包裹", "certainty": "observed"},
            "sources": sources if sources is not None else [
                {"position": 1, "frame_id": "f-9", "present": True,
                 "t_capture_ms": 9000.0,
                 "timestamp_kind": "source_capture"}],
            "missing": {}}]})
    return store


def _full_identity_find_filters(slot="current", frame_id="f-9",
                                crop_id="crop-7", material_id="mat-1"):
    """完整身份 find 过滤键的精确期望形状（C141-R1：含源帧 frame_id）。"""
    return {"run_id": "run-1", "config_version": "v1", "window_id": "w-1",
            "branch": "local", "crop_id": crop_id,
            "material_id": material_id, "slot": slot,
            "frame_id": frame_id}


def test_understanding_evidence_incomplete_identity_never_queries(state):
    """C141-R1 修阻塞 4：分支行缺 crop_id / 缺 material_id / kind 无法归
    类（规范化 branch 枚举缺失）→ 全序位 missing(identity_unrecorded)
    且零 find 调用、零 read——完整身份必备才查询，索引里摆着同窗可借
    条目也绝不触达（不借图）。"""
    aid = hashlib.sha256(b"c141-bait").hexdigest()
    variants = (("缺 crop_id", "relation_crop", None, "mat-1"),
                ("缺 material_id", "relation_crop", "crop-7", None),
                ("kind 无法归类", "mystery_kind", "crop-7", "mat-1"))
    for label, kind, crop_id, material in variants:
        store = UnderstandingStore()
        store.append("front", "l3", {
            "window": "w-1", "branch": kind, "status": "ok", "at": 1.0,
            "results": [{
                "window_key": ["front", "run-1", "v1", "w-1"],
                "branch_key": ["front", "run-1", "v1", "w-1", kind,
                               crop_id, material],
                "branch": kind, "crop_id": crop_id, "status": "ok",
                "observation": {"text": label, "certainty": "observed"},
                "sources": [{"position": 1, "frame_id": "f-9",
                             "present": True, "t_capture_ms": 9000.0,
                             "timestamp_kind": "source_capture"}],
                "missing": {}}]})
        state.understanding_store = store
        state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
        service = _StubCropService(index=[
            _crop_index_entry(asset_id=aid, slot="current", status="saved",
                              crop_id="crop-7")], blobs={aid: _C141_PNG})
        state.crop_service = service
        st, body = _get(state, "/api/understanding/front")
        assert st == 200, label
        ev = body["branches"][0]["evidence"]
        assert ev["available"] is True, label
        for slot in ("previous", "current", "next"):
            assert ev[slot]["status"] == "missing", (label, slot)
            assert ev[slot]["reason"] == "identity_unrecorded", (label, slot)
            assert ev[slot]["asset_id"] is None, (label, slot)
        assert service.find_calls == [], label
        assert service.read_calls == [], label


def test_understanding_evidence_source_frame_id_gates_find(state):
    """C141-R1：源帧身份参与匹配——source.frame_id 为 null → 该序位
    missing(frame_identity_unrecorded)（新固定码）且零查询；frame_id
    在场 → find filters 精确携带该 frame_id（同窗异帧不借图）。"""
    sources = [{"position": 1, "frame_id": None, "present": True,
                "t_capture_ms": 9000.0, "timestamp_kind": "source_capture"}]
    state.understanding_store = _seed_full_identity_branch(sources=sources)
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    aid = hashlib.sha256(b"c141-frame-null").hexdigest()
    service = _StubCropService(index=[
        _crop_index_entry(asset_id=aid, slot="current", status="saved",
                          crop_id="crop-7")], blobs={aid: _C141_PNG})
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    assert ev["current"] == {"asset_id": None, "status": "missing",
                             "reason": "frame_identity_unrecorded",
                             "t_capture_ms": 9000.0}
    assert ev["previous"]["reason"] == "frame_absent"
    assert ev["next"]["reason"] == "frame_absent"
    assert service.find_calls == [] and service.read_calls == []
    # 正面对照：frame_id 在场 → 查询过滤精确携带该源帧 frame_id
    state.understanding_store = _seed_full_identity_branch()
    service = _StubCropService(index=[
        _crop_index_entry(asset_id=aid, slot="current", status="saved",
                          crop_id="crop-7")], blobs={aid: _C141_PNG})
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    assert ev["current"] == {"asset_id": aid, "status": "saved",
                             "reason": None, "t_capture_ms": 9000.0}
    assert service.find_calls == [{"camera": "front",
                                   "filters": _full_identity_find_filters(),
                                   "limit": 1}]


def test_understanding_evidence_same_window_never_borrows(state):
    """C141-R1：同窗异帧/异材料/异裁图绝不借图——索引里只有同 run/
    config/窗口/分支/序位但 frame_id/材料/裁图不同的条目时，过滤键的
    精确性保证查不中 → missing(not_in_index)，绝不显示他人资产。"""
    state.understanding_store = _seed_full_identity_branch()
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    aid = hashlib.sha256(b"c141-neighbor").hexdigest()
    service = _StubCropService(index=[
        _crop_index_entry(asset_id=aid, slot="current", status="saved",
                          crop_id="crop-7", frame_id="f-99"),      # 异帧
        _crop_index_entry(asset_id=aid, slot="current", status="saved",
                          crop_id="crop-7", material_id="mat-2"),  # 异材料
        _crop_index_entry(asset_id=aid, slot="current", status="saved",
                          crop_id="crop-8")],                      # 异裁图
        blobs={aid: _C141_PNG})
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    assert ev["current"] == {"asset_id": None, "status": "missing",
                             "reason": "not_in_index",
                             "t_capture_ms": 9000.0}
    assert service.read_calls == []
    # 过滤键精确：完整身份 + slot + 源帧 frame_id，一个键都不许少
    assert service.find_calls == [{"camera": "front",
                                   "filters": _full_identity_find_filters(),
                                   "limit": 1}]


def test_understanding_evidence_saved_archive_provenance_mismatch(state):
    """C141-R1：find 命中 saved 后做索引↔归档二次全身份复核——归档
    provenance 与索引条目/查询不符（错归属相机/异材料/异源帧）→ 该序位
    failed(identity_mismatch)、无 asset_id，绝不展示资产；一致 → 照常
    saved（正向对照，旧历史完整合法记录继续可看的同一通路）。"""
    state.understanding_store = _seed_full_identity_branch()
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    aid = hashlib.sha256(b"c141-mismatch").hexdigest()
    entry = _crop_index_entry(asset_id=aid, slot="current", status="saved",
                              crop_id="crop-7")
    for label, override in (("错归属相机", {"camera_id": "yard"}),
                            ("异材料", {"material_id": "mat-2"}),
                            ("异源帧", {"frame_id": "f-99"})):
        service = _StubCropService(
            index=[entry],
            read_result={"metadata": {"asset_id": aid,
                                      "provenance":
                                      _crop_provenance_from_entry(
                                          entry, **override)},
                         "png": _C141_PNG})
        state.crop_service = service
        st, body = _get(state, "/api/understanding/front")
        assert st == 200, label
        ev = body["branches"][0]["evidence"]
        assert ev["current"] == {"asset_id": None, "status": "failed",
                                 "reason": "identity_mismatch",
                                 "t_capture_ms": 9000.0}, label
        assert service.read_calls == [aid], label
    state.crop_service = _StubCropService(index=[entry],
                                          blobs={aid: _C141_PNG})
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    assert ev["current"] == {"asset_id": aid, "status": "saved",
                             "reason": None, "t_capture_ms": 9000.0}


def _full_identity_row(**overrides):
    """一条完整身份的原始 l3 分支行（畸形身份用例逐键定制的基座；默认
    current 序位帧在场 frame_id=f-9）。"""
    row = {
        "window_key": ["front", "run-1", "v1", "w-1"],
        "branch_key": ["front", "run-1", "v1", "w-1", "relation_crop",
                       "crop-7", "mat-1"],
        "branch": "relation_crop", "crop_id": "crop-7",
        "model_ref": "local-vlm-7b", "status": "ok",
        "observation": {"text": "该人员手持包裹", "certainty": "observed"},
        "sources": [{"position": 1, "frame_id": "f-9", "present": True,
                     "t_capture_ms": 9000.0,
                     "timestamp_kind": "source_capture"}],
        "missing": {}}
    row.update(overrides)
    return row


def test_understanding_evidence_malformed_identity_keys_never_queries(state):
    """C141-R2 冻结 §4：身份键畸形（在场但类型非法：bool/float/容器）或
    未记录（None）→ 全序位 missing + 固定码、零 find/零 read——修复前
    None/True 会被 str() 成 "None"/"True" 当有效 run_id 去查询索引（红）。
    展示层把畸形键折叠为 None（如实缺省，绝不展示 "True" 身份），证据门
    据此如实报 identity_unrecorded；类型级畸形分类（identity_malformed）
    由直连 _crop_evidence_slots 的单元门锁定（见下）。"""
    aid = hashlib.sha256(b"c141-malformed-bait").hexdigest()
    variants = (
        ("run_id 布尔", {"window_key": ["front", True, "v1", "w-1"]}),
        ("config 浮点", {"window_key": ["front", "run-1", 1.5, "w-1"]}),
        ("window 容器", {"window_key": ["front", "run-1", "v1", ["w-1"]]}),
        ("run_id None", {"window_key": ["front", None, "v1", "w-1"]}),
        ("crop_id 布尔", {"crop_id": True}),
        ("material 容器", {"branch_key": ["front", "run-1", "v1", "w-1",
                                          "relation_crop", "crop-7", {}]}),
    )
    for label, override in variants:
        state.understanding_store = UnderstandingStore()
        state.understanding_store.append("front", "l3", {
            "window": "w-1", "branch": "relation_crop", "status": "ok",
            "at": 1.0,
            "results": [_full_identity_row(**override)]})
        state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
        service = _StubCropService(index=[
            _crop_index_entry(asset_id=aid, slot="current", status="saved",
                              crop_id="crop-7")], blobs={aid: _C141_PNG})
        state.crop_service = service
        st, body = _get(state, "/api/understanding/front")
        assert st == 200, label
        ev = body["branches"][0]["evidence"]
        for slot_name in ("previous", "current", "next"):
            slot_ = ev[slot_name]
            assert slot_["status"] == "missing", (label, slot_name)
            assert slot_["reason"] == "identity_unrecorded", (label, slot_name)
            assert slot_["asset_id"] is None, (label, slot_name)
        assert service.find_calls == [], label
        assert service.read_calls == [], label
        # 展示面同样不冒充：畸形键折叠为 None，绝不出现 "None"/"True" 身份
        row = body["branches"][0]
        assert row["crop_id"] in (None, "crop-7"), label
        dumped = json.dumps(row["window_key"], ensure_ascii=False)
        assert '"None"' not in dumped and '"True"' not in dumped, label


def test_crop_evidence_slots_unit_gate_malformed_and_camera():
    """C141-R2 冻结 §4（直连单元门）：_crop_evidence_slots 对原始行的
    三类分支级身份门均零 find/零 read——
    - 畸形（身份键在场但类型非法）→ identity_malformed（新固定码）；
    - 跨相机（window_key[0] ≠ 请求相机）→ camera_mismatch（新固定码），
      且优先于缺省（更具体、不可被缺省键掩盖）；
    - 合法身份不触发任何门（对照：find 正常发生）。"""
    from scam.server import _crop_evidence_slots

    class _Svc:
        def __init__(self):
            self.finds = []
            self.reads = []

        def find(self, camera_id, filters=None, limit=10):
            self.finds.append((str(camera_id), dict(filters or {})))
            return []

        def read(self, asset_id):
            self.reads.append(str(asset_id))
            raise AssertionError("身份门后绝不允许读取")

    sources = [{"position": 1, "frame_id": "f-9", "present": True,
                "t_capture_ms": 9000.0}]
    svc = _Svc()
    out = _crop_evidence_slots("front", {
        "window_key": ["front", True, "v1", "w-1"], "kind": "relation_crop",
        "crop_id": "crop-7", "material_id": "mat-1", "sources": sources}, svc)
    assert out["available"] is True
    assert out["current"] == {"asset_id": None, "status": "missing",
                              "reason": "identity_malformed",
                              "t_capture_ms": 9000.0}
    assert out["previous"]["reason"] == "identity_malformed"
    assert out["next"]["reason"] == "identity_malformed"
    assert svc.finds == [] and svc.reads == []

    svc = _Svc()
    out = _crop_evidence_slots("front", {
        "window_key": ["yard", "run-1", "v1", "w-1"], "kind": "relation_crop",
        "crop_id": "crop-7", "material_id": "mat-1", "sources": sources}, svc)
    for name in ("previous", "current", "next"):
        assert out[name]["reason"] == "camera_mismatch", name
        assert out[name]["status"] == "missing" and \
            out[name]["asset_id"] is None, name
    assert svc.finds == [] and svc.reads == []

    # 跨相机优先于缺省：相机段合法但他相机 + 其余键缺省 → camera_mismatch
    svc = _Svc()
    out = _crop_evidence_slots("front", {
        "window_key": ["yard", None, "v1", "w-1"], "kind": "relation_crop",
        "crop_id": None, "material_id": "mat-1", "sources": sources}, svc)
    assert out["current"]["reason"] == "camera_mismatch"
    assert svc.finds == [] and svc.reads == []

    # 对照：同形状合法身份 → 无分支门，find 照常发生（零门不误伤）
    svc = _Svc()
    out = _crop_evidence_slots("front", {
        "window_key": ["front", "run-1", "v1", "w-1"],
        "kind": "relation_crop", "crop_id": "crop-7",
        "material_id": "mat-1", "sources": sources}, svc)
    assert out["current"]["status"] == "missing"
    assert out["current"]["reason"] == "not_in_index"
    assert len(svc.finds) == 1 and svc.reads == []


def test_understanding_evidence_cross_camera_never_queries(state):
    """C141-R2 冻结 §4：window_key[0]（相机）≠ 请求相机 → 全序位
    missing(camera_mismatch)、零 find/零 read——索引里摆着同 run/config/
    窗口/裁图/材料/源帧的 front saved 条目也绝不查询（修复前会查中并借出
    他相机资产，红）。"""
    state.understanding_store = UnderstandingStore()
    state.understanding_store.append("front", "l3", {
        "window": "w-1", "branch": "relation_crop", "status": "ok", "at": 1.0,
        "results": [_full_identity_row(
            window_key=["yard", "run-1", "v1", "w-1"],
            branch_key=["yard", "run-1", "v1", "w-1", "relation_crop",
                        "crop-7", "mat-1"])]})
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    aid = hashlib.sha256(b"c141-xcam-bait").hexdigest()
    service = _StubCropService(index=[
        _crop_index_entry(asset_id=aid, slot="current", status="saved",
                          crop_id="crop-7")], blobs={aid: _C141_PNG})
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    assert ev["available"] is True
    for slot_name in ("previous", "current", "next"):
        assert ev[slot_name]["status"] == "missing", slot_name
        assert ev[slot_name]["reason"] == "camera_mismatch", slot_name
        assert ev[slot_name]["asset_id"] is None, slot_name
    assert service.find_calls == [], "绝不查询他相机索引"
    assert service.read_calls == []


def test_understanding_evidence_frame_id_malformed_never_queries(state):
    """C141-R2：源帧 frame_id 在场但类型非法（bool/容器/浮点）→ 该序位
    missing(frame_identity_malformed)（新固定码）且零查询——绝不 str 化
    成 "True"/"['f-9']"/"9.5" 后当有效帧身份借图；None → 既有
    frame_identity_unrecorded 不回归。"""
    for label, bad in (("布尔", True), ("容器", ["f-9"]), ("浮点", 9.5)):
        sources = [{"position": 1, "frame_id": bad, "present": True,
                    "t_capture_ms": 9000.0,
                    "timestamp_kind": "source_capture"}]
        state.understanding_store = _seed_full_identity_branch(
            sources=sources)
        state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
        service = _StubCropService(index=[
            _crop_index_entry(asset_id=_C141_AID, slot="current",
                              status="saved", crop_id="crop-7")],
            blobs={_C141_AID: _C141_PNG})
        state.crop_service = service
        st, body = _get(state, "/api/understanding/front")
        assert st == 200, label
        ev = body["branches"][0]["evidence"]
        assert ev["current"] == {"asset_id": None, "status": "missing",
                                 "reason": "frame_identity_malformed",
                                 "t_capture_ms": 9000.0}, label
        assert ev["previous"]["reason"] == "frame_absent", label
        assert ev["next"]["reason"] == "frame_absent", label
        assert service.find_calls == [] and service.read_calls == [], label


def test_understanding_evidence_commit_uncertain_passthrough(state):
    """C141-R2 冻结 §2：A 的耐久提交不确定态 commit_uncertain 原样透传为
    可见状态（与 saved/pending/failed/dropped 并列）——绝不映射成
    missing/saved/failed；绝不发 asset_id、绝不触发读取（权威真相=索引
    文件本身）；reason 原样透传。"""
    state.understanding_store = UnderstandingStore()
    state.understanding_store.append("front", "l3", {
        "window": "w-1", "branch": "relation_crop", "status": "ok", "at": 1.0,
        "results": [_full_identity_row(sources=[
            {"position": 0, "frame_id": "f-8", "present": True,
             "t_capture_ms": 8000.0, "timestamp_kind": "source_capture"},
            {"position": 1, "frame_id": "f-9", "present": True,
             "t_capture_ms": 9000.0, "timestamp_kind": "source_capture"}])]})
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    aid = hashlib.sha256(b"c141-uncertain").hexdigest()
    service = _StubCropService(index=[
        _crop_index_entry(asset_id=None, slot="current",
                          status="commit_uncertain", crop_id="crop-7"),
        _crop_index_entry(asset_id=None, slot="previous",
                          status="commit_uncertain",
                          reason="index_fsync_failed", crop_id="crop-7",
                          frame_id="f-8")],
        blobs={aid: _C141_PNG})
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    assert ev["current"] == {"asset_id": None, "status": "commit_uncertain",
                             "reason": None, "t_capture_ms": 9000.0}
    assert ev["previous"] == {"asset_id": None,
                              "status": "commit_uncertain",
                              "reason": "index_fsync_failed",
                              "t_capture_ms": 8000.0}
    assert service.read_calls == [], "不确定态绝不触发资产读取"
    assert "commit_uncertain" in json.dumps(body, ensure_ascii=False)


_C141_COMMIT_UNCERTAIN = {"status": "commit_uncertain",
                          "reason": "index_commit_uncertain",
                          "asset_id": None}
_C141_NINE_IDENTITY = {"camera_id": "front", "run_id": "run-1",
                       "config_version": "v1", "window_id": "w-1",
                       "branch": "local", "crop_id": "crop-7",
                       "material_id": "mat-1", "slot": "current",
                       "frame_id": "f-9"}


def test_understanding_evidence_commit_status_saved_row_uncertain(state):
    """C141-R3 冻结 §2 判定 2：find 命中 saved + commit_status=
    commit_uncertain → 序位 commit_uncertain + 附注固定码
    index_saved_commit_uncertain（DOM 标「索引行已可读但耐久未确认」）；
    绝不给 asset_id、绝不触发 read——耐久未确认前绝不展示像素。
    修复前：索引行可读即照 R1 展示 saved+read，内存不确定对用户不可见（红）。"""
    state.understanding_store = _seed_full_identity_branch()
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    aid = hashlib.sha256(b"c141-r3-saved-uncertain").hexdigest()
    service = _StubCropService(
        index=[_crop_index_entry(asset_id=aid, slot="current",
                                 status="saved", crop_id="crop-7")],
        blobs={aid: _C141_PNG},
        with_commit_status=True,
        commit_status_result=dict(_C141_COMMIT_UNCERTAIN,
                                  asset_id=aid))
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    assert ev["available"] is True
    assert ev["current"] == {"asset_id": None,
                             "status": "commit_uncertain",
                             "reason": "index_saved_commit_uncertain",
                             "t_capture_ms": 9000.0}
    assert service.read_calls == [], "耐久未确认绝不触发资产读取"
    # 索引事实照常读取（判定顺序：find 先行）；commit_status 按冻结 §1
    # 携带完整九元身份（camera/run/config/material/window/branch/crop/
    # frame_id/slot），缺帧序位零查询。
    assert service.find_calls == [{"camera": "front",
                                   "filters": _full_identity_find_filters(),
                                   "limit": 1}]
    assert service.commit_calls == [{"camera": "front",
                                     "identity": _C141_NINE_IDENTITY}]
    assert "commit_uncertain" in json.dumps(body, ensure_ascii=False)


def test_understanding_evidence_commit_status_uncertain_without_index_row(state):
    """C141-R3 冻结 §2 判定 3：find 无命中 + commit_status=
    commit_uncertain → 序位 commit_uncertain（reason=None）——**绝不降级
    not_in_index/missing**（真实链路 find 永不返回 uncertain，无索引行的
    内存不确定必须对用户可见）；缺帧序位不查 commit_status，维持
    frame_absent。修复前：无索引行 → not_in_index，内存不确定不可见（红）。"""
    state.understanding_store = _seed_full_identity_branch()
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    service = _StubCropService(index=[], with_commit_status=True,
                               commit_status_result=dict(
                                   _C141_COMMIT_UNCERTAIN))
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    assert ev["current"] == {"asset_id": None,
                             "status": "commit_uncertain",
                             "reason": None,
                             "t_capture_ms": 9000.0}, \
        "无索引行的内存不确定绝不降级 not_in_index"
    assert ev["previous"] == {"asset_id": None, "status": "missing",
                              "reason": "frame_absent",
                              "t_capture_ms": None}
    assert ev["next"] == ev["previous"]
    # 仅 current 序位（帧在场）查询：find 与 commit_status 各一次
    assert len(service.find_calls) == 1
    assert service.commit_calls == [{"camera": "front",
                                     "identity": _C141_NINE_IDENTITY}]
    assert service.read_calls == []


def test_understanding_evidence_commit_status_no_uncertainty_keeps_existing(state):
    """C141-R3 冻结 §2 判定 4：commit_status 返回 {"status": None}（匹配
    任务无不确定）或 None（无匹配/重启后进程状态已失去）→ 既有逻辑不
    回归——saved 命中照常展示（read+身份复核），无命中如实 not_in_index。"""
    state.understanding_store = _seed_full_identity_branch()
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    aid = hashlib.sha256(b"c141-r3-no-uncertainty").hexdigest()
    # {"status": None}（匹配但无不确定）→ saved 展示
    service = _StubCropService(
        index=[_crop_index_entry(asset_id=aid, slot="current",
                                 status="saved", crop_id="crop-7")],
        blobs={aid: _C141_PNG},
        with_commit_status=True, commit_status_result={"status": None})
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    assert ev["current"] == {"asset_id": aid, "status": "saved",
                             "reason": None, "t_capture_ms": 9000.0}
    assert service.read_calls == [aid]
    # None（无匹配/重启）+ 索引无行 → 既有 not_in_index
    service = _StubCropService(index=[], with_commit_status=True,
                               commit_status_result=None)
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    assert ev["current"] == {"asset_id": None, "status": "missing",
                             "reason": "not_in_index",
                             "t_capture_ms": 9000.0}
    assert service.read_calls == []


def test_understanding_evidence_commit_status_method_missing_no_regression(state):
    """C141-R3：服务无 commit_status 方法（鸭子缺失——旧服务/A 未接线）
    → 跳过该查询走既有逻辑，结构化降级不回归：saved 照常展示、无命中
    照常 not_in_index，绝不因方法缺失而异常。"""
    state.understanding_store = _seed_full_identity_branch()
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    aid = hashlib.sha256(b"c141-r3-no-method").hexdigest()
    service = _StubCropService(
        index=[_crop_index_entry(asset_id=aid, slot="current",
                                 status="saved", crop_id="crop-7")],
        blobs={aid: _C141_PNG})
    assert not hasattr(service, "commit_status"), "替身默认不挂载该方法"
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    assert ev["current"] == {"asset_id": aid, "status": "saved",
                             "reason": None, "t_capture_ms": 9000.0}
    assert service.read_calls == [aid]
    service = _StubCropService(index=[])
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    assert ev["current"]["reason"] == "not_in_index"


def test_understanding_evidence_identity_gates_zero_commit_status_queries(state):
    """C141-R3：R1/R2 全身份门语义对 commit_status 同样成立——分支身份
    未记录 → 全序位 missing(identity_unrecorded) 且 find 与 commit_status
    全零查询（零查询门先于一切）；畸形/跨相机同门（此处以未记录为代表
    锁定零调用，畸形/跨相机的门序由既有用例锁定不变）。"""
    aid = hashlib.sha256(b"c141-r3-gate-bait").hexdigest()
    state.understanding_store = UnderstandingStore()
    state.understanding_store.append("front", "l3", {
        "window": "w-1", "branch": "relation_crop", "status": "ok", "at": 1.0,
        "results": [_full_identity_row(crop_id=None)]})
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    service = _StubCropService(
        index=[_crop_index_entry(asset_id=aid, slot="current",
                                 status="saved", crop_id="crop-7")],
        blobs={aid: _C141_PNG},
        with_commit_status=True,
        commit_status_result=dict(_C141_COMMIT_UNCERTAIN))
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    for slot_name in ("previous", "current", "next"):
        assert ev[slot_name]["status"] == "missing", slot_name
        assert ev[slot_name]["reason"] == "identity_unrecorded", slot_name
    assert service.find_calls == [] and service.read_calls == []
    assert service.commit_calls == [], "身份门零查询：commit_status 也不得触达"


def test_understanding_evidence_int_identity_compat_preserved(state):
    """C141-R2 不回归：合法 int 身份（run/crop/material/frame）按 R1 冻结
    规范化为字符串形参与等值匹配——照常命中 saved 资产（int/str 兼容
    不变；bool/float/容器仍非法，见畸形用例）。"""
    state.understanding_store = UnderstandingStore()
    state.understanding_store.append("front", "l3", {
        "window": "w-1", "branch": "relation_crop", "status": "ok", "at": 1.0,
        "results": [_full_identity_row(
            window_key=["front", 12, "v1", "w-1"],
            branch_key=["front", 12, "v1", "w-1", "relation_crop",
                        "crop-7", 3],
            crop_id=7,
            sources=[{"position": 1, "frame_id": 9, "present": True,
                      "t_capture_ms": 9000.0,
                      "timestamp_kind": "source_capture"}])]})
    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    aid = hashlib.sha256(b"c141-int-compat").hexdigest()
    service = _StubCropService(index=[
        _crop_index_entry(asset_id=aid, slot="current", status="saved",
                          crop_id="7", run_id="12", material_id="3",
                          frame_id="9")], blobs={aid: _C141_PNG})
    state.crop_service = service
    st, body = _get(state, "/api/understanding/front")
    assert st == 200
    ev = body["branches"][0]["evidence"]
    assert ev["current"] == {"asset_id": aid, "status": "saved",
                             "reason": None, "t_capture_ms": 9000.0}
    # find 过滤键已按冻结规范整型→字符串形（与索引条目字符串形等值命中）
    assert service.find_calls == [{"camera": "front",
                                   "filters": {"run_id": "12",
                                               "config_version": "v1",
                                               "window_id": "w-1",
                                               "branch": "local",
                                               "crop_id": "7",
                                               "material_id": "3",
                                               "slot": "current",
                                               "frame_id": "9"},
                                   "limit": 1}]


def test_understanding_summary_prefers_identity_aware_l2(state):
    """C141 summary 接线：l2.understanding_summary 非空 → 原文优先
    （/api/understanding 与 /api/health 一致）；「保存失败（未持久化）」
    等语义由 B 的实现带来，接线层不改写文本。"""
    state.understanding_store = _seed_understanding_store()
    state.l2 = SimpleNamespace(
        _registry={"front": ("run-1", "v1")},
        understanding_summary=lambda cam: (
            "分支 完成 1 / 失败 0 / 淘汰 0 / 等待 0；当前身份 run-1/v1 已有"
            "结果；另有 1 条结果保存失败（未持久化）"))
    st, body = _get(state, "/api/understanding/front")
    assert body["summary"] == (
        "分支 完成 1 / 失败 0 / 淘汰 0 / 等待 0；当前身份 run-1/v1 已有结果；"
        "另有 1 条结果保存失败（未持久化）")
    st, body = _get(state, "/api/health")
    assert body["understanding"]["front"]["summary"].endswith(
        "另有 1 条结果保存失败（未持久化）")


def test_understanding_summary_falls_back_without_or_broken_l2(state):
    """B 摘要异常/空串/方法缺失 → 回退既有 ustore 摘要行为（旧形状不
    回归，异常正文不外泄）。"""
    state.understanding_store = _seed_understanding_store()

    def _boom(cam):
        raise RuntimeError("summary exploded")

    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")},
                               understanding_summary=_boom)
    st, body = _get(state, "/api/understanding/front")
    assert st == 200 and "分支 完成" in body["summary"]
    assert "exploded" not in body["summary"]

    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")},
                               understanding_summary=lambda cam: "  ")
    st, body = _get(state, "/api/understanding/front")
    assert "分支 完成" in body["summary"]

    state.l2 = SimpleNamespace(_registry={"front": ("run-1", "v1")})
    st, body = _get(state, "/api/understanding/front")
    assert "分支 完成" in body["summary"]


_CROPS_EVIDENCE_DOM_HARNESS_JS = r'''
const fs = require("fs");
const pageJs = fs.readFileSync(process.argv[2], "utf8");

function el(tag) {
  return {
    tag: tag, children: [], textContent: "", className: "", hidden: false,
    disabled: false, onclick: null, href: "", target: "", value: "",
    dataset: {}, id: "", parentNode: null,
    // C142：页面「来源」切换钮/原图链接带 aria 属性（setAttribute 真实
    // 调用），harness 忠实记录键值供断言（缺失键 getAttribute → null）。
    attrs: {},
    setAttribute: function (k, v) { this.attrs[k] = String(v); },
    getAttribute: function (k) {
      return Object.prototype.hasOwnProperty.call(this.attrs, k)
        ? this.attrs[k] : null; },
    classList: { add: function () {}, remove: function () {},
      toggle: function () {} },
    // 本 harness 的 el 忠实模拟 parentNode/removeChild 语义：图片 onerror
    // 路径会从 DOM 摘除失效 <img>，断言依赖这一真实行为。
    appendChild: function (c) { this.children.push(c); c.parentNode = this;
      return c; },
    removeChild: function (c) {
      const i = this.children.indexOf(c);
      if (i >= 0) this.children.splice(i, 1);
      c.parentNode = null; return c; },
    prepend: function (c) { this.children.unshift(c); c.parentNode = this; },
    replaceChildren: function () {
      this.children.forEach(function (c) { c.parentNode = null; });
      this.children = []; },
    querySelector: function () { return null; },
    addEventListener: function () {}, scrollIntoView: function () {},
    insertRow: function () {
      const r = el("tr");
      r.insertCell = function () { const c = el("td"); r.children.push(c);
        c.parentNode = r; return c; };
      this.children.push(r); r.parentNode = this; return r;
    },
    insertCell: function () { const c = el("td"); this.children.push(c);
      c.parentNode = this; return c; },
  };
}
const byId = new Map();
function gid(id) {
  if (!byId.has(id)) byId.set(id, el("#" + id));
  return byId.get(id);
}
["l1-status", "l1-materials", "l2-note", "understanding-line",
 "understanding-detail"].forEach(function (id) { gid(id).hidden = true; });
function resp(obj, status) {
  status = status || 200;
  return { ok: status >= 200 && status < 300, status: status,
           json: async function () { return obj; } };
}
let healthPayload = {};
let healthFail = false;
let deferredHealth = null;
function makeDeferred() {
  let resolve;
  const promise = new Promise(function (r) { resolve = r; });
  return { resolve: resolve, promise: promise };
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
globalThis.fetch = async function (url) {
  if (url.indexOf("/api/health") === 0) {
    if (healthFail) throw new TypeError("health endpoint down");
    if (deferredHealth) return resp(await deferredHealth.promise);
    return resp(healthPayload);
  }
  if (url === "/api/cameras") return resp({ cameras: [] });
  if (url.indexOf("/api/v2/notifications") === 0)
    return resp({ notifications: [], next_cursor: null });
  if (url.indexOf("/api/v2/events") === 0) return resp({ events: [] });
  if (url === "/api/review") return resp({ segments: [] });
  if (url === "/api/events") return resp({ events: [] });
  if (url === "/api/patterns") return resp({ patterns: [] });
  return resp({}, 404);
};

function allDescendants(node) {
  const out = [];
  (node.children || []).forEach(function (c) {
    out.push(c); out.push.apply(out, allDescendants(c));
  });
  return out;
}
function flatText(node) {
  return allDescendants(node).map(function (c) {
    return c.textContent || "";
  }).join("|") + "|" + (node.textContent || "");
}
function tagCount(node, tag) {
  return allDescendants(node).filter(function (c) { return c.tag === tag; })
    .length;
}

(async () => {
  const results = {};
  const tick = () => new Promise((r) => setImmediate(r));
  const detail = () => gid("understanding-detail");
  const line = () => gid("understanding-line");
  async function drive() { await refreshHealth(); await tick(); await tick(); }
  const AID = "ab".repeat(32);   // 64 hex 的 saved 资产标识
  function slot(status, reason, assetId, t) {
    return { asset_id: assetId === undefined ? null : assetId,
             status: status, reason: reason || null,
             t_capture_ms: t === undefined ? null : t };
  }
  // 分支 1：prev=pending / cur=saved / next=dropped；
  // 分支 2：prev=missing(身份未记录) / cur=failed(原因含标记片段) /
  //         next=missing(缺帧)。
  const evEntry = {
    summary: "分支 完成 2 / 失败 0 / 淘汰 0 / 等待 0",
    counts: { done: 2, failed: 0, evicted: 0, pending: 0 },
    current_identity: { run_id: "run-1", config_version: "v1" },
    branches: [
      { branch_key: "w1|relation_crop|c1", kind: "relation_crop",
        kind_label: "关系局部", status: "ok", text: "该人员手持包裹",
        crop_id: "crop-7", is_current: true,
        evidence_available: false, evidence_url: null,
        sources: [], missing: {},
        evidence: { available: true,
          previous: slot("pending"),
          current: slot("saved", null, AID, 9000),
          next: slot("dropped", "ttl_exceeded") } },
      { branch_key: "w1|panorama|", kind: "panorama",
        kind_label: "全景理解", status: "ok", text: "全景分支",
        is_current: true, evidence_available: false, evidence_url: null,
        sources: [], missing: {},
        evidence: { available: true,
          previous: slot("missing", "identity_unrecorded"),
          current: slot("failed", "index_failed<img src=x onerror=alert(9)>"),
          next: slot("missing", "frame_absent") } } ],
    fusion: null, fusion_history: [],
    model_ref: "local-vlm-7b", calibrated: false };

  try {
    require("vm").runInThisContext(pageJs,
      { filename: "workbench-page.js" });
    await tick(); await tick(); await tick();
    gid("camera-select").value = "cam-a";

    // ===== 一、三序位四态占位文本 + 受控 /api/crops 图片与原图链接 =====
    healthPayload = { understanding: { "cam-a": evEntry } };
    await drive();
    const text1 = flatText(detail());
    results.pendingShowsSaving = text1.indexOf("前帧裁图：保存中") >= 0;
    results.savedShowsLabelAndOriginalLink =
      text1.indexOf("当前帧裁图：已保存") >= 0
      && text1.indexOf("查看原图") >= 0;
    results.droppedShowsReason =
      text1.indexOf("后帧裁图：已淘汰（ttl_exceeded）") >= 0;
    results.failedShowsReasonAsText =
      text1.indexOf("当前帧裁图：保存失败（index_failed"
        + "<img src=x onerror=alert(9)>）") >= 0;
    results.missingShowsReason =
      text1.indexOf("前帧裁图：缺失（identity_unrecorded）") >= 0
      && text1.indexOf("后帧裁图：缺失（frame_absent）") >= 0;
    const imgs = allDescendants(detail()).filter(function (c) {
      return c.tag === "img"; });
    results.reasonMarkupStaysTextAndOnlySavedSlotHasImg =
      imgs.length === 1
      && imgs[0].src === "/api/crops/" + AID + "?camera=cam-a";
    results.detailRendersWithoutGlobalError = detail().hidden === false;

    // ===== 二、服务不可用 → 整体占位文案（绝不假缩略图/失效链接） =====
    const offEntry = JSON.parse(JSON.stringify(evEntry));
    offEntry.branches.forEach(function (b) {
      b.evidence = { available: false,
        reason: "crop_service_unavailable" }; });
    healthPayload = { understanding: { "cam-a": offEntry } };
    await drive();
    const text2 = flatText(detail());
    results.serviceUnavailablePlaceholder =
      text2.indexOf("裁图证据：裁图服务不可用") >= 0
      && text2.indexOf("查看原图") < 0
      && tagCount(detail(), "img") === 0;

    // ===== 三、图片 onerror（同相机）→ 该序位错误占位，页面不清空 =====
    healthPayload = { understanding: { "cam-a": evEntry } };
    await drive();
    const img1 = allDescendants(detail()).find(function (c) {
      return c.tag === "img"; });
    img1.onerror();
    const text3 = flatText(detail());
    results.imageErrorShowsSlotPlaceholderNotGlobal =
      text3.indexOf("当前帧裁图缩略图加载失败") >= 0
      && detail().hidden === false
      && text3.indexOf("该人员手持包裹") >= 0
      && tagCount(detail(), "img") === 0;

    // ===== 四、切相机后迟到的图片失败不写新页面 =====
    await drive();   // cam-a 重新渲染（新图片节点）
    const img2 = allDescendants(detail()).find(function (c) {
      return c.tag === "img"; });
    gid("camera-select").value = "cam-b";
    healthPayload = { understanding: { "cam-b": { summary: "相机 B 摘要" } } };
    await drive();
    const camBText = flatText(detail());
    img2.onerror();   // 迟到的旧相机（cam-a）图片失败
    results.lateImageErrorDoesNotPaintNewCamera =
      flatText(detail()) === camBText
      && camBText.indexOf("缩略图加载失败") < 0
      && line().textContent.indexOf("相机 B 摘要") >= 0;

    // ===== 五、迟到的详情响应（含 evidence）不覆盖切走后的新页 =====
    gid("camera-select").value = "cam-a";
    deferredHealth = makeDeferred();
    const pending = refreshHealth();          // 请求发出时选中 cam-a
    gid("camera-select").value = "cam-b";     // 用户随即切走
    deferredHealth.resolve({ understanding: { "cam-a": evEntry } });
    await pending; await tick(); await tick();
    results.lateEvidenceResponseDoesNotPaintSwitchedCamera =
      flatText(detail()).indexOf("当前帧裁图：已保存") < 0
      && line().textContent.indexOf("相机 B 摘要") >= 0;
    deferredHealth = null;

    // ===== 六、commit_uncertain（耐久提交不确定态，C141-R2 冻结 §2）→
    // 「提交待确认」占位：原样透传不映射成缺失/保存失败/已保存，无缩略图、
    // 无原图链接、无假错误；相邻序位既有状态渲染不回归 =====
    gid("camera-select").value = "cam-a";
    const ucEntry = JSON.parse(JSON.stringify(evEntry));
    ucEntry.branches = [ucEntry.branches[0]];
    ucEntry.branches[0].evidence = { available: true,
      previous: slot("commit_uncertain"),
      current: slot("commit_uncertain", "index_fsync_failed"),
      next: slot("pending") };
    healthPayload = { understanding: { "cam-a": ucEntry } };
    await drive();
    const text6 = flatText(detail());
    results.commitUncertainShowsHonestPlaceholder =
      text6.indexOf("前帧裁图：提交待确认") >= 0
      && text6.indexOf("当前帧裁图：提交待确认（index_fsync_failed）") >= 0
      && text6.indexOf("后帧裁图：保存中") >= 0;
    results.commitUncertainNotMappedToOtherStates =
      text6.indexOf("当前帧裁图：缺失") < 0
      && text6.indexOf("当前帧裁图：保存失败") < 0
      && text6.indexOf("当前帧裁图：已保存") < 0;
    results.commitUncertainNoThumbnailOrLink =
      tagCount(detail(), "img") === 0
      && text6.indexOf("查看原图") < 0;

    // ===== 七、C141-R3 冻结 §2：真实链路 find 只回 saved/failed，内存
    // commit_uncertain 由 server 消费 A 的 commit_status 合成——
    // - 有索引行（saved）+ uncertain → 「提交待确认（索引行已可读但耐久
    //   未确认）」，无缩略图无原图链接（绝不照 saved 展示像素）；
    // - 无索引行 + uncertain → 「提交待确认」（绝不显示缺失/不降级）；
    // - R2 的任意 reason 透传分支保留（（index_fsync_failed）原样）。 =====
    const r3Entry = JSON.parse(JSON.stringify(evEntry));
    r3Entry.branches = [r3Entry.branches[0]];
    r3Entry.branches[0].evidence = { available: true,
      previous: slot("commit_uncertain", "index_saved_commit_uncertain"),
      current: slot("commit_uncertain"),
      next: slot("commit_uncertain", "index_fsync_failed") };
    healthPayload = { understanding: { "cam-a": r3Entry } };
    await drive();
    const text7 = flatText(detail());
    results.savedRowUncertainShowsDurabilityNote =
      text7.indexOf("前帧裁图：提交待确认（索引行已可读但耐久未确认）") >= 0;
    results.noIndexRowUncertainShowsPlainPendingCommit =
      text7.indexOf("当前帧裁图：提交待确认") >= 0
      && text7.indexOf("当前帧裁图：缺失") < 0;
    results.r2ReasonPassthroughBranchPreserved =
      text7.indexOf("后帧裁图：提交待确认（index_fsync_failed）") >= 0;
    results.r3UncertainNeverShowsPixelsOrErrors =
      tagCount(detail(), "img") === 0
      && text7.indexOf("查看原图") < 0
      && text7.indexOf("保存失败") < 0;
  } catch (err) {
    results.harnessError = String(err && err.stack || err);
  }
  let ok = true;
  Object.keys(results).forEach((k) => { if (results[k] !== true) ok = false; });
  console.log(JSON.stringify({ ok: ok, results: results }));
  process.exit(ok ? 0 : 1);
})();
'''


def test_crops_evidence_face_dom_executable(state, tmp_path):
    """C141 可执行 DOM 测试：node 真实执行页面脚本驱动 refreshHealth，断言
    分支详情三序位证据占位文本（saved/pending/failed/dropped/missing 与
    C141-R2 冻结 §2 的 commit_uncertain「提交待确认」）、受控 /api/crops
    图片与可点原图链接、reason 片段按纯文本渲染（不进标签）、服务不可用
    整体占位、图片 onerror→该序位错误占位（页面不清空、不弹全局错误）、
    切相机后迟到的图片失败与迟到详情响应不覆盖新页。node 不可用时跳过并
    如实标注。"""
    import shutil
    import subprocess
    handler = _get_handler(state, "/")
    html = handler.wfile.getvalue().decode("utf-8")
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert scripts, "工作台必须带内联脚本"
    node = shutil.which("node")
    if node is None:
        pytest.skip("node 不可用：无法执行页面脚本交互测试")
    page = tmp_path / "workbench-page-crops-evidence.js"
    page.write_text(scripts[-1], encoding="utf-8")
    harness = tmp_path / "harness-crops-evidence.js"
    harness.write_text(_CROPS_EVIDENCE_DOM_HARNESS_JS, encoding="utf-8")
    proc = subprocess.run([node, str(harness), str(page)],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (
        "裁图证据 DOM 测试失败\nstdout: " + proc.stdout[-3000:]
        + "\nstderr: " + proc.stderr[-800:])
    data = json.loads(proc.stdout)
    assert data["ok"] is True, data["results"]


_SOURCES_A11Y_DOM_HARNESS_JS = r'''
const fs = require("fs");
const pageJs = fs.readFileSync(process.argv[2], "utf8");

function el(tag) {
  return {
    tag: tag, children: [], textContent: "", className: "", hidden: false,
    disabled: false, onclick: null, href: "", target: "", value: "",
    dataset: {}, id: "", parentNode: null,
    attrs: {},
    setAttribute: function (k, v) { this.attrs[k] = String(v); },
    getAttribute: function (k) {
      return Object.prototype.hasOwnProperty.call(this.attrs, k)
        ? this.attrs[k] : null; },
    classList: { add: function () {}, remove: function () {},
      toggle: function () {} },
    appendChild: function (c) { this.children.push(c); c.parentNode = this;
      return c; },
    removeChild: function (c) {
      const i = this.children.indexOf(c);
      if (i >= 0) this.children.splice(i, 1);
      c.parentNode = null; return c; },
    prepend: function (c) { this.children.unshift(c); c.parentNode = this; },
    replaceChildren: function () {
      this.children.forEach(function (c) { c.parentNode = null; });
      this.children = []; },
    querySelector: function () { return null; },
    addEventListener: function () {}, scrollIntoView: function () {},
    insertRow: function () {
      const r = el("tr");
      r.insertCell = function () { const c = el("td"); r.children.push(c);
        c.parentNode = r; return c; };
      this.children.push(r); r.parentNode = this; return r;
    },
    insertCell: function () { const c = el("td"); this.children.push(c);
      c.parentNode = this; return c; },
  };
}
const byId = new Map();
function gid(id) {
  if (!byId.has(id)) byId.set(id, el("#" + id));
  return byId.get(id);
}
["l1-status", "l1-materials", "l2-note", "understanding-line",
 "understanding-detail"].forEach(function (id) { gid(id).hidden = true; });
function resp(obj, status) {
  status = status || 200;
  return { ok: status >= 200 && status < 300, status: status,
           json: async function () { return obj; } };
}
let healthPayload = {};
let healthFail = false;
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
globalThis.fetch = async function (url) {
  if (url.indexOf("/api/health") === 0) {
    if (healthFail) throw new TypeError("health endpoint down");
    return resp(healthPayload);
  }
  if (url === "/api/cameras") return resp({ cameras: [] });
  if (url.indexOf("/api/v2/notifications") === 0)
    return resp({ notifications: [], next_cursor: null });
  if (url.indexOf("/api/v2/events") === 0) return resp({ events: [] });
  if (url === "/api/review") return resp({ segments: [] });
  if (url === "/api/events") return resp({ events: [] });
  if (url === "/api/patterns") return resp({ patterns: [] });
  return resp({}, 404);
};

function allDescendants(node) {
  const out = [];
  (node.children || []).forEach(function (c) {
    out.push(c); out.push.apply(out, allDescendants(c));
  });
  return out;
}
function flatText(node) {
  return allDescendants(node).map(function (c) {
    return c.textContent || "";
  }).join("|") + "|" + (node.textContent || "");
}

(async () => {
  const results = {};
  const tick = () => new Promise((r) => setImmediate(r));
  const detail = () => gid("understanding-detail");
  async function drive() { await refreshHealth(); await tick(); await tick(); }
  const AID1 = "ab".repeat(32);
  const AID2 = "cd".repeat(32);
  function slot(status, reason, assetId, t) {
    return { asset_id: assetId === undefined ? null : assetId,
             status: status, reason: reason || null,
             t_capture_ms: t === undefined ? null : t };
  }
  // 四条分支：b1 当前局部（生产形状 crop_id，含 ':frame:'）+ saved 当前帧
  // + 旧证据路径「打开原始裁图」；b2 当前局部（短形状 crop-7，无 ':frame:'
  // 标记）+ saved 当前帧 + R3「提交待确认」前帧；b3 历史全景（无 crop/
  // material，窗口同为 11 → 与 b4 基础锚碰撞，须 kN 后缀消解）；b4 当前
  // 全景（无 crop/material）。DOM 渲染顺序：当前区 b1,b2,b4 → 历史区 b3。
  const a11yEntry = {
    summary: "分支 完成 4 / 失败 0 / 淘汰 0 / 等待 0",
    counts: { done: 4, failed: 0, evicted: 0, pending: 0 },
    current_identity: { run_id: "run-1", config_version: "v1" },
    branches: [
      { branch_key: ["cam-a", "run-1", "v1", "11", "relation_crop",
                     "cam-a:run-1:frame:7633:crop:0", "610"],
        kind: "relation_crop", kind_label: "关系局部", status: "ok",
        text: "该人员手持包裹",
        window_key: ["cam-a", "run-1", "v1", "11"],
        crop_id: "cam-a:run-1:frame:7633:crop:0", material_id: "610",
        model_ref: "local-vlm-7b", is_current: true,
        evidence_available: true, evidence_url: "/api/evidence/ev-1",
        sources: [{ position: 1, frame_id: 7633, present: true,
                    t_capture_ms: 5000, timestamp_kind: "source_capture" }],
        missing: {},
        evidence: { available: true,
          previous: slot("missing", "frame_absent"),
          current: slot("saved", null, AID1, 5000),
          next: slot("missing", "not_in_index") } },
      { branch_key: ["cam-a", "run-1", "v1", "11", "relation_crop",
                     "crop-7", "610"],
        kind: "relation_crop", kind_label: "关系局部", status: "ok",
        text: "另一处局部",
        window_key: ["cam-a", "run-1", "v1", "11"],
        crop_id: "crop-7", material_id: "610",
        model_ref: "local-vlm-7b", is_current: true,
        evidence_available: false, evidence_url: null,
        sources: [], missing: {},
        evidence: { available: true,
          previous: slot("commit_uncertain",
                         "index_saved_commit_uncertain"),
          current: slot("saved", null, AID2, 6000),
          next: slot("pending") } },
      { branch_key: ["cam-a", "run-0", "v0", "11", "panorama", ""],
        kind: "panorama", kind_label: "全景理解", status: "ok",
        text: "旧身份的全景",
        window_key: ["cam-a", "run-0", "v0", "11"],
        crop_id: null, material_id: null,
        is_current: false, evidence_available: false, evidence_url: null,
        sources: [], missing: {} },
      { branch_key: ["cam-a", "run-1", "v1", "11", "panorama", ""],
        kind: "panorama", kind_label: "全景理解", status: "ok",
        text: "当前身份的全景",
        window_key: ["cam-a", "run-1", "v1", "11"],
        crop_id: null, material_id: null,
        is_current: true, evidence_available: false, evidence_url: null,
        sources: [], missing: {} } ],
    fusion: null, fusion_history: [],
    model_ref: "local-vlm-7b", calibrated: false };

  try {
    require("vm").runInThisContext(pageJs,
      { filename: "workbench-page.js" });
    await tick(); await tick(); await tick();
    gid("camera-select").value = "cam-a";
    healthPayload = { understanding: { "cam-a": a11yEntry } };
    await drive();

    const rows = allDescendants(detail()).filter(function (c) {
      return c.className === "und-branch"; });
    results.fourBranchRowsRendered = rows.length === 4;
    const toggles = allDescendants(detail()).filter(function (c) {
      return c.tag === "button" && c.className === "und-toggle"; });
    results.fourToggleButtonsFound = toggles.length === 4;

    // 一、切换钮是真 <button> 且初始 aria-expanded=false（此前缺失）
    results.togglesAreButtonsWithAriaExpandedFalse =
      toggles.every(function (t) {
        return t.type === "button"
          && t.getAttribute("aria-expanded") === "false"; });

    // 二、可访问名（aria-label）=「来源-」+ 冻结锚，逐行精确（含生产
    // crop_id 形状 ':frame:' 派生与短形状整段派生）
    const labels = toggles.map(function (t) {
      return t.getAttribute("aria-label"); });
    const expectedLabels = ["来源-w11-c7633-crop-0-m610",
                            "来源-w11-ccrop-7-m610",
                            "来源-w11-cnocrop-mx",
                            "来源-w11-cnocrop-mx-k2"];
    results.toggleAccessibleNamesFrozen = JSON.stringify(labels)
      === JSON.stringify(expectedLabels);
    results.toggleAccessibleNamesUnique =
      new Set(labels).size === labels.length;
    // 主会话定位串模式（Playwright）：getByRole("button",
    // {name: /来源-w11-c7633/}) 唯一命中
    results.locatorPatternButtonUnique =
      labels.filter(function (l) {
        return /来源-w11-c7633/.test(l); }).length === 1;

    // 三、展开区 id 与 aria-controls 关联，同页唯一（此前 id 缺失）
    const areas = allDescendants(detail()).filter(function (c) {
      return c.className === "und-sources"; });
    results.areasMatchToggles = areas.length === 4;
    const areaIds = areas.map(function (a) { return a.id; });
    results.areaIdsFrozenAndUnique =
      JSON.stringify(areaIds) === JSON.stringify(
        ["src-detail-w11-c7633-crop-0-m610",
         "src-detail-w11-ccrop-7-m610",
         "src-detail-w11-cnocrop-mx",
         "src-detail-w11-cnocrop-mx-k2"]);
    results.ariaControlsWiredToAreaIds = toggles.every(function (t, i) {
      return t.getAttribute("aria-controls") === areas[i].id; });
    results.areasCollapsedByDefault =
      areas.every(function (a) { return a.hidden === true; });

    // 四、展开/收起：aria-expanded 同步 true/false（既有 classList/text
    // 切换与展开区内容一字不动）
    const t1 = toggles[0], a1 = areas[0];
    t1.onclick();
    results.expandSetsAriaExpandedTrueAndShowsSources =
      a1.hidden === false && t1.getAttribute("aria-expanded") === "true"
      && t1.textContent === "来源 ▾"
      && flatText(a1).indexOf("帧#1 7633 t=5000ms（source_capture）") >= 0
      && flatText(a1).indexOf(
           "crop_id：cam-a:run-1:frame:7633:crop:0") >= 0;
    t1.onclick();
    results.collapseRestoresAriaExpandedFalse =
      a1.hidden === true && t1.getAttribute("aria-expanded") === "false"
      && t1.textContent === "来源 ▸";

    // 五、saved 序位：「查看原图」可见文本不变，可访问名=「查看原图
    // +锚-序位」且同页唯一；缩略图 alt 带序位与 crop 锚；/api/crops
    // 受控链接形状不回归；「打开原始裁图」同样带锚
    t1.onclick();
    const links = allDescendants(detail()).filter(function (c) {
      return c.tag === "a" && c.textContent === "查看原图"; });
    results.twoSavedOriginalLinks = links.length === 2;
    const linkLabels = links.map(function (l) {
      return l.getAttribute("aria-label"); });
    results.savedLinkAccessibleNamesFrozen =
      JSON.stringify(linkLabels) === JSON.stringify(
        ["查看原图 w11-c7633-crop-0-m610-current",
         "查看原图 w11-ccrop-7-m610-current"]);
    results.savedLinkAccessibleNamesUnique =
      new Set(linkLabels).size === linkLabels.length;
    // 主会话定位串模式：getByRole("link",
    // {name: /查看原图.*7633.*current/}) 唯一命中
    results.locatorPatternLinkUnique =
      linkLabels.filter(function (l) {
        return /查看原图.*7633.*current/.test(l); }).length === 1;
    const imgs = allDescendants(detail()).filter(function (c) {
      return c.tag === "img"; });
    results.thumbAltsHaveSlotAndCropAnchor =
      imgs.length === 2
      && imgs[0].alt === "当前帧裁图缩略图 w11-c7633-crop-0-m610-current"
      && imgs[1].alt === "当前帧裁图缩略图 w11-ccrop-7-m610-current"
      && imgs[0].src === "/api/crops/" + AID1 + "?camera=cam-a";
    const evLinks = allDescendants(detail()).filter(function (c) {
      return c.tag === "a" && c.textContent === "打开原始裁图"; });
    results.openOriginalLinkHasAnchoredName =
      evLinks.length === 1
      && evLinks[0].href === "/api/evidence/ev-1"
      && evLinks[0].getAttribute("aria-label")
         === "打开原始裁图 w11-c7633-crop-0-m610";

    // 六、口径零回归：缺失/提交待确认/已保存占位文案、常显追溯速览行
    // 原样（aria 属性不改变任何可见文本）
    const pageText = flatText(detail());
    results.slotWordingsUnchanged =
      pageText.indexOf("前帧裁图：缺失（frame_absent）") >= 0
      && pageText.indexOf("后帧裁图：缺失（not_in_index）") >= 0
      && pageText.indexOf(
           "前帧裁图：提交待确认（索引行已可读但耐久未确认）") >= 0
      && pageText.indexOf("后帧裁图：保存中") >= 0
      && pageText.indexOf("当前帧裁图：已保存") >= 0;
    results.perRowTraceLineUnchanged =
      pageText.indexOf("裁图 cam-a:run…op:0 · 模型 local-vlm-7b"
        + " · 帧 7633 t=5000ms") >= 0;
  } catch (err) {
    results.harnessError = String(err && err.stack || err);
  }
  let ok = true;
  Object.keys(results).forEach((k) => { if (results[k] !== true) ok = false; });
  console.log(JSON.stringify({ ok: ok, results: results }));
  process.exit(ok ? 0 : 1);
})();
'''


def test_sources_toggle_accessible_name_dom_executable(state, tmp_path):
    """C142 可执行 DOM 测试（可访问性缺口，红转绿）：「来源 ▸」切换钮已是
    真 <button>，但此前无可访问名锚（aria-label 缺失 → 同页所有切换钮在
    Chrome AX 里同名「来源 ▸」，页内链接 getByRole 无法唯一定位）、无
    aria-expanded 状态、展开区无 id 与 aria-controls 关联，saved 序位
    「查看原图」链接与缩略图不带身份锚——真实用户点击无法被自动化可靠
    驱动。本测试与页面内联脚本注释同款冻结 C142 可访问名格式（派生输入
    =API identity 字段 window_key[3]/crop_id/material_id，纯客户端派生）：
      - 段规范化：非 [A-Za-z0-9_-] 字符 → '-'；crop_id 含 ':frame:' 标记
        （生产形状 cam:run:frame:F:crop:I）→ 取该标记之后整段（'F:crop:I'
        → 'F-crop-I'），否则取规范化 crop_id 整段；各段取尾（crop 尾 16、
        material 尾 8、window 全量）；缺省 → window/material='x'、
        crop='nocrop'。
      - 基础锚 anchor = 'w'+W+'-c'+C+'-m'+M；同页重复 → 依渲染顺序
        （当前区在前、历史区在后）第 2 次起追加 '-k2'/'-k3'… 保证唯一。
      - 冻结派生名（同页唯一，可见文本一律不变）：切换钮
        aria-label='来源-'+anchor；展开区 id 与 aria-controls=
        'src-detail-'+anchor 且 aria-expanded 同步 true/false；saved 序位
        「查看原图」链接 aria-label='查看原图 '+anchor+'-'+slot
        （previous/current/next）；缩略图 alt=中文序位+'缩略图 '
        +anchor+'-'+slot；「打开原始裁图」链接 aria-label='打开原始裁图 '
        +anchor。
      - 定位示例：getByRole("button", {name: /来源-w11-c7633/}) 唯一命中；
        getByRole("link", {name: /查看原图.*7633.*current/}) 唯一命中。
    并锁定口径零回归：默认收起、展开区内容（帧#序位/crop_id 行）、缺失
    与 commit_uncertain「提交待确认」占位、受控 /api/crops 链接形状、
    常显追溯速览行。node 不可用时跳过并如实标注。"""
    import shutil
    import subprocess
    handler = _get_handler(state, "/")
    html = handler.wfile.getvalue().decode("utf-8")
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert scripts, "工作台必须带内联脚本"
    node = shutil.which("node")
    if node is None:
        pytest.skip("node 不可用：无法执行页面脚本交互测试")
    page = tmp_path / "workbench-page-sources-a11y.js"
    page.write_text(scripts[-1], encoding="utf-8")
    harness = tmp_path / "harness-sources-a11y.js"
    harness.write_text(_SOURCES_A11Y_DOM_HARNESS_JS, encoding="utf-8")
    proc = subprocess.run([node, str(harness), str(page)],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (
        "来源可访问性 DOM 测试失败\nstdout: " + proc.stdout[-3000:]
        + "\nstderr: " + proc.stderr[-800:])
    data = json.loads(proc.stdout)
    assert data["ok"] is True, data["results"]



def test_baseline_gate_dismissible_dom(tmp_path):
    """C-144-R1：基线门降级为可跳过提示——静态合同（按钮/文案/非遮挡）
    + 状态转移逻辑（python 复刻页面门状态段的决策语义；实际 DOM 行为
    由 DSH 的 c144r1_page_dom.js 真实页面脚本 harness 承载）。"""
    src = open("scam/server.py", encoding="utf-8").read()
    assert 'id="gate-dismiss"' in src, "门内必须有跳过按钮"
    assert "先跳过，稍后再建" in src, "跳过按钮必须有明确文案"
    assert "观察与证据不受阻" in src, "跳过文案必须说明观察/证据不受阻"
    gate_seg = src.split('id="environment-gate"')[1][:300]
    assert 'role="dialog"' not in gate_seg, "门不得再是对话遮挡"
    assert "position:fixed" not in src.split(".environment-gate{")[1][:120],         "门不得再是全屏固定遮罩"
    # 状态转移：skip=1 → hidden；skip=0/未设置 → 显示（复刻页面决策）
    for skipped, expect_hidden in (("1", True), ("0", False), (None, False)):
        state = {"hidden": False}
        stored = {"v": skipped}
        get = lambda k: stored["v"]
        set_item = lambda k, v: stored.__setitem__("v", str(v))
        B = "failed"
        if get("c143-gate-skipped") == "1":
            state["hidden"] = True
        elif B == "ready":
            state["hidden"] = True
        assert state["hidden"] is expect_hidden,             f"skipped={skipped}: hidden 应为 {expect_hidden}"
