"""monitor 快系统端到端测试：门控→检测节奏→网格判定→告警 ≤1s（P1 验收）。"""

import json

import numpy as np
import pytest

from scam.monitor import Monitor, to_gray
from scam.db import connect
from scam.sinks import JsonlSink, SqliteSink
from scam.zones import Grid

W, H = 640, 360


def frame(t_ms, present):
    """合成帧：深灰底；present=True 时白色块出现在管理格中心（带 40ms 抖动模拟运动）。"""
    f = np.zeros((H, W, 3), np.uint8)
    f[:] = (30, 30, 30)
    if present:
        x0 = int(0.45 * W) + (t_ms // 40 % 2) * 8
        y0 = int(0.45 * H)
        cv2.rectangle(f, (x0, y0), (x0 + 60, y0 + 80), (255, 255, 255), -1)
    return f


import cv2  # noqa: E402


def bright(frame):
    """块中心像素亮度（白块=255，深灰底=30）。"""
    return float(frame[200, 330].mean())


def detect_person_when_present(frame):
    if bright(frame) > 100:
        return [{"cls": "person", "conf": 0.9,
                 "bbox": [0.45, 0.45, 0.10, 0.22],
                 "cx": 0.50, "cy": 0.56}]
    return []


def make_monitor(tmp_path, rules, sinks):
    cfg = {"id": "front-door",
           "grid": {"rows": 18, "cols": 22},
           "zones": [{"id": "z1", "name": "门口", "cells": [231, 232, 253, 254],
                      "rules": rules}]}
    return Monitor(cfg, detect_fn=detect_person_when_present, sinks=sinks)


def test_immediate_template_alarm_within_1s(tmp_path):
    """结构条件触发（immediate）：块出现 → ≤1s 告警，写 jsonl。"""
    jsonl = str(tmp_path / "events.jsonl")
    alarms = []
    sinks = [alarms.append, JsonlSink(jsonl)]
    cfg = {"id": "front-door",
           "grid": {"rows": 18, "cols": 22},
           "zones": [{"id": "z1", "name": "门口", "cells": [231, 232, 253, 254],
                      "rules": [{"cls": "person", "template": "immediate"}]}]}
    m = Monitor(cfg, detect_fn=detect_person_when_present, sinks=sinks)

    fired_at = None
    for t in range(0, 6000, 100):
        f = frame(t, present=t >= 2000)
        got = m.step(f, to_gray(f, m.GRAY_W), t)
        if got and fired_at is None:
            fired_at = t
    assert fired_at is not None and fired_at - 2000 <= 1000, \
        f"块出现后 1s 内必须告警（实际 {fired_at}ms）"
    assert len(alarms) >= 1
    a = alarms[0]
    assert a["short_name"].startswith("重点区域")
    assert a["detail"], "细节描述必须非空"
    lines = open(jsonl, encoding="utf-8").read().strip().splitlines()
    assert lines and "重点区域" in lines[0]


def test_no_alarm_when_motion_outside_zone():
    """格外运动：检测照跑但零告警（预算语义）。"""
    cfg = {"id": "front-door",
           "grid": {"rows": 18, "cols": 22},
           "zones": [{"id": "z1", "name": "门口", "cells": [0, 1, 22, 23],
                      "rules": [{"cls": "person", "template": "immediate"}]}]}
    alarms = []
    m = Monitor(cfg, detect_fn=lambda f: [], sinks=[alarms.append])
    for t in range(0, 8000, 100):
        f = frame(t, present=t >= 2000)
        m.step(f, to_gray(f, m.GRAY_W), t)
    assert alarms == [], "格内无目标不得告警"


# ---- 审查回归断言（2026-09-18）：告警风暴 / 多区域隔离 ----

def frame_at(cx, cy, t_ms):
    """合成帧：目标中心可操控（带 40ms 抖动保证门控持续判运动）。"""
    f = np.zeros((H, W, 3), np.uint8)
    f[:] = (30, 30, 30)
    x0 = int(cx * W) + (t_ms // 40 % 2) * 8
    y0 = int(cy * H)
    cv2.rectangle(f, (x0, y0), (x0 + 60, y0 + 80), (255, 255, 255), -1)
    return f


class FixedDet:
    """可控检测源：cx/cy 由测试逐步改写。"""

    def __init__(self):
        self.cx = self.cy = None

    def __call__(self, frame):
        if self.cx is None:
            return []
        return [{"cls": "person", "conf": 0.9,
                 "bbox": [self.cx - 0.05, self.cy - 0.11, 0.10, 0.22],
                 "cx": self.cx, "cy": self.cy}]


def test_dwell_5s_fires_exactly_one_alarm():
    """滞留 5 秒：全程只允许 1 条告警（回归：曾 5s 刷 46 条）。"""
    det = FixedDet()
    det.cx, det.cy = 0.50, 0.56          # 格 231（10 行 11 列）
    alarms = []
    cfg = {"id": "front-door",
           "grid": {"rows": 18, "cols": 22},
           "zones": [{"id": "z1", "cells": [231],
                      "rules": [{"cls": "person", "template": "enter-dwell",
                                 "dwell_s": 5}]}]}
    m = Monitor(cfg, detect_fn=det, sinks=[alarms.append])
    fired_at = None
    for t in range(0, 9000, 100):
        f = frame_at(det.cx, det.cy, t)
        got = m.step(f, to_gray(f, m.GRAY_W), t)
        if got and fired_at is None:
            fired_at = t
    assert len(alarms) == 1, f"滞留 5s 必须恰好 1 条告警（实际 {len(alarms)}）"
    assert fired_at is not None and 4800 <= fired_at <= 7000, \
        f"滞留达标即报（实际 {fired_at}ms）"


def test_multi_zone_isolation_and_dwell_reset():
    """双区域独立判定：A 区滞留不计入 B 区；zone 归属各自正确。"""
    det = FixedDet()
    alarms = []
    cfg = {"id": "front-door",
           "grid": {"rows": 18, "cols": 22},
           "zones": [
               {"id": "zA", "cells": [121],   # 格 (5,11) ← 归一化 (0.50, 0.28)
                "rules": [{"cls": "person", "template": "enter-dwell",
                           "dwell_s": 2}]},
               {"id": "zB", "cells": [319],   # 格 (14,11) ← 归一化 (0.50, 0.78)
                "rules": [{"cls": "person", "template": "enter-dwell",
                           "dwell_s": 2}]},
           ]}
    m = Monitor(cfg, detect_fn=det, sinks=[alarms.append])
    for t in range(0, 8000, 100):
        if t >= 4000:
            det.cx, det.cy = 0.50, 0.78        # 4s 时跨区移动到 B
        else:
            det.cx, det.cy = 0.50, 0.28        # 0-4s 驻留 A（2s 即达标）
        f = frame_at(det.cx, det.cy, t)
        m.step(f, to_gray(f, m.GRAY_W), t)

    zones = [a["zone"] for a in alarms]
    assert zones == ["zA", "zB"], f"两区各报一条且归属正确（实际 {zones}）"
    assert len({a["event_id"] for a in alarms}) == 2, "event_id 必须可区分"
    b_at = alarms[1]["t_source"] * 1000.0
    assert b_at >= 5500, (f"B 区滞留必须从进区重新计时"
                          f"（继承 A 区滞留会 4s 即报，实际 {b_at:.0f}ms）")


def test_zone_update_applies_at_frame_boundary_and_closes_old_event():
    class Sink(list):
        def __init__(self):
            super().__init__()
            self.closed = []

        def __call__(self, alarm):
            self.append(alarm)

        def close_semantic_events(self, event_ids, **fields):
            self.closed.append((list(event_ids), fields))

    det = FixedDet()
    det.cx, det.cy = 0.50, 0.56
    sink = Sink()
    cfg = {"id": "front-door", "grid": {"rows": 18, "cols": 22},
           "zones": [{"id": "old", "cells": [231],
                      "rules": [{"cls": "person",
                                 "template": "immediate"}]}]}
    monitor = Monitor(cfg, detect_fn=det, sinks=[sink], run_id="zones")
    monitor.MOTION_DET_INTERVAL = 1
    monitor.PATROL_INTERVAL = 1
    for now in range(0, 1000, 100):
        f = frame_at(det.cx, det.cy, now)
        monitor.step(f, to_gray(f, monitor.GRAY_W), now)
        if sink:
            break
    assert sink and monitor.zones[0]["id"] == "old"

    revision = monitor.request_zone_update([
        {"id": "new", "cells": [0],
         "rules": [{"cls": "person", "template": "immediate"}]}
    ])
    assert revision == 1
    assert monitor.zones[0]["id"] == "old", "HTTP线程不得中途改写当前帧配置"
    now += 100
    f = frame_at(det.cx, det.cy, now)
    monitor.step(f, to_gray(f, monitor.GRAY_W), now)
    assert monitor.zones[0]["id"] == "new"
    assert monitor.zone_revision == 1
    assert sink.closed[0][1]["reason"] == "zone-reconfigured"
    assert monitor.stats()["zone_update_pending"] is False


def test_monitor_sqlite_lifecycle_creates_and_closes_three_truth_layers(
        tmp_path, monkeypatch):
    """默认快路径真实接线：检测对象→审查段→管理员语义事件→闭合。"""
    import scam.track as track_module

    monkeypatch.setattr(track_module, "CONFIRMED_MAX_AGE", 50)
    db_path = str(tmp_path / "truth.db")
    sink = SqliteSink(db_path)
    detections_left = 2

    def detect_twice(_frame):
        nonlocal detections_left
        if detections_left <= 0:
            return []
        detections_left -= 1
        return [{"cls": "person", "conf": 0.9,
                 "bbox": [0.45, 0.45, 0.10, 0.22],
                 "cx": 0.50, "cy": 0.56}]

    cfg = {"id": "front-door", "grid": {"rows": 18, "cols": 22},
           "zones": [{"id": "z1", "cells": [231],
                      "rules": [{"cls": "person",
                                 "template": "immediate"}]}]}
    monitor = Monitor(
        cfg, detect_fn=detect_twice, sinks=[sink], run_id="test-run")
    monitor.MOTION_DET_INTERVAL = 1
    monitor.PATROL_INTERVAL = 1
    monitor.REVIEW_IDLE_CUTOFF = 0.05

    for now in (0, 100, 200, 300):
        f = frame(now, present=now < 200)
        monitor.step(f, to_gray(f, monitor.GRAY_W), now)

    conn = connect(db_path)
    obj = conn.execute("SELECT * FROM tracked_objects").fetchone()
    review = conn.execute("SELECT * FROM review_segments").fetchone()
    event = conn.execute("SELECT * FROM semantic_events").fetchone()
    assets = conn.execute(
        "SELECT owner_type,path,state FROM evidence_assets").fetchall()
    conn.close()

    assert obj["object_id"] == "front-door:test-run:track:1"
    assert obj["t_end"] is not None and obj["end_reason"] == "track-lost"
    assert review["severity"] == "alert"
    assert review["t_end"] is not None and review["end_reason"] == "idle-timeout"
    assert event["review_id"] == review["review_id"]
    assert event["object_id"] == obj["object_id"]
    assert event["state"] == "closed" and event["end_reason"] == "track-lost"
    assert event["evidence_state"] == "image_only"
    assert event["best_frame_path"] == obj["best_frame_path"]
    assert {row["owner_type"] for row in assets} == {
        "tracked_object", "semantic_event"}

# ---------- F9：审查段写入失败不得被当作成功（挂起 + 节流重试 + 补写） ----------

class BlockingSink:
    """可切换"开段被拒"的真值出口桩：记录每次生命周期调用。

    含事件事实钩子（合同 v1.1：事件事实不依赖审查段落库）——内存字典模拟
    真值存储，open 不受 blocked 影响。
    """

    def __init__(self, *, blocked=True):
        self.blocked = blocked
        self.calls = []
        self.semantic_events = []
        self.event_facts = {}
        self.opened = False

    def __call__(self, alarm):
        self.calls.append(("alarm", alarm["event_id"]))
        if not self.opened:
            return False          # 审查段没落库：语义事件写不进去
        self.semantic_events.append(alarm["event_id"])
        return True

    def open_event_fact(self, *, event_id, camera, object_id, t_start, cls,
                        conf=None, bbox_first=None, bbox_last=None,
                        review_id=None, evidence_state="metadata_only",
                        best_frame_path=None, payload=None):
        self.calls.append(("open_event_fact", event_id))
        self.event_facts.setdefault(event_id, {"review_id": review_id})
        return True

    def update_event_fact(self, event_id, *, t_last, conf=None, bbox_last=None,
                          payload=None):
        self.calls.append(("update_event_fact", event_id))
        return True

    def close_event_fact(self, event_id, *, reason):
        self.calls.append(("close_event_fact", event_id))
        self.event_facts.pop(event_id, None)
        return True

    def link_event_review(self, event_id, review_id):
        self.calls.append(("link_event_review", event_id))
        if event_id in self.event_facts:
            self.event_facts[event_id]["review_id"] = review_id
        return True

    def link_event_escalation(self, *, event_id, semantic_event_id, t_linked,
                              payload=None):
        self.calls.append(("link_event_escalation", event_id))
        return True

    def open_review(self, *, review_id, camera, t_start, object_ids,
                    payload=None):
        self.calls.append(("open_review", review_id))
        if self.blocked:
            raise RuntimeError("UNIQUE constraint failed: review_segments.camera")
        self.opened = True

    def observe_object(self, **kwargs):
        self.calls.append(("observe_object", kwargs.get("review_id")))

    def update_review(self, review_id, **kwargs):
        self.calls.append(("update_review", review_id))

    def close_review(self, review_id, **kwargs):
        self.calls.append(("close_review", review_id))

    def write_semantic_event(self, alarm):
        self.calls.append(("write_semantic_event", alarm["event_id"]))
        if not self.opened:
            return False
        if alarm["event_id"] not in self.semantic_events:
            self.semantic_events.append(alarm["event_id"])
        return True


def _drive(m, *, start_ms=1_000_000.0, span_ms=1_200.0, step_ms=40.0):
    alarms = []
    t = start_ms
    while t < start_ms + span_ms:
        f = frame(int(t), True)
        alarms += m.step(f, to_gray(f, Monitor.GRAY_W), t)
        t += step_ms
    return alarms


def test_f9_open_failure_never_counts_as_persisted(tmp_path):
    """旧段占位导致开段失败：内存段保留但标记未落库，告警挂起待补写。"""
    sink = BlockingSink(blocked=True)
    m = make_monitor(tmp_path, [{"cls": "person", "template": "immediate"}],
                     [sink])

    alarms = _drive(m)

    state = m.persistence_state()
    assert m._review is not None, "内存段身份要保留（不能凭空丢段）"
    assert state["review_unpersisted"] is True
    assert state["degraded"] is True
    assert state["review_open_failures"] >= 1
    assert state["deferred_alarms"] == len(alarms) >= 1
    assert sink.semantic_events == [], "真值没写进去就不能算写过"
    assert all(call[0] != "update_review" for call in sink.calls),         "未落库的段不得发更新（那是把失败伪装成成功）"


def test_f9_preexisting_free_segment_opens_immediately(tmp_path):
    """对照组：没有占位时首轮就落库，告警立即进真值，不产生挂起。"""
    sink = BlockingSink(blocked=False)
    m = make_monitor(tmp_path, [{"cls": "person", "template": "immediate"}],
                     [sink])

    alarms = _drive(m)

    assert alarms, "规则应触发告警"
    assert m.persistence_state() == {
        "review_open_failures": 0, "review_unpersisted": False,
        "deferred_alarms": 0, "event_open_failures": 0,
        "event_facts_unpersisted": 0, "sink_failures": 0, "degraded": False}
    assert sink.semantic_events == [a["event_id"] for a in alarms]


def test_f9_deferred_alarm_is_written_once_block_clears(tmp_path):
    """旧段收口后：节流重试建立自己的段，并把挂起告警补写为真值。"""
    sink = BlockingSink(blocked=True)
    m = make_monitor(tmp_path, [{"cls": "person", "template": "immediate"}],
                     [sink])
    first = _drive(m)
    mem_id = m._review["review_id"]
    assert m.persistence_state()["deferred_alarms"] == len(first)

    sink.blocked = False                      # 旧段被 F8 收口
    _drive(m, start_ms=1_002_000.0, span_ms=1_200.0)

    assert m._review["review_id"] == mem_id, "段身份必须稳定，不新起第二段"
    assert m._review["persisted"] is True
    assert m.persistence_state()["degraded"] is False
    assert sink.semantic_events == [a["event_id"] for a in first],         "挂起告警必须原样补写（同 event_id，不制造重复）"
    assert sink.calls.count(("write_semantic_event", first[0]["event_id"])) == 1


def test_f9_open_retry_is_rate_limited(tmp_path):
    """重试按 REVIEW_OPEN_RETRY_MS 节流：不忙轮询，成功后不再重试。"""
    sink = BlockingSink(blocked=True)
    m = make_monitor(tmp_path, [{"cls": "person", "template": "immediate"}],
                     [sink])
    _drive(m, span_ms=1_200.0)                # 30 帧 / 1.2s
    attempts_before = sum(1 for c in sink.calls if c[0] == "open_review")
    assert attempts_before <= 3, f"1.2s 内不得反复开段（实际 {attempts_before}）"

    sink.blocked = False
    _drive(m, start_ms=1_002_000.0, span_ms=400.0)
    attempts_after_success = sum(1 for c in sink.calls if c[0] == "open_review")
    _drive(m, start_ms=1_003_000.0, span_ms=400.0)
    assert sum(1 for c in sink.calls if c[0] == "open_review") ==         attempts_after_success, "落库成功后不得继续重试开段"


def test_f9_foreign_segment_is_never_touched(tmp_path):
    """另一进程的开放段：只重试自己的段，绝不更新/关闭别人的段。"""
    sink = BlockingSink(blocked=True)
    m = make_monitor(tmp_path, [{"cls": "person", "template": "immediate"}],
                     [sink])
    _drive(m, span_ms=2_000.0)

    foreign = "front-door:OTHERPROC:review:1"
    own = m._review["review_id"]
    assert own != foreign
    assert all(call[1] != foreign for call in sink.calls),         "不得对别人的审查段做任何写操作"
    assert all(call[1] != foreign for call in sink.calls
               if call[0] in ("update_review", "close_review"))

# ---------- 事件事实（合同 v1.1 阶段一）：无规则建事件、独立于审查段、诚实降级 ----------

def _flip_frame(present, flip):
    """交替位移的合成帧：保证门控每帧都有运动（时间戳抖动在宽步距下会同相位）。"""
    f = np.zeros((H, W, 3), np.uint8)
    f[:] = (30, 30, 30)
    if present:
        x0 = int(0.45 * W) + (8 if flip else 0)
        cv2.rectangle(f, (x0, int(0.45 * H)),
                      (x0 + 60, int(0.45 * H) + 80), (255, 255, 255), -1)
    return f


def _two_target_frame(flip):
    """两个分离白块：0.25W 与 0.70W 各一人，交替位移。"""
    f = np.zeros((H, W, 3), np.uint8)
    f[:] = (30, 30, 30)
    for cx, own_flip in ((int(0.25 * W), flip), (int(0.70 * W), not flip)):
        x0 = cx + (8 if own_flip else 0)
        cv2.rectangle(f, (x0, int(0.45 * H)),
                      (x0 + 60, int(0.45 * H) + 80), (255, 255, 255), -1)
    return f


def _detect_two(frame):
    dets = []
    for cx in (0.28, 0.73):
        x0 = int(cx * W)
        if frame[int(0.45 * H) + 40, x0 + 30].mean() > 100:
            dets.append({"cls": "person", "conf": 0.9,
                         "bbox": [cx - 0.05, 0.45, 0.10, 0.22],
                         "cx": cx, "cy": 0.56})
    return dets


def _drive_flip(m, *, start_ms, frames, present, step_ms=400.0, det=None):
    """按帧序号交替位移驱动：present 为布尔或 f(i)->bool。"""
    t = start_ms
    for i in range(frames):
        there = present(i) if callable(present) else present
        f = (_two_target_frame(i % 2) if det is not None
             else _flip_frame(there, i % 2))
        m.step(f, to_gray(f, Monitor.GRAY_W), t)
        t += step_ms
    return t


def _event_rows(db_path):
    conn = connect(db_path)
    rows = conn.execute(
        "SELECT event_id,camera,object_id,review_id,t_start,t_last,t_end,"
        "end_reason,state,cls,evidence_state,bbox_first,bbox_last,payload"
        " FROM event_facts ORDER BY t_start").fetchall()
    conn.close()
    return rows


def test_event_fact_lifecycle_without_rules(tmp_path):
    """无 zones/无规则：确认目标即建事件，目标消失按最后观察时间收口。"""
    db_path = str(tmp_path / "events.db")
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []},
                detect_fn=detect_person_when_present,
                sinks=[SqliteSink(db_path)])

    _drive_flip(m, start_ms=1_000_000.0, frames=10, present=True)

    rows = _event_rows(db_path)
    assert len(rows) == 1, "无规则也必须建立用户可见事件"
    ev = rows[0]
    assert ev["state"] == "open" and ev["cls"] == "person"
    assert ev["camera"] == "front-door"
    assert ev["object_id"].startswith("front-door:")
    assert ev["review_id"] is not None, "审查段落库后应迟后关联"
    assert ev["review_id"] == m._review["review_id"]
    # 最佳帧资产行存在且 available：证据状态必须如实升级，不得假称无证据
    assert ev["evidence_state"] == "image_only"
    assert m.persistence_state()["degraded"] is False

    # 目标消失：Tracker 老化后 track-lost 收口，t_end == 记录自身 t_last
    #（32 帧 × 500ms 覆盖到老化判定所在的巡检检测轮）
    _drive_flip(m, start_ms=1_004_000.0, frames=32, present=False,
                step_ms=500.0)

    rows = _event_rows(db_path)
    ev = rows[0]
    assert ev["state"] == "closed" and ev["end_reason"] == "track-lost"
    assert ev["t_end"] == ev["t_last"], "结束时间必须是最后一次可信观察"
    assert m.persistence_state()["degraded"] is False


def test_two_confirmed_targets_yield_two_events_one_review(tmp_path):
    """多目标并存：每个已确认目标一件事件，共用审查段，不合并。"""
    db_path = str(tmp_path / "events.db")
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []},
                detect_fn=_detect_two, sinks=[SqliteSink(db_path)])

    _drive_flip(m, start_ms=1_000_000.0, frames=12, present=True,
                det=_detect_two)

    rows = _event_rows(db_path)
    assert len(rows) == 2
    assert {row["state"] for row in rows} == {"open"}
    assert len({row["object_id"] for row in rows}) == 2
    assert len({row["review_id"] for row in rows}) == 1


def test_event_fact_opens_even_when_review_open_fails(tmp_path):
    """合同边界1：事件不依赖审查段落库——开段被拒时事件照常落库、迟后回填。"""
    db_path = str(tmp_path / "events.db")
    sink = SqliteSink(db_path)
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []},
                detect_fn=detect_person_when_present, sinks=[sink])

    original_open_review = sink.open_review
    sink.open_review = lambda **kwargs: False   # 模拟旧段占位：开段被拒
    _drive_flip(m, start_ms=1_000_000.0, frames=10, present=True)

    rows = _event_rows(db_path)
    assert len(rows) == 1 and rows[0]["state"] == "open"
    assert rows[0]["review_id"] is None, "审查段未落库，事件不得携带假关联"
    state = m.persistence_state()
    assert state["review_unpersisted"] is True
    assert state["degraded"] is True

    sink.open_review = original_open_review    # 旧段被收口，可开段
    _drive_flip(m, start_ms=1_004_000.0, frames=6, present=True)

    rows = _event_rows(db_path)
    assert rows[0]["review_id"] == m._review["review_id"], "落库后必须迟后回填"
    assert m.persistence_state()["degraded"] is False


def test_event_open_failure_retries_and_reports_degraded(tmp_path):
    """合同边界1：写库失败进重试状态机，未落库期间健康面可见，绝不冒充已保存。"""
    db_path = str(tmp_path / "events.db")
    sink = SqliteSink(db_path)
    original = sink.open_event_fact
    attempts = {"left": 1}

    def flaky_open(**kwargs):
        if attempts["left"] > 0:
            attempts["left"] -= 1
            raise RuntimeError("injected open_event_fact failure")
        return original(**kwargs)

    sink.open_event_fact = flaky_open
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []},
                detect_fn=detect_person_when_present, sinks=[sink])

    # 阶段一：首帧尝试失败；2 帧（800ms）内不越过 1s 重试间隔，状态确定
    _drive_flip(m, start_ms=1_000_000.0, frames=2, present=True)

    assert m.event_open_failures == 1
    assert _event_rows(db_path) == [], "写入失败期间不得存在事件行"
    state = m.persistence_state()
    assert state["event_open_failures"] == 1
    assert state["event_facts_unpersisted"] >= 1
    assert state["degraded"] is True

    # 阶段二：越过重试间隔后必须真实落库
    _drive_flip(m, start_ms=1_002_000.0, frames=10, present=True)

    rows = _event_rows(db_path)
    assert len(rows) == 1 and rows[0]["state"] == "open"
    assert m.persistence_state()["degraded"] is False


def test_rule_escalation_links_event_fact_explicitly(tmp_path):
    """合同边界4：规则命中时写显式幂等关联，不改写 semantic_events 语义。"""
    db_path = str(tmp_path / "events.db")
    m = make_monitor(tmp_path, [{"cls": "person", "template": "immediate"}],
                     [SqliteSink(db_path)])

    alarms = _drive(m)

    assert alarms, "规则应命中"
    conn = connect(db_path)
    sem = {row["semantic_event_id"]
           for row in conn.execute(
               "SELECT semantic_event_id FROM semantic_events")}
    links = conn.execute(
        "SELECT event_id,semantic_event_id FROM event_escalations").fetchall()
    facts = conn.execute("SELECT event_id FROM event_facts").fetchall()
    conn.close()

    assert len(facts) == 1, "规则命中的同一目标也必须有事件事实"
    assert len(links) == len(alarms)
    assert {row["semantic_event_id"] for row in links} == sem
    fact_event_id = facts[0]["event_id"]
    assert all(row["event_id"] == fact_event_id for row in links)


def test_stream_lost_grace_keeps_then_closes_open_events(tmp_path):
    """合同边界3：宽限内保留开放事件；超宽限收口，恢复后新目标=新事件。"""
    db_path = str(tmp_path / "events.db")
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []},
                detect_fn=detect_person_when_present,
                sinks=[SqliteSink(db_path)])

    t = _drive_flip(m, start_ms=1_000_000.0, frames=10, present=True)
    grace_ms = Monitor.STREAM_LOST_GRACE_S * 1000.0

    m.on_stream_lost(t)
    m.on_stream_lost(t + grace_ms / 2)
    assert _event_rows(db_path)[0]["state"] == "open", "宽限内不得收口"
    assert m.stats()["stream_lost"] is True

    m.on_stream_lost(t + grace_ms + 1.0)
    rows = _event_rows(db_path)
    assert rows[0]["state"] == "closed"
    assert rows[0]["end_reason"] == "stream-lost"
    assert rows[0]["t_end"] == rows[0]["t_last"], "断流收口也按最后观察时间"
    assert m.stats()["stream_lost"] is True

    m.on_stream_recovered()
    assert m.stats()["stream_lost"] is False
    _drive_flip(m, start_ms=t + grace_ms + 1000.0, frames=10, present=True)
    rows = _event_rows(db_path)
    assert len(rows) == 2, "恢复后新目标必须是新事件"
    assert rows[1]["state"] == "open"


def test_camera_stopped_closes_all_open_event_facts(tmp_path):
    """线程退出兜底：优雅停止把开放事件按各自最后观察时间收口。"""
    db_path = str(tmp_path / "events.db")
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []},
                detect_fn=detect_person_when_present,
                sinks=[SqliteSink(db_path)])

    _drive_flip(m, start_ms=1_000_000.0, frames=10, present=True)
    m.close_all_event_facts()

    rows = _event_rows(db_path)
    assert rows and all(row["state"] == "closed" for row in rows)
    assert all(row["end_reason"] == "camera-stopped" for row in rows)
    assert all(row["t_end"] == row["t_last"] for row in rows)
    m.close_all_event_facts()   # 幂等：二次调用零改动
    assert len(_event_rows(db_path)) == len(rows)


def test_event_close_failure_is_retried_until_persisted(tmp_path):
    """闭合失败进待重试队列：降级可见，重试成功后降级清除。"""
    db_path = str(tmp_path / "events.db")
    sink = SqliteSink(db_path)
    original = sink.close_event_fact
    attempts = {"left": 1}

    def flaky_close(event_id, *, reason):
        if attempts["left"] > 0:
            attempts["left"] -= 1
            raise RuntimeError("injected close_event_fact failure")
        return original(event_id, reason=reason)

    sink.close_event_fact = flaky_close
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []},
                detect_fn=detect_person_when_present, sinks=[sink])
    m.EVENT_OPEN_RETRY_MS = 1e9    # 冻结重试：闭合失败后窗口内不得自愈

    _drive_flip(m, start_ms=1_000_000.0, frames=10, present=True)
    _drive_flip(m, start_ms=1_004_000.0, frames=32, present=False,
                step_ms=500.0)

    state = m.persistence_state()
    assert state["event_facts_unpersisted"] >= 1
    assert state["degraded"] is True

    # 解除冻结：释放待重试队列，下一次重试必须真实闭合
    m._event_close_pending[0]["next_retry_ms"] = 0.0
    _drive_flip(m, start_ms=1_022_000.0, frames=3, present=False,
                step_ms=500.0)

    rows = _event_rows(db_path)
    assert rows[0]["state"] == "closed" and rows[0]["end_reason"] == "track-lost"
    assert m.persistence_state()["degraded"] is False


def test_event_fact_records_timestamp_kind_and_ignores_time_regression(tmp_path):
    """合同边界3：不可信源时间如实入档；时间倒退不得回退事件观察时间。"""
    db_path = str(tmp_path / "events.db")
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []},
                detect_fn=detect_person_when_present,
                sinks=[SqliteSink(db_path)])
    m.timestamp_kind = "host_receive"   # 非源采集时间：处理时间口径

    _drive_flip(m, start_ms=1_000_000.0, frames=8, present=True)
    rows = _event_rows(db_path)
    assert len(rows) == 1
    payload = json.loads(rows[0]["payload"])
    assert payload["timestamp_kind"] == "host_receive"
    t_last_before = rows[0]["t_last"]

    # 源时间倒退（重放/时钟跳变）：t_last 必须保持在最大可信观察
    _drive_flip(m, start_ms=999_000.0, frames=3, present=True)

    rows = _event_rows(db_path)
    assert rows[0]["t_last"] >= t_last_before, "时间倒退不得回退观察时间"
    assert rows[0]["state"] == "open"


def test_escalation_link_is_deferred_until_event_fact_persists(tmp_path):
    """合同边界4：事实未落库时升级关联挂起，事实落库后补挂，不丢不重。"""
    db_path = str(tmp_path / "events.db")
    sink = SqliteSink(db_path)
    original = sink.open_event_fact
    attempts = {"left": 1}

    def flaky_open(**kwargs):
        if attempts["left"] > 0:
            attempts["left"] -= 1
            raise RuntimeError("injected open_event_fact failure")
        return original(**kwargs)

    sink.open_event_fact = flaky_open
    m = make_monitor(tmp_path, [{"cls": "person", "template": "immediate"}],
                     [sink])

    alarms = _drive(m)   # 首轮：事件 open 失败，规则告警已产生

    assert alarms
    conn = connect(db_path)
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_facts").fetchone()["c"] == 0
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_escalations").fetchone()["c"] == 0, \
        "事实未落库时不得留下悬空关联"
    conn.close()
    fact = m._event_facts[alarms[0]["track_id"]]
    assert fact["state"] == "pending-open"
    assert fact["escalations"] == [alarms[0]["event_id"]], "挂起等补挂"

    _drive(m, start_ms=1_002_000.0, span_ms=1_200.0)   # 事实落库后补挂

    conn = connect(db_path)
    links = conn.execute(
        "SELECT event_id,semantic_event_id FROM event_escalations").fetchall()
    conn.close()
    assert len(links) == len(alarms)
    assert all(link["semantic_event_id"] == alarm["event_id"]
               for link, alarm in zip(links, alarms))
    assert m.persistence_state()["degraded"] is False


def test_short_event_survives_open_failure_and_closes_exactly_once(tmp_path):
    """边界1：事件未入库即消亡——携带完整事实快照补建收口，恰好一条闭合事实。

    故障注入：open 首次失败后冻结重试，目标随即消亡。恢复写入后按
    open→补最后观察→close 落库；结束时间=快照里的最后观察，不是补建时的
    处理时间；同 event_id 幂等，不制造第二个事件。
    """
    db_path = str(tmp_path / "events.db")
    sink = SqliteSink(db_path)
    original = sink.open_event_fact
    attempts = {"left": 1}

    def flaky_open(**kwargs):
        if attempts["left"] > 0:
            attempts["left"] -= 1
            raise RuntimeError("injected open_event_fact failure")
        return original(**kwargs)

    sink.open_event_fact = flaky_open
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []},
                detect_fn=detect_person_when_present, sinks=[sink])
    m.EVENT_OPEN_RETRY_MS = 1e9   # 冻结重试：短目标在 open 成功前就结束

    _drive_flip(m, start_ms=1_000_000.0, frames=2, present=True)
    _drive_flip(m, start_ms=1_004_000.0, frames=32, present=False,
                step_ms=500.0)

    assert _event_rows(db_path) == [], "落库前不得存在事件行（也不得丢失）"
    state = m.persistence_state()
    assert state["degraded"] is True
    assert len(m._event_close_pending) == 1
    snapshot_item = m._event_close_pending[0]
    assert snapshot_item["fact"] is not None, "必须携带完整事实快照"
    expected_last = snapshot_item["fact"]["last"]["t_last"]
    # 快照保存的是最后一次真实处理观察（≤对象层 close 顶上去的处理时间戳）；
    # 事件收口不得使用更晚的处理时间冒充观察时间（边界1/3 口径）。

    # 恢复写入：待写事件按 open→补观察→close 补建收口
    m._event_close_pending[0]["next_retry_ms"] = 0.0
    _drive_flip(m, start_ms=1_022_000.0, frames=3, present=False,
                step_ms=500.0)

    rows = _event_rows(db_path)
    assert len(rows) == 1, f"必须恰好落一条事件（实际 {len(rows)}）"
    ev = rows[0]
    assert ev["state"] == "closed" and ev["end_reason"] == "track-lost"
    assert ev["t_end"] == pytest.approx(expected_last, abs=1e-6), \
        "结束时间必须是快照里的最后观察，不是补建时的处理时间"
    assert ev["object_id"].startswith("front-door:")
    assert m.persistence_state()["degraded"] is False


def test_object_write_failure_defers_event_until_object_persists(tmp_path):
    """边界2：对象先落库——对象写入失败时事件保持待写、不产生孤儿事件。"""
    db_path = str(tmp_path / "events.db")
    sink = SqliteSink(db_path)
    original = sink.observe_object
    attempts = {"left": 3}

    def flaky_observe(**kwargs):
        if attempts["left"] > 0:
            attempts["left"] -= 1
            raise RuntimeError("injected observe_object failure")
        return original(**kwargs)

    sink.observe_object = flaky_observe
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []},
                detect_fn=detect_person_when_present, sinks=[sink])

    _drive_flip(m, start_ms=1_000_000.0, frames=4, present=True)

    conn = connect(db_path)
    objects = conn.execute("SELECT COUNT(*) c FROM tracked_objects"
                           ).fetchone()["c"]
    events = conn.execute("SELECT COUNT(*) c FROM event_facts"
                          ).fetchone()["c"]
    conn.close()
    assert objects == 0 and events == 0, "对象失败期间不得有孤儿事件"
    entry = next(iter(m._event_facts.values()))
    assert entry["state"] == "pending-object", "事件必须保持待写"
    assert m.persistence_state()["degraded"] is True

    sink.observe_object = original    # 对象写入恢复
    _drive_flip(m, start_ms=1_004_000.0, frames=6, present=True)

    conn = connect(db_path)
    objects = conn.execute("SELECT COUNT(*) c FROM tracked_objects"
                           ).fetchone()["c"]
    events = conn.execute("SELECT event_id,object_id FROM event_facts"
                          ).fetchall()
    orphans = conn.execute(
        "SELECT COUNT(*) c FROM event_facts WHERE object_id NOT IN"
        " (SELECT object_id FROM tracked_objects)").fetchone()["c"]
    conn.close()
    assert objects >= 1 and len(events) == 1, "对象恢复后事件补建"
    assert orphans == 0
    assert m.persistence_state()["degraded"] is False


def test_exit_reports_unsaved_events_instead_of_claiming_saved(tmp_path):
    """边界1：退出前仍写不进去——如实返回未保存条数，健康面降级可见。"""
    db_path = str(tmp_path / "events.db")
    sink = SqliteSink(db_path)

    def always_fail(**kwargs):
        raise RuntimeError("injected permanent open_event_fact failure")

    sink.open_event_fact = always_fail
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []},
                detect_fn=detect_person_when_present, sinks=[sink])

    _drive_flip(m, start_ms=1_000_000.0, frames=4, present=True)
    assert m.persistence_state()["degraded"] is True

    pending = m.close_all_event_facts()
    assert pending == 1, "退出收口必须如实报告未保存条数"
    assert _event_rows(db_path) == [], "写不进去就是没保存"
    assert m.persistence_state()["degraded"] is True

    # 对照组：写入正常时退出收口返回 0
    m2 = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                  "zones": []},
                 detect_fn=detect_person_when_present,
                 sinks=[SqliteSink(str(tmp_path / "control.db"))])
    _drive_flip(m2, start_ms=1_000_000.0, frames=4, present=True)
    assert m2.close_all_event_facts() == 0


# ---------- 复验边界：对象写入失败期间目标结束 → 补建链必须同时恢复对象与事件 ----------

@pytest.mark.parametrize("end_mode,reason", [
    ("track-lost", "track-lost"),
    ("stream-lost", "stream-lost"),
    ("camera-exit", "camera-stopped"),
])
def test_object_failure_then_target_end_recovers_both_layers(
        tmp_path, end_mode, reason):
    """复现条件：observe_object 持续失败；目标在恢复前结束；随后恢复写入。

    断言：对象与事件最终各恰好一条、均已闭合、无孤儿、t_end=快照最后可信
    观察（非重试处理时间）、重复重试不增行。
    """
    db_path = str(tmp_path / f"repro-{end_mode}.db")
    sink = SqliteSink(db_path)
    real_observe = sink.observe_object
    state = {"fail": True}

    def flaky_observe(**kwargs):
        if state["fail"]:
            raise RuntimeError("injected observe failure")
        return real_observe(**kwargs)

    sink.observe_object = flaky_observe
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []},
                detect_fn=detect_person_when_present, sinks=[sink])
    m.EVENT_OPEN_RETRY_MS = 1e9   # 冻结：结束必须发生在任何成功写入之前

    t = _drive_flip(m, start_ms=1_000_000.0, frames=4, present=True)

    def assert_before_recovery():
        conn = connect(db_path)
        objects = conn.execute(
            "SELECT COUNT(*) c FROM tracked_objects").fetchone()["c"]
        events = conn.execute(
            "SELECT COUNT(*) c FROM event_facts").fetchone()["c"]
        conn.close()
        assert objects == 0 and events == 0, "恢复写入前两表必须仍为空"
        assert m.persistence_state()["degraded"] is True

    if end_mode == "track-lost":
        _drive_flip(m, start_ms=1_004_000.0, frames=32, present=False,
                    step_ms=500.0)
        assert_before_recovery()
    elif end_mode == "stream-lost":
        grace_ms = Monitor.STREAM_LOST_GRACE_S * 1000.0
        m.on_stream_lost(t)
        m.on_stream_lost(t + grace_ms + 1.0)   # 超宽限收口
        assert_before_recovery()
    else:
        assert m.close_all_event_facts() == 1, "退出时必须如实报未保存条数"
        assert_before_recovery()

    snapshot_item = m._event_close_pending[0]
    fact = snapshot_item["fact"]
    assert fact is not None and fact["last"].get("t_last") is not None
    expected_last = fact["last"]["t_last"]
    assert snapshot_item["reason"] == reason

    # 恢复写入：待写链从安全位置补建
    state["fail"] = False
    if end_mode == "track-lost":
        snapshot_item["next_retry_ms"] = 0.0
        _drive_flip(m, start_ms=1_022_000.0, frames=3, present=False,
                    step_ms=500.0)
    elif end_mode == "stream-lost":
        snapshot_item["next_retry_ms"] = 0.0
        m.on_stream_lost(t + grace_ms + 2000.0)   # 断流期间的有界重试通道
    else:
        assert m.close_all_event_facts() == 0, "补齐后未保存计数归零"

    conn = connect(db_path)
    objects = conn.execute(
        "SELECT object_id,t_end,end_reason FROM tracked_objects").fetchall()
    events = conn.execute(
        "SELECT event_id,state,t_end,t_last,end_reason,object_id"
        " FROM event_facts").fetchall()
    orphans = conn.execute(
        "SELECT COUNT(*) c FROM event_facts WHERE object_id NOT IN"
        " (SELECT object_id FROM tracked_objects)").fetchone()["c"]
    conn.close()

    assert len(objects) == 1 and len(events) == 1, "对象与事件各恰好一条"
    obj, ev = objects[0], events[0]
    assert obj["t_end"] is not None, "不得留下开放对象"
    assert obj["end_reason"] == reason and ev["end_reason"] == reason
    assert ev["state"] == "closed"
    assert ev["t_end"] == ev["t_last"] == pytest.approx(expected_last, abs=1e-6), \
        "结束时间必须是最后可信观察，不是恢复写入的处理时间"
    assert orphans == 0
    assert m.persistence_state()["degraded"] is False

    # 重复重试不增行
    m._retry_pending_event_closes(9_999_999_999.0)
    m._retry_pending_event_closes(9_999_999_999.0 + 1)
    conn = connect(db_path)
    assert conn.execute(
        "SELECT COUNT(*) c FROM tracked_objects").fetchone()["c"] == 1
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_facts").fetchone()["c"] == 1
    conn.close()


def test_persistent_object_failure_reports_unsaved_and_stays_degraded(
        tmp_path):
    """持续失败：不得出现"测试通过但事实丢失"——明确报未保存、降级保持。"""
    db_path = str(tmp_path / "repro-persist.db")
    sink = SqliteSink(db_path)

    def always_fail(**kwargs):
        raise RuntimeError("injected permanent observe failure")

    sink.observe_object = always_fail
    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []},
                detect_fn=detect_person_when_present, sinks=[sink])

    t = _drive_flip(m, start_ms=1_000_000.0, frames=4, present=True)
    grace_ms = Monitor.STREAM_LOST_GRACE_S * 1000.0

    # 源持续断开：断流收口 + 有界重试通道反复触发，仍写不进去
    m.on_stream_lost(t)
    m.on_stream_lost(t + grace_ms + 1.0)
    m.on_stream_lost(t + grace_ms + 60_000.0)

    conn = connect(db_path)
    assert conn.execute(
        "SELECT COUNT(*) c FROM tracked_objects").fetchone()["c"] == 0
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_facts").fetchone()["c"] == 0
    conn.close()
    assert m.close_all_event_facts() == 1, "退出必须明确报未保存条数"
    state = m.persistence_state()
    assert state["event_facts_unpersisted"] >= 1
    assert state["degraded"] is True, "补齐之前健康面必须保持降级"


# ---------- L1 异步检测结果消费（合同 C132 F4/F5/F6）：detection_mode="async" ----------
#
# async 契约：快系统永不等待模型——detect_fn 绝不被调用，检测结果只经
# apply_detection_result 进入；事实工作只发生在 ok/empty 消费点且按结果帧
# t_capture 推进，非消费帧零事实工作（D1）；消费前五重复核（D2）；冻结
# pause/restore 不补算间隙滞留（D3）；巡检/确认/失联契约统一（D4）。

PERSON_DET = {"cls": "person", "conf": 0.9,
              "bbox": [0.45, 0.45, 0.10, 0.22], "cx": 0.50, "cy": 0.56}


class FakeL1Result:
    """duck-typed L1Result（合同 §1 字段；故意不 import win11_pipeline 避免耦合）。"""

    def __init__(self, t_capture_ms, detections=(), status="ok",
                 error_code=None, camera_id="front-door", run_id="async-run",
                 config_version=0, frame_bgr=None, frame_id=0):
        self.camera_id = camera_id
        self.run_id = run_id
        self.frame_id = frame_id
        self.t_capture_ms = t_capture_ms
        self.reason = "latest"
        self.config_version = config_version
        self.frame_bgr = (np.zeros((H, W, 3), np.uint8)
                          if frame_bgr is None else frame_bgr)
        self.detections = list(detections)
        self.status = status
        self.error_code = error_code
        self.classes = ["person"]


class AsyncTruthSink:
    """async 用真值出口桩：记录告警、observe_object 证据帧与对象/事件收口。"""

    def __init__(self):
        self.alarms = []
        self.observe_frames = []
        self.event_updates = []
        self.closed_objects = []
        self.closed_events = []

    def __call__(self, alarm):
        self.alarms.append(alarm)
        return True

    def open_event_fact(self, **kwargs):
        return True

    def update_event_fact(self, event_id, *, t_last, conf=None,
                          bbox_last=None, payload=None):
        self.event_updates.append((event_id, t_last))
        return True

    def close_event_fact(self, event_id, *, reason):
        self.closed_events.append((event_id, reason))
        return True

    def observe_object(self, **kwargs):
        self.observe_frames.append(kwargs.get("frame_bgr"))
        return True

    def close_object(self, object_id, *, t_end, reason):
        self.closed_objects.append((object_id, t_end, reason))
        return True


def make_async_monitor(sinks, run_id="async-run", **kwargs):
    cfg = {"id": "front-door",
           "grid": {"rows": 18, "cols": 22},
           "zones": [{"id": "z1", "name": "门口",
                      "cells": [231, 232, 253, 254],
                      "rules": [{"cls": "person",
                                 "template": "immediate"}]}]}
    return Monitor(cfg, detect_fn=None, sinks=sinks, run_id=run_id,
                   detection_mode="async", **kwargs)


def _drive_async_frame(m, present, i, t):
    f = _flip_frame(present, i % 2)
    return m.step(f, to_gray(f, m.GRAY_W), t)


def test_async_detect_fn_is_never_called():
    """async：同步检测路径彻底关闭——detect_fn 一被调用就炸，step 必须无恙。"""
    calls = []

    def detect_fn(frame_bgr):
        calls.append(frame_bgr)
        raise RuntimeError("sync detector must not run in async mode")

    m = Monitor({"id": "front-door", "grid": {"rows": 18, "cols": 22},
                 "zones": []},
                detect_fn=detect_fn, sinks=[], run_id="async-run",
                detection_mode="async")
    materials = []
    m.set_material_sink(materials.append)
    m.MATERIAL_LATEST_MS = 100.0
    m.MATERIAL_PATROL_MS = 100.0
    for i in range(20):
        _drive_async_frame(m, present=i >= 5, i=i, t=i * 100.0)
    assert calls == [] and m.det_calls == 0, "async 模式不得同步调用检测器"
    assert materials, "材料出口仍须按节奏提交"
    assert m.stats()["detection_mode"] == "async"


def test_async_material_edge_and_cadence():
    """材料三理由：静→动边沿 change_start；motion 中每 400ms（可覆盖）发
    latest；静止中每 5000ms（可覆盖）发 patrol；首帧 prev_available 如实。"""
    materials = []
    m = make_async_monitor([])
    m.set_material_sink(materials.append)
    m.MATERIAL_LATEST_MS = 300.0
    m.MATERIAL_PATROL_MS = 300.0

    for i in range(5):                       # 静止 t=0..400
        _drive_async_frame(m, False, i, i * 100.0)
    for i in range(8):                       # 运动 t=500..1200
        _drive_async_frame(m, True, i, 500.0 + i * 100.0)

    reasons = [mat["reason"] for mat in materials]
    assert reasons == ["patrol", "patrol", "change_start",
                       "latest", "latest"], reasons
    assert materials[0]["prev_available"] is False, "首帧处理前没有前帧"
    assert all(mat["prev_available"] for mat in materials[1:])
    assert materials[2]["change_boxes"], "change_start 必须携带运动框"
    assert materials[3]["change_boxes"], "latest 携带当前运动框"
    assert materials[0]["change_boxes"] == [], "patrol 不带运动框"
    assert materials[0]["frame_id"] == 1 and materials[0]["t_capture_ms"] == 0.0
    assert materials[2]["frame_id"] == 6 and materials[2]["t_capture_ms"] == 500.0
    for mat in materials:
        assert mat["camera_id"] == "front-door"
        assert mat["run_id"] == "async-run"
        assert mat["config_version"] == m.zone_revision
        assert mat["gate_w"] == 96 and mat["gate_h"] == 54


def test_async_material_frame_passed_by_reference():
    """合同 §2.2：frame_bgr 按引用交出（同一对象）；sink 侧立即 copy 后，
    后续对原帧的原地改写不得影响已存副本。"""
    seen = []

    def sink(material):
        seen.append({"reason": material["reason"],
                     "ref": material["frame_bgr"],
                     "copy": material["frame_bgr"].copy()})
        return True

    m = make_async_monitor([])
    m.set_material_sink(sink)
    m.MATERIAL_PATROL_MS = 100.0

    f = frame(0, present=False)
    m.step(f, to_gray(f, m.GRAY_W), 0.0)
    assert seen[0]["reason"] == "patrol"
    assert seen[0]["ref"] is f, "材料帧必须是引用（与 step 收到的是同一对象）"
    assert seen[0]["copy"] is not f
    assert seen[0]["copy"].mean() < 50
    f[:] = 255                               # 原地改写原帧（模拟复用缓冲）
    assert seen[0]["copy"].mean() < 50, "sink 侧副本不受原帧后续改写影响"


def test_async_apply_detection_result_validates_identity():
    """apply 四拒：错相机/错运行/旧配置版本/乱序各自拒收并计数；正确则受理；
    旧结果未消费被顶掉计 superseded。"""
    m = make_async_monitor([])

    good = FakeL1Result(1000.0)
    assert m.apply_detection_result(good, 1100.0) is True
    assert m.results_rejected_identity == 0
    assert m._pending_result is good

    wrong_cam = FakeL1Result(1200.0, camera_id="back-door")
    wrong_run = FakeL1Result(1200.0, run_id="other-run")
    stale_cfg = FakeL1Result(1200.0, config_version=7)
    stale_seq = FakeL1Result(900.0)          # 乱序：早于已受理采集时间
    for bad in (wrong_cam, wrong_run, stale_cfg, stale_seq):
        assert m.apply_detection_result(bad, 1300.0) is False
    assert m.results_rejected_identity == 4
    assert m._pending_result is good, "拒收不得触碰已受理的待消费结果"

    newer = FakeL1Result(1500.0)
    assert m.apply_detection_result(newer, 1600.0) is True
    assert m.results_superseded == 1, "旧结果未消费即被顶掉必须计数"
    assert m._pending_result is newer


def test_async_consume_ok_builds_track_alarm_and_same_picture_evidence():
    """消费 ok 结果：轨迹建立、区域规则告警触发、t_source=结果帧时间
    （不是处理帧时间）、observe_object 证据帧与结果帧是同一对象。"""
    sink = AsyncTruthSink()
    m = make_async_monitor([sink])
    ev1 = _flip_frame(True, 0)
    ev2 = _flip_frame(True, 1)
    res1 = FakeL1Result(1000.0, [dict(PERSON_DET)], frame_bgr=ev1, frame_id=1)
    res2 = FakeL1Result(1100.0, [dict(PERSON_DET)], frame_bgr=ev2, frame_id=3)

    m.step(_flip_frame(True, 0), to_gray(_flip_frame(True, 0), m.GRAY_W), 1000.0)
    assert m.apply_detection_result(res1, 1000.0) is True
    m.step(_flip_frame(True, 1), to_gray(_flip_frame(True, 1), m.GRAY_W), 1100.0)
    assert m.apply_detection_result(res2, 1100.0) is True
    alarms = m.step(_flip_frame(True, 0),
                    to_gray(_flip_frame(True, 0), m.GRAY_W), 1200.0)

    assert len(alarms) == 1
    a = alarms[0]
    assert a["t_source"] == pytest.approx(1.1), \
        "t_source 必须是结果帧采集时间，不是消费帧处理时间"
    assert a["zone"] == "z1" and a["cls"] == "person"
    assert a["thumbnail"] is not None, "消费帧必须带同画面缩略图证据"
    confirmed = m.tracker.get_confirmed()
    assert len(confirmed) == 1 and confirmed[0]["count"] == 2
    assert m.results_applied == 2
    assert m.l1_health == {"state": "ready", "code": None, "at": 1200.0}
    assert sink.observe_frames == [ev2], \
        "observe_object 的证据帧必须就是结果自带帧（同一对象）"
    stats = m.stats()
    assert stats["l1_state"] == "ready"
    assert stats["results_applied"] == 2
    assert stats["l1_last_result_age_ms"] is not None


def test_async_empty_result_keeps_zero_tracks_and_material_flow():
    """empty 结果：零轨迹、零告警，但 l1_health=ready 且材料通道继续提交。"""
    materials = []
    sink = AsyncTruthSink()
    m = make_async_monitor([sink])
    m.set_material_sink(materials.append)
    m.MATERIAL_LATEST_MS = 100.0
    m.MATERIAL_PATROL_MS = 100.0

    res = FakeL1Result(0.0, [], status="empty")
    assert m.apply_detection_result(res, 0.0) is True
    _drive_async_frame(m, True, 0, 0.0)      # 消费 empty
    _drive_async_frame(m, True, 1, 100.0)
    _drive_async_frame(m, True, 0, 200.0)
    _drive_async_frame(m, True, 1, 300.0)

    assert m.tracker.tracks == {}, "empty 结果不得产生轨迹"
    assert sink.alarms == []
    assert m.results_applied == 1
    assert m._last_result_ms == 0.0
    assert m.l1_health["state"] == "ready"
    assert [mat["reason"] for mat in materials] == [
        "patrol", "change_start", "latest", "latest"], "材料须继续按节奏提交"


def test_async_model_unavailable_gap_then_closes_and_recovers():
    """失败结果：tracker 不动、非消费帧零事实工作（F4，不累计不延展）；
    距最后 ok 结果超过 detection_lost_ms 且 l1 失败态（T2 双条件）→
    detection-lost 诚实收口；随后 ok 结果恢复：新轨迹、新事件、新告警。

    （C-133 修正 C-132 旧名/旧注释：不存在"冻结"语义——非消费帧只是零
    事实工作；间隙滞留按 T1 连续性在 ok 消费点处理。）
    """
    sink = AsyncTruthSink()
    m = make_async_monitor([sink], detection_lost_ms=800.0,
                           detection_max_age_ms=2500.0)
    materials = []
    m.set_material_sink(materials.append)
    m.MATERIAL_LATEST_MS = 100.0
    m.MATERIAL_PATROL_MS = 100.0

    ev1 = _flip_frame(True, 0)
    ev2 = _flip_frame(True, 1)
    assert m.apply_detection_result(
        FakeL1Result(1000.0, [dict(PERSON_DET)], frame_bgr=ev1, frame_id=1),
        1000.0) is True
    _drive_async_frame(m, True, 0, 1000.0)   # 消费 ok1：轨迹1（未确认）
    assert m.apply_detection_result(
        FakeL1Result(1100.0, [dict(PERSON_DET)], frame_bgr=ev2, frame_id=2),
        1100.0) is True
    _drive_async_frame(m, True, 1, 1100.0)   # 消费 ok2：确认 + immediate 告警
    assert len(sink.alarms) == 1
    track_id = sink.alarms[0]["track_id"]
    object_id = sink.alarms[0]["object_id"]

    assert m.apply_detection_result(
        FakeL1Result(1300.0, status="model_unavailable",
                     error_code="detector_load_failed", frame_id=3),
        1300.0) is True
    _drive_async_frame(m, True, 0, 1300.0)   # 消费失败结果：健康如实、不碰 tracker
    assert m.l1_health == {"state": "model_unavailable",
                           "code": "detector_load_failed", "at": 1300.0}
    assert track_id in m.tracker.tracks
    assert m._last_result_ms == 1100.0, "失败结果不得续新鲜度"

    for i, t in ((1, 1400.0), (0, 1500.0), (1, 1600.0), (0, 1700.0),
                 (1, 1800.0)):
        _drive_async_frame(m, True, i, t)    # 非消费帧：零事实工作（F4）
    assert sink.event_updates == [
        ("front-door:async-run:event:1", 1.1)
    ], "仅首次确认帧推进 t_last；失败/非消费帧不得追加更新"
    assert sink.observe_frames == [ev2], "非消费帧不产观察、不产证据"

    _drive_async_frame(m, True, 0, 1900.0)   # 距最后 ok 800ms 未满：不收口
    assert m.detection_lost_closes == 0
    assert len(materials) > 5, "检测不可用期间变化材料仍须继续记录"

    _drive_async_frame(m, True, 1, 2000.0)   # 距最后 ok 900ms > lost + l1 失败
    assert m.tracker.tracks == {} and m._prev_live == set()
    assert m.zone_rt._enter == {}, "滞留表必须随收口清理"
    assert m.detection_lost_closes == 1
    assert m.stats()["detection_lost_closes"] == 1
    assert sink.closed_objects == [(object_id, 2.0, "detection-lost")]
    assert sink.closed_events == [
        (f"front-door:async-run:event:{track_id}", "detection-lost")]
    assert sink.event_updates == [
        ("front-door:async-run:event:1", 1.1)
    ], "间隙与收口期间无新增观察更新，保留首次确认更新"

    # ---- 恢复：ok 结果回到 → 新轨迹、新事件、新告警 ----
    assert m.apply_detection_result(
        FakeL1Result(2700.0, [dict(PERSON_DET)], frame_id=4), 2700.0) is True
    _drive_async_frame(m, True, 0, 2700.0)   # 消费 ok3：新轨迹（未确认）
    assert m.l1_health == {"state": "ready", "code": None, "at": 2700.0}
    assert m.apply_detection_result(
        FakeL1Result(2800.0, [dict(PERSON_DET)], frame_id=5), 2800.0) is True
    _drive_async_frame(m, True, 1, 2800.0)   # 消费 ok4：确认 → 新告警

    assert len(sink.alarms) == 2, "恢复后必须能再次告警"
    assert sink.alarms[1]["track_id"] != track_id
    assert sink.alarms[1]["event_id"] != sink.alarms[0]["event_id"]
    assert sink.alarms[1]["t_source"] == pytest.approx(2.8)


def test_async_expired_result_is_rejected_not_consumed():
    """超龄结果（detection_max_age_ms 可覆盖）：计 rejected_expired 不消费，
    不计零对象、不续新鲜度；后续新鲜结果照常消费。"""
    sink = AsyncTruthSink()
    m = make_async_monitor([sink], detection_max_age_ms=400.0)

    stale = FakeL1Result(1000.0, [dict(PERSON_DET)])
    assert m.apply_detection_result(stale, 2000.0) is True, \
        "apply 只验身份；新鲜度在消费时验"
    alarms = m.step(_flip_frame(True, 0),
                    to_gray(_flip_frame(True, 0), m.GRAY_W), 2000.0)
    assert alarms == []
    assert m.tracker.tracks == {}, "过期结果不得消费（也不得计成零对象）"
    assert m.results_rejected_expired == 1
    assert m.results_applied == 0
    assert m._pending_result is None
    assert m._last_result_ms is None
    assert m.l1_health is None
    assert sink.observe_frames == []

    fresh = FakeL1Result(2100.0, [dict(PERSON_DET)])
    assert m.apply_detection_result(fresh, 2100.0) is True
    m.step(_flip_frame(True, 1), to_gray(_flip_frame(True, 1), m.GRAY_W), 2100.0)
    assert m.results_applied == 1, "拒收过期结果不得影响后续新鲜结果"
    assert m.tracker.tracks, "新鲜结果照常建立轨迹"


# ---------- C-132 回归：D1 empty 不复活 / D2 消费复核 / D3 冻结滞留 / D4 契约 ----------

def test_async_empty_then_idle_frames_do_not_revive_cached_tracks():
    """D1/F4 回归（清单a）：ok×2 确认 → empty → 多个普通帧——对象事实零更新、
    零新增告警、零新证据帧：缓存轨迹不得被冒充新观察。"""
    sink = AsyncTruthSink()
    m = make_async_monitor([sink])
    ev1 = _flip_frame(True, 0)
    ev2 = _flip_frame(True, 1)
    assert m.apply_detection_result(
        FakeL1Result(1000.0, [dict(PERSON_DET)], frame_bgr=ev1, frame_id=1),
        1000.0) is True
    _drive_async_frame(m, True, 0, 1000.0)   # ok1：轨迹（未确认）
    assert m.apply_detection_result(
        FakeL1Result(1100.0, [dict(PERSON_DET)], frame_bgr=ev2, frame_id=2),
        1100.0) is True
    _drive_async_frame(m, True, 1, 1100.0)   # ok2：确认 + 告警
    assert len(sink.alarms) == 1
    observes_after_ok = len(sink.observe_frames)
    updates_after_ok = len(sink.event_updates)

    assert m.apply_detection_result(
        FakeL1Result(1200.0, [], status="empty", frame_id=3), 1200.0) is True
    _drive_async_frame(m, True, 0, 1200.0)   # 消费 empty：真实"本轮无对象"
    for i, t in ((1, 1300.0), (0, 1400.0), (1, 1500.0), (0, 1600.0)):
        _drive_async_frame(m, True, i, t)    # 多个普通帧（无结果可消费）

    assert m.results_applied == 3
    assert len(sink.alarms) == 1, "empty/普通帧不得新增告警"
    assert len(sink.observe_frames) == observes_after_ok, \
        "非消费帧不得更新对象事实（不复活缓存轨迹）"
    assert len(sink.event_updates) == updates_after_ok, \
        "非消费帧不得推进事件 t_last"
    assert m.detection_lost_closes == 0
    assert m.tracker.tracks, "empty 不清轨迹：由老化与后续结果自然推进"


def test_async_zone_switch_invalidates_pending_result_then_recovers():
    """D2/F4 回归（清单b）：受理 config0 结果 → 区域切换 → 旧结果直接失效
    （results_invalidated_config）、零轨迹零旧结果告警；config1 结果正常消费。"""
    sink = AsyncTruthSink()
    m = make_async_monitor([sink])

    assert m.apply_detection_result(
        FakeL1Result(1000.0, [dict(PERSON_DET)], frame_id=1,
                     config_version=0), 1000.0) is True
    m.request_zone_update([
        {"id": "z1", "name": "门口", "cells": [231, 232, 253, 254],
         "rules": [{"cls": "person", "template": "immediate"}]}])
    m.step(_flip_frame(True, 0), to_gray(_flip_frame(True, 0), m.GRAY_W),
           1100.0)                            # step 顶部切 config1 → 结果失效
    stats = m.stats()
    assert stats["results_invalidated_config"] == 1
    assert m.tracker.tracks == {} and sink.alarms == []
    assert m.results_applied == 0
    assert m.zone_revision == 1

    assert m.apply_detection_result(
        FakeL1Result(1200.0, [dict(PERSON_DET)], frame_id=2,
                     config_version=1), 1200.0) is True
    m.step(_flip_frame(True, 1), to_gray(_flip_frame(True, 1), m.GRAY_W),
           1200.0)                            # 消费检测1（未确认）
    assert m.results_applied == 1
    assert m.apply_detection_result(
        FakeL1Result(1300.0, [dict(PERSON_DET)], frame_id=3,
                     config_version=1), 1300.0) is True
    alarms = m.step(_flip_frame(True, 0),
                    to_gray(_flip_frame(True, 0), m.GRAY_W), 1300.0)
    assert len(alarms) == 1 and alarms[0]["zone"] == "z1", \
        "新配置结果必须正常消费并告警"
    assert len(sink.alarms) == 1


def test_async_consume_rechecks_future_order_and_timestamp_ties():
    """D2/F4 回归（清单c）：消费复核——未来时间拒、重复 frame_id 拒、
    乱序（t_capture 回退）apply 拒、同时间戳不同 frame_id 正常消费。"""
    sink = AsyncTruthSink()
    m = make_async_monitor([sink], detection_max_age_ms=2500.0)
    f = _flip_frame(True, 0)
    g = to_gray(f, m.GRAY_W)

    # 同时间戳不同 frame_id（严格递增）：视为正常顺序，两次都消费
    assert m.apply_detection_result(
        FakeL1Result(1000.0, [dict(PERSON_DET)], frame_id=7), 1000.0) is True
    m.step(f, g, 1000.0)
    assert m.results_applied == 1
    assert m.apply_detection_result(
        FakeL1Result(1000.0, [dict(PERSON_DET)], frame_id=8), 1000.0) is True
    m.step(f, g, 1100.0)
    assert m.results_applied == 2, "同时间戳不同 frame_id 视为正常顺序"

    # 重复 frame_id：消费复核拒绝，不得二次消费
    assert m.apply_detection_result(
        FakeL1Result(1200.0, [dict(PERSON_DET)], frame_id=8), 1200.0) is True
    m.step(f, g, 1200.0)
    assert m.results_rejected_order == 1
    assert m.stats()["results_rejected_order"] == 1
    assert m.results_applied == 2

    # 未来时间（t_capture = now + 1000）：消费复核拒绝
    assert m.apply_detection_result(
        FakeL1Result(2400.0, [dict(PERSON_DET)], frame_id=9), 1400.0) is True
    m.step(f, g, 1400.0)
    assert m.results_rejected_future == 1
    assert m.results_applied == 2

    # 边界内未来（t_capture = now + 100）：允许消费
    assert m.apply_detection_result(
        FakeL1Result(2600.0, [dict(PERSON_DET)], frame_id=10), 2500.0) is True
    m.step(f, g, 2500.0)
    assert m.results_applied == 3

    # 乱序（t_capture 回退）：apply 阶段按身份拒收
    assert m.apply_detection_result(
        FakeL1Result(1000.0, [dict(PERSON_DET)], frame_id=11), 2600.0) is False
    assert m.results_rejected_identity == 1


def test_async_discontinuity_does_not_backfill_gap_dwell():
    """T1 回归（清单d）：进区 ok（滞留1s）→ 失败（不连续介入）→ 时间推进
    很远 → ok 恢复：不连续消费把 enter 平移为 t_capture − 上次 ok 消费点
    快照滞留——已累计滞留保留、未知间隙不补算；enter-dwell 规则不因间隙
    越门槛（补算即触发的规则未触发）。"""
    sink = AsyncTruthSink()
    cfg = {"id": "front-door", "grid": {"rows": 18, "cols": 22},
           "zones": [{"id": "z1", "cells": [231, 232, 253, 254],
                      "rules": [{"cls": "person", "template": "enter-dwell",
                                 "dwell_s": 5}]}]}
    m = Monitor(cfg, detect_fn=None, sinks=[sink], run_id="async-run",
                detection_mode="async", detection_lost_ms=15000.0)
    materials = []
    m.set_material_sink(materials.append)   # 材料持续受理：T2 下提交不重置计时
    m.MATERIAL_LATEST_MS = 100.0
    m.MATERIAL_PATROL_MS = 300.0

    def ok(t, fid):
        assert m.apply_detection_result(
            FakeL1Result(t, [dict(PERSON_DET)], frame_id=fid), t) is True
        _drive_async_frame(m, True, int(t) % 2, t)

    ok(1000.0, 1)    # 轨迹建立（未确认）
    ok(2000.0, 2)    # 确认；进区，滞留从 2000 起算
    ok(3000.0, 3)    # 滞留 1.0s
    assert m.zone_rt._enter[(1, "z1")] == pytest.approx(2000.0)

    assert m.apply_detection_result(
        FakeL1Result(3100.0, status="model_unavailable",
                     error_code="detector_infer_failed", frame_id=4),
        3100.0) is True
    _drive_async_frame(m, True, 0, 3100.0)   # 失败结果：间隙不连续标记

    t, i = 3200.0, 1
    while t < 9200.0:                        # 间隙 ~6s，远超滞留增量本身
        _drive_async_frame(m, True, i % 2, t)
        t += 100.0
        i += 1
    assert m.detection_lost_closes == 0, \
        "距最后 ok 未超过 lost 阈值：看门狗持续条件不满足，不得收口"
    assert m.tracker.tracks, "间隙窗口内轨迹保留（confirmed 12s 存活窗）"

    ok(9300.0, 5)    # 恢复：平移 enter = 9300 - 1000 = 8300（间隙不补算）
    assert m.zone_rt._enter[(1, "z1")] == pytest.approx(8300.0), \
        "不连续消费把 enter 平移为 t_capture - 上次消费快照滞留"
    ok(9800.0, 6)    # 连续：自然增长，滞留 1.5s（若补算间隙会是 ~7.8s ≥ 5s 门槛）

    assert sink.alarms == [], "enter-dwell 规则不得因未知间隙越门槛"
    assert m.zone_rt._enter[(1, "z1")] == pytest.approx(8300.0)


def test_async_quiet_target_confirms_across_two_patrols():
    """D4/F6 回归（清单e）：MATERIAL_PATROL_MS=1500 < tracker MAX_AGE=2000——
    首次静止目标两次巡检检测完成确认，不因节奏过疏永远无法确认。"""
    import scam.track as track_module

    sink = AsyncTruthSink()
    m = make_async_monitor([sink])
    m.MATERIAL_PATROL_MS = 1500.0
    assert m.MATERIAL_PATROL_MS < track_module.MAX_AGE, \
        "F6 契约：patrol 节奏必须小于未确认轨迹老化窗"

    materials = []
    m.set_material_sink(materials.append)
    f = frame(0, present=True)               # 静止目标：门控零运动 → patrol
    g = to_gray(f, m.GRAY_W)
    m.step(f, g, 0.0)                        # 巡检#1 材料受理
    assert materials[0]["reason"] == "patrol"
    assert m.apply_detection_result(
        FakeL1Result(0.0, [dict(PERSON_DET)], frame_id=1), 0.0) is True
    m.step(f, g, 100.0)                      # 消费检测#1：轨迹 count=1
    for t in range(200, 1500, 100):
        m.step(f, g, float(t))               # 正常等待下一巡检（零事实工作）
    assert m.tracker.tracks, "1.5s < MAX_AGE 2s：轨迹不得老化"
    m.step(f, g, 1500.0)                     # 巡检#2 材料受理
    assert [mat["reason"] for mat in materials] == ["patrol", "patrol"]
    assert m.apply_detection_result(
        FakeL1Result(1500.0, [dict(PERSON_DET)], frame_id=2), 1500.0) is True
    m.step(f, g, 1600.0)                     # 消费检测#2：确认
    confirmed = m.tracker.get_confirmed()
    assert len(confirmed) == 1 and confirmed[0]["count"] == 2
    assert m.detection_lost_closes == 0


def test_async_multi_patrol_with_results_never_loses_detection():
    """D4/F6 回归（清单f）：静止目标跨多个巡检周期、结果按节奏返回——
    正常等待永不触发 detection-lost 收口。"""
    sink = AsyncTruthSink()
    m = make_async_monitor([sink], detection_lost_ms=1500.0,
                           result_wait_ms=800.0)
    materials = []
    m.set_material_sink(materials.append)
    m.MATERIAL_PATROL_MS = 300.0

    t = 0.0
    for fid in range(1, 11):                 # 10 个巡检周期，每周期都有结果
        _drive_async_frame(m, False, fid, t)          # patrol 材料受理 @t
        assert m.apply_detection_result(
            FakeL1Result(t, [dict(PERSON_DET)], frame_id=fid), t) is True
        _drive_async_frame(m, False, fid, t + 100.0)  # 下一帧消费 @t+100
        t += 300.0
    confirmed = m.tracker.get_confirmed()
    assert len(confirmed) == 1, "节奏内两次检测即完成确认"
    assert m.detection_lost_closes == 0
    assert m.stats()["detection_lost_closes"] == 0
    assert sink.closed_objects == [], "跨多巡检周期有正常结果：不收口"


def test_async_persistent_model_unavailable_honest_close_after_threshold():
    """清单g：持续 model_unavailable（无 ok/empty）→ 非消费帧零事实工作；
    距最后 ok 超过 lost 且 l1 失败态 → detection-lost 诚实收口（close_object
    reason=detection-lost）。"""
    sink = AsyncTruthSink()
    m = make_async_monitor([sink], detection_lost_ms=1500.0,
                           result_wait_ms=800.0)
    materials = []
    m.set_material_sink(materials.append)
    m.MATERIAL_LATEST_MS = 100.0
    m.MATERIAL_PATROL_MS = 100.0

    assert m.apply_detection_result(
        FakeL1Result(1000.0, [dict(PERSON_DET)], frame_id=1), 1000.0) is True
    _drive_async_frame(m, True, 0, 1000.0)   # ok1：轨迹（未确认）
    assert m.apply_detection_result(
        FakeL1Result(1100.0, [dict(PERSON_DET)], frame_id=2), 1100.0) is True
    _drive_async_frame(m, True, 1, 1100.0)   # ok2：确认 + 告警
    assert len(sink.alarms) == 1
    object_id = sink.alarms[0]["object_id"]

    fid, t = 3, 1200.0
    while t < 2600.0:                        # 持续失败：每次检测都不可用
        assert m.apply_detection_result(
            FakeL1Result(t, status="model_unavailable",
                         error_code="detector_load_failed", frame_id=fid),
            t) is True
        _drive_async_frame(m, True, int(t) % 2, t)
        assert m.detection_lost_closes == 0, "到阈值前只冻结，不收口"
        t += 100.0
        fid += 1
    assert m.l1_health["state"] == "model_unavailable"
    assert len(sink.observe_frames) == 1, "失败期间零事实工作（无新观察）"

    _drive_async_frame(m, True, 0, 2700.0)   # 距最后 ok 1600ms > lost → 收口
    assert m.detection_lost_closes == 1
    assert m.tracker.tracks == {}
    assert [(oid, reason) for oid, _, reason in sink.closed_objects] == \
        [(object_id, "detection-lost")]
    assert sink.closed_events == [
        (f"front-door:async-run:event:{sink.alarms[0]['track_id']}",
         "detection-lost")]


def test_async_silent_pipeline_stalled_probe_honest_close():
    """T2 看门狗 v3：管道静默（最后提交永不返回）→ 探针报最老未完结任务
    年龄持续增长，超过 RESULT_WAIT_MS 且距最后 ok 超过 DETECTION_LOST_MS
    → detection-lost 诚实收口（l1 全程健康：超期分支独立于 l1 失败态）。
    任务年龄未超/未到 lost 的正常等待期永不触发；持续提交不重置计时
    （基准是任务年龄，不是最近受理时刻）。"""
    sink = AsyncTruthSink()
    m = make_async_monitor([sink], detection_lost_ms=1500.0,
                           result_wait_ms=800.0)
    materials = []
    m.set_material_sink(materials.append)
    m.MATERIAL_LATEST_MS = 100.0
    m.MATERIAL_PATROL_MS = 100.0
    clock = {"now": 0.0}   # 探针=最老未完结任务年龄（@300 提交后持续增长）
    m.set_progress_probe(lambda: max(0.0, clock["now"] - 300.0))
    f = _flip_frame(True, 0)
    g = to_gray(f, m.GRAY_W)

    m.step(f, g, 0.0)                        # patrol 材料受理 @0
    assert m.apply_detection_result(
        FakeL1Result(0.0, [dict(PERSON_DET)], frame_id=1), 0.0) is True
    clock["now"] = 100.0
    m.step(f, g, 100.0)                      # 消费 ok1
    assert m.apply_detection_result(
        FakeL1Result(100.0, [dict(PERSON_DET)], frame_id=2), 100.0) is True
    clock["now"] = 200.0
    m.step(f, g, 200.0)                      # 消费 ok2：确认
    assert len(sink.alarms) == 1
    clock["now"] = 300.0
    m.step(f, g, 300.0)                      # 最新一次提交 @300（受理成功）
    assert materials and m.material_rejected == 0
    m.set_material_sink(None)                # 管道静默：该提交永不返回

    for t in (700.0, 1100.0):                # 任务年龄 400/800 未超 wait：不收口
        clock["now"] = t
        m.step(f, g, t)
        assert m.detection_lost_closes == 0
    clock["now"] = 1700.0                    # 年龄 1400>wait、距最后 ok 1600>lost
    m.step(f, g, 1700.0)
    assert m.detection_lost_closes == 1
    assert m.l1_health["state"] == "ready", "超期分支独立于 l1 失败态"
    assert sink.closed_objects and sink.closed_objects[-1][2] == "detection-lost"


# ---------- 合同 C133 T3 必测：连续性滞留 / 探针看门狗（全走 async 消费路径） ----------

def test_t3_continuous_ok_dwell_grows_at_consumptions():
    """T3-a：连续 ok@1000/2000/3000/4000、每对结果间插 ≥3 个普通帧——
    dwell 逐消费自然增长（enter 不动，断言具体数值序列），enter-dwell 正
    门槛在 dwell 达标的那次消费真实触发；对象事实只在消费帧更新。"""
    sink = AsyncTruthSink()
    cfg = {"id": "front-door", "grid": {"rows": 18, "cols": 22},
           "zones": [{"id": "z1", "name": "门口",
                      "cells": [231, 232, 253, 254],
                      "rules": [{"cls": "person", "template": "enter-dwell",
                                 "dwell_s": 2}]}]}
    m = Monitor(cfg, detect_fn=None, sinks=[sink], run_id="async-run",
                detection_mode="async")
    materials = []
    m.set_material_sink(materials.append)    # 普通帧期间材料照常提交
    m.MATERIAL_LATEST_MS = 100.0
    m.MATERIAL_PATROL_MS = 100.0

    trace = []       # (帧类型, 事实写入增量)：普通帧必须零增量
    dwells = []      # 每次 ok 消费点的配对滞留毫秒
    enters = []      # 每次 ok 消费点的 enter（连续自然增长必须不动）
    counter = {"i": 0}

    def consume_ok(t, fid):
        assert m.apply_detection_result(
            FakeL1Result(t, [dict(PERSON_DET)], frame_id=fid), t) is True
        before = len(sink.observe_frames) + len(sink.event_updates)
        counter["i"] += 1
        _drive_async_frame(m, True, counter["i"], t)
        if (1, "z1") in m.zone_rt._enter:
            dwells.append(t - m.zone_rt._enter[(1, "z1")])
            enters.append(m.zone_rt._enter[(1, "z1")])
        trace.append(("consume", len(sink.observe_frames)
                      + len(sink.event_updates) - before))

    def idle(t):
        before = len(sink.observe_frames) + len(sink.event_updates)
        counter["i"] += 1
        _drive_async_frame(m, True, counter["i"], t)
        trace.append(("idle", len(sink.observe_frames)
                      + len(sink.event_updates) - before))

    consume_ok(1000.0, 1)                    # 轨迹建立（未确认）
    for k in range(3):
        idle(1100.0 + 100.0 * k)
    consume_ok(2000.0, 5)                    # 确认：进区 enter=2000，dwell 0
    for k in range(3):
        idle(2100.0 + 100.0 * k)
    consume_ok(3000.0, 9)                    # 连续：dwell 自然增长到 1.0s
    for k in range(3):
        idle(3100.0 + 100.0 * k)
    consume_ok(4000.0, 13)                   # 连续：dwell 2.0s → 正门槛触发

    assert dwells == [0.0, 1000.0, 2000.0], f"dwell 必须逐消费自然增长 {dwells}"
    assert enters == [2000.0, 2000.0, 2000.0], "连续增长 enter 不动"
    assert all(delta == 0 for kind, delta in trace if kind == "idle"), \
        "非消费帧零事实工作（对象事实只在消费帧更新）"
    assert len(sink.observe_frames) == 3
    assert sink.event_updates == [
        ("front-door:async-run:event:1", 2.0),
        ("front-door:async-run:event:1", 3.0),
        ("front-door:async-run:event:1", 4.0),
    ], "确认和后续更新都仅使用实际消费帧时间"
    assert len(sink.alarms) == 1
    a = sink.alarms[0]
    assert a["t_source"] == pytest.approx(4.0), "告警时间取结果帧采集时间"
    assert a["rule"] == "enter-dwell" and a["zone"] == "z1"
    assert "滞留 2 秒" in a["detail"], "正门槛按真实累计滞留触发"
    assert m.results_applied == 4
    assert m.detection_lost_closes == 0
    assert materials, "普通帧期间材料照常提交"


def test_t3_failure_gap_not_counted_into_dwell():
    """T3-b：正常 ok → 连续失败（model_unavailable）→ 恢复 ok——失败期间
    gap 不计入（恢复后 dwell ≈ 失败前值），不瞬间越门槛；l1 失败但未到
    DETECTION_LOST_MS 不收口。"""
    sink = AsyncTruthSink()
    cfg = {"id": "front-door", "grid": {"rows": 18, "cols": 22},
           "zones": [{"id": "z1", "name": "门口",
                      "cells": [231, 232, 253, 254],
                      "rules": [{"cls": "person", "template": "enter-dwell",
                                 "dwell_s": 3}]}]}
    m = Monitor(cfg, detect_fn=None, sinks=[sink], run_id="async-run",
                detection_mode="async")
    materials = []
    m.set_material_sink(materials.append)
    m.MATERIAL_LATEST_MS = 100.0
    m.MATERIAL_PATROL_MS = 100.0

    def ok(t, fid):
        assert m.apply_detection_result(
            FakeL1Result(t, [dict(PERSON_DET)], frame_id=fid), t) is True
        _drive_async_frame(m, True, int(t) % 2, t)

    ok(1000.0, 1)
    ok(2000.0, 2)                            # 确认；enter=2000
    ok(3000.0, 3)                            # dwell 1.0s（失败前值）
    assert m.zone_rt._enter[(1, "z1")] == pytest.approx(2000.0)

    fid = 4
    for t in range(3100, 6400, 300):         # 连续失败 ~3.3s（l1 失败态）
        assert m.apply_detection_result(
            FakeL1Result(float(t), status="model_unavailable",
                         error_code="detector_load_failed", frame_id=fid),
            float(t)) is True
        _drive_async_frame(m, True, fid % 2, float(t))
        fid += 1
    assert m.detection_lost_closes == 0, "未到 DETECTION_LOST_MS：不收口"
    assert m.zone_rt._enter[(1, "z1")] == pytest.approx(2000.0), \
        "失败结果不触碰滞留表"
    assert len(sink.observe_frames) == 2, "失败期间零事实工作"

    ok(7000.0, fid)      # 恢复：失败介入 → 平移 enter = 7000 - 1000 = 6000
    assert m.zone_rt._enter[(1, "z1")] == pytest.approx(6000.0), \
        "失败间隙不计入：enter 平移为 t_capture - 失败前 dwell"
    ok(8000.0, fid + 1)  # 连续：自然增长 dwell 2.0s
    assert m.zone_rt._enter[(1, "z1")] == pytest.approx(6000.0)
    assert sink.alarms == [], "恢复后不瞬间越门槛（dwell 2.0s < 3s）"
    assert m.detection_lost_closes == 0


def test_t3_gap_over_continuity_limit_not_backfilled():
    """T3-c：gap=7000 > CONTINUITY_MAX_GAP_MS(6000) 的两个 ok（期间无失败）
    ——未知间隙不补算：dwell ≈ 前值（0），不是 7s；enter 平移到本次消费点。"""
    sink = AsyncTruthSink()
    cfg = {"id": "front-door", "grid": {"rows": 18, "cols": 22},
           "zones": [{"id": "z1", "name": "门口",
                      "cells": [231, 232, 253, 254],
                      "rules": [{"cls": "person", "template": "enter-dwell",
                                 "dwell_s": 5}]}]}
    m = Monitor(cfg, detect_fn=None, sinks=[sink], run_id="async-run",
                detection_mode="async", continuity_max_gap_ms=6000.0)

    def ok(t, fid):
        assert m.apply_detection_result(
            FakeL1Result(t, [dict(PERSON_DET)], frame_id=fid), t) is True
        _drive_async_frame(m, True, int(t) % 2, t)

    ok(1000.0, 1)
    ok(2000.0, 2)                            # 确认；enter=2000，dwell 0
    assert m.zone_rt._enter[(1, "z1")] == pytest.approx(2000.0)
    for k in range(69):                      # 普通帧推进 ~6.8s（零事实工作）
        _drive_async_frame(m, True, k % 2, 2100.0 + 100.0 * k)
    ok(9000.0, 3)        # gap = 9000-2000 = 7000 > 6000：平移不补算
    assert m.zone_rt._enter[(1, "z1")] == pytest.approx(9000.0), \
        "enter 平移为 t_capture - 快照滞留 0：7s 间隙不计入滞留"
    ok(9500.0, 4)        # 连续：自然增长
    assert m.zone_rt._enter[(1, "z1")] == pytest.approx(9000.0)
    assert sink.alarms == [], "7s 间隙不得计入滞留（否则 9s≥5s 门槛误触发）"
    assert m.detection_lost_closes == 0


def test_t3_stalled_probe_honest_close_then_recovers():
    """T3-d：已确认对象 → 探针持续返回 >RESULT_WAIT 的最老任务年龄（模拟
    检测器卡死，快系统照常提交/受理——提交不重置计时）→ lost 门槛内
    detection-lost 诚实收口（reason 断言）；探针恢复小值后不再收口，后续
    ok 正常消费并告警。"""
    sink = AsyncTruthSink()
    m = make_async_monitor([sink], detection_lost_ms=2000.0,
                           result_wait_ms=1000.0)
    materials = []
    m.set_material_sink(materials.append)
    m.MATERIAL_LATEST_MS = 100.0
    m.MATERIAL_PATROL_MS = 100.0
    probe_age = [None]
    m.set_progress_probe(lambda: probe_age[0])

    def ok(t, fid):
        assert m.apply_detection_result(
            FakeL1Result(t, [dict(PERSON_DET)], frame_id=fid), t) is True
        _drive_async_frame(m, True, int(t) % 2, t)

    ok(1000.0, 1)
    ok(2000.0, 2)                            # 确认 + immediate 告警
    assert len(sink.alarms) == 1
    track_id = sink.alarms[0]["track_id"]
    object_id = sink.alarms[0]["object_id"]

    probe_age[0] = 5000.0                    # 检测器卡死：最老未完结任务持续增长
    for t in (2100.0, 2500.0, 3000.0, 3500.0, 4000.0):
        _drive_async_frame(m, True, int(t) // 100 % 2, t)
        assert m.detection_lost_closes == 0, "未到 DETECTION_LOST_MS 不得收口"
    assert len(materials) >= 5 and m.material_rejected == 0, \
        "卡死期间快系统照常提交且受理——提交不重置失联计时"
    assert len(sink.observe_frames) == 1, "卡死期间零事实工作（滞留不增长）"

    _drive_async_frame(m, True, 0, 4100.0)   # 距最后 ok 2100>lost 且无进展
    assert m.detection_lost_closes == 1
    assert m.tracker.tracks == {}
    assert sink.closed_objects == [(object_id, 4.1, "detection-lost")]
    assert sink.closed_events == [
        (f"front-door:async-run:event:{track_id}", "detection-lost")]

    probe_age[0] = 50.0                      # 管道恢复：任务清空（小年龄）
    for k in range(11):
        _drive_async_frame(m, True, k % 2, 4200.0 + 100.0 * k)
    assert m.detection_lost_closes == 1, "探针恢复后不得再次收口"

    ok(5500.0, 10)                           # 后续 ok 正常：新轨迹
    ok(5600.0, 11)                           # 确认 → 新告警
    assert len(sink.alarms) == 2
    assert sink.alarms[1]["track_id"] != track_id
    assert m.detection_lost_closes == 1


def test_t3_probe_none_never_false_closes():
    """T3-e：探针返回 None（仅预览/无任务）→ 即使远超失联时长也永不误报。"""
    sink = AsyncTruthSink()
    m = make_async_monitor([sink], detection_lost_ms=1000.0,
                           result_wait_ms=500.0)
    materials = []
    m.set_material_sink(materials.append)
    m.MATERIAL_LATEST_MS = 100.0
    m.MATERIAL_PATROL_MS = 100.0
    m.set_progress_probe(lambda: None)       # 仅预览/无任务

    def ok(t, fid):
        assert m.apply_detection_result(
            FakeL1Result(t, [dict(PERSON_DET)], frame_id=fid), t) is True
        _drive_async_frame(m, True, int(t) % 2, t)

    ok(1000.0, 1)
    ok(2000.0, 2)
    assert len(sink.alarms) == 1
    for k in range(41):                      # 4s >> lost 1s：持续无结果
        _drive_async_frame(m, True, k % 2, 2100.0 + 100.0 * k)
    assert m.detection_lost_closes == 0, "probe=None 不得失联误报"
    assert m.tracker.tracks, "对象轨迹保留"
    assert sink.closed_objects == []


def test_first_confirmed_event_persists_observation_before_immediate_close(tmp_path):
    sink = SqliteSink(str(tmp_path / "first-confirmation.db"))
    m = make_async_monitor([sink])
    m.timestamp_kind = "host_receive"
    for fid, t in ((1, 1000.0), (2, 1100.0)):
        assert m.apply_detection_result(
            FakeL1Result(t, [dict(PERSON_DET)], frame_id=fid), t)
        _drive_async_frame(m, True, fid, t)
    event = next(iter(m._event_facts.values()))["event_id"]
    row = sink.conn.execute("SELECT t_start,t_last,state FROM event_facts WHERE event_id=?",
                            (event,)).fetchone()
    assert row["t_start"] == 1.0
    assert row["t_last"] == 1.1
    assert row["state"] == "open"
    v1 = dict(sink.conn.execute("SELECT * FROM event_descriptions WHERE event_id=?",
                                (event,)).fetchone())
    assert m.close_all_event_facts() == 0
    row = sink.conn.execute("SELECT t_start,t_last,t_end,state FROM event_facts WHERE event_id=?",
                            (event,)).fetchone()
    assert (row["t_start"], row["t_last"], row["t_end"], row["state"]) == (1.0, 1.1, 1.1, "closed")
    assert m.close_all_event_facts() == 0
    assert dict(sink.conn.execute("SELECT * FROM event_descriptions WHERE event_id=?",
                                  (event,)).fetchone()) == v1
    sink.conn.close()


@pytest.mark.parametrize("failure", ["false", "exception"])
def test_first_confirmation_update_failure_pending_then_recovery(tmp_path, failure):
    sink = SqliteSink(str(tmp_path / "first-update-failure.db"))
    original = sink.update_event_fact

    def broken(*args, **kwargs):
        if failure == "exception":
            raise RuntimeError("injected first observation failure")
        return False

    sink.update_event_fact = broken
    m = make_async_monitor([sink])
    m.timestamp_kind = "host_receive"
    for fid, t in ((1, 1000.0), (2, 1100.0)):
        assert m.apply_detection_result(
            FakeL1Result(t, [dict(PERSON_DET)], frame_id=fid), t)
        _drive_async_frame(m, True, fid, t)
    entry = next(iter(m._event_facts.values()))
    event = entry["event_id"]
    assert entry["state"] == "pending-open"
    assert m.persistence_state()["degraded"]
    assert sink.conn.execute("SELECT t_last FROM event_facts WHERE event_id=?", (event,)).fetchone()[0] == 1.0
    sink.update_event_fact = original
    entry["next_retry_ms"] = 0.0
    for fid, t in ((3, 1200.0), (4, 1300.0)):
        assert m.apply_detection_result(
            FakeL1Result(t, [dict(PERSON_DET)], frame_id=fid), t)
        _drive_async_frame(m, True, fid, t)
    assert entry["state"] == "open"
    assert sink.conn.execute("SELECT t_start,t_last FROM event_facts WHERE event_id=?", (event,)).fetchone()["t_last"] == 1.3
    assert sink.conn.execute("SELECT count(*) FROM event_facts").fetchone()[0] == 1
    assert sink.conn.execute("SELECT count(*) FROM event_descriptions WHERE event_id=?", (event,)).fetchone()[0] == 1
    assert sink.conn.execute("SELECT count(*) FROM event_notifications WHERE kind='initial_fact' AND event_id=?", (event,)).fetchone()[0] == 1
    sink.conn.close()
