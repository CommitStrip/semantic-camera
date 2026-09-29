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
