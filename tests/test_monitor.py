"""monitor 快系统端到端测试：门控→检测节奏→网格判定→告警 ≤1s（P1 验收）。"""

import numpy as np
import pytest

from scam.monitor import Monitor, to_gray
from scam.sinks import JsonlSink
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
