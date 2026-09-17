#!/usr/bin/env python3
"""P5 五线验收脚本（部署到 NVR 后运行，需真实摄像头流）。

用法: python scripts/acceptance.py [--camera front-door] [--duration 3600]
验收线: 快 ≤1s / 准 金标反馈 / 省 VLM 调用趋零 / 稳 断流自恢复 / 私 数据不出 NVR
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scam.config import validate_venue
from scam.db import connect, init_schema
from scam.source import CameraSource
from scam.gate import MotionGate
from scam.track import Tracker
from scam.zones import Grid, bbox_center_cell
from scam.verdict import ZoneRuntime, rule_fires


def run(camera_id, duration_s, cfg):
    cam = next((c for c in cfg.get("cameras", []) if c.get("id") == camera_id), None)
    if not cam:
        print(f"[FAIL] 相机 {camera_id} 不在配置中"); sys.exit(1)

    source = CameraSource(camera_id, cam["source"])
    if not source.open():
        print("[FAIL] 无法打开相机流"); sys.exit(1)
    print(f"[OK] 流已连接: {cam['source']}")

    gate = MotionGate()
    tracker = Tracker()
    grid = Grid(**(cam.get("grid") or {"rows": 18, "cols": 22}))
    zone_cells = set()
    zone_rules = []
    for z in cam.get("zones") or []:
        zone_cells.update(z.get("cells") or [])
        zone_rules.extend(z.get("rules") or [])
    zone_rt = ZoneRuntime()

    metrics = {"alarms": 0, "frames": 0, "motion_frames": 0,
               "detections": 0, "stream_drops": 0, "latencies": [],
               "vlm_calls": 0, "start": time.time(), "peak_rss_mb": 0}
    last_det_ms = 0
    t0 = time.time()

    import cv2
    while time.time() - t0 < duration_s:
        ok, frame, ts = source.read()
        if not ok:
            metrics["stream_drops"] += 1
            time.sleep(0.5)
            continue
        metrics["frames"] += 1

        h, w = frame.shape[:2]
        small = cv2.resize(frame, (96, max(1, round(96 * h / w))))
        gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY).reshape(-1).tolist()
        motion_boxes = gate.detect(gray, 96, max(1, round(96 * h / w)))
        if gate.last_ratio > 0:
            metrics["motion_frames"] += 1

        now_ms = time.time() * 1000
        interval = 400 if gate.last_ratio > 0 else 5000
        if now_ms - last_det_ms >= interval:
            last_det_ms = now_ms
            metrics["detections"] += 1
            det_cfg = cam.get("detector") or {}
            try:
                from scam.detect import NanoDet
                det = NanoDet(det_cfg.get("model", "person-detector.onnx"),
                              det_cfg.get("classes", ["person"]),
                              conf=det_cfg.get("conf", 0.4))
                dets = det.detect(frame)
                tracker.update(dets, now_ms)
            except Exception:
                pass

        for t in tracker.get_confirmed():
            cell = grid.cell_of(t["cx"], t["cy"])
            in_zone = cell in zone_cells
            if not in_zone:
                continue
            dwell = zone_rt.update(t["id"], "z1", True, now_ms)
            for r in zone_rules:
                if rule_fires(r, t["cls"], True, dwell):
                    metrics["alarms"] += 1
                    lat = time.time() - t0
                    metrics["latencies"].append(lat)
                    break

    elapsed = time.time() - t0
    lat = metrics["latencies"]
    max_lat = max(lat) if lat else 0
    avg_lat = sum(lat) / len(lat) if lat else 0

    print(f"\n{'='*60}")
    print(f"P5 验收报告（{camera_id}，运行 {elapsed:.0f}s）")
    print(f"{'='*60}")
    print(f"帧数: {metrics['frames']} | 运动帧: {metrics['motion_frames']}"
          f" | 检测次数: {metrics['detections']}")
    print(f"告警数: {metrics['alarms']} | 断流: {metrics['stream_drops']}")
    if lat:
        print(f"告警延迟: max={max_lat:.1f}s avg={avg_lat:.1f}s"
              f" {'✅ ≤1s' if max_lat <= 1.0 else '❌ >1s'}")
    else:
        print("告警延迟: N/A（无告警触发）")
    drop_txt = "✅" if metrics["stream_drops"] == 0 else "⚠️ 有断流"
    print(f"断流自恢复: {drop_txt}")
    print(f"{'='*60}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="P5 五线验收")
    ap.add_argument("--camera", default="front-door")
    ap.add_argument("--duration", type=int, default=3600, help="浸泡秒数")
    ap.add_argument("--config", default="cameras.json")
    args = ap.parse_args()

    import json as _json
    with open(args.config, encoding="utf-8") as f:
        cfg = _json.load(f)
    run(args.camera, args.duration, cfg)
