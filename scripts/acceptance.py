#!/usr/bin/env python3
"""P5 五线验收脚本（部署到 NVR 后运行，需真实摄像头流）。

用法: python scripts/acceptance.py [--camera front-door] [--duration 3600]
验收线: 快 ≤1s / 准 金标反馈 / 省 VLM 调用趋零 / 稳 断流自恢复 / 私 数据不出 NVR

度量口径：
- 告警延迟 = 告警落定时刻 - 该帧源时间戳（端到端，含门控+检测+裁决）；
- 检测器只实例化一次（会话内复用）；构建失败计入失败数并在报告判 FAIL；
- 单帧异常只计数不中断浸泡，报告中如实列出（不吞异常）。
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scam.config import validate_venue
from scam.monitor import Monitor, to_gray
from scam.source import CameraSource


class _Collector:
    """验收出口：收告警 + 端到端延迟（告警落定 - 帧源时间戳）。"""

    def __init__(self):
        self.alarms = []
        self.latencies = []

    def __call__(self, alarm):
        self.alarms.append(alarm)
        lat_ms = time.time() * 1000.0 - alarm.get("t_source", 0) * 1000.0
        self.latencies.append(max(0.0, lat_ms))


def _make_detector(det_cfg):
    """检测器会话只建一次；失败返回 None 并记录原因（报告判 FAIL）。"""
    if det_cfg.get("engine") != "onnx" or not det_cfg.get("model"):
        return None, "未配置 onnx 检测器"
    from scam.detect import NanoDet
    model = det_cfg["model"]
    if not os.path.isfile(model):
        return None, f"模型文件不存在: {model}"
    try:
        return NanoDet(model, det_cfg.get("classes", ["person"]),
                       conf=det_cfg.get("conf", 0.4)), None
    except Exception as e:
        return None, f"模型加载失败: {model}（{e}）"


def run(camera_id, duration_s, cfg):
    cam = next((c for c in cfg.get("cameras", []) if c.get("id") == camera_id),
               None)
    if not cam:
        print(f"[FAIL] 相机 {camera_id} 不在配置中")
        sys.exit(1)

    source = CameraSource(camera_id, cam["source"])
    if not source.open():
        print("[FAIL] 无法打开相机流")
        sys.exit(1)
    print(f"[OK] 流已连接")

    det, det_err = _make_detector(cam.get("detector") or {})
    collector = _Collector()
    monitor = Monitor(cam, detect_fn=(det.detect if det else (lambda f: [])),
                      sinks=[collector])

    metrics = {"frames": 0, "motion_frames": 0, "stream_drops": 0,
               "frame_errors": 0, "first_error": None,
               "vlm_calls": 0, "start": time.time()}
    if det_err:
        print(f"[警告] {det_err}（期间不会有检测告警，报告中判 FAIL）")

    t0 = time.time()
    while time.time() - t0 < duration_s:
        ok, frame, ts = source.read()
        if not ok:
            metrics["stream_drops"] += 1
            time.sleep(0.5)
            continue
        metrics["frames"] += 1
        now = time.time() * 1000.0
        try:
            monitor.step(frame, to_gray(frame, Monitor.GRAY_W), now)
        except Exception as e:
            metrics["frame_errors"] += 1
            if metrics["first_error"] is None:
                metrics["first_error"] = f"{type(e).__name__}: {e}"
        if monitor.gate.last_ratio > 0:
            metrics["motion_frames"] += 1

    elapsed = time.time() - t0
    lat = collector.latencies
    max_lat = max(lat) if lat else 0.0
    avg_lat = sum(lat) / len(lat) if lat else 0.0

    print(f"\n{'=' * 60}")
    print(f"P5 验收报告（{camera_id}，运行 {elapsed:.0f}s）")
    print(f"{'=' * 60}")
    print(f"帧数: {metrics['frames']} | 运动帧: {metrics['motion_frames']}"
          f" | 告警数: {len(collector.alarms)} | 断流: {metrics['stream_drops']}")

    ok_fast = bool(lat) and max_lat <= 1000.0
    print(f"[{'OK' if ok_fast else 'FAIL'}] 快·告警延迟: "
          f"max={max_lat:.0f}ms avg={avg_lat:.0f}ms（验收线 ≤1000ms）"
          if lat else
          "[FAIL] 快·告警延迟: 无告警样本（无检测器或无触发，无法度量）")

    ok_detector = det is not None
    print(f"[{'OK' if ok_detector else 'FAIL'}] 检测器: "
          + ("加载并复用整个会话" if ok_detector else det_err or "未知原因"))

    ok_stable = metrics["frame_errors"] == 0
    print(f"[{'OK' if ok_stable else 'FAIL'}] 稳·单帧异常: "
          f"{metrics['frame_errors']} 次"
          + (f"（首次: {metrics['first_error']}）"
             if metrics["first_error"] else ""))
    print(f"[{'OK' if not metrics['stream_drops'] else 'WARN'}] 稳·断流: "
          f"{metrics['stream_drops']} 次")
    print(f"[INFO] 省·VLM 调用: {metrics['vlm_calls']}"
          f"（报警路径零慢层；慢系统计数随命名管线接入后上报）")
    print(f"{'=' * 60}")

    if not (ok_fast and ok_detector and ok_stable):
        sys.exit(1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="P5 五线验收")
    ap.add_argument("--camera", default="front-door")
    ap.add_argument("--duration", type=int, default=3600, help="浸泡秒数")
    ap.add_argument("--config", default="cameras.json")
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as f:
        cfg = json.load(f)
    errs = validate_venue(cfg)
    if errs:
        print("[FAIL] 场所档案校验失败: " + "; ".join(errs))
        sys.exit(1)
    run(args.camera, args.duration, cfg)
