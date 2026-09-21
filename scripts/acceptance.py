#!/usr/bin/env python3
"""单相机实验探针（部署到 NVR 后运行，需真实摄像头流）。

诚实边界：本脚本只验收单个相机、单个进程的局部质量线，报告固定标记
`scope=single_camera_lab_probe`，顶层 `release_gate_passed` 恒为 null——
两路RTSP、systemd、24小时、资源平台期、断流恢复、准确率、证据可播放性、
隐私与运维门禁均未评估，局部子门禁通过不得推导正式发布通过。

用法: python scripts/acceptance.py [--camera front-door] [--duration 3600]
局部验收线: 快 ≤1s / 检测器 / 稳 单帧异常

度量口径：
- 告警延迟 = 告警出口收到时刻 - CameraSource 返回的可信墙钟源时间戳；
- 源时间戳缺失、不是墙钟域或样本不足时拒绝给出“≤1秒通过”结论；
- 报告保存每个原始样本并计算 P50/P95/P99，不能只用 max/avg 代替分位数；
- 检测器只实例化一次（会话内复用）；构建失败计入失败数并在报告判 FAIL；
- 单帧异常只计数不中断浸泡，报告中如实列出（不吞异常）。
"""

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scam.config import validate_venue
from scam.monitor import Monitor, to_gray
from scam.source import CameraSource


# 单相机实验探针未评估的正式发布门禁（如实列出，报告中原样携带）
UNEVALUATED_GATES = [
    "dual_rtsp_sources",
    "systemd_service",
    "soak_24h",
    "resource_plateau",
    "stream_recovery",
    "detection_accuracy",
    "evidence_playability",
    "privacy",
    "operations",
]


class _Collector:
    """验收出口：收告警 + 端到端延迟（告警落定 - 帧源时间戳）。"""

    def __init__(self):
        self.alarms = []
        self.latencies = []
        self.samples = []

    def __call__(self, alarm):
        delivered_at = time.time()
        self.alarms.append(alarm)
        source_at = float(alarm["t_source"])
        lat_ms = max(0.0, (delivered_at - source_at) * 1000.0)
        self.latencies.append(lat_ms)
        self.samples.append({
            "event_id": alarm.get("event_id"),
            "source_at": source_at,
            "delivered_at": delivered_at,
            "latency_ms": lat_ms,
        })


def _source_seconds(value, wall_now=None, max_skew_s=300.0):
    """把源时间戳规范为Unix秒，并拒绝处理时钟或媒体相对PTS冒充墙钟。"""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError("相机源未提供数值时间戳")
    source_s = float(value)
    if source_s > 10_000_000_000:  # 毫秒Unix时间戳
        source_s /= 1000.0
    wall_now = time.time() if wall_now is None else wall_now
    skew = abs(wall_now - source_s)
    if skew > max_skew_s:
        raise ValueError(
            f"源时间戳不在墙钟域（与本机相差 {skew:.1f}s）")
    return source_s


def _percentile(values, p):
    """线性插值分位数；输入为空时返回None。"""
    if not values:
        return None
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * p
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def run(camera_id, duration_s, cfg, *, report_path="acceptance-report.json",
        config_path=None, min_alert_samples=20):
    cam = next((c for c in cfg.get("cameras", []) if c.get("id") == camera_id),
               None)
    if not cam:
        print(f"[FAIL] 相机 {camera_id} 不在配置中")
        sys.exit(1)

    source = CameraSource(camera_id, cam["source"])
    if not source.open():
        print("[FAIL] 无法打开相机流")
        sys.exit(1)
    print("[OK] 流已连接")

    exit_ok = False
    try:
        # 从流打开到退出判定的任何异常都先经 finally 释放相机源，
        # 且原异常照常上抛，不吞掉、不伪造成功报告。
        timestamp_kind = (source.stats or {}).get("timestamp_kind", "unknown")

        det, det_err = _make_detector(cam.get("detector") or {})
        collector = _Collector()
        monitor = Monitor(cam, detect_fn=(det.detect if det else (lambda f: [])),
                          sinks=[collector])

        metrics = {"frames": 0, "motion_frames": 0, "stream_drops": 0,
                   "frame_errors": 0, "first_error": None,
                   "timestamp_errors": 0, "first_timestamp_error": None,
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
            try:
                source_s = _source_seconds(ts)
                monitor.step(
                    frame, to_gray(frame, Monitor.GRAY_W), source_s * 1000.0)
            except ValueError as e:
                metrics["timestamp_errors"] += 1
                if metrics["first_timestamp_error"] is None:
                    metrics["first_timestamp_error"] = str(e)
            except Exception as e:
                metrics["frame_errors"] += 1
                if metrics["first_error"] is None:
                    metrics["first_error"] = f"{type(e).__name__}: {e}"
            if monitor.gate.last_ratio > 0:
                metrics["motion_frames"] += 1

        elapsed = time.time() - t0
        lat = collector.latencies
        percentiles = {
            "p50": _percentile(lat, 0.50),
            "p95": _percentile(lat, 0.95),
            "p99": _percentile(lat, 0.99),
        }

        print(f"\n{'=' * 60}")
        print(f"单相机实验探针报告（{camera_id}，运行 {elapsed:.0f}s）")
        print(f"{'=' * 60}")
        print(f"帧数: {metrics['frames']} | 运动帧: {metrics['motion_frames']}"
              f" | 告警数: {len(collector.alarms)}"
              f" | 断流: {metrics['stream_drops']}")

        enough_samples = len(lat) >= min_alert_samples
        timestamp_provenance_ok = timestamp_kind == "source_capture"
        ok_fast = (enough_samples and metrics["timestamp_errors"] == 0 and
                   timestamp_provenance_ok and
                   percentiles["p95"] <= 1000.0)
        print(f"[{'OK' if ok_fast else 'FAIL'}] 快·告警延迟: "
              f"P50={percentiles['p50']:.0f}ms "
              f"P95={percentiles['p95']:.0f}ms "
              f"P99={percentiles['p99']:.0f}ms "
              f"n={len(lat)}（验收线 P95≤1000ms，n≥{min_alert_samples}）"
              if lat else
              "[FAIL] 快·告警延迟: 无告警样本（无检测器或无触发，无法度量）")
        if lat and not enough_samples:
            print(f"[FAIL] 快·样本量: {len(lat)} < {min_alert_samples}，"
                  "不得据此声明P95通过")
        print(f"[{'OK' if metrics['timestamp_errors'] == 0 else 'FAIL'}] "
              f"快·源时间戳: {metrics['timestamp_errors']} 次非法"
              + (f"（首次: {metrics['first_timestamp_error']}）"
                 if metrics["first_timestamp_error"] else ""))
        print(f"[{'OK' if timestamp_provenance_ok else 'FAIL'}] "
              f"快·时间戳来源: {timestamp_kind}"
              + ("" if timestamp_provenance_ok else
                 "（只有source_capture可用于端到端质量门禁；"
                 "host_receive/unknown只能作为处理链观察值）"))

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
        print(f"[INFO] 发布门禁: 未评估（单相机实验探针不构成正式验收；"
              f"未评估项 {len(UNEVALUATED_GATES)} 类，见报告）")
        print(f"{'=' * 60}")

        report = {
            "schema_version": 2,
            "scope": "single_camera_lab_probe",
            "release_gate_passed": None,
            "unevaluated_gates": list(UNEVALUATED_GATES),
            "camera": camera_id,
            "started_at": metrics["start"],
            "ended_at": time.time(),
            "duration_s": elapsed,
            "config_sha256": _sha256(config_path) if config_path else None,
            "model_sha256": (_sha256(cam["detector"]["model"])
                             if det is not None else None),
            "metrics": metrics,
            "latency": {
                "definition": "alarm_sink_received_at - source_adapter_timestamp",
                "timestamp_kind": timestamp_kind,
                "timestamp_provenance_passed": timestamp_provenance_ok,
                "sample_count": len(lat),
                "minimum_required": min_alert_samples,
                "p50_ms": percentiles["p50"],
                "p95_ms": percentiles["p95"],
                "p99_ms": percentiles["p99"],
                "passed": ok_fast,
                "samples": collector.samples,
            },
            "gates": {
                "detector": ok_detector,
                "frame_processing": ok_stable,
                "source_timestamps": metrics["timestamp_errors"] == 0,
                "source_timestamp_provenance": timestamp_provenance_ok,
                "fast_latency": ok_fast,
            },
        }
        report_dir = os.path.dirname(os.path.abspath(report_path))
        os.makedirs(report_dir, exist_ok=True)
        report_bytes = (json.dumps(report, ensure_ascii=False, indent=2)
                        + "\n").encode("utf-8")
        fd, temp_report = tempfile.mkstemp(
            prefix=os.path.basename(os.path.abspath(report_path)) + ".",
            suffix=".tmp", dir=report_dir)
        try:
            with os.fdopen(fd, "wb") as handle:
                fd = None
                handle.write(report_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_report, os.path.abspath(report_path))
        except BaseException:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(temp_report)
            except FileNotFoundError:
                pass
            raise
        print(f"原始验收报告: {os.path.abspath(report_path)}")

        exit_ok = ok_fast and ok_detector and ok_stable
    except BaseException as original:
        try:
            source.close()
        except Exception as close_error:
            note = ("相机源关闭也失败，但保留原始异常: "
                    f"{type(close_error).__name__}: {close_error}")
            if hasattr(original, "add_note"):
                original.add_note(note)
            else:
                print(f"[WARN] {note}", file=sys.stderr)
        raise
    else:
        source.close()

    if not exit_ok:
        sys.exit(1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="单相机实验探针（非总发布门禁）")
    ap.add_argument("--camera", default="front-door")
    ap.add_argument("--duration", type=int, default=3600, help="浸泡秒数")
    ap.add_argument("--config", default="cameras.json")
    ap.add_argument("--report", default="acceptance-report.json")
    ap.add_argument("--min-alert-samples", type=int, default=20)
    args = ap.parse_args()

    def safe_output_path(raw: str) -> str:
        """规范化输出路径并禁止越出脚本工作目录（防相对路径穿越）。"""
        base = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
        resolved = os.path.abspath(os.path.join(base, raw))
        if not (resolved == base or resolved.startswith(base + os.sep)):
            ap.error(f"--report 必须位于 {base} 内")
        return resolved

    args.report = safe_output_path(args.report)

    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    errs = validate_venue(cfg)
    if errs:
        print("[FAIL] 场所档案校验失败: " + "; ".join(errs))
        sys.exit(1)
    if args.min_alert_samples < 1:
        print("[FAIL] --min-alert-samples 必须 ≥1")
        sys.exit(1)
    run(args.camera, args.duration, cfg, report_path=args.report,
        config_path=args.config, min_alert_samples=args.min_alert_samples)
