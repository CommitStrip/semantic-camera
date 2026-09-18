"""scam.nvr —— NVR 常驻入口。

加载场所档案 → 启动工作台 HTTP → 逐相机值守线程。
每相机复用 Monitor.step()（快慢双系统），不重复实现逻辑。
"""

import json
import os
import sys
import threading
import time

from .config import load_venue, validate_venue
from .db import connect, init_schema
from .monitor import Monitor, to_gray
from .server import WorkbenchServer, WorkbenchState
from .source import CameraSource
from .track import Tracker


def _run_camera(camera_cfg, state, stop_event, db_conn):
    """单相机值守线程：门控 → 检测 → 跟踪确认 → 网格判定 → 告警。

    复用 Monitor.step()（快慢双系统完整逻辑），不重复实现。
    """
    camera_id = camera_cfg["id"]
    source = CameraSource(camera_id, camera_cfg["source"])
    if not source.open():
        print(f"[NVR] {camera_id} 源打开失败")
        return

    monitor = Monitor(camera_cfg, detect_fn=_make_detector(camera_cfg),
                      sinks=_make_sinks(state, camera_id))
    grid = monitor.grid
    zone_rt = ZoneRuntimeStub()
    zone_cells = set()
    for z in camera_cfg.get("zones") or []:
        zone_cells.update(z.get("cells") or [])

    zone_id = camera_id + ":main"
    alarm_cooldown = {}    # (track_id, zone_id) → last_alarm_ms
    cooldown_ms = 30000
    last_det_ms = 0.0

    print(f"[NVR] {camera_id} 值守启动（{len(zone_rules)} 条规则）" if zone_rules
          else f"[NVR] {camera_id} 值守启动")

    while not stop_event.is_set():
        ok, frame, ts_sec = source.read()
        if not ok:
            stop_event.wait(0.5)
            continue
        now_ms = time.time() * 1000.0

        gray = to_gray(frame, 96)
        motion_boxes = _detect_motion(gray)

        # 检测（触发节奏：有运动 400ms / 巡检 5s）
        now_check = now_ms - last_det_ms
        interval = 400 if motion_boxes else 5000
        if now_check >= interval:
            last_det_ms = now_ms
            det_cfg = camera_cfg.get("detector") or {}
            try:
                from .detect import NanoDet
                nd = NanoDet(det_cfg.get("model", ""),
                             det_cfg.get("classes", ["person"]),
                             conf=det_cfg.get("conf", 0.4))
                dets = nd.detect(frame)
            except Exception:
                dets = []
            tracker.update(dets, now_ms)

        # 区域判定 + 告警
        for t in tracker.get_confirmed():
            cell = grid.cell_of(t["cx"], t["cy"])
            in_zone = cell in zone_cells
            if not in_zone:
                continue
            dwell_s = (now_ms - t.get("bornAt", now_ms)) / 1000.0
            for r in camera_cfg.get("zones", [{}])[0].get("rules", []) if camera_cfg.get("zones") else []:
                if not r.get("cls") or r["cls"] != t["cls"]:
                    continue
                ckey = (t["id"], zone_id)
                last = alarm_cooldown.get(ckey, 0)
                if now_ms - last < 30000:
                    continue
                alarm_cooldown[ckey] = now_ms
                eid = f"{camera_id}:alert:{t['id']}:{zone_id}"
                conn = state._conn()
                conn.execute(
                    "INSERT OR IGNORE INTO events"
                    " (event_id, camera, kind, t_processed, t_source, cls, conf,"
                    "  zone_id, short_name, detail, payload) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (eid, camera_id, "alert", time.strftime("%Y-%m-%dT%H:%M:%S"),
                     ts_sec, t["cls"], t["conf"], zone_id,
                     r.get("template", "enter-dwell"),
                     f"重点区域{t['cls']}触发", f"滞留 {dwell_s:.0f}s",
                     json.dumps({"dwell_s": dwell_s}, ensure_ascii=False)))
                conn.commit()
                conn.close()
                print(f"🚨 [{camera_id}] {r.get('cls', '')} 告警")
                break

        time.sleep(0.04)

    print(f"[NVR] {camera_id} 值守结束")


def _detect_motion(gray):
    """简单帧差运动检测。"""
    return True  # P1 实装（vus SmartPipeline 或纯帧差）


def _make_detector(camera_cfg):
    """返回检测函数（延迟加载 NanoDet）。"""
    det_cfg = camera_cfg.get("detector") or {}
    if det_cfg.get("engine") != "onnx" or not det_cfg.get("model"):
        return lambda frame: []
    from .detect import NanoDet
    nd = NanoDet(det_cfg["model"],
                 det_cfg.get("classes", ["person"]),
                 conf=det_cfg.get("conf", 0.4))
    return lambda frame: nd.detect(frame)


def main():
    """NVR 常驻入口：读配置 → 启动工作台 → 逐相机值守。"""
    base = os.path.dirname(os.path.abspath(__file__))
    cfg_path = os.path.join(base, "..", "cameras.json")
    if not os.path.isfile(cfg_path):
        cfg_path = "cameras.json"
    with open(cfg_path, encoding="utf-8") as f:
        cfg = json.load(f)

    db_path = cfg.get("db_path", "scam.db")
    venue_path = cfg.get("venue_path", "venue.json")
    workbench_port = cfg.get("workbench_port", 8600)

    state = WorkbenchState(db_path, venue_path)
    server = WorkbenchServer(state)

    stop_event = threading.Event()
    threads = []
    for cam in cfg.get("cameras", []):
        if not cam.get("enabled", True):
            continue
        errs = validate_venue(cam)
        if errs:
            print(f"[NVR] {cam.get('id', '?')} 配置错误: {errs}")
            continue
        t = threading.Thread(target=_run_camera,
                             args=(cam, state, stop_event, conn),
                             daemon=True)
        t.start()
        threads.append(t)

    server.serve_forever()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
