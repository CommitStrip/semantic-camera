"""scam.nvr —— NVR 常驻入口（python -m scam.nvr）。

加载 cameras.json → 逐相机值守线程（门控→检测→网格判定→告警→SQLite）。
Ctrl+C / SIGTERM 优雅停机。
"""

import json
import os
import signal
import sys
import threading
import time

from .config import validate_venue
from .db import connect, init_schema
from .gate import MotionGate
from .source import CameraSource
from .track import Tracker
from .verdict import rule_fires
from .zones import Grid, bbox_center_cell


def _to_gray(frame, gw=96):
    import cv2
    h, w = frame.shape[:2]
    gh = max(1, round(gw * h / w))
    small = cv2.resize(frame, (gw, gh))
    return cv2.cvtColor(small, cv2.COLOR_BGR2GRAY).reshape(-1).tolist()


def _run_camera(camera_cfg, db_conn, stop_event):
    """单相机值守线程：门控 → 检测 → 跟踪 → 网格判定 → 告警 → SQLite。"""
    camera_id = camera_cfg["id"]
    source = CameraSource(camera_id, camera_cfg["source"])
    if not source.open():
        print(f"[NVR] {camera_id} 源打开失败")
        return

    det = None
    det_cfg = camera_cfg.get("detector") or {}
    if det_cfg.get("engine") == "onnx" and det_cfg.get("model"):
        from .detect import NanoDet
        det = NanoDet(det_cfg["model"],
                      det_cfg.get("classes", ["person"]),
                      conf=det_cfg.get("conf", 0.4))

    grid = Grid(**(camera_cfg.get("grid") or {"rows": 18, "cols": 22}))
    zone_cells = set()
    zone_rules = []
    for z in camera_cfg.get("zones") or []:
        zone_cells.update(z.get("cells") or [])
        zone_id = z["id"]
        zone_rules.extend(z.get("rules") or [])

    tracker = Tracker()
    gate = MotionGate()
    zone_rt = ZoneRuntimeStub()
    alarm_cooldown = {}
    last_det_ms = 0.0

    print(f"[NVR] {camera_id} 值守启动")
    conn = db_conn

    while not stop_event.is_set():
        ok, frame, ts_sec = source.read()
        if not ok:
            stop_event.wait(0.5)
            continue
        now_ms = time.time() * 1000.0

        gray = _to_gray(frame, 96)
        motion = gate.detect(gray, 96, max(1, round(len(gray) / 96)))

        if det and (motion or now_ms - last_det_ms >= 5000):
            det_results = det.detect(frame)
            tracker.update(det_results, now_ms)
            last_det_ms = now_ms

        for t in tracker.get_confirmed():
            cell = grid.cell_of(t["cx"], t["cy"])
            in_zone = cell in zone_cells
            if not in_zone:
                continue
            dwell_s = (now_ms - t.get("bornAt", now_ms)) / 1000.0
            for r in zone_rules:
                if not rule_fires(r, t["cls"], True, dwell_s):
                    continue
                ckey = (t["id"], zone_id)
                last = alarm_cooldown.get(ckey, 0)
                if now_ms - last < 30000:
                    continue
                alarm_cooldown[ckey] = now_ms
                eid = f"{camera_id}:alert:{t['id']}:{zone_id}"
                conn.execute(
                    "INSERT OR IGNORE INTO events"
                    " (event_id, camera, kind, t_processed, t_source,"
                    "  cls, conf, zone_id, template, short_name, detail,"
                    "  payload) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (eid, camera_id, "alert",
                     time.strftime("%Y-%m-%dT%H:%M:%S"), ts_sec,
                     t["cls"], t["conf"], zone_id,
                     r.get("template", ""),
                     f"重点区域{t['cls']}触发",
                     f"滞留 {dwell_s:.0f}s",
                     json.dumps({"dwell_s": dwell_s},
                                ensure_ascii=False)))
                conn.commit()
                print(f"🚨 [{camera_id}] {r.get('cls', '')} 告警")
                break

        time.sleep(0.04)

    print(f"[NVR] {camera_id} 值守结束")


class ZoneRuntimeStub:
    def update(self, *a): pass
    def leave(self, *a): pass


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    cfg_path = os.path.join(base, "..", "cameras.json")
    if not os.path.isfile(cfg_path):
        cfg_path = "cameras.json"
    with open(cfg_path, encoding="utf-8") as f:
        cfg = json.load(f)

    cams = [c for c in cfg.get("cameras", []) if c.get("enabled", True)]
    if not cams:
        print("[NVR] 无已启用相机")
        sys.exit(1)

    stop_event = threading.Event()
    threads = []
    for cam in cams:
        t = threading.Thread(target=_run_camera, args=(cam, None, stop_event),
                             daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
