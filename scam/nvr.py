"""scam.nvr —— NVR 常驻入口。

加载场所档案 → 启动工作台 HTTP → 逐相机值守线程（快慢双系统）。
systemd 常驻 / 手动运行均可。
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


def _run_camera(camera_cfg, db_conn, state, stop_event):
    """单相机值守线程：门控→检测→裁决→告警（复用 Monitor，零重复）。"""
    camera_id = camera_cfg["id"]

    source = CameraSource(camera_id, camera_cfg["source"])
    if not source.open():
        print(f"[NVR] {camera_id} 源打开失败")
        return

    det_cfg = camera_cfg.get("detector") or {}
    det = None
    if det_cfg.get("engine") == "onnx" and det_cfg.get("model"):
        from .detect import NanoDet
        det = NanoDet(det_cfg["model"],
                      det_cfg.get("classes", ["person"]),
                      conf=det_cfg.get("conf", 0.4))

    grid = Grid(**(camera_cfg.get("grid") or {"rows": 18, "cols": 22}))
    zone_cells = set()
    zone_rules = []
    zone_id = camera_id + ":main"
    for z in camera_cfg.get("zones") or []:
        zone_cells.update(z.get("cells") or [])
        zone_id = z["id"]
        zone_rules.extend(z.get("rules") or [])

    tracker = Tracker()
    zone_rt = ZoneRuntime()
    last_alarm_ms = {}      # (track_id, zone_id) → 冷却
    cooldown_ms = 30000     # 同轨迹同区域 30s 冷却

    print(f"[NVR] {camera_id} 值守启动（{len(zone_rules)} 条规则）")
    conn = connect(state.db_path)
    init_schema(conn)

    while not stop_event.is_set():
        ok, frame, ts = source.read()
        if not ok:
            stop_event.wait(0.5)
            continue
        now_ms = time.time() * 1000.0

        # 门控
        gate = MotionGate()
        gray = _to_gray(frame)
        motion = gate.detect(gray, 96, max(1, round(len(gray) / 96)))

        # 检测（触发节奏：有运动 400ms / 无运动 5s）
        det_results = []
        if motion or _patrol_due(last_det_ms, now_ms):
            det_results = det.detect(frame) if det else []
            tracker.update(det_results, now_ms)

        # 区域判定 + 告警（含冷却）
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
                last = last_alarm_ms.get(ckey, 0)
                if now_ms - last < 30000:
                    continue
                last_alarm_ms[ckey] = now_ms
                eid = f"{camera_id}:alert:{t['id']}:{zone_id}"
                conn.execute(
                    "INSERT OR IGNORE INTO events"
                    " (event_id, camera, kind, t_processed, t_source,"
                    "  cls, conf, zone_id, template, short_name, detail,"
                    "  payload) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (eid, camera_id, "alert",
                     time.strftime("%Y-%m-%dT%H:%M:%S"), ts / 1000.0,
                     t["cls"], t["conf"], zone_id,
                     r.get("template", ""),
                     f"重点区域{r.get('cls', '')}触发",
                     f"滞留 {dwell_s:.0f}s",
                     json.dumps({"dwell_s": dwell_s},
                                ensure_ascii=False)))
                conn.commit()
                print(f"🚨 [{camera_id}] {r.get('cls', '')} 告警")
                break

        time.sleep(0.04)

    conn.close()
    print(f"[NVR] {camera_id} 值守结束")


def _to_gray(frame):
    import cv2
    h, w = frame.shape[:2]
    small = cv2.resize(frame, (96, max(1, round(96 * h / w))))
    return cv2.cvtColor(small, cv2.COLOR_BGR2GRAY).reshape(-1).tolist()


def main():
    """NVR 常驻入口：读 cameras.json → 逐相机值守。"""
    base = os.path.dirname(os.path.abspath(__file__))
    cfg_path = os.path.join(base, "..", "cameras.json")
    if not os.path.isfile(cfg_path):
        cfg_path = "cameras.json"
    with open(cfg_path, encoding="utf-8") as f:
        cfg = json.load(f)

    cams = [c for c in cfg.get("cameras", []) if c.get("enabled", True)]
    if not cams:
        print("[NVR] 无已启用相机——请编辑 cameras.json")
        sys.exit(1)

    threads = []
    for cam in cams:
        t = threading.Thread(target=_run_camera,
                             args=(cam, None, None, threading.Event()),
                             daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
