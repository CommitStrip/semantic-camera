"""scam.nvr —— NVR 常驻入口（python -m scam.nvr）。

加载场所档案 → 启动快慢双系统 → 起工作台 HTTP 服务。
systemd 常驻 / 手动运行均可。
"""

import json
import os
import signal
import sys

from .config import load_venue, validate_venue
from .db import connect, init_schema
from .source import CameraSource
from .gate import MotionGate
from .detect import NanoDet
from .track import Tracker
from .zones import Grid
from .verdict import ZoneRuntime, rule_fires
from .models import build_provider


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def nvr_main(camera_cfg, db_path, workbench_port=8600, provider=None):
    """单相机快系统值守主循环（阻塞）。"""
    from .sinks import BannerSink
    from .monitor import Monitor

    camera_id = camera_cfg["id"]
    source = CameraSource(camera_id, camera_cfg["source"])
    if not source.open():
        print(f"[NVR] {camera_id} 源打开失败: {camera_cfg['source']}")
        return

    det_cfg = camera_cfg.get("detector", {})
    det = None
    if det_cfg.get("engine") == "onnx" and det_cfg.get("model"):
        det = NanoDet(det_cfg["model"], det_cfg.get("classes", ["person"]),
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
    sinks = [lambda a: print(f"\n🚨 [{camera_id}] {a['short_name']} (dwell={a.get('dwell_s', 0):.0f}s)")]

    gate = MotionGate()
    last_det = None
    running = True

    def _signal(sig, frm):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, _signal)
    signal.signal(signal.SIGINT, _signal)

    print(f"[NVR] {camera_id} 值守启动（{len(zone_rules)} 条规则）")
    conn = connect(db_path)
    init_schema(conn)

    while running:
        ok, frame, ts = source.read()
        if not ok:
            time.sleep(1)
            continue

        gray = _to_gray(frame)
        gate = MotionGate()
        motion = gate.detect(gray, 96, max(1, round(len(gray) / 96)))

        det_results = []
        if det and (motion or _patrol_due(last_det)):
            det_results = det.detect(frame)

        tracker.update(det_results, ts * 1000)

        for t in tracker.tracks.values():
            if not t.get("confirmed"):
                continue
            cell = grid.cell_of(t["cx"], t["cy"])
            in_zone = cell in zone_cells
            if not in_zone:
                continue
            for r in zone_rules:
                if rule_fires(r, t["cls"], True,
                              (ts * 1000 - t.get("bornAt", 0)) / 1000.0):
                    eid = f"{camera_id}:alert:{t['id']}:{int(ts * 1000)}"
                    conn.execute(
                        "INSERT OR IGNORE INTO events"
                        " (event_id, camera, kind, t_processed, cls, conf,"
                        "  zone_id, template, short_name, detail, payload)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (eid, camera_id, "alert",
                         time.strftime("%Y-%m-%dT%H:%M:%S"), ts, t["cls"],
                         t["conf"], zone_id, r.get("template", ""),
                         f"重点区域{r.get('cls', '')}触发",
                         json.dumps({"dwell_s": (ts * 1000 - t.get("bornAt", 0)) / 1000.0},
                                    ensure_ascii=False)))
                    conn.commit()
                    print(f"🚨 [{camera_id}] {r.get('cls', '')} 触发 {r.get('template', '')}")
                    break

        time.sleep(0.04)  # ~25fps 门控节奏

    source.close()
    conn.close()
    print(f"[NVR] {camera_id} 值守结束")


def _to_gray(frame):
    import cv2
    h, w = frame.shape[:2]
    small = cv2.resize(frame, (96, max(1, round(96 * h / w))))
    return cv2.cvtColor(small, cv2.COLOR_BGR2GRAY).reshape(-1).tolist()


def _patrol_due(last_det):
    return last_det is None or time.time() * 1000 - last_det >= 5000


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
        t = threading.Thread(target=nvr_main, args=(cam,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
