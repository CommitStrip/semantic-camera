"""scam.nvr —— NVR 常驻入口（python -m scam.nvr）。

加载场所档案（fail-closed 校验）→ 每相机一个值守线程（Monitor 快系统：
门控→检测→网格判定→告警→SQLite）→ 工作台 HTTP 随驻。
信号在主线程统一注册（SIGINT/SIGTERM → Event 优雅停机）。

区域配置真值：SQLite zones 表（工作台圈选保存的结果）优先，场所档案兜底；
启动时把档案区域种入 SQLite（工作台已保存的不覆盖）。重启后生效。
"""

import argparse
import json
import os
import signal
import sys
import threading
import time

from .config import validate_venue
from .db import connect, init_schema
from .monitor import Monitor, to_gray
from .platform import default_data_root, fix_console_encoding
from .server import WorkbenchServer, WorkbenchState
from .sinks import build_sinks
from .source import CameraSource


def _load_json(path):
    # utf-8-sig：容忍 Windows 记事本保存时加的 BOM
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def _seed_zones(conn, cams):
    """档案区域种入 zones 表（工作台已保存的相机不覆盖）。"""
    for c in cams:
        conn.execute(
            "INSERT OR IGNORE INTO zones (camera, data) VALUES (?,?)",
            (c["id"], json.dumps(c.get("zones") or [], ensure_ascii=False)))
    conn.commit()


def _zones_of(conn, camera_id, fallback):
    """读相机区域配置：SQLite 优先，档案兜底。"""
    row = conn.execute(
        "SELECT data FROM zones WHERE camera = ?", (camera_id,)).fetchone()
    if row:
        try:
            return json.loads(row["data"])
        except (TypeError, ValueError):
            pass
    return fallback


def _make_detector(det_cfg):
    """构建 NanoDet；模型缺失/加载失败时返回 None 并大声告警（绝不静默零检测）。"""
    if det_cfg.get("engine") != "onnx" or not det_cfg.get("model"):
        return None
    from .detect import NanoDet
    model = det_cfg["model"]
    if not os.path.isfile(model):
        print(f"[警告] 检测模型不存在: {model}"
              f"（该相机只跑门控，不会产生检测告警；放置模型后重启）")
        return None
    try:
        return NanoDet(model, det_cfg.get("classes", ["person"]),
                       conf=det_cfg.get("conf", 0.4))
    except Exception as e:
        print(f"[警告] 检测模型加载失败: {model}（{e}；"
              f"该相机只跑门控，不会产生检测告警）")
        return None


def _run_camera(cam_cfg, zones, db_path, stop_event, state):
    """单相机值守线程：源 → Monitor.step（门控/检测/裁决/告警全在内）。"""
    camera_id = cam_cfg["id"]
    source = CameraSource(camera_id, cam_cfg["source"])
    while not stop_event.is_set() and not source.open():
        print(f"[NVR] {camera_id} 源打开失败，5s 后重试")
        stop_event.wait(5.0)
    if stop_event.is_set():
        return

    det = _make_detector(cam_cfg.get("detector") or {})
    monitor = Monitor({**cam_cfg, "zones": zones},
                      detect_fn=(det.detect if det else (lambda f: [])),
                      sinks=build_sinks({"sqlite": db_path}))
    if state is not None:
        state.monitors[camera_id] = monitor

    print(f"[NVR] {camera_id} 值守启动"
          + ("" if det else "（无检测器：只跑门控，不产生检测告警）"))
    while not stop_event.is_set():
        ok, frame, ts = source.read()
        if not ok:
            stop_event.wait(0.5)
            continue
        now = time.time() * 1000.0
        try:
            monitor.step(frame, to_gray(frame, Monitor.GRAY_W), now)
        except Exception as e:
            print(f"[NVR] {camera_id} 单帧处理异常: {e}")
    source.close()
    if state is not None:
        state.monitors.pop(camera_id, None)
    print(f"[NVR] {camera_id} 值守结束")


def main(argv=None):
    fix_console_encoding()
    ap = argparse.ArgumentParser(description="语义摄像头 NVR 值守")
    ap.add_argument("--config", default="cameras.json")
    ap.add_argument("--db",
                    default=os.path.join(default_data_root(),
                                         "storage", "scam.db"))
    ap.add_argument("--host", default="127.0.0.1",
                    help="工作台监听地址（默认仅本机；远程走 SSH 隧道/反向代理）")
    ap.add_argument("--port", type=int, default=8600)
    ap.add_argument("--no-workbench", action="store_true")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.config):
        print(f"[NVR] 配置不存在: {args.config}")
        sys.exit(1)
    try:
        cfg = _load_json(args.config)
    except ValueError as e:
        print(f"[NVR] 配置不是合法 JSON: {e}")
        sys.exit(1)
    errs = validate_venue(cfg)
    if errs:
        print("[NVR] 场所档案校验失败（fail-closed，拒绝布防）:")
        for e in errs:
            print(f"  - {e}")
        sys.exit(1)

    cams = [c for c in cfg.get("cameras", []) if c.get("enabled", True)]
    if not cams:
        print("[NVR] 无已启用相机")
        sys.exit(1)

    os.makedirs(os.path.dirname(args.db) or ".", exist_ok=True)
    conn = connect(args.db)
    init_schema(conn)
    _seed_zones(conn, cams)
    zones_by_cam = {c["id"]: _zones_of(conn, c["id"], c.get("zones") or [])
                    for c in cams}
    conn.close()

    state = None
    server = None
    if not args.no_workbench:
        state = WorkbenchState(args.db)
        try:
            server = WorkbenchServer(state, host=args.host, port=args.port)
        except OSError as e:
            print(f"[NVR] 工作台启动失败（{e}）——值守继续，无工作台")
            server = None
            state = None

    stop_event = threading.Event()

    def _shutdown(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    threads = []
    for cam in cams:
        t = threading.Thread(
            target=_run_camera,
            args=(cam, zones_by_cam[cam["id"]], args.db, stop_event, state),
            daemon=True)
        t.start()
        threads.append(t)

    if server is not None:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"[NVR] 工作台: http://{args.host}:{args.port}")

    print(f"[NVR] 值守中（{len(cams)} 路相机，Ctrl+C 停机）")
    try:
        while not stop_event.wait(1.0):
            pass
    except KeyboardInterrupt:
        stop_event.set()
    if server is not None:
        server.shutdown()
    for t in threads:
        t.join(timeout=5)
    print("[NVR] 已停机")


if __name__ == "__main__":
    main()
