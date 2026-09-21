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
import shutil
import signal
import sys
import threading
import time

from .config import validate_venue
from .db import connect, init_schema, recover_stale_records
from .monitor import Monitor, to_gray
from .editions import get_edition
from .health import HealthRegistry
from .platform import fix_console_encoding
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


def _recover_event_truth(conn, *, now=None, stale_after_s=30.0):
    """启动时收口异常退出遗留的开放事实，并公开恢复数量。"""
    counts = recover_stale_records(
        conn, now=time.time() if now is None else now,
        stale_after_s=stale_after_s)
    recovered = sum(counts.values())
    if recovered:
        print("[NVR] 已恢复上次异常退出遗留记录: "
              f"对象 {counts['tracked_objects']}，"
              f"审查段 {counts['review_segments']}，"
              f"语义事件 {counts['semantic_events']}")
    return counts


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


def _run_camera(cam_cfg, zones, db_path, stop_event, state, watchdog=None):
    """单相机值守线程：源 → Monitor.step（门控/检测/裁决/告警全在内）。

    值守消费 detect 角色（source_kind 决定源类型；detect_source 可覆盖 source）；
    record 角色与录像接线属 L2（Z3），配置缺省不开录像。
    """
    camera_id = cam_cfg["id"]
    source_kind = cam_cfg.get("source_kind", "rtsp")
    detect_url = cam_cfg.get("detect_source") or cam_cfg["source"]
    source = CameraSource(camera_id, detect_url, source_kind=source_kind)
    if watchdog is not None:
        watchdog.started()
    had_open_failure = False
    while not stop_event.is_set() and not source.open():
        had_open_failure = True
        if watchdog is not None:
            watchdog.failure("open", "source open failed")
        print(f"[NVR] {camera_id} 源打开失败，5s 后重试")
        stop_event.wait(5.0)
    if stop_event.is_set():
        source.close()
        if watchdog is not None:
            watchdog.stopped()
        return

    if watchdog is not None:
        watchdog.opened(reconnect=had_open_failure)

    try:
        det = _make_detector(cam_cfg.get("detector") or {})
        monitor = Monitor({**cam_cfg, "zones": zones},
                          detect_fn=(det.detect if det else (lambda f: [])),
                          sinks=build_sinks({"sqlite": db_path}))
        if state is not None:
            state.monitors[camera_id] = monitor

        print(f"[NVR] {camera_id} 值守启动"
              + ("" if det else "（无检测器：只跑门控，不产生检测告警）"))
        recovering = False
        while not stop_event.is_set():
            ok, frame, ts = source.read()
            if not ok:
                recovering = True
                if watchdog is not None:
                    watchdog.failure("read", "source read failed")
                stop_event.wait(0.5)
                continue
            # 真实源时间戳贯穿：仅当源显式证明 source_capture 才采用采集时间；
            # host_receive 含解码等待、unknown 无法溯源——都不能冒充采集时刻
            # （L4 验收口径），此时退回墙钟处理时间。
            kind = (source.stats or {}).get("timestamp_kind")
            if watchdog is not None:
                if recovering:
                    watchdog.opened(reconnect=True)
                    recovering = False
                watchdog.frame(source_ts=ts, timestamp_kind=kind)
            now = (ts * 1000.0) if (ts and kind == "source_capture") \
                else time.time() * 1000.0
            try:
                monitor.step(frame, to_gray(frame, Monitor.GRAY_W), now)
            except Exception as e:
                print(f"[NVR] {camera_id} 单帧处理异常: {e}")
    finally:
        source.close()
        if watchdog is not None:
            watchdog.stopped()
        if state is not None:
            state.monitors.pop(camera_id, None)
        print(f"[NVR] {camera_id} 值守结束")


def main(argv=None, *, edition=None):
    """启动共享运行时。

    edition 由平台入口显式传入；直接运行 ``scam.nvr`` 时仅作为兼容入口，
    按当前操作系统选择版本。新部署不得再引用兼容入口。
    """
    fix_console_encoding()
    product = get_edition(edition)
    ap = argparse.ArgumentParser(description=product.display_name)
    ap.add_argument("--config", default="cameras.json")
    ap.add_argument("--db", default=product.default_db())
    ap.add_argument("--host", default=product.default_host,
                    help="工作台监听地址（默认仅本机；远程走 SSH 隧道/反向代理）")
    ap.add_argument("--port", type=int, default=product.default_port)
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
    # Linux NVR 由 systemd 保证单实例；新进程启动时数据库里的开放状态只可能
    # 属于上一实例，所以立即按最后活动时刻闭合。其他产品保留宽限窗。
    _recover_event_truth(
        conn, stale_after_s=0.0 if product.key == "linux-nvr" else 30.0)
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

    # L3 Linux看门狗：即使工作台关闭也持续记录逐相机生命周期；有工作台时先把
    # registry挂到状态对象，API接线由server热区释放后完成。Win11不自动启用该
    # Linux发布门禁，避免把Linux状态冒充另一产品的交付证据。
    health_registry = None
    if product.key == "linux-nvr":
        health_registry = HealthRegistry(
            [c["id"] for c in cams],
            os.path.dirname(os.path.abspath(args.db)))
        if state is not None:
            state.health = health_registry

    # L2 录像证据链：默认关闭，只有显式 record_enabled 的相机才起录像；
    # 录像失败只降级证据并大声提示，绝不阻断告警（DEC-004）。
    record_cams = [c for c in cams if c.get("record_enabled")]
    recorders = None
    recording_store = None
    ffmpeg_path = None
    config_hashes = {}
    if record_cams:
        from .recording import RecordingManager, RecordingStore, config_hash
        from .platform import find_ffmpeg
        db_dir = os.path.dirname(os.path.abspath(args.db))
        recorders = RecordingManager(os.path.join(db_dir, "cameras"))
        recording_store = RecordingStore(db_dir, args.db)
        for c in record_cams:
            url = c.get("record_source") or c["source"]
            if recorders.enable(
                    c["id"], url,
                    retention_days=c.get("record_retention_days", 7),
                    cap_gb=c.get("record_cap_gb"),
                    segment_seconds=c.get("record_segment_seconds", 600)):
                config_hashes[c["id"]] = config_hash(c)
            else:
                print(f"[警告] {c['id']} 录像未启动（告警不受影响）："
                      f"{recorders.status()}")
        if state is not None:
            state.recorders = recorders
            state.recording = recording_store
        ffmpeg_path = find_ffmpeg()
        if not ffmpeg_path:
            print("[警告] ffmpeg 缺失——事件片段导出不可用（告警不受影响）")

    stop_event = threading.Event()

    def _export_loop():
        """闭合审查段 → 事件片段导出（at-least-once，失败下轮重试）。"""
        from .recording import export_pending_clips
        ffprobe = shutil.which("ffprobe")
        camera_map = {c["id"]: c["id"] for c in record_cams}
        conn = connect(args.db)
        while not stop_event.wait(60.0):
            try:
                recorders.maintain()
                export_pending_clips(
                    conn, store=recording_store, ffmpeg=ffmpeg_path,
                    camera_map=camera_map, config_hashes=config_hashes,
                    ffprobe=ffprobe)
            except Exception as e:
                print(f"[NVR] 事件片段导出异常（下一轮重试）: {e}")
        conn.close()

    if record_cams and recording_store is not None and ffmpeg_path:
        threading.Thread(target=_export_loop, daemon=True).start()

    def _shutdown(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    threads = []
    for cam in cams:
        t = threading.Thread(
            target=_run_camera,
            args=(cam, zones_by_cam[cam["id"]], args.db, stop_event, state,
                  (health_registry.camera(cam["id"])
                   if health_registry is not None else None)),
            daemon=True)
        t.start()
        threads.append(t)

    if server is not None:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"[NVR] 工作台: http://{args.host}:{args.port}")

    print(f"[NVR] {product.display_name}值守中"
          f"（{len(cams)} 路相机，Ctrl+C 停机）")
    try:
        while not stop_event.wait(1.0):
            pass
    except KeyboardInterrupt:
        stop_event.set()
    if server is not None:
        server.shutdown()
    if recorders is not None:
        recorders.stop_all()
    for t in threads:
        t.join(timeout=5)
    print("[NVR] 已停机")
    return 0


if __name__ == "__main__":
    main()
