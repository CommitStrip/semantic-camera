"""scam.nvr —— NVR 常驻入口（python -m scam.nvr）。

加载场所档案（fail-closed 校验）→ 每相机一个值守线程（Monitor 快系统：
门控→检测→网格判定→告警→SQLite）→ 工作台 HTTP 随驻。
信号在主线程统一注册（SIGINT/SIGTERM → Event 优雅停机）。

区域配置真值：SQLite zones 表（工作台圈选保存的结果）优先，场所档案兜底；
启动时把档案区域种入 SQLite（工作台已保存的不覆盖）。重启后生效。
"""

import argparse
import errno
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
from .server import (ISSUE_ACTIONS, CameraRuntimeRegistry, WorkbenchServer,
                     WorkbenchState)
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


def _detector_plan(det_cfg):
    """只按配置判定检测能力（不加载模型）：返回 (能力, 固定issue code)。

    仅预览是管理员明确选择；配置了 ONNX 却缺模型，才算检测不可用。
    """
    if det_cfg.get("engine") != "onnx" or not det_cfg.get("model"):
        return "monitor_only", None
    if not os.path.isfile(det_cfg["model"]):
        return "detector_unavailable", "detector_missing"
    # 模型在位只代表"可加载"，真实加载结果由 _make_detector 覆盖。
    return "alerting", None


def _make_detector(det_cfg):
    """构建 NanoDet；返回 (检测器或None, 能力状态, 固定issue code)。

    模型缺失/加载失败绝不静默零检测：如实进入 detector_unavailable。
    """
    capability, det_issue = _detector_plan(det_cfg)
    if capability != "alerting":
        if det_issue == "detector_missing":
            print(f"[警告] 检测模型不存在: {det_cfg['model']}"
                  f"（该相机只跑门控，不会产生检测告警；放置模型后重启）")
        return None, capability, det_issue
    model = det_cfg["model"]
    try:
        # 导入也放进 try：onnxruntime/依赖缺失同样是"检测不可用"，
        # 绝不能让异常逃逸后留下一个声称 alerting 的假状态。
        from .detect import NanoDet
        return (NanoDet(model, det_cfg.get("classes", ["person"]),
                        conf=det_cfg.get("conf", 0.4)),
                "alerting", None)
    except Exception as e:
        print(f"[警告] 检测模型加载失败: {model}（{e}；"
              f"该相机只跑门控，不会产生检测告警）")
        return None, "detector_unavailable", "detector_load_failed"


def _run_camera(cam_cfg, zones, db_path, stop_event, state, watchdog=None):
    """单相机值守线程：源 → Monitor.step（门控/检测/裁决/告警全在内）。

    值守消费 detect 角色（source_kind 决定源类型；detect_source 可覆盖 source）；
    record 角色与录像接线属 L2（Z3），配置缺省不开录像。
    运行/能力状态只写固定状态与固定issue code——source、凭据、模型路径与异常
    正文都不进工作台。
    """
    camera_id = cam_cfg["id"]
    runtime = getattr(state, "runtime", None)
    det_cfg = cam_cfg.get("detector") or {}
    # 先按配置判定检测能力：源没打开时也要让管理员看到真实能力与下一步动作。
    # 但“模型在位”只代表可加载：NanoDet 真实构造成功前不得预判 alerting，否则
    # 加载窗口里工作台会显示“检测告警已启用”（C-052）。缺失/加载失败的固定结果
    # 仍按配置如实上报。
    if runtime is not None:
        capability, det_issue = _detector_plan(det_cfg)
        declared = "monitor_only" if capability == "alerting" else capability
        runtime.detector(camera_id, declared, det_issue)
        runtime.starting(camera_id)
    source_kind = cam_cfg.get("source_kind", "rtsp")
    detect_url = cam_cfg.get("detect_source") or cam_cfg["source"]
    source = CameraSource(camera_id, detect_url, source_kind=source_kind)
    # 文件源的故障口径与网络相机不同（文件不存在/损坏 ≠ 网络/供电问题）。
    open_issue = ("file_source_open_failed" if source_kind == "file"
                  else "source_open_failed")
    read_issue = ("file_source_read_failed" if source_kind == "file"
                  else "source_read_failed")
    if watchdog is not None:
        watchdog.started()
    had_open_failure = False
    while not stop_event.is_set() and not source.open():
        had_open_failure = True
        if watchdog is not None:
            watchdog.failure("open", "source open failed")
        if runtime is not None:
            runtime.degraded(camera_id, open_issue)
        print(f"[NVR] {camera_id} 源打开失败，5s 后重试")
        stop_event.wait(5.0)
    if stop_event.is_set():
        source.close()
        if watchdog is not None:
            watchdog.stopped()
        if runtime is not None:
            runtime.stopped(camera_id)
        return

    if watchdog is not None:
        watchdog.opened(reconnect=had_open_failure)

    try:
        det, capability, det_issue = _make_detector(det_cfg)
        if runtime is not None:
            runtime.detector(camera_id, capability, det_issue)
        monitor = Monitor({**cam_cfg, "zones": zones},
                          detect_fn=(det.detect if det else (lambda f: [])),
                          sinks=build_sinks({"sqlite": db_path}))
        if state is not None:
            state.monitors[camera_id] = monitor
        # 首次 online 必须推迟到检测器加载与 Monitor 构造都成功之后：源 open()
        # 成功只证明视频源可达，模型在位但仍在加载的窗口里工作台要保持保守的
        # connecting，不能提前宣称“在线+检测告警已启用”。
        if runtime is not None:
            runtime.online(camera_id)

        print(f"[NVR] {camera_id} 值守启动"
              + ("" if det else "（无检测器：只跑门控，不产生检测告警）"))
        recovering = False
        while not stop_event.is_set():
            ok, frame, ts = source.read()
            if not ok:
                recovering = True
                if watchdog is not None:
                    watchdog.failure("read", "source read failed")
                if runtime is not None:
                    runtime.degraded(camera_id, read_issue)
                stop_event.wait(0.5)
                continue
            # 真实源时间戳贯穿：仅当源显式证明 source_capture 才采用采集时间；
            # host_receive 含解码等待、unknown 无法溯源——都不能冒充采集时刻
            # （L4 验收口径），此时退回墙钟处理时间。
            kind = (source.stats or {}).get("timestamp_kind")
            if recovering:
                # 恢复与看门狗无关：无 watchdog 时也必须把状态收回 online。
                if watchdog is not None:
                    watchdog.opened(reconnect=True)
                if runtime is not None:
                    runtime.online(camera_id)
                recovering = False
            if watchdog is not None:
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
        if runtime is not None:
            runtime.stopped(camera_id)
        if state is not None:
            state.monitors.pop(camera_id, None)
        print(f"[NVR] {camera_id} 值守结束")


# 固定中文绑定失败原因；原始异常正文（可能夹带主机与磁盘细节）不外露。
_BIND_REASONS = {
    errno.EADDRINUSE: "端口已被其它程序占用",
    errno.EACCES: "端口被系统保留或权限不足",
    errno.EADDRNOTAVAIL: "监听地址在本机不可用",
    10048: "端口已被其它程序占用",   # Windows WSAEADDRINUSE 的原始码
}


def _bind_failure_reason(exc):
    """把绑定失败翻成固定中文原因；未知码只给通用原因。"""
    for code in (getattr(exc, "errno", None),
                 getattr(exc, "winerror", None)):
        reason = _BIND_REASONS.get(code)
        if reason is not None:
            return reason
    return "无法绑定工作台监听地址"


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
    ap.add_argument("--no-slow", action="store_true",
                    help="停用慢系统后台 worker（快路径告警不受影响）")
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

    # 逐相机运行/能力状态的唯一真值：相机线程写，工作台读。
    runtime = CameraRuntimeRegistry([c["id"] for c in cams])
    state = None
    server = None
    if not args.no_workbench:
        state = WorkbenchState(args.db)
        state.runtime = runtime
        try:
            server = WorkbenchServer(state, host=args.host, port=args.port)
        except OSError as e:
            if product.key == "win11":
                # Win11门禁：没有工作台就看不到相机状态与下一步动作，值守会
                # 变成不可观测的盲跑——给出固定中文原因后中止启动。
                print(f"[NVR] 工作台启动失败：{args.host}:{args.port} "
                      f"{_bind_failure_reason(e)}")
                print(f"[NVR] {ISSUE_ACTIONS['workbench_port_in_use']}")
                print("[NVR] 已中止启动，未启动任何相机线程")
                return 1
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

    # S2 慢系统有界后台接线（Linux 主链）：独立线程消费闭合审查段（S1 核心）；
    # 快路径永不等待，worker 故障只降级慢结果并在 /api/health slow 段可见。
    # provider 暂缺省 None：重复段纯结构匹配零 VLM，新异段 pending_naming
    # 诚实降级（真实 VLM 通道由后续批次按配置显式接入）。
    slow_worker = None
    if product.key == "linux-nvr" and not args.no_slow:
        from .slow_worker import SlowWorker
        # V-JEPA 段嵌入（可选）：任一相机显式配置 slow_embed_model 且文件在
        # 位才构建；缺失/加载失败大声降级为纯结构匹配（零成本，不阻断）。
        embedder = None
        embed_model = next(
            (c.get("slow_embed_model") for c in cams
             if c.get("slow_embed_model")), None)
        if embed_model:
            if os.path.isfile(embed_model):
                try:
                    from .embed import JepaEmbedder
                    embedder = JepaEmbedder(embed_model)
                    print(f"[NVR] 慢系统段嵌入已启用（{embed_model}）")
                except Exception as e:
                    print(f"[警告] 段嵌入模型加载失败（降级纯结构匹配）：{e}")
            else:
                print(f"[警告] 段嵌入模型不存在: {embed_model}"
                      f"（降级纯结构匹配；放置模型后重启）")
        slow_worker = SlowWorker(args.db, [c["id"] for c in cams],
                                 stop_event=stop_event, embedder=embedder)
        slow_worker.start()
        if state is not None:
            state.slow_worker = slow_worker
        print("[NVR] 慢系统 worker 已启动（30s 轮询；--no-slow 可停用）")

    # 通知出口（可选顶层 notify 段）：MQTT + webhook；未配置=线程不启动
    # 零开销；出口失败只计数降级（/api/health notify 段），绝不阻断告警。
    notify_hub = None
    if cfg.get("notify"):
        from .notify import NotificationHub
        notify_hub = NotificationHub(args.db, cfg["notify"],
                                     stop_event=stop_event)
        notify_hub.start()
        if state is not None:
            state.notify_hub = notify_hub
        print("[NVR] 通知出口已启动（配置了 notify 段）")

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
    if slow_worker is not None:
        if not slow_worker.stop(timeout=10.0):
            print("[NVR] 慢系统 worker 关机超时（未完成事实留在水位，"
                  "下次启动续跑）")
    if notify_hub is not None:
        notify_hub.stop(timeout=5.0)
    for t in threads:
        t.join(timeout=5)
    print("[NVR] 已停机")
    return 0


if __name__ == "__main__":
    main()
