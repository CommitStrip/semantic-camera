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
from .models import build_provider
from .db import (backfill_initial_fact_pairs, connect,
                 finalize_snapshot_records, init_schema,
                  recover_stale_records, snapshot_pending_recovery)
from .monitor import Monitor, to_gray
from .editions import get_edition
from .health import HealthRegistry
from .platform import fix_console_encoding
from .server import (ISSUE_ACTIONS, CameraRuntimeRegistry, WorkbenchServer,
                     WorkbenchState)
from .sinks import build_sinks
from .source import CameraSource
from .win11_materials import MaterialsStore
from .win11_pipeline import L1Pipeline, L1Task


# C-136：L2 生产运行面（窗口调度/闸门/兜底→L3/持久化/L4 链）移至独立模块
from .win11_l2_runtime import L2Runtime


def _build_l2_runtime(l2_cfg, store, camera_ids, *, l3_cfg=None,
                      persist_dir=None, crop_worker=None, db_path=None):
    """按显式开关构建 L2 运行面（C-136：唯一适配器+窗口调度+持久化）；
    模型依赖缺失延迟到首次推理才失败，健康面以 stage 输出与 backend
    diagnostic 如实呈现（不回退假模型）。l3.enabled 时构建 L3Stage（B 的
    本地或显式云端适配器）；云端缺省启用 L4，显式 l4.enabled 可覆盖。
    C-141：crop_worker 为原始裁图证据工作者（可选注入；None=仅内存，
    裁图证据不落盘、重启不可回看）。"""
    from .win11_l2_backend import RelateAnythingAdapter
    from .win11_l2_contract import L2Budget, L2RelationStage
    # 仅当 L2 启用时才要求显式 repo_path；未启用的运行面保持可构造
    # （空路径不加载模型，若误调用则按模型不可用如实失败）。
    repo_path = l2_cfg.get("repo_path") or ""
    if l2_cfg.get("enabled") and not repo_path:
        raise ValueError("l2.enabled 需要显式 repo_path（受控本地模型目录，"
                         "不自动下载、不使用内置默认路径）")
    adapter = RelateAnythingAdapter(
        repo_path=repo_path,
        checkpoint=l2_cfg.get("checkpoint") or "",
        vocabulary=list(l2_cfg.get("vocabulary") or []),
        infer_timeout_s=float(l2_cfg.get("infer_timeout_s") or 10.0))
    budget = L2Budget(
        max_candidates=int(l2_cfg.get("max_candidates") or 8),
        max_crops=int(l2_cfg.get("max_crops") or 4))
    stage = L2RelationStage(model=adapter, budget=budget)
    l3_stage = None
    l3_backend = None
    if l3_cfg and l3_cfg.get("enabled"):
        from .win11_l3 import L3Stage
        provider = l3_cfg.get("provider", "local")
        timing = dict(timeout_s=float(l3_cfg.get("timeout_s") or 180.0),
                      infer_timeout_s=float(l3_cfg.get("infer_timeout_s") or 120.0),
                      load_timeout_s=float(l3_cfg.get("load_timeout_s") or 60.0))
        if provider == "cloud":
            from .config import validate_l3_config
            errors = validate_l3_config(l3_cfg)
            if errors:
                raise ValueError("; ".join(errors))
            from .win11_l3_cloud import CloudOpenAICompatibleL3Backend
            l3_model = CloudOpenAICompatibleL3Backend(
                base_url=l3_cfg["base_url"], model=l3_cfg["model"],
                key_env=l3_cfg["key_env"], consent=l3_cfg["image_upload_consent"],
                **timing, **{key: l3_cfg[key] for key in (
                    "request_timeout_s", "max_tokens", "max_frames",
                    "jpeg_budget_bytes_per_frame") if key in l3_cfg})
        elif provider == "local":
            from .win11_l3_backend import LocalTransformersL3Backend
            model_path = l3_cfg.get("model_path")
            if not model_path:
                raise ValueError("l3.enabled 需要显式 model_path（受控本地模型，"
                                 "不自动下载）")
            l3_model = LocalTransformersL3Backend(
                model_path=model_path, **timing,
                **{key: l3_cfg[key] for key in (
                    "dtype", "precision_mode", "attention_implementation", "vision_chunk_size")
                   if key in l3_cfg})
        else:
            raise ValueError("l3.provider 必须为 local|cloud")
        l3_stage = L3Stage(model=l3_model, budget=None)
        l3_backend = l3_model
    l4_factory = None
    l4_cfg = (l3_cfg or {}).get("l4") or {}
    # 云向导的新路径默认保留渐进融合；显式关闭仍受尊重。
    cloud_progress_default = bool(
        l3_cfg and l3_cfg.get("enabled") is True
        and l3_cfg.get("provider") == "cloud")
    if l4_cfg.get("enabled", cloud_progress_default):
        from .win11_l4 import L4Stage
        l4_factory = L4Stage
    event_progress = None
    if l4_factory is not None and db_path is not None:
        from .win11_event_progress import EventProgress
        event_progress = EventProgress(db_path)
    # C154 车道 G：同事件跨窗选材——生产默认启用（有界池 + 事实链只读绑定）。
    # 绑定来源 = `event_progress`（事实链快照，先于选材点写入）；它只在
    # l4.enabled 且有持久化库时才存在——不为此新建第二条事件桥。无来源时池
    # 一律不聚合（如实记 `binding_source_missing`）并继续旧窗口路径，绝不猜
    # 事件；共享预算仍归 L2Runtime 默认启用的 C153 账本，不申请第二份。
    from .win11_event_materials import EventMaterialPool
    # C155 最小一期（主协调批准 P0-1/P0-2/P0-3(a)）：Win11 **生产入口**显式开启
    # 逐帧严格归属与主帧事件键查找；共享 EventMaterialPool 默认仍为关闭
    # （其他调用方与既有行为不受影响）。两开关的实际取值经
    # `runtime.snapshot()["event_materials"]`（即 /api/health 的 l2 段）可核，
    # 不依赖实验驱动注入。
    event_materials = EventMaterialPool(
        binding_source=event_progress,
        frame_level_binding=True,
        primary_frame_binding=True)
    return L2Runtime(camera_ids, store, stage, adapter=adapter,
                     l3_backend=l3_backend,
                     vocabulary_id=str(l2_cfg.get("vocabulary_id")
                                       or "upstream-default"),
                     vocabulary=tuple(l2_cfg.get("vocabulary") or ()),
                     max_age_s=float(l2_cfg.get("max_age_s") or 30.0),
                     poll_interval_s=float(l2_cfg.get("poll_interval_s")
                                           or 0.5),
                     l3_stage=l3_stage,
                     l3_max_queue=int((l3_cfg or {}).get("max_queue") or 4),
                     persist_dir=persist_dir,
                     l4_factory=l4_factory,
                     crop_worker=crop_worker,
                     event_progress=event_progress,
                     event_materials=event_materials)


def _stop_l1_components(l1_groups, l1_store):
    """停机收尾：先提交方已 join，再关管道与材料仓。

    返回未完成组件标签列表：close() 返回 False（worker 超时仍活）或关闭
    异常都如实入列；调用方据此决定打印"已停机"还是"停机未完成"，绝不
    在线程仍运行时宣称资源已释放。逐项 try/except，互不掩盖。
    """
    incomplete = []
    for group in l1_groups:
        try:
            if not group["pipeline"].close():
                incomplete.append(f"检测管线（相机 {group['cameras']}）")
        except Exception as exc:
            incomplete.append(f"检测管线关闭异常（相机 {group['cameras']}，"
                              f"{type(exc).__name__}）")
    if l1_store is not None:
        try:
            l1_store.close()
        except Exception as exc:
            print(f"[NVR] 材料仓关闭异常: {type(exc).__name__}")
    return incomplete


def _load_json(path):
    # utf-8-sig：容忍 Windows 记事本保存时加的 BOM
    with open(path, encoding="utf-8-sig") as f:
        value = json.load(f)
    if isinstance(value, dict) and "asset_paths" in value:
        from .config import resolve_venue_asset_paths
        return resolve_venue_asset_paths(value, path)
    return value


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
              f"语义事件 {counts['semantic_events']}，"
              f"事件 {counts['event_facts']}")
    return counts


def _schedule_pending_recovery(db_path, snapshot, *, delay_s, stop_event=None,
                               on_done=None):
    """宽限窗过后的**一次性**遗留记录复核（F8 收口）。

    - 只处理启动时定格进快照的记录（不扫描新建事实）；
    - 独立数据库连接，绝不占用启动连接；
    - daemon 线程 + 可被停机事件提前唤醒：进程退出不被定时器阻塞；
    - 复核走 CAS（见 `finalize_snapshot_records`），新实例续写、管理员关闭或
      状态改写的记录一律不覆盖。
    """
    if not snapshot:
        return None

    def _worker():
        if stop_event is not None:
            if stop_event.wait(delay_s) or stop_event.is_set():
                return
        else:
            time.sleep(delay_s)
        conn = connect(db_path)
        try:
            counts = finalize_snapshot_records(conn, snapshot)
        except Exception as e:
            # 恢复是兜底动作：任何失败都不许打断值守或退出流程。
            print(f"[NVR] 遗留记录延迟复核失败: {type(e).__name__}")
            return
        finally:
            conn.close()
        if sum(counts.values()):
            print("[NVR] 宽限窗后收口遗留记录: "
                  f"对象 {counts['tracked_objects']}，"
                  f"审查段 {counts['review_segments']}，"
                  f"语义事件 {counts['semantic_events']}")
        if on_done is not None:
            on_done(counts)

    thread = threading.Thread(target=_worker, name="pending-recovery", daemon=True)
    thread.start()
    return thread


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


def _l1_detector_factory(det_cfg):
    """L1 worker 线程内的检测器懒加载工厂（合同 C-131 §1）。

    复用 _make_detector 的加载路径与告警日志；与同步路径唯一的差别是失败
    不被吞掉——工厂要么返回检测器，要么以异常上抛，让 L1Pipeline 产出
    model_unavailable 结果并在退避后重试，绝不给 worker 一个假检测器。
    """
    def factory():
        det, _capability, _issue = _make_detector(det_cfg)
        if det is None:
            raise RuntimeError("detector_load_failed")
        return det

    return factory


def _run_camera(cam_cfg, zones, db_path, stop_event, state, watchdog=None,
                pipeline=None, store=None, l2_runtime=None):
    """单相机值守线程：源 → Monitor.step（门控/检测/裁决/告警全在内）。

    值守消费 detect 角色（source_kind 决定源类型；detect_source 可覆盖 source）；
    record 角色与录像接线属 L2（Z3），配置缺省不开录像。
    运行/能力状态只写固定状态与固定issue code——source、凭据、模型路径与异常
    正文都不进工作台。
    pipeline 或 store 非 None 时走 Win11 异步模式（合同 C-132）：快系统逐帧只做
    轻量观察与材料选择，检测结果只经 apply_detection_result 进入。有管道的相机
    材料同帧双投（L1 调度 + 材料留档，F8）；仅预览/缺模型相机只投材料仓（统一
    轻量材料路径，不偷偷启动检测模型、不产生对象告警）。两者皆 None
    （Linux）保持同步路径，逐字节不变。
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
    persistence_reported = None
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

    monitor = None
    try:
        if pipeline is not None or store is not None:
            # Win11 异步模式（合同 C-132 F10）：检测器由管道 worker 线程懒加载
            # 一次，快系统绝不等待模型；检测结果只经 apply_detection_result
            # 进入（detect_fn=None），sync 分支不进此路径。仅预览/缺模型相机
            # （store 有、pipeline 无）走同一条轻量材料路径。
            monitor = Monitor({**cam_cfg, "zones": zones},
                              detect_fn=None,
                              sinks=build_sinks({"sqlite": db_path}),
                              detection_mode="async")

            def _material_sink(material):
                # 快系统材料出口（合同 C-132 F3/F8）：同帧双投——L1 调度 +
                # 材料留档；只做内存复制与组装，绝不阻塞、绝不 I/O。返回
                # 真实受理布尔（两者都受理才算受理）；False 时由 monitor
                # 计 material_rejected（原因由管道/材料仓各自计数，两层
                # 各计一层不重复）。时间可信度标注取当帧已登记的
                # monitor.timestamp_kind（nvr 逐帧写入）。
                accepted = True
                if pipeline is not None:
                    task = L1Task(
                        camera_id=material["camera_id"],
                        run_id=material["run_id"],
                        frame_id=material["frame_id"],
                        t_capture_ms=material["t_capture_ms"],
                        frame_bgr=material["frame_bgr"].copy(),
                        reason=material["reason"],
                        change_boxes=material["change_boxes"],
                        gate_w=material["gate_w"],
                        gate_h=material["gate_h"],
                        config_version=material["config_version"],
                        prev_available=material["prev_available"])
                    accepted = pipeline.submit(task)
                stored = store.ingest(
                    camera_id=material["camera_id"],
                    run_id=material["run_id"],
                    config_version=material["config_version"],
                    frame_id=material["frame_id"],
                    frame_bgr=material["frame_bgr"],
                    t_capture_ms=material["t_capture_ms"],
                    timestamp_kind=monitor.timestamp_kind,
                    change_boxes=material["change_boxes"],
                    gate_w=material["gate_w"],
                    gate_h=material["gate_h"],
                    material_reason=material["reason"])
                if not (accepted and stored):
                    # 拒收计数唯一责任方=monitor（按 sink 返回值计一次，
                    # C-133 R2）；原因明细由管道/材料仓各自计数，这里不重复
                    pass
                return accepted and stored

            monitor.set_material_sink(_material_sink)
            # T2 进展探针：管道最老未完结任务年龄（卡死时持续增长，新提交
            # 不重置）；monitor 经此判失联，自己不感知管道内部。
            monitor.set_progress_probe(
                lambda: pipeline.oldest_unfinished_age_ms(camera_id))
        else:
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
              + ("（L1 异步检测）" if pipeline is not None else "")
              + ("（材料留档）" if store is not None else "")
              + ("" if pipeline is not None or store is not None else
                 ("" if det else "（无检测器：只跑门控，不产生检测告警）")))
        recovering = False
        # L1 能力上报的去重缓存：只在 l1_health 状态变化时写注册表。
        l1_reported = None
        while not stop_event.is_set():
            ok, frame, ts = source.read()
            if not ok:
                recovering = True
                if watchdog is not None:
                    watchdog.failure("read", "source read failed")
                if runtime is not None:
                    runtime.degraded(camera_id, read_issue)
                # 断流登记：宽限内保留开放事件，超宽限由 Monitor 按合同收口
                monitor.on_stream_lost(time.time() * 1000.0)
                stop_event.wait(0.5)
                continue
            # 真实源时间戳贯穿：仅当源显式证明 source_capture 才采用采集时间；
            # host_receive 含解码等待、unknown 无法溯源——都不能冒充采集时刻
            # （L4 验收口径），此时退回墙钟处理时间。
            kind = (source.stats or {}).get("timestamp_kind")
            monitor.timestamp_kind = kind
            if recovering:
                # 恢复与看门狗无关：无 watchdog 时也必须把状态收回 online。
                if watchdog is not None:
                    watchdog.opened(reconnect=True)
                if runtime is not None:
                    runtime.online(camera_id)
                monitor.on_stream_recovered()
                recovering = False
            if watchdog is not None:
                watchdog.frame(source_ts=ts, timestamp_kind=kind)
            now = (ts * 1000.0) if (ts and kind == "source_capture") \
                else time.time() * 1000.0
            if l2_runtime is not None:
                # C-137 §4：当前有效身份注册表推进（廉价；区域切换/重启
                # 后 run 变化即生效，发布门禁据此拒收旧结果）
                try:
                    l2_runtime.update_camera_identity(
                        camera_id, monitor.run_id, monitor.zone_revision)
                except Exception:
                    pass
            if pipeline is not None:
                # 消费就绪的 L1 结果（非阻塞，读帧成功后、step 之前）：
                # 消费异常只记日志，绝不阻塞或杀死值守线程。结果的最终
                # 关联在 step 之后按统一消费结论执行（R1）——step 的
                # 配置/TTL/顺序复核此前不预写任何"有效ok"。
                try:
                    result = pipeline.take_result(camera_id)
                    if result is not None:
                        monitor.apply_detection_result(result, now)
                except Exception as e:
                    print(f"[NVR] {camera_id} L1 结果消费异常: {e}")
            try:
                monitor.step(frame, to_gray(frame, Monitor.GRAY_W), now)
            except Exception as e:
                print(f"[NVR] {camera_id} 单帧处理异常: {e}")
            if pipeline is not None and store is not None:
                # R1 统一消费结论（C-133）：step 复核后才允许关联——被拒
                # 结果以 accepted=False+原因作诊断（四元校验由材料仓兜底），
                # 绝不预写有效 ok，也不与 Monitor 各判一套身份规则。
                conclusion = getattr(monitor, "consume_conclusion", lambda: None)()
                if conclusion is not None:
                    # A metadata adapter fault cannot suppress material delivery.
                    progress = getattr(l2_runtime, "event_progress", None)
                    if progress is not None:
                        try:
                            progress.record_conclusion(monitor, conclusion)
                        except Exception as exc:
                            print(f"[NVR] {camera_id} 事件身份快照失败: "
                                  f"{type(exc).__name__}")
                    try:
                        store.attach_result(
                            conclusion["camera_id"], conclusion["run_id"],
                            conclusion["config_version"],
                            conclusion["frame_id"], conclusion["status"],
                            conclusion.get("error_code"),
                            conclusion.get("detections") or [],
                            accepted=conclusion["accepted"],
                            reject_reason=conclusion.get("reason"))
                    except Exception as e:
                        print(f"[NVR] {camera_id} 材料关联异常: {e}")
            # L1 能力上报（最小面，合同 C-131 §3）：只在 l1_health 状态变化
            # 时写注册表——首次 ready 置检测可用，model_unavailable 置检测
            # 不可用；复用既有 detector 能力与 issue code 词表，状态无变化
            # 时零调用。其余状态（如 infer_failed）不改写能力事实。
            if pipeline is not None and runtime is not None:
                health = getattr(monitor, "l1_health", None)
                l1_state = (health or {}).get("state")
                if l1_state is not None and l1_state != l1_reported:
                    if l1_state == "ready":
                        runtime.detector(camera_id, "alerting", None)
                        l1_reported = l1_state
                    elif l1_state == "model_unavailable":
                        code = (health or {}).get("code")
                        runtime.detector(
                            camera_id, "detector_unavailable",
                            code if code in ISSUE_ACTIONS
                            else "detector_load_failed")
                        l1_reported = l1_state
            # 数据面故障（审查段/告警写不进库）必须在健康面可见，不能只留在
            # 监控线程的内部计数里；只在状态变化时写，避免逐帧刷注册表。
            if runtime is not None:
                degraded = monitor.persistence_state()["degraded"]
                code = "persistence_degraded" if degraded else None
                if code != persistence_reported:
                    runtime.persistence(camera_id, code)
                    persistence_reported = code
    finally:
        # 边界3：退出收口的每一项各自得到执行机会——source.close() 抛错不得
        # 跳过事件收口/看门狗/运行状态清理；清理异常逐项记录，绝不掩盖 try 内
        # 更早的主异常；无主异常时上抛第一条清理异常，不静默吞掉。
        in_flight = sys.exc_info()[0] is not None
        cleanup_errors = []

        def _cleanup(label, action):
            try:
                action()
            except Exception as exc:
                cleanup_errors.append((label, exc))

        _cleanup("source-close", source.close)

        def _event_closeout():
            pending = monitor.close_all_event_facts()
            if pending:
                # 边界1：退出前仍未能落库的事件必须如实报"未保存"，
                # 绝不宣称已保存；进程结束后内存快照消失，这是真实丢失。
                print(f"[NVR] {camera_id} 事件收口未完成：{pending} 条事件"
                      "未能写入数据库（未保存）")

        if monitor is not None:
            _cleanup("event-closeout", _event_closeout)
        if watchdog is not None:
            _cleanup("watchdog-stop", watchdog.stopped)
        if runtime is not None:
            _cleanup("runtime-stop", lambda: runtime.stopped(camera_id))
        if state is not None:
            _cleanup("registry-pop", lambda: state.monitors.pop(camera_id, None))
        for label, exc in cleanup_errors:
            print(f"[NVR] {camera_id} 退出清理异常（{label}）: {exc}")
        if cleanup_errors and not in_flight:
            raise cleanup_errors[0][1]
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


def main(argv=None, *, edition=None, stop_event=None,
         lifecycle_hook=None):
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
    startup_grace_s = 0.0 if product.key == "linux-nvr" else 30.0
    _recover_event_truth(conn, stale_after_s=startup_grace_s)
    # 宽限窗内没被立即闭合的遗留记录不能就此悬挂：定格它们的启动快照，
    # 等宽限窗结束后做一次性 CAS 复核（Linux 零宽限时快照必为空，行为不变）。
    pending_recovery = snapshot_pending_recovery(
        conn, now=time.time(), stale_after_s=startup_grace_s)
    # 崩溃窗口补账：只找缺描述 v1 / 缺 initial_fact 的事件，稳定键分批、
    # 有界执行（UNIQUE 兜底恰一次）；未补完由后台周期续跑，待补数如实显示
    # ——"值守已启动"绝不写成"积压已清零"。
    backfill_pending = 0
    backfill_stats = None
    try:
        backfilled = backfill_initial_fact_pairs(conn, created_at=time.time())
        backfill_pending = backfilled["remaining"]
        backfill_stats = backfilled
        if backfilled["descriptions"] or backfilled["notifications"]                 or backfilled["failed"]:
            print("[NVR] 启动补账：事件描述 v1 ×"
                  f"{backfilled['descriptions']}，初始事实提醒 ×"
                  f"{backfilled['notifications']}，失败 ×"
                  f"{backfilled['failed']}（恰一次）")
        if backfill_pending:
            print(f"[NVR] 补账未完：剩余待补 {backfill_pending} 条，"
                  "后台周期继续补齐")
    except Exception as exc:
        # 补账失败不阻断值守：缺失项仍由后台/下次启动继续；固定摘要不给原文。
        print(f"[NVR] 启动补账未完成（{type(exc).__name__}），后台重试")
        backfill_pending = -1
    _seed_zones(conn, cams)
    zones_by_cam = {c["id"]: _zones_of(conn, c["id"], c.get("zones") or [])
                    for c in cams}
    conn.close()

    # 逐相机运行/能力状态的唯一真值：相机线程写，工作台读。
    runtime = CameraRuntimeRegistry([c["id"] for c in cams])
    state = None
    server = None
    if not args.no_workbench:
        state = WorkbenchState(
            args.db,
            environment_provider=build_provider(cfg.get("models")
                                                 or {"channel": "local"}))
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

    # C152 桌面壳注入点（默认 None → 行为与既有完全一致）：
    # 外部 stop_event 让壳可直接请求正常停机；lifecycle_hook 上报事实性事件。
    stop_event = stop_event if stop_event is not None else threading.Event()

    def _lifecycle(event, **fields):
        """生命周期钩子：只上报事实；钩子异常绝不改变生产停机语义。"""
        if lifecycle_hook is None:
            return
        try:
            lifecycle_hook(event, **fields)
        except Exception:
            pass


    # Win11「进行中事件的语义更新」后台链（第一切片，Win11 专属接线）：
    # 独立守护线程、限并发限队列、可停止；快路径零同步等待模型；
    # 模型失败/超时/不可用只记状态，v1 提醒与事件记录照常工作。
    semantic_updater = None
    # 显式关闭新理解开关时，也不再偷偷启动旧的语义更新worker。
    # 无l3段的旧配置仍保留既有更新链，不把它误报为理解已关闭。
    understanding_configured = ("l3" not in cfg
                                or (cfg.get("l3") or {}).get("enabled") is True)
    if product.key == "win11" and state is not None:
        state.understanding_enabled = understanding_configured
    if product.key == "win11" and state is not None and understanding_configured:
        try:
            from .semantic_updater import SemanticUpdater
            semantic_updater = SemanticUpdater(
                args.db,
                build_provider(cfg.get("semantic_models")
                               or cfg.get("models")
                               or {"channel": "local"}),
                stop_event=stop_event)
            state.semantic = semantic_updater
            semantic_updater.start()
            print("[NVR] 语义更新后台链已启动（进行中事件 · 增量理解 · "
                  "真实模型，质量未验证）")
        except Exception as exc:
            print(f"[NVR] 语义更新后台链未启动（{type(exc).__name__}）；"
                  "v1 提醒与事件记录照常工作")
            semantic_updater = None

    # Win11 快系统→L1 中间层（合同 C-131 §3/§4）：edition==win11 且存在可用
    # 检测配置（engine=onnx 且模型在位）时，按（model+classes+conf）规范键
    # 分组建共享 L1Pipeline——同组相机共享一个 worker、一次模型加载；不同组
    # 各自独立，仍比每相机一份检测器都不多建。Linux 与仅预览/模型缺失不建
    # 管道、不挂 state.l1：既有路径零改动。/api/health 在请求时读 state，
    # 此处挂载先于工作台服务线程启动。
    l1_groups = []
    camera_pipelines = {}
    if product.key == "win11":
        groups = {}
        for cam in cams:
            det_cfg = cam.get("detector") or {}
            if _detector_plan(det_cfg)[0] != "alerting":
                continue
            key = (det_cfg["model"], tuple(det_cfg.get("classes", ["person"])),
                   det_cfg.get("conf", 0.4))
            group = groups.setdefault(key, {"det_cfg": det_cfg, "cameras": []})
            group["cameras"].append(cam["id"])
        for group in groups.values():
            pipeline = L1Pipeline(
                _l1_detector_factory(group["det_cfg"]), stop_event=stop_event,
                model_name=os.path.basename(group["det_cfg"]["model"]),
                # W1（主协调批准）：Win11 生产入口显式启用**一个受保护槽位**，使
                # "静→动"边沿反复发出的 change_start 材料帧不再被合并丢弃
                # （真实通路实测：L1 服务覆盖 58%→75%、带检出材料 30→44、
                # 三帧全齐备 18→36；submit 增量 ≈0.42 µs/次，快路径仍非阻塞）。
                # 共享 L1Pipeline 默认仍为 0，其他调用方与 Linux 不受影响。
                latest_protected_slots=1)
            l1_groups.append({"cameras": list(group["cameras"]),
                              "pipeline": pipeline})
            for camera_id in group["cameras"]:
                camera_pipelines[camera_id] = pipeline
        for group in l1_groups:
            group["pipeline"].start()
        if state is not None and l1_groups:
            state.l1 = l1_groups
            print(f"[NVR] L1 异步检测已启用（{len(l1_groups)} 组共享检测器，"
                  f"覆盖 {sum(len(g['cameras']) for g in l1_groups)} 路相机）")

    # 有界时序材料仓（合同 C-132 F7）：全部 Win11 相机统一轻量材料路径——
    # 有检测器的相机与 L1 同帧双投；仅预览/缺模型相机只投材料仓（变化材料
    # 不丢失，也绝不偷偷启动检测模型）。Linux 不建仓：既有路径零改动。
    l1_store = None
    if product.key == "win11":
        l1_store = MaterialsStore()
        if state is not None:
            state.materials = l1_store
        print(f"[NVR] 材料留档已启用（覆盖 {len(cams)} 路相机，"
              "后续语义理解未接入）")

    # L2 关系/互动裁图（C-134）：默认关闭；仅当配置显式 enabled 且材料仓
    # 在位时才构建独立线程（不进入快系统/L1 线程）。未配置模型依赖时延迟
    # 到首次推理才失败，健康面 model_unavailable 如实呈现，不回退假模型。
    l2_runtime = None
    l2_cfg = cfg.get("l2") or {}
    l3_cfg = cfg.get("l3") or {}
    # L3 使用同一有界调度面；显式启用理解无需重复开启 L2 配置。
    semantic_runtime_enabled = product.key == "win11" and (
        l2_cfg.get("enabled") is True or l3_cfg.get("enabled") is True)
    # 原始裁图证据（C-141）：有界异步工作者+持久索引；存储根在每用户数据
    # 目录（db 同目录 understanding/crops/）。构建失败→诚实仅内存（不落盘、
    # 重启不可回看），其余链路照常；关停/重启不删库不误清证据。
    crop_worker = None
    if semantic_runtime_enabled:
        try:
            from .win11_crop_evidence import CropEvidenceStore
            from .win11_crop_worker import CropWorker
            crops_root = os.path.join(os.path.dirname(os.path.abspath(args.db)),
                                      "understanding", "crops")
            crop_worker = CropWorker(CropEvidenceStore(crops_root))
            crop_worker.start()
            print("[NVR] 原始裁图持久化已启用（原始 PNG+持久索引；"
                  "重启后可回看）")
        except Exception as exc:
            crop_worker = None
            print(f"[NVR] 原始裁图持久化未启用（{type(exc).__name__}）；"
                  "裁图证据仅内存，重启不可回看")
    if semantic_runtime_enabled:
        try:
            l2_runtime = _build_l2_runtime(
                l2_cfg, l1_store, [c["id"] for c in cams], l3_cfg=l3_cfg,
                persist_dir=os.path.join(
                    os.path.dirname(os.path.abspath(args.db)),
                    "understanding"),
                crop_worker=crop_worker, db_path=args.db)
            l2_runtime.start()
            if state is not None:
                state.l2 = l2_runtime
                if crop_worker is not None:
                    state.crop_service = crop_worker
            note = ("；L2→L3 路径已启用（真实多帧，质量未验证）"
                    if l3_cfg.get("enabled") else "")
            print("[NVR] L2 关系阶段已启用（显式开关；独立线程，"
                  "不阻塞快系统/L1；关系分数未经校准）" + note)
        except Exception as exc:
            print(f"[NVR] L2 关系阶段启用失败（{type(exc).__name__}）；"
                  "其余链路照常，未回退假模型")

    # 补账后台续跑（工作包 B）：有界批次 + 周期机会，直到积压清零；
    # 待补数写入 state.backfill 供工作台健康面如实显示。
    if state is not None:
        state.backfill = {"pending": backfill_pending,
                          "failed": (backfill_stats or {}).get("failed", 0),
                          "scanned": (backfill_stats or {}).get("scanned", 0),
                          "wrapped": (backfill_stats or {}).get("wrapped", False)}

    def _backfill_worker():
        nonlocal backfill_pending
        while not stop_event.is_set():
            if stop_event.wait(60.0):
                return
            try:
                bconn = connect(args.db)
                try:
                    stats = backfill_initial_fact_pairs(
                        bconn, created_at=time.time())
                finally:
                    bconn.close()
                backfill_pending = stats["remaining"]
                if state is not None:
                    state.backfill = {"pending": stats["remaining"],
                                      "descriptions": stats["descriptions"],
                                      "notifications": stats["notifications"],
                                      "failed": stats["failed"],
                                      "scanned": stats["scanned"],
                                      "wrapped": stats["wrapped"]}
                if stats["remaining"] == 0 and not stats["failed"]:
                    return
            except Exception:
                # 持续失败绝不显示成"已清零"：pending 保留真值并标记运行错误
                if state is not None:
                    state.backfill = {"pending": backfill_pending,
                                      "failed": state.backfill.get("failed", 0),
                                      "error": "backfill_run_failed"}

    if backfill_pending:
        threading.Thread(target=_backfill_worker, name="notify-backfill",
                         daemon=True).start()

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
                   if health_registry is not None else None),
                  camera_pipelines.get(cam["id"]),
                  l1_store if product.key == "win11" else None,
                  l2_runtime if product.key == "win11" else None),
            daemon=True)
        t.start()
        threads.append(t)

    if server is not None:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"[NVR] 工作台: http://{args.host}:{args.port}")
        # HTTP 入口已监听：仅此含义，不代表相机/模型就绪。
        _lifecycle("http_ready", host=args.host, port=args.port)

    # 事实性就绪上报：只报可核实项。**模型就绪当前无证据源 → 明确 unknown**，
    # 不得由 HTTP 就绪或等待时长推断。
    _lifecycle("runtime_state", cameras=len(cams),
               camera_health_source=("health_registry"
                                     if health_registry is not None
                                     else "unavailable"),
               models="unknown")

    # 宽限窗结束后做一次性遗留收口（Linux 零宽限时快照为空，不会起线程）。
    _schedule_pending_recovery(args.db, pending_recovery,
                               delay_s=startup_grace_s + 1.0,
                               stop_event=stop_event)

    print(f"[NVR] {product.display_name}值守中"
          f"（{len(cams)} 路相机，Ctrl+C 停机）")
    try:
        while not stop_event.wait(1.0):
            pass
    except KeyboardInterrupt:
        stop_event.set()
    _lifecycle("stopping")
    # 停机未完成项：能在本段**可靠观察**的组件才计入；无法可靠观察的组件
    # （recorders/notify_hub/semantic_updater 的返回状态未被本段使用）保持
    # **unknown/未验证**，不因"调用过 stop"就宣称完成。
    incomplete: list[str] = []
    if server is not None:
        server.shutdown()
    if recorders is not None:
        recorders.stop_all()
    if slow_worker is not None:
        if not slow_worker.stop(timeout=10.0):
            print("[NVR] 慢系统 worker 关机超时（未完成事实留在水位，"
                  "下次启动续跑）")
            incomplete.append("慢系统 worker（关机超时，未完成事实留在水位）")
    if notify_hub is not None:
        notify_hub.stop(timeout=5.0)
    for index, t in enumerate(threads):
        t.join(timeout=5)
        if t.is_alive():                    # join 后仍存活 → 未完成收尾
            incomplete.append(f"相机线程#{index}（join 后仍存活）")
    # L1 worker 在全部提交方（相机线程）join 之后停机（合同 C-132 F10）。
    incomplete.extend(_stop_l1_components(l1_groups, l1_store))
    if l2_runtime is not None and not l2_runtime.stop(timeout=5.0):
        # C154-R1：停机未完成必须按**事实**分列，不再一律写成
        # "L2 消费线程未退出"（材料池/模型在途/backend 关闭各自独立）。
        _reasons = []
        try:
            _st = l2_runtime.execution_status()
            if isinstance(_st, dict):
                _sched = _st.get("scheduler") or {}
                if not _sched.get("stopped", True):
                    _reasons.append("消费线程未退出")
                _unfinished = _st.get("executions_unfinished") or {}
                if _unfinished.get("count"):
                    _reasons.append(
                        f"模型调用仍在途({_unfinished.get('count')})")
                _close = _st.get("resources_close_incomplete") or {}
                if _close.get("incomplete"):
                    _reasons.append("backend 关闭未完成")
        except Exception:
            pass
        try:
            _pool = l2_runtime.material_pool_status()
            if isinstance(_pool, dict) and _pool.get("available") \
                    and not _pool.get("complete", True):
                _reasons.append("材料池未完成")
        except Exception:
            pass
        incomplete.append("L2 关系阶段（" + (
            "、".join(_reasons) if _reasons else "原因未分类") + "）")
    if crop_worker is not None:
        crop_worker.close(timeout_s=5.0)
        if not crop_worker.join(timeout_s=5.0):
            incomplete.append("原始裁图工作者（线程未退出）")
    if semantic_updater is not None:
        semantic_updater.stop(timeout=5)
    if incomplete:
        print("[NVR] 停机未完成（以下组件线程仍在运行，资源未完全释放）："
              + "；".join(incomplete))
    else:
        print("[NVR] 已停机")
    # 事实性收尾上报：incomplete 非空即"已停止但未完成"，壳不得当正常完成。
    # 退出码与握手一致地表示"是否未完成"：未完成 → 3，完整停止 → 0。
    exit_code = 3 if incomplete else 0
    _lifecycle("stopped", incomplete=list(incomplete), exit_code=exit_code)
    return exit_code


if __name__ == "__main__":
    main()
