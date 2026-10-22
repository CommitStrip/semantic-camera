"""monitor.py —— 单相机快系统值守循环（T0 门控 → T1 检测 → 裁决 → 告警）。

报警路径零慢层：本循环全程不碰 JEPA/VLM。
按区域独立判定与滞留计时；边沿触发锁存（同一驻留事件只报一次，
离区自动复位）；轨迹消亡即清理滞留表与锁存（防长期值守慢泄漏）。
"""

import threading
import time
import uuid

from .gate import MotionGate
from .track import Tracker
from .verdict import ZoneRuntime, rule_fires
from .zones import Grid, normalize_zones


def to_gray(frame_bgr, gw=96):
    """帧 → 降采样扁平灰度序列（快系统口径，纯 cv2）。"""
    import cv2
    h, w = frame_bgr.shape[:2]
    gh = max(1, round(gw * h / w))
    small = cv2.resize(frame_bgr, (gw, gh))
    gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)
    return gray.reshape(-1).tolist()


class Monitor:
    """单相机快系统值守。

    camera_cfg: {id, zones:[{id,name,cells,rules[]}], grid:{rows,cols}}
    detect_fn:  frame_bgr → dets（生产=NanoDet.detect，测试=注入脚本）
    sinks:      告警出口列表（callable(alarm)）
    """

    MOTION_DET_INTERVAL = 400
    PATROL_INTERVAL = 5000
    GRAY_W = 96
    REVIEW_IDLE_CUTOFF = 20.0
    # 审查段写失败后的最小重试间隔：不忙轮询，但也不放弃（旧段被收口后即可建立）
    REVIEW_OPEN_RETRY_MS = 1000.0
    # 事件事实写失败后的最小重试间隔（合同 v1.1 边界1：失败重试 + 幂等重放）
    EVENT_OPEN_RETRY_MS = 1000.0
    # 断流宽限：短暂断流保留开放事件；超过即收口（end_reason=stream-lost），
    # 不允许事件无限期保持 open（合同 v1.1 边界3）
    STREAM_LOST_GRACE_S = 30.0
    # ---- L1 异步检测消费（合同 C132 F4/F6 + C133 T1/T2；仅 detection_mode=
    # "async" 参与，sync 路径一个字节的行为都不碰）----
    DETECTION_LOST_MS = 8000.0     # 距最后 ok/empty 结果超过即满足失联持续条件
    DETECTION_MAX_AGE_MS = 2500.0  # 结果相对当前帧时间超龄即拒收（不消费）
    RESULT_WAIT_MS = 3500.0        # 管道最老未完结任务无进展阈值（探针口径，
                                   # 管道 TTL 2000+1500 余量）
    CONTINUITY_MAX_GAP_MS = 6000.0  # ok 结果连续性上限（≥巡检1500+双相机共享
                                    # worker 的健康滞后上限）：ok 消费点间隙
                                    # 超限即未知间隙，滞留不补算（C133 T1）
    MATERIAL_LATEST_MS = 400.0     # motion 中 latest 材料节奏
    MATERIAL_PATROL_MS = 1500.0    # 静止中 patrol 材料节奏（< tracker MAX_AGE
                                   # 2000：未确认轨迹能两次巡检完成确认，F6）

    def __init__(self, camera_cfg, detect_fn, sinks, seq=0, run_id=None,
                 detection_mode="sync",
                 continuity_max_gap_ms=CONTINUITY_MAX_GAP_MS,
                 detection_lost_ms=DETECTION_LOST_MS,
                 detection_max_age_ms=DETECTION_MAX_AGE_MS,
                 result_wait_ms=RESULT_WAIT_MS):
        self.camera_id = camera_cfg["id"]
        self.detect_fn = detect_fn
        self.sinks = sinks
        self.grid = Grid(**(camera_cfg.get("grid") or {}))
        self.zones = self._runtime_zones(normalize_zones(
            camera_cfg.get("zones") or [], self.grid))
        self._zone_lock = threading.Lock()
        self._pending_zones = None
        self._zone_requested_revision = 0
        self.zone_revision = 0
        self.gate = MotionGate()
        self.tracker = Tracker()
        self.zone_rt = ZoneRuntime()
        self.last_det = None
        self.seq = seq
        self.run_id = run_id or uuid.uuid4().hex[:12]
        self.violations = 0
        self._alarm_fired = set()   # (track_id, zone_id, cls, template) 边沿锁存
        self._occurrence = {}       # 同键第几次驻留事件（event_id 稳定键）
        self._prev_live = set()     # 上一帧活跃轨迹 id（消亡检测）
        self._open_events = {}      # 规则锁存键 → semantic_event_id
        self._review = None
        self._review_seq = 0
        self.frames = 0
        self.motion_frames = 0
        self.det_calls = 0
        self.alarms = 0
        self.last_alarm_ms = None
        self.max_latency_ms = 0
        self.sink_failures = 0
        self.last_sink_error = None
        self.latest_frame_bgr = None
        # F9：审查段写入失败不得被当成已持久化。开段失败时保留内存段身份，
        # 但标记未落库、按最小间隔重试，并把这一段的告警挂起等补写。
        self.review_open_failures = 0
        self._deferred_alarms = []
        # 事件事实（合同 v1.1）：track_id → 内存账目。内存条目不是持久化事实，
        # 写库失败按最小间隔重试；未落库期间健康面如实报降级。
        self._event_facts = {}      # track_id -> entry（pending-open/open）
        self._event_close_pending = []
        # 同一 track 的新出现（旧事件已收口后重现）必须拿到新事件身份；
        # 出现序号保证 event_id 永不撞上已闭合行。
        self._event_occurrence = {}
        self.event_open_failures = 0
        self.stream_lost_since = None
        self.stream_lost_closed = False
        # 源时间可信度由 nvr 逐帧标注；不可信源的时间退回处理时间并在
        # 事件 payload 里如实记录（不产出虚假延迟指标）。
        self.timestamp_kind = None
        # ---- L1 异步检测消费（合同 C132 F4/F6 + C133 T1/T2）：sync 模式下全部惰性 ----
        self.detection_mode = detection_mode
        self.continuity_max_gap_ms = float(continuity_max_gap_ms)
        self.detection_lost_ms = float(detection_lost_ms)
        self.detection_max_age_ms = float(detection_max_age_ms)
        self.result_wait_ms = float(result_wait_ms)
        self._material_sink = None   # 快系统材料出口（set_material_sink 接线）
        self._progress_probe = None  # 管道进展探针（set_progress_probe 接线，T2）
        self._pending_result = None  # apply 已验身份、待 step 消费的结果
        self._conclusion = None      # R1 统一消费结论
        self._conclusion_delivered = False  # C-134 一次性语义：已下行即不再消费
        self._last_result_ms = None  # 最近一次 ok/empty 结果的采集时间
        self._last_applied_capture_ms = None  # 乱序/迟到拒收基准
        self._last_material_ms = None  # 最近一次材料提交尝试时刻
        self._last_consumed_frame_id = None  # 上一消费帧 frame_id（F4 顺序基准）
        self._dwell_snapshot = None  # T1 上次 ok 消费点的在区配对滞留快照
        self._dwell_interrupted = False  # 上次 ok 消费后有无 empty/失败介入
        self._material_in_motion = False  # 材料侧运动锁存（静→动边沿检测）
        self.l1_health = None           # {"state","code","at"} 最近 L1 健康
        self.results_applied = 0        # 已消费（含失败态）的结果数
        self.results_rejected_expired = 0
        self.results_rejected_future = 0
        self.results_rejected_order = 0
        self.results_rejected_identity = 0
        self.results_invalidated_config = 0
        self.results_superseded = 0
        self.detection_lost_closes = 0
        self.material_rejected = 0

    def step(self, frame_bgr, gray, now):
        """推进一帧；返回本步产生的告警列表。"""
        zone_switched = self._apply_pending_zones(now)
        self._retry_pending_event_closes(now)
        # 仅原子替换引用；JPEG缩放/编码由工作台请求线程按需完成，不占报警快路径。
        self.latest_frame_bgr = frame_bgr
        self.frames += 1
        gw = self.GRAY_W
        gh = max(1, round(len(gray) / gw))
        if self.detection_mode == "async":
            # prev_available 必须取本帧处理前的门控状态（detect 会覆盖 prev）
            had_prev = self.gate.prev is not None
        boxes = self.gate.detect(gray, gw, gh)
        if self.gate.last_ratio > 0:
            self.motion_frames += 1
        if self.detection_mode == "async":
            # async：材料选择 + 消费 L1 结果；上方共用流程与 sync 逐字节同效
            return self._step_async(frame_bgr, boxes, gray, now, gh,
                                    had_prev, zone_switched)
        interval = (self.MOTION_DET_INTERVAL if self.gate.last_ratio > 0
                    else self.PATROL_INTERVAL)
        observed_ids = None
        if self.last_det is None or now - self.last_det >= interval:
            self.last_det = now
            self.det_calls += 1
            self.gate.reset_background(gray)
            dets = self.detect_fn(frame_bgr) or []
            observed = self.tracker.update(dets, now)
            observed_ids = {track["id"] for track in observed
                            if track.get("confirmed")}

        return self._post_detection(observed_ids, now, frame_bgr)

    # ---- L1 异步检测结果消费（合同 C131 §2；sync 路径不进） --------------

    def set_material_sink(self, fn):
        """接线快系统材料出口（async 模式）；None=关闭。

        fn(material_dict) 在相机线程内同步调用，必须非阻塞；返回 False
        表示未受理（计 material_rejected，材料机会不重置门控背景）。
        """
        self._material_sink = fn

    def set_progress_probe(self, fn):
        """接线管道进展探针（合同 C133 T2，async 模式）；None=关闭。

        fn() 由管道侧提供、经 nvr 注入：返回该相机**最老未完结任务**的年龄
        毫秒（槽内或推理中；合并/替换/过期任务已出槽不算；无任务返回
        None）。每帧至多调用一次、必须廉价；monitor 不 import 管道模块。
        看门狗以此为准：卡住任务的年龄持续增长，新提交再多也不重置。
        """
        self._progress_probe = fn

    def apply_detection_result(self, result, now):
        """帧循环逐帧调用（非阻塞）：核验结果身份后存入待消费槽。

        apply 只验"是谁的、是不是旧"：相机/运行不匹配、旧配置版本、
        乱序/迟到（采集时间早于已受理基准）一律计 results_rejected_identity
        并返回 False；通过后占据待消费槽（顶掉未消费旧结果计
        results_superseded）并返回 True。消费时的新鲜度校验在 step() 内。
        每个被判定的结果都产生统一消费结论（R1），供生产侧如实关联材料——
        被拒结果只作诊断，绝不冒充有效检测。
        """
        t_capture = getattr(result, "t_capture_ms", None)
        if (getattr(result, "camera_id", None) != self.camera_id
                or getattr(result, "run_id", None) != self.run_id
                or getattr(result, "config_version", None)
                != self.zone_revision
                or t_capture is None
                or (self._last_applied_capture_ms is not None
                    and t_capture < self._last_applied_capture_ms)):
            self.results_rejected_identity += 1
            self._record_conclusion(result, False, "identity")
            return False
        self._last_applied_capture_ms = t_capture
        if self._pending_result is not None:
            self.results_superseded += 1
        self._pending_result = result
        return True

    def _record_conclusion(self, result, accepted, reason):
        self._conclusion = self._make_conclusion(result, accepted, reason)
        self._conclusion_delivered = False

    @staticmethod
    def _make_conclusion(result, accepted, reason):
        """R1 统一消费结论：模型原始输出与 Monitor 裁决的唯一下行通道。"""
        return {"camera_id": getattr(result, "camera_id", None),
                "run_id": getattr(result, "run_id", None),
                "config_version": getattr(result, "config_version", None),
                "frame_id": getattr(result, "frame_id", None),
                "status": getattr(result, "status", None),
                "error_code": getattr(result, "error_code", None),
                "detections": (list(getattr(result, "detections", None) or [])
                               if accepted else []),
                "accepted": bool(accepted),
                "reason": reason}

    def consume_conclusion(self):
        """取走最近一次结果判定的统一结论（C-134：一次性语义）。

        同一真实结果的接受/拒收结论只下行关联一次：consume 返回该结论并
        标记已消费，再次调用返回 None——后续普通帧绝不重放历史结论（修复
        C-133 复现的"每帧重复 attach/attach_missed 虚增"）。最近结论仍可经
        last_conclusion() 作诊断展示，但不再作为新结果消费。
        """
        if self._conclusion is None or self._conclusion_delivered:
            return None
        self._conclusion_delivered = True
        return self._conclusion

    def last_conclusion(self):
        """诊断视图：最近一次结论原样可读（不改变消费状态）。"""
        return self._conclusion

    def _step_async(self, frame_bgr, boxes, gray, now, gh, prev_available,
                    zone_switched=False):
        """async 模式一帧：材料选择 → 消费就绪 L1 结果（五重复核）→ 共用裁决。

        快系统永不等待模型：本路径绝不调用 detect_fn，检测结果只经
        apply_detection_result 进入。事实工作（滞留/对象事实/事件/审查活跃）
        只发生在 ok/empty 消费点，且按结果帧的 t_capture 推进（F1/F4）；
        非消费帧零事实工作（_idle_step），绝不拿缓存轨迹冒充新观察——
        不存在"非消费帧即冻结"的语义，滞留按 T1 连续性只在 ok 消费点推进。
        消费帧的时间线与证据帧都取自结果本身（同画面绑定，不拿新帧配旧框）。
        """
        self._select_material(frame_bgr, boxes, gray, now, gh,
                              prev_available)
        result = self._pending_result
        self._pending_result = None
        if result is not None:
            if zone_switched:
                # F4：apply 后区域已切换——待消费结果直接失效（旧配置的框
                # 对新区域不再可信），不得消费。
                self.results_invalidated_config += 1
                self._record_conclusion(result, False,
                                        "invalidated_config")
                result = None
            else:
                checked = self._recheck_result(result, now)
                if checked is None:
                    # 复核拒收：_recheck_result 内已记结论与计数
                    result = None
                else:
                    result = checked
        if result is not None:
            self.results_applied += 1   # 已消费（含失败态）
            frame_id = getattr(result, "frame_id", None)
            if frame_id is not None:
                self._last_consumed_frame_id = frame_id
            # R1：消费成立（ok/empty 事实推进、失败态作进展），结论如实下行
            self._record_conclusion(result, True, None)
        if result is not None and result.status in ("ok", "empty"):
            # 消费帧：区域/审查时间线与证据帧都用结果帧（同画面）
            t_capture = result.t_capture_ms
            continuous = (
                self._last_result_ms is not None
                and t_capture - self._last_result_ms
                <= self.continuity_max_gap_ms
                and not self._dwell_interrupted)
            self._last_result_ms = t_capture
            self.l1_health = {"state": "ready", "code": None, "at": now}
            observed = self.tracker.update(result.detections or [],
                                           t_capture)
            observed_ids = {track["id"] for track in observed
                            if track.get("confirmed")}
            if result.status == "ok":
                # T1：滞留只在 ok 消费点推进——连续则 enter 不动自然增长；
                # 未知间隙（超限或有 empty/失败介入）平移 enter 不补算
                self._advance_dwell_continuity(observed_ids, t_capture,
                                               continuous)
                self._dwell_interrupted = False
            else:
                # empty：本帧无观察——只标记间隙不连续；轨迹离区/消亡仍按
                # 既有路径复位滞留
                self._dwell_interrupted = True
            alarms = self._post_detection(observed_ids, t_capture,
                                          result.frame_bgr)
            if result.status == "ok":
                # T1：消费点快照全部在区配对滞留（含本帧新进区配对），供
                # 下一次 ok 消费做连续性判定
                self._dwell_snapshot = self.zone_rt.pause_open(t_capture)
            return alarms
        if result is not None:
            # 模型失败：不碰 tracker、不伪造观察；健康面如实记录失败态；
            # 间隙按不连续处理（滞留不跨失败窗口累计）
            self.l1_health = {"state": result.status,
                              "code": result.error_code, "at": now}
            self._dwell_interrupted = True
        return self._idle_step(now)

    def _recheck_result(self, result, now):
        """F4 消费阶段复核：身份/未来/超龄/顺序四验，失败按原因计数拒收。

        apply 阶段验过一次（当时的 zone_revision）；apply 与 step 之间配置、
        时钟与帧序都可能变化，消费前必须再验。拒收的结果不消费、不触碰
        tracker、不续失联计时基准（_last_result_ms），也不得冒充一次"本轮
        无对象"的观察。
        """
        t_capture = getattr(result, "t_capture_ms", None)
        if (getattr(result, "camera_id", None) != self.camera_id
                or getattr(result, "run_id", None) != self.run_id
                or getattr(result, "config_version", None)
                != self.zone_revision):
            self.results_rejected_identity += 1
            self._record_conclusion(result, False, "identity")
            return None
        if t_capture is None or t_capture > now + 100.0:
            # 未来异常时间：观察时间不得来自未来（F1）
            self.results_rejected_future += 1
            self._record_conclusion(result, False, "future")
            return None
        if now - t_capture > self.detection_max_age_ms:
            # 过期结果拒收不消费（帧时间只前进，留着只会反复过期）
            self.results_rejected_expired += 1
            self._record_conclusion(result, False, "expired")
            return None
        frame_id = getattr(result, "frame_id", None)
        if (frame_id is not None
                and self._last_consumed_frame_id is not None
                and frame_id <= self._last_consumed_frame_id):
            # 重复/乱序拒；同时间戳不同 frame_id（严格递增）视为正常顺序
            self.results_rejected_order += 1
            self._record_conclusion(result, False, "order")
            return None
        return result

    def _advance_dwell_continuity(self, observed_ids, t_capture, continuous):
        """T1 连续性推进（只在 ok 消费点调用）：自然增长或平移，不补算。

        连续（gap ≤ CONTINUITY_MAX_GAP_MS 且期间无 empty/失败介入）：enter
        从未被非消费帧触碰，dwell = t_capture − enter 自然增长，无需动作。
        不连续（间隙超限或有 empty/失败介入）：未知间隙不补算——按上次 ok
        消费点快照把仍在原区的配对 enter 平移为 t_capture − 快照滞留（已
        累计部分保留，间隙不记）；已离区/轨迹已亡的配对交给本帧区域判定
        与消亡路径复位。快照一次性：无论是否平移都清空。
        """
        pairs = self._dwell_snapshot
        self._dwell_snapshot = None
        if not pairs or continuous:
            return
        for (tid, zid), dwell in pairs.items():
            track = self.tracker.tracks.get(tid)
            if track is None or not track.get("confirmed") \
                    or tid not in observed_ids:
                continue
            cx = track.get("cx", track["bbox"][0] + track["bbox"][2] / 2.0)
            cy = track.get("cy", track["bbox"][1] + track["bbox"][3] / 2.0)
            cell = self.grid.cell_of(cx, cy)
            for zone in self.zones:
                if zone["id"] == zid and cell in zone["cells"]:
                    self.zone_rt.restore_pair(tid, zid, dwell, t_capture)
                    break

    def _idle_step(self, now):
        """非消费帧：零事实工作（合同 T1）。

        不更新对象事实、不推进事件 t_last、不累计滞留、不延展审查段活跃、
        不产告警、不产证据——既无暂停也无平移，更没有任何快照动作。仅允许：
        审查段空闲收口、待写收口重试（step 顶部已做）、失联看门狗（T2 探针
        口径）。绝不拿处理帧时间推进对象存在时间，也绝不凭空续命。
        """
        self._detection_lost_watchdog(now)
        self._review_step(now, set(), {}, [], None, frame_evidence=False)
        return []

    def _detection_lost_watchdog(self, now):
        """T2 失联看门狗 v3：双条件 + 开放轨迹全满足才诚实收口。

        条件1（无进展）：管道探针报最老未完结任务年龄 > RESULT_WAIT_MS——
        卡住任务的年龄持续增长，新提交再多也不重置计时；或 l1_health 处于
        失败态（model_unavailable/infer_failed）。
        条件2（持续）：距最后 ok/empty 结果 > DETECTION_LOST_MS。
        两条件同时成立才 detection-lost 诚实收口（对象/语义事件/事件事实），
        随后清空 tracker。正常等待（任务已完结、仅预览/无任务 probe=None、
        l1 健康）永不触发；"正常未安排检测"≠失联。
        """
        if not self.tracker.tracks or self._last_result_ms is None:
            return
        if now - self._last_result_ms <= self.detection_lost_ms:
            return
        l1_failed = (self.l1_health or {}).get("state") in (
            "model_unavailable", "infer_failed")
        stalled = False
        if not l1_failed and self._progress_probe is not None:
            oldest = self._progress_probe()
            stalled = oldest is not None and oldest > self.result_wait_ms
        if not (l1_failed or stalled):
            return
        for tid in list(self.tracker.tracks):
            # 滞留表一并清理：track id 单调递增，残留会慢泄漏（同 sync）
            for zone in self.zones:
                self.zone_rt.leave(tid, zone["id"])
            self._release(tid, None, now, "detection-lost")
            self._call_sinks(
                "close_object", self._object_id(tid),
                t_end=now / 1000.0, reason="detection-lost")
            self._close_event_fact(tid, "detection-lost", now)
        self.tracker.tracks.clear()
        self._prev_live = set()
        self._dwell_snapshot = None
        self.detection_lost_closes += 1

    def _select_material(self, frame_bgr, boxes, gray, now, gh,
                         prev_available):
        """快系统材料出口（合同 §2.2）：变化边沿 / 最新画面 / 巡检三理由。

        frame_bgr 按引用交出（sink 侧负责 copy，monitor 不复制）；材料被
        受理后才以当前帧重置门控背景（与 sync 检测帧同节奏；被拒收不重置，
        保留运动信号等下一节奏重试）。材料机会绝不阻塞帧循环：失败只计数。
        """
        if self._material_sink is None:
            return
        motion = bool(boxes)
        reason = None
        if motion and not self._material_in_motion:
            reason = "change_start"    # 静→动边沿：变化开始帧最优先
        elif motion:
            if (self._last_material_ms is None
                    or now - self._last_material_ms
                    >= self.MATERIAL_LATEST_MS):
                reason = "latest"
        elif (self._last_material_ms is None
                or now - self._last_material_ms >= self.MATERIAL_PATROL_MS):
            reason = "patrol"
        self._material_in_motion = motion
        if reason is None:
            return
        material = {
            "camera_id": self.camera_id,
            "run_id": self.run_id,
            "frame_id": self.frames,
            "t_capture_ms": now,
            "frame_bgr": frame_bgr,    # 引用语义；sink 侧负责 copy
            "reason": reason,
            "change_boxes": [] if reason == "patrol" else list(boxes),
            "gate_w": self.GRAY_W,
            "gate_h": gh,
            "config_version": self.zone_revision,
            "prev_available": prev_available,
        }
        self._last_material_ms = now
        try:
            accepted = self._material_sink(material)
        except Exception as exc:
            self.material_rejected += 1
            self._record_sink_error(self._material_sink, "material", exc)
            return
        if accepted is False:
            self.material_rejected += 1
        else:
            # 材料受理只重置门控背景（与 sync 检测帧同节奏）；看门狗进展
            # 基准是管道任务年龄（T2 探针），提交受理不重置任何失联计时。
            self.gate.reset_background(gray)

    def _post_detection(self, observed_ids, now, frame_bgr,
                        frame_evidence=True):
        """检测已产生（或明确本轮无观察）后的共用裁决：区域/事件/审查段。

        sync 检测帧、async 消费帧、async 新鲜非消费帧共用本段；差别只在
        observed_ids（None=沿用既有轨迹）与 frame_evidence（False=本轮
        不携带证据帧：observe_object 与告警缩略图都不拿新帧配旧框）。
        """
        alarms = []
        live_ids = set()
        activity_ids = set()
        active_zones = {}
        for t in self.tracker.tracks.values():
            if not t.get("confirmed"):
                continue
            live_ids.add(t["id"])
            # 没有到检测节奏时沿用现有轨迹；本轮检测明确未观察到的旧轨迹
            # 只等待 Tracker 老化，不继续累计活动、滞留或审查时长。
            if observed_ids is not None and t["id"] not in observed_ids:
                continue
            activity_ids.add(t["id"])
            cx = t.get("cx", t["bbox"][0] + t["bbox"][2] / 2.0)
            cy = t.get("cy", t["bbox"][1] + t["bbox"][3] / 2.0)
            cell = self.grid.cell_of(cx, cy)
            for zone in self.zones:
                zid = zone["id"]
                if cell in zone["cells"]:
                    active_zones.setdefault(t["id"], []).append(zid)
                    dwell = self.zone_rt.update(t["id"], zid, True, now)
                    for r in zone["rules"]:
                        skey = self._skey(t, zid, r)
                        if skey in self._alarm_fired:
                            continue
                        if rule_fires(r, t["cls"], True, dwell):
                            self._alarm_fired.add(skey)
                            alarm = self._alarm(
                                t, r, dwell, now, zid,
                                frame_bgr if frame_evidence else None)
                            self._open_events[skey] = alarm["event_id"]
                            alarms.append(alarm)
                            break
                else:
                    # 离区：滞留表复位 + 锁存复位（再次进入视为新事件）
                    self.zone_rt.leave(t["id"], zid)
                    self._release(t["id"], zid, now, "zone-leave")

        # 轨迹消亡：滞留表与锁存全量清理（track id 单调递增，不清理会慢泄漏）
        for tid in self._prev_live - live_ids:
            for zone in self.zones:
                self.zone_rt.leave(tid, zone["id"])
            self._release(tid, None, now, "track-lost")
            self._call_sinks(
                "close_object", self._object_id(tid),
                t_end=now / 1000.0, reason="track-lost")
            self._close_event_fact(tid, "track-lost", now)
        self._prev_live = live_ids

        review_id = self._review_step(
            now, activity_ids, active_zones, alarms, frame_bgr,
            frame_evidence=frame_evidence)
        for alarm in alarms:
            alarm["review_id"] = review_id
            alarm["object_id"] = self._object_id(alarm["track_id"])

        self.alarms += len(alarms)
        for a in alarms:
            self.max_latency_ms = max(
                self.max_latency_ms, a.get("latency_ms", 0))
            truth_failed = False
            for sink in self.sinks:
                # 只有真值出口（能写语义事件的那个）失败才谈得上"告警没落库"；
                # 旁路出口（横幅/JSONL/证据旁路）坏了不影响真值已写入的事实。
                is_truth = hasattr(sink, "write_semantic_event")
                try:
                    if sink(a) is False and is_truth:
                        truth_failed = True
                except Exception as exc:
                    self._record_sink_error(sink, "alarm", exc)
                    if is_truth:
                        truth_failed = True
            if truth_failed and self._review is not None \
                    and not self._review["persisted"]:
                # 审查段还没落库：真值写入必然被外键拒绝。挂起等补写，
                # 绝不把"没写进去"计成成功，也不丢这条告警。
                self._deferred_alarms.append(a)
            elif not truth_failed:
                # 规则告警真值已落库：把语义事件幂等挂到同一目标的事件事实上
                #（显式关联，不靠事后猜测；合同 v1.1 边界4）。
                self._link_escalation(a)
        if alarms:
            self.last_alarm_ms = now
        return alarms

    def stats(self):
        """工作台可读的运行计数；不把模块存在冒充为主机质量证据。"""
        return {
            "camera": self.camera_id,
            "frames": self.frames,
            "motion_frames": self.motion_frames,
            "det_calls": self.det_calls,
            "alarms": self.alarms,
            "max_latency_ms": self.max_latency_ms,
            "last_alarm_ms": self.last_alarm_ms,
            "motion_ratio": round(self.gate.last_ratio, 4),
            "tracks": len(self.tracker.get_confirmed()),
            "open_events": len(self._open_events),
            "review_open": self._review is not None,
            "event_facts_open": sum(
                1 for entry in self._event_facts.values()
                if entry["state"] == "open"),
            "stream_lost": self.stream_lost_since is not None,
            "sink_failures": self.sink_failures,
            "last_sink_error": self.last_sink_error,
            "zone_revision": self.zone_revision,
            "zone_update_pending": self._pending_zones is not None,
            # L1 异步检测消费（合同 C131 §2 末）；sync 模式下恒为默认值
            "detection_mode": self.detection_mode,
            "l1_state": (self.l1_health or {}).get("state"),
            "l1_last_result_age_ms": (
                None if self._last_result_ms is None else
                max(0.0, time.time() * 1000.0 - self._last_result_ms)),
            "results_applied": self.results_applied,
            "results_rejected_expired": self.results_rejected_expired,
            "results_rejected_future": self.results_rejected_future,
            "results_rejected_order": self.results_rejected_order,
            "results_rejected_identity": self.results_rejected_identity,
            "results_invalidated_config": self.results_invalidated_config,
            "results_superseded": self.results_superseded,
            "detection_lost_closes": self.detection_lost_closes,
        }

    @staticmethod
    def _runtime_zones(zones):
        return tuple({"id": zone["id"], "name": zone.get("name", zone["id"]),
                      "cells": set(zone["cells"]),
                      "rules": [dict(rule) for rule in zone["rules"]]}
                     for zone in zones)

    def request_zone_update(self, zones):
        """从工作台排队一份已校验区域；只在下个视频帧边界切换。"""
        prepared = self._runtime_zones(normalize_zones(zones, self.grid))
        with self._zone_lock:
            self._zone_requested_revision += 1
            revision = self._zone_requested_revision
            self._pending_zones = (revision, prepared)
        return revision

    def _apply_pending_zones(self, now):
        with self._zone_lock:
            pending = self._pending_zones
            self._pending_zones = None
        if pending is None:
            return False
        revision, zones = pending
        # 旧规则的开放事件必须在同一帧边界关闭，不能成为配置变更后的幽灵事件。
        keys = set(self._alarm_fired) | set(self._open_events)
        for track_id in {key[0] for key in keys}:
            self._release(track_id, None, now, "zone-reconfigured")
        self._alarm_fired.clear()
        self._open_events.clear()
        self.zone_rt = ZoneRuntime()
        # 旧配置的消费点滞留快照一并作废：配对引用旧 zone 身份，不得恢复进新配置
        self._dwell_snapshot = None
        self.zones = zones
        self.zone_revision = revision
        return True

    def _object_id(self, track_id):
        return f"{self.camera_id}:{self.run_id}:track:{track_id}"

    def _release(self, track_id, zone_id, now, reason):
        keys = [key for key in self._alarm_fired
                if key[0] == track_id and
                (zone_id is None or key[1] == zone_id)]
        event_ids = []
        for key in keys:
            self._alarm_fired.discard(key)
            event_id = self._open_events.pop(key, None)
            if event_id:
                event_ids.append(event_id)
        if event_ids:
            self._call_sinks(
                "close_semantic_events", event_ids,
                t_end=now / 1000.0, reason=reason)

    def _review_step(self, now, live_ids, active_zones, alarms, frame_bgr,
                     frame_evidence=True):
        """每相机聚合一个活动段；检测开段，管理员规则告警只负责升级。

        frame_evidence=False（async 非消费帧）时 observe_object 不带证据帧：
        绝不拿新帧给旧检测结果配图（同画面绑定，合同 C131 §0）。
        """
        if live_ids:
            if self._review is None:
                self._review_seq += 1
                review_id = (f"{self.camera_id}:{self.run_id}:review:"
                             f"{self._review_seq}")
                self._review = {
                    "review_id": review_id,
                    "t_start": now / 1000.0,
                    "last_active_ms": now,
                    "severity": "detection",
                    "objects": set(),
                    "events": set(),
                    "zones": set(),
                    "detections": {},
                    "alarms": 0,
                    # F9：只有当开段真的写进数据库才置 True。同相机唯一开放段
                    # 被别的进程占用时这里会是 False——内存段仍在，但绝不冒充
                    # 已持久化，也不去接管别人的段。
                    "persisted": False,
                    "next_open_retry_ms": now,
                }
            review = self._review
            if not review["persisted"] and now >= review["next_open_retry_ms"]:
                review["next_open_retry_ms"] = now + self.REVIEW_OPEN_RETRY_MS
                if self._call_sinks(
                        "open_review", review_id=review["review_id"],
                        camera=self.camera_id, t_start=review["t_start"],
                        object_ids=sorted(review["objects"]),
                        payload={"zones": sorted(review["zones"]),
                                 "alarms": review["alarms"]}):
                    review["persisted"] = True
                    self._flush_deferred_truth()
                else:
                    self.review_open_failures += 1
            review["last_active_ms"] = now
            review["alarms"] += len(alarms)
            if alarms:
                review["severity"] = "alert"
                review["events"].update(a["event_id"] for a in alarms)
            for track_id in live_ids:
                track = self.tracker.tracks.get(track_id) or {}
                object_id = self._object_id(track_id)
                zones = active_zones.get(track_id, [])
                review["objects"].add(object_id)
                review["zones"].update(zones)
                review["detections"][object_id] = track.get("cls", "")
                # 证据帧只在消费帧携带（False=本轮没有同画面帧，宁缺勿假）
                evidence = ({"frame_bgr": frame_bgr}
                            if frame_evidence else {})
                object_ok = self._call_sinks(
                    "observe_object", object_id=object_id,
                    camera=self.camera_id,
                    t_start=track.get("bornAt", now) / 1000.0,
                    t_last=now / 1000.0, cls=track.get("cls", ""),
                    conf=track.get("conf"), zones=zones,
                    review_id=review["review_id"],
                    payload={"track_id": track_id},
                    bbox=track.get("bbox"), **evidence)
                # 边界2（存储顺序）：对象事实先可靠落库，事件事实才允许建立；
                # 对象写入失败时事件保持待写（pending-object），对象恢复后补建。
                self._event_fact_step(track_id, track, now, object_ok=object_ok,
                                      zones=zones)
            if review["persisted"]:
                payload = {
                    "zones": sorted(review["zones"]),
                    "detections": review["detections"],
                    "alarms": review["alarms"],
                }
                self._call_sinks(
                    "update_review", review["review_id"],
                    t_last=now / 1000.0, severity=review["severity"],
                    object_ids=sorted(review["objects"]),
                    semantic_event_ids=sorted(review["events"]),
                    payload=payload)
            return review["review_id"]

        if self._review is not None and (
                now - self._review["last_active_ms"] >=
                self.REVIEW_IDLE_CUTOFF * 1000.0):
            review = self._review
            self._call_sinks(
                "close_review", review["review_id"],
                t_end=review["last_active_ms"] / 1000.0,
                reason="idle-timeout")
            self._review = None
        return self._review["review_id"] if self._review else None

    def persistence_state(self):
        """数据面（审查段/语义事件/事件事实）当前是否尚未落库；供值守线程上报。

        ``degraded`` 只说"现在有没有真值没落地"：审查段尚未落库、还有挂起
        待补写的告警、或事件事实仍在 open/收口重试中。累计计数另外给出，
        便于排查但不单独作为故障判据。
        """
        review = self._review
        unpersisted = bool(review is not None and not review["persisted"])
        event_pending = sum(
            1 for entry in self._event_facts.values()
            if entry["state"] != "open") + len(self._event_close_pending)
        return {
            "review_open_failures": self.review_open_failures,
            "review_unpersisted": unpersisted,
            "deferred_alarms": len(self._deferred_alarms),
            "event_open_failures": self.event_open_failures,
            "event_facts_unpersisted": event_pending,
            "sink_failures": self.sink_failures,
            "degraded": (unpersisted or bool(self._deferred_alarms)
                         or event_pending > 0),
        }

    def _event_fact_id(self, track_id):
        occ = self._event_occurrence.get(track_id, 0)
        suffix = f":{occ}" if occ > 1 else ""
        return f"{self.camera_id}:{self.run_id}:event:{track_id}{suffix}"

    def _event_fact_step(self, track_id, t, now, object_ok=True, zones=None):
        """事件事实生命周期（合同 v1.1）：无规则也建立，独立于审查段落库状态。

        存储顺序（边界2）：对象事实先可靠落库，事件才允许建立——对象写入失败
        时事件保持 pending-object 待写（健康面可见），对象恢复后补建。
        内存条目不是持久化事实：open/update 失败回到 pending-open，按最小
        间隔借幂等 open 重申整行；未落库期间 persistence_state() 报降级，
        绝不把"内存里见过目标"冒充"事件已保存"。open 返回"未真正落为
        open"（如同 track 撞上已闭合行）时换下一个出现序号重试。
        """
        entry = self._event_facts.get(track_id)
        if entry is None:
            occ = self._event_occurrence.get(track_id, 0) + 1
            self._event_occurrence[track_id] = occ
            entry = {
                "event_id": self._event_fact_id(track_id),
                "occurrence": occ,
                "state": "pending-object" if not object_ok else "pending-open",
                "next_retry_ms": 0.0,
                "t_start": t.get("bornAt", now) / 1000.0,
                "cls": t.get("cls", ""),
                "bbox_first": t.get("bbox"),
                "last": {},
                "zones": [],
                "escalations": [],
                "review_linked": False,
            }
            self._event_facts[track_id] = entry
        # 最后可信观察始终记入内存账目：事件未落库即结束时，随快照补建收口
        entry["last"] = {"t_last": now / 1000.0, "conf": t.get("conf"),
                         "bbox_last": t.get("bbox")}
        entry["payload"] = {"track_id": track_id,
                            "timestamp_kind": self.timestamp_kind}
        if zones:
            entry["zones"] = list(zones)
        if entry["state"] == "pending-object":
            if not object_ok:
                return
            entry["state"] = "pending-open"   # 对象已可靠落库，允许建事件
            entry["next_retry_ms"] = 0.0
        review = self._review
        review_id = review["review_id"] if review else None
        review_persisted = bool(review and review["persisted"])
        bbox = t.get("bbox")
        payload = entry["payload"]
        if entry["state"] == "pending-open" and now >= entry["next_retry_ms"]:
            entry["next_retry_ms"] = now + self.EVENT_OPEN_RETRY_MS
            if self._call_sinks(
                    "open_event_fact", event_id=entry["event_id"],
                    camera=self.camera_id, object_id=self._object_id(track_id),
                    t_start=entry["t_start"], cls=entry["cls"],
                    conf=t.get("conf"), bbox_first=bbox, bbox_last=bbox,
                    review_id=(review_id if review_persisted else None),
                    payload=payload):
                # open initializes t_last at the object's first appearance.
                # The confirmation frame may be later: persist that actual
                # observation before claiming an open, current event. Otherwise
                # an immediate close loses the confirmation time and an L4
                # source frame is outside the stored fact interval.
                if self._call_sinks(
                        "update_event_fact", entry["event_id"],
                        t_last=entry["last"]["t_last"],
                        conf=entry["last"].get("conf"),
                        bbox_last=entry["last"].get("bbox_last"),
                        payload=payload):
                    entry["state"] = "open"
                else:
                    entry["state"] = "pending-open"
                    self.event_open_failures += 1
            else:
                self.event_open_failures += 1
        elif entry["state"] == "open":
            if not self._call_sinks(
                    "update_event_fact", entry["event_id"],
                    t_last=now / 1000.0, conf=t.get("conf"), bbox_last=bbox,
                    payload=payload):
                entry["state"] = "pending-open"
                entry["next_retry_ms"] = now + self.EVENT_OPEN_RETRY_MS
        if entry["state"] == "open" and not entry["review_linked"] \
                and review_persisted and review_id:
            if self._call_sinks("link_event_review", entry["event_id"],
                                review_id):
                entry["review_linked"] = True
        if entry["state"] == "open" and entry["escalations"]:
            remaining = []
            for semantic_event_id in entry["escalations"]:
                if not self._call_sinks(
                        "link_event_escalation", event_id=entry["event_id"],
                        semantic_event_id=semantic_event_id,
                        t_linked=now / 1000.0):
                    remaining.append(semantic_event_id)
            entry["escalations"] = remaining

    def _close_event_fact(self, track_id, reason, now=None):
        """闭合目标的事件事实；t_end 由存储层固定为自身 t_last（最后可信观察）。

        边界1：事件尚未入库即结束时，绝不只留一个"找不到行"的 close 重试——
        待写条目携带完整事实快照：对象侧（object_id/t_start/cls/最后观察/zones）
        与事件侧（event_id/t_start/bbox_first/最后观察/升级关联）加真实结束
        原因；不保存整帧、不凭空补造图片证据。行不存在/已闭合对存储层是幂等
        收口，不视为失败。
        """
        entry = self._event_facts.pop(track_id, None)
        if entry is None:
            return
        if now is None:
            now = time.time() * 1000.0
        item = {"event_id": entry["event_id"], "reason": reason,
                "next_retry_ms": now + self.EVENT_OPEN_RETRY_MS,
                "object_done": False, "opened": False, "updated": False,
                "fact": None}
        if entry["state"] == "open":
            if self._call_sinks("close_event_fact", entry["event_id"],
                                reason=reason):
                return
            # 行已存在：对象也已在库（open 前提），重试只需闭合事件
            item["object_done"] = True
            item["opened"] = True
            item["updated"] = True
        else:
            review = self._review
            item["fact"] = {
                "object_id": self._object_id(track_id),
                "t_start": entry["t_start"],
                "cls": entry["cls"],
                "bbox_first": entry.get("bbox_first"),
                "last": dict(entry.get("last") or {}),
                "zones": list(entry.get("zones") or []),
                "review_id": review["review_id"] if review else None,
                "escalations": list(entry.get("escalations") or []),
                "payload": entry.get("payload"),
            }
        self._event_close_pending.append(item)

    def _retry_one_event_close(self, item, now, force=False):
        """待写事件补建收口；True=完成。

        恢复顺序（复验边界2）：幂等补建/推进对象事实 → 按最后可信观察时间
        闭合对象 → 幂等补建/推进事件事实 → 按其自身 t_last 闭合事件 → 补齐
        仍有效的规则升级关联。任一步失败保留同一条待写任务，下次从安全位置
        继续；同 event_id 幂等，不生成第二个事件、不留开放对象、重试处理时间
        不冒充结束时间。
        """
        if not force and now < item["next_retry_ms"]:
            return False
        item["next_retry_ms"] = now + self.EVENT_OPEN_RETRY_MS
        fact = item.get("fact")
        if not item["object_done"]:
            if fact is None:
                return False
            # 对象事实：幂等 open+推进到最后可信观察（observe_object 两合一）
            if not self._call_sinks(
                    "observe_object", object_id=fact["object_id"],
                    camera=self.camera_id, t_start=fact["t_start"],
                    t_last=fact["last"].get("t_last"), cls=fact["cls"],
                    conf=fact["last"].get("conf"), zones=fact.get("zones"),
                    review_id=fact.get("review_id"),
                    payload=fact.get("payload")):
                return False
            # 对象按最后可信观察时间闭合（不留开放对象）
            if not self._call_sinks(
                    "close_object", fact["object_id"],
                    t_end=fact["last"].get("t_last"), reason=item["reason"]):
                return False
            item["object_done"] = True
        if not item["opened"]:
            if fact is None:
                return False
            if not self._call_sinks(
                    "open_event_fact", event_id=item["event_id"],
                    camera=self.camera_id, object_id=fact["object_id"],
                    t_start=fact["t_start"], cls=fact["cls"],
                    conf=fact["last"].get("conf"),
                    bbox_first=fact.get("bbox_first"),
                    bbox_last=fact["last"].get("bbox_last"),
                    payload=fact.get("payload")):
                return False
            item["opened"] = True
        if not item["updated"]:
            last = (fact or {}).get("last") or {}
            if last.get("t_last") is not None and not self._call_sinks(
                    "update_event_fact", item["event_id"],
                    t_last=last["t_last"], conf=last.get("conf"),
                    bbox_last=last.get("bbox_last"),
                    payload=fact.get("payload") if fact else None):
                return False
            item["updated"] = True
            # 补建路径上把挂起的规则升级关联一并落账（事件行现已存在）
            for semantic_event_id in (fact or {}).get("escalations", ()):
                self._call_sinks(
                    "link_event_escalation", event_id=item["event_id"],
                    semantic_event_id=semantic_event_id,
                    t_linked=last["t_last"])
        return self._call_sinks("close_event_fact", item["event_id"],
                                reason=item["reason"])

    def _retry_pending_event_closes(self, now):
        """闭合失败/待补建的事件事实按最小间隔重试；成功即出队。"""
        if not self._event_close_pending:
            return
        self._event_close_pending = [
            item for item in self._event_close_pending
            if not self._retry_one_event_close(item, now)]

    def _link_escalation(self, alarm):
        """规则告警 ↔ 事件事实的幂等显式关联；事实未落库时挂起等补写。"""
        fact = self._event_facts.get(alarm.get("track_id"))
        if fact is None or not any(
                hasattr(sink, "link_event_escalation") for sink in self.sinks):
            return
        if fact["state"] != "open" or not self._call_sinks(
                "link_event_escalation", event_id=fact["event_id"],
                semantic_event_id=alarm["event_id"],
                t_linked=alarm.get("t_source"),
                payload={"rule": alarm.get("rule"), "zone": alarm.get("zone")}):
            fact["escalations"].append(alarm["event_id"])

    def on_stream_lost(self, now):
        """断流登记（nvr 读失败分支逐次调用）：宽限内保留开放事件。

        超过 STREAM_LOST_GRACE_S 仍未恢复时按合同收口（end_reason=stream-lost，
        t_end=各自最后一次可信观察时间）；不允许事件无限期保持 open。
        每次调用顺带有界重试待写收口：目标已消失且源持续断开时，不能只依赖
        下一帧成功读取才有补建机会。
        """
        if self.stream_lost_since is None:
            self.stream_lost_since = now
        if (not self.stream_lost_closed
                and now - self.stream_lost_since
                >= self.STREAM_LOST_GRACE_S * 1000.0):
            for track_id in list(self._event_facts):
                self._close_event_fact(track_id, "stream-lost", now)
            self.stream_lost_closed = True
        self._retry_pending_event_closes(now)

    def on_stream_recovered(self):
        """源恢复：复位断流计时；宽限内未被收口的事件继续。"""
        self.stream_lost_since = None
        self.stream_lost_closed = False

    def close_all_event_facts(self, reason="camera-stopped"):
        """相机线程退出兜底收口（优雅停止/线程异常退出）；强杀由 F8 恢复链收口。

        返回仍未落库（未保存）的事件条数：调用方必须如实报告，绝不声称已保存。
        """
        now = time.time() * 1000.0
        for track_id in list(self._event_facts):
            self._close_event_fact(track_id, reason, now)
        self._event_close_pending = [
            item for item in self._event_close_pending
            if not self._retry_one_event_close(item, now, force=True)]
        # 待消费的 L1 结果随之作废：相机停止后不得再消费旧检测结果
        self._pending_result = None
        return len(self._event_close_pending)

    def _flush_deferred_truth(self):
        """审查段落库后补写挂起的语义事件；同 event_id 幂等，失败留待下次。"""
        if not self._deferred_alarms:
            return 0
        pending, self._deferred_alarms = self._deferred_alarms, []
        written = 0
        for alarm in pending:
            ok = True
            for sink in self.sinks:
                hook = getattr(sink, "write_semantic_event", None)
                if hook is None:
                    continue
                try:
                    if hook(alarm) is False:
                        ok = False
                except Exception as exc:
                    ok = False
                    self._record_sink_error(sink, "semantic_event", exc)
            if ok:
                written += 1
                self._link_escalation(alarm)
            else:
                self._deferred_alarms.append(alarm)
        return written

    def _call_sinks(self, method, *args, **kwargs):
        """调用所有实现了该能力的出口；返回**是否至少有一个出口写成功**。

        语义是"这条事实有没有进到某个存储里"：旁路出口（横幅/JSONL/证据旁路）
        失败不改变真值已落库的事实，因此判定用"任一成功"而不是"全部成功"；
        逐出口的失败仍逐个计入 sink 失败并保留最后一条错误，绝不静默吞掉。
        """
        any_ok = False
        for sink in self.sinks:
            callback = getattr(sink, method, None)
            if callback is None:
                continue
            try:
                if callback(*args, **kwargs) is False:
                    continue
                any_ok = True
            except Exception as exc:
                self._record_sink_error(sink, method, exc)
        return any_ok

    def _record_sink_error(self, sink, operation, exc):
        self.sink_failures += 1
        self.last_sink_error = {
            "sink": type(sink).__name__,
            "operation": operation,
            "error": str(exc),
        }

    @staticmethod
    def _skey(t, zone_id, rule):
        return (t["id"], zone_id, rule.get("cls", ""),
                rule.get("template", "enter-dwell"))

    def _alarm(self, t, rule, dwell, now, zone_id, frame_bgr=None):
        self.seq += 1
        self.violations += 1
        thumb_b64 = None
        if frame_bgr is not None:
            import cv2
            import base64
            h, w = frame_bgr.shape[:2]
            tw = 320
            th = max(1, round(tw * h / w))
            thumb = cv2.resize(frame_bgr, (tw, th))
            ok, buf = cv2.imencode(".jpg", thumb, [cv2.IMWRITE_JPEG_QUALITY, 70])
            if ok:
                thumb_b64 = base64.b64encode(buf.tobytes()).decode()
        skey = self._skey(t, zone_id, rule)
        occ = self._occurrence.get(skey, 0) + 1
        self._occurrence[skey] = occ
        template = rule.get("template", "enter-dwell")
        wall_ms = time.time() * 1000.0
        return {
            # 稳定键：不含毫秒时间戳——同一次驻留事件幂等（INSERT OR IGNORE 生效）；
            # 驻留序号区分离区再入的新事件
            "event_id": f"{self.camera_id}:{self.run_id}:alert:{t['id']}:{zone_id}:"
                        f"{template}:{occ}",
            "camera": self.camera_id,
            "zone": zone_id,
            "rule": template,
            "cls": t["cls"],
            "conf": t["conf"],
            "track_id": t["id"],
            "t_source": now / 1000.0,
            "short_name": f"重点区域{rule.get('cls', '目标')}触发",
            "detail": (f"{rule.get('cls', '目标')}进入重点管理区域，"
                       f"滞留 {dwell:.0f} 秒触发规则"),
            "rationale": f"模板 {template} 命中",
            "thumbnail": thumb_b64,
            "latency_ms": round(max(0.0, wall_ms - now)),
        }
