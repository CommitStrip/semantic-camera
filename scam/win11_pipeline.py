"""win11_pipeline.py —— 快系统→L1 中间层有界调度（Win11 专用异步对象感知）。

快系统逐帧只做轻量观察，本模块在独立线程内消费有界材料槽并执行 NanoDet：
- 每相机固定 2 个任务槽（change_start 保留最早变化开始帧 + latest 保留最新画面）
  与 1 个结果槽；全局容量 2N，永不随帧数增长。
- 检测器在 worker 线程内经工厂懒加载一次并持续复用；加载失败与推理失败是
  独立状态，均不阻塞提交方。
- 结果带完整任务身份（相机/运行/帧号/采集时间/配置版本）与检测所用同一帧，
  供 Monitor 在帧边界核验后消费；过期/乱序/换配置结果由消费方拒收。

接口合同见 docs/context/L1-接口合同-C132.md（本地）：F2 生命周期
（lifecycle=closing/stop_incomplete/stopped 收敛、close 后 submit 恒拒、关闭
请求后的返回一律不发布）与 F2 失败终态（每个任务必归
model_unavailable/infer_failed 之一，附固定错误码）。零 SQL、零文件写。

C-133 增补（docs/context/L1-时间-材料-结果合同-C133.md）：
- R3 外部停止同权：外部 stop_event.set() 与显式 close() 完全同权——任何
  停止请求开始后 submit 恒拒（rejected_closed+1）、不发布新有效结果、
  lifecycle 与线程真实存活一致（running→closing→stop_incomplete|stopped）、
  未启动即停止→stopped、worker 正常退出后不残留 running 或无人消费队列、
  已终止/已请求停止实例 start() 抛 RuntimeError。
- T2 进展信号：oldest_unfinished_age_ms(camera_id) 返回该相机最老未完结
  任务（槽内或推理在途）的单调年龄；供失联看门狗经探针每帧调用，必须
  廉价（锁内 O(1) 查表）。

C154 / M2 增补（**默认关闭**，`latest_protected_slots=0` 时既有语义逐字节不变）：
- 事实：聚合判据要求材料包 prev/cur/nxt 三帧**都有**事实链快照
  （`scam/win11_event_progress.py:511-556`），而旧策略下 `latest` 只有一个
  待服务位——下一次 `latest` 提交即把上一帧挤掉，于是"连续两帧只有一帧有
  结论"成为稳态（实测 11/11 为 `frame_binding_missing`）。丢掉的帧**不留
  终态身份**，事后无法回答"这一帧去哪了"。
- 最小机制：`latest_protected_slots` 允许把 `latest` 待服务位从 1 个扩到
  1+1 个（**常量容量，与帧数/时长无关**）。满位时最早一帧出队，并按参数
  决定它进保护位（`protected_retained`）还是显式丢弃
  （`dropped_oldest_latest`）。最新优先、`change_start` 最早优先、`patrol`
  让位、TTL、结果槽覆盖**全部不变**；`submit` 仍只做锁内 O(1) 入槽、
  绝不阻塞相机线程。
- 账目：每次受理/拒收都记入 `counters["dispositions"][终态码]`，并新增
  `snapshot()["cameras"][cam]["material_tasks"]`（逐槽身份与字节）——
  任务数、持有字节、等待上限、终态因此**可核验**。
- 生产开启属**接线点**，不在本模块内：`scam/nvr.py` 的 `L1Pipeline(...)`
  构造处显式传参；不传即保持现合同。
"""

import threading
import time


class L1Task:
    """提交给 L1 的材料任务（submit 时帧已被复制，任务独占该副本）。"""

    __slots__ = ("camera_id", "run_id", "frame_id", "t_capture_ms",
                 "t_submit_mono_ms", "frame_bgr", "frame_w", "frame_h",
                 "reason", "change_boxes", "gate_w", "gate_h",
                 "config_version", "prev_available")

    def __init__(self, camera_id, run_id, frame_id, t_capture_ms, frame_bgr,
                 reason, change_boxes, gate_w, gate_h, config_version,
                 prev_available):
        self.camera_id = camera_id
        self.run_id = run_id
        self.frame_id = frame_id
        self.t_capture_ms = t_capture_ms
        self.t_submit_mono_ms = time.monotonic() * 1000.0
        self.frame_bgr = frame_bgr
        self.frame_w, self.frame_h = frame_bgr.shape[1], frame_bgr.shape[0]
        self.reason = reason
        self.change_boxes = change_boxes
        self.gate_w = gate_w
        self.gate_h = gate_h
        self.config_version = config_version
        self.prev_available = prev_available


class L1Result:
    """L1 产出（与检测所用字节同一帧）；status 四态互斥。"""

    __slots__ = ("camera_id", "run_id", "frame_id", "t_capture_ms", "reason",
                 "config_version", "frame_bgr", "detections", "status",
                 "error_code", "classes", "queued_ms", "infer_ms",
                 "t_done_mono_ms")

    def __init__(self, task, detections, status, error_code, classes,
                 queued_ms, infer_ms):
        self.camera_id = task.camera_id
        self.run_id = task.run_id
        self.frame_id = task.frame_id
        self.t_capture_ms = task.t_capture_ms
        self.reason = task.reason
        self.config_version = task.config_version
        self.frame_bgr = task.frame_bgr
        self.detections = detections
        self.status = status
        self.error_code = error_code
        self.classes = classes
        self.queued_ms = queued_ms
        self.infer_ms = infer_ms
        self.t_done_mono_ms = time.monotonic() * 1000.0


class L1Pipeline:
    """单 worker 有界调度器；同检测配置组的全部相机共享一个实例。"""

    # 每个任务的终态码（C154/M2）：任何一次 submit 恰好落进其中一个。
    DISPOSITIONS = ("served", "merged_start", "patrol_skipped",
                    "protected_retained", "dropped_oldest_latest",
                    "dropped_expired", "rejected_closed", "discarded_closing")

    def __init__(self, detector_factory, *, stop_event, model_name="unknown",
                 task_ttl_s=2.0, load_backoff_s=2.0, poll_timeout_s=0.2,
                 latest_protected_slots=0):
        if isinstance(latest_protected_slots, bool) \
                or not isinstance(latest_protected_slots, int) \
                or latest_protected_slots not in (0, 1):
            # 有界保护位只允许 0（关闭，默认）或 1（至多两帧待服务）；
            # 拒绝更大的值以杜绝"静默扩队列"。
            raise ValueError(
                "latest_protected_slots must be 0 or 1, got {!r}".format(
                    latest_protected_slots))
        self.detector_factory = detector_factory
        self.stop_event = stop_event
        self.model_name = model_name
        self.task_ttl_s = float(task_ttl_s)
        self.load_backoff_s = float(load_backoff_s)
        self.poll_timeout_s = float(poll_timeout_s)
        self.latest_protected_slots = int(latest_protected_slots)
        self._lock = threading.Lock()
        self._close_evt = threading.Event()
        self._slots = {}        # camera_id -> {"change_start": L1Task|None,
        #                                  "latest": L1Task|None,
        #                                  "protected_latest": L1Task|None,
        #                                  "latest_tasks": [L1Task, ...]}
        self._results = {}      # camera_id -> L1Result
        self._last_served_index = 0
        self._detector = None
        self._detector_classes = []
        self._state = "idle"    # idle|loading|ready|model_unavailable
        self._lifecycle = "running"  # running|closing|stop_incomplete|stopped
        self._load_blocked_until_mono = 0.0
        self._in_flight = {}    # camera_id -> L1Task|None（在途任务本体；
        #                           None=空闲；T2 进展信号据此计在途年龄）
        self._last_status = {}  # camera_id -> str|None
        self._last_detections = {}  # camera_id -> 最近 ok 结果的对象数（可观测）
        self._refused_dispositions = {}  # 停止请求后的拒收终态（不建相机槽）
        self.counters = {
            "submitted": 0, "merged_start": 0, "replaced_latest": 0,
            "patrol_skipped": 0, "dropped_expired": 0, "results_produced": 0,
            "results_superseded": 0, "ok": 0, "empty": 0,
            "model_unavailable": 0, "infer_failed": 0,
            "rejected_closed": 0, "discarded_closing": 0,
            "queued_ms_last": 0.0, "queued_ms_max": 0.0,
            "infer_ms_last": 0.0, "infer_ms_max": 0.0,
            # C154/M2（只增不改既有键）
            "latest_protected_slots": self.latest_protected_slots,
            "protected_retained": 0, "dropped_oldest_latest": 0,
        }
        self._thread = threading.Thread(
            target=self._run, name="scam-l1", daemon=True)

    # ---- 内部：槽位与账目 -------------------------------------------------

    @staticmethod
    def _new_camera_slots():
        return {"change_start": None, "latest": None,
                "protected_latest": None, "latest_tasks": []}

    def _count_disposition_locked(self, camera_id, code):
        """锁内调用：记一次任务终态（逐相机累计，供账目闭合核验）。"""
        if code not in self.DISPOSITIONS:
            raise ValueError("unknown disposition: " + str(code))
        slot = self._slots.get(camera_id)
        if slot is None:
            return
        counts = slot.setdefault("dispositions", {})
        counts[code] = counts.get(code, 0) + 1

    def _count_refused_locked(self, code):
        """锁内调用：停止请求后的拒收终态（**不建相机槽**，避免"从未入槽"
        的相机出现在 `snapshot()["cameras"]` 里——R3 合同要求拒收不入槽）。"""
        if code not in self.DISPOSITIONS:
            raise ValueError("unknown disposition: " + str(code))
        self._refused_dispositions[code] = \
            self._refused_dispositions.get(code, 0) + 1


    # ---- 提交方接口（相机线程调用，非阻塞） ------------------------------

    def submit(self, task):
        """受理材料任务；返回 False=未受理（已计数），绝不阻塞或抛错。

        C-133 R3：任何停止请求（显式 close() 或外部 stop_event.set()）开始
        后恒拒且不入槽（rejected_closed+1）——不留无人消费的任务槽。

        C154/M2：每次调用（含被拒）都记一个终态码到该相机的
        `dispositions`；`latest_protected_slots=1` 时 `latest` 由单待服务位
        变为两位，满位时最早一帧进保护位（`protected_retained`）而非静默
        消失。容量为常量，与帧数无关。
        """
        try:
            with self._lock:
                if self._close_evt.is_set() or self.stop_event.is_set():
                    # D5a/R3：close 调用或外部停止后（closing/
                    # stop_incomplete/stopped 皆然）恒拒且不入槽。
                    self._refresh_lifecycle_locked()
                    self.counters["rejected_closed"] += 1
                    self._count_refused_locked("rejected_closed")
                    return False
                cam = task.camera_id
                if cam not in self._slots:      # 新相机首次出现：初始化槽
                    self._slots[cam] = self._new_camera_slots()
                    self._in_flight.setdefault(cam, None)
                    self._last_status.setdefault(cam, None)
                slot = self._slots[cam]
                if task.reason == "change_start":
                    previous = slot["change_start"]
                    if previous is not None:
                        # 保留最早变化开始帧（合同语义不变：最早者在**队首**，
                        # 先被服务）；被位移的那一帧由共享保护位承接。生产实测：
                        # 变化期内门控会**反复**发出 `change_start`（相邻材料帧
                        # 间隔常为 2 帧），因此"被合并的那一帧"同样是**已选中的
                        # 关键材料帧**，它必须有结论才算数——静默丢弃正是
                        # `frame_binding_missing` 的来源。
                        self.counters["merged_start"] += 1
                        retained = self._retain_displaced_locked(cam, slot,
                                                                 previous)
                        if retained:
                            # 位移帧被真的留下：其终态是 `protected_retained`，
                            # 不再计 `merged_start`（避免同一次提交两个终态）。
                            slot["change_start"] = task
                            return True
                        self._count_disposition_locked(cam, "merged_start")
                        # 默认关闭（=0）：按现合同返回 False（未受理、不入槽）
                        return False
                    slot["change_start"] = task
                elif task.reason == "patrol":
                    if (slot["change_start"] is not None
                            or slot["latest"] is not None):
                        # 巡检不占变化材料机会
                        self.counters["patrol_skipped"] += 1
                        self._count_disposition_locked(cam, "patrol_skipped")
                        return False
                    slot["latest"] = task
                    slot["latest_tasks"] = [task]
                else:                           # "latest"：替换 latest 槽
                    previous = slot["latest"]
                    if previous is not None:
                        self.counters["replaced_latest"] += 1
                    tasks = slot["latest_tasks"]
                    if not tasks:
                        tasks.append(task)
                    else:
                        tasks[0] = task            # 队首=最新（替换语义不变）
                    self._retain_displaced_locked(cam, slot, previous)
                    slot["latest"] = tasks[0]
                self.counters["submitted"] += 1
                return True
        except Exception:
            return False

    def _retain_displaced_locked(self, cam, slot, displaced):
        """锁内调用：处理"本来会被静默丢弃的那一帧"；返回是否真的留住了它。

        `latest_protected_slots=0`（默认）时不做任何额外动作——`merged_start`
        / `replaced_latest` 已计数，与现合同逐字节一致，返回 False。
        开启时该帧进**共享保护位**（`change_start` 与 `latest` 共用，容量 =
        `latest_protected_slots`，默认 1 个）。若保护位已被占，被顶替的那一帧
        才是真正无法留存的——显式计数 `dropped_oldest_latest`，不静默消失。
        """
        if displaced is None or self.latest_protected_slots <= 0:
            return False
        if slot["protected_latest"] is not None:
            self.counters["dropped_oldest_latest"] += 1
            self._count_disposition_locked(cam, "dropped_oldest_latest")
        slot["protected_latest"] = displaced
        self.counters["protected_retained"] += 1
        self._count_disposition_locked(cam, "protected_retained")
        return True

    def take_result(self, camera_id):
        """非阻塞取走该相机最近结果；无则 None。"""
        with self._lock:
            return self._results.pop(camera_id, None)

    def has_pending(self, camera_id):
        """该相机是否还有未消费任务槽（供巡检让位判断）。

        C154/M2：保护位（`protected_latest`）也是未消费任务槽，照实计入。
        """
        with self._lock:
            slot = self._slots.get(camera_id)
            if not slot:
                return False
            return (slot["change_start"] is not None
                    or slot["latest"] is not None
                    or slot["protected_latest"] is not None)

    def oldest_unfinished_age_ms(self, camera_id):
        """C-133 T2 进展信号：该相机最老未完结任务的单调年龄（ms）。

        未完结 = 任务仍在槽内（change_start/latest/protected_latest）或推理
        在途；已产出结果、合并、替换、过期出槽、提交被拒的任务一律不算。
        无未完结任务返回 None。口径 time.monotonic；每次调用一次锁内 O(1)
        查表，供相机线程每帧调用（看门狗经探针注入），新提交不重置该年龄。
        """
        now_mono_ms = time.monotonic() * 1000.0
        with self._lock:
            oldest_submit = None
            inflight = self._in_flight.get(camera_id)
            if inflight is not None:
                oldest_submit = inflight.t_submit_mono_ms
            slot = self._slots.get(camera_id)
            if slot is not None:
                for key in ("change_start", "latest", "protected_latest"):
                    t = slot[key]
                    if (t is not None
                            and (oldest_submit is None
                                 or t.t_submit_mono_ms < oldest_submit)):
                        oldest_submit = t.t_submit_mono_ms
            if oldest_submit is None:
                return None
            return max(0.0, now_mono_ms - oldest_submit)

    # ---- 观测与生命周期 --------------------------------------------------

    @staticmethod
    def _task_identity(task):
        """只读任务身份（不含像素/路径/凭据）：任务数、持有字节可核验。"""
        if task is None:
            return None
        return {
            "frame_id": task.frame_id,
            "reason": task.reason,
            "t_submit_mono_ms": task.t_submit_mono_ms,
            "t_capture_ms": task.t_capture_ms,
            "bytes": int(getattr(task.frame_bgr, "nbytes", 0) or 0),
        }

    def snapshot(self):
        """线程安全只读快照；不含路径/凭据。

        R3：读取即校准 lifecycle 与停止请求/线程真实存活一致（廉价）。
        C154/M2：新增 `material_tasks`（逐槽身份+字节）与 `dispositions`
        （逐任务终态计数）——容量、持有字节、等待与终态可核验。
        """
        now_mono_ms = time.monotonic() * 1000.0
        with self._lock:
            self._refresh_lifecycle_locked()
            cameras = {}
            for cam in sorted(self._slots):
                slot = self._slots[cam]
                res = self._results.get(cam)
                cameras[cam] = {
                    "pending": ((1 if slot["change_start"] is not None else 0)
                                + (1 if slot["latest"] is not None else 0)
                                + (1 if slot["protected_latest"] is not None
                                   else 0)),
                    "in_flight": bool(self._in_flight.get(cam, False)),
                    "last_status": self._last_status.get(cam),
                    "last_detections": self._last_detections.get(cam),
                    "last_result_age_ms": ((now_mono_ms - res.t_done_mono_ms)
                                           if res is not None else None),
                    "material_tasks": {
                        "change_start": self._task_identity(
                            slot["change_start"]),
                        "latest": self._task_identity(slot["latest"]),
                        "protected_latest": self._task_identity(
                            slot["protected_latest"]),
                        "pending_latest": len(slot["latest_tasks"]),
                        "in_flight": self._task_identity(
                            self._in_flight.get(cam)),
                        "held_bytes": sum(
                            int(getattr(t.frame_bgr, "nbytes", 0) or 0)
                            for t in (slot["change_start"], slot["latest"],
                                      slot["protected_latest"])
                            if t is not None),
                    },
                    "dispositions": dict(slot.get("dispositions", {})),
                }
            return {
                "lifecycle": self._lifecycle,
                "state": self._state,
                "model": self.model_name,
                "classes": list(self._detector_classes),
                "cameras": cameras,
                "refused_dispositions": dict(self._refused_dispositions),
                "counters": dict(self.counters),
            }

    def _refresh_lifecycle_locked(self):
        """锁内调用：使 lifecycle 与停止请求/线程真实存活一致（R3）。

        - 无停止请求：不动。
        - 线程已不存在（未启动或已真实退出）：收敛 stopped。
        - 线程仍活：running→closing（stop_incomplete 仅由 close() 超时判
          定；worker 自行退出时在 finally 收敛 stopped，之后再次观察即
          真实）。
        """
        if not (self._close_evt.is_set() or self.stop_event.is_set()):
            return
        if self._lifecycle == "stopped":
            return
        if not self._thread.is_alive():
            self._lifecycle = "stopped"
        elif self._lifecycle == "running":
            self._lifecycle = "closing"

    def start(self):
        """启动 worker；对已请求停止/已终止的管道禁止（杜绝重复 worker）。

        C-133 R3：外部 stop_event 已置位与显式 close 同权，同样禁止 start。
        """
        if (self._close_evt.is_set() or self.stop_event.is_set()
                or self._lifecycle in ("stop_incomplete", "stopped")):
            raise RuntimeError(
                "L1Pipeline already stopped/closed; start forbidden")
        self._thread.start()

    def close(self, timeout_s=5.0):
        """请求停机并等待 worker 退出；幂等且收敛。

        C-133 R3：外部 stop_event 可能早已置位——close 与之外部停止同权，
        同样走 closing→(stop_incomplete|stopped) 收敛。返回 True=stopped：
        worker 已退出且槽/结果已清空（帧引用释放）；返回 False=
        stop_incomplete：超时 worker 仍活，可观测状态（槽/结果/在途标记）
        原样保留，绝不冒充已释放。对 stop_incomplete 再次调用会继续等待
        直至收敛（worker 也可能自行退出并把 lifecycle 置 stopped）。
        """
        if not self._close_evt.is_set():
            self._close_evt.set()
            with self._lock:
                if self._lifecycle == "running":
                    self._lifecycle = "closing"    # 请求已受理，尚未定论
        if self._thread.is_alive():
            self._thread.join(timeout=timeout_s)
        if self._thread.is_alive():
            with self._lock:
                if self._lifecycle != "stopped":
                    self._lifecycle = "stop_incomplete"
            return False
        self._drain_all()
        with self._lock:
            self._lifecycle = "stopped"
        return True

    # ---- worker ----------------------------------------------------------

    def _run(self):
        try:
            while not (self.stop_event.is_set() or self._close_evt.is_set()):
                task = None
                try:
                    task = self._next_task()
                    if task is None:
                        self.stop_event.wait(self.poll_timeout_s)
                    else:
                        self._process(task)
                except Exception:
                    # 兜底：worker 任何异常不得杀死线程；任务必有分类终态
                    # （合同红线：无结果也无失败记录=缺陷）。
                    if task is not None:
                        try:
                            now_mono_ms = time.monotonic() * 1000.0
                            self._produce(task, [], "infer_failed",
                                          "detector_infer_failed",
                                          now_mono_ms - task.t_submit_mono_ms,
                                          0.0)
                        except Exception:
                            with self._lock:
                                self._in_flight[task.camera_id] = None
        finally:
            self._drain_all()
            if self._close_evt.is_set() or self.stop_event.is_set():
                # 任何停止请求（close 或外部 stop_event，R3 同权）下 worker
                # 此刻真实退出：收敛为 stopped——外部 stop 路径同样不得残留
                # running（覆盖 close 超时判 stop_incomplete 后才退出的路径）。
                with self._lock:
                    self._lifecycle = "stopped"

    def _next_task(self):
        """加锁清理过期任务并按跨相机轮转选出下一任务；无任务返回 None。

        公平性：_last_served_index 在排序相机键上作轮转起点（递增）；
        同相机先 change_start，再 latest（队首=最新），最后 protected_latest。
        过期清理覆盖全部待服务槽（含保护位），每次出槽记一个终态码。
        """
        now_mono_ms = time.monotonic() * 1000.0
        with self._lock:
            cams = sorted(self._slots)
            ttl_ms = self.task_ttl_s * 1000.0
            for cam in cams:                # 过期清理（丢帧引用）
                slot = self._slots[cam]
                for key in ("change_start", "latest", "protected_latest"):
                    t = slot[key]
                    if t is not None and t.t_submit_mono_ms + ttl_ms < now_mono_ms:
                        slot[key] = None
                        self.counters["dropped_expired"] += 1
                        self._count_disposition_locked(cam, "dropped_expired")
                        if key == "latest":
                            # 队首过期：同步队列视图（保护位仍留待下一轮判定，
                            # 绝不在本轮的过期清理里"提权"到 latest——否则它
                            # 会绕过本轮 TTL 判定被服务）
                            slot["latest_tasks"] = [
                                q for q in slot["latest_tasks"] if q is not t]
                            slot["latest"] = (slot["latest_tasks"][0]
                                              if slot["latest_tasks"] else None)
            n = len(cams)
            for i in range(n):
                idx = (self._last_served_index + i) % n
                slot = self._slots[cams[idx]]
                if slot["change_start"] is not None:
                    task = slot["change_start"]
                    slot["change_start"] = None
                elif slot["latest"] is not None:
                    task = slot["latest"]
                    slot["latest"] = None
                    if slot["latest_tasks"] and slot["latest_tasks"][0] is task:
                        slot["latest_tasks"].pop(0)
                    if slot["latest_tasks"] and slot["latest"] is None:
                        slot["latest"] = slot["latest_tasks"][0]
                elif slot["protected_latest"] is not None:
                    task = slot["protected_latest"]
                    slot["protected_latest"] = None
                else:
                    continue
                cam = cams[idx]
                self._last_served_index = (idx + 1) % n
                self._in_flight[cam] = task    # T2：在途任务本体可观测
                self._count_disposition_locked(cam, "served")
                return task
            return None

    def _ensure_detector(self, now_mono_ms):
        """worker 独占：确保检测器可用；失败返回 (False, 固定错误码)。

        首次任务或 backoff 结束后才真正调工厂；backoff 窗口内的任务直接产出
        model_unavailable 结果（不堆积、不重试）。
        """
        if self._detector is not None:
            return True, None
        if now_mono_ms < self._load_blocked_until_mono:
            return False, "detector_load_failed"
        self._state = "loading"
        try:
            detector = self.detector_factory()
        except Exception:
            self._state = "model_unavailable"
            self._load_blocked_until_mono = (
                time.monotonic() * 1000.0 + self.load_backoff_s * 1000.0)
            return False, "detector_load_failed"
        self._detector = detector
        self._detector_classes = list(getattr(detector, "classes", []) or [])
        self._state = "ready"
        return True, None

    def _process(self, task):
        ok, err = self._ensure_detector(time.monotonic() * 1000.0)
        if not ok:
            now_mono_ms = time.monotonic() * 1000.0
            self._produce(task, [], "model_unavailable", err,
                          now_mono_ms - task.t_submit_mono_ms, 0.0)
            return
        t0 = time.monotonic()
        queued_ms = t0 * 1000.0 - task.t_submit_mono_ms
        dets, status, err = self._detect_classified(task)
        infer_ms = (time.monotonic() - t0) * 1000.0
        self._produce(task, dets, status, err, queued_ms, infer_ms)

    def _detect_classified(self, task):
        """执行一次检测并给出分类终态（D-B3）。

        返回 (detections, status, error_code)：
        - detect 抛错，或返回值物化（list()，必须在 try 内）迭代中途抛错
          → infer_failed / "detector_infer_failed"；
        - 返回 None / 顶层非 list（dict、生成器等）/ 元素不是 dict 或缺
          cls/conf/bbox 键 → infer_failed / "detector_output_invalid"；
        - 正常 list：非空 → ok，空 → empty。
        """
        try:
            raw = self._detector.detect(task.frame_bgr)
            if raw is None:
                return [], "infer_failed", "detector_output_invalid"
            dets = list(raw)                # 物化在 try 内：迭代中途异常可归类
        except Exception:
            return [], "infer_failed", "detector_infer_failed"
        if not isinstance(raw, list):
            return [], "infer_failed", "detector_output_invalid"
        for d in dets:
            if not (isinstance(d, dict)
                    and all(k in d for k in ("cls", "conf", "bbox"))):
                return [], "infer_failed", "detector_output_invalid"
        if dets:
            return dets, "ok", None
        return [], "empty", None

    def _produce(self, task, detections, status, error_code, queued_ms, infer_ms):
        """落结果槽（旧未取结果→替换计数）并更新全部计数与可观测状态。

        D5b/R3：任何停止请求（close 或外部 stop_event，同权）已受理后，
        任何任务终态一律不发布——丢弃（连同其帧引用）并计 discarded_closing
        （迟到结果绝不得成为有效结果），只复位在途标记。
        """
        with self._lock:
            if self._close_evt.is_set() or self.stop_event.is_set():
                self.counters["discarded_closing"] += 1
                self._in_flight[task.camera_id] = None
                self._count_disposition_locked(task.camera_id,
                                               "discarded_closing")
                return
            result = L1Result(task, detections, status, error_code,
                              list(self._detector_classes), queued_ms, infer_ms)
            if task.camera_id in self._results:
                self.counters["results_superseded"] += 1
            self._results[task.camera_id] = result
            c = self.counters
            c["results_produced"] += 1
            c[status] += 1
            c["queued_ms_last"] = queued_ms
            c["queued_ms_max"] = max(c["queued_ms_max"], queued_ms)
            c["infer_ms_last"] = infer_ms
            c["infer_ms_max"] = max(c["infer_ms_max"], infer_ms)
            self._last_status[task.camera_id] = status
            self._last_detections[task.camera_id] = (
                len(detections) if status == "ok" else 0)
            self._in_flight[task.camera_id] = None

    def _drain_all(self):
        """清空全部槽与结果（释放帧引用）；在途标记复位。"""
        with self._lock:
            self._slots.clear()
            self._results.clear()
            for cam in self._in_flight:
                self._in_flight[cam] = None
