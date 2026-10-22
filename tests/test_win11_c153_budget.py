"""C153-R1 §3：全局预算与两相机屏障回归。

覆盖（裁定 §3 逐条）：

1. **窗口总预算 ≠ 全局执行资源上限**：窗口额度（`L3WindowBudget`）只约束
   单个窗口的任务/帧数；跨相机的**共享排队资源**（`l3_max_queue` +
   整组淘汰）与**执行资源**（单 L3 worker + `L3Stage` 并发槽）是另一层上限。
2. 走**真实构建路径** `nvr._build_l2_runtime` 建运行时，材料仓/窗口调度/
   L3 队列/容量收敛/窗口状态机/预算账本/L4 全部是**生产对象**；只把
   **L3 后端（模型）** 换成确定性假实现（裁定明确允许），L2 关系模型同样
   以确定性假 stage 替身（无真实模型条件，绝不伪装成真实推理）。
3. 两相机、各带**全景 + 局部**分支；
4. 共享排队/执行资源上限（队列深度 ≤ `l3_max_queue`、模型调用并发 ≤ 1）；
5. 跨相机**公平轮转**（严格 A,B,A,B；无相机饿死）；
6. 同窗重复入队**不重获完整预算**（第二次只拿剩余额度）；
7. **超时但未结束**的调用不造成**超发**（执行资源不提前返还）；
8. **无饥饿、无永久预算泄漏**（每分支恰一次终态；账本活页全部封口）；
9. `dropped`/`merged` 后窗口**仍可封口**（且 L4 保留"未分析 + 原因"）；
10. 迟到结果/拒收/淘汰/封口/停止路径**都不重复结算**。

断言里的数字一律来自真实生产对象的快照（非估算）。
"""

from __future__ import annotations

import threading
import time

import numpy as np
import pytest

from scam import nvr as nvr_mod
from scam.win11_l2_contract import (CropTransform, FrameIdentity,
                                    L2Output, L2RelationStage, L2Status,
                                    L2TaskInput, L3BranchSpec,
                                    L3LocalFrameSlice)
from scam.win11_l3 import L3Stage
from scam.win11_l3_contract import (L3BranchKind, L3BranchResult, L3Budget,
                                    L3Omission, L3Output, L3SourceRef,
                                    L3Status, L3Uncertainty)
from scam.win11_l4 import L4Stage
from scam.win11_materials import MaterialsStore

CAM_A = "cam-a"
CAM_B = "cam-b"

_REGION = (0.25, 0.25, 0.25, 0.25)


# ---------------------------------------------------------------------------
# 确定性假 L2 / L3（生产对象保持真实：队列、容量、并发、窗口状态机、账本）
# ---------------------------------------------------------------------------

def _make_frame(value, w=16, h=12):
    return np.full((h, w, 3), value % 256, dtype=np.uint8)


def _feed(store, cam, run, cfg, fid, detections):
    assert store.ingest(cam, run, cfg, fid, _make_frame(fid), 1000.0 + fid,
                        "host_receive", [], 16, 12)
    assert store.attach_result(cam, run, cfg, fid, "ok", None, detections,
                               accepted=True, reject_reason=None)


_PERSONS_A = [
    {"cls": "person", "conf": 0.9, "bbox": [0.2, 0.3, 0.2, 0.3],
     "trackId": 1},
    {"cls": "person", "conf": 0.8, "bbox": [0.6, 0.35, 0.2, 0.3],
     "trackId": 2},
]
_PERSONS_B = [
    {"cls": "person", "conf": 0.85, "bbox": [0.3, 0.4, 0.25, 0.3],
     "trackId": 11},
    {"cls": "car", "conf": 0.7, "bbox": [0.1, 0.1, 0.4, 0.4],
     "trackId": 12},
]


def _side(task_input):
    """L2TaskInput 的 prev/next 侧（同生产形状：各自带自己的帧与身份）。"""
    return L2TaskInput(
        identity=task_input.identity, frame_bgr=task_input.frame_bgr,
        width=task_input.width, height=task_input.height, detections=(),
        l1_status=None, change_regions=(), prev=None, next=None,
        prev_gap_ms=None, next_gap_ms=None, vocabulary_id="test-v1",
        relation_vocabulary=(), budget=None)


def _local_slice(frame_input, crop_id, position):
    """局部区域切片（真实像素切片，缺帧显式占位）。"""
    if frame_input is None or frame_input.frame_bgr is None:
        return L3LocalFrameSlice(
            position=position, present=False, crop_id=crop_id, frame_id=None,
            t_capture_ms=None, timestamp_kind=None, width=None, height=None,
            frame_bgr=None)
    arr = frame_input.frame_bgr
    h, w = arr.shape[:2]
    y0, y1 = max(1, h // 4), max(2, h // 2)
    x0, x1 = max(1, w // 4), max(2, w // 2)
    return L3LocalFrameSlice(
        position=position, present=True, crop_id=crop_id,
        frame_id=frame_input.identity.frame_id,
        t_capture_ms=frame_input.identity.t_capture_ms,
        timestamp_kind=frame_input.identity.timestamp_kind,
        width=w, height=h, frame_bgr=arr[y0:y1, x0:x1].copy())


class _DeterministicL2Stage:
    """确定性 L2 关系 stage：每包产出**全景 + 关系裁图**两个分支（真实形状）。

    只替换"关系模型"这一层；分支身份、序位、切片像素与生产转换同形。
    `duplicate_relation`：额外再产一条**同身份同来源**的关系分支（用于验证
    幂等合并）；`extra_same_crop` 用于构造"不同 crop 不合并"的对照。
    """

    budget = None

    def __init__(self, *, duplicate_relation=False):
        self.calls = []
        self.duplicate_relation = duplicate_relation

    def process(self, task):
        self.calls.append(task)
        ident = task.identity
        crop_id = "{}:{}:frame:{}:crop:0".format(
            ident.camera_id, ident.run_id, ident.frame_id)
        crop_ref = CropTransform(
            union_norm=(0.0, 0.0, 1.0, 1.0), margin_ratio=0.0,
            bbox_norm=_REGION, bbox_px=(4, 3, 8, 6), clamped=False,
            whole_frame_fallback=False, context_capped=False)
        slices = (
            _local_slice(task.prev, crop_id, 0),
            _local_slice(task, crop_id, 1),
            _local_slice(task.next, crop_id, 2),
        )
        panorama = L3BranchSpec(
            branch_kind="panorama", identity=ident, crop_ref=None,
            cur_present=True, prev_present=task.prev is not None,
            next_present=task.next is not None, cur_gap_ms=0.0,
            prev_gap_ms=None, next_gap_ms=None, cur_detections=(),
            prev_detections=None, next_detections=None, candidates=(),
            crop_id=crop_id + ":whole")
        relation = L3BranchSpec(
            branch_kind="relation_crop", identity=ident, crop_ref=crop_ref,
            cur_present=True, prev_present=task.prev is not None,
            next_present=task.next is not None, cur_gap_ms=0.0,
            prev_gap_ms=None, next_gap_ms=None, cur_detections=(),
            prev_detections=None, next_detections=None, candidates=(),
            crop_id=crop_id, frame_sequence=slices)
        branches = [panorama, relation]
        if self.duplicate_relation:
            branches.append(L3BranchSpec(
                branch_kind="relation_crop", identity=ident, crop_ref=crop_ref,
                cur_present=True, prev_present=task.prev is not None,
                next_present=task.next is not None, cur_gap_ms=0.0,
                prev_gap_ms=None, next_gap_ms=None, cur_detections=(),
                prev_detections=None, next_detections=None, candidates=(),
                crop_id=crop_id, frame_sequence=slices))
        return L2Output(identity=ident, status=L2Status.OK, error_code=None,
                        candidates=(), crops=(), crop_images=(),
                        omission=None, vocabulary_id="test-v1",
                        model_ref="deterministic-l2", calibrated=False,
                        timings_ms={}, l3_branches=tuple(branches))


def _ok_output(task, observation="走廊中两人行走"):
    result = L3BranchResult(
        branch=task.branch, status=L3Status.OK, error_code=None,
        observation=observation, inference="可能继续前行",
        uncertainty=L3Uncertainty(),
        sources=(L3SourceRef(0, 1, True, 1000.0, "host_receive"),),
        window=task.window, crop_id=getattr(task, "crop_id", None),
        model_ref="deterministic-l3", region_only=False)
    return L3Output(window=task.window, branch=task.branch,
                    status=L3Status.OK, error_code=None, results=(result,),
                    omission=L3Omission(0, ""), model_ref="deterministic-l3",
                    timings_ms={"total": 1.0})


class _CountingL3Stage:
    """确定性假 L3 后端（裁定允许）：计数 + 可选阻塞门（屏障测试用）。"""

    def __init__(self, *, gate=None, entered=None, observation="走廊中两人行走"):
        self.gate = gate
        self.entered = entered
        self.observation = observation
        self.calls = []
        self.max_concurrent = 0
        self._cur = 0
        self._lock = threading.Lock()

    def process(self, task):
        with self._lock:
            self.calls.append(task)
            self._cur += 1
            self.max_concurrent = max(self.max_concurrent, self._cur)
        try:
            if self.entered is not None:
                self.entered.set()
            if self.gate is not None:
                assert self.gate.wait(10.0), "测试卡点：阻塞门未放行"
            return _ok_output(task, self.observation)
        finally:
            with self._lock:
                self._cur -= 1


def _build_runtime(monkeypatch, *, l3_stage, l3_max_queue=3,
                   duplicate_relation=False):
    """真实构建路径：`nvr._build_l2_runtime`（材料仓/调度/队列/账本全生产）。"""
    monkeypatch.setattr(
        "scam.win11_l2_contract.L2RelationStage",
        lambda **kw: _DeterministicL2Stage(
            duplicate_relation=duplicate_relation))
    store = MaterialsStore()
    runtime = nvr_mod._build_l2_runtime(
        {"repo_path": "unused-in-tests", "vocabulary": ["walking past"],
         "vocabulary_id": "test-v1", "max_age_s": 3600.0,
         "poll_interval_s": 0.01},
        store, [CAM_A, CAM_B],
        l3_cfg={"enabled": False, "max_queue": l3_max_queue,
                "l4": {"enabled": True}},
        persist_dir=None, crop_worker=None, db_path=None)
    # 账本必须是**默认启用**的生产账本（不是测试注入的替身）
    assert runtime.l3_window_budget_ledger is not None, \
        "生产入口的窗口级共享预算必须默认启用"
    assert runtime.l4_factory is L4Stage
    # 裁定 §3：只允许注入确定性假 L3 后端；队列/容量/并发仍是生产对象
    runtime.l3_stage = l3_stage
    runtime.l3_backend = None
    return runtime, store


def _wait_until(predicate, timeout=10.0, interval=0.01):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


def _feed_window(store, cam, run, cfg, detections, *, fid_base):
    """喂两个材料包（窗口组最小形状：prev/cur/nxt 由材料仓真实回填）。"""
    _feed(store, cam, run, cfg, fid_base, detections)
    _feed(store, cam, run, cfg, fid_base + 1, detections)


def _settled_terminals(camera_counts):
    return {kind: value for kind, value in camera_counts.items()
            if kind.startswith("settled_") and value}


# ---------------------------------------------------------------------------
# 1. 两相机屏障：共享排队上限 + 跨相机公平 + 无饥饿 + 窗口封口
# ---------------------------------------------------------------------------

def test_two_camera_barrier_shared_queue_cap_and_no_starvation(monkeypatch):
    """两相机（各全景+局部分支）在**阻塞的**执行资源下：全局排队不超过
    `l3_max_queue`（整组淘汰生效）、两相机都能推进（无饥饿）、被淘汰分支
    恰好一次终态、窗口全部封口、账本活页全部封口（无永久泄漏）。"""
    gate = threading.Event()
    entered = threading.Event()
    stage = _CountingL3Stage(gate=gate, entered=entered)
    runtime, store = _build_runtime(monkeypatch, l3_stage=stage,
                                    l3_max_queue=2)
    runtime.set_camera_identity(CAM_A, "run-a", 1)
    runtime.set_camera_identity(CAM_B, "run-b", 1)
    _feed_window(store, CAM_A, "run-a", 1, _PERSONS_A, fid_base=1)
    _feed_window(store, CAM_B, "run-b", 1, _PERSONS_B, fid_base=11)
    try:
        runtime.start()
        assert entered.wait(10.0), "L3 执行资源应被第一个任务占用（屏障）"
        # 两个窗口都会被 L2 侧面处理入队（L3 侧被阻塞占用 1 个执行槽）
        assert _wait_until(lambda: runtime.snapshot()["cameras"][CAM_A].get(
            "l3_enqueued", 0) >= 2), "相机 A 应完成入队"
        assert _wait_until(lambda: runtime.snapshot()["cameras"][CAM_B].get(
            "l3_enqueued", 0) >= 1), "相机 B 应完成入队"

        # 共享排队上限：实测队列深度恒 ≤ l3_max_queue，且**上限确实起作用**
        # （队列满 → 整组淘汰；不是无限排队）。采样覆盖整个阻塞期。
        peaks = []
        for _ in range(200):
            peaks.append(runtime.snapshot()["l3"]["queue_depth"])
            if len(peaks) >= 20 and peaks[-1] == peaks[-2] == peaks[-3]:
                break
            time.sleep(0.002)
        assert max(peaks) <= runtime.l3_max_queue, \
            f"排队不得超过全局上限：{max(peaks)} > {runtime.l3_max_queue}"
        evicted = sum(runtime.snapshot()["cameras"][cam].get(
            "l3_dropped", 0) for cam in (CAM_A, CAM_B))
        assert evicted >= 1, "队列满必须整组淘汰（不是无限排队）"
        assert runtime.snapshot()["l3"]["queue_depth"] <= runtime.l3_max_queue

        gate.set()
        assert _wait_until(lambda: runtime.snapshot()["open_windows"] == {
            "producing": 0, "sealed": 0}), "全部分支终态后窗口应全部收口"
    finally:
        gate.set()
        assert runtime.stop() is True

    snap = runtime.snapshot()
    # 执行资源上限：单 L3 worker + stage 单并发（无并行 provider）
    assert stage.max_concurrent == 1, "模型调用并发恒为 1（生产单 worker）"
    # 无饥饿：两相机都拿到过真实分析结果
    for cam in (CAM_A, CAM_B):
        counts = snap["cameras"][cam]
        assert counts.get("l3_enqueued", 0) >= 1, f"{cam} 必须入队过"
    assert snap["cameras"][CAM_A]["l3_completed"] + \
        snap["cameras"][CAM_B]["l3_completed"] >= 1, "至少一条真实分析完成"
    assert snap["cameras"][CAM_A].get("settled_queue_evicted", 0) + \
        snap["cameras"][CAM_B].get("settled_queue_evicted", 0) >= 1, \
        "被淘汰分支必须恰一次终态（不静默消失）"
    # 无永久预算泄漏：账本里所有窗口都已封口（forget 过）
    ledger = runtime.l3_window_budget_ledger
    assert ledger.window_keys(), "应登记过窗口"
    for window_key in ledger.window_keys():
        assert ledger.is_settled(window_key) is True, \
            f"{window_key} 未封口（永久占用预算）"


# ---------------------------------------------------------------------------
# 2. 跨相机公平轮转（严格 A,B,A,B；无相机饿死）
# ---------------------------------------------------------------------------

def test_cross_camera_round_robin_dequeue_is_fair(monkeypatch):
    """跨相机取队首严格轮转：两相机队列都非空时 A,B,A,B——任何相机都不会
    被另一台的有界队列长期饿死。"""
    stage = _CountingL3Stage()
    runtime, store = _build_runtime(monkeypatch, l3_stage=stage,
                                    l3_max_queue=8)
    runtime.set_camera_identity(CAM_A, "run-a", 1)
    runtime.set_camera_identity(CAM_B, "run-b", 1)
    _feed_window(store, CAM_A, "run-a", 1, _PERSONS_A, fid_base=1)
    _feed_window(store, CAM_B, "run-b", 1, _PERSONS_B, fid_base=11)
    try:
        # 直接驱动生产窗口入口（与 L2 worker 同一调用），不入队就跑
        for _ in range(2):
            handle = runtime.scheduler.acquire()
            if handle is None:
                break
            runtime._process_handle(handle)
        order = []
        while True:
            entry = runtime._l3_dequeue()
            if entry is None:
                break
            order.append(entry[1]["camera"])
        assert order, "应有排队任务"
        # 严格轮转：相邻任务不得来自同一相机（两侧都有货时）
        assert order[:2] == [CAM_A, CAM_B] or order[:2] == [CAM_B, CAM_A]
        for first, second in zip(order, order[1:]):
            assert first != second, f"轮转被破坏：{order}"
        assert set(order) == {CAM_A, CAM_B}, "两相机都必须被服务"
    finally:
        assert runtime.stop() is True


# ---------------------------------------------------------------------------
# 3. 同窗重复入队不重获完整预算
# ---------------------------------------------------------------------------

def test_same_window_second_package_gets_remainder_not_full_budget(monkeypatch):
    """同一窗口第二次入队（第 2 个材料包）拿到的是**剩余**额度：4 个分支
    共用一份窗口预算 → 3 个任务 + 1 个如实 dropped，绝不是每包一份完整预算。"""
    stage = _CountingL3Stage()
    runtime, store = _build_runtime(monkeypatch, l3_stage=stage,
                                    l3_max_queue=8)
    runtime.set_camera_identity(CAM_A, "run-a", 1)
    _feed_window(store, CAM_A, "run-a", 1, _PERSONS_A, fid_base=1)
    try:
        handle = runtime.scheduler.acquire()
        assert handle is not None and len(handle.packages) == 2
        runtime._process_handle(handle)
        counts = runtime.snapshot()["cameras"][CAM_A]
        assert counts["l3_enqueued"] == 3, "2 包×2 分支共用 3 个窗口额度"
        assert counts["settled_budget_dropped"] == 1
        coverage = runtime.snapshot()["l3_shared_budget"]["recent_coverage"]
        (cov,) = list(coverage.values())
        assert cov["branches_total"] == 4
        assert cov["branches_kept"] == 3 and cov["branches_dropped"] == 1
        assert cov["tasks_reserved"] == 3
        assert cov["frames_reserved"] <= cov["budget"]["max_total_frames"], \
            "窗口总帧预算是共享上限（全景+局部合计）"
        assert cov["dropped"][0]["reason"] == "window_budget_tasks_exhausted"
        # 覆盖 ↔ 终态一一对应
        assert len(cov["plan_settlement"]) == 1
        row = cov["plan_settlement"][0]
        assert row["terminal"] == "budget_dropped" and row["settled"] is True
        assert row["branch_key"] == cov["dropped"][0]["branch_key"]
    finally:
        assert runtime.stop() is True


def test_two_cameras_never_borrow_window_budget(monkeypatch):
    """跨相机**不借预算**：相机 A 用满自己的窗口额度（4 分支 → 3 任务 +
    1 dropped），相机 B 的窗口额度**不受影响**（2 分支全部进任务）。
    预算键=window_key 四元（首段 camera_id）→ 结构上无法跨相机借。"""
    stage = _CountingL3Stage()
    runtime, store = _build_runtime(monkeypatch, l3_stage=stage,
                                    l3_max_queue=8)
    runtime.set_camera_identity(CAM_A, "run-a", 1)
    runtime.set_camera_identity(CAM_B, "run-b", 1)
    _feed_window(store, CAM_A, "run-a", 1, _PERSONS_A, fid_base=1)
    _feed(store, CAM_B, "run-b", 1, 11, _PERSONS_B)
    try:
        for _ in range(2):
            handle = runtime.scheduler.acquire()
            assert handle is not None
            runtime._process_handle(handle)
        coverage = runtime.snapshot()["l3_shared_budget"]["recent_coverage"]
        assert len(coverage) == 2, "两相机各有一份窗口账目（互不覆盖）"
        by_camera = {}
        for key, cov in coverage.items():
            by_camera[key.split("|")[0]] = cov
        assert set(by_camera) == {CAM_A, CAM_B}
        # 相机 A 用满自身窗口额度并按上限丢弃 1 个分支
        assert by_camera[CAM_A]["branches_total"] == 4
        assert by_camera[CAM_A]["tasks_reserved"] == 3
        assert by_camera[CAM_A]["branches_dropped"] == 1
        # 相机 B **不因 A 用满而被削减**：自己的窗口额度完整
        assert by_camera[CAM_B]["branches_total"] == 2
        assert by_camera[CAM_B]["tasks_reserved"] == 2
        assert by_camera[CAM_B]["branches_dropped"] == 0
        counts_b = runtime.snapshot()["cameras"][CAM_B]
        assert counts_b["l3_enqueued"] == 2
        assert counts_b.get("settled_budget_dropped", 0) == 0
    finally:
        assert runtime.stop() is True


# ---------------------------------------------------------------------------
# 4. dropped / merged 后窗口仍可封口；L4 保留未知/未分析
# ---------------------------------------------------------------------------

def test_dropped_branch_settles_once_l4_gap_and_window_still_seals(monkeypatch):
    """被预算丢弃的分支：runtime 终态 `budget_dropped` 恰一次 + 进 L4 缺失
    因素（未分析 + 原因）；窗口照常封口、照常收口。"""
    stage = _CountingL3Stage()
    runtime, store = _build_runtime(monkeypatch, l3_stage=stage,
                                    l3_max_queue=8)
    runtime.set_camera_identity(CAM_A, "run-a", 1)
    _feed_window(store, CAM_A, "run-a", 1, _PERSONS_A, fid_base=1)
    try:
        handle = runtime.scheduler.acquire()
        runtime._process_handle(handle)
        # 把已入队的 3 个任务全部跑完（生产 worker 单步驱动）
        for _ in range(3):
            entry = runtime._l3_dequeue()
            assert entry is not None
            runtime._l3_process_entry(entry[0], entry[1])
        snap = runtime.snapshot()
        counts = snap["cameras"][CAM_A]
        assert counts["settled_budget_dropped"] == 1, "恰一次（不重复累计）"
        assert counts["l3_completed"] == 3
        assert snap["open_windows"] == {"producing": 0, "sealed": 0}
        assert counts["windows_settled"] == 1, "dropped 之后窗口仍可封口"
        # L4：被丢弃分支保留"未分析"，绝不编造内容顶上
        l4 = runtime.history(CAM_A, "l4")
        texts = [item["text"] for rec in l4 for item in rec.get("items", ())]
        gaps = [text for text in texts if "budget_dropped" in text]
        assert gaps, "L4 必须保留被丢弃分支的缺失因素"
        assert "not_analyzed" in gaps[0] and \
            "window_budget_tasks_exhausted" in gaps[0], \
            "缺失因素必须写明未分析 + 受控原因"
    finally:
        assert runtime.stop() is True


def test_duplicate_identity_task_is_merged_once_and_not_reanalysed(monkeypatch):
    """同身份同来源的重复分支（同窗同材料同分支同 crop 同像素）→ 只跑一次
    推理；被合并行进覆盖账目并指向复用对象，**不冒充执行过推理**；窗口仍封口。"""
    stage = _CountingL3Stage()
    runtime, store = _build_runtime(monkeypatch, l3_stage=stage,
                                    l3_max_queue=8,
                                    duplicate_relation=True)
    runtime.set_camera_identity(CAM_A, "run-a", 1)
    _feed(store, CAM_A, "run-a", 1, 1, _PERSONS_A)
    try:
        handle = runtime.scheduler.acquire()
        runtime._process_handle(handle)
        counts = runtime.snapshot()["cameras"][CAM_A]
        # 3 个分支只有 2 个任务（重复的关系分支被合并）
        assert counts["l3_enqueued"] == 2, "重复身份只跑一次（3 分支→2 任务）"
        coverage = runtime.snapshot()["l3_shared_budget"]["recent_coverage"]
        (cov,) = list(coverage.values())
        assert cov["branches_total"] == 3
        assert cov["branches_kept"] == 2 and cov["branches_merged"] == 1
        merged = cov["merged"][0]
        assert merged["reason"] == "merged_same_identity_fingerprint"
        assert merged["branch_key"] == merged["into_branch_key"]
        (row,) = cov["plan_settlement"]
        assert row["disposition"] == "merged_into"
        assert row["terminal"] is None, "复用既有任务：不冒充独立终态/推理"
        assert row["owned_by"] == "kept_task"
        assert row["merged_into"] == 1
        assert row["merged_into_branch_key"] == merged["into_branch_key"], \
            "复用来源必须可追溯（指向被复用的对象）"
        assert row["reason"] == "merged_same_identity_fingerprint"
        # 跑完两个任务 → 窗口收口
        for _ in range(2):
            entry = runtime._l3_dequeue()
            runtime._l3_process_entry(entry[0], entry[1])
        snap = runtime.snapshot()
        assert snap["open_windows"] == {"producing": 0, "sealed": 0}
        assert snap["cameras"][CAM_A]["l3_completed"] == 2, \
            "完成数只计真实执行（合并分支不重复累计）"
    finally:
        assert runtime.stop() is True


# ---------------------------------------------------------------------------
# 5. 超时但未结束 → 执行资源不提前返还（不超发）
# ---------------------------------------------------------------------------

class _ProbingTimeoutModel:
    """等待超时但执行未结束的 L3 后端（自报探测源同生产 adapter 形状）。"""

    model_ref = "deterministic/probing-timeout"
    infer_timeout_s = 0.2

    def __init__(self):
        self.calls = 0
        self.still_running = True
        self.poisoned = False
        self.close_requested = False
        self.phase = "ready"

    def understand_frames(self, prompt, frames_bgr, frames_meta):
        self.calls += 1
        if self.still_running:
            raise TimeoutError("wait timeout: worker call NOT cancelled")
        return {"observation": "恢复", "inference": "继续"}

    def snapshot(self):
        return {
            "pending_call_still_running": bool(self.still_running),
            "pending_calls": 1 if self.still_running else 0,
            "executor_threads_alive": 1 if self.still_running else 0,
            "poisoned": self.poisoned,
            "close_requested": self.close_requested,
            "phase": self.phase,
        }


def test_timeout_while_executing_never_over_issues(monkeypatch):
    """真实 `L3Stage`（生产对象）+ 确定性假后端：第一个任务等待超时但执行
    未结束 → 执行资源（并发槽 + 在途 gauge）**不提前返还**；第二个任务拿不到
    槽位 → 如实 timeout，**不发出第二次模型调用**（不超发）。"""
    model = _ProbingTimeoutModel()
    stage = L3Stage(model, budget=L3Budget(concurrency=1),
                    slot_wait_timeout_s=0.2)
    runtime, store = _build_runtime(monkeypatch, l3_stage=stage,
                                    l3_max_queue=8)
    runtime.set_camera_identity(CAM_A, "run-a", 1)
    _feed(store, CAM_A, "run-a", 1, 1, _PERSONS_A)
    try:
        handle = runtime.scheduler.acquire()
        runtime._process_handle(handle)
        counts = runtime.snapshot()["cameras"][CAM_A]
        assert counts["l3_enqueued"] == 2, "全景 + 局部两个分支"
        for _ in range(2):
            entry = runtime._l3_dequeue()
            assert entry is not None
            runtime._l3_process_entry(entry[0], entry[1])
        res = stage.execution_resources()
        assert res["concurrency"] == 1
        assert res["held_unfinished"] == 1, "未结束的执行资源必须保持占用"
        assert res["in_flight"] == 1, "在途 gauge 不提前归零"
        assert model.calls == 1, "执行资源未返还时绝不超发第二次调用"
        counts = runtime.snapshot()["cameras"][CAM_A]
        assert counts["settled_model_failed"] == 2, "两分支各恰一次终态"
        assert counts["settled_branch_ok"] == 0, "不得冒充成功"
        # 两个分支各自留下的记录都如实标 timeout（没有成功结果）
        l3 = runtime.history(CAM_A, "l3")
        assert len(l3) == 2
        assert {rec["status"] for rec in l3} == {"timeout"}
        assert all(row["error_code"] == "timeout"
                   for rec in l3 for row in rec["results"])
        # C153-R1 §3 修正：停机**不**强清仍在执行的占用（旧行为把"丢掉引用"
        # 当"释放资源"，与模型自报"执行仍在跑"的事实矛盾）
        assert runtime.stop() is True
        res = stage.execution_resources()
        assert res["held_unfinished"] == 1, "执行未结束 → 记录不得被 stop 清空"
        assert res["in_flight"] == 1, "执行未结束 → 在途 gauge 不得归零"
        assert res["reclaimed_total"] == 0, "无真实结束证据 → 一次也不得回收"
        # 真实结束（唯一证据来源）→ 恰一次回收（原意中正确的部分保留）
        model.still_running = False
        assert stage.release_held_executions(reason="execution_finished") == 1
        res = stage.execution_resources()
        assert res["held_unfinished"] == 0 and res["in_flight"] == 0
        assert res["reclaimed_total"] == 1
    finally:
        runtime.stop()


def test_stop_releases_held_execution_resource(monkeypatch):
    """停机路径**只回收真实执行已结束**的挂起执行资源（C153-R1 §3 修正版）。

    原断言（旧行为）要求 stop 把"等待超时但未结束"的执行资源强制归零——
    那是把"丢掉引用"当"释放资源"，会让并发上限失真。修正后的合同：停机后
    此刻仍应在途（数量 + 可识别身份）、槽位/gauge **不清零**、回收计数为 0；
    只有模型**真正结束**后才**恰一次**回收（原意中正确的部分保留）。
    """
    model = _ProbingTimeoutModel()
    stage = L3Stage(model, budget=L3Budget(concurrency=1),
                    slot_wait_timeout_s=0.2)
    runtime, store = _build_runtime(monkeypatch, l3_stage=stage,
                                    l3_max_queue=8)
    runtime.set_camera_identity(CAM_A, "run-a", 1)
    _feed(store, CAM_A, "run-a", 1, 1, _PERSONS_A)
    try:
        handle = runtime.scheduler.acquire()
        runtime._process_handle(handle)
        entry = runtime._l3_dequeue()
        task, context = entry
        runtime._l3_process_entry(task, context)
        assert stage.execution_resources()["held_unfinished"] == 1
        assert runtime.stop() is True
        res = stage.execution_resources()
        assert res["held_unfinished"] == 1, "执行未结束 → 记录不得被 stop 清空"
        assert res["in_flight"] == 1, "执行未结束 → 在途 gauge 不得归零"
        assert res["reclaimed_total"] == 0, "无真实结束证据 → 一次也不得回收"
        unfinished = runtime.execution_status()["executions_unfinished"]
        assert unfinished["count"] == 1, "停机后仍须如实报告在途数量"
        assert unfinished["items"][0]["branch_key"] == list(context["branch_key"]), \
            "停机后仍须如实报告在途身份（task/branch 键）"
        assert model.calls == 1, "收口不追发、不重跑"
        # 真实结束（唯一证据来源）→ 恰一次回收；重复收口不重复释放
        model.still_running = False
        assert stage.release_held_executions(reason="execution_finished") == 1
        res = stage.execution_resources()
        assert res["held_unfinished"] == 0 and res["in_flight"] == 0
        assert res["reclaimed_total"] == 1, "真实结束后恰一次回收"
        assert stage.release_held_executions() == 0
        assert stage.execution_resources()["reclaimed_total"] == 1
    finally:
        runtime.stop()


# ---------------------------------------------------------------------------
# 5b. C153-R1 §3 屏障负例 a–e：停机未完成 → 保留执行占用 + 三件事分列报告
# ---------------------------------------------------------------------------

class _BlockingBarrierBackend:
    """确定性假 L3 后端（生产 adapter 形状，不依赖真实模型/相机）。

    调用在**独立执行线程**里真实阻塞（`gate` 放行=模型真正结束）；
    `understand_frames` 有界等待后抛 TimeoutError（执行线程**未**被中止，
    同生产 provider 无法 abort）；`snapshot()` 自报执行线程是否仍在跑；
    `close()` 按真实在途返回 `closed=False + close_incomplete=True`。
    """

    model_ref = "deterministic/blocking-barrier"
    infer_timeout_s = 30.0        # stage 侧用显式 slot_wait_timeout_s 控制等待

    def __init__(self, *, wait_s=0.2):
        self.gate = threading.Event()          # 真实执行门（放行=真正结束）
        self.wait_s = float(wait_s)
        self._lock = threading.Lock()
        self.calls = 0
        self.worker_threads = []
        self.close_calls = 0
        self.close_requested = False

    def understand_frames(self, prompt, frames_bgr, frames_meta):
        with self._lock:
            self.calls += 1
        worker = threading.Thread(target=self._work, name="fake-l3-exec",
                                  daemon=True)
        with self._lock:
            self.worker_threads.append(worker)
        worker.start()
        if self.gate.wait(self.wait_s):
            return {"observation": "对象继续移动", "inference": "可能继续前行"}
        raise TimeoutError("wait timeout: worker call NOT cancelled")

    def _work(self):
        self.gate.wait(30.0)                   # 真实执行：测试放行才结束

    def _threads_alive(self):
        with self._lock:
            return sum(1 for t in self.worker_threads if t.is_alive())

    def join(self, timeout=5.0):
        with self._lock:
            threads = list(self.worker_threads)
        for t in threads:
            t.join(timeout)
        return not self._threads_alive()

    def snapshot(self):
        alive = self._threads_alive()
        # 形状同生产 adapter：`pending_call_done` = 真实 future 是否完成
        return {"pending_call_still_running": alive > 0,
                "pending_call_done": alive == 0,
                "pending_calls": alive, "executor_threads_alive": alive,
                "poisoned": False, "close_requested": self.close_requested,
                "phase": "retired" if self.close_requested else "ready"}

    def close(self, timeout_s=5.0):
        with self._lock:
            self.close_calls += 1
            self.close_requested = True
        alive = self._threads_alive()
        if alive:
            return {"closed": False, "pending_calls": alive,
                    "threads_alive": alive, "close_incomplete": True}
        return {"closed": True, "pending_calls": 0, "threads_alive": 0,
                "close_incomplete": False}


def _blocked_execution(monkeypatch, *, wait_s=0.2, slot_wait_timeout_s=0.2):
    """真实生产对象（L2Runtime/L3Stage/队列/窗口）+ 阻塞假后端：在途 1 个执行。

    返回 (runtime, stage, backend, handle, task, context)。
    """
    backend = _BlockingBarrierBackend(wait_s=wait_s)
    stage = L3Stage(backend, budget=L3Budget(concurrency=1),
                    slot_wait_timeout_s=slot_wait_timeout_s)
    runtime, store = _build_runtime(monkeypatch, l3_stage=stage, l3_max_queue=8)
    runtime.l3_backend = backend            # 生产同源收尾：backend.close 参与
    runtime.set_camera_identity(CAM_A, "run-a", 1)
    _feed(store, CAM_A, "run-a", 1, 1, _PERSONS_A)
    handle = runtime.scheduler.acquire()
    runtime._process_handle(handle)
    entry = runtime._l3_dequeue()
    assert entry is not None
    task, context = entry
    runtime._l3_process_entry(task, context)
    return runtime, stage, backend, handle, task, context


def test_stop_keeps_unfinished_execution_and_reports_three_facts(monkeypatch):
    """屏障负例 a：模型调用仍在阻塞、`backend.close` 返回未完成 →
    `Runtime.stop` 返回后**仍报告在途**（数量+身份）、槽位/gauge **未归零**、
    资源关闭状态为**未完成**；三件事（调度/执行/资源关闭）分列。"""
    runtime, stage, backend, handle, task, context = _blocked_execution(
        monkeypatch)
    try:
        res = stage.execution_resources()
        assert res["held_unfinished"] == 1 and res["in_flight"] == 1
        assert backend.calls == 1
        assert runtime.stop() is False, "backend close 未完成 → 停机未完成（如实）"
        # 执行占用保留（不清零、不冒充结束）
        res = stage.execution_resources()
        assert res["in_flight"] == 1, "在途 gauge 不得被 stop 归零"
        assert res["held_unfinished"] == 1, "未完成记录不得被 stop 清空"
        assert res["reclaimed_total"] == 0, "无真实结束证据 → 不得回收"
        # 三件事分开报告
        status = runtime.execution_status()
        assert status["scheduler"]["stopped"] is True, "① 调度已停止"
        assert status["scheduler"]["queue_depth"] == 0, "停机后队列应清空"
        unfinished = status["executions_unfinished"]
        assert unfinished["available"] is True and unfinished["source"] == "live"
        assert unfinished["count"] == 1, "② 执行仍在途（数量）"
        (item,) = unfinished["items"]
        assert item["branch_key"] == list(context["branch_key"]), \
            "② 在途身份（task/branch 键）必须可识别"
        assert item["camera_id"] == CAM_A and item["window_id"] == context["window_key"][3]
        assert item["detail"] == "wait_timeout_execution_unfinished"
        close = status["resources_close_incomplete"]
        assert close["attempted"] is True and close["incomplete"] is True, \
            "③ 资源关闭未完成（backend close 的事实）"
        assert close["backends"][-1]["close_incomplete"] is True
        assert close["backends"][-1]["pending_calls"] >= 1
        assert runtime.snapshot()["execution_status"]["executions_unfinished"][
            "count"] == 1, "健康面（snapshot）同样可见"
        report = runtime.stop_report()
        assert report["executions_unfinished"]["count"] == 1
        assert report["resources_close_incomplete"]["incomplete"] is True
    finally:
        backend.gate.set()
        assert backend.join(timeout=5.0)
        runtime.stop()


def test_stop_rejects_new_submission_after_stop(monkeypatch):
    """屏障负例 b：停止后**新提交被拒**（不入队、无孤儿任务、如实计数）。"""
    runtime, stage, backend, handle, task, context = _blocked_execution(
        monkeypatch)
    try:
        assert runtime.stop() is False
        # 停止后再登记一扇窗（生产：相机线程已 join，不再有新提交；
        # 这里直接走 runtime 的同一提交门禁），提交同一分支
        window_key = runtime._register_window(handle)
        assert window_key is not None
        before = dict(runtime.snapshot()["cameras"][CAM_A])
        assert runtime._enqueue_l3_task(CAM_A, handle.packages[0],
                                        window_key=window_key,
                                        task=task) is False, "停止后不得受理"
        after = dict(runtime.snapshot()["cameras"][CAM_A])
        assert after["l3_enqueued"] == before["l3_enqueued"], "拒绝路径不入队"
        assert runtime.snapshot()["l3"]["queue_depth"] == 0, "不得留孤儿任务"
        assert after["rejected_stale"] == before["rejected_stale"] + 1, \
            "拒收如实计数（rejected_stale）"
        assert after.get("settled_stop_cancelled", 0) == \
            before.get("settled_stop_cancelled", 0) + 1, \
            "该分支按 stop_cancelled 恰一次结算"
        runtime._seal_window(window_key)
    finally:
        backend.gate.set()
        assert backend.join(timeout=5.0)
        runtime.stop()


def test_finished_execution_reclaimed_exactly_once_after_stop(monkeypatch):
    """屏障负例 c：模型**真正结束**后恰一次回收（计数回到 0，且只回收一次）。"""
    runtime, stage, backend, handle, task, context = _blocked_execution(
        monkeypatch)
    try:
        assert runtime.stop() is False
        assert stage.execution_resources()["held_unfinished"] == 1
        assert stage.execution_resources()["reclaimed_total"] == 0
        backend.gate.set()                     # 真实执行结束（唯一证据来源）
        assert backend.join(timeout=5.0)
        assert backend.snapshot()["pending_call_still_running"] is False
        assert stage.release_held_executions(reason="finished") == 1
        res = stage.execution_resources()
        assert res["held_unfinished"] == 0 and res["in_flight"] == 0, "计数回到 0"
        assert res["reclaimed_total"] == 1, "恰一次"
        assert stage.release_held_executions() == 0, "不重复释放"
        assert stage.execution_resources()["reclaimed_total"] == 1
        runtime.stop()                          # 运行面同样按证据收敛
        status = runtime.execution_status()
        assert status["executions_unfinished"]["count"] == 0
        assert status["executions_unfinished"]["reclaimed_total"] == 1
    finally:
        backend.gate.set()
        assert backend.join(timeout=5.0)
        runtime.stop()


def test_repeated_stop_is_idempotent_no_loss_no_double_release(monkeypatch):
    """屏障负例 d：重复 stop 幂等——不丢记录、不重复释放。"""
    runtime, stage, backend, handle, task, context = _blocked_execution(
        monkeypatch)
    try:
        assert runtime.stop() is False
        first = runtime.execution_status()["executions_unfinished"]
        assert first["count"] == 1
        assert first["items"][0]["branch_key"] == list(context["branch_key"])
        for _ in range(2):                     # 执行仍在途时重复 stop
            assert runtime.stop() is False
        res = stage.execution_resources()
        assert res["held_unfinished"] == 1, "重复 stop 不得丢在途记录"
        assert res["in_flight"] == 1, "重复 stop 不得把 gauge 归零"
        assert res["reclaimed_total"] == 0, "无结束证据 → 一次也不得释放"
        again = runtime.execution_status()["executions_unfinished"]
        assert again["count"] == 1
        assert again["items"][0]["branch_key"] == list(context["branch_key"])
        assert runtime.stop_report()["executions_unfinished"]["count"] == 1
        # 真实结束 → 恰一次回收；再 stop 仍不重复释放
        backend.gate.set()
        assert backend.join(timeout=5.0)
        runtime.stop()
        res = stage.execution_resources()
        assert res["reclaimed_total"] == 1 and res["held_unfinished"] == 0
        runtime.stop()
        res = stage.execution_resources()
        assert res["reclaimed_total"] == 1, "实际结束后只回收一次"
        assert res["in_flight"] == 0
    finally:
        backend.gate.set()
        assert backend.join(timeout=5.0)
        runtime.stop()


def test_unfinished_summary_survives_instance_retirement(monkeypatch):
    """屏障负例 e：实例退休（stage/backend 被替换、引用释放）后，
    未完成摘要仍在且可查询（不因对象被替换而丢失在途记录）。"""
    runtime, stage, backend, handle, task, context = _blocked_execution(
        monkeypatch)
    try:
        assert runtime.stop() is False
        before = runtime.execution_status()["executions_unfinished"]
        assert before["available"] is True and before["count"] == 1
        # 退休：stage 只标记不再作为当前实例（不清记录）；随后对象被替换/释放
        retired = stage.retire(reason="replaced_by_new_run")
        assert retired and retired[0]["branch_key"] == list(context["branch_key"])
        fres = stage.execution_resources()
        assert fres["retired"] is True and fres["held_unfinished"] == 1, \
            "退休不得清空/归零未完成执行记录"
        assert fres["reclaimed_total"] == 0
        runtime.l3_stage = None                # 对象被替换/释放（引用丢弃）
        runtime.l3_backend = None
        after = runtime.execution_status()
        assert after["retired"] is True
        assert after["live_stage_available"] is False
        unfinished = after["executions_unfinished"]
        assert unfinished["available"] is False
        assert unfinished["source"] == "stop_report", "退回冻结记录，不冒充现场"
        assert unfinished["count"] == 1, "退休后未完成摘要仍在"
        assert unfinished["items"][0]["branch_key"] == list(context["branch_key"])
        assert unfinished["items"][0]["camera_id"] == CAM_A
        report = runtime.stop_report()
        assert report["executions_unfinished"]["count"] == 1
        assert report["executions_unfinished"]["items"][0]["branch_key"] == \
            list(context["branch_key"])
        # 幂等：重复查询不丢、不重复计数
        assert runtime.execution_status()["executions_unfinished"]["count"] == 1
        assert stage.unfinished_executions()[0]["branch_key"] == \
            list(context["branch_key"]), "退休实例自身也可查未完成摘要"
    finally:
        backend.gate.set()
        assert backend.join(timeout=5.0)
        runtime.stop()


# ---------------------------------------------------------------------------
# 6. 迟到结果 / 拒收 / 封口 / 停止路径都不重复结算
# ---------------------------------------------------------------------------

def test_plan_settlement_is_idempotent_on_replay(monkeypatch):
    """同一份计划重放两次：终态只结算一次（`plan_settled` 键去重），
    L4 缺失因素不重复注入。"""
    stage = _CountingL3Stage()
    runtime, store = _build_runtime(monkeypatch, l3_stage=stage,
                                    l3_max_queue=8)
    runtime.set_camera_identity(CAM_A, "run-a", 1)
    _feed_window(store, CAM_A, "run-a", 1, _PERSONS_A, fid_base=1)
    try:
        handle = runtime.scheduler.acquire()
        window_key = runtime._register_window(handle)
        plans = []
        from scam.win11_l3_tasks import tasks_from_package
        for pkg in handle.packages:
            output = runtime.stage.process(runtime._build_task(pkg))
            tasks = tasks_from_package(
                pkg=pkg, branches=output.l3_branches,
                crop_images_by_crop_id={},
                vocabulary_id="test-v1", vocabulary=(),
                budget=runtime.l3_budget, window_id=window_key[3],
                budget_ledger=runtime.l3_window_budget_ledger, plan_out=plans)
            assert tasks
        plan = plans[-1]
        first = runtime._settle_l3_plan(CAM_A, window_key, plan)
        second = runtime._settle_l3_plan(CAM_A, window_key, plan)
        assert len(first) == 1 and first[0]["terminal"] == "budget_dropped"
        assert second == [], "重放同一计划不得重复结算"
        counts = runtime.snapshot()["cameras"][CAM_A]
        assert counts["settled_budget_dropped"] == 1
        l4 = runtime.history(CAM_A, "l4")
        texts = [item["text"] for rec in l4 for item in rec.get("items", ())]
        assert sum(1 for text in texts if "budget_dropped" in text) == 1, \
            "缺失因素不得因重放重复注入"
    finally:
        handle.release()
        runtime._seal_window(window_key)
        assert runtime.stop() is True


def test_stop_settles_pending_branches_exactly_once(monkeypatch):
    """停止路径：仍在排队的任务按 stop_cancelled 恰一次结算；窗口全部收口，
    账本活页全部封口（无永久泄漏），且不存在"永不封口"的窗口。"""
    gate = threading.Event()
    stage = _CountingL3Stage(gate=gate)
    runtime, store = _build_runtime(monkeypatch, l3_stage=stage,
                                    l3_max_queue=4)
    runtime.set_camera_identity(CAM_A, "run-a", 1)
    _feed_window(store, CAM_A, "run-a", 1, _PERSONS_A, fid_base=1)
    try:
        handle = runtime.scheduler.acquire()
        window_key = runtime._register_window(handle)
        for pkg in handle.packages:
            output = runtime.stage.process(runtime._build_task(pkg))
            runtime._maybe_enqueue_l3(CAM_A, pkg, output,
                                      window_key=window_key)
        handle.release()
        runtime._seal_window(window_key)
        assert runtime.stop() is True
        snap = runtime.snapshot()
        counts = snap["cameras"][CAM_A]
        assert counts["windows_settled"] == 1, "停止后窗口必须收口"
        assert snap["open_windows"] == {"producing": 0, "sealed": 0}
        settled = sum(value for kind, value in counts.items()
                      if kind.startswith("settled_"))
        assert settled == counts["l3_enqueued"] + counts[
            "settled_budget_dropped"], \
            "每个预期分支恰一次终态（无重复、无遗漏）"
        for key in runtime.l3_window_budget_ledger.window_keys():
            assert runtime.l3_window_budget_ledger.is_settled(key) is True
    finally:
        gate.set()
        runtime.stop()


def test_forgotten_window_never_gets_second_budget(monkeypatch):
    """窗口封口（账本 `forget`）后**重放**计划：不发第二份预算；仍在执行的
    任务归属不丢（分支仍能恰一次终态）。"""
    stage = _CountingL3Stage()
    runtime, store = _build_runtime(monkeypatch, l3_stage=stage,
                                    l3_max_queue=8)
    runtime.set_camera_identity(CAM_A, "run-a", 1)
    _feed(store, CAM_A, "run-a", 1, 1, _PERSONS_A)
    try:
        handle = runtime.scheduler.acquire()
        window_key = runtime._register_window(handle)
        pkg = handle.packages[0]
        output = runtime.stage.process(runtime._build_task(pkg))
        runtime._maybe_enqueue_l3(CAM_A, pkg, output, window_key=window_key)
        handle.release()
        runtime._seal_window(window_key)
        ledger = runtime.l3_window_budget_ledger
        assert ledger.is_settled(window_key) is True, "封口后账本活页应清掉"
        frozen = ledger.coverage(window_key)
        assert frozen is not None and frozen["tasks_reserved"] == 2

        # 封口后的重放：不得发第二份预算（逐行 dropped + 受控原因）
        plans = []
        from scam.win11_l3_tasks import tasks_from_package
        replay_tasks = tasks_from_package(
            pkg=pkg, branches=output.l3_branches, crop_images_by_crop_id={},
            vocabulary_id="test-v1", vocabulary=(), budget=runtime.l3_budget,
            window_id=window_key[3], budget_ledger=ledger, plan_out=plans)
        assert replay_tasks == [], "封口窗口的重放不得产出新任务"
        assert plans[0]["kept"] == ()
        assert {row["reason"] for row in plans[0]["entries"]} == {
            "window_budget_window_settled"}
        assert ledger.coverage(window_key)["tasks_reserved"] == 2, \
            "重放不得新增额度（无第二份预算）"
        rows = runtime._settle_l3_plan(CAM_A, window_key, plans[0])
        assert rows and all(row["owned_by"] == "kept_task" for row in rows), \
            "重放行只如实记账：身份仍归已在排队的任务，不伪造第二份终态"
        assert all(row["settled"] is False for row in rows)
        counts = runtime.snapshot()["cameras"][CAM_A]
        assert counts.get("settled_budget_dropped", 0) == 0, "重放不得新增终态"

        # 归属不丢：仍在排队的任务仍能恰一次终态并让窗口收口
        for _ in range(2):
            entry = runtime._l3_dequeue()
            assert entry is not None
            runtime._l3_process_entry(entry[0], entry[1])
        snap = runtime.snapshot()
        assert snap["cameras"][CAM_A]["windows_settled"] == 1
        assert snap["cameras"][CAM_A]["l3_completed"] == 2
    finally:
        assert runtime.stop() is True
