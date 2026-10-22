"""win11_materials 有界时序材料包测试（合同 C-133 §二 M1—M6 + R1 配合；
C-134 修正：A1/A2/A3；C-135 修正：waiting_l1 状态机 + 真实存活字节；
C-136 A1 修正：finalizer 注册原子性——准备段失败完整回滚零幽灵；
C-137 适配：窗口生命周期接口 role/area_at_entry 随租约副本透传）。

覆盖：原图修改隔离 / 真实前后帧与 M2 回填边界（同 run 同 config、
0 < t_gap ≤ 10000，gap 显式记录）/ 状态机 waiting_l1 不可摘与 attach
驱动迁移（consumable / fallback_terminal 各原因矩阵、超时兜底、迟到
晋升一次性与已消费诊断拒绝、FIFO 跳过等待头部、双相机独立）/ 门控坐
标→原图映射 / M3 uid 引用计数账本（共享帧所有者逐出仍计费、最后引用
消失才减费、全库真实字节全局预算跨相机公平逐出、账实双验）/ M4
take_ready 隔离副本与租约记账（槽位/字节超限拒、release、到期只标
记）/ M1 四元身份（跨 run/跨 config 回填与 attach 拒、重复 frame_id
同 run 拒）/ R1 被拒结果只作诊断 / M5 close 恒拒且租约如实 / 并发进
出账目守恒 / C-134 A1 租约强引用（TTL 到期只标记不减字节、过期仍计费
背压、release 唯一任务资格解除、weakref/可达性核验）/ C-135 §二 真实
存活字节（consumer_alive_bytes finalize 口径：release 不等于内存返还、
视图持基对象计费、第三方 copy 不计费、租约预算检查对象=存活字节）/
A2 take_ready 复制原子性（prev/cur/nxt 任一复制失败→不提交消费、无半
租约、无幽灵账本）/ C-136 A1 finalize 注册原子性（第 1/2/3 个图像的
注册分别注入失败→包/引用/字节/租约槽/close 后账目全部一致，detach 防
幽灵回收记录）/ A3 检测逐检测深拷贝（嵌套框双向不污染、track_id
透传不伪造）。

全部用注入 FakeClock 推进时间（无长 sleep）；禁 subprocess / eval /
f-string SQL / `..` 路径。
"""

import gc
import threading
import weakref

import pytest

import numpy as np

import scam.win11_materials as win11_materials
from scam.win11_materials import (
    MAX_ADJACENT_GAP_MS,
    MaterialsStore,
)

_MATERIALS_DOC = win11_materials.__doc__   # 被测模块 docstring（边界断言）
FRAME_BYTES = 6 * 8 * 3          # make_frame 默认形状的 nbytes
DET = {"cls": "person", "conf": 0.9, "bbox": [0.1, 0.1, 0.2, 0.2]}

# 合同冻结清单：C-134 每相机 18 字段 + C-135 新增 5（状态机）+ 5（租约/
# 字节分列）；全局 C-134 4 键 + C-135 新增 5 键
CAMERA_KEYS = {"ready", "waiting_l1", "consumable", "fallback",
               "late_promotions", "l1_timeouts",
               "consumed", "expired", "dropped_pressure",
               "global_drops", "rejected_attach", "attach_missed",
               "dup_rejected", "leased", "active_leases", "lease_expired",
               "expired_leases", "released_leases", "lease_bytes",
               "consumer_alive_bytes", "total_bytes", "store_bytes",
               "oldest_age_s", "ready_with_prev",
               "ready_with_next", "last_l1_status", "last_l1_accepted",
               "last_reject_reason",
               # C-144：最近包触发原因随快照透出（界面状态映射/准入诊断）
               "last_material_reason"}
GLOBAL_KEYS = {"cameras", "total_bytes", "store_bytes", "lease_bytes",
               "consumer_alive_bytes", "active_leases", "released_leases",
               "expired_leases", "total_packages"}


# ---- 构造辅助 --------------------------------------------------------------

class FakeClock:
    """可手动推进的单调钟（秒）；store 以 clock()*1000 记 created_mono_ms。"""

    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def make_frame(value=7, w=8, h=6, dtype=np.uint8):
    """合成帧：整幅单一数值（数值即身份标记，可字节比较）。"""
    return np.full((h, w, 3), value, dtype=dtype)


def ingest(store, cam, frame_id, frame, t_capture_ms=1000.0, boxes=None,
           gate_w=96, gate_h=48, run_id="r1", config_version=1,
           timestamp_kind="capture"):
    return store.ingest(cam, run_id, config_version, frame_id, frame,
                        t_capture_ms, timestamp_kind, boxes or [],
                        gate_w, gate_h)


def ingest_ok(store, cam, frame_id, frame, t_capture_ms=1000.0, boxes=None,
              gate_w=96, gate_h=48, run_id="r1", config_version=1,
              timestamp_kind="capture", dets=None, status="ok",
              error_code=None):
    """ingest + attach(ok)：C-135 状态机下让包立即进入 consumable 的管道
    辅助（仅供不关心 L1 状态语义的用例使用；受理失败不 attach）。"""
    ok = ingest(store, cam, frame_id, frame, t_capture_ms, boxes, gate_w,
                gate_h, run_id, config_version, timestamp_kind)
    if ok:
        store.attach_result(cam, run_id, config_version, frame_id, status,
                            error_code, dets if dets is not None else [])
    return ok


def reachable_frame_bytes(store):
    """账实双验（白箱）：遍历在仓包 prev/cur/nxt 收集独立图像对象求和。"""
    seen = {}
    for cam in store._cams.values():
        for pkg in cam["ring"]:
            for frame in (pkg.prev, pkg.cur, pkg.nxt):
                if frame is not None:
                    seen[id(frame.frame_bgr)] = int(frame.frame_bgr.nbytes)
    return sum(seen.values())


# ---- a. 原图修改隔离 --------------------------------------------------------

def test_ingest_copies_frame_caller_mutation_isolated():
    """ingest 后原地改写调用方数组与框列表，包内帧/框字节必须不变。"""
    store = MaterialsStore()
    frame = make_frame(value=7)
    boxes = [{"x": 1, "y": 2, "w": 3, "h": 4}]
    assert ingest_ok(store, "a", 1, frame, boxes=boxes, gate_w=8, gate_h=6) \
        is True
    frame[:] = 255                        # 原地污染源头缓冲
    boxes[0]["x"] = 99                    # 原地污染框
    boxes.append({"x": 50, "y": 50, "w": 5, "h": 5})
    pkg = store.take_ready("a")
    assert pkg is not None
    assert pkg.cur.frame_bgr is not frame, "包内帧不得是调用方数组本身"
    expected = np.full((6, 8, 3), 7, dtype=np.uint8)
    assert pkg.cur.frame_bgr.tobytes() == expected.tobytes(), "帧被源头污染"
    assert pkg.change_boxes == [{"x": 1, "y": 2, "w": 3, "h": 4}]
    assert pkg.change_original_boxes() == [{"x": 1, "y": 2, "w": 3, "h": 4}]
    assert pkg.cur.width == 8 and pkg.cur.height == 6
    assert pkg.cur.frame_id == 1
    assert pkg.cur.t_capture_ms == 1000.0
    assert pkg.cur.timestamp_kind == "capture"
    assert pkg.state == "consumed"
    assert pkg.l1_terminal_reason is None, "consumable 包 reason=None"


# ---- b. 真实前后帧与有界回填（M2 gap 记录） ---------------------------------

def test_real_adjacent_frames_and_bounded_backfill():
    """四帧入包：prev/nxt 指向真实相邻帧（take 后为隔离副本），gap 显式
    记录、缺失显式 None；每包只回填一次，不得被后来帧改写。"""
    store = MaterialsStore()
    for i in range(1, 5):
        assert ingest_ok(store, "a", 10 + i, make_frame(i),
                         t_capture_ms=1000.0 * i) is True
    snap = store.snapshot()
    cam = snap["cameras"]["a"]
    assert cam["ready"] == 4
    assert cam["ready_with_prev"] == 3    # 第 2—4 包有 prev
    assert cam["ready_with_next"] == 3    # 第 1—3 包有 nxt
    p1 = store.take_ready("a")
    p2 = store.take_ready("a")
    p3 = store.take_ready("a")
    p4 = store.take_ready("a")
    assert p1.prev is None and p1.prev_gap_ms is None
    assert p4.nxt is None and p4.nxt_gap_ms is None
    assert p1.nxt is not p2.cur, "take_ready 输出隔离副本，不再共享对象"
    assert p1.nxt.frame_id == p2.cur.frame_id == 12
    assert p2.prev.frame_id == p1.cur.frame_id == 11
    assert p2.prev is not p1.cur
    assert p2.nxt.frame_id == 13 and p3.prev.frame_id == 12
    assert p3.nxt.frame_id == 14 and p4.prev.frame_id == 13
    assert p1.nxt.frame_id == 12, "有界回填：每包只回填一次，不得被后来帧改写"
    assert (p1.cur.frame_id, p2.cur.frame_id, p3.cur.frame_id,
            p4.cur.frame_id) == (11, 12, 13, 14)
    assert [p.cur.t_capture_ms for p in (p1, p2, p3, p4)] == \
        [1000.0, 2000.0, 3000.0, 4000.0]
    assert p1.nxt_gap_ms == 1000.0 and p2.prev_gap_ms == 1000.0
    assert p2.nxt_gap_ms == 1000.0 and p3.prev_gap_ms == 1000.0
    assert p1.nxt.frame_bgr[0, 0, 0] == 2
    assert p2.nxt.frame_bgr[0, 0, 0] == 3
    assert p2.nxt.t_capture_ms == 3000.0
    assert p2.nxt.timestamp_kind == "capture"
    assert p4.prev.frame_bgr[0, 0, 0] == 3


# ---- c. 状态机：waiting_l1 不可摘 + 零对象与 L1 不可用如实可取 ----------------

def test_waiting_l1_invisible_until_attach():
    """C-135 §一：ingest → waiting_l1，take_ready 返回 None（不可被摘）；
    attach ok → consumable 可摘且 l1_terminal_reason is None；摘走包带
    consumed 态且 late_promotion=False。"""
    store = MaterialsStore()
    assert ingest(store, "a", 1, make_frame(1)) is True
    assert store.take_ready("a") is None, "waiting_l1 对 L2 不可见"
    snap = store.snapshot()
    cam = snap["cameras"]["a"]
    assert cam["ready"] == 0 and cam["waiting_l1"] == 1
    assert cam["consumable"] == 0 and cam["fallback"] == 0
    assert cam["l1_timeouts"] == 0 and cam["late_promotions"] == 0
    assert snap["total_packages"] == 1, "waiting_l1 持续入仓不受限"
    assert store.attach_result("a", "r1", 1, 1, "ok", None,
                               [dict(DET)]) is True
    snap = store.snapshot()
    cam = snap["cameras"]["a"]
    assert cam["waiting_l1"] == 0 and cam["consumable"] == 1
    assert cam["ready"] == 1
    pkg = store.take_ready("a")
    assert pkg is not None
    assert pkg.l1_terminal_reason is None, "consumable 包 terminal_reason=None"
    assert pkg.late_promotion is False
    assert pkg.state == "consumed"
    assert pkg.detections == [dict(DET)]
    assert store.snapshot()["cameras"]["a"]["consumed"] == 1


def test_take_skips_waiting_returns_oldest_takeable():
    """take_ready 跳过 waiting_l1 摘最旧可摘包（FIFO 不被等待头部阻塞）；
    waiting_l1 包不被摘走、留在仓内。"""
    store = MaterialsStore()
    assert ingest(store, "a", 1, make_frame(1)) is True          # p1 等待
    assert ingest(store, "a", 2, make_frame(2)) is True
    assert store.attach_result("a", "r1", 1, 2, "ok", None, []) is True
    pkg = store.take_ready("a")
    assert pkg is not None and pkg.cur.frame_id == 2, \
        "跳过 waiting_l1 摘最旧可摘包"
    snap = store.snapshot()
    assert snap["cameras"]["a"]["waiting_l1"] == 1, "等待包不被摘走"
    assert snap["total_packages"] == 1


def test_zero_object_and_l1_unavailable_honest_materials():
    """C-135 状态机：未 attach 的包 waiting_l1 不可摘，超时兜底后如实可取
    （l1_status=None 不伪造 empty）；attach empty / model_unavailable / ok
    驱动迁移且如实标注；缺帧 attach 计 miss、已消费包迟到结果只作诊断
    拒绝（rejected_attach，C-135 冻结规则）。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock, l1_wait_s=3.0)
    # 未 attach：waiting_l1 不可摘；超时 sweep 转 fallback(l1_wait_timeout)
    assert ingest(store, "a", 1, make_frame(1)) is True
    assert store.take_ready("a") is None, "waiting_l1 对 L2 不可见"
    clock.advance(3.5)
    snap = store.snapshot()
    assert snap["cameras"]["a"]["l1_timeouts"] == 1
    p1 = store.take_ready("a")
    assert p1 is not None
    assert p1.l1_status is None and p1.l1_error_code is None
    assert p1.detections is None, "未处理材料不得伪造空检测结果"
    assert p1.l1_terminal_reason == "l1_wait_timeout"

    assert ingest(store, "a", 2, make_frame(2)) is True
    assert store.attach_result("a", "r1", 1, 2, "empty", None, []) is True
    p2 = store.take_ready("a")
    assert p2.l1_status == "empty" and p2.detections == []
    assert p2.l1_error_code is None
    assert p2.l1_terminal_reason == "empty"

    assert ingest(store, "a", 3, make_frame(3)) is True
    assert store.attach_result("a", "r1", 1, 3, "model_unavailable",
                               "detector_load_failed", []) is True
    p3 = store.take_ready("a")
    assert p3.l1_status == "model_unavailable"
    assert p3.l1_error_code == "detector_load_failed"
    assert p3.detections == [], "L1 不可用材料照常可取且如实标注"
    assert p3.l1_terminal_reason == "model_unavailable"

    dets = [dict(DET)]
    assert ingest(store, "a", 4, make_frame(4)) is True
    assert store.attach_result("a", "r1", 1, 4, "ok", None, dets) is True
    p4 = store.take_ready("a")
    assert p4.l1_status == "ok"
    # A3：take 输出逐检测深拷贝——值相等但不是同一对象（非引用共享）
    assert p4.detections == dets and p4.detections is not dets
    assert p4.detections[0] is not dets[0]
    assert p4.last_l1_accepted is True and p4.last_reject_reason is None
    assert p4.l1_terminal_reason is None

    # 缺帧不伪造：未知 frame_id → attach_missed；已消费包（frame 1）迟到
    # 结果 → 只作诊断拒绝 rejected_attach（C-135 冻结规则）
    assert store.attach_result("a", "r1", 1, 999, "ok", None, dets) is False
    assert store.attach_result("a", "r1", 1, 1, "ok", None, dets) is False
    snap = store.snapshot()
    assert snap["cameras"]["a"]["attach_missed"] == 1
    assert snap["cameras"]["a"]["rejected_attach"] == 1
    assert snap["cameras"]["a"]["last_l1_status"] == "ok"

    assert store.attach_result("zz", "r1", 1, 1, "ok", None, []) is False
    assert store.snapshot()["cameras"]["zz"]["attach_missed"] == 1


def test_l1_fallback_transition_matrix():
    """状态迁移矩阵：accepted empty / model_unavailable / infer_failed /
    rejected 各自 fallback_terminal 原因正确；fallback 包可摘；双相机
    独立（cam a 的 fallback 不影响 cam b 正常摘取）。"""
    store = MaterialsStore()
    cases = [(2, "empty", None, "empty"),
             (3, "model_unavailable", "detector_load_failed",
              "model_unavailable"),
             (4, "infer_failed", "backend boom", "infer_failed")]
    for fid, status, err, _reason in cases:
        assert ingest(store, "a", fid, make_frame(fid % 256)) is True
        assert store.attach_result("a", "r1", 1, fid, status, err,
                                   []) is True
    assert ingest(store, "a", 5, make_frame(5)) is True
    assert store.attach_result("a", "r1", 1, 5, "ok", None, [],
                               accepted=False,
                               reject_reason="expired") is True
    snap = store.snapshot()
    cam = snap["cameras"]["a"]
    assert cam["waiting_l1"] == 0 and cam["consumable"] == 0
    assert cam["fallback"] == 4 and cam["ready"] == 4, \
        "fallback_terminal 包可被 take_ready 摘取"
    taken = [store.take_ready("a") for _ in range(4)]
    assert [p.l1_terminal_reason for p in taken] == \
        ["empty", "model_unavailable", "infer_failed", "rejected:expired"]
    assert all(p.state == "consumed" for p in taken)
    assert taken[3].last_reject_reason == "expired"
    assert taken[3].last_l1_accepted is False

    # 双相机公平：cam a 的 fallback 不影响 cam b 独立摘取
    assert ingest(store, "b", 1, make_frame(9)) is True
    assert store.attach_result("b", "r1", 1, 1, "ok", None, []) is True
    pb = store.take_ready("b")
    assert pb is not None and pb.cur.frame_id == 1
    assert pb.l1_terminal_reason is None


def test_l1_wait_timeout_sweep_fallback():
    """超时兜底：clock 注入跨 L1_WAIT_S → sweep（挂在观察调用点）转
    fallback_terminal(reason="l1_wait_timeout") 后可摘；边界值（恰等于
    L1_WAIT_S）不超时（单调钟，严格大于）。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock, l1_wait_s=3.0)
    assert ingest(store, "a", 1, make_frame(1)) is True          # t=1000
    clock.advance(2.9)
    assert store.take_ready("a") is None, "未超 L1_WAIT_S 仍在等待"
    snap = store.snapshot()
    assert snap["cameras"]["a"]["waiting_l1"] == 1
    assert snap["cameras"]["a"]["l1_timeouts"] == 0
    clock.advance(0.1)                    # 恰好 3.0s：严格大于才超时
    snap = store.snapshot()
    assert snap["cameras"]["a"]["waiting_l1"] == 1, "边界值不超时"
    assert snap["cameras"]["a"]["l1_timeouts"] == 0
    clock.advance(0.05)                   # 3.05s > 3.0s
    snap = store.snapshot()               # sweep 挂在观察调用点
    cam = snap["cameras"]["a"]
    assert cam["waiting_l1"] == 0 and cam["fallback"] == 1
    assert cam["l1_timeouts"] == 1 and cam["ready"] == 1
    pkg = store.take_ready("a")
    assert pkg is not None
    assert pkg.l1_terminal_reason == "l1_wait_timeout"
    assert pkg.l1_status is None, "超时兜底不伪造 L1 结果"
    assert pkg.state == "consumed"


def test_late_promotion_after_timeout_and_consumed_reject():
    """迟到晋升（冻结规则）：超时 fallback 后有效 ok 结果迟到且未消费 →
    一次性晋升 consumable + late_promotion=True；已消费 → 只作诊断拒绝
    （rejected_attach）；确定性 fallback（empty）不因迟到 ok 晋升。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock, l1_wait_s=3.0)
    # 未消费：超时 fallback 后有效 ok 迟到 → 一次性晋升
    assert ingest(store, "a", 1, make_frame(1)) is True
    clock.advance(3.5)
    snap = store.snapshot()               # sweep：l1_wait_timeout
    assert snap["cameras"]["a"]["fallback"] == 1
    assert store.attach_result("a", "r1", 1, 1, "ok", None,
                               [dict(DET)]) is True
    snap = store.snapshot()
    cam = snap["cameras"]["a"]
    assert cam["consumable"] == 1 and cam["fallback"] == 0
    assert cam["late_promotions"] == 1 and cam["l1_timeouts"] == 1
    pkg = store.take_ready("a")
    assert pkg.late_promotion is True, "晋升包带 late_promotion 标记"
    assert pkg.l1_terminal_reason is None
    assert pkg.detections == [dict(DET)]
    # 已消费：同一身份再迟到 → 只作诊断拒绝（rejected_attach）
    assert store.attach_result("a", "r1", 1, 1, "ok", None, []) is False
    snap = store.snapshot()
    assert snap["cameras"]["a"]["rejected_attach"] == 1
    assert snap["cameras"]["a"]["late_promotions"] == 1, "晋升一次性"
    # 确定性 fallback（empty）：迟到 ok 不晋升（冻结规则只覆盖超时）
    assert ingest(store, "a", 2, make_frame(2)) is True
    assert store.attach_result("a", "r1", 1, 2, "empty", None, []) is True
    rejects_before = store.snapshot()["cameras"]["a"]["rejected_attach"]
    assert store.attach_result("a", "r1", 1, 2, "ok", None,
                               [dict(DET)]) is False
    snap = store.snapshot()
    cam = snap["cameras"]["a"]
    assert cam["fallback"] == 1 and cam["consumable"] == 0
    assert cam["late_promotions"] == 1, "确定性 fallback 定案后不晋升（R1）"
    assert cam["rejected_attach"] == rejects_before + 1
    p2 = store.take_ready("a")
    assert p2.l1_terminal_reason == "empty"
    assert p2.l1_status == "empty", "迟到 ok 不改写已定案的结果槽"


# ---- d. 门控坐标 → 原图映射 --------------------------------------------------

def test_change_original_boxes_mapping():
    """200×100 原图 + gate 100×50 + 框(10,5,20,10) → (20,10,40,20)；
    gate 尺寸缺失/为零返回 []，不猜测比例。"""
    store = MaterialsStore()
    boxes = [{"x": 10, "y": 5, "w": 20, "h": 10}]
    assert ingest_ok(store, "a", 1, make_frame(w=200, h=100), boxes=boxes,
                     gate_w=100, gate_h=50) is True
    pkg = store.take_ready("a")
    assert pkg.change_original_boxes() == [{"x": 20, "y": 10, "w": 40,
                                            "h": 20}]

    assert ingest_ok(store, "a", 2, make_frame(w=200, h=100), boxes=boxes,
                     gate_w=0, gate_h=50) is True
    assert store.take_ready("a").change_original_boxes() == []

    assert ingest_ok(store, "a", 3, make_frame(w=200, h=100), boxes=boxes,
                     gate_w=100, gate_h=None) is True
    assert store.take_ready("a").change_original_boxes() == []

    assert ingest_ok(store, "a", 4, make_frame(w=200, h=100), boxes=[],
                     gate_w=100, gate_h=50) is True
    assert store.take_ready("a").change_original_boxes() == []


# ---- e. 多相机隔离与分账 -------------------------------------------------------

def test_camera_isolation_and_per_camera_accounting():
    """cam a 压力逐出不波及 cam b；快照按相机分账。注意 M3：被逐出包的
    cur 帧经邻包 prev 仍被引用 → 仍计费（cam a 账面=3 帧而非 2 帧）。"""
    store = MaterialsStore(max_packages_per_camera=2)
    for fid in (1, 2, 3):                 # cap=2 → 第 3 帧挤掉第 1 包
        assert ingest_ok(store, "a", fid, make_frame(fid),
                         t_capture_ms=1000.0 + 10 * fid) is True
    assert ingest_ok(store, "b", 1, make_frame(9)) is True
    snap = store.snapshot()
    cam_a = snap["cameras"]["a"]
    assert cam_a == {
        "ready": 2, "waiting_l1": 0, "consumable": 2, "fallback": 0,
        "late_promotions": 0, "l1_timeouts": 0,
        "consumed": 0, "expired": 0, "dropped_pressure": 1,
        "global_drops": 0, "rejected_attach": 0, "attach_missed": 0,
        "dup_rejected": 0, "leased": 0, "active_leases": 0,
        "lease_expired": 0, "expired_leases": 0, "released_leases": 0,
        "lease_bytes": 0, "consumer_alive_bytes": 0,
        "total_bytes": 3 * FRAME_BYTES, "store_bytes": 3 * FRAME_BYTES,
        "oldest_age_s": cam_a["oldest_age_s"],
        "ready_with_prev": 2, "ready_with_next": 1, "last_l1_status": "ok",
        "last_l1_accepted": True, "last_reject_reason": None,
        # C-144：last_material_reason 随快照透出（本用例 ingest 未传
        # reason → None 如实；透传链路由专用用例覆盖）
        "last_material_reason": None}
    # 逐出语义：pkg1 被逐出但 pkg2.prev 仍持 f1（账面 3 帧：f1/f2/f3）；
    # ready_with_next=1：仅 pkg2.nxt 指向 pkg3.cur，pkg3 是最新包无后继
    assert snap["cameras"]["b"]["dropped_pressure"] == 0
    assert snap["cameras"]["b"]["ready"] == 1
    assert snap["cameras"]["b"]["total_bytes"] == FRAME_BYTES
    assert snap["cameras"]["b"]["store_bytes"] == FRAME_BYTES
    assert snap["total_bytes"] == 4 * FRAME_BYTES
    assert snap["total_bytes"] == reachable_frame_bytes(store), "账实相符"
    assert snap["total_packages"] == 3

    pkg_b = store.take_ready("b")
    assert pkg_b is not None and pkg_b.cur.frame_bgr[0, 0, 0] == 9
    pkg_a = store.take_ready("a")
    assert pkg_a.cur.frame_id == 2, "cam a 逐出的必须是最旧包，且不波及 cam b"
    assert pkg_a.prev.frame_id == 1, "被逐出所有者的帧经邻包 prev 诚实保留"


# ---- f. 压力逐出级联 / 帧引用释放 / 重复 frame_id 拒收 -------------------------

def test_pressure_eviction_cascade_and_frame_release():
    """字节触顶按全库真实存活字节逐出：共享帧只要还有在仓引用就继续计费，
    逐出最旧包不减费时级联继续（直到账实达标）；store 侧帧引用随取走
    释放（weakref）；同 run 重复 frame_id 拒收且仅 dup_rejected 变化。"""
    clock = FakeClock()
    store = MaterialsStore(max_total_bytes=2 * FRAME_BYTES + 72, clock=clock)
    # 预算 2.5 帧：p1(cur=f1,nxt=f2) + p2(prev=f1,cur=f2)，f1/f2 各 2 引用
    f1 = make_frame(1)
    f2 = make_frame(2)
    f3 = make_frame(3)
    assert ingest_ok(store, "a", 1, f1, t_capture_ms=1000.0) is True
    assert ingest_ok(store, "a", 2, f2, t_capture_ms=1010.0) is True
    snap = store.snapshot()
    assert snap["total_bytes"] == 2 * FRAME_BYTES

    # 第 3 帧：f1 经 p2.prev 仍被引用 → 逐出 p1 不减费 → 级联逐出 p2
    # （f1/f2 最后引用消失）才真正回落；插入后 p3(prev=None,cur=f3)
    assert ingest_ok(store, "a", 3, f3, t_capture_ms=1020.0) is True
    snap = store.snapshot()
    cam = snap["cameras"]["a"]
    assert cam["dropped_pressure"] == 2
    assert cam["ready"] == 1
    assert snap["total_bytes"] == FRAME_BYTES
    assert snap["total_bytes"] == reachable_frame_bytes(store)

    w_store_f3 = weakref.ref(store._cams["a"]["ring"][0].cur.frame_bgr)
    p3 = store.take_ready("a")
    assert p3 is not None and p3.cur.frame_id == 3
    assert p3.prev is None and p3.nxt is None
    assert p3.cur.frame_bgr is not f3, "取走的是隔离副本"
    assert int(p3.cur.frame_bgr[0, 0, 0]) == 3
    assert store.snapshot()["total_bytes"] == 0, "取走后 store 预算全部回落"
    del p3, f1, f2, f3
    gc.collect()
    assert w_store_f3() is None, "store 帧随取走释放（消费者只持副本）"

    # 同 run 重复 frame_id 拒收（dup_rejected 进快照，其余字段零变化）
    assert ingest_ok(store, "a", 10, make_frame(4), t_capture_ms=1030.0) \
        is True
    before = store.snapshot()
    assert ingest(store, "a", 10, make_frame(5), t_capture_ms=1040.0) is False
    after = store.snapshot()
    assert after["cameras"]["a"]["dup_rejected"] == \
        before["cameras"]["a"]["dup_rejected"] + 1
    for key in CAMERA_KEYS:
        if key != "dup_rejected":
            assert after["cameras"]["a"][key] == before["cameras"]["a"][key], \
                key
    assert after == {**before,
                     "cameras": {**before["cameras"],
                                 "a": {**before["cameras"]["a"],
                                       "dup_rejected": 1}}}
    assert store._rejects["a"]["dup"] == 1


def test_shared_frame_billing_survives_owner_eviction():
    """M3 核心：逐出 cur 所有者包后，邻包 prev 仍持共享帧 → 继续计费；
    最后一个引用（邻包）消失才真正减费。账实双验（不只信内部账）。"""
    clock = FakeClock()
    store = MaterialsStore(max_total_bytes=2 * FRAME_BYTES, max_age_s=10.0,
                           clock=clock)
    assert ingest_ok(store, "a", 1, make_frame(1), t_capture_ms=1000.0) \
        is True
    clock.advance(1.0)
    assert ingest_ok(store, "a", 2, make_frame(2), t_capture_ms=1010.0) \
        is True
    snap = store.snapshot()
    assert snap["total_bytes"] == 2 * FRAME_BYTES
    assert snap["total_bytes"] == reachable_frame_bytes(store)

    clock.advance(10.0)                   # t=1011：p1 年龄 11s > 10s 逐出，
    snap = store.snapshot()               # p2 年龄 10s ≤ 10s 保留
    assert snap["cameras"]["a"]["expired"] == 1
    assert snap["cameras"]["a"]["ready"] == 1
    assert snap["total_bytes"] == 2 * FRAME_BYTES, \
        "所有者被逐出，但 p2.prev 仍持共享帧：不得减费"
    assert snap["cameras"]["a"]["total_bytes"] == 2 * FRAME_BYTES
    assert snap["total_bytes"] == reachable_frame_bytes(store), "账实相符"

    pkg = store.take_ready("a")           # 最后引用消失才减费
    assert pkg.cur.frame_id == 2 and pkg.prev.frame_id == 1
    snap = store.snapshot()
    assert snap["total_bytes"] == 0 and snap["total_packages"] == 0
    assert reachable_frame_bytes(store) == 0


def test_shared_frame_last_reference_decay():
    """链式共享逐步衰减：3 包逐包取走，账面 3→3→2→0 帧（引用计数账本，
    逐出/取走只减独占引用）。"""
    store = MaterialsStore()
    for i in range(1, 4):
        assert ingest_ok(store, "a", i, make_frame(i),
                         t_capture_ms=1000.0 + 100 * i) is True
    snap = store.snapshot()
    assert snap["total_bytes"] == 3 * FRAME_BYTES
    assert snap["total_bytes"] == reachable_frame_bytes(store)
    p1 = store.take_ready("a")
    assert store.snapshot()["total_bytes"] == 3 * FRAME_BYTES, \
        "f1/f2 仍被 p2.prev/nxt 持有：取走 p1 不减费"
    p2 = store.take_ready("a")
    snap = store.snapshot()
    assert snap["total_bytes"] == 2 * FRAME_BYTES, \
        "f1 最后引用消失减费；f2/f3 仍被 p3.prev/cur 持有"
    assert snap["total_bytes"] == reachable_frame_bytes(store)
    p3 = store.take_ready("a")
    snap = store.snapshot()
    assert snap["total_bytes"] == 0 and snap["total_packages"] == 0
    assert p2.prev.frame_id == 1 and p2.nxt.frame_id == 3
    del p1, p2, p3


# ---- g. 消费者污染隔离（M4 隔离副本） -----------------------------------------

def test_consumer_pollution_isolated_copy():
    """take_ready 输出隔离副本：消费者原地改写图像（写 255）与框（改值+
    append）→ 仓内/后续取走包的图与框必须不变（真实断言）。"""
    store = MaterialsStore()
    boxes = [{"x": 1, "y": 2, "w": 3, "h": 4}]
    for i in range(1, 4):
        assert ingest_ok(store, "a", i, make_frame(i),
                         t_capture_ms=1000.0 + 10 * i, boxes=boxes) is True
    p1 = store.take_ready("a")
    assert p1.nxt is not None
    p1.cur.frame_bgr[:] = 255             # 原地污染取走包的 cur 图
    p1.nxt.frame_bgr[:] = 255             # 原地污染取走包的 nxt 图
    p1.change_boxes[0]["x"] = 42          # 原地污染框
    p1.change_boxes.append({"x": 9, "y": 9, "w": 9, "h": 9})
    p2 = store.take_ready("a")
    p3 = store.take_ready("a")
    assert int(p2.cur.frame_bgr[0, 0, 0]) == 2, "仓内 cur 图未被消费者改写"
    assert int(p2.prev.frame_bgr[0, 0, 0]) == 1
    assert int(p2.nxt.frame_bgr[0, 0, 0]) == 3
    assert p2.change_boxes == [{"x": 1, "y": 2, "w": 3, "h": 4}], \
        "仓内框未被消费者改写"
    assert p3.cur.frame_bgr[0, 0, 0] == 3
    assert p3.prev.frame_bgr[0, 0, 0] == 2
    assert p3.change_boxes == [{"x": 1, "y": 2, "w": 3, "h": 4}]
    assert p1.change_boxes == [{"x": 42, "y": 2, "w": 3, "h": 4},
                               {"x": 9, "y": 9, "w": 9, "h": 9}], \
        "消费者副本自身可自由改写"


# ---- h. M1 身份边界：跨 run / 跨 config / 超时间隔 ------------------------------

def test_identity_backfill_and_attach_boundaries():
    """M1/M2：回填与 attach 必须 (camera, run, config, frame) 四元全匹配；
    跨 run / 跨 config / gap ≤ 0 / gap > 10000 一律不冒充紧邻帧；身份不符
    的 attach 计 rejected_attach 且包不被污染；完全未知 frame 计
    attach_missed；同 frame_id 换 run/config 不是重复。"""
    store = MaterialsStore()
    # 跨 run：同 camera 邻接也不得回填
    assert ingest_ok(store, "a", 1, make_frame(1), t_capture_ms=1000.0) \
        is True
    assert ingest_ok(store, "a", 2, make_frame(2), t_capture_ms=1010.0,
                     run_id="r2") is True
    snap = store.snapshot()
    assert snap["cameras"]["a"]["ready_with_prev"] == 0
    assert snap["cameras"]["a"]["ready_with_next"] == 0
    # 跨 run attach：frame_id 命中但 run 不符 → rejected_attach，包不被污染
    assert store.attach_result("a", "r1", 1, 2, "ok", None,
                               [dict(DET)]) is False
    snap = store.snapshot()
    assert snap["cameras"]["a"]["rejected_attach"] == 1
    assert snap["cameras"]["a"]["attach_missed"] == 0
    p1 = store.take_ready("a")
    p2 = store.take_ready("a")
    assert p1.cur.frame_id == 1 and p2.cur.frame_id == 2
    assert p1.prev is None and p1.prev_gap_ms is None
    assert p2.prev is None and p2.prev_gap_ms is None and p2.nxt is None
    assert p2.l1_status == "ok" and p2.detections == [], \
        "身份不符的旧 run 结果被拒：p2 只保留自身 r2 的 attach 结果（未污染）"

    # 跨 config：回填与 attach 同样拒绝
    assert ingest_ok(store, "a", 3, make_frame(3), t_capture_ms=1020.0) \
        is True
    assert ingest_ok(store, "a", 4, make_frame(4), t_capture_ms=1030.0,
                     config_version=2) is True
    snap = store.snapshot()
    assert snap["cameras"]["a"]["ready_with_prev"] == 0
    assert store.attach_result("a", "r1", 1, 4, "ok", None, []) is False
    assert store.snapshot()["cameras"]["a"]["rejected_attach"] == 2

    # 超 10s 间隔：不冒充紧邻帧（gap 显式 None）
    assert ingest_ok(store, "a", 5, make_frame(5), t_capture_ms=1040.0) \
        is True
    assert ingest_ok(store, "a", 6, make_frame(6),
                     t_capture_ms=1040.0 + MAX_ADJACENT_GAP_MS + 1.0) is True
    drained = [store.take_ready("a") for _ in range(4)]
    by_id = {p.cur.frame_id: p for p in drained}
    assert by_id[6].prev is None and by_id[6].prev_gap_ms is None
    assert by_id[6].nxt is None
    assert by_id[5].prev is None and by_id[5].nxt is None

    # 边界内：gap == MAX_ADJACENT_GAP_MS(10000) 仍算紧邻并记录 gap
    store_b = MaterialsStore()
    assert ingest_ok(store_b, "b", 1, make_frame(1), t_capture_ms=1000.0) \
        is True
    assert ingest_ok(store_b, "b", 2, make_frame(2),
                     t_capture_ms=1000.0 + MAX_ADJACENT_GAP_MS) is True
    q1 = store_b.take_ready("b")
    q2 = store_b.take_ready("b")
    assert q2.prev is not None
    assert q2.prev_gap_ms == MAX_ADJACENT_GAP_MS
    assert q1.nxt_gap_ms == MAX_ADJACENT_GAP_MS

    # gap == 0 与时间倒退（gap ≤ 0）：都不算紧邻
    store_c = MaterialsStore()
    assert ingest(store_c, "c", 1, make_frame(1), t_capture_ms=2000.0) is True
    assert ingest(store_c, "c", 2, make_frame(2), t_capture_ms=2000.0) is True
    assert ingest(store_c, "c", 3, make_frame(3), t_capture_ms=1000.0) is True
    assert store_c.snapshot()["cameras"]["c"]["ready_with_prev"] == 0

    # 完全未知 frame_id → attach_missed（与 rejected_attach 分账）
    assert store_c.attach_result("c", "r1", 1, 999, "ok", None, []) is False
    snap = store_c.snapshot()
    assert snap["cameras"]["c"]["attach_missed"] == 1
    assert snap["cameras"]["c"]["rejected_attach"] == 0

    # M1：同 frame_id 换 run / 换 config 是不同身份，不是重复；同身份才拒
    assert store.ingest("a", "r1", 1, 5, make_frame(5), 5000.0, "capture",
                        [], 96, 48) is True
    assert store.ingest("a", "r9", 1, 5, make_frame(5), 5010.0, "capture",
                        [], 96, 48) is True
    assert store.ingest("a", "r1", 1, 5, make_frame(5), 5020.0, "capture",
                        [], 96, 48) is False
    assert store.attach_result("a", "r1", 1, 5, "ok", None, []) is True
    assert store.attach_result("a", "r9", 1, 5, "ok", None, []) is True
    snap = store.snapshot()
    assert snap["cameras"]["a"]["dup_rejected"] == 1
    assert snap["cameras"]["a"]["ready"] == 2


def test_duplicate_frame_id_same_run_rejected():
    """同 (run, config, frame_id) 在存重复拒收（dup_rejected 进快照）；
    快照其余字段零变化；内部账同步。"""
    store = MaterialsStore()
    assert ingest_ok(store, "a", 10, make_frame(1), t_capture_ms=1000.0) \
        is True
    before = store.snapshot()
    assert ingest(store, "a", 10, make_frame(2), t_capture_ms=1010.0) is False
    after = store.snapshot()
    cam_b, cam_a = before["cameras"]["a"], after["cameras"]["a"]
    assert cam_a["dup_rejected"] == cam_b["dup_rejected"] + 1
    for key in CAMERA_KEYS:
        if key != "dup_rejected":
            assert cam_a[key] == cam_b[key], key
    assert after["total_packages"] == before["total_packages"]
    assert store._rejects["a"]["dup"] == 1
    # 换 run / 换 config 的同 frame_id 不是重复（M1 身份四元）
    assert ingest_ok(store, "a", 20, make_frame(3), t_capture_ms=1020.0,
                     run_id="r2") is True
    assert ingest_ok(store, "a", 10, make_frame(4), t_capture_ms=1030.0,
                     config_version=2) is True
    assert store.snapshot()["cameras"]["a"]["dup_rejected"] == 1


# ---- i. 全局预算跨相机公平逐出（M3/M6） ---------------------------------------

def test_global_budget_cross_camera_fairness():
    """全库 24 帧、三相机各提交 12 帧 → 全库存活字节至多 24 帧（实际恰好
    打满）；跨相机按 created_mono 公平逐出（各丢最旧 5 包，不是 36 帧全留
    也不是单相机饿死其余）；账面字节=实际可达独立图像字节之和（账实双验）。"""
    clock = FakeClock()
    store = MaterialsStore(max_total_bytes=24 * FRAME_BYTES,
                           max_packages_per_camera=64, clock=clock)
    for i in range(1, 13):
        for cam in ("a", "b", "c"):
            assert ingest_ok(store, cam, i, make_frame(i % 256),
                             t_capture_ms=1000.0 + 10 * i) is True
            clock.advance(0.001)   # created_mono 严格递增 → 逐出顺序确定
    snap = store.snapshot()
    assert snap["total_bytes"] <= 24 * FRAME_BYTES
    # 稳态账目（M3 真实字节计费）：全库 24 帧字节恰好打满预算；每相机
    # 7 包 + 1 个孤儿 prev 帧（被逐出所有者的共享帧仍在仓被引用、仍计费）
    # = 各 8 个独立存活帧。包数 21 ≤ 24：孤儿帧占字节不占包槽，逐包逐出
    # 只释放独占引用——账面以字节为准，这正是 M3 要求的真实计费。
    assert snap["total_packages"] == 21
    assert snap["total_bytes"] == 24 * FRAME_BYTES
    for cam in ("a", "b", "c"):
        c = snap["cameras"][cam]
        assert c["ready"] == 7, "跨相机公平：各保留 7 包"
        assert c["dropped_pressure"] == 5
        assert c["global_drops"] == 5, "逐出因全库预算压力发生并如实分账"
        assert c["total_bytes"] == 8 * FRAME_BYTES
        assert c["expired"] == 0 and c["consumed"] == 0
    assert snap["total_bytes"] == sum(
        c["total_bytes"] for c in snap["cameras"].values())
    assert snap["total_bytes"] == reachable_frame_bytes(store), "账实相符"
    ids = [store.take_ready("a").cur.frame_id for _ in range(7)]
    assert ids == [6, 7, 8, 9, 10, 11, 12], "逐出的是各相机最旧包"


# ---- j. 租约记账（M4） ---------------------------------------------------------

def test_lease_slots_bytes_release_and_expiry():
    """租约：每相机槽位超限拒、全库字节超限拒、release 后消费者弃引+gc
    （finalize 真实回收）字节才返还、LEASE_MAX_S 到期只标记不返还（A1：
    字节仍计费直到数组真被回收，clock 注入）、lease_bytes（=
    consumer_alive_bytes 别名）入账且账实相符。"""
    clock = FakeClock()
    store = MaterialsStore(max_leases=2, max_lease_bytes=6 * FRAME_BYTES,
                           max_lease_s=50.0, clock=clock)
    for i in range(1, 5):
        assert ingest_ok(store, "a", i, make_frame(i),
                         t_capture_ms=1000.0 + 10 * i) is True
    p1 = store.take_ready("a")            # 副本 (cur f1, nxt f2) = 2 帧
    p2 = store.take_ready("a")            # 副本 (prev f1, cur f2, nxt f3) = 3 帧
    assert p1 is not None and p2 is not None
    snap = store.snapshot()
    assert snap["cameras"]["a"]["leased"] == 2
    assert snap["cameras"]["a"]["active_leases"] == 2
    assert snap["cameras"]["a"]["released_leases"] == 0
    assert snap["cameras"]["a"]["lease_bytes"] == 5 * FRAME_BYTES
    assert snap["cameras"]["a"]["consumer_alive_bytes"] == 5 * FRAME_BYTES
    assert snap["lease_bytes"] == 5 * FRAME_BYTES
    assert store.take_ready("a") is None, "每相机租约槽满 → take 拒绝"
    assert store._rejects["a"]["lease_slots"] == 1
    assert store.release(p1) is True
    del p1
    gc.collect()                          # C-135 §二：数组真被回收才返还
    p3 = store.take_ready("a")            # 存活字节回落 3 帧，3+3 ≤ 6 可取
    assert p3 is not None
    snap = store.snapshot()
    assert snap["cameras"]["a"]["released_leases"] == 1
    assert snap["cameras"]["a"]["lease_bytes"] == 6 * FRAME_BYTES
    assert snap["consumer_alive_bytes"] == 6 * FRAME_BYTES
    assert snap["lease_bytes"] == sum(c["lease_bytes"]
                                      for c in snap["cameras"].values())

    # 全库租约字节预算：超出 → take 拒；消费者弃引+gc 后可取
    store2 = MaterialsStore(max_leases=99, max_lease_bytes=4 * FRAME_BYTES,
                            clock=clock)
    for i in range(1, 4):
        assert ingest_ok(store2, "a", i, make_frame(i),
                         t_capture_ms=1000.0 + 10 * i) is True
    q1 = store2.take_ready("a")           # 2 帧
    assert q1 is not None
    assert store2.take_ready("a") is None, "全库租约字节超预算 → take 拒绝"
    assert store2._rejects["a"]["lease_bytes"] == 1
    assert store2.release(q1) is True
    del q1
    gc.collect()
    q2 = store2.take_ready("a")
    assert q2 is not None
    assert store2.snapshot()["cameras"]["a"]["lease_bytes"] == 3 * FRAME_BYTES

    # LEASE_MAX_S 到期（A1）：只标记 leased→expired + lease_expired 计数，
    # 字节仍计费（真实存活副本，不冒充图片释放）；消费者弃引+gc 才真实
    # 返还
    store3 = MaterialsStore(clock=clock, max_lease_s=5.0)
    assert ingest_ok(store3, "a", 1, make_frame(1), t_capture_ms=1000.0) \
        is True
    r1 = store3.take_ready("a")
    clock.advance(4.0)
    snap = store3.snapshot()
    assert snap["cameras"]["a"]["leased"] == 1
    assert snap["cameras"]["a"]["lease_expired"] == 0
    clock.advance(2.0)                    # 持有 6s > 5s
    snap = store3.snapshot()
    assert snap["cameras"]["a"]["leased"] == 0
    assert snap["cameras"]["a"]["expired_leases"] == 1
    assert snap["cameras"]["a"]["lease_expired"] == 1
    assert snap["cameras"]["a"]["lease_bytes"] == FRAME_BYTES, \
        "到期只标记：字节仍在账（A1 强引用）"
    assert snap["lease_bytes"] == FRAME_BYTES
    assert store3.release(r1) is True, "过期未释放租约仍可显式 release"
    assert store3.release(r1) is False, "重复 release 如实返回 False"
    del r1
    gc.collect()
    snap = store3.snapshot()
    assert snap["cameras"]["a"]["lease_bytes"] == 0, "release 才真实返还"
    assert snap["cameras"]["a"]["released_leases"] == 1
    assert snap["lease_bytes"] == 0
    assert snap["cameras"]["a"]["lease_expired"] == 0, \
        "已释放的过期租约不再属于“已过期仍计费”"


# ---- k. 消费者慢/不存在：超龄逐出 ----------------------------------------------

def test_consumer_slow_packages_expire_and_budget_falls():
    """不取走：包超 max_age_s 逐出（expired 计数）、字节预算回落到 0；
    未超龄包照常可取（waiting_l1 与 TTL 逐出分账，l1_timeouts 不吃
    expired 计数）。"""
    clock = FakeClock()
    store = MaterialsStore(max_age_s=10.0, clock=clock)
    assert ingest(store, "a", 1, make_frame(1)) is True          # t=1000
    clock.advance(2.0)
    assert ingest(store, "a", 2, make_frame(2)) is True          # t=1002
    snap = store.snapshot()
    assert snap["cameras"]["a"]["oldest_age_s"] == 2.0   # 第 1 包创建于 t=1000
    assert snap["total_bytes"] == 2 * FRAME_BYTES

    clock.advance(11.0)                   # t=1013：两包年龄 13s/11s > 10s
    snap = store.snapshot()
    cam = snap["cameras"]["a"]
    assert cam["expired"] == 2 and cam["ready"] == 0
    assert cam["l1_timeouts"] == 0, "TTL 逐出照旧分账，不计 l1_timeouts"
    assert snap["total_bytes"] == 0 and cam["total_bytes"] == 0
    assert cam["oldest_age_s"] is None
    assert store.take_ready("a") is None

    assert ingest_ok(store, "a", 3, make_frame(3)) is True       # t=1013
    clock.advance(5.0)                    # t=1018：年龄 5s ≤ 10s 保留
    snap = store.snapshot()
    assert snap["cameras"]["a"]["ready"] == 1
    assert snap["cameras"]["a"]["expired"] == 2
    assert snap["cameras"]["a"]["oldest_age_s"] == 5.0
    pkg = store.take_ready("a")
    assert pkg is not None and pkg.cur.frame_id == 3
    assert pkg.cur.frame_bgr[0, 0, 0] == 3
    assert pkg.l1_terminal_reason is None
    assert store.snapshot()["cameras"]["a"]["consumed"] == 1


# ---- l. close 语义（M5） -------------------------------------------------------

def test_close_rejects_and_keeps_leases_honest():
    """close：ingest/attach 恒拒（内部计 closed，与显式清空区分）；在途
    租约如实（leased/lease_bytes 直到 release + 消费者弃引回收）；已取走
    包不受影响；幂等。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    assert ingest_ok(store, "a", 1, make_frame(1), t_capture_ms=1000.0) \
        is True
    assert ingest_ok(store, "a", 2, make_frame(2), t_capture_ms=1010.0) \
        is True
    taken = store.take_ready("a")         # 租约：副本 (cur f1, nxt f2) = 2 帧
    assert taken is not None
    assert store.state == "running"

    store.close()
    assert store.state == "stopped"
    snap = store.snapshot()
    cam = snap["cameras"]["a"]
    assert cam["ready"] == 0 and cam["total_bytes"] == 0
    assert cam["store_bytes"] == 0
    assert cam["consumed"] == 1
    assert cam["leased"] == 1 and cam["lease_bytes"] == 2 * FRAME_BYTES
    assert snap["total_bytes"] == 0 and snap["total_packages"] == 0
    assert snap["lease_bytes"] == 2 * FRAME_BYTES

    # 恒拒：与显式清空区分（clear 后本可照常受理）
    assert ingest(store, "a", 3, make_frame(3), t_capture_ms=1020.0) is False
    assert store.attach_result("a", "r1", 1, 3, "ok", None, []) is False
    assert ingest(store, "a", 4, make_frame(4), t_capture_ms=1030.0) is False
    assert store._rejects["a"]["closed"] == 3

    # 幂等：重复 close 不改变任何可观测状态
    snap2 = store.snapshot()
    store.close()
    assert store.state == "stopped"
    assert store.snapshot() == snap2

    # 已取走包不受影响（隔离副本，消费者仍可读帧）
    assert taken.state == "consumed"
    assert taken.cur.frame_id == 1
    assert int(taken.cur.frame_bgr[0, 0, 0]) == 1

    # 租约如实直到 release；release 只解除任务资格，消费者弃引+gc 后
    # finalize 口径字节才真实返还
    assert store.release(taken) is True
    assert store.release(taken) is False, "重复 release 如实返回 False"
    w = weakref.ref(taken.cur.frame_bgr)
    del taken
    gc.collect()
    assert w() is None
    snap3 = store.snapshot()
    assert snap3["cameras"]["a"]["leased"] == 0
    assert snap3["cameras"]["a"]["released_leases"] == 1
    assert snap3["cameras"]["a"]["lease_bytes"] == 0
    assert snap3["lease_bytes"] == 0


def test_close_lease_expires_honestly():
    """close 后租约仍按 LEASE_MAX_S 到期：只标记 expired（A1 字节仍计费），
    显式 release + 消费者弃引回收才真实返还。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock, max_lease_s=5.0)
    assert ingest_ok(store, "a", 1, make_frame(1), t_capture_ms=1000.0) \
        is True
    pkg = store.take_ready("a")
    assert pkg is not None
    store.close()
    clock.advance(6.0)
    snap = store.snapshot()
    assert snap["cameras"]["a"]["lease_expired"] == 1
    assert snap["cameras"]["a"]["leased"] == 0
    assert snap["cameras"]["a"]["lease_bytes"] == FRAME_BYTES, \
        "到期只标记：字节仍在账（A1 强引用）"
    assert snap["lease_bytes"] == FRAME_BYTES
    assert store.release(pkg) is True, "close 后过期未释放租约仍可 release"
    del pkg
    gc.collect()
    snap = store.snapshot()
    assert snap["cameras"]["a"]["lease_bytes"] == 0, "release 才真实返还"
    assert snap["lease_bytes"] == 0


# ---- m. 高分辨率字节预算 --------------------------------------------------------

def test_high_resolution_byte_budget():
    """单帧超全库预算：拒收且不逐出在存材料；可容大帧触顶时按最旧包
    逐出腾位后收纳；账实相符。"""
    store = MaterialsStore(max_total_bytes=10000,
                           max_packages_per_camera=64)
    small_bytes = FRAME_BYTES
    for fid in range(1, 61):              # 60 × 144 = 8640 ≤ 10000
        assert ingest_ok(store, "a", fid, make_frame(fid % 256)) is True
    snap = store.snapshot()
    assert snap["cameras"]["a"]["dropped_pressure"] == 0
    assert snap["total_bytes"] == 60 * small_bytes

    big_reject = np.zeros((100, 10, 3), dtype=np.float64)   # 24000 > 10000
    assert ingest(store, "a", 61, big_reject) is False
    snap = store.snapshot()
    assert snap["cameras"]["a"]["ready"] == 60
    assert snap["total_bytes"] == 60 * small_bytes
    assert snap["cameras"]["a"]["dropped_pressure"] == 0, \
        "必拒材料不得破坏任何在存材料"
    assert store._rejects["a"]["oversize"] == 1

    big_ok = np.zeros((20, 10, 3), dtype=np.float64)        # 4800 字节
    assert ingest_ok(store, "a", 61, big_ok) is True
    snap = store.snapshot()
    cam = snap["cameras"]["a"]
    assert cam["dropped_pressure"] == 24   # 8640-24×144+4800 = 9984 ≤ 10000
    assert cam["ready"] == 37              # 36 小帧 + 1 大帧
    assert snap["total_bytes"] == 36 * small_bytes + 4800
    assert snap["total_bytes"] == reachable_frame_bytes(store), "账实相符"
    assert store.take_ready("a").cur.frame_id == 25, "逐出的是最旧包"


# ---- n. R1 配合：被拒结果只作诊断 ------------------------------------------------

def test_rejected_result_diagnostic_only():
    """R1：attach accepted=False + reject_reason 只作诊断标注——记录
    last_l1_accepted/last_reject_reason 供状态面闸门，不计 attach_missed；
    迁移为 fallback_terminal(reason="rejected:<原因>")，如实可摘。"""
    store = MaterialsStore()
    assert ingest(store, "a", 1, make_frame(1), t_capture_ms=1000.0) is True
    assert store.attach_result("a", "r1", 1, 1, "ok", None, [dict(DET)],
                               accepted=False,
                               reject_reason="expired") is True
    snap = store.snapshot()
    cam = snap["cameras"]["a"]
    assert cam["last_l1_status"] == "ok"
    assert cam["last_l1_accepted"] is False
    assert cam["last_reject_reason"] == "expired"
    assert cam["attach_missed"] == 0
    assert cam["fallback"] == 1 and cam["ready"] == 1
    pkg = store.take_ready("a")
    assert pkg.last_l1_accepted is False
    assert pkg.last_reject_reason == "expired"
    assert pkg.l1_status == "ok"
    assert pkg.l1_terminal_reason == "rejected:expired"
    # 恢复有效受理：闸门复位
    assert ingest_ok(store, "a", 2, make_frame(2), t_capture_ms=1010.0) \
        is True
    snap = store.snapshot()
    assert snap["cameras"]["a"]["last_l1_accepted"] is True
    assert snap["cameras"]["a"]["last_reject_reason"] is None


# ---- 快照冻结结构（M4 + C-135 新增冻结） -------------------------------------------

def test_snapshot_frozen_structure():
    """快照字段名与合同冻结结构逐字段一致（不多不少）：C-134 18+4 键全
    保留，C-135 新增每相机 5+5 键、全局 5 键。"""
    store = MaterialsStore()
    assert store.snapshot() == {
        "cameras": {}, "total_bytes": 0, "store_bytes": 0, "lease_bytes": 0,
        "consumer_alive_bytes": 0, "active_leases": 0, "released_leases": 0,
        "expired_leases": 0, "total_packages": 0}
    assert ingest_ok(store, "a", 1, make_frame(1)) is True
    snap = store.snapshot()
    assert set(snap) == GLOBAL_KEYS
    cam = snap["cameras"]["a"]
    assert set(cam) == CAMERA_KEYS
    expected = {
        "ready": 1, "waiting_l1": 0, "consumable": 1, "fallback": 0,
        "late_promotions": 0, "l1_timeouts": 0,
        "consumed": 0, "expired": 0, "dropped_pressure": 0,
        "global_drops": 0, "rejected_attach": 0, "attach_missed": 0,
        "dup_rejected": 0, "leased": 0, "active_leases": 0,
        "lease_expired": 0, "expired_leases": 0, "released_leases": 0,
        "lease_bytes": 0, "consumer_alive_bytes": 0,
        "total_bytes": FRAME_BYTES, "store_bytes": FRAME_BYTES,
        "oldest_age_s": cam["oldest_age_s"],
        "ready_with_prev": 0, "ready_with_next": 0, "last_l1_status": "ok",
        "last_l1_accepted": True, "last_reject_reason": None,
        "last_material_reason": None}
    assert cam == expected
    assert snap == {"cameras": {"a": expected},
                    "total_bytes": FRAME_BYTES, "store_bytes": FRAME_BYTES,
                    "lease_bytes": 0, "consumer_alive_bytes": 0,
                    "active_leases": 0, "released_leases": 0,
                    "expired_leases": 0, "total_packages": 1}
    assert isinstance(cam["oldest_age_s"], float) and cam["oldest_age_s"] >= 0.0


# ---- 并发进出账目守恒 -------------------------------------------------------------

def test_concurrent_ingest_take_accounting_consistent():
    """多线程 ingest/take 并发下账目守恒：受理数 = 在存（含 waiting_l1）
    +已消费+逐出，全库字节 = 各相机之和，ready 不超每相机上限，租约账目
    守恒。l1_wait_s=0.0：等待包在任一后续仓调用点兜底为可摘 fallback
    （生产取值由接线决定，store 只提供机制）。"""
    store = MaterialsStore(l1_wait_s=0.0)
    plan = [("a", 0, 50), ("a", 50, 100), ("b", 100, 150), ("b", 150, 200)]
    successes = {cam: [0] for cam, _, _ in plan}
    lock = threading.Lock()
    stop = threading.Event()

    def producer(cam, lo, hi):
        local = 0
        for fid in range(lo, hi):
            if ingest(store, cam, fid, make_frame(fid % 256)):
                local += 1
        with lock:
            successes[cam][0] += local

    def consumer():
        while not stop.is_set():
            for cam in ("a", "b"):
                store.take_ready(cam)
            store.snapshot()

    threads = [threading.Thread(target=producer, args=job) for job in plan]
    threads += [threading.Thread(target=consumer) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads[:4]:
        t.join(timeout=10.0)
        assert not t.is_alive(), "ingest 线程阻塞（契约要求非阻塞）"
    stop.set()
    for t in threads[4:]:
        t.join(timeout=10.0)
        assert not t.is_alive()

    snap = store.snapshot()
    assert set(snap) == GLOBAL_KEYS
    assert snap["total_bytes"] == sum(c["total_bytes"]
                                      for c in snap["cameras"].values())
    assert snap["consumer_alive_bytes"] == sum(
        c["consumer_alive_bytes"] for c in snap["cameras"].values())
    assert snap["lease_bytes"] == snap["consumer_alive_bytes"]
    assert snap["total_packages"] == sum(c["ready"] + c["waiting_l1"]
                                         for c in snap["cameras"].values())
    for cam in ("a", "b"):
        c = snap["cameras"][cam]
        in_ring = c["ready"] + c["waiting_l1"]
        assert in_ring <= store.max_packages_per_camera
        assert c["leased"] <= store.max_leases, "take 不能绕过租约预算"
        assert c["expired"] == 0        # 测试远短于 60s 默认存活
        assert c["consumed"] + in_ring + c["dropped_pressure"] == \
            successes[cam][0], "受理数 = 在存(含等待) + 已消费 + 压力逐出"
        assert c["total_bytes"] == in_ring * FRAME_BYTES
    assert snap["total_bytes"] == reachable_frame_bytes(store), "账实相符"


# ---- C-134 A1：租约强引用——TTL 不冒充图片释放 / 背压 / release 真实资格解除 ----

def test_expired_leases_keep_billing_until_release():
    """A1 核心：store 对租约副本持强引用——消费者持多个过期包不 release：
    TTL 到期只标记（leased→expired、lease_expired 计数），存活字节持续
    计费、绝不因 TTL 反复返还；账面字节=租约记录中实际存活副本字节（白
    盒可达性核验）；release 解除任务资格、消费者弃引+gc 后字节经 finalize
    真实返还（weakref 核验）。"""
    clock = FakeClock()
    store = MaterialsStore(max_leases=8, max_lease_bytes=8 * FRAME_BYTES,
                           max_lease_s=10.0, clock=clock)
    for i in range(1, 7):
        assert ingest_ok(store, "a", i, make_frame(i),
                         t_capture_ms=1000.0 + 10 * i) is True
    p1 = store.take_ready("a")            # 副本 (cur f1, nxt f2) = 2 帧
    p2 = store.take_ready("a")            # 副本 (prev f1, cur f2, nxt f3) = 3 帧
    snap = store.snapshot()
    assert snap["cameras"]["a"]["lease_bytes"] == 5 * FRAME_BYTES
    assert snap["cameras"]["a"]["leased"] == 2
    assert snap["cameras"]["a"]["lease_expired"] == 0

    # 强引用证明：消费者弃掉 p1（无别名、无法再 release），store 租约记录
    # 仍持副本 → 图像真实存活、字节仍计费
    w1 = weakref.ref(p1.cur.frame_bgr)
    del p1
    gc.collect()
    assert w1() is not None, "store 对租约副本持强引用，不随消费者弃引消失"

    clock.advance(11.0)                   # 两个租约同批到期
    snap = store.snapshot()
    cam = snap["cameras"]["a"]
    assert cam["leased"] == 0 and cam["lease_expired"] == 2
    assert cam["lease_bytes"] == 5 * FRAME_BYTES, "到期只标记：字节仍在账"
    assert snap["lease_bytes"] == 5 * FRAME_BYTES
    assert w1() is not None, "到期不移除强引用：过期租约副本仍真实存活"
    assert all(lease["state"] == "expired"
               for lease in store._cams["a"]["leases"]), "状态标记 expired"

    for _ in range(3):                    # 反复跨 TTL：不得反复返还字节
        clock.advance(10.0)
        assert store.snapshot()["cameras"]["a"]["lease_bytes"] == \
            5 * FRAME_BYTES
        assert store.snapshot()["lease_bytes"] == 5 * FRAME_BYTES

    # 账实相符（白盒可达性）：账面 = 租约记录中实际存活副本字节之和
    live = sum(int(f.frame_bgr.nbytes)
               for lease in store._cams["a"]["leases"]
               for f in (lease["pkg"].prev, lease["pkg"].cur,
                         lease["pkg"].nxt) if f is not None)
    assert store.snapshot()["lease_bytes"] == live == 5 * FRAME_BYTES
    assert cam["leased"] + cam["lease_expired"] == \
        len(store._cams["a"]["leases"]), "活跃+过期未释放=在途租约总数"

    # release 消费者仍持有的 p2：任务资格解除；消费者弃引+gc 后 finalize
    # 真实返还（weakref 核验）
    w2 = weakref.ref(p2.cur.frame_bgr)
    assert store.release(p2) is True
    assert store.release(p2) is False, "重复 release 如实返回 False"
    del p2
    gc.collect()
    assert w2() is None, "release + 消费者弃引：副本真实可回收"
    snap = store.snapshot()
    assert snap["cameras"]["a"]["lease_bytes"] == 2 * FRAME_BYTES
    assert snap["cameras"]["a"]["lease_expired"] == 1, "p1 仍未释放、仍计费"
    assert snap["lease_bytes"] == 2 * FRAME_BYTES
    assert w1() is not None


def test_lease_backpressure_saturates_and_recovers():
    """租约预算饱和 → 新 take 拒（背压，诚实有界）；TTL 过期不返还预算、
    过期租约继续占槽与字节；双相机租约槽位分账、全库字节共享；租约压力
    不波及仓内原图预算（两池独立，ingest 照常）；全部 release + 消费者
    弃引回收后吞吐恢复。"""
    clock = FakeClock()
    store = MaterialsStore(max_leases=2, max_lease_bytes=8 * FRAME_BYTES,
                           max_lease_s=5.0, clock=clock)
    for cam in ("a", "b"):
        for i in range(1, 5):
            assert ingest_ok(store, cam, i, make_frame(i),
                             t_capture_ms=1000.0 + 10 * i) is True
    holds = []
    for _ in range(2):                    # cam a：租满槽位（2+3=5 帧）
        pkg = store.take_ready("a")
        assert pkg is not None
        holds.append(pkg)
    assert store.take_ready("a") is None, "每相机租约槽满 → take 拒（背压）"
    assert store._rejects["a"]["lease_slots"] == 1
    b1 = store.take_ready("b")            # 5+2=7 ≤ 8：b 槽位独立可用
    assert b1 is not None
    holds.append(b1)
    assert store.take_ready("b") is None, "全库租约字节预算触顶 → take 拒"
    assert store._rejects["b"]["lease_bytes"] == 1

    # 两池独立：租约饱和不波及仓内原图预算——ingest 照常受理
    assert ingest_ok(store, "a", 5, make_frame(5),
                     t_capture_ms=1000.0 + 10 * 5) is True
    snap = store.snapshot()
    assert snap["cameras"]["a"]["ready"] == 3
    assert snap["cameras"]["a"]["total_bytes"] == 4 * FRAME_BYTES
    assert snap["lease_bytes"] == 7 * FRAME_BYTES

    # TTL 过期不返还预算：过期租约仍占槽与字节，新 take 仍被拒（诚实有界）
    clock.advance(6.0)
    snap = store.snapshot()
    assert snap["cameras"]["a"]["lease_expired"] == 2
    assert snap["cameras"]["b"]["lease_expired"] == 1
    assert snap["cameras"]["a"]["leased"] == 0
    assert snap["cameras"]["b"]["leased"] == 0
    assert snap["lease_bytes"] == 7 * FRAME_BYTES, "过期不返还：预算仍饱和"
    assert store.take_ready("a") is None, "过期租约仍占槽 → 仍拒"
    assert store.take_ready("b") is None, "过期租约仍占字节 → 仍拒"

    # 正常回收（全部 release + 消费者弃引 gc）→ 预算腾空 → 吞吐恢复
    for held_pkg in holds:
        assert store.release(held_pkg) is True
    del held_pkg, pkg, b1                # 局部变量仍持副本：全部弃引
    holds.clear()
    gc.collect()                          # finalize 入队 → 下次调用排空
    snap = store.snapshot()
    assert snap["lease_bytes"] == 0
    assert snap["consumer_alive_bytes"] == 0
    assert snap["cameras"]["a"]["lease_expired"] == 0
    assert snap["cameras"]["b"]["lease_expired"] == 0
    ra, rb = store.take_ready("a"), store.take_ready("b")
    assert ra is not None and rb is not None, "release 后 take 恢复"
    snap = store.snapshot()
    assert snap["cameras"]["a"]["consumed"] == 3
    assert snap["cameras"]["b"]["consumed"] == 2
    assert snap["cameras"]["a"]["leased"] == 1
    assert snap["cameras"]["b"]["leased"] == 1
    assert snap["lease_bytes"] == 6 * FRAME_BYTES, \
        "恢复后的两个租约各持 prev/cur/nxt 三帧副本"


# ---- C-135 §二：真实存活字节（finalize 口径） ---------------------------------

def test_consumer_alive_bytes_true_lifecycle():
    """真实存活字节生命周期：take 后计入 consumer_alive_bytes；release 只
    解除任务资格——finalize 未触发（对象仍存活，weakref 证明）→ 字节仍
    计费；del 消费者引用 + gc → 数组真被回收 → 下次仓调用点字节真实返
    还；released_leases 累计。"""
    store = MaterialsStore()
    assert ingest(store, "a", 1, make_frame(1)) is True
    assert store.attach_result("a", "r1", 1, 1, "ok", None, []) is True
    pkg = store.take_ready("a")
    assert pkg is not None
    snap = store.snapshot()
    assert snap["consumer_alive_bytes"] == FRAME_BYTES, \
        "take 后计入消费者存活字节"
    assert snap["store_bytes"] == 0, "仓内原图字节随摘包回落（两池分列）"
    assert snap["cameras"]["a"]["consumer_alive_bytes"] == FRAME_BYTES
    assert snap["cameras"]["a"]["store_bytes"] == 0
    assert snap["cameras"]["a"]["lease_bytes"] == FRAME_BYTES, "兼容别名"
    assert snap["lease_bytes"] == FRAME_BYTES
    assert snap["cameras"]["a"]["active_leases"] == 1
    assert snap["cameras"]["a"]["leased"] == 1

    # release 只解除任务资格：finalize 未触发（对象仍存活）→ 字节仍计费
    w = weakref.ref(pkg.cur.frame_bgr)
    assert store.release(pkg) is True
    snap = store.snapshot()
    assert snap["consumer_alive_bytes"] == FRAME_BYTES, \
        "release 不等于内存返还"
    assert snap["cameras"]["a"]["released_leases"] == 1
    assert snap["cameras"]["a"]["active_leases"] == 0
    assert snap["cameras"]["a"]["expired_leases"] == 0
    assert w() is not None, "消费者仍持引用：对象真实存活（weakref 证明）"

    # del 消费者引用 + gc → finalize 触发 → 仓调用点字节真实返还
    del pkg
    gc.collect()
    snap = store.snapshot()
    assert snap["consumer_alive_bytes"] == 0, "数组真被回收才减除"
    assert snap["cameras"]["a"]["consumer_alive_bytes"] == 0
    assert w() is None


def test_consumer_alive_bytes_view_keeps_base_billed():
    """视图/别名安全：消费者持副本数组的视图（切片）时，基对象（副本数
    组本身）存活 → 持续计费；视图弃掉 + gc 后基对象真回收才返还。"""
    store = MaterialsStore()
    assert ingest(store, "a", 1, make_frame(1)) is True
    assert store.attach_result("a", "r1", 1, 1, "ok", None, []) is True
    pkg = store.take_ready("a")
    view = pkg.cur.frame_bgr[:]           # 视图/别名：引用同一基对象
    w = weakref.ref(pkg.cur.frame_bgr)
    assert store.release(pkg) is True     # 解除 store 强引用与任务资格
    del pkg
    gc.collect()
    snap = store.snapshot()
    assert snap["consumer_alive_bytes"] == FRAME_BYTES, \
        "视图存活即基对象存活，计费正确"
    assert w() is not None
    del view
    gc.collect()
    snap = store.snapshot()
    assert snap["consumer_alive_bytes"] == 0, "基对象真回收后字节返还"
    assert w() is None


def test_lease_budget_checks_consumer_alive_bytes():
    """租约预算检查对象=consumer_alive_bytes（C-135 §二冻结）：release
    后消费者仍持副本 → 字节仍计费 → take 仍拒（背压诚实）；消费者弃引
    +gc 真实返还后吞吐恢复。"""
    store = MaterialsStore(max_leases=8, max_lease_bytes=3 * FRAME_BYTES)
    for i in (1, 2, 3):
        assert ingest_ok(store, "a", i, make_frame(i),
                         t_capture_ms=1000.0 + 10 * i) is True
    p1 = store.take_ready("a")            # 副本 (cur f1, nxt f2) = 2 帧
    assert p1 is not None
    assert store.take_ready("a") is None, "2+3=5 > 3 帧 → 字节预算拒"
    assert store._rejects["a"]["lease_bytes"] == 1
    # release 只解除任务资格：副本仍被消费者持有 → 字节仍计费 → 仍拒
    assert store.release(p1) is True
    assert store.take_ready("a") is None, "背压诚实：存活字节未返还仍拒"
    assert store._rejects["a"]["lease_bytes"] == 2
    # 消费者真正弃掉引用 + gc → finalize 返还 → 摘取恢复
    del p1
    gc.collect()
    p2 = store.take_ready("a")
    assert p2 is not None, "存活字节真实返还后吞吐恢复"
    snap = store.snapshot()
    assert snap["consumer_alive_bytes"] == 3 * FRAME_BYTES
    assert snap["cameras"]["a"]["released_leases"] == 1
    del p2


def test_alive_bytes_module_boundary_documented():
    """派生边界：模块 docstring 写明第三方自行额外 copy 的内存不归本模块
    保证、生产派生输出归运行面自计；快照 store_bytes 与 consumer_alive_
    bytes 分列；行为核验：第三方 copy 不由本模块计费且自身不受影响。"""
    assert "第三方" in MaterialsStore.__doc__ \
        and "copy" in MaterialsStore.__doc__, \
        "类 docstring 写明第三方额外 copy 边界"
    assert "派生" in MaterialsStore.__doc__, \
        "类 docstring 写明派生输出归运行面自计"
    assert "第三方" in _MATERIALS_DOC and "派生" in _MATERIALS_DOC, \
        "模块 docstring 写明边界（归属清晰）"
    store = MaterialsStore()
    assert ingest(store, "a", 1, make_frame(1)) is True
    assert store.attach_result("a", "r1", 1, 1, "ok", None, []) is True
    pkg = store.take_ready("a")
    third_party = pkg.cur.frame_bgr.copy()   # 消费者自行额外复制
    assert store.release(pkg) is True        # 解除 store 强引用与任务资格
    del pkg
    gc.collect()
    snap = store.snapshot()
    assert snap["consumer_alive_bytes"] == 0, "第三方额外 copy 不由本模块计费"
    assert int(third_party[0, 0, 0]) == 1, "第三方副本自身不受影响"
    assert set(snap) == GLOBAL_KEYS
    cam = snap["cameras"]["a"]
    assert "store_bytes" in cam and "consumer_alive_bytes" in cam
    assert cam["store_bytes"] == 0 and cam["consumer_alive_bytes"] == 0


# ---- C-134 A2/A3：take_ready 复制原子性 ----------------------------------------

def test_take_ready_copy_failure_atomic(monkeypatch):
    """A2/A3：prev/cur/nxt 任一复制失败 → 异常如实原样上抛且不提交消费、
    不创建半租约、不产生幽灵账本：包仍在原位（同一对象）、账本/预算/
    consumed/租约全不变、无拒收计数；异常后 close 无幽灵占用；复制恢复
    后 take 成功（TTL/维护 sweep 为独立维护动作，本用例静态钟下不受扰）。"""
    orig = MaterialsStore._copy_frame_locked
    for target_fid, slot in ((11, "prev"), (12, "cur"), (13, "nxt")):
        clock = FakeClock()
        store = MaterialsStore(clock=clock)
        for i in range(1, 4):
            assert ingest_ok(store, "a", 10 + i, make_frame(i),
                             t_capture_ms=1000.0 * i) is True
        first = store.take_ready("a")     # pkg1 (cur f11, nxt f12) 正常取走
        assert first is not None
        assert store.release(first) is True   # 租约池清空，便于 close 核验
        before = store.snapshot()
        head = store._cams["a"]["ring"][0]
        assert (head.prev.frame_id, head.cur.frame_id,
                head.nxt.frame_id) == (11, 12, 13), \
            "三帧俱全的包：prev/cur/nxt 任一槽位都可注入复制失败"
        rejects_before = dict(store._rejects["a"])
        boom = RuntimeError(f"copy boom {slot}")

        def _boom_copy(frame, _fid=target_fid, _boom=boom):
            if frame is not None and frame.frame_id == _fid:
                raise _boom
            return orig(store, frame)

        monkeypatch.setattr(store, "_copy_frame_locked", _boom_copy)
        with pytest.raises(RuntimeError) as excinfo:
            store.take_ready("a")
        assert excinfo.value is boom, "复制异常如实原样上抛"
        monkeypatch.undo()
        after = store.snapshot()
        assert after == before, "复制失败：快照零变化（包/账本/预算/计数）"
        assert store._cams["a"]["ring"][0] is head, "包仍在 ready 原位"
        assert store._rejects["a"] == rejects_before, "复制失败不是拒收"
        del first                     # 消费者弃引 + gc：finalize 真实返还
        gc.collect()
        store.close()                     # 异常后 close：无幽灵占用
        snap = store.snapshot()
        assert snap["total_bytes"] == 0 and snap["lease_bytes"] == 0
        assert snap["consumer_alive_bytes"] == 0
        assert snap["total_packages"] == 0
        assert store._ledger == {}, "异常后 close 无幽灵账本"

    # 复制恢复后正常路径不受影响：take 成功且计数只走一步
    clock = FakeClock()
    store2 = MaterialsStore(clock=clock)
    for i in range(1, 4):
        assert ingest_ok(store2, "a", 10 + i, make_frame(i),
                         t_capture_ms=1000.0 * i) is True
    before = store2.snapshot()
    monkeypatch.setattr(store2, "_copy_frame_locked",
                        lambda frame: orig(store2, frame))
    pkg = store2.take_ready("a")
    monkeypatch.undo()
    assert pkg is not None and pkg.state == "consumed"
    after = store2.snapshot()
    assert after["cameras"]["a"]["consumed"] == \
        before["cameras"]["a"]["consumed"] + 1
    assert after["cameras"]["a"]["leased"] == 1
    assert after["cameras"]["a"]["lease_bytes"] == 2 * FRAME_BYTES


# ---- C-136 A1：finalize 注册原子性（准备段失败零幽灵） --------------------------

def test_finalize_registration_failure_atomic(monkeypatch):
    """C-136 A1：第 1/2/3 个图像（prev/cur/nxt）的 finalize 注册分别注入
    失败 → 完整回滚、零幽灵：异常如实原样上抛；包仍在 ready 原位（同一
    对象）；consumed/leased/租约槽/字节账快照零变化；已注册回调被
    detach——副本数组成垃圾后 gc 也不产生回收记录（_pending_dead 恒空、
    多个仓调用点反复核验存活字节恒 0）；注册失败不是拒收；异常后 close
    无幽灵账本；注册恢复后 take 成功且账目只走一步。"""
    real_finalize = weakref.finalize
    for target_call in (1, 2, 3):
        clock = FakeClock()
        store = MaterialsStore(clock=clock)
        for i in range(1, 4):
            assert ingest_ok(store, "a", 10 + i, make_frame(i),
                             t_capture_ms=1000.0 * i) is True
        first = store.take_ready("a")     # pkg1 (cur f11, nxt f12) 正常取走
        assert first is not None
        assert store.release(first) is True   # 租约池清空，便于 close 核验
        before = store.snapshot()
        head = store._cams["a"]["ring"][0]
        assert (head.prev.frame_id, head.cur.frame_id,
                head.nxt.frame_id) == (11, 12, 13), \
            "三帧俱全的包：第 1/2/3 个图像的 finalize 注册都可注入失败"
        rejects_before = dict(store._rejects["a"])
        boom = RuntimeError(f"finalize boom #{target_call}")
        calls = {"n": 0}

        def _boom_finalize(obj, callback, *args, _boom=boom,
                           _target=target_call, _calls=calls, **kwargs):
            _calls["n"] += 1
            if _calls["n"] == _target:
                raise _boom
            return real_finalize(obj, callback, *args, **kwargs)

        monkeypatch.setattr(win11_materials.weakref, "finalize",
                            _boom_finalize)
        with pytest.raises(RuntimeError) as excinfo:
            store.take_ready("a")
        assert excinfo.value is boom, "注册异常如实原样上抛"
        assert calls["n"] == target_call, "失败点前恰好尝试注册 target_call 次"
        monkeypatch.undo()
        after = store.snapshot()
        assert after == before, "注册失败：快照零变化（包/账本/预算/计数）"
        assert store._cams["a"]["ring"][0] is head, "包仍在 ready 原位"
        assert store._cams["a"]["leases"] == [], "无半租约（租约槽未动）"
        assert store._rejects["a"] == rejects_before, "注册失败不是拒收"
        gc.collect()
        assert list(store._pending_dead) == [], \
            "已注册回调被 detach：副本成垃圾也不产生幽灵回收记录"
        for _ in range(3):                # 多个仓调用点反复核验：账目恒定
            snap = store.snapshot()
            assert snap["consumer_alive_bytes"] == \
                before["consumer_alive_bytes"], \
                "无幽灵字节：精确回到失败前水平且反复核验不变"
            assert snap["lease_bytes"] == before["lease_bytes"]
        del first                     # 消费者弃引 + gc：finalize 真实返还
        gc.collect()
        store.close()                     # 异常后 close：无幽灵占用
        snap = store.snapshot()
        assert snap["total_bytes"] == 0 and snap["lease_bytes"] == 0
        assert snap["consumer_alive_bytes"] == 0
        assert snap["total_packages"] == 0
        assert store._ledger == {}, "异常后 close 无幽灵账本"

    # 注册恢复后正常路径不受影响：take 成功且账目只走一步
    clock = FakeClock()
    store2 = MaterialsStore(clock=clock)
    for i in range(1, 4):
        assert ingest_ok(store2, "a", 10 + i, make_frame(i),
                         t_capture_ms=1000.0 * i) is True
    before = store2.snapshot()
    pkg = store2.take_ready("a")
    assert pkg is not None and pkg.state == "consumed"
    after = store2.snapshot()
    assert after["cameras"]["a"]["consumed"] == \
        before["cameras"]["a"]["consumed"] + 1
    assert after["cameras"]["a"]["leased"] == 1
    assert after["cameras"]["a"]["lease_bytes"] == 2 * FRAME_BYTES


# ---- C-134 A3：检测结果所有权（逐检测深拷贝） ---------------------------------

def test_detections_deep_copy_two_way_isolation():
    """A3：take 时逐检测深拷贝（新 dict+新 bbox list+逐字段）——改原结构
    （attach 传入、仓内包引用的检测嵌套结构）不影响已取走副本；改副本
    嵌套框不影响原结构与后续取走包；track_id 原样透传不伪造（缺就是缺）。"""
    store = MaterialsStore()
    dets = [{"cls": "person", "conf": 0.9, "bbox": [1.0, 2.0, 3.0, 4.0],
             "track_id": 42},
            {"cls": "car", "conf": 0.5, "bbox": [5.0, 6.0, 7.0, 8.0]}]
    assert ingest(store, "a", 1, make_frame(1)) is True
    assert ingest(store, "a", 2, make_frame(2)) is True
    assert store.attach_result("a", "r1", 1, 1, "ok", None, dets) is True
    assert store.attach_result("a", "r1", 1, 2, "ok", None, dets) is True

    p1 = store.take_ready("a")            # 深拷贝点
    assert p1.detections is not dets
    assert p1.detections[0] is not dets[0]
    assert p1.detections[0]["bbox"] is not dets[0]["bbox"]
    assert p1.detections == dets
    assert p1.detections[0]["track_id"] == 42
    assert "track_id" not in p1.detections[1], "缺失的 track_id 不伪造"

    # 方向一：改原结构（仓内包曾引用的嵌套结构）→ 已取走副本不变
    dets[0]["bbox"][0] = 999.0
    dets[0]["cls"] = "hacked"
    dets.append({"cls": "ghost", "conf": 1.0, "bbox": [9.0, 9.0, 9.0, 9.0]})
    assert p1.detections[0]["bbox"][0] == 1.0
    assert p1.detections[0]["cls"] == "person"
    assert len(p1.detections) == 2

    # 方向二：改副本嵌套框 → 原结构与仓内不变（p2 仍从原结构如实拷贝）
    p1.detections[1]["bbox"][3] = -77.0
    p1.detections[1]["new_key"] = "x"
    assert dets[1]["bbox"][3] == 8.0
    assert "new_key" not in dets[1]
    p2 = store.take_ready("a")
    assert p2.detections == dets, "仓内包未被副本改写；取走时按当前值诚实拷贝"
    assert p2.detections[1]["bbox"][3] == 8.0
    assert p2.detections[0]["bbox"][0] == 999.0
    assert p2.detections is not dets and p2.detections[0] is not dets[0]


def test_change_boxes_nested_deep_copy():
    """A2 框深拷贝：ingest 与 take 都逐字段深拷贝——嵌套 list 字段（poly）
    不与调用方或已取走副本串线。"""
    store = MaterialsStore()
    boxes = [{"x": 1, "y": 2, "w": 3, "h": 4, "poly": [1, 2, 3, 4]}]
    for fid in (1, 2):
        assert ingest_ok(store, "a", fid, make_frame(fid), boxes=boxes) \
            is True
    boxes[0]["poly"].append(99)           # 调用方改嵌套 list
    p1 = store.take_ready("a")
    assert p1.change_boxes[0]["poly"] == [1, 2, 3, 4], "ingest 即逐字段深拷贝"
    assert p1.change_boxes[0]["poly"] is not boxes[0]["poly"]
    p1.change_boxes[0]["poly"].append(77)
    p1.change_boxes[0]["x"] = 42
    p2 = store.take_ready("a")
    assert p2.change_boxes == [{"x": 1, "y": 2, "w": 3, "h": 4,
                                "poly": [1, 2, 3, 4]}], \
        "take 深拷贝：副本改写不回写仓内"


# ---- C-137：窗口生命周期接口（role/area_at_entry 随租约副本透传） ---------------

def test_window_lifecycle_fields_copied_to_lease_copy():
    """C-137 窗口生命周期接口：包携带窗口角色（role）与入窗面积
    （area_at_entry）——由窗口调度器写入，本模块只承载与随 take_ready
    隔离副本透传；未登记包显式 None（不伪造角色）；副本可写且不回写仓
    内（隔离语义与框/检测一致）。"""
    store = MaterialsStore()
    boxes = [{"x": 0, "y": 0, "w": 2, "h": 3}]
    for fid in (1, 2):
        assert ingest_ok(store, "a", fid, make_frame(fid), boxes=boxes,
                         gate_w=8, gate_h=6) is True
    head = store._cams["a"]["ring"][0]    # 白箱：模拟调度器入窗登记
    assert head.role is None and head.area_at_entry is None, \
        "未登记包显式 None（不伪造角色）"
    head.role = "turning"
    head.area_at_entry = 6.0
    p1 = store.take_ready("a")
    p2 = store.take_ready("a")
    assert p1 is not None and p2 is not None
    assert p1.role == "turning" and p1.area_at_entry == 6.0, \
        "登记随租约副本透传（窗口任务组身份可由帧 ID/面积证明）"
    assert p2.role is None and p2.area_at_entry is None, "未登记包不冒充"
    assert p1.change_original_boxes() == [{"x": 0.0, "y": 0.0, "w": 2.0,
                                           "h": 3.0}], \
        "面积可由包内容独立复算（gate=帧尺寸 → 比例 1）"
    p1.role = "latest"                    # 副本可写：消费者侧自由
    assert p1.role == "latest"
