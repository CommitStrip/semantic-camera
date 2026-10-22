"""win11_windows L2 窗口任务组调度器测试（C-136 §二 + C-137 §1/§3）。

覆盖：acquire 冻结窗不被新素材改写（推理期间 ingest→进待处理窗；占用解
除后待处理窗整窗提升、window_id 单调）/ **A1 三层账目分列**（release 只
还租约不解除逻辑占用：A 相机 L3 阻塞场景——调用方不调 settled 时冻结窗
保持占用、新材料只进 A 待处理窗、B 相机照常服务；settled 解除占用且不
动租约/字节账；窗龄上限 age_cap 解除；mark_branch_done 幂等计数）/
**A2 窗口任务组**（note_omission 同键合并计数、进 omissions 与 snapshot
汇总、release/settled 后仍可登记）/ **A3 确定性转折保留**（keep_start_
turning_latest：面积序列局部极值选取转折、等值游程取首个极值、保留角色
start/turning/latest 可由帧 ID/面积证明、容量不足保角色裁剪并记入合并
记录）/ 待处理满丢最旧（drop_oldest）/ 跨相机公平轮转 / 安静且无新信息
返回 None（零计数）/ 超龄取消（两处复核，cancelled_reason="expired"）/
close 清理待处理窗（在途/冻结不假装释放、close 后 release/settled 仍有
效、幂等）/ snapshot 冻结结构（每相机九字段+全局和+omissions）/ l2_in_
flight>1 同相机多扇冻结窗 / 构造参数校验 / 双相机并发压力（Barrier 同
步起步；window_id 单调唯一且含收尾排空期窗口；一次释放/无幽灵租约/无
幽灵字节）。

全部用注入 FakeClock 推进时间（无长 sleep；并发条件用 Barrier/Event 同
步点构造，不靠 sleep/retry 通过）；禁 subprocess / eval / f-string SQL /
`..` 路径。
"""

import gc
import threading
import time
import weakref

import numpy as np
import pytest

from scam.win11_materials import MaterialsStore
from scam.win11_windows import WindowScheduler, WindowHandle

SCHED_CAMERA_KEYS = {"frozen_windows", "in_flight", "pending", "merged",
                     "dropped", "cancelled", "windows_total", "branch_done",
                     "settled"}
SCHED_GLOBAL_KEYS = {"cameras", "omissions", "omitted_branches",
                     "frozen_windows", "in_flight", "pending", "merged",
                     "dropped", "cancelled", "windows_total", "branch_done",
                     "settled"}
FRAME_BYTES = 6 * 8 * 3          # make_frame 默认形状的 nbytes


# ---- 构造辅助 --------------------------------------------------------------

class FakeClock:
    """可手动推进的单调钟（秒）；store/scheduler 同源注入。"""

    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def make_frame(value=7, w=8, h=6):
    """合成帧：整幅单一数值（数值即身份标记）。"""
    return np.full((h, w, 3), value % 256, dtype=np.uint8)


def feed(store, cam, fid, boxes=None):
    """ingest + attach ok：让包立即进入 consumable（可被调度器摘取）。"""
    assert store.ingest(cam, "r1", 1, fid, make_frame(fid),
                        1000.0 + fid, "capture", boxes or [], 96, 48) is True
    assert store.attach_result(cam, "r1", 1, fid, "ok", None, []) is True


def feed_boxed(store, cam, fid, w, h):
    """ingest + attach ok：单框面积 = w*h（gate=帧尺寸 → 原图比例 1），
    入窗面积可直读断言（A3 面积序列的确定性输入）。"""
    boxes = [{"x": 0, "y": 0, "w": w, "h": h}]
    assert store.ingest(cam, "r1", 1, fid, make_frame(fid),
                        1000.0 + fid, "capture", boxes, 8, 6) is True
    assert store.attach_result(cam, "r1", 1, fid, "ok", None, []) is True


def settle(handle):
    """生产接线语义：租约归还 + 窗内全部分支终态 → 解除逻辑占用。"""
    assert handle.release() is True
    assert handle.mark_window_settled() is True


def cam_snap(sched, cam):
    return sched.snapshot()["cameras"][cam]


# ---- a. 冻结窗与待处理路由（窗口任务组） --------------------------------------

def test_acquire_frozen_window_and_pending_routing():
    """acquire 出窗后冻结：推理期间 ingest 的新素材不改写冻结窗、进入待
    处理窗；占用相机不重复出窗（安静 None）；release 只还租约（逻辑占用
    仍在），settled 解除占用后待处理窗整窗提升，window_id 单调；整窗释
    放后租约账目归位。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sched = WindowScheduler(("a", "b"), store, clock=clock)
    feed(store, "a", 1)
    h1 = sched.acquire()
    assert isinstance(h1, WindowHandle)
    assert h1 is not None and h1.camera_id == "a"
    assert h1.window_id == 1
    assert isinstance(h1.packages, tuple)
    assert [p.cur.frame_id for p in h1.packages] == [1]
    assert all(p.camera_id == "a" for p in h1.packages), "窗口不跨相机混合"
    assert cam_snap(sched, "a") == {
        "frozen_windows": 1, "in_flight": 1, "pending": 0, "merged": 0,
        "dropped": 0, "cancelled": 0, "windows_total": 1, "branch_done": 0,
        "settled": 0}

    # 推理期间新素材：冻结窗内容不变（同一租约包对象），进待处理窗
    feed(store, "a", 2)
    assert h1.packages[0].cur.frame_id == 1, "冻结窗不被新素材改写"
    assert len(h1.packages) == 1
    assert sched.acquire() is None, "占用相机不重复出窗；轮转无新信息安静 None"
    snap = cam_snap(sched, "a")
    assert snap["frozen_windows"] == 1 and snap["in_flight"] == 1
    assert snap["pending"] == 1 and snap["windows_total"] == 1

    # 分支终态登记：幂等计数，不解除占用
    branch = ("a", 1, 1, "panorama", "pan")
    assert h1.mark_branch_done(branch) is True
    assert h1.mark_branch_done(branch) is False, "同键幂等"
    assert cam_snap(sched, "a")["branch_done"] == 1
    assert cam_snap(sched, "a")["frozen_windows"] == 1, "分支终态≠窗口终结"

    # release 只还租约：L2 在途结束，逻辑占用仍在（settled 才解除）
    assert h1.release() is True
    assert h1.release() is False, "重复 release 如实返回 False"
    snap = cam_snap(sched, "a")
    assert snap["in_flight"] == 0 and snap["frozen_windows"] == 1, \
        "release 不解除逻辑占用（C-137：L2 完成≠窗口完成）"
    assert h1.mark_window_settled() is True
    assert h1.mark_window_settled() is False, "重复 settled 幂等"
    snap = cam_snap(sched, "a")
    assert snap["frozen_windows"] == 0 and snap["settled"] == 1

    # 占用解除后：待处理窗整窗提升为冻结窗（分支随窗不散落），id 单调
    h2 = sched.acquire()
    assert h2 is not None and h2.camera_id == "a" and h2.window_id == 2
    assert [p.cur.frame_id for p in h2.packages] == [2]
    settle(h2)
    snap = cam_snap(sched, "a")
    assert snap == {"frozen_windows": 0, "in_flight": 0, "pending": 0,
                    "merged": 0, "dropped": 0, "cancelled": 0,
                    "windows_total": 2, "branch_done": 1, "settled": 2}
    s = store.snapshot()["cameras"]["a"]
    assert s["consumed"] == 2 and s["released_leases"] == 2
    assert s["leased"] == 0, "整窗释放后租约账目归位"


# ---- b. 待处理满：确定性转折合并（C-137 A3） / 丢最旧 --------------------------

def test_pending_full_merge_keeps_earliest_and_latest():
    """待处理满（默认 keep_start_turning_latest）：无面积信息（全 0 面积
    →无转折候选）退化为保留最早+最新、折叠中间并如实释放租约（C-136 语
    义在 C-137 算法下保持）；角色标签 start/latest 如实；max_pending=1
    退化保最新。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sched = WindowScheduler(("a",), store, max_pending=2, clock=clock)
    feed(store, "a", 1)
    h1 = sched.acquire()                  # 冻结窗 (1)，相机进入推理
    assert h1 is not None
    assert h1.packages[0].role == "latest", "单包窗口角色=latest"
    for fid in (2, 3, 4):
        feed(store, "a", fid)
        assert sched.acquire() is None
    assert sched.acquire() is None        # p4 触发合并后仍无新窗
    cam = cam_snap(sched, "a")
    assert cam["merged"] == 1 and cam["pending"] == 2 and cam["dropped"] == 0
    rec = sched._cams["a"]["records"][0]
    assert rec["kind"] == "merged" and rec["reason"] == "pending_full"
    assert rec["packages"] == 1 and rec["t_mono_ms"] == 1000000.0
    assert rec["kept"] == [{"frame_id": 2, "role": "start", "area": 0.0},
                           {"frame_id": 4, "role": "latest", "area": 0.0}]
    assert rec["folded"] == [{"frame_id": 3, "role": None, "area": 0.0}], \
        "折叠明细（非转折候选：角色 None）如实入账"
    settle(h1)
    h2 = sched.acquire()
    assert [(p.cur.frame_id, p.role) for p in h2.packages] == \
        [(2, "start"), (4, "latest")], \
        "无面积序列（全 0）：合并保留最早(2)+最新(4)，中间(3)被折叠"
    settle(h2)
    s = store.snapshot()["cameras"]["a"]
    assert s["consumed"] == 4 and s["released_leases"] == 4, \
        "折叠包租约如实归还（h1+折叠3+h2 两包），无泄漏"
    assert s["leased"] == 0

    # max_pending=1：容量 1 退化保留最新（C-136 冻结语义），最早被折叠
    store1 = MaterialsStore(clock=clock)
    sched1 = WindowScheduler(("a",), store1, max_pending=1, clock=clock)
    feed(store1, "a", 1)
    g1 = sched1.acquire()
    assert g1 is not None
    for fid in (2, 3):
        feed(store1, "a", fid)
        assert sched1.acquire() is None
    cam1 = cam_snap(sched1, "a")
    assert cam1["pending"] == 1 and cam1["merged"] == 1
    settle(g1)
    g2 = sched1.acquire()
    assert [(p.cur.frame_id, p.role) for p in g2.packages] == \
        [(3, "latest")], "max_pending=1：唯一槽位保留最新"
    g2.release()


def test_merge_keeps_start_turning_latest_roles():
    """C-137 A3 核心：面积序列 [小,大,小,更大,小] + 容量 3 → 保留角色
    start/turning/latest，可由帧 ID 与入窗面积证明；候选超容量按 [起点,
    距起点时间最远的转折, 最新] 保角色裁剪，被裁转折记入合并记录（遗漏
    明细）。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sched = WindowScheduler(("a",), store, max_pending=3, clock=clock)
    feed_boxed(store, "a", 1, 1, 1)       # f1 面积 1（小）
    h1 = sched.acquire()
    assert h1 is not None
    feed_boxed(store, "a", 2, 2, 2)       # f2 面积 4（大）
    feed_boxed(store, "a", 3, 1, 1)       # f3 面积 1（小）
    feed_boxed(store, "a", 4, 3, 3)       # f4 面积 9（更大）→ 待处理满
    assert sched.acquire() is None
    feed_boxed(store, "a", 5, 1, 1)       # f5 面积 1（小）→ 触发合并
    assert sched.acquire() is None
    cam = cam_snap(sched, "a")
    assert cam["merged"] == 1 and cam["pending"] == 3
    rec = sched._cams["a"]["records"][0]
    assert rec["kind"] == "merged" and rec["packages"] == 1
    assert rec["branches"] == 1, "遗漏分支=被裁包 change_boxes 数"
    assert rec["kept"] == [
        {"frame_id": 2, "role": "start", "area": 4.0},
        {"frame_id": 4, "role": "turning", "area": 9.0},
        {"frame_id": 5, "role": "latest", "area": 1.0}], \
        "保留明细带角色标签与面积（面积序列 4,1,9,1 的极值=1 与 9）"
    assert rec["folded"] == [
        {"frame_id": 3, "role": "turning", "area": 1.0}], \
        "被裁候选是极值 1（局部极小）；距起点更近的转折被裁剪"
    settle(h1)
    h2 = sched.acquire()
    assert [(p.cur.frame_id, p.role, p.area_at_entry)
            for p in h2.packages] == [
        (2, "start", 4.0), (4, "turning", 9.0), (5, "latest", 1.0)], \
        "角色分配可由帧 ID 与入窗面积证明（[小,大,小,更大,小]+容量3）"
    settle(h2)
    s = store.snapshot()["cameras"]["a"]
    assert s["consumed"] == 5 and s["released_leases"] == 5, \
        "被裁转折租约如实归还（h1+裁3+h2 三包），无泄漏"
    assert s["leased"] == 0


def test_merge_turning_plateau_takes_first_extremum():
    """等值游程（等宽窗口）取首个极值：面积序列 [2,3,3,2] → 转折落在游
    程首个包（面积 3 的第一个），游程第二个包如实折叠（角色 None）。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sched = WindowScheduler(("a",), store, max_pending=3, clock=clock)
    feed_boxed(store, "a", 1, 3, 3)       # 冻结窗占位
    h1 = sched.acquire()
    assert h1 is not None
    feed_boxed(store, "a", 2, 1, 2)       # 面积 2
    feed_boxed(store, "a", 3, 3, 1)       # 面积 3
    feed_boxed(store, "a", 4, 1, 3)       # 面积 3（与 f3 等值游程）
    assert sched.acquire() is None
    feed_boxed(store, "a", 5, 2, 1)       # 面积 2 → 触发合并
    assert sched.acquire() is None
    rec = sched._cams["a"]["records"][0]
    assert rec["kept"] == [
        {"frame_id": 2, "role": "start", "area": 2.0},
        {"frame_id": 3, "role": "turning", "area": 3.0},
        {"frame_id": 5, "role": "latest", "area": 2.0}], \
        "等值游程取首个极值：转折=f3（不是同值的 f4）"
    assert rec["folded"] == [{"frame_id": 4, "role": None, "area": 3.0}]
    settle(h1)
    h2 = sched.acquire()
    assert [(p.cur.frame_id, p.role) for p in h2.packages] == \
        [(2, "start"), (3, "turning"), (5, "latest")]
    settle(h2)


# ---- a. F1：折叠/丢弃/取消**之前**的观察点（C154 车道 Q） ----------------------

class _HarvestSink:
    """观察回调替身：只记录身份（不解引用、不复制、零阻塞）。"""

    def __init__(self, *, fail=False):
        self.entries = []
        self.fail = fail
        self.threads = []
        self.durations = []

    def __call__(self, entries):
        started = time.monotonic()
        self.threads.append(threading.current_thread())
        self.entries.append(tuple(entries))
        if self.fail:
            raise RuntimeError("sink boom")
        self.durations.append(time.monotonic() - started)


def _fids(entries):
    return [pkg.cur.frame_id for pkg in entries]


def _norm_store_snapshot(store):
    """材料仓快照的**确定性**视图：剔除只由 GC 时机决定的存活字节字段
    （`consumer_alive_bytes`/`lease_bytes` 随"消费者是否已弃引用"变化，
    与本参数无关）。其余字段逐字段比较。"""
    snap = store.snapshot()
    return {cam: {k: v for k, v in row.items() if "bytes" not in k}
            for cam, row in snap["cameras"].items()}


def test_f1_folded_material_is_observed_before_release():
    """RED→GREEN（F1 要求 2）：即将被折叠的有对象材料必须在 `store.release`
    **之前**被通知观察；通知发生在窗口调度锁内且只是"记身份"（零复制、
    零 I/O），因此生产者与相机不受影响；被通知的包与 `records` 里被折叠
    的包**逐一对应**（不凭空多报、不遗漏）。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sink = _HarvestSink()
    sched = WindowScheduler(("a",), store, max_pending=2, clock=clock,
                            on_packages_released=sink)
    feed_boxed(store, "a", 1, 5, 5)         # 冻结窗占位（面积 25）
    h1 = sched.acquire()
    assert h1 is not None
    assert sink.entries == [], "开新窗不是释放路径：不得通知"

    feed_boxed(store, "a", 2, 2, 1)         # 待处理 1（面积 2）
    assert sched.acquire() is None
    feed_boxed(store, "a", 3, 3, 1)         # 待处理 2（面积 3）
    assert sched.acquire() is None
    feed_boxed(store, "a", 4, 4, 1)         # 触发合并（面积序列 2,3,4）
    assert sched.acquire() is None
    rec = sched._cams["a"]["records"][0]
    assert rec["kind"] == "merged" and rec["reason"] == "pending_full"
    folded_ids = [row["frame_id"] for row in rec["folded"]]
    assert folded_ids, "本场景必须真实发生折叠（单调面积序列：中间帧被折叠）"
    # 通知批次与折叠明细**逐一对应**（同一次合并、同一个包对象）
    observed = [pkg for group in sink.entries for pkg in group]
    assert [pkg.cur.frame_id for pkg in observed] == folded_ids
    assert observed[0] is not None and observed[0].camera_id == "a"
    assert rec["kept"] == [
        {"frame_id": 2, "role": "start", "area": 2.0},
        {"frame_id": 4, "role": "latest", "area": 4.0}]

    settle(h1)
    h2 = sched.acquire()
    assert sorted(p.cur.frame_id for p in h2.packages) == \
        sorted(row["frame_id"] for row in rec["kept"])
    settle(h2)
    assert store.snapshot()["cameras"]["a"]["leased"] == 0
    # 生产者/相机未被观察拖住：回调在调用者线程同步完成（无新线程）
    assert set(sink.threads) == {threading.current_thread()}


def test_f1_drop_oldest_and_expired_release_paths_observe_first():
    """F1 要求 2：`drop_oldest` 丢弃与超龄取消同样先观察后 `release`；
    观察不改变任何既有账目（dropped/cancelled/leased 与旧行为一致）。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sink = _HarvestSink()
    sched = WindowScheduler(("a",), store, max_pending=1,
                            merge_policy="drop_oldest", clock=clock,
                            on_packages_released=sink)
    feed(store, "a", 1)
    h1 = sched.acquire()
    assert h1 is not None
    feed(store, "a", 2)
    assert sched.acquire() is None
    feed(store, "a", 3)                     # 满 → 丢最旧（f2）
    assert sched.acquire() is None
    assert cam_snap(sched, "a")["dropped"] == 1
    assert [_fids(group) for group in sink.entries] == [[2]], \
        "drop_oldest 丢弃前必须观察（顺序 = 丢弃顺序）"
    settle(h1)

    # 超龄取消：同样先观察后释放
    clock2 = FakeClock()
    store2 = MaterialsStore(clock=clock2)
    sink2 = _HarvestSink()
    sched2 = WindowScheduler(("a",), store2, max_age_s=1.0,
                             max_window_hold_s=60.0, clock=clock2,
                             on_packages_released=sink2)
    feed(store2, "a", 1)
    g1 = sched2.acquire()
    assert g1 is not None
    feed(store2, "a", 2)
    clock2.advance(2.0)                     # f2 在待处理窗前超龄
    assert sched2.acquire() is None
    assert cam_snap(sched2, "a")["cancelled"] == 1
    assert [_fids(group) for group in sink2.entries] == [[2]], \
        "超龄取消前必须观察"
    settle(g1)


def test_f1_observer_failure_never_breaks_window_convergence():
    """RED→GREEN（F1 回归 d）：观察回调抛异常不得中断 `acquire`、不得改
    变窗口账目/收敛，也不得吞掉后续包的观察（可见性由调用方计数承担）。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sink = _HarvestSink(fail=True)
    sched = WindowScheduler(("a",), store, max_pending=2, clock=clock,
                            on_packages_released=sink)
    feed_boxed(store, "a", 1, 5, 5)
    h1 = sched.acquire()
    for fid, (w, h) in ((2, (2, 1)), (3, (3, 1)), (4, (4, 1))):
        feed_boxed(store, "a", fid, w, h)
        assert sched.acquire() is None, "观察失败不得中断窗口收敛"
    cam = cam_snap(sched, "a")
    assert cam["merged"] == 1 and cam["pending"] == 2
    rec = sched._cams["a"]["records"][0]
    folded_ids = [row["frame_id"] for row in rec["folded"]]
    assert folded_ids
    assert [p.cur.frame_id for group in sink.entries
            for p in group] == folded_ids
    settle(h1)
    h2 = sched.acquire()
    assert sorted(p.cur.frame_id for p in h2.packages) == \
        sorted(row["frame_id"] for row in rec["kept"])
    settle(h2)
    assert store.snapshot()["cameras"]["a"]["leased"] == 0


def test_f1_close_observes_pending_before_closing_release():
    """RED→GREEN（F1 回归 f 的调度器侧）：`close()` 清理待处理窗前先观察
    （在 `release` 之前）；关闭后 `acquire` 恒 None、`snapshot` 结构不变。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sink = _HarvestSink()
    sched = WindowScheduler(("a",), store, clock=clock,
                            on_packages_released=sink)
    feed(store, "a", 1)
    h1 = sched.acquire()
    assert h1 is not None
    feed(store, "a", 2)
    feed(store, "a", 3)
    assert sched.acquire() is None
    assert sink.entries == [], "进入待处理窗不是释放路径"
    sched.close()
    assert [_fids(group) for group in sink.entries] == [[3], [2]], \
        "关闭前逐包观察（顺序 = close 的清理顺序：末尾先出）"
    assert cam_snap(sched, "a")["cancelled"] == 2
    assert sched.snapshot()["omissions"] == 0
    assert store.snapshot()["cameras"]["a"]["leased"] == 1, "在途租约不变"
    settle(h1)


def test_f1_no_observer_keeps_existing_behaviour():
    """F1 要求 1：默认**未注入**观察回调 = 既有行为（窗口账目逐字段等价；
    材料仓确定性账目逐字段等价；回调位置零副作用）。"""
    results = []
    sinks = []
    for injected in (False, True):
        clock = FakeClock()
        store = MaterialsStore(clock=clock)
        sink = _HarvestSink() if injected else None
        sched = WindowScheduler(("a",), store, max_pending=2, clock=clock,
                                on_packages_released=sink)
        feed_boxed(store, "a", 1, 5, 5)
        h1 = sched.acquire()
        for fid, (w, h) in ((2, (2, 1)), (3, (3, 1)), (4, (4, 1))):
            feed_boxed(store, "a", fid, w, h)
            assert sched.acquire() is None
        snap_mid = sched.snapshot()
        records_mid = [dict(row) for row in sched._cams["a"]["records"]]
        folded_ids = [row["frame_id"] for row in records_mid[0]["folded"]]
        settle(h1)
        h2 = sched.acquire()
        settle(h2)
        results.append((snap_mid, records_mid, _norm_store_snapshot(store)))
        sinks.append((sink, folded_ids))
    assert results[0] == results[1], \
        "未注入与注入（只读记录）时窗口账目/记录/材料仓账目逐字段等价"
    assert sinks[0][0] is None, "第一次未注入"
    assert sinks[0][1] == sinks[1][1], "折叠集合不因观察而变"
    assert sinks[1][1], "本场景必须真的发生折叠（否则等价性无意义）"
    assert [pkg.cur.frame_id for pkg in sinks[1][0].entries[0]] == sinks[1][1]


def test_f1_constructor_validation_for_observer():
    """新参数构造校验：非法 `on_packages_released` 如实拒绝（不静默吞）。"""
    store = MaterialsStore()
    with pytest.raises(ValueError):
        WindowScheduler(("a",), store, on_packages_released="not-callable")
    sched = WindowScheduler(("a",), store, on_packages_released=None)
    assert sched.on_packages_released is None, "缺省未注入（零行为）"


def test_pending_full_drop_oldest_policy():
    """drop_oldest 策略：满窗丢弃最旧（释放租约，dropped 计数，记录原因
    pending_full 与时间），新包追加；提升后窗内容=(次旧, 最新)。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sched = WindowScheduler(("a",), store, max_pending=2,
                            merge_policy="drop_oldest", clock=clock)
    feed(store, "a", 1)
    h1 = sched.acquire()
    assert h1 is not None
    for fid in (2, 3, 4):
        feed(store, "a", fid)
        assert sched.acquire() is None
    cam = cam_snap(sched, "a")
    assert cam["dropped"] == 1 and cam["pending"] == 2 and cam["merged"] == 0
    rec = sched._cams["a"]["records"][0]
    assert rec["kind"] == "dropped" and rec["reason"] == "pending_full"
    assert rec["packages"] == 1 and rec["t_mono_ms"] == 1000000.0
    settle(h1)
    h2 = sched.acquire()
    assert [p.cur.frame_id for p in h2.packages] == [3, 4], \
        "丢最旧：2 被丢弃，保留 3+4"
    settle(h2)
    s = store.snapshot()["cameras"]["a"]
    assert s["released_leases"] == 4 and s["leased"] == 0, \
        "被丢弃包租约如实归还（h1+丢2+h2 两包）"


# ---- c. A1：逻辑占用与三层账目 -------------------------------------------------

def test_release_keeps_logical_occupancy_until_settled():
    """A 相机 L3 阻塞场景模拟（调用方不调 settled）：release 只还租约，
    冻结窗保持逻辑占用（frozen_windows≥1）；新材料只进 A 待处理窗；B 相
    机照常获得服务；settled 后占用解除、待处理窗整窗提升。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sched = WindowScheduler(("a", "b"), store, clock=clock)
    feed(store, "a", 1)
    h1 = sched.acquire()
    assert h1 is not None
    h1.release()                          # L2 完成（租约归还）；L3 异步执行中
    snap = cam_snap(sched, "a")
    assert snap["frozen_windows"] == 1 and snap["in_flight"] == 0
    s = store.snapshot()["cameras"]["a"]
    assert s["leased"] == 0 and s["released_leases"] == 1, \
        "租约层已解除（不等 L3）"

    # A 占用中：新材料只进 A 待处理窗，A 不出新窗
    feed(store, "a", 2)
    feed(store, "a", 3)
    assert sched.acquire() is None, "A 逻辑冻结：不出新窗"
    snap = cam_snap(sched, "a")
    assert snap["frozen_windows"] == 1 and snap["pending"] == 2

    # B 相机照常获得服务（忙相机不长期霸占轮转）
    feed(store, "b", 1)
    hb = sched.acquire()
    assert hb is not None and hb.camera_id == "b", "B 相机照常出窗"
    assert [p.cur.frame_id for p in hb.packages] == [1]
    settle(hb)

    # 分支终态登记与占用解除
    assert h1.mark_branch_done(("w", 1, 1, "relation", "crop-9")) is True
    assert cam_snap(sched, "a")["branch_done"] == 1
    before = store.snapshot()
    assert h1.mark_window_settled() is True
    snap = cam_snap(sched, "a")
    assert snap["frozen_windows"] == 0 and snap["settled"] == 1
    assert store.snapshot() == before, \
        "settled 只解除逻辑占用：store 租约/字节账零变化"

    # 占用解除后：A 待处理窗整窗提升（分支随窗不散落）
    h2 = sched.acquire()
    assert h2 is not None and h2.camera_id == "a" and h2.window_id == 3
    assert [p.cur.frame_id for p in h2.packages] == [2, 3]
    settle(h2)
    snap = cam_snap(sched, "a")
    assert snap["frozen_windows"] == 0 and snap["windows_total"] == 2, \
        "A 相机两扇窗（阻塞窗 + 提升窗）"
    assert sched.snapshot()["windows_total"] == 3, "全局含 B 相机一扇窗"
    assert snap["settled"] == 2
    s = store.snapshot()["cameras"]["a"]
    assert s["leased"] == 0 and s["released_leases"] == s["consumed"] == 3, \
        "A 三包（阻塞窗 1 + 提升窗 2）全部如实归还一次"


def test_three_layer_accounting_independent():
    """三层账目独立（C-137 §3）：settled 只解除逻辑占用（租约/字节不
    动）；release 只解除租约（占用/字节不动）；字节跟随真实数组回收
    （finalize 口径），任一层解除不回弹其他层。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sched = WindowScheduler(("a",), store, clock=clock)
    feed(store, "a", 1)
    h1 = sched.acquire()
    pkg1 = h1.packages[0]

    # 层1：只 settled（不 release）——占用解除，租约与字节原样
    assert h1.mark_window_settled() is True
    assert cam_snap(sched, "a")["frozen_windows"] == 0
    s = store.snapshot()["cameras"]["a"]
    assert s["leased"] == 1 and s["released_leases"] == 0
    assert s["lease_bytes"] == FRAME_BYTES, "字节仍计费（层3 未动）"

    # 占用已解除即可再服务（租约未释放不妨碍下一窗）：层间独立
    feed(store, "a", 2)
    h2 = sched.acquire()
    assert h2 is not None, "settled 后占用解除：相机可再出窗"
    settle(h2)

    # 层2：release 解除租约；层3 字节仍计费（消费者仍持引用）
    assert h1.release() is True
    s = store.snapshot()["cameras"]["a"]
    assert s["leased"] == 0 and s["released_leases"] == 2
    assert s["lease_bytes"] == 2 * FRAME_BYTES, \
        "release 不等于内存返还（pkg1 与 h2 副本仍存活）"
    assert cam_snap(sched, "a")["frozen_windows"] == 0, "层1 不回弹"

    # 层3：数组真被回收才返还（weakref/finalize 口径）
    w1 = weakref.ref(pkg1.cur.frame_bgr)
    del h1, pkg1                        # handle 的 packages 元组也是引用
    gc.collect()
    s = store.snapshot()["cameras"]["a"]
    assert s["lease_bytes"] == FRAME_BYTES, "h2 副本仍被引用：仍计费"
    assert w1() is None, "pkg1 弃引后真实回收"
    del h2
    gc.collect()
    assert store.snapshot()["cameras"]["a"]["lease_bytes"] == 0
    assert cam_snap(sched, "a")["settled"] == 2, "层1 计数不受层2/3 影响"


def test_window_hold_age_cap_releases_occupancy():
    """窗龄上限（可覆盖）：逻辑占用超 max_window_hold_s（单调钟，严格大
    于）→ sweep 解除占用（计 settled，记录原因 age_cap）；租约与字节账
    不动（不假装释放）；相机恢复服务。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock, max_age_s=60.0)
    sched = WindowScheduler(("a",), store, max_window_hold_s=5.0, clock=clock)
    feed(store, "a", 1)
    h1 = sched.acquire()
    assert h1 is not None
    h1.release()                          # 租约归还；逻辑占用仍在
    clock.advance(5.0)                    # 恰等于上限：严格大于不解除
    assert sched.acquire() is None, "占用中且未超窗龄：不出新窗"
    snap = cam_snap(sched, "a")
    assert snap["frozen_windows"] == 1 and snap["settled"] == 0

    clock.advance(0.5)                    # 5.5s > 5.0s
    assert sched.acquire() is None, "sweep 解除占用后无新素材：安静 None"
    snap = cam_snap(sched, "a")
    assert snap["frozen_windows"] == 0 and snap["settled"] == 1
    rec = sched._cams["a"]["records"][-1]
    assert rec["kind"] == "settled" and rec["reason"] == "age_cap"
    assert rec["window_id"] == 1 and rec["t_mono_ms"] == 1005500.0
    s = store.snapshot()["cameras"]["a"]
    assert s["leased"] == 0 and s["released_leases"] == 1, \
        "窗龄解除不动租约层（调用方租约已显式归还）"

    # 被 sweep 先行解除的窗口：显式 settled 幂等返回 False，不重复计数
    assert h1.mark_window_settled() is False
    assert cam_snap(sched, "a")["settled"] == 1

    feed(store, "a", 2)
    h2 = sched.acquire()
    assert h2 is not None and h2.window_id == 2, "相机恢复服务"
    settle(h2)


# ---- d. A2：窗口任务组缺失登记 --------------------------------------------------

def test_note_omission_records_and_snapshot():
    """note_omission：同 (branch_key, reason) 合并累加 count；进
    handle.omissions、snapshot 汇总（omissions=调用次数、omitted_branches
    =缺失分支累计）与相机诊断记录；release/settled 后仍可登记（L3 迟到
    发现照常入账）；count < 1 如实拒绝。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sched = WindowScheduler(("a",), store, clock=clock)
    feed(store, "a", 1)
    h1 = sched.acquire()
    assert h1 is not None
    k1 = ("w", 1, 1, "relation", "crop-9")
    k2 = ("w", 1, 1, "panorama", "pan")
    assert h1.note_omission(k1, "budget_truncated", 2) == 2
    assert h1.note_omission(k1, "budget_truncated", 3) == 5, "同键同因合并"
    assert h1.note_omission(k2, "budget_truncated", 1) == 1
    assert h1.omissions == (
        {"branch_key": k1, "reason": "budget_truncated", "count": 5},
        {"branch_key": k2, "reason": "budget_truncated", "count": 1})
    snap = sched.snapshot()
    assert snap["omissions"] == 3 and snap["omitted_branches"] == 6
    omissions = [r for r in sched._cams["a"]["records"]
                 if r["kind"] == "omission"]
    assert len(omissions) == 3
    assert omissions[0]["branch_key"] == k1
    assert omissions[0]["branches"] == 2

    settle(h1)
    assert h1.note_omission(k1, "budget_truncated", 1) == 6, \
        "release/settled 后仍可登记（L3 迟到发现）"
    snap = sched.snapshot()
    assert snap["omissions"] == 4 and snap["omitted_branches"] == 7

    with pytest.raises(ValueError):
        h1.note_omission(k1, "budget_truncated", 0)
    with pytest.raises(ValueError):
        h1.note_omission(k1, "budget_truncated", -1)


# ---- e. 跨相机公平轮转 -------------------------------------------------------

def test_round_robin_fairness_across_cameras():
    """双相机都有素材时交替出窗（a,b,a,b）；占用相机不长期霸占（a 逻辑
    冻结时 b 的新素材照常出窗）；双方占用时各自进待处理窗、acquire 安
    静；窗口不跨相机混合；window_id 全局单调唯一。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sched = WindowScheduler(("a", "b"), store, clock=clock)
    fid = 0
    for expected in ("a", "b", "a", "b"):
        fid += 1
        feed(store, "a", fid)
        feed(store, "b", fid)
        h = sched.acquire()
        assert h is not None and h.camera_id == expected, "跨相机公平轮转"
        assert all(p.camera_id == h.camera_id for p in h.packages), \
            "窗口不跨相机混合"
        settle(h)

    # 占用相机不长期霸占：a 逻辑冻结（release 未 settled），b 照常出窗
    feed(store, "a", 10)
    ha = sched.acquire()
    assert ha is not None and ha.camera_id == "a"
    ha.release()                          # 只还租约：a 保持逻辑占用
    assert cam_snap(sched, "a")["frozen_windows"] == 1
    feed(store, "b", 10)
    hb = sched.acquire()
    assert hb is not None and hb.camera_id == "b", "占用相机不长期霸占"

    # 双方占用：新素材各自进待处理窗，acquire 安静返回 None
    feed(store, "a", 11)
    feed(store, "b", 11)
    assert sched.acquire() is None
    snap = sched.snapshot()
    assert snap["cameras"]["a"]["pending"] == 1
    assert snap["cameras"]["b"]["pending"] == 1
    assert snap["frozen_windows"] == 2 and snap["in_flight"] == 1
    assert snap["windows_total"] == sum(
        v["windows_total"] for v in snap["cameras"].values())

    assert ha.mark_window_settled() is True
    settle(hb)
    # 释放后按轮转整窗提升：先 a 后 b（上次服务 b，从其后轮转）
    h_a = sched.acquire()
    assert h_a is not None and h_a.camera_id == "a"
    h_b = sched.acquire()
    assert h_b is not None and h_b.camera_id == "b"
    assert [p.cur.frame_id for p in h_a.packages] == [11]
    assert [p.cur.frame_id for p in h_b.packages] == [11]
    settle(h_a)
    settle(h_b)
    snap = sched.snapshot()
    assert snap["windows_total"] == 8, "4 轮交替 + 双忙期 2 窗 + 提升待处理 2 窗"
    assert snap["frozen_windows"] == 0 and snap["in_flight"] == 0
    assert snap["pending"] == 0


# ---- f. 安静且无新信息 -------------------------------------------------------

def test_quiet_returns_none_no_actions():
    """空仓/仅 waiting_l1（L2 不可见）→ acquire 返回 None；安静轮询零计
    数（不把轮询当理解）；close 后恒 None。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sched = WindowScheduler(("a", "b"), store, clock=clock)
    assert sched.acquire() is None, "空仓安静：None"
    assert store.ingest("a", "r1", 1, 1, make_frame(1), 1000.0, "capture",
                        [], 96, 48) is True          # 未 attach：waiting_l1
    assert sched.acquire() is None, "waiting_l1 对调度器不可见（无新信息）"
    before = sched.snapshot()
    assert sched.acquire() is None
    assert sched.snapshot() == before, "安静轮询零计数（不产生理解动作）"
    sched.close()
    assert sched.acquire() is None, "close 后 acquire 恒 None"


# ---- g. 超龄取消（A3 时效） ---------------------------------------------------

def test_expired_packages_cancelled_with_reason():
    """超龄复核两处生效（max_age_s 可覆盖，单调钟严格大于；窗龄上限独立
    覆盖避免干扰）：收割入口已超龄→取消不入待处理窗；待处理窗排队期间
    老化→出队（提升）时取消不开窗。cancelled 计数、原因 expired 带时间、
    租约如实释放。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock, max_age_s=60.0)
    sched = WindowScheduler(("a",), store, max_age_s=1.0,
                            max_window_hold_s=60.0, clock=clock)

    # 路径一：收割入口复核（包入待处理窗前已超龄）
    feed(store, "a", 1)
    h1 = sched.acquire()
    assert h1 is not None
    feed(store, "a", 2)
    clock.advance(2.0)                    # p2 年龄 2.0s > 1.0s（仓 60s 未逐）
    assert sched.acquire() is None        # 收割：超龄 → 取消
    snap = cam_snap(sched, "a")
    assert snap["cancelled"] == 1 and snap["pending"] == 0
    rec = sched._cams["a"]["records"][0]
    assert rec["kind"] == "cancelled" and rec["reason"] == "expired"
    assert rec["t_mono_ms"] == 1002000.0
    assert store.snapshot()["cameras"]["a"]["released_leases"] == 1, \
        "超龄包租约如实释放"
    assert h1.release() is True
    assert h1.mark_window_settled() is True
    assert sched.acquire() is None

    # 路径二：出队（提升）复核（新鲜入窗、排队期间老化）
    feed(store, "a", 3)
    h2 = sched.acquire()
    assert h2 is not None
    feed(store, "a", 4)                   # 新鲜：正常进入待处理窗
    assert sched.acquire() is None
    assert cam_snap(sched, "a")["pending"] == 1
    clock.advance(2.0)                    # 排队期间老化：4 年龄 2.0s > 1.0s
    assert h2.release() is True
    assert h2.mark_window_settled() is True
    assert sched.acquire() is None, "出队复核：超龄待处理包取消，不开窗"
    snap = cam_snap(sched, "a")
    assert snap["cancelled"] == 2 and snap["windows_total"] == 2
    assert store.snapshot()["cameras"]["a"]["released_leases"] == 4, \
        "p2 取消 + h1 整窗 + h2 整窗 + p4 取消，租约账目守恒"


# ---- h. close 语义（A3 取消） --------------------------------------------------

def test_close_cancels_pending_and_releases_after_close():
    """close：清理全部待处理窗（逐包 release + cancelled 计数，原因
    closing）；在途/逻辑冻结窗如实显示、不假装释放；close 后
    handle.release/mark_window_settled 仍有效（租约如实归还、占用如实解
    除）；此后 acquire 恒 None；幂等。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sched = WindowScheduler(("a", "b"), store, clock=clock)
    feed(store, "a", 1)
    h1 = sched.acquire()
    assert h1 is not None
    feed(store, "a", 2)
    feed(store, "a", 3)
    assert sched.acquire() is None        # 全部进待处理窗
    assert cam_snap(sched, "a")["pending"] == 2

    sched.close()
    snap = cam_snap(sched, "a")
    assert snap["pending"] == 0
    assert snap["cancelled"] == 2, "close 清理待处理窗计数"
    assert snap["in_flight"] == 1 and snap["frozen_windows"] == 1, \
        "在途与逻辑冻结窗如实显示（不假装释放）"
    rec = sched._cams["a"]["records"][0]
    assert rec["kind"] == "cancelled" and rec["reason"] == "closing"
    assert store.snapshot()["cameras"]["a"]["leased"] == 1, \
        "在途租约仍由调用方持有"
    assert sched.acquire() is None, "close 后 acquire 恒 None"

    # 在途 handle 在 close 后仍可如实释放与解除占用
    assert h1.release() is True
    assert h1.mark_window_settled() is True
    snap = cam_snap(sched, "a")
    assert snap["in_flight"] == 0 and snap["frozen_windows"] == 0
    s = store.snapshot()["cameras"]["a"]
    assert s["leased"] == 0 and s["released_leases"] == 3, \
        "close 后 release：在途租约如实归还（h1 + 关闭取消两包）"

    # 幂等：重复 close 零变化
    after = sched.snapshot()
    sched.close()
    assert sched.snapshot() == after


# ---- i. snapshot 冻结结构 -----------------------------------------------------

def test_snapshot_frozen_structure():
    """快照字段名与合同冻结结构逐字段一致（不多不少）：每相机九字段，
    全局为各相机之和 + omissions/omitted_branches；max_age_s 缺省跟随
    store.max_age_s、max_window_hold_s 缺省跟随 max_age_s（同源）；
    poll_timeout_s 为轮询节奏提示（本模块不阻塞）。"""
    store = MaterialsStore()
    sched = WindowScheduler(("a", "b"), store)
    snap = sched.snapshot()
    assert snap == {"cameras": {cam: {"frozen_windows": 0, "in_flight": 0,
                                      "pending": 0, "merged": 0,
                                      "dropped": 0, "cancelled": 0,
                                      "windows_total": 0, "branch_done": 0,
                                      "settled": 0}
                                for cam in ("a", "b")},
                    "omissions": 0, "omitted_branches": 0,
                    "frozen_windows": 0, "in_flight": 0, "pending": 0,
                    "merged": 0, "dropped": 0, "cancelled": 0,
                    "windows_total": 0, "branch_done": 0, "settled": 0}
    assert set(snap) == SCHED_GLOBAL_KEYS
    assert all(set(v) == SCHED_CAMERA_KEYS
               for v in snap["cameras"].values())
    assert sched.max_age_s == store.max_age_s, "max_age_s 缺省跟随 store"
    assert sched.max_window_hold_s == sched.max_age_s, \
        "窗龄上限缺省跟随 max_age_s（同源口径）"
    assert sched.poll_timeout_s == 0.2
    assert sched.l2_in_flight == 1 and sched.max_pending == 2


# ---- j. l2_in_flight>1：同相机多扇冻结窗 -------------------------------------

def test_l2_in_flight_allows_multiple_windows_per_camera():
    """l2_in_flight=2：同相机可同时持有两扇冻结窗（各自独立
    release/settled）；第三次 acquire 安静 None；release 不解除占用、
    settled 逐窗解除；占用计数如实。"""
    clock = FakeClock()
    store = MaterialsStore(clock=clock)
    sched = WindowScheduler(("a",), store, l2_in_flight=2, clock=clock)
    feed(store, "a", 1)
    h1 = sched.acquire()
    assert h1 is not None
    feed(store, "a", 2)
    h2 = sched.acquire()
    assert h2 is not None and h2.window_id == 2, "占用<上限：同相机再出窗"
    assert h1.packages[0] is not h2.packages[0]
    snap = cam_snap(sched, "a")
    assert snap["frozen_windows"] == 2 and snap["in_flight"] == 2
    assert sched.acquire() is None, "占用满：安静 None"
    h1.release()
    h2.release()
    snap = cam_snap(sched, "a")
    assert snap["in_flight"] == 0 and snap["frozen_windows"] == 2, \
        "release 只结束 L2 在途：逻辑占用保持"
    h1.mark_window_settled()
    assert sched.acquire() is None, "占用 1 < 上限 2，但无新素材：安静 None"
    feed(store, "a", 3)
    h3 = sched.acquire()
    assert h3 is not None and h3.window_id == 3, "占用<上限：可再出窗"
    settle(h3)
    h2.mark_window_settled()
    snap = cam_snap(sched, "a")
    assert snap["frozen_windows"] == 0 and snap["settled"] == 3


# ---- k. 构造参数校验 -----------------------------------------------------------

def test_constructor_validation():
    """非法构造参数如实拒绝（ValueError）：l2_in_flight/max_pending < 1、
    未知 merge_policy、max_window_hold_s ≤ 0。"""
    store = MaterialsStore()
    with pytest.raises(ValueError):
        WindowScheduler(("a",), store, l2_in_flight=0)
    with pytest.raises(ValueError):
        WindowScheduler(("a",), store, max_pending=0)
    with pytest.raises(ValueError):
        WindowScheduler(("a",), store, merge_policy="newest_only")
    with pytest.raises(ValueError):
        WindowScheduler(("a",), store, max_window_hold_s=0)
    with pytest.raises(ValueError):
        WindowScheduler(("a",), store, max_window_hold_s=-1.0)


# ---- l. 双相机并发压力（Barrier 同步点） -----------------------------------------

def test_two_camera_concurrent_stress():
    """双相机生产/多消费者并发（Barrier 同步起步，并发条件由同步点构造，
    不靠 sleep/retry）：window_id 全局单调唯一且与开窗总数一致——含收尾
    排空（提升/关闭）期新增窗口；每个摘走的包恰好归还一次（一次释放/
    无幽灵租约）；排空+settled 后逻辑占用清零；消费侧副本全部弃引回收
    后 finalize 字节账清零（无幽灵字节）。"""
    store = MaterialsStore(l1_wait_s=0.02, max_packages_per_camera=16)
    sched = WindowScheduler(("a", "b"), store, max_pending=2,
                            poll_timeout_s=0.001)
    lock = threading.Lock()
    stop = threading.Event()
    start = threading.Barrier(5)          # 2 生产者 + 3 消费者同步起步
    window_ids = set()
    errors = []
    total = 200

    def producer(cam):
        try:
            start.wait(timeout=30)
            for fid in range(total):
                if store.ingest(cam, "r1", 1, fid, make_frame(fid % 256),
                                1000.0 + fid, "capture", [], 96, 48):
                    # 压力下包可能在 attach 前被逐出（attach 落空属正常
                    # 竞态，未 attach 包经 l1_wait 兜底同样可摘）
                    store.attach_result(cam, "r1", 1, fid, "ok", None, [])
        except Exception as exc:          # 线程内异常汇聚到主线程断言
            errors.append(exc)

    def consumer():
        try:
            start.wait(timeout=30)
            while not stop.is_set():
                handle = sched.acquire()
                if handle is None:
                    if stop.wait(sched.poll_timeout_s):
                        break             # Event 同步收尾，不空转
                    continue
                with lock:
                    assert handle.window_id not in window_ids, "id 重复"
                    window_ids.add(handle.window_id)
                snap = sched.snapshot()
                assert snap["cameras"][handle.camera_id][
                    "frozen_windows"] >= 1, "持窗期间逻辑占用如实"
                assert handle.release() is True
                assert handle.mark_window_settled() is True
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=producer, args=(cam,))
               for cam in ("a", "b")]
    threads += [threading.Thread(target=consumer) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads[:2]:
        t.join(timeout=30.0)
        assert not t.is_alive(), "ingest 线程阻塞（合同要求非阻塞）"
    stop.set()
    for t in threads[2:]:
        t.join(timeout=30.0)
        assert not t.is_alive(), "consumer 线程阻塞"
    assert not errors, errors

    # 收尾排空：剩余待处理窗整窗交出并释放/解除占用；新增窗口纳入 ID 集合
    drained = []
    while True:
        handle = sched.acquire()
        if handle is None:
            break
        drained.append(handle)
        with lock:
            assert handle.window_id not in window_ids, "排空期 id 重复"
            window_ids.add(handle.window_id)
        assert handle.release() is True
        assert handle.mark_window_settled() is True
    sched.close()

    snap = sched.snapshot()
    assert all(v["frozen_windows"] == 0 for v in snap["cameras"].values()), \
        "排空+settled 后逻辑占用清零"
    assert all(v["in_flight"] == 0 for v in snap["cameras"].values())
    assert all(v["pending"] == 0 for v in snap["cameras"].values())
    total_windows = snap["windows_total"]
    assert window_ids == set(range(1, total_windows + 1)), \
        "window_id 单调唯一，与开窗总数一致（含排空期窗口）"
    assert total_windows == sum(v["windows_total"]
                                for v in snap["cameras"].values())
    for cam in ("a", "b"):
        s = store.snapshot()["cameras"][cam]
        assert s["leased"] == 0, "全部租约经调度器归还"
        assert s["released_leases"] == s["consumed"], \
            "调度器摘走的每个包恰好归还一次（合并/丢弃/取消/整窗释放守恒）"
    assert not errors, errors

    # 无幽灵字节：消费侧副本（含排空清单）全部弃引回收后 finalize 清零
    del drained, handle
    gc.collect()
    assert store.snapshot()["consumer_alive_bytes"] == 0
