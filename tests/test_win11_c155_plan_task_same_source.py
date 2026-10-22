"""C155-R1 修复验收：事件汇聚任务与选材计划**同源**，只送自身严格绑定帧。

主协调批复（2026-10-16）两项修复的回归：
① real-p7 plan-9 声明 [118,122,130] 而 task-10 实发 [118,120,130]——任务
   构造不得再从本窗三序位二次合并，必须消费计划帧集（同源）；已绑定转折
   帧必须保留；预算可裁**计划帧集的子集**，绝不替换为计划外未绑定帧。
② 最小一期事件汇聚任务只送**自身严格绑定**的帧（bound 且 event/object
   身份齐备）；task-33 帧 437（event/object=null、bound=false）必须阻塞；
   未绑定上下文留独立 unassociated 路径；禁止统一给本窗帧赋 event_id。

红→绿次序：本文件先在旧实现上失败（plan_frames 能力缺失/未绑定帧混入），
修复后全绿。只读生产判据：EventProgress、池、身份/TTL/预算档零改动。
"""

import numpy as np
import pytest

from scam.win11_l2_contract import FrameIdentity, L3BranchSpec
from scam.win11_l3_tasks import tasks_from_package
from scam.win11_event_materials import (FramePlan, SequenceFrame,
                                        TURN_MARKER_CHANGE_START)
from scam.win11_materials import MaterialFrame, MaterialPackage

EVENT_ID = "cam1:run1:event:1"
OBJECT_ID = "cam1:run1:track:1"


def _bgr(mark):
    return np.full((8, 8, 3), mark, dtype=np.uint8)


def _mframe(fid, t, mark):
    return MaterialFrame(fid, _bgr(mark), float(t), "host_receive")


def _pkg(prev_fid, cur_fid, nxt_fid, material_id, t_prev=1000.0,
         t_cur=1017.0, t_nxt=1070.0):
    """手工包（形状同 take_ready 副本；三序位帧 id 与 real-p7 同构）。"""
    pkg = MaterialPackage("cam1", "run1", 7, material_id, 12345.0,
                          _mframe(cur_fid, t_cur, 1), [], 64, 48)
    pkg.prev = _mframe(prev_fid, t_prev, 0)
    pkg.nxt = _mframe(nxt_fid, t_nxt, 2)
    return pkg


def _sf(fid, t, *, bound, window_id=4, material_id=10):
    """事件页/本窗帧（SequenceFrame 载体；bound=自身严格绑定）。"""
    return SequenceFrame(
        camera_id="cam1", run_id="run1", config_version=7,
        window_id=window_id, window_key=("cam1", "run1", 7, window_id),
        material_id=material_id, frame_id=fid, t_capture_ms=float(t),
        timestamp_kind="host_receive", frame_bgr=_bgr(9), width=8, height=8,
        source_width=8, source_height=8, downscaled=False,
        material_reason="change_start", change_boxes=(), change_area=0.0,
        origin="window_material",
        event_id=EVENT_ID if bound else None,
        object_id=OBJECT_ID if bound else None,
        track_id=1 if bound else None, bound=bound,
        observed_mono_ms=None, crop_id=None)


def _branch(pkg):
    """全景分支规格（形状同 runtime `_fallback_branch_spec`）。"""
    ident = FrameIdentity(pkg.camera_id, pkg.run_id, pkg.config_version,
                          pkg.cur.frame_id, pkg.material_id,
                          pkg.cur.t_capture_ms, pkg.cur.timestamp_kind)
    return L3BranchSpec(
        branch_kind="panorama", identity=ident, crop_ref=None,
        cur_present=True, prev_present=pkg.prev is not None,
        next_present=pkg.nxt is not None, cur_gap_ms=0.0,
        prev_gap_ms=None, next_gap_ms=None, cur_detections=(),
        prev_detections=None, next_detections=None, candidates=(),
        crop_id=None, region_only=False, frame_sequence=())


def _build(pkg, plan_frames, **kwargs):
    return tasks_from_package(
        pkg=pkg, branches=(_branch(pkg),), crop_images_by_crop_id={},
        vocabulary_id="c155-test", vocabulary=("walking past",),
        window_id=4, plan_frames=plan_frames,
        plan_event_key=("cam1", "run1", 7, EVENT_ID, OBJECT_ID), **kwargs)


def _ids(task):
    return [fr.identity.frame_id for fr in task.frames]


# ---------------------------------------------------------------------------
# 修复①：计划与任务同源；已绑定转折帧保留；不替换为计划外未绑定帧
# ---------------------------------------------------------------------------

def test_plan9_form_bound_turning_preserved_no_substitution():
    """红例形态：计划 [118(u),122(b转折),130(b跨窗)]，包三序位 118/120/122。

    旧实现实发 [118,120,130]（122 被未绑定的 120 顶替）；修复后任务帧集
    = 计划帧集的自身严格绑定子集 [122,130]——122 保留、120 绝不出现。
    """
    plan = (_sf("118", 1000.0, bound=False),
            _sf("122", 1070.0, bound=True),
            _sf("130", 13530.0, bound=True, window_id=None, material_id=14))
    pkg = _pkg("118", "120", "122", material_id=10)
    tasks = _build(pkg, plan, carried_frames=(), gate_reason="empty")
    assert len(tasks) == 1
    ids = _ids(tasks[0])
    assert ids == ["122", "130"], ids
    assert "120" not in ids, "计划外未绑定帧不得顶替已绑定转折帧"
    assert "118" not in ids
    assert set(ids) <= {"118", "122", "130"}, "任务帧必须 ⊆ 计划帧集（同源）"
    # 已绑定转折帧 122：来源可追溯的转折标记随帧保留（不因序位变化丢失）
    assert tasks[0].frames[0].turning_marker == TURN_MARKER_CHANGE_START


def test_task33_form_unbound_latest_blocked():
    """task-33 形态：计划 [214(b),230(b),437(u latest)]——437 必须阻塞。

    最小一期事件汇聚任务只送自身严格绑定帧；帧 437 event/object=null、
    bound=false，不得以"本窗已标注"免责进入事件任务。
    """
    plan = (_sf("214", 6316.17, bound=True, window_id=6, material_id=49),
            _sf("230", 6880.76, bound=True, window_id=None, material_id=57),
            _sf("437", 23751.76, bound=False, window_id=9, material_id=82))
    pkg = _pkg("434", "436", "438", material_id=82, t_prev=23700.0,
               t_cur=23720.0, t_nxt=23780.0)
    tasks = _build(pkg, plan, carried_frames=(), gate_reason="empty")
    assert len(tasks) == 1
    ids = _ids(tasks[0])
    assert ids == ["214", "230"], ids
    assert "437" not in ids, "未绑定 latest 帧不得进入事件汇聚任务"
    assert "436" not in ids and "434" not in ids


def test_sent_frames_subset_of_plan_same_source_identity():
    """同源不变式：任务帧集 = 计划帧集子集，逐帧身份与计划帧全等。"""
    plan = (_sf("212", 6252.88, bound=False),
            _sf("214", 6316.17, bound=True, material_id=49),
            _sf("230", 6880.76, bound=True, window_id=None, material_id=57))
    pkg = _pkg("210", "212", "214", material_id=49, t_prev=6200.0)
    tasks = _build(pkg, plan, carried_frames=(), gate_reason="empty")
    ids = _ids(tasks[0])
    assert ids == ["214", "230"], ids
    plan_by_id = {f.frame_id: f for f in plan}
    for fr in tasks[0].frames:
        src = plan_by_id[fr.identity.frame_id]
        assert fr.identity.camera_id == src.camera_id
        assert fr.identity.run_id == src.run_id
        assert fr.identity.config_version == src.config_version
        assert fr.t_capture_ms == src.t_capture_ms
        assert fr.timestamp_kind == src.timestamp_kind
    # 时序升序（首个=开始、末个=最新锚点语义承接）
    ts = [fr.t_capture_ms for fr in tasks[0].frames]
    assert ts == sorted(ts)


# ---------------------------------------------------------------------------
# 接线防呆与旧路径逐字节兼容
# ---------------------------------------------------------------------------

def test_plan_frames_and_carried_frames_mutually_exclusive():
    """同源修复后事件任务不得再走"三序位+carried 二次合并"旧路。"""
    plan = (_sf("122", 1070.0, bound=True),)
    pkg = _pkg("118", "120", "122", material_id=10)
    with pytest.raises(ValueError):
        _build(pkg, plan, carried_frames=(_sf("130", 13530.0, bound=True,
                                             window_id=None),))


def test_plan_frames_without_bound_frame_rejected():
    """aggregated 不变式守卫：计划帧集无任何自身严格绑定帧 → 拒绝构造。"""
    plan = (_sf("118", 1000.0, bound=False),
            _sf("120", 1017.0, bound=False))
    pkg = _pkg("118", "120", "122", material_id=10)
    with pytest.raises(ValueError):
        _build(pkg, plan, carried_frames=(), gate_reason="empty")


def test_without_plan_frames_old_path_unchanged():
    """未传 plan_frames（window_only/旧调用方）：三序位+carried 旧路径
    逐字节保留——unassociated 上下文路径不受本修复影响。"""
    pkg = _pkg("118", "120", "122", material_id=10)
    carried = (_sf("130", 13530.0, bound=True, window_id=None,
                   material_id=14),)
    tasks = tasks_from_package(
        pkg=pkg, branches=(_branch(pkg),), crop_images_by_crop_id={},
        vocabulary_id="c155-test", vocabulary=("walking past",),
        window_id=4, carried_frames=carried, gate_reason="empty")
    assert len(tasks) == 1
    assert _ids(tasks[0]) == ["118", "120", "122", "130"]


# ---------------------------------------------------------------------------
# runtime 接线：aggregated → 计划帧源；window_only → 旧路径
# ---------------------------------------------------------------------------

def test_l2runtime_event_task_frames_selector():
    from scam.win11_l2_runtime import L2Runtime
    bound = (_sf("122", 1070.0, bound=True),
             _sf("130", 13530.0, bound=True, window_id=None))
    aggregated = FramePlan(status="aggregated", reason="ok", frames=bound)
    window_only = FramePlan(status="window_only", reason="no_event_binding")
    assert L2Runtime._event_task_frames(aggregated) == bound
    assert L2Runtime._event_task_frames(window_only) is None
    assert L2Runtime._event_task_frames(None) is None
