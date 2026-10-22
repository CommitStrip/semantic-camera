"""C-137/C-138 tests: scam.win11_l3_tasks —— 材料→L3 任务、L3Output→可
保存结构统一转换（docs/context/C137-接口冻结.md §2；C-138 §1/D1/D2/D4）。

覆盖：
- C1 tasks_from_package：全景三序位内容/顺序/frame_id/时间逐项绑定；缺
  prev → 序位 0 显式占位不塌缩；局部关系/变化区域分支用 frame_sequence
  三切片各自绑定自己的 frame_id/时间/内容（=各自帧的同区域真实切片，非
  cur 复制）；crop_id 显式键匹配（乱序 dict 也正确）；无 frame_sequence
  旧分支退化路径（cur 裁图+前后显式缺位，绝不挪身份）；gate_reason 进
  prompt 头部；分支顺序保持；window_id 必填、分支身份 M1 校验拒串线；
  转换不改写输入切片/帧（只读语义保留）。
- C-138 D1 兜底统一三序位：branches=None/空 + fallback_reason → 单一
  全景任务（只有 cur 时序位 0/2 显式缺位、prompt 首行携带原因原样、
  非完整连续过程声明；gate_reason 全词表逐个透传不改写）；与非空
  branches 互斥；兜底任务过真实 stage 零 identity_rejected。
- C-138 D4 同窗多包 branch key 去重：branch_key 七元含 material 段——
  同窗两个材料包的任务身份与 results 条目 key 凭 material 段区分，存档/
  摘要并排不互相覆盖。
- C2 results_from_output：接线级——真实 L3Stage（假模型边界注入）产真实
  L3Output → 逐字段转换（结构化 dict/纯文本 unstructured/缺帧 partial/
  预算截断 partial/失败态条目），JSON 可序列化；禁止空 text+ok；未知状
  态不变 ok；失败/拒绝分支条目保留。
- C-139 §3/R2 失败血缘：失败条目保留已知任务身份事实——crop_id/
  branch_key（七元含 material 段）/帧来源/帧时间不清空；观察侧未知字段
  置 None；受控细分码（load_timeout 等）随 error_code 保留不压平。
- summary_text：中文一行、确定性、有界。
- C3 确认：stage 产出的 L3BranchResult 逐字段齐备（转换所需字段全在），
  stage 未改动。
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from scam.win11_l2_contract import (CropTransform, FrameIdentity,
                                    L3BranchSpec, L3LocalFrameSlice)
from scam.win11_l2_crops import norm_box_to_px, slice_region
from scam.win11_l3 import L3Stage
from scam.win11_l3_contract import (L3BranchKind, L3Budget,
                                    L3FrameIdentity, L3FrameInput,
                                    L3ModelUnavailable, L3Status, L3Task,
                                    L3WindowIdentity)
from scam.win11_l3_tasks import (L3TaskBudgetLedger, L3WindowBudget,
                                 branch_key_of, results_from_output,
                                 summary_text, tasks_from_package,
                                 window_key_of)
from scam.win11_materials import MaterialFrame, MaterialPackage

# ---------------------------------------------------------------------------
# 工具：像素可区分的材料包/分支（真实切片数学同 C-135 L2）
# ---------------------------------------------------------------------------

_REGION = (0.25, 0.25, 0.5, 0.5)      # 同区域 bbox_norm（含水印像素 (8,8)）
_PATTERNS = {0: (40, 111), 1: (80, 222), 2: (160, 254)}   # 序位→(底色,水印)


def _frame_bgr(base, mark):
    arr = np.full((24, 32, 3), base, dtype=np.uint8)
    arr[8, 8] = mark                   # 水印值落在同区域内，可逐序位区分
    return arr


def _mframe(fid, position, t):
    base, mark = _PATTERNS[position]
    return MaterialFrame(fid, _frame_bgr(base, mark), float(t), "observed")


def _pkg(prev=True, nxt=True):
    """手工构建 MaterialPackage（形状同 take_ready 副本；不触 store）。"""
    cur = _mframe("cur-f3", 1, 3000.0)
    pkg = MaterialPackage("cam1", "run1", 7, 42, 12345.0, cur, [], 64, 48)
    if prev:
        pkg.prev = _mframe("prev-f2", 0, 2000.0)
        pkg.prev_gap_ms = 1000.0
    if nxt:
        pkg.nxt = _mframe("nxt-f4", 2, 4000.0)
        pkg.nxt_gap_ms = 1000.0
    return pkg


def _identity(pkg):
    return FrameIdentity(pkg.camera_id, pkg.run_id, pkg.config_version,
                         pkg.cur.frame_id, pkg.material_id,
                         pkg.cur.t_capture_ms, pkg.cur.timestamp_kind)


def _region_slices(pkg, crop_id):
    """同区域三帧真实切片（每帧自己尺寸上映射；数学同 L2 _local_frame_
    sequence：norm_box_to_px + slice_region）。"""
    slices = []
    for position, fr in ((0, pkg.prev), (1, pkg.cur), (2, pkg.nxt)):
        if fr is None:
            slices.append(L3LocalFrameSlice(
                position=position, present=False, crop_id=crop_id,
                frame_id=None, t_capture_ms=None, timestamp_kind=None,
                width=None, height=None, frame_bgr=None))
            continue
        px = norm_box_to_px(_REGION, fr.width, fr.height)
        slices.append(L3LocalFrameSlice(
            position=position, present=True, crop_id=crop_id,
            frame_id=fr.frame_id, t_capture_ms=fr.t_capture_ms,
            timestamp_kind=fr.timestamp_kind, width=fr.width,
            height=fr.height, frame_bgr=slice_region(fr.frame_bgr, px)))
    return slices


def _branch(pkg, kind, crop_id, *, with_sequence=True, pixel_tag=0):
    slices = _region_slices(pkg, crop_id) if with_sequence else ()
    if with_sequence and pixel_tag:
        # 只改真实像素（+pixel_tag），身份/时间/序位不动——用于构造"同身份
        # 不同内容"的分支（覆盖账目与合并判定的区分场景）。
        tuned = []
        for sl in slices:
            arr = sl.frame_bgr
            if arr is not None:
                arr = np.clip(arr.astype(np.int16) + pixel_tag, 0,
                              255).astype(np.uint8)
            tuned.append(L3LocalFrameSlice(
                position=sl.position, present=sl.present, crop_id=sl.crop_id,
                frame_id=sl.frame_id, t_capture_ms=sl.t_capture_ms,
                timestamp_kind=sl.timestamp_kind, width=sl.width,
                height=sl.height, frame_bgr=arr))
        slices = tuple(tuned)
    return L3BranchSpec(
        branch_kind=kind, identity=_identity(pkg),
        crop_ref=CropTransform(union_norm=(0.0, 0.0, 1.0, 1.0),
                               margin_ratio=0.0, bbox_norm=_REGION,
                               bbox_px=(8, 6, 24, 18), clamped=False,
                               whole_frame_fallback=False,
                               context_capped=False),
        cur_present=True, prev_present=pkg.prev is not None,
        next_present=pkg.nxt is not None, cur_gap_ms=0.0,
        prev_gap_ms=pkg.prev_gap_ms, next_gap_ms=pkg.nxt_gap_ms,
        cur_detections=(), prev_detections=None, next_detections=None,
        candidates=(), calibrated=False, enhanced=None, omissions=(),
        crop_id=crop_id, region_only=True,
        frame_sequence=slices)


def _tasks(pkg, branches, crop_map=None, gate_reason=None, window_id=101,
           budget=None):
    return tasks_from_package(pkg=pkg, branches=branches,
                              crop_images_by_crop_id=(crop_map or {}),
                              vocabulary_id="vocab-1",
                              vocabulary=("near", "hold"),
                              budget=budget if budget is not None else L3Budget(),
                              window_id=window_id,
                              gate_reason=gate_reason)


class _ScriptedModel:
    """假模型边界注入（禁 fake 进生产——仅测试注入 L3Stage）：记录调用，
    返回可配置结构化 dict / 纯文本 / 异常。"""

    model_ref = "scripted/l3"

    def __init__(self, result=None, exc=None):
        self.result = result
        self.exc = exc
        self.calls = []

    def understand_frames(self, prompt, frames_bgr, frames_meta):
        self.calls.append({"prompt": prompt,
                           "present": [f is not None for f in frames_bgr],
                           "meta": [dict(m) for m in frames_meta]})
        if self.exc is not None:
            raise self.exc
        if self.result is not None:
            return self.result
        return {"observation": "看见区域内亮度上升", "inference": "同区域对象在移动"}


def _model_unavailable(code):
    """带结构化细分码的加载失败异常（同 win11_l3_backend 形态：加载超时
    抛 L3ModelUnavailable code="load_timeout"，隔离并如实报告线程残留）。"""
    exc = L3ModelUnavailable(
        "load_timeout: L3 provider first load did not complete within "
        "load_timeout_s=60.0s; the load thread is still alive and cannot "
        "be aborted; this instance is isolated")
    exc.code = code
    return exc


# ---------------------------------------------------------------------------
# C1：全景分支——三序位内容/顺序/身份逐项绑定
# ---------------------------------------------------------------------------

def test_panorama_task_binds_three_positions_with_own_identity():
    pkg = _pkg()
    task = _tasks(pkg, [_branch(pkg, "panorama", "m:whole")])[0]

    # window_key 全四元（window_id 来自调用方，不以 material_id 冒充）
    assert window_key_of(task.window) == ("cam1", "run1", 7, 101)
    assert task.window.window_id == 101 and pkg.material_id == 42
    assert task.branch is L3BranchKind.PANORAMA
    assert task.crop_id == "m:whole"
    assert isinstance(task.budget, L3Budget)
    assert isinstance(task.created_mono_ms, float)

    frames = task.frames
    assert [f.identity.frame_id for f in frames] == \
        ["prev-f2", "cur-f3", "nxt-f4"]             # 固定序位 0/1/2
    assert [f.t_capture_ms for f in frames] == [2000.0, 3000.0, 4000.0]
    assert all(f.timestamp_kind == "observed" for f in frames)
    assert all(f.branch is L3BranchKind.PANORAMA for f in frames)
    # 内容逐序位 = 各自整帧（不同亮度图案+水印值可区分）
    for f, position in zip(frames, (0, 1, 2)):
        base, mark = _PATTERNS[position]
        assert np.array_equal(f.frame_bgr, _frame_bgr(base, mark))
    # 隔离副本只读（L3 只读消费）
    with pytest.raises(ValueError):
        frames[1].frame_bgr[0, 0, 0] = 1
    # 输入材料帧未被转换改写
    assert pkg.cur.frame_bgr[8, 8, 0] == 222


def test_panorama_missing_prev_keeps_slot_zero_placeholder():
    pkg = _pkg(prev=False)
    task = _tasks(pkg, [_branch(pkg, "panorama", "m:whole")])[0]
    frames = task.frames
    assert len(frames) == 3                          # 缺帧不塌缩序位
    assert frames[0].frame_bgr is None               # 序位 0 显式占位
    assert frames[0].identity.frame_id is None
    assert frames[0].t_capture_ms is None
    assert frames[0].timestamp_kind is None
    assert frames[1].identity.frame_id == "cur-f3"
    assert frames[2].identity.frame_id == "nxt-f4"

    pkg2 = _pkg(prev=False, nxt=False)               # 只有 cur：两翼占位
    frames2 = _tasks(pkg2, [_branch(pkg2, "panorama", "m:whole")])[0].frames
    assert [f.frame_bgr is None for f in frames2] == [True, False, True]


# ---------------------------------------------------------------------------
# C1：局部关系分支——frame_sequence 三切片各自绑定自己的身份与内容
# ---------------------------------------------------------------------------

def test_relation_branch_slices_carry_own_identity_and_content():
    pkg = _pkg()
    branch = _branch(pkg, "relation_crop", "m:crop:1")
    slices_before = [np.array(s.frame_bgr, copy=True)
                     for s in branch.frame_sequence]
    task = _tasks(pkg, [branch])[0]

    frames = task.frames
    assert [f.identity.frame_id for f in frames] == \
        ["prev-f2", "cur-f3", "nxt-f4"]             # 切片自带 frame_id
    assert [f.t_capture_ms for f in frames] == [2000.0, 3000.0, 4000.0]
    assert all(f.branch is L3BranchKind.RELATION_CROP for f in frames)
    # 内容 = 各自帧的同区域真实切片（逐序位复算同一切图数学）
    for f, fr in zip(frames, (pkg.prev, pkg.cur, pkg.nxt)):
        px = norm_box_to_px(_REGION, fr.width, fr.height)
        assert np.array_equal(f.frame_bgr, slice_region(fr.frame_bgr, px))
    # 非 cur 复制：prev/nxt 位内容与 cur 位不同（底色/水印可区分）
    assert not np.array_equal(frames[0].frame_bgr, frames[1].frame_bgr)
    assert not np.array_equal(frames[2].frame_bgr, frames[1].frame_bgr)
    means = [float(f.frame_bgr.mean()) for f in frames]
    assert means[0] < means[1] < means[2]
    # 转换不改写已构造切片对象（只读语义保留）
    for s, before in zip(branch.frame_sequence, slices_before):
        assert np.array_equal(s.frame_bgr, before)
    # crop_id 与区域坐标进 prompt
    assert "crop_id=m:crop:1" in task.prompt
    assert "bbox_norm" in task.prompt and "0.250000" in task.prompt
    assert "不保证同一对象" in task.prompt


def test_relation_branch_missing_prev_placeholder_preserves_slot():
    pkg = _pkg(prev=False)
    task = _tasks(pkg, [_branch(pkg, "relation_crop", "m:crop:1")])[0]
    frames = task.frames
    assert len(frames) == 3
    assert frames[0].frame_bgr is None               # prev 缺失：显式占位
    assert frames[0].identity.frame_id is None
    assert frames[1].identity.frame_id == "cur-f3"   # 序位不塌缩
    assert frames[2].identity.frame_id == "nxt-f4"
    # 在场切片内容仍=各自帧切片（cur 未被复制到 prev 位）
    px_cur = norm_box_to_px(_REGION, pkg.cur.width, pkg.cur.height)
    assert np.array_equal(frames[1].frame_bgr,
                          slice_region(pkg.cur.frame_bgr, px_cur))


def test_change_region_branch_same_slot_semantics():
    pkg = _pkg()
    task = _tasks(pkg, [_branch(pkg, "change_region", "m:chg:1")])[0]
    frames = task.frames
    assert [f.identity.frame_id for f in frames] == \
        ["prev-f2", "cur-f3", "nxt-f4"]
    assert all(f.branch is L3BranchKind.CHANGE_REGION for f in frames)
    for f, fr in zip(frames, (pkg.prev, pkg.cur, pkg.nxt)):
        px = norm_box_to_px(_REGION, fr.width, fr.height)
        assert np.array_equal(f.frame_bgr, slice_region(fr.frame_bgr, px))


# ---------------------------------------------------------------------------
# C1：crop_id 显式键匹配（乱序 dict 也正确）；旧分支退化路径
# ---------------------------------------------------------------------------

def test_crop_images_matched_by_crop_id_not_by_position():
    pkg = _pkg()
    img_b = _frame_bgr(5, 250)        # crop "m:crop:b" 的图
    img_a = _frame_bgr(250, 5)        # crop "m:crop:a" 的图
    branches = [_branch(pkg, "relation_crop", "m:crop:b", with_sequence=False),
                _branch(pkg, "relation_crop", "m:crop:a", with_sequence=False)]
    # 乱序 dict：键与分支顺序无关——匹配只认 crop_id
    tasks = _tasks(pkg, branches, crop_map={"m:crop:a": img_a,
                                            "m:crop:b": img_b})
    assert [t.crop_id for t in tasks] == ["m:crop:b", "m:crop:a"]
    assert np.array_equal(tasks[0].frames[1].frame_bgr, img_b)
    assert np.array_equal(tasks[1].frames[1].frame_bgr, img_a)


def test_legacy_relation_branch_cur_crop_with_explicit_missing_slots():
    """无 frame_sequence 旧分支：cur 位=crop_id 映射裁图（cur 侧身份），
    prev/next 位显式缺位——绝不把 cur 裁图替换到 prev 位沿用其身份。"""
    pkg = _pkg()
    img = _frame_bgr(9, 199)
    task = _tasks(pkg, [_branch(pkg, "relation_crop", "m:crop:x",
                                with_sequence=False)],
                  crop_map={"m:crop:x": img})[0]
    frames = task.frames
    assert len(frames) == 3
    assert frames[0].frame_bgr is None and frames[0].identity.frame_id is None
    assert np.array_equal(frames[1].frame_bgr, img)
    assert frames[1].identity.frame_id == "cur-f3"   # cur 侧身份
    assert frames[1].t_capture_ms == 3000.0
    assert frames[2].frame_bgr is None and frames[2].identity.frame_id is None


# ---------------------------------------------------------------------------
# C1：gate_reason / 分支顺序 / 键 / 校验拒收
# ---------------------------------------------------------------------------

def test_gate_reason_lands_in_prompt_head():
    pkg = _pkg()
    task = _tasks(pkg, [_branch(pkg, "panorama", "m:whole")],
                  gate_reason="l1_wait_timeout")[0]
    assert task.prompt.startswith("兜底任务")
    assert "l1_wait_timeout" in task.prompt
    normal = _tasks(pkg, [_branch(pkg, "panorama", "m:whole")])[0]
    assert "兜底" not in normal.prompt


def test_branch_order_preserved_and_branch_key():
    pkg = _pkg()
    branches = [_branch(pkg, "panorama", "m:whole"),
                _branch(pkg, "relation_crop", "m:crop:1"),
                _branch(pkg, "change_region", "m:chg:1")]
    tasks = _tasks(pkg, branches)
    assert [t.branch for t in tasks] == [L3BranchKind.PANORAMA,
                                         L3BranchKind.RELATION_CROP,
                                         L3BranchKind.CHANGE_REGION]
    for t in tasks:
        # C-138 §1：branch_key 七元 = window_key + (branch, crop_id,
        # material_id)；window_key 恒四元
        assert window_key_of(t.window) == ("cam1", "run1", 7, 101)
        assert branch_key_of(t.window, t.branch, t.crop_id) == \
            ("cam1", "run1", 7, 101, t.branch.value, t.crop_id, 42)
    assert branch_key_of(tasks[0].window, tasks[0].branch, None) == \
        ("cam1", "run1", 7, 101, "panorama", None, 42)


def test_tasks_from_package_no_branches_returns_empty():
    assert _tasks(_pkg(), []) == []


def test_unknown_branch_kind_raises():
    pkg = _pkg()
    with pytest.raises(ValueError):
        _tasks(pkg, [_branch(pkg, "zzz_unknown", "m:x")])


def test_window_id_required_not_material_id():
    with pytest.raises(ValueError):
        tasks_from_package(pkg=_pkg(), branches=(),
                           crop_images_by_crop_id={}, vocabulary_id=None,
                           vocabulary=(), budget=None, window_id=None)


def test_branch_identity_mismatch_refuses_cross_material():
    pkg = _pkg()
    wrong = _branch(pkg, "panorama", "m:whole")
    wrong.identity = FrameIdentity("cam1", "run1", 7, "cur-f3", 43,
                                   3000.0, "observed")   # material 43≠42
    with pytest.raises(ValueError):
        _tasks(pkg, [wrong])
    wrong_run = _branch(pkg, "panorama", "m:whole")
    wrong_run.identity = FrameIdentity("cam1", "run9", 7, "cur-f3", 42,
                                       3000.0, "observed")
    with pytest.raises(ValueError):
        _tasks(pkg, [wrong_run])


def test_tasks_pass_stage_identity_validation_end_to_end():
    """转换产物全部通过 stage 身份校验（窗口三元+分支标签），零 identity_
    rejected——接线级前提。"""
    pkg = _pkg()
    model = _ScriptedModel()
    stage = L3Stage(model)
    for task in _tasks(pkg, [_branch(pkg, "panorama", "m:whole"),
                             _branch(pkg, "relation_crop", "m:crop:1"),
                             _branch(pkg, "change_region", "m:chg:1")]):
        out = stage.process(task)
        assert out.status is not L3Status.IDENTITY_REJECTED
        assert len(model.calls[-1]["present"]) == 3   # 三序位齐进模型协议
        assert model.calls[-1]["meta"][1]["frame_id"] == "cur-f3"


# ---------------------------------------------------------------------------
# C-138 D1：兜底统一三序位（无 branches + fallback_reason → 单一全景任务）
# ---------------------------------------------------------------------------

def _fallback(pkg, reason, *, branches=None, budget=None, window_id=101):
    return tasks_from_package(
        pkg=pkg, branches=branches, crop_images_by_crop_id=None,
        vocabulary_id=None, vocabulary=(), budget=budget,
        window_id=window_id, fallback_reason=reason)


def test_fallback_only_cur_single_task_three_explicit_slots():
    """只有 cur（prev/nxt=None）：一个任务、三固定序位、0/2 显式缺位、
    prompt 首行携带原因原样——模型可描述当前画面，但 prompt/presence
    如实表明非完整连续过程。"""
    pkg = _pkg(prev=False, nxt=False)
    tasks = _fallback(pkg, "l1_wait_timeout")
    assert len(tasks) == 1                          # 兜底=单一全景任务
    task = tasks[0]
    assert task.branch is L3BranchKind.PANORAMA
    assert task.crop_id is None                     # 无 L2 裁图来源，不编造
    assert window_key_of(task.window) == ("cam1", "run1", 7, 101)
    assert task.window.material_id == 42            # 任务身份含 material 段
    assert task.budget is None                      # budget=None → stage 构造档
    frames = task.frames
    assert len(frames) == 3                         # 序位不塌缩
    assert [f.frame_bgr is None for f in frames] == [True, False, True]
    assert frames[0].identity.frame_id is None      # 缺位身份/时间如实留空
    assert frames[0].t_capture_ms is None
    assert frames[2].identity.frame_id is None
    assert frames[1].identity.frame_id == "cur-f3"  # cur 在序位 1
    assert frames[1].t_capture_ms == 3000.0
    assert all(f.branch is L3BranchKind.PANORAMA for f in frames)
    lines = task.prompt.splitlines()
    assert lines[0] == "L1 关系识别不可用（原因：l1_wait_timeout）。"
    assert "非完整连续过程" in task.prompt
    assert "缺失序位：0、2" in task.prompt
    assert "在场序位：1" in task.prompt
    # 输入材料帧未被转换改写
    assert pkg.cur.frame_bgr[8, 8, 0] == 222


def test_fallback_full_three_frames_binds_positions_and_omits_gap_line():
    pkg = _pkg()
    task = _fallback(pkg, "empty")[0]
    frames = task.frames
    assert [f.identity.frame_id for f in frames] == \
        ["prev-f2", "cur-f3", "nxt-f4"]
    for f, position in zip(frames, (0, 1, 2)):      # 在场帧逐序位真实内容
        base, mark = _PATTERNS[position]
        assert np.array_equal(f.frame_bgr, _frame_bgr(base, mark))
    assert "非完整连续过程" not in task.prompt       # 三帧齐→无缺位声明行
    assert task.prompt.splitlines()[0] == "L1 关系识别不可用（原因：empty）。"


def test_fallback_missing_prev_only_lists_actual_slots():
    pkg = _pkg(prev=False)                          # 仅 prev 缺失
    task = _fallback(pkg, "model_unavailable")[0]
    assert [f.frame_bgr is None for f in task.frames] == [True, False, False]
    assert "在场序位：1、2" in task.prompt
    assert "缺失序位：0" in task.prompt


@pytest.mark.parametrize("reason", [
    "empty", "model_unavailable", "infer_failed", "timeout",
    "l1_wait_timeout", "rejected:门控裁决拒绝-安全帽缺失",
])
def test_fallback_gate_reason_vocabulary_passthrough_verbatim(reason):
    """gate_reason 全词表逐个透传：原因原样进 prompt 首行，不改写不淡化。"""
    task = _fallback(_pkg(), reason)[0]
    assert task.prompt.splitlines()[0] == \
        "L1 关系识别不可用（原因：{}）。".format(reason)
    assert reason in task.prompt


def test_fallback_mutually_exclusive_with_nonempty_branches():
    pkg = _pkg()
    with pytest.raises(ValueError):
        _fallback(pkg, "empty",
                  branches=[_branch(pkg, "panorama", "m:whole")])


def test_fallback_no_reason_no_branches_yields_no_task():
    """branches 空 + 无 fallback_reason → 无任务（C-137 语义保持）；
    gate_reason 只修饰分支任务，不触发兜底。"""
    assert _tasks(_pkg(), []) == []
    assert tasks_from_package(pkg=_pkg(), branches=None,
                              crop_images_by_crop_id=None,
                              vocabulary_id=None, vocabulary=(),
                              budget=None, window_id=101,
                              gate_reason="empty") == []


def test_fallback_task_passes_stage_end_to_end():
    """兜底任务过真实 stage：零 identity_rejected，presence 如实进模型协议
    （[False, True, False]）；stage 渲染 prompt 含任务兜底原因行（stage
    自身头部在前为既有冻结行为，任务 prompt 首行断言见上）。"""
    pkg = _pkg(prev=False, nxt=False)
    task = _fallback(pkg, "infer_failed")[0]
    assert task.prompt.splitlines()[0] == \
        "L1 关系识别不可用（原因：infer_failed）。"   # 任务 prompt 首行
    model = _ScriptedModel()
    out = L3Stage(model).process(task)
    assert out.status is not L3Status.IDENTITY_REJECTED
    (call,) = model.calls
    assert call["present"] == [False, True, False]
    assert "L1 关系识别不可用（原因：infer_failed）。" in call["prompt"]
    assert call["meta"][1]["frame_id"] == "cur-f3"


# ---------------------------------------------------------------------------
# C2：results_from_output（真实 L3Stage + 假模型边界注入；不经伪造输出）
# ---------------------------------------------------------------------------

def test_results_roundtrip_structured_fields_end_to_end():
    pkg = _pkg()
    task = _tasks(pkg, [_branch(pkg, "relation_crop", "m:crop:1")])[0]
    model = _ScriptedModel()
    out = L3Stage(model).process(task)
    assert out.status is L3Status.OK and len(out.results) == 1

    entries = results_from_output(out)
    assert len(entries) == 1
    e = entries[0]
    assert e["window_key"] == ["cam1", "run1", 7, 101]
    # C-138 §1：branch_key 追加 material 段（七元）
    assert e["branch_key"] == ["cam1", "run1", 7, 101,
                               "relation_crop", "m:crop:1", 42]
    assert e["branch"] == "relation_crop" and e["crop_id"] == "m:crop:1"
    assert e["status"] == "ok" and e["error_code"] is None
    assert e["model_ref"] == "scripted/l3"
    assert e["region_only"] is True and e["unstructured"] is False
    assert e["observation"] == {"text": "看见区域内亮度上升",
                                "unstructured": False,
                                "certainty": "model_inferred"}
    assert e["inference"] == {"text": "同区域对象在移动",
                              "unstructured": False,
                              "certainty": "model_inferred"}
    assert e["uncertainty"] == {"frame_missing": False,
                                "frames_truncated": False,
                                "pixels_downscaled": False,
                                "unenhanced": True}
    assert [s["position"] for s in e["sources"]] == [0, 1, 2]
    assert all(s["present"] for s in e["sources"])
    assert [s["frame_id"] for s in e["sources"]] == \
        ["prev-f2", "cur-f3", "nxt-f4"]              # 帧身份随条目保留
    assert [s["t_capture_ms"] for s in e["sources"]] == \
        [2000.0, 3000.0, 4000.0]                     # 时间类型同保留
    assert all(s["timestamp_kind"] == "observed" for s in e["sources"])
    assert e["frame_gaps_ms"] == [1000.0, 1000.0]
    assert e["missing"] == {"frames": [], "frames_dropped": 0,
                            "omission_reason": ""}
    assert e["reason"] is None
    json.dumps(entries, ensure_ascii=False)          # 可保存：JSON 可序列化


def test_results_free_text_marked_unstructured_and_missing_frame_partial():
    pkg = _pkg(prev=False)
    task = _tasks(pkg, [_branch(pkg, "relation_crop", "m:crop:1")])[0]
    out = L3Stage(_ScriptedModel(
        result="画面整体变亮，推断有人经过。")).process(task)
    assert out.status is L3Status.PARTIAL

    e = results_from_output(out)[0]
    assert e["status"] == "partial"
    assert e["observation"] == {"text": "画面整体变亮，推断有人经过。",
                                "unstructured": True,
                                "certainty": "model_inferred"}
    assert e["inference"] is None
    assert e["unstructured"] is True
    assert e["uncertainty"]["frame_missing"] is True
    assert e["missing"]["frames"] == [0]             # 缺失信息随条目
    assert e["sources"][0]["present"] is False
    assert e["sources"][0]["frame_id"] is None
    assert e["frame_gaps_ms"] == [None, 1000.0]      # 缺帧侧间隔未知如实，另侧如实


def test_results_failure_branch_entry_kept_not_empty_ok():
    """失败分支也产出条目（status/原因）——禁止只保存空 text+ok；C-139 §3：
    已知身份事实（crop_id/branch_key 七元/帧来源）保留不清空。"""
    pkg = _pkg()
    task = _tasks(pkg, [_branch(pkg, "panorama", "m:whole")])[0]
    out = L3Stage(_ScriptedModel(exc=ValueError("upstream boom"))).process(task)
    assert out.status is L3Status.INFER_FAILED and len(out.results) == 1

    e = results_from_output(out)[0]
    assert e["status"] == "infer_failed" and e["error_code"] == "infer_failed"
    assert e["observation"] is None and e["inference"] is None
    assert e["reason"] and "infer_failed" in e["reason"]
    assert e["model_ref"] == "scripted/l3"
    # 身份事实保留：crop_id + branch_key 七元（含 crop 与 material 段）
    assert e["crop_id"] == "m:whole"
    assert e["branch_key"] == ["cam1", "run1", 7, 101, "panorama",
                               "m:whole", 42]
    assert e["window_key"] == ["cam1", "run1", 7, 101]
    # 帧来源/时间保留（已知任务事实，不编造也不清空）
    assert [s["frame_id"] for s in e["sources"]] == \
        ["prev-f2", "cur-f3", "nxt-f4"]
    assert all(s["present"] for s in e["sources"])
    assert [s["t_capture_ms"] for s in e["sources"]] == [2000.0, 3000.0, 4000.0]
    # 观察侧语义未知：置 None 不编造
    assert e["region_only"] is None and e["unstructured"] is None
    assert e["uncertainty"] is None
    assert not (e["status"] == "ok"
                and not (e["observation"] or {}).get("text"))
    json.dumps(results_from_output(out), ensure_ascii=False)

    # identity_rejected：真实 stage 产出 → 条目保留状态、原因与任务帧事实
    bad = L3Task(window=L3WindowIdentity("cam1", "run1", 7, 101),
                 branch=L3BranchKind.PANORAMA,
                 frames=(L3FrameInput(
                     branch=L3BranchKind.PANORAMA,
                     identity=L3FrameIdentity("cam1", "run2", 7, "x"),
                     t_capture_ms=1.0, timestamp_kind="observed",
                     frame_bgr=np.full((4, 4, 3), 1, np.uint8)),),
                 prompt="p")
    out2 = L3Stage(_ScriptedModel()).process(bad)
    assert out2.status is L3Status.IDENTITY_REJECTED
    e2 = results_from_output(out2)[0]
    assert e2["status"] == "identity_rejected"
    assert e2["error_code"] == "identity_mismatch:frame0"
    assert e2["reason"] and "identity_mismatch:frame0" in e2["reason"]
    assert e2["crop_id"] is None                  # 任务未带 crop：不编造
    assert [s["frame_id"] for s in e2["sources"]] == ["x"]   # 帧事实保留
    assert e2["branch_key"] == ["cam1", "run1", 7, 101, "panorama",
                                None, None]       # 七元键形恒定（缺段如实 None）


def test_results_load_timeout_keeps_cropA_frame2_identity_and_branch_key():
    """必测（C-139-R2）：真实 L3Stage 注入加载超时模型（adapter 结构化
    code=load_timeout）→ 失败结果保留 cropA/frame2 身份 + detail_code=
    load_timeout + 七元 branch_key（含 material 段）。"""
    model = _ScriptedModel()
    exc = _model_unavailable("load_timeout")
    model.exc = exc
    window = L3WindowIdentity("cam1", "run1", 7, 101, material_id=42)
    task = L3Task(
        window=window, branch=L3BranchKind.RELATION_CROP,
        frames=(L3FrameInput(
            branch=L3BranchKind.RELATION_CROP,
            identity=L3FrameIdentity("cam1", "run1", 7, "frame2"),
            t_capture_ms=3000.0, timestamp_kind="source_capture",
            frame_bgr=np.full((4, 4, 3), 1, np.uint8)),),
        prompt="分析画面变化。", crop_id="cropA")
    out = L3Stage(model).process(task)
    assert out.status is L3Status.MODEL_UNAVAILABLE
    assert out.error_code == "load_timeout"       # 受控细分码不压平

    e = results_from_output(out)[0]
    assert e["status"] == "model_unavailable"
    assert e["error_code"] == "load_timeout"      # detail_code 保留
    assert e["crop_id"] == "cropA"                # 裁剪来源不清空
    assert e["branch_key"] == ["cam1", "run1", 7, 101, "relation_crop",
                               "cropA", 42]       # 七元含 material 段
    assert [s["frame_id"] for s in e["sources"]] == ["frame2"]
    assert [s["timestamp_kind"] for s in e["sources"]] == ["source_capture"]
    assert [s["t_capture_ms"] for s in e["sources"]] == [3000.0]
    assert e["observation"] is None and e["inference"] is None
    json.dumps([e], ensure_ascii=False)           # 可保存：JSON 可序列化


def test_results_entry_unknown_fields_not_fabricated_on_failure():
    out = L3Stage(_ScriptedModel(exc=ValueError("x"))).process(
        _tasks(_pkg(), [_branch(_pkg(), "panorama", "m:whole")])[0])
    e = results_from_output(out)[0]
    assert e["region_only"] is None and e["unstructured"] is None
    assert e["uncertainty"] is None
    # 帧间隔是任务帧的已知事实：照实保留（三序位全景 → 两个间隔）
    assert e["frame_gaps_ms"] == [1000.0, 1000.0]
    assert e["crop_id"] == "m:whole"              # 身份不清空
    assert e["missing"]["frames"] == []           # 无缺帧序位（如实）


def test_results_budget_truncated_entry_keeps_status_reason_missing():
    """C-138 D2：预算截断条目——status=partial 非 ok、截断/缺失因素、
    omission 原因与保序 sources 齐备（未知不编造，已知不丢失）。"""
    pkg = _pkg()
    task = tasks_from_package(
        pkg=pkg, branches=[_branch(pkg, "panorama", "m:whole")],
        crop_images_by_crop_id={}, vocabulary_id=None, vocabulary=(),
        budget=L3Budget(max_frames_per_task=2), window_id=101)[0]
    out = L3Stage(_ScriptedModel()).process(task)
    assert out.status is L3Status.PARTIAL

    e = results_from_output(out)[0]
    assert e["status"] == "partial" and e["status"] != "ok"
    assert e["uncertainty"]["frames_truncated"] is True
    assert e["missing"]["frames_dropped"] == 1
    assert e["missing"]["omission_reason"]
    assert [s["position"] for s in e["sources"]] == [0, 1]   # 保序保留前 N 帧
    assert (e["observation"] or {}).get("text")              # 文本不丢
    json.dumps(results_from_output(out), ensure_ascii=False)


# ---------------------------------------------------------------------------
# 接线级：材料→任务→真实 stage→可保存结构（模拟 runtime 消费全链）
# ---------------------------------------------------------------------------

def test_wiring_pipeline_package_to_saveable_structure():
    """pkg + L2 分支 → tasks_from_package → 逐任务过真实 L3Stage（假模型
    边界注入）→ results_from_output → 全部条目进"可保存结构"并整体 JSON
    可序列化（模拟 runtime 落盘消费），summary 随行供健康面。"""
    pkg = _pkg()
    model = _ScriptedModel()
    stage = L3Stage(model)
    payload = {"window_key": ["cam1", "run1", 7, 101], "branches": []}
    for task in _tasks(pkg, [_branch(pkg, "panorama", "m:whole"),
                             _branch(pkg, "relation_crop", "m:crop:1"),
                             _branch(pkg, "change_region", "m:chg:1")]):
        out = stage.process(task)
        entries = results_from_output(out)
        assert entries and entries[0]["status"] == "ok"
        payload["branches"].append({
            "summary": summary_text(out),
            "results": entries,
        })
    blob = json.dumps(payload, ensure_ascii=False)
    assert "看见区域内亮度上升" in blob
    assert "model_inferred" in blob
    for item in payload["branches"]:
        assert item["summary"] and "\n" not in item["summary"]


# ---------------------------------------------------------------------------
# C-138 D4：同窗多材料包 branch key 去重（material 段区分，互不覆盖）
# ---------------------------------------------------------------------------

def _pkg_with_material(material_id, *, prev=True, nxt=True):
    """同窗不同材料的材料包：camera/run/config 不变，仅 material_id 不同。"""
    pkg = _pkg(prev=prev, nxt=nxt)
    pkg.material_id = material_id
    return pkg


def test_same_window_two_materials_task_branch_keys_differ():
    """同窗两个材料包各产出 relation_crop 任务：branch_key 仅 material 段
    不同——不同材料的同区域分支 key 必不相同（C-138 §1）。"""
    wargs = dict(crop_images_by_crop_id={}, vocabulary_id=None,
                 vocabulary=(), budget=None, window_id=101)
    pkg_a = _pkg_with_material(42)
    pkg_b = _pkg_with_material(43)
    task_a = tasks_from_package(
        pkg=pkg_a, branches=[_branch(pkg_a, "relation_crop", "m:crop:1")],
        **wargs)[0]
    task_b = tasks_from_package(
        pkg=pkg_b, branches=[_branch(pkg_b, "relation_crop", "m:crop:1")],
        **wargs)[0]
    assert window_key_of(task_a.window) == window_key_of(task_b.window)
    assert task_a.window.material_id == 42
    assert task_b.window.material_id == 43
    key_a = branch_key_of(task_a.window, task_a.branch, task_a.crop_id)
    key_b = branch_key_of(task_b.window, task_b.branch, task_b.crop_id)
    assert key_a != key_b
    assert key_a[:-1] == key_b[:-1]                 # 仅 material 段可区分
    # 同窗兜底全景任务同样凭 material 段区分
    fb_a = tasks_from_package(pkg=pkg_a, branches=None,
                              fallback_reason="empty", **wargs)[0]
    fb_b = tasks_from_package(pkg=pkg_b, branches=None,
                              fallback_reason="empty", **wargs)[0]
    assert branch_key_of(fb_a.window, fb_a.branch, fb_a.crop_id) != \
        branch_key_of(fb_b.window, fb_b.branch, fb_b.crop_id)


def test_same_window_two_materials_results_archive_side_by_side():
    """同窗双包结果并排存档：branch_key 含 material 段，按 key 收录两条，
    互不覆盖（各自观察文本原样保留）。"""
    wargs = dict(crop_images_by_crop_id={}, vocabulary_id=None,
                 vocabulary=(), budget=None, window_id=101)
    archived = {}
    for material_id, obs in ((42, "材料A：区域内叉车靠近"), (43, "材料B：区域内无人")):
        pkg = _pkg_with_material(material_id)
        task = tasks_from_package(
            pkg=pkg, branches=[_branch(pkg, "relation_crop", "m:crop:1")],
            **wargs)[0]
        out = L3Stage(_ScriptedModel(result={
            "observation": obs, "inference": "同区域对象状态待定"}
        )).process(task)
        for e in results_from_output(out):
            key = tuple(e["branch_key"])
            assert key not in archived              # 同窗不互相覆盖
            archived[key] = e
    assert len(archived) == 2
    assert {key[-1] for key in archived} == {42, 43}  # material 段在 key 内
    texts = {e["observation"]["text"] for e in archived.values()}
    assert texts == {"材料A：区域内叉车靠近", "材料B：区域内无人"}
    json.dumps({str(k): v for k, v in archived.items()}, ensure_ascii=False)


# ---------------------------------------------------------------------------
# summary_text（健康面一行）
# ---------------------------------------------------------------------------

def test_summary_text_one_line_deterministic():
    pkg = _pkg()
    task = _tasks(pkg, [_branch(pkg, "relation_crop", "m:crop:1")])[0]
    out = L3Stage(_ScriptedModel()).process(task)
    s1, s2 = summary_text(out), summary_text(out)
    assert s1 == s2 and "\n" not in s1
    assert "relation_crop" in s1 and "ok" in s1
    assert "观察：看见区域内亮度上升" in s1
    assert "推断：同区域对象在移动" in s1
    assert "未增强" in s1                             # 不确定性如实入行

    fail = L3Stage(_ScriptedModel(exc=ValueError("boom"))).process(task)
    sf = summary_text(fail)
    assert "infer_failed" in sf and "\n" not in sf


def test_summary_text_clips_long_text_and_folds_newlines():
    long_text = "很长的叙述。" * 100
    pkg = _pkg()
    task = _tasks(pkg, [_branch(pkg, "panorama", "m:whole")])[0]
    out = L3Stage(_ScriptedModel(result=long_text + "\n第二行")).process(task)
    s = summary_text(out)
    assert len(s) < 400 and "…" in s and "\n" not in s


# ---------------------------------------------------------------------------
# C3：stage 产出字段齐备性（转换所需字段全在；stage 未改动）
# ---------------------------------------------------------------------------

def test_stage_result_fields_complete_for_conversion():
    out = L3Stage(_ScriptedModel()).process(
        _tasks(_pkg(), [_branch(_pkg(), "relation_crop", "m:crop:1")])[0])
    (result,) = out.results
    for attr in ("branch", "status", "error_code", "observation", "inference",
                 "uncertainty", "sources", "window", "crop_id", "model_ref",
                 "region_only", "unstructured", "frame_gaps_ms"):
        assert hasattr(result, attr)
    assert out.omission is not None and out.status is not None
    assert [s.position for s in result.sources] == [0, 1, 2]


# ---------------------------------------------------------------------------
# C153 A：窗口/事件级共享总预算 + 覆盖账目（合并重复材料保留来源）
# ---------------------------------------------------------------------------

_WKEY = ("cam1", "run1", 7, 101)


def _mpkg(material_id, *, prev=True, nxt=True):
    """本节的材料包：同上，material 段显式（复用既有 _pkg 形状）。"""
    return _pkg_with_material(material_id, prev=prev, nxt=nxt)


def _planned(pkg, branches, *, ledger, task_budget=None, window_id=101,
             crop_map=None, **kw):
    """共享预算路径的任务转换（与 _tasks 同参，仅多 ledger）。"""
    return tasks_from_package(
        pkg=pkg, branches=branches, crop_images_by_crop_id=(crop_map or {}),
        vocabulary_id="vocab-1", vocabulary=("near", "hold"),
        budget=task_budget, window_id=window_id, budget_ledger=ledger, **kw)


def _frame_sig(task):
    """任务帧的可比签名（身份 + 存在性 + 尺寸）：避开对象身份比较。"""
    return tuple(
        (fr.identity.frame_id, fr.frame_bgr is not None,
         None if fr.frame_bgr is None else tuple(fr.frame_bgr.shape))
        for fr in task.frames)


def test_legacy_path_unchanged_without_ledger():
    """无账本（默认）→ 与旧路径逐字段一致：任务数、帧签名、预算原样。"""
    pkg = _mpkg(41)
    branches = [_branch(pkg, "panorama", "m:whole"),
                _branch(pkg, "relation_crop", "m:crop:1")]
    budget = L3Budget()
    legacy = _tasks(pkg, branches, budget=budget)
    with_none = tasks_from_package(
        pkg=pkg, branches=branches, crop_images_by_crop_id={},
        vocabulary_id="vocab-1", vocabulary=("near", "hold"), budget=budget,
        window_id=101, budget_ledger=None)

    assert len(legacy) == len(with_none) == 2
    for a, b in zip(legacy, with_none):
        assert _frame_sig(a) == _frame_sig(b)
        assert a.branch is b.branch and a.crop_id == b.crop_id
        assert a.prompt == b.prompt
        assert a.budget is b.budget is budget   # 未派生、未改写（同一个档对象）


def test_shared_window_budget_limits_total_frames_and_keeps_start_latest():
    """共享总预算：全景+局部**合计** ≤ 窗口总帧预算（不是每分支一份）；
    每个任务保开始/最新（模型输入侧稠密序位 0..M-1）。"""
    pkg = _mpkg(1)
    branches = [_branch(pkg, "panorama", "m:whole"),
                _branch(pkg, "relation_crop", "m:crop:1")]
    ledger = L3TaskBudgetLedger(L3WindowBudget(max_tasks_per_window=3,
                                               max_frames_per_task=3,
                                               max_total_frames=5))
    tasks = _planned(pkg, branches, ledger=ledger)

    assert [t.branch for t in tasks] == [L3BranchKind.PANORAMA,
                                        L3BranchKind.RELATION_CROP]
    # 共享额度被真实切分：第 2 个任务只拿到 2 帧份额（派生档=2）
    assert [t.budget.max_frames_per_task for t in tasks] == [3, 2]
    cov = ledger.coverage(_WKEY)
    assert cov["frames_reserved"] == 5            # 全景+局部共享一份总预算
    assert cov["tasks_reserved"] == 2 and cov["branches_kept"] == 2
    assert cov["branches_merged"] == 0 and cov["branches_dropped"] == 0
    # 派生档只下调（≤ 窗口档 3 ≤ 旧默认 8）
    for task in tasks:
        assert task.budget.max_frames_per_task <= 3
        assert task.budget.max_frames_per_task <= L3Budget().max_frames_per_task
    # 执行侧按派生档选择：保开始与最新状态（首帧/末帧身份在场）
    stage = L3Stage(_ScriptedModel())
    outs = [stage.process(task) for task in tasks]
    assert len(outs[1].results[0].sources) == 2
    assert outs[1].results[0].uncertainty.frames_truncated is True
    assert [s.present for s in outs[1].results[0].sources] == [True, True]
    assert "kept_positions=0,2" in outs[1].omission.reason
    assert outs[0].results[0].uncertainty.frames_truncated is False


def test_identical_source_material_merges_once_with_source_accounting():
    """同身份同内容指纹（同窗口、同分支、同 crop、同帧像素）的重复表达 →
    只跑一次模型，账目保留被覆盖来源（两条七元 branch_key）。"""
    pkg = _mpkg(1)
    branches = [_branch(pkg, "relation_crop", "m:crop:1"),
                _branch(pkg, "relation_crop", "m:crop:1")]
    ledger = L3TaskBudgetLedger(L3WindowBudget())
    tasks = _planned(pkg, branches, ledger=ledger)

    assert len(tasks) == 1                       # 重复材料不重复进模型
    cov = ledger.coverage(_WKEY)
    assert cov["branches_total"] == 2
    assert cov["branches_kept"] == 1 and cov["branches_merged"] == 1
    assert len(cov["merged"]) == 1
    merged = cov["merged"][0]
    assert merged["branch_index"] == 1 and merged["into_index"] == 0
    assert merged["reason"] == "merged_same_identity_fingerprint"
    assert merged["branch_key"][:4] == list(_WKEY)        # 身份四元在 key 内
    assert merged["branch_key"][4:] == ["relation_crop", "m:crop:1", 1]
    assert merged["into_branch_key"] == merged["branch_key"]


def test_different_branch_kind_never_merges_even_with_identical_content():
    """归属分支不同（全景 vs 变化区域）即使像素完全相同也**绝不合并**：
    语义角色不同，合并会丢角色。"""
    pkg = _mpkg(1)
    branches = [_branch(pkg, "change_region", "m:crop:1"),
                _branch(pkg, "panorama", "m:whole")]
    ledger = L3TaskBudgetLedger(L3WindowBudget(max_tasks_per_window=3))
    tasks = _planned(pkg, branches, ledger=ledger)

    assert [t.branch for t in tasks] == [L3BranchKind.CHANGE_REGION,
                                        L3BranchKind.PANORAMA]
    assert ledger.coverage(_WKEY)["branches_merged"] == 0


def test_different_crop_ids_never_merge_even_with_identical_pixels():
    """C153-R1 裁定 §1：**不同 crop_id 必须保留独立任务身份与来源**——
    像素/帧身份/内容 hash 完全相同也**不得**自动合并（两个 crop 在业务上
    可代表不同对象）。合并只允许发生在**完整任务身份与来源相同**之处。"""
    pkg = _mpkg(1)
    branches = [_branch(pkg, "change_region", "m:crop:1"),
                _branch(pkg, "change_region", "m:crop:2")]
    ledger = L3TaskBudgetLedger(L3WindowBudget(max_tasks_per_window=3))
    tasks = _planned(pkg, branches, ledger=ledger)

    assert len(tasks) == 2                        # 不同 crop → 各自独立任务
    assert [t.crop_id for t in tasks] == ["m:crop:1", "m:crop:2"]
    cov = ledger.coverage(_WKEY)
    assert cov["branches_total"] == 2
    assert cov["branches_kept"] == 2
    assert cov["branches_merged"] == 0 and cov["merged"] == []
    assert cov["branches_dropped"] == 0
    # 指纹相同（同一份像素）也不构成合并理由：两条计划行指纹一致
    entries = cov["plan_entries"]
    assert [row["crop_id"] for row in entries] == ["m:crop:1", "m:crop:2"]
    assert entries[0]["fingerprint_short"] == entries[1]["fingerprint_short"]
    assert {row["disposition"] for row in entries} == {"keep"}


def test_same_full_identity_resubmission_is_idempotent():
    """相同**完整身份与来源**（同窗/同材料/同分支/同 crop/同像素）重复提交
    → 幂等：只跑一次，被覆盖行带合并来源（reason 受控码）。"""
    pkg = _mpkg(1)
    branches = [_branch(pkg, "change_region", "m:crop:1"),
                _branch(pkg, "change_region", "m:crop:1")]
    ledger = L3TaskBudgetLedger(L3WindowBudget(max_tasks_per_window=3))
    tasks = _planned(pkg, branches, ledger=ledger)

    assert len(tasks) == 1
    cov = ledger.coverage(_WKEY)
    assert (cov["branches_kept"], cov["branches_merged"]) == (1, 1)
    assert cov["merged"][0]["branch_index"] == 1
    assert cov["merged"][0]["into_index"] == 0
    assert cov["merged"][0]["reason"] == "merged_same_identity_fingerprint"
    assert cov["merged"][0]["branch_key"] == cov["merged"][0][
        "into_branch_key"]
    assert cov["tasks_reserved"] == 1             # 幂等：不重复占额度


def test_same_identity_no_merge_when_content_fingerprint_differs():
    """身份与 crop 全同但真实像素不同 → 指纹不同 → 绝不合并（内容优先）。"""
    pkg = _mpkg(1)
    branch_a = _branch(pkg, "change_region", "m:crop:1")
    branch_b = _branch(pkg, "change_region", "m:crop:1")
    for sl in branch_b.frame_sequence:            # 只改真实像素，身份不动
        if sl.frame_bgr is not None:
            sl.frame_bgr = np.array(sl.frame_bgr, copy=True)
            sl.frame_bgr[0, 0] = 250
    ledger = L3TaskBudgetLedger(L3WindowBudget(max_tasks_per_window=3))
    tasks = _planned(pkg, [branch_a, branch_b], ledger=ledger)

    assert len(tasks) == 2
    cov = ledger.coverage(_WKEY)
    assert cov["branches_merged"] == 0 and cov["branches_kept"] == 2


def test_unknown_content_identity_never_merges():
    """内容完全不可得（像素不在手）→ 指纹 None → 绝不合并；预算按可分析
    帧数=0 如实丢弃（不冒充"能分析的帧"）。"""
    pkg = _mpkg(1, prev=False, nxt=False)
    branches = [_branch(pkg, "relation_crop", "m:crop:1",
                        with_sequence=False),
                _branch(pkg, "relation_crop", "m:crop:1",
                        with_sequence=False)]
    # 像素不在手（runtime 未给裁图像素时的真实形状）：frame_bgr 全 None
    pixel_less = (L3LocalFrameSlice(
        position=1, present=False, crop_id="m:crop:1", frame_id="cur-f3",
        t_capture_ms=3000.0, timestamp_kind="observed", width=32, height=24,
        frame_bgr=None),)
    ledger = L3TaskBudgetLedger(L3WindowBudget())
    plan = ledger.plan(window_key=_WKEY, pkg=pkg, branches=branches,
                       crop_ids=["m:crop:1", "m:crop:1"],
                       frames_by_index={0: pixel_less, 1: pixel_less})
    entries = plan["entries"]
    assert len(entries) == 2 and plan["kept"] == ()
    assert all(row["fingerprint_short"] is None for row in entries)
    assert all(row["reason"] == "branch_below_min_frames" for row in entries)
    assert all(row["frames_available"] == 0 for row in entries)   # 像素不在手
    cov = plan["coverage"]
    assert cov["branches_merged"] == 0 and cov["branches_dropped"] == 2


def test_legacy_branch_with_pixels_is_analyzable_and_budgeted():
    """旧分支（无 frame_sequence）像素在手：可分析帧数=1（只有当前帧），
    存在性=3 序位——预算按可分析帧计，绝不把缺帧占位算成"能分析的帧"。"""
    pkg = _mpkg(1)
    crop = np.full((12, 16, 3), 77, dtype=np.uint8)
    ledger = L3TaskBudgetLedger(L3WindowBudget())
    tasks = _planned(pkg, [_branch(pkg, "relation_crop", "m:crop:1",
                                   with_sequence=False)],
                     ledger=ledger, crop_map={"m:crop:1": crop})

    assert len(tasks) == 1                       # 1 帧 ≥ 下限 1：服务而不是丢
    cov = ledger.coverage(_WKEY)
    assert cov["dropped"] == []
    assert cov["frames_available"] == 1 and cov["frames_reserved"] == 1
    # 帧形状与旧行为完全一致：前后显式缺位占位（序位不塌缩）
    frames = tasks[0].frames
    assert len(frames) == 3
    assert [fr.frame_bgr is not None for fr in frames] == [False, True, False]
    assert frames[1].frame_bgr.shape == (12, 16, 3)
    assert frames[1].identity.frame_id == "cur-f3"
    # 帧身份完整（camera/run/config/frame_id 都在）→ 指纹身份口径如实为 True
    plan = ledger.plan(window_key=_WKEY, pkg=pkg,
                       branches=[_branch(pkg, "panorama", "m:whole")])
    (row,) = plan["entries"]
    assert row["fingerprint_identity_complete"] is True
    assert row["fingerprint_short"] is not None


def test_same_crop_different_material_never_merges():
    """同 crop_id 但不同材料包（像素不同）→ 指纹不同 → 不合并。"""
    pkg_a = _mpkg(1)
    pkg_b = _mpkg(2)
    pkg_b.cur.frame_bgr[8, 8] = 9                # 真实像素差异（同尺寸同标记位）
    ledger = L3TaskBudgetLedger(L3WindowBudget())
    tasks_a = _planned(pkg_a, [_branch(pkg_a, "relation_crop", "m:crop:1")],
                       ledger=ledger)
    tasks_b = _planned(pkg_b, [_branch(pkg_b, "relation_crop", "m:crop:1")],
                       ledger=ledger)

    assert len(tasks_a) == 1 and len(tasks_b) == 1
    cov = ledger.coverage(_WKEY)
    assert cov["branches_merged"] == 0 and cov["branches_kept"] == 2
    # 两份材料的 branch_key material 段不同（同窗并存不互相覆盖）
    assert [row["material_id"] for row in cov["dropped"]] == []
    plan_b = ledger.plan(window_key=_WKEY, pkg=pkg_b, branches=())
    assert plan_b["entries"] == ()                # 无新分支：账目不凭空增加


def test_ledger_isolated_per_window_identity():
    """跨 window_key 完全隔离：另一窗口用同名分支仍有自己的完整额度。"""
    pkg = _mpkg(1)
    branch = [_branch(pkg, "panorama", "m:whole")]
    ledger = L3TaskBudgetLedger(L3WindowBudget(max_total_frames=3,
                                               max_frames_per_task=3))
    first = _planned(pkg, branch, ledger=ledger, window_id=101)
    second = _planned(pkg, branch, ledger=ledger, window_id=202)

    assert len(first) == 1 and len(second) == 1
    assert len(first[0].frames) == 3 and len(second[0].frames) == 3
    assert ledger.coverage(("cam1", "run1", 7, 101))["frames_reserved"] == 3
    assert ledger.coverage(("cam1", "run1", 7, 202))["frames_reserved"] == 3
    assert ledger.coverage(("cam1", "run1", 8, 101)) is None   # 未登记不编造


def test_second_package_in_same_window_shares_remaining_budget():
    """同窗口后续材料包拿**剩余**额度（不是又一份完整预算）。"""
    ledger = L3TaskBudgetLedger(L3WindowBudget(max_tasks_per_window=3,
                                               max_frames_per_task=3,
                                               max_total_frames=6))
    pkg_a = _mpkg(1)
    pkg_b = _mpkg(2)
    first = _planned(pkg_a, [_branch(pkg_a, "panorama", "m:whole")],
                     ledger=ledger)
    second = _planned(pkg_b, [_branch(pkg_b, "panorama", "m:whole")],
                      ledger=ledger)

    assert len(first[0].frames) == 3
    assert len(second[0].frames) == 3             # 6 帧共享额度被两包分掉
    cov = ledger.coverage(_WKEY)
    assert cov["tasks_reserved"] == 2 and cov["frames_reserved"] == 6


def test_window_budget_exhausted_reports_specific_reason_and_scope():
    """额度耗尽 → 该分支如实 dropped（具体原因 + 范围），不是静默丢。"""
    pkg = _mpkg(1)
    branches = [_branch(pkg, "panorama", "m:whole"),
                _branch(pkg, "relation_crop", "m:crop:1", pixel_tag=1),
                _branch(pkg, "relation_crop", "m:crop:2", pixel_tag=2)]
    ledger = L3TaskBudgetLedger(L3WindowBudget(max_tasks_per_window=2,
                                               max_frames_per_task=3,
                                               max_total_frames=6))
    tasks = _planned(pkg, branches, ledger=ledger)

    assert len(tasks) == 2
    cov = ledger.coverage(_WKEY)
    assert cov["branches_total"] == 3 and cov["branches_dropped"] == 1
    assert cov["branches_merged"] == 0            # 内容不同 → 不合并
    dropped = cov["dropped"][0]
    assert dropped["branch_index"] == 2
    assert dropped["reason"] == "window_budget_tasks_exhausted"
    assert dropped["frames_available"] == 3        # 范围如实（本可分析 3 帧）
    assert dropped["branch_key"][:4] == list(_WKEY)
    assert dropped["branch_key"][4:] == ["relation_crop", "m:crop:2", 1]


def test_branch_below_min_frames_reports_its_own_reason():
    """分支本身可分析帧数低于下限 → 专属原因，不冒充分支间预算耗尽。"""
    pkg = _mpkg(1)
    branches = [_branch(pkg, "relation_crop", "m:crop:1",
                        with_sequence=False),
                _branch(pkg, "relation_crop", "m:crop:2",
                        with_sequence=False)]
    ledger = L3TaskBudgetLedger(L3WindowBudget(min_frames_per_task=2))
    tasks = _planned(pkg, branches, ledger=ledger, crop_map={})

    assert tasks == []                            # 连下限都凑不到 → 不静默少给
    cov = ledger.coverage(_WKEY)
    assert cov["branches_dropped"] == 2
    assert {row["reason"] for row in cov["dropped"]} == {
        "branch_below_min_frames"}


def test_real_merge_records_source_and_dropped_without_count_subtraction():
    """账目只记计划期事实：被覆盖=merged（带来源），未分析=dropped（带原因）；
    绝不出现由计数相减推导的字段。"""
    pkg = _mpkg(1)
    branches = [_branch(pkg, "panorama", "m:whole"),
                _branch(pkg, "relation_crop", "m:crop:1", pixel_tag=1),
                _branch(pkg, "relation_crop", "m:crop:1", pixel_tag=1),
                _branch(pkg, "relation_crop", "m:crop:2", pixel_tag=2)]
    ledger = L3TaskBudgetLedger(L3WindowBudget(max_tasks_per_window=2,
                                               max_total_frames=6))
    tasks = _planned(pkg, branches, ledger=ledger)
    cov = ledger.coverage(_WKEY)

    assert len(tasks) == 2
    assert cov["branches_total"] == 4
    assert (cov["branches_kept"], cov["branches_merged"],
            cov["branches_dropped"]) == (2, 1, 1)
    assert cov["merged"][0]["branch_index"] == 2
    assert cov["merged"][0]["reason"] == "merged_same_identity_fingerprint"
    assert cov["dropped"][0]["branch_index"] == 3
    assert cov["dropped"][0]["reason"] == "window_budget_tasks_exhausted"
    assert set(cov) == {
        "window_key", "branches_total", "branches_kept", "branches_merged",
        "branches_dropped", "tasks_reserved", "frames_available",
        "frames_reserved", "source_bytes_available", "source_bytes_reserved",
        "merged", "dropped", "released", "plan_entries",
        "unknown_branch_kinds", "budget"}
    json.dumps(cov, ensure_ascii=False, sort_keys=True)   # JSON 可序列化
    assert cov["unknown_branch_kinds"] == []              # 无未知标签


def test_unknown_branch_kind_is_listed_not_guessed():
    """无法归类的分支标签进 unknown_branch_kinds（如实列出，不猜语义）。"""
    pkg = _mpkg(1)
    ledger = L3TaskBudgetLedger(L3WindowBudget())

    class _Odd:
        branch_kind = "heatmap"
        crop_id = "m:odd"
        identity = _identity(pkg)
        frame_sequence = ()

    plan = ledger.plan(window_key=_WKEY, pkg=pkg, branches=[_Odd()])
    assert plan["coverage"]["unknown_branch_kinds"] == ["heatmap"]
    (entry,) = plan["entries"]
    assert entry["branch_kind"] == "heatmap"


def test_release_returns_budget_and_is_idempotent():
    """调用方在设计丢弃时归还额度；重复归还不重复计数。"""
    pkg = _mpkg(1)
    ledger = L3TaskBudgetLedger(L3WindowBudget(max_total_frames=3))
    tasks = _planned(pkg, [_branch(pkg, "panorama", "m:whole")],
                     ledger=ledger)
    assert len(tasks[0].frames) == 3
    assert ledger.coverage(_WKEY)["frames_reserved"] == 3

    assert ledger.release(_WKEY, 0, reason="plan_dropped") is True
    cov = ledger.coverage(_WKEY)
    assert cov["frames_reserved"] == 0 and cov["tasks_reserved"] == 0
    assert cov["released"][0]["reason"] == "plan_dropped"
    assert ledger.release(_WKEY, 0) is False       # 幂等：不重复归还
    assert ledger.release(("cam1", "run1", 7, 999), 0) is False


def test_coverage_snapshot_is_deep_copy_and_forget_clears_live_page():
    """账目快照外部改不动账本；封口 `forget` 清**活页**（防无界增长）但
    **归属不丢**：快照转存有界已封口表，`coverage()` 仍可读；同键再 plan
    **不得获得第二份预算**（C153-R1 裁定 §2）。"""
    pkg = _mpkg(1)
    ledger = L3TaskBudgetLedger(L3WindowBudget())
    _planned(pkg, [_branch(pkg, "panorama", "m:whole")], ledger=ledger)

    snapshot = ledger.coverage(_WKEY)
    snapshot["merged"].append({"branch_index": 999})
    snapshot["budget"]["max_tasks_per_window"] = 999
    snapshot["window_key"][0] = "tampered"

    fresh = ledger.coverage(_WKEY)
    assert fresh["merged"] == []
    assert fresh["budget"]["max_tasks_per_window"] == 3
    assert fresh["window_key"] == list(_WKEY)
    assert ledger.window_keys() == (_WKEY,)
    assert ledger.forget(_WKEY)["tasks_reserved"] == 1
    assert ledger.is_settled(_WKEY) is True
    # 归属不丢：封口快照仍可读，且外部依旧改不动
    frozen = ledger.coverage(_WKEY)
    assert frozen["tasks_reserved"] == 1
    frozen["dropped"].append({"branch_index": 999})
    assert ledger.coverage(_WKEY)["dropped"] == []
    assert ledger.forget(_WKEY)["tasks_reserved"] == 1      # 幂等
    assert ledger.window_keys() == (_WKEY,)

    # 已封口窗口的重放：不发第二份预算（逐行如实 dropped + 受控原因）
    replay = ledger.plan(window_key=_WKEY, pkg=pkg,
                         branches=[_branch(pkg, "panorama", "m:whole")])
    assert replay["kept"] == ()
    assert [row["disposition"] for row in replay["entries"]] == ["dropped"]
    assert replay["entries"][0]["reason"] == "window_budget_window_settled"
    assert ledger.coverage(_WKEY)["tasks_reserved"] == 1   # 未新增额度
    assert ledger.release(_WKEY, 0) is False               # 封口后不归还
    assert ledger.window_keys() == (_WKEY,)


def test_planned_tasks_pass_real_stage_identity_validation():
    """共享预算路径产出的任务过真实 stage：零 identity_rejected（身份未损）。"""
    pkg = _mpkg(1)
    branches = [_branch(pkg, "panorama", "m:whole"),
                _branch(pkg, "relation_crop", "m:crop:1")]
    ledger = L3TaskBudgetLedger(L3WindowBudget(max_total_frames=5))
    stage = L3Stage(_ScriptedModel())
    outs = [stage.process(task)
            for task in _planned(pkg, branches, ledger=ledger)]

    assert L3Status.IDENTITY_REJECTED not in [out.status for out in outs]
    # 受预算切分的任务如实 partial（帧截断）+ 选择记账；未切分的任务 ok
    assert [out.status for out in outs] == [L3Status.OK, L3Status.PARTIAL]
    assert outs[0].omission.frames_dropped == 0
    assert "selection=" in outs[1].omission.reason      # 选择记账如实
    assert outs[1].omission.frames_dropped == 1


# ---------------------------------------------------------------------------
# C153-R1 §1：跨 camera/run/config/窗口/材料 不合并、不借预算
# ---------------------------------------------------------------------------

def test_cross_run_config_window_never_share_budget_or_merge():
    """同名分支在**不同 run / config / window** 下：既不合并且**不共享预算**
    ——每个 window_key 各有一份完整额度（key 第一段即身份四元）。"""
    ledger = L3TaskBudgetLedger(L3WindowBudget(max_tasks_per_window=1,
                                               max_total_frames=3))
    scopes = [("cam1", "run1", 7, 101), ("cam1", "run1", 7, 102),
              ("cam1", "run2", 7, 101), ("cam1", "run1", 8, 101)]
    for camera, run, config, window_id in scopes:
        pkg = _mpkg(1)
        pkg.camera_id, pkg.run_id, pkg.config_version = camera, run, config
        tasks = _planned(pkg, [_branch(pkg, "panorama", "m:whole")],
                         ledger=ledger, window_id=window_id)
        key = (camera, run, config, window_id)
        assert len(tasks) == 1, f"{key} 应各有独立额度（不借预算）"
        cov = ledger.coverage(key)
        assert cov["tasks_reserved"] == 1 and cov["branches_kept"] == 1
        assert cov["dropped"] == []
        assert window_key_of(tasks[0].window) == key

    # 四把键互不覆盖，账目各自独立
    assert len(ledger.window_keys()) == 4
    for key in scopes:
        assert ledger.coverage(key)["window_key"] == list(key)


def test_cross_material_never_merges_and_keeps_own_branch_key():
    """同窗不同 material（材料包来源）→ 身份段不同 → 绝不合并；两条七元
    branch_key 的 material 段各留自家值（来源不丢）。"""
    pkg_a = _mpkg(1)
    pkg_b = _mpkg(2)
    ledger = L3TaskBudgetLedger(L3WindowBudget(max_tasks_per_window=3))
    tasks_a = _planned(pkg_a, [_branch(pkg_a, "relation_crop", "m:crop:1")],
                       ledger=ledger)
    tasks_b = _planned(pkg_b, [_branch(pkg_b, "relation_crop", "m:crop:1")],
                       ledger=ledger)

    assert len(tasks_a) == 1 and len(tasks_b) == 1
    cov = ledger.coverage(_WKEY)
    assert cov["branches_total"] == 2 and cov["branches_kept"] == 2
    assert cov["branches_merged"] == 0
    materials = [row["material_id"] for row in cov["plan_entries"]]
    assert materials == [1, 2]
    keys = [row["branch_key"] for row in cov["plan_entries"]]
    assert keys[0][:4] == list(_WKEY) == keys[1][:4]
    assert keys[0][6] == 1 and keys[1][6] == 2      # material 段各留自家值


def test_plan_out_returns_plan_matching_tasks_in_order():
    """`plan_out`（runtime 接线用）：追加的计划 `kept` 与返回任务**同序**，
    供 runtime 把任务绑定到计划分支下标（release 精确归还）。"""
    pkg = _mpkg(1)
    branches = [_branch(pkg, "panorama", "m:whole"),
                _branch(pkg, "relation_crop", "m:crop:2", pixel_tag=2)]
    ledger = L3TaskBudgetLedger(L3WindowBudget(max_tasks_per_window=3))
    plans = []
    tasks = _planned(pkg, branches, ledger=ledger, plan_out=plans)

    assert len(plans) == 1
    plan = plans[0]
    assert [row["index"] for row in plan["kept"]] == [0, 1]
    assert [t.branch for t in tasks] == [L3BranchKind.PANORAMA,
                                         L3BranchKind.RELATION_CROP]
    assert [t.crop_id for t in tasks] == ["m:whole", "m:crop:2"]
    # 计划额度可按下标精确归还（runtime 设计丢弃/淘汰路径用）
    assert ledger.release(_WKEY, plan["kept"][1]["index"],
                          reason="enqueue_rejected") is True
    cov = ledger.coverage(_WKEY)
    assert cov["tasks_reserved"] == 1
    assert cov["released"][0]["branch_index"] == 1
    # 未注入 plan_out → 不产生副作用（旧行为逐字节不变）
    assert _planned(pkg, branches[:1], ledger=ledger) != []


# ---------------------------------------------------------------------------
# C154 车道 G：同事件跨窗保留帧 → 任务帧序（增测，不删旧断言）
# ---------------------------------------------------------------------------

def _c154_package():
    from scam.win11_materials import MaterialsStore
    store = MaterialsStore()
    for fid in (1, 2):
        assert store.ingest("cam-g", "run-g", 1, fid, _c154_frame(fid),
                            1000.0 + fid, "host_receive", [], 16, 12,
                            material_reason="change_start")
        assert store.attach_result("cam-g", "run-g", 1, fid, "ok", None,
                                   [{"cls": "person", "conf": 0.9,
                                     "bbox": [0.2, 0.3, 0.2, 0.3],
                                     "trackId": 7}],
                                   accepted=True, reject_reason=None)
    return store.take_ready("cam-g")


def _c154_frame(value):
    import numpy as np
    return np.full((12, 16, 3), value % 256, dtype=np.uint8)


def _c154_carried(pool, *, fid, t_ms, window, reason, marker=None):
    """把一批材料并入池并取出一帧（跨窗保留帧的载体）。"""
    from scam.win11_event_materials import observe_window_materials
    pool.observe(
        camera_id="cam-g", run_id="run-g", config_version=1,
        window_key=("cam-g", "run-g", 1, window), window_id=window,
        material_id=f"m{window}",
        frames=[{"frame_id": fid, "frame_bgr": _c154_frame(fid),
                 "t_capture_ms": t_ms, "timestamp_kind": "host_receive"}],
        object_ids=["cam-g:run-g:track:7"], frame_time_kind="host_receive",
        material_reason=reason, turning_marker=marker)
    return None


def _c154_pool_with(event_frames):
    """构造一个绑定来源固定的池，并注入若干 `(fid, t_ms, window, reason)`。"""
    from scam.win11_event_materials import EventMaterialPool

    class _Source:
        def resolve_material_binding(self, *, camera_id, run_id,
                                     config_version, object_ids=(),
                                     frames=(), frame_time_kind=None):
            return {"status": "unique", "reason": None,
                    "binding": {"camera_id": camera_id, "run_id": run_id,
                                "config_version": config_version,
                                "object_id": "cam-g:run-g:track:7",
                                "track_id": 7,
                                "event_id": "cam-g:run-g:event:7",
                                "time_kind": "host_receive", "t_ms": 1.0},
                    "frames": tuple({"frame_id": row.get("frame_id"),
                                     "t_ms": 1.0,
                                     "time_kind": "host_receive"}
                                    for row in frames)}

    pool = EventMaterialPool(binding_source=_Source())
    for fid, t_ms, window, reason in event_frames:
        _c154_carried(pool, fid=fid, t_ms=t_ms, window=window, reason=reason)
    return pool


def _c154_panorama_branch(pkg):
    from scam.win11_l2_contract import FrameIdentity, L3BranchSpec
    cur = pkg.cur
    identity = FrameIdentity(
        camera_id=pkg.camera_id, run_id=pkg.run_id,
        config_version=pkg.config_version, frame_id=cur.frame_id,
        material_id=pkg.material_id, t_capture_ms=cur.t_capture_ms,
        timestamp_kind=cur.timestamp_kind)
    return L3BranchSpec(
        branch_kind="panorama", identity=identity, crop_ref=None,
        cur_present=True, prev_present=pkg.prev is not None,
        next_present=pkg.nxt is not None, cur_gap_ms=0.0, prev_gap_ms=None,
        next_gap_ms=None, cur_detections=(), prev_detections=None,
        next_detections=None, candidates=(), crop_id=None, region_only=False,
        frame_sequence=())


def test_c154_carried_frames_merge_into_panorama_with_identity_kept():
    """跨窗保留帧与本窗帧合并成**一条按时序**的帧序；身份逐帧保留、不重复。"""
    pkg = _c154_package()
    pool = _c154_pool_with([(90, 500.0, 9, "latest")])
    _c154_carried(pool, fid=91, t_ms=700.0, window=10, reason="latest")
    # 本窗口（5）必须先被观察过，才有"本窗事实绑定"可用（与生产同序）
    _c154_carried(pool, fid=5, t_ms=1002.0, window=5, reason="latest")
    plan = pool.plan_frames(
        window_key=("cam-g", "run-g", 1, 5), window_id=5,
        material_id=pkg.material_id,
        primary=[{"frame_id": 1, "frame_bgr": _c154_frame(1),
                  "t_capture_ms": 1001.0, "timestamp_kind": "host_receive"},
                 {"frame_id": 2, "frame_bgr": _c154_frame(2),
                  "t_capture_ms": 1002.0, "timestamp_kind": "host_receive"}],
        limit=3)
    carried = tuple(frame for frame in plan.frames
                    if tuple(frame.window_key) != plan.window_key)
    assert carried, "必须真的取到跨窗保留帧"
    records = []
    tasks = tasks_from_package(
        pkg=pkg, branches=(_c154_panorama_branch(pkg),),
        crop_images_by_crop_id={}, vocabulary_id="v", vocabulary=(),
        budget=None, window_id=5, budget_ledger=None,
        carried_frames=carried, carried_limit=plan.limit,
        carried_reason="latest", material_selection_out=records.append)
    assert len(tasks) == 1
    task = tasks[0]
    assert len(task.frames) <= plan.limit, "合并结果不得超过派生帧上限"
    times = [fr.t_capture_ms for fr in task.frames
             if fr.frame_bgr is not None]
    assert times == sorted(times), "帧序必须按观察钟升序（首=开始、末=最新）"
    ids = [fr.identity.frame_id for fr in task.frames]
    assert len(ids) == len(set(ids)), "同身份帧只出现一次（幂等去重）"
    for fr in task.frames:
        assert (fr.identity.camera_id, fr.identity.run_id,
                fr.identity.config_version) == ("cam-g", "run-g", 1)
    record = records[0]
    assert record["status"] == "bound"
    assert list(record["sent_frame_ids"]) == ids
    assert record["roles"][0] == "start"
    assert record["roles"][-1] == "latest"


def test_c154_carried_frames_empty_keeps_legacy_task_shape():
    """`carried_frames=()` → 旧路径不变：三序位、无转折标记、无对齐账目。"""
    pkg = _c154_package()
    tasks = tasks_from_package(
        pkg=pkg, branches=(_c154_panorama_branch(pkg),),
        crop_images_by_crop_id={}, vocabulary_id="v", vocabulary=(),
        budget=None, window_id=5, budget_ledger=None)
    assert len(tasks) == 1
    task = tasks[0]
    assert [fr.identity.frame_id for fr in task.frames] == [None, 1, 2]
    assert getattr(task, "turning_positions", None) is None
    assert getattr(task, "turning_positions_source", None) is None


def test_c154_turning_marker_written_only_with_source():
    """转折位次**只在有来源标记**时写入任务（stage 认位次+来源两者齐全）。"""
    pkg = _c154_package()
    pool = _c154_pool_with([(90, 500.0, 9, "latest")])
    _c154_carried(pool, fid=91, t_ms=700.0, window=10, reason="change_start")
    _c154_carried(pool, fid=5, t_ms=1002.0, window=5, reason="latest")
    plan = pool.plan_frames(
        window_key=("cam-g", "run-g", 1, 5), window_id=5,
        material_id=pkg.material_id,
        primary=[{"frame_id": 1, "frame_bgr": _c154_frame(1),
                  "t_capture_ms": 1001.0, "timestamp_kind": "host_receive"},
                 {"frame_id": 2, "frame_bgr": _c154_frame(2),
                  "t_capture_ms": 1002.0, "timestamp_kind": "host_receive"}],
        limit=4)
    carried = tuple(frame for frame in plan.frames
                    if tuple(frame.window_key) != plan.window_key)
    records = []
    tasks = tasks_from_package(
        pkg=pkg, branches=(_c154_panorama_branch(pkg),),
        crop_images_by_crop_id={}, vocabulary_id="v", vocabulary=(),
        budget=None, window_id=5, budget_ledger=None,
        carried_frames=carried, carried_limit=plan.limit,
        carried_reason="latest", material_selection_out=records.append)
    task = tasks[0]
    record = records[0]
    assert record["turning_positions"], "change_start 来源必须保留转折位次"
    assert task.turning_positions == tuple(record["turning_positions"])
    assert task.turning_positions_source == "material_reason:change_start"
    turning_rows = [row for row in record["frames"]
                    if row["role"] == "turning"]
    assert turning_rows, "中间帧（有来源依据）角色为 turning"
    for row in turning_rows:
        assert row["turn_basis"] == "material_reason:change_start"
