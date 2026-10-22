"""win11_l2_crops 测试（C-134 §5 + C-135 §六 B 侧裁图全矩阵；规则 C-133 §3）。

覆盖：双对象联合框+外扩的数值精确断言（归一化 approx、像素框精确）/
边缘框外扩夹取（margin 下限 0.02、clamped 记录、无越界像素）/ 退化框拒收
（NaN/Inf/零宽/负宽高/完全越界，计 omitted 不崩溃）/ 拥挤多候选确定性去重
（IoU≥0.8 合并、来源候选全部保留、距离远不误合并）/ 参与者覆盖不变式
（C-135 §六 B2：合并守卫 + coverage_ratio ≥50% 可见面积 + 构建后
verify_participant_coverage 核验，记录与实际裁图一致）/ 单张预算三判据独
立触发（C-135 §六：area_ratio / pixels_fixed 绝对像素 / bytes 真实 JPEG
计量，取最严；兼容别名行为）/ 联合框超上限整帧替代 / 外扩超上限
context_capped / 分辨率语义（归一化几何一致；绝对像素预算在高分辨率如实
触发——取消按帧面积同比放大）/ 全景兜底记录与图像隔离 / 变化区域兜底
（非法区域跳过、上限截断、预算舍弃显式计数）/ stage 级装配（全景恒保留
槽 0、优先级、合并裁图参与者 ≥50% 覆盖）与 prev=None 显式缺失。

纯引擎直测 + 注入假模型驱 stage；零 I/O（JPEG 编码仅内存内计量）、永不
真调模型、不落盘。
"""

import math

import numpy as np
import pytest

from scam.win11_l2_contract import (
    ChangeRegion,
    CropRecord,
    CropTransform,
    DetectionView,
    FrameIdentity,
    L2Budget,
    L2RelationStage,
    L2Status,
    L2TaskInput,
    ObjectRef,
    RelationCandidate,
    Uncertainty,
)
from scam.win11_l2_crops import (
    CropRequest,
    DEDUP_IOU,
    JPEG_MEASURE_QUALITY,
    MARGIN_RATIO,
    MIN_MARGIN_NORM,
    PARTICIPANT_MIN_COVERAGE,
    UNION_AREA_CAP,
    box_iou,
    build_candidate_crops,
    build_change_region_crops,
    build_whole_frame_crop,
    clamp_box,
    coverage_ratio,
    expand_box,
    is_valid_box,
    jpeg_encoded_bytes,
    norm_box_to_px,
    slice_region,
    union_box,
    verify_participant_coverage,
)

IDENT = FrameIdentity("camA", "r1", "c1", 7, 3, 1000.0, "capture")


# ---- 构造辅助 ---------------------------------------------------------------

class FakeModel:
    """最小假模型（鸭子类型即可满足 stage 注入；不继承不加载）。"""

    model_ref = "fake-relate/crops"

    def __init__(self, triples=()):
        self.triples = tuple(triples)

    def infer(self, frame_bgr, boxes_px, labels, vocabulary):
        return list(self.triples)


def make_frame(value=5, w=200, h=100):
    return np.full((h, w, 3), value, dtype=np.uint8)


def make_candidate(score, relation="holding", frame_id=7):
    return RelationCandidate(
        subject=ObjectRef(f"camA:r1:track:1", frame_id, True),
        obj=ObjectRef(f"camA:r1:track:2", frame_id, True),
        relation=relation, graph="spatial", score_raw=score,
        vocabulary_id="v1", uncertainty=Uncertainty())


def make_request(score, subj_box, obj_box, relation="holding"):
    return CropRequest(make_candidate(score, relation), tuple(subj_box),
                       tuple(obj_box))


def make_task(dets, *, triples=(), change=(), w=200, h=100, prev=None,
              budget=None):
    frame = make_frame(w=w, h=h)
    return L2TaskInput(
        identity=FrameIdentity("camA", "r1", "c1", 7, 3, 1000.0, "capture"),
        frame_bgr=frame, width=w, height=h, detections=tuple(dets),
        l1_status="ok", change_regions=tuple(change), prev=prev, next=None,
        prev_gap_ms=None, next_gap_ms=None, vocabulary_id="v1",
        relation_vocabulary=("holding",), budget=budget or L2Budget())


def det(bbox):
    return DetectionView("person", 0.9, tuple(bbox), None, False)


def _triple(s, o, score):
    return {"s": s, "o": o, "relation": "holding", "graph": "spatial",
            "score": score}


# ---- a. 纯几何助手 -----------------------------------------------------------

def test_union_expand_clamp_math():
    assert union_box((0.1, 0.2, 0.3, 0.4), (0.5, 0.5, 0.2, 0.25)) \
        == pytest.approx((0.1, 0.2, 0.6, 0.55))
    assert expand_box((0.5, 0.5, 0.2, 0.2), 0.1) \
        == pytest.approx((0.4, 0.4, 0.4, 0.4))
    clamped_box, flag = clamp_box((-0.05, 0.9, 0.2, 0.2))
    assert clamped_box == pytest.approx((0.0, 0.9, 0.15, 0.1))
    assert flag is True
    intact_box, flag2 = clamp_box((0.2, 0.2, 0.3, 0.3))
    assert flag2 is False and intact_box == pytest.approx((0.2, 0.2, 0.3, 0.3))
    assert clamp_box((-0.5, 0.5, 0.2, 0.2)) is None      # 夹取后完全出帧退化


def test_box_iou_scale_invariant_and_ordered():
    a = (0.0, 0.0, 0.5, 0.5)
    assert box_iou(a, a) == pytest.approx(1.0)
    assert box_iou(a, (0.25, 0.25, 0.5, 0.5)) == pytest.approx(
        (0.25 * 0.25) / (0.25 + 0.25 - 0.0625))
    assert box_iou(a, (0.9, 0.9, 0.1, 0.1)) == pytest.approx(0.0)
    # 归一化空间与像素空间同值（尺度不变）——去重不因分辨率漂移
    norm_iou = box_iou((0.0, 0.0, 0.5, 0.5), (0.25, 0.0, 0.5, 0.5))
    px_iou = box_iou((0.0, 0.0, 500.0, 500.0), (250.0, 0.0, 500.0, 500.0))
    assert norm_iou == pytest.approx(px_iou)
    assert box_iou((0.0, 0.0, 0.0, 0.0), (0.0, 0.0, 0.1, 0.1)) == 0.0


def test_is_valid_box_rejects_degenerate_and_out_of_frame():
    assert is_valid_box((0.1, 0.1, 0.2, 0.2)) is True
    assert is_valid_box((-0.2, -0.2, 0.3, 0.3)) is True   # 部分出帧合法
    assert is_valid_box((0.95, 0.1, 0.2, 0.2)) is True    # 部分出帧合法
    assert is_valid_box((0.5, 0.5, 0.0, 0.2)) is False    # 零宽
    assert is_valid_box((0.5, 0.5, 0.2, -0.1)) is False   # 负高
    assert is_valid_box((float("nan"), 0.1, 0.1, 0.1)) is False
    assert is_valid_box((0.1, float("inf"), 0.1, 0.1)) is False
    assert is_valid_box((1.5, 0.5, 0.2, 0.2)) is False    # 完全出帧
    assert is_valid_box((0.5, -0.9, 0.2, 0.2)) is False   # 完全出帧（y 向）


def test_norm_box_to_px_exact_and_clamped():
    assert norm_box_to_px((0.1, 0.2, 0.3, 0.4), 200, 100) == (20, 20, 80, 60)
    assert norm_box_to_px((0.15, 0.15, 0.7, 0.45), 200, 100) \
        == (30, 15, 170, 60)
    # 分量夹取（裁决 #1，对齐冻结 §1 bbox_norm (x,y,w,h) 分量语义）：
    # x/y 分量夹到 [0,1] 且保持 w/h 换算——0.2 宽 @200px=40、0.2 高
    # @100px=20，负坐标平移不改变宽高换算。原期望 (0,0,20,20) 混用两种
    # 语义（x2=20 是端点夹取值、y2=20 是分量保持值），任何单一语义下均
    # 不可达，故按裁决语义修正为 (0,0,40,20)。
    assert norm_box_to_px((-0.1, -0.1, 0.2, 0.2), 200, 100) == (0, 0, 40, 20)
    assert norm_box_to_px((0.999, 0.999, 0.01, 0.01), 200, 100) \
        == (199, 99, 200, 100)
    assert norm_box_to_px((0.5, 0.5, 0.0, 0.0), 200, 100) is None  # 退化


def test_slice_region_copies_and_clamps():
    frame = make_frame(value=6)
    crop = slice_region(frame, (10, 10, 50, 40))
    assert crop.shape == (30, 40, 3)
    crop[:] = 0
    assert (frame == 6).all()                             # 隔离副本
    assert slice_region(frame, (150, 10, 500, 40)).shape == (30, 50, 3)
    assert slice_region(frame, (50, 10, 50, 40)) is None  # 退化


def test_coverage_ratio_visible_area_semantics():
    """覆盖比例分母=可见面积：出帧部分物理不可覆盖不计入；完全出帧=1.0。"""
    assert coverage_ratio((0.1, 0.1, 0.2, 0.2), (0.1, 0.1, 0.2, 0.2)) \
        == pytest.approx(1.0)
    assert coverage_ratio((0.1, 0.1, 0.2, 0.2), (0.0, 0.0, 1.0, 1.0)) \
        == pytest.approx(1.0)                             # 全景恒全覆盖
    assert coverage_ratio((0.1, 0.1, 0.2, 0.2), (0.5, 0.5, 0.5, 0.5)) \
        == pytest.approx(0.0)
    # 90% 出帧的参与者：可见部分全在裁框内 → 1.0（分母只取可见 0.1×0.2）
    assert coverage_ratio((0.95, 0.1, 0.2, 0.2), (0.0, 0.0, 1.0, 1.0)) \
        == pytest.approx(1.0)
    # 部分覆盖：交 0.1×0.2 / 可见 0.2×0.2 = 0.5（恰在下限）
    assert coverage_ratio((0.0, 0.0, 0.2, 0.2), (0.1, 0.0, 0.9, 1.0)) \
        == pytest.approx(0.5)
    assert coverage_ratio((1.5, 0.5, 0.2, 0.2), (0.0, 0.0, 1.0, 1.0)) \
        == pytest.approx(1.0)                             # 完全出帧不判违规


# ---- b. 候选裁图主路：联合+外扩数值精确断言 ----------------------------------

def test_union_margin_expansion_exact_values():
    """双对象联合框 + k=0.2 外扩：归一化 approx、像素框与裁图形状精确。"""
    frame = make_frame()
    requests = [make_request(0.9, (0.25, 0.25, 0.25, 0.25),
                             (0.5, 0.25, 0.25, 0.25))]
    records, images, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, requests, L2Budget())
    assert dropped == 0 and notes == ()
    assert len(records) == len(images) == 1
    t = records[0].transform
    # 联合框 x[0.25,0.75] w0.5，y[0.25,0.5] h0.25；margin=0.2*0.5=0.1
    assert t.union_norm == pytest.approx((0.25, 0.25, 0.5, 0.25))
    # margin_ratio 记录实际外扩量（裁决 #2）：基数=长边 k×max(w,h)=0.2×0.5
    # =0.1；系数 k=0.2 由 MARGIN_RATIO 常量断言锁定（见边缘框测试），且本
    # 测试下方 bbox_norm/bbox_px/裁图形状均按 margin=0.1 编码——记录 0.2
    # 将与变换记录自相矛盾。
    assert t.margin_ratio == pytest.approx(0.1)
    assert t.bbox_norm == pytest.approx((0.15, 0.15, 0.7, 0.45))
    assert t.bbox_px == (30, 15, 170, 60)
    assert t.clamped is False and t.context_capped is False
    assert t.whole_frame_fallback is False
    assert images[0].shape == (45, 140, 3)
    # 四要素：变换/参与者/理由/省略（same_region_as 本批恒 None）
    assert records[0].participants == (records[0].reason_candidates[0].subject,
                                       records[0].reason_candidates[0].obj)
    assert len(records[0].reason_candidates) == 1
    assert records[0].omitted == ()
    assert records[0].same_region_as is None
    assert records[0].crop_id == "camA:r1:frame:7:crop:0"
    assert records[0].identity is IDENT


def test_edge_box_clamped_with_margin_floor():
    """边缘框：贴边联合框外扩被夹取；margin 触底 0.02；无越界像素。"""
    frame = make_frame()
    requests = [make_request(0.8, (0.9, 0.9, 0.05, 0.05),
                             (0.93, 0.93, 0.05, 0.05))]
    records, images, dropped, notes = build_candidate_crops(
        frame, 100, 100, IDENT, requests, L2Budget())
    assert dropped == 0 and notes == ()
    t = records[0].transform
    # 联合框 w=0.08 → 0.2*0.08=0.016 < 0.02 → 取下限 0.02
    assert t.margin_ratio == pytest.approx(MIN_MARGIN_NORM)
    assert MARGIN_RATIO == pytest.approx(0.2)             # 冻结建议值不变
    assert t.clamped is True
    assert t.bbox_norm == pytest.approx((0.88, 0.88, 0.12, 0.12))
    assert t.bbox_px == (88, 88, 100, 100)                # 夹到帧边界，无越界
    assert images[0].shape == (12, 12, 3)
    # 裁框仍完整包含双方（夹取后的）参与者框
    assert (t.bbox_px[0] <= 90 and t.bbox_px[2] >= 98
            and t.bbox_px[1] <= 90 and t.bbox_px[3] >= 98)


def test_degenerate_participant_boxes_rejected_and_counted():
    frame = make_frame()
    requests = [
        make_request(0.9, (0.5, 0.5, 0.0, 0.2), (0.7, 0.7, 0.1, 0.1)),
        make_request(0.8, (float("nan"), 0.1, 0.1, 0.1), (0.7, 0.7, 0.1, 0.1)),
        make_request(0.7, (float("inf"), 0.1, 0.1, 0.1), (0.7, 0.7, 0.1, 0.1)),
        make_request(0.6, (1.5, 0.5, 0.2, 0.2), (0.1, 0.1, 0.1, 0.1)),
        make_request(0.5, (0.5, 0.5, -0.1, 0.2), (0.1, 0.1, 0.1, 0.1)),
        make_request(0.95, (0.05, 0.05, 0.2, 0.2), (0.3, 0.05, 0.2, 0.2)),
    ]
    records, images, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, requests, L2Budget())
    assert dropped == 5
    assert notes.count("invalid_participant_box") == 5
    assert len(records) == len(images) == 1               # 唯一合法候选存活
    assert records[0].reason_candidates[0].score_raw == pytest.approx(0.95)


# ---- c. 确定性去重（IoU≥0.8 合并，来源保留）+ 参与者覆盖不变式 ----------------

def test_dedup_merges_high_iou_and_keeps_all_sources():
    frame = make_frame()
    near_a = make_request(0.9, (0.2, 0.2, 0.2, 0.2), (0.5, 0.2, 0.2, 0.2))
    near_b = make_request(0.8, (0.21, 0.2, 0.2, 0.2), (0.51, 0.2, 0.2, 0.2))
    far = make_request(0.7, (0.05, 0.7, 0.1, 0.1), (0.25, 0.7, 0.1, 0.1))
    assert box_iou((0.1, 0.1, 0.7, 0.4), (0.11, 0.1, 0.7, 0.4)) \
        == pytest.approx(0.971830985915, abs=1e-6)        # > 0.8 → 合并
    records, images, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, [near_a, near_b, far], L2Budget())
    assert dropped == 0 and notes == ()
    assert len(records) == 2                              # 重复合并 + 远距离独立
    merged = records[0]                                   # 分数降序：0.9 领衔
    assert merged.merged_count == 1
    assert [c.score_raw for c in merged.reason_candidates] \
        == pytest.approx([0.9, 0.8])                      # 全部来源候选保留
    assert merged.participants[0] is merged.reason_candidates[0].subject
    assert records[1].merged_count == 0
    assert len(records[1].reason_candidates) == 1
    assert len(images) == 2


def test_participant_coverage_invariant_on_merged_records():
    """C-135 §六 B2 参与者覆盖不变式：合并后 CropRecord 的全部参与对象框
    与实际裁框相交 ≥ 其可见面积 50%（构建后核验函数判定）。"""
    frame = make_frame()
    near_a = make_request(0.9, (0.2, 0.2, 0.2, 0.2), (0.5, 0.2, 0.2, 0.2))
    near_b = make_request(0.8, (0.21, 0.2, 0.2, 0.2), (0.51, 0.2, 0.2, 0.2))
    records, _, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, [near_a, near_b], L2Budget())
    assert len(records) == 1 and records[0].merged_count == 1
    assert dropped == 0 and notes == ()
    # 构建后核验：合并记录的全部来源候选参与者均被覆盖
    assert verify_participant_coverage(records, [near_a, near_b]) == ()
    # 逐框断言：每个参与对象框与裁图框相交 ≥ 其可见面积 50%
    crop_norm = records[0].transform.bbox_norm
    for request in (near_a, near_b):
        for box in (request.subject_box_norm, request.object_box_norm):
            assert coverage_ratio(tuple(box), crop_norm) \
                >= PARTICIPANT_MIN_COVERAGE


def test_merge_guard_keeps_record_consistent_with_actual_crop():
    """合并守卫：IoU≥0.8 但新增参与者不被保留裁框覆盖（<50% 可见面积）
    → 不合并、独立成图——不能只追加候选来源却裁掉新增参与者。"""
    frame = make_frame()
    # 领衔裁框 (0,0,0.8,0.5)（外扩超上限 → 不外扩）；合并候选 obj
    # (0.75,0,0.15,0.5) 只有 1/3 可见面积落在其中
    leader = make_request(0.9, (0.0, 0.0, 0.4, 0.5), (0.4, 0.0, 0.4, 0.5))
    outsider = make_request(0.8, (0.0, 0.0, 0.4, 0.5), (0.75, 0.0, 0.15, 0.5))
    assert box_iou((0.0, 0.0, 0.8, 0.5), (0.0, 0.0, 0.9, 0.5)) \
        == pytest.approx(0.888888888888, abs=1e-6)        # ≥ 0.8 触发合并判定
    records, images, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, [leader, outsider], L2Budget())
    assert dropped == 0 and notes == ()
    assert len(records) == len(images) == 2               # 守卫拦截 → 各自成图
    assert records[0].reason_candidates[0].score_raw == pytest.approx(0.9)
    assert records[1].reason_candidates == (outsider.candidate,)
    # 核验通过：每张记录的参与者都真被自己的裁框覆盖
    assert verify_participant_coverage(records, [leader, outsider]) == ()


def test_verify_participant_coverage_flags_violations():
    """核验函数直接单元：覆盖 <50% 的参与者给出 (crop_id, object_id,
    ratio) 违规；不在请求中的候选跳过（无框可查不臆测）。"""
    cand = make_candidate(0.9)
    request = CropRequest(cand, (0.0, 0.0, 0.2, 0.2), (0.9, 0.9, 0.1, 0.1))
    transform = CropTransform((0.0, 0.0, 1.0, 1.0), 0.0,
                              (0.0, 0.0, 0.2, 0.2), (0, 0, 40, 20),
                              False, False, False)
    record = CropRecord("camA:r1:frame:7:crop:0", IDENT, transform,
                        (cand.subject, cand.obj), (cand,), 0, (), None)
    violations = verify_participant_coverage([record], [request])
    assert len(violations) == 1
    crop_id, object_id, ratio = violations[0]
    assert crop_id == "camA:r1:frame:7:crop:0"
    assert object_id == cand.obj.object_id
    assert ratio == pytest.approx(0.0)
    assert verify_participant_coverage([record], []) == ()


def test_dedup_threshold_is_frozen_constant():
    assert DEDUP_IOU == pytest.approx(0.8)
    assert UNION_AREA_CAP == pytest.approx(0.5)
    assert PARTICIPANT_MIN_COVERAGE == pytest.approx(0.5)
    assert JPEG_MEASURE_QUALITY == 85
    # 恰在阈值之下不合并：IoU ≈ 0.786 < 0.8
    assert box_iou((0.1, 0.2, 0.6, 0.55), (0.1, 0.2, 0.7, 0.6)) \
        == pytest.approx(0.785714285714, abs=1e-6)
    assert box_iou((0.1, 0.2, 0.6, 0.55), (0.1, 0.2, 0.7, 0.6)) < DEDUP_IOU


# ---- d. 分辨率语义（C-133 T5 几何一致 + C-135 绝对预算如实触发） --------------

def test_same_norm_boxes_across_resolutions():
    """归一化几何跨分辨率一致；像素判据为绝对上限（C-135 §六取消按帧面积
    同比放大）：同归一化框在 1080p 因 pixels_fixed 触顶被拒——预算的真实
    语义，不再是"高分辨率豁免"。"""
    frame_a = make_frame(w=1920, h=1080)
    frame_b = make_frame(w=320, h=240)
    request = make_request(0.9, (0.25, 0.25, 0.25, 0.25),
                           (0.5, 0.25, 0.25, 0.25))
    rec_a, _, drop_a, notes_a = build_candidate_crops(
        frame_a, 1920, 1080, IDENT, [request], L2Budget())
    rec_b, img_b, drop_b, notes_b = build_candidate_crops(
        frame_b, 320, 240, IDENT, [request], L2Budget())
    # 1080p：裁框 1344×486=653184 像素 > 640×640 绝对上限（area_ratio
    # 0.315 ≤ 0.5 不触发——判据独立）
    assert drop_a == 1 and notes_a == ("crop_pixels_cap",) and rec_a == ()
    # 240p：同一归一化框 224×108=24192 像素 ≤ 上限 → 存活
    assert drop_b == 0 and notes_b == ()
    tb = rec_b[0].transform
    assert tb.bbox_norm == pytest.approx((0.15, 0.15, 0.7, 0.45))
    assert tb.clamped is False and tb.context_capped is False
    assert tb.bbox_px == (48, 36, 272, 144)
    assert img_b[0].shape == (108, 224, 3)


# ---- e. 预算压力（三判据独立触发，显式记账，不静默丢弃） ----------------------

def test_max_crops_budget_keeps_top_scores_and_accounts():
    frame = make_frame()
    requests = []
    for k, score in enumerate((0.9, 0.85, 0.8, 0.75, 0.7)):
        x = 0.05 + 0.18 * k
        requests.append(make_request(score, (x, 0.1, 0.08, 0.08),
                                     (x + 0.09, 0.6, 0.08, 0.08)))
    budget = L2Budget(max_crops=2)      # 兼容别名 → max_crops_total
    assert budget.max_crops_total == 2
    records, images, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, requests, budget)
    assert dropped == 3
    assert notes.count("budget_cap") == 3
    assert len(records) == len(images) == 2
    # 分数降序取舍：保留 0.9 / 0.85
    assert [r.reason_candidates[0].score_raw for r in records] \
        == pytest.approx([0.9, 0.85])
    assert [r.crop_id for r in records] == ["camA:r1:frame:7:crop:0",
                                            "camA:r1:frame:7:crop:1"]


def test_max_crops_total_budget_keeps_top_scores_and_accounts():
    """同上，走 C-135 冻结新字段名（engine 直驱时不预留全景槽）。"""
    frame = make_frame()
    requests = []
    for k, score in enumerate((0.9, 0.85, 0.8, 0.75, 0.7)):
        x = 0.05 + 0.18 * k
        requests.append(make_request(score, (x, 0.1, 0.08, 0.08),
                                     (x + 0.09, 0.6, 0.08, 0.08)))
    records, images, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, requests, L2Budget(max_crops_total=2))
    assert dropped == 3 and notes.count("budget_cap") == 3
    assert len(records) == len(images) == 2
    assert [r.reason_candidates[0].score_raw for r in records] \
        == pytest.approx([0.9, 0.85])


def test_engine_max_records_override_reserves_panorama_slot():
    """stage 装配预留：max_records 显式传入时按剩余槽位截断（全景占槽 0
    后的关系裁图额度由 stage 计算）。"""
    frame = make_frame()
    near = make_request(0.9, (0.2, 0.2, 0.2, 0.2), (0.5, 0.2, 0.2, 0.2))
    far = make_request(0.8, (0.05, 0.7, 0.1, 0.1), (0.25, 0.7, 0.1, 0.1))
    records, images, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, [near, far], L2Budget(max_crops_total=4),
        max_records=1)
    assert len(records) == len(images) == 1
    assert records[0].reason_candidates[0].score_raw == pytest.approx(0.9)
    assert dropped == 1 and notes == ("budget_cap",)


def test_max_crop_pixels_budget_rejects_oversized_crop():
    """兼容别名 max_crop_pixels → max_crop_pixels_fixed：绝对像素判据。"""
    frame = make_frame()
    requests = [make_request(0.9, (0.25, 0.25, 0.25, 0.25),
                             (0.5, 0.25, 0.25, 0.25))]
    budget = L2Budget(max_crop_pixels=100)                # 70x45=3150 px > 100
    records, images, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, requests, budget)
    assert records == () and images == ()
    assert dropped == 1
    assert notes == ("crop_pixels_cap",)


def test_max_crop_pixels_fixed_cap_independent_trigger():
    """pixels_fixed 判据独立触发：area_ratio（0.315 ≤ 0.5）不拦、bytes
    上限默认宽松，仅绝对像素触顶。"""
    frame = make_frame()
    requests = [make_request(0.9, (0.25, 0.25, 0.25, 0.25),
                             (0.5, 0.25, 0.25, 0.25))]
    budget = L2Budget(max_crop_pixels_fixed=100)
    records, images, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, requests, budget)
    assert records == () and images == ()
    assert dropped == 1 and notes == ("crop_pixels_cap",)


def test_max_crop_area_ratio_cap_independent_trigger():
    """area_ratio 判据独立触发：裁框占帧 0.315 > 0.05；像素 140×45=6300
    ≤ 默认 pixels_fixed、JPEG 字节 ≤ 默认 bytes 上限——仅比例触顶。"""
    frame = make_frame()
    requests = [make_request(0.9, (0.25, 0.25, 0.25, 0.25),
                             (0.5, 0.25, 0.25, 0.25))]
    budget = L2Budget(max_crop_area_ratio=0.05)
    records, images, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, requests, budget)
    assert records == () and images == ()
    assert dropped == 1 and notes == ("crop_area_ratio_cap",)


def test_max_crop_bytes_cap_measures_real_jpeg_and_triggers():
    """bytes 判据独立触发：JPEG 编码仅内存内计量（不落盘），实测字节数
    真实 > 100；默认档不触发。"""
    frame = make_frame()
    requests = [make_request(0.9, (0.25, 0.25, 0.25, 0.25),
                             (0.5, 0.25, 0.25, 0.25))]
    budget = L2Budget(max_crop_bytes=100)
    records, images, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, requests, budget)
    assert records == () and images == ()
    assert dropped == 1 and notes == ("crop_bytes_cap",)
    # 计量真实性：同框实测编码字节确实超限（真实 JPEG，非估算/拍脑袋）
    measured = jpeg_encoded_bytes(slice_region(frame, (30, 15, 170, 60)))
    assert measured is not None and measured > 100
    # 宽松上限（默认档）同图不触发
    ok_records, _, ok_dropped, ok_notes = build_candidate_crops(
        frame, 200, 100, IDENT, requests, L2Budget())
    assert len(ok_records) == 1 and ok_dropped == 0 and ok_notes == ()


def test_bytes_budget_unmeasurable_recorded_not_faked(monkeypatch):
    """编码器不可用：字节预算无法计量→如实记账并放行，绝不用估算冒充。"""
    import scam.win11_l2_crops as crops_mod
    monkeypatch.setattr(crops_mod, "jpeg_encoded_bytes", lambda image: None)
    frame = make_frame()
    requests = [make_request(0.9, (0.25, 0.25, 0.25, 0.25),
                             (0.5, 0.25, 0.25, 0.25))]
    records, images, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, requests, L2Budget(max_crop_bytes=1))
    assert len(records) == len(images) == 1 and dropped == 0
    assert notes == ("bytes_budget_unmeasurable",)


def test_max_crops_zero_yields_nothing():
    frame = make_frame()
    requests = [make_request(0.9, (0.25, 0.25, 0.25, 0.25),
                             (0.5, 0.25, 0.25, 0.25))]
    records, _, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, requests, L2Budget(max_crops=0))
    assert records == () and dropped == 1
    assert notes == ("budget_cap",)


# ---- f. 面积上限：整帧替代与 context_capped ----------------------------------

def test_union_over_area_cap_substitutes_whole_frame():
    frame = make_frame()
    requests = [make_request(0.9, (0.0, 0.0, 0.6, 0.6), (0.4, 0.4, 0.6, 0.6))]
    records, images, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, requests, L2Budget())
    assert dropped == 0 and notes == ()                   # 替代不是丢弃
    t = records[0].transform
    assert t.whole_frame_fallback is True                 # 整帧替代标注
    assert t.context_capped is False
    assert t.bbox_norm == (0.0, 0.0, 1.0, 1.0)
    assert t.bbox_px == (0, 0, 200, 100)
    # 省略理由如实记录（与全景分支重叠）
    assert records[0].omitted \
        == ("union_over_area_cap:whole_frame_substituted",)
    assert images[0].shape == (100, 200, 3)


def test_expansion_over_area_cap_context_capped_no_expansion():
    frame = make_frame()
    # 联合框 (0.1,0.1,0.55,0.55) 面积 0.3025 ≤ 0.5；margin=0.11 外扩后
    # (−0.01,−0.01,0.77,0.77) 面积 0.5929 > 0.5 → 不再外扩
    requests = [make_request(0.9, (0.1, 0.1, 0.3, 0.3), (0.35, 0.35, 0.3, 0.3))]
    records, images, dropped, notes = build_candidate_crops(
        frame, 200, 100, IDENT, requests, L2Budget())
    assert dropped == 0 and notes == ()
    t = records[0].transform
    assert t.context_capped is True                       # 不再外扩标注
    assert t.whole_frame_fallback is False
    assert t.margin_ratio == pytest.approx(0.0)           # 实际外扩量为 0
    assert t.bbox_norm == pytest.approx((0.1, 0.1, 0.55, 0.55))
    assert t.clamped is False
    assert t.bbox_px == (20, 10, 130, 65)
    assert images[0].shape == (55, 110, 3)


# ---- g. 全景与变化区域支路（构建纯函数；并存不互替） -------------------------

def test_whole_frame_fallback_record_and_isolation():
    frame = make_frame(value=5)
    record, image = build_whole_frame_crop(frame, IDENT)
    assert record.crop_id == "camA:r1:frame:7:crop:whole"
    t = record.transform
    assert t.whole_frame_fallback is True
    assert t.bbox_norm == (0.0, 0.0, 1.0, 1.0)
    assert t.bbox_px == (0, 0, 200, 100)
    assert record.participants == () and record.reason_candidates == ()
    assert record.omitted == ()
    assert image.shape == (100, 200, 3)
    image[:] = 0
    assert (frame == 5).all()                             # 改写兜底图不污染帧


def test_whole_frame_crop_accepts_participants():
    """C-135 §六：全景参与者=全部参与对象（显式传入，零对象显式为空）。"""
    frame = make_frame(value=5)
    ref_a = ObjectRef("camA:r1:track:1", 7, True)
    ref_b = ObjectRef("camA:r1:track:2", 7, True)
    record, image = build_whole_frame_crop(frame, IDENT,
                                           participants=(ref_a, ref_b))
    assert record.participants == (ref_a, ref_b)
    assert record.reason_candidates == ()
    assert record.transform.bbox_norm == (0.0, 0.0, 1.0, 1.0)
    assert image.shape == (100, 200, 3)


def test_change_region_crops_valid_invalid_and_cap():
    frame = make_frame()
    regions = [(0.1, 0.1, 0.2, 0.2), (0.5, 0.5, 0.0, 0.1),
               (1.5, 0.5, 0.2, 0.2), (0.6, 0.6, 0.3, 0.3)]
    records, images, budget_dropped = build_change_region_crops(
        frame, 200, 100, IDENT, regions, max_crops=4)
    assert len(records) == len(images) == 2               # 非法区域跳过
    assert budget_dropped == 0                            # 槽位充足无舍弃
    assert records[0].crop_id == "camA:r1:frame:7:chg:0"
    assert records[0].transform.bbox_norm == pytest.approx((0.1, 0.1, 0.2, 0.2))
    assert records[0].transform.bbox_px == (20, 10, 60, 30)
    assert records[1].crop_id == "camA:r1:frame:7:chg:1"
    assert records[1].transform.bbox_px == (120, 60, 180, 90)
    assert records[0].participants == ()
    assert records[0].reason_candidates == ()
    # 上限截断：max_crops=1 只产第一个合法区域；被预算舍弃的区域显式计数
    records_1, images_1, budget_dropped_1 = build_change_region_crops(
        frame, 200, 100, IDENT, regions, max_crops=1)
    assert len(records_1) == 1
    assert budget_dropped_1 == 1                          # 第二块合法区域被舍弃
    assert records_1[0].crop_id.endswith(":chg:0")
    # 零槽位：全部合法区域计入预算舍弃
    _, _, budget_dropped_0 = build_change_region_crops(
        frame, 200, 100, IDENT, regions, max_crops=0)
    assert budget_dropped_0 == 2
    # 边缘区域夹取
    records_c, _, budget_dropped_c = build_change_region_crops(
        frame, 200, 100, IDENT, [(0.9, 0.9, 0.2, 0.2)], max_crops=1)
    assert budget_dropped_c == 0
    assert records_c[0].transform.clamped is True
    assert records_c[0].transform.bbox_px == (180, 90, 200, 100)


# ---- h. stage 级装配（全景恒保留槽 0 + 优先级 + 覆盖不变式） -----------------

def test_stage_fallback_whole_frame_and_change_regions_coexist():
    """无候选/失败：全景与变化区域兜底并存不互替；全景参与者=全部可用
    对象（C-135 §六）；prev=None 显式缺失。"""
    dets = (det((0.1, 0.2, 0.3, 0.4)), det((0.5, 0.5, 0.2, 0.25)))
    change = (ChangeRegion(0.1, 0.1, 0.2, 0.2), ChangeRegion(0.6, 0.6, 0.3, 0.3))
    stage = L2RelationStage(FakeModel(()))                # 模型无关系输出
    out = stage.process(make_task(dets, change=change))
    assert out.status is L2Status.NO_RELATION_ABOVE_FLOOR
    kinds = [c.transform.whole_frame_fallback for c in out.crops]
    assert kinds == [True, False, False]                  # 全景 + 两块局部并存
    ids = [c.crop_id for c in out.crops]
    assert ids[0].endswith(":crop:whole")
    assert ids[1].endswith(":chg:0") and ids[2].endswith(":chg:1")
    # 全景参与者=全部可用对象（帧内标识，引用不伪造）；变化区域无对象语义
    assert [ref.object_id for ref in out.crops[0].participants] \
        == ["camA:r1:frame:7:det:0", "camA:r1:frame:7:det:1"]
    assert out.crops[1].participants == () and out.crops[2].participants == ()
    assert all(c.reason_candidates == () for c in out.crops)
    assert len(out.crop_images) == len(out.crops)
    assert all(img is not None for img in out.crop_images)
    assert out.omission.crops_dropped == 0
    # prev=None 显式缺失：不产任何 prev 证据（identity 只有 cur）
    assert out.identity.frame_id == 7
    assert all(c.identity.frame_id == 7 for c in out.crops)
    # L3 分支一一对应：种类/缺失显式
    assert [b.branch_kind for b in out.l3_branches] \
        == ["panorama", "change_region", "change_region"]
    assert all(b.prev_detections is None for b in out.l3_branches)


def test_stage_model_failure_fallback_still_produces_both_branches():
    """失败态兜底照常：失败不冒充"无关系"，也不切断全景/变化区域支路。"""

    class Boom(FakeModel):
        def infer(self, frame_bgr, boxes_px, labels, vocabulary):
            raise TimeoutError("over budget")

    dets = (det((0.1, 0.2, 0.3, 0.4)), det((0.5, 0.5, 0.2, 0.25)))
    change = (ChangeRegion(0.1, 0.1, 0.2, 0.2),)
    out = L2RelationStage(Boom()).process(make_task(dets, change=change))
    assert out.status is L2Status.TIMEOUT
    assert out.candidates == ()
    assert [c.transform.whole_frame_fallback for c in out.crops] == [True, False]
    assert len(out.crop_images) == 2
    assert math.isfinite(out.timings_ms["total"])


def test_stage_ok_state_panorama_and_relation_crop_coexist():
    """C-135 §六 核心：有关系候选成功（ok）也保留全景（槽 0，原图整帧切片，
    participants=全部参与对象），与关系裁图并存。"""
    dets = (det((0.25, 0.25, 0.25, 0.25)), det((0.5, 0.25, 0.25, 0.25)))
    out = L2RelationStage(FakeModel((_triple(0, 1, 0.9),))).process(
        make_task(dets))
    assert out.status is L2Status.OK
    assert len(out.candidates) == 1
    pano = out.crops[0]
    assert pano.transform.whole_frame_fallback is True
    assert pano.transform.bbox_px == (0, 0, 200, 100)
    assert [ref.object_id for ref in pano.participants] \
        == ["camA:r1:frame:7:det:0", "camA:r1:frame:7:det:1"]
    assert out.crops[1].transform.whole_frame_fallback is False
    assert len(out.crop_images) == 2
    assert out.crop_images[0].shape == (100, 200, 3)
    assert out.omission.crops_dropped == 0


def test_stage_merged_crop_participants_covered_at_least_half():
    """stage 级覆盖不变式：去重合并后的关系裁图，其 participants 与实际
    裁框相交 ≥ 各自可见面积 50%（记录与实际裁图一致）。"""
    dets = (det((0.2, 0.2, 0.2, 0.2)), det((0.5, 0.2, 0.2, 0.2)))
    out = L2RelationStage(FakeModel((_triple(0, 1, 0.9), _triple(1, 0, 0.8)))
                          ).process(make_task(dets))
    assert out.status is L2Status.OK
    assert len(out.crops) == 2                            # 全景 + 合并裁图
    rel = out.crops[1]
    assert rel.merged_count == 1
    assert len(rel.reason_candidates) == 2                # 来源候选全部保留
    assert rel.participants == (rel.reason_candidates[0].subject,
                                rel.reason_candidates[0].obj)
    for box in (dets[0].bbox_norm, dets[1].bbox_norm):
        assert coverage_ratio(tuple(box), rel.transform.bbox_norm) \
            >= PARTICIPANT_MIN_COVERAGE


def test_stage_max_crops_total_two_priority_panorama_first():
    """stage 级总预算：max_crops_total=2 → 全景 + 1 关系裁图，其余显式
    进 omission；变化区域因无剩余槽位被舍弃并计数。"""
    dets = (det((0.05, 0.05, 0.08, 0.08)), det((0.3, 0.05, 0.08, 0.08)),
            det((0.6, 0.05, 0.08, 0.08)))
    change = (ChangeRegion(0.05, 0.8, 0.1, 0.1),)
    budget = L2Budget(max_crops_total=2)
    out = L2RelationStage(FakeModel((_triple(0, 1, 0.9), _triple(1, 2, 0.8),
                                     _triple(0, 2, 0.7)))).process(
        make_task(dets, change=change, budget=budget))
    assert out.status is L2Status.OK
    assert out.crops[0].transform.whole_frame_fallback is True   # 全景槽 0
    assert len(out.crops) == len(out.crop_images) == 2           # 全景+1 关系
    assert out.crops[1].reason_candidates[0].score_raw == pytest.approx(0.9)
    assert "budget_cap=2" in out.omission.reason
    assert "change_region_budget_cap=1" in out.omission.reason
    assert out.omission.crops_dropped == 3
    assert [b.branch_kind for b in out.l3_branches] \
        == ["panorama", "relation_crop"]
