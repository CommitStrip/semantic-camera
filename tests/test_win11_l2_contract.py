"""win11_l2_contract 测试（C-134 §1/§2/§3/§5 + C-135 §六 的 B 侧分界）。

覆盖：数据形状与字段名冻结（__slots__ 探针）/ L2Budget 新档位默认值与
兼容别名（C-135 §六：max_crops_total 含全景占首位槽 0；area_ratio/
pixels_fixed/bytes 三判据独立验证）/ L2Status 11 态冻结 / 身份校验（五字
段全等助手；prev/next 跨 run/跨 config/跨 material/同 frame_id 错配→
identity_rejected 且不产候选不产裁图不调模型不产分支）/ 状态机矩阵（零
对象/单对象/空词表/非法尺寸/缺帧字节/四类模型异常映射/空三元组/全低于丢
弃线/低分带）/ floor 分层与候选预算（降序取舍、舍弃显式记账）/ ObjectRef
引用不伪造（track 引用仅当 track_id 在场且 stable）/ 坐标唯一切换点
（stage 传给模型的像素框数值断言）/ calibrated 恒 False / timings 分段 /
全景恒保留（ok 态也占槽 0，C-135 §六）/ max_crops_total 优先级装配（全
景 > 关系裁图 > 变化区域，被舍弃区域显式记账）/ L3 有序材料分支（种类/
数量/缺失显式 None/enhanced 恒 None/候选引用与 calibrated 透传）/
C-136 C1/C2 局部连续画面帧序列（同区域真实三帧切片像素断言/缺帧固定序位
显式占位/crop_id 显式映射/region_only 标注/切片只读隔离）/ 兜底
预算开关 / 裁图图像隔离（改写裁图不影响任务帧）/ prev=None 显式缺失的
不确定性标注 / 退化检出框不参与配对。

全部注入假模型（L2RelationModel 子类，永不离线调真模型）；零 I/O、零
cv2（字节预算的引擎侧测试见 test_win11_l2_crops.py）。
"""

import numpy as np
import pytest

from scam.win11_l2_contract import (
    AdapterIsolated,
    ChangeRegion,
    CropRecord,
    CropTransform,
    DetectionView,
    FrameIdentity,
    L2Budget,
    L2Omission,
    L2Output,
    L2RelationModel,
    L2RelationStage,
    L2Status,
    L2TaskInput,
    L3BranchSpec,
    L3LocalFrameSlice,
    ModelUnavailable,
    ObjectRef,
    RelationCandidate,
    Uncertainty,
    adjacent_identity_matches,
    frame_object_ref,
    identity_matches,
)

DET_A = DetectionView("person", 0.9, (0.1, 0.2, 0.3, 0.4), None, False)
DET_B = DetectionView("person", 0.8, (0.5, 0.5, 0.2, 0.25), None, False)
DET_C = DetectionView("person", 0.7, (0.7, 0.7, 0.1, 0.1), None, False)
TRIPLE = {"s": 0, "o": 1, "relation": "holding", "graph": "semantic",
          "score": 0.9}


# ---- 构造辅助 ---------------------------------------------------------------

class FakeModel(L2RelationModel):
    """假模型：记录调用（boxes_px/labels/vocabulary），按脚本返回三元组或
    抛异常——永不真调模型。"""

    def __init__(self, triples=(), exc=None, model_ref="fake-relate/test"):
        self.model_ref = model_ref
        self.triples = tuple(triples)
        self.exc = exc
        self.calls = []

    def infer(self, frame_bgr, boxes_px, labels, vocabulary):
        self.calls.append({
            "boxes_px": [tuple(int(v) for v in box) for box in boxes_px],
            "labels": list(labels),
            "vocabulary": tuple(vocabulary),
        })
        if self.exc is not None:
            raise self.exc
        return list(self.triples)


def make_identity(cam="camA", run="r1", config="c1", frame_id=7,
                  material_id=3, t_capture_ms=1000.0,
                  timestamp_kind="capture"):
    return FrameIdentity(cam, run, config, frame_id, material_id,
                         t_capture_ms, timestamp_kind)


def make_det(cls="person", conf=0.9, bbox=(0.1, 0.1, 0.2, 0.2), track_id=None,
             stable=False):
    return DetectionView(cls, conf, tuple(bbox), track_id, stable)


def make_task(dets=(), *, identity=None, w=200, h=100, value=9, prev=None,
              nxt=None, vocab=("holding",), vocab_id="v1", change=(),
              l1_status="ok", budget=None):
    frame = np.full((h, w, 3), value, dtype=np.uint8)
    return L2TaskInput(
        identity=identity or make_identity(), frame_bgr=frame, width=w,
        height=h, detections=tuple(dets), l1_status=l1_status,
        change_regions=tuple(change), prev=prev, next=nxt,
        prev_gap_ms=None if prev is None else 33.0,
        next_gap_ms=None if nxt is None else 33.0,
        vocabulary_id=vocab_id, relation_vocabulary=tuple(vocab),
        budget=budget or L2Budget())


def triple(s, o, score, relation="holding", graph="spatial"):
    return {"s": s, "o": o, "relation": relation, "graph": graph,
            "score": score}


# ---- a. 数据形状与字段名冻结（C-134 §1 + C-135 §六） -------------------------

SHAPE_CASES = [
    (FrameIdentity, ("camera_id", "run_id", "config_version", "frame_id",
                     "material_id", "t_capture_ms", "timestamp_kind")),
    (DetectionView, ("cls", "conf", "bbox_norm", "track_id", "stable")),
    (ChangeRegion, ("x", "y", "w", "h")),
    (L2TaskInput, ("identity", "frame_bgr", "width", "height", "detections",
                   "l1_status", "change_regions", "prev", "next",
                   "prev_gap_ms", "next_gap_ms", "vocabulary_id",
                   "relation_vocabulary", "budget")),
    # C-135 §六 冻结：max_crops_total（含全景）+ 三判据单张预算；旧字段名
    # max_crops/max_crop_pixels 退为只读兼容 property（不在 __slots__）
    (L2Budget, ("max_candidates", "max_crops_total", "max_crop_area_ratio",
                "max_crop_pixels_fixed", "max_crop_bytes", "relation_floor",
                "low_conf_floor", "whole_frame_fallback",
                "change_region_fallback")),
    (ObjectRef, ("object_id", "frame_id", "stable")),
    (Uncertainty, ("frame_missing_prev", "frame_missing_next",
                   "identity_uncertain", "drift", "pair_overlap_high",
                   "low_confidence")),
    (RelationCandidate, ("subject", "obj", "relation", "graph", "score_raw",
                         "vocabulary_id", "uncertainty")),
    (CropTransform, ("union_norm", "margin_ratio", "bbox_norm", "bbox_px",
                     "clamped", "whole_frame_fallback", "context_capped")),
    (CropRecord, ("crop_id", "identity", "transform", "participants",
                  "reason_candidates", "merged_count", "omitted",
                  "same_region_as")),
    (L2Omission, ("candidates_dropped", "crops_dropped", "reason")),
    # C-135 §六 冻结：L3 有序材料分支规格；C-136 C1/C2 新增 crop_id/
    # region_only/frame_sequence（局部连续画面 + 缺帧固定序位 + 显式映射键）
    (L3BranchSpec, ("branch_kind", "identity", "crop_id", "crop_ref",
                    "frame_sequence", "region_only", "cur_present",
                    "prev_present", "next_present", "cur_gap_ms",
                    "prev_gap_ms", "next_gap_ms", "cur_detections",
                    "prev_detections", "next_detections", "candidates",
                    "calibrated", "enhanced", "omissions")),
    # C-136 C1/C2：局部连续画面帧序列项（固定序位 + 同区域真实切片）
    (L3LocalFrameSlice, ("position", "present", "crop_id", "frame_id",
                         "t_capture_ms", "timestamp_kind", "width", "height",
                         "frame_bgr")),
    (L2Output, ("identity", "status", "error_code", "candidates", "crops",
                "crop_images", "omission", "vocabulary_id", "model_ref",
                "calibrated", "timings_ms", "l3_branches")),
]


def test_frozen_shapes_use_slots_and_field_names():
    for cls, fields in SHAPE_CASES:
        assert tuple(cls.__slots__) == fields, cls.__name__
        probe = object.__new__(cls)          # 不经 __init__ 探针实例
        assert not hasattr(probe, "__dict__"), cls.__name__


def test_l2_budget_defaults_are_frozen_placeholders():
    """C-135 §六 冻结默认档：全部保守占位，原生实测前不宣称达标。"""
    budget = L2Budget()
    assert budget.max_candidates == 8
    assert budget.max_crops_total == 4                   # 含全景（槽 0）
    assert budget.max_crop_area_ratio == pytest.approx(0.5)
    assert budget.max_crop_pixels_fixed == 640 * 640     # 绝对像素上限
    assert budget.max_crop_bytes == 256 * 1024           # JPEG 计量字节上限
    assert budget.relation_floor == pytest.approx(0.20)
    assert budget.low_conf_floor == pytest.approx(0.10)
    assert budget.whole_frame_fallback is True
    assert budget.change_region_fallback is True


def test_l2_budget_legacy_aliases_map_to_new_fields():
    """兼容别名（全局一致裁决）：构造别名映射新字段；同名只读 property 透传；
    新字段显式传入优先于别名。"""
    legacy = L2Budget(max_crops=2, max_crop_pixels=100)
    assert legacy.max_crops_total == 2
    assert legacy.max_crop_pixels_fixed == 100
    assert legacy.max_crops == 2                # 只读别名透传新字段值
    assert legacy.max_crop_pixels == 100
    explicit = L2Budget(max_crops_total=6, max_crops=2)
    assert explicit.max_crops_total == 6        # 新字段显式传入优先
    assert explicit.max_crop_pixels_fixed == 640 * 640
    fresh = L2Budget()
    assert fresh.max_crops == fresh.max_crops_total == 4
    assert fresh.max_crop_pixels == fresh.max_crop_pixels_fixed == 640 * 640


def test_l2_status_members_frozen():
    assert {s.name: s.value for s in L2Status} == {
        "OK": "ok",
        "NO_OBJECTS": "no_objects",
        "SINGLE_OBJECT": "single_object",
        "NO_RELATION_ABOVE_FLOOR": "no_relation_above_floor",
        "LOW_CONFIDENCE_ONLY": "low_confidence_only",
        "MODEL_UNAVAILABLE": "model_unavailable",
        "INFER_FAILED": "infer_failed",
        "TIMEOUT": "timeout",
        "BACKEND_ISOLATED": "backend_isolated",
        "IDENTITY_REJECTED": "identity_rejected",
        "UNSUPPORTED": "unsupported",
    }
    assert len(L2Status) == 11


def test_uncertainty_defaults_all_false():
    unc = Uncertainty()
    assert (unc.frame_missing_prev is False
            and unc.frame_missing_next is False
            and unc.identity_uncertain is False
            and unc.drift is False
            and unc.pair_overlap_high is False
            and unc.low_confidence is False)


def test_l3_branch_spec_defaults_explicit():
    """enhanced 恒 None（显式未增强）、calibrated 恒 False、region_only
    恒 True（同区域不保证同一对象）、crop_id/frame_sequence 缺省空为
    构造默认（C-135 §六 + C-136 C1/C2）。"""
    identity = make_identity()
    branch = L3BranchSpec("panorama", identity, None, True, False, False,
                          0.0, None, None, (), None, None, ())
    assert branch.calibrated is False
    assert branch.enhanced is None
    assert branch.omissions == ()
    assert branch.crop_id is None
    assert branch.region_only is True
    assert branch.frame_sequence == ()


# ---- b. 身份校验（M1 五字段；identity_rejected 不产出） ----------------------

def test_identity_matches_requires_all_five_fields():
    base = make_identity()
    assert identity_matches(base, make_identity()) is True
    for override in ({"cam": "camB"}, {"run": "r9"}, {"config": "c9"},
                     {"frame_id": 8}, {"material_id": 4}):
        assert identity_matches(base, make_identity(**override)) is False


def test_adjacent_identity_matches_curates_prev_next():
    cur = make_identity(frame_id=7)
    assert adjacent_identity_matches(cur, make_identity(frame_id=6)) is True
    assert adjacent_identity_matches(cur, make_identity(frame_id=7)) is False
    assert adjacent_identity_matches(cur, make_identity(run="r9",
                                                        frame_id=6)) is False
    assert adjacent_identity_matches(cur, make_identity(config="c9",
                                                        frame_id=6)) is False
    assert adjacent_identity_matches(cur, make_identity(material_id=4,
                                                        frame_id=6)) is False
    assert adjacent_identity_matches(cur, None) is False


def _assert_rejected(out, model, slot):
    assert out.status is L2Status.IDENTITY_REJECTED
    assert out.error_code == f"identity_mismatch:{slot}"
    assert out.candidates == () and out.crops == ()     # 不产出
    assert out.crop_images == ()
    assert out.l3_branches == ()                        # 不产 L3 分支
    assert model.calls == []                            # 不调模型
    assert out.calibrated is False


def test_prev_cross_run_rejected():
    model = FakeModel((TRIPLE,))
    stage = L2RelationStage(model)
    prev = make_task(identity=make_identity(run="r0", frame_id=6))
    out = stage.process(make_task(dets=(DET_A, DET_B), prev=prev))
    _assert_rejected(out, model, "prev")


def test_prev_cross_config_rejected():
    model = FakeModel((TRIPLE,))
    stage = L2RelationStage(model)
    prev = make_task(identity=make_identity(config="c0", frame_id=6))
    out = stage.process(make_task(dets=(DET_A, DET_B), prev=prev))
    _assert_rejected(out, model, "prev")


def test_prev_cross_material_rejected():
    model = FakeModel((TRIPLE,))
    stage = L2RelationStage(model)
    prev = make_task(identity=make_identity(material_id=99, frame_id=6))
    out = stage.process(make_task(dets=(DET_A, DET_B), prev=prev))
    _assert_rejected(out, model, "prev")


def test_prev_same_frame_id_rejected():
    model = FakeModel((TRIPLE,))
    stage = L2RelationStage(model)
    prev = make_task(identity=make_identity(frame_id=7))   # 同 frame_id 冒充
    out = stage.process(make_task(dets=(DET_A, DET_B), prev=prev))
    _assert_rejected(out, model, "prev")


def test_next_cross_camera_rejected():
    model = FakeModel((TRIPLE,))
    stage = L2RelationStage(model)
    nxt = make_task(identity=make_identity(cam="camB", frame_id=8))
    out = stage.process(make_task(dets=(DET_A, DET_B), nxt=nxt))
    _assert_rejected(out, model, "next")


def test_valid_adjacent_identity_not_rejected():
    model = FakeModel((TRIPLE,))
    stage = L2RelationStage(model)
    prev = make_task(identity=make_identity(frame_id=6))
    nxt = make_task(identity=make_identity(frame_id=8))
    out = stage.process(make_task(dets=(DET_A, DET_B), prev=prev, nxt=nxt))
    assert out.status is L2Status.OK
    assert out.candidates[0].uncertainty.frame_missing_prev is False
    assert out.candidates[0].uncertainty.frame_missing_next is False


# ---- c. 状态机矩阵（零对象/单对象/结构校验/模型异常） ------------------------

def test_zero_objects_no_objects_with_fallback_and_no_model_call():
    model = FakeModel((TRIPLE,))
    change = (ChangeRegion(0.1, 0.1, 0.2, 0.2),)
    out = L2RelationStage(model).process(
        make_task(dets=(), change=change))
    assert out.status is L2Status.NO_OBJECTS
    assert out.error_code is None
    assert out.candidates == ()
    assert model.calls == []                             # 零对象不调模型
    # 兜底：全景 + 变化区域并存不互替
    assert [c.transform.whole_frame_fallback for c in out.crops] \
        == [True, False]
    assert out.crop_images[0].shape == (100, 200, 3)
    assert len(out.crop_images) == len(out.crops) == 2
    # L3 分支与裁图一一对应；零对象全景参与者显式为空
    assert [b.branch_kind for b in out.l3_branches] \
        == ["panorama", "change_region"]
    assert out.crops[0].participants == ()


def test_single_object_single_object_no_pair_no_model_call():
    model = FakeModel((TRIPLE,))
    out = L2RelationStage(model).process(make_task(dets=(DET_A,)))
    assert out.status is L2Status.SINGLE_OBJECT
    assert out.candidates == ()
    assert model.calls == []
    assert len(out.crops) == 1                            # 全景兜底
    assert out.crops[0].transform.whole_frame_fallback is True


def test_empty_vocabulary_unsupported_no_model_call():
    model = FakeModel((TRIPLE,))
    out = L2RelationStage(model).process(
        make_task(dets=(DET_A, DET_B), vocab=()))
    assert out.status is L2Status.UNSUPPORTED
    assert out.error_code == "empty_vocabulary"
    assert out.candidates == () and out.crops == ()       # 结构性不可处理不产裁图
    assert out.l3_branches == ()                          # 也不产 L3 分支
    assert model.calls == []


def test_invalid_frame_size_unsupported():
    model = FakeModel((TRIPLE,))
    out = L2RelationStage(model).process(
        make_task(dets=(DET_A, DET_B), w=0, h=0))
    assert out.status is L2Status.UNSUPPORTED
    assert out.error_code == "invalid_frame_size"
    assert out.crops == ()
    assert out.l3_branches == ()
    assert model.calls == []


def test_missing_frame_bytes_unsupported():
    model = FakeModel((TRIPLE,))
    task = make_task(dets=(DET_A, DET_B))
    bare = L2TaskInput(task.identity, None, task.width, task.height,
                       task.detections, task.l1_status,
                       task.change_regions, None, None, None, None,
                       task.vocabulary_id, task.relation_vocabulary,
                       task.budget)
    out = L2RelationStage(model).process(bare)
    assert out.status is L2Status.UNSUPPORTED
    assert out.error_code == "missing_frame"


@pytest.mark.parametrize("exc,status,code", [
    (AdapterIsolated("poisoned executor"), L2Status.BACKEND_ISOLATED,
     "backend_isolated"),
    (TimeoutError("infer over budget"), L2Status.TIMEOUT, "timeout"),
    (ModelUnavailable("missing checkpoint"), L2Status.MODEL_UNAVAILABLE,
     "model_unavailable"),
    (RuntimeError("upstream boom"), L2Status.INFER_FAILED, "infer_failed"),
])
def test_model_exception_mapping(exc, status, code):
    model = FakeModel(exc=exc, model_ref="fake-relate/test")
    out = L2RelationStage(model).process(make_task(dets=(DET_A, DET_B)))
    assert out.status is status
    assert out.error_code == code
    assert out.candidates == ()
    assert len(model.calls) == 1
    # 失败态不切断兜底：全景照常产出；失败不冒充"无关系/零对象"
    assert len(out.crops) == 1
    assert out.crops[0].transform.whole_frame_fallback is True
    assert out.crop_images[0] is not None
    assert out.model_ref == "fake-relate/test"
    assert out.omission.candidates_dropped == 0
    assert out.omission.crops_dropped == 0


def test_empty_triples_reports_no_candidates_code():
    model = FakeModel(())
    out = L2RelationStage(model).process(make_task(dets=(DET_A, DET_B)))
    assert out.status is L2Status.NO_RELATION_ABOVE_FLOOR
    assert out.error_code == "no_candidates"
    assert out.candidates == ()
    assert len(out.crops) == 1                            # 全景兜底并存
    assert out.crops[0].transform.whole_frame_fallback is True


def test_all_below_low_floor_no_relation_above_floor():
    model = FakeModel((triple(0, 1, 0.05),))
    out = L2RelationStage(model).process(make_task(dets=(DET_A, DET_B)))
    assert out.status is L2Status.NO_RELATION_ABOVE_FLOOR
    assert out.error_code == "below_floor"
    assert out.candidates == ()
    assert out.omission.candidates_dropped == 1
    assert "below_low_conf_floor=1" in out.omission.reason
    assert len(out.crops) == 1                            # 全景兜底


def test_low_confidence_only_band_kept_as_reference():
    model = FakeModel((triple(0, 1, 0.15), triple(1, 0, 0.12)))
    out = L2RelationStage(model).process(make_task(dets=(DET_A, DET_B)))
    assert out.status is L2Status.LOW_CONFIDENCE_ONLY
    assert out.error_code is None
    assert len(out.candidates) == 2
    assert all(c.uncertainty.low_confidence is True for c in out.candidates)
    assert [c.score_raw for c in out.candidates] == pytest.approx([0.15, 0.12])
    # 低分候选只作参考；C-135 §六 全景恒保留：全景槽 0 + 同对对象合并裁图
    assert [c.transform.whole_frame_fallback for c in out.crops] \
        == [True, False]
    assert out.crops[1].merged_count == 1
    assert out.crops[1].transform.whole_frame_fallback is False


# ---- d. floor 分层与候选预算 -------------------------------------------------

def test_floor_layering_ok_state_keeps_above_floor_only_desc():
    model = FakeModel((triple(0, 1, 0.9), triple(0, 2, 0.6),
                       triple(1, 2, 0.15), triple(2, 1, 0.05)))
    out = L2RelationStage(model).process(
        make_task(dets=(DET_A, DET_B, DET_C)))
    assert out.status is L2Status.OK
    assert out.error_code is None
    assert [c.score_raw for c in out.candidates] == pytest.approx([0.9, 0.6])
    assert out.omission.candidates_dropped == 2
    assert "below_relation_floor=1" in out.omission.reason
    assert "below_low_conf_floor=1" in out.omission.reason
    # C-135 §六 全景恒保留：全景槽 0 + 两个不同区域的关系裁图
    assert [c.transform.whole_frame_fallback for c in out.crops] \
        == [True, False, False]
    assert len(out.crop_images) == 3
    assert out.calibrated is False


def test_candidate_budget_cap_drops_lowest_scores():
    model = FakeModel((triple(0, 1, 0.9), triple(0, 2, 0.8),
                       triple(1, 2, 0.7)))
    budget = L2Budget(max_candidates=2)
    out = L2RelationStage(model).process(
        make_task(dets=(DET_A, DET_B, DET_C), budget=budget))
    assert out.status is L2Status.OK
    assert len(out.candidates) == 2
    assert [c.score_raw for c in out.candidates] == pytest.approx([0.9, 0.8])
    assert out.omission.candidates_dropped == 1
    assert "candidates_budget_cap=1" in out.omission.reason


def test_custom_floors_respected():
    model = FakeModel((triple(0, 1, 0.65), triple(0, 2, 0.5)))
    budget = L2Budget(relation_floor=0.6, low_conf_floor=0.4)
    out = L2RelationStage(model).process(
        make_task(dets=(DET_A, DET_B, DET_C), budget=budget))
    assert out.status is L2Status.OK
    assert [c.score_raw for c in out.candidates] == pytest.approx([0.65])


# ---- e. 全景恒保留 + 总预算优先级（C-135 §六 B1/B2） -------------------------

def test_ok_state_keeps_panorama_at_slot_zero_with_all_participants():
    """有关系候选成功（ok）也保留全景 CropRecord（不是 fallback 专属）：
    原图整帧切片占槽 0，participants=全部参与对象。"""
    model = FakeModel((TRIPLE,))
    out = L2RelationStage(model).process(make_task(dets=(DET_A, DET_B)))
    assert out.status is L2Status.OK
    pano = out.crops[0]
    assert pano.transform.whole_frame_fallback is True
    assert pano.crop_id.endswith(":crop:whole")
    assert pano.transform.bbox_norm == (0.0, 0.0, 1.0, 1.0)
    assert pano.transform.bbox_px == (0, 0, 200, 100)
    assert out.crop_images[0].shape == (100, 200, 3)
    assert [ref.object_id for ref in pano.participants] \
        == ["camA:r1:frame:7:det:0", "camA:r1:frame:7:det:1"]
    # 全景与关系裁图并存（不再"有裁图就不补全景"）
    assert len(out.crops) == len(out.crop_images) == 2
    assert out.crops[1].transform.whole_frame_fallback is False
    assert len(out.l3_branches) == 2


def test_max_crops_total_two_keeps_panorama_plus_top_relation_rest_omitted():
    """max_crops_total 含全景、全景占首位槽：=2 时全景 + 1 关系裁图，
    其余关系裁图与变化区域进 omission（显式原因 + 数量）。"""
    model = FakeModel((triple(0, 1, 0.9), triple(1, 2, 0.8),
                       triple(0, 2, 0.7)))
    change = (ChangeRegion(0.05, 0.05, 0.1, 0.1),)
    budget = L2Budget(max_crops_total=2)
    out = L2RelationStage(model).process(
        make_task(dets=(DET_A, DET_B, DET_C), change=change, budget=budget))
    assert out.status is L2Status.OK
    assert out.crops[0].transform.whole_frame_fallback is True   # 全景槽 0
    assert len(out.crops) == len(out.crop_images) == 2           # 全景+1 关系
    assert out.crops[1].reason_candidates[0].score_raw == pytest.approx(0.9)
    # 被预算舍弃的区域显式记录（原因 + 数量）：2 张关系裁图 + 1 块变化区域
    assert "budget_cap=2" in out.omission.reason
    assert "change_region_budget_cap=1" in out.omission.reason
    assert out.omission.crops_dropped == 3
    # L3 分支与存留裁图一一对应
    assert [b.branch_kind for b in out.l3_branches] \
        == ["panorama", "relation_crop"]


def test_change_region_budget_dropped_counted_at_stage():
    """变化区域消费剩余槽位；因预算未产出的合法区域显式计数。"""
    model = FakeModel(())                    # 无关系候选
    change = (ChangeRegion(0.05, 0.05, 0.1, 0.1),
              ChangeRegion(0.4, 0.4, 0.1, 0.1),
              ChangeRegion(0.8, 0.8, 0.1, 0.1))
    budget = L2Budget(max_crops_total=2)
    out = L2RelationStage(model).process(
        make_task(dets=(DET_A, DET_B), change=change, budget=budget))
    assert out.status is L2Status.NO_RELATION_ABOVE_FLOOR
    assert len(out.crops) == 2               # 全景 + 1 块变化区域
    assert out.crops[1].crop_id.endswith(":chg:0")
    assert "change_region_budget_cap=2" in out.omission.reason
    assert out.omission.crops_dropped == 2
    assert [b.branch_kind for b in out.l3_branches] \
        == ["panorama", "change_region"]


def test_panorama_budget_cap_when_total_zero():
    """总额度为 0：全景也被预算舍弃并显式记账（不静默）。"""
    model = FakeModel((TRIPLE,))
    budget = L2Budget(max_crops_total=0)
    out = L2RelationStage(model).process(
        make_task(dets=(DET_A, DET_B), budget=budget))
    assert out.crops == () and out.crop_images == ()
    assert out.l3_branches == ()
    assert "panorama_budget_cap=1" in out.omission.reason
    assert "budget_cap=1" in out.omission.reason     # 关系裁图同样无槽位
    assert out.omission.crops_dropped == 2


# ---- f. L3 有序材料分支（C-135 §六 B3） --------------------------------------

def test_l3_branches_ok_state_kinds_candidates_and_participants():
    """分支数量/种类与 crops 一一对应；全景带全帧检测与全部候选引用；
    关系分支携带该裁图参与者的框（归一化）与其来源候选。"""
    model = FakeModel((triple(0, 1, 0.9), triple(0, 2, 0.6)))
    task = make_task(dets=(DET_A, DET_B, DET_C))
    out = L2RelationStage(model).process(task)
    branches = out.l3_branches
    assert len(out.crops) == len(branches) == 3
    assert [b.branch_kind for b in branches] \
        == ["panorama", "relation_crop", "relation_crop"]
    pano = branches[0]
    assert pano.identity is task.identity              # 四元+material_id
    assert pano.crop_ref is out.crops[0].transform     # 原图↔裁图对应
    assert pano.crop_ref.whole_frame_fallback is True
    assert pano.cur_detections == task.detections      # 全帧检测清单
    assert pano.candidates == out.candidates           # 候选引用（非复制）
    rel1, rel2 = branches[1], branches[2]
    assert rel1.crop_ref is out.crops[1].transform
    assert rel1.candidates == out.crops[1].reason_candidates
    assert rel1.cur_detections == (DET_A, DET_B)       # 参与者的框
    assert rel2.cur_detections == (DET_A, DET_C)
    # 坐标语义：映射全部经由 crop_ref——bbox_norm 整帧归一化 ∈[0,1]，
    # bbox_px 整帧像素且落在帧内（分支本体不另造像素坐标）
    for branch in (rel1, rel2):
        nx, ny, nw, nh = branch.crop_ref.bbox_norm
        assert all(0.0 <= v <= 1.0 for v in (nx, ny, nw, nh))
        x1, y1, x2, y2 = branch.crop_ref.bbox_px
        assert 0 <= x1 < x2 <= 200 and 0 <= y1 < y2 <= 100


def test_l3_branch_missing_prev_next_explicit_none_not_fabricated():
    """prev/next 缺失显式 None：材料包不携带前后帧检测，绝不复制当前帧框
    冒充；存在性/gap 如实；enhanced 恒 None、calibrated 恒 False。"""
    model = FakeModel((TRIPLE,))
    task = make_task(dets=(DET_A, DET_B))
    out = L2RelationStage(model).process(task)
    assert len(out.l3_branches) == 2
    for branch, record in zip(out.l3_branches, out.crops):
        assert branch.cur_present is True
        assert branch.prev_present is False and branch.next_present is False
        assert branch.prev_detections is None
        assert branch.next_detections is None
        assert branch.cur_gap_ms == 0.0
        assert branch.prev_gap_ms is None and branch.next_gap_ms is None
        assert branch.enhanced is None                 # 显式未增强
        assert branch.calibrated is False
        assert branch.omissions == record.omitted      # 分支级省略透传


def test_l3_branch_prev_present_reports_prev_own_detections():
    """prev 在场：prev_detections 如实携带 prev 帧自带检测（非 cur 复制），
    gap 如实。"""
    model = FakeModel((TRIPLE,))
    prev_det = make_det(bbox=(0.0, 0.0, 0.1, 0.1))
    prev = make_task(dets=(prev_det,), identity=make_identity(frame_id=6))
    task = make_task(dets=(DET_A, DET_B), prev=prev)
    out = L2RelationStage(model).process(task)
    assert out.status is L2Status.OK
    assert len(out.l3_branches) == 2
    for branch in out.l3_branches:
        assert branch.prev_present is True
        assert branch.prev_detections == (prev_det,)   # prev 自带，非冒充
        assert branch.prev_gap_ms == 33.0
        assert branch.next_present is False
        assert branch.next_detections is None
    # 当前帧检测不被误写进 prev 槽（prev_detections is not cur 清单）
    assert out.l3_branches[0].prev_detections != task.detections


def test_l3_change_region_branch_has_no_object_semantics():
    """变化区域分支：来自门控无对象语义——cur_detections/candidates 为空，
    omissions 透传对应 CropRecord。"""
    model = FakeModel(())
    change = (ChangeRegion(0.1, 0.1, 0.2, 0.2),)
    out = L2RelationStage(model).process(
        make_task(dets=(DET_A, DET_B), change=change))
    assert len(out.crops) == len(out.l3_branches) == 2
    region_branch = out.l3_branches[1]
    assert region_branch.branch_kind == "change_region"
    assert region_branch.cur_detections == ()
    assert region_branch.candidates == ()
    assert region_branch.omissions == out.crops[1].omitted == ()
    assert region_branch.crop_ref is out.crops[1].transform


# ---- f2. 局部连续画面帧序列（C-136 C1/C2） -----------------------------------

def test_l3_branch_frame_sequence_real_three_frame_slices():
    """C-136 C1：局部分支帧序列=同一 crop 区域在 prev/cur/nxt 上的同空间
    真实切片（prev 用不同分辨率验证按各帧尺寸映射），固定序位 0=前/1=当前/
    2=后；像素断言三帧各自对应（内容标记 7/9/5），绝不复制当前帧冒充。"""
    model = FakeModel((TRIPLE,))
    prev = make_task(identity=make_identity(frame_id=6), w=400, h=200,
                     value=7)
    nxt = make_task(identity=make_identity(frame_id=8), value=5)
    task = make_task(dets=(DET_A, DET_B), value=9, prev=prev, nxt=nxt)
    out = L2RelationStage(model).process(task)
    assert out.status is L2Status.OK
    branch = out.l3_branches[1]                    # 关系裁图分支
    seq = branch.frame_sequence
    assert [s.position for s in seq] == [0, 1, 2]  # 固定序位
    assert all(s.present for s in seq)
    assert all(s.crop_id == out.crops[1].crop_id for s in seq)
    assert branch.region_only is True              # 同区域，不保证同一对象
    # 同一归一化区域映射到各帧自身尺寸（prev 400x200，cur/nxt 200x100）
    assert (seq[0].width, seq[0].height) == (400, 200)
    assert (seq[1].width, seq[1].height) == (200, 100)
    assert (seq[2].width, seq[2].height) == (200, 100)
    nx, ny, nw, nh = branch.crop_ref.bbox_norm     # (0.1,0.2,0.6,0.55)
    assert tuple(round(v, 6) for v in (nx, ny, nw, nh)) \
        == (0.1, 0.2, 0.6, 0.55)
    # 像素断言：切片=对应源帧上同空间区域的真实像素（内容各自对应）
    assert seq[0].frame_bgr.shape == (110, 240, 3)   # prev @400x200 映射
    assert np.array_equal(seq[0].frame_bgr,
                          prev.frame_bgr[40:150, 40:280, :])
    assert (seq[0].frame_bgr == 7).all()
    assert seq[1].frame_bgr.shape == (55, 120, 3)    # cur @200x100
    assert np.array_equal(seq[1].frame_bgr, task.frame_bgr[40:95, 20:140, :])
    assert (seq[1].frame_bgr == 9).all()
    assert seq[2].frame_bgr.shape == (55, 120, 3)    # nxt @200x100 同区域
    assert np.array_equal(seq[2].frame_bgr, nxt.frame_bgr[40:95, 20:140, :])
    assert (seq[2].frame_bgr == 5).all()
    # 三帧内容互不相同（真实三帧，非单帧复制）
    assert not np.array_equal(seq[0].frame_bgr, seq[1].frame_bgr)
    assert not np.array_equal(seq[1].frame_bgr, seq[2].frame_bgr)
    # 切片只读隔离副本：改写不影响源帧、不可写
    with pytest.raises(ValueError):
        seq[1].frame_bgr[0, 0, 0] = 0
    assert (task.frame_bgr == 9).all() and (prev.frame_bgr == 7).all()


def test_l3_branch_frame_sequence_panorama_whole_frames():
    """全景分支帧序列：bbox_norm=(0,0,1,1) → 各帧整帧切片（各帧自身尺寸）。"""
    model = FakeModel((TRIPLE,))
    prev = make_task(identity=make_identity(frame_id=6), w=320, h=240,
                     value=4)
    out = L2RelationStage(model).process(
        make_task(dets=(DET_A, DET_B), value=9, prev=prev))
    pano = out.l3_branches[0]
    assert pano.branch_kind == "panorama"
    seq = pano.frame_sequence
    assert [s.position for s in seq] == [0, 1, 2]
    assert seq[0].frame_bgr.shape == (240, 320, 3)   # prev 整帧（自身尺寸）
    assert np.array_equal(seq[0].frame_bgr, prev.frame_bgr)
    assert seq[1].frame_bgr.shape == (100, 200, 3)   # cur 整帧
    assert np.array_equal(seq[1].frame_bgr, out.crop_images[0])
    assert seq[2].present is False and seq[2].frame_bgr is None


def test_l3_branch_missing_prev_keeps_fixed_slot_placeholder():
    """C-136 C2：缺 prev→序位 0 显式缺失（present=False、frame_bgr=None、
    身份字段不伪造），序位不塌缩不补位；只有 cur 在场绝不呈现三帧齐全。"""
    model = FakeModel((TRIPLE,))
    out = L2RelationStage(model).process(make_task(dets=(DET_A, DET_B)))
    for branch in out.l3_branches:
        seq = branch.frame_sequence
        assert [s.position for s in seq] == [0, 1, 2]
        assert seq[0].present is False and seq[0].frame_bgr is None
        assert seq[0].frame_id is None and seq[0].t_capture_ms is None
        assert seq[1].present is True
        assert seq[2].present is False and seq[2].frame_bgr is None
        assert branch.region_only is True


def test_l3_branch_missing_prev_with_identity_keeps_slot_identity():
    """prev 任务在产但帧体缺失（frame_bgr=None）：序位 0 仍显式缺失，
    但保留该帧已知身份/时间（占位不伪造图像，也不丢身份）。"""
    model = FakeModel((TRIPLE,))
    prev = make_task(identity=make_identity(frame_id=6), value=7)
    bare = L2TaskInput(prev.identity, None, prev.width, prev.height,
                       prev.detections, prev.l1_status, prev.change_regions,
                       None, None, None, None, prev.vocabulary_id,
                       prev.relation_vocabulary, prev.budget)
    out = L2RelationStage(model).process(
        make_task(dets=(DET_A, DET_B), prev=bare))
    seq = out.l3_branches[0].frame_sequence
    assert seq[0].present is False and seq[0].frame_bgr is None
    assert seq[0].frame_id == 6                      # 缺帧序位的已知身份
    assert seq[0].width == 200 and seq[0].height == 100
    assert seq[1].present is True


def test_l3_branch_crop_id_explicit_mapping_not_index_guess():
    """C-136 C1：分支→图片映射用 crop_id 显式键——branch.crop_id、
    frame_sequence[].crop_id 与对应 CropRecord.crop_id 三方一致；全部分支
    覆盖全部裁图，无列表索引猜测。"""
    model = FakeModel((triple(0, 1, 0.9), triple(0, 2, 0.6)))
    out = L2RelationStage(model).process(
        make_task(dets=(DET_A, DET_B, DET_C)))
    crop_ids = [c.crop_id for c in out.crops]
    assert len(set(crop_ids)) == len(crop_ids) == 3
    assert sorted(b.crop_id for b in out.l3_branches) == sorted(crop_ids)
    for branch in out.l3_branches:
        assert {s.crop_id for s in branch.frame_sequence} \
            == {branch.crop_id}


# ---- g. ObjectRef 映射（引用不伪造） -----------------------------------------

def test_objectref_track_ref_only_when_tracked_and_stable():
    ident = make_identity()
    stable = frame_object_ref(ident, make_det(track_id=42, stable=True), 0)
    assert stable.object_id == "camA:r1:track:42"
    assert stable.stable is True and stable.frame_id == 7


def test_objectref_frame_internal_ref_when_untracked():
    ident = make_identity()
    ref = frame_object_ref(ident, make_det(track_id=None, stable=False), 3)
    assert ref.object_id == "camA:r1:frame:7:det:3"
    assert ref.stable is False


def test_objectref_never_fabricates_track_identity():
    ident = make_identity()
    # track_id 缺失但 stable=True（矛盾输入）→ 帧内标识，绝不伪造 track 引用
    ref = frame_object_ref(ident, make_det(track_id=None, stable=True), 2)
    assert ref.object_id == "camA:r1:frame:7:det:2"
    assert ref.stable is False
    # track_id 在场但未确认（stable=False）→ 帧内标识，不冒充稳定对象
    ref2 = frame_object_ref(ident, make_det(track_id=9, stable=False), 1)
    assert ref2.object_id == "camA:r1:frame:7:det:1"
    assert ref2.stable is False


def test_stage_maps_triples_to_object_refs():
    model = FakeModel((triple(0, 1, 0.9),))
    out = L2RelationStage(model).process(
        make_task(dets=(make_det(track_id=5, stable=True,
                                 bbox=(0.1, 0.2, 0.3, 0.4)),
                        DET_B)))
    cand = out.candidates[0]
    assert cand.subject.object_id == "camA:r1:track:5"
    assert cand.subject.stable is True
    assert cand.obj.object_id == "camA:r1:frame:7:det:1"
    assert cand.obj.stable is False


def test_triple_with_invalid_index_dropped_not_crash():
    model = FakeModel(({"s": 5, "o": 1, "relation": "holding",
                        "graph": "spatial", "score": 0.9},))
    out = L2RelationStage(model).process(make_task(dets=(DET_A, DET_B)))
    assert out.status is L2Status.NO_RELATION_ABOVE_FLOOR
    assert out.error_code == "no_candidates"
    assert out.omission.candidates_dropped == 1
    assert "invalid_index=1" in out.omission.reason


def test_malformed_triple_counted_not_crash():
    model = FakeModel(({"s": 0, "o": 1},))               # 缺 relation/score
    out = L2RelationStage(model).process(make_task(dets=(DET_A, DET_B)))
    assert out.status is L2Status.NO_RELATION_ABOVE_FLOOR
    assert "malformed_triple=1" in out.omission.reason


def test_degenerate_detections_excluded_from_pairing():
    bad = make_det(bbox=(0.5, 0.5, 0.0, 0.2))            # 零宽
    model = FakeModel((triple(0, 1, 0.9),))
    out = L2RelationStage(model).process(make_task(dets=(bad, DET_A, DET_B)))
    assert out.status is L2Status.OK                     # 两个可用框成对
    assert "degenerate_detections=1" in out.omission.reason
    # 模型只收到 2 个可用框（像素），索引对应可用列表
    assert len(model.calls[0]["boxes_px"]) == 2
    # 帧内标识使用原始检测序号（可用位次 1、2 → det:1 / det:2）
    assert out.candidates[0].subject.object_id == "camA:r1:frame:7:det:1"
    assert out.candidates[0].obj.object_id == "camA:r1:frame:7:det:2"
    # 退化框不进全景参与者清单（participants=全部*可用*对象）
    pano_participants = [ref.object_id for ref in out.crops[0].participants]
    assert pano_participants == ["camA:r1:frame:7:det:1",
                                 "camA:r1:frame:7:det:2"]


# ---- h. 坐标唯一切换点 / 输出形状 / 隔离 -------------------------------------

def test_norm_to_pixel_switch_happens_once_in_stage():
    model = FakeModel((TRIPLE,))
    out = L2RelationStage(model).process(make_task(dets=(DET_A, DET_B)))
    assert out.status is L2Status.OK
    call = model.calls[0]
    # (0.1,0.2,0.3,0.4)@200x100 → (20,20,80,60)；(0.5,0.5,0.2,0.25) → (100,50,140,75)
    assert call["boxes_px"] == [(20, 20, 80, 60), (100, 50, 140, 75)]
    assert call["labels"] == ["person", "person"]
    assert call["vocabulary"] == ("holding",)
    # 唯一像素出现在模型调用边界；输出记录的变换像素字段与同一换算一致
    # （C-135 起槽 0 为全景，关系裁图在槽 1）
    assert out.crops[0].transform.bbox_px == (0, 0, 200, 100)
    assert out.crops[1].transform.bbox_px[0] >= 0


def test_output_shape_identity_timings_and_calibrated_false():
    model = FakeModel((TRIPLE,), model_ref="fake-relate/v3")
    task = make_task(dets=(DET_A, DET_B), vocab_id="v7")
    out = L2RelationStage(model).process(task)
    assert isinstance(out, L2Output)
    assert out.identity is task.identity
    assert out.status is L2Status.OK
    assert out.vocabulary_id == "v7"
    assert out.model_ref == "fake-relate/v3"
    assert out.calibrated is False                        # 恒 False
    assert set(("infer", "crops", "total")) <= set(out.timings_ms)
    assert all(v >= 0.0 for v in out.timings_ms.values())
    assert out.timings_ms["total"] >= out.timings_ms["infer"]
    assert out.timings_ms["total"] >= out.timings_ms["crops"]
    assert len(out.crops) == len(out.crop_images)
    assert all(isinstance(img, np.ndarray) for img in out.crop_images)


def test_crop_images_are_isolated_copies():
    model = FakeModel((TRIPLE,))
    task = make_task(dets=(DET_A, DET_B))
    original = task.frame_bgr.copy()
    out = L2RelationStage(model).process(task)
    for img in out.crop_images:
        img[:] = 0                                        # 消费者原地改写
    assert task.frame_bgr.tobytes() == original.tobytes()


def test_fallback_budget_flags_disable_fallback_crops():
    model = FakeModel(())
    budget = L2Budget(whole_frame_fallback=False,
                      change_region_fallback=False)
    out = L2RelationStage(model).process(
        make_task(dets=(), change=(ChangeRegion(0.1, 0.1, 0.2, 0.2),),
                  budget=budget))
    assert out.status is L2Status.NO_OBJECTS
    assert out.crops == () and out.crop_images == ()      # 预算显式关闭兜底
    assert out.l3_branches == ()


def test_stage_holds_exactly_one_model_reference():
    model = FakeModel(())
    stage = L2RelationStage(model)
    assert stage.model is model
    stage.process(make_task(dets=(DET_A, DET_B)))
    assert stage.model is model                           # 引用计数=1，不换不重启


# ---- i. prev/next 显式缺失的不确定性标注 -------------------------------------

def test_prev_none_explicit_missing_marked_not_fabricated():
    model = FakeModel((TRIPLE,))
    out = L2RelationStage(model).process(make_task(dets=(DET_A, DET_B)))
    cand = out.candidates[0]
    assert cand.uncertainty.frame_missing_prev is True    # prev=None 显式缺失
    assert cand.uncertainty.frame_missing_next is True
    assert out.crops[0].identity.frame_id == 7            # 证据只引用 cur
    assert all(ref.frame_id == 7 for ref in
               (cand.subject, cand.obj))
