"""C-136/C-137 tests: scam.win11_l4 —— L4 结构化渐进融合（纯规则，固定案例）。

覆盖（L2L3L4-接口冻结-C136.md §四 + C137-接口冻结.md §5 + 任务书固定案例）：
- 合同（零模型依赖、零 cv2、独立导入）：__slots__ 冻结、kind/certainty/
  status/source/时间类型值域冻结、非法值拒绝；两模块源码无 cv2/numpy/torch/
  模型依赖、不 import l2/l3 合同（按冻结合同的当前交付形态鸭子只读消费）；
  指纹 netstring 序列化确定性；
- 一致输入 → ok（观察/推断逐条带来源，无冲突无缺口）；
- 重复合并：同文本跨分支合并保留双方来源、同候选三元组重复提交合并保留
  双方来源、重复 L1 引用合并；
- 矛盾：人数描述不一致 → 双方 observation 原文并存 + conflict 记录
  （unknown，不投票不强选）；关系高分 vs 叙事否定 → 候选保持
  model_inferred 不升级 + 双方并存 + conflict；
- 缺分支/失败/缺失清单 → gap（partial）；全部缺失 → insufficient 仍成版本；
- 渐进：部分结果先成版本；晚到结果 → 新版本追加，旧版本原样保留；
- 身份：跨 camera/run/config 拒绝融合（FusionIdentityRejected，不产版本
  不产 items）；对象引用内嵌 {cam}:{run}: 前缀与输入身份不符同判拒绝；
- 无稳定对象身份：帧内引用与稳定 track 引用不合并为同一对象；跨帧行内
  引用不合并；
- 自由文本不可结构化：unstructured=True + 原文逐字保留；
- 模型"安全/无异常"文本 → 仅 observation 记录；模型自报 confirmed →
  model_inferred 非系统核实；本模块无任何"关闭事件/撤销提醒"类 API、
  输出形状不携带动作语义（固定回归）；
- 确定性：同输入重放同 version_id（created_mono 不参与）；重复提交幂等
  返回同一版本对象；
- 时钟类型：混合/非 source_capture → 时间项 unknown 且不按时间排序
  （不强排）；单一 source_capture 无时间缺口；
- snapshot 计数（fused/idempotent_hits/identity_rejected/versions）。

C-137 新增（D1–D6）：
- D1 指纹 v2 覆盖：改 obj/subject frame_id/stable 位 → 新指纹；改 L3
  crop_id/model_ref/分支 window/帧来源 → 新指纹；失败/缺失清单逐项；
  全同 → 幂等；
- D2 材料身份：L3 分支自带 window 与顶层四元逐字段不符 → 拒绝+原因清单；
- D3 同窗累计：accumulate 追加语义（前版本材料保留+新增）、失败并入缺失
  因素、重复提交不追加、每窗缓存有界 archived 标记、cleanup 终结清理；
- D4 双 crop 同文本合并一条 + sources 并集含全部 crop/model 来源 +
  JSON 可序列化；
- D5 时空对齐字段：稳定引用对齐合并、空间重叠不合并对象+不确定性 gap、
  时间类型透传；
- D6 因素透传：failures/gaps/clock_kinds 逐项进版本（断言透传）+ partial。

C-138 新增（B1–B3/B5，docs/context/C138-接口冻结.md §4）：
- B1 累计结构化材料：人数矛盾（先1后2/先2后1/交错）与候选 vs 否定叙事
  任意到达顺序 → 最终 items/conflict/sources 一致（同 version_id）；
- B2 历史携带：后版本含前版本对象引用/观察/缺失因素+新材料与 frame_refs
  并集；坐标体系不一致标记（mixed 联合声明、各帧声明保留、跨体系不比较、
  旧材料不被覆盖）；时钟类型按累计并集判定；
- B3 缓存硬上限：17 窗→最旧活跃窗真淘汰（versions 不可达+计数+回调收
  到数据）；淘汰后同指纹重提交按新材料如实计数；归档/活跃两态、归档窗
  只读、归档窗在活跃淘汰压力下存活、无活跃可淘汰时才淘汰归档窗、回调
  失败不删窗、构造下界守卫；
- B5：模块 docstring 生产调用顺序示例（人工对照测试构造方式核对）。

既有断言适配（C-138 修订，冲突处以 C-138 为准）：
- FusionFrameRef.__slots__ 增加 coord_space（逐帧坐标声明，B2）；
- FusionInput/FusionFrameRef 的 coord_space="pixels" 由 ValueError 改为
  已声明体系（值域冻结 COORD_SPACES=("normalized","pixels")）；未声明
  体系（"meters"）仍 ValueError；逐帧声明与本批声明不一致 ValueError。

C-139-R1/R2 新增（§2，docs/context/C139R1-接口冻结.md）：
- FusionVersion.__slots__ 增加 parent_version_id（版本父子：同窗累计链
  首版 None、后续指向前版；跨窗不串链；fuse 恒 None；非 str 拒绝）；
- fusion_version_to_json：sources 结构化 {kind, ref}（不 str() 压平）、
  bbox_norm 随 frame_refs 保存、parent_version_id 写入、非有限数
  （NaN/Inf）ValueError 拒绝（不静默变 null）；
- fusion_version_from_json：返回 FusionVersion（读回对照）；关键类型
  校验（version_id 非空 str、status 在值域、items/frame_refs 为 list、
  item kind/certainty 在值域、source {kind, ref}、archived 布尔）；
  成功/失败版本 to_json→from_json 往返关键字段等价。
"""

from __future__ import annotations

import inspect
import json
import re

import pytest

from scam import win11_l4 as l4
from scam import win11_l4_contract as l4c
from scam.win11_l2_contract import (
    DetectionView,
    FrameIdentity,
    ObjectRef,
    RelationCandidate,
    Uncertainty,
    frame_object_ref,
)
from scam.win11_l3_contract import (
    L3BranchKind,
    L3BranchResult,
    L3SourceRef,
    L3Status,
    L3Uncertainty,
    L3WindowIdentity,
)
from scam.win11_l4_contract import (
    COMPARABLE_CLOCK_KIND,
    COORD_SPACES,
    DEFAULT_COORD_SPACE,
    FUSION_CERTAINTIES,
    FUSION_KINDS,
    FUSION_SOURCE_KINDS,
    FUSION_STATUS,
    FUSION_TIME_KINDS,
    MAX_ACTIVE_WINDOWS,
    MAX_WINDOW_VERSIONS,
    MIXED_COORD_SPACE_PREFIX,
    WINDOW_STATES,
    FusionFrameRef,
    FusionIdentityRejected,
    FusionInput,
    FusionItem,
    FusionSource,
    FusionVersion,
    fusion_fingerprint,
)
from scam.win11_l4 import L4Stage


# ---------------------------------------------------------------------------
# 工具：按冻结合同的当前交付形态构造上游材料（真实 ObjectRef/L3BranchResult）
# ---------------------------------------------------------------------------

def _frame_identity(cam="cam-1", run="run-1", frame="f1"):
    return FrameIdentity(cam, run, "cfg-1", frame, "m-1", 1000.0,
                         "source_capture")


def _ref(cam="cam-1", run="run-1", frame="f1", track=7, stable=True, idx=0):
    """L1 对象事实引用（走 win11_l2_contract.frame_object_ref 真实形态）。"""
    det = DetectionView("person", 0.9, (0.1, 0.1, 0.2, 0.2),
                        track if stable else None, stable)
    return frame_object_ref(_frame_identity(cam, run, frame), det, idx)


def _cand(subj, obj, relation="holding", score=0.8, graph="spatial",
          vocab="v7", **unc):
    return RelationCandidate(subject=subj, obj=obj, relation=relation,
                             graph=graph, score_raw=score,
                             vocabulary_id=vocab, uncertainty=Uncertainty(**unc))


def _l3src(frame_id="f1", present=True, t_capture_ms=1000.0,
           timestamp_kind="source_capture"):
    return L3SourceRef(position=1, frame_id=frame_id, present=present,
                       t_capture_ms=t_capture_ms,
                       timestamp_kind=timestamp_kind)


def _l3win(cam="cam-1", run="run-1", cfg="cfg-1", win="w-1"):
    return L3WindowIdentity(cam, run, cfg, win)


def _branch(kind="panorama", status=L3Status.OK, obs=None, inf=None,
            uncertainty=None, sources=None, error_code=None, window=None,
            crop_id=None, model_ref=None):
    return L3BranchResult(
        branch=L3BranchKind(kind), status=status, error_code=error_code,
        observation=obs, inference=inf,
        uncertainty=(uncertainty if uncertainty is not None
                     else L3Uncertainty()),
        sources=(sources if sources is not None else (_l3src(),)),
        window=window, crop_id=crop_id, model_ref=model_ref)


def _wkey(win="w-1", cam="cam-1", run="run-1", cfg="cfg-1"):
    return (cam, run, cfg, win)


def _finput(**kw):
    defaults = dict(camera_id="cam-1", run_id="run-1",
                    config_version="cfg-1", window_id="w-1",
                    l1_object_refs=(), l2_candidates=(), l3_branches=(),
                    failures=(), gaps=(), clock_kinds=("source_capture",))
    defaults.update(kw)
    return FusionInput(**defaults)


def _stage(cam="cam-1", run="run-1", cfg="cfg-1"):
    return L4Stage(cam, run, cfg)


def _kinds(version):
    return [item.kind for item in version.items]


def _by_kind(version, kind):
    return [item for item in version.items if item.kind == kind]


def _find(version, substring):
    return [item for item in version.items if substring in item.text]


# ---------------------------------------------------------------------------
# 合同：形状冻结、值域冻结、零依赖、指纹确定性
# ---------------------------------------------------------------------------

def test_contract_shapes_and_frozen_values():
    assert FusionInput.__slots__ == (
        "camera_id", "run_id", "config_version", "window_id",
        "l1_object_refs", "l2_candidates", "l3_branches", "failures",
        "gaps", "clock_kinds", "coord_space", "frame_refs")
    assert FusionFrameRef.__slots__ == (
        "frame_id", "t_ms", "time_kind", "bbox_norm", "crop_ref",
        "stable_ref", "coord_space")
    assert FusionItem.__slots__ == (
        "kind", "text", "sources", "certainty", "unstructured")
    # C-139-R1 §2：版本父子关系随版本携带（parent_version_id）
    assert FusionVersion.__slots__ == (
        "version_id", "status", "items", "created_mono", "camera_id",
        "run_id", "config_version", "window_id", "coord_space",
        "frame_refs", "archived", "parent_version_id")
    assert FusionSource.__slots__ == ("kind", "ref")
    assert FUSION_KINDS == ("observation", "inference", "conflict", "gap")
    assert FUSION_CERTAINTIES == ("observed", "model_inferred", "unknown")
    assert FUSION_STATUS == ("ok", "partial", "insufficient")
    assert FUSION_SOURCE_KINDS == ("l1_object", "l2_candidate",
                                   "l3_branch", "failure", "gap")
    assert COMPARABLE_CLOCK_KIND == "source_capture"
    assert FUSION_TIME_KINDS == ("source_capture", "host_receive", "unknown")
    assert DEFAULT_COORD_SPACE == "normalized"
    assert MAX_WINDOW_VERSIONS == 32
    # C-138 B2/B3：坐标体系值域、窗口缓存两态与活跃窗硬上限冻结
    assert COORD_SPACES == ("normalized", "pixels")
    assert MIXED_COORD_SPACE_PREFIX == "mixed:"
    assert WINDOW_STATES == ("active", "archived")
    assert MAX_ACTIVE_WINDOWS == 16
    with pytest.raises(ValueError):
        FusionItem(kind="action", text="x", sources=(), certainty="observed")
    with pytest.raises(ValueError):
        FusionItem(kind="observation", text="x", sources=(),
                   certainty="confirmed")
    with pytest.raises(ValueError):
        FusionSource("model", "x")
    with pytest.raises(ValueError):
        FusionVersion(version_id="ab", status="rejected", items=(),
                      created_mono=0.0, camera_id="c", run_id="r",
                      config_version="cfg", window_id="w")
    with pytest.raises(ValueError):               # parent 非 str/None 拒绝
        FusionVersion(version_id="ab", status="ok", items=(),
                      created_mono=0.0, camera_id="c", run_id="r",
                      config_version="cfg", window_id="w",
                      parent_version_id=123)
    # C-137 D5 + C-138 B2：时间类型与坐标体系值域冻结——未声明体系拒绝
    # （不猜不换算）；已声明体系（pixels）可接收；逐帧声明与本批声明
    # 不一致拒绝（单批材料单声明）
    with pytest.raises(ValueError):
        FusionFrameRef("f1", time_kind="wallclock")
    with pytest.raises(ValueError):
        FusionFrameRef("f1", bbox_norm=(0.1, 0.2))
    with pytest.raises(ValueError):
        FusionFrameRef("f1", coord_space="meters")
    with pytest.raises(ValueError):
        FusionInput("c", "r", "cfg", "w", coord_space="meters")
    assert FusionInput("c", "r", "cfg", "w",
                       coord_space="pixels").coord_space == "pixels"
    with pytest.raises(ValueError):
        FusionInput("c", "r", "cfg", "w", coord_space="pixels",
                    frame_refs=(FusionFrameRef("f1"),))


def test_contract_version_carries_alignment_fields():
    r7 = _ref(track=7)
    refs = (FusionFrameRef("f1", 1000.0, "source_capture",
                           (0.1, 0.1, 0.2, 0.2), None, r7.object_id),)
    version = _stage().fuse(_finput(l1_object_refs=(r7,), frame_refs=refs))
    assert version.coord_space == "normalized"
    assert version.frame_refs == refs
    assert version.archived is False
    ref = version.frame_refs[0]
    assert ref.frame_id == "f1" and ref.t_ms == 1000.0
    assert ref.time_kind == "source_capture"
    assert ref.bbox_norm == (0.1, 0.1, 0.2, 0.2)
    assert ref.stable_ref == r7.object_id


def test_l4_modules_pure_structured_no_model_cv2_dependency():
    """零模型依赖、零 cv2：两模块 import 面无模型/数组库/l2/l3 合同（按冻结
    合同的当前交付形态鸭子只读消费，保持独立可导入），调用面无模型协议痕迹。"""
    forbidden_roots = {"cv2", "numpy", "torch", "transformers", "models",
                       "win11_l2", "win11_l3", "win11_l2_backend",
                       "win11_l3_backend", "win11_l2_contract",
                       "win11_l3_contract"}
    for module in (l4c, l4):
        source = inspect.getsource(module)
        roots = set()
        for from_mod, import_mods in re.findall(
                r"^[ \t]*(?:from\s+([\w.]+)\s+import\s|import\s+(.+))$",
                source, re.M):
            if from_mod:
                roots.add(from_mod.split(".")[0])
            else:
                for name in import_mods.split(","):
                    name = name.strip().split(" as ")[0].strip()
                    if name:
                        roots.add(name.split(".")[0])
        assert roots.isdisjoint(forbidden_roots), (
            module.__name__, roots & forbidden_roots)
        assert "understand_frames" not in source
        assert ".infer(" not in source


def test_fingerprint_deterministic_and_order_sensitive():
    refs = (_ref(track=7), _ref(track=8))
    base = _finput(l1_object_refs=refs)
    assert fusion_fingerprint(base) == fusion_fingerprint(_finput(l1_object_refs=refs))
    changed = _finput(l1_object_refs=(refs[1], refs[0]))
    assert fusion_fingerprint(base) != fusion_fingerprint(changed)
    assert fusion_fingerprint(
        _finput(window_id="w-2")) != fusion_fingerprint(base)


# ---------------------------------------------------------------------------
# D3 固定案例 1：一致输入 → ok
# ---------------------------------------------------------------------------

def test_consistent_inputs_fuse_ok_with_sourced_items():
    r7, r8 = _ref(track=7), _ref(track=8)
    inp = _finput(
        l1_object_refs=(r7, r8),
        l2_candidates=(_cand(r7, r8, "holding", 0.82),),
        l3_branches=(
            _branch("panorama", obs="桌上有一个人，旁边有一只杯子"),
            _branch("relation_crop", obs="杯子被手持的画面清楚"),
        ))
    version = _stage().fuse(inp)
    assert version.status == "ok"
    assert version.camera_id == "cam-1" and version.run_id == "run-1"
    assert version.config_version == "cfg-1" and version.window_id == "w-1"
    assert len(version.items) == 5
    obs_items = _by_kind(version, "observation")
    assert len(obs_items) == 4
    l1_items = [it for it in obs_items if it.certainty == "observed"]
    assert len(l1_items) == 2
    assert all(it.sources[0].kind == "l1_object" for it in l1_items)
    assert all(not it.unstructured for it in l1_items)
    cand_items = _by_kind(version, "inference")
    assert len(cand_items) == 1
    cand = cand_items[0]
    assert cand.certainty == "model_inferred"
    assert "0.820000" in cand.text and "未校准" in cand.text
    assert cand.sources[0].kind == "l2_candidate"
    l3_items = [it for it in obs_items if it.certainty == "model_inferred"]
    assert len(l3_items) == 2 and all(it.unstructured for it in l3_items)
    assert {it.sources[0].ref for it in l3_items} == {"panorama",
                                                      "relation_crop"}
    assert not _by_kind(version, "conflict")
    assert not _by_kind(version, "gap")


# ---------------------------------------------------------------------------
# D3 固定案例 2：重复合并（保留双方来源）
# ---------------------------------------------------------------------------

def test_duplicate_merge_keeps_both_sources():
    r7, r8 = _ref(track=7), _ref(track=8)
    same_text = "画面中出现一个人走向桌边"
    inp = _finput(
        l1_object_refs=(r7, r7),                    # 同一引用重复登记
        l2_candidates=(_cand(r7, r8, "near", 0.7),
                       _cand(r7, r8, "near", 0.7)),  # 同三元组重复提交
        l3_branches=(
            _branch("panorama", obs=same_text),
            _branch("relation_crop", obs=same_text),  # 同文本跨分支
        ))
    version = _stage().fuse(inp)
    merged_obs = _find(version, same_text)
    assert len(merged_obs) == 1
    assert {src.ref for src in merged_obs[0].sources} == {"panorama",
                                                          "relation_crop"}
    merged_l1 = [it for it in _by_kind(version, "observation")
                 if r7.object_id in it.text]
    assert len(merged_l1) == 1
    merged_cand = _by_kind(version, "inference")
    assert len(merged_cand) == 1
    assert len(merged_cand[0].sources) == 2          # 双方来源都保留
    assert len({src.ref for src in merged_cand[0].sources}) == 2
    assert version.status == "ok"


# ---------------------------------------------------------------------------
# D3 固定案例 3：矛盾（全景 vs 局部人数）→ 双方并存 + conflict，不强选
# ---------------------------------------------------------------------------

def test_conflict_person_count_both_sides_preserved_no_voting():
    pano = "桌边有两个人"
    local = "画面中只有一个人手持杯子"
    inp = _finput(l3_branches=(
        _branch("panorama", obs=pano),
        _branch("relation_crop", obs=local),
    ))
    version = _stage().fuse(inp)
    obs_items = _by_kind(version, "observation")
    assert [it.text for it in obs_items] == [pano, local]   # 双方原文并存
    conflicts = _by_kind(version, "conflict")
    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert conflict.certainty == "unknown"
    assert "2人" in conflict.text and "1人" in conflict.text
    assert {src.ref for src in conflict.sources} == {"panorama",
                                                     "relation_crop"}
    assert version.status == "partial"          # 冲突因素不冒充 ok


# ---------------------------------------------------------------------------
# D3 固定案例 4：关系高分但叙事否定 → 候选不升级、双方并存 + conflict
# ---------------------------------------------------------------------------

def test_high_score_relation_vs_narrative_denial_kept_both():
    r7, r8 = _ref(track=7), _ref(track=8)
    inp = _finput(
        l2_candidates=(_cand(r7, r8, "holding", score=0.92),),
        l3_branches=(
            _branch("panorama", obs="未检测到 holding 行为：杯子仍在桌上。"),
        ))
    version = _stage().fuse(inp)
    cand_items = _by_kind(version, "inference")
    assert len(cand_items) == 1
    assert cand_items[0].certainty == "model_inferred"   # 高分不升级为 observed
    assert "0.920000" in cand_items[0].text
    pano_items = _find(version, "杯子仍在桌上")
    assert len(pano_items) == 1 and pano_items[0].kind == "observation"
    conflicts = _by_kind(version, "conflict")
    assert len(conflicts) == 1
    assert conflicts[0].certainty == "unknown"
    assert {src.kind for src in conflicts[0].sources} == {"l2_candidate",
                                                          "l3_branch"}
    assert version.status == "partial"


# ---------------------------------------------------------------------------
# D3 固定案例 5：缺分支/失败/缺失清单 → gap（partial）；全缺 → insufficient
# ---------------------------------------------------------------------------

def test_missing_branch_failures_gaps_become_gap_items_partial():
    inp = _finput(
        l3_branches=(
            _branch("panorama", status=L3Status.INFER_FAILED,
                    error_code="infer_failed"),
            _branch("relation_crop", obs="有人"),
        ),
        failures=({"source": "l3", "code": "timeout",
                   "detail": "全景分支超时"},),
        gaps=({"kind": "frame", "detail": "prev 缺失"},),
        clock_kinds=())
    version = _stage().fuse(inp)
    assert version.status == "partial"
    assert len(_find(version, "分支不可用：panorama 状态 infer_failed")) == 1
    assert len(_find(version, "失败：l3 timeout：全景分支超时")) == 1
    assert len(_find(version, "缺失：frame prev 缺失")) == 1
    assert any(item.kind == "observation" and item.text == "有人"
               for item in version.items)
    assert all(item.certainty == "unknown"
               for item in _by_kind(version, "gap"))


def test_insufficient_when_nothing_fusable_still_a_version():
    inp = _finput(failures=({"source": "l2", "code": "model_unavailable"},),
                  clock_kinds=())
    stage = _stage()
    version = stage.fuse(inp)
    assert version.status == "insufficient"
    assert _kinds(version) == ["gap"]
    assert stage.versions() == (version,)   # 部分结果先成版本，空融合不冒充


# ---------------------------------------------------------------------------
# D3 固定案例 6：迟到结果 → 新版本追加，旧版本原样保留
# ---------------------------------------------------------------------------

def test_partial_then_late_result_appends_new_version():
    r7 = _ref(track=7)
    early_pano = _branch("panorama",
                         obs="全景部分结果：有人影",
                         uncertainty=L3Uncertainty(frame_missing=True))
    inp1 = _finput(l1_object_refs=(r7,), l3_branches=(early_pano,))
    stage = _stage()
    v1 = stage.fuse(inp1)
    assert v1.status == "partial"
    assert _kinds(v1) == ["observation", "observation", "gap"]
    v1_items_snapshot = v1.items

    late_local = _branch("relation_crop", obs="局部后到：杯子被拿起")
    inp2 = _finput(l1_object_refs=(r7,),
                   l3_branches=(early_pano, late_local))
    v2 = stage.fuse(inp2)

    assert stage.versions() == (v1, v2)             # 版本追加，不覆盖
    assert v1.version_id != v2.version_id           # 指纹随输入变化
    assert v1.items == v1_items_snapshot            # 原始版本原样保留
    assert any(item.kind == "observation"
               and "局部后到" in item.text for item in v2.items)
    assert v2.status == "partial"


# ---------------------------------------------------------------------------
# D3 固定案例 7：旧帧内身份 vs 新稳定身份 → 不合并为同一对象
# ---------------------------------------------------------------------------

def test_old_frame_ref_not_merged_with_new_track_identity():
    old_ref = _ref(frame="f0", stable=False, idx=0)   # 旧帧内引用
    new_ref = _ref(track=7, stable=True)              # 新稳定 track
    inp = _finput(l1_object_refs=(old_ref, new_ref))
    version = _stage().fuse(inp)
    obs_items = _by_kind(version, "observation")
    assert len(obs_items) == 2                        # 两条独立观察
    assert {it.sources[0].ref for it in obs_items} == {
        old_ref.object_id, new_ref.object_id}
    texts = " ".join(it.text for it in obs_items)
    assert "帧内引用" in texts and "稳定跟踪身份" in texts
    assert all(it.certainty == "observed" for it in obs_items)


def test_no_stable_identity_no_cross_frame_merge():
    ref_a = _ref(frame="f0", stable=False, idx=0)
    ref_b = _ref(frame="f1", stable=False, idx=0)     # 同 det 序位，不同帧
    version = _stage().fuse(_finput(l1_object_refs=(ref_a, ref_b)))
    obs_items = _by_kind(version, "observation")
    assert len(obs_items) == 2                        # 绝不合并为同一对象
    assert ref_a.object_id != ref_b.object_id
    assert {it.sources[0].ref for it in obs_items} == {
        ref_a.object_id, ref_b.object_id}


# ---------------------------------------------------------------------------
# D3 固定案例 8：自由文本不可结构化 → unstructured 标注 + 原文保留
# ---------------------------------------------------------------------------

def test_unstructured_free_text_marked_and_verbatim():
    free_obs = "模型自由发挥的一段话：画面整体明亮，有晃动人影，说不清具体动作。"
    free_inf = "模型猜测：可能有人正在整理物品（无法结构化）。"
    version = _stage().fuse(_finput(l3_branches=(
        _branch("panorama", obs=free_obs, inf=free_inf),
    )))
    obs_items = [it for it in _by_kind(version, "observation")
                 if it.certainty == "model_inferred"]
    inf_items = _by_kind(version, "inference")
    assert len(obs_items) == 1 and len(inf_items) == 1
    assert obs_items[0].unstructured is True
    assert obs_items[0].text == free_obs              # 原文逐字保留
    assert inf_items[0].unstructured is True
    assert inf_items[0].text == free_inf
    assert all(it.certainty == "model_inferred"
               for it in obs_items + inf_items)


# ---------------------------------------------------------------------------
# D3 固定案例 9：模型"安全/无异常"文本 → 仅记录，绝不产生关闭/撤销动作
# ---------------------------------------------------------------------------

def test_model_safety_text_never_closes_events_or_revokes():
    version = _stage().fuse(_finput(
        l1_object_refs=(_ref(track=7),),
        l3_branches=(_branch("panorama", obs="场景安全，无异常。"),)))
    # 仅记录：文本只成为 observation 条目（模型自报，不升级为系统核实）
    assert set(_kinds(version)) == {"observation"}
    safety = _find(version, "场景安全，无异常。")
    assert len(safety) == 1
    assert safety[0].certainty == "model_inferred"
    assert safety[0].unstructured is True
    # 无任何"关闭/撤销"类动作语义：输入无动作词，输出也不得出现
    for item in version.items:
        assert "关闭" not in item.text and "撤销" not in item.text
    # 本模块无该 API：类面上不存在关闭/撤销/压制/取消事件的方法
    forbidden_methods = ("close", "revoke", "dismiss", "suppress", "cancel")
    for name in dir(L4Stage):
        assert not any(f in name.lower() for f in forbidden_methods), name
    # 输出形状不携带动作/事件生命周期字段；kind 值域无动作语义
    forbidden_fields = ("action", "command", "event", "close", "revoke")
    for field in FusionVersion.__slots__ + FusionItem.__slots__:
        assert not any(f in field for f in forbidden_fields), field
    assert set(FUSION_KINDS).isdisjoint({"close_event", "revoke",
                                         "suppress"})


def test_model_confirmed_claim_stays_model_inferred():
    version = _stage().fuse(_finput(l3_branches=(
        _branch("panorama",
                inf="已确认（confirmed）：两人正在交接物品。"),)))
    inf_items = _by_kind(version, "inference")
    assert len(inf_items) == 1
    assert inf_items[0].certainty == "model_inferred"   # 非系统核实
    assert inf_items[0].certainty != "observed"
    assert not any(item.certainty == "observed"
                   for item in version.items if item.kind != "gap")


# ---------------------------------------------------------------------------
# 确定性重放 + 幂等
# ---------------------------------------------------------------------------

def test_deterministic_replay_same_version_id_and_idempotent():
    def build():
        return _finput(
            l1_object_refs=(_ref(track=7),),
            l2_candidates=(_cand(_ref(track=7), _ref(track=8), "near", 0.66),),
            l3_branches=(_branch("panorama", obs="桌边有人"),))

    stage_a, stage_b = _stage(), _stage()
    va = stage_a.fuse(build())
    vb = stage_b.fuse(build())
    assert va.version_id == vb.version_id            # 同输入重放同 version_id
    assert va.version_id == fusion_fingerprint(build())
    assert [it.text for it in va.items] == [it.text for it in vb.items]
    assert isinstance(va.created_mono, float)        # 打点不参与 version_id

    again = stage_a.fuse(build())                    # 重复提交：幂等同版本
    assert again is va
    assert stage_a.versions() == (va,)
    snap = stage_a.snapshot()
    assert snap["idempotent_hits"] == 1 and snap["fused"] == 1


# ---------------------------------------------------------------------------
# 时钟类型：不可比 → unknown，不强排
# ---------------------------------------------------------------------------

def test_clock_kinds_mixed_time_unknown_and_no_time_ordering():
    pano = _branch("panorama", obs="全景观察记录",
                   sources=(_l3src(frame_id="f1", t_capture_ms=900.0),))
    local = _branch("relation_crop", obs="局部观察记录",
                    sources=(_l3src(frame_id="f2", t_capture_ms=100.0),))
    inp = _finput(l3_branches=(pano, local),
                  clock_kinds=("source_capture", "host_receive"))
    version = _stage().fuse(inp)
    clock_gaps = _find(version, "时钟类型不可比")
    assert len(clock_gaps) == 1
    assert clock_gaps[0].certainty == "unknown"
    assert "unknown" in clock_gaps[0].text
    assert "host_receive" in clock_gaps[0].text
    # 不强排：items 保持构造序（输入分支序），绝不按 t_capture 排序
    # （pano t=900 > local t=100，但 pano 条目仍在前）
    pano_item = _find(version, "全景观察记录")[0]
    local_item = _find(version, "局部观察记录")[0]
    assert version.items.index(pano_item) < version.items.index(local_item)
    assert version.status == "partial"


def test_clock_uniform_source_capture_no_clock_gap_but_host_receive_unknown():
    ok_version = _stage().fuse(_finput(
        l3_branches=(_branch("panorama", obs="一致时钟观察"),),
        clock_kinds=("source_capture",)))
    assert not _find(ok_version, "时钟类型不可比")
    assert ok_version.status == "ok"

    recv_version = _stage().fuse(_finput(
        l3_branches=(_branch("panorama", obs="接收时钟观察"),),
        clock_kinds=("host_receive",)))
    assert len(_find(recv_version, "时钟类型不可比")) == 1
    assert recv_version.status == "partial"


# ---------------------------------------------------------------------------
# 身份红线：跨 camera/run/config 拒绝融合；引用前缀错配同判拒绝
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kw", [
    {"camera_id": "cam-2"},
    {"run_id": "run-2"},
    {"config_version": "cfg-2"},
])
def test_cross_identity_fusion_rejected_no_version_no_items(kw):
    stage = _stage()
    with pytest.raises(FusionIdentityRejected, match="identity_rejected"):
        stage.fuse(_finput(l1_object_refs=(_ref(track=7),), **kw))
    assert stage.versions() == ()
    assert stage.snapshot()["identity_rejected"] == 1


def test_material_ref_identity_mismatch_rejected():
    stage = _stage()
    with pytest.raises(FusionIdentityRejected, match="identity_rejected"):
        stage.fuse(_finput(l2_candidates=(
            _cand(_ref(cam="cam-9", track=1), _ref(track=8), "near"),)))
    with pytest.raises(FusionIdentityRejected, match="identity_rejected"):
        stage.fuse(_finput(l1_object_refs=(_ref(cam="cam-2", track=3),)))
    assert stage.versions() == ()
    assert stage.snapshot()["identity_rejected"] == 2


# ---------------------------------------------------------------------------
# snapshot 计数面
# ---------------------------------------------------------------------------

def test_snapshot_counters_and_version_ids():
    stage = _stage()
    v1 = stage.fuse(_finput(l1_object_refs=(_ref(track=7),)))
    v2 = stage.fuse(_finput(l1_object_refs=(_ref(track=7),),
                            l3_branches=(_branch("panorama", obs="后到"),)))
    stage.fuse(_finput(l1_object_refs=(_ref(track=7),)))   # 幂等命中
    try:
        stage.fuse(_finput(camera_id="cam-x"))             # 拒绝
    except FusionIdentityRejected:
        pass
    snap = stage.snapshot()
    assert snap["fused"] == 2
    assert snap["idempotent_hits"] == 1
    assert snap["identity_rejected"] == 1
    assert snap["versions"] == 2
    assert snap["version_ids"] == (v1.version_id, v2.version_id)
    assert snap["camera_id"] == "cam-1"


# ---------------------------------------------------------------------------
# C-137 D1：指纹 v2 覆盖面——改任一被覆盖字段必新指纹，全同必同指纹
# ---------------------------------------------------------------------------

def test_d1_fingerprint_covers_candidate_obj_frame_and_stable():
    r7, r8 = _ref(track=7), _ref(track=8)

    def fp(subj, obj):
        return fusion_fingerprint(_finput(l2_candidates=(_cand(subj, obj,
                                                           "near", 0.7),)))

    base = fp(r7, r8)
    assert fp(_ref(track=7), _ref(track=8)) == base          # 全同 → 同指纹
    assert fp(r7, _ref(track=9)) != base                     # 改 obj → 新指纹
    assert fp(_ref(frame="f2", track=7), r8) != base         # 改 subject 帧身份
    assert fp(ObjectRef(r7.object_id, "f1", False), r8) != base  # stable 位
    assert fp(r7, ObjectRef(r8.object_id, "f1", False)) != base  # obj stable 位
    assert fusion_fingerprint(_finput(l2_candidates=(
        _cand(r7, r8, "near", 0.7),))) != fusion_fingerprint(_finput(
        l2_candidates=(_cand(r7, r8, "holding", 0.7),)))     # 改 relation
    assert fusion_fingerprint(_finput(l2_candidates=(
        _cand(r7, r8, "near", 0.71),))) != fusion_fingerprint(_finput(
        l2_candidates=(_cand(r7, r8, "near", 0.7),)))        # 改 score_raw
    assert fusion_fingerprint(_finput(l2_candidates=(
        _cand(r7, r8, "near", 0.7, graph="semantic"),))) != fusion_fingerprint(
        _finput(l2_candidates=(_cand(r7, r8, "near", 0.7),)))  # 改 graph
    assert fusion_fingerprint(_finput(l2_candidates=(
        _cand(r7, r8, "near", 0.7, vocab="v9"),))) != fusion_fingerprint(
        _finput(l2_candidates=(_cand(r7, r8, "near", 0.7),)))  # 改 vocabulary


def test_d1_fingerprint_covers_l3_crop_model_window_and_frame_sources():
    def build(crop_id="c-1", model_ref="m-1", win="w-1", frame_id="f1",
              ts_kind="source_capture", obs="同文本观察"):
        return _finput(l3_branches=(_branch(
            "relation_crop", obs=obs, window=_l3win(win=win),
            crop_id=crop_id, model_ref=model_ref,
            sources=(_l3src(frame_id=frame_id, timestamp_kind=ts_kind),)),))

    base = fusion_fingerprint(build())
    assert fusion_fingerprint(build()) == base                # 全同 → 同指纹
    assert fusion_fingerprint(build(crop_id="c-2")) != base   # 改 crop 来源
    assert fusion_fingerprint(build(model_ref="m-2")) != base  # 改 model_ref
    assert fusion_fingerprint(build(win="w-2")) != base       # 改分支 window
    assert fusion_fingerprint(build(frame_id="f9")) != base   # 改帧来源
    assert fusion_fingerprint(build(ts_kind="host_receive")) != base
    assert fusion_fingerprint(build(obs="另一文本")) != base   # 改观察文本


def test_d1_fingerprint_covers_failure_gap_lists_itemized():
    def build(failures=(), gaps=()):
        return _finput(failures=failures, gaps=gaps, clock_kinds=())

    base = build(failures=({"source": "l2", "code": "timeout"},),
                 gaps=({"kind": "frame", "detail": "prev"},))
    assert fusion_fingerprint(base) == fusion_fingerprint(build(
        failures=({"source": "l2", "code": "timeout"},),
        gaps=({"kind": "frame", "detail": "prev"},)))         # 全同 → 同指纹
    assert fusion_fingerprint(base) != fusion_fingerprint(build(
        failures=({"source": "l2", "code": "timeout", "detail": "x"},),
        gaps=({"kind": "frame", "detail": "prev"},)))         # 失败条目变化
    assert fusion_fingerprint(base) != fusion_fingerprint(build(
        failures=({"source": "l2", "code": "timeout"},),
        gaps=({"kind": "frame", "detail": "next"},)))         # 缺失条目变化
    assert fusion_fingerprint(base) != fusion_fingerprint(build(
        failures=({"source": "l2", "code": "cancelled"},),
        gaps=({"kind": "frame", "detail": "prev"},)))         # 取消码变化


def test_d1_same_fingerprint_idempotent_via_fuse():
    def build():
        return _finput(l3_branches=(_branch(
            "relation_crop", obs="同文本", crop_id="c-1", model_ref="m-1",
            window=_l3win()),))

    stage = _stage()
    v1 = stage.fuse(build())
    v2 = stage.fuse(build())
    assert v2 is v1                       # 同指纹幂等：返回既有版本对象
    assert stage.versions() == (v1,)
    assert stage.snapshot()["idempotent_hits"] == 1


# ---------------------------------------------------------------------------
# C-137 D2：L3 分支自带 window 与顶层四元逐字段核对 → 拒绝 + 原因清单
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field,value", [
    ("camera_id", "cam-2"),
    ("run_id", "run-2"),
    ("config_version", "cfg-2"),
    ("window_id", "w-9"),
])
def test_d2_branch_window_mismatch_rejected_with_reason_list(field, value):
    # 顶层四元合法且与绑定一致，仅分支自带 window 的单字段与顶层不符
    window = _l3win()
    setattr(window, field, value)
    branch = _branch("panorama", obs="有人", window=window)
    stage = _stage()
    with pytest.raises(FusionIdentityRejected, match="identity_rejected") as ei:
        stage.fuse(_finput(l3_branches=(branch,)))
    reasons = ei.value.details["reasons"]
    assert len(reasons) == 1
    assert reasons[0]["branch"] == "panorama"
    assert reasons[0]["mismatched_fields"] == [field]
    assert stage.versions() == ()
    assert stage.snapshot()["identity_rejected"] == 1


def test_d2_top_level_mismatch_still_rejected_with_branches_present():
    """顶层 camera 与绑定不符（分支 window 同样不符）→ 绑定红线优先拒绝，
    同样不产版本（拒绝语义不因分支窗口缺失而放行）。"""
    branch = _branch("panorama", obs="有人", window=_l3win())
    stage = _stage()
    with pytest.raises(FusionIdentityRejected, match="identity_rejected"):
        stage.fuse(_finput(l3_branches=(branch,), camera_id="cam-2"))
    assert stage.versions() == ()


def test_d2_matching_branch_window_and_absent_window_accepted():
    matched = _stage().fuse(_finput(l3_branches=(
        _branch("panorama", obs="有人", window=_l3win()),)))
    assert matched.status == "ok"
    unmarked = _stage().fuse(_finput(l3_branches=(
        _branch("panorama", obs="无自带窗口身份"),)))
    assert unmarked.status == "ok"        # 未携带 window 不猜：不伪造拒绝


# ---------------------------------------------------------------------------
# C-137 D3：同窗累计——追加语义 / 幂等 / 有界归档 / 终结清理
# ---------------------------------------------------------------------------

def test_d3_accumulate_retains_prior_materials_and_appends_new():
    r7 = _ref(track=7)
    pano = _branch("panorama", obs="全景：有人影", window=_l3win(),
                   crop_id="whole")
    local = _branch("relation_crop", obs="局部：杯子被拿起", window=_l3win(),
                    crop_id="c-1", model_ref="m-1")
    stage = _stage()
    key = _wkey()
    v1 = stage.accumulate(key, _finput(l1_object_refs=(r7,),
                                       l3_branches=(pano,)))
    v2 = stage.accumulate(key, _finput(l1_object_refs=(r7,),
                                       l3_branches=(pano, local)))
    assert stage.versions(key) == (v1, v2)          # 只读时间序
    assert v1.version_id != v2.version_id           # 材料集变化 → 新版本
    v2_texts = [it.text for it in v2.items]
    assert "全景：有人影" in v2_texts                # 前版本材料保留
    assert "局部：杯子被拿起" in v2_texts            # 新增材料并入
    assert any(it.kind == "observation" and it.certainty == "observed"
               for it in v2.items)                  # L1 材料同样保留
    pano_item = [it for it in v2.items if it.text == "全景：有人影"][0]
    assert pano_item.sources[0].ref == "panorama@whole"   # 来源随材料保留
    assert v2.status == "ok"


def test_d3_accumulate_appends_failure_as_missing_factor_and_partial():
    stage = _stage()
    key = _wkey()
    pano = _branch("panorama", obs="全景观察", window=_l3win())
    v1 = stage.accumulate(key, _finput(l3_branches=(pano,)))
    assert v1.status == "ok"
    v2 = stage.accumulate(key, _finput(
        l3_branches=(pano,),
        failures=({"source": "l3", "code": "cancelled", "detail": "分支取消"},)))
    assert v2.status == "partial"                    # 失败因素进入 status
    assert len(_find(v2, "失败：l3 cancelled：分支取消")) == 1
    assert len(_find(v2, "全景观察")) == 1           # 前版本材料仍在


def test_d3_accumulate_same_input_idempotent_no_append():
    stage = _stage()
    key = _wkey()
    v1 = stage.accumulate(key, _finput(l3_branches=(
        _branch("panorama", obs="同输入观察", window=_l3win()),)))
    v2 = stage.accumulate(key, _finput(l3_branches=(   # 重建等价输入（非同对象）
        _branch("panorama", obs="同输入观察", window=_l3win()),)))
    assert v2 is v1
    assert len(stage.versions(key)) == 1
    assert stage.snapshot()["idempotent_hits"] == 1


def test_d3_accumulate_late_resubmission_of_old_input_is_idempotent():
    """材料集不变的重提交（晚到重试）→ 指纹不变 → 幂等返回既有版本。"""
    stage = _stage()
    key = _wkey()
    pano = _branch("panorama", obs="全景观察", window=_l3win())
    v1 = stage.accumulate(key, _finput(l3_branches=(pano,)))
    v2 = stage.accumulate(key, _finput(l3_branches=(
        pano, _branch("relation_crop", obs="局部观察", window=_l3win(),
                      crop_id="c-1"))))
    stage.accumulate(key, _finput(l3_branches=(pano,)))   # 旧输入重试
    assert stage.versions(key) == (v1, v2)                # 不追加
    assert len(stage.versions(key)) == 2


@pytest.mark.parametrize("key,kw", [
    (_wkey(cfg="cfg-2"), {"config_version": "cfg-2"}),   # key 前三元≠绑定
    (_wkey(win="w-1"), {"window_id": "w-2"}),            # key 四元≠输入顶层
])
def test_d3_accumulate_key_mismatch_rejected_no_version(key, kw):
    stage = _stage()
    with pytest.raises(FusionIdentityRejected, match="identity_rejected"):
        stage.accumulate(key, _finput(**kw))
    assert stage.versions(key) == ()
    assert stage.snapshot()["identity_rejected"] == 1


def test_d3_versions_bounded_archived_mark_and_cleanup():
    stage = _stage()
    key = _wkey()
    versions = [stage.accumulate(key, _finput(
        gaps=({"kind": "frame", "detail": f"g{k}"},), clock_kinds=()))
        for k in range(MAX_WINDOW_VERSIONS + 2)]
    assert len(stage.versions(key)) == MAX_WINDOW_VERSIONS + 2
    assert versions[0].archived is True                  # 超出 → 最旧归档标记
    assert versions[1].archived is True
    assert versions[MAX_WINDOW_VERSIONS - 1].archived is False
    assert versions[MAX_WINDOW_VERSIONS].archived is False
    assert stage.versions(key)[-1].archived is False
    assert stage.snapshot()["archived_versions"] == 2
    removed = stage.cleanup(key)                         # 终结清理
    assert removed == {"removed_versions": MAX_WINDOW_VERSIONS + 2,
                       "archived": 2}
    assert stage.versions(key) == ()
    fresh = stage.accumulate(key, _finput(
        gaps=({"kind": "frame", "detail": "g0"},), clock_kinds=()))
    assert len(stage.versions(key)) == 1 and fresh is not versions[0]
    assert stage.cleanup(_wkey(win="w-none")) == {"removed_versions": 0,
                                                  "archived": 0}


# ---------------------------------------------------------------------------
# C-137 D4：双 crop 同文本 → 合并一条 + sources 并集 + JSON 可持久化
# ---------------------------------------------------------------------------

def test_d4_dual_crop_same_text_merged_with_union_sources_json_safe():
    same_text = "杯子被手持"
    version = _stage().fuse(_finput(l3_branches=(
        _branch("relation_crop", obs=same_text, crop_id="c-1",
                model_ref="m-1"),
        _branch("relation_crop", obs=same_text, crop_id="c-2",
                model_ref="m-1"),
    )))
    merged = _find(version, same_text)
    assert len(merged) == 1                       # 合并为一条展示
    refs = {src.ref for src in merged[0].sources}
    assert refs == {"relation_crop@c-1|m-1", "relation_crop@c-2|m-1"}
    assert all(src.kind == "l3_branch" for src in merged[0].sources)
    # 纯数据可 JSON 持久化（重启后仍可查看——无对象引用）
    payload = [{"kind": s.kind, "ref": s.ref} for s in merged[0].sources]
    assert json.loads(json.dumps(payload)) == payload


def test_d4_sources_carry_model_ref_and_distinct_models_kept_both():
    same_text = "同一结论两种模型来源"
    version = _stage().fuse(_finput(l3_branches=(
        _branch("panorama", obs=same_text, crop_id="whole", model_ref="m-a"),
        _branch("panorama", obs=same_text, crop_id="whole", model_ref="m-b"),
    )))
    merged = _find(version, same_text)
    assert len(merged) == 1
    assert {src.ref for src in merged[0].sources} == {
        "panorama@whole|m-a", "panorama@whole|m-b"}


# ---------------------------------------------------------------------------
# C-137 D5：最小时空对齐字段
# ---------------------------------------------------------------------------

def test_d5_stable_ref_alignment_merges_across_frames():
    r7a = _ref(frame="f1", track=7)
    r7b = _ref(frame="f2", track=7)               # 同一稳定 track，不同帧
    assert r7a.object_id == r7b.object_id
    frame_refs = (
        FusionFrameRef("f1", 1000.0, "source_capture", (0.1, 0.1, 0.2, 0.2),
                       None, r7a.object_id),
        FusionFrameRef("f2", 1300.0, "source_capture", (0.12, 0.1, 0.2, 0.2),
                       None, r7b.object_id),
    )
    version = _stage().fuse(_finput(l1_object_refs=(r7a, r7b),
                                    frame_refs=frame_refs))
    obs = [it for it in _by_kind(version, "observation")
           if it.certainty == "observed"]
    assert len(obs) == 1                          # 稳定引用对齐合并为同一对象
    assert obs[0].sources[0].ref == r7a.object_id
    assert not _find(version, "对齐不确定")        # 明确可比 → 无不确定性标注
    assert version.status == "ok"
    assert version.coord_space == "normalized"
    assert version.frame_refs == frame_refs       # 对齐字段随版本携带


def test_d5_spatial_overlap_without_shared_stable_ref_kept_both_annotated():
    ra = _ref(frame="f1", track=7)
    rb = _ref(frame="f1", track=8)                # 不同稳定身份，区域重叠
    frame_refs = (
        FusionFrameRef("f1", 1000.0, "source_capture", (0.1, 0.1, 0.3, 0.3),
                       None, ra.object_id),
        FusionFrameRef("f1", 1000.0, "source_capture", (0.15, 0.15, 0.3, 0.3),
                       None, rb.object_id),
    )
    version = _stage().fuse(_finput(l1_object_refs=(ra, rb),
                                    frame_refs=frame_refs))
    obs = [it for it in _by_kind(version, "observation")
           if it.certainty == "observed"]
    assert len(obs) == 2                          # 空间重叠不合并对象
    annotated = _find(version, "对齐不确定")
    assert len(annotated) == 1
    assert annotated[0].kind == "gap"
    assert annotated[0].certainty == "unknown"
    assert "保留双方" in annotated[0].text
    assert version.status == "partial"            # 不确定因素进入 status


def test_d5_unstable_refs_overlap_kept_both_annotated():
    ra = _ref(frame="f0", stable=False, idx=0)
    rb = _ref(frame="f1", stable=False, idx=0)
    frame_refs = (
        FusionFrameRef("f0", 900.0, "source_capture", (0.0, 0.0, 0.5, 0.5)),
        FusionFrameRef("f1", 1000.0, "source_capture", (0.2, 0.2, 0.5, 0.5)),
    )
    version = _stage().fuse(_finput(l1_object_refs=(ra, rb),
                                    frame_refs=frame_refs))
    assert len([it for it in _by_kind(version, "observation")
                if it.certainty == "observed"]) == 2   # 帧内引用不合并
    assert len(_find(version, "对齐不确定")) == 1       # 身份不确定 → 标注
    assert version.status == "partial"


def test_d5_frame_refs_time_kinds_carried_verbatim_unknown_not_ordered():
    pano = _branch("panorama", obs="全景观察记录",
                   sources=(_l3src(frame_id="f1", t_capture_ms=900.0),))
    local = _branch("relation_crop", obs="局部观察记录",
                    sources=(_l3src(frame_id="f2", t_capture_ms=100.0),))
    frame_refs = (
        FusionFrameRef("f1", 900.0, "source_capture", (0.0, 0.0, 1.0, 1.0)),
        FusionFrameRef("f2", None, "unknown"),   # 时间值/类型未知如实携带
    )
    version = _stage().fuse(_finput(
        l3_branches=(pano, local), frame_refs=frame_refs,
        clock_kinds=("source_capture", "unknown")))
    kinds = [ref.time_kind for ref in version.frame_refs]
    assert kinds == ["source_capture", "unknown"]   # 真实类型透传，不写死
    assert version.frame_refs[1].t_ms is None       # 未知时间不伪造
    assert len(_find(version, "时钟类型不可比")) == 1
    # 不强排：pano(t=900) 仍在 local(t=100) 之前（输入序，绝不按时间排序）
    pano_item = _find(version, "全景观察记录")[0]
    local_item = _find(version, "局部观察记录")[0]
    assert version.items.index(pano_item) < version.items.index(local_item)
    assert version.status == "partial"


# ---------------------------------------------------------------------------
# C-137 D6：因素透传（失败/缺失/时钟类型逐项进版本；不恒传空清单）
# ---------------------------------------------------------------------------

def test_d6_factors_propagated_itemized_and_partial():
    inp = _finput(
        l3_branches=(_branch("panorama", obs="有观察", window=_l3win()),),
        failures=({"source": "l2", "code": "budget_evicted",
                   "detail": "crop_dropped=1"},
                  {"source": "l3", "code": "cancelled",
                   "detail": "窗口取消"}),
        gaps=({"kind": "frame", "detail": "prev 缺失"},),
        clock_kinds=("host_receive",))
    version = _stage().fuse(inp)
    # 逐项透传：每个失败/缺失条目各自成条，原文细节逐字出现
    assert len(_find(version, "失败：l2 budget_evicted：crop_dropped=1")) == 1
    assert len(_find(version, "失败：l3 cancelled：窗口取消")) == 1
    assert len(_find(version, "缺失：frame prev 缺失")) == 1
    clock_gaps = _find(version, "时钟类型不可比")
    assert len(clock_gaps) == 1
    assert "host_receive" in clock_gaps[0].text     # 真实时钟类型传播（不写死）
    gap_texts = [it.text for it in _by_kind(version, "gap")]
    assert len(gap_texts) == 4                      # 3 项清单 + 1 时钟因素
    assert version.status == "partial"              # 因素进入 status 判定


def test_d6_no_factors_no_fabricated_gaps():
    """输入无失败/缺失/时钟因素 → 版本不携带任何 gap（禁止恒传空清单的
    反面：也不凭空造因素）。"""
    version = _stage().fuse(_finput(
        l3_branches=(_branch("panorama", obs="正常观察"),),
        clock_kinds=("source_capture",)))
    assert _by_kind(version, "gap") == []
    assert _by_kind(version, "conflict") == []
    assert version.status == "ok"


# ---------------------------------------------------------------------------
# C-138 B1：累计结构化材料——针对累计集重算冲突，任意到达顺序结果一致
# ---------------------------------------------------------------------------

_OBS_ONE = "画面中有一个人在桌边"
_OBS_TWO = "桌边有两个人在交谈"
# 材料身份与内容绑定（同观察恒同 crop_id）——不同到达顺序下累计集相同
_OBS_CROPS = {_OBS_ONE: "c-1", _OBS_TWO: "c-2"}


def _obs_batch(text):
    return _finput(l3_branches=(_branch("panorama", obs=text,
                                        window=_l3win(),
                                        crop_id=_OBS_CROPS[text]),))


def _items_signature(version):
    return sorted((item.kind, item.text) for item in version.items)


def _sources_signature(version):
    return sorted((item.kind, item.text,
                   sorted((src.kind, src.ref) for src in item.sources))
                  for item in version.items)


def _accumulate_all(batches):
    stage, key, last = _stage(), _wkey(), None
    for batch in batches:
        last = stage.accumulate(key, batch)
    return last


def test_b1_person_count_conflict_identical_across_arrival_orders():
    orders = (
        (_OBS_ONE, _OBS_TWO),                    # 先1后2
        (_OBS_TWO, _OBS_ONE),                    # 先2后1
        (_OBS_ONE, _OBS_TWO, _OBS_ONE, _OBS_TWO),  # 交错+重复材料（幂等）
    )
    finals = [_accumulate_all([_obs_batch(text) for text in order])
              for order in orders]
    base = finals[0]
    for other in finals[1:]:
        assert _items_signature(other) == _items_signature(base)
        assert _sources_signature(other) == _sources_signature(base)
        assert other.version_id == base.version_id   # 同累计集必同指纹
    # 两观察并存 + conflict（unknown，双方保留，不投票不强选）
    texts = [item.text for item in base.items]
    assert _OBS_ONE in texts and _OBS_TWO in texts
    conflicts = _by_kind(base, "conflict")
    assert len(conflicts) == 1
    assert conflicts[0].certainty == "unknown"
    assert "1人" in conflicts[0].text and "2人" in conflicts[0].text
    assert {src.ref for src in conflicts[0].sources} == {"panorama@c-1",
                                                         "panorama@c-2"}
    assert base.status == "partial"


def test_b1_candidate_vs_narrative_orders_deterministic():
    r7, r8 = _ref(track=7), _ref(track=8)

    def cand_batch():
        return _finput(l2_candidates=(_cand(r7, r8, "holding", score=0.92),))

    def narr_batch():
        return _finput(l3_branches=(_branch(
            "panorama", obs="未检测到 holding 行为：杯子仍在桌上。",
            window=_l3win(), crop_id="whole"),))

    orders = (
        (cand_batch(), narr_batch()),            # 先候选后否定叙事
        (narr_batch(), cand_batch()),            # 反序
        (cand_batch(), narr_batch(), cand_batch()),  # 交错+重复材料
    )
    finals = [_accumulate_all(order) for order in orders]
    base = finals[0]
    for other in finals[1:]:
        assert _items_signature(other) == _items_signature(base)
        assert _sources_signature(other) == _sources_signature(base)
        assert other.version_id == base.version_id
    inf_items = _by_kind(base, "inference")
    assert len(inf_items) == 1
    assert inf_items[0].certainty == "model_inferred"   # 候选不升级
    assert len(_find(base, "杯子仍在桌上")) == 1         # 叙事观察在
    conflicts = _by_kind(base, "conflict")
    assert len(conflicts) == 1
    assert conflicts[0].certainty == "unknown"
    assert {src.kind for src in conflicts[0].sources} == {"l2_candidate",
                                                          "l3_branch"}
    assert base.status == "partial"


# ---------------------------------------------------------------------------
# C-138 B2：后版本携带完整历史因素；坐标体系/时钟不可比显式标记
# ---------------------------------------------------------------------------

def test_b2_later_version_carries_full_history_factors_and_refs():
    r7 = _ref(track=7)
    pano = _branch("panorama", obs="全景：有人影", window=_l3win(),
                   crop_id="whole")
    ref_a = FusionFrameRef("f1", 1000.0, "source_capture",
                           (0.1, 0.1, 0.2, 0.2), None, r7.object_id)
    stage, key = _stage(), _wkey()
    v1 = stage.accumulate(key, _finput(
        l1_object_refs=(r7,), l3_branches=(pano,),
        gaps=({"kind": "frame", "detail": "prev 缺失"},),
        frame_refs=(ref_a,)))
    late = _branch("relation_crop", obs="局部：杯子被拿起", window=_l3win(),
                   crop_id="c-1", model_ref="m-1")
    ref_b = FusionFrameRef("f2", 1300.0, "source_capture",
                           (0.3, 0.3, 0.2, 0.2), None, None)
    v2 = stage.accumulate(key, _finput(
        l3_branches=(late,), frame_refs=(ref_b,),
        failures=({"source": "l3", "code": "cancelled",
                   "detail": "分支取消"},)))
    # 前版本全部对象引用/观察/缺失因素 + 新材料（新批次未重提交旧材料）
    assert any(item.kind == "observation" and item.certainty == "observed"
               and r7.object_id in item.text for item in v2.items)
    v2_texts = [item.text for item in v2.items]
    assert "全景：有人影" in v2_texts
    assert "缺失：frame prev 缺失" in v2_texts
    assert "局部：杯子被拿起" in v2_texts
    assert "失败：l3 cancelled：分支取消" in v2_texts
    # frame_refs 并集（各帧声明随行）；来源并集含前批次分支来源
    assert {ref.frame_id for ref in v2.frame_refs} == {"f1", "f2"}
    pano_item = [it for it in v2.items if it.text == "全景：有人影"][0]
    assert pano_item.sources[0].ref == "panorama@whole"
    assert v2.status == "partial"
    # 旧版本原样保留（渐进版本不重写历史）
    assert v1.frame_refs == (ref_a,)
    assert "缺失：frame prev 缺失" in [it.text for it in v1.items]


def test_b2_coord_space_mismatch_marked_and_old_declaration_kept():
    ref_norm = FusionFrameRef("f1", 1000.0, "source_capture",
                              (0.1, 0.1, 0.4, 0.4))          # normalized
    ref_pix = FusionFrameRef("f2", 1000.0, "source_capture",
                             (0.2, 0.2, 0.2, 0.2), None, None, "pixels")
    stage, key = _stage(), _wkey()
    v1 = stage.accumulate(key, _finput(
        l3_branches=(_branch("panorama", obs="归一化体系观察",
                             window=_l3win(), crop_id="whole"),),
        frame_refs=(ref_norm,)))
    assert v1.coord_space == "normalized"
    # 新批声明 pixels（数值区域与 f1 重叠，但体系不同不比较）
    v2 = stage.accumulate(key, FusionInput(
        "cam-1", "run-1", "cfg-1", "w-1",
        l3_branches=(_branch("panorama", obs="像素体系观察",
                             window=_l3win(), crop_id="whole"),),
        coord_space="pixels", frame_refs=(ref_pix,),
        clock_kinds=("source_capture",)))
    marked = _find(v2, "坐标体系不一致")
    assert len(marked) == 1
    assert marked[0].kind == "gap" and marked[0].certainty == "unknown"
    assert "normalized" in marked[0].text and "pixels" in marked[0].text
    assert v2.coord_space == "mixed:normalized|pixels"   # 联合声明，不覆盖
    assert {ref.coord_space for ref in v2.frame_refs} == {"normalized",
                                                          "pixels"}
    assert [it.text for it in v2.items if it.text == "归一化体系观察"]
    # 跨体系不比较：区域数值重叠但不产生跨体系"对齐不确定"标注
    assert not _find(v2, "对齐不确定")
    assert v2.status == "partial"


def test_b2_clock_incomparability_judged_on_cumulative_union():
    stage, key = _stage(), _wkey()
    v1 = stage.accumulate(key, _finput(l3_branches=(
        _branch("panorama", obs="采集钟观察", window=_l3win(),
                crop_id="whole"),)))
    assert not _find(v1, "时钟类型不可比")          # 单一可比时钟：无标记
    v2 = stage.accumulate(key, _finput(l3_branches=(
        _branch("relation_crop", obs="接收钟观察", window=_l3win(),
                crop_id="c-1"),),
        clock_kinds=("source_capture", "host_receive")))
    clock_gaps = _find(v2, "时钟类型不可比")
    assert len(clock_gaps) == 1
    assert clock_gaps[0].certainty == "unknown"
    assert "host_receive" in clock_gaps[0].text
    assert "source_capture" in clock_gaps[0].text   # 并集判定，不继承新声明
    assert v2.status == "partial"


# ---------------------------------------------------------------------------
# C-138 B3：缓存硬上限——真淘汰/淘汰回调/重提交如实计数/两态
# ---------------------------------------------------------------------------

def _acc_batch(win, obs):
    return _finput(window_id=win, l3_branches=(_branch(
        "panorama", obs=obs, window=_l3win(win=win), crop_id="whole"),))


def test_b3_seventeenth_window_evicts_oldest_active_for_real():
    seen = []
    stage = L4Stage("cam-1", "run-1", "cfg-1",
                    evict_callback=lambda key, versions:
                        seen.append((key, versions)))
    keys = [_wkey(win=f"w-{i:02d}") for i in range(17)]
    version_by_key = {}
    for k in keys:
        version_by_key[k] = stage.accumulate(k, _acc_batch(k[3], f"观察{k[3]}"))
    oldest = keys[0]
    # 真淘汰内存口径：versions(key) 不可达 + 计数（非仅 archived 标记）
    assert stage.versions(oldest) == ()
    assert stage.window_state(oldest) is None
    snap = stage.snapshot()
    assert snap["windows"] == 16
    assert snap["windows_active"] == 16 and snap["windows_archived"] == 0
    assert snap["windows_evicted"] == 1
    assert stage.versions(keys[1]) == (version_by_key[keys[1]],)
    assert version_by_key[oldest].archived is False   # 是删除，不是归档
    # 淘汰回调收到该窗全部版本数据（供持久化）
    assert len(seen) == 1
    evicted_key, evicted_versions = seen[0]
    assert evicted_key == oldest
    assert [v.version_id for v in evicted_versions] == \
        [version_by_key[oldest].version_id]


def test_b3_resubmission_after_eviction_counts_as_new_material():
    stage = L4Stage("cam-1", "run-1", "cfg-1")
    key = _wkey()
    v1 = stage.accumulate(key, _acc_batch("w-1", "首轮观察"))
    for i in range(1, 17):
        stage.accumulate(_wkey(win=f"w-{i:02d}"),
                         _acc_batch(f"w-{i:02d}", f"填充{i}"))
    assert stage.versions(key) == ()                  # 已被真淘汰
    before = stage.snapshot()
    v2 = stage.accumulate(key, _acc_batch("w-1", "首轮观察"))  # 同指纹重提交
    assert v2 is not v1
    assert stage.versions(key) == (v2,)
    after = stage.snapshot()
    assert after["accumulated"] == before["accumulated"] + 1
    assert after["idempotent_hits"] == before["idempotent_hits"]


def test_b3_archive_two_states_readonly_then_cleanup():
    stage = L4Stage("cam-1", "run-1", "cfg-1")
    key = _wkey()
    v1 = stage.accumulate(key, _acc_batch("w-1", "终结前观察"))
    assert stage.window_state(key) == "active"
    assert stage.archive_window(key) is True
    assert stage.window_state(key) == "archived"      # 仍占缓存
    assert stage.versions(key) == (v1,)               # 证据仍可达
    snap = stage.snapshot()
    assert snap["windows_archived"] == 1
    assert snap["windows_active"] == 0 and snap["windows"] == 1
    with pytest.raises(ValueError, match="archived"):
        stage.accumulate(key, _acc_batch("w-1", "归档后再累计"))
    assert stage.versions(key) == (v1,)               # 只读：未新增版本
    assert stage.snapshot()["accumulated"] == 1
    assert stage.archive_window(key) is True          # 幂等
    assert stage.archive_window(_wkey(win="w-none")) is False
    removed = stage.cleanup(key)                      # 归档窗可清理
    assert removed == {"removed_versions": 1, "archived": 0}
    assert stage.window_state(key) is None
    assert stage.versions(key) == ()


def test_b3_archived_window_survives_active_eviction_pressure():
    stage = L4Stage("cam-1", "run-1", "cfg-1", max_active_windows=2)
    keep = _wkey(win="w-keep")
    stage.accumulate(keep, _acc_batch("w-keep", "归档保留窗"))
    stage.archive_window(keep)
    key_a, key_b, key_c = (_wkey(win=f"w-{n}") for n in ("a", "b", "c"))
    stage.accumulate(key_a, _acc_batch("w-a", "A"))
    stage.accumulate(key_b, _acc_batch("w-b", "B"))        # 满 2 窗
    stage.accumulate(key_c, _acc_batch("w-c", "C"))        # 超限→淘汰最旧活跃
    assert stage.versions(key_a) == ()
    assert stage.versions(keep) != ()                 # 归档窗不被活跃淘汰压力回收
    assert stage.window_state(keep) == "archived"
    key_d = _wkey(win="w-d")
    stage.accumulate(key_d, _acc_batch("w-d", "D"))        # 再超限→淘汰 b，后 c
    assert stage.versions(key_b) == ()
    assert stage.versions(key_c) == ()
    assert stage.versions(keep) != ()
    snap = stage.snapshot()
    assert snap["windows"] == 2 and snap["windows_evicted"] == 3


def test_b3_archived_window_evicted_only_as_last_resort():
    seen = []
    stage = L4Stage("cam-1", "run-1", "cfg-1", max_active_windows=1,
                    evict_callback=lambda key, versions:
                        seen.append((key, versions)))
    only = _wkey(win="w-only")
    stage.accumulate(only, _acc_batch("w-only", "唯一窗"))
    stage.archive_window(only)
    other = _wkey(win="w-other")
    stage.accumulate(other, _acc_batch("w-other", "新窗"))  # 无活跃可淘汰
    assert stage.versions(only) == ()            # 归档窗最终被淘汰（硬上限）
    assert stage.versions(other) != ()
    assert stage.snapshot()["windows_evicted"] == 1
    assert seen[0][0] == only


def test_b3_evict_callback_failure_keeps_window_and_propagates():
    def boom(key, versions):
        raise RuntimeError("persist failed")

    stage = L4Stage("cam-1", "run-1", "cfg-1", max_active_windows=1,
                    evict_callback=boom)
    key_1, key_2 = _wkey(win="w-1"), _wkey(win="w-2")
    v1 = stage.accumulate(key_1, _acc_batch("w-1", "一"))
    with pytest.raises(RuntimeError, match="persist failed"):
        stage.accumulate(key_2, _acc_batch("w-2", "二"))
    assert stage.versions(key_1) == (v1,)         # 回调失败：该窗保持未删
    assert stage.window_state(key_2) is None      # 新窗不留空壳
    assert stage.snapshot()["windows"] == 1


def test_b3_max_active_windows_guard():
    with pytest.raises(ValueError, match="max_active_windows"):
        L4Stage("cam-1", "run-1", "cfg-1", max_active_windows=0)
    stage = L4Stage("cam-1", "run-1", "cfg-1", max_active_windows=1)
    assert stage.max_active_windows == 1
    default_stage = L4Stage("cam-1", "run-1", "cfg-1")
    assert default_stage.max_active_windows == MAX_ACTIVE_WINDOWS == 16


# ---------------------------------------------------------------------------
# C-139-R1 §2 / R2：L4 JSON-safe 双向序列化（血缘完整 + 关键类型校验）
# ---------------------------------------------------------------------------

def test_serialization_roundtrip_success_version_full_pedigree():
    """成功版本 to_json/from_json 往返：全 window 四元/字段等价、sources
    结构化保留（不 str() 压平）、bbox_norm 不丢、首版 parent=null。"""
    r7 = _ref(track=7)
    pano = _branch("panorama", obs="全景观察", window=_l3win(),
                   crop_id="whole")
    ref = FusionFrameRef("f1", 1000.0, "source_capture",
                         (0.1, 0.1, 0.2, 0.2), None, r7.object_id)
    v1 = _stage().accumulate(_wkey(), _finput(
        l1_object_refs=(r7,), l3_branches=(pano,), frame_refs=(ref,)))
    payload = l4c.fusion_version_to_json(v1)
    json.loads(json.dumps(payload))                    # JSON-safe
    assert payload["version_id"] == v1.version_id
    assert payload["status"] == "ok"
    assert (payload["camera_id"], payload["run_id"],
            payload["config_version"], payload["window_id"]) == \
        ("cam-1", "run-1", "cfg-1", "w-1")
    assert payload["coord_space"] == "normalized"
    assert payload["archived"] is False
    assert payload["parent_version_id"] is None        # 首版 null
    # sources 结构化 {kind, ref}：证据键可读，repr 字符串即缺陷
    for it in payload["items"]:
        for s in it["sources"]:
            assert set(s) == {"kind", "ref"}
    src_kinds = {s["kind"] for it in payload["items"]
                 for s in it["sources"]}
    assert {"l1_object", "l3_branch"} <= src_kinds
    (fr,) = payload["frame_refs"]                      # bbox_norm 不丢
    assert fr["frame_id"] == "f1" and fr["t_ms"] == 1000.0
    assert fr["time_kind"] == "source_capture"
    assert fr["bbox_norm"] == [0.1, 0.1, 0.2, 0.2]
    assert fr["coord_space"] == "normalized"
    assert fr["stable_ref"] == r7.object_id
    # 读回对照：关键字段等价（FusionVersion，非裸 dict）
    back = l4c.fusion_version_from_json(payload)
    assert isinstance(back, FusionVersion)
    assert back.version_id == v1.version_id and back.status == v1.status
    assert (back.camera_id, back.run_id, back.config_version,
            back.window_id) == (v1.camera_id, v1.run_id,
                                v1.config_version, v1.window_id)
    assert back.coord_space == v1.coord_space
    assert back.parent_version_id is None
    assert [(i.kind, i.text, i.certainty, i.unstructured)
            for i in back.items] == [(i.kind, i.text, i.certainty,
                                      i.unstructured) for i in v1.items]
    assert [sorted((s.kind, s.ref) for s in i.sources)
            for i in back.items] == \
        [sorted((s.kind, s.ref) for s in i.sources) for i in v1.items]
    (bref,) = back.frame_refs
    assert bref.frame_id == "f1" and bref.t_ms == 1000.0
    assert bref.bbox_norm == (0.1, 0.1, 0.2, 0.2)      # 往返不丢
    assert bref.stable_ref == r7.object_id
    assert bref.coord_space == "normalized"
    assert back.created_mono is None                   # 单调钟不序列化不伪造


def test_serialization_parent_chain_and_no_cross_window_linking():
    """parent_version_id：同窗首版 null、后续指向前版；跨窗绝不串链；
    幂等命中不追加不改链；to_json 携带父子关系。"""
    stage = _stage()
    key_a, key_b = _wkey(win="w-a"), _wkey(win="w-b")
    v1 = stage.accumulate(key_a, _acc_batch("w-a", "A1"))
    v2 = stage.accumulate(key_a, _acc_batch("w-a", "A2"))
    assert v1.parent_version_id is None                # 首版 null
    assert v2.parent_version_id == v1.version_id       # 后续指向前版
    other_first = stage.accumulate(key_b, _acc_batch("w-b", "B1"))
    assert other_first.parent_version_id is None       # 跨窗不串链
    v3 = stage.accumulate(key_a, _finput(
        window_id="w-a",
        failures=({"source": "l3", "code": "timeout"},)))
    assert v3.parent_version_id == v2.version_id       # 失败因素版本同链
    payload = l4c.fusion_version_to_json(v3)
    assert payload["parent_version_id"] == v2.version_id
    assert l4c.fusion_version_from_json(
        payload).parent_version_id == v2.version_id
    again = stage.accumulate(key_a, _finput(           # 幂等：不改链
        window_id="w-a",
        failures=({"source": "l3", "code": "timeout"},)))
    assert again is v3
    assert stage.versions(key_a) == (v1, v2, v3)


def test_serialization_failure_version_roundtrip():
    """失败版本（仅失败/缺失因素 → insufficient）to_json/from_json 往返：
    失败来源结构保留、gap 因素等价。"""
    v = _stage().accumulate(_wkey(), _finput(
        failures=({"source": "l3", "code": "load_timeout",
                   "detail": "加载超时"},),
        gaps=({"kind": "frame", "detail": "prev 缺失"},),
        clock_kinds=()))
    assert v.status == "insufficient"
    payload = l4c.fusion_version_to_json(v)
    json.loads(json.dumps(payload))
    assert {it["kind"] for it in payload["items"]} == {"gap"}
    fail_srcs = [s for it in payload["items"] for s in it["sources"]
                 if s["kind"] == "failure"]
    assert any("load_timeout" in s["ref"] for s in fail_srcs)
    back = l4c.fusion_version_from_json(payload)
    assert back.status == "insufficient"
    assert [(i.kind, i.text, i.certainty) for i in back.items] == \
        [(i.kind, i.text, i.certainty) for i in v.items]
    assert back.parent_version_id is None


def test_to_json_rejects_non_finite_values():
    """非有限数（NaN/Inf）→ ValueError 拒绝，绝不静默变 null（null 会在
    血缘里冒充"未知时间/未知区域"）。"""
    stage = _stage()
    nan_ref = FusionFrameRef("f1", float("nan"), "unknown")
    v = stage.fuse(_finput(frame_refs=(nan_ref,)))
    with pytest.raises(ValueError, match="non-finite"):
        l4c.fusion_version_to_json(v)
    inf_ref = FusionFrameRef("f1", 1000.0, "source_capture",
                             (float("inf"), 0.1, 0.2, 0.2))
    v2 = stage.fuse(_finput(window_id="w-2", frame_refs=(inf_ref,)))
    with pytest.raises(ValueError, match="non-finite"):
        l4c.fusion_version_to_json(v2)


def test_from_json_validates_key_types():
    """from_json 关键类型校验：version_id 非空 str、status 在值域、
    items/frame_refs 为 list、parent str/None、archived 布尔、item kind/
    certainty 与 source kind 在冻结值域——坏形状 ValueError 不静默。"""
    good = l4c.fusion_version_to_json(
        _stage().fuse(_finput(l1_object_refs=(_ref(track=7),))))
    assert isinstance(l4c.fusion_version_from_json(good), FusionVersion)
    mutations = (
        lambda d: d.update(version_id=None),
        lambda d: d.update(version_id=123),
        lambda d: d.update(version_id=""),
        lambda d: d.update(status="rejected"),
        lambda d: d.update(items={"kind": "gap"}),
        lambda d: d.update(frame_refs={}),
        lambda d: d.update(parent_version_id=99),
        lambda d: d.update(archived="yes"),
    )
    for mutate in mutations:
        bad = json.loads(json.dumps(good))
        mutate(bad)
        with pytest.raises(ValueError):
            l4c.fusion_version_from_json(bad)
    bad_item = json.loads(json.dumps(good))            # item kind 值域
    bad_item["items"].append({"kind": "action", "text": "x", "sources": [],
                              "certainty": "observed"})
    with pytest.raises(ValueError):
        l4c.fusion_version_from_json(bad_item)
    bad_cert = json.loads(json.dumps(good))            # certainty 值域
    bad_cert["items"][0]["certainty"] = "confirmed"
    with pytest.raises(ValueError):
        l4c.fusion_version_from_json(bad_cert)
    bad_src = json.loads(json.dumps(good))             # source kind 值域
    bad_src["items"][0]["sources"].append({"kind": "model", "ref": "x"})
    with pytest.raises(ValueError):
        l4c.fusion_version_from_json(bad_src)
    bad_time = json.loads(json.dumps(good))            # time_kind 值域
    bad_time["frame_refs"] = [{"frame_id": "f1", "t_ms": 1.0,
                               "time_kind": "wallclock"}]
    with pytest.raises(ValueError):
        l4c.fusion_version_from_json(bad_time)
