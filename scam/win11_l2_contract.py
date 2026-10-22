"""win11_l2_contract.py —— L2 关系层数据形状、预算与阶段合同（C-134 冻结；
C-135 §六 修订：全景/局部分支并存 + 真实预算 + L3 有序材料输出；C-136
C1/C2 修订：局部连续画面帧序列 + 缺帧固定序位 + crop_id 显式映射）。

C-134（docs/context/L2-接口冻结-C134.md）B 侧合同：全部数据形状（__slots__
类）+ L2Status + L2Budget + 身份校验助手 + L2RelationModel 协议 +
L2RelationStage（process(task)->L2Output，构造注入 model 与 budget）。
裁图数学委托 scam/win11_l2_crops.py（纯裁图引擎）；真实模型适配器归 C
（scam/win11_l2_backend.py，本模块不 import、不加载任何模型）。

C-135 §六 修订（与 C-134 冲突处以 C-135 为准，docs/context/
L2L3-接口冻结-C135.md）：
- 全景分支恒保留：有关系候选成功（status ok）也占首位槽 0（不是"没有
  裁图才补 fallback"）；装配优先级冻结：全景 > 关系裁图 > 变化区域兜底。
- L2Budget 字段重命名/新增（冻结）：max_crops_total（含全景）/max_crop_
  area_ratio / max_crop_pixels_fixed / max_crop_bytes——单张关系裁图三判据
  （占帧比例 / 绝对像素 / JPEG 编码字节，编码仅用于计量不落盘）独立验证
  取最严，取消 C-134"像素预算按帧面积同比放大"单判据；旧字段名
  max_crops/max_crop_pixels 全局一致保留为构造兼容别名 + 只读 property。
- 参与者覆盖不变式：去重合并后 CropRecord 的全部参与对象必须被实际裁框
  覆盖（引擎合并守卫 + verify_participant_coverage 构建后核验，相交
  ≥ 参与对象可见面积 50%）——记录与实际裁图一致，不能只追加候选来源
  却裁掉新增参与者。
- L2Output.l3_branches: tuple[L3BranchSpec]——L3 有序材料输出，与 crops
  一一对应；prev/next 检测缺失显式 None（材料包本就不携带前后帧检测，
  绝不复制当前帧框冒充）；enhanced 恒 None（为超分留位，显式未增强）；
  calibrated 恒 False。

分界红线（违反即缺陷）：
- 零 I/O、零模型加载、零 cv2 依赖；生产入口禁 fake；L2 永不进入快系统/L1
  线程；stage 持有模型引用计数=1，不重启被隔离的 adapter（重建由生产层决定）。
- 字段名冻结（C-134 §1 + C-135 §六），与草案/本文件冲突处以冻结文件为准。
- 身份：四元 (camera_id, run_id, config_version, frame_id) + material_id
  全匹配（M1）；prev/next 关联须同 camera/run/config/material 且 frame_id
  不同，错配→identity_rejected——不产候选、不产裁图、不调模型、不产
  L3 分支。
- 坐标：归一化→像素的唯一切换点在 stage（调 model 前一次完成）；adapter
  不做坐标数学；除该边界与 CropTransform 记录外不携带裸像素坐标。
- ObjectRef 引用 L1 侧身份，不新造：仅当 track_id 在场且 stable 才生成
  {cam}:{run}:track:{id}；否则帧内标识 {cam}:{run}:frame:{frame_id}:det:{idx}
  ——track_id 缺失时绝不伪造 track 引用；L3 分支不另造稳定关联标记。
- 状态互斥不互冒充：no_objects 是"未检测到"，不是"无事件/无风险"；
  失败态（model_unavailable/infer_failed/timeout/backend_isolated）与 no_*
  态严格分开。floor 分层：score≥relation_floor→候选；
  [low_conf_floor, relation_floor)→low_confidence_only；都不到→
  no_relation_above_floor。
- calibrated 恒 False：score_raw 是模型原始分，不是校准概率；候选不是已
  确认行为（C-133 §2.2 声明随输出传播，不得被中间层抹掉）。
- 兜底：全景帧（whole_frame_fallback）与门控变化区域
  （change_region_fallback）并存不互替；C-135 起全景在一切产裁图状态恒
  保留（含 ok/低分带/失败/零单对象）；identity_rejected/unsupported 不产
  任何裁图与 L3 分支。退化检出框（NaN/Inf/非正宽高/完全出帧）不参与
  配对，计数入 omission（C-133 T4）。
- l1_status 如实透传语义归生产接线（C-134 §4）：非 ok 材料不得以带框任务
  形态送入 stage；stage 按 task.detections 如实处理，不代行 L1 状态闸门。
"""

import enum
import math
import time

import numpy as np

__all__ = [
    "IDENTITY_FIELDS",
    "AdapterIsolated",
    "ChangeRegion",
    "CropRecord",
    "CropTransform",
    "DetectionView",
    "FrameIdentity",
    "L2Budget",
    "L2Omission",
    "L2Output",
    "L2RelationModel",
    "L2RelationStage",
    "L2Status",
    "L2TaskInput",
    "L3BranchSpec",
    "L3LocalFrameSlice",
    "ModelUnavailable",
    "ObjectRef",
    "RelationCandidate",
    "Uncertainty",
    "adjacent_identity_matches",
    "frame_object_ref",
    "identity_matches",
]

# M1 身份五字段：四元 + material_id（全匹配才允许关联）
IDENTITY_FIELDS = ("camera_id", "run_id", "config_version", "frame_id",
                   "material_id")

# L2Budget 旧字段名→新字段名的兼容别名裁决标记（仅"新字段未显式传入时
# 别名生效"；别名与新字段同时传入以新字段为准——全局一致，无随机性）
_UNSET = object()


# ---- 异常（C 适配器抛出；B 的 stage 分类映射，异常类定义在 contract 保持
#      B/C 分界干净：C import 本模块，B 不 import C） -----------------------

class ModelUnavailable(Exception):
    """关系模型不可用：依赖/权重缺失等结构性原因（C-134 §3，结构化）。"""

    def __init__(self, reason, details=None):
        super().__init__(reason)
        self.reason = reason
        self.details = details


class AdapterIsolated(Exception):
    """adapter 已被隔离：超时毒化后拒绝再接任务（C-134 §3）。

    不假装取消成功；残留占用由 snapshot 如实报告。stage 不重启被隔离的
    adapter——是否重建由生产层决定。
    """

    def __init__(self, reason, details=None):
        super().__init__(reason)
        self.reason = reason
        self.details = details


# ---- 数据形状（字段名冻结，C-134 §1 + C-135 §六；全 __slots__） -----------

class FrameIdentity:
    """材料包完整身份：四元 + material_id + 观察钟时间（C-132 F1/F8）。"""

    __slots__ = ("camera_id", "run_id", "config_version", "frame_id",
                 "material_id", "t_capture_ms", "timestamp_kind")

    def __init__(self, camera_id, run_id, config_version, frame_id,
                 material_id, t_capture_ms, timestamp_kind):
        self.camera_id = camera_id
        self.run_id = run_id
        self.config_version = config_version
        self.frame_id = frame_id
        self.material_id = material_id
        self.t_capture_ms = t_capture_ms
        self.timestamp_kind = timestamp_kind


class DetectionView:
    """L1 检出框只读视图：归一化 bbox[x,y,w,h]∈[0,1]；track_id None=帧内
    引用（stable=False）；不伪造 track_id。"""

    __slots__ = ("cls", "conf", "bbox_norm", "track_id", "stable")

    def __init__(self, cls, conf, bbox_norm, track_id, stable):
        self.cls = cls
        self.conf = conf
        self.bbox_norm = bbox_norm
        self.track_id = track_id
        self.stable = stable


class ChangeRegion:
    """门控变化区域（已归一化；gate→归一化换算归 L2 入口接线）。"""

    __slots__ = ("x", "y", "w", "h")

    def __init__(self, x, y, w, h):
        self.x = x
        self.y = y
        self.w = w
        self.h = h


class L2Budget:
    """预算档位（全部保守占位，原生实测前不宣称达标；字段名 C-135 §六 冻结）。

    - max_crops_total：任务裁图总数（**含全景**；全景恒占首位槽 0——优先级
      全景 > 关系裁图 > 变化区域兜底）。
    - max_crop_area_ratio / max_crop_pixels_fixed / max_crop_bytes：单张
      **关系裁图**三判据——占帧面积比例上限 / 绝对像素上限 / JPEG 编码后
      字节上限（编码仅用于计量不落盘）；三者独立验证取最严。全景与整帧
      替代不受单张预算约束（否则"全景恒保留"不可能成立）；变化区域仅受
      总数约束（门控给定区域，沿 C-134 口径不做单张判裁）。
    - 兼容别名（C-134 旧字段名，全局一致保留）：构造参数 max_crops→
      max_crops_total、max_crop_pixels→max_crop_pixels_fixed，仅当对应新
      字段未显式传入时生效；同名只读 property 透传新字段值。
    """

    __slots__ = ("max_candidates", "max_crops_total", "max_crop_area_ratio",
                 "max_crop_pixels_fixed", "max_crop_bytes", "relation_floor",
                 "low_conf_floor", "whole_frame_fallback",
                 "change_region_fallback")

    def __init__(self, max_candidates=8, max_crops_total=_UNSET,
                 max_crop_area_ratio=0.5, max_crop_pixels_fixed=_UNSET,
                 max_crop_bytes=256 * 1024, relation_floor=0.20,
                 low_conf_floor=0.10, whole_frame_fallback=True,
                 change_region_fallback=True, max_crops=None,
                 max_crop_pixels=None):
        self.max_candidates = max_candidates
        if max_crops_total is _UNSET:
            max_crops_total = 4 if max_crops is None else int(max_crops)
        self.max_crops_total = max_crops_total
        self.max_crop_area_ratio = max_crop_area_ratio
        if max_crop_pixels_fixed is _UNSET:
            max_crop_pixels_fixed = (640 * 640 if max_crop_pixels is None
                                     else int(max_crop_pixels))
        self.max_crop_pixels_fixed = max_crop_pixels_fixed
        self.max_crop_bytes = max_crop_bytes
        self.relation_floor = relation_floor
        self.low_conf_floor = low_conf_floor
        self.whole_frame_fallback = whole_frame_fallback
        self.change_region_fallback = change_region_fallback

    @property
    def max_crops(self):
        """兼容别名（只读）：= max_crops_total（C-134 旧字段名）。"""
        return self.max_crops_total

    @property
    def max_crop_pixels(self):
        """兼容别名（只读）：= max_crop_pixels_fixed（C-134 旧字段名）。"""
        return self.max_crop_pixels_fixed


class L2TaskInput:
    """单任务输入（只读）：cur 必有；prev/next 为 None 即显式缺失。

    prev/next 各自带自己的 detections——没有就是空 + l1_status 如实，
    绝不复制当前帧框冒充前后帧检测。frame_bgr 为隔离副本（M4），L2 只读。
    """

    __slots__ = ("identity", "frame_bgr", "width", "height", "detections",
                 "l1_status", "change_regions", "prev", "next", "prev_gap_ms",
                 "next_gap_ms", "vocabulary_id", "relation_vocabulary",
                 "budget")

    def __init__(self, identity, frame_bgr, width, height, detections,
                 l1_status, change_regions, prev, next, prev_gap_ms,
                 next_gap_ms, vocabulary_id, relation_vocabulary, budget):
        self.identity = identity
        self.frame_bgr = frame_bgr
        self.width = width
        self.height = height
        self.detections = detections
        self.l1_status = l1_status
        self.change_regions = change_regions
        self.prev = prev
        self.next = next
        self.prev_gap_ms = prev_gap_ms
        self.next_gap_ms = next_gap_ms
        self.vocabulary_id = vocabulary_id
        self.relation_vocabulary = relation_vocabulary
        self.budget = budget


class ObjectRef:
    """对象引用（不新造身份）：object_id = {cam}:{run}:track:{id}（stable）
    或 {cam}:{run}:frame:{frame_id}:det:{idx}（帧内）。"""

    __slots__ = ("object_id", "frame_id", "stable")

    def __init__(self, object_id, frame_id, stable):
        self.object_id = object_id
        self.frame_id = frame_id
        self.stable = stable


class Uncertainty:
    """候选不确定性标注集（全默认 False；可多选）。"""

    __slots__ = ("frame_missing_prev", "frame_missing_next",
                 "identity_uncertain", "drift", "pair_overlap_high",
                 "low_confidence")

    def __init__(self, frame_missing_prev=False, frame_missing_next=False,
                 identity_uncertain=False, drift=False, pair_overlap_high=False,
                 low_confidence=False):
        self.frame_missing_prev = frame_missing_prev
        self.frame_missing_next = frame_missing_next
        self.identity_uncertain = identity_uncertain
        self.drift = drift
        self.pair_overlap_high = pair_overlap_high
        self.low_confidence = low_confidence


class RelationCandidate:
    """关系候选三元组：score_raw 为模型原始分（未校准）；graph ∈
    spatial|semantic（上游双图机制，一对对象可同时出现在两图，非重复 bug）。
    """

    __slots__ = ("subject", "obj", "relation", "graph", "score_raw",
                 "vocabulary_id", "uncertainty")

    def __init__(self, subject, obj, relation, graph, score_raw,
                 vocabulary_id, uncertainty):
        self.subject = subject
        self.obj = obj
        self.relation = relation
        self.graph = graph
        self.score_raw = score_raw
        self.vocabulary_id = vocabulary_id
        self.uncertainty = uncertainty


class CropTransform:
    """裁图坐标变换记录：归一化与像素是同一变换的两种记录形式。

    坐标语义（冻结）：bbox_norm/union_norm 为整帧归一化 [x,y,w,h]，
    bbox_px 为整帧像素 [x1,y1,x2,y2]——原图↔裁图的对应由本记录唯一给出。
    """

    __slots__ = ("union_norm", "margin_ratio", "bbox_norm", "bbox_px",
                 "clamped", "whole_frame_fallback", "context_capped")

    def __init__(self, union_norm, margin_ratio, bbox_norm, bbox_px, clamped,
                 whole_frame_fallback, context_capped):
        self.union_norm = union_norm
        self.margin_ratio = margin_ratio
        self.bbox_norm = bbox_norm
        self.bbox_px = bbox_px
        self.clamped = clamped
        self.whole_frame_fallback = whole_frame_fallback
        self.context_capped = context_capped


class CropRecord:
    """裁图四要素：变换 / 参与者 / 理由（reason_candidates）/ 省略
    （omitted）——四项缺一不可（C-133 §3.2）；same_region_as 本批恒 None。"""

    __slots__ = ("crop_id", "identity", "transform", "participants",
                 "reason_candidates", "merged_count", "omitted",
                 "same_region_as")

    def __init__(self, crop_id, identity, transform, participants,
                 reason_candidates, merged_count, omitted, same_region_as):
        self.crop_id = crop_id
        self.identity = identity
        self.transform = transform
        self.participants = participants
        self.reason_candidates = reason_candidates
        self.merged_count = merged_count
        self.omitted = omitted
        self.same_region_as = same_region_as


class L2Omission:
    """省略记账：不静默丢弃（candidates_dropped / crops_dropped + reason）。"""

    __slots__ = ("candidates_dropped", "crops_dropped", "reason")

    def __init__(self, candidates_dropped, crops_dropped, reason):
        self.candidates_dropped = candidates_dropped
        self.crops_dropped = crops_dropped
        self.reason = reason


class L3LocalFrameSlice:
    """局部连续画面帧序列项（C-136 C1/C2）：固定序位 + 同区域真实切片。

    - position：固定序位，0=前、1=当前、2=后（缺失帧保留序位，不塌缩）。
    - present：真实存在性；False 时 frame_bgr=None 显式占位——绝不复制其他
      帧冒充前后帧。
    - crop_id：分支→图片显式映射键（= 来源 CropRecord.crop_id）；消费侧按
      键取图，绝不靠列表索引猜图片与分支对应。
    - frame_bgr：该帧上同空间区域的真实像素切片（按 CropTransform.bbox_norm
      映射到该帧尺寸后切取；构造时拷贝并置只读，隔离副本）。
    - width/height：切片所在源帧整帧尺寸（bbox_norm 的坐标语义锚点）。
    """

    __slots__ = ("position", "present", "crop_id", "frame_id", "t_capture_ms",
                 "timestamp_kind", "width", "height", "frame_bgr")

    def __init__(self, position, present, crop_id, frame_id, t_capture_ms,
                 timestamp_kind, width, height, frame_bgr):
        self.position = position
        self.present = present
        self.crop_id = crop_id
        self.frame_id = frame_id
        self.t_capture_ms = t_capture_ms
        self.timestamp_kind = timestamp_kind
        self.width = width
        self.height = height
        if frame_bgr is not None:
            arr = np.asarray(frame_bgr).copy()
            arr.setflags(write=False)      # 隔离副本 + 只读
            frame_bgr = arr
        self.frame_bgr = frame_bgr


class L3BranchSpec:
    """L3 有序材料分支规格（C-135 §六/§八 + C-136 C1/C2；字段名冻结，
    全 __slots__）。

    - branch_kind："panorama"（原图整帧切片）|"relation_crop"（关系裁图）|
      "change_region"（门控变化区域兜底）。
    - identity：来源身份四元 + material_id + 观察钟（cur 侧 FrameIdentity）。
    - crop_id：来源 CropRecord.crop_id——分支→图片显式映射键（C-136 C1：
      不得只靠列表索引猜图片与分支对应）。
    - crop_ref：CropTransform|None——原图↔裁图对应与坐标语义（bbox_norm
      整帧归一化 / bbox_px 整帧像素）；本批分支均来自实际裁图，恒在场。
    - frame_sequence：tuple[L3LocalFrameSlice]——局部连续画面：同一 crop
      区域在 prev/cur/nxt 帧上的同空间区域切片（bbox_norm 按各帧尺寸映射），
      固定序位 0=前、1=当前、2=后；缺失帧序位保留、present=False 显式占位，
      绝不复制当前帧冒充前后帧（C-136 C1/C2）。
    - region_only：恒 True——帧序列按空间区域关联，无可靠跨帧对象身份，
      「同区域，不保证同一对象」全局一致标注（C-136 C1）。
    - cur/prev/next_present：各帧真实存在性（cur 恒 True；prev/next 按任务
      显式缺失为 False）。
    - cur/prev/next_gap_ms：各自间隔（cur 自身恒 0.0；缺失帧侧 None）。
    - cur_detections：分支相关当前帧检测（归一化整帧坐标）；全景=全部
      检出、关系裁图=该裁图参与者、变化区域=空（区域来自门控无对象语义）。
    - prev/next_detections：tuple|None——帧在场时如实携带该帧自带检测
      （材料包不携带即空元组，绝不复制当前帧框冒充）；帧缺失显式 None。
    - candidates：该分支候选引用（全景=全部输出候选；关系裁图=其来源
      候选；变化区域=空）。
    - calibrated：恒 False（原始分透传，不得被中间层抹掉）。
    - enhanced：恒 None——为超分留位，显式"未增强"标记（不得省略字段）。
    - omissions：分支级省略理由（来自对应 CropRecord.omitted）。
    """

    __slots__ = ("branch_kind", "identity", "crop_id", "crop_ref",
                 "frame_sequence", "region_only", "cur_present",
                 "prev_present", "next_present", "cur_gap_ms", "prev_gap_ms",
                 "next_gap_ms", "cur_detections", "prev_detections",
                 "next_detections", "candidates", "calibrated", "enhanced",
                 "omissions")

    def __init__(self, branch_kind, identity, crop_ref, cur_present,
                 prev_present, next_present, cur_gap_ms, prev_gap_ms,
                 next_gap_ms, cur_detections, prev_detections,
                 next_detections, candidates, calibrated=False, enhanced=None,
                 omissions=(), crop_id=None, region_only=True,
                 frame_sequence=()):
        self.branch_kind = branch_kind
        self.identity = identity
        self.crop_id = crop_id
        self.crop_ref = crop_ref
        self.frame_sequence = tuple(frame_sequence)
        self.region_only = region_only
        self.cur_present = cur_present
        self.prev_present = prev_present
        self.next_present = next_present
        self.cur_gap_ms = cur_gap_ms
        self.prev_gap_ms = prev_gap_ms
        self.next_gap_ms = next_gap_ms
        self.cur_detections = cur_detections
        self.prev_detections = prev_detections
        self.next_detections = next_detections
        self.candidates = candidates
        self.calibrated = calibrated
        self.enhanced = enhanced
        self.omissions = omissions


class L2Status(enum.Enum):
    """互斥状态枚举（C-134 §1）；失败态与 no_* 态不得互相冒充。"""

    OK = "ok"
    NO_OBJECTS = "no_objects"
    SINGLE_OBJECT = "single_object"
    NO_RELATION_ABOVE_FLOOR = "no_relation_above_floor"
    LOW_CONFIDENCE_ONLY = "low_confidence_only"
    MODEL_UNAVAILABLE = "model_unavailable"
    INFER_FAILED = "infer_failed"
    TIMEOUT = "timeout"
    BACKEND_ISOLATED = "backend_isolated"
    IDENTITY_REJECTED = "identity_rejected"
    UNSUPPORTED = "unsupported"


class L2Output:
    """单任务输出：candidates/crops 与 crop_images 等长对齐；crops 与
    l3_branches 一一对应（分支即裁图的材料视图）；calibrated 恒 False；
    timings_ms 至少含 infer/crops/total。"""

    __slots__ = ("identity", "status", "error_code", "candidates", "crops",
                 "crop_images", "omission", "vocabulary_id", "model_ref",
                 "calibrated", "timings_ms", "l3_branches")

    def __init__(self, identity, status, error_code, candidates, crops,
                 crop_images, omission, vocabulary_id, model_ref, calibrated,
                 timings_ms, l3_branches=()):
        self.identity = identity
        self.status = status
        self.error_code = error_code
        self.candidates = candidates
        self.crops = crops
        self.crop_images = crop_images
        self.omission = omission
        self.vocabulary_id = vocabulary_id
        self.model_ref = model_ref
        self.calibrated = calibrated
        self.timings_ms = timings_ms
        self.l3_branches = l3_branches


# ---- 身份校验助手（M1 四元 + material_id） --------------------------------

def identity_matches(a, b):
    """五字段全等（四元 + material_id）；任一不符即 False。"""
    for field in IDENTITY_FIELDS:
        if getattr(a, field) != getattr(b, field):
            return False
    return True


def adjacent_identity_matches(cur, other):
    """prev/next 关联身份校验（M1/M2）。

    同 camera/run/config/material 且 frame_id 不同才可作为紧邻帧；跨 run/
    跨 config/跨 material/同 frame 的混入一律 False（stage 据此返回
    identity_rejected）。
    """
    if cur is None or other is None:
        return False
    if cur.frame_id == other.frame_id:
        return False
    return (cur.camera_id == other.camera_id
            and cur.run_id == other.run_id
            and cur.config_version == other.config_version
            and cur.material_id == other.material_id)


def frame_object_ref(identity, det, index):
    """DetectionView → ObjectRef（引用 L1 侧身份，绝不伪造 track_id）。

    仅当 track_id 在场且 stable 才生成 track 引用；否则帧内标识
    {cam}:{run}:frame:{frame_id}:det:{index}（stable=False）。
    """
    if det.stable and det.track_id is not None:
        return ObjectRef(
            f"{identity.camera_id}:{identity.run_id}:track:{det.track_id}",
            identity.frame_id, True)
    return ObjectRef(
        f"{identity.camera_id}:{identity.run_id}:frame:{identity.frame_id}"
        f":det:{index}",
        identity.frame_id, False)


# ---- 模型协议（C-134 §3：C 实现真实适配器；B 测试注入假实现） --------------

class L2RelationModel:
    """关系模型协议。

    model_ref：名称/来源/版本描述（不含路径）。
    infer(frame_bgr, boxes_px, labels, vocabulary) 返回
    [{"s": i, "o": j, "relation": str, "graph": str, "score": float}]——
    只含上游真实输出；无关系返回空列表；分数原样不加工。
    boxes_px 为像素 [x1,y1,x2,y2]（stage 已完成唯一切换）。
    """

    model_ref = "unspecified"

    def infer(self, frame_bgr, boxes_px, labels, vocabulary):
        raise NotImplementedError("L2RelationModel 是协议；注入具体实现")


# ---- 阶段类（方案乙，C-134 §0/§2 + C-135 §六） ------------------------------

def _bump(notes, key, count=1):
    notes[key] = notes.get(key, 0) + count


def _render(notes):
    """确定性渲染省略原因："k1=v1;k2=v2"（dict 插入序）。"""
    return ";".join(f"{key}={value}" for key, value in notes.items())


def _ms_since(t):
    return (time.perf_counter() - t) * 1000.0


class L2RelationStage:
    """L2 关系阶段：process(task) -> L2Output（构造注入 model 与 budget）。

    行为（C-134 §2 + C-135 §六）：身份校验（错配→identity_rejected，不产
    出）→ 结构校验（词表空/尺寸非法/缺帧→unsupported）→ 零/单对象精确
    返回 → 归一化→像素唯一切换（调 model 前一次完成）→ model.infer + 异常
    四分类 → 原始三元组映射 ObjectRef → floor 分层 → 候选预算 → 分支裁图
    装配（全景恒保留占槽 0；优先级 全景 > 关系裁图 > 变化区域；单张三判据
    预算在引擎内独立验证取最严；参与者覆盖不变式构建后核验）→ L2Output
    （含 l3_branches，与 crops 一一对应）。identity_rejected/unsupported
    不产任何裁图与 L3 分支；退化检出框不参与配对并计入 omission。
    生效预算：task.budget 优先（L2TaskInput 携带，冻结 §1），缺位回落构造
    注入的 budget——floor 分层/候选预算/裁图预算/兜底开关全部同源，不双轨
    （构造签名 Stage(model, budget) 保持不变，作为任务缺省档）。
    """

    def __init__(self, model, budget=None):
        self.model = model                    # 模型引用计数=1
        self.budget = budget if budget is not None else L2Budget()

    def process(self, task):
        # 延迟导入：contract（纯数据层）不在模块加载期反向依赖裁图引擎
        from scam.win11_l2_crops import (
            CropRequest,
            is_valid_box,
            norm_box_to_px,
        )

        t0 = time.perf_counter()
        identity = task.identity
        # 生效预算：任务自带优先，缺位回落构造注入（见类 docstring；生产
        # 接线 cur 任务携带 stage.budget，prev/next 侧任务 budget=None）
        budget = self._effective_budget(task)
        notes = {}

        # 1) 身份校验：task 与 prev/next 关联四元+material_id（M1）
        for slot in ("prev", "next"):
            adj = getattr(task, slot)
            if (adj is not None
                    and not adjacent_identity_matches(identity, adj.identity)):
                return self._assemble(
                    task, L2Status.IDENTITY_REJECTED,
                    "identity_mismatch:" + slot, (), fallback=False,
                    notes=notes, t0=t0, infer_ms=0.0)

        # 2) 结构校验（unsupported：结构性不可处理，与 no_*/失败态互斥）
        if not task.relation_vocabulary:
            return self._assemble(task, L2Status.UNSUPPORTED,
                                  "empty_vocabulary", (), fallback=False,
                                  notes=notes, t0=t0, infer_ms=0.0)
        if not task.width or not task.height or task.width <= 0 \
                or task.height <= 0:
            return self._assemble(task, L2Status.UNSUPPORTED,
                                  "invalid_frame_size", (), fallback=False,
                                  notes=notes, t0=t0, infer_ms=0.0)
        if task.frame_bgr is None:
            return self._assemble(task, L2Status.UNSUPPORTED, "missing_frame",
                                  (), fallback=False, notes=notes, t0=t0,
                                  infer_ms=0.0)

        # 3) 可用对象：退化检出框（NaN/Inf/非正宽高/完全出帧）不参与配对
        dets = tuple(task.detections or ())
        usable = [(i, d) for i, d in enumerate(dets)
                  if is_valid_box(tuple(d.bbox_norm))]
        degenerate = len(dets) - len(usable)
        if degenerate:
            _bump(notes, "degenerate_detections", degenerate)
        # ObjectRef 映射（引用 L1 身份，与模型无关）：零/单对象与失败态的
        # 全景参与者、L3 分支检测清单都从这里取
        refs = [frame_object_ref(identity, d, i) for i, d in usable]
        usable_by_ref = {ref: d for ref, (_, d) in zip(refs, usable)}
        if not usable:
            return self._assemble(task, L2Status.NO_OBJECTS, None, (),
                                  fallback=True, notes=notes, t0=t0,
                                  infer_ms=0.0, usable_by_ref=usable_by_ref)
        if len(usable) == 1:
            return self._assemble(task, L2Status.SINGLE_OBJECT, None, (),
                                  fallback=True, notes=notes, t0=t0,
                                  infer_ms=0.0, usable_by_ref=usable_by_ref)

        # 4) 唯一坐标切换点：归一化[x,y,w,h]→像素[x1,y1,x2,y2]，一次完成
        boxes_px = [norm_box_to_px(tuple(d.bbox_norm), task.width, task.height)
                    for _, d in usable]
        labels = [d.cls for _, d in usable]

        # 5) infer + 异常四分类（互斥不互冒充；失败不切断兜底）
        t1 = time.perf_counter()
        try:
            triples = self.model.infer(task.frame_bgr, boxes_px, labels,
                                       tuple(task.relation_vocabulary))
        except AdapterIsolated:
            return self._assemble(task, L2Status.BACKEND_ISOLATED,
                                  "backend_isolated", (), fallback=True,
                                  notes=notes, t0=t0, infer_ms=_ms_since(t1),
                                  usable_by_ref=usable_by_ref)
        except TimeoutError:
            return self._assemble(task, L2Status.TIMEOUT, "timeout", (),
                                  fallback=True, notes=notes, t0=t0,
                                  infer_ms=_ms_since(t1),
                                  usable_by_ref=usable_by_ref)
        except ModelUnavailable:
            return self._assemble(task, L2Status.MODEL_UNAVAILABLE,
                                  "model_unavailable", (), fallback=True,
                                  notes=notes, t0=t0, infer_ms=_ms_since(t1),
                                  usable_by_ref=usable_by_ref)
        except Exception:
            return self._assemble(task, L2Status.INFER_FAILED, "infer_failed",
                                  (), fallback=True, notes=notes, t0=t0,
                                  infer_ms=_ms_since(t1),
                                  usable_by_ref=usable_by_ref)
        infer_ms = _ms_since(t1)

        # 6) 原始三元组 → ObjectRef（引用 L1 身份；分数原样不加工）
        n = len(usable)
        parsed = []
        for order, triple in enumerate(triples or ()):
            try:
                s = int(triple["s"])
                o = int(triple["o"])
                relation = triple["relation"]
                graph = triple["graph"]
                score = float(triple["score"])
            except (KeyError, TypeError, ValueError):
                _bump(notes, "malformed_triple")
                continue
            if not (0 <= s < n) or not (0 <= o < n):
                _bump(notes, "invalid_index")
                continue
            if not math.isfinite(score):
                _bump(notes, "nonfinite_score")
                continue
            parsed.append((order, s, o, relation, graph, score))
        parsed.sort(key=lambda p: (-p[5], p[0]))   # 分数降序，同分稳定

        # 7) floor 分层：≥relation_floor→候选；[low,relation)→low_confidence
        #    only；都不到→no_relation_above_floor
        above = [p for p in parsed if p[5] >= budget.relation_floor]
        low = [p for p in parsed
               if budget.low_conf_floor <= p[5] < budget.relation_floor]
        below = len(parsed) - len(above) - len(low)
        if below:
            _bump(notes, "below_low_conf_floor", below)

        low_flag = False
        if above:
            chosen, status, error_code = above, L2Status.OK, None
            if low:                                # ok 态下低分带不保留
                _bump(notes, "below_relation_floor", len(low))
        elif low:
            chosen, status, error_code = low, L2Status.LOW_CONFIDENCE_ONLY, None
            low_flag = True
        else:
            chosen = []
            status = L2Status.NO_RELATION_ABOVE_FLOOR
            error_code = "no_candidates" if not parsed else "below_floor"

        # 8) 候选预算上限（分数降序取舍，舍弃显式记账不静默）
        if len(chosen) > budget.max_candidates:
            _bump(notes, "candidates_budget_cap",
                  len(chosen) - budget.max_candidates)
            chosen = chosen[:budget.max_candidates]

        candidates = []
        requests = []
        for (_order, s, o, relation, graph, score) in chosen:
            cand = RelationCandidate(
                subject=refs[s], obj=refs[o], relation=relation, graph=graph,
                score_raw=score, vocabulary_id=task.vocabulary_id,
                uncertainty=Uncertainty(
                    frame_missing_prev=(task.prev is None),
                    frame_missing_next=(task.next is None),
                    low_confidence=low_flag))
            candidates.append(cand)
            requests.append(CropRequest(
                cand, tuple(usable[s][1].bbox_norm),
                tuple(usable[o][1].bbox_norm)))

        # 9) 分支裁图装配（C-135 §六）：全景恒保留占槽 0，优先级
        #    全景 > 关系裁图 > 变化区域；单张三判据预算与参与者覆盖守卫
        #    在引擎内完成，构建后核验在这里兜底（违规记录不外发）
        t2 = time.perf_counter()
        records, images, crop_dropped = self._build_branch_crops(
            task, budget, requests, usable_by_ref, notes)
        crops_ms = _ms_since(t2)

        cand_dropped = sum(notes.get(key, 0) for key in
                           ("malformed_triple", "invalid_index",
                            "nonfinite_score", "below_low_conf_floor",
                            "below_relation_floor", "candidates_budget_cap"))

        return self._assemble(
            task, status, error_code, tuple(candidates), fallback=False,
            notes=notes, t0=t0, infer_ms=infer_ms, crops_ms=crops_ms,
            records=records, images=images, cand_dropped=cand_dropped,
            crop_dropped=crop_dropped, usable_by_ref=usable_by_ref)

    # ---- 内部 --------------------------------------------------------------

    def _effective_budget(self, task):
        """生效预算唯一裁决点：task.budget 优先（冻结 §1 任务携带），缺位
        回落构造注入档——floor 分层/候选预算/裁图预算/兜底开关全部同源。"""
        return task.budget if task.budget is not None else self.budget

    def _build_branch_crops(self, task, budget, requests, usable_by_ref,
                            notes):
        """分支裁图装配（优先级冻结：全景 > 关系裁图 > 变化区域兜底）。

        - 全景恒保留（C-135 §六，有关系候选也保留，不是"没有裁图才补"）：
          whole_frame_fallback 开且 max_crops_total>0 时占首位槽 0，原图
          整帧切片，participants=全部可用对象（零对象显式为空）；总额度为
          0 时全景被预算舍弃，显式记账（panorama_budget_cap）。
        - 关系裁图消费剩余槽位（引擎内三判据单张预算独立验证 + 合并守卫）。
        - 变化区域消费最终剩余槽位；因预算未产出的合法区域显式计数
          （change_region_budget_cap），非法区域跳过不计入预算舍弃。
        返回 (records, images, crops_dropped)；全部舍弃显式记账不静默。
        """
        from scam.win11_l2_crops import (
            build_candidate_crops,
            build_change_region_crops,
            build_whole_frame_crop,
            verify_participant_coverage,
        )
        total = max(0, int(budget.max_crops_total))
        records = []
        images = []
        dropped = 0

        if budget.whole_frame_fallback:
            if total <= 0:
                _bump(notes, "panorama_budget_cap")
                dropped += 1
            else:
                rec, img = build_whole_frame_crop(
                    task.frame_bgr, task.identity,
                    participants=tuple(usable_by_ref))
                records.append(rec)
                images.append(img)

        relation_slots = total - len(records)
        if requests:
            rel_records, rel_images, rel_dropped, rel_notes = \
                build_candidate_crops(task.frame_bgr, task.width, task.height,
                                      task.identity, requests, budget,
                                      max_records=max(0, relation_slots))
            for note in rel_notes:
                _bump(notes, note)
            dropped += rel_dropped
            # 参与者覆盖不变式（C-135 §六 B2）构建后核验：违规记录不得外发
            violations = verify_participant_coverage(rel_records, requests)
            if violations:
                _bump(notes, "participant_coverage_violation", len(violations))
                bad_ids = {crop_id for crop_id, _, _ in violations}
                kept = [(rec, img)
                        for rec, img in zip(rel_records, rel_images)
                        if rec.crop_id not in bad_ids]
                dropped += len(rel_records) - len(kept)
                rel_records = tuple(rec for rec, _ in kept)
                rel_images = tuple(img for _, img in kept)
            records.extend(rel_records)
            images.extend(rel_images)

        if budget.change_region_fallback and task.change_regions:
            remaining = total - len(records)
            chg_records, chg_images, chg_dropped = build_change_region_crops(
                task.frame_bgr, task.width, task.height, task.identity,
                [(r.x, r.y, r.w, r.h) for r in task.change_regions],
                remaining)
            if chg_dropped:
                _bump(notes, "change_region_budget_cap", chg_dropped)
            dropped += chg_dropped
            records.extend(chg_records)
            images.extend(chg_images)

        return tuple(records), tuple(images), dropped

    def _build_l3_branches(self, task, records, candidates, usable_by_ref):
        """L3 有序材料分支（C-135 §六/§八 + C-136 C1/C2）：与 crops 一一对应。

        - 全景分支：cur_detections=当前帧全部检出（诚实全帧清单），
          candidates=全部输出候选（引用，非复制）。
        - 关系裁图分支：cur_detections=该裁图 participants 对应的检出视图
          （携带参与者框，归一化整帧坐标），candidates=其来源候选。
        - 变化区域分支：无对象语义（cur_detections=()、candidates=()）。
        - prev/next 检测：帧在场如实携带该帧自带检测（材料包不携带即空
          元组），帧缺失显式 None——绝不复制当前帧框冒充。
        - 局部连续画面（C-136 C1/C2）：每分支带 frame_sequence——同一
          crop 区域在 prev/cur/nxt 帧上的同空间真实切片（bbox_norm 按各帧
          尺寸映射切取），固定序位 0=前、1=当前、2=后；缺失帧序位保留、
          present=False 显式占位，绝不复制其他帧冒充；crop_id 显式映射键；
          region_only=True（同区域，不保证同一对象）。
        """
        branches = []
        all_dets = tuple(task.detections or ())
        prev_present = task.prev is not None
        next_present = task.next is not None
        for record in records:
            crop_id = record.crop_id
            if ":chg:" in crop_id:
                kind = "change_region"
                branch_dets = ()
                branch_cands = ()
            elif crop_id.endswith(":crop:whole"):
                kind = "panorama"
                branch_dets = all_dets
                branch_cands = tuple(candidates)
            else:
                kind = "relation_crop"
                branch_dets = tuple(usable_by_ref[ref]
                                    for ref in record.participants
                                    if ref in usable_by_ref)
                branch_cands = tuple(record.reason_candidates)
            branches.append(L3BranchSpec(
                branch_kind=kind,
                identity=task.identity,
                crop_ref=record.transform,
                cur_present=True,
                prev_present=prev_present,
                next_present=next_present,
                cur_gap_ms=0.0,
                prev_gap_ms=task.prev_gap_ms if prev_present else None,
                next_gap_ms=task.next_gap_ms if next_present else None,
                cur_detections=branch_dets,
                prev_detections=(tuple(task.prev.detections or ())
                                 if prev_present else None),
                next_detections=(tuple(task.next.detections or ())
                                 if next_present else None),
                candidates=branch_cands,
                calibrated=False,
                enhanced=None,
                omissions=tuple(record.omitted),
                crop_id=crop_id,
                region_only=True,
                frame_sequence=self._local_frame_sequence(task, record)))
        return tuple(branches)

    @staticmethod
    def _local_frame_sequence(task, record):
        """局部连续画面帧序列（C-136 C1/C2）：固定序位 0=前/1=当前/2=后。

        同一 crop 区域（CropTransform.bbox_norm，整帧归一化）映射到各帧
        自身尺寸后切取真实像素——prev/nxt 尺寸可与 cur 不同，各帧按自己
        的宽高换算（同空间区域，非同分辨率复制）。缺失帧保留序位、
        present=False 显式占位（frame_bgr=None），绝不复制其他帧冒充。
        """
        from scam.win11_l2_crops import norm_box_to_px, slice_region

        bbox_norm = tuple(float(v) for v in record.transform.bbox_norm)
        slices = []
        for position, adj in ((0, task.prev), (1, None), (2, task.next)):
            if position == 1:
                frame = task.frame_bgr
                width, height = task.width, task.height
                frame_id = task.identity.frame_id
                t_ms = task.identity.t_capture_ms
                ts_kind = task.identity.timestamp_kind
                px = record.transform.bbox_px      # cur 侧像素框已冻结在变换
            else:
                if adj is None:
                    slices.append(L3LocalFrameSlice(
                        position=position, present=False, crop_id=record.crop_id,
                        frame_id=None, t_capture_ms=None,
                        timestamp_kind=None, width=None, height=None,
                        frame_bgr=None))
                    continue
                frame = adj.frame_bgr
                width = adj.width if adj.width else (
                    int(frame.shape[1]) if frame is not None else None)
                height = adj.height if adj.height else (
                    int(frame.shape[0]) if frame is not None else None)
                frame_id = adj.identity.frame_id
                t_ms = adj.identity.t_capture_ms
                ts_kind = adj.identity.timestamp_kind
                px = (norm_box_to_px(bbox_norm, width, height)
                      if (frame is not None and width and height) else None)
            image = slice_region(frame, px) if (frame is not None
                                                and px is not None) else None
            slices.append(L3LocalFrameSlice(
                position=position, present=image is not None,
                crop_id=record.crop_id, frame_id=frame_id, t_capture_ms=t_ms,
                timestamp_kind=ts_kind,
                width=int(width) if width else None,
                height=int(height) if height else None,
                frame_bgr=image))
        return tuple(slices)

    def _assemble(self, task, status, error_code, candidates=(), *, fallback,
                  notes, t0, infer_ms, crops_ms=0.0, records=(), images=(),
                  cand_dropped=0, crop_dropped=0, usable_by_ref=None):
        if fallback and not records:
            # 兜底支路（无候选/失败/零单对象）：全景 + 变化区域并存不互替，
            # 预算开关/闸门消费生效预算（task.budget 优先）——预算显式关闭
            # 的支路不产出（不静默回退到默认档）
            tf = time.perf_counter()
            records, images, built_dropped = self._build_branch_crops(
                task, self._effective_budget(task), (),
                usable_by_ref if usable_by_ref is not None else {}, notes)
            crop_dropped += built_dropped
            crops_ms = _ms_since(tf)
        l3_branches = self._build_l3_branches(task, records, candidates,
                                              usable_by_ref or {})
        omission = L2Omission(candidates_dropped=cand_dropped,
                              crops_dropped=crop_dropped,
                              reason=_render(notes))
        return L2Output(
            identity=task.identity, status=status, error_code=error_code,
            candidates=tuple(candidates), crops=tuple(records),
            crop_images=tuple(images), omission=omission,
            vocabulary_id=task.vocabulary_id,
            model_ref=getattr(self.model, "model_ref", None) or "unspecified",
            calibrated=False,
            timings_ms={"infer": infer_ms, "crops": crops_ms,
                        "total": _ms_since(t0)},
            l3_branches=l3_branches)
