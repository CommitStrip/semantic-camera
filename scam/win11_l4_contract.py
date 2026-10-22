"""win11_l4_contract.py —— L4 融合层数据形状与状态合同（C-136 §四 冻结）。

零模型依赖、零 cv2、零 I/O：纯结构化规则的数据合同。上游材料（L1 对象事实
引用、L2 RelationCandidate、L3 L3BranchResult）按冻结合同的当前交付形态以
属性只读方式消费——本模块不 import l2/l3 合同（保持 L4 可独立导入、可独立
测试），也不新造对象身份：引用字符串形态沿 L1/L2（win11_l2_contract.
frame_object_ref 与 scam/monitor.py 对象事实 object_id =
f"{camera_id}:{run_id}:track:{track_id}"），L4 只透传引用。

分界红线（违反即缺陷）：
- 融合身份：窗口四元 (camera_id, run_id, config_version, window_id)；
  camera/run/config 任一不同 → 拒绝融合（identity_rejected），不产版本、
  不产 items。对象引用内嵌 {cam}:{run}: 前缀与输入身份不符同判拒绝。
- 状态互斥不互冒充：ok=有观察/推断且无缺失/失败/冲突/时钟不可比因素；
  partial=有内容但存在上述因素；insufficient=无任何观察与推断可融合。
  绝不把空融合冒充 ok，也不把冲突冒充一致。
- 冲突保留双方证据：检测到矛盾时双方各自条目并存，另立 conflict 记录；
  不投票、不按最高分强选、不抹掉任何一方。
- 确定性：version_id = sha256(输入指纹序)（netstring 逐字段序列化，输入
  顺序即指纹顺序，见 fusion_fingerprint）；同输入重放同 version_id；
  同一 stage 重复提交同指纹幂等返回同一版本对象。
- 不做文本拼接式融合：items 逐条带来源（sources），无任何"汇总叙述"
  字段；L3 自由文本原样保留并标 unstructured=True。
- 确定性三级：observed 仅限 L1 对象事实引用；L2 候选/L3 文本一律
  model_inferred（模型自报 confirmed/安全不升级为系统核实）；缺失/失败/
  冲突/时钟不可比 → unknown。
- 无动作语义：本合同不携带、不表达"关闭事件/撤销提醒/压制告警"类动作；
  模型"安全/无异常"文本只能成为 observation 记录，绝不作为关闭/撤销依据
  （固定回归）。
- 时钟类型：clock_kinds 取源侧 timestamp_kind 实际值域（source_capture /
  host_receive / unknown，见 scam/nvr.py）；仅全部来源同为 source_capture
  才视为可比（host_receive 含解码等待、unknown 无法溯源）；不可比 →
  跨来源时间顺序 unknown，不按时间排序/合并（不强排）。

C-137 修订（docs/context/C137-接口冻结.md §5，冲突处以 C-137 为准）：
- 指纹 v2：version_id 指纹必须覆盖——L2 每候选 subject/obj 各自
  (object_id+frame_id+stable)、relation、score_raw、graph、vocabulary_id；
  L3 每分支 window 四元、branch_kind、crop_id、model_ref、unstructured、
  每条结果帧来源（frame_id/时间类型）、observation/inference 文本；
  失败/缺失清单逐项。同指纹幂等；不同指纹必新版本（绝不再因指纹漏项把
  不同客体/不同裁图/不同模型来源误判"相同输入"）。
- 材料身份校验（D2）：除顶层四元外，逐条核对 L3BranchResult.window 与
  输入顶层四元，不符 → FusionIdentityRejected（带逐分支原因清单）。
- 同窗累计（D3）：L4Stage.accumulate(window_key, input) 追加语义——后版本
  保留前版本全部材料（含来源），失败/取消/缺失并入；每窗版本缓存有界
  （MAX_WINDOW_VERSIONS=32，超出标 archived），cleanup(window_key) 终结清理。
- 来源内容身份（D4）：L3 来源引用 = branch_kind[@crop_id][|model_ref]——
  同窗同类型不同裁图可区分；合并条目 sources 并集保留全部来源，结构为
  纯数据（kind/ref 字符串），可 JSON 持久化。
- 最小时空对齐字段（D5）：FusionInput/FusionVersion 携带 coord_space
  （原图坐标体系声明）与 frame_refs（FusionFrameRef：frame_id/t_ms/
  time_kind/bbox_norm/crop_ref/stable_ref）；仅在明确可比条件下对齐
  （同 camera+同时间类型+稳定引用）；空间重叠不合并对象；不可比时钟
  不强排；身份/时间不确定 → 保留双方 + 不确定性 gap 标注。

C-138 修订（docs/context/C138-接口冻结.md §4，冲突处以 C-138 为准）：
- B1 累计结构化材料：accumulate 保存累计**材料集**（原始 L1 引用/L2 候选/
  L3 分支结果/失败/缺失清单，按材料身份=指纹行存集），每次新材料到达针对
  累计集重算冲突与条目——先"1个人"后"2个人"、先候选后否定叙事（或任意
  反序/交错），最终 items/conflict/sources 一致（确定性）。累计指纹行按
  字节排序去重（cumulative_fingerprint_rows）：同累计集必同 version_id，
  created_mono 允许不同。逐帧引用行加入坐标体系声明字段（行格式变更 →
  FINGERPRINT_VERSION 升 v3）。
- B2 历史携带与不可比标记：后版本 items/frame_refs 必含前版本全部对象
  引用/来源/缺失因素+新材料。坐标体系值域冻结 COORD_SPACES=
  ("normalized","pixels")（未声明体系仍 ValueError，绝不换算）；逐帧引用
  自带 coord_space 声明（FusionFrameRef.coord_space），累计出现多体系 →
  "坐标体系不一致" gap 标记 + 版本 coord_space=combine_coord_spaces 联合
  声明（mixed: 前缀），新声明绝不覆盖旧材料；时钟类型按累计并集判定
  可比性，不可比显式标记（不继承新声明）。
- B3 缓存硬上限（实现见 win11_l4.L4Stage）：窗口级
  max_active_windows=MAX_ACTIVE_WINDOWS=16（构造可覆盖）——活跃+归档
  窗口总数超限真淘汰最旧活跃窗（从缓存删除，非仅标记）；每窗版本上限
  MAX_WINDOW_VERSIONS=32 的 archived 标记语义保留；窗口两态
  WINDOW_STATES=("active","archived")，终结窗 archive_window 后仍占缓存
  直到 cleanup，两态同在 max_active_windows 预算内；淘汰/清理只影响
  活跃缓存，淘汰后同指纹重提交视为新材料（如实计数）。
"""

import hashlib
import math

__all__ = [
    "COMPARABLE_CLOCK_KIND",
    "COORD_SPACES",
    "DEFAULT_COORD_SPACE",
    "FINGERPRINT_VERSION",
    "FUSION_CERTAINTIES",
    "FUSION_KINDS",
    "FUSION_SOURCE_KINDS",
    "FUSION_STATUS",
    "FUSION_TIME_KINDS",
    "MAX_ACTIVE_WINDOWS",
    "MAX_WINDOW_VERSIONS",
    "MIXED_COORD_SPACE_PREFIX",
    "WINDOW_STATES",
    "FusionFrameRef",
    "FusionIdentityRejected",
    "FusionInput",
    "FusionItem",
    "FusionSource",
    "FusionVersion",
    "clock_fingerprint_row",
    "combine_coord_spaces",
    "coords_fingerprint_row",
    "cumulative_fingerprint_rows",
    "enum_value",
    "failure_fingerprint_row",
    "fingerprint_version_row",
    "fusion_fingerprint",
    "frameref_fingerprint_row",
    "gap_fingerprint_row",
    "input_fingerprint_rows",
    "l1_fingerprint_rows",
    "l2_fingerprint_rows",
    "l3_fingerprint_rows",
    "merge_fingerprint_rows",
    "normalize_failure",
    "normalize_gap",
    "object_ref_camera_run",
    "object_ref_id",
    "object_ref_stable",
    "rows_digest",
    "window_fingerprint_row",
]

# ---- 冻结值域（C-136 §四；字符串字面量即合同） ------------------------------

FUSION_KINDS = ("observation", "inference", "conflict", "gap")
FUSION_CERTAINTIES = ("observed", "model_inferred", "unknown")
FUSION_STATUS = ("ok", "partial", "insufficient")
FUSION_SOURCE_KINDS = ("l1_object", "l2_candidate", "l3_branch", "failure",
                       "gap")

# 时钟可比的唯一基准（scam/nvr.py：仅源显式证明 source_capture 才是采集时刻）
COMPARABLE_CLOCK_KIND = "source_capture"

# 时间类型值域（源侧 timestamp_kind 实际值域，见 scam/nvr.py；C-137 D5 冻结）
FUSION_TIME_KINDS = ("source_capture", "host_receive", "unknown")

# 原图坐标体系声明值域（C-137 D5 + C-138 B2）：bbox 一律随声明解释——
# "normalized"=整帧归一化 [x,y,w,h]（对齐基准，默认）；"pixels"=原始像素
# 坐标。体系之间不换算、不比较（无外参不猜）；未声明体系一律 ValueError。
# 跨体系材料并存 → "坐标体系不一致"标记，各自声明保留（不覆盖）。
DEFAULT_COORD_SPACE = "normalized"
COORD_SPACES = ("normalized", "pixels")

# 多体系并存的联合声明前缀（C-138 B2）：combine_coord_spaces 产出
# "mixed:" + 排序后 "|".join(体系集)；逐帧引用仍各自携带真实声明。
MIXED_COORD_SPACE_PREFIX = "mixed:"

# 每窗版本缓存上限（C-137 §5 D3）：超出最旧版本标记 archived=True（证据
# 保留、标记出活跃窗；终结内存回收由 runtime 调 cleanup(window_key)）。
MAX_WINDOW_VERSIONS = 32

# 活跃窗口缓存硬上限（C-138 §4 B3）：活跃+归档窗口总数超限 → 真淘汰最旧
# 活跃窗（从缓存删除，非仅标记）；L4Stage 构造可覆盖。淘汰契约：被淘汰
# 窗的版本必须已持久化——调用方在淘汰前保存，或提供 evict_callback
# （window_key, versions）现场保存（见 win11_l4.L4Stage docstring）。
MAX_ACTIVE_WINDOWS = 16

# 窗口缓存两态（C-138 B3 冻结值域）：active=仍在累计；archived=窗口终结
# 核准后归档（仍占缓存直到 cleanup）；两态同在 max_active_windows 预算内。
WINDOW_STATES = ("active", "archived")

# 指纹版本标记（序列化首行；行格式变更必须换版本号——不同口径指纹永不
# 碰撞）。v3（C-138 B2）：frameref 行尾新增逐帧坐标体系声明字段。
FINGERPRINT_VERSION = "L4-FUSION-FINGERPRINT-v3"

# L2 候选不确定性标注名（win11_l2_contract.Uncertainty 字段，冻结序）
_CANDIDATE_UNCERTAINTY_FLAGS = (
    "frame_missing_prev", "frame_missing_next", "identity_uncertain",
    "drift", "pair_overlap_high", "low_confidence")

# L3 分支不确定性标注名（win11_l3_contract.L3Uncertainty 字段，冻结序）
_L3_UNCERTAINTY_FLAGS = (
    "frame_missing", "frames_truncated", "pixels_downscaled", "unenhanced")


# ---- 异常 -------------------------------------------------------------------

class FusionIdentityRejected(Exception):
    """融合身份拒绝：窗口前三元与融合绑定不符，或材料引用内嵌身份与输入
    身份不符——拒绝融合，不产版本、不产 items（FusionVersion.status 只保留
    ok/partial/insufficient 三值，拒绝态以异常表达，绝不冒充任何成功态）。
    """

    def __init__(self, reason, details=None):
        super().__init__(reason)
        self.reason = reason
        self.details = details


# ---- 规范化助手（引用与清单条目；全部确定性） --------------------------------

def enum_value(x):
    """枚举或字符串 → 冻结字符串值（L3BranchKind/L3Status 透传 .value）。"""
    return getattr(x, "value", x)


def object_ref_id(ref):
    """对象引用 → object_id 字符串：ObjectRef 形态取 .object_id；纯字符串
    透传。只引用 L1/L2 侧已有身份，绝不新造。"""
    return str(getattr(ref, "object_id", ref))


def object_ref_stable(ref):
    """稳定身份判定：ObjectRef 形态取 .stable；纯字符串按引用形态推断
    （{cam}:{run}:track:{id} 为稳定，其余帧内引用不稳定）。"""
    return bool(getattr(ref, "stable", ":track:" in object_ref_id(ref)))


def object_ref_camera_run(object_id):
    """object_id 内嵌 {camera}:{run}: 前缀解析；不是该形态返回 None
    （不可判——不猜、不伪造）。"""
    parts = str(object_id).split(":")
    if len(parts) >= 3 and parts[0] and parts[1]:
        return (parts[0], parts[1])
    return None


def normalize_failure(entry):
    """失败清单条目 → (source, code, detail)（确定性规范化）。

    接受 dict{source,code,detail} / 同名属性对象 / 纯字符串（code=原文，
    source=caller）。失败清单只进 gap 类 items，绝不冒充观察/推断。
    """
    if isinstance(entry, dict):
        return (str(entry.get("source", "caller")),
                str(entry.get("code", "unknown")),
                str(entry.get("detail", "")))
    if hasattr(entry, "code") or hasattr(entry, "source"):
        return (str(getattr(entry, "source", "caller")),
                str(getattr(entry, "code", "unknown")),
                str(getattr(entry, "detail", "")))
    return ("caller", str(entry), "")


def normalize_gap(entry):
    """缺失清单条目 → (kind, detail)（确定性规范化；接受形态同上）。"""
    if isinstance(entry, dict):
        return (str(entry.get("kind", "missing")),
                str(entry.get("detail", "")))
    if hasattr(entry, "kind") or hasattr(entry, "detail"):
        return (str(getattr(entry, "kind", "missing")),
                str(getattr(entry, "detail", "")))
    return ("missing", str(entry))


# ---- 数据形状（字段名冻结，C-136 §四；全 __slots__） ------------------------

class FusionFrameRef:
    """最小时空对齐字段（C-137 D5）：单帧身份 + 时间 + 区域 + 稳定引用。

    - frame_id：帧身份（随输入/版本携带，纯字符串）。
    - t_ms：观察钟时间值（ms）；None=未知（不伪造时间）。
    - time_kind：时间类型，FUSION_TIME_KINDS 值域——真实类型透传，绝不
      写死（D6）。
    - bbox_norm：随 coord_space 声明解释的区域 [x,y,w,h]（默认
      coord_space="normalized" 整帧归一化）或 None。
    - crop_ref：裁图引用键（crop_id）——区域可用 crop 引用替代 bbox。
    - stable_ref：稳定对象引用（{cam}:{run}:track:{id}）或 None（无稳定
      身份，绝不伪造）。
    - coord_space：本引用坐标体系声明（C-138 B2，COORD_SPACES 值域）；
      跨体系材料不换算不比较，各自声明保留（"坐标体系不一致"标记）。

    对齐红线（D5 + C-138 B2）：仅在明确可比条件下对齐（同 camera + 同
    时间类型 + 同坐标体系 + 稳定引用或显式同区域声明）；空间重叠绝不作
    为合并对象的依据；不可比时钟不强排（时间项 unknown）；身份/时间不确定
    → 保留双方并标注不确定性（消费侧产出 gap 因素进入 partial）。
    """

    __slots__ = ("frame_id", "t_ms", "time_kind", "bbox_norm", "crop_ref",
                 "stable_ref", "coord_space")

    def __init__(self, frame_id, t_ms=None, time_kind="unknown",
                 bbox_norm=None, crop_ref=None, stable_ref=None,
                 coord_space=DEFAULT_COORD_SPACE):
        if time_kind not in FUSION_TIME_KINDS:
            raise ValueError(f"unknown fusion time kind: {time_kind!r}")
        if coord_space not in COORD_SPACES:
            raise ValueError(f"unknown coord_space: {coord_space!r} "
                             f"(declared: {COORD_SPACES})")
        if bbox_norm is not None:
            bbox_norm = tuple(float(v) for v in bbox_norm)
            if len(bbox_norm) != 4:
                raise ValueError(
                    f"bbox_norm must be [x,y,w,h], got {bbox_norm!r}")
        self.frame_id = str(frame_id)
        self.t_ms = None if t_ms is None else float(t_ms)
        self.time_kind = time_kind
        self.bbox_norm = bbox_norm
        self.crop_ref = None if crop_ref is None else str(crop_ref)
        self.stable_ref = None if stable_ref is None else str(stable_ref)
        self.coord_space = coord_space


class FusionInput:
    """融合输入：窗口身份四元 + 各层材料引用（字段名冻结）。

    - camera_id/run_id/config_version/window_id：窗口身份四元；前三元即
      融合绑定身份，任一不同的材料不得进入同一融合（identity_rejected）。
    - l1_object_refs：L1 对象事实引用（ObjectRef 形态：object_id/frame_id/
      stable；也接受等价属性对象或纯字符串）。
    - l2_candidates：L2 关系候选（RelationCandidate 形态：subject/obj/
      relation/graph/score_raw/uncertainty；score_raw 为未校准原始分，
      calibrated=False 声明随输出传播）。
    - l3_branches：L3 分支结果（L3BranchResult 形态：branch/status/
      observation/inference/uncertainty/sources/window/crop_id/model_ref
      ——观察/推断/不确定性/缺失/窗口与裁图与模型来源，C-136 C4 形态）。
    - failures：失败清单（L2/L3 失败态摘要）；gaps：缺失清单（缺帧/缺
      分支等）；取消/预算淘汰同按这两清单逐项入账。两者只进 gap 类 items，
      输入是什么就传播什么（绝不恒传空清单、绝不写死时钟类型）。
    - clock_kinds：本窗各来源时钟类型标注（timestamp_kind 值域）；非单一
      source_capture → 跨来源时间不可比，时间项 unknown，不按时间排序。
    - coord_space：本批材料坐标体系声明（C-137 D5 + C-138 B2，
      COORD_SPACES 值域，默认 DEFAULT_COORD_SPACE="normalized"；未声明
      体系 ValueError——不猜不换算；单批材料单声明，跨体系分批提交，
      累计层负责"坐标体系不一致"标记）。
    - frame_refs：逐帧时空对齐字段（FusionFrameRef，C-137 D5）；每帧
      coord_space 声明必须与本批声明一致（C-138 B2）。
    """

    __slots__ = ("camera_id", "run_id", "config_version", "window_id",
                 "l1_object_refs", "l2_candidates", "l3_branches",
                 "failures", "gaps", "clock_kinds", "coord_space",
                 "frame_refs")

    def __init__(self, camera_id, run_id, config_version, window_id,
                 l1_object_refs=(), l2_candidates=(), l3_branches=(),
                 failures=(), gaps=(), clock_kinds=(),
                 coord_space=DEFAULT_COORD_SPACE, frame_refs=()):
        if coord_space not in COORD_SPACES:
            raise ValueError(
                f"unsupported coord_space: {coord_space!r} "
                f"(declared: {COORD_SPACES})")
        frame_refs = tuple(frame_refs)
        for ref in frame_refs:
            if getattr(ref, "coord_space", DEFAULT_COORD_SPACE) != coord_space:
                raise ValueError(
                    f"frame_ref coord_space "
                    f"{getattr(ref, 'coord_space', None)!r} 与本批声明 "
                    f"{coord_space!r} 不一致（单批材料单声明，跨体系分批"
                    "提交；不猜不换算）")
        self.camera_id = camera_id
        self.run_id = run_id
        self.config_version = config_version
        self.window_id = window_id
        self.l1_object_refs = tuple(l1_object_refs)
        self.l2_candidates = tuple(l2_candidates)
        self.l3_branches = tuple(l3_branches)
        self.failures = tuple(failures)
        self.gaps = tuple(gaps)
        self.clock_kinds = tuple(clock_kinds)
        self.coord_space = coord_space
        self.frame_refs = tuple(frame_refs)


class FusionSource:
    """来源引用：kind ∈ FUSION_SOURCE_KINDS + ref 稳定字符串（分支/候选/
    对象事实引用）；按 (kind, ref) 相等——合并保留双方来源。"""

    __slots__ = ("kind", "ref")

    def __init__(self, kind, ref):
        if kind not in FUSION_SOURCE_KINDS:
            raise ValueError(
                f"unknown fusion source kind: {kind!r}")
        self.kind = kind
        self.ref = str(ref)

    def __eq__(self, other):
        if not isinstance(other, FusionSource):
            return NotImplemented
        return (self.kind == other.kind and self.ref == other.ref)

    def __hash__(self):
        return hash((self.kind, self.ref))

    def __repr__(self):
        return f"FusionSource({self.kind!r}, {self.ref!r})"


class FusionItem:
    """融合条目（字段名冻结）：kind/text/sources/certainty/unstructured。

    - kind：observation|inference|conflict|gap。
    - text：单条陈述（非拼接叙述）；L3 自由文本原样保留（不加工不改写）。
    - sources：来源引用元组（FusionSource）；重复项合并保留双方来源。
    - certainty：observed（仅 L1 对象事实）| model_inferred（L2 候选/L3
      文本，模型自报 confirmed 不升级）| unknown（缺失/失败/冲突/时钟）。
    - unstructured：自由文本未结构化标注——True=原文保留、未抽取结构槽位
      （L3 叙事恒 True；L1 引用与 L2 候选自带结构槽位，False）。
    """

    __slots__ = ("kind", "text", "sources", "certainty", "unstructured")

    def __init__(self, kind, text, sources, certainty, unstructured=False):
        if kind not in FUSION_KINDS:
            raise ValueError(f"unknown fusion item kind: {kind!r}")
        if certainty not in FUSION_CERTAINTIES:
            raise ValueError(f"unknown fusion certainty: {certainty!r}")
        self.kind = kind
        self.text = text if isinstance(text, str) else str(text)
        self.sources = tuple(sources)
        self.certainty = certainty
        self.unstructured = bool(unstructured)


class FusionVersion:
    """融合版本（字段名冻结）：version_id=sha256(输入指纹序)（确定性）；
    status=ok|partial|insufficient；items 逐条带来源（sources 纯数据可
    JSON 持久化，重启后仍可查看）；created_mono 单调钟打点（不参与
    version_id）；window 身份四元随版本携带（渐进版本链里每版自证身份）；
    coord_space/frame_refs 随版本携带时空对齐声明（C-137 D5）——coord_space
    为单体系声明或 mixed: 联合声明（C-138 B2 combine_coord_spaces，逐帧
    引用各带真实声明）；archived 为阶段缓存归档标记（C-137 D3：超出每窗
    上限被标记，证据保留至终结清理，初始恒 False）；parent_version_id 为
    版本父子关系（C-139-R1 §2：同窗累计链内首版 None、后续版本指向前一
    版本；跨窗绝不串链；fuse 单次融合路径恒 None；不参与 version_id）。
    无任何动作/事件生命周期字段——L4 不关闭、不撤销。"""

    __slots__ = ("version_id", "status", "items", "created_mono",
                 "camera_id", "run_id", "config_version", "window_id",
                 "coord_space", "frame_refs", "archived",
                 "parent_version_id")

    def __init__(self, version_id, status, items, created_mono,
                 camera_id, run_id, config_version, window_id,
                 coord_space=DEFAULT_COORD_SPACE, frame_refs=(),
                 archived=False, parent_version_id=None):
        if status not in FUSION_STATUS:
            raise ValueError(f"unknown fusion status: {status!r}")
        if parent_version_id is not None and not isinstance(
                parent_version_id, str):
            raise ValueError(
                f"parent_version_id must be None or str, "
                f"got {type(parent_version_id).__name__}")
        self.version_id = str(version_id)
        self.status = status
        self.items = tuple(items)
        self.created_mono = created_mono
        self.camera_id = camera_id
        self.run_id = run_id
        self.config_version = config_version
        self.window_id = window_id
        self.coord_space = coord_space
        self.frame_refs = tuple(frame_refs)
        self.archived = bool(archived)
        self.parent_version_id = parent_version_id


# ---- C-139-R1 §2：JSON-safe 双向序列化 ---------------------------------------

def _require_finite(value, where):
    """数值有限性校验（C-139 §4 同口径）：NaN/Inf 拒绝（ValueError），
    绝不静默改写成 null——静默 null 会在血缘里冒充"未知时间/未知区域"。"""
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"non-finite value in fusion version at {where}")
    return value


def fusion_version_to_json(version):
    """FusionVersion → JSON-safe dict（C-139-R1 §2 完整血缘）。

    覆盖：全 window 四元、version_id、status、parent_version_id（首版
    None/后续指向前版）、items（kind/text/certainty/unstructured + sources
    逐条结构化 {kind, ref}——绝不 str() 压平成 repr 字符串）、累计
    frame_refs（frame_id/t_ms/time_kind/bbox_norm/coord_space/crop_ref/
    stable_ref）、coord_space（含 mixed: 前缀）、archived 标记。缺失因素
    随 items 的 gap/conflict 条目携带。非有限数（NaN/Inf）→ ValueError
    拒绝（不静默变 null）；不含路径/凭据/图像数据；created_mono 是进程内
    单调钟（跨进程不可比、不参与血缘）→ 不序列化。
    """
    items = []
    for it in (version.items or ()):
        items.append({
            "kind": it.kind,
            "text": it.text,
            "certainty": it.certainty,
            "unstructured": bool(getattr(it, "unstructured", False)),
            "sources": [{"kind": s.kind, "ref": s.ref}
                        for s in (it.sources or ())],
        })
    frame_refs = []
    for fr in (version.frame_refs or ()):
        bbox = getattr(fr, "bbox_norm", None)
        if bbox is not None:
            bbox = [_require_finite(float(v), "frame_refs.bbox_norm")
                    for v in bbox]
        t_ms = getattr(fr, "t_ms", None)
        if t_ms is not None:
            t_ms = _require_finite(float(t_ms), "frame_refs.t_ms")
        frame_refs.append({
            "frame_id": getattr(fr, "frame_id", None),
            "t_ms": t_ms,
            "time_kind": getattr(fr, "time_kind", None),
            "bbox_norm": bbox,
            "coord_space": getattr(fr, "coord_space", DEFAULT_COORD_SPACE),
            "crop_ref": getattr(fr, "crop_ref", None),
            "stable_ref": getattr(fr, "stable_ref", None),
        })
    return {"version_id": version.version_id,
            "status": version.status,
            "parent_version_id": getattr(version, "parent_version_id", None),
            "camera_id": version.camera_id,
            "run_id": version.run_id,
            "config_version": version.config_version,
            "window_id": version.window_id,
            "coord_space": version.coord_space,
            "items": items,
            "frame_refs": frame_refs,
            "archived": version.archived}


def fusion_version_from_json(data):
    """JSON dict → FusionVersion（C-139-R1 §2 读回对照用，带关键类型校验）。

    校验（坏形状 ValueError，绝不静默改写）：data 必须 dict；version_id
    非空 str；status ∈ FUSION_STATUS；items/frame_refs 必须 list 且逐条
    dict；item kind/certainty 在冻结值域、sources 逐条 {kind, ref}（kind
    ∈ FUSION_SOURCE_KINDS）；frame_ref 经 FusionFrameRef 构造复核
    （time_kind/coord_space 值域、bbox 四元）；parent_version_id None 或
    str；archived 布尔。created_mono 不序列化（单调钟）→ 读回恒 None
    （跨进程不可比，不伪造时间）。"""
    if not isinstance(data, dict):
        raise ValueError(
            f"fusion_version_from_json: data must be a dict, "
            f"got {type(data).__name__}")
    version_id = data.get("version_id")
    if not isinstance(version_id, str) or not version_id:
        raise ValueError(
            f"fusion_version_from_json: version_id must be a non-empty "
            f"str, got {version_id!r}")
    status = data.get("status")
    if status not in FUSION_STATUS:
        raise ValueError(
            f"fusion_version_from_json: unknown status: {status!r}")
    raw_items = data.get("items", [])
    if not isinstance(raw_items, list):
        raise ValueError(
            f"fusion_version_from_json: items must be a list, "
            f"got {type(raw_items).__name__}")
    items = []
    for row in raw_items:
        if not isinstance(row, dict):
            raise ValueError(
                f"fusion_version_from_json: item must be a dict, "
                f"got {type(row).__name__}")
        raw_sources = row.get("sources", ())
        if not isinstance(raw_sources, (list, tuple)):
            raise ValueError(
                "fusion_version_from_json: item sources must be a list")
        sources = []
        for src in raw_sources:
            if not isinstance(src, dict):
                raise ValueError(
                    "fusion_version_from_json: source must be a "
                    f"{{kind, ref}} dict, got {src!r}")
            sources.append(FusionSource(src.get("kind"), src.get("ref")))
        items.append(FusionItem(
            kind=row.get("kind"), text=row.get("text", ""),
            sources=tuple(sources), certainty=row.get("certainty"),
            unstructured=bool(row.get("unstructured", False))))
    raw_refs = data.get("frame_refs", [])
    if not isinstance(raw_refs, list):
        raise ValueError(
            f"fusion_version_from_json: frame_refs must be a list, "
            f"got {type(raw_refs).__name__}")
    frame_refs = []
    for row in raw_refs:
        if not isinstance(row, dict):
            raise ValueError(
                f"fusion_version_from_json: frame_ref must be a dict, "
                f"got {type(row).__name__}")
        frame_refs.append(FusionFrameRef(
            frame_id=row.get("frame_id"),
            t_ms=row.get("t_ms"),
            time_kind=row.get("time_kind", "unknown"),
            bbox_norm=row.get("bbox_norm"),
            crop_ref=row.get("crop_ref"),
            stable_ref=row.get("stable_ref"),
            coord_space=row.get("coord_space", DEFAULT_COORD_SPACE)))
    archived = data.get("archived", False)
    if not isinstance(archived, bool):
        raise ValueError(
            f"fusion_version_from_json: archived must be a bool, "
            f"got {archived!r}")
    return FusionVersion(
        version_id=version_id, status=status, items=items, created_mono=None,
        camera_id=data.get("camera_id"), run_id=data.get("run_id"),
        config_version=data.get("config_version"),
        window_id=data.get("window_id"),
        coord_space=data.get("coord_space", DEFAULT_COORD_SPACE),
        frame_refs=frame_refs, archived=archived,
        parent_version_id=data.get("parent_version_id"))


# ---- 输入指纹（确定性序列化；version_id 的唯一来源） ------------------------

def _field(text):
    raw = str(text).encode("utf-8")
    return str(len(raw)).encode("ascii") + b":" + raw


def _row(*fields):
    return b"".join(_field(f) for f in fields) + b"\n"


def _ref_fields(ref):
    """对象引用指纹三字段：object_id + frame_id + stable（C-137 D1：候选
    双方都必须覆盖引用的帧与稳定位，绝不只看 object_id）。"""
    return (object_ref_id(ref),
            str(getattr(ref, "frame_id", "") or ""),
            "1" if object_ref_stable(ref) else "0")


def _window_fields(window):
    """窗口身份四字段（L3BranchResult.window 侧；缺字段如实空串，不猜）。"""
    return (str(getattr(window, "camera_id", "") or ""),
            str(getattr(window, "run_id", "") or ""),
            str(getattr(window, "config_version", "") or ""),
            str(getattr(window, "window_id", "") or ""))


def fingerprint_version_row():
    """指纹版本标记行（序列化首行；输入指纹与累计指纹共用）。"""
    return _row(FINGERPRINT_VERSION)


def window_fingerprint_row(camera_id, run_id, config_version, window_id):
    """窗口身份四元行（输入指纹与累计指纹共用首段）。"""
    return _row("window", camera_id, run_id, config_version, window_id)


def l1_fingerprint_rows(ref):
    """L1 引用材料行组（单行）：object_id + frame_id + stable。"""
    return (_row("l1", *_ref_fields(ref)),)


def l2_fingerprint_rows(cand):
    """L2 候选材料行组（单行）：subject/obj 各自 (object_id+frame_id+
    stable)、relation、score_raw、graph、vocabulary_id、不确定性标注。"""
    unc = getattr(cand, "uncertainty", None)
    flags = ("+".join(name for name in _CANDIDATE_UNCERTAINTY_FLAGS
                      if getattr(unc, name, False))
             if unc is not None else "")
    score = getattr(cand, "score_raw", 0.0)
    score_repr = (repr(float(score)) if isinstance(score, (int, float))
                  else str(score))
    return (_row(
        "l2", *_ref_fields(getattr(cand, "subject", "")),
        *_ref_fields(getattr(cand, "obj", "")),
        getattr(cand, "relation", ""), getattr(cand, "graph", ""),
        score_repr, str(getattr(cand, "vocabulary_id", "")), flags),)


def l3_fingerprint_rows(branch):
    """L3 分支材料行组（主行 + 不确定性行 + 每条帧来源行）。"""
    label = str(enum_value(getattr(branch, "branch", "")))
    status = str(enum_value(getattr(branch, "status", "")))
    err = getattr(branch, "error_code", None)
    window = getattr(branch, "window", None)
    rows = [_row(
        "l3", label, status, "" if err is None else str(err),
        str(getattr(branch, "crop_id", "") or ""),
        str(getattr(branch, "model_ref", "") or ""),
        "1" if getattr(branch, "unstructured", False) else "0",
        str(getattr(branch, "observation", None)),
        str(getattr(branch, "inference", None)),
        *(_window_fields(window) if window is not None
          else ("", "", "", "")),
        repr(tuple(getattr(branch, "frame_gaps_ms", ()) or ())))]
    unc = getattr(branch, "uncertainty", None)
    # Add a row only for newly supplied model unknowns: old material fingerprints
    # stay byte-identical; a changed unknown must not disappear as a replay.
    model_unknown = getattr(branch, "model_unknown", None)
    if model_unknown is not None and model_unknown != "":
        rows.append(_row("l3unknown", label, str(model_unknown)))
    rows.append(_row(
        "l3unc", label,
        *(("1" if getattr(unc, name, False) else "0")
          for name in _L3_UNCERTAINTY_FLAGS)))
    for src in (getattr(branch, "sources", ()) or ()):
        rows.append(_row(
            "l3src", label, str(getattr(src, "position", "")),
            str(getattr(src, "frame_id", "")),
            "1" if getattr(src, "present", False) else "0",
            repr(getattr(src, "t_capture_ms", None)),
            str(getattr(src, "timestamp_kind", ""))))
    return tuple(rows)


def failure_fingerprint_row(entry):
    """失败清单条目行（逐项；取消/预算淘汰随清单入账）。"""
    return _row("failure", *normalize_failure(entry))


def gap_fingerprint_row(entry):
    """缺失清单条目行（逐项）。"""
    return _row("gap", *normalize_gap(entry))


def coords_fingerprint_row(coord_space):
    """坐标体系声明行（C-138 B2：体系声明是材料身份的一部分）。"""
    return _row("coords", str(coord_space))


def frameref_fingerprint_row(frame_ref):
    """逐帧时空对齐行（v3：尾字段=该帧坐标体系声明，C-138 B2——不同
    体系声明的引用必不同材料身份）。"""
    bbox = getattr(frame_ref, "bbox_norm", None)
    return _row(
        "frameref", str(getattr(frame_ref, "frame_id", "")),
        repr(getattr(frame_ref, "t_ms", None)),
        str(getattr(frame_ref, "time_kind", "")),
        "" if bbox is None else ",".join(repr(float(v)) for v in bbox),
        str(getattr(frame_ref, "crop_ref", "") or ""),
        str(getattr(frame_ref, "stable_ref", "") or ""),
        str(getattr(frame_ref, "coord_space", DEFAULT_COORD_SPACE)))


def clock_fingerprint_row(clock_kinds):
    """时钟类型标注行（值集，序不敏感）。"""
    kinds = sorted({str(kind) for kind in (clock_kinds or ())})
    return _row("clock", *kinds)


def input_fingerprint_rows(input):
    """输入指纹序：netstring 逐字段序列化行序（长度前缀自定界，无歧义拼
    接），输入顺序即指纹顺序。覆盖面（C-137 D1 v2 + C-138 B2 v3）：
    - 窗口身份四元；
    - L1 引用：object_id + frame_id + stable；
    - L2 每候选：subject(object_id+frame_id+stable)、obj(同)、relation、
      score_raw、graph、vocabulary_id、不确定性标注；
    - L3 每分支：branch_kind、status/error_code、crop_id、model_ref、
      unstructured、observation/inference 文本、window 四元、帧间隔、
      不确定性标注、每条来源（position/frame_id/present/t_capture_ms/
      timestamp_kind）；
    - 失败/缺失清单逐项（取消/预算淘汰随清单入账）；
    - 时空对齐声明（coord_space + 逐帧 frame_refs，帧行含坐标体系声明）；
    - 时钟类型标注（值集，序不敏感）。"""
    rows = [fingerprint_version_row(),
            window_fingerprint_row(input.camera_id, input.run_id,
                                   input.config_version, input.window_id)]
    for ref in input.l1_object_refs:
        rows.extend(l1_fingerprint_rows(ref))
    for cand in input.l2_candidates:
        rows.extend(l2_fingerprint_rows(cand))
    for branch in input.l3_branches:
        rows.extend(l3_fingerprint_rows(branch))
    for entry in input.failures:
        rows.append(failure_fingerprint_row(entry))
    for entry in input.gaps:
        rows.append(gap_fingerprint_row(entry))
    rows.append(coords_fingerprint_row(
        getattr(input, "coord_space", DEFAULT_COORD_SPACE)))
    for frame_ref in (getattr(input, "frame_refs", ()) or ()):
        rows.append(frameref_fingerprint_row(frame_ref))
    rows.append(clock_fingerprint_row(input.clock_kinds))
    return tuple(rows)


def fingerprint_bytes(input):
    """输入指纹序字节串（input_fingerprint_rows 的连接形式，向后兼容名）。"""
    return b"".join(input_fingerprint_rows(input))


def merge_fingerprint_rows(prev_rows, rows):
    """指纹行并集（C-137 D3 首现序；保留供非累计场景）：前版本行在前、
    新输入行在后，按内容去重保首现序。（C-138 B1 起累计路径改用
    cumulative_fingerprint_rows 排序并集——到达顺序无关的确定性。）"""
    seen = set()
    merged = []
    for row in list(prev_rows) + list(rows):
        if row not in seen:
            seen.add(row)
            merged.append(row)
    return tuple(merged)


def cumulative_fingerprint_rows(window_row, material_rows):
    """累计材料集指纹行（C-138 B1）：版本标记行 + 窗口行 + 全部材料身份
    行，按字节排序去重——同累计材料集必得同指纹（与到达顺序无关，确定
    性），新增/变化材料必改指纹（不同指纹必新版本）。"""
    rows = {fingerprint_version_row(), window_row}
    rows.update(material_rows)
    return tuple(sorted(rows))


def combine_coord_spaces(spaces):
    """坐标体系声明联合（C-138 B2，确定性）：单体系 → 该声明；多体系
    并存 → MIXED_COORD_SPACE_PREFIX + 排序后 "|" 连接（版本级联合声明，
    不换算不合并；各帧引用仍各自携带真实 coord_space）；空集 → 默认。"""
    distinct = sorted({str(space) for space in (spaces or ())})
    if not distinct:
        return DEFAULT_COORD_SPACE
    if len(distinct) == 1:
        return distinct[0]
    return MIXED_COORD_SPACE_PREFIX + "|".join(distinct)


def rows_digest(rows):
    """指纹行序 → sha256 hex（确定性）。"""
    return hashlib.sha256(b"".join(rows)).hexdigest()


def fusion_fingerprint(input):
    """输入指纹序 → sha256 hex（确定性）：同输入重放同指纹；
    FusionVersion.version_id 即本值（C-136 §四；覆盖面 C-137 D1 v2）。"""
    return rows_digest(input_fingerprint_rows(input))
