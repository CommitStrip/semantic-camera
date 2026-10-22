"""win11_l3_contract.py —— L3 多帧层数据形状、预算与状态合同（C-135 §8 冻结；
C-136 C2/C3/C4 修订：缺帧固定序位 + 实际模型预算记账 + 结构化分支输出）。

全部数据形状（__slots__ 类）+ L3BranchKind + L3Status + L3Budget + 身份校验
助手 + L3VisionModel 协议 + L3 异常类。L3Stage 与 LocalTransformers 薄壳
适配器在 scam/win11_l3.py（构造注入模型，本模块不 import、不加载任何模型）。

C-136 修订（C2/C3/C4）：
- 缺帧固定序位（C2）：帧序位 0 基且固定——0=前、1=当前、2=后（更多帧按
  时间升序 0..N-1）；缺帧保留序位、present=False 显式占位/存在性记录；
  只有一帧在场绝不呈现三帧完整 ok（partial 语义如实）。缺帧、相邻帧时间
  间隔（frame_gaps_ms，缺帧侧 None=未知）、对象关联不确定性（region_only
  =同区域不保证同一对象）进入结果供 L4 输入。
- 实际模型预算（C3）：三层数值记账——原图证据尺寸（source_w/h）、传输
  （预处理后送 adapter）尺寸（transport_w/h）、模型真实 patch/token 预算
  （InternVL 448/14/0.5 → 每帧 1 个 patch 段=256 token，按实际送入尺寸
  计算）。预处理降采样后 provider 仍放回 448×448 → 不虚报 patch 预算
  下降（downscale_reduced_patch_budget=False + notes 如实标注）。图片数、
  真实 patch 数、上下文上限在调用边界断言/记录。
- 结构化分支输出（C4）：每条观察/推断保留 window+branch 身份、crop_id
  裁剪来源、源帧/时间（sources）、不确定性、缺失、model_ref；模型输出
  无法结构化时保留原文并显式 unstructured=True，不靠关键词猜"已确认
  行为"；enhanced=None 显式未增强（超分合同位保留）。

分界红线（违反即缺陷）：
- 零模型加载、零 I/O、零 cv2 依赖；生产入口禁 fake；L3 永不进入快系统/L1
  线程；stage 持有模型引用计数=1，不重启被隔离的 adapter（重建由生产层决定）。
- 状态枚举（C-135 §8 冻结八值）互斥不互冒充：ok/partial 是成功侧；
  unsupported/model_unavailable/infer_failed/timeout/backend_isolated/
  identity_rejected 是失败侧，与 L2 失败态语义同源。partial=模型调用成功但
  有缺帧/预算截断/降采样等不完整因素；绝不把失败冒充 partial，也不把
  partial 冒充 ok。
- 身份：帧四元 (camera_id, run_id, config_version, frame_id)；窗口四元
  (camera_id, run_id, config_version, window_id)。帧与窗口前三元全匹配才可
  处理，错配→identity_rejected——不调模型、不产观察/推断文本；帧的 branch
  标签与任务 branch 不符同判 identity_rejected（分支身份是身份的一部分，
  C-135 §9「窗口四元+分支身份」）。
- frame_bgr 隔离副本：L3FrameInput 构造时拷贝并置只读——调用方原数组后续
  变化不影响任务，stage/模型只读消费。
- enhanced=None 显式未增强（超分接入前恒 None）；绝不冒充已增强。
- 缺帧显式：frame_bgr=None 即占位缺失；stage 在 prompt 标注「第 N 帧缺失」、
  不给该帧任何图像占位符，绝不伪造图像，也不静默丢弃（来源引用 present=False）。
- 窗口输入冻结：stage 只处理 task.frames 给定的有序帧，不自行扩窗/等待新
  素材（新素材进下一窗口，归生产接线）。
- 无 L4 融合：L3Output 只带逐分支观察/推断/不确定性/来源记录，不做跨分支
  融合结论。
- 预算：max_frames_per_task（每任务帧数上限，超限截断进 omission）、
  max_total_pixels（送模型总像素上限，超限同比降采样显式记账）、max_queue
  （生产队列深度，C-135 §9 归生产接线，stage 同步处理不排队、不读它）、
  in_flight=1、concurrency=1（模型调用并发，默认 1，按设备能力构造可调）。
"""

import enum

import numpy as np

__all__ = [
    "INTERNVL_DOWNSAMPLE",
    "INTERNVL_IMAGE_SIDE",
    "INTERNVL_PATCH_SIDE",
    "INTERNVL_TOKENS_PER_PATCH_SEGMENT",
    "L3AdapterIsolated",
    "L3BranchKind",
    "L3BranchResult",
    "L3Budget",
    "L3BudgetAccounting",
    "L3_FAILURE_DETAIL_CODES",
    "L3FrameBudgetUsage",
    "L3FrameIdentity",
    "L3FrameInput",
    "L3ModelUnavailable",
    "L3Omission",
    "L3Output",
    "L3SourceRef",
    "L3Status",
    "L3Task",
    "L3Uncertainty",
    "L3VisionModel",
    "L3WindowIdentity",
    "window_matches_frame",
]


# ---- 模型预算口径常量（C-136 C3；InternVL 448/14/0.5 → 256 token/帧段） ----
# 口径来源：scam/models.py 本机 HF 缓存快照 5648fa26 的
# modeling_internvl_chat.py——force_image_size=448 / patch_size=14 /
# downsample_ratio=0.5，固定 Resize(448,448) → 每帧恰 1 个 patch 段；
# num_image_token=(448//14)**2*0.25=32*32*0.25=256。
INTERNVL_IMAGE_SIDE = 448
INTERNVL_PATCH_SIDE = 14
INTERNVL_DOWNSAMPLE = 0.5
INTERNVL_TOKENS_PER_PATCH_SEGMENT = int(
    (INTERNVL_IMAGE_SIDE // INTERNVL_PATCH_SIDE) ** 2
    * INTERNVL_DOWNSAMPLE ** 2)          # = 256（token 计数为整数）


# ---- 枚举（C-135 §8 冻结值） -----------------------------------------------

class L3BranchKind(enum.Enum):
    """分支标签（与 L2Output.l3_branches 的 branch_kind 对齐，C-135 §6）。"""

    PANORAMA = "panorama"
    RELATION_CROP = "relation_crop"
    CHANGE_REGION = "change_region"


class L3Status(enum.Enum):
    """互斥状态枚举（C-135 §8 冻结八值）；失败态不冒充成功态。"""

    OK = "ok"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    MODEL_UNAVAILABLE = "model_unavailable"
    INFER_FAILED = "infer_failed"
    TIMEOUT = "timeout"
    BACKEND_ISOLATED = "backend_isolated"
    IDENTITY_REJECTED = "identity_rejected"


# ---- detail_code 受控词表（C-139 §3 / C-139-R1 §2；L3 失败侧细分码） --------
# L3Output.error_code（=存档条目 detail_code，server /api 面透传）只取本表：
# stage 自身分类码 + 生产 adapter（win11_l3_backend）结构化异常的细分码
# （.code 原样保留，不压平成泛化码）。词表外的异常 code 一律回退到 stage
# 分类码——绝不透传未受控字符串（防异常文本里的路径/凭据细节进存档）。
# runtime 侧终态码（queue_wait_exceeded/publish_age_exceeded/dequeue/
# stop_cancelled 等，C-139 §2）归 Agent A 的 _settle_branch_terminal，
# 不经本表（本表只冻结 L3 stage/adapter 侧）。
L3_FAILURE_DETAIL_CODES = (
    "model_unavailable",     # stage 分类：模型不可用（缺权重/依赖等结构原因）
    "load_timeout",          # adapter：首次加载超时（隔离，线程残留如实）
    "timeout",               # stage 分类：推理等待超时（adapter 中毒隔离）
    "infer_failed",          # stage 分类：上游推理异常（非等待超时）
    "backend_isolated",      # adapter：隔离/关闭实例拒绝新任务（泛化拒收）
    "closed_rejected",       # adapter：已关闭后接单/交付拒收（结构化 code）
    "poisoned_rejected",     # adapter：中毒后接单/交付拒收（结构化 code）
    "generation_rejected",   # adapter：交付代次不符拒收（结构化 code）
    "stage_exception",       # 生产接线：stage 处理入口自身异常（runtime 记账）
    "unknown_error",         # 兜底：无法分类的失败（不编造具体原因）
)


# ---- 异常（适配器抛出；stage 分类映射。定义在 contract 保持分界干净） -------

class L3ModelUnavailable(Exception):
    """L3 模型不可用：依赖/权重缺失等结构性原因（结构化）。"""

    def __init__(self, reason, details=None):
        super().__init__(reason)
        self.reason = reason
        self.details = details


class L3AdapterIsolated(Exception):
    """adapter 已被隔离：超时毒化后拒绝再接任务（沿用 C-134 惯例）。

    不假装取消成功；残留占用由 snapshot() 如实报告。stage 不重启被隔离的
    adapter——是否重建由生产层决定。
    """

    def __init__(self, reason, details=None):
        super().__init__(reason)
        self.reason = reason
        self.details = details


# ---- 数据形状（字段名冻结，C-135 §8；全 __slots__） -------------------------

class L3FrameIdentity:
    """帧身份四元：camera/run/config/frame。"""

    __slots__ = ("camera_id", "run_id", "config_version", "frame_id")

    def __init__(self, camera_id, run_id, config_version, frame_id):
        self.camera_id = camera_id
        self.run_id = run_id
        self.config_version = config_version
        self.frame_id = frame_id


class L3WindowIdentity:
    """窗口身份四元：camera/run/config/window（window_key 恒四元，C-138 §1）。

    material_id（C-138 §1 新增可选段）：不参与窗口身份与 stage 三元身份
    校验（window_matches_frame 只看 camera/run/config），只用于同窗多材
    料包时 branch_key 的来源区分（branch_key 追加 material 段）；None=
    未提供（旧形状兼容），branch_key 的 material 段同样如实 None，键长
    恒定不变。
    """

    __slots__ = ("camera_id", "run_id", "config_version", "window_id",
                 "material_id")

    def __init__(self, camera_id, run_id, config_version, window_id,
                 material_id=None):
        self.camera_id = camera_id
        self.run_id = run_id
        self.config_version = config_version
        self.window_id = window_id
        self.material_id = material_id


class L3FrameInput:
    """有序帧输入：branch 标签 + 帧四元身份 + 观察钟时间 + 隔离副本图像。

    frame_bgr 构造时拷贝并置只读（隔离副本）；None=显式缺帧占位（prompt
    标注，绝不伪造图像）。enhanced=None 显式未增强。
    """

    __slots__ = ("branch", "identity", "t_capture_ms", "timestamp_kind",
                 "frame_bgr", "enhanced")

    def __init__(self, branch, identity, t_capture_ms, timestamp_kind,
                 frame_bgr, enhanced=None):
        self.branch = branch
        self.identity = identity
        self.t_capture_ms = t_capture_ms
        self.timestamp_kind = timestamp_kind
        if frame_bgr is not None:
            arr = np.asarray(frame_bgr).copy()
            arr.setflags(write=False)      # 隔离副本 + 只读（L3 只读消费）
            frame_bgr = arr
        self.frame_bgr = frame_bgr
        self.enhanced = enhanced


class L3Budget:
    """预算档位（C-135 §8 冻结默认：帧 8 / 队列 4 / 在途 1 / 并发 1）。"""

    __slots__ = ("max_frames_per_task", "max_total_pixels", "max_queue",
                 "in_flight", "concurrency")

    def __init__(self, max_frames_per_task=8,
                 max_total_pixels=8 * 448 * 448, max_queue=4, in_flight=1,
                 concurrency=1):
        self.max_frames_per_task = max_frames_per_task
        self.max_total_pixels = max_total_pixels
        self.max_queue = max_queue
        self.in_flight = in_flight
        self.concurrency = concurrency


class L3Task:
    """单分支任务：窗口身份 + 有序帧元组 + branch 标签 + 指令文本。

    frames 恒为 tuple（有序，prev→cur→next 语义由生产接线保证，stage 不
    重排；序位 0 基固定：0=前、1=当前、2=后，C-136 C2）。created_mono_ms
    为单调钟打点（生产队列记账用，stage 不读——stage 同步处理单任务，
    不排队不等待）。budget 缺位时用 stage 构造档。crop_id 为分支→裁图
    显式映射键（C-136 C1/C4：来自 L3BranchSpec.crop_id；全景/兜底任务
    同样携带对应 crop_id，缺省 None=生产接线未提供，绝不靠列表索引猜）。
    prompt 为分析指令；禁止携带 <image> 占位符（帧段布局由模型适配层按
    实际帧渲染，防止占位符数与图像数错位）。
    """

    __slots__ = ("window", "branch", "frames", "prompt", "created_mono_ms",
                 "budget", "crop_id")

    def __init__(self, window, branch, frames, prompt, created_mono_ms=None,
                 budget=None, crop_id=None):
        self.window = window
        self.branch = branch
        self.frames = tuple(frames)
        self.prompt = prompt
        self.created_mono_ms = created_mono_ms
        self.budget = budget
        self.crop_id = crop_id


class L3Uncertainty:
    """逐分支不确定性标注（全默认 False；可多选）。

    unenhanced=True 表示参与帧全部未增强（首版恒如此，如实标注）。
    """

    __slots__ = ("frame_missing", "frames_truncated", "pixels_downscaled",
                 "unenhanced")

    def __init__(self, frame_missing=False, frames_truncated=False,
                 pixels_downscaled=False, unenhanced=False):
        self.frame_missing = frame_missing
        self.frames_truncated = frames_truncated
        self.pixels_downscaled = pixels_downscaled
        self.unenhanced = unenhanced


class L3SourceRef:
    """来源引用：帧的固定序位 + 帧身份 + 真实存在性 + 观察钟时间。

    position 序位 0 基固定（C-136 C2）：0=前、1=当前、2=后（更多帧按时间
    升序 0..N-1）；缺帧保留序位，present=False 显式占位，绝不伪造来源。
    """

    __slots__ = ("position", "frame_id", "present", "t_capture_ms",
                 "timestamp_kind")

    def __init__(self, position, frame_id, present, t_capture_ms,
                 timestamp_kind):
        self.position = position
        self.frame_id = frame_id
        self.present = present
        self.t_capture_ms = t_capture_ms
        self.timestamp_kind = timestamp_kind


class L3FrameBudgetUsage:
    """逐帧三层预算记账（C-136 C3）。

    - source_width/height：原图证据尺寸（任务帧构造时的真实像素）。
    - transport_width/height：传输尺寸——stage 预处理（有界缩放/降采样）
      后实际送 adapter 的像素。
    - provider_rescaled：传输尺寸任一边 < 448（provider 侧固定
      Resize(448,448) 会放回 448——降采样未降低模型侧预算，如实标注）。
    - effective_patches/effective_tokens：模型真实 patch 段与 token 预算，
      按实际送入（provider 变换后）尺寸计算：InternVL 固定 448×448 →
      每帧 1 patch 段 = 256 token（INTERNVL_TOKENS_PER_PATCH_SEGMENT）。
    """

    __slots__ = ("position", "present", "source_width", "source_height",
                 "transport_width", "transport_height", "provider_rescaled",
                 "effective_patches", "effective_tokens")

    def __init__(self, position, present, source_width, source_height,
                 transport_width, transport_height, provider_rescaled,
                 effective_patches, effective_tokens):
        self.position = position
        self.present = present
        self.source_width = source_width
        self.source_height = source_height
        self.transport_width = transport_width
        self.transport_height = transport_height
        self.provider_rescaled = provider_rescaled
        self.effective_patches = effective_patches
        self.effective_tokens = effective_tokens


class L3BudgetAccounting:
    """单任务实际模型预算记账（C-136 C3；成功侧与调用后失败侧如实携带）。

    - frames：逐帧 L3FrameBudgetUsage（固定序位，与任务帧序一致）。
    - image_count：实际进模型图像数（=present 帧数，调用边界断言）。
    - total_patches/total_tokens：真实 patch 段与 token 合计（调用边界
      断言 = Σ逐帧 effective_*）。
    - context_limit_tokens：模型/adapter 声明的上下文 token 上限；未声明
      → None（不编造）。声明且超限时 notes 如实记录。
    - downscale_reduced_patch_budget：预处理降采样是否真实降低了 patch
      预算。本 provider 固定 Resize(448,448) → 恒 False——降采样后又被
      放回 448，绝不虚报 patch 预算下降（notes 记 provider_rescaled 帧数）。
    - notes：确定性渲染的记账备注（"k1=v1;k2=v2"，同 L2/L3 omission 惯例）。
    """

    __slots__ = ("image_side", "patch_side", "downsample_ratio",
                 "tokens_per_patch_segment", "frames", "image_count",
                 "total_patches", "total_tokens", "context_limit_tokens",
                 "downscale_reduced_patch_budget", "notes")

    def __init__(self, image_side, patch_side, downsample_ratio,
                 tokens_per_patch_segment, frames, image_count, total_patches,
                 total_tokens, context_limit_tokens,
                 downscale_reduced_patch_budget, notes):
        self.image_side = image_side
        self.patch_side = patch_side
        self.downsample_ratio = downsample_ratio
        self.tokens_per_patch_segment = tokens_per_patch_segment
        self.frames = tuple(frames)
        self.image_count = image_count
        self.total_patches = total_patches
        self.total_tokens = total_tokens
        self.context_limit_tokens = context_limit_tokens
        self.downscale_reduced_patch_budget = downscale_reduced_patch_budget
        self.notes = notes


class L3BranchResult:
    """逐分支结构化结果（C-135 §8 + C-136 C4）：观察文本 / 推断文本 /
    不确定性 / 来源引用 + 状态 + 身份与来源标注。

    - observation/inference 是模型输出原样文本（不加工不改写）；无 L4 融合。
    - model_unknown：可选模型自报未知，字符串原样、其他JSON值确定性编码；
      不是已核实结论。L4以unknown确定性等级保留，旧调用缺省None。
    - window/branch/crop_id/model_ref：每条结果自带窗口+分支身份、裁剪
      来源键与模型版本来源（C-136 C4）。
    - unstructured：模型输出无法结构化时 True——原文保留在 observation，
      自由文本不冒充系统确认事实，不靠关键词猜"已确认行为"（C-136 C4）。
    - region_only：True=帧间按同空间区域关联，不保证同一对象（C-136 C1/C2）。
    - frame_gaps_ms：相邻序位帧的观察钟间隔（ms）；任一侧缺帧为 None
      （未知间隔，如实）——缺帧/时间间隔进入结果供 L4（C-136 C2）。
    """

    __slots__ = ("branch", "status", "error_code", "observation", "inference",
                 "uncertainty", "sources", "window", "crop_id", "model_ref",
                 "region_only", "unstructured", "frame_gaps_ms", "model_unknown")

    def __init__(self, branch, status, error_code, observation, inference,
                 uncertainty, sources, window=None, crop_id=None,
                 model_ref=None, region_only=False, unstructured=False,
                 frame_gaps_ms=(), model_unknown=None):
        self.branch = branch
        self.status = status
        self.error_code = error_code
        self.observation = observation
        self.inference = inference
        self.uncertainty = uncertainty
        self.sources = sources
        self.window = window
        self.crop_id = crop_id
        self.model_ref = model_ref
        self.region_only = region_only
        self.unstructured = unstructured
        self.frame_gaps_ms = tuple(frame_gaps_ms)
        # Model-reported unknown text, not a system-verified conclusion.
        # Optional trailing field preserves existing constructors.
        self.model_unknown = model_unknown


class L3Omission:
    """省略记账：不静默丢弃（frames_dropped + 确定性 reason）。"""

    __slots__ = ("frames_dropped", "reason")

    def __init__(self, frames_dropped, reason):
        self.frames_dropped = frames_dropped
        self.reason = reason


class L3Output:
    """单任务输出：逐分支 results（本版一任务一分支）；status 为聚合状态
    （单分支即该分支状态）；timings_ms 至少含 preprocess/infer/total；
    budget_accounting=实际模型预算记账（C-136 C3：成功侧与调用后失败侧
    携带；identity_rejected/unsupported 等未到调用边界→None，绝不编造）。"""

    __slots__ = ("window", "branch", "status", "error_code", "results",
                 "omission", "model_ref", "timings_ms", "budget_accounting")

    def __init__(self, window, branch, status, error_code, results, omission,
                 model_ref, timings_ms, budget_accounting=None):
        self.window = window
        self.branch = branch
        self.status = status
        self.error_code = error_code
        self.results = results
        self.omission = omission
        self.model_ref = model_ref
        self.timings_ms = timings_ms
        self.budget_accounting = budget_accounting


# ---- 身份校验助手（窗口三元 + 分支标签） ------------------------------------

def window_matches_frame(window, frame_identity):
    """窗口与帧的 camera/run/config 三元全等（frame_id 不参与窗口匹配）；
    任一不符即 False（stage 据此返回 identity_rejected）。"""
    return (window.camera_id == frame_identity.camera_id
            and window.run_id == frame_identity.run_id
            and window.config_version == frame_identity.config_version)


# ---- 模型协议（C-135 §8：win11_l3.py 实现真实薄壳；测试注入假实现） --------

class L3VisionModel:
    """L3 多帧视觉模型协议（鸭子类型）。

    model_ref：名称/来源/版本描述（不含路径）。
    understand_frames(prompt, frames_bgr, frames_meta) -> dict：
    - frames_bgr：有序 BGR ndarray 列表，None 项=显式缺帧占位；
    - frames_meta：与 frames_bgr 等长的逐帧元信息 dict 列表（键序冻结：
      position/present/branch/camera_id/run_id/config_version/frame_id/
      t_capture_ms/timestamp_kind/enhanced）；
    - 返回模型输出 dict（如 {"observation": …, "inference": …} 或
      {"text": …}）；失败抛异常（L3ModelUnavailable / TimeoutError 子类 /
      L3AdapterIsolated / 其他=infer_failed），由 stage 分类映射状态。
    生产默认 LocalTransformers 薄壳（win11_l3.py）；禁 fake 进生产。
    """

    model_ref = "unspecified"

    def understand_frames(self, prompt, frames_bgr, frames_meta):
        raise NotImplementedError("L3VisionModel 是协议；注入具体实现")
