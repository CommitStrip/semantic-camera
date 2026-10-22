"""win11_event_materials.py —— 同事件**跨窗口选材**（C154 车道 G）。

目标（只做这一件欠账）：在**共享预算内**保留同一事件的**开始、可证明的
选材转折、最新状态**，原始帧/裁图/事件身份可追溯，并且**生产入口实际使用**
（不是只新增一个模块）。

## 1. 作用域与守卫（不得削弱）

只有在**明确唯一 `event_id`** 且 camera/run/config/object 绑定成立时，才允许
跨窗汇聚；没有可信绑定时**继续旧窗口路径**，把原因记入账目，**绝不猜事件**：

- 绑定来源 = 事实链快照（`EventProgress` 的只读查询），**不是** L4 结果；
- 不得按相邻时间 / latest / 文本相似合并；
- 多对象关系**不**无条件归给一个对象（`multi_object` 直接拒绝汇聚）；
- 跨 camera / run / config **结构上不可能**汇聚：池键第一段即
  `(camera, run, config)`，事件身份再进一级；
- 同一帧上多个不同 `event_id` → `conflicting_events`（如实不猜）。

**选材点能看到的事实（设计声明，禁止倒用未来结果）**：调用方在
`observe()/plan_frames()` 处只能看到

1. 生产身份 `camera_id` / `run_id` / `config_version` / `window_key` /
   `material_id` / `frame_id` / `t_capture_ms` / `timestamp_kind`；
2. L1 材料触发事实 `material_reason`（`change_start|latest|patrol`，见
   `Monitor._select_material`）与门控变化框 `change_boxes`；
3. 该帧在事实链里**已经落库**的对象/事件绑定（`object_id` / `track_id` /
   `event_id` / `event_t_start` / `event_t_last` / `event_occurrence`）——
   它在同一帧循环里由 `record_conclusion` 先写入，**先于**材料进入理解阶段；
4. 材料包的 prev/cur/nxt 序位与像素。

**看不到**（因此绝不使用）：L4 融合版本号/`version_id`、事件关闭后的
`event_end_reason`、任何后一窗口才产生的结果、后续窗口的帧、以及页面上
才出现的阶段文案。

## 2. 有界保存（上限明确、可查询、不无界增长）

- 全局：`max_events`（默认 32）个事件槽、`max_total_pixels`（默认
  12e6 像素）总持有像素、`max_total_bytes`（默认 64 MiB）总持有字节。
- 单事件：`max_frames_per_event`（默认 6）帧。
- 单帧：`max_frame_pixels`（默认 2_073_600 = 1920×1080）；超出则**有界
  降采样**（记录原尺寸，身份不变），绝不无界持有原图。
- 超限淘汰有确定优先序：优先淘汰**未绑定**帧，其次淘汰**无转折依据的
  中间采样**，再淘汰**最旧**帧；**开始帧与最新帧最后才淘汰**
  （“开始、最新优先保留”）。
- 每帧/每事件/全局计数与最近淘汰原因进 `snapshot()`（可查询、有界）。
- **复制前预算（C154-R1 车道 H，见 §6）**：任何复制之前先算目标形态
  （尺寸/通道/dtype/字节）；满池先**安全淘汰或拒绝**，再为复制预留容量。
- **两本账**：`held_*`＝已入池帧的持有内存；`reserved_temp_*`＝复制在途的
  临时（预留）内存——分别记账、分别可查（`accounting()` /
  `snapshot()["accounting"]`）。

## 3. 转折依据（不得编造）

`turn_basis` 只认**来源事实**：材料触发原因 `change_start`
（`Monitor._select_material` 的“静→动边沿：变化开始帧最优先”）是**该事件
内**的一次真实状态转变（静止→运动），因此该帧标 `"turning"`，并携带
`turn_basis="material_reason:change_start"` 与 `turn_marker`（受控词表）。
其余取值（`latest|patrol|None|未知`）**没有**转折依据 → 中间帧标
`"middle_sample"` + `turn_basis="unknown"`，并按 C153-R1 §4 写
“**中间采样，转折覆盖未证明**”。绝不把“第二张图”强行当转折。

## 4. 身份（聚合不丢原身份，聚合任务身份 ≠ 源帧身份）

- 聚合键 = `(camera_id, run_id, config_version, event_id, object_id)`；
- 每张源帧保留原 `window_id` / `material_id` / `frame_id` / `t_capture_ms`
  / `timestamp_kind`（`SequenceFrame` 原样转交），`L3FrameIdentity` 仍由
  真实 `(camera, run, config, frame_id)` 构造；
- 送入任务的帧序 = 本窗口主序位帧 + 事件池内**同事件同身份**的保留帧，
  去重（同身份同像素只出现一次）、按观察钟升序、有上限；
- 聚合**不申请**第二份预算：帧数上限由 C153 `L3TaskBudgetLedger` 的派生
  单任务档给出，本模块只做**有界选材**，绝不 reserve/upgrade 额度。

## 5. 分界红线

零模型、零 I/O、零库写入、零线程；不读 L4 结果；不改事件开闭；不替代
`L3TaskBudgetLedger`（共享预算账本仍归 `win11_l3_tasks`）。

## 6. 复制前校验与账目（C154-R1 车道 H）

- **先校验、后复制**：`_plan_image()` 在**零复制**的前提下算出目标尺寸
  （长边/短边、降采样后尺寸）、通道数、dtype 与字节数；非法/不支持的图像
  形态按**受控原因码**拒绝（`unsupported_image_type` / `unsupported_ndim` /
  `unsupported_dtype` / `unsupported_channels` / `invalid_shape`），
  **不按像素数限额放行**。
- **单帧超池上限直接拒绝**：`frame_bytes_over_pool_cap` /
  `frame_pixels_over_pool_cap`——不复制、不预留。
- **满池**：先按 §2 既有优先序安全淘汰；淘汰后仍放不下 → 拒绝
  `pool_total_cap_refused`。**拒绝路径零复制**（绝不“先 copy 再判断超限”）。
- **恰一次复制**：`_copy_once()` 只用一次 `np.array(..., order="C",
  copy=True)` 落成只读、C 连续副本；非连续输入不再
  `ascontiguousarray().copy()` 形成**双份副本**。`copy_count` 可查。
- **预留恰一次归还**：`_CopyReservation` 只有 commit / release 两条出口；
  复制异常、形态不符、池关闭、事件页已被淘汰一律 release
  （`reserved_temp_*` 归零；`copy_reservations == committed + released`；
  `reservation_release_after_settle == 0`）。归还**只**减在途预留，
  **不清**已有帧的持有账目。
- **关闭协调（C154-R1 车道 J：有序关闭）**：关闭分五步，各步可分别调用、
  可分别验证——runtime 按其时序调用，本池只提供**可被这样调用**的 API：

  1. **封准入** `close_begin(reason=...)`（`close()` 是其兼容别名）：**立即**
     封闭准入、拒绝新材料（`pool_closed`），**不等待**任何消费线程 join、
     **不**释放任何像素、**不**清零任何账目；幂等。
  2. **结算已接纳任务**：池侧只保证"不再接纳"——已接纳观察的提交段发现
     关闭即归还预留、帧不入池（`refused_reasons[pool_closed]`），
     `plan_frames()` 一律按 `pool_closed` 走旧窗口路径。池**不越权**改
     runtime 的线程模型（join/消费线程收口仍归 runtime）。
  3. **锁外有界等在途预留归还** `await_reservations(timeout_s=5.0)`：只在
     "是否仍有在途预留"的判定瞬间持锁，**等待期间绝不持锁**（复制线程因此
     可以继续拿锁完成提交/归还）；返回是否**全部**归还。超时 → `False`，
     真实在途账目**原样保留**。**为什么"全部归还"足以支撑步骤 4**：`_store_row`
     里"关闭检查 + 预留"在同一次持锁内完成（见该方法第 2 段），所以
     `close_begin()` 返回之后**不可能**再新增预留；而提交段在同一把锁下
     再次检查关闭（已封 → 归还、不入池），因此也不可能再新增像素——
     等待归零 = 池内像素此后**冻结**。
  4. **解除像素持有** `release_pixels(dependencies_done=None)`：仅在
     ①准入已封 ②无在途预留 ③调用方未声明仍有依赖 时释放已入池帧的**像素**
     （`frame_bgr=None`，账目只减该帧实际持有），并冻结**有界、无像素**的
     身份/计数摘要；任一条件不满足 → **拒绝**且**不强清引用**（真实
     held/reserved 原样保留）。
  5. **收尾报告** `close_report()`：`closed` / `complete` / 当前持有像素与
     字节 / 在途预留 / 未完成原因（受控码）/ 历史保留·释放·拒绝计数
     （**不因关闭而清零**）。

  成功关闭 = 当前像素持有与在途预留**归零**且历史身份与计数**仍可查**；
  超时或仍有依赖 = `complete=False` + 真实 held/reserved + 受控原因。
  **不得**把材料池释放等同于 L3 模型执行资源释放（两者账目分列，互不代偿）。
- **不长歪**：`snapshot()["accounting"]` 同时给增量账本与按帧重算值
  （`drift_bytes` / `drift_pixels`），任何漂移可查、不隐藏。

## 7. 逐帧准入与主帧事件键（C155 车道 B；**两个默认关的开关**）

共享构造**默认保持兼容**：`frame_level_binding=False` 与
`primary_frame_binding=False`，旧整包分支与旧窗口索引路径**逐字未动**。
生产由主会话在构建点显式开启（能力探测：绑定来源必须真的提供
`resolve_frame_bindings`，否则如实回 `package` 模式）。

- **逐帧准入（`frame_level_binding`）**：判定粒度从整包降到**帧**，复用**同一
  只读一致性快照**与原守卫（身份/时基/持久区间/对象集合），**不新增任何宽松
  绑定真相**——分类只由来源给出，缺证据一律保守拒绝。包内"只有 `cur` 合法
  绑定"时**只保留 `cur`**；未知帧**零像素保留**、零搬运，只在
  `record["unattributed"]` 留 `{frame_id, classification, reason}`。
  同包不同事件/对象 → `conflicting_events` / `multi_object`（拒绝聚合，不按
  多数/latest/文本/邻帧择一）；零保留 → 按**逐帧主导原因**拒绝，继续原
  未关联路径。
- **主帧事件键（`primary_frame_binding`）**：事件页按**显式、已核验的主帧事件
  键**定位（`primary_event_key` → 主帧行自带键 → 池侧对**主帧一帧**的只读
  查询 → 旧窗口索引）。因此"取包点观察（`window_key=None`）注册的事件页"不再
  让真实窗口永久 `no_event_binding`（无 `None` 键死路）。多候选指向不同页 →
  拒绝搬运；窗口已 `forget_window` 封口 → 不得再由窗口无关路由搬回。
- **两次闸门**：多对象二次闸门在生产解析器**不返回 `refs`** 时长期惰性；缺
  `refs` 时按调用方声明的对象集合判定（>1 个对象 → `multi_object`），证据
  模式记入 `record["multi_object_gate"]` 与 `snapshot()["multi_object_gate"]`。
- **账目分列**：逐帧口径的拒绝/分类/原因记入 `frame_level_refusals` /
  `frame_classifications` / `frame_level_reasons` 与新增 `counts` 键，**与整包
  口径分列**——历史臂的整包计数**不可**与本组直接横比。
"""

from __future__ import annotations

import math
import threading
import time

import numpy as np

__all__ = [
    "CLOSE_DEPENDENCIES_PENDING",
    "CLOSE_INCOMPLETE_REASONS",
    "CLOSE_NOT_BEGUN",
    "CLOSE_PIXELS_STILL_HELD",
    "CLOSE_RESERVATIONS_OUTSTANDING",
    "DEFAULT_CLOSE_TIMEOUT_S",
    "DEFAULT_MAX_EVENTS",
    "DEFAULT_MAX_FRAMES_PER_EVENT",
    "DEFAULT_MAX_FRAMES_PER_TASK",
    "DEFAULT_MAX_FRAME_PIXELS",
    "DEFAULT_MAX_TOTAL_BYTES",
    "DEFAULT_MAX_TOTAL_PIXELS",
    "DEFAULT_SEALED_WINDOW_CAP",
    "EVENT_MATERIALS_SCHEMA",
    "FRAME_CLASSES",
    "FRAME_CLASS_AMBIGUOUS",
    "FRAME_CLASS_BOUND",
    "FRAME_CLASS_CONTEXT",
    "FRAME_CLASS_REJECTED",
    "FRAME_LEVEL_REASONS",
    "FRAME_REASON_PRIORITY",
    "IMAGE_REFUSAL_REASONS",
    "MODE_PACKAGE",
    "MODE_PER_FRAME",
    "MULTI_OBJECT_GATE_DECLARED",
    "MULTI_OBJECT_GATE_NONE",
    "MULTI_OBJECT_GATE_REFS",
    "OBJECT_REASON_INVALID",
    "OBJECT_REASON_L1_PENDING",
    "OBJECT_REASON_MISSING",
    "OBJECT_STATE_IDENTITY_INSUFFICIENT",
    "OBJECT_STATE_L1_PENDING",
    "OBJECT_STATE_NO_OBJECTS",
    "REFUSE_BINDING_IDENTITY_MISMATCH",
    "REFUSE_COPY_FAILED",
    "REFUSE_COPY_SHAPE_MISMATCH",
    "REFUSE_ENTRY_EVICTED",
    "REFUSE_FRAME_BYTES_OVER_TOTAL",
    "REFUSE_FRAME_PIXELS_OVER_TOTAL",
    "REFUSE_INVALID_SHAPE",
    "REFUSE_POOL_CLOSED",
    "REFUSE_POOL_FULL",
    "REFUSE_UNSUPPORTED_CHANNELS",
    "REFUSE_UNSUPPORTED_DTYPE",
    "REFUSE_UNSUPPORTED_IMAGE",
    "REFUSE_UNSUPPORTED_NDIM",
    "ROLE_LATEST",
    "ROLE_MIDDLE",
    "ROLE_START",
    "ROLE_TURNING",
    "SUPPORTED_CHANNELS",
    "SUPPORTED_DTYPES",
    "TURN_BASIS_UNKNOWN",
    "TURN_COVERAGE_NOTE",
    "TURN_MARKER_CHANGE_START",
    "EventMaterialPool",
    "FramePlan",
    "SequenceFrame",
    "observe_window_materials",
]

EVENT_MATERIALS_SCHEMA = "scam.win11.event_materials/v1"

DEFAULT_MAX_EVENTS = 32
DEFAULT_MAX_FRAMES_PER_EVENT = 6
DEFAULT_MAX_TOTAL_PIXELS = 12_000_000     # 池内总数：12 MP（≈6 帧 1080p）
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_FRAME_PIXELS = 1920 * 1080     # 单帧上限：超出即有界降采样
DEFAULT_MAX_FRAMES_PER_TASK = 3            # 回落到共享预算档时的保守上限

# 角色词表（与 win11_l3.select_frames_within_budget 同形，但不互相依赖）
ROLE_START = "start"
ROLE_TURNING = "turning"
ROLE_LATEST = "latest"
ROLE_MIDDLE = "middle_sample"

# 转折依据词表（受控；只认来源事实）
TURN_MARKER_CHANGE_START = "material_reason:change_start"
_TURN_MARKERS = frozenset({TURN_MARKER_CHANGE_START})
TURN_BASIS_UNKNOWN = "unknown"
TURN_COVERAGE_NOTE = "中间采样，转折覆盖未证明"

# 选材点可见的材料触发原因（`Monitor._select_material`；其余值按未知处理）
_MATERIAL_REASONS = frozenset({"change_start", "latest", "patrol"})

# ---- 受控原因码（C154-R1 车道 H：复制前校验 / 容量 / 生命周期） --------------
# 图像形态（复制**之前**判定；绝不以像素数限额代替形态校验）
REFUSE_UNSUPPORTED_IMAGE = "unsupported_image_type"
REFUSE_UNSUPPORTED_NDIM = "unsupported_ndim"
REFUSE_UNSUPPORTED_CHANNELS = "unsupported_channels"
REFUSE_UNSUPPORTED_DTYPE = "unsupported_dtype"
REFUSE_INVALID_SHAPE = "invalid_shape"
# 池容量（先淘汰或拒绝，再预留）
REFUSE_FRAME_BYTES_OVER_TOTAL = "frame_bytes_over_pool_cap"
REFUSE_FRAME_PIXELS_OVER_TOTAL = "frame_pixels_over_pool_cap"
REFUSE_POOL_FULL = "pool_total_cap_refused"
REFUSE_ENTRY_EVICTED = "event_entry_evicted"
# 复制与生命周期
REFUSE_COPY_FAILED = "frame_copy_failed"
REFUSE_COPY_SHAPE_MISMATCH = "frame_copy_shape_mismatch"
REFUSE_POOL_CLOSED = "pool_closed"
# 身份边界（绑定来源给出的身份必须与本次观察参数全等，否则不搬运）
REFUSE_BINDING_IDENTITY_MISMATCH = "binding_identity_mismatch"

# ---- F3（C154 车道 Q）：**无对象**的受控细分（**只加诊断，零判定改动**） ------
# 现状：`detections is None`（L1 从未给出结论 / 结论尚未取得）与
# `detections == []`（结论确认无对象）得到**同一个** `object_ids_missing`，
# 账目上不可分辨。以下常量只用于**新增诊断字段**（`object_ids_state` /
# `object_ids_reason`）：既有 `reason` 与 `refusals[...]` 逐字不变，准入判据
# （仍交 `resolve_material_binding`）一字未动。
# 状态（互斥三态；不适用时为 None）：
OBJECT_STATE_NO_OBJECTS = "no_objects"            # 结论已到且确认零对象
OBJECT_STATE_L1_PENDING = "l1_pending"            # 结论尚未取得 / 失败 / 被拒
OBJECT_STATE_IDENTITY_INSUFFICIENT = "identity_insufficient"  # 有检出但对象身份不足
# 原因码（诊断用；`unknown` 绝不写成 `empty`）：
OBJECT_REASON_MISSING = "object_ids_missing"      # 兼容码：确认无对象
OBJECT_REASON_L1_PENDING = "object_ids_missing_l1_pending"
OBJECT_REASON_INVALID = "object_ids_invalid"

# ---- 受控原因码（C154-R1 车道 J：有序关闭的"未完成"原因） -------------------
# `close_report()["incomplete_reason"]` 只取下列值之一（或 None=已完成）：
CLOSE_NOT_BEGUN = "close_not_begun"                        # 准入尚未封闭
CLOSE_RESERVATIONS_OUTSTANDING = "close_reservations_outstanding"  # 仍有在途预留
CLOSE_DEPENDENCIES_PENDING = "close_dependencies_pending"  # 调用方声明仍有依赖
CLOSE_PIXELS_STILL_HELD = "close_pixels_still_held"        # 像素尚未释放
CLOSE_INCOMPLETE_REASONS = frozenset({
    CLOSE_NOT_BEGUN, CLOSE_RESERVATIONS_OUTSTANDING,
    CLOSE_DEPENDENCIES_PENDING, CLOSE_PIXELS_STILL_HELD,
})

# 关闭等待在途预留的缺省上限（与 runtime 停机 timeout 同量级）
DEFAULT_CLOSE_TIMEOUT_S = 5.0

# 逐帧拒绝的**受控集合**（测试断言原因码不越界；新增必须先在此登记）
IMAGE_REFUSAL_REASONS = frozenset({
    REFUSE_UNSUPPORTED_IMAGE, REFUSE_UNSUPPORTED_NDIM,
    REFUSE_UNSUPPORTED_CHANNELS, REFUSE_UNSUPPORTED_DTYPE,
    REFUSE_INVALID_SHAPE, REFUSE_FRAME_BYTES_OVER_TOTAL,
    REFUSE_FRAME_PIXELS_OVER_TOTAL, REFUSE_POOL_FULL, REFUSE_ENTRY_EVICTED,
    REFUSE_COPY_FAILED, REFUSE_COPY_SHAPE_MISMATCH, REFUSE_POOL_CLOSED,
})

# ---- C155 车道 B：**逐帧准入**（判定粒度：整包 → 逐帧；旧整包路径零改动） ---
# 旧口径（`resolve_material_binding`）是**整包** all-or-nothing：包内任一帧缺
# 快照即整包 `frame_binding_missing`，于是"只有 `cur` 帧合法绑定"的启动形态
# 永远拿不到证据。以下常量只服务于**并存**的逐帧路径：
#
# - 只有显式打开 `frame_level_binding` **且**绑定来源真的提供
#   `resolve_frame_bindings`（能力探测）时才走逐帧路径；
# - 逐帧路径**复用同一一致性快照与原守卫**（身份/时基/持久区间/对象集合），
#   分类只由只读来源给出——**不新增任何宽松绑定真相**：来源缺证据即保守拒绝；
# - 原 `resolve_material_binding` 与本池的旧整包分支**逐字不变**。
MODE_PACKAGE = "package"
MODE_PER_FRAME = "per_frame"

# 逐帧分类词表（与 `win11_event_progress.resolve_frame_bindings` 的三分类同源）
FRAME_CLASS_BOUND = "bound"          # 该帧自身已成立唯一 object/event 绑定
FRAME_CLASS_CONTEXT = "context"      # 该帧明确未归属（可作画面参考，**不是证据**）
FRAME_CLASS_AMBIGUOUS = "ambiguous"  # 该帧自身事实歧义（多对象/对象不符/多事件）
FRAME_CLASS_REJECTED = "rejected"    # 该帧被拒（缺快照/时基不符/已关闭/身份不全）
FRAME_CLASSES = frozenset({
    FRAME_CLASS_BOUND, FRAME_CLASS_CONTEXT, FRAME_CLASS_AMBIGUOUS,
    FRAME_CLASS_REJECTED,
})

# 包级**主导原因**优先级（只在"零保留"时用于如实说明，**绝不**用于挑事件）
FRAME_REASON_PRIORITY = (
    "multi_object", "conflicting_events", "frame_binding_missing",
    "no_event_binding", "object_mismatch", "object_ids_missing",
    "time_kind_mismatch", "identity_incomplete", "identity_mismatch",
    "closed", "event_binding_ambiguous",
)

# 逐帧路径可用的受控原因码（帧级 + 逐帧路径的包级；新增必须先在此登记）
FRAME_LEVEL_REASONS = frozenset({
    "frame_binding_missing", "no_event_binding", "multi_object",
    "object_mismatch", "object_ids_missing", "time_kind_mismatch",
    "identity_incomplete", "identity_mismatch", "closed",
    "event_binding_ambiguous", "frame_binding_unclassified",
    "conflicting_events", "binding_source_bad_shape", REFUSE_POOL_CLOSED,
})

# 二次闸门（多对象）的**证据模式**：生产 `resolve_material_binding` 的帧行是
# `{frame_id, t_ms, time_kind}`（`:585-589`）**不含 `refs`** ⇒ 该闸门在生产路径
# 上**长期惰性**（只有返回 `refs` 的替身才会触发）。缺 `refs` 时改用**调用方
# 声明的对象集合**这一可得证据判定，**绝不静默跳过**（负例已先证后修）。
MULTI_OBJECT_GATE_REFS = "refs"
MULTI_OBJECT_GATE_DECLARED = "declared_object_ids"
MULTI_OBJECT_GATE_NONE = "no_object_evidence"

# 已**封口**窗口的有界记忆（`forget_window` 后不得再由窗口无关路径重开搬运）
DEFAULT_SEALED_WINDOW_CAP = 64

# 支持的图像形态（与 L3 预处理/编码一致：BGR/灰度/带 alpha 的 8/16 位图）
SUPPORTED_DTYPES = ("uint8", "uint16")
SUPPORTED_CHANNELS = (1, 3, 4)

_MAX_FRAME_ID_CHARS = 160

# 池键槽位：`(camera, run, config, event_id, object_id)`——聚合键逐段可断言
_KEY_CAMERA, _KEY_RUN, _KEY_CONFIG, _EVENT_ID_SLOT, _OBJECT_ID_SLOT = range(5)


def _text(value, limit=_MAX_FRAME_ID_CHARS):
    """有界文本（None 原样 None；不改写语义，只截断长度）。"""
    if value is None:
        return None
    return str(value)[:limit]


def _frame_id(value):
    """帧 id 的**稳定比较口径**（字符串化；None 原样，缺帧不伪造）。

    生产帧 id 可能是 int（调度器序号）或 str（外部来源）；池内、绑定来源与
    任务帧序之间必须用同一口径比较，否则"同一帧"会被当成两帧各自保留。
    身份语义不变（只做规范化表示，不发明新 id）。
    """
    if value is None:
        return None
    return str(value)[:_MAX_FRAME_ID_CHARS]


def _finite(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


class SequenceFrame:
    """一帧真实材料（跨窗口搬运的载体；原身份 + 有界像素副本）。

    - `identity_key`：`(camera_id, run_id, config_version, frame_id)`——
      去重键，也是送入任务时构造 `L3FrameIdentity` 的依据；
    - `window_id` / `material_id` / `window_key`：**源**窗口身份
      （聚合任务身份 ≠ 源帧身份，两者都保留，不互相冒充）；
    - `t_capture_ms` / `timestamp_kind`：观察钟与时基原样；
    - `frame_bgr`：只读像素副本（构造时拷贝；可能已如实降采样，
      `width/height` 为送入模型的真实尺寸，`source_width/source_height`
      为原始证据尺寸）；
    - `material_reason` / `change_boxes` / `change_area`：来源事实
      （转折依据与账目用）。
    """

    __slots__ = ("camera_id", "run_id", "config_version", "window_id",
                 "window_key", "material_id", "frame_id", "t_capture_ms",
                 "timestamp_kind", "frame_bgr", "width", "height",
                 "source_width", "source_height", "downscaled",
                 "material_reason", "change_boxes", "change_area", "origin",
                 "event_id", "object_id", "track_id", "bound",
                 "observed_mono_ms", "crop_id", "turning_marker")

    def __init__(self, *, camera_id, run_id, config_version, window_id,
                 window_key, material_id, frame_id, t_capture_ms,
                 timestamp_kind, frame_bgr, width, height, source_width,
                 source_height, downscaled, material_reason, change_boxes,
                 change_area, origin, event_id=None, object_id=None,
                 track_id=None, bound=False, observed_mono_ms=None,
                 crop_id=None, turning_marker=None):
        self.camera_id = camera_id
        self.run_id = run_id
        self.config_version = config_version
        self.window_id = window_id
        self.window_key = tuple(window_key)
        self.material_id = material_id
        self.frame_id = frame_id
        self.t_capture_ms = t_capture_ms
        self.timestamp_kind = timestamp_kind
        self.frame_bgr = frame_bgr
        self.width = int(width)
        self.height = int(height)
        self.source_width = int(source_width)
        self.source_height = int(source_height)
        self.downscaled = bool(downscaled)
        self.material_reason = material_reason
        self.change_boxes = tuple(change_boxes or ())
        self.change_area = float(change_area or 0.0)
        self.origin = origin
        self.event_id = event_id
        self.object_id = object_id
        self.track_id = track_id
        self.bound = bool(bound)
        self.observed_mono_ms = observed_mono_ms
        self.crop_id = crop_id
        self.turning_marker = turning_marker

    # -- 身份与角色 ----------------------------------------------------------

    @property
    def identity_key(self):
        return (self.camera_id, self.run_id, self.config_version,
                self.frame_id)

    def role(self):
        """该帧在同事件跨窗序列里的角色（确定性，只由来源事实决定）。"""
        return self.role_basis()[0]

    def role_basis(self):
        """`(role, turn_basis, turn_marker)`——转折只认来源事实。

        `change_start` 是 `Monitor._select_material` 记录的“静→动边沿：变化
        开始帧最优先”，即**该事件内**一次真实状态转变 → `turning`；其余
        一律 `middle_sample` + `unknown`（“中间采样，转折覆盖未证明”）。
        """
        if not self.bound:
            return (ROLE_MIDDLE, TURN_BASIS_UNKNOWN, None)
        if self.material_reason == "change_start":
            return (ROLE_TURNING, TURN_MARKER_CHANGE_START,
                    TURN_MARKER_CHANGE_START)
        return (ROLE_MIDDLE, TURN_BASIS_UNKNOWN, None)

    # -- 可变角色（同一事件序列内由位置决定 start/latest） --------------------

    def _positional_role(self, first_id, last_id):
        if self.frame_id == first_id:
            return ROLE_START
        if self.frame_id == last_id:
            return ROLE_LATEST
        return self.role()

    def identity_record(self, role=None, positional=(None, None)):
        """可打印/可断言的帧身份（含角色、来源、时序与依据）。"""
        if role is None:
            role = self._positional_role(positional[0], positional[1])
        _role, basis, marker = self.role_basis()
        if role in (ROLE_START, ROLE_LATEST):
            basis = "sequence_anchor:{}".format(role)
            marker = None
        return {
            "frame_id": self.frame_id,
            "role": role,
            "turn_basis": basis,
            "turn_marker": marker,
            "event_id": self.event_id,
            "object_id": self.object_id,
            "track_id": self.track_id,
            "window_id": self.window_id,
            "window_key": list(self.window_key),
            "material_id": self.material_id,
            "crop_id": self.crop_id,
            "t_capture_ms": self.t_capture_ms,
            "timestamp_kind": self.timestamp_kind,
            "origin": self.origin,
            "bound": self.bound,
            "material_reason": self.material_reason,
            "downscaled": self.downscaled,
            "source_size": [self.source_width, self.source_height],
            "stored_size": [self.width, self.height],
            "change_area": self.change_area,
        }

    def as_identity_row(self, role=None, positional=(None, None)):
        """账目/证据用：**不含像素**的身份行（有界、可 JSON 化）。"""
        return self.identity_record(role=role, positional=positional)

    def to_frame_input(self, branch):
        """→ 送入任务的帧（身份=真实四元 + 真实观察钟/时基 + 只读像素）。

        stage 的 `window_matches_frame` 只校验 camera/run/config 三元——
        跨窗帧与本窗口三元相同（同事件同身份），因此结构上不可能冒充
        其它相机/运行/配置；源窗口身份另在 `window_id/material_id` 保留。
        返回 `_CarriedFrame`（`L3FrameInput` 的**透明包装**：属性/形状与
        `L3FrameInput` 一致，多带一个来源可追溯的 `turning_marker`）——
        `L3FrameInput` 是冻结形状（`__slots__`），本车道不改冻结合同。
        """
        from .win11_l3_contract import L3FrameIdentity, L3FrameInput
        image = None if self.frame_bgr is None else self.frame_bgr
        frame = L3FrameInput(
            branch=branch,
            identity=L3FrameIdentity(self.camera_id, self.run_id,
                                     self.config_version, self.frame_id),
            t_capture_ms=self.t_capture_ms,
            timestamp_kind=self.timestamp_kind,
            frame_bgr=image, enhanced=None)
        _role, _basis, marker = self.role_basis()
        return _CarriedFrame(frame, marker)


class _CarriedFrame:
    """`L3FrameInput` 的**透明包装**（跨窗帧专用；形状/属性逐项委托）。

    为什么需要包装：`L3FrameInput` 是冻结形状（`__slots__`，无转折槽位），
    而"转折必须说明来源"要求逐帧携带 `turning_marker`。包装不复制像素、
    不改身份、不改任何既有字段语义；`branch` / `identity` / `t_capture_ms`
    / `timestamp_kind` / `frame_bgr` / `enhanced` 全部透传，因此 stage 的
    身份校验、预处理与预算记账读到的都是同一份真实帧。
    """

    __slots__ = ("_frame", "turning_marker")

    def __init__(self, frame, turning_marker=None):
        self._frame = frame
        self.turning_marker = turning_marker

    def __getattr__(self, name):
        return getattr(self._frame, name)

    def __repr__(self):  # pragma: no cover - 诊断可读性
        return "<_CarriedFrame {} marker={}>".format(
            getattr(self._frame, "identity", None), self.turning_marker)


class FramePlan:
    """一次选材计划（**有界**帧序 + 角色 + 来源，供任务构造与对齐断言）。

    `status="aggregated"` 时 `frames` 是**送入任务的全序**（本窗口主序位帧 +
    同事件保留帧，去重、按时序、≤ `limit`）；`status="window_only"` 时
    `frames` 只是本窗口主序位帧（旧路径，原因在 `reason`）。
    `block_ids` 是**本窗口主序位**帧 id（旧身份口径），`frame_bindings`
    是逐帧角色表（与 `frames` 同序）。
    """

    __slots__ = ("status", "reason", "event_id", "object_id", "window_key",
                 "window_id", "carried_ids", "block_ids", "frames",
                 "frame_bindings", "turning_ids", "turn_basis",
                 "turn_coverage", "limit", "carried_total", "deduped",
                 "dropped_extra", "downscaled", "observation",
                 "event_key", "key_source")

    def __init__(self, *, status, reason, event_id=None, object_id=None,
                 window_key=(), window_id=None, carried_ids=(), block_ids=(),
                 frames=(), frame_bindings=(), turning_ids=(), turn_basis=None,
                 turn_coverage=None, limit=None, carried_total=0, deduped=0,
                 dropped_extra=0, downscaled=0, observation=None,
                 event_key=None, key_source=None):
        self.status = status
        self.reason = reason
        self.event_id = event_id
        self.object_id = object_id
        self.window_key = tuple(window_key)
        self.window_id = window_id
        self.carried_ids = tuple(carried_ids)
        self.block_ids = tuple(block_ids)
        self.frames = tuple(frames)
        self.frame_bindings = tuple(frame_bindings)
        self.turning_ids = tuple(turning_ids)
        self.turn_basis = turn_basis
        self.turn_coverage = turn_coverage
        self.limit = limit
        self.carried_total = int(carried_total)
        self.deduped = int(deduped)
        self.dropped_extra = int(dropped_extra)
        self.downscaled = int(downscaled)
        self.observation = observation
        # C155 车道 B（**加法**）：本次定位事件页用的**完整池键**与来源。
        # `key_source` ∈ {primary_event_key, primary_row_binding,
        # primary_frame_query, window_index, declared_event_id, None}。
        self.event_key = (None if event_key is None else tuple(event_key))
        self.key_source = key_source

    @property
    def aggregated(self):
        return self.status == "aggregated"

    def frame_ids(self):
        """送入任务的帧 id（与 `frames` 同序）——**对齐断言的唯一口径**。"""
        return tuple(row["frame_id"] for row in self.frame_bindings)

    def roles(self):
        return tuple(row["role"] for row in self.frame_bindings)

    def role_of(self, frame_id):
        for row in self.frame_bindings:
            if row["frame_id"] == frame_id:
                return row["role"]
        return None

    def as_ledger(self):
        """账目（不含像素；确定性键序）。"""
        return {
            "schema": EVENT_MATERIALS_SCHEMA,
            "status": self.status,
            "reason": self.reason,
            "event_id": self.event_id,
            "object_id": self.object_id,
            "event_key": (None if self.event_key is None
                          else list(self.event_key)),
            "event_key_source": self.key_source,
            "window_key": list(self.window_key),
            "window_id": self.window_id,
            "status_limit": self.limit,
            "carried_ids": list(self.carried_ids),
            "block_ids": list(self.block_ids),
            "sent_frame_ids": list(self.frame_ids()),
            "sent_roles": list(self.roles()),
            "sent_frames": [dict(row) for row in self.frame_bindings],
            "turning_ids": list(self.turning_ids),
            "turn_basis": self.turn_basis,
            "turn_coverage": self.turn_coverage,
            "carried_total": self.carried_total,
            "deduped": self.deduped,
            "dropped_extra": self.dropped_extra,
            "downscaled": self.downscaled,
            "observation": self.observation,
        }


class _EventEntry:
    """单事件池页（内部；不外传）。"""

    __slots__ = ("key", "object_id", "frames", "first_mono_ms",
                 "last_mono_ms", "observations", "downscaled", "evicted")

    def __init__(self, key, object_id, now):
        self.key = key
        self.object_id = object_id
        self.frames = []                 # list[SequenceFrame]（按观察钟升序）
        self.first_mono_ms = now
        self.last_mono_ms = now
        self.observations = 0
        self.downscaled = 0
        self.evicted = 0


class _CopyReservation:
    """一次复制的**在途预留**（复制临时内存账；C154-R1 H）。

    只有 `commit`（转为持有）与 `release`（归还）两条出口，各恰一次；
    池侧以 `reserved_temp_bytes/pixels` 与自身持有账目分开记账。预留对象
    不持有像素（复制前只有算出来的目标字节数），因此预留期本身零复制。
    """

    __slots__ = ("pixels", "bytes", "_settled")

    def __init__(self, pixels, bytes_):
        self.pixels = int(pixels)
        self.bytes = int(bytes_)
        self._settled = False

    @property
    def settled(self):
        return self._settled


class EventMaterialPool:
    """同事件跨窗口有界材料池（线程安全；零 I/O、零模型、零库写入）。

    只被生产调用方（`L2Runtime`）使用；`binding_source` 必须提供**只读**
    的 `resolve_material_binding(...)`（生产= `EventProgress`），否则本池
    一律**不聚合**（如实记 `binding_source_missing`），继续旧窗口路径。
    """

    def __init__(self, *, binding_source=None, max_events=DEFAULT_MAX_EVENTS,
                 max_frames_per_event=DEFAULT_MAX_FRAMES_PER_EVENT,
                 max_total_pixels=DEFAULT_MAX_TOTAL_PIXELS,
                 max_total_bytes=DEFAULT_MAX_TOTAL_BYTES,
                 max_frame_pixels=DEFAULT_MAX_FRAME_PIXELS,
                 max_frames_per_task=DEFAULT_MAX_FRAMES_PER_TASK,
                 mono_ms=None, frame_level_binding=False,
                 primary_frame_binding=False,
                 sealed_window_cap=DEFAULT_SEALED_WINDOW_CAP):
        if min(int(max_events), int(max_frames_per_event),
               int(max_total_pixels), int(max_total_bytes),
               int(max_frame_pixels), int(max_frames_per_task)) < 1:
            raise ValueError("positive bounded limits required")
        self.binding_source = binding_source
        self.max_events = int(max_events)
        self.max_frames_per_event = int(max_frames_per_event)
        self.max_total_pixels = int(max_total_pixels)
        self.max_total_bytes = int(max_total_bytes)
        self.max_frame_pixels = int(max_frame_pixels)
        self.max_frames_per_task = int(max_frames_per_task)
        # ---- C155 车道 B：两个**默认关**的显式开关（共享构造保持兼容） ------
        # 生产由主会话在构建点显式开启；只实现旧接口的替身行为逐字不变。
        # 读的是实例属性（调用时读取），因此接线点可以只置位、无需重建池。
        self.frame_level_binding = bool(frame_level_binding)
        self.primary_frame_binding = bool(primary_frame_binding)
        self.sealed_window_cap = max(1, int(sealed_window_cap))
        self._clock = mono_ms or (lambda: time.monotonic() * 1000.0)
        self._lock = threading.Lock()
        self._events = {}                # event_key -> _EventEntry
        self._window_events = {}         # window_key -> (event_id, object_id)
        self._counts = {
            "observe_calls": 0,
            "frames_considered": 0,
            "frames_retained": 0,
            "frames_duplicate": 0,
            "frames_downscaled": 0,
            "frames_evicted": 0,
            "events_created": 0,
            "events_evicted": 0,
            "aggregated_windows": 0,
            "window_only_windows": 0,
            # C154-R1 H：逐帧拒绝/复制失败/预留结算异常（两本账可查）
            "frames_refused": 0,
            "frames_copy_failed": 0,
            "reservation_release_after_settle": 0,
            "reservation_accounting_anomaly": 0,
            "close_calls": 0,
            # C154-R1 J：有序关闭各步的可查计数（历史计数不因关闭清零）
            "close_begin_calls": 0,        # close_begin/close 调用次数（含重复）
            "close_await_calls": 0,        # await_reservations 调用次数
            "close_await_timeouts": 0,     # 其中有界等待超时（未全部归还）次数
            "close_release_calls": 0,      # release_pixels 调用次数
            "close_release_refusals": 0,   # 其中被拒（不释放、不强清）次数
            "close_reports": 0,            # close_report 调用次数
            "frames_pixels_released": 0,   # 累计释放像素的帧数（历史，不清零）
            # ---- C155 车道 B：逐帧准入与主帧事件键（**新增计数**，与旧计数
            # 分列——历史臂的整包口径计数**不可**与本组直接横比） ----------
            "frame_level_windows": 0,          # 走逐帧准入的 observe 次数
            "frame_level_window_only": 0,      # 其中零保留（逐帧账目拒绝）
            "frame_level_admitted_windows": 0,  # 其中 ≥1 保留帧
            "frames_admitted": 0,              # 逐帧判为 bound 并保留的帧数
            "frames_unattributed": 0,          # 明确未归属（context）的帧数
            "frames_ambiguous_or_rejected": 0,  # 歧义/被拒的帧数
            "frame_level_conflicts": 0,        # 跨事件/跨对象拒绝聚合次数
            "frame_level_source_errors": 0,    # 逐帧来源异常/形状不符次数
            "plan_frame_binding_queries": 0,   # 主帧自身绑定查询次数（plan 侧）
            "plan_frame_binding_resolved": 0,  # 其中成功定位事件页
            "plan_frame_binding_refused": 0,   # 其中未绑定/被拒（走旧路径）
            "plan_event_key_conflicts": 0,     # 显式键与窗口索引指向不同页
            "plan_sealed_windows": 0,          # 已封口窗口的计划（不再搬运）
            "window_sealed": 0,                # forget_window 实际封口次数
        }
        self._refusals = {}
        self._last_refusal = None
        self._evictions = []
        # ---- C155 车道 B：逐帧账目（**与整包账目分列**，互不覆盖） ----------
        self._frame_level_refusals = {}     # 逐帧路径的窗口级拒绝（主导原因）
        self._last_frame_level_refusal = None
        self._frame_classifications = {name: 0 for name in sorted(FRAME_CLASSES)}
        self._frame_level_reasons = {}      # 逐帧原因码计数（含 context/rejected）
        self._multi_object_gate = {
            MULTI_OBJECT_GATE_REFS: 0,       # 闸门由来源 `refs` 判定
            MULTI_OBJECT_GATE_DECLARED: 0,   # 闸门由声明对象集合判定（缺 refs）
            MULTI_OBJECT_GATE_NONE: 0,       # 无任何对象证据（如实记账）
        }
        self._last_multi_object_gate = None
        self._sealed_windows = {}            # window_key -> True（有界 LRU）
        # ---- 复制前预算与两本账（C154-R1 H） --------------------------------
        # held_*：已入池帧的**持有内存**；reserved_temp_*：复制在途的
        # **临时内存**（预留）。两者分别记账、分别可查，绝不相混。
        self._held_pixels = 0
        self._held_bytes = 0
        self._reserved_temp_pixels = 0
        self._reserved_temp_bytes = 0
        self._copies = 0                      # 实际像素复制次数（copy_count）
        self._copy_reservations = 0
        self._copy_reservations_committed = 0
        self._copy_reservations_released = 0
        self._copy_failures = 0
        self._frame_refusals = {}
        self._last_frame_refusal = None
        # ---- 生命周期（关闭后新副本不入池；账目不清零） ---------------------
        self._closed = False
        self._close_reason = None
        # ---- 有序关闭（C154-R1 J） ------------------------------------------
        self._live_reservations = 0           # 在途预留**条数**（账目之外的计数）
        self._close_begin_mono_ms = None      # 步骤 1 时刻（观察钟）
        self._pixel_release = None            # 步骤 4 冻结的有界摘要（无像素）
        self._close_release_refusal = None    # 步骤 4 最近一次受控拒绝原因
        self._dependencies_attested = None    # 调用方对"无依赖"的声明（如实记录）

    # -- 只读查询 ------------------------------------------------------------

    def _held_totals_locked(self):
        """按帧**重算**的持有总量（策略判定用；避免任何账本漂移影响预算）。

        只计**仍持像素**的帧（`frame_bgr is None` = 步骤 4 已释放像素，身份行
        照旧保留但不再算持有）——因此"释放像素"后重算值归零，与账面减记
        同步，不会把已释放的字节当成仍持有。
        """
        pixels = 0
        total_bytes = 0
        for entry in self._events.values():
            for frame in entry.frames:
                if frame.frame_bgr is None:
                    continue
                pixels += int(frame.width) * int(frame.height)
                total_bytes += int(frame.frame_bgr.nbytes)
        return (pixels, total_bytes)

    def _accounting_locked(self):
        """两本账 + 复制计数（调用方持锁）：持有与临时分别给出，漂移可查。"""
        pixels, total_bytes = self._held_totals_locked()
        return {
            "limits": {
                "max_total_pixels": self.max_total_pixels,
                "max_total_bytes": self.max_total_bytes,
                "max_frame_pixels": self.max_frame_pixels,
            },
            "held_frames": sum(len(entry.frames)
                               for entry in self._events.values()),
            "held_pixel_frames": sum(1 for entry in self._events.values()
                                     for frame in entry.frames
                                     if frame.frame_bgr is not None),
            "held_pixels": pixels,
            "held_bytes": total_bytes,
            "held_pixels_book": self._held_pixels,
            "held_bytes_book": self._held_bytes,
            "drift_pixels": self._held_pixels - pixels,
            "drift_bytes": self._held_bytes - total_bytes,
            "reserved_temp_pixels": self._reserved_temp_pixels,
            "reserved_temp_bytes": self._reserved_temp_bytes,
            "reservations_outstanding": self._live_reservations,
            "pixels_released": bool(self._pixel_release is not None),
            "copy_count": self._copies,
            "copy_reservations": self._copy_reservations,
            "copy_reservations_committed": self._copy_reservations_committed,
            "copy_reservations_released": self._copy_reservations_released,
            "reservation_release_after_settle": self._counts.get(
                "reservation_release_after_settle", 0),
            "reservation_accounting_anomaly": self._counts.get(
                "reservation_accounting_anomaly", 0),
            "copy_failures": self._copy_failures,
            "closed": self._closed,
            "close_reason": self._close_reason,
        }

    def accounting(self):
        """复制/容量账目（只读）：**持有内存**与**复制临时内存**分开可查。"""
        with self._lock:
            return self._accounting_locked()

    @property
    def closed(self):
        """池是否已关闭（关闭后 `observe()`/`plan_frames()` 一律拒绝）。"""
        with self._lock:
            return self._closed

    def close(self, *, reason=None):
        """**步骤 1 的兼容别名**（= `close_begin()`）：只封准入，不做后续步骤。

        保留旧调用点语义：幂等、只置状态、只记原因，**不清零**任何账目。
        完整有序收尾必须显式走 `await_reservations()` → `release_pixels()`
        （否则像素仍被池持有，`close_report()["complete"]` 为 False）。
        """
        return self.close_begin(reason=reason)

    def close_begin(self, *, reason=None):
        """**步骤 1：立即封闭准入**（不等任何消费线程 join、不释放像素）。

        只做三件事：置 `closed`、记受控原因与时刻（观察钟）、计数。此后
        `observe()` / `plan_frames()` 一律按 `pool_closed` 拒绝；在途复制的
        提交段发现关闭即归还预留、帧不入池。幂等：重复调用返回 False
        （`close_begin_calls` 仍逐次可查，历史账目一律不动）。
        """
        with self._lock:
            self._counts["close_begin_calls"] += 1
            if self._closed:
                return False
            self._closed = True
            self._close_reason = _text(reason, 64) or "closed"
            self._close_begin_mono_ms = float(self._clock())
            self._counts["close_calls"] += 1
            return True

    def _reservations_settled_locked(self):
        """是否已无在途复制预留（调用方持锁）：条数与两本临时账**都**归零。"""
        return (self._live_reservations <= 0
                and self._reserved_temp_pixels <= 0
                and self._reserved_temp_bytes <= 0)

    def await_reservations(self, timeout_s=DEFAULT_CLOSE_TIMEOUT_S):
        """**步骤 3：锁外**有界等待在途复制预留归还；返回是否**全部**归还。

        只在"是否仍有在途预留"的判定瞬间持池锁；等待期间**绝不持锁**——
        复制线程因此可以继续拿锁完成提交/归还（这正是本方法要证明的性质，
        持锁等待会被并发复制用例直接暴露）。超时返回 False 并**保留真实
        在途账目**：不伪造归还、不清零、不改任何持有账目。

        返回 True 的**语义强度**：由于"关闭检查 + 预留"在同一次持锁内完成
        （`_store_row`），`close_begin()` 之后不可能新增预留；提交段又在同一
        把锁下复查关闭。因此"全部归还"= 不会再有任何复制把像素送入池，
        这正是步骤 4 释放像素所依赖的证据。
        """
        try:
            budget = float(timeout_s)
        except (TypeError, ValueError):
            budget = 0.0
        if not math.isfinite(budget) or budget < 0.0:
            budget = 0.0
        deadline = time.monotonic() + budget
        with self._lock:
            self._counts["close_await_calls"] += 1
            if self._reservations_settled_locked():
                return True
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                break
            time.sleep(min(0.002, remaining))
            with self._lock:
                if self._reservations_settled_locked():
                    return True
        with self._lock:
            if self._reservations_settled_locked():
                return True
            self._counts["close_await_timeouts"] += 1
            return False

    def release_pixels(self, *, dependencies_done=None):
        """**步骤 4：解除像素持有**（仅在确认无依赖后）；返回是否已无像素持有。

        释放条件（**全部**满足才动手，否则拒绝且**不强清引用**）：

        1. 准入已封（`close_begin()` 已调用）——否则 `close_not_begun`；
        2. 无在途复制预留（条数与临时账归零）——否则
           `close_reservations_outstanding`（真实在途账目原样保留）；
        3. `dependencies_done is not False`——调用方若声明"仍有任务依赖池内
           像素"，一律不释放（`close_dependencies_pending`）。调用方的声明
           只作**否决**用、如实记入报告，**不能**覆盖池自身的预留证据。

        允许时逐帧释放已入池像素（`frame_bgr=None`，账目只减该帧实际持有），
        并把**有界、无像素**的身份/计数摘要冻结进 `pixel_release`
        （`close_report()["pixel_release"]` 可查；身份行上限 =
        `max_events × max_frames_per_event`，超出置 `truncated`）。幂等：
        已释放后重复调用返回 True，不重复记账（`calls` 如实自增）。
        """
        with self._lock:
            self._counts["close_release_calls"] += 1
            blocker = None
            if not self._closed:
                blocker = CLOSE_NOT_BEGUN
            elif not self._reservations_settled_locked():
                blocker = CLOSE_RESERVATIONS_OUTSTANDING
            elif dependencies_done is False:
                blocker = CLOSE_DEPENDENCIES_PENDING
            if blocker is not None:
                self._counts["close_release_refusals"] += 1
                self._close_release_refusal = blocker
                if dependencies_done is False:
                    self._dependencies_attested = False
                return False
            self._dependencies_attested = (None if dependencies_done is None
                                           else True)
            self._close_release_refusal = None
            now = float(self._clock())
            cap = max(1, int(self.max_events) * int(self.max_frames_per_event))
            released_frames = 0
            released_pixels = 0
            released_bytes = 0
            rows = []
            truncated = False
            for entry in self._events.values():
                first_id = entry.frames[0].frame_id if entry.frames else None
                last_id = entry.frames[-1].frame_id if entry.frames else None
                for frame in entry.frames:
                    if frame.frame_bgr is None:
                        continue
                    released_frames += 1
                    released_pixels += int(frame.width) * int(frame.height)
                    released_bytes += int(frame.frame_bgr.nbytes)
                    if len(rows) < cap:
                        rows.append(frame.as_identity_row(
                            positional=(first_id, last_id)))
                    else:
                        truncated = True          # 摘要**有界**：超出即如实标记
                    # 账目只减该帧**实际持有**，再把像素引用置空：
                    # 释放引用与释放资源是两件事，两者都做且只做一次。
                    self._drop_frame_accounting_locked(frame)
                    frame.frame_bgr = None
            self._counts["frames_pixels_released"] += released_frames
            summary = self._pixel_release
            if summary is None:
                summary = {
                    "schema": EVENT_MATERIALS_SCHEMA,
                    "calls": 0, "frames": 0, "pixels": 0, "bytes": 0,
                    "first_mono_ms": now, "last_mono_ms": now,
                    "truncated": False, "identities": [],
                }
                self._pixel_release = summary
            summary["calls"] += 1
            summary["frames"] += released_frames
            summary["pixels"] += released_pixels
            summary["bytes"] += released_bytes
            summary["last_mono_ms"] = now
            for row in rows:
                if len(summary["identities"]) >= cap:
                    truncated = True
                    break
                summary["identities"].append(dict(row))
            if truncated:
                summary["truncated"] = True
            return True

    def close_report(self):
        """**步骤 5：收尾报告**（真实值；绝不把未完成说成完成）。

        字段见模块头 §6；`complete` 只由**可验证状态**推出：准入已封 +
        无在途预留 + 当前零像素/零字节 + 零漂移。历史保留/释放/拒绝计数
        一律**不因关闭清零**（`history` 逐项可查）。
        """
        with self._lock:
            self._counts["close_reports"] += 1
            pixels, total_bytes = self._held_totals_locked()
            drift_pixels = self._held_pixels - pixels
            drift_bytes = self._held_bytes - total_bytes
            held_frames = sum(len(entry.frames)
                              for entry in self._events.values())
            held_pixel_frames = sum(1 for entry in self._events.values()
                                    for frame in entry.frames
                                    if frame.frame_bgr is not None)
            settled = self._reservations_settled_locked()
            if not self._closed:
                reason = CLOSE_NOT_BEGUN
            elif not settled:
                reason = CLOSE_RESERVATIONS_OUTSTANDING
            elif pixels or total_bytes or drift_pixels or drift_bytes:
                reason = CLOSE_PIXELS_STILL_HELD
            else:
                reason = None
            summary = self._pixel_release
            return {
                "schema": EVENT_MATERIALS_SCHEMA,
                "closed": self._closed,
                "complete": reason is None,
                "incomplete_reason": reason,
                "close_reason": self._close_reason,
                "close_begin_mono_ms": self._close_begin_mono_ms,
                "held_frames": held_frames,
                "held_pixel_frames": held_pixel_frames,
                "held_pixels": pixels,
                "held_bytes": total_bytes,
                "held_pixels_book": self._held_pixels,
                "held_bytes_book": self._held_bytes,
                "drift_pixels": drift_pixels,
                "drift_bytes": drift_bytes,
                "reserved_temp_pixels": self._reserved_temp_pixels,
                "reserved_temp_bytes": self._reserved_temp_bytes,
                "reservations_outstanding": self._live_reservations,
                "reservations_settled": settled,
                "reservations_total": self._copy_reservations,
                "reservations_committed": self._copy_reservations_committed,
                "reservations_released": self._copy_reservations_released,
                "dependencies_attested": self._dependencies_attested,
                "pixel_release_refusal": self._close_release_refusal,
                "pixel_release": (None if summary is None else {
                    "schema": summary["schema"],
                    "calls": summary["calls"],
                    "frames": summary["frames"],
                    "pixels": summary["pixels"],
                    "bytes": summary["bytes"],
                    "first_mono_ms": summary["first_mono_ms"],
                    "last_mono_ms": summary["last_mono_ms"],
                    "truncated": summary["truncated"],
                    "identities": [dict(row) for row in summary["identities"]],
                }),
                "history": {
                    "counts": dict(self._counts),
                    "refusals": dict(self._refusals),
                    # C155 B：逐帧口径的拒绝**另列**（不混入整包 `refusals`）
                    "frame_level_refusals": dict(self._frame_level_refusals),
                    "frame_classifications": dict(self._frame_classifications),
                    "mode": self.admission_mode(),
                    "last_refusal": (None if self._last_refusal is None
                                     else dict(self._last_refusal)),
                    "frame_refusals": dict(self._frame_refusals),
                    "last_frame_refusal": (None if self._last_frame_refusal is
                                           None
                                           else dict(self._last_frame_refusal)),
                    "events_retained": len(self._events),
                    "window_index_size": len(self._window_events),
                    "recent_evictions": [dict(row) for row in self._evictions],
                },
            }

    def snapshot(self):
        """账目快照（深拷贝；有界：逐事件只给身份行，不给像素）。"""
        with self._lock:
            events = []
            for entry in sorted(self._events.values(),
                                key=lambda e: (-e.last_mono_ms,
                                               tuple(str(p) for p in e.key))):
                first_id = entry.frames[0].frame_id if entry.frames else None
                last_id = entry.frames[-1].frame_id if entry.frames else None
                events.append({
                    "event_id": entry.key[_EVENT_ID_SLOT],
                    "object_id": entry.object_id,
                    "camera_id": entry.key[0],
                    "run_id": entry.key[1],
                    "config_version": entry.key[2],
                    "frames": [f.as_identity_row(positional=(first_id,
                                                             last_id))
                               for f in entry.frames],
                    "observations": entry.observations,
                    "downscaled": entry.downscaled,
                    "evicted": entry.evicted,
                })
            return {
                "schema": EVENT_MATERIALS_SCHEMA,
                "limits": {
                    "max_events": self.max_events,
                    "max_frames_per_event": self.max_frames_per_event,
                    "max_total_pixels": self.max_total_pixels,
                    "max_total_bytes": self.max_total_bytes,
                    "max_frame_pixels": self.max_frame_pixels,
                    "max_frames_per_task": self.max_frames_per_task,
                },
                "binding_source": type(self.binding_source).__name__
                if self.binding_source is not None else None,
                "events_held": len(self._events),
                "events": events,
                "counts": dict(self._counts),
                "refusals": dict(self._refusals),
                "last_refusal": (None if self._last_refusal is None
                                 else dict(self._last_refusal)),
                "recent_evictions": [dict(row) for row in self._evictions],
                # C154-R1 H：两本账（持有 / 复制临时）+ 复制计数 + 漂移
                "accounting": self._accounting_locked(),
                "frame_refusals": dict(self._frame_refusals),
                "last_frame_refusal": (None if self._last_frame_refusal is None
                                       else dict(self._last_frame_refusal)),
                # ---- C155 车道 B：**加法**块（旧键含义一律不变） ------------
                # 逐帧准入与整包准入的账目**分列**：`refusals` 仍是整包口径
                # （其逐帧路径条目另见 `frame_level_refusals`），历史臂计数
                # **不可**与这些新计数直接横比。
                "mode": self.admission_mode(),
                "admission": {
                    "frame_level_binding": self.frame_level_binding,
                    "primary_frame_binding": self.primary_frame_binding,
                    "source_supports_frame_bindings": (
                        self.source_supports_frame_bindings()),
                    "active_mode": self.admission_mode(),
                    "classifications": dict(self._frame_classifications),
                    "reasons": dict(self._frame_level_reasons),
                    "refusals": dict(self._frame_level_refusals),
                    "last_refusal": (None if self._last_frame_level_refusal
                                     is None
                                     else dict(self._last_frame_level_refusal)),
                },
                "multi_object_gate": {
                    "counts": dict(self._multi_object_gate),
                    "last": (None if self._last_multi_object_gate is None
                             else dict(self._last_multi_object_gate)),
                },
            }

    def window_event_id(self, window_key):
        """该窗口已核验的事件键（未登记/无绑定 → None；只读）。"""
        with self._lock:
            row = self._window_events.get(tuple(window_key))
            return None if row is None else row[1]

    def retained_frames(self, event_id, object_id=None, identity=None):
        """某事件当前保留的帧（身份行，按时序；有界）。

        `identity=(camera, run, config)` 时**只**认该身份下的事件页（防跨身份
        同名 id 串绑）；缺省 `None` 保持"只按事件/对象 id 查"的旧口径。
        """
        with self._lock:
            entry = self._entry_for(event_id, object_id, identity=identity)
            if entry is None:
                return ()
            first_id = entry.frames[0].frame_id if entry.frames else None
            last_id = entry.frames[-1].frame_id if entry.frames else None
            return tuple(f.as_identity_row(positional=(first_id, last_id))
                         for f in entry.frames)

    def _entry_for(self, event_id, object_id=None, identity=None):
        """按事件身份找事件页。

        `identity=(camera, run, config)` 必须与事件页键的前三段全等——同一
        `(event_id, object_id)` 出现在不同身份时**绝不**互相借材料（跨
        camera/run/config 串绑在查找层即不可能）。缺省 `None`＝旧口径
        （只按事件/对象 id，用于不带身份的只读查询）。
        """
        wanted = None if identity is None else tuple(identity)[:3]
        for entry in self._events.values():
            if wanted is not None and tuple(entry.key[:3]) != wanted:
                continue
            if entry.key[_EVENT_ID_SLOT] != event_id:
                continue
            if object_id is not None and entry.object_id != object_id:
                continue
            return entry
        return None

    # -- C155 车道 B：模式、能力探测与逐帧账目（只读判定） --------------------

    def admission_mode(self):
        """当前准入模式（只读）：`per_frame` 需**开关打开 + 能力探测通过**。

        `frame_level_binding` 打开但来源没实现 `resolve_frame_bindings` 时，
        如实回 `package`（绝不假装逐帧、也不静默失败）。
        """
        return (MODE_PER_FRAME
                if self.frame_level_binding
                and hasattr(self.binding_source, "resolve_frame_bindings")
                else MODE_PACKAGE)

    def source_supports_frame_bindings(self):
        """绑定来源是否提供逐帧只读接口（能力探测；只读、无副作用）。"""
        return hasattr(self.binding_source, "resolve_frame_bindings")

    def event_key_for_frame(self, camera_id, run_id, config_version, frame_id):
        """该帧在池内**已核验**的完整事件键（只读；未保留 → None）。

        只回答"这一帧自己当初以哪个事件键入池"，供生产接线取显式主帧事件键；
        不做任何推断（不取最新、不取多数、不跨身份）。
        """
        wanted = (camera_id, run_id, config_version, _frame_id(frame_id))
        if wanted[3] is None:
            return None
        with self._lock:
            for entry in self._events.values():
                if tuple(entry.key[:3]) != tuple(wanted[:3]):
                    continue
                for frame in entry.frames:
                    if frame.frame_id == wanted[3]:
                        return tuple(entry.key)
        return None

    def _frame_level_reason_locked(self, classification, reason):
        """逐帧原因记账（分类计数 + 原因计数；调用方持锁）。"""
        name = (classification if classification in FRAME_CLASSES
                else FRAME_CLASS_REJECTED)
        self._frame_classifications[name] = (
            self._frame_classifications.get(name, 0) + 1)
        text = _text(reason, 64)
        if text:
            self._frame_level_reasons[text] = (
                self._frame_level_reasons.get(text, 0) + 1)

    def _refuse_frame_level(self, reason, record):
        """逐帧路径的**窗口级**拒绝（与旧整包账目**分列**，互不覆盖）。"""
        reason = _text(reason, 64) or "frame_binding_missing"
        with self._lock:
            self._frame_level_refusals[reason] = (
                self._frame_level_refusals.get(reason, 0) + 1)
            self._counts["frame_level_window_only"] += 1
            self._counts["window_only_windows"] += 1
            self._last_frame_level_refusal = {
                "reason": reason,
                "mode": MODE_PER_FRAME,
                "window_key": list(record.get("window_key") or ()),
                "window_id": record.get("window_id"),
                "unattributed": [dict(row) for row
                                 in (record.get("unattributed") or ())],
            }
            self._last_refusal = {
                "reason": reason,
                "mode": MODE_PER_FRAME,
                "window_key": list(record.get("window_key") or ()),
                "window_id": record.get("window_id"),
                "camera_id": (record.get("window_key") or [None])[0],
            }
        return record

    # -- 写入（有界） --------------------------------------------------------

    def observe(self, *, camera_id, run_id, config_version, window_key,
                window_id, material_id, frames, object_ids=(),
                frame_time_kind=None, turning_marker=None,
                material_reason=None, l1_terminal_reason=None,
                detection_count=None, harvest_id=None):
        """把一个窗口的材料观测并入事件池；返回 `(record)`。

        `frames`：可迭代项，每项含
        `{frame_id, frame_bgr, t_capture_ms, timestamp_kind}`（源帧身份+像素）。
        绑定解析委托 `binding_source.resolve_material_binding(...)`：只有
        **唯一**事件 + **单**对象时才聚合；否则 `status="window_only"` 并记录
        原因（继续旧窗口路径，不猜）。

        F3（只加诊断，零判定改动）：`l1_terminal_reason` / `detection_count`
        / `harvest_id` 只用于**无对象**原因的细分（`object_ids_state` /
        `object_ids_reason`）。既有 `reason` / `refusals[...]` 逐字不变，
        准入判据仍完全由绑定来源给出。
        """
        object_ids_tuple = tuple(object_ids or ())
        object_state, object_reason = _missing_object_diagnostic(
            object_ids_present=bool(object_ids_tuple),
            detection_count=detection_count,
            l1_terminal_reason=l1_terminal_reason)
        mode = self.admission_mode()
        record = {
            "status": "window_only",
            "reason": None,
            "event_id": None,
            "object_id": None,
            "track_id": None,
            "window_key": list(tuple(window_key)),
            "window_id": window_id,
            "harvest_id": harvest_id,
            "resolved": None,
            "retained": 0,
            "retained_ids": [],
            "duplicate": 0,
            "downscaled": 0,
            "evicted": 0,
            # C154-R1 H：逐帧拒绝（受控原因码）如实带入记录，便于账目对齐
            "refused": 0,
            "refused_reasons": {},
            # F3（C154 Q）：无对象原因细分（诊断；判定不读这些字段）
            "object_ids_state": object_state,
            "object_ids_reason": object_reason,
            "object_ids_count": len(object_ids_tuple),
            "detection_count": (None if detection_count is None
                                else int(detection_count)),
            "l1_terminal_reason": _text(l1_terminal_reason, 64),
            # ---- C155 车道 B：**加法**字段（旧键含义一律不变） --------------
            "mode": mode,                    # package | per_frame（本次实际口径）
            "unattributed": [],              # 未归属帧（帧 id + 受控原因），零像素
            "admission": None,               # 逐帧准入明细（三分类 + 事件/对象键）
            "multi_object_gate": None,       # 二次闸门的证据模式（refs/declared/none）
            "event_key": None,               # 已核验的完整池键（5 元组）
        }
        key = (camera_id, run_id, config_version)
        window_key = tuple(window_key)
        frame_rows = []
        for row in tuple(frames or ()):
            if not isinstance(row, dict):
                continue
            frame_rows.append(row)
        with self._lock:
            self._counts["observe_calls"] += 1
            self._counts["frames_considered"] += len(frame_rows)
            closed = self._closed
        if closed:
            # 关闭后**不**进新副本（也不先解析绑定/不复制整帧）
            record["reason"] = REFUSE_POOL_CLOSED
            if mode == MODE_PER_FRAME:
                self._refuse_frame_level(record["reason"], record)
                return record
            self._refuse(record["reason"], record)
            return record
        if not frame_rows:
            record["reason"] = "no_frames"
            if mode == MODE_PER_FRAME:
                self._refuse_frame_level(record["reason"], record)
                return record
            self._refuse(record["reason"], record)
            return record
        if mode == MODE_PER_FRAME:
            return self._observe_frame_level(
                record=record, camera_id=camera_id, run_id=run_id,
                config_version=config_version, window_key=window_key,
                window_id=window_id, material_id=material_id,
                frame_rows=frame_rows, object_ids=object_ids,
                declared=_declared_objects(object_ids),
                frame_time_kind=frame_time_kind, turning_marker=turning_marker,
                material_reason=material_reason)
        # ---- 绑定解析（只读事实链快照；缺来源即不聚合） ----
        resolved = self._resolve_binding(
            camera_id=camera_id, run_id=run_id, config_version=config_version,
            frames=frame_rows, object_ids=object_ids,
            frame_time_kind=frame_time_kind)
        record["resolved"] = dict(resolved)
        if resolved.get("status") != "unique":
            record["reason"] = str(resolved.get("reason") or "unbound")
            self._refuse(record["reason"], record)
            return record
        binding = dict(resolved["binding"])
        if _binding_identity_mismatch(binding, camera_id, run_id,
                                      config_version):
            # 绑定来源给出的事件身份与本次观察身份不符：不得按"同名 id"
            # 搬运（防跨 camera/run/config 串绑）。生产来源自带该校验
            # （`EventProgress.resolve_material_binding` → identity_mismatch），
            # 这里是池边界的兜底核对。
            record["reason"] = REFUSE_BINDING_IDENTITY_MISMATCH
            self._refuse(record["reason"], record)
            return record
        record["event_id"] = binding.get("event_id")
        record["object_id"] = binding.get("object_id")
        record["track_id"] = binding.get("track_id")
        binding_keys = {_frame_id(frame.get("frame_id"))
                        for frame in (resolved.get("frames") or ())}
        bound_rows = [row for row in frame_rows
                      if _frame_id(row.get("frame_id")) in binding_keys]
        if not bound_rows:
            record["reason"] = "frame_binding_missing"
            self._refuse(record["reason"], record)
            return record
        # 事实链给出的**帧内对象集合**（来源事实）：不止一个对象时不得把
        # 场景级叙事无条件归给单个对象 → 拒绝汇聚并如实记原因。
        #
        # C155 车道 B（先证后修）：生产 `resolve_material_binding` 返回的帧行是
        # `{frame_id, t_ms, time_kind}`（**不含 `refs`**）⇒ 下面这个闸门在生产
        # 路径上**长期惰性**（负例已先复现：声明 2 个对象仍被判 `unique` 汇聚）。
        # 因此缺 `refs` 时改用**调用方声明的对象集合**这一可得证据判定：
        # 声明集合里有 >1 个对象 → `multi_object`（零复制、零建页）。闸门
        # **绝不静默跳过**，其证据模式如实记入 `multi_object_gate`。
        refs_missing = False
        for frame in tuple(resolved.get("frames") or ()):
            refs = frame.get("refs")
            if isinstance(refs, (list, tuple, set, frozenset)):
                if len(set(refs)) > 1:
                    record["reason"] = "multi_object"
                    self._note_multi_object_gate(
                        MULTI_OBJECT_GATE_REFS, record)
                    self._refuse(record["reason"], record)
                    return record
            else:
                refs_missing = True
        gate = MULTI_OBJECT_GATE_NONE if not object_ids_tuple else (
            MULTI_OBJECT_GATE_DECLARED if refs_missing
            else MULTI_OBJECT_GATE_REFS)
        if gate == MULTI_OBJECT_GATE_DECLARED \
                and len(set(object_ids_tuple)) > 1:
            record["reason"] = "multi_object"
            self._note_multi_object_gate(MULTI_OBJECT_GATE_DECLARED, record)
            self._refuse(record["reason"], record)
            return record
        self._note_multi_object_gate(gate, record)
        event_key = (camera_id, run_id, config_version,
                     _text(binding.get("event_id")),
                     _text(binding.get("object_id")))
        record["event_key"] = list(event_key)      # C155 B：加法键（可追溯池键）
        now = float(self._clock())
        with self._lock:
            entry = self._events.get(event_key)
            if entry is None:
                entry = _EventEntry(event_key, binding.get("object_id"), now)
                self._events[event_key] = entry
                self._counts["events_created"] += 1
                self._evict_events_locked()
            entry.observations += 1
            entry.last_mono_ms = now
            self._window_events[window_key] = (event_key,
                                              _text(binding.get("event_id")),
                                              _text(binding.get("object_id")),
                                              now)
        # 逐帧入池：**先校验、先淘汰或拒绝、再预留**，复制在锁外恰一次；
        # 提交阶段若发现关闭/事件页已被淘汰，在途预留归还、帧不入池。
        for row in bound_rows:
            stored, reason = self._store_row(
                entry, row, binding=binding, window_key=window_key,
                window_id=window_id, material_id=material_id,
                camera_id=camera_id, run_id=run_id,
                config_version=config_version,
                material_reason=material_reason,
                turning_marker=turning_marker, now=now)
            if stored == "duplicate":
                record["duplicate"] += 1
            elif stored == "downscaled":
                record["downscaled"] += 1
            elif stored == "stored":
                pass
            elif stored in ("refused", "copy_failed"):
                record["refused"] += 1
                if reason:
                    record["refused_reasons"][reason] = (
                        record["refused_reasons"].get(reason, 0) + 1)
        with self._lock:
            closed_now = self._closed
            live = self._events.get(event_key)
            holder = live if live is not None else None
            if holder is None:
                # 事件页已被并发淘汰（各自独立终态）：不得虚报保留帧
                record["retained"] = 0
                record["retained_ids"] = []
                record["retained_roles"] = []
                record["evicted"] = entry.evicted
            else:
                first_id = (holder.frames[0].frame_id if holder.frames
                            else None)
                last_id = (holder.frames[-1].frame_id if holder.frames
                           else None)
                record["retained"] = len(holder.frames)
                record["retained_ids"] = [f.frame_id for f in holder.frames]
                record["evicted"] = holder.evicted
                record["retained_roles"] = [
                    f._positional_role(first_id, last_id)
                    for f in holder.frames]
        if closed_now:
            # 关闭落在本次观察途中：帧级拒绝已计入 `refused`，窗口按旧路径
            # 如实收口（不重复计窗口级拒绝）。
            record["status"] = "window_only"
            record["reason"] = REFUSE_POOL_CLOSED
            return record
        record["status"] = "aggregated_allowed"
        return record

    # -- C155 车道 B：逐帧准入（与旧整包分支**并存**；上面那条分支逐字未动） --

    def _note_multi_object_gate(self, mode, record):
        """如实记录二次闸门本次的**证据模式**（诊断；不参与判定）。"""
        if mode not in self._multi_object_gate:
            mode = MULTI_OBJECT_GATE_NONE
        with self._lock:
            self._multi_object_gate[mode] = (
                self._multi_object_gate.get(mode, 0) + 1)
            self._last_multi_object_gate = {
                "mode": mode,
                "window_key": list(record.get("window_key") or ()),
                "window_id": record.get("window_id"),
                "reason": record.get("reason"),
            }
        record["multi_object_gate"] = mode

    def _source_accepts_primary_frame_id(self, source):
        """只读能力探测：绑定源是否接受 `primary_frame_id`（结果缓存）。

        旧替身/旧实现不含该参数 ⇒ 保持旧实参调用（行为不变，不误判绑定失败）。
        """
        key = id(source)
        cached = getattr(self, "_primary_param_probe", None)
        if cached is not None and cached[0] == key:
            return cached[1]
        import inspect as _inspect
        try:
            params = _inspect.signature(
                source.resolve_frame_bindings).parameters
            ok = ("primary_frame_id" in params
                  or any(p.kind is _inspect.Parameter.VAR_KEYWORD
                         for p in params.values()))
        except Exception:
            ok = False
        self._primary_param_probe = (key, ok)
        return ok

    def _resolve_frame_bindings(self, *, camera_id, run_id, config_version,
                                frames, frame_time_kind,
                                primary_frame_id=None):
        """逐帧只读查询（能力探测 + 受控失败；**绝不**放行到"看起来还行"）。

        返回 `(result, failure)`：`failure` 非 None 表示整次查询不可用
        （缺接口 / 异常 / 形状不符），调用方按保守拒绝处理，**不新增绑定真相**。
        """
        source = self.binding_source
        if source is None or not hasattr(source, "resolve_frame_bindings"):
            return (None, "binding_source_bad_shape")
        try:
            _kw = {"camera_id": camera_id, "run_id": run_id,
                   "config_version": config_version, "frames": frames,
                   "frame_time_kind": frame_time_kind}
            # P0-3(a)：主帧 id 必须**原样**到达解析器（计划级）；观察分类调用
            # 保持缺省（合法 0）。**防御式**：旧替身签名不含该参数时退回旧实参，
            # 避免把"源不支持新参数"误判成绑定失败。
            _want_primary = (primary_frame_id is not None
                             and self._source_accepts_primary_frame_id(source))
            if _want_primary:
                _kw["primary_frame_id"] = primary_frame_id
            # C155 收口：**不做**宽泛 TypeError 去参重试——签名探测已足够；
            # 解析器内部的真实 TypeError 必须一次可见拒绝，绝不能被吞掉后重调。
            result = source.resolve_frame_bindings(**_kw)
        except Exception as exc:             # 只读查询异常不得外抛
            return (None, "binding_source_error:{}".format(
                type(exc).__name__))
        if not isinstance(result, dict):
            return (None, "binding_source_bad_shape")
        return (result, None)

    @staticmethod
    def _grouped_frame_rows(result):
        """三分类分组 → 最小形状的逐帧行（来源只给分组、没给逐帧事实时）。

        **不合成**任何对象/事件身份：这样得到的 `bound` 行没有 `event_id`，
        会被如实判为不可准入——分组本身不足以成为绑定真相。
        """
        rows = {}
        for key, classification in (
                ("bound_frames", FRAME_CLASS_BOUND),
                ("context_frames", FRAME_CLASS_CONTEXT),
                ("ambiguous_or_rejected", FRAME_CLASS_AMBIGUOUS)):
            for value in tuple(result.get(key) or ()):
                fid = _frame_id(value if not isinstance(value, dict)
                                else value.get("frame_id"))
                if fid is not None and fid not in rows:
                    rows[fid] = {"frame_id": fid, "classification": classification}
        for key in ("rejected_frames", "ambiguous_frames"):
            for value in tuple(result.get(key) or ()):
                fid = _frame_id(value if not isinstance(value, dict)
                                else value.get("frame_id"))
                if fid is not None and fid not in rows:
                    rows[fid] = {"frame_id": fid,
                                 "classification": FRAME_CLASS_REJECTED}
        return rows

    def _observe_frame_level(self, *, record, camera_id, run_id,
                             config_version, window_key, window_id,
                             material_id, frame_rows, object_ids, declared,
                             frame_time_kind, turning_marker, material_reason):
        """逐帧准入（最小一期）：**只留自身严格绑定的帧**。

        - 复用同一只读快照与原守卫（身份/时基/持久区间/对象集合全由来源给出）；
        - 未归属上下文（`context`）**零像素保留**、不入事件页、不搬运，
          只在 `record["unattributed"]` 里留帧 id + 受控原因；
        - 同包不同事件/对象 → **拒绝聚合**（`conflicting_events` / `multi_object`），
          不按多数/latest/文本/邻帧挑一个；
        - 零保留 → 按逐帧主导原因拒绝，继续原未关联路径（不阻断快系统/L1）。
        """
        with self._lock:
            self._counts["frame_level_windows"] += 1
        result, failure = self._resolve_frame_bindings(
            camera_id=camera_id, run_id=run_id,
            config_version=config_version, frames=frame_rows,
            frame_time_kind=frame_time_kind)
        if failure is not None:
            with self._lock:
                self._counts["frame_level_source_errors"] += 1
            record["reason"] = failure
            return self._refuse_frame_level(record["reason"], record)
        record["resolved"] = dict(result)
        # 新接口的包级状态**没有** `unique`：出现即来源形状不符——部分成功
        # 不得伪装成整包 unique，绝不据此建页或复制。
        if result.get("status") == "unique":
            with self._lock:
                self._counts["frame_level_source_errors"] += 1
            record["reason"] = "binding_source_bad_shape"
            return self._refuse_frame_level(record["reason"], record)
        rows_by_frame = {}
        for row in tuple(result.get("frames") or ()):
            if not isinstance(row, dict):
                continue
            fid = _frame_id(row.get("frame_id"))
            if fid is not None and fid not in rows_by_frame:
                rows_by_frame[fid] = row
        if not rows_by_frame:
            rows_by_frame = self._grouped_frame_rows(result)
        admissions = []
        for row in frame_rows:
            fid = _frame_id(row.get("frame_id"))
            facts = _frame_row_admission(rows_by_frame.get(fid),
                                        declared=declared)
            facts["frame_id"] = fid if fid is not None else facts["frame_id"]
            with self._lock:
                self._frame_level_reason_locked(facts["classification"],
                                                facts["reason"])
            admissions.append(facts)
        kept = []
        unattributed = []
        event_ids = []
        kept_objects = []
        kept_occurrences = []
        for facts in admissions:
            if facts["classification"] == FRAME_CLASS_BOUND:
                kept.append(facts)
                if facts["event_id"] not in event_ids:
                    event_ids.append(facts["event_id"])
                if facts["object_id"] not in kept_objects:
                    kept_objects.append(facts["object_id"])
                occurrence = facts.get("event_occurrence")
                if occurrence is not None and occurrence not in kept_occurrences:
                    kept_occurrences.append(occurrence)
            else:
                unattributed.append({
                    "frame_id": facts["frame_id"],
                    "classification": facts["classification"],
                    "reason": facts["reason"],
                })
        with self._lock:
            self._counts["frames_unattributed"] += sum(
                1 for row in unattributed
                if row["classification"] == FRAME_CLASS_CONTEXT)
            self._counts["frames_ambiguous_or_rejected"] += sum(
                1 for row in unattributed
                if row["classification"] != FRAME_CLASS_CONTEXT)
        record["unattributed"] = unattributed
        record["admission"] = {
            "mode": MODE_PER_FRAME,
            "bound": [facts["frame_id"] for facts in kept],
            "context": [row["frame_id"] for row in unattributed
                        if row["classification"] == FRAME_CLASS_CONTEXT],
            "ambiguous_or_rejected": [
                row["frame_id"] for row in unattributed
                if row["classification"] != FRAME_CLASS_CONTEXT],
            "event_ids": list(event_ids),
            "object_ids": list(kept_objects),
            "event_occurrences": list(kept_occurrences),
            "source_status": _text(result.get("status"), 32),
            "source_reason": _text(result.get("reason"), 64),
        }
        if len(event_ids) > 1 or len(kept_occurrences) > 1:
            # 同包不同事件 / 同一事件 id 的不同 occurrence：**不得**按多数/
            # latest/文本/邻帧择一 → 拒绝聚合
            with self._lock:
                self._counts["frame_level_conflicts"] += 1
            record["reason"] = "conflicting_events"
            return self._refuse_frame_level(record["reason"], record)
        if len(kept_objects) > 1:
            # 同一事件下的多个对象：不得把场景级叙事无条件归给单个对象
            with self._lock:
                self._counts["frame_level_conflicts"] += 1
            record["reason"] = "multi_object"
            return self._refuse_frame_level(record["reason"], record)
        if not kept:
            record["reason"] = _dominant_frame_reason(
                [facts["reason"] or facts["classification"]
                 for facts in admissions])
            return self._refuse_frame_level(record["reason"], record)
        for facts in kept:
            identity = facts.get("identity") or {}
            for field, expected in (("camera_id", camera_id),
                                    ("run_id", run_id),
                                    ("config_version", config_version)):
                actual = identity.get(field)
                if actual is None or expected is None:
                    continue
                if str(actual) != str(expected):
                    # 绑定来源给出的帧身份与本次观察身份不符：不按"同名 id"
                    # 搬运（防跨 camera/run/config 串绑）。
                    record["reason"] = REFUSE_BINDING_IDENTITY_MISMATCH
                    return self._refuse_frame_level(record["reason"], record)
        head = kept[0]
        binding = {
            "camera_id": camera_id, "run_id": run_id,
            "config_version": config_version, "object_id": head["object_id"],
            "track_id": head["track_id"], "event_id": head["event_id"],
        }
        event_key = (camera_id, run_id, config_version, head["event_id"],
                     head["object_id"])
        record["event_id"] = head["event_id"]
        record["object_id"] = head["object_id"]
        record["track_id"] = head["track_id"]
        record["event_key"] = list(event_key)
        now = float(self._clock())
        with self._lock:
            entry = self._events.get(event_key)
            if entry is None:
                entry = _EventEntry(event_key, head["object_id"], now)
                self._events[event_key] = entry
                self._counts["events_created"] += 1
                self._evict_events_locked()
            entry.observations += 1
            entry.last_mono_ms = now
            self._window_events[window_key] = (event_key, head["event_id"],
                                              head["object_id"], now)
        kept_ids = {facts["frame_id"] for facts in kept}
        for row in frame_rows:
            if _frame_id(row.get("frame_id")) not in kept_ids:
                continue                       # 未归属帧：零复制、零搬运
            stored, reason = self._store_row(
                entry, row, binding=binding, window_key=window_key,
                window_id=window_id, material_id=material_id,
                camera_id=camera_id, run_id=run_id,
                config_version=config_version,
                material_reason=material_reason,
                turning_marker=turning_marker, now=now)
            if stored == "duplicate":
                record["duplicate"] += 1
            elif stored == "downscaled":
                record["downscaled"] += 1
            elif stored == "stored":
                pass
            elif stored in ("refused", "copy_failed"):
                record["refused"] += 1
                if reason:
                    record["refused_reasons"][reason] = (
                        record["refused_reasons"].get(reason, 0) + 1)
        with self._lock:
            self._counts["frame_level_admitted_windows"] += 1
            # 去重口径：同一帧被重复请求时只计一次准入（重复由既有
            # `frames_duplicate` 单独记账，两本账不相混）。
            self._counts["frames_admitted"] += len(
                {facts["frame_id"] for facts in kept})
            closed_now = self._closed
            holder = self._events.get(event_key)
            if holder is None:
                record["retained"] = 0
                record["retained_ids"] = []
                record["retained_roles"] = []
                record["evicted"] = entry.evicted
            else:
                first_id = holder.frames[0].frame_id if holder.frames else None
                last_id = holder.frames[-1].frame_id if holder.frames else None
                record["retained"] = len(holder.frames)
                record["retained_ids"] = [f.frame_id for f in holder.frames]
                record["evicted"] = holder.evicted
                record["retained_roles"] = [
                    f._positional_role(first_id, last_id)
                    for f in holder.frames]
        if closed_now:
            record["status"] = "window_only"
            record["reason"] = REFUSE_POOL_CLOSED
            return record
        record["status"] = "aggregated_allowed"
        return record

    # -- 选材计划 ------------------------------------------------------------

    def plan_frames(self, *, window_key, window_id, material_id, primary,
                    event_id=None, object_id=None, limit=None,
                    primary_reason=None, primary_change_boxes=None,
                    primary_event_id=None, primary_event_key=None,
                    primary_frame_id=None):
        """本窗口任务的**有界帧序**（主序位帧 + 同事件保留帧）。

        `primary`：本窗口主序位帧行（`{frame_id, frame_bgr, t_capture_ms,
        timestamp_kind}`；缺帧行 `frame_bgr=None` 保留序位）。
        `primary_reason` / `primary_change_boxes` / `primary_event_id`：本窗口
        主序位帧的**来源事实**（L1 材料触发原因、门控变化框、本窗事实链事件
        键）——只在行内缺该项时作为缺省，绝不覆盖行内自带值。
        返回 `FramePlan`；`status="window_only"` 时 `frames` 即主序位帧
        （旧路径，`reason` 说明为何未汇聚）。

        C155 车道 B（P0-3(a)，**只在 `primary_frame_binding` 打开时生效**）：
        事件页按**显式、已核验的主帧事件键**定位，键来源依次为

        1. `primary_event_key`（调用方给出：(camera, run, config[, event[, object]])）；
        2. **主序位帧行自带**的 `event_key`/`event_id`（该帧自身绑定事实）；
        3. 池侧对**主帧一帧**的只读逐帧查询（能力探测；仅 ①② 都缺时）；
        4. 旧窗口索引 / 声明的 `event_id`（旧路径，逐字保留）。

        邻帧行自带的绑定键**一律不参与**（不借邻帧选事件）；主帧无唯一合法
        绑定时按旧路径如实 `no_event_binding`。多个候选指向**不同**事件页时
        拒绝搬运（`conflicting_events`），绝不按多数/latest/文本择一。
        `primary_frame_id` 可显式指定主序位帧（缺省：行内 `slot=="cur"`/单行/
        三序位中位）。
        """
        window_key = tuple(window_key)
        source_rows = [row for row in tuple(primary or ())
                       if isinstance(row, dict)]
        # 本窗主序位帧的来源事实缺省（**行内自带优先**——源事实永远优先于
        # 缺省值，绝不覆盖行内已有的 material_reason/change_boxes/event_id）
        rows = []
        for row in source_rows:
            copied = dict(row)
            if copied.get("material_reason") is None:
                copied["material_reason"] = primary_reason
            if copied.get("change_boxes") is None:
                copied["change_boxes"] = primary_change_boxes
            if copied.get("event_id") is None:
                copied["event_id"] = primary_event_id
            rows.append(copied)
        block_ids = [row.get("frame_id") for row in rows]
        plan_limit = int(limit) if limit else int(self.max_frames_per_task)
        plan_limit = max(1, plan_limit)
        base = {
            "window_key": window_key, "window_id": window_id,
            "block_ids": block_ids, "limit": plan_limit,
            "observation": primary_reason,
        }
        if not rows or all(row.get("frame_bgr") is None for row in rows):
            base["event_id"] = event_id
            base["object_id"] = object_id
            self._window_only("no_primary_frames", base)
            return FramePlan(status="window_only", reason="no_primary_frames",
                             event_id=event_id, object_id=object_id,
                             window_key=window_key, window_id=window_id,
                             block_ids=block_ids, limit=plan_limit,
                             observation=primary_reason)
        event_identity = window_key[:3]
        carried = []
        reason = None
        key_source = None
        event_key = None
        # C155 B：显式/已核验的主帧事件键候选（**锁外**求值：候选③要调用
        # 只读绑定来源，绝不在持池锁时调用外部对象）。关闭后不再做任何查询。
        candidates = []
        if self.primary_frame_binding and not self.closed \
                and not self._window_sealed(window_key):
            candidates = self._plan_candidates(
                window_key=window_key, rows=rows,
                primary_frame_id=primary_frame_id,
                primary_event_key=primary_event_key)
        with self._lock:
            if self._closed:
                # 关闭后不得搬运任何保留帧（旧窗口路径照旧）
                reason = REFUSE_POOL_CLOSED
            elif self.primary_frame_binding \
                    and window_key in self._sealed_windows:
                # 窗口已封口：窗口无关的主帧绑定路由**不得**把迟到材料搬回来
                self._counts["plan_sealed_windows"] += 1
                reason = "no_event_binding"
            entry = None
            if reason is None and candidates:
                located = []
                for source_name, key in candidates:
                    found = self._entry_for(key[3], key[4],
                                            identity=tuple(key[:3]))
                    if found is not None:
                        located.append((source_name, key, found))
                if len({id(found) for _, _, found in located}) > 1:
                    # 两个**已核验**来源指向不同事件页：歧义 → 拒绝，不挑一个
                    self._counts["plan_event_key_conflicts"] += 1
                    reason = "conflicting_events"
                elif located:
                    key_source, event_key, entry = located[0]
                    self._counts["plan_frame_binding_resolved"] += 1
                    carried = list(entry.frames)
                    event_id = entry.key[_EVENT_ID_SLOT]
                    object_id = entry.object_id
                    event_key = tuple(entry.key)
            if reason is None and entry is None:
                window_row = self._window_events.get(window_key)
                if window_row is not None and window_row[1] is not None:
                    # 事件页必须与**本窗口身份**全等（`window_row[0]` 是入池
                    # 时登记的事件键）：同名 (event_id, object_id) 出现在别的
                    # camera/run/config 时绝不互相借材料。
                    entry = self._entry_for(
                        window_row[1], window_row[2],
                        identity=tuple(window_row[0])[:3])
                    if entry is not None and key_source is None:
                        key_source = "window_index"
                if entry is None and event_id is not None:
                    entry = self._entry_for(event_id, object_id,
                                            identity=event_identity)
                    if entry is not None and key_source is None:
                        key_source = "declared_event_id"
                if entry is None:
                    reason = "no_event_binding"
                else:
                    carried = list(entry.frames)
                    event_id = entry.key[_EVENT_ID_SLOT]
                    object_id = entry.object_id
                    event_key = tuple(entry.key)
        if not carried:
            reason = reason or "no_retained_frames"
            base["event_id"] = event_id
            base["object_id"] = object_id
            self._window_only(reason, base)
            return FramePlan(status="window_only", reason=reason,
                             event_id=event_id, object_id=object_id,
                             window_key=window_key, window_id=window_id,
                             block_ids=block_ids, limit=plan_limit,
                             observation=primary_reason, event_key=event_key,
                             key_source=key_source)
        if entry is not None:
            self._mark_primary_row_evidence(rows, entry,
                                            primary_event_id=primary_event_id)
        merged, deduped, dropped = _merge_and_bound(
            rows, carried, window_key=window_key, limit=plan_limit,
            window_id=window_id, material_id=material_id,
            primary_window_id=window_id)
        first_id = merged[0].frame_id if merged else None
        last_id = merged[-1].frame_id if merged else None
        bindings = [f.identity_record(positional=(first_id, last_id))
                    for f in merged]
        for row, frame in zip(bindings, merged):
            row["carried"] = frame.window_key != window_key
            row["carried_from_window_id"] = (frame.window_id
                                             if row["carried"] else None)
            # C155 B（加法）：本帧在该事件页内的"严格绑定"证据状态——
            # 未出现在事件页里的本窗帧一律为 False（不入事件证据）。
            row["event_evidence"] = bool(
                row["event_id"] is not None and not row["carried"])
        turning_ids = [row["frame_id"] for row in bindings
                       if row["role"] == ROLE_TURNING]
        marks = [index for index, row in enumerate(bindings)
                 if row["role"] == ROLE_TURNING]
        turn_basis = None
        if turning_ids:
            turn_basis = TURN_MARKER_CHANGE_START
        elif any(row["role"] == ROLE_MIDDLE for row in bindings):
            turn_basis = TURN_BASIS_UNKNOWN
        carried_ids = [row["frame_id"] for row in bindings if row["carried"]]
        plan = FramePlan(
            status="aggregated", reason="ok", event_id=event_id,
            object_id=object_id, window_key=window_key, window_id=window_id,
            carried_ids=carried_ids, block_ids=block_ids, frames=merged,
            frame_bindings=bindings, turning_ids=turning_ids,
            turn_basis=turn_basis,
            turn_coverage=(None if turning_ids else TURN_COVERAGE_NOTE)
            if turn_basis == TURN_BASIS_UNKNOWN else None,
            limit=plan_limit, carried_total=len(carried), deduped=deduped,
            dropped_extra=dropped,
            downscaled=sum(1 for f in merged if f.downscaled),
            observation=primary_reason, event_key=event_key,
            key_source=key_source)
        plan.observation = {"primary_reason": primary_reason,
                            "turn_positions": marks}
        with self._lock:
            self._counts["aggregated_windows"] += 1
        return plan

    def forget_window(self, window_key):
        """窗口封口：只清该窗口→事件的**索引**（材料池按事件保留，不丢归属）。

        C155 车道 B（**加法**）：同时把该窗口记入**有界**封口集合。该集合只在
        `primary_frame_binding` 打开时被查询，因此默认口径逐字不变；它的作用
        是"窗口封口后，窗口无关的主帧绑定路由不得把迟到材料搬回来"
        （收口即收口，不因池内仍保留该事件页而重开搬运）。
        """
        window_key = tuple(window_key)
        with self._lock:
            self._window_events.pop(window_key, None)
            if window_key not in self._sealed_windows:
                self._counts["window_sealed"] += 1
            self._sealed_windows[window_key] = True
            while len(self._sealed_windows) > self.sealed_window_cap:
                self._sealed_windows.pop(next(iter(self._sealed_windows)))

    def _window_sealed(self, window_key):
        with self._lock:
            return tuple(window_key) in self._sealed_windows

    def _plan_candidates(self, *, window_key, rows, primary_frame_id,
                         primary_event_key):
        """计划期的**已核验**事件页候选键（有序去重；锁外求值）。

        只认主序位帧**自身**的绑定：显式键 → 主帧行自带键 → 池侧对主帧一帧
        的只读查询。邻帧行自带的 `event_id` **一律不参与**（不得借邻帧选事件）。
        """
        candidates = []
        explicit = _normalized_event_key(primary_event_key)
        if explicit is not None:
            candidates.append(("primary_event_key", explicit))
        primary_id = _primary_frame_id(rows, primary_frame_id)
        if not candidates and primary_id is not None:
            for row in tuple(rows or ()):
                if _frame_id(row.get("frame_id")) != primary_id:
                    continue
                key = _normalized_event_key(row.get("event_key"))
                if key is None and row.get("event_id") not in (None, ""):
                    key = (window_key[0], window_key[1], window_key[2],
                           _text(row.get("event_id")),
                           _text(row.get("object_id")))
                if key is not None:
                    candidates.append(("primary_row_binding", key))
                break
        if not candidates and primary_id is not None \
                and self.source_supports_frame_bindings():
            key, _failure = self._query_primary_frame_binding(
                window_key=window_key, rows=rows,
                primary_frame_id=primary_id)
            if key is not None:
                candidates.append(("primary_frame_query", key))
        unique = []
        for source_name, key in candidates:
            if key not in [existing for _, existing in unique]:
                unique.append((source_name, key))
        return unique

    def _query_primary_frame_binding(self, *, window_key, rows,
                                     primary_frame_id):
        """池侧对**主帧一帧**的只读逐帧查询（能力探测；绝不外抛）。

        返回 `(event_key, failure)`。只有"该帧自身恰好一个对象且已完成 open
        事件绑定"才给键；未绑定/歧义/异常/形状不符一律 `(None, 受控原因)`，
        调用方照旧走窗口索引（**不猜事件**）。
        """
        row = None
        for candidate in tuple(rows or ()):
            if _frame_id(candidate.get("frame_id")) == primary_frame_id:
                row = candidate
                break
        if row is None:
            return (None, "no_primary_frame")
        with self._lock:
            self._counts["plan_frame_binding_queries"] += 1
        result, failure = self._resolve_frame_bindings(
            camera_id=window_key[0], run_id=window_key[1],
            config_version=window_key[2],
            frames=[{"frame_id": row.get("frame_id"),
                     "timestamp_kind": row.get("timestamp_kind")}],
            frame_time_kind=row.get("timestamp_kind"),
            primary_frame_id=_frame_id(row.get("frame_id")))
        if failure is None and result.get("status") == "unique":
            failure = "binding_source_bad_shape"
        facts = None
        if failure is None:
            source_row = None
            for item in tuple(result.get("frames") or ()):
                if isinstance(item, dict) \
                        and _frame_id(item.get("frame_id")) == primary_frame_id:
                    source_row = item
                    break
            if source_row is None:
                source_row = self._grouped_frame_rows(result).get(primary_frame_id)
            facts = _frame_row_admission(source_row)
            facts["frame_id"] = primary_frame_id
        if failure is None and facts["classification"] != FRAME_CLASS_BOUND:
            failure = facts["reason"] or facts["classification"]
        if failure is None:
            identity = facts.get("identity") or {}
            for field, expected in (("camera_id", window_key[0]),
                                    ("run_id", window_key[1]),
                                    ("config_version", window_key[2])):
                actual = identity.get(field)
                if actual is None or expected is None:
                    continue
                if str(actual) != str(expected):
                    failure = REFUSE_BINDING_IDENTITY_MISMATCH
                    break
        if failure is not None:
            with self._lock:
                self._counts["plan_frame_binding_refused"] += 1
            return (None, _text(failure, 64))
        return ((window_key[0], window_key[1], window_key[2],
                 facts["event_id"], facts["object_id"]), None)

    def _mark_primary_row_evidence(self, rows, entry, *, primary_event_id=None):
        """逐帧口径下按**事件页证据**修正本窗帧的证据标记（加法，零复制）。

        - 本窗帧若**确实在事件页内**（该帧自身绑定已核验并保留）→ 它的键本来
          就是事件证据（仅在行内缺键时补齐）；
        - 只靠窗口级 `primary_event_id` 缺省带上的帧、且**不在**事件页内 →
          清掉该键：它在池内**没有自身绑定**，不得冒充事件证据。

        只在逐帧口径（`frame_level_binding` 打开）时生效——旧整包口径下本方法
        直接返回，行为逐字不变。
        """
        if not self.frame_level_binding:
            return rows
        page = {frame.frame_id: (frame.event_id, frame.object_id)
                for frame in entry.frames}
        for row in rows:
            frame_id = _frame_id(row.get("frame_id"))
            if frame_id in page:
                event_id, object_id = page[frame_id]
                if row.get("event_id") is None:
                    row["event_id"] = event_id
                if row.get("object_id") is None:
                    row["object_id"] = object_id
                continue
            if primary_event_id is not None \
                    and row.get("event_id") == primary_event_id:
                row["event_id"] = None
                row["object_id"] = None
        return rows

    # -- 内部：绑定与存储 ----------------------------------------------------

    def _resolve_binding(self, *, camera_id, run_id, config_version, frames,
                         object_ids=(), frame_time_kind=None):
        source = self.binding_source
        if source is None or not hasattr(source, "resolve_material_binding"):
            return {"status": "unbound", "reason": "binding_source_missing",
                    "binding": None, "frames": ()}
        try:
            result = source.resolve_material_binding(
                camera_id=camera_id, run_id=run_id,
                config_version=config_version, object_ids=tuple(object_ids),
                frames=frames, frame_time_kind=frame_time_kind)
        except Exception as exc:
            return {"status": "unbound",
                    "reason": "binding_source_error:{}".format(
                        type(exc).__name__),
                    "binding": None, "frames": ()}
        if not isinstance(result, dict):
            return {"status": "unbound", "reason": "binding_source_bad_shape",
                    "binding": None, "frames": ()}
        return result

    def _refuse(self, reason, record):
        reason = str(reason)[:64]
        with self._lock:
            self._refusals[reason] = self._refusals.get(reason, 0) + 1
            self._counts["window_only_windows"] += 1
            self._last_refusal = {
                "reason": reason,
                "window_key": list(record.get("window_key") or ()),
                "window_id": record.get("window_id"),
                "camera_id": (record.get("window_key") or [None])[0],
            }
        return record

    def _window_only(self, reason, base):
        reason = str(reason)[:64]
        with self._lock:
            self._refusals[reason] = self._refusals.get(reason, 0) + 1
            self._counts["window_only_windows"] += 1
            self._last_refusal = {
                "reason": reason,
                "window_key": list(base.get("window_key") or ()),
                "window_id": base.get("window_id"),
                "camera_id": (base.get("window_key") or [None])[0],
            }

    def _refuse_frame_locked(self, reason, window_key, window_id, frame_id):
        """逐帧拒绝（受控原因；调用方持锁）：计数 + 最近一条，账目有界。"""
        reason = str(reason)[:64]
        self._frame_refusals[reason] = self._frame_refusals.get(reason, 0) + 1
        self._counts["frames_refused"] += 1
        self._last_frame_refusal = {
            "reason": reason,
            "frame_id": frame_id,
            "window_key": list(window_key or ()),
            "window_id": window_id,
        }

    def _settle_reservation_locked(self, reservation, *, commit,
                                   pixels=None, bytes_=None):
        """预留的**唯一**出口（commit/release 各恰一次；调用方持锁）。

        - `commit=True`：在途临时账 → 持有账（像素已真实入池）；
        - `commit=False`：只减在途临时账（**不动**已有帧的持有账）。
        重复结算不重复记账，只计 `reservation_release_after_settle`（异常可查）。
        """
        if reservation.settled:
            self._counts["reservation_release_after_settle"] += 1
            return False
        if (self._reserved_temp_bytes < reservation.bytes
                or self._reserved_temp_pixels < reservation.pixels):
            # 不静默：账目异常可见（正常路径永不发生）
            self._counts["reservation_accounting_anomaly"] += 1
        reservation._settled = True
        if self._live_reservations > 0:
            # 在途预留条数（步骤 3 的等待对象）；与字节/像素账目一并归零
            self._live_reservations -= 1
        self._reserved_temp_bytes -= reservation.bytes
        self._reserved_temp_pixels -= reservation.pixels
        if commit:
            self._held_pixels += int(reservation.pixels if pixels is None
                                     else pixels)
            self._held_bytes += int(reservation.bytes if bytes_ is None
                                    else bytes_)
            self._copy_reservations_committed += 1
        else:
            self._copy_reservations_released += 1
        return True

    def _capacity_victim_locked(self):
        """超限淘汰优先序（与既有规则**同形**，不改优先序）：

        先未绑定帧、再无依据的中间采样（最旧优先）；都没有 → `(None, None)`
        （宁可拒绝，也不为放新帧而拆掉唯一证据）。调用方持锁。
        """
        victim_entry = None
        victim_index = None
        oldest = None
        for entry in self._events.values():
            for index, frame in enumerate(entry.frames):
                if not frame.bound or frame.role() == ROLE_MIDDLE:
                    if oldest is None or frame.observed_mono_ms < oldest:
                        oldest = frame.observed_mono_ms
                        victim_entry = entry
                        victim_index = index
        return (victim_entry, victim_index)

    def _make_room_locked(self, need_bytes, need_pixels):
        """为即将到来的复制**腾容量**：先安全淘汰，淘汰不动 → False（拒绝）。

        预留（`reserved_temp_*`）也计入判定：在途复制占用的容量不被重复许诺。
        """
        pixels, total_bytes = self._held_totals_locked()
        while (total_bytes + self._reserved_temp_bytes + need_bytes
               > self.max_total_bytes
               or pixels + self._reserved_temp_pixels + need_pixels
               > self.max_total_pixels):
            victim_entry, victim_index = self._capacity_victim_locked()
            if victim_entry is None or victim_index is None:
                return False
            self._evict_locked(victim_entry, victim_index, "pool_total_cap",
                               float(self._clock()))
            victim_entry.evicted += 1
            if not victim_entry.frames:
                self._events.pop(victim_entry.key, None)
                self._counts["events_evicted"] += 1
            pixels, total_bytes = self._held_totals_locked()
        return True

    def _reserve_locked(self, entry, plan, window_key, window_id, frame_id):
        """**复制之前**的容量决定：单帧超池上限 → 拒绝；满池 → 先淘汰再预留。

        返回 `(reservation, None)` 或 `(None, 受控原因)`。拒绝路径**零复制**、
        不占用预留（因此无需归还）。
        """
        if self._events.get(entry.key) is not entry:
            self._refuse_frame_locked(REFUSE_ENTRY_EVICTED, window_key,
                                      window_id, frame_id)
            return (None, REFUSE_ENTRY_EVICTED)
        if plan.target_bytes > self.max_total_bytes:
            # 单帧就超过总字节上限：永远放不进 → 明确拒绝（不复制、不预留）
            self._refuse_frame_locked(REFUSE_FRAME_BYTES_OVER_TOTAL, window_key,
                                      window_id, frame_id)
            return (None, REFUSE_FRAME_BYTES_OVER_TOTAL)
        if plan.target_pixels > self.max_total_pixels:
            self._refuse_frame_locked(REFUSE_FRAME_PIXELS_OVER_TOTAL,
                                      window_key, window_id, frame_id)
            return (None, REFUSE_FRAME_PIXELS_OVER_TOTAL)
        if not self._make_room_locked(plan.target_bytes, plan.target_pixels):
            self._refuse_frame_locked(REFUSE_POOL_FULL, window_key, window_id,
                                      frame_id)
            return (None, REFUSE_POOL_FULL)
        reservation = _CopyReservation(plan.target_pixels, plan.target_bytes)
        self._reserved_temp_pixels += reservation.pixels
        self._reserved_temp_bytes += reservation.bytes
        self._live_reservations += 1
        self._copy_reservations += 1
        return (reservation, None)

    def _store_row(self, entry, row, *, binding, window_key, window_id,
                   material_id, camera_id, run_id, config_version,
                   material_reason, turning_marker, now):
        """单帧入池（C154-R1 H 三段式）：**先校验 → 先淘汰/拒绝 → 再预留 →
        锁外恰一次复制 → 提交**。

        返回 `(状态, 受控原因)`：`stored|downscaled|duplicate|skipped|
        refused|copy_failed`。拒绝路径不复制整帧；异常/形态不符/关闭/事件页
        被淘汰一律把在途预留**恰一次归还**，且不触碰已有帧的持有账目。
        """
        frame_id = _frame_id(row.get("frame_id"))
        if frame_id is None:
            return ("skipped", None)
        identity = (camera_id, run_id, config_version, frame_id)
        with self._lock:
            for existing in entry.frames:
                if existing.identity_key == identity:
                    self._counts["frames_duplicate"] += 1
                    if existing.event_id is None and binding:
                        existing.event_id = _text(binding.get("event_id"))
                    return ("duplicate", None)
        image = row.get("frame_bgr")
        if image is None:
            return ("skipped", None)
        # 1) 复制前形态校验（零复制）：尺寸/dtype/通道/字节
        plan = _plan_image(image, self.max_frame_pixels)
        if not plan.ok:
            with self._lock:
                self._refuse_frame_locked(plan.reason, window_key, window_id,
                                          frame_id)
            return ("refused", plan.reason)
        # 2) 关闭检查与容量预留（先淘汰/拒绝，再预留）
        with self._lock:
            if self._closed:
                self._refuse_frame_locked(REFUSE_POOL_CLOSED, window_key,
                                          window_id, frame_id)
                return ("refused", REFUSE_POOL_CLOSED)
            reservation, reason = self._reserve_locked(
                entry, plan, window_key, window_id, frame_id)
        if reservation is None:
            return ("refused", reason)
        # 3) 锁外**恰一次**复制（在途预留记账、可查、可归还）
        try:
            stored = _copy_once(image, plan)
        except Exception:
            with self._lock:
                self._copy_failures += 1
                self._counts["frames_copy_failed"] += 1
                self._settle_reservation_locked(reservation, commit=False)
                self._refuse_frame_locked(REFUSE_COPY_FAILED, window_key,
                                          window_id, frame_id)
            return ("copy_failed", REFUSE_COPY_FAILED)
        with self._lock:
            self._copies += 1
        if (int(stored.shape[0]), int(stored.shape[1])) != plan.target_size \
                or int(stored.nbytes) != plan.target_bytes:
            with self._lock:
                self._copy_failures += 1
                self._counts["frames_copy_failed"] += 1
                self._settle_reservation_locked(reservation, commit=False)
                self._refuse_frame_locked(REFUSE_COPY_SHAPE_MISMATCH,
                                          window_key, window_id, frame_id)
            return ("copy_failed", REFUSE_COPY_SHAPE_MISMATCH)
        reason = row.get("material_reason", material_reason)
        if reason not in _MATERIAL_REASONS:
            reason = None
        if turning_marker is not None and reason is None:
            reason = str(turning_marker)
        boxes = row.get("change_boxes")
        frame = SequenceFrame(
            camera_id=camera_id, run_id=run_id, config_version=config_version,
            window_id=window_id, window_key=window_key, material_id=material_id,
            frame_id=frame_id,
            t_capture_ms=_finite(row.get("t_capture_ms")),
            timestamp_kind=row.get("timestamp_kind"),
            frame_bgr=stored, width=int(stored.shape[1]),
            height=int(stored.shape[0]),
            source_width=plan.source_w, source_height=plan.source_h,
            downscaled=plan.downscaled, material_reason=reason,
            change_boxes=boxes if isinstance(boxes, (list, tuple)) else (),
            change_area=_change_area(boxes), origin="window_material",
            event_id=_text(binding.get("event_id")),
            object_id=_text(binding.get("object_id")),
            track_id=binding.get("track_id"), bound=True,
            observed_mono_ms=now, crop_id=row.get("crop_id"))
        # 4) 提交：关闭后 / 事件页已被淘汰 → 在途预留**不落入池**，恰一次归还
        with self._lock:
            if self._closed or self._events.get(entry.key) is not entry:
                blocker = (REFUSE_POOL_CLOSED if self._closed
                           else REFUSE_ENTRY_EVICTED)
                self._settle_reservation_locked(reservation, commit=False)
                self._refuse_frame_locked(blocker, window_key, window_id,
                                          frame_id)
                return ("refused", blocker)
            entry.frames.append(frame)
            entry.frames.sort(key=_sequence_sort_key)
            entry.downscaled += 1 if plan.downscaled else 0
            self._settle_reservation_locked(
                reservation, commit=True, pixels=plan.target_pixels,
                bytes_=int(stored.nbytes))
            if plan.downscaled:
                self._counts["frames_downscaled"] += 1
            self._counts["frames_retained"] += 1
            entry.evicted += self._trim_event_locked(entry, now)
            self._enforce_totals_locked(now)
        return ("downscaled" if plan.downscaled else "stored", None)

    def _trim_event_locked(self, entry, now):
        evicted = 0
        while len(entry.frames) > self.max_frames_per_event:
            victim = self._evictable_index(entry)
            self._evict_locked(entry, victim, "event_frame_cap", now)
            evicted += 1
        return evicted

    @staticmethod
    def _evictable_index(entry):
        """淘汰优先序（"开始、最新优先保留"）：

        1. 未绑定帧；
        2. 序列**最旧**的无依据中间采样（最旧优先——最新状态优先保留）；
        3. 只剩锚点与带依据转折时：淘汰最旧的非锚点帧。
        序列首帧（开始）在还有其它可淘汰帧时**永不**被选；序末帧（最新）
        同样最后才动——因此"开始"在整个事件存续期里被钉住，最新状态随新
        观测自然前移（而不是被旧中间帧挤掉）。
        """
        if len(entry.frames) <= 2:
            return 0
        for index, frame in enumerate(entry.frames):
            if not frame.bound:
                return index
        middle = [(index, frame)
                  for index, frame in enumerate(entry.frames[1:-1], start=1)
                  if frame.role() == ROLE_MIDDLE]
        if middle:
            return middle[0][0]              # 最旧的无依据中间采样
        candidates = list(range(1, len(entry.frames) - 1))
        return candidates[0] if candidates else 1

    def _drop_frame_accounting_locked(self, frame):
        """帧离池：**只**减该帧的持有账目（绝不动其它帧与在途预留）。

        像素已被步骤 4 释放的帧不再减记（减一次就够）：否则会造出负的
        持有账目，等于用"重复减账"掩盖真实状态。
        """
        if frame.frame_bgr is None:
            return
        self._held_pixels -= int(frame.width) * int(frame.height)
        self._held_bytes -= int(frame.frame_bgr.nbytes)

    def _evict_locked(self, entry, index, reason, now):
        if not entry.frames:
            return None
        index = max(0, min(index, len(entry.frames) - 1))
        victim = entry.frames.pop(index)
        self._drop_frame_accounting_locked(victim)
        self._counts["frames_evicted"] += 1
        self._evictions.append({
            "reason": reason,
            "event_id": victim.event_id,
            "object_id": victim.object_id,
            "frame_id": victim.frame_id,
            "window_id": victim.window_id,
            "material_id": victim.material_id,
            "role": victim.role(),
            "at_mono_ms": now,
        })
        while len(self._evictions) > 32:
            self._evictions.pop(0)
        return victim

    def _enforce_totals_locked(self, now=None):
        """提交后的**兜底**核对：仍超池上限 → 按同一优先序淘汰（正常无动作）。"""
        pixels, total_bytes = self._held_totals_locked()
        while (total_bytes > self.max_total_bytes
               or pixels > self.max_total_pixels):
            victim_entry, victim_index = self._capacity_victim_locked()
            if victim_entry is None or victim_index is None:
                return
            self._evict_locked(victim_entry, victim_index, "pool_total_cap",
                               float(self._clock() if now is None else now))
            victim_entry.evicted += 1
            if not victim_entry.frames:
                self._events.pop(victim_entry.key, None)
                self._counts["events_evicted"] += 1
            pixels, total_bytes = self._held_totals_locked()

    def _evict_events_locked(self):
        while len(self._events) > self.max_events:
            oldest_key = None
            oldest = None
            for key, entry in self._events.items():
                if oldest is None or entry.last_mono_ms < oldest:
                    oldest = entry.last_mono_ms
                    oldest_key = key
            if oldest_key is None:
                return
            dropped = self._events.pop(oldest_key, None)
            if dropped is not None:
                # 事件页整体离池：逐帧减持有账目（不静默留账），并把陈旧
                # 引用上的帧清空，避免并发观察读到幽灵帧。
                for frame in list(dropped.frames):
                    self._drop_frame_accounting_locked(frame)
                dropped.frames = []
            self._counts["events_evicted"] += 1


# ---- 纯函数：复制前形态计划、恰一次复制、时序合并、容量取舍 ------------------

class _ImagePlan:
    """**复制之前**算出的目标形态（零像素、零复制；C154-R1 H）。"""

    __slots__ = ("ok", "reason", "source_h", "source_w", "channels",
                 "dtype_name", "itemsize", "step", "downscaled",
                 "target_size", "target_pixels", "target_bytes")

    def __init__(self, *, ok, reason=None, source_h=0, source_w=0, channels=0,
                 dtype_name=None, itemsize=0, step=1, downscaled=False,
                 target_size=(0, 0), target_pixels=0, target_bytes=0):
        self.ok = bool(ok)
        self.reason = None if reason is None else str(reason)[:64]
        self.source_h = int(source_h)
        self.source_w = int(source_w)
        self.channels = int(channels)
        self.dtype_name = dtype_name
        self.itemsize = int(itemsize)
        self.step = int(step)
        self.downscaled = bool(downscaled)
        self.target_size = (int(target_size[0]), int(target_size[1]))
        self.target_pixels = int(target_pixels)
        self.target_bytes = int(target_bytes)

    @property
    def source_pixels(self):
        return self.source_h * self.source_w


def _plan_image(image, max_pixels):
    """图像形态与目标尺寸的**复制前**判定（纯函数，绝不复制像素）。

    校验顺序（受控原因码如实反映第一处不合法）：
    `unsupported_image_type`（非 ndarray）→ `unsupported_ndim`（非 2/3 维）→
    `invalid_shape`（长/短边非正）→ `unsupported_dtype`（非 uint8/uint16）→
    `unsupported_channels`（通道数不在 1/3/4）。降采样步长与目标字节数只由
    形状/dtype 推出，因此**不需要**先复制一份才知道会不会超限。
    """
    if not isinstance(image, np.ndarray):
        return _ImagePlan(ok=False, reason=REFUSE_UNSUPPORTED_IMAGE)
    if int(image.ndim) not in (2, 3):
        return _ImagePlan(ok=False, reason=REFUSE_UNSUPPORTED_NDIM)
    source_h, source_w = int(image.shape[0]), int(image.shape[1])
    if source_h <= 0 or source_w <= 0:
        return _ImagePlan(ok=False, reason=REFUSE_INVALID_SHAPE)
    dtype_name = str(image.dtype.name)
    if dtype_name not in SUPPORTED_DTYPES:
        return _ImagePlan(ok=False, reason=REFUSE_UNSUPPORTED_DTYPE)
    channels = 1 if int(image.ndim) == 2 else int(image.shape[2])
    if channels not in SUPPORTED_CHANNELS:
        return _ImagePlan(ok=False, reason=REFUSE_UNSUPPORTED_CHANNELS)
    itemsize = int(image.dtype.itemsize)
    limit = int(max_pixels)
    step = 1
    if source_h * source_w > limit:
        step = max(1, int(math.ceil(
            math.sqrt((source_h * source_w) / float(limit)))))
    target_h = int(math.ceil(source_h / float(step)))
    target_w = int(math.ceil(source_w / float(step)))
    target_pixels = target_h * target_w
    return _ImagePlan(
        ok=True, source_h=source_h, source_w=source_w, channels=channels,
        dtype_name=dtype_name, itemsize=itemsize, step=step,
        downscaled=(target_h, target_w) != (source_h, source_w),
        target_size=(target_h, target_w), target_pixels=target_pixels,
        target_bytes=target_pixels * channels * itemsize)


def _copy_once(image, plan):
    """**恰一次**复制：只读、C 连续、形状/ dtype 与计划全等（纯函数）。

    非连续输入（切片视图等）由 `np.array(..., order="C", copy=True)` 一次落成
    连续副本——不再走 `np.ascontiguousarray(...).copy()` 的双份副本路径。
    """
    source = image if plan.step <= 1 else image[::plan.step, ::plan.step]
    copied = np.array(source, dtype=source.dtype, order="C", copy=True)
    copied.setflags(write=False)
    return copied


def _binding_identity_mismatch(binding, camera_id, run_id, config_version):
    """事实链绑定的事件身份是否与本次观察身份全等（缺项不判错、不猜）。

    生产来源自带该校验（`EventProgress.resolve_material_binding` →
    `identity_mismatch`，见 `win11_event_progress.py`）；池边界再核一次，
    使"同一 (event_id, object_id) 出现在别的 camera/run/config"无法串绑。
    """
    for field, expected in (("camera_id", camera_id), ("run_id", run_id),
                            ("config_version", config_version)):
        actual = binding.get(field)
        if actual is None or expected is None:
            continue
        if str(actual) != str(expected):
            return True
    return False


# ---- C155 车道 B：逐帧准入的纯函数（零 I/O、零复制、零猜） ------------------

def _refs_set(value):
    """帧内对象集合（**只认来源给出的**；缺证据返回 None，不猜、不补）。"""
    if not isinstance(value, (list, tuple, set, frozenset)):
        return None
    return {str(item) for item in value if item is not None}


def _declared_objects(object_ids):
    """调用方声明的对象集合（有序去重；空即"未声明对象身份"）。"""
    declared = []
    for value in tuple(object_ids or ()):
        if value is None:
            continue
        text = str(value)
        if text not in declared:
            declared.append(text)
    return tuple(declared)


def _frame_row_admission(row, *, declared=()):
    """**单帧**分类（纯函数）：只读来源给出的事实 → 受控分类 + 原因码。

    输入 = `resolve_frame_bindings` 的同序同行返回项（来源缺失时调用方传
    `None`）。判定**不读**任何"包的对象集合/并集"、不读 L4 结果、不按
    多数/latest/文本/邻帧补绑定：

    - `classification` 不在受控词表 → 由 `bound`/`snapshot_present`/`event_id`
      **保守推导**（缺证据一律不判 `bound`）；
    - `bound` 帧必须**自带** `object_id` 与 `event_id`，且其**自身** `refs`
      （若来源给出）恰为该对象；`refs` 多于一个 → `ambiguous/multi_object`；
    - 调用方声明的对象集合非空时，帧自身对象必须落在其中，否则
      `ambiguous/object_mismatch`（不得把帧归到没被请求的对象上）。

    返回 `{frame_id, classification, reason, event_id, object_id, track_id,
    refs, snapshot_present, t_ms, time_kind, identity}`。
    """
    row = row if isinstance(row, dict) else {}
    facts = {
        "frame_id": _frame_id(row.get("frame_id")),
        "classification": None,
        "reason": None,
        "event_id": _text(row.get("event_id")),
        "object_id": _text(row.get("object_id")),
        "track_id": row.get("track_id"),
        "event_occurrence": row.get("event_occurrence"),
        "refs": None,
        "snapshot_present": row.get("snapshot_present"),
        "t_ms": _finite(row.get("t_ms")),
        "time_kind": _text(row.get("time_kind"), 32),
        "identity": {field: row.get(field) for field in
                     ("camera_id", "run_id", "config_version")},
    }
    if facts["frame_id"] is None:
        facts["classification"] = FRAME_CLASS_REJECTED
        facts["reason"] = "frame_binding_missing"
        return facts
    reason = _text(row.get("reason"), 64) or None
    classification = row.get("classification")
    if not isinstance(classification, str) \
            or classification not in FRAME_CLASSES:
        # 最小约定（车道 A 落地前）：形状只有 `bound`/`snapshot_present` 时
        # 保守推导——缺证据绝不升级为 `bound`。
        if row.get("bound") is True and facts["event_id"]:
            classification = FRAME_CLASS_BOUND
        elif facts["snapshot_present"] is False:
            classification = FRAME_CLASS_REJECTED
        elif row.get("bound") is False and facts["snapshot_present"] is True:
            classification = FRAME_CLASS_CONTEXT
        else:
            classification = FRAME_CLASS_REJECTED
            reason = reason or "frame_binding_unclassified"
    if classification == FRAME_CLASS_BOUND:
        refs = _refs_set(row.get("refs"))
        if refs is not None and len(refs) > 1:
            return _classified(facts, FRAME_CLASS_AMBIGUOUS, "multi_object")
        if refs is not None and facts["object_id"] is not None \
                and refs != {facts["object_id"]}:
            return _classified(facts, FRAME_CLASS_AMBIGUOUS, "object_mismatch")
        if facts["object_id"] is None or not facts["event_id"]:
            # `bound` 却拿不到唯一对象/事件身份：来源形状自相矛盾 →
            # 保守拒绝（绝不代它挑一个对象或事件）。
            return _classified(facts, FRAME_CLASS_REJECTED,
                               reason or "frame_binding_unclassified")
        if declared:
            if refs is not None:
                if refs != set(declared):
                    return _classified(facts, FRAME_CLASS_AMBIGUOUS,
                                       "object_mismatch")
            elif facts["object_id"] not in set(declared):
                return _classified(facts, FRAME_CLASS_AMBIGUOUS,
                                   "object_mismatch")
        facts["refs"] = None if refs is None else sorted(refs)
        facts["classification"] = FRAME_CLASS_BOUND
        return facts
    if classification == FRAME_CLASS_CONTEXT:
        return _classified(facts, FRAME_CLASS_CONTEXT,
                           reason or "no_event_binding")
    # ambiguous / rejected：原因缺失时按分类给受控缺省（绝不空手放行）
    default = ("multi_object" if classification == FRAME_CLASS_AMBIGUOUS
               else "frame_binding_unclassified")
    return _classified(facts, classification, reason or default)


def _classified(facts, classification, reason):
    facts["classification"] = classification
    facts["reason"] = _text(reason, 64)
    facts["event_id"] = None
    facts["object_id"] = None
    facts["track_id"] = None
    facts["event_occurrence"] = None
    return facts


def _dominant_frame_reason(reasons):
    """零保留时的**主导原因**（受控优先级；未登记码按字典序，绝不静默）。"""
    counts = {}
    for reason in reasons:
        text = _text(reason, 64) or "frame_binding_missing"
        counts[text] = counts.get(text, 0) + 1
    for code in FRAME_REASON_PRIORITY:
        if code in counts:
            return code
    return sorted(counts)[0] if counts else "frame_binding_missing"


def _normalized_event_key(value):
    """显式**事件键**规范化（`(camera, run, config[, event_id[, object_id]]])`）。

    只做形状规范化：长度 3/4/5；缺 `event_id` 即"无显式主帧事件键"（返回
    `None`，调用方照旧走窗口索引）。**不合成**任何缺项、不猜事件。
    """
    if value is None:
        return None
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        return None
    parts = list(value)
    if len(parts) not in (3, 4, 5):
        return None
    while len(parts) < 5:
        parts.append(None)
    camera, run, config, event_id, object_id = parts
    if event_id in (None, ""):
        return None
    return (camera, run, config, _text(event_id), _text(object_id))


def _primary_frame_id(rows, explicit=None):
    """**主序位帧** id（显式优先 → 行内 `slot=="cur"`/`primary` → 单行 → 三序位中位）。

    只用于"该帧自身的绑定"这一条窗口无关的路由；找不到即返回 `None`
    （宁可不搬运，也不借邻帧）。
    """
    if explicit is not None:
        return _frame_id(explicit)
    for row in tuple(rows or ()):
        if row.get("slot") == "cur" or row.get("primary") is True:
            return _frame_id(row.get("frame_id"))
    if len(rows) == 1:
        return _frame_id(rows[0].get("frame_id"))
    if len(rows) == 3:
        # 生产 `primary_frame_rows` 恒为 (prev, cur, nxt) 三行
        return _frame_id(rows[1].get("frame_id"))
    return None


def _missing_object_diagnostic(*, object_ids_present, detection_count,
                               l1_terminal_reason):
    """F3：把"为什么没有可聚合的对象身份"**细分**成受控三态（纯函数）。

    只在 `object_ids` 为空时使用；返回 `(state, reason)`：

    - `detection_count > 0`（有检出）却没有可用 `trackId` → 调用方判定为
      `identity_insufficient` / `object_ids_invalid`（**有检出**，只是拿不到
      稳定的对象身份——绝不把这种情况写成"确认无对象"）；
    - `detection_count == 0` 且 `l1_terminal_reason in (None, "empty")`
      → `no_objects` / `object_ids_missing`（**兼容码逐字保留**）。
      生产 `take_ready` 摘出的 `consumable` 包 `l1_terminal_reason is None`，
      其 `detections` 由该帧自己的 `ok` 结论写入——空元组就是"该结论确认
      零对象"；`"empty"` 是同一结论的显式措辞；
    - `detection_count` 未知（None：包没有 L1 结论字段/从未有结论）或
      `l1_terminal_reason` 是失败/超时/被拒（`l1_wait_timeout` /
      `infer_failed` / `model_unavailable` / `rejected:*` …）
      → `l1_pending` / `object_ids_missing_l1_pending`（结论尚未取得/失败/
      被拒，`unknown` 不当 `empty`）。

    本函数**不参与**任何准入判定：判定仍在
    `EventProgress.resolve_material_binding`，这里只补诊断。
    """
    if object_ids_present:
        return (None, None)
    if detection_count is not None and int(detection_count) > 0:
        return (OBJECT_STATE_IDENTITY_INSUFFICIENT, OBJECT_REASON_INVALID)
    if detection_count is not None and int(detection_count) == 0 \
            and l1_terminal_reason in (None, "empty"):
        return (OBJECT_STATE_NO_OBJECTS, OBJECT_REASON_MISSING)
    return (OBJECT_STATE_L1_PENDING, OBJECT_REASON_L1_PENDING)


def _change_area(boxes):
    total = 0.0
    for box in tuple(boxes or ()):
        if not isinstance(box, dict):
            continue
        try:
            width = float(box.get("w") or 0.0)
            height = float(box.get("h") or 0.0)
        except (TypeError, ValueError):
            continue
        if math.isfinite(width) and math.isfinite(height):
            total += max(0.0, width) * max(0.0, height)
    return total


def _sequence_sort_key(frame):
    t_ms = frame.t_capture_ms
    if t_ms is None:
        return (float("inf"), str(frame.frame_id))
    return (float(t_ms), str(frame.frame_id))


def _merge_and_bound(primary_rows, carried, *, window_key, limit,
                     window_id=None, material_id=None,
                     primary_window_id=None):
    """主序位帧 + 事件保留帧 → 去重、按时序、容量内取舍（纯函数）。

    返回 `(merged_frames, deduped_count, dropped_count)`；`merged` 是
    `SequenceFrame` 列表（主序位帧转成同样的载体，来源仍标
    `window_material`）。语义锚点：**首个=开始、末个=最新**（时序升序，
    与 `win11_l3.select_frames_within_budget` 一致）；容量不足时保留
    首帧、末帧、**有依据的转折帧**，其余按确定性等距采样（中段偏新）。
    """
    rows = []
    seen = set()
    deduped = 0
    for row in tuple(primary_rows or ()):
        frame_id = _frame_id(row.get("frame_id"))
        if frame_id is None:
            continue
        identity = (window_key[0], window_key[1], window_key[2], frame_id)
        if identity in seen:
            deduped += 1
            continue
        seen.add(identity)
        rows.append(_row_to_frame(
            row, window_key,
            window_id=(primary_window_id if primary_window_id is not None
                       else window_id),
            material_id=material_id))
    for frame in tuple(carried or ()):
        if frame.identity_key in seen:
            deduped += 1
            continue
        seen.add(frame.identity_key)
        rows.append(frame)
    rows.sort(key=_sequence_sort_key)
    if len(rows) <= limit:
        return (rows, deduped, 0)
    keeps = {0, len(rows) - 1}
    turning = [(index, frame) for index, frame in enumerate(rows[1:-1],
                                                          start=1)
               if frame.role() == ROLE_TURNING]
    for index, _frame in turning:
        if len(keeps) >= limit:
            break
        keeps.add(index)
    middle = [(index, frame) for index, frame in enumerate(rows[1:-1],
                                                          start=1)
              if index not in keeps]
    free = limit - len(keeps)
    if free > 0 and middle:
        if free >= len(middle):
            chosen = middle
        else:
            nodes = sorted({int(round(index * (len(middle) - 1)
                                      / float(max(1, free - 1))))
                            for index in range(free)})
            chosen = [middle[node] for node in nodes]
        for index, _frame in chosen:
            if len(keeps) >= limit:
                break
            keeps.add(index)
    merged = [frame for index, frame in enumerate(rows) if index in keeps]
    merged.sort(key=_sequence_sort_key)
    return (merged, deduped, len(rows) - len(merged))


def _row_to_frame(row, window_key, *, window_id=None, material_id=None):
    """主序位帧行 → `SequenceFrame`（本窗口材料来源；缺帧仍保留序位）。

    `window_id` / `material_id` 缺省取调用方（选材点）给出的**本窗口**身份；
    行内自带时不覆盖——源身份永远优先于调用方默认值。
    """
    image = row.get("frame_bgr")
    height = width = 0
    if isinstance(image, np.ndarray) and image.ndim >= 2:
        height, width = int(image.shape[0]), int(image.shape[1])
    reason = row.get("material_reason")
    if reason not in _MATERIAL_REASONS:
        reason = None
    return SequenceFrame(
        camera_id=window_key[0], run_id=window_key[1],
        config_version=window_key[2],
        window_id=(row.get("window_id")
                   if row.get("window_id") is not None else window_id),
        window_key=tuple(window_key),
        material_id=(row.get("material_id")
                     if row.get("material_id") is not None else material_id),
        frame_id=_frame_id(row.get("frame_id")),
        t_capture_ms=_finite(row.get("t_capture_ms")),
        timestamp_kind=row.get("timestamp_kind"),
        frame_bgr=image if isinstance(image, np.ndarray) else None,
        width=width, height=height, source_width=width, source_height=height,
        downscaled=False, material_reason=reason,
        change_boxes=row.get("change_boxes") or (), change_area=0.0,
        origin="window_material", event_id=row.get("event_id"),
        object_id=row.get("object_id"), track_id=row.get("track_id"),
        bound=bool(row.get("event_id")), observed_mono_ms=None,
        crop_id=row.get("crop_id"))


# ---- 生产调用方助手 --------------------------------------------------------

def observe_window_materials(pool, *, pkg, window_key, output=None,
                             camera=None, harvest_id=None):
    """生产助手：把一窗材料并入事件池（`pool=None` → None，零行为）。

    只读取选材点**可得**的事实（见模块头 §1）；返回 `observe()` 的记录。
    异常一律不外抛（选材失败不得影响既有窗口路径）。

    `window_key=None`（C154 车道 Q F1）：**窗口尚未分配**的观察点——材料
    在窗口调度折叠/丢弃/取消/关闭**之前**被看到，此时它不属于任何窗口。
    身份三元（camera/run/config）仍从材料包取，窗口槽位如实写 `None`
    （不借用别的窗口身份），`harvest_id` 说明来源是取包点。
    """
    if pool is None:
        return None
    camera_id = camera or getattr(pkg, "camera_id", None)
    if window_key is None:
        window_key = (camera_id, getattr(pkg, "run_id", None),
                      getattr(pkg, "config_version", None), None)
    else:
        window_key = tuple(window_key)
    frames = []
    for slot, frame in (("prev", getattr(pkg, "prev", None)),
                        ("cur", getattr(pkg, "cur", None)),
                        ("next", getattr(pkg, "nxt", None))):
        if frame is None:
            continue
        frames.append({
            "slot": slot,
            "frame_id": getattr(frame, "frame_id", None),
            "frame_bgr": getattr(frame, "frame_bgr", None),
            "t_capture_ms": getattr(frame, "t_capture_ms", None),
            "timestamp_kind": getattr(frame, "timestamp_kind", None),
            "material_reason": (getattr(pkg, "material_reason", None)
                                if slot == "cur" else None),
            "change_boxes": getattr(pkg, "change_boxes", None),
        })
    detections = tuple(getattr(pkg, "detections", None) or ())
    object_ids = [f"{camera_id}:{getattr(pkg, 'run_id', None)}:track:"
                  f"{d.get('trackId')}"
                  for d in detections if d.get("trackId") is not None]
    # F3：`detection_count` 只用于无对象原因的细分。材料包显式给出时以它为准
    # （= L1 结论里的检出数），否则按摘出的 detections 计数。它**不参与**
    # 任何准入判定（判定仍看 object_ids 与绑定来源）。包没有 detections
    # 字段（L1 从未有结论）时计数按**未知**记（None），不冒充 0。
    if not hasattr(pkg, "detection_count"):
        detection_count = (len(detections) if hasattr(pkg, "detections")
                           else None)
    else:
        reported = getattr(pkg, "detection_count", None)
        detection_count = None if reported is None else int(reported)
    try:
        return pool.observe(
            camera_id=camera_id, run_id=getattr(pkg, "run_id", None),
            config_version=getattr(pkg, "config_version", None),
            window_key=window_key, window_id=window_key[3],
            material_id=getattr(pkg, "material_id", None), frames=frames,
            object_ids=object_ids,
            frame_time_kind=(getattr(getattr(pkg, "cur", None),
                                     "timestamp_kind", None)),
            material_reason=getattr(pkg, "material_reason", None),
            l1_terminal_reason=getattr(pkg, "l1_terminal_reason", None),
            detection_count=detection_count,
            harvest_id=harvest_id)
    except Exception as exc:                     # 选材不得影响既有路径
        return {"status": "window_only",
                "reason": "observe_failed:{}".format(type(exc).__name__),
                "event_id": None, "object_id": None,
                "window_key": list(window_key), "retained": 0,
                "retained_ids": []}


def primary_frame_rows(pkg, *, window_id=None, material_id=None):
    """材料包 prev/cur/nxt → 主序位帧行（缺帧留序位；**不复制像素**）。

    C155 车道 B（**加法**）：每行多带 `slot`（`prev|cur|nxt`）与 `primary`
    布尔（仅 `cur` 为真），使"主序位帧"在任何调用点都**显式**可指认——
    事件页定位只允许用主帧自身的绑定，绝不借邻帧。旧消费方忽略多出的键。
    """
    rows = []
    for slot, frame in (("prev", getattr(pkg, "prev", None)),
                        ("cur", getattr(pkg, "cur", None)),
                        ("nxt", getattr(pkg, "nxt", None))):
        if frame is None:
            rows.append({"frame_id": None, "frame_bgr": None,
                         "t_capture_ms": None, "timestamp_kind": None,
                         "window_id": window_id, "material_id": material_id,
                         "slot": slot, "primary": slot == "cur"})
            continue
        rows.append({
            "frame_id": getattr(frame, "frame_id", None),
            "frame_bgr": getattr(frame, "frame_bgr", None),
            "t_capture_ms": getattr(frame, "t_capture_ms", None),
            "timestamp_kind": getattr(frame, "timestamp_kind", None),
            "window_id": window_id, "material_id": material_id,
            "material_reason": getattr(pkg, "material_reason", None),
            "change_boxes": getattr(pkg, "change_boxes", None),
            "slot": slot, "primary": slot == "cur",
        })
    return rows
