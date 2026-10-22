"""win11_l3_tasks.py —— L3 材料→任务、结果→可保存结构的统一转换（C-137 §2；
C-138 D1/D2/D4 修订：兜底统一三序位 + branch_key 追加 material 来源段）。

统一转换层（docs/context/C137-接口冻结.md §2；C-138 §1/D1 在其上修订）：
runtime 只消费本模块的转换结果，不再自行读 L3Output 内部字段拼 text。纯
函数、零模型加载、零 I/O、零 cv2——只做数据形状搬运与确定性 prompt 渲染；
不 git、不排队、不调 stage（stage 由调用方驱动）。

tasks_from_package(...)：材料包 + L2Output.l3_branches（C-135
L3BranchSpec，含 crop_id/frame_sequence/region_only）→ 有序 list[L3Task]
（分支顺序保持；一任务一分支）。固定序位 0=前、1=当前、2=后（C-136 C2）：
- 全景分支：pkg.prev/cur/nxt 全景帧（在场帧）；缺帧序位保留、
  L3FrameInput(frame_bgr=None) 显式占位（stage 标注缺失，绝不伪造图像，
  绝不因 continue 丢失序位）；
- 局部关系/变化区域分支：L3BranchSpec.frame_sequence（同区域三帧真实
  切片，C-135 已交付）——每张切片绑定它自己的 frame_id/观察钟时间/时间
  类型；绝不把当前裁图替换到 prev/next 位置沿用其身份；不改写任何已
  构造帧对象绕过只读（L3FrameInput 构造时再拷贝置只读，输入切片与原图
  不受影响）；分支无 frame_sequence 时（旧分支兼容路径）退化为 cur 侧
  裁图 + 前后显式缺位——cur 图按 branch.crop_id 从 crop_images_by_crop_id
  显式映射键取（runtime 按此传参），绝不按列表位置猜；
- 兜底统一三序位（C-138 D1）：branches 为 None/空且 fallback_reason 非
  None → 不经 L2 分支，产出单一全景任务（prev/cur/nxt 固定序位、缺帧
  显式占位；只有 cur 时两翼缺帧显式——模型可描述当前画面，但 prompt/
  presence 如实表明非完整连续过程）；prompt 首行携带兜底原因原样
  （"L1 关系识别不可用（原因：…）"，词表 empty/model_unavailable/
  infer_failed/timeout/l1_wait_timeout/rejected:* 全覆盖，不改写不淡
  化）；关系模型调用为零是调用方职责（本模块纯转换）；
- 材料匹配一律用 crop_id/branch 标识；分支 identity（M1 四元+material_id）
  与材料包不符 → ValueError（不跨材料串线，不静默混料）；
- gate_reason 非 None → 分支任务 prompt 头部携带真实原因标注（兜底任务，
  L1 门控未产出的原因原样进 prompt，不加工）；
- window_id 必填（C-137 §1：来自调度器 WindowHandle.window_id；
  material_id 与 window_id 分开，本模块不以 material_id 冒充窗口身份）；
  任务窗口身份携带 pkg.material_id 附加段（C-138 §1：仅供 branch_key
  来源区分，不参与窗口四元与 stage 身份校验）。

results_from_output(l3_output)：读**真实 L3Output.results** → list[dict]
（JSON 可序列化"可保存结构"）。每条保留：window_key 全四元、branch_key
（window_key+分支+crop_id+material_id，C-138 §1：追加 material 来源段，
同窗多材料包的同区域分支 key 必不相同，存档/摘要并排不互相覆盖）、观察/
推断（text item）、不确定性、sources（帧身份+时间类型+存在性）、model_ref、
缺失信息（缺帧序位/截断/omission 原因）。自由文本 → {"text": 原文,
"unstructured": True, "certainty": "model_inferred"}（C-137 §2；结构化
模型文本同样 model_inferred——与 win11_l4_contract.FUSION_CERTAINTIES 词
表对齐，模型自报 confirmed 不升级）。失败/拒绝分支（C-139 §3 修订）：
结果条目保留已知任务身份事实——crop_id/branch_key（七元含 material 段）/
帧来源/帧时间不清空，观察侧未知字段置 None，reason 携带受控细分码与
omission 原因——禁止只保存空 text+ok 冒充成功；未知状态绝不改写为 ok。

summary_text(out)：给人看的中文一行（供健康面）；确定性渲染、换行折叠、
截断有界，绝不改写文本语义。

分界红线：生产入口禁 fake（本模块不含任何模型路径）；不改 stage 校验
语义（身份校验仍归 L3Stage.window_matches_frame）；L3Task/L3Output 等合
同形状只消费不改造。
"""

from __future__ import annotations

import hashlib
import threading
import time

import numpy as np

from scam.win11_l3_contract import (
    L3BranchKind,
    L3Budget,
    L3FrameIdentity,
    L3FrameInput,
    L3Status,
    L3Task,
    L3WindowIdentity,
)

__all__ = [
    "L3TaskBudgetLedger",
    "L3WindowBudget",
    "branch_key_of",
    "results_from_output",
    "summary_text",
    "tasks_from_package",
    "window_key_of",
]

_SUMMARY_CLIP = 80          # 健康面单行文本截断上限（有界，防长叙述刷屏）

# C153 A：窗口/事件级共享总预算默认档（全景+局部共用一份）。
_WINDOW_MAX_TASKS = 3            # 一窗最多几个任务进模型（全景+局部合计）
_WINDOW_MAX_TOTAL_FRAMES = 6     # 一窗共享总帧预算（≈ 全景 3 + 局部 3）
_WINDOW_MAX_SOURCE_BYTES = 0     # 0=不设限（源字节预算，按实际材料像素计）
_CONTENT_SAMPLE_ROWS = 32        # 指纹采样行数上限（有界：32×W×3 字节/帧）


# ---- 键助手（C-137 §1：window_key / branch_key） ----------------------------

def window_key_of(window):
    """窗口四元 tuple：(camera_id, run_id, config_version, window_id)。"""
    return (window.camera_id, window.run_id, window.config_version,
            window.window_id)


def branch_key_of(window, branch, crop_id):
    """branch_key = window_key + (branch_kind, crop_id 或 region_id,
    material_id)（C-138 §1：追加 material 来源段，键长恒定七元）。

    同窗两个同类型局部裁图凭 crop_id 可区分（C-137 §1）；同窗多材料包时
    同区域分支凭 material 段区分——不同材料的分支 key 必不相同，存档/
    摘要并排不互相覆盖；window 无 material_id（旧形状/未知来源）时该段
    如实 None，不因缺 material 改变键形。"""
    return window_key_of(window) + (_enum_value(branch), crop_id,
                                    getattr(window, "material_id", None))


# ---- C153 A：窗口级共享总预算 + 覆盖账目（计划期，纯函数） ------------------
#
# 目标（C153 §A）：全景与局部（relation_crop/change_region）**共享**一份窗口
# 级任务总预算，而不是每个分支各自拿一份完整预算；合并重复材料时保留
# **来源与覆盖账目**（哪些帧/分支被覆盖、哪些未分析）。
#
# **作用域措辞如实**：预算键是 window_key 四元（camera/run/config/window_id）；
# 生产链路没有**可信 event_id** 进键，因此这里与下游一律称"**窗口级**共享
# 预算"，**不**称"事件级"，也**不**按事件聚合/借预算。
#
# 红线：
# - 身份只取自生产身份字段（camera/run/config/window/material/branch_kind/
#   crop_id + 帧身份/尺寸/采样内容），绝不靠时间邻近或文本相似猜合并；
#   合并键第一段即身份四元 → 跨 camera/run/config/窗口**结构上不可能**合并；
#   **crop_id 进合并键** → 不同 crop（不同对象/区域）绝不因像素相同而合并。
# - 预算只下调不上调：派生 L3Budget 恒 ≤ 传入档；无计划器时行为与旧路径
#   逐字节一致（`budget_ledger=None`）。
# - 状态只在账本对象内；无 I/O、无模型、无线程、无时间依赖（created_mono_ms
#   仍由调用方打点），可重复调用且记账单调。
# - 绝不用"入队数 - 完成数"推导遗漏：本账目只记计划期事实（保留/合并/丢弃/
#   释放），执行期过期与失败仍由 runtime 既有终态码如实给出。
# - 计划额度（plan/release）≠ 执行资源（executor/in-flight，归 stage）≠
#   已执行消费（`L3Output.budget_accounting`，事实账）；三者分列不冲抵。

class L3WindowBudget:
    """窗口/事件级共享预算档（C153 A）。

    与既有 `L3Budget`（单任务档，冻结形状）分开：`L3Budget` 描述"一个任务
    最多用多少"，本类描述"一个窗口总共能用多少"——两者共同决定每任务份额。

    - max_tasks_per_window：本窗最多几个任务进模型（全景+局部合计）。
    - max_frames_per_task：单任务帧上限（与 L3Budget.max_frames_per_task 同义，
      用作派生任务的帧上限）。
    - min_frames_per_task：在预算内单个任务的帧下限；连下限都凑不到 → 该任务
      如实丢弃（reason=branch_below_min_frames），绝不静默少给帧。
    - max_total_frames：**全景+局部共享**的窗口总帧预算（共享的落点）。
    - max_total_pixels：窗口总像素预算；派生单任务档按
      max_total_pixels // max_frames_per_task 折算（≤ 传入档）。
    - max_total_source_bytes：窗口总源字节预算（0=不设限）；按材料帧
      `frame_bgr.nbytes` 实际值计，缺数（None）则不计、不猜。
    - frames_per_branch_floor：参与"保底服务"的分支数下限（保证开始/转折/
      最新这一类身份不会被预算整体饿死）；上限取 max_tasks_per_window。
    """

    __slots__ = ("max_tasks_per_window", "max_frames_per_task",
                 "min_frames_per_task", "max_total_frames",
                 "max_total_pixels", "max_total_source_bytes",
                 "frames_per_branch_floor")

    def __init__(self, max_tasks_per_window=_WINDOW_MAX_TASKS,
                 max_frames_per_task=3, min_frames_per_task=1,
                 max_total_frames=_WINDOW_MAX_TOTAL_FRAMES,
                 max_total_pixels=_WINDOW_MAX_TOTAL_FRAMES * 448 * 448,
                 max_total_source_bytes=_WINDOW_MAX_SOURCE_BYTES,
                 frames_per_branch_floor=1):
        self.max_tasks_per_window = int(max_tasks_per_window)
        self.max_frames_per_task = int(max_frames_per_task)
        self.min_frames_per_task = int(min_frames_per_task)
        self.max_total_frames = int(max_total_frames)
        self.max_total_pixels = int(max_total_pixels)
        self.max_total_source_bytes = int(max_total_source_bytes)
        self.frames_per_branch_floor = int(frames_per_branch_floor)

    def as_dict(self):
        """确定性快照（账目"budget"段；键序冻结）。"""
        return {
            "max_tasks_per_window": self.max_tasks_per_window,
            "max_frames_per_task": self.max_frames_per_task,
            "min_frames_per_task": self.min_frames_per_task,
            "max_total_frames": self.max_total_frames,
            "max_total_pixels": self.max_total_pixels,
            "max_total_source_bytes": self.max_total_source_bytes,
            "frames_per_branch_floor": self.frames_per_branch_floor,
        }


class _LedgerWindow:
    """单窗口账页（账本内部；不外传）。"""

    __slots__ = ("tasks_reserved", "frames_reserved", "bytes_reserved",
                 "reserved_by_index", "coverage")

    def __init__(self, coverage):
        self.tasks_reserved = 0
        self.frames_reserved = 0
        self.bytes_reserved = 0
        self.reserved_by_index = {}
        self.coverage = coverage


class L3TaskBudgetLedger:
    """按 window_key 记账的**共享**预算账本（C153 A；生产接线=默认启用）。

    唯一状态载体：同一账本对象被同一窗口的多次 `plan` 调用复用，因此第二次
    入队（如后续材料包）拿到的是**剩余**预算而不是又一份完整预算——这就是
    "全景与局部共享窗口总预算"的机制本体。

    **作用域如实**：键是 `window_key` 四元（camera/run/config/window_id）。
    生产链路里没有**可信 event_id** 进本键，因此本账本只称"**窗口级**共享
    预算"——不称"事件级"，也不得按事件聚合。

    - 键：window_key 四元（生产身份字段）。不同 window_key 完全隔离；
      同一 key 内按 branch_key 七元（含 material 段）去重与记账。
      → 跨 camera/run/config/窗口/材料**结构上不可能**借预算或合并。
    - 单调：`plan` 只在仍有余额时 reserve；余额耗尽的分支如实 dropped 且
      **不占用**额度（后续仍可服务其它分支）。
    - `release(window_key, task_index)`：调用方在设计丢弃/淘汰时归还**计划
      额度**并记入 coverage["released"]；执行期失败/超时**不**归还（模型已
      消耗）。计划额度 ≠ 执行资源（executor/in-flight）≠ 已执行消费
      （`L3Output.budget_accounting`），三者分列不互相冲抵。
    - `coverage(window_key)`：只读快照（深拷贝，外部改不动账本）；含
      `plan_entries`（逐分支 disposition/reason/plan_seq），供 runtime 做
      "覆盖 ↔ 终态"一一对应结算。
    - `forget(window_key)`：窗口封口后清**活页**（防无界增长），快照转存
      有界"已封口"表：**同一 window_key 再 plan 不得获得第二份预算**
      （窗口 id 在调度器存续期单调，同键重现=重放），且 `coverage()` 仍可
      读到封口时的账目（归属不丢）。
    - 线程安全（内部锁）；不做任何 I/O/模型/排队/线程/时钟操作。
    """

    _FORGOTTEN_CAP = 64          # 已封口窗口快照上限（有界，LRU 淘汰）

    def __init__(self, budget=None):
        self.budget = budget if budget is not None else L3WindowBudget()
        self._lock = threading.Lock()
        self._windows = {}
        self._forgotten = {}
        self._plan_seq = 0

    # -- 查询 ----------------------------------------------------------------

    def coverage(self, window_key):
        """覆盖账目只读快照；未登记窗口 → None（不编造零账目）。

        已 `forget` 的窗口仍返回**封口时**的快照（归属与账目不因清活页而
        丢失）；只有从未登记过的键才返回 None。"""
        key = tuple(window_key)
        with self._lock:
            entry = self._windows.get(key)
            if entry is not None:
                return _copy_coverage(entry.coverage)
            frozen = self._forgotten.get(key)
            return None if frozen is None else _copy_coverage(frozen)

    def is_settled(self, window_key):
        """该窗口是否已封口（`forget` 过）；未登记 → False。"""
        key = tuple(window_key)
        with self._lock:
            return key in self._forgotten

    def plan_entries(self, window_key):
        """逐分支计划账目（含 disposition/reason/plan_seq）；无 → ()。"""
        cov = self.coverage(window_key)
        if cov is None:
            return ()
        return tuple(cov.get("plan_entries", ()))

    def window_keys(self):
        """已登记窗口键（含已封口；确定性升序，str 化比较；诊断用）。"""
        with self._lock:
            keys = set(self._windows) | set(self._forgotten)
            return tuple(sorted(keys, key=lambda k: tuple(
                str(part) for part in k)))

    # -- 记账 ----------------------------------------------------------------

    def plan(self, *, window_key, pkg, branches, task_budget=None,
             branch_kinds=None, crop_ids=None, material_id=None,
             positions=None, byte_sizes=None, frames_by_index=None):
        """共享预算判定 + 预留（纯内存；返回计划 dict，形状见 INTERFACE-A §3）。

        参数：
        - window_key：四元生产身份（camera/run/config/window）。
        - pkg：材料包（只读消费 camera/run/config/material 与帧，用于指纹）。
        - branches：`L2Output.l3_branches` 同形序列（与 tasks_from_package 同源）。
        - task_budget：调用方档位（None=只按窗口共享档判定）。
        - positions / byte_sizes：由调用方给出的逐分支帧形状提示（可选；
          缺省从 branches 的 frame_sequence/identity 推导）。
        - frames_by_index：逐分支**实际将进任务**的帧序（可选；`tasks_from
          _package` 传入已构造帧，保证"计划所测=任务所用"，指纹与可分析帧
          数不因二次推导而失真）。
        """
        key = tuple(window_key)
        rows = _branch_rows(pkg, branches, window_key=key,
                            branch_kinds=branch_kinds,
                            crop_ids=crop_ids, material_id=material_id,
                            positions=positions, byte_sizes=byte_sizes,
                            frames_by_index=frames_by_index)
        budget = self.budget
        cap_tasks = max(1, int(budget.max_tasks_per_window))
        cap_frames = max(1, int(budget.max_total_frames))
        cap_bytes = int(budget.max_total_source_bytes)
        floor_branches = max(1, min(int(budget.frames_per_branch_floor),
                                    cap_tasks))

        with self._lock:
            frozen = self._forgotten.get(key)
            if frozen is not None:
                # 已封口窗口的**重放**：绝不发第二份预算（窗口 id 在调度器
                # 存续期单调，同键重现只能是重放/重复提交）。逐分支如实
                # dropped + 受控原因；不 reserve、不改封口快照。
                entries = tuple({
                    "index": row["index"],
                    "branch_key": list(row["branch_key"]),
                    "branch_kind": row["branch_kind_value"],
                    "crop_id": row["crop_id"],
                    "material_id": row["material_id"],
                    "frames_available": row["frames_available"],
                    "frames_present": row["frames_present"],
                    "disposition": "dropped",
                    "reason": "window_budget_window_settled",
                    "fingerprint_short": row["fingerprint_short"],
                    "fingerprint_identity_complete": row[
                        "fingerprint_identity_complete"],
                } for row in rows)
                return {"window_key": list(key), "kept": (),
                        "entries": entries,
                        "coverage": _copy_coverage(frozen),
                        "positions": {row["index"]: row["positions"]
                                      for row in rows}}
            entry = self._windows.get(key)
            if entry is None:
                entry = _LedgerWindow(_empty_coverage(key, budget))
                self._windows[key] = entry
            cov = entry.coverage
            self._plan_seq += 1
            plan_seq = self._plan_seq
            cov["branches_total"] = (cov["branches_total"] + len(rows))
            cov["frames_available"] += sum(r["frames_available"] for r in rows)
            cov["source_bytes_available"] += sum(
                r["frame_bgr_nbytes"] or 0 for r in rows)

            kept = []
            entries = []
            # 合并判定与预算判定分开：先分组（身份内），再按顺序分配额度。
            for row, disposition, reason, into in _group_rows(
                    rows, entry.coverage):
                index = row["index"]
                bkey = row["branch_key"]
                entry_row = {
                    "index": index,
                    "plan_seq": plan_seq,
                    "branch_key": list(bkey),
                    "branch_kind": row["branch_kind_value"],
                    "crop_id": row["crop_id"],
                    "material_id": row["material_id"],
                    "frames_available": row["frames_available"],
                    "frames_present": row["frames_present"],
                    "disposition": disposition,
                    "reason": reason,
                    "fingerprint_short": row["fingerprint_short"],
                    "fingerprint_identity_complete": row[
                        "fingerprint_identity_complete"],
                }
                if into is not None:
                    entry_row["merged_into"] = into["index"]
                    entry_row["merged_into_branch_key"] = list(
                        into["branch_key"])
                if disposition != "keep":
                    entries.append(entry_row)
                    cov["plan_entries"].append(entry_row)
                    continue
                remaining_tasks = cap_tasks - entry.tasks_reserved
                remaining_frames = cap_frames - entry.frames_reserved
                remaining_bytes = ((cap_bytes - entry.bytes_reserved)
                                   if cap_bytes > 0 else None)
                needed = max(0, row["frames_available"])
                granted = _grant_frames(
                    needed, remaining_frames,
                    max(0, int(budget.max_frames_per_task)),
                    max(1, int(budget.min_frames_per_task)),
                    max(0, remaining_tasks), floor_branches,
                    entry.tasks_reserved,
                    remaining_bytes, row["frame_bgr_nbytes"])
                if granted == 0:
                    entry_row["disposition"] = "dropped"
                    entry_row["reason"] = _budget_reason(
                        remaining_tasks, remaining_frames, remaining_bytes,
                        needed, int(budget.min_frames_per_task))
                    entries.append(entry_row)
                    cov["plan_entries"].append(entry_row)
                    continue
                task_b = _derive_task_budget(task_budget, granted, budget)
                entry.tasks_reserved += 1
                entry.frames_reserved += granted
                reserved_bytes = ((row["frame_bgr_nbytes"] or 0)
                                  if granted == needed else 0)
                entry.bytes_reserved += reserved_bytes
                entry.reserved_by_index[index] = (granted, reserved_bytes)
                entry_row["disposition"] = "keep"
                entry_row["reason"] = "ok"
                entry_row["frames_reserved"] = granted
                entries.append(entry_row)
                cov["plan_entries"].append(entry_row)
                kept.append({"index": index, "budget": task_b,
                             "frames_reserved": granted,
                             "bytes_reserved": reserved_bytes})

            cov["branches_kept"] += len(kept)
            cov["branches_merged"] += sum(
                1 for row in entries if row["disposition"] == "merged_into")
            cov["branches_dropped"] += sum(
                1 for row in entries if row["disposition"] == "dropped")
            cov["tasks_reserved"] = entry.tasks_reserved
            cov["frames_reserved"] = entry.frames_reserved
            cov["source_bytes_reserved"] = entry.bytes_reserved
            for row in entries:
                if row["disposition"] == "merged_into":
                    cov["merged"].append({
                        "branch_index": row["index"],
                        "branch_key": list(row["branch_key"]),
                        "into_index": row["merged_into"],
                        "into_branch_key": list(
                            row["merged_into_branch_key"]),
                        "reason": row["reason"]})
                elif row["disposition"] == "dropped":
                    cov["dropped"].append({
                        "branch_index": row["index"],
                        "branch_key": list(row["branch_key"]),
                        "frames_available": row["frames_available"],
                        "reason": row["reason"]})
            for row in rows:
                if row["branch_kind_value"] not in _KNOWN_BRANCH_KINDS:
                    seen_kinds = cov["unknown_branch_kinds"]
                    if row["branch_kind_value"] not in seen_kinds:
                        seen_kinds.append(row["branch_kind_value"])
            snapshot = _copy_coverage(cov)
        return {"window_key": list(key), "kept": tuple(kept),
                "entries": tuple(entries), "coverage": snapshot,
                "positions": {row["index"]: row["positions"] for row in rows}}

    def release(self, window_key, task_index, reason="caller_released"):
        """归还某任务的**计划额度**（调用方在设计丢弃/淘汰时调用）。

        语义边界（C153-R1 裁定 §2，三者分清）：
        - 本方法只动**计划额度**（plan/release 的 reserve 账）；
        - **执行资源**（executor 槽位 / in-flight gauge）归 stage，本方法不碰；
        - **已执行消费**（`L3Output.budget_accounting`）是事实账，本方法不冲抵。
        执行期失败/超时**不归还**（模型已消耗，绝不粉饰）。返回是否确有额度
        可归还（False=该任务从未预留、已归还或窗口已封口）。
        """
        key = tuple(window_key)
        with self._lock:
            entry = self._windows.get(key)
            if entry is None:
                return False
            reserved = entry.reserved_by_index.pop(task_index, None)
            if reserved is None:
                return False
            granted, reserved_bytes = reserved
            entry.tasks_reserved = max(0, entry.tasks_reserved - 1)
            entry.frames_reserved = max(0, entry.frames_reserved - granted)
            entry.bytes_reserved = max(0,
                                       entry.bytes_reserved - reserved_bytes)
            entry.coverage["released"].append({
                "branch_index": task_index,
                "frames_released": granted,
                "bytes_released": reserved_bytes,
                "reason": reason})
            entry.coverage["tasks_reserved"] = entry.tasks_reserved
            entry.coverage["frames_reserved"] = entry.frames_reserved
            entry.coverage["source_bytes_reserved"] = entry.bytes_reserved
            return True

    def forget(self, window_key):
        """窗口封口后清**活页**（防无界增长）；返回封口时的账目快照或 None。

        快照转存有界"已封口"表（LRU 上限 `_FORGOTTEN_CAP`）：`coverage()` 仍
        可读到，**归属不丢**；但同一 window_key 再 `plan` **不得获得第二份
        预算**（见 `plan` 的已封口分支）。
        """
        key = tuple(window_key)
        with self._lock:
            entry = self._windows.pop(key, None)
            if entry is None:
                return self._forgotten.get(key)
            snapshot = _copy_coverage(entry.coverage)
            self._forgotten[key] = snapshot
            while len(self._forgotten) > self._FORGOTTEN_CAP:
                self._forgotten.pop(next(iter(self._forgotten)))
            return _copy_coverage(snapshot)


def _empty_coverage(window_key, budget):
    return {
        "window_key": list(window_key),
        "branches_total": 0,
        "branches_kept": 0,
        "branches_merged": 0,
        "branches_dropped": 0,
        "tasks_reserved": 0,
        "frames_available": 0,
        "frames_reserved": 0,
        "source_bytes_available": 0,
        "source_bytes_reserved": 0,
        "merged": [],
        "dropped": [],
        "released": [],
        "plan_entries": [],
        "unknown_branch_kinds": [],
        "budget": budget.as_dict(),
    }


def _copy_coverage(cov):
    """账目深拷贝（只读外传；外部改不动账本）。"""
    out = {key: value for key, value in cov.items()
           if key not in ("merged", "dropped", "released", "plan_entries",
                          "unknown_branch_kinds", "budget", "window_key")}
    out["window_key"] = list(cov["window_key"])
    out["unknown_branch_kinds"] = list(cov["unknown_branch_kinds"])
    out["budget"] = dict(cov["budget"])
    for name in ("merged", "dropped", "released", "plan_entries"):
        out[name] = [dict(row) for row in cov.get(name, ())]
        for row in out[name]:
            for key in ("branch_key", "into_branch_key",
                        "merged_into_branch_key"):
                if key in row:
                    row[key] = list(row[key])
    return out


_KNOWN_BRANCH_KINDS = frozenset(kind.value for kind in L3BranchKind)
_KNOWN_BRANCH_KIND_ENUM = {kind.value: kind for kind in L3BranchKind}


def _grant_frames(needed, remaining_frames, per_task_cap, min_frames,
                  remaining_tasks, floor_branches, tasks_reserved,
                  remaining_bytes, frame_bytes):
    """本任务可得帧数（0=放弃；绝不超卖；字节预算不足 → 0）。"""
    if remaining_tasks <= 0 or needed <= 0:
        return 0
    granted = min(needed, per_task_cap, remaining_frames)
    if granted < min_frames and tasks_reserved >= floor_branches:
        return 0                      # 保底分支已服务，差额不再凑
    if granted <= 0:
        return 0
    if remaining_bytes is not None and frame_bytes:
        cost = frame_bytes if granted == needed else 0
        if cost > remaining_bytes:
            return 0
    return granted


def _budget_reason(remaining_tasks, remaining_frames, remaining_bytes,
                   needed, min_frames):
    """拒绝原因受控词表（确定性优先序；绝不发散字符串）。"""
    if remaining_tasks <= 0:
        return "window_budget_tasks_exhausted"
    if needed < min_frames:
        return "branch_below_min_frames"
    if remaining_bytes is not None and remaining_bytes <= 0:
        return "window_budget_bytes_exhausted"
    if remaining_frames <= 0:
        return "window_budget_frames_exhausted"
    return "window_budget_frames_exhausted"


def _derive_task_budget(task_budget, granted_frames, window_budget):
    """派生单任务档：只下调——帧/像素/并发取与传入档的更小者。"""
    frames = int(granted_frames)
    pixels = max(1, int(window_budget.max_total_pixels)
                 // max(1, int(window_budget.max_frames_per_task)))
    if task_budget is None:
        return L3Budget(max_frames_per_task=frames, max_total_pixels=pixels)
    return L3Budget(
        max_frames_per_task=min(frames,
                                int(task_budget.max_frames_per_task)),
        max_total_pixels=min(pixels, int(task_budget.max_total_pixels)),
        max_queue=int(task_budget.max_queue),
        in_flight=int(task_budget.in_flight),
        concurrency=int(task_budget.concurrency))


def _branch_rows(pkg, branches, *, window_key, branch_kinds=None,
                 crop_ids=None, material_id=None, positions=None,
                 byte_sizes=None, frames_by_index=None):
    """分支 → 计划行（身份 + 形状 + 内容指纹）；身份字段全部来自生产数据。

    `window_key` 由调用方显式给出（四元生产身份）——材料包本身只有
    material_id、没有 window_id，绝不拿 material_id 冒充窗口身份（C-137 §1）。
    `frames_by_index`（可选）优先于分支自身形状：调用方给出"实际将进任务
    的帧"，保证计划所测=任务所用（指纹/可分析帧数不因二次推导失真）。
    """
    kind_defaults = (None if branch_kinds is None
                     else {int(i): kind
                           for i, kind in enumerate(branch_kinds)})
    crop_defaults = (None if crop_ids is None
                     else {int(i): cid for i, cid in enumerate(crop_ids)})
    pos_defaults = (None if positions is None
                    else {int(i): tuple(pos)
                          for i, pos in enumerate(positions)})
    size_defaults = (None if byte_sizes is None
                     else {int(i): size for i, size in enumerate(byte_sizes)})
    pkg_material = getattr(pkg, "material_id", None)
    rows = []
    for index, branch in enumerate(tuple(branches or ())):
        kind_raw = (kind_defaults.get(index) if kind_defaults is not None
                    else getattr(branch, "branch_kind", None))
        if isinstance(kind_raw, L3BranchKind):
            kind_value = kind_raw.value
        else:
            kind_value = _enum_value(kind_raw)
        crop_id = (crop_defaults.get(index) if crop_defaults is not None
                   else getattr(branch, "crop_id", None))
        if material_id is not None:
            mat = material_id
        else:
            ident = getattr(branch, "identity", None)
            mat = (getattr(ident, "material_id", None)
                   if ident is not None else None)
            if mat is None:
                mat = pkg_material
        seq = tuple(getattr(branch, "frame_sequence", None) or ())
        if frames_by_index is not None and index in frames_by_index:
            frames = tuple(frames_by_index[index])
        elif seq:
            # frame_sequence 可能是 L2LocalFrameSlice（带显式 position）或已
            # 构造好的 L3FrameInput（序位标签已并入 identity，无 position
            # 属性）——后者保持给定顺序，绝不按不存在的位置字段排序。
            if all(getattr(sl, "position", None) is not None for sl in seq):
                frames = tuple(sorted(seq, key=lambda s: s.position))
            else:
                frames = seq
        else:
            frames = _frames_from_package(pkg, branch)
        if (frames_by_index is None or index not in frames_by_index) \
                and pos_defaults is not None and index in pos_defaults:
            stated = pos_defaults[index]
            frames = tuple(
                _positioned(stated[i] if i < len(stated) else None, fr)
                for i, fr in enumerate(frames))
        positions_list = [int(getattr(fr, "position", i))
                          for i, fr in enumerate(frames)]
        # 预算按**可分析帧**计：像素在手（`frame_bgr is not None`；L3FrameInput
        # 形状没有 present 字段，present 只作补充）。缺帧占位不消耗预算，
        # 也不冒充"能分析的帧"；presence 另计，供外显与对账。
        analyzable = 0
        present_count = 0
        for fr in frames:
            has_pixels = _has_pixels(fr)
            if has_pixels or getattr(fr, "present", False):
                present_count += 1
            if has_pixels:
                analyzable += 1
        frame_bytes = _frame_bytes(frames)
        byte_size = (size_defaults.get(index) if size_defaults is not None
                     else None)
        row = {
            "index": index,
            "branch_kind": (_KNOWN_BRANCH_KIND_ENUM.get(kind_value)
                            or kind_value),
            "branch_kind_value": kind_value,
            "crop_id": crop_id,
            "material_id": mat,
            "branch_key": tuple(window_key) + (kind_value, crop_id, mat),
            "frames": frames,
            "positions": positions_list,
            "frames_available": analyzable,
            "frames_present": present_count,
            "frame_bgr_nbytes": (int(byte_size) if byte_size is not None
                                 else frame_bytes),
            "fingerprint": None,
            "fingerprint_short": None,
            "_identity": (str(getattr(pkg, "camera_id", None)),
                          str(getattr(pkg, "run_id", None)),
                          str(getattr(pkg, "config_version", None)),
                          str(mat)),
        }
        fingerprint, identity_complete = _content_scope_fingerprint(
            kind_value, crop_id, frames)
        row["fingerprint"] = fingerprint
        row["fingerprint_short"] = (fingerprint[:12]
                                    if fingerprint is not None else None)
        row["fingerprint_identity_complete"] = identity_complete
        rows.append(row)
    return rows


class _PositionedFrame:
    """预算形状用的原位次视图（不复制像素，只带显式序位与帧身份）。

    只有在调用方显式给出 positions 提示时才使用；序位未知（None）时计划器
    退回枚举下标（如实，不假装知道语义序位）。
    """

    __slots__ = ("position", "present", "frame_bgr", "frame_id")

    def __init__(self, position, frame_id, present, frame_bgr):
        self.position = position
        self.frame_id = frame_id
        self.present = present
        self.frame_bgr = frame_bgr


def _positioned(position, frame):
    """(显式序位, 真实帧) → 形状视图（帧身份/像素原样透传）。"""
    if position is None:
        position = getattr(frame, "position", None)
    ident = getattr(frame, "identity", None)
    if ident is None:
        ident = _LegacyFrameIdentity(getattr(frame, "frame_id", None))
    elif getattr(ident, "frame_id", None) is None:
        ident = _LegacyFrameIdentity(getattr(frame, "frame_id", None))
    return _PositionedFrame(
        position=(-1 if position is None else int(position)),
        frame_id=ident,
        present=getattr(frame, "present", True)
        and getattr(frame, "frame_bgr", None) is not None,
        frame_bgr=getattr(frame, "frame_bgr", None))


class _LegacyFrameIdentity:
    """旧切片（只带 frame_id）的身份视图——字段真缺时如实 None。"""

    __slots__ = ("camera_id", "run_id", "config_version", "frame_id",
                 "t_capture_ms", "timestamp_kind")

    def __init__(self, frame_id):
        self.camera_id = None
        self.run_id = None
        self.config_version = None
        self.frame_id = frame_id
        self.t_capture_ms = None
        self.timestamp_kind = None


class _PackageFrame:
    """材料包单帧的只读计划视图（prev/cur/nxt 定序位）。"""

    __slots__ = ("position", "present", "frame_bgr")

    def __init__(self, position, present, frame_bgr):
        self.position = position
        self.present = present
        self.frame_bgr = frame_bgr


def _frames_from_package(pkg, branch):
    """分支无 frame_sequence（旧形状）→ 从材料包推导形状（不取像素副本）。

    形状与 `tasks_from_package` 的旧分支兼容路径一致：cur 位 + 前后显式缺位。
    cur 位携带分支身份的真实帧身份（camera/run/config/frame_id/时间），缺帧
    序位如实无身份——绝不把 cur 的身份挪到缺帧序位上。
    """
    ident = getattr(branch, "identity", None)
    cur_identity = None
    if ident is not None and getattr(ident, "frame_id", None) is not None:
        cur_identity = _LocalFrameIdentity(
            camera_id=getattr(ident, "camera_id", None),
            run_id=getattr(ident, "run_id", None),
            config_version=getattr(ident, "config_version", None),
            frame_id=ident.frame_id,
            t_capture_ms=getattr(ident, "t_capture_ms", None),
            timestamp_kind=getattr(ident, "timestamp_kind", None))
    cur = getattr(pkg, "cur", None)
    return (_PackageFrame(0, False, None, None),
            _PackageFrame(1, cur is not None,
                          getattr(cur, "frame_bgr", None), cur_identity),
            _PackageFrame(2, False, None, None))


class _PackageFrame:
    """材料包单帧的只读计划视图（prev/cur/nxt 定序位）。"""

    __slots__ = ("position", "present", "frame_bgr", "identity")

    def __init__(self, position, present, frame_bgr, identity=None):
        self.position = position
        self.present = present
        self.frame_bgr = frame_bgr
        self.identity = identity


class _LocalFrameIdentity:
    """分支身份派生的帧身份视图（旧形状帧用；缺项如实 None）。"""

    __slots__ = ("camera_id", "run_id", "config_version", "frame_id",
                 "t_capture_ms", "timestamp_kind")

    def __init__(self, camera_id, run_id, config_version, frame_id,
                 t_capture_ms=None, timestamp_kind=None):
        self.camera_id = camera_id
        self.run_id = run_id
        self.config_version = config_version
        self.frame_id = frame_id
        self.t_capture_ms = t_capture_ms
        self.timestamp_kind = timestamp_kind


def _frame_bytes(frames):
    """帧像素字节合计（BGR 3 通道）。

    像素不在手时用帧声明的原图尺寸（width/height，真实元数据）折算——绝不
    用"未知"充当 0 字节；两处都缺 → None（不猜）。"""
    total = 0
    seen = False
    for fr in frames:
        arr = getattr(fr, "frame_bgr", None)
        if arr is not None:
            nbytes = getattr(arr, "nbytes", None)
            if nbytes is None:
                return None
            total += int(nbytes)
            seen = True
            continue
        width = getattr(fr, "width", None)
        height = getattr(fr, "height", None)
        if width and height:
            total += int(width) * int(height) * 3
            seen = True
    return total if seen else None


def _has_pixels(frame):
    """帧是否有可用像素（内容权威口径）。

    `frame_bgr is not None` 即内容在手——`L3FrameInput`（生产任务帧形状）
    根本没有 `present` 字段，因此**绝不**用 `present` 当内容判据；旧切片
    形状两者一致时互为印证。"""
    arr = getattr(frame, "frame_bgr", None)
    if arr is None:
        return False
    return bool(getattr(arr, "shape", ()))


def _content_scope_fingerprint(kind_value, crop_id, frames):
    """身份内的内容指纹（None=内容完全不可得 → 绝不参与合并）。

    指纹输入全是**内容**事实：逐序位在场性、帧身份（有则入摘要）、原图尺寸与
    **实际像素采样**（对只读 ndarray 按固定行距取 32 行，绝不是尺寸猜内容）。
    分支种类与 crop_id **不进指纹**——它们是合并键的前几段，进指纹反而会让
    "同一份材料被两个 crop 键表达"永远合并不掉。

    帧身份缺失时**不再一票否决**（旧 L2 局部切片只带 frame_id、没有
    camera/run/config）：只要像素在手就给指纹——绝不因为缺标签就丢掉可分析
    材料（标签缺失如实记入 `fingerprint_identity_complete`）。全无像素 →
    None（内容未知不猜）。
    """
    digest = hashlib.sha256()
    complete = False
    identity_complete = True
    for fr in frames:
        position = int(getattr(fr, "position", -1))
        has_pixels = _has_pixels(fr)
        digest.update("pos={};present={}\n".format(
            position, has_pixels).encode("utf-8"))
        if not has_pixels:
            continue
        ident = getattr(fr, "identity", None)
        if ident is None:
            ident = getattr(fr, "frame_id", None)
        text = None if ident is None else _identity_digest_text(ident)
        if text is None or text == "None|None|None|None":
            identity_complete = False
        else:
            digest.update("ident={}\n".format(text).encode("utf-8"))
        arr = getattr(fr, "frame_bgr", None)
        try:
            shape = tuple(int(v) for v in arr.shape)
            sample = np.ascontiguousarray(
                arr[::max(1, shape[0] // _CONTENT_SAMPLE_ROWS)])
        except Exception:
            return None, False               # 无法确定性采样 → 不参与合并
        digest.update("shape={}\n".format(shape).encode("utf-8"))
        digest.update(np.ascontiguousarray(sample).tobytes())
        complete = True
    if not complete:
        return None, False                   # 全缺帧/无像素 → 内容未知
    return digest.hexdigest(), identity_complete


def _identity_digest_text(ident):
    """帧身份的确定性摘要文本（对象形态或字符串都接受）。"""
    if isinstance(ident, str):
        return ident
    return "{}|{}|{}|{}".format(
        getattr(ident, "camera_id", None), getattr(ident, "run_id", None),
        getattr(ident, "config_version", None),
        getattr(ident, "frame_id", None))


def _group_rows(rows, coverage):
    """身份内合并判定：**完全相同任务身份与来源**才并入先到者。

    合并键（必须全同，缺一段都不算同身份）：
    `(身份四元, material, 分支种类, crop_id, 内容指纹, 序位形状)`。

    返回 (row, disposition, reason, into)；`into`=被复用的先到者行（不重跑
    推理），reason 恒受控码 `merged_same_identity_fingerprint`。

    红线（C153-R1 裁定 §1）：
    - **不同 crop_id 绝不合并**：crop_id 是"这份材料是哪个对象/区域"的任务
      身份段，像素/`frame_id`/内容 hash 相同**不构成**合并理由（两个 crop 在
      业务上可代表不同对象）。因此 crop_id 进合并键。
    - 身份四元是合并键第一段——跨 camera/run/config/**结构上不可能**合并；
      不同 material（材料包来源）同样不可能合并（material 进身份段）。
    - 指纹为 None（内容未知）一律不合并。
    - **归属分支**=分支种类（全景/关系裁图/变化区域）：不同归属分支**绝不
      合并**（语义角色不同，合并会丢角色）。
    - 本函数**只看单次调用内的行**；跨 camera/run/config/窗口的预算隔离由
      账本键（window_key 四元）保证，不靠这里。
    """
    groups = {}
    out = []
    for row in rows:
        key = None
        if row["fingerprint"] is not None:
            key = (row["_identity"], row["branch_kind_value"], row["crop_id"],
                   row["fingerprint"], tuple(row["positions"]))
        target = groups.get(key) if key is not None else None
        if target is not None and target["fingerprint"] == row["fingerprint"]:
            out.append((row, "merged_into",
                        "merged_same_identity_fingerprint", target))
            continue
        if key is not None:
            groups[key] = row
        out.append((row, "keep", "ok", None))
    return out


# ---- C1：材料包 + L2 分支 → L3 任务 -----------------------------------------

def tasks_from_package(*, pkg, branches=None, crop_images_by_crop_id=None,
                       vocabulary_id=None, vocabulary=(), budget=None,
                       window_id=None, gate_reason=None,
                       fallback_reason=None, budget_ledger=None,
                       plan_out=None, carried_frames=(),
                       carried_limit=None, carried_reason=None,
                       plan_frames=None, plan_event_key=None,
                       material_selection_out=None):
    """材料包 + L2Output.l3_branches → 有序 list[L3Task]（纯转换）。

    参数：
    - pkg：MaterialPackage（prev/cur/nxt 帧；cur 必有，缺帧显式 None）。
    - branches：L2Output.l3_branches（L3BranchSpec 元组；顺序=输出任务顺
      序）。None/空且 fallback_reason 为 None → 返回 []（无分支无兜底=
      无任务）。
    - fallback_reason（C-138 D1）：非 None → 兜底统一三序位模式——不经
      L2 分支，产出单一全景任务（prev/cur/nxt 固定序位、缺帧显式占位），
      prompt 首行携带该原因原样（"L1 关系识别不可用（原因：…）"）。与
      非空 branches 互斥（兜底无 L2 分支；混传即接线缺陷 → ValueError）。
      词表 empty/model_unavailable/infer_failed/timeout/l1_wait_timeout/
      rejected:* 全部原样透传，不改写不淡化。
    - crop_images_by_crop_id：dict[crop_id, image]——runtime 按此传参；
      仅在分支无 frame_sequence 时作为 cur 侧裁图来源（显式键匹配）。
    - vocabulary_id / vocabulary：L2 词表标识与关系词表（渲染进 prompt）。
    - budget：L3Budget 档位（None=交由 stage 构造档，合同允许）。
    - window_id：调度器 WindowHandle.window_id（必填；不以 material_id 冒充）。
    - gate_reason：L1 门控未产出的真实原因（None=正常任务；非 None=分支
      任务 prompt 头部标注；仅修饰 branches 任务，branches 空时仍无任务
      ——兜底必须显式走 fallback_reason）。
    - budget_ledger（C153 A）：`L3TaskBudgetLedger` 或 None。None（默认）
      → 行为与旧路径**逐字节一致**（无计划/合并/预算下调）。非 None →
      在身份校验之后、构造任务之前按**窗口共享总预算**判定：只为
      disposition=keep 的分支构造任务，并把派生（只下调）的 L3Budget 放进
      `task.budget`；被合并（同身份同内容指纹）/被预算丢弃的分支如实进
      账本 coverage（哪些被覆盖、哪些未分析），绝不静默丢。
    - plan_out（C153-R1 §2 接线用，可选）：传入 list 时把本次 `plan` 的完整
      计划 dict 追加进去（`kept` 与返回任务**同序**）。runtime 据此把每个
      任务的**计划分支下标**绑定到入队上下文，供设计丢弃/淘汰时精确
      `release(window_key, plan_index)`（只归还该任务自己的计划额度）。
    - carried_frames（C154 车道 G，可选）：同事件跨窗保留帧
      （`win11_event_materials.SequenceFrame` 序列；空=旧路径逐字节一致）。
      只作用于**全景分支**：与本窗主序位帧合并成一条有序序列（去重、按观察
      钟升序、每个任务帧数 ≤ carried_limit），首个=开始、末个=最新；
      每帧身份、时间、时基、来源窗口原样保留。
    - carried_limit（可选）：合并后单任务帧数上限（缺省=不裁剪，交由共享
      预算账本派生档与 stage 预算选择处理）。
    - carried_reason（可选）：本窗 L1 材料触发原因
      （`change_start|latest|patrol`）——是本窗主序位帧的**来源事实**，
      用于 `turn_basis`（不得编造）。
    - plan_frames（可选）：None 为独立旧路径；显式序列为事件计划，
      空序列拒绝。事件计划必须同时传 FramePlan.event_key 为 plan_event_key，
      不从帧反推权威事件键。以下为 aggregated 计划的帧集：
      （`win11_event_materials.SequenceFrame` 序列，已去重、已时序、已
      限幅）——事件汇聚任务与选材计划**同源**：全景帧直接取自该帧集的
      **自身严格绑定子集**（`bound` 且 event/object 身份齐备；保序、不
      重合并、不补本窗三序位），已绑定转折帧因此必然保留；预算裁剪只能
      得到该帧集的子集，绝不替换为计划外未绑定帧。未绑定上下文不入事件
      任务（独立 unassociated 路径承载）。与 `carried_frames` 互斥（同时
      非空 → ValueError）；子集为空 → ValueError（aggregated 不变式）。
    - material_selection_out（C154，可选）：可调用对象；仅在**构造出任务
      之后**被调用一次，参数是「声明保留 ↔ 实际送入模型」对齐账目
      `{"schema","frames":[逐帧身份+角色+turning_positions_source],
      "turning_positions", "turning_positions_source", "sent_frame_ids",
      "roles"}`——由本模块用**真实构造出的帧序**生成，用于断言
      "送入模型的帧集合 = 声明的开始/转折/最新"，不是日志宣称。

    分支 identity 与材料包身份（M1 四元+material_id）不符、分支标签未知、
    window_id 缺失 → ValueError（接线缺陷当场暴露，不静默混料/丢分支）。
    产出任务的窗口身份携带 pkg.material_id 附加段（C-138 §1：仅供
    branch_key 来源区分；window_key 恒四元，stage 三元校验不含 material）。
    """
    if pkg is None:
        raise ValueError("tasks_from_package: pkg is required")
    if window_id is None:
        raise ValueError(
            "tasks_from_package: window_id is required (C-137 §1："
            "window_id 来自调度器 WindowHandle，不得以 material_id 冒充)")
    branch_list = tuple(branches or ())
    carried_frames = tuple(carried_frames or ())
    # None means independent/window-only; an explicitly empty event plan is
    # still an event plan and must never fall back to unbound package pixels.
    plan_frames = None if plan_frames is None else tuple(plan_frames)
    if plan_frames is not None and carried_frames:
        raise ValueError(
            "tasks_from_package: plan_frames 与 carried_frames 互斥"
            "（C155-R1：事件汇聚任务同源取计划帧集，不再二次合并本窗"
            "三序位与跨窗帧；混传即接线缺陷）")
    if fallback_reason is not None:
        if plan_frames is not None or plan_event_key is not None:
            raise ValueError("tasks_from_package: fallback cannot ignore event plan")
        if branch_list:
            raise ValueError(
                "tasks_from_package: fallback_reason 与非空 branches 互斥"
                "（兜底转换不经 L2 分支，混传即接线缺陷）")
        task = _fallback_task(pkg, window_id=window_id,
                              fallback_reason=fallback_reason,
                              vocabulary_id=vocabulary_id,
                              vocabulary=vocabulary, budget=budget)
        if budget_ledger is None:
            return [task]
        return _planned_tasks(pkg, task.window,
                              [(task.branch, task.frames, task.prompt,
                                task.crop_id)],
                              budget_ledger, budget=budget,
                              plan_out=plan_out)
    crop_map = (crop_images_by_crop_id
                if crop_images_by_crop_id is not None else {})
    window = L3WindowIdentity(pkg.camera_id, pkg.run_id, pkg.config_version,
                              window_id, pkg.material_id)
    prepared = []          # [(kind, frames, prompt, crop_id)]，顺序=分支顺序
    rejected = []
    selection_callback = material_selection_out
    if selection_callback is not None:
        def material_selection_out(record):
            record["rejected_branches"] = list(rejected)
            selection_callback(record)
    for branch in branch_list:
        kind = L3BranchKind(branch.branch_kind)   # 未知标签→ValueError
        _check_branch_identity(pkg, branch)
        if kind is L3BranchKind.PANORAMA:
            frames = _panorama_frames(pkg, kind, carried_frames=carried_frames,
                limit=carried_limit, material_reason=carried_reason,
                change_boxes=getattr(pkg, "change_boxes", None),
                window_id=window_id, material_id=pkg.material_id,
                plan_frames=plan_frames, plan_event_key=plan_event_key)
        else:
            try:
                frames = _local_frames(pkg, branch, kind, crop_map,
                                       plan_frames=plan_frames,
                                       plan_event_key=plan_event_key)
            except ValueError as exc:
                if selection_callback is None:
                    raise  # No diagnostic consumer: never silently drop input.
                rejected.append({"branch": kind.value, "crop_id": branch.crop_id,
                                 "status": "input_rejected", "reason": str(exc)[:256]})
                continue
        prepared.append((kind, frames,
                         _prompt_for_branch(branch, kind,
                                            vocabulary_id=vocabulary_id,
                                            vocabulary=vocabulary,
                                            gate_reason=gate_reason),
                         branch.crop_id))
    if budget_ledger is None:
        tasks = [L3Task(
            window=window, branch=kind, frames=frames, prompt=prompt,
            created_mono_ms=time.monotonic() * 1000.0,
            budget=budget, crop_id=crop_id)
            for kind, frames, prompt, crop_id in prepared]
        if material_selection_out is not None:
            # C154 G：无账本路径同样产出对齐账目（任务已构造完，帧序即真实）
            _bind_material_selection(tasks, prepared, {}, material_selection_out)
        return tasks
    return _planned_tasks(
        pkg, window, prepared, budget_ledger, budget=budget,
        plan_out=plan_out, material_selection_out=material_selection_out)


def _planned_tasks(pkg, window, prepared, budget_ledger, *, budget,
                   plan_out=None, material_selection_out=None):
    """共享预算下的任务构造（C153 A）：plan → 只为 keep 构造任务。

    plan 的账目与任务一一对应（索引=分支顺序），因此分支身份、crop_id 与
    `task.budget` 三方不会错位；被合并/被丢弃的分支不产生任务，其身份与
    原因留在 `ledger.coverage(window_key)`（调用方取用）。
    `plan_out`（可选 list）：追加本次 plan dict，`kept` 与返回任务**同序**
    ——调用方据此把任务绑定到计划分支下标（release 精确归还用）。
    `material_selection_out`（C154，可选 callable）：任务构造完成后用**真实
    帧序**生成「声明保留 ↔ 实际送入模型」对齐账目并回调一次；同时把
    **来源可追溯**的转折标记写进任务（`win11_l3._declared_turning_positions`
    认 `turning_positions` + `turning_positions_source` 两者齐全）。
    """
    window_key = (window.camera_id, window.run_id, window.config_version,
                  window.window_id)
    ledger_branches = _ledger_branch_rows(prepared)
    frames_by_index = {index: frames
                       for index, (_kind, frames, _prompt, _crop)
                       in enumerate(prepared)}
    plan = budget_ledger.plan(window_key=window_key, pkg=pkg,
                              branches=ledger_branches,
                              frames_by_index=frames_by_index,
                              task_budget=budget)
    if plan_out is not None:
        plan_out.append(plan)
    kept_by_index = {row["index"]: row for row in plan["kept"]}
    tasks = []
    for index, (kind, frames, prompt, crop_id) in enumerate(prepared):
        row = kept_by_index.get(index)
        if row is None:
            continue                     # 合并/预算丢弃：账目已如实记录
        tasks.append(L3Task(
            window=window, branch=kind, frames=frames, prompt=prompt,
            created_mono_ms=time.monotonic() * 1000.0,
            budget=row["budget"], crop_id=crop_id))
    if material_selection_out is not None:
        _bind_material_selection(tasks, prepared, kept_by_index,
                                 material_selection_out)
    return tasks


_TURN_SOURCE = "material_reason:change_start"


class _TurningTask(L3Task):
    """带**来源可追溯**转折标记的全景任务（同形状；只增两个运行期属性）。

    `win11_l3.L3Stage._declared_turning_positions` 只认 `turning_positions`
    （int 序列）+ 非空 `turning_positions_source` 二者齐全——两者都来自
    真实来源事实（L1 材料触发原因 `change_start`：静→动边沿），不是调用方
    口头断言。`__slots__` 子类：isinstance/形状与 `L3Task` 一致，不改冻结
    合同形状。
    """

    __slots__ = ("turning_positions", "turning_positions_source")


def _bind_material_selection(tasks, prepared, kept_by_index, out):
    """把「声明的开始/转折/最新」与**实际构造的帧**对齐后回调（C154）。

    逐帧身份来自真实 `L3FrameInput.identity`（四元）与其 `t_capture_ms`/
    `timestamp_kind`；角色 = 序列锚点（首个在场=start、末个在场=latest）
    或**来源事实**转折（`change_start`）。该账目在**任务构造之后**生成，
    因此是"实际送入模型"的口径，可用假 L3 后端收到的 `frames_meta`
    逐帧对齐断言——不是日志宣称。
    有来源依据的转折位次同时写到**对应分支任务**上
    （`turning_positions` + `turning_positions_source` 两者齐全，stage 才认）。
    """
    from .win11_event_materials import (ROLE_LATEST, ROLE_MIDDLE, ROLE_START,
                                        ROLE_TURNING, TURN_BASIS_UNKNOWN,
                                        TURN_COVERAGE_NOTE,
                                        TURN_MARKER_CHANGE_START)
    panorama_index = None
    for index, (kind, frames, _prompt, _crop) in enumerate(prepared):
        if _enum_value(kind) == "panorama" and frames:
            panorama_index = index
            break
    record = {
        "schema": "scam.win11.material_selection/v1",
        "status": "bound" if panorama_index is not None else "no_panorama",
        "branch_index": panorama_index,
        "frames": [],
        "sent_frame_ids": [],
        "roles": [],
        "turning_positions": [],
        "turning_positions_source": None,
        "turn_coverage": None,
    }
    if panorama_index is None:
        out(record)
        return record
    kind, frames, _prompt, _crop = prepared[panorama_index]
    rows = list(frames)
    present = [index for index, fr in enumerate(rows)
               if fr.frame_bgr is not None]
    first_index = present[0] if present else None
    last_index = present[-1] if present else None
    turning_positions = tuple(
        position for position, fr in enumerate(rows)
        if getattr(fr, "turning_marker", None))
    for index, fr in enumerate(rows):
        row = {
            "position": index,
            "frame_id": getattr(getattr(fr, "identity", None), "frame_id",
                                None),
            "t_capture_ms": getattr(fr, "t_capture_ms", None),
            "timestamp_kind": getattr(fr, "timestamp_kind", None),
            "present": fr.frame_bgr is not None,
            "role": ROLE_MIDDLE,
            "turn_basis": TURN_BASIS_UNKNOWN,
            "turning_marker": getattr(fr, "turning_marker", None),
        }
        if index == first_index:
            row["role"] = ROLE_START
            row["turn_basis"] = "sequence_anchor:start"
        elif index == last_index:
            row["role"] = ROLE_LATEST
            row["turn_basis"] = "sequence_anchor:latest"
        elif row["turning_marker"] == TURN_MARKER_CHANGE_START:
            row["role"] = ROLE_TURNING
            row["turn_basis"] = TURN_MARKER_CHANGE_START
        record["frames"].append(row)
    record["sent_frame_ids"] = [row["frame_id"] for row in record["frames"]]
    record["roles"] = [row["role"] for row in record["frames"]]
    if turning_positions:
        record["turning_positions"] = list(turning_positions)
        record["turning_positions_source"] = _TURN_SOURCE
        _place_turning_positions(tasks, kind, turning_positions)
    elif any(row["role"] == ROLE_MIDDLE for row in record["frames"]):
        record["turn_coverage"] = TURN_COVERAGE_NOTE
    kept_row = kept_by_index.get(panorama_index)
    if kept_row is not None:
        record["frames_reserved"] = kept_row.get("frames_reserved")
    out(record)
    return record


def _place_turning_positions(tasks, kind, positions):
    """把来源可追溯的转折位次写到对应全景任务上（同位置替换，保持任务顺序）。

    `L3Task` 是 `__slots__` 冻结形状（无转折槽位），而
    `win11_l3._declared_turning_positions` 通过 `getattr` 读取——因此这里用
    `__slots__` 子类 `_TurningTask` 承载，**不改冻结合同形状、不改帧序**。
    """
    for index, task in enumerate(tasks):
        if task.branch != kind or not task.frames:
            continue
        decorated = _TurningTask(task.window, task.branch, task.frames,
                                 task.prompt, task.created_mono_ms,
                                 task.budget, task.crop_id)
        decorated.turning_positions = tuple(positions)
        decorated.turning_positions_source = _TURN_SOURCE
        tasks[index] = decorated
        return True
    return False


class _LedgerBranch:
    """账本入参视图：把已构造的帧序（含真实切片像素）暴露给计划器。

    计划器只读 `branch_kind/crop_id/identity/frame_sequence`；这里把
    `tasks_from_package` 已解析好的 (kind, frames, crop_id) 三角拼成同形
    对象——避免二次切片/二次取像素。identity 段由计划器回落到材料包身份
    （计划器只读身份字段，不构造任务）。"""

    __slots__ = ("branch_kind", "crop_id", "frame_sequence")

    def __init__(self, kind, frames, crop_id):
        self.branch_kind = _enum_value(kind)
        self.crop_id = crop_id
        self.frame_sequence = tuple(frames)


def _ledger_branch_rows(prepared):
    """(kind, frames, prompt, crop_id) → 计划器入参（同序）。

    帧序由调用方经 `frames_by_index` 单独传给计划器（"计划所测=任务所用"）；
    这里只带分支身份段，避免计划器二次切片/二次取像素。"""
    return [_LedgerBranch(kind, frames, crop_id)
            for kind, frames, _prompt, crop_id in prepared]


def _fallback_task(pkg, *, window_id, fallback_reason, vocabulary_id,
                   vocabulary, budget):
    """兜底统一三序位任务（C-138 D1）：无 L2 分支的单一全景任务。

    prev/cur/nxt 在场帧按固定序位进任务（_panorama_frames 复用有效路径，
    缺帧显式占位、绝不伪造、绝不塌缩序位）；crop_id=None（无 L2 裁图来
    源，不编造）；关系模型调用为零由调用方保证（本模块纯转换）。
    """
    kind = L3BranchKind.PANORAMA
    frames = _panorama_frames(pkg, kind)
    window = L3WindowIdentity(pkg.camera_id, pkg.run_id, pkg.config_version,
                              window_id, pkg.material_id)
    return L3Task(
        window=window, branch=kind, frames=frames,
        prompt=_fallback_prompt(frames, fallback_reason,
                                vocabulary_id=vocabulary_id,
                                vocabulary=vocabulary),
        created_mono_ms=time.monotonic() * 1000.0,
        budget=budget, crop_id=None)


def _fallback_prompt(frames, fallback_reason, *, vocabulary_id, vocabulary):
    """兜底任务 prompt（确定性渲染；不含 <image>——占位符归模型适配层）。

    首行携带兜底原因原样（不改写不淡化）；存在缺帧序位时显式列出场/缺
    序位并声明非完整连续过程——模型可描述在场帧画面，但不得虚构完整跨
    帧过程，缺帧序位如实标注缺失。"""
    lines = ["L1 关系识别不可用（原因：{}）。".format(fallback_reason)]
    lines.append("任务：以下是提供的全景采样帧（序位 0=前、1=当前、2=后）。"
                 "按时间顺序描述画面可见内容与跨帧变化；区分观察与推断；"
                 "缺帧序位如实标注缺失。")
    lines.append("采样点之间的经过未提供，不能视为连续录像；不得补全未见的"
                 "动作、人物去向或意图，无法确认的事项写入unknown。")
    missing = [i for i, f in enumerate(frames) if f.frame_bgr is None]
    if missing:
        present = [i for i, f in enumerate(frames)
                   if f.frame_bgr is not None]
        lines.append(
            "本任务在场序位：{}；缺失序位：{}——非完整连续过程，仅基于"
            "在场帧描述可见内容并如实标注缺失序位，不虚构完整跨帧过程。"
            .format(_positions_text(present), _positions_text(missing)))
    if vocabulary_id is not None or vocabulary:
        rels = "、".join(str(v) for v in tuple(vocabulary or ()))
        lines.append("关系词表 vocabulary_id={}：{}。".format(
            vocabulary_id, rels or "（未提供）"))
    lines.append('输出要求：优先输出 JSON {"observation": "可直接观察的事实'
                 '", "inference": "跨采样点推断（非确认）", "unknown": '
                 '"无法确认的事项"}；无法结构化时输出'
                 "纯文本。")
    return "\n".join(lines)


def _positions_text(positions):
    """序位列表 → 确定性中文串（如 "0、2"）；空列表 → "（无）"。"""
    return "、".join(str(i) for i in positions) if positions else "（无）"


def _check_branch_identity(pkg, branch):
    """分支身份与材料包 M1 全匹配（四元+material_id）；不符即拒绝。"""
    ident = getattr(branch, "identity", None)
    if ident is None:
        raise ValueError(
            "tasks_from_package: L3BranchSpec.identity 缺失"
            "（分支身份是身份的一部分，C-135 §9）")
    if (ident.camera_id != pkg.camera_id
            or ident.run_id != pkg.run_id
            or ident.config_version != pkg.config_version
            or getattr(ident, "material_id", None) != pkg.material_id):
        raise ValueError(
            "tasks_from_package: 分支身份与材料包不符（M1 四元+material_id，"
            "不跨材料串线）：branch=({},{},{},material={}) pkg=({},{},{},"
            "material={})".format(ident.camera_id, ident.run_id,
                                  ident.config_version,
                                  getattr(ident, "material_id", None),
                                  pkg.camera_id, pkg.run_id,
                                  pkg.config_version, pkg.material_id))


def _panorama_frames(pkg, kind, *, carried_frames=(), limit=None,
                     material_reason=None, change_boxes=None,
                     window_id=None, material_id=None, plan_frames=None,
                     plan_event_key=None):
    """全景分支：prev/cur/nxt 全景帧，固定序位 0/1/2；缺帧显式占位。

    C154 §4（同事件跨窗选材）：`carried_frames` 非空时，把**同事件同身份**
    的保留帧与本窗主序位帧合并成一条**有序序列**（去重、按观察钟升序、
    有上限），首个=开始、末个=最新——序位含义由 `win11_l3.select_frames_
    within_budget` 的顺序语义承接（`present` 过滤 + 首末锚点）；
    `carried_frames=()` 时行为与旧路径**逐字节一致**。

    C155-R1 修复①②：`plan_frames` 非空（aggregated 计划）时**不经三序位
    合并**——事件汇聚任务帧集 = 计划帧集的**自身严格绑定子集**（逐帧
    `bound` 且 event/object 身份齐备才入任务；保序、去重、不重排），与
    计划**同源**，已绑定转折帧必然保留；未绑定帧（含本窗 cur/prev/nxt 与
    计划内 latest 占位）一律不入事件任务——上下文由独立 unassociated
    路径承载，绝不统一赋 event_id 冒充证据。子集为空即 aggregated 不变
    式被破坏 → ValueError（不静默降级、不伪造事件任务）。
    """
    if plan_frames is not None:
        if carried_frames:
            raise ValueError(
                "_panorama_frames: plan_frames 与 carried_frames 互斥"
                "（C155-R1 同源约束）")
        if (not isinstance(plan_event_key, (tuple, list))
                or len(plan_event_key) != 5
                or any(value is None or value == "" for value in plan_event_key)):
            raise ValueError("event plan key must be a complete authoritative five-tuple")
        expected = tuple(plan_event_key)
        if expected[:3] != (pkg.camera_id, pkg.run_id, pkg.config_version):
            raise ValueError("event plan identity does not match package")
        rows = []
        seen = set()
        for frame in tuple(plan_frames):
            if frame.bound is not True:
                continue          # 修复②：非自身严格绑定帧绝不入事件任务
            identity = (frame.camera_id, frame.run_id, frame.config_version,
                        frame.event_id, frame.object_id)
            if (identity != expected or frame.frame_id is None
                    or frame.material_id is None
                    or tuple(frame.window_key)[:3] != expected[:3]):
                raise ValueError("event frame identity does not match authoritative plan key")
            if frame.identity_key in seen:
                continue
            seen.add(frame.identity_key)
            rows.append(frame.to_frame_input(kind))
        if not rows:
            raise ValueError(
                "_panorama_frames: plan_frames has no bound frames / 无自身严格绑定帧"
                "（aggregated 计划必须至少含一帧已核验绑定；拒绝伪造）")
        return tuple(rows)

    if plan_event_key is not None:
        raise ValueError("event plan key requires explicit plan_frames")

    rows = []
    for fr in (pkg.prev, pkg.cur, pkg.nxt):
        if fr is None:
            rows.append({"frame_id": None, "frame_bgr": None,
                         "t_capture_ms": None, "timestamp_kind": None})
            continue
        rows.append({
            "frame_id": fr.frame_id,
            "frame_bgr": fr.frame_bgr,
            "t_capture_ms": fr.t_capture_ms,
            "timestamp_kind": fr.timestamp_kind,
            "window_id": window_id,
            "material_id": material_id,
            "material_reason": material_reason,
            "change_boxes": change_boxes,
            "event_id": None,
        })
    if carried_frames:
        from .win11_event_materials import _merge_and_bound
        window_key = (pkg.camera_id, pkg.run_id, pkg.config_version,
                      window_id)
        merged, _deduped, _dropped = _merge_and_bound(
            rows, tuple(carried_frames), window_key=window_key,
            limit=max(1, int(limit or len(rows) + len(carried_frames))))
        return tuple(frame.to_frame_input(kind) for frame in merged)
    frames = []
    for fr in (pkg.prev, pkg.cur, pkg.nxt):
        if fr is None:
            frames.append(_missing_frame(pkg, kind))
            continue
        frames.append(L3FrameInput(
            branch=kind,
            identity=L3FrameIdentity(pkg.camera_id, pkg.run_id,
                                     pkg.config_version, fr.frame_id),
            t_capture_ms=fr.t_capture_ms,
            timestamp_kind=fr.timestamp_kind,
            frame_bgr=fr.frame_bgr,
            enhanced=None))               # pkg 帧无增强概念：显式未增强
    return tuple(frames)


def _local_frames(pkg, branch, kind, crop_images_by_crop_id, *,
                  plan_frames=None, plan_event_key=None):
    """局部关系/变化区域分支：同区域三帧真实切片，序位同全景。

    frame_sequence（C-135）为权威来源——每张切片自带 frame_id/时间/时间
    类型/真实像素，逐帧绑定其自身身份（按 position 归一序位，不按列表序
    猜）；绝不把 cur 裁图替换到 prev/next 位。分支无 frame_sequence 时
    （旧分支兼容）：cur 位用 crop_id 显式映射取图（身份取分支 identity 的
    cur 侧），prev/next 位显式缺位占位——全缺时 stage 如实报 unsupported。
    """
    seq = tuple(getattr(branch, "frame_sequence", None) or ())
    event_mode = plan_frames is not None
    bound_sources = {}
    if event_mode:
        if (not isinstance(plan_event_key, (tuple, list))
                or len(plan_event_key) != 5
                or any(v is None or v == "" for v in plan_event_key)):
            raise ValueError("local event plan key must be a complete authoritative five-tuple")
        key = tuple(plan_event_key)
        if key[:3] != (pkg.camera_id, pkg.run_id, pkg.config_version):
            raise ValueError("local event plan identity does not match package")
        for source in plan_frames:
            if source.bound is not True:
                continue
            if ((source.camera_id, source.run_id, source.config_version,
                 source.event_id, source.object_id) != key
                    or source.material_id is None or source.frame_id is None
                    or isinstance(source.frame_id, bool)
                    or tuple(source.window_key)[:3] != key[:3]):
                raise ValueError("local frame identity does not match authoritative plan key")
            # Event pool / EventProgress canonicalize frame IDs to strings;
            # package and local slices may retain the same integer ID.
            source_key = (str(source.frame_id), source.t_capture_ms, source.timestamp_kind)
            if source_key in bound_sources:
                raise ValueError("ambiguous local event frame source")
            bound_sources[source_key] = source
        if not bound_sources:
            raise ValueError("local event plan has no bound frames")
        if not seq:
            raise ValueError("local event crop requires attributable frame_sequence, not bare array map")
        participants = [ref for candidate in (getattr(branch, "candidates", ()) or ())
                        for ref in (candidate.subject, candidate.obj)]
        if not any(ref.object_id == key[4] and ref.stable is True
                   and ref.frame_id is not None
                   and str(ref.frame_id) == str(pkg.cur.frame_id) for ref in participants):
            raise ValueError("local event crop has no matching object participant")
    elif plan_event_key is not None:
        raise ValueError("local event plan key requires explicit plan_frames")
    if seq:
        rows = sorted(seq, key=lambda s: s.position)   # 固定序位归一
        positions = set()
        selected = []
        package_frames = (pkg.prev, pkg.cur, pkg.nxt)
        for s in rows:
            if (type(s.position) is not int or s.position not in (0, 1, 2)
                    or s.position in positions or s.crop_id != branch.crop_id
                    or isinstance(s.frame_id, bool)):
                raise ValueError("local slice position/crop identity mismatch")
            positions.add(s.position)
            original = package_frames[s.position]
            if s.frame_bgr is None:
                if s.present:
                    raise ValueError("local slice claims present without pixels")
                if not event_mode:
                    selected.append(s)
                continue
            if not s.present:
                raise ValueError("local slice has pixels but claims absent")
            # Independent region-only sequences retain their own source IDs;
            # legacy callers need not use the package's three frame IDs.
            # Only an event claim requires package + authoritative-plan proof.
            if event_mode and (original is None
                    or (s.frame_id, s.t_capture_ms, s.timestamp_kind) !=
                       (original.frame_id, original.t_capture_ms, original.timestamp_kind)):
                raise ValueError("local slice source identity does not match package frame")
            if event_mode:
                source = bound_sources.get((str(s.frame_id), s.t_capture_ms, s.timestamp_kind))
                if source is None:
                    continue  # independent region context is not event evidence
                # A local slice cannot borrow whole-frame identity without its pixels.
                # Views only; no additional full-frame copy or model work.
                from .win11_l2_crops import norm_box_to_px
                if source.frame_bgr is None or branch.crop_ref is None:
                    raise ValueError("local event crop source pixels/transform missing")
                h, w = source.frame_bgr.shape[:2]
                if (h, w) != original.frame_bgr.shape[:2]:
                    raise ValueError("local event source dimensions differ")
                px = norm_box_to_px(branch.crop_ref.bbox_norm, w, h)
                if px is None:
                    raise ValueError("local event crop transform is empty")
                x1, y1, x2, y2 = px
                if not np.array_equal(s.frame_bgr, source.frame_bgr[y1:y2, x1:x2, :]):
                    raise ValueError("local event crop pixels do not match bound source")
            selected.append(s)
        if event_mode and not selected:
            raise ValueError("local event crop has no attributable bound pixels")
        return tuple(
            L3FrameInput(
                branch=kind,
                identity=L3FrameIdentity(pkg.camera_id, pkg.run_id,
                                         pkg.config_version, s.frame_id),
                t_capture_ms=s.t_capture_ms,
                timestamp_kind=s.timestamp_kind,
                frame_bgr=s.frame_bgr,
                enhanced=getattr(branch, "enhanced", None))
            for s in selected)
    ident = branch.identity
    image = None
    if branch.crop_id is not None:
        image = crop_images_by_crop_id.get(branch.crop_id)
    return (
        _missing_frame(pkg, kind),
        L3FrameInput(
            branch=kind,
            identity=L3FrameIdentity(pkg.camera_id, pkg.run_id,
                                     pkg.config_version, ident.frame_id),
            t_capture_ms=ident.t_capture_ms,
            timestamp_kind=ident.timestamp_kind,
            frame_bgr=image,
            enhanced=getattr(branch, "enhanced", None)),
        _missing_frame(pkg, kind),
    )


def _missing_frame(pkg, kind):
    """缺帧显式占位（L3FrameInput frame_bgr=None 语义）：序位保留，
    身份/时间如实留空——绝不伪造帧、绝不挪用其他序位身份。"""
    return L3FrameInput(
        branch=kind,
        identity=L3FrameIdentity(pkg.camera_id, pkg.run_id,
                                 pkg.config_version, None),
        t_capture_ms=None, timestamp_kind=None, frame_bgr=None, enhanced=None)


def _prompt_for_branch(branch, kind, *, vocabulary_id, vocabulary,
                       gate_reason=None):
    """任务指令 prompt（确定性渲染；不含 <image>——占位符归模型适配层）。

    gate_reason 非 None → 头部第一行携带真实原因（兜底任务）；局部分支
    携带 crop_id 与区域 bbox_norm（整帧归一化原图坐标，逐切片绑定的坐标
    语义锚点）与「同区域，不保证同一对象」声明。
    """
    lines = []
    if gate_reason is not None:
        lines.append(
            "兜底任务：L1 门控未产出有效受理结果（原因：{}）；请仅基于现有"
            "帧如实描述可见内容，不冒充门控未确认的事件。".format(gate_reason))
    if kind is L3BranchKind.PANORAMA:
        lines.append("任务：以下是按给定顺序提供的全景采样帧。按时间顺序描述画面"
                     "可见内容与跨帧变化；区分观察与推断；缺帧序位如实标注"
                     "缺失。")
    elif kind is L3BranchKind.RELATION_CROP:
        lines.append("任务：以下是同一空间区域在给定采样帧上的切片（同区域，"
                     "不保证同一对象、不代表全景）。描述区域内对象及其关系的变化；区分"
                     "观察与推断；缺帧序位如实标注缺失。")
    else:
        lines.append("任务：以下是门控变化区域在给定采样帧上的同区域切片"
                     "（不保证同一对象、不代表全景）。描述区域内发生的变化；区分观察与"
                     "推断；缺帧序位如实标注缺失。")
    lines.append("采样点之间的经过未提供，不能视为连续录像；不得补全未见的"
                 "动作、人物去向或意图，无法确认的事项写入unknown。")
    bits = []
    if branch.crop_id:
        bits.append("crop_id={}".format(branch.crop_id))
    if kind is not L3BranchKind.PANORAMA:
        bbox = getattr(getattr(branch, "crop_ref", None), "bbox_norm", None)
        if bbox:
            bits.append("区域 bbox_norm(整帧归一化x,y,w,h)=({})".format(
                ",".join("{:.6f}".format(float(v)) for v in bbox)))
    if bits:
        lines.append("；".join(bits) + "。")
    if vocabulary_id is not None or vocabulary:
        rels = "、".join(str(v) for v in tuple(vocabulary or ()))
        lines.append("关系词表 vocabulary_id={}：{}。".format(
            vocabulary_id, rels or "（未提供）"))
    lines.append('输出要求：优先输出 JSON {"observation": "可直接观察的事实'
                 '", "inference": "跨采样点推断（非确认）", "unknown": '
                 '"无法确认的事项"}；无法结构化时输出'
                 "纯文本。")
    return "\n".join(lines)


# ---- C2：L3Output → 可保存结构 ----------------------------------------------

# L3 失败侧状态值（win11_l3_contract.L3Status 失败侧六值，冻结；ok/partial
# 是成功侧）。失败条目：身份/来源/时间保留（已知任务事实，C-139 §3），
# 观察侧语义字段（region_only/unstructured/uncertainty）置 None 不编造。
_FAILURE_STATUS_VALUES = frozenset({
    L3Status.UNSUPPORTED.value,
    L3Status.MODEL_UNAVAILABLE.value,
    L3Status.INFER_FAILED.value,
    L3Status.TIMEOUT.value,
    L3Status.BACKEND_ISOLATED.value,
    L3Status.IDENTITY_REJECTED.value,
})


def results_from_output(l3_output):
    """真实 L3Output → list[dict]（JSON 可序列化的"可保存结构"）。

    results 非空 → 逐分支条目（观察/推断/不确定性/来源/帧身份/时间类型/
    缺失）；失败/拒绝态分支结果（C-139 §3：已知身份事实不清空）同样逐条
    转换——crop_id/branch_key（七元含 material 段）/帧来源/时间类型保留，
    观察侧未知字段置 None，reason 携带 error_code+omission 原因；results
    为空（无任何分支结果的旧形状输出）→ 单条失败条目（status/error_code/
    reason），绝不只保存空 text+ok。字段集冻结（消费方 runtime 依赖）：
    window_key/branch_key/branch/crop_id/status/error_code/model_ref/
    region_only/unstructured/uncertainty/sources/frame_gaps_ms/missing/
    observation/inference/reason。branch_key = window_key + [branch,
    crop_id, material_id]（C-138 §1：追加 material 来源段——material 取
    自 out.window.material_id，旧形状无该段时如实 None，键长恒定；同窗
    多材料包的同区域分支 key 必不相同，存档/摘要并排不互相覆盖）。
    """
    out = l3_output
    wkey = _window_key_list(out.window)
    material_id = getattr(out.window, "material_id", None)
    entries = [_branch_entry(out, r, wkey, material_id)
               for r in tuple(getattr(out, "results", None) or ())]
    if not entries:
        entries.append(_failure_entry(out, wkey, material_id))
    return entries


def _enum_value(value):
    """枚举→冻结字符串值；字符串原样（容错手写形状，不加工语义）。"""
    return value.value if hasattr(value, "value") else str(value)


def _window_key_list(window):
    return [window.camera_id, window.run_id, window.config_version,
            window.window_id]


def _text_item(text, unstructured):
    """模型文本 → text item（C-137 §2：自由文本 unstructured=True +
    model_inferred；结构化模型文本同为 model_inferred——L3 文本不升级）。"""
    if text is None:
        return None
    return {"text": str(text), "unstructured": bool(unstructured),
            "certainty": "model_inferred"}


def _uncertainty_dict(unc):
    if unc is None:
        return None
    return {"frame_missing": bool(getattr(unc, "frame_missing", False)),
            "frames_truncated": bool(getattr(unc, "frames_truncated", False)),
            "pixels_downscaled": bool(getattr(unc, "pixels_downscaled",
                                              False)),
            "unenhanced": bool(getattr(unc, "unenhanced", False))}


def _sources_list(sources):
    """来源引用 → dict 行：固定序位 + 帧身份 + 真实存在性 + 观察钟时间
    （帧身份与时间类型随条目保留，供 L4 与保存面）。"""
    return [{"position": s.position, "frame_id": s.frame_id,
             "present": bool(s.present), "t_capture_ms": s.t_capture_ms,
             "timestamp_kind": s.timestamp_kind}
            for s in tuple(sources or ())]


def _gaps_list(gaps):
    return [None if g is None else float(g) for g in tuple(gaps or ())]


def _missing_dict(out):
    omission = getattr(out, "omission", None)
    return {
        "frames_dropped": (int(omission.frames_dropped)
                           if omission is not None else 0),
        "omission_reason": (omission.reason
                            if omission is not None else None),
    }


def _branch_entry(out, r, wkey, material_id):
    branch_value = _enum_value(r.branch)
    crop_id = r.crop_id
    sources = _sources_list(r.sources)
    missing_frames = [row["position"] for row in sources
                      if not row["present"]]
    missing = _missing_dict(out)
    missing["frames"] = missing_frames
    status_value = _enum_value(r.status)
    is_failure = status_value in _FAILURE_STATUS_VALUES
    reason = None
    if is_failure:
        # 失败条目 reason：受控细分码 + omission 记账（确定性渲染，无
        # 原始异常文本——路径/凭据不进存档）。
        bits = []
        if r.error_code:
            bits.append("error_code={}".format(r.error_code))
        omission = getattr(out, "omission", None)
        if omission is not None and omission.reason:
            bits.append("omission={}".format(omission.reason))
        reason = "；".join(bits) if bits else None
    entry = {
        "window_key": list(wkey),
        "branch_key": list(wkey) + [branch_value, crop_id, material_id],
        "branch": branch_value,
        "crop_id": crop_id,
        "status": status_value,
        "error_code": r.error_code,
        "model_ref": r.model_ref if r.model_ref is not None else out.model_ref,
        # 失败态观察侧语义未知：置 None 不编造；身份/来源/时间照实保留
        "region_only": None if is_failure else bool(r.region_only),
        "unstructured": None if is_failure else bool(r.unstructured),
        "uncertainty": _uncertainty_dict(r.uncertainty),
        "sources": sources,
        "frame_gaps_ms": _gaps_list(r.frame_gaps_ms),
        "missing": missing,
        "observation": _text_item(r.observation, r.unstructured),
        "inference": _text_item(r.inference, r.unstructured),
        "reason": reason,
    }
    model_unknown = getattr(r, "model_unknown", None)
    if not is_failure and model_unknown is not None and model_unknown != "":
        # Optional additive export: absent data leaves the legacy key set intact.
        # Model uncertainty must not be labelled as a model-inferred conclusion.
        entry["model_unknown"] = {"text": model_unknown, "certainty": "unknown"}
    return entry


def _failure_entry(out, wkey, material_id):
    """无任何分支结果（results 空）的兜底失败条目：status+原因保留，
    未知字段（crop_id/来源/观察侧语义）不编造——正常失败路径已由 stage
    产出带身份的失败分支结果（_branch_entry 处理），本条目只兜旧形状。"""
    branch_value = _enum_value(out.branch)
    bits = []
    if out.error_code:
        bits.append("error_code={}".format(out.error_code))
    omission = getattr(out, "omission", None)
    if omission is not None and omission.reason:
        bits.append("omission={}".format(omission.reason))
    missing = _missing_dict(out)
    missing["frames"] = []
    return {
        "window_key": list(wkey),
        "branch_key": list(wkey) + [branch_value, None, material_id],
        "branch": branch_value,
        "crop_id": None,          # 失败态无分支结果——裁图来源未知，不编造
        "status": _enum_value(out.status),
        "error_code": out.error_code,
        "model_ref": out.model_ref,
        "region_only": None,      # 失败态未产分支结果——未知
        "unstructured": None,
        "uncertainty": None,
        "sources": [],
        "frame_gaps_ms": [],
        "missing": missing,
        "observation": None,
        "inference": None,
        "reason": "；".join(bits) if bits else None,
    }


# ---- 健康面一行摘要 ----------------------------------------------------------

def summary_text(l3_output):
    """给人看的中文一行（确定性；换行折叠、截断有界；不改写文本语义）。"""
    out = l3_output
    head = "窗口{}·分支{}：{}".format(out.window.window_id,
                                      _enum_value(out.branch),
                                      _enum_value(out.status))
    if out.error_code:
        head += "（{}）".format(out.error_code)
    parts = [head]
    results = tuple(getattr(out, "results", None) or ())
    if not results:
        omission = getattr(out, "omission", None)
        reason = omission.reason if omission is not None else None
        if reason:
            parts.append(_one_line(reason))
        return "；".join(parts)
    for r in results:
        seg = []
        obs = _one_line(_clip(r.observation))
        inf = _one_line(_clip(r.inference))
        if obs:
            seg.append("观察：" + obs)
        if inf:
            seg.append("推断：" + inf)
        model_unknown = _one_line(_clip(getattr(r, "model_unknown", None)))
        if model_unknown:
            seg.append("模型未确认：" + model_unknown)
        flags = []
        unc = r.uncertainty
        if unc is not None:
            if unc.frame_missing:
                flags.append("缺帧")
            if unc.frames_truncated:
                flags.append("帧截断")
            if unc.pixels_downscaled:
                flags.append("降采样")
            if unc.unenhanced:
                flags.append("未增强")
        if flags:
            seg.append("不确定性：" + "、".join(flags))
        if not seg:
            seg.append("（无文本结果）")
        parts.append("｜".join(seg))
    return "；".join(parts)


def _clip(text, limit=_SUMMARY_CLIP):
    if text is None:
        return ""
    s = str(text)
    if len(s) > limit:
        s = s[:limit] + "…"
    return s


def _one_line(text):
    return " ".join(str(text).split())
