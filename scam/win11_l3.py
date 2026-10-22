"""win11_l3.py —— L3 多帧阶段（C-135 §8 首版；C-136 C2/C3/C4 输入与
结构化输出整改）：L3Stage + LocalTransformers 薄壳。

职责与语义（C-135 §8，超时/隔离沿用 C-134 惯例）：
- process(task) -> L3Output：身份校验（窗口三元+分支标签，错配→
  identity_rejected，不调模型）→ 结构校验（unsupported）→ 预算（帧数截断/
  总像素降采样，显式记账进 omission，绝不静默）→ 预处理（唯一重活=有界
  缩放；解码已在 L3FrameInput 构造完成——该段无模型依赖，可与其他任务的
  预处理并行）→ 预算记账（C-136 C3：原图证据尺寸/传输尺寸/模型真实
  patch-token 预算三层数值，调用边界断言图片数与真实 patch 数）→ 模型
  调用（并发=concurrency 信号量闸，默认 1；在途计数如实）→ 逐分支结果
  组装（观察/推断/不确定性/来源/缺帧固定序位/帧间隔/unstructured 标注，
  无 L4 融合）。
- 缺帧固定序位（C-136 C2）：帧序位 0 基——0=前、1=当前、2=后；缺帧保留
  序位、present=False 显式记录；只有 cur 在场时 partial 如实，绝不呈现
  三帧完整 ok；缺帧、帧间隔、region_only（同区域不保证同一对象）进入结果。
- 结构化输出（C-136 C4）：模型输出可结构化（observation/inference 键）
  → 结构化字段；无法结构化 → 原文保留 + unstructured=True，不靠关键词
  猜"已确认行为"。enhanced 恒 None 显式未增强。
- 共享一个模型实例：构造注入，stage 不复制、不重建；被隔离的 adapter 不
  重启（重建由生产层决定）。
- 窗口输入冻结：stage 只用 task.frames 给定帧，不扩窗、不等待新素材。
- 队列归生产接线（C-135 §9：≤4 任务满则丢最旧+计数）；stage 同步处理单
  任务不排队——L3Budget.max_queue 是生产队列的合同字段，stage 不读它。
- 模型协议 L3VisionModel.understand_frames(prompt, frames_bgr, frames_meta)
  -> dict（合同层）；生产适配器归 scam/win11_l3_backend.py（C-136 起
  由 B 交付、主会话接线）。本文件保留 C-135 交付的
  LocalTransformersL3Adapter 薄壳直至接线完成——本批不在 l3.py 新建
  适配器类；禁 fake 进生产。
- 状态：partial=模型成功但有缺帧/截断/降采样；失败态互斥不互冒充。

超时与隔离（LocalTransformersL3Adapter，C-134 惯例）：
- understand_frames 在专属单线程 executor 执行；超过 infer_timeout_s →
  抛 L3InferTimeout（TimeoutError 子类，stage 映射 timeout）并将 adapter
  标记 poisoned；此后每次调用立即抛 L3AdapterIsolated（stage 映射
  backend_isolated），不再给卡住实例派任务。
- 工作线程不可中止：超时的调用可能仍在运行（GIL/CPU/内存残留为事实），
  snapshot() 如实报告（线程存活数、残留调用是否仍在跑、abortable 恒
  False），绝不假装取消成功，也绝不假装恢复——poisoned 是终态。
- 上游自身抛出的 TimeoutError（future 已完成）≠ 等待超时→infer_failed，
  不毒化（与 C-134 同一区分）。
- 执行资源（C153-R1 §3）：等待超时但未被中止的调用，其并发槽 + 在途 gauge
  只在**真实执行结束证据**（future.done()/结果回收/自报线程已退出）下回收，
  且恰一次；停机/关闭/退休**不**强清挂起记录（那会把"丢掉引用"当"释放
  资源"），未完成的数量与身份经 `unfinished_executions()` 如实可查。
"""

from __future__ import annotations

import base64
import concurrent.futures
import json
import math
import threading
import time
import uuid

import numpy as np

from scam.win11_l3_contract import (
    INTERNVL_IMAGE_SIDE,
    INTERNVL_TOKENS_PER_PATCH_SEGMENT,
    L3_FAILURE_DETAIL_CODES,
    L3AdapterIsolated,
    L3BranchResult,
    L3Budget,
    L3BudgetAccounting,
    L3FrameBudgetUsage,
    L3ModelUnavailable,
    L3Omission,
    L3Output,
    L3SourceRef,
    L3Status,
    L3Uncertainty,
    L3VisionModel,
    window_matches_frame,
)

__all__ = [
    "DEFAULT_INFER_TIMEOUT_S",
    "L3InferFailed",
    "L3InferTimeout",
    "L3Stage",
    "LocalTransformersL3Adapter",
    "MAX_FRAME_SIDE",
    "select_frames_within_budget",
]

MAX_FRAME_SIDE = 448            # 与 LocalTransformers 输入侧 Resize(448,448) 对齐
DEFAULT_INFER_TIMEOUT_S = 120.0  # 与 LocalTransformers 默认 timeout 同量级

# C153 A/R1：预算内帧选择——保序位语义锚点（首位=开始，末位可分析=最新
# 状态，中间=**中间采样**；只有来源可追溯的转折标记才叫 turning）。
_ROLE_START = "start"
_ROLE_TURNING = "turning"
_ROLE_MIDDLE = "middle_sample"
_ROLE_LATEST = "latest"
# C153-R1 §4：无转折标记时 omission 必须如实写明的措辞（不得把等距中间帧
# 称为"关键转折"）。
_TURN_COVERAGE_UNPROVEN = "中间采样，转折覆盖未证明"
_DEFAULT_MAX_FRAMES = 8         # L3Budget.max_frames_per_task 冻结默认（缺档回退）


# ---- 异常（adapter 侧；合同层持有 L3ModelUnavailable/L3AdapterIsolated） ----

class L3InferTimeout(TimeoutError):
    """单次 understand_frames 等待超时。固定码 timeout；调用未被中止，
    adapter 随即 poisoned（继承 TimeoutError：stage 按 except TimeoutError
    分类）。"""

    code = "timeout"


class L3InferFailed(RuntimeError):
    """上游推理异常。固定码 infer_failed。"""

    code = "infer_failed"


# ---- 生产默认适配器：真实 LocalTransformers 薄壳 ----------------------------

def _encode_jpeg_b64(frame_bgr):
    """BGR ndarray → 纯 base64 JPEG（无 data: 前缀）。cv2 延迟导入。"""
    import cv2
    ok, buf = cv2.imencode(".jpg", frame_bgr)
    if not ok:
        raise ValueError("JPEG 编码失败")
    return base64.b64encode(buf.tobytes()).decode("ascii")


def _norm_meta(meta):
    """元信息行规范化：None→{}；dict→浅拷贝（只允许标量值）。"""
    if meta is None:
        return {}
    if not isinstance(meta, dict):
        return {"raw": str(meta)}
    return dict(meta)


class LocalTransformersL3Adapter(L3VisionModel):
    """真实 LocalTransformers 的 L3 协议薄壳（生产默认；禁 fake 进生产）。

    provider: scam.models.LocalTransformers 实例（延迟加载语义保留——首次
    调用才经 _ensure_loaded 走本机受控模型路径，trust_remote_code 读本机
    HF 缓存，不触网）。加载失败→L3ModelUnavailable（结构化，绝不回退假模型）。
    """

    def __init__(self, provider, infer_timeout_s=DEFAULT_INFER_TIMEOUT_S):
        self._provider = provider
        self.infer_timeout_s = (float(infer_timeout_s)
                                if infer_timeout_s is not None
                                and infer_timeout_s > 0 else None)
        self.model_ref = "transformers/{}".format(
            getattr(provider, "model_id", None) or "model")
        self._executor = None
        self._poisoned = False
        self._poison_reason = None
        self._pending_future = None

    # -- L3VisionModel 协议 ---------------------------------------------------

    def understand_frames(self, prompt, frames_bgr, frames_meta):
        frames_bgr = list(frames_bgr)
        if self._poisoned:
            raise L3AdapterIsolated(
                "backend_isolated: adapter refused new work after a previous "
                "infer timed out ({}); isolation is permanent for this "
                "instance, rebuild is a production-layer decision".format(
                    self._poison_reason),
                details={"poison_reason": self._poison_reason})
        try:
            # 加载在调用线程执行，不受 infer 超时约束（只发生一次，同 C-134）
            self._provider._ensure_loaded()
        except Exception as exc:
            raise L3ModelUnavailable(
                "model_unavailable: LocalTransformers load failed: "
                "{}: {}".format(type(exc).__name__, exc),
                details={"load_error": "{}: {}".format(type(exc).__name__,
                                                       exc)}) from exc
        if self._executor is None:
            self._executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="scam-l3-internvl")
        fut = self._executor.submit(self._call_once, prompt, frames_bgr,
                                    frames_meta)
        self._pending_future = fut
        try:
            if self.infer_timeout_s is not None:
                return fut.result(timeout=self.infer_timeout_s)
            return fut.result()
        except TimeoutError:
            # Python >=3.11：concurrent.futures.TimeoutError 即内建 TimeoutError
            if fut.done():
                # future 已完成且抛的是上游自己的 TimeoutError——不是等待超时
                cause = fut.exception()
                raise L3InferFailed(
                    "infer_failed: upstream raised TimeoutError: "
                    "{!r}".format(cause)) from cause
            self._poisoned = True
            self._poison_reason = (
                "infer exceeded infer_timeout_s={}s; the upstream call may "
                "still be running in the dedicated worker thread and cannot "
                "be aborted".format(self.infer_timeout_s))
            raise L3InferTimeout(
                "timeout: L3 understand_frames exceeded infer_timeout_s={}s; "
                "the worker call is NOT cancelled (cannot be aborted) and the "
                "adapter is now isolated".format(self.infer_timeout_s)
            ) from None
        except Exception as exc:
            raise L3InferFailed(
                "infer_failed: upstream LocalTransformers error: {}: "
                "{}".format(type(exc).__name__, exc)) from exc

    def snapshot(self):
        """如实报告加载态与超时隔离残留（不假装取消/恢复）。"""
        fut = self._pending_future
        pending_running = bool(fut is not None and not fut.done()
                               and not fut.cancelled())
        threads = ()
        if self._executor is not None:
            threads = tuple(getattr(self._executor, "_threads", ()) or ())
        return {
            "model_ref": self.model_ref,
            "backend": "transformers",
            "loaded": getattr(self._provider, "_model", None) is not None,
            "poisoned": self._poisoned,
            "poison_reason": self._poison_reason,
            "infer_timeout_s": self.infer_timeout_s,
            "pending_call_still_running": pending_running,
            "pending_call_done": (fut.done() if fut is not None else None),
            "worker_threads_alive": sum(1 for t in threads if t.is_alive()),
            "worker_abortable": False,
            "note": ("a timed-out upstream call cannot be aborted; its worker "
                     "thread may keep running and is reported here as-is, "
                     "never as cancelled"),
        }

    # -- 内部 -----------------------------------------------------------------

    def _call_once(self, prompt, frames_bgr, frames_meta):
        """在专属 executor 线程内执行：BGR→b64（缺帧占位 None 直通）→
        真实有序多帧路径（多图占位符+pixel_values 拼接，见 models.py）。"""
        b64s = [None if f is None else _encode_jpeg_b64(f)
                for f in frames_bgr]
        meta = [_norm_meta(m) for m in (frames_meta or ())]
        while len(meta) < len(b64s):     # 防御性等长对齐（stage 已保证）
            meta.append({})
        return self._provider.understand_frames(prompt, b64s, meta)


# ---- 预处理（纯数组，cv2 延迟导入；无模型依赖，可并行） ---------------------

def _resize_to(arr, width, height):
    import cv2
    return cv2.resize(arr, (width, height), interpolation=cv2.INTER_AREA)


def _bound_side(frame_bgr, max_side=MAX_FRAME_SIDE):
    """长边≤max_side 的等比缩放（模型输入侧本就 Resize 到 448——只缩不放，
    不放大细节）。"""
    h, w = frame_bgr.shape[:2]
    side = max(h, w)
    if side <= max_side:
        return frame_bgr
    scale = max_side / float(side)
    nw = max(1, int(round(w * scale)))
    nh = max(1, int(round(h * scale)))
    return _resize_to(frame_bgr, nw, nh)


def _scale_pixels(frame_bgr, factor):
    """按 factor(<1) 等比缩小（总像素预算超限时统一降采样，显式记账）。"""
    h, w = frame_bgr.shape[:2]
    nw = max(1, int(round(w * factor)))
    nh = max(1, int(round(h * factor)))
    if nw == w and nh == h:
        return frame_bgr
    return _resize_to(frame_bgr, nw, nh)


def _raw_model_text(value):
    """Keep malformed JSON readable without passing containers to text consumers."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def _split_model_output(result):
    """模型返回 → (观察, 推断, unstructured)（C-136 C4 结构化输出）。

    - dict 且带 observation/inference/unknown 显式键 → 结构化字段
      （unstructured=False；缺键侧为 None；unknown另经model_unknown保留）；
    - 其余（纯文本 / {"text": …} / 无已知键的 dict）→ 原文保留为观察且
      unstructured=True——自由文本不冒充系统确认事实，也不靠关键词猜
      "已确认行为"。绝不加工/改写文本。
    """
    if isinstance(result, dict) and ("observation" in result
                                     or "inference" in result
                                     or "unknown" in result):
        observation, inference = result.get("observation"), result.get("inference")
        if all(value is None or isinstance(value, str)
               for value in (observation, inference)):
            return observation, inference, False
        # A JSON object is not proof of the expected field schema. Preserve the
        # complete response as unstructured text, not selected/rewritten claims.
        return _raw_model_text(result), None, True
    if isinstance(result, dict):
        if "text" in result:
            return _raw_model_text(result["text"]), None, True
        return _raw_model_text(result), None, True
    return ("" if result is None else str(result)), None, True


def _model_unknown(result):
    """Preserve reported unknowns without inferring or rewriting model claims."""
    if not isinstance(result, dict) or result.get("unknown") is None:
        return None
    value = result["unknown"]
    if isinstance(value, str):
        return value or None
    # Keep JSON values auditable (including false/0); no truthiness filtering.
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _ms_since(t):
    return (time.perf_counter() - t) * 1000.0


def _detail_code(exc, fallback):
    """异常 → 受控词表内 detail_code（C-139 §3/C-139-R1 §2）。

    生产 adapter（win11_l3_backend）对加载超时/交付拒收抛带结构化 .code
    的异常（load_timeout/closed_rejected/poisoned_rejected/
    generation_rejected）——失败分类保留该细分事实，不压平成泛化码；
    词表外/缺位 → stage 分类码回退（绝不透传未受控字符串，防异常文本
    中的路径/凭据细节经 error_code 进存档）。
    """
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code in L3_FAILURE_DETAIL_CODES:
        return code
    return fallback


def _bump(notes, key, count=1):
    notes[key] = notes.get(key, 0) + count


def _render(notes):
    """确定性渲染省略原因："k1=v1;k2=v2"（dict 插入序，同 L2 惯例）。"""
    return ";".join(f"{key}={value}" for key, value in notes.items())


def _task_execution_identity(task):
    """执行占用的**可识别身份**（task/branch 键），供"仍在途"摘要如实指认。

    形状与 `win11_l3_tasks.branch_key_of` 一致（window 四元 + 分支 + crop_id
    + material 段），但本模块**不反向依赖** tasks 模块：只读 task 的公开字段，
    取不到就如实留 None（绝不猜一个键出来）。
    """
    window = getattr(task, "window", None)
    window_key = [getattr(window, name, None) for name in
                  ("camera_id", "run_id", "config_version", "window_id")]
    material_id = getattr(window, "material_id", None)
    branch_holder = getattr(task, "branch", None)
    branch = getattr(branch_holder, "value", None)
    if branch is None and branch_holder is not None:
        branch = str(branch_holder)
    crop_id = getattr(task, "crop_id", None)
    return {
        "window_key": list(window_key),
        "branch_key": list(window_key) + [branch, crop_id, material_id],
        "camera_id": window_key[0], "run_id": window_key[1],
        "config_version": window_key[2], "window_id": window_key[3],
        "material_id": material_id, "branch": branch, "crop_id": crop_id,
    }


# ---- C153 A：预算内帧选择（保开始/最新状态，绝不塌缩序位） -------------------

def select_frames_within_budget(n_total, positions, max_frames,
                                min_frames=1, *, present=None,
                                turning_positions=None):
    """预算内的帧选择（纯函数，可单测）：返回 `(kept_indexes,
    source_positions, role_by_position, dropped_positions)`。

    语义锚点（帧序位 0 基固定，C-136 C2）：首位 = 开始、末位 = 最新状态。
    超预算时的取舍顺序：
    1. 先保**可分析**的末位（最新状态）与首位（开始）——"开始/最新"绝不因
       预算被省略；
    2. 剩余名额在头段/中段等距取样，对头部轻微倾斜；
    3. 名额为 1 时保末位（最新状态优先：正在发生的事才是可行动事实）。

    **只在有像素的帧里选**（`present`，C153-R1 修复）：永久缺帧占位
    （`frame_bgr is None`）不消耗预算、也不得挤掉真正可分析的帧——否则
    "一帧在手 + 前后缺位"的常见窗口（窗口首帧/尾帧）会把唯一名额花在占位
    上，整支任务变成"无帧可分析"（`unsupported`）：既是假失败，也是真实
    材料被丢掉。`present=None` → 退回旧口径（全部下标可参与），供无像素
    信息的纯形状调用。

    两种序位口径**分开、都不丢**：
    - `kept_indexes`：在任务帧列表里的下标（0..N-1），升序 → 调用方据此
      取帧，得到的 M 帧仍是**稠密序位 0..M-1**（模型输入侧的 px 序位语义：
      0=前/1=当前/…，与 prompt 固定序位声明一致，绝不出现"第 5 帧=当前"）；
    - `source_positions`：这些帧在**原窗口**里的原位次（稀疏即真实：
      `0,1,5,9` 表示窗口第 2/3 帧与第 6..9 帧未被分析）——进 omission
      记账与解码侧映射，是"哪些帧被省略/哪些未分析"的权威口径；
    - `role_by_position` ∈ `start` | `turning` | `middle_sample` | `latest`，
      键=**原位次**。只有首/末标 `start`/`latest`；中间位**只在有来源可
      追溯的转折标记时**才标 `turning`（`turning_positions`=调用方给出的
      真实标记位次），否则一律标 `middle_sample`——**等距/中点取样绝不
      自动称为"关键转折"**（C153-R1 裁定 §4）。
    - `dropped_positions`：被省略的**原位次**（进 omission 记账，不静默）。

    任何输入下 `len(kept_indexes) <= max(1, max_frames)`；`max_frames>=2`
    且可分析帧 ≥2 时首位与末位都保留。无可分析帧 → 四个空值（调用方如实
    报 `no_present_frames`，不编造帧）。
    """
    total = max(0, int(n_total))
    if total <= 0:
        return [], [], {}, []
    names = tuple(range(total)) if positions is None else tuple(positions)
    if len(names) != total:
        names = tuple(range(total))
    eligible = list(range(total))
    if present is not None:
        flags = tuple(bool(flag) for flag in present)
        eligible = [i for i in eligible if i < len(flags) and flags[i]]
        if not eligible:
            return [], [], {}, []
    marked = set()
    if turning_positions:
        marked = {names[i] for i in turning_positions
                  if isinstance(i, int) and 0 <= i < total}
    limit = int(max_frames)
    if limit <= 0:
        kept = [eligible[-1]]
    elif len(eligible) <= limit:
        kept = list(eligible)
    else:
        keep_latest = eligible[-1]
        if limit == 1:
            kept = [keep_latest]
        else:
            # 尾段保位=最新状态（"最新状态"绝不因预算被省略）；其余名额均分
            # 头段/中段，取样对头部轻微倾斜（开始权重更高）。
            slots = limit - 1
            head = max(1, (slots + 1) // 2)
            head_idx = eligible[:head]
            middle = eligible[head:-1]
            middle_slots = slots - len(head_idx)
            # 有来源可追溯的转折标记 → **按来源保留**（占中段名额，取最近的
            # 若干个：最新转折最可行动）；无标记 → 全名额走等距取样。
            marked_middle = [idx for idx in middle if names[idx] in marked]
            chosen_marked = (marked_middle[-middle_slots:]
                             if middle_slots > 0 else [])
            picked = []
            free_slots = middle_slots - len(chosen_marked)
            rest = [idx for idx in middle if idx not in set(chosen_marked)]
            if free_slots > 0 and rest:
                if free_slots > 1:
                    nodes = sorted({
                        int(round(i * (len(rest) - 1)
                                  / float(free_slots - 1)))
                        for i in range(free_slots)})
                else:
                    nodes = [len(rest) // 2]
                picked = [rest[node] for node in nodes]
            kept = sorted(set(head_idx) | set(chosen_marked) | set(picked)
                          | {keep_latest})
            if len(kept) > limit:                      # 取样重叠时收紧
                kept = kept[:limit - 1] + [keep_latest]
    roles = {}
    for idx in kept:
        if idx == eligible[-1]:
            # 最末**可分析**位=最新状态；名额只有 1 时它同时是唯一锚点
            roles[idx] = _ROLE_LATEST
        elif idx == eligible[0]:
            roles[idx] = _ROLE_START
        elif names[idx] in marked:
            roles[idx] = _ROLE_TURNING
        else:
            roles[idx] = _ROLE_MIDDLE
    dropped = [idx for idx in range(total) if idx not in set(kept)]
    return (kept, [names[idx] for idx in kept],
            {names[idx]: role for idx, role in roles.items()},
            [names[idx] for idx in dropped])


def _selection_note(kept_positions, role_by_position, dropped_positions):
    """选择记账渲染（确定性；进 omission reason，既有字段不改形状）。

    模型输入侧序位是稠密 0..M-1，因此这里同时给出两个口径：
    `kept_positions` 与 `dropped_positions` 都是**原窗口原位次**——一眼可判
    "哪些帧被省略、哪些未分析"，绝不塌缩成"看起来连续的 M 帧"。

    `roles` 里的取值只有 `start`/`latest`/`turning`/`middle_sample`：中间帧
    默认是 `middle_sample`（**中间采样**），只有调用方给出**来源可追溯**的
    转折标记时才是 `turning`——等距取样绝不冒充"关键转折"（C153-R1 §4）。
    """
    roles = ",".join(
        "{}:{}".format(position, role_by_position.get(position, _ROLE_MIDDLE))
        for position in kept_positions)
    return ("kept_positions={};dropped_positions={};roles={}").format(
        ",".join(str(p) for p in kept_positions) or "-",
        ",".join(str(p) for p in dropped_positions) or "-",
        roles or "-")


# ---- 阶段 -------------------------------------------------------------------

class L3MeasurementContext:
    """Per-call immutable identity; sink is runtime's bounded INTERNAL writer.

    Never pass an external observer here. Runtime's writer only enqueues;
    user callbacks remain isolated on its bounded observer thread.
    """
    def __init__(self, runtime, branch_key):
        self._runtime = runtime
        self.branch_key = tuple(branch_key)
        self.call_id = uuid.uuid4().hex
        self._lock = threading.Lock()
        self.started = self.finished = self.wait_timed_out = False

    def emit(self, stage, **fields):
        self._runtime._trace_emit(stage,
            window_key=list(self.branch_key[:4]), branch=list(self.branch_key),
            task_key=list(self.branch_key), model_call_id=self.call_id,
            execution_thread_id=threading.get_ident(), **fields)

    def start_model(self):
        with self._lock:
            self.started = True
        self.emit("model_start")

    def finish_model(self, failed=False):
        with self._lock:
            self.finished = True
            late = self.wait_timed_out
        self.emit("model_failed" if failed else "model_end",
                  actual_execution_finished=True, late_after_wait_timeout=late)

    def timeout(self):
        with self._lock:
            self.wait_timed_out = True
            running = self.started and not self.finished
        self.emit("model_wait_timeout", execution_still_running=running,
                  actual_execution_finished=self.finished, abortable=False)


class L3Stage:
    """L3 多帧阶段：process(task) -> L3Output（构造注入 model 与 budget）。

    行为（C-135 §8 + C-136 C2/C3/C4）：身份校验（分支标签+窗口三元，错配→
    identity_rejected 不调模型）→ 结构校验（空帧/全缺帧/非法数组/prompt
    携带 <image>→unsupported）→ 预算（帧数超限**保开始/转折/最新状态**的
    原位次选择+记账；总像素超限统一降采样+记账）→ 预处理（有界缩放，锁外
    可并行）→ 实际
    预算记账（原图/传输/真实 patch-token 三层，调用边界断言）→ 模型调用
    （信号量闸 concurrency，默认 1）→ 组装（固定序位来源/帧间隔/
    region_only/unstructured）。模型调用失败四分类：L3AdapterIsolated→
    backend_isolated；TimeoutError→timeout；L3ModelUnavailable→
    model_unavailable；其他→infer_failed——异常携带受控词表内的结构化
    细分码（.code，如 load_timeout/closed_rejected）时 error_code 保留
    细分事实不压平。失败/拒绝终态产单条失败分支结果：已知身份事实
    （窗口+material/branch/crop_id/帧身份/观察钟时间/时间类型）从 task
    透传不清空，观察/推断/不确定性置 None 不编造（C-139 §3）。partial
    与 ok 的唯一差别是存在缺帧/截断/降采样等不完整因素，模型文本本身
    不因 partial 降级。
    """

    def __init__(self, model, budget=None, *, slot_wait_timeout_s=None):
        self.model = model                    # 模型引用计数=1，不复制
        self.budget = budget if budget is not None else L3Budget()
        self._model_slots = threading.BoundedSemaphore(
            max(1, int(self.budget.concurrency)))
        self._gauge_lock = threading.Lock()
        self._in_flight = 0
        # C153-R1 §2/§3：**执行资源**（并发槽 + 在途 gauge）与计划额度分开
        # 记账。等待超时的调用**未被中止**（provider 无法 abort）——执行线程
        # 可能仍在跑，因此槽位与 gauge 不提前返还，直到有**真实执行结束证据**
        # （future.done()/结果回收/model 自报 pending 与线程状态）才回收。槽位
        # 等待有界（`slot_wait_timeout_s`），拿不到就如实判 timeout——绝不因为
        # 一个卡死的调用让后续分支永久排队（无饥饿）；也绝不因为"停机了就
        # 当作已释放"而把并发上限归零冒充实际结束（无假释放）。
        self._held_executions = []            # [{"probe","detail","identity",...}]
        # C153-R1 §3：真实结束后**恰一次**回收的计数（重复收口不重复释放）。
        self._execution_reclaims = 0
        # 退休标记：只表示"不再作为当前实例被依赖"，**不**清空/归零在途记录。
        self._retired_reason = None
        self._last_close_reason = None
        declared = getattr(model, "infer_timeout_s", None)
        if slot_wait_timeout_s is None:
            try:
                slot_wait_timeout_s = max(1.0, float(declared))
            except (TypeError, ValueError):
                slot_wait_timeout_s = DEFAULT_INFER_TIMEOUT_S
        self.slot_wait_timeout_s = float(slot_wait_timeout_s)

    # ---- 执行资源（C153-R1 §2：与计划额度/已执行消费分列） --------------------

    def _probe_execution_finished(self, probe):
        """探测某次"等待超时但未被中止"的执行是否已真正结束。

        探测源只取 **model 自报**（adapter 的 `snapshot()`/`diagnostic()`；
        生产 `LocalTransformersL3Backend` 提供 `pending_call_still_running`
        / `pending_call_done`（= `future.done()`）/`pending_calls`/
        `executor_threads_alive`）：查不到证据 → 一律当
        **仍在执行**（保守：绝不因探测不到就提前返还执行资源）。
        """
        if probe is None:
            return False
        try:
            info = probe()
        except Exception:
            return False
        if not isinstance(info, dict):
            return False
        still_running = info.get("pending_call_still_running")
        if still_running is True:
            return False
        if still_running is False:
            return True
        # C153-R1 §3：**真实 future 完成**是明确的执行结束证据（生产 adapter
        # 的 `pending_call_done` 即 `future.done()`）；未完成/取消都不是结束。
        future_done = info.get("pending_call_done")
        if future_done is True:
            return True
        if future_done is False:
            return False
        for key in ("pending_calls", "worker_threads_alive",
                    "executor_threads_alive"):
            value = info.get(key)
            if value is None:
                continue
            try:
                return int(value) <= 0
            except (TypeError, ValueError):
                return False
        return False

    def _execution_probe(self):
        """未结束执行的**自报探测源**；model 无自报能力 → None（无证据源）。

        生产 `LocalTransformersL3Backend` 提供 `snapshot()`（含
        `pending_call_still_running`/`pending_calls`/`executor_threads_alive`）
        与 `diagnostic()`——本方法只读它们的公开字段，不改 adapter。
        """
        for name in ("snapshot", "diagnostic"):
            probe = getattr(self.model, name, None)
            if callable(probe):
                return probe
        return None

    def _model_refusal(self):
        """model 自报"已隔离/已关闭、不再接单"的受控原因；无法判定 → None。

        只读公开字段（`poisoned` / `snapshot().poisoned|close_requested|phase`，
        与生产 adapter 的 `_refuse_reason` 同源）；**不猜**、不改 adapter。
        """
        if getattr(self.model, "poisoned", None) is True:
            return "poisoned"
        probe = self._execution_probe()
        if probe is None:
            return None
        try:
            info = probe()
        except Exception:
            return None
        if not isinstance(info, dict):
            return None
        if info.get("poisoned") is True:
            return "poisoned"
        if info.get("close_requested") is True:
            return "close_requested"
        phase = info.get("phase")
        if isinstance(phase, str) and phase in ("poisoned", "closed"):
            return phase
        return None

    def _release_slot_and_gauge(self):
        """返还一个并发槽与在途 gauge（幂等保护：不重复 release 爆 Bounded）。"""
        with self._gauge_lock:
            self._in_flight = max(0, self._in_flight - 1)
        try:
            self._model_slots.release()
        except ValueError:
            pass

    def _hold_execution_resource(self, task=None):
        """等待超时且**执行可能未结束**：槽位与 gauge 保持占用，登记探测源。

        返回 True=已挂起（执行资源**未**返还，等真实结束证据回收）；False=
        已确认执行结束或 model 无自报能力（同步异常=调用已返回）→ 正常返还。
        挂起记录携带**可识别身份**（task/branch 键），停机后仍能如实指认
        "谁还在途"（C153-R1 §3）。
        """
        probe = self._execution_probe()
        if probe is None:
            return False
        if self._probe_execution_finished(probe):
            return False
        identity = _task_execution_identity(task) if task is not None else None
        with self._gauge_lock:
            self._held_executions.append(
                {"probe": probe, "detail": "wait_timeout_execution_unfinished",
                 "identity": identity,
                 "held_since_mono_ms": time.monotonic() * 1000.0})
        return True

    def _collect_finished_executions(self):
        """回收"实际执行已结束"的挂起槽位（幂等；无挂起=零行为）。

        **唯一**的回收入口：只在探测到真实结束证据（`future.done()`/结果
        回收/model 自报执行线程已退出）时回收，并计数恰一次。
        """
        with self._gauge_lock:
            held = list(self._held_executions)
        released = 0
        for item in held:
            if not self._probe_execution_finished(item["probe"]):
                continue
            with self._gauge_lock:
                if item not in self._held_executions:
                    continue
                self._held_executions.remove(item)
            self._release_slot_and_gauge()
            with self._gauge_lock:
                self._execution_reclaims += 1
            released += 1
        return released

    def release_held_executions(self, reason="close_requested"):
        """收口请求（停机/关闭路径）：**只回收真实执行已结束**的挂起项。

        C153-R1 §3 修正：旧实现无条件清空挂起记录并返还全部槽位/gauge——
        那是把"丢掉引用"当"释放资源"（`backend.close` 返回
        `close_incomplete=True` 时尤其自相矛盾），会让并发上限失真、把仍在
        执行的占用冒充成已结束。现在：

        - 执行仍在进行（探测不到"已结束"）→ 记录与占用**保留**，由
          `unfinished_executions()` / `execution_resources()` 如实上报；
        - 有真实结束证据 → 回收**恰一次**（`reclaimed_total` 计数），重复
          调用不重复释放、不丢记录。

        返回本次实际回收数量（未完成项不计入）；`reason` 只作诊断记录。
        """
        with self._gauge_lock:
            self._last_close_reason = str(reason)
        return self._collect_finished_executions()

    def retire(self, reason="retired"):
        """实例退休：只标记"不再是当前实例"，**不**清空/归零在途执行记录。

        返回退休时刻的未完成执行摘要（数量+身份）——对象被替换/释放后，
        该摘要仍经 `unfinished_executions()` 可查询（不因引用释放而丢失）。
        """
        self._retired_reason = str(reason)
        return self.unfinished_executions()

    def _held_item_locked(self, item):
        """挂起项 → 冻结的身份摘要（调用方持 `_gauge_lock`）。"""
        identity = item.get("identity")
        out = dict(identity) if isinstance(identity, dict) else {}
        if not out:
            out = {"identity_unknown": True}
        out["detail"] = item.get("detail")
        out["held_since_mono_ms"] = item.get("held_since_mono_ms")
        return out

    def unfinished_executions(self):
        """未完成执行的**冻结身份摘要**（可查询；退休/替换后记录仍在）。

        每次读取先做一次真实结束证据回收（读到的就是"此刻仍在途"的事实）。
        """
        self._collect_finished_executions()
        with self._gauge_lock:
            return [self._held_item_locked(item)
                    for item in self._held_executions]

    def execution_resources(self):
        """执行资源如实快照（与计划额度、已执行消费分列）。

        `held_unfinished` = 仍在执行的占用数量；`held` = 其身份摘要；
        `reclaimed_total` = 真实结束后恰一次回收的累计次数。
        """
        self._collect_finished_executions()
        with self._gauge_lock:
            in_flight = self._in_flight
            reclaimed = self._execution_reclaims
            held_items = [self._held_item_locked(item)
                          for item in self._held_executions]
            retired = self._retired_reason
            close_reason = self._last_close_reason
        return {
            "concurrency": max(1, int(self.budget.concurrency)),
            "in_flight": in_flight,
            "held_unfinished": len(held_items),
            "held": held_items,
            "reclaimed_total": reclaimed,
            "retired": retired is not None,
            "retired_reason": retired,
            "last_close_reason": close_reason,
            "slot_wait_timeout_s": self.slot_wait_timeout_s,
        }

    def _acquire_model_slot(self):
        """有界获取并发槽：返回 `acquired` / `refused` / `timeout`。

        等待期间反复做"已结束执行"的回收（实际执行结束即可继续），因此正常
        的慢调用不会误判；只有真正"卡住不放"才让后续分支如实失败。若 model
        自报已隔离/关闭（不再接单），立即返回 `refused`——不空等一个已被隔离
        的 provider（那会把诚实失败变成长期饥饿）。
        """
        deadline = time.monotonic() + self.slot_wait_timeout_s
        while True:
            self._collect_finished_executions()
            if self._model_slots.acquire(timeout=0.05):
                return "acquired"
            if self._model_refusal() is not None:
                return "refused"
            if time.monotonic() >= deadline:
                return "timeout"

    def snapshot(self):
        """运行面信息（在途 gauge 如实；队列字段只是合同透传，stage 不排队）。"""
        resources = self.execution_resources()
        return {
            "model_ref": getattr(self.model, "model_ref", None) or "unspecified",
            "in_flight": self._in_flight,
            "concurrency": self.budget.concurrency,
            "in_flight_limit": self.budget.in_flight,
            "max_frames_per_task": self.budget.max_frames_per_task,
            "max_queue": self.budget.max_queue,   # 生产队列深度；stage 不排队
            "max_total_pixels": self.budget.max_total_pixels,
            "model_image_side": INTERNVL_IMAGE_SIDE,
            "tokens_per_patch_segment": INTERNVL_TOKENS_PER_PATCH_SEGMENT,
            "execution_resources": resources,
        }

    def process_measured(self, task, measurement):
        return self.process(task, measurement=measurement)

    def process(self, task, *, measurement=None):
        t0 = time.perf_counter()
        notes = {}
        window, branch = task.window, task.branch
        frames = tuple(task.frames)

        # 1) 身份校验：分支标签 + 窗口三元（frame_id 不参与窗口匹配）
        for i, fr in enumerate(frames):
            if fr.branch != branch:
                return self._reject(task, f"branch_mismatch:frame{i}",
                                    notes, t0)
            if not window_matches_frame(window, fr.identity):
                return self._reject(task, f"identity_mismatch:frame{i}",
                                    notes, t0)

        # 2) 结构校验（unsupported：结构性不可处理，与失败态互斥）
        if not frames:
            return self._unsupported(task, "empty_frames", notes, t0)
        if "<image>" in (task.prompt or ""):
            # 帧段布局由模型适配层按实际帧渲染；调用方自带占位符会造成
            # 占位符数与图像数错位（上游 generate 硬协议）——如实拒绝。
            return self._unsupported(task, "prompt_contains_image_marker",
                                     notes, t0)
        budget = task.budget if task.budget is not None else self.budget
        used = frames
        frames_truncated = False
        source_positions = None
        if len(frames) > budget.max_frames_per_task:
            # C153 A：预算内选择**保开始/最新状态**（旧行为是"保前 N 帧"——
            # 中间/尾部关键转折会被整段省略）。模型输入侧序位仍稠密 0..M-1
            # （prompt 的固定序位声明成立），原窗口原位次单独记账不丢。
            # C153-R1：只在**有像素的帧**里选（缺帧占位不占名额、不挤掉真实
            # 材料）；中间帧一律记 middle_sample，除非有来源可追溯的转折标记
            # （本阶段暂无该标记来源 → 如实写"转折覆盖未证明"）。
            frames_truncated = True
            limit = max(1, int(budget.max_frames_per_task))
            turning = self._declared_turning_positions(task, frames)
            kept, source_positions, roles, dropped_positions = (
                select_frames_within_budget(
                    len(frames), None, limit,
                    present=[fr.frame_bgr is not None for fr in frames],
                    turning_positions=turning))
            notes["frames_budget_cap"] = len(dropped_positions)
            legacy_dropped = len(frames) - limit      # 旧口径：保前 N 帧丢弃数
            if len(dropped_positions) != legacy_dropped:
                # 与旧记账键名撞车（旧值=按"保前 N 帧"计的丢弃数）：数值
                # 不同则显式改名并注明旧口径，绝不让键名对不上真实数值
                # （诚实优先于兼容展示）。
                del notes["frames_budget_cap"]
                notes["frames_budget_selected"] = len(dropped_positions)
                notes["frames_budget_cap_legacy_prefix"] = legacy_dropped
            notes["selection"] = _selection_note(
                source_positions, roles, dropped_positions)
            if _ROLE_TURNING in roles.values():
                notes["turn_evidence"] = "declared_source_traceable"
            elif _ROLE_MIDDLE in roles.values():
                # 无标记：不得把等距中间帧称为"关键转折"，如实写缺口
                notes["turn_coverage"] = _TURN_COVERAGE_UNPROVEN
            used = tuple(frames[index] for index in kept)
        present_idx = [i for i, fr in enumerate(used)
                       if fr.frame_bgr is not None]
        if not present_idx:
            return self._unsupported(task, "no_present_frames", notes, t0)
        for i in present_idx:
            arr = used[i].frame_bgr
            if arr.ndim != 3 or arr.shape[0] <= 0 or arr.shape[1] <= 0:
                return self._unsupported(task, f"invalid_frame:frame{i}",
                                         notes, t0)

        # 3) 预处理（可并行段）：长边≤448 对齐模型输入侧；总像素超预算统一降采样
        t1 = time.perf_counter()
        if measurement is not None:
            measurement.emit("l3_preprocess_start")
        arrays = [None if fr.frame_bgr is None
                  else _bound_side(fr.frame_bgr) for fr in used]
        total_px = sum(a.shape[0] * a.shape[1] for a in arrays
                       if a is not None)
        pixels_downscaled = False
        if total_px > budget.max_total_pixels and total_px > 0:
            factor = math.sqrt(budget.max_total_pixels / float(total_px))
            arrays = [a if a is None else _scale_pixels(a, factor)
                      for a in arrays]
            pixels_downscaled = True
            _bump(notes, "pixels_downscaled", 1)
        preprocess_ms = _ms_since(t1)
        if measurement is not None:
            measurement.emit("l3_preprocess_end")

        # 3.5) 实际模型预算记账（C-136 C3）：原图证据尺寸/传输尺寸/模型真实
        #      patch-token 预算三层数值；降采样被 provider 放回 448 时如实
        #      标注不虚报 patch 预算下降
        accounting = self._build_budget_accounting(used, arrays,
                                                   pixels_downscaled)

        # 4) prompt（指令；帧段由模型适配层按实际帧渲染占位符与缺帧标注）
        #    C153 A：预算选择后如实声明"这是省略后的降采样序列"（不给模型
        #    连续过程的错觉，也不让它猜哪些帧被省略）。
        prompt = self._build_prompt(task, reduced=source_positions)
        frames_meta = [self._meta_row(fr, i)
                       for i, fr in enumerate(used)]

        # 5) 模型调用（并发闸 + 在途 gauge）+ 异常四分类。
        #    调用边界断言（C-136 C3）：图片数、真实 patch 数、元信息行数
        #    与记账一致——不一致立即失败，不带错账调模型。
        #    C153-R1 §2：等待超时**未中止**的调用，其执行资源（槽位+gauge）
        #    不提前返还；只有证据（model 自报执行结束）或 close() 才返还。
        assert accounting.image_count == sum(1 for a in arrays
                                             if a is not None)
        assert accounting.total_patches == sum(
            u.effective_patches for u in accounting.frames if u.present)
        assert len(accounting.frames) == len(arrays) == len(frames_meta)
        t2 = time.perf_counter()
        slot = self._acquire_model_slot()
        if slot == "refused":
            # model 自报已隔离/关闭：不占槽、不空等，如实判 backend_isolated
            _bump(notes, "model_refuses_new_work", 1)
            notes["refusal"] = str(self._model_refusal() or "unavailable")
            return self._failed(task, L3Status.BACKEND_ISOLATED,
                                "backend_isolated", notes, t0, preprocess_ms,
                                _ms_since(t2), accounting=accounting)
        if slot == "timeout":
            # 槽位被"等待超时但仍在执行"的调用占用且到期未释放：如实判
            # timeout（本轮**没有**给这个分支发出模型调用，不冒充已分析）。
            _bump(notes, "concurrency_unavailable", 1)
            notes["held_unfinished"] = self.execution_resources()[
                "held_unfinished"]
            return self._failed(task, L3Status.TIMEOUT, "timeout", notes, t0,
                                preprocess_ms, _ms_since(t2),
                                accounting=accounting)
        with self._gauge_lock:
            self._in_flight += 1
        execution_finished = False
        try:
            measured = getattr(self.model, "understand_frames_measured", None) if measurement is not None else None
            if callable(measured):
                result = measured(prompt, arrays, frames_meta, measurement)
            else:
                if measurement is not None:
                    measurement.emit("model_measurement_unavailable",
                                     reason="opaque_execution_boundary")
                result = self.model.understand_frames(prompt, arrays,
                                                      frames_meta)
            execution_finished = True
        except L3AdapterIsolated as exc:
            self._release_slot_and_gauge()
            return self._failed(task, L3Status.BACKEND_ISOLATED,
                                _detail_code(exc, "backend_isolated"),
                                notes, t0, preprocess_ms, _ms_since(t2),
                                accounting=accounting)
        except TimeoutError as exc:
            # 等待超时 ≠ 执行结束：provider 无法 abort，执行线程可能仍在跑。
            # 有自报证据表明仍未结束 → 执行资源**不返还**（挂起待回收，登记
            # task/branch 身份）；后续分支拿不到槽位时由 `_acquire_model_slot`
            # 如实判 timeout。**只有真实结束证据**才回收（停机/关闭也不强清）。
            if not self._hold_execution_resource(task):
                self._release_slot_and_gauge()
            return self._failed(task, L3Status.TIMEOUT,
                                _detail_code(exc, "timeout"), notes, t0,
                                preprocess_ms, _ms_since(t2),
                                accounting=accounting)
        except L3ModelUnavailable as exc:
            self._release_slot_and_gauge()
            return self._failed(task, L3Status.MODEL_UNAVAILABLE,
                                _detail_code(exc, "model_unavailable"),
                                notes, t0, preprocess_ms, _ms_since(t2),
                                accounting=accounting)
        except Exception as exc:
            self._release_slot_and_gauge()
            return self._failed(task, L3Status.INFER_FAILED,
                                _detail_code(exc, "infer_failed"),
                                notes, t0, preprocess_ms, _ms_since(t2),
                                accounting=accounting)
        finally:
            if execution_finished:
                self._release_slot_and_gauge()
        infer_ms = _ms_since(t2)

        # 6) 逐分支结果组装（无 L4 融合；C-136 C2/C4：固定序位来源、帧
        #    间隔、region_only、身份与来源、unstructured 标注）
        any_missing = any(fr.frame_bgr is None for fr in used)
        status = (L3Status.PARTIAL
                  if (any_missing or frames_truncated or pixels_downscaled)
                  else L3Status.OK)
        observation, inference, unstructured = _split_model_output(result)
        model_ref = getattr(self.model, "model_ref", None) or "unspecified"
        branch_result = L3BranchResult(
            branch=branch, status=status, error_code=None,
            observation=observation, inference=inference,
            uncertainty=L3Uncertainty(
                frame_missing=any_missing,
                frames_truncated=frames_truncated,
                pixels_downscaled=pixels_downscaled,
                unenhanced=all(fr.enhanced is None for fr in used)),
            sources=tuple(L3SourceRef(
                position=i, frame_id=fr.identity.frame_id,
                present=fr.frame_bgr is not None,
                t_capture_ms=fr.t_capture_ms,
                timestamp_kind=fr.timestamp_kind)
                for i, fr in enumerate(used)),
            window=window, crop_id=task.crop_id, model_ref=model_ref,
            region_only=True, unstructured=unstructured,
            frame_gaps_ms=self._frame_gaps_ms(used),
            model_unknown=_model_unknown(result))
        return L3Output(
            window=window, branch=branch, status=status, error_code=None,
            results=(branch_result,),
            omission=L3Omission(
                frames_dropped=len(frames) - len(used),
                reason=_render(notes)),
            model_ref=model_ref,
            timings_ms={"preprocess": preprocess_ms, "infer": infer_ms,
                        "total": _ms_since(t0)},
            budget_accounting=accounting)

    # ---- 内部 ---------------------------------------------------------------

    @staticmethod
    def _declared_turning_positions(task, frames):
        """**来源可追溯**的转折标记位次；无 → None（绝不猜）。

        当前冻结契约（`L3Task`/`L3FrameInput` 均 `__slots__`）**没有**转折
        标记字段，生产形状因此恒为 None → omission 如实写
        "中间采样，转折覆盖未证明"（C153-R1 §4：等距中间帧不得自动称为
        关键转折）。这里只保留一个**显式**扩展点：调用方在任务对象上同时
        给出 `turning_positions`（int 序列）与**非空**来源说明
        `turning_positions_source`（可追溯字符串）才被认可；缺来源说明一律
        不认——"有标记"必须可追溯到某个真实来源，不是调用方口头断言。
        """
        declared = getattr(task, "turning_positions", None)
        source = getattr(task, "turning_positions_source", None)
        if not declared or not source:
            return None
        try:
            marks = tuple(int(index) for index in declared)
        except (TypeError, ValueError):
            return None
        total = len(frames)
        marks = tuple(index for index in marks if 0 <= index < total)
        return marks or None

    @staticmethod
    def _frame_gaps_ms(frames):
        """相邻序位帧的观察钟间隔（ms，C-136 C2）；任一侧缺帧→None（未知
        间隔如实进结果，供 L4），不猜测、不补零。"""
        gaps = []
        for a, b in zip(frames, frames[1:]):
            if a.frame_bgr is None or b.frame_bgr is None:
                gaps.append(None)
            else:
                gaps.append(float(b.t_capture_ms) - float(a.t_capture_ms))
        return tuple(gaps)

    def _build_budget_accounting(self, used, arrays, pixels_downscaled):
        """实际模型预算记账（C-136 C3）。

        三层数值：source=原图证据尺寸（任务帧构造时）；transport=预处理后
        送 adapter 的传输尺寸；effective=模型真实 patch/token 预算——按
        实际送入（provider 变换后）尺寸计算：本 provider 固定
        Resize(448,448) → 每帧 1 patch 段 = 256 token。传输任一边 <448 的
        帧会被 provider 放回 448（provider_rescaled=True）——降采样不降低
        patch 预算，downscale_reduced_patch_budget 恒 False 不虚报。
        context_limit_tokens 取 adapter 声明（无声明 None，不编造）。
        """
        side = INTERNVL_IMAGE_SIDE
        frames = []
        provider_rescaled_count = 0
        for i, (fr, arr) in enumerate(zip(used, arrays)):
            if fr.frame_bgr is None or arr is None:
                frames.append(L3FrameBudgetUsage(
                    position=i, present=False, source_width=None,
                    source_height=None, transport_width=None,
                    transport_height=None, provider_rescaled=False,
                    effective_patches=0, effective_tokens=0))
                continue
            src_h, src_w = int(fr.frame_bgr.shape[0]), int(fr.frame_bgr.shape[1])
            tr_h, tr_w = int(arr.shape[0]), int(arr.shape[1])
            rescaled = tr_w < side or tr_h < side
            if rescaled:
                provider_rescaled_count += 1
            fed_w, fed_h = max(tr_w, side), max(tr_h, side)
            patches = max(1, math.ceil(fed_h / side) * math.ceil(fed_w / side))
            frames.append(L3FrameBudgetUsage(
                position=i, present=True, source_width=src_w,
                source_height=src_h, transport_width=tr_w,
                transport_height=tr_h, provider_rescaled=rescaled,
                effective_patches=patches,
                effective_tokens=patches * INTERNVL_TOKENS_PER_PATCH_SEGMENT))
        image_count = sum(1 for u in frames if u.present)
        total_patches = sum(u.effective_patches for u in frames if u.present)
        total_tokens = sum(u.effective_tokens for u in frames if u.present)
        context_limit = getattr(self.model, "context_token_limit", None)
        notes = []
        if provider_rescaled_count:
            notes.append(
                f"provider_rescales_to_tile={provider_rescaled_count}")
        if pixels_downscaled and provider_rescaled_count:
            notes.append("downscale_does_not_reduce_patch_budget=1")
        if context_limit is not None:
            try:
                over = total_tokens > int(context_limit)
            except (TypeError, ValueError):
                over = False
            if over:
                notes.append("context_limit_exceeded=1")
        # fed 尺寸恒 ≥448×448（provider 固定 tile）→ 降采样不可能降低
        # patch 段数；本 provider 合同下该值恒 False（如实，非虚报）
        downscale_reduced = False
        return L3BudgetAccounting(
            image_side=side,
            patch_side=14,
            downsample_ratio=0.5,
            tokens_per_patch_segment=INTERNVL_TOKENS_PER_PATCH_SEGMENT,
            frames=tuple(frames), image_count=image_count,
            total_patches=total_patches, total_tokens=total_tokens,
            context_limit_tokens=context_limit,
            downscale_reduced_patch_budget=downscale_reduced,
            notes=";".join(notes))

    @staticmethod
    def _build_prompt(task, reduced=None):
        """指令 prompt：窗口四元+分支身份头（C-135 §9 全链身份）；不含
        <image>（process 已拒绝）。帧段布局归模型适配层。C-136：固定序位
        （0=前/1=当前/2=后）与「同区域切片，不保证同一对象」如实进 prompt
        ——不确定性显式声明，不靠模型猜。

        `reduced` 非 None = C153 A 预算选择后的降采样序列（值为保留帧在**原
        窗口**的原位次）：如实声明"省略后的子集"，避免模型把稀疏取样当成
        连续过程。
        """
        w = task.window
        head = (f"窗口身份 camera={w.camera_id} run={w.run_id} "
                f"config={w.config_version} window={w.window_id}；"
                f"分支={task.branch.value}。帧序位固定（0=前、1=当前、"
                f"2=后，更多帧按时间升序 0..N-1），缺帧处已显式标注。")
        if reduced is not None:
            head += ("本任务是预算内的保留帧子集（原窗口原位次 {}，帧数已"
                     "受限）：场间可能存在未提供的中间帧，如实描述可见变化，"
                     "不虚构完整连续过程。".format(
                         ",".join(str(p) for p in reduced) or "-"))
        if task.crop_id:
            head += (f"裁剪来源 crop_id={task.crop_id}；各帧为同空间区域"
                     "切片，不保证同一对象。")
        if task.prompt:
            return head + "\n" + task.prompt
        return head

    @staticmethod
    def _meta_row(fr, position):
        """传给模型的逐帧元信息行（键序冻结；仅标量，见 L3VisionModel）。

        position 序位 0 基固定（C-136 C2）：0=前、1=当前、2=后。
        """
        ident = fr.identity
        return {
            "position": position,
            "present": fr.frame_bgr is not None,
            "branch": fr.branch.value,
            "camera_id": ident.camera_id,
            "run_id": ident.run_id,
            "config_version": ident.config_version,
            "frame_id": ident.frame_id,
            "t_capture_ms": fr.t_capture_ms,
            "timestamp_kind": fr.timestamp_kind,
            "enhanced": fr.enhanced is not None,
        }

    def _reject(self, task, error_code, notes, t0):
        return self._terminal(task, L3Status.IDENTITY_REJECTED, error_code,
                              notes, t0)

    def _unsupported(self, task, error_code, notes, t0):
        return self._terminal(task, L3Status.UNSUPPORTED, error_code, notes,
                              t0)

    def _failed(self, task, status, error_code, notes, t0, preprocess_ms,
                infer_ms, accounting=None):
        return self._terminal(task, status, error_code, notes, t0,
                              preprocess_ms=preprocess_ms, infer_ms=infer_ms,
                              accounting=accounting)

    def _terminal(self, task, status, error_code, notes, t0,
                  preprocess_ms=0.0, infer_ms=0.0, accounting=None):
        """失败/拒绝终态（identity_rejected/unsupported/失败侧四分类）：
        C-139 §3——失败不清空已知材料事实。单条失败 L3BranchResult 从 task
        透传已知身份：窗口四元（含 material 附加段→branch_key 七元）、
        分支标签、crop_id 裁剪来源、帧身份/观察钟时间/时间类型（sources
        固定序位，缺帧 present=False 显式）、帧间隔。观察/推断/不确定性
        置 None——未产出的内容绝不编造，也绝不冒充成功侧文本。失败侧若
        已到调用边界（预处理完成）则如实携带预算记账；未到边界（身份/
        结构拒绝）accounting=None——绝不编造。"""
        frames = tuple(task.frames)
        model_ref = getattr(self.model, "model_ref", None) or "unspecified"
        failure_result = L3BranchResult(
            branch=task.branch, status=status, error_code=error_code,
            observation=None, inference=None, uncertainty=None,
            sources=tuple(L3SourceRef(
                position=i, frame_id=fr.identity.frame_id,
                present=fr.frame_bgr is not None,
                t_capture_ms=fr.t_capture_ms,
                timestamp_kind=fr.timestamp_kind)
                for i, fr in enumerate(frames)),
            window=task.window, crop_id=task.crop_id, model_ref=model_ref,
            region_only=True, unstructured=False,
            frame_gaps_ms=self._frame_gaps_ms(frames))
        return L3Output(
            window=task.window, branch=task.branch, status=status,
            error_code=error_code, results=(failure_result,),
            omission=L3Omission(frames_dropped=0, reason=_render(notes)),
            model_ref=model_ref,
            timings_ms={"preprocess": preprocess_ms, "infer": infer_ms,
                        "total": _ms_since(t0)},
            budget_accounting=accounting)
