"""C-136 L3 唯一生产适配器：LocalTransformersL3Backend（scam.win11_l3_backend）。

实现 docs/context/L2L3L4-接口冻结-C136.md §一 冻结签名（L3VisionModel 协议，
基类由 scam.win11_l3_contract 持有，本模块直接继承）：

    model_ref: str
    LocalTransformersL3Backend(provider=None, *, model_path=None,
                               timeout_s=180.0, infer_timeout_s=120.0,
                               load_timeout_s=60.0, dtype=None)
    understand_frames(prompt, frames_bgr, frames_meta) -> dict
    close(timeout_s=5.0) -> dict     # closed/pending_calls/threads_alive/
                                     # close_incomplete（与 l2_backend 同一收尾合同）
    diagnostic() -> dict             # phase/load_stage/pending_calls/
                                     # executor_threads_alive/close_incomplete/
                                     # load_error（与 l2_backend 六字段同形）

取代 nvr.py 中的重复壳 LocalTransformersL3Adapter（主会话 M1 删除）与
win11_l3.py 的旧壳——本模块是唯一 L3 生产适配器，生产禁 fake。

provider 双构造路径
-------------------
* provider 显式注入：直接使用（延迟加载语义归 provider；本模块只做有界
  等待与隔离）。model_ref 取 ``transformers/<provider.model_id>``（provider
  声明）。
* provider 缺位：按 model_path 自建 ``scam.models.LocalTransformers``
  （延迟加载——构造只存配置，首次 understand_frames 才加载）。加载前置
  纯文件系统缺失检查：model_path 必须是已存在的本地 HF 快照目录（含
  config.json），缺失 → 结构化 model_unavailable（.details["missing"]
  带清单），绝不触网、绝不自动下载（离线红线）。model_ref 取
  ``transformers/<model_path 快照目录短码>``（HF 快照目录名即 revision
  短码；不含绝对路径）。

dtype 路由（C173-A3 方案 B）
---------------------------
* ``dtype``：显式精度选择，缺省 None=FP32（既有调用逐字节不变）。仅接受
  规范名 ``"float32"``/``"bfloat16"``，其他值构造时 ValueError 明确拒绝
  （绝不静默降级、不猜别名）。
* 自建 provider：dtype 透传 ``scam.models.LocalTransformers(dtype=…)``，
  加载参数与 pixel_values 由 provider 同源派生；加载失败如实结构化上抛，
  **绝不自动回退 FP32**。
* 注入 provider：provider 必须自行声明 ``dtype``（构造时定死，本模块绝不
  事后覆盖模型精度）——声明缺失或与请求不一致 → ValueError 明确拒绝；
  声明一致 → 放行。缺省（不传 dtype）时快照 ``dtype`` 取 provider 声明为
  真相（未声明口径为 float32）。
* 可查性：``snapshot()["dtype"]`` 报配置精度，``snapshot()[
  "last_call_dtypes"]`` 报最近一次调用的请求/实际精度（来自 provider
  ``_last_call_info``）；``diagnostic()`` 六冻结字段不动（冻结合同优先，
  dtype 只进信息面 snapshot）。约束记忆：CPU BF16 加载可行但生成慢
  （C169/C171 实测）；量化/模型版本/生成预算/设备选择不在本参数职责内。

生产超时真实化（沿用 l2_backend 惯例）
--------------------------------------
* understand_frames 的真实推理（BGR→JPEG b64→provider.understand_frames）
  跑在专属单线程 executor；超过 ``infer_timeout_s``（默认 120.0）→ 抛
  :class:`L3InferTimeout`（码 ``timeout``，TimeoutError 子类——stage 按
  except TimeoutError 分类）并把实例标记 poisoned；此后每次调用立即抛
  :class:`L3AdapterIsolated`（码 ``backend_isolated``），不再给卡住实例派任务。
* provider 首次加载同样在该专属 executor 内执行，受 ``load_timeout_s``
  （默认 60.0）约束：超时 → 结构化 model_unavailable（code="load_timeout"）
  并隔离；加载线程不可中止、仍存活的事实由 :meth:`diagnostic`
  （executor_threads_alive）如实呈现，绝不假装已停止。
* 工作线程不可中止：超时的调用可能仍在运行（GIL/CPU/内存残留为事实），
  diagnostic/snapshot 如实报告（线程存活数、残留调用是否仍在跑、
  abortable 恒 False），绝不假装取消成功，也绝不假装恢复——poisoned/
  isolated 都是终态，重建由生产层决定。
* provider 其他加载异常 → 结构化 model_unavailable（失败非终态，phase
  回 unloaded，可重试；详细异常只进抛出的结构化异常/本机日志）。
* 上游推理异常 → :class:`L3InferFailed`（码 ``infer_failed``）。上游自身
  抛出的 TimeoutError（future 已完成）≠ 等待超时 → infer_failed，不毒化
  （与 l2_backend 同一区分）。

生命周期（同一收尾合同）
------------------------
* :meth:`close(timeout_s=5.0)`：幂等。空闲 → executor shutdown 干净退出
  （``{"closed": True, "pending_calls": 0, "threads_alive": 0,
  "close_incomplete": False}``，无线程遗留）；有在途不可中止调用 → 停止
  接单（后续调用立即 AdapterIsolated）+ 返回 ``{"closed": False,
  "pending_calls": n, "threads_alive": k, "close_incomplete": True}``——
  不宣布全部释放、绝不重建实例绕过隔离。停止标志之后才完成的调用结果
  一律丢弃（不发布，计数入 snapshot）。关闭过程自身异常 → 返回结构如实
  报 ``closed=False + close_incomplete=True + error="close_failed"``，
  绝不视为停止成功。C-137 B2 三态区分（与 l2_backend 同一口径）：已完成
  关闭（closed=True）/未完成（close_incomplete=True + 残留）/关闭自身
  异常（closed=False + error 码）。在途调用随后结束时再次 close 即收敛
  为干净收口。
* :meth:`diagnostic()`：六冻结字段与 l2_backend 同形；phase ∈
  unloaded|loading|ready|poisoned|isolated。全部字段不含绝对路径
  （load_error 只含异常类型与失败阶段；详细异常只进本机日志/抛出的
  结构化异常——missing 清单仅在结构化异常里）。

交付前重检（C-137 §6 B1：调用方收不到成功值）
----------------------------------------------
understand_frames 在 future 完成后、**向调用方交付前**，锁下重检
closed/poisoned/generation（交付闸门 :meth:`_delivery_reject_code_locked`）：
已停止/已隔离/代次不符 → 抛结构化拒收（L3AdapterIsolated，code=
"closed_rejected"/"poisoned_rejected"/"generation_rejected"）——调用方
确实收不到成功值，discarded 计数只是补充不是替代。每次 close/隔离请求
递增交付代次（_delivery_gen，snapshot.delivery_generation 可观察），
提交时随单捕获、交付时核对。加载路径同一闸门合同
（:meth:`_finish_load_wait_ok`，迟到模型绝不采用）。与 l2_backend 同一
合同、同一实现模式。

多帧协议
--------
frames_bgr：有序 BGR ndarray 列表，None 项=显式缺帧占位（原样传 None，
绝不伪造图像）；frames_meta 逐帧元信息 dict（None 项归一为 {}、等长防御
对齐）；prompt 原样透传（占位符布局归 models.py 渲染层）。委托
provider.understand_frames 的多帧语义（[N,3,448,448]/占位符=N/行序=帧序）
由 scam.models.LocalTransformers 持有并已被 tests/test_models.py 捕获级
断言覆盖——本模块只做委托与生命周期，不改写映射。

批处理/并行能力（C153 A）
------------------------
:meth:`capabilities` 如实声明：唯一生产 provider 无 batch 入口 → 真实批处理
``batch.supported=False``（**绝不**用循环调用改名 batch）；预处理与推理共用
同一专属单线程 → ``parallel.supported=False``。多开模型实例不是本层的自由度
（模型引用计数=1，重建由生产层决定）。

超时参数命名：本类统一 ``*_timeout_s``（timeout_s/infer_timeout_s/
load_timeout_s；None 或 <=0 表示不设限，不建议）——与 l2_backend 的
close(timeout_s) 口径一致；调用方必须用 timeout_s= 关键字（nvr.py 历史
调用 close(timeout=...) 属参数名不一致，归主会话 M1 修正）。
"""

from __future__ import annotations

import concurrent.futures
import os
import threading
import time
from typing import Any, Dict, List, Optional, Sequence

from scam.win11_l3_contract import L3AdapterIsolated, L3ModelUnavailable, L3VisionModel

__all__ = [
    "LocalTransformersL3Backend",
    "L3InferTimeout",
    "L3InferFailed",
    "INFER_TIMEOUT_S_DEFAULT",
    "LOAD_TIMEOUT_S_DEFAULT",
    "TOTAL_TIMEOUT_S_DEFAULT",
]

INFER_TIMEOUT_S_DEFAULT = 120.0
LOAD_TIMEOUT_S_DEFAULT = 60.0
TOTAL_TIMEOUT_S_DEFAULT = 180.0   # 单次调用总预算口径（load+infer 量级上限）

# 本模块定义/透传的后端异常码（L3 状态分类的 adapter 侧子集）；
# future.result 重抛时按码放行，不二次包装。
_BACKEND_CODES = frozenset(
    {"model_unavailable", "backend_isolated", "timeout", "infer_failed",
     "load_timeout"})

# diagnostic() 冻结取值域（与 l2_backend 同形；load_stage 取值为 L3 侧口径）。
_HEALTH_PHASES = ("unloaded", "loading", "ready", "poisoned", "isolated")
_LOAD_STAGES = ("provider_load", "done")

_EXECUTOR_PREFIX = "scam-l3-backend"


class L3InferTimeout(TimeoutError):
    """understand_frames 等待超过 infer_timeout_s。固定码 timeout；调用未被
    中止，实例随即 poisoned（继承 TimeoutError：stage 按 except TimeoutError
    分类）。"""

    code = "timeout"


class L3InferFailed(RuntimeError):
    """上游推理异常。固定码 infer_failed。"""

    code = "infer_failed"


def _alive_threads(executor: Optional["concurrent.futures.ThreadPoolExecutor"]) -> int:
    """executor 内仍存活的 worker 线程数（私有属性仅作信息性残留报告）。"""
    if executor is None:
        return 0
    threads = tuple(getattr(executor, "_threads", ()) or ())
    return sum(1 for t in threads if t.is_alive())


def _norm_meta(meta):
    """元信息行规范化：None→{}；dict→浅拷贝；非 dict→{"raw": …}（同旧壳）。"""
    if meta is None:
        return {}
    if not isinstance(meta, dict):
        return {"raw": str(meta)}
    return dict(meta)


def _encode_jpeg_b64(frame_bgr):
    """BGR ndarray → 纯 base64 JPEG（无 data: 前缀）。cv2 延迟导入。"""
    import cv2
    ok, buf = cv2.imencode(".jpg", frame_bgr)
    if not ok:
        raise ValueError("JPEG 编码失败")
    import base64
    return base64.b64encode(buf.tobytes()).decode("ascii")


def _ref_code(value) -> str:
    """模型标识收敛为短码：取路径末段（HF 快照目录名即 revision 短码），
    绝不携带盘符/目录形态；收敛后为空 → "model"。"""
    if not value:
        return "model"
    text = os.fspath(value)
    code = os.path.basename(os.path.normpath(text))
    return code or "model"


class LocalTransformersL3Backend(L3VisionModel):
    """唯一 L3 生产适配器：真实 LocalTransformers 多帧 + 有界生命周期。

    参数
    ----
    provider:
        已构造的模型 provider（如 scam.models.LocalTransformers）。缺位时
        按 ``model_path`` 自建（延迟加载，受控本地路径，缺失→结构化
        model_unavailable，绝不下载）。
    model_path:
        自建路径（provider 缺位时必填）：本地 HF 快照目录（含 config.json）。
        只作目录短码进 model_ref，绝不进健康面字段。
    timeout_s:
        单次调用总预算口径（默认 180.0）：自建 provider 的构造 timeout
        透传值，并如实入 snapshot；分阶段有界由 infer/load 两个超时承担。
    infer_timeout_s:
        单次 understand_frames 的有界等待秒数，默认 120.0；None 或 <=0
        表示不设超时（不建议）。超时 → 该调用失败 + 实例 poisoned。
    load_timeout_s:
        provider 首次加载的有界等待秒数，默认 60.0；None 或 <=0 表示不限
        （不建议）。超时 → 结构化 model_unavailable code="load_timeout" +
        隔离（加载线程残留如实）。
    dtype:
        C173-A3 方案 B：显式精度选择（None=FP32 缺省，既有调用不变）。
        仅接受 "float32"/"bfloat16"；自建路径透传 provider 同源派生，注入
        路径要求与 provider 声明一致（缺失/不一致 ValueError）。加载失败
        绝不自动回退 FP32。
    precision_mode:
        缺省uniform；显式mixed_vision_fp32要求dtype=bfloat16，只在provider
        加载时配置视觉/投影FP32、语言BF16。注入provider须声明相同模式。
    """

    def __init__(self, provider=None, *, model_path=None, timeout_s=TOTAL_TIMEOUT_S_DEFAULT,
                 infer_timeout_s=INFER_TIMEOUT_S_DEFAULT,
                 load_timeout_s=LOAD_TIMEOUT_S_DEFAULT, dtype=None,
                 precision_mode=None, attention_implementation=None,
                 vision_chunk_size=None) -> None:
        # C173-A3 dtype 方案 B：先做字符串级快速失败（自建/注入两路径都
        # 拒绝非法值），再做 provider 声明对齐（注入路径绝不事后覆盖精度）。
        if dtype is not None and str(dtype) not in ("float32", "bfloat16"):
            raise ValueError(
                "不支持的 dtype {!r}（仅允许 'float32'/'bfloat16'；显式拒绝，"
                "绝不静默降级）".format(dtype))
        if precision_mode is not None and precision_mode not in ("uniform", "mixed_vision_fp32"):
            raise ValueError("unsupported precision_mode")
        if precision_mode == "mixed_vision_fp32" and dtype != "bfloat16":
            raise ValueError("mixed_vision_fp32 requires explicit bfloat16 language dtype")
        if attention_implementation is not None and attention_implementation not in ("eager", "sdpa"):
            raise ValueError("unsupported attention_implementation")
        if vision_chunk_size is not None and (type(vision_chunk_size) is not int or vision_chunk_size != 1):
            raise ValueError("vision_chunk_size supports only explicit integer 1")
        if provider is None:
            if not model_path:
                raise ValueError(
                    "LocalTransformersL3Backend requires an injected provider "
                    "or an explicit local model_path (offline policy: no "
                    "download, no implicit hub id)")
            options = {key: value for key, value in (
                ("precision_mode", precision_mode),
                ("attention_implementation", attention_implementation),
                ("vision_chunk_size", vision_chunk_size)) if value is not None}
            provider = self._build_provider(model_path, timeout_s, dtype, **options)
        declared_mode = getattr(provider, "precision_mode", "uniform")
        if precision_mode is not None and declared_mode != precision_mode:
            raise ValueError("injected provider precision_mode mismatch")
        self.precision_mode = declared_mode
        declared_attention = getattr(provider, "attention_implementation", None)
        if attention_implementation is not None and declared_attention != attention_implementation:
            raise ValueError("injected provider attention implementation mismatch")
        declared_chunk = getattr(provider, "vision_chunk_size", None)
        if vision_chunk_size is not None and (type(declared_chunk) is not int or declared_chunk != vision_chunk_size):
            raise ValueError("injected provider vision chunk size mismatch")
        self.attention_implementation = declared_attention
        self.vision_chunk_size = declared_chunk
        declared = getattr(provider, "dtype", None)
        if dtype is not None:
            dtype_text = str(dtype)
            if declared is None:
                raise ValueError(
                    "注入的 provider 未声明 dtype（{}）；无法保证 dtype 路由，"
                    "请以 provider 构造时的显式 dtype 为准或对齐后注入".format(
                        type(provider).__name__))
            if str(declared) != dtype_text:
                raise ValueError(
                    "dtype 不一致：backend 请求 {}，注入 provider 声明 {}；"
                    "绝不静默覆盖 provider 已定精度".format(
                        dtype_text, declared))
            self.dtype = dtype_text
        else:
            # 缺省：provider 声明即真相（自建 provider 已归一 float32/bfloat16）
            self.dtype = str(declared) if declared is not None else "float32"
        self._provider = provider
        self._provider_built_here = model_path is not None and provider is not None
        self._model_path = os.fspath(model_path) if model_path else None

        self.timeout_s = (float(timeout_s)
                          if timeout_s is not None and float(timeout_s) > 0
                          else None)
        self.infer_timeout_s = (float(infer_timeout_s)
                                if infer_timeout_s is not None and infer_timeout_s > 0
                                else None)
        self._load_timeout_s = (float(load_timeout_s)
                                if load_timeout_s is not None and load_timeout_s > 0
                                else None)

        # model_ref：provider 声明（model_id）或 model_path 快照目录短码，
        # 一律收敛为末段短码（model_id 对 Windows 反斜杠路径可能携带完整
        # 路径形态——必须清洗，健康面/model_ref 零路径泄漏）。
        ref = getattr(provider, "model_id", None)
        if not ref and self._model_path:
            ref = self._model_path
        self.model_ref = "transformers/{}".format(_ref_code(ref))

        # 运行态（构造绝不触碰 provider 加载）：
        self._lock = threading.Lock()
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._provider_loaded = False
        self._load_error: Optional[str] = None   # 健康面口径：类型+阶段，无路径
        self._poisoned = False
        self._poison_reason: Optional[str] = None
        self._pending: List[concurrent.futures.Future] = []
        self._pending_future: Optional[concurrent.futures.Future] = None
        self._phase = "unloaded"                 # _HEALTH_PHASES 之一
        self._load_stage: Optional[str] = None   # _LOAD_STAGES 之一（None=未开始）
        self._stages_seen: List[str] = []
        self._load_future: Optional[concurrent.futures.Future] = None
        self._load_gen = 0                       # 迟到加载结果的代次令牌
        self._load_ms: Optional[float] = None
        self._close_requested = False
        self._close_error: Optional[str] = None  # 关闭自身异常码（B2 三态）
        self._delivery_gen = 0                 # C-137 B1 交付代次：close/隔离递增
        self._discarded_results = 0
        self._discarded_loads = 0

    # -- L3VisionModel 协议 ---------------------------------------------------

    def understand_frames_measured(self, prompt, frames_bgr, frames_meta, measurement):
        return self._understand_frames(prompt, frames_bgr, frames_meta, measurement)

    def understand_frames(self, prompt, frames_bgr, frames_meta) -> dict:
        return self._understand_frames(prompt, frames_bgr, frames_meta)

    def _understand_frames(self, prompt, frames_bgr, frames_meta, measurement=None) -> dict:
        """L3VisionModel 协议：委托真实多帧路径（有界 + 可隔离）。

        frames_bgr：有序 BGR ndarray 列表（None=显式缺帧占位，原样传
        provider，绝不伪造图像）；frames_meta：逐帧元信息 dict 列表（等长
        防御对齐）。返回 provider 输出 dict（原样，不加工）。
        """
        refuse = self._refuse_reason()
        if refuse is not None:
            raise self._isolated(
                "backend_isolated: backend refuses new work ({})".format(refuse),
                refuse_reason=refuse)
        self._ensure_loaded()
        with self._lock:
            executor = self._ensure_executor_locked()
        frames = list(frames_bgr) if frames_bgr is not None else []
        meta = [_norm_meta(m) for m in (frames_meta or ())]
        while len(meta) < len(frames):    # 防御性等长对齐（stage 已保证）
            meta.append({})
        try:
            if measurement is None:
                fut = executor.submit(self._call_once, prompt, frames, meta)
            else:
                fut = executor.submit(self._call_once, prompt, frames, meta, measurement)
        except RuntimeError:
            # close() 已收口 executor（拒绝检查先于 close 到达的竞态窗口）：
            # 结构化拒收——绝不给已关闭的实例派任务，也绝不让裸 RuntimeError
            # 泄漏给调用方/stage。
            raise self._isolated(
                "backend_isolated: the executor is already shut down (close() "
                "came first); the call is refused and its result will never be "
                "published") from None
        fut.add_done_callback(self._drop_late_result)
        with self._lock:
            self._pending.append(fut)
            self._prune_pending_locked()
            self._pending_future = fut
            gen = self._delivery_gen    # C-137 B1：交付代次随单捕获（原子）
        timeout = self.infer_timeout_s
        try:
            if timeout is not None:
                result = fut.result(timeout=timeout)
            else:
                result = fut.result()
        except concurrent.futures.CancelledError:
            raise self._isolated(
                "backend_isolated: the submitted call was discarded "
                "(backend closed/stopped); its result will never be published"
            ) from None
        except TimeoutError:
            # Python >=3.11：concurrent.futures.TimeoutError 即内建 TimeoutError。
            if fut.done():
                # future 已完成且抛的是上游自己的 TimeoutError——不是等待超时。
                cause = fut.exception()
                raise L3InferFailed(
                    "infer_failed: upstream raised TimeoutError: {!r}".format(cause)
                ) from cause
            with self._lock:
                self._poisoned = True
                self._phase = "poisoned"
                self._poison_reason = (
                    "understand_frames exceeded infer_timeout_s={}s; the upstream "
                    "call may still be running in the dedicated worker thread and "
                    "cannot be aborted".format(self.infer_timeout_s))
                self._delivery_gen += 1   # C-137 B1：隔离请求递增交付代次
            self._retire_executor_best_effort()
            if measurement is not None:
                measurement.timeout()
            raise L3InferTimeout(
                "timeout: L3 understand_frames exceeded infer_timeout_s={}s; the "
                "worker call is NOT cancelled (cannot be aborted) and the backend "
                "is now isolated".format(self.infer_timeout_s)) from None
        except Exception as exc:
            code = getattr(exc, "code", None)
            if code in _BACKEND_CODES:
                raise  # 合同异常原样上抛，交 stage 分类
            raise L3InferFailed(
                "infer_failed: upstream LocalTransformers error: {}: {}".format(
                    type(exc).__name__, exc)) from exc
        # -- C-137 B1 交付前重检（交付闸门）：future 成功完成后、交回调用方
        #    前锁下重检 closed/poisoned/generation——拒收时成功值就地丢弃，
        #    调用方只收到结构化拒收异常（与完成回调协同去重计数）。--
        with self._lock:
            reject = self._delivery_reject_code_locked(gen)
            if reject is not None and not getattr(
                    fut, "_scam_discard_counted", False):
                self._discarded_results += 1
                try:
                    fut._scam_discard_counted = True
                except Exception:
                    pass
        if reject is not None:
            raise self._reject_delivery(reject)
        return result

    def capabilities(self) -> Dict[str, Any]:
        """C153 A：批处理/并行能力的**如实**声明（纯只读，绝不触发加载）。

        判定依据（本机生产事实，不靠文档猜）：
        - 唯一生产 provider `scam.models.LocalTransformers` 只有单次
          ``understand_frames(prompt, frames_b64, frames_meta)`` 入口，无
          batch 形参、无 batch 语义；本类亦不提供"循环调用改名 batch"的
          入口 —— 因此 ``batch.supported=False``（真实批处理 unsupported）。
        - 本 adapter 的推理与 BGR→JPEG 预处理共用**同一个**专属单线程
          executor（``max_workers=1``）：输入侧与推理侧不并行 ——
          ``parallel.supported=False``。
        - 帧上限取本 provider 侧口径（448 单 tile 多帧占位符协议；真正的
          每调用帧上限由 stage 的 `L3Budget.max_frames_per_task` 决定）。

        字段不含路径、不含张量、不触发任何模型加载（构造后即可读）。
        """
        frames_per_call = 8          # 与 L3Budget.max_frames_per_task 冻结默认同量级
        return {
            "model_ref": self.model_ref,
            "backend": "transformers",
            "batch": {
                "supported": False,
                "reason": "provider_has_no_batch_api",
                "max_frames_per_call": frames_per_call,
                "note": ("single-call provider API only; wrapping repeated "
                         "calls is not real batching and is not offered"),
            },
            "parallel": {
                "supported": False,
                "reason": "single_worker_thread",
                "workers": 1,
                "note": ("BGR->JPEG preprocessing and provider inference run "
                         "on the same dedicated single worker thread; no real "
                         "input/inference overlap is claimed"),
            },
            "infer_timeout_s": self.infer_timeout_s,
            "load_timeout_s": self._load_timeout_s,
            "timeout_s": self.timeout_s,
            "phase": self._phase,
            "poisoned": self._poisoned,
        }

    def close(self, timeout_s: float = 5.0) -> Dict[str, Any]:
        """生命周期收口（与 l2_backend 同一收尾合同）。幂等。

        空闲停止：等待在途任务（无）→ executor shutdown 干净退出，返回
        ``{"closed": True, "pending_calls": 0, "threads_alive": 0,
        "close_incomplete": False}``。
        有在途不可中止调用：等待 ``timeout_s`` 秒仍未完成 → 停止接单 +
        ``{"closed": False, "pending_calls": n, "threads_alive": k,
        "close_incomplete": True}``——不宣布全部释放，绝不重建实例绕过
        隔离；停止标志之后才完成的调用结果一律丢弃（交付闸门同时保证
        调用方收不到成功值）。关闭过程自身异常 → ``closed=False +
        close_incomplete=True + error="close_failed"``（返回结构如实，供
        停机汇总判定，绝不视为停止成功）。每次 close 请求递增交付代次
        （C-137 B1）。
        """
        with self._lock:
            self._close_requested = True
            self._close_error = None        # 如实反映最近一次 close 尝试
            self._delivery_gen += 1         # C-137 B1：每次 close 请求递增代次
            if self._phase != "poisoned":   # poisoned 是更早的终态，保持
                self._phase = "isolated"
            self._prune_pending_locked()
            pending = list(self._pending)
            executor = self._executor
        deadline = time.monotonic() + max(float(timeout_s), 0.0)
        for fut in pending:
            remaining = max(deadline - time.monotonic(), 0.0)
            try:
                fut.result(timeout=remaining)
            except (Exception, concurrent.futures.CancelledError):
                pass  # 上游异常/超时/取消都不是 close 的职责——只是不再等它
        with self._lock:
            self._prune_pending_locked()
            still = [f for f in self._pending if not f.done()]
        if still:
            # 在途不可中止：如实报告残留；shutdown(wait=False) 让 worker 在
            # 当前任务结束后自然退出（不可中止也不假装中止）。
            if executor is not None:
                try:
                    executor.shutdown(wait=False)
                except Exception:
                    pass
            return {"closed": False,
                    "pending_calls": len(still),
                    "threads_alive": _alive_threads(executor),
                    "close_incomplete": True}
        if executor is not None:
            try:
                executor.shutdown(wait=True)   # 干净收口：join 全部 worker 线程
            except Exception:
                # 关闭自身异常：绝不视为停止成功（停机汇总按结构判定）。
                with self._lock:
                    self._close_error = "close_failed"
                return {"closed": False,
                        "pending_calls": 0,
                        "threads_alive": _alive_threads(executor),
                        "close_incomplete": True,
                        "error": "close_failed"}
        return {"closed": True,
                "pending_calls": 0,
                "threads_alive": 0,
                "close_incomplete": False}

    def diagnostic(self) -> Dict[str, Any]:
        """C-136 冻结健康字段（与 l2_backend 六字段同形），健康面直接消费。

        全部字段不含绝对路径：``load_error`` 只含异常类型与失败阶段；
        详细异常（可能含路径）只进本机日志/抛出的结构化异常。
        """
        with self._lock:
            self._prune_pending_locked()
            return {
                "phase": self._phase,
                "load_stage": self._load_stage,
                "pending_calls": len(self._pending),
                "executor_threads_alive": _alive_threads(self._executor),
                # C-137 B2：在途残留与关闭自身异常都算"关闭未完成"（如实）。
                "close_incomplete": bool((self._close_requested
                                          and self._pending)
                                         or self._close_error),
                "load_error": self._load_error,
            }

    def snapshot(self) -> Dict[str, Any]:
        """如实报告加载态与超时隔离残留（不假装取消/恢复）；在 diagnostic
        冻结字段之外补充信息性口径（丢弃计数/超时配置等，无路径）。"""
        with self._lock:
            fut = self._pending_future
            self._prune_pending_locked()
            pending_running = bool(
                fut is not None and not fut.done() and not fut.cancelled())
            # C173-A3：请求精度 vs 实际精度如实透出（来源 provider
            # _last_call_info；实际取不到的键不列，绝无编造值）。
            last_info = getattr(self._provider, "_last_call_info", None)
            last_call_dtypes = None
            if isinstance(last_info, dict):
                last_call_dtypes = {
                    key: last_info[key]
                    for key in ("dtype_requested", "model_dtype",
                                "pixel_values_dtype", "precision_mode", "component_dtypes")
                    if last_info.get(key) is not None} or None
            return {
                "model_ref": self.model_ref,
                "backend": "transformers",
                "dtype": self.dtype,
                "precision_mode": self.precision_mode,
                "attention_implementation": self.attention_implementation,
                "vision_chunk_size": self.vision_chunk_size,
                "last_call_execution": ({key: last_info[key] for key in (
                    "attention_requested", "language_attention", "vision_chunk_size")
                    if last_info.get(key) is not None} or None)
                    if isinstance(last_info, dict) else None,
                "last_call_dtypes": last_call_dtypes,
                "loaded": self._provider_loaded,
                "load_error": self._load_error,
                "poisoned": self._poisoned,
                "poison_reason": self._poison_reason,
                "infer_timeout_s": self.infer_timeout_s,
                "load_timeout_s": self._load_timeout_s,
                "timeout_s": self.timeout_s,
                "provider_built_here": self._provider_built_here,
                "pending_call_still_running": pending_running,
                "pending_call_done": (fut.done() if fut is not None else None),
                "worker_threads_alive": _alive_threads(self._executor),
                "worker_abortable": False,
                "note": ("a timed-out upstream call cannot be aborted; its worker "
                         "thread may keep running and is reported here as-is, "
                         "never as cancelled"),
                "phase": self._phase,
                "load_stage": self._load_stage,
                "load_stages_seen": list(self._stages_seen),
                "load_ms": self._load_ms,
                "pending_calls": len(self._pending),
                "executor_threads_alive": _alive_threads(self._executor),
                "close_requested": self._close_requested,
                "close_error": self._close_error,
                "delivery_generation": self._delivery_gen,
                "close_incomplete": bool((self._close_requested and self._pending)
                                         or self._close_error),
                "discarded_results": self._discarded_results,
                "discarded_loads": self._discarded_loads,
            }

    # -- 内部：构造与来源 ------------------------------------------------------

    @staticmethod
    def _build_provider(model_path, timeout_s, dtype=None, precision_mode=None,
                        attention_implementation=None, vision_chunk_size=None):
        """按显式本地 model_path 自建 LocalTransformers（延迟加载；只存配置，
        不 import torch/transformers、不触网）。dtype=C173-A3 方案 B 显式
        精度选择（None=FP32 缺省；校验与同源派生归 provider）。"""
        from scam.models import LocalTransformers
        timeout = (int(timeout_s) if timeout_s is not None
                   and float(timeout_s) > 0 else 120)
        options = {key: value for key, value in (
            ("precision_mode", precision_mode),
            ("attention_implementation", attention_implementation),
            ("vision_chunk_size", vision_chunk_size)) if value is not None}
        return LocalTransformers(model_path=os.fspath(model_path),
                                 timeout=timeout, dtype=dtype, **options)

    def _check_missing(self) -> List[str]:
        """自建路径的纯文件系统缺失项检查（零 import、零网络）——离线红线：
        缺失即结构化拒绝，绝不把 repo id 形态的路径交给 transformers 的
        远端解析去触发下载。注入 provider 的可用性由其自身加载路径如实
        上报。"""
        if not self._provider_built_here:
            return []
        missing: List[str] = []
        mp = self._model_path or ""
        if not mp:
            missing.append("model_path is required when provider is not injected")
        elif not os.path.exists(mp):
            missing.append(
                "local model path not found (offline policy: no download): "
                "{}".format(mp))
        elif not os.path.isdir(mp):
            missing.append("model_path is not a directory: {}".format(mp))
        elif not os.path.isfile(os.path.join(mp, "config.json")):
            missing.append(
                "config.json not found under model_path (not a local HF "
                "snapshot layout): {}".format(mp))
        return missing

    # -- 内部：隔离与拒绝 ------------------------------------------------------

    @property
    def poisoned(self) -> bool:
        return self._poisoned

    @staticmethod
    def _isolated(message, **details) -> L3AdapterIsolated:
        payload = dict(details)
        payload.setdefault("code", "backend_isolated")
        exc = L3AdapterIsolated(message, details=payload)
        try:
            exc.code = "backend_isolated"
        except Exception:
            pass
        return exc

    @staticmethod
    def _unavailable(message, *, code="model_unavailable",
                     missing: Optional[Sequence[str]] = None,
                     details: Optional[Dict[str, Any]] = None) -> L3ModelUnavailable:
        payload = dict(details or {})
        payload.setdefault("code", code)
        if missing:
            payload["missing"] = list(missing)
        exc = L3ModelUnavailable(message, details=payload)
        try:
            exc.code = code
        except Exception:
            pass
        return exc

    def _refuse_reason(self) -> Optional[str]:
        """拒绝接单的原因（隔离/中毒/已关闭）；None=可接单。"""
        if self._poisoned:
            return self._poison_reason or (
                "a previous failure permanently isolated this instance")
        if self._close_requested:
            return "close() was called; this instance no longer accepts calls"
        return None

    def _delivery_reject_code_locked(self, gen: int) -> Optional[str]:
        """（持锁）C-137 B1 交付闸门裁决：future 成功完成后、交回调用方前
        重检 poisoned/closed/generation。返回拒收码（poisoned_rejected /
        closed_rejected / generation_rejected）或 None（可交付）。"""
        if self._poisoned:
            return "poisoned_rejected"
        if self._close_requested:
            return "closed_rejected"
        if gen != self._delivery_gen:
            return "generation_rejected"
        return None

    @staticmethod
    def _reject_delivery(reject: str) -> L3AdapterIsolated:
        """C-137 B1 交付闸门拒收异常：调用方收不到成功值，只收到结构化拒收
        （code/reject_code=closed_rejected|poisoned_rejected|
        generation_rejected）。"""
        exc = L3AdapterIsolated(
            "backend_isolated: result delivery rejected ({}): the backend was "
            "closed/isolated after this call was submitted; the caller never "
            "receives its success value".format(reject),
            details={"code": reject, "reject_code": reject})
        try:
            exc.code = reject
        except Exception:
            pass
        return exc

    # -- 内部：executor 与 pending ---------------------------------------------

    def _ensure_executor_locked(self) -> "concurrent.futures.ThreadPoolExecutor":
        """（持锁）惰性创建专属单线程 executor：加载与推理共用一条 worker
        线程，加载超时后该线程仍存活的事实由线程存活数如实呈现。"""
        if self._executor is None:
            self._executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=1, thread_name_prefix=_EXECUTOR_PREFIX)
        return self._executor

    def _prune_pending_locked(self) -> None:
        if self._pending:
            self._pending = [f for f in self._pending if not f.done()]

    def _retire_executor_best_effort(self) -> None:
        """隔离（加载超时/推理中毒）后退役专属 executor：shutdown(wait=False)
        不等待也不取消——在途调用继续跑完（不可中止，绝不假装取消），随后
        worker 自然退出；线程残留只减不增，事实由 diagnostic 如实呈现。"""
        executor = self._executor
        if executor is not None:
            try:
                executor.shutdown(wait=False)
            except Exception:
                pass

    def _drop_late_result(self, fut: "concurrent.futures.Future") -> None:
        """infer future 完成回调（worker 线程内执行）：停止/隔离之后才完成
        的结果一律丢弃——消费掉（含异常标记已读）且绝不发布，计数如实
        （与交付闸门协同去重：闸门只补计回调未及计数的一次，一个 future
        至多计一次丢弃）。"""
        try:
            if not (self._close_requested or self._poisoned):
                return
            try:
                fut.exception()
            except Exception:
                pass
            with self._lock:
                self._discarded_results += 1
                try:
                    fut._scam_discard_counted = True
                except Exception:
                    pass
        except Exception:
            pass

    # -- 内部：有界加载 --------------------------------------------------------

    def _provider_load_fn(self):
        """provider 的加载入口（鸭子类型）：优先 load(timeout_s)（B2 参数化
        入口，本处不传预算——预算由本 backend 的 load_timeout_s 统一承担，
        残留线程归本 backend executor 如实呈现）；旧 provider 退回
        _ensure_loaded；都没有则视为预就绪（调用失败如实分类）。"""
        load = getattr(self._provider, "load", None)
        if callable(load):
            return lambda: load()
        ensure = getattr(self._provider, "_ensure_loaded", None)
        if callable(ensure):
            return ensure
        return lambda: None

    def _ensure_loaded(self) -> None:
        """首次调用的加载路径：拒绝态检查 →（自建）缺失检查 → 专属线程内
        有界加载（load_timeout_s）。任何失败 → 结构化异常。"""
        if self._provider_loaded:
            return
        with self._lock:
            if self._provider_loaded:
                return
            refuse = self._refuse_reason()
            if refuse is not None:
                raise self._isolated(
                    "backend_isolated: load refused ({})".format(refuse))
            fut = self._load_future
            if fut is None:
                missing = self._check_missing()
                if missing:
                    raise self._unavailable(
                        "model_unavailable: L3 backend cannot start; missing: "
                        + "; ".join(missing),
                        code="model_unavailable", missing=missing)
                self._phase = "loading"
                # 专属单线程 executor 内有界加载；阶段推进由加载线程内 set（锁保护）。
                self._prune_pending_locked()
                executor = self._ensure_executor_locked()
                fut = executor.submit(self._load_worker, self._load_gen)
                self._pending.append(fut)
                self._load_future = fut
        timeout = self._load_timeout_s
        try:
            if timeout is not None:
                fut.result(timeout=timeout)
            else:
                fut.result()
        except concurrent.futures.CancelledError:
            raise self._isolated(
                "backend_isolated: load was discarded (backend closed/stopped); "
                "refusing to use it") from None
        except TimeoutError:
            if fut.done():
                # 恰在超时瞬间结算完成：按真实结局处理，不冒充超时。
                cause = fut.exception()
                if cause is None:
                    with self._lock:
                        return self._finish_load_wait_ok()
                with self._lock:
                    if not self._poisoned and not self._close_requested:
                        self._reset_load_locked()
                code = getattr(cause, "code", None)
                if code in _BACKEND_CODES:
                    raise cause
                raise self._unavailable(
                    "model_unavailable: L3 provider load failed: {}: {}".format(
                        type(cause).__name__, cause),
                    code="model_unavailable",
                    missing=["provider load failed: {}: {}".format(
                        type(cause).__name__, cause)]) from cause
            self._isolate_load_timeout()
            raise self._unavailable(
                "load_timeout: L3 provider first load did not complete within "
                "load_timeout_s={}s; the load thread is still alive and cannot "
                "be aborted; this instance is isolated".format(
                    self._load_timeout_s),
                code="load_timeout",
                details={"timeout_s": self._load_timeout_s,
                         "load_stage": self._load_stage}) from None
        except Exception as exc:
            with self._lock:
                if not self._poisoned and not self._close_requested:
                    self._reset_load_locked()
            code = getattr(exc, "code", None)
            if code in _BACKEND_CODES:
                raise  # 加载线程内抛的结构化异常原样上抛
            raise self._unavailable(
                "model_unavailable: L3 provider load failed: {}: {}".format(
                    type(exc).__name__, exc),
                code="model_unavailable",
                missing=["provider load failed: {}: {}".format(
                    type(exc).__name__, exc)]) from exc
        with self._lock:
            return self._finish_load_wait_ok()

    def _reset_load_locked(self) -> None:
        """（持锁）加载失败（非超时隔离）后的可重试复位：清掉已失败的
        load future，让下一次调用重新提交加载（单飞不受影响）；失败非终态，
        但绝不复活已隔离/已关闭的实例。"""
        self._phase = "unloaded"
        self._load_stage = None
        self._load_future = None

    def _finish_load_wait_ok(self) -> None:
        """（持锁）加载 future 正常结算后的收尾：模型可能已被丢弃
        （close/隔离先到）——绝不绕过隔离采用迟到的加载结果（C-137 B1
        交付闸门同一合同：调用方收到结构化拒收，绝不收到成功值）。"""
        if not self._provider_loaded:
            if self._poisoned:
                reject = "poisoned_rejected"
            elif self._close_requested:
                reject = "closed_rejected"
            else:
                reject = "generation_rejected"
            raise self._isolated(
                "backend_isolated: load finished but its result was discarded "
                "(close()/isolation came first); the late model is not adopted",
                reject_code=reject, discarded_load=True)

    def _isolate_load_timeout(self) -> None:
        """（有锁调用）加载超时隔离：诚实超时，不假装加载线程已停止。"""
        with self._lock:
            if self._provider_loaded:
                return  # 竞态：实际已就绪
            self._load_gen += 1          # 迟到的加载结果按代次丢弃
            self._delivery_gen += 1      # C-137 B1：隔离请求递增交付代次
            self._phase = "isolated"
            self._poisoned = True
            self._poison_reason = (
                "first load exceeded load_timeout_s={}s; the load thread keeps "
                "running and cannot be aborted; isolation is permanent, rebuild "
                "is a production-layer decision".format(self._load_timeout_s))
            self._load_error = (
                "LoadTimeout: first load exceeded load_timeout_s={:.1f}s "
                "(load thread still alive; not abortable)".format(
                    float(self._load_timeout_s)))
        self._retire_executor_best_effort()

    def _set_load_stage_locked(self, stage: str) -> None:
        """（持锁）加载线程内推进 diagnostic.load_stage。"""
        self._load_stage = stage
        if stage not in self._stages_seen:
            self._stages_seen.append(stage)

    def _load_worker(self, gen: int) -> None:
        """专属 executor 线程内的 provider 加载：provider_load → done → 就绪。
        任何异常原样上抛交等待方结构化包装；迟到/已停的加载结果按代次丢弃
        （不绕过隔离采用）。"""
        try:
            with self._lock:
                self._set_load_stage_locked("provider_load")
            t0 = time.perf_counter()
            self._provider_load_fn()()
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            with self._lock:
                if gen != self._load_gen or self._close_requested:
                    self._discarded_loads += 1   # 迟到/已停：结果丢弃，不绕过隔离
                    return
                self._provider_loaded = True
                self._set_load_stage_locked("done")
                self._load_ms = elapsed_ms
                self._phase = "ready"
        except Exception as exc:
            with self._lock:
                if not self._poisoned and not self._close_requested:
                    if getattr(exc, "code", None) not in _BACKEND_CODES:
                        stage = self._load_stage or "load"
                        # 健康面口径：类型+失败阶段，不含路径；详细异常只进
                        # 本机日志/抛出的结构化异常。
                        self._load_error = "{}: {} failed".format(
                            type(exc).__name__, stage)
                    self._phase = "unloaded"
                    self._load_stage = None
            raise

    # -- 内部：推理 ------------------------------------------------------------

    def _call_once(self, prompt, frames_bgr, frames_meta, measurement=None) -> dict:
        """在专属 executor 线程内执行：BGR→b64（缺帧占位 None 直通）→
        真实有序多帧路径（多图占位符+pixel_values 拼接，见 models.py——
        映射语义归 provider，本层不改写）。"""
        if measurement is not None:
            measurement.emit("backend_preprocess_start")
        b64s = [None if f is None else _encode_jpeg_b64(f) for f in frames_bgr]
        if measurement is not None:
            measurement.emit("backend_preprocess_end")
            measurement.start_model()
        try:
            result = self._provider.understand_frames(prompt, b64s, frames_meta)
        except BaseException:
            if measurement is not None:
                measurement.finish_model(failed=True)
            raise
        if measurement is not None:
            measurement.finish_model()
        return result
