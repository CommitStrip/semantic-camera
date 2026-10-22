"""C-135 L2 真实 RelateAnything 本机适配器（scam.win11_l2_backend）。

实现 docs/context/L2-接口冻结-C134.md §3 的 ``L2RelationModel`` 协议
（鸭子类型；协议基类与状态枚举由子代理 B 的 ``scam.win11_l2_contract``
持有，本模块对其动态解析、缺位时用本地同名回退类，主会话集成时统一）：

    model_ref: str
    infer(frame_bgr, boxes_px, labels, vocabulary) -> list[dict]
        # [{"s": i, "o": j, "relation": str, "graph": "spatial"|"semantic",
        #   "score": float}]；只含上游真实输出，无关系返回空列表，分数原样。

上游（真实本机克隆，不复制进本仓库）
------------------------------------
* 克隆位置：``D:\\Program\\Zcode\\RelateAnything``（构造参数 ``repo_path``
  传入；首次 infer 时注入 ``sys.path`` 后 ``import relsgg``）。
* 实测入口（api.py:107-149 / 250-337，上游 commit 06766fd）：
  ``RelateAnything.from_checkpoint(ckpt_path, predicates=None, device="cpu",
  text_student=None, ...)`` 与 ``ra.predict(image, boxes_xyxy, box_labels=...,
  decompose=True) -> {"spatial": [Triplet...], "semantic": [Triplet...]}``；
  ``Triplet.subject_idx/.object_idx/.predicate/.score``（decompose 模式分数
  已过 sigmoid，为上游该模式的原样输出）。
* 输入：HWC uint8 BGR（OpenCV 读帧原样直喂，不做坐标换算——归一化→像素
  的唯一切换点在 B 的 stage）+ ``[N,4]`` 像素 xyxy 框（api.py:250-267）。
* 权重：本机 HF 缓存 ``models--maelic--relsgg-vits16plus``（model.pth /
  text_student.pt / predicate_embeddings.npz / calibration.json /
  tokenizer.json），历史上由 work/relate-anything-report.json 记录的试跑
  下载而来；本模块只读使用，绝不下载、绝不联网。
* 全离线保证：显式传 text_student 旁路 ``resolve_student_path`` 的 hf://
  分支（relsgg/text/student.py:154-168）；发布检查点内嵌 backbone 配置，
  ``materialize_backbone_config`` 写临时目录、``AutoConfig.from_pretrained``
  只读本地（relsgg/checkpoint.py:48-59）；tokenizer 用检查点同目录文件
  （relsgg/text/student.py:23-33）。``from_pretrained``/hub 下载路径在本
  模块中不出现（测试静态断言）。

延迟加载（C-135：状态化 + 有界）
--------------------------------
构造只存配置（repo_path/checkpoint/vocabulary/infer_timeout_s/
load_timeout_s/device）并从 ``.git`` 文件读取 commit 短码拼 model_ref
（纯文件读，不 import 不加载，不跑子进程）；首次 infer 才在专属单线程
executor 内加载：缺失项清单检查 → 来源防错配检查（sys.modules 已有
``relsgg`` 且其 ``__file__`` 不在配置 repo_path 内 → 结构化拒绝，
error_code="source_mismatch"）→ import torch/relsgg → ``from_checkpoint``
加载权重（构造期词表的文本编码发生在该调用内部，本机实测约 20s）。
加载全程受 ``load_timeout_s``（默认 60.0，构造可覆盖）约束：超时 →
加载失败隔离（ModelUnavailable code="load_timeout"），加载线程仍存活的
事实由 :meth:`diagnostic` 如实报告，绝不假装已停止。加载阶段在加载线程
内推进 diagnostic.load_stage（import → checkpoint → vocabulary → done，
锁保护）；加载耗时按阶段记入 :meth:`snapshot` 的 ``load_ms``。
缺失项/来源错配 → :class:`ModelUnavailable`（固定错误码 + ``.missing``
清单），绝不回退假模型。

model_ref 区分权重实际版本：加载成功后为
``relateanything/<上游 commit 短码>/<checkpoint sha256 前 16 位>``
（sha256 对检查点文件实算）；加载未成功时保留文件名占位。

<2 个框直接返回空列表且不触发加载：少于两个区域不存在关系对，属真实
空结果，非模型态（no_objects/single_object 由 stage 判定）。

超时与隔离
----------
predict（含首次词表切换）在同一专属单线程 ``ThreadPoolExecutor`` 执行；
超过 ``infer_timeout_s``（默认 10.0）→ 抛 :class:`InferTimeout`（码
``timeout``）并将 adapter 标记 poisoned；此后每次 infer 立即抛
:class:`AdapterIsolated`（码 ``backend_isolated``），不再给卡住实例派
任务。工作线程不可中止：超时的调用可能仍在运行（GIL/CPU/内存占用残留
为事实），:meth:`snapshot`/:meth:`diagnostic` 如实报告（线程存活数、
残留调用是否仍在跑、abortable 恒 False），绝不假装取消成功，也绝不假装
恢复——poisoned 是终态，重建由生产层决定（§2）。停止/隔离之后才完成的
上游结果一律丢弃（不发布），丢弃计数如实入 snapshot。

上游其他异常→ :class:`InferFailed`（码 ``infer_failed``）。

生命周期（C-135 §7）
--------------------
* :meth:`close(timeout_s=5.0)`：空闲停止 → executor shutdown 干净退出
  （``{"closed": True, ...}``，无线程遗留，幂等）；有在途不可中止调用 →
  停止接单（后续 infer 立即 AdapterIsolated）+ 返回
  ``{"closed": False, "pending_calls": n, "threads_alive": k,
  "close_incomplete": True}``——不宣布全部释放、绝不重建实例绕过隔离。
  在途调用之后完成（解除/自然结束），再次 close 即收敛为干净收口。
  C-137 B2 三态区分（与 l3_backend 同一口径）：已完成关闭（closed=True）/
  未完成（close_incomplete=True + pending/threads 残留如实）/关闭自身异常
  （closed=False + close_incomplete=True + error="close_failed"）。
* :meth:`diagnostic()`：冻结健康字段
  ``{phase, load_stage, pending_calls, executor_threads_alive,
  close_incomplete, load_error}``，phase ∈ unloaded|loading|ready|
  poisoned|isolated；健康面直接消费，全部字段不含绝对路径
  （load_error 只含异常类型与失败阶段，详细异常只进本机日志/抛出的
  结构化异常）。

交付前重检（C-137 §6 B1：调用方收不到成功值）
----------------------------------------------
infer 在 future 完成后、**向调用方交付前**，锁下重检
closed/poisoned/generation（交付闸门 :meth:`_delivery_reject_code_locked`）：
已停止/已隔离/代次不符 → 抛结构化拒收（AdapterIsolated 形态，code=
"closed_rejected"/"poisoned_rejected"/"generation_rejected"）——调用方
确实收不到成功值，discarded 计数只是补充不是替代。每次 close/隔离请求
递增交付代次（_delivery_gen，snapshot.delivery_generation 可观察），
提交时随单捕获、交付时核对。加载路径同一闸门合同
（:meth:`_finish_load_wait_ok`，迟到模型绝不采用）。

许可证事实（不作法律结论）
--------------------------
* 上游代码 LICENSE = AGPL-3.0-only，另有 AGPLv3 §7 附加条款（NOTICE）：
  界面须保留署名 "Based on RelateAnything by Maëlic Neau" 及仓库链接；
  不得用 "RelateAnything"/作者名做衍生产品宣传；另有商业授权渠道。
* 权重与 RA-4M 标注另有条款（THIRD_PARTY_NOTICES.md）：RA-4M 关系标注由
  google/gemma-4-26B-A4B-it 生成，随附 Gemma Terms of Use 声明，下游使用
  须遵守 Gemma Prohibited Use Policy。
* 本模块只运行、不复制、不分发上游代码/权重。上述为事实记录；本仓分发
  义务（AGPL 触发条件、商用安排）为未决项，未作法律结论。

生产禁 fake：本模块无任何 fake/回退路径；tests/test_win11_l2_backend.py
含对生产入口（scam/nvr.py）的契约式静态断言。
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import importlib
import os
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

__all__ = [
    "RelateAnythingAdapter",
    "ModelUnavailable",
    "AdapterIsolated",
    "InferTimeout",
    "InferFailed",
    "INFER_TIMEOUT_S_DEFAULT",
    "LOAD_TIMEOUT_S_DEFAULT",
]

INFER_TIMEOUT_S_DEFAULT = 10.0
LOAD_TIMEOUT_S_DEFAULT = 60.0

# 本模块/合同层定义的后端异常码（L2 状态分类的 adapter 侧子集）；
# future.result 重抛时按码放行，不二次包装。
_BACKEND_CODES = frozenset(
    {"model_unavailable", "backend_isolated", "timeout", "infer_failed",
     "load_timeout", "source_mismatch"}
)

# diagnostic()/健康面的冻结取值域（L2L3-接口冻结-C135.md §5/§7）。
_HEALTH_PHASES = ("unloaded", "loading", "ready", "poisoned", "isolated")
_LOAD_STAGES = ("import", "checkpoint", "vocabulary", "done")

_EXECUTOR_PREFIX = "scam-l2-relateanything"

# 本地回退异常类：仅当 B 的 scam.win11_l2_contract 尚不存在时使用。
# 结构化约定：.code 固定错误码；ModelUnavailable 另有 .missing 缺失项清单。


class ModelUnavailable(RuntimeError):
    """依赖/权重缺失、来源错配或加载失败。固定码 model_unavailable
    （加载超时 code="load_timeout"、来源错配 code="source_mismatch"）；
    .missing=缺失项清单。"""

    code = "model_unavailable"

    def __init__(self, message: str, missing: Optional[Sequence[str]] = None):
        super().__init__(message)
        self.missing: List[str] = list(missing or [])


class AdapterIsolated(RuntimeError):
    """永久隔离（超时中毒/加载失败隔离/已关闭）。固定码 backend_isolated；
    不再接受任何 infer。"""

    code = "backend_isolated"


class InferTimeout(TimeoutError):
    """上游 predict 超过 infer_timeout_s。固定码 timeout；调用未被中止。

    继承内建 TimeoutError：B 的 stage 以 ``except TimeoutError`` 分类
    超时态（win11_l2_contract.py L2RelationStage.process）。
    """

    code = "timeout"


class InferFailed(RuntimeError):
    """上游推理异常。固定码 infer_failed。"""

    code = "infer_failed"


def _make_exc(name: str, fallback: type, message: str, *, code: str,
              missing: Optional[Sequence[str]] = None,
              details: Optional[Dict[str, Any]] = None) -> Exception:
    """按名解析 B 的合同异常类（存在即用，运行时自愈），否则用本地回退。
    结构化属性 best-effort 附加：``.code`` 固定错误码、``.missing`` 缺失项
    清单、``.details`` 结构化细节（B 的合同类带 ``.reason/.details``，
    本地回退类带 ``.code/.missing``——两边都有实话可读）。"""
    cls: type = fallback
    try:
        from . import win11_l2_contract as _contract  # B 的模块，可能尚未落地

        cls = getattr(_contract, name, None) or fallback
    except Exception:
        pass
    try:
        exc = cls(message)  # type: ignore[call-arg]
    except TypeError:
        exc = fallback(message)  # B 的类签名未知时的兜底构造
    payload = dict(details or {})
    if missing is not None:
        payload.setdefault("missing", list(missing))
    payload.setdefault("code", code)
    for attr, value in (("code", code), ("missing", missing), ("details", payload)):
        if value is None:
            continue
        try:
            setattr(exc, attr, value)
        except Exception:
            pass
    return exc


def _git_short_code(repo_path: str) -> str:
    """从 .git 普通文件读 HEAD commit 短码（纯文件读，无子进程、无 import）。
    读不到（非 git 目录/打包引用缺失/任何异常）→ "local"。"""
    try:
        git_dir = os.path.join(repo_path, ".git")
        if not os.path.isdir(git_dir):
            return "local"
        with open(os.path.join(git_dir, "HEAD"), "r", encoding="utf-8") as fh:
            head = fh.read().strip()
        if not head.startswith("ref: "):
            return head[:12] or "local"
        ref = head[len("ref: "):].strip()
        ref_file = os.path.join(git_dir, *ref.split("/"))
        if os.path.isfile(ref_file):
            with open(ref_file, "r", encoding="utf-8") as fh:
                return fh.read().strip()[:12] or "local"
        packed = os.path.join(git_dir, "packed-refs")
        if os.path.isfile(packed):
            with open(packed, "r", encoding="utf-8") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) == 2 and parts[1] == ref:
                        return parts[0][:12]
        return "local"
    except Exception:
        return "local"


def _path_inside(child: str, parent: str) -> bool:
    """child 路径是否位于 parent 目录内（Windows 大小写/盘符安全）。"""
    try:
        c = os.path.abspath(child)
        p = os.path.abspath(parent)
        if os.name == "nt":
            c = os.path.normcase(c)
            p = os.path.normcase(p)
        return os.path.commonpath([c, p]) == p
    except (ValueError, OSError):
        return False


def _sha256_16(path: str) -> Optional[str]:
    """流式实算文件 sha256 前 16 位；读不了 → None（调用方保留占位）。"""
    try:
        sha = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                sha.update(chunk)
        return sha.hexdigest()[:16]
    except OSError:
        return None


def _alive_threads(executor: Optional["concurrent.futures.ThreadPoolExecutor"]) -> int:
    """executor 内仍存活的 worker 线程数（私有属性仅作信息性残留报告）。"""
    if executor is None:
        return 0
    threads = tuple(getattr(executor, "_threads", ()) or ())
    return sum(1 for t in threads if t.is_alive())


def _protocol_base() -> type:
    """B 的 L2RelationModel 协议基类（存在即继承，满足 isinstance 检查）；
    B 的模块未落地时退化为 object（协议本为鸭子类型，C-134 §3）。"""
    try:
        from .win11_l2_contract import L2RelationModel as _base

        return _base
    except Exception:
        return object


def _raise(name: str, fallback: type, message: str, *, code: str,
           missing: Optional[Sequence[str]] = None,
           details: Optional[Dict[str, Any]] = None) -> Exception:
    """构造合同异常并立即 raise（供 `raise _raise(...)` 惯用法）。"""
    exc = _make_exc(name, fallback, message, code=code, missing=missing,
                    details=details)
    raise exc


class RelateAnythingAdapter(_protocol_base()):
    """真实 RelateAnything（relsgg）延迟加载适配器，满足 L2RelationModel 协议。

    参数
    ----
    repo_path:
        上游克隆根目录（含 ``relsgg/`` 包）。只注入 sys.path + import，
        不复制、不修改上游。
    checkpoint:
        ``model.pth`` 绝对/相对路径（发布版目录应含 text_student.pt、
        tokenizer 文件与 calibration.json；缺项进 ModelUnavailable.missing）。
    vocabulary:
        构造期词表（可选）：给定时随加载一次性编码（发生在上游
        from_checkpoint 内部）；缺省用上游默认词表。infer 的 per-call
        ``vocabulary`` 非空且与当前激活词表不同时会触发
        ``set_vocabulary``（一次文本编码）；空词表表示"不切换，沿用当前"。
    infer_timeout_s:
        单次 predict 超时秒数，默认 10.0；None 或 <=0 表示不设超时（不
        建议）。超时只约束 executor 中的 predict。
    load_timeout_s:
        首次加载（import+权重+词表编码，本机实测约 20s）的有界等待秒数，
        默认 60.0；None 或 <=0 表示不限（不建议）。超时 → 加载失败隔离
        （ModelUnavailable code="load_timeout"），加载线程仍存活的事实由
        :meth:`diagnostic` 如实报告。
    device:
        透传上游 ``from_checkpoint(device=...)``，默认 "cpu"。
    """

    def __init__(self, repo_path: str | os.PathLike, checkpoint: str | os.PathLike,
                 vocabulary: Optional[Sequence[str]] = None,
                 infer_timeout_s: Optional[float] = INFER_TIMEOUT_S_DEFAULT,
                 device: str = "cpu",
                 load_timeout_s: Optional[float] = LOAD_TIMEOUT_S_DEFAULT) -> None:
        self.repo_path = os.fspath(repo_path)
        self.checkpoint = os.fspath(checkpoint)
        self.vocabulary: Tuple[str, ...] = tuple(vocabulary) if vocabulary else ()
        self.infer_timeout_s = (float(infer_timeout_s)
                                if infer_timeout_s is not None and infer_timeout_s > 0
                                else None)
        self._load_timeout_s = (float(load_timeout_s)
                                if load_timeout_s is not None and load_timeout_s > 0
                                else None)
        self.device = device
        # 占位 model_ref：relateanything/<上游 commit 短码>/<checkpoint 文件名>，
        # 不含绝对路径；加载成功后尾段替换为权重 sha256 前 16 位（实算）。
        self._commit_code = _git_short_code(os.path.abspath(self.repo_path))
        self.model_ref = "relateanything/{}/{}".format(
            self._commit_code, os.path.basename(self.checkpoint))
        # 运行态（构造绝不触碰）：
        self._repo_abs = os.path.abspath(self.repo_path)
        self._lock = threading.Lock()
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._model: Any = None                # 加载后的 relsgg.RelateAnything
        self._active_vocab: Optional[Tuple[str, ...]] = None
        self._load_error: Optional[str] = None  # 健康面口径：类型+阶段，不含路径
        self._poisoned = False
        self._poison_reason: Optional[str] = None
        self._pending_future: Optional[concurrent.futures.Future] = None
        # C-135 生命周期状态：
        self._phase = "unloaded"               # _HEALTH_PHASES 之一
        self._load_stage: Optional[str] = None  # _LOAD_STAGES 前缀之一（None=未开始）
        self._stages_seen: List[str] = []
        self._load_future: Optional[concurrent.futures.Future] = None
        self._load_gen = 0                     # 迟到加载结果的代次令牌
        self._load_ms: Optional[Dict[str, float]] = None
        self._vocab_switch_ms: Optional[float] = None
        self._ckpt_sha16: Optional[str] = None
        self._close_requested = False
        self._close_error: Optional[str] = None  # 关闭自身异常码（B2 三态）
        self._delivery_gen = 0                 # C-137 B1 交付代次：close/隔离递增
        self._pending: List[concurrent.futures.Future] = []
        self._discarded_results = 0
        self._discarded_loads = 0

    # -- 协议 ---------------------------------------------------------------

    def infer(self, frame_bgr, boxes_px, labels, vocabulary) -> List[dict]:
        """L2RelationModel 协议。boxes_px: [(x1,y1,x2,y2)] 像素 xyxy（stage 已
        切换坐标系，本 adapter 不做坐标数学）；labels 仅作上游展示标签透传；
        vocabulary: tuple[str]。返回 [{"s","o","relation","graph","score"}]，
        分数原样；无关系→空列表。"""
        refuse = self._refuse_reason()
        if refuse is not None:
            raise _raise(
                "AdapterIsolated", AdapterIsolated,
                "backend_isolated: adapter refuses new work ({})".format(refuse),
                code="backend_isolated", details={"refuse_reason": refuse})
        n_boxes = 0 if boxes_px is None else len(boxes_px)
        if n_boxes < 2:
            # <2 区域不存在关系对：真实空结果，无需加载模型（不冒充模型态）。
            return []
        model = self._ensure_loaded()
        with self._lock:
            executor = self._ensure_executor_locked()
        vocab = tuple(vocabulary) if vocabulary else ()
        try:
            fut = executor.submit(self._predict_once, model,
                                  frame_bgr, boxes_px, labels, vocab)
        except RuntimeError:
            # executor 已收口（close/隔离先到的竞态窗口）：结构化拒收——绝不
            # 给已关闭的实例派任务，也绝不让裸 RuntimeError 泄漏（与
            # l3_backend 同一合同）。
            raise _raise(
                "AdapterIsolated", AdapterIsolated,
                "backend_isolated: the executor is already shut down (close() "
                "came first); the call is refused and its result will never "
                "be published",
                code="backend_isolated") from None
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
            raise _raise(
                "AdapterIsolated", AdapterIsolated,
                "backend_isolated: the submitted call was discarded "
                "(backend closed/stopped); its result will never be published",
                code="backend_isolated") from None
        except TimeoutError:
            # Python >=3.11：concurrent.futures.TimeoutError 即内建 TimeoutError。
            if fut.done():
                # future 已完成且抛的是上游自己的 TimeoutError——不是等待超时。
                cause = fut.exception()
                raise _raise(
                    "InferFailed", InferFailed,
                    "infer_failed: upstream raised TimeoutError: {!r}".format(cause),
                    code="infer_failed") from cause
            with self._lock:
                self._poisoned = True
                self._phase = "poisoned"
                self._poison_reason = (
                    "infer exceeded infer_timeout_s={}s; the upstream call may still be "
                    "running in the dedicated worker thread and cannot be aborted".format(
                        self.infer_timeout_s))
                self._delivery_gen += 1   # C-137 B1：隔离请求递增交付代次
            self._retire_executor_best_effort()
            raise _raise(
                "InferTimeout", InferTimeout,
                "timeout: RelateAnything infer exceeded infer_timeout_s={}s; the "
                "worker call is NOT cancelled (cannot be aborted) and the adapter is "
                "now isolated".format(self.infer_timeout_s),
                code="timeout",
                details={"timeout_s": self.infer_timeout_s}) from None
        except Exception as exc:
            code = getattr(exc, "code", None)
            if code in _BACKEND_CODES:
                raise  # 合同异常（含 B 侧类）原样上抛，交 stage 分类
            raise _raise(
                "InferFailed", InferFailed,
                "infer_failed: upstream RelateAnything error: {}: {}".format(
                    type(exc).__name__, exc),
                code="infer_failed") from exc
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
            raise _raise(
                "AdapterIsolated", AdapterIsolated,
                "backend_isolated: result delivery rejected ({}): the backend was "
                "closed/isolated after this call was submitted; the caller never "
                "receives its success value".format(reject),
                code=reject, details={"reject_code": reject})
        return result

    def close(self, timeout_s: float = 5.0) -> Dict[str, Any]:
        """生命周期收口（L2L3-接口冻结-C135.md §7）。幂等。

        空闲停止：等待在途任务（无）→ executor shutdown 干净退出，返回
        ``{"closed": True, "pending_calls": 0, "threads_alive": 0,
        "close_incomplete": False}``，无线程遗留。
        有在途不可中止调用：等待 ``timeout_s`` 秒仍未完成 → 停止接单
        （此后 infer 立即 AdapterIsolated），返回
        ``{"closed": False, "pending_calls": n, "threads_alive": k,
        "close_incomplete": True}``——不宣布全部释放，绝不重建实例绕过
        隔离；停止标志之后才完成的调用结果一律丢弃（交付闸门同时保证
        调用方收不到成功值）。在途调用随后结束（解除/自然完成）时再次
        close 即收敛为干净收口。
        关闭自身异常（C-137 B2 三态之三）→ ``{"closed": False,
        "close_incomplete": True, "error": "close_failed"}``，绝不视为
        停止成功。每次 close 请求递增交付代次（C-137 B1）。
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
                # C-137 B2：关闭自身异常 → closed=False + 错误码，绝不视为
                # 停止成功（停机汇总按结构判定）。
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
        """C-135 冻结健康字段（§5 backend 块 / §7 生命周期），健康面直接消费。

        全部字段不含绝对路径：``load_error`` 只含异常类型与失败阶段，
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
        冻结字段之外补充信息性口径（阶段耗时/丢弃计数/权重指纹等）。"""
        with self._lock:
            fut = self._pending_future
            self._prune_pending_locked()
            pending_running = bool(
                fut is not None and not fut.done() and not fut.cancelled())
            return {
                "model_ref": self.model_ref,
                "backend": "relateanything",
                "loaded": self._model is not None,
                "load_error": self._load_error,
                "poisoned": self._poisoned,
                "poison_reason": self._poison_reason,
                "infer_timeout_s": self.infer_timeout_s,
                "load_timeout_s": self._load_timeout_s,
                "pending_call_still_running": pending_running,
                "pending_call_done": (fut.done() if fut is not None else None),
                "worker_threads_alive": _alive_threads(self._executor),
                "worker_abortable": False,
                "active_vocabulary": list(self._active_vocab) if self._active_vocab else [],
                "note": ("a timed-out upstream call cannot be aborted; its worker thread "
                         "may keep running and is reported here as-is, never as cancelled"),
                # -- C-135 信息性扩展（diagnostic 冻结字段之外）--
                "phase": self._phase,
                "load_stage": self._load_stage,
                "load_stages_seen": list(self._stages_seen),
                "load_ms": dict(self._load_ms) if self._load_ms else None,
                "vocab_switch_ms": self._vocab_switch_ms,
                "checkpoint_sha256_16": self._ckpt_sha16,
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

    # -- 内部 ---------------------------------------------------------------

    @property
    def poisoned(self) -> bool:
        return self._poisoned

    def _refuse_reason(self) -> Optional[str]:
        """拒绝接单的原因（隔离/中毒/已关闭）；None=可接单。"""
        if self._poisoned:
            return self._poison_reason or (
                "a previous failure permanently isolated this instance")
        if self._close_requested:
            return "close() was called; this instance no longer accepts infer calls"
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

    def _ensure_executor_locked(self) -> "concurrent.futures.ThreadPoolExecutor":
        """（持锁）惰性创建专属单线程 executor：加载与 predict 共用一条
        worker 线程，加载超时后该线程仍存活的事实由线程存活数如实呈现。"""
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

    def _check_missing(self) -> List[str]:
        """纯文件系统缺失项检查（零 import、零网络）。"""
        missing: List[str] = []
        if not os.path.isdir(self._repo_abs):
            missing.append("repo directory not found: {}".format(self.repo_path))
        elif not os.path.isfile(os.path.join(self._repo_abs, "relsgg", "__init__.py")):
            missing.append("relsgg package not found under repo_path: {}".format(
                os.path.join(self.repo_path, "relsgg")))
        if not os.path.isfile(self.checkpoint):
            missing.append("checkpoint file not found: {}".format(self.checkpoint))
        else:
            ckpt_dir = os.path.dirname(os.path.abspath(self.checkpoint))
            text_student = os.path.join(ckpt_dir, "text_student.pt")
            if not os.path.isfile(text_student):
                missing.append("text_student.pt not found beside checkpoint: {}".format(
                    text_student))
            elif not any(
                all(os.path.isfile(os.path.join(ckpt_dir, f)) for f in layout)
                for layout in (("tokenizer.json",), ("vocab.json", "merges.txt"))
            ):
                missing.append(
                    "tokenizer files (tokenizer.json, or vocab.json+merges.txt) not "
                    "found beside checkpoint: {} (offline vocabulary encoding "
                    "requires them; fetching from the hub is forbidden)".format(ckpt_dir))
        return missing

    def _check_source_mismatch(self) -> None:
        """来源防错配（C-135 §7）：sys.modules 已有 ``relsgg`` 时，其
        ``__file__`` 必须位于配置 repo_path 内；来自别处或无法验证来源
        （``__file__`` 缺失）→ 结构化拒绝，绝不静默使用错误来源模块。
        （详细路径只进本机日志/抛出异常，健康面字段不含路径。）"""
        mod = sys.modules.get("relsgg")
        if mod is None:
            return
        mod_file = getattr(mod, "__file__", None)
        if mod_file and _path_inside(mod_file, self._repo_abs):
            return  # 同源（含同仓重复加载的合法复用）
        origin = ("origin unverifiable (__file__ missing)" if not mod_file
                  else "imported from outside the configured repo_path")
        raise _raise(
            "ModelUnavailable", ModelUnavailable,
            "source_mismatch: an incompatible 'relsgg' module is already imported "
            "({}); refusing to silently use the wrong source. Load this adapter in "
            "a fresh interpreter or correct repo_path.".format(origin),
            code="source_mismatch",
            missing=["relsgg source mismatch: module __file__={!r} is not under "
                     "repo_path={!r}".format(mod_file, self._repo_abs)])

    def _ensure_loaded(self):
        """首次 infer 的加载路径：拒绝态检查 → 缺项检查 → 来源防错配 →
        专属线程内有界加载（load_timeout_s）。任何失败→结构化异常。"""
        if self._model is not None:
            return self._model
        with self._lock:
            if self._model is not None:
                return self._model
            refuse = self._refuse_reason()
            if refuse is not None:
                raise _raise(
                    "AdapterIsolated", AdapterIsolated,
                    "backend_isolated: load refused ({})".format(refuse),
                    code="backend_isolated")
            fut = self._load_future
            if fut is None:
                missing = self._check_missing()
                if missing:
                    raise _raise(
                        "ModelUnavailable", ModelUnavailable,
                        "model_unavailable: RelateAnything backend cannot start; missing: "
                        + "; ".join(missing),
                        code="model_unavailable", missing=missing)
                self._check_source_mismatch()
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
            raise _raise(
                "AdapterIsolated", AdapterIsolated,
                "backend_isolated: load was discarded (backend closed/stopped); "
                "refusing to use it",
                code="backend_isolated") from None
        except TimeoutError:
            if fut.done():
                # 恰在超时瞬间结算完成：按真实结局处理，不冒充超时。
                cause = fut.exception()
                if cause is None:
                    with self._lock:
                        return self._finish_load_wait_ok()
                with self._lock:
                    if not self._poisoned and not self._close_requested:
                        self._phase = "unloaded"
                        self._load_stage = None
                code = getattr(cause, "code", None)
                if code in _BACKEND_CODES:
                    raise cause
                raise _raise(
                    "ModelUnavailable", ModelUnavailable,
                    "model_unavailable: RelateAnything load failed: {}: {}".format(
                        type(cause).__name__, cause),
                    code="model_unavailable",
                    missing=["upstream load failed: {}: {}".format(
                        type(cause).__name__, cause)]) from cause
            self._isolate_load_timeout()
            raise _raise(
                "ModelUnavailable", ModelUnavailable,
                "load_timeout: RelateAnything first load did not complete within "
                "load_timeout_s={}s; the load thread is still alive and cannot be "
                "aborted; this instance is isolated".format(self._load_timeout_s),
                code="load_timeout",
                details={"timeout_s": self._load_timeout_s,
                         "load_stage": self._load_stage}) from None
        except Exception as exc:
            with self._lock:
                if not self._poisoned and not self._close_requested:
                    self._phase = "unloaded"
                    self._load_stage = None
            code = getattr(exc, "code", None)
            if code in _BACKEND_CODES:
                raise  # 加载线程内抛的结构化异常（source_mismatch 等）原样上抛
            raise _raise(
                "ModelUnavailable", ModelUnavailable,
                "model_unavailable: RelateAnything load failed: {}: {}".format(
                    type(exc).__name__, exc),
                code="model_unavailable",
                missing=["upstream load failed: {}: {}".format(
                    type(exc).__name__, exc)]) from exc
        with self._lock:
            return self._finish_load_wait_ok()

    def _finish_load_wait_ok(self):
        """（持锁）加载 future 正常结算后的收尾：模型可能已被丢弃
        （close/隔离先到）——绝不绕过隔离采用迟到的加载结果（C-137 B1
        交付闸门同一合同：调用方收到结构化拒收，绝不收到成功值）。"""
        if self._model is None:
            if self._poisoned:
                reject = "poisoned_rejected"
            elif self._close_requested:
                reject = "closed_rejected"
            else:
                reject = "generation_rejected"
            raise _raise(
                "AdapterIsolated", AdapterIsolated,
                "backend_isolated: load finished but its result was discarded "
                "(close()/isolation came first); the late model is not adopted",
                code="backend_isolated",
                details={"discarded_load": True, "reject_code": reject})
        return self._model

    def _isolate_load_timeout(self) -> None:
        """（有锁调用）加载超时隔离：诚实超时，不假装加载线程已停止。"""
        with self._lock:
            if self._model is not None:
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
        """专属 executor 线程内的加载：import → checkpoint（含构造期词表
        编码，上游一次文本编码）→ vocabulary 完成标记 → 就绪。任何异常
        原样上抛交等待方结构化包装；迟到/已停的加载结果按代次丢弃。"""
        timings: Dict[str, float] = {}
        try:
            with self._lock:
                self._set_load_stage_locked("import")
            t0 = time.perf_counter()
            if self._repo_abs not in sys.path:
                sys.path.insert(0, self._repo_abs)  # 必要的持久注入，仅此一处
            importlib.import_module("torch")       # 依赖预检，缺了给结构化清单
            self._check_source_mismatch()          # import 前复核（防竞态错配）
            relsgg = importlib.import_module("relsgg")
            ra_cls = relsgg.RelateAnything         # 触发上游惰性 api 导入
            timings["import_ms"] = (time.perf_counter() - t0) * 1000.0
            with self._lock:
                self._set_load_stage_locked("checkpoint")
            t1 = time.perf_counter()
            ckpt_dir = os.path.dirname(os.path.abspath(self.checkpoint))
            text_student = os.path.join(ckpt_dir, "text_student.pt")
            predicates = list(self.vocabulary) if self.vocabulary else None
            ra = ra_cls.from_checkpoint(
                self.checkpoint,
                predicates=predicates,
                device=self.device,
                text_student=text_student,  # 显式旁路上游 hf:// 下载分支
            )
            sha16 = _sha256_16(self.checkpoint)    # 权重实际版本指纹（实算）
            timings["checkpoint_ms"] = (time.perf_counter() - t1) * 1000.0
            with self._lock:
                if self.vocabulary:
                    # 构造期词表编码发生在上游 from_checkpoint 内部（计时并入
                    # checkpoint 阶段）；此标记表示词表编码确已完成。
                    self._set_load_stage_locked("vocabulary")
                if gen != self._load_gen or self._close_requested:
                    self._discarded_loads += 1     # 迟到/已停：结果丢弃，不绕过隔离
                    return
                self._model = ra
                self._active_vocab = (tuple(self.vocabulary) if self.vocabulary
                                      else tuple(ra.predicates))
                self._ckpt_sha16 = sha16
                if sha16:
                    self.model_ref = "relateanything/{}/{}".format(
                        self._commit_code, sha16)
                self._set_load_stage_locked("done")
                self._load_ms = dict(timings,
                                     total_ms=(time.perf_counter() - t0) * 1000.0)
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

    def _predict_once(self, model, frame_bgr, boxes_px, labels, vocabulary) -> List[dict]:
        """在专属 executor 线程内执行：按需切词表 → 上游 predict(decompose)
        → 最小映射为协议 dict（s/o 框索引、relation、graph、score 原样）。"""
        ra = model
        if vocabulary and vocabulary != self._active_vocab:
            t_switch = time.perf_counter()
            try:
                ra.set_vocabulary(list(vocabulary))
            except Exception as exc:
                # 词表编码依赖检查点旁的 text student/tokenizer——属后端可用性。
                raise _raise(
                    "ModelUnavailable", ModelUnavailable,
                    "model_unavailable: set_vocabulary failed (text student / "
                    "tokenizer beside checkpoint): {}: {}".format(
                        type(exc).__name__, exc),
                    code="model_unavailable",
                    missing=["vocabulary encoding: {}: {}".format(
                        type(exc).__name__, exc)]) from exc
            self._active_vocab = tuple(vocabulary)
            self._vocab_switch_ms = (time.perf_counter() - t_switch) * 1000.0
        boxes = np.asarray(boxes_px, dtype=np.float32).reshape(-1, 4)
        decomposed = ra.predict(
            frame_bgr,                       # HWC uint8 BGR，上游原生支持（api.py:215）
            boxes,
            box_labels=([str(x) for x in labels] if labels is not None else None),
            decompose=True,                  # 一次前向给 spatial+semantic 两条图
        )
        out: List[dict] = []
        for graph_tag in ("spatial", "semantic"):
            for t in (decomposed or {}).get(graph_tag, ()) or ():
                out.append({
                    "s": int(t.subject_idx),
                    "o": int(t.object_idx),
                    "relation": str(t.predicate),
                    "graph": graph_tag,
                    "score": float(t.score),   # 上游分数原样，不加工
                })
        return out
