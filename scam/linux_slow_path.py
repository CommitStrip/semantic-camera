"""linux_slow_path.py —— [SC-B 退役] 旧 Linux 慢系统入口的薄兼容适配器。

历史说明：本模块曾拥有一整套独立认领、重试、模式写入、事件文本补充与
终态状态机。SC-B 起，**唯一慢系统执行核心是 `scam.slow_core.SlowCore`**；
本模块只保留 `run_once()` 兼容入口：

    参数校验/翻译 → 逐相机委托 SlowCore → canonical 统计翻译

本模块不再包含：任何 SQL 写语句、独立认领/重试/陈旧/终态状态机、独立
模式回滚、独立 pattern 持久化、事务上下文。历史 `segments` 行保持原样。

兼容边界（诚实声明）：
- `vlm`（旧 callable(seg, keyframes)→dict）桥接为 SlowCore provider，至多
  一次调用；`embedder`（旧 callable(frames)→vec）桥接为 emb_fn，至多一次；
- `recover_stale` 原样传递（是否接管异实例陈旧认领）；
- `max_attempts` 映射 SlowCore.max_retries；`limit` 映射批上限（同上限）；
- `environment` 仅校验类型后接受（SlowCore 不消费环境档案，不伪装消费）；
- `now` 仅为兼容接受，不参与调度（SlowCore 使用真实时钟）；
- 调用方连接原样使用不关闭；连接处于事务中时 fail-closed；
- 路径输入不接受（旧建表逻辑随状态机退役）：须传入已由 `scam.db.init_schema`
  初始化的连接。
"""

import math
import os

from .slow_core import SlowCore, _approx_modality

SCHEMA = "scam.linux-slow-path/v1"     # 兼容常量（历史报告/调用方引用）
KIND = "review_processing"
STAT_FIELDS = ("claimed", "processed", "pattern_hits", "new_patterns",
               "vlm_calls", "fallbacks", "retried", "failed", "backlog")
DEFAULT_LIMIT = 20
MAX_LIMIT = 100
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_STALE_AFTER_S = 900.0


class _LegacyVlmProvider:
    """旧 vlm callable 到 SlowCore provider 的桥接（至多一次调用）。

    P1-A(R1)：从 SlowCore 已加载的 `frames_b64` 在**内存内**解码为旧接口
    可消费的 BGR 帧（≤3）；不重新调用 frame_loader（无双读取/TOCTOU）、
    不联网、不子进程、不按外部路径读取；单帧解码失败跳过，全部失败时
    旧 VLM 收到空列表并继续诚实降级。
    """

    name = "legacy-vlm-adapter"

    def __init__(self, vlm):
        self.vlm = vlm
        self.calls = 0

    @staticmethod
    def _decode_frames(frames_b64, limit=3):
        import base64
        import cv2
        import numpy as np
        frames = []
        for payload in list(frames_b64 or [])[:limit]:
            frame = None
            try:
                raw = base64.b64decode(payload, validate=True)
                buffer = np.frombuffer(raw, dtype=np.uint8)
                frame = cv2.imdecode(buffer, cv2.IMREAD_COLOR)
            except Exception:
                frame = None
            if frame is not None:
                frames.append(frame)
        return frames

    def understand(self, prompt, frames_b64, context=None):
        context = context or {}
        seg = {"signature": context.get("signature"),
               "segment_id": context.get("segment_id")}
        frames = self._decode_frames(frames_b64)
        self.calls += 1
        out = self.vlm(seg, frames)
        if isinstance(out, dict):
            return out.get("short_name")
        return None


def _check_limit(value):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("limit 必须是正整数")
    if value > MAX_LIMIT:
        raise ValueError(f"limit 不得超过 {MAX_LIMIT}")
    return value


def _check_attempts(value):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("max_attempts 必须是正整数")
    return value


def _check_stale(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or value <= 0:
        raise ValueError("stale_after_s 必须为正数")
    return float(value)


def _connect(source):
    """兼容连接处理：sqlite3 连接原样使用（不关闭）；路径须已初始化。"""
    import sqlite3
    if isinstance(source, sqlite3.Connection):
        return source
    if isinstance(source, str) and source:
        if not os.path.isfile(source):
            raise ValueError(
                "数据库路径不存在（请先用 scam.db.init_schema 初始化）")
        from .db import connect as _canonical_connect
        return _canonical_connect(source)
    raise ValueError("source 必须是 sqlite3 连接或已存在的数据库路径")


def run_once(source, *, limit=DEFAULT_LIMIT, library=None, vlm=None,
             embedder=None, frame_loader=None, environment=None,
             max_attempts=DEFAULT_MAX_ATTEMPTS,
             stale_after_s=DEFAULT_STALE_AFTER_S, recover_stale=False,
             now=None):
    """兼容入口：委托唯一核心 SlowCore，返回九个固定统计字段（非负整数）。

    所有慢处理语义（认领 CAS、重试、陈旧恢复、generation CAS、事务、
    三帧证据、命名纪律、空文本补充）由 SlowCore 执行；本函数只做参数
    翻译与统计汇总——同一输入只发生一次 canonical 执行。
    """
    checked_limit = _check_limit(limit)
    attempts = _check_attempts(max_attempts)
    _check_stale(stale_after_s)          # 兼容校验（阈值口径由 SlowCore 固定）
    if environment is not None and not isinstance(environment, dict):
        raise ValueError("environment: 必须是环境档案对象或 None")
    connection = _connect(source)
    if connection.in_transaction:
        raise ValueError("调用方连接处于事务中：fail-closed，绝不代为提交")

    cameras = [row[0] for row in connection.execute(
        "SELECT DISTINCT camera FROM review_segments"
        " WHERE t_end IS NOT NULL ORDER BY camera").fetchall()]
    totals = {key: 0 for key in STAT_FIELDS}
    provider = _LegacyVlmProvider(vlm) if vlm is not None else None
    # P0-A(R1)：limit 是**单次 run_once 调用的全局上限**——跨相机共享预算，
    # 按稳定相机顺序消耗（processed+retried+failed+conflict），归零即停。
    remaining = checked_limit
    for camera in cameras:
        if remaining <= 0:
            break
        core = SlowCore(connection, camera=camera, max_retries=attempts,
                        frame_loader=frame_loader)
        if library is not None:
            core._library = library
            core._library_generation_seen = core._read_generation_sql()

        def emb_fn(review, _core=core, _embedder=embedder):
            if _embedder is None:
                return None, None
            frames, _error = _core._load_frames(review, limit=1)
            if not frames:
                return None, None
            return _embedder(frames), _approx_modality(
                float(review["t_start"]))

        stats = core.process_pending(
            limit=remaining, emb_fn=emb_fn if embedder else None,
            provider=provider, recover_stale=bool(recover_stale),
            stale_after_s=_check_stale(stale_after_s))
        consumed = (stats["processed"] + stats["retried"]
                    + stats["failed"] + stats["conflict"])
        remaining -= consumed
        totals["claimed"] += consumed
        totals["processed"] += stats["processed"]
        totals["pattern_hits"] += stats["matched"]
        totals["new_patterns"] += stats["recorded"]
        totals["vlm_calls"] += stats["vlm_calls"]
        totals["fallbacks"] += stats["fallbacks"]
        totals["retried"] += stats["retried"]
        totals["failed"] += stats["failed"]
    # backlog：处理结束后对**全部相机**做只读水位汇总（不启动任何处理）。
    # SC-B-R4：本模块不再自带第二份 backlog SQL——调用唯一真值入口，与核心
    # `SlowCore.waterlevel()` 同口径（损坏/未知状态一律计入，只有三个已知
    # 终态退出）；坏 JSON 因此不会再在"处理已提交"之后抛 OperationalError。
    totals["backlog"] = SlowCore.count_pending_reviews(connection, camera=None)
    return {key: max(0, int(totals[key])) for key in STAT_FIELDS}
