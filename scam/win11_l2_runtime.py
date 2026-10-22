"""win11_l2_runtime.py —— L2 关系阶段生产运行面（C-136 主会话模块；
C-137/C-138 生产收口）。

职责：窗口调度消费（A 的 WindowScheduler）、有效结果闸门（M2）、
兜底→L3 补充任务（经 D 的统一转换）、逐状态健康计数、后端诊断透传、
L2→L3→L4 首版链（L4 走同窗累计 accumulate）、理解结果有界持久化与
重启恢复（经 C 的 UnderstandingStore）。

C-138 窗口状态机（§2，本模块权威实现）：
- ``_open_windows[window_key] = {handle, camera, state, branches,
  born_mono_ms, done}``（锁保护；废除 C-137 的 pending 整数）；
- ``window_key = (camera_id, run_id, config_version, window_id)``；
- ``branch_key = window_key + (branch_kind, crop_id, material_id)``
  （同窗多材料包以 material_id 段区分，不同材料同区域分支不互相覆盖）；
- 状态 producing → sealed → settled；分支终态集
  ``branch_ok / model_failed / expired / stale_identity / queue_evicted /
  stop_cancelled``——每个分支恰好结算一次（幂等）；结算=计数、缺失因素
  （进 L4 accumulate）、窗口占用解除、引用清理四件事一致完成；唯一终态
  提交点是 ``_settle_branch_terminal``（C-139 §2：TTL/停机收口也经它
  结算，重复回调不重复 gap/版本/提醒）；
- 只有 sealed 且未终态分支集合为空才 settled；L3 首分支先于生产封口完成
  时窗口仍在 producing → 不提前 settled。

C-139 §2（提交边界与一次性终态，本模块权威实现）：
- **A1 stop/enqueue 交错**：最终队列提交点（``_l3_queues[camera].append``
  处）锁内重检 stop/窗口有效/分支资格（window 仍在 _open_windows 且未
  settled 且分支仍 pending）；停机清理与入队用一致锁序（先 ``_l3_lock``
  后 ``_win_lock``，全仓不反序嵌套），状态锁内不等待模型/磁盘/join
  （结算一律在状态锁外完成）；
- **A3 发布身份边界（C-139-R1 §1 发布裁决）**：专用发布锁
  ``_publish_lock`` 内做 stop/身份/发布时效三检，并**在同一锁段内完成
  分支终态裁决**（成功记录另核分支仍 pending，通过即把分支字典
  pending→branch_ok——发布权一次授予；后续帧到达时分支已 terminal→
  不重复发布也不重复结算）；锁内不做磁盘 I/O——裁决产物（完整历史
  payload）交调用方在锁外 append（已裁决的历史事实可以写，但不能冒充
  当前有效；记录自带完整身份 window_key/branch_key/run/config，与当前
  结果分列由消费方按身份过滤）。身份注册表写入与发布世代（
  ``_identity_epoch``）递增在同一发布锁段完成——裁决段内重检身份/世代
  不被并发更新插队。不符 → 旧结果以 stale 诊断计数
  （rejected_stale/expired），不写历史；
- **L4 产出门禁**：L3 保存后、L4 累计前重检身份+世代——身份切换后旧
  窗口不再产出新的融合版本（含缺失因素注入路径；stop 缺失因素是当前
  身份窗口的如实诊断，照常入账），已算未存版本随窗口收口清理；
- **生产血缘（C-139 §2/§3）**：FusionInput 的 coord_space 从材料 bbox
  原始值域×帧实际尺寸推导（不恒默认 normalized）、frame_refs 从
  L3Output.results sources（L3SourceRef）逐条提取真实
  frame_id/时间值/时间类型（全景=三帧、局部=同区域三帧切片各自绑定的
  帧 ID；缺帧序位不伪造引用）；两条 L4 保存路径（有效分支/缺失因素）
  均经 ``fusion_version_to_json`` 完整序列化后持久化，不手工缩水字典。

C-140 §1（stop 与发布成功裁决竞态，本模块权威实现）：
- ``_commit_epoch``：停机提交原子计数器（``_l3_lock`` 内递增）。
  ``stop()`` 先 ``_stop.set()``，再经 ``_commit_stop`` 置位 ``_l3_stop``
  并锁内递增；join/清队列/窗口收口/模型关闭全部在其后的锁外进行；
- 发布门禁初检（``_publish_l3_record`` 开头 stop/身份/时效三检）通过后，
  最终裁决段在 **pending→branch_ok 之前**经 ``_l3_lock``（与 stop 提交
  同一把锁）比对门禁入口捕获的提交基线并同锁授予成功权——"重检→授予"
  之间 stop 提交无法插入，先后语义由锁取得顺序唯一确定：stop 先提交 →
  拒绝成功权，调用方收到结构化拒收（不返回成功值，detail=
  stop_committed_after_gate）；发布先授予 → 授予后提交的 stop 不追回，
  已授予结果作为完整身份历史保存。不用"再检查一次 Event"代替共享提交
  机制；stop 的缺失因素诊断与模型成功结果分列（终态词表不同）；
- 裁决锁段（publish→l3→win 连续持锁）内不做磁盘写入/模型调用/join/
  backend 关闭；全仓锁序单向：publish→l3→win→lock，无反序嵌套；
- **C-140-R1 A1 授予前锁内重检发布年龄**：最终裁决段（``_l3_lock`` 内）
  在授予前与 stop/身份同段重检发布年龄——初检通过后结果可能在等待
  ``_l3_lock`` 期间越过 ``max_publish_age_s``；锁内以单调钟重检（纯内存
  判定），超期不授予成功权、不发布成功结果，reject=("expired",
  "publish_age_exceeded_in_lock")，由调用方在发布门禁点按 expired 恰好
  结算一次（一次性终态，不重复结算）；锁等待期间未过期→正常授予。

C-141 §5（B 侧生产接线与精准收口，本模块权威实现）：
- **真实裁图提交（B1）**：``crop_worker`` 依赖注入（鸭子类型：
  ``submit(image_bgr, provenance) -> ref``；``status(ref)``/``find(...)``
  只读；None=未配置持久化 → 纯 no-op；不 import 裁图仓模块）。提交点
  在 L2→L3 入队处（``_maybe_enqueue_l3``，增强/编码前、像素在手即提交、
  不等待 L3）：只对**局部分支**（relation_crop/change_region）中帧存在
  且真实切片在手的序位逐个提交；provenance 携带冻结 §1 完整 9 元身份
  （camera_id/run_id/config_version/material_id/window_id/branch/
  crop_id/frame_id/slot）+ 既有 10 键字段（t_capture_ms/timestamp_kind/
  source_size/bbox_px）+ 在手扩展段（participants/relation_candidates/
  box_notes；分支级 uncertainty 段在 L2 输出不存在——缺省省略不伪造）。
  全景/零对象不提交（全景兜底与缺失说明保留，不借用他相机/最新画面）。
  submit 异常/返回 dropped 一律吞并为 ``crop_submit_dropped`` 计数，
  绝不阻塞快系统/L1/L2/L3 路径（纯内存入队，发布锁之外调用）。
- **L4 短临界区身份授权（B2）**：最终落盘前在专用短锁 ``_l4_auth_lock``
  （绝不复用 ``_publish_lock``；全仓锁序 publish→l3→win→l4_auth 单向）
  内做「注册表 run/config == 待写版本身份」+「发布世代 == 累计入口捕获
  世代」的接受授权——一致→授权，磁盘写在**锁外**执行（写的是已授权旧
  身份的历史事实，消费方按身份过滤；写入期间身份变化不追回）；不一致→
  结构化拒绝（``l4_auth_rejected`` 计数，不写盘）。锁内零磁盘 I/O。
  终止例外（冻结 §5 显式说明）：授权只检身份不检 stop——stop 已提交后，
  stop 提交前已授权的最后一个版本允许完成写入（stop 的缺失因素诊断
  同样经本授权照常入账——二者都是如实诊断，不冒充当前）。
- **身份感知摘要（B4）**：``summary_line`` 只呈现当前完整身份（权威
  注册表 run/config）的文本；无当前结果→「正在分析/暂无当前结果」；
  历史文本如出现必须标注「历史」；分支类别如实（局部结果不得标成
  全景）；既有「保存失败」提示保留（内存可见≠已落盘）。组装逻辑抽为
  模块级纯函数 ``compose_current_summary``（server enriched 视图复用；
  无运行时依赖，可单测）。

全终态路径（§5）：队列淘汰 / dequeue 拒收（旧 config 或停止后——拒收该
任务并结算该分支，**不是 worker 退出理由**，只有 stop 才结束循环）/
推理后拒收 / stage 异常 / 全部包过期 / 零分支 / L3 未启用 / stop / 窗口
TTL——统一走 ``_settle_branch_terminal``/``_maybe_settle_window`` 幂等收
口；TTL 到期时 open_windows/队列中该窗任务/handle 引用一并清理（不能只
减 scheduler frozen 数）；未结束模型仍持有的数组继续如实计费（finalize
口径归材料仓，本模块不挪账）。

单调钟门禁三类分列（§5）：材料年龄（pkg.created_mono_ms）/ 排队年龄
（入队时记 mono）/ 发布时效（保存前 mono，按任务 created_mono_ms 计）；
上限分别可覆盖；**绝不刷新 created_mono 续命**；过期拒收也结算。

队列（§5）：每相机独立 FIFO，跨相机公平轮转取队首（不再全局 pop(0)）；
容量不足按窗口收敛（整组淘汰，优先淘汰最旧的其它窗口组），被淘汰窗口
的相机/分支/原因经缺失因素注入该窗口 L4 accumulate。

持久化边界：本模块只接受已解析的持久化根目录（persist_dir）并经
UnderstandingStore 施加摘要目录键 + 归一化围栏（同 evidence.py 双层防
穿越，pathlib 读写）；persist_dir=None → 纯内存历史（用户查看能力不因
persist_dir=None 消失）。快照/历史不含绝对路径、凭据或图像数据。

C147（测量批，可选轻量内存 trace，默认全关零行为）：
- ``trace_sink=None``（默认）：零行为——不构造事件 dict、不调用
  观察钟，不改任何既有语义/顺序/计数；
- ``trace_sink``=callable（接收一个 JSON-safe dict 事件）：埋点事件
  （mono_ns/kind/camera/run_id/config_version/window_key/材料与原因字段）
  经有界非阻塞队列交独立观察线程；回调不在业务线程运行。
  溢出/异常/未汇合不得声称完整交付；
- 内存环形：仅当 trace_sink 为 None 且 trace_events_cap 显式给出时启用
  （有界 deque，超限丢最老）；两者都默认关闭；无任何磁盘 I/O；
- 事件词表（受控、无自由模型文本/路径/凭据）：window_admitted /
  window_suppressed / l3_enqueued / l3_rejected / l3_dequeued /
  stage_started / stage_finished / l4_partial / l4_final / expired /
  rejected_stale / queue_evicted。
"""

import hashlib
import json
import math
import os
import queue
import uuid
import threading
import time
import traceback
import weakref
from collections import OrderedDict, deque
from pathlib import Path

from .win11_admission import decide as admission_decide
from .win11_admission import change_signature as admission_signature
from .win11_admission import det_signature as admission_det_signature
from .win11_admission import ADMIT_RETRY_MAX
from .win11_l3_tasks import (L3TaskBudgetLedger, results_from_output,
                             tasks_from_package)
from .win11_l4_contract import (FUSION_TIME_KINDS, FusionFrameRef,
                                FusionIdentityRejected, FusionInput,
                                fusion_version_to_json)

try:    # C-138 §3：Agent C 的理解保存仓（交付后自动接管运行时保存）
    from .win11_understanding_store import UnderstandingStore
except ImportError:  # pragma: no cover - C 交付前的接口子集兜底（冻结签名）
    class UnderstandingStore:
        """UnderstandingStore 接口子集兜底（root=None → 纯内存历史）。

        Agent C 的 win11_understanding_store.py 交付后本兜底自动让位
        （import 优先真实模块）；此处只保证 runtime 的保存/查看/恢复
        能力不缺席：append/history/summary/snapshot 冻结签名，磁盘侧
        摘要目录键 + Path.resolve 围栏 + tmp+replace 原子轮转。
        """

        _KINDS = ("l2", "l3", "l4")

        def __init__(self, root=None, *, max_per_camera=50,
                     max_record_bytes=64 * 1024, load_budget_records=400):
            self._root = Path(root).resolve() if root is not None else None
            self._max_per_camera = max(1, int(max_per_camera))
            self._max_record_bytes = max(1, int(max_record_bytes))
            self._load_budget = max(1, int(load_budget_records))
            self._lock = threading.Lock()
            self._mem = {}          # (camera, kind) -> list[dict]
            self._loaded = set()
            self._counters = {"appended": 0, "rotated": 0, "bad_lines": 0,
                              "persist_failed": 0, "load_bad_lines": 0}

        def _path(self, camera, kind):
            if self._root is None or kind not in self._KINDS:
                return None
            key = hashlib.sha256(str(camera).encode("utf-8")).hexdigest()[:16]
            resolved = (self._root / key / (kind + ".jsonl")).resolve()
            if not resolved.is_relative_to(self._root):
                raise ValueError("understanding persistence path escaped root")
            return resolved

        def _load_locked(self, camera, kind):
            token = (camera, kind)
            if token in self._loaded:
                return
            self._loaded.add(token)
            records = self._mem.setdefault(token, [])
            try:
                path = self._path(camera, kind)
            except ValueError:
                return
            if path is None or not path.exists():
                return
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                return
            for line in lines[-self._load_budget:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except ValueError:
                    self._counters["load_bad_lines"] += 1
            del records[:-self._max_per_camera]

        def append(self, camera, kind, record):
            with self._lock:
                try:
                    line = json.dumps(record, ensure_ascii=False)
                except (TypeError, ValueError):
                    self._counters["persist_failed"] += 1
                    return False
                if len(line.encode("utf-8")) > self._max_record_bytes:
                    self._counters["persist_failed"] += 1
                    return False
                self._load_locked(camera, kind)
                records = self._mem.setdefault((camera, kind), [])
                records.append(record)
                self._counters["appended"] += 1
                rotated = False
                while len(records) > self._max_per_camera:
                    records.pop(0)
                    rotated = True
                try:
                    path = self._path(camera, kind)
                except ValueError:
                    return True
                if path is None:
                    return True
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open("a", encoding="utf-8") as handle:
                        handle.write(line + "\n")
                    if rotated:
                        tmp = path.with_name(path.name + ".tmp")
                        with tmp.open("w", encoding="utf-8") as handle:
                            for item in records:
                                handle.write(json.dumps(
                                    item, ensure_ascii=False) + "\n")
                        tmp.replace(path)
                        self._counters["rotated"] += 1
                except OSError:
                    self._counters["persist_failed"] += 1
                    return False
                return True

        def history(self, camera, kind):
            with self._lock:
                self._load_locked(camera, kind)
                return list(self._mem.get((camera, kind), []))

        def summary(self, camera):
            with self._lock:
                out = {"camera": camera}
                for kind in self._KINDS:
                    self._load_locked(camera, kind)
                    rows = self._mem.get((camera, kind), [])
                    out[kind] = len(rows)
                    out[kind + "_last_at"] = (rows[-1].get("at")
                                              if rows else None)
                return out

        def snapshot(self):
            with self._lock:
                return dict(self._counters)


# ---- C-141 B4：身份感知摘要组装（模块级纯函数；server 复用，无运行时依赖） ----

def _summary_record_identity(record):
    """store.history 形状记录 → (run_id, config_version) 身份对。

    l3 记录：window_key=[camera, run, config, window] 或顶层 run_id/
    config_version（发布 payload 两者都有）；l4 记录：
    fusion_version_to_json payload（run_id/config_version + window_key）。
    两者皆缺（旧形状/手工 append）→ None（无法归属任何身份，不猜测）。
    """
    if not isinstance(record, dict):
        return None
    window_key = record.get("window_key")
    if isinstance(window_key, (list, tuple)) and len(window_key) >= 3:
        return (window_key[1], window_key[2])
    run_id = record.get("run_id")
    config_version = record.get("config_version")
    if run_id is not None or config_version is not None:
        return (run_id, config_version)
    return None


def _summary_branch_label(branch_value):
    """分支值 → 中文类别标签（分支类别如实：局部结果不得标成全景）。"""
    value = str(branch_value or "")
    if value == "panorama":
        return "全景理解"
    if value == "relation_crop":
        return "局部关系"
    if value == "change_region":
        return "局部变化区域"
    return "理解"


def _execution_record_key(record):
    """在途执行记录的**稳定身份键**（C153-R1 §3；用于冻结副本去重/排序）。

    优先 branch_key 七元（window 四元+分支+crop+material，与
    `win11_l3_tasks.branch_key_of` 同形）；缺身份段的记录按可得字段回退，
    绝不因为键取不到就把记录丢掉。
    """
    if not isinstance(record, dict):
        return ("non_record", str(record))
    branch_key = record.get("branch_key")
    if isinstance(branch_key, (list, tuple)) and branch_key:
        return ("branch_key", tuple(str(part) for part in branch_key))
    window_key = record.get("window_key")
    if isinstance(window_key, (list, tuple)) and window_key:
        return ("window_key", tuple(str(part) for part in window_key),
                str(record.get("branch")), str(record.get("crop_id")),
                str(record.get("held_since_mono_ms")))
    return ("opaque", str(record.get("held_since_mono_ms")),
            str(record.get("detail")))


def _summary_observation_text(record, clip=60):
    """l3 记录首条观察文本（无则如实退回记录 status；不编造文本）。"""
    results = record.get("results")
    if isinstance(results, list):
        for row in results:
            observation = (row.get("observation")
                           if isinstance(row, dict) else None)
            if isinstance(observation, dict) and observation.get("text"):
                return str(observation["text"])[:clip]
    return str(record.get("status", ""))[:clip]


def compose_current_summary(camera, records_by_kind, current_identity,
                            persist_failed=0, extra_parts=()):
    """C-141 B4：身份感知理解摘要（模块级纯函数，无运行时依赖可单测）。

    - 只呈现**当前完整身份**（current_identity=(run_id, config_version)，
      取自权威注册表）的文本；无当前结果→「正在分析，当前身份暂无已完成
      结果」（注册表无身份→「暂无当前结果」）；
    - 无法归属或属于其它身份的 l3 文本如出现必须标「历史」（不冒充当前；
      重启恢复的 legacy 记录同样归历史）；
    - 分支类别如实标注（panorama/relation_crop/change_region 各自标签，
      局部不得标成全景）；
    - 融合版本计数只统计当前身份的 l4 记录（历史版本不冒充当前产出）；
    - persist_failed>0 → 「保存失败」提示（内存可见≠已落盘，branch_ok≠
      保存成功——既有 A2e 语义保留）；
    - extra_parts：调用方的运行时侧段落（如门控原因），插在记录段落之前。

    纯函数：只读入参、不触 store/锁/线程，返回完整中文一行
    （"理解进展：…"；无路径无大图无凭据）。"""
    records_by_kind = records_by_kind or {}
    l3_records = [row for row in (records_by_kind.get("l3") or ())
                  if isinstance(row, dict)]
    l4_records = [row for row in (records_by_kind.get("l4") or ())
                  if isinstance(row, dict)]
    current = tuple(current_identity) if current_identity is not None else None
    current_l3 = []
    historical_l3 = []
    current_l4 = []
    for record in l3_records:
        if current is not None and _summary_record_identity(record) == current:
            current_l3.append(record)
        else:
            historical_l3.append(record)
    for record in l4_records:
        if current is not None and _summary_record_identity(record) == current:
            current_l4.append(record)
    parts = [str(part) for part in (extra_parts or ()) if part]
    if current_l3:
        latest = current_l3[-1]
        parts.append(_summary_branch_label(latest.get("branch")) + "："
                     + _summary_observation_text(latest))
    else:
        parts.append("正在分析，当前身份暂无已完成结果"
                     if current is not None else "暂无当前结果")
    if current_l4:
        parts.append("融合版本 {} 条（{}）".format(
            len(current_l4), str(current_l4[-1].get("status", ""))))
    if historical_l3:
        latest = historical_l3[-1]
        parts.append("历史：" + _summary_branch_label(latest.get("branch"))
                     + "：" + _summary_observation_text(latest))
    if persist_failed:
        parts.append("有 {} 条结果保存失败（未持久化）".format(
            int(persist_failed)))
    return "理解进展：" + "；".join(parts)


# ---- C147：trace 事件 JSON-safe 归一（受控字段；不触碰既有路径语义） -------

def _trace_json_value(value, depth=0):
    """任意埋点字段值 → JSON-safe 标量/列表/字典（不可序列化对象 str 化，
    绝不让事件构造抛异常——事件是观测，不是快路径的一部分）。"""
    if depth > 6:
        raise ValueError("trace nesting budget exceeded")
    if isinstance(value, str) and len(value) > 1024:
        raise ValueError("trace string budget exceeded")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("nonfinite trace field")
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        if len(value) > 512:
            raise ValueError("trace item budget exceeded")
        return [_trace_json_value(item, depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > 64:
            raise ValueError("trace field budget exceeded")
        return {str(key): _trace_json_value(item, depth + 1)
                for key, item in value.items()}
    raise ValueError("unsupported trace value")


# C153-R1：`l3_budget_ledger` 注入位哨兵——**缺省即建账本**（生产入口的
# 有界窗口级共享预算默认生效）。显式传 None = 明确关闭（旧行为逐字节不变，
# 仅测试/对照用）；传账本对象 = 用调用方的那一本（多相机共享同一上限）。
class _BudgetLedgerDefault:
    __slots__ = ()

    def __repr__(self):  # pragma: no cover - 诊断可读性
        return "<l3_budget_ledger: default on>"


_BUDGET_LEDGER_DEFAULT = _BudgetLedgerDefault()


# C154 车道 G：`event_materials` 注入位哨兵——**缺省即建**同事件跨窗选材池
# （生产入口默认生效）。显式传 None = 明确关闭（旧窗口路径逐字节不变，仅
# 对照/测试用）；传池对象 = 用调用方那一只（多相机共享同一只有界池）。
# 绑定来源缺省取 `event_progress`（事实链只读快照）；无来源时池一律**不聚合**
# 并如实记 `binding_source_missing`——绝不猜事件。
class _EventMaterialsDefault:
    __slots__ = ()

    def __repr__(self):  # pragma: no cover - 诊断可读性
        return "<event_materials: default on>"


_EVENT_MATERIALS_DEFAULT = _EventMaterialsDefault()

# C154 车道 Q F1：取包点观察移交的**有界**上限（容量满 → 明确拒绝并计数，
# 绝不无界积压）+ 幂等键表与逐材料记录的有界上限。
# 64→256（车道 Q）：逐材料去向要能覆盖一次真实运行的全部折叠/取包材料
# （固定素材实测 46–48 个），仍是有界常量，不是无界增长。
_HARVEST_HANDOFF_CAP = 32
_HARVEST_OBSERVED_KEYS_CAP = 512
_HARVEST_RECORDS_CAP = 256
# C154 车道 U F1：移交队列的**外部引用账目**（第三本账）专用有界上限。
# 队列虽不复制像素，但 `append(pkg)` 是货真价实的外部强引用——它把包内
# 像素缓冲的存活期延长到"排空为止"。该账本按**独立缓冲**去重计费（同一
# 缓冲被多个包引用只计一次），故条目上限只需覆盖"队列容量 × 单包缓冲数"
# 再加一次在途排空批次；这里取 512（= 观测键表同量级），是**有界常量**，
# 不是随运行时长增长的容器。缓存被逐出只影响弱引用证据，**绝不影响**账目
# （见 `_harvest_ref_release`）。
_HARVEST_REF_CACHE_CAP = 512


class L2Runtime:
    """L2 关系阶段生产运行面（C-138：窗口状态机+闸门+统一转换+累计+仓）。

    - 消费经 WindowScheduler（每相机冻结窗+有界合并窗，跨相机公平）；
    - 有效结果闸门：仅 l1_status=="ok" 且 last_l1_accepted 的包进入关系
      模型；fallback 包模型调用=0，经统一转换生成全景 L3 补充任务（携带
      真实原因），健康计数如实（l1_gate_blocked/l1_wait_timeout）；
    - L3 worker：旧 config/停止后任务=拒收该任务并结算该分支后 continue，
      只有 stop 才结束循环（C-138 §5 退出修复）；
    - L3 完成（可选 L4Stage）经 accumulate 组装同窗累计融合版本；
    - 理解摘要经 UnderstandingStore 有界持久化（重启恢复；persist_dir
      None → 纯内存历史，查看能力保留）。
    """

    FALLBACK_STATUS_MAP = {
        "empty": "no_objects",
        "model_unavailable": "model_unavailable",
        "infer_failed": "infer_failed",
        "timeout": "timeout",
    }

    # C-138 §2：分支终态集（互斥；每个分支恰好结算一次）
    TERMINAL_OK = "branch_ok"
    # C153-R1 §2：预算计划期终态（**不冒充执行过推理**）——
    # - budget_dropped：窗口共享预算未服务该分支 → 未分析 + 受控原因；
    # - budget_merged：该分支与**同身份同来源**的既有任务合并 → 复用该任务，
    #   自身未执行推理。
    TERMINAL_BUDGET_DROPPED = "budget_dropped"
    TERMINAL_BUDGET_MERGED = "budget_merged"
    TERMINALS = ("branch_ok", "model_failed", "expired", "stale_identity",
                 "queue_evicted", "stop_cancelled", "input_rejected",
                 TERMINAL_BUDGET_DROPPED, TERMINAL_BUDGET_MERGED)
    # 与 win11_l4.FAILURE_STATUS_VALUES 对齐的 L3 失败态（不引入反向依赖）
    _L3_FAILURE_STATUSES = frozenset({
        "unsupported", "model_unavailable", "infer_failed", "timeout",
        "backend_isolated"})

    HISTORY_MAX = 50
    _PERSIST_KINDS = ("l2", "l3", "l4")
    _L4_MAX_WINDOWS = 16   # l4 stage 每窗缓存硬上限（超限最旧 cleanup）

    def __init__(self, camera_ids, store, stage, *, adapter=None,
                 scheduler=None, vocabulary_id="upstream-default",
                 vocabulary=(), max_age_s=30.0, poll_interval_s=0.5,
                 l3_stage=None, l3_backend=None, l3_max_queue=4,
                 l3_budget_ledger=_BUDGET_LEDGER_DEFAULT,
                 persist_dir=None, l4_factory=None, understanding=None,
                 max_queue_wait_s=None, max_publish_age_s=None,
                 window_ttl_s=None, mono_clock=None, crop_worker=None,
                 source_capture=None, event_progress=None,
                 event_materials=_EVENT_MATERIALS_DEFAULT,
                 trace_sink=None, trace_events_cap=None,
                 trace_clock_domain=None, trace_clock=None,
                 trace_clock_kind="real", trace_queue_cap=128):
        self.camera_ids = list(camera_ids)
        self.store = store
        self.stage = stage
        self.adapter = adapter
        if scheduler is None:
            from .win11_windows import WindowScheduler
            scheduler = WindowScheduler(camera_ids, store)
        self.scheduler = scheduler
        self.vocabulary_id = str(vocabulary_id)
        self.vocabulary = tuple(vocabulary)
        self.max_age_s = float(max_age_s)
        # C-138 §5：三类单调钟门禁上限分列（缺省同源跟随 max_age_s）
        self.max_queue_wait_s = (float(max_queue_wait_s)
                                 if max_queue_wait_s is not None
                                 else self.max_age_s)
        self.max_publish_age_s = (float(max_publish_age_s)
                                  if max_publish_age_s is not None
                                  else self.max_age_s)
        # 窗口 TTL（open_windows/队列/handle 同步收口的时限）；缺省跟随
        # 调度器逻辑占用窗龄上限（同源口径，占用有界不永久饿死相机）
        self.window_ttl_s = (
            float(window_ttl_s) if window_ttl_s is not None
            else float(getattr(scheduler, "max_window_hold_s",
                               self.max_age_s)))
        self.poll_interval_s = float(poll_interval_s)
        self.l3_stage = l3_stage
        self.l3_backend = l3_backend
        self.l3_max_queue = int(l3_max_queue)
        # L3 共享总预算账本。早期默认**未启用**（显式注入才生效），因为
        # 生产实测发现"被预算丢弃/合并的分支"缺少 runtime 终态结算 →
        # 窗口不收敛、L4 部分结果缺失（定向回归失败）。
        # 补齐该前置条件（计划终态结算 + 三窗口材料验证）后**生产默认启用**。
        # 同一账本对象被同窗多次入队复用 → 第二次拿到的是**剩余**额度，
        # 而不是又一份完整预算；多相机共用同一本账本时，上限仍是**每窗口**
        # 一份（跨相机不互相借额度：键=window_key 四元）。
        # 作用域措辞如实：生产链路没有可信 event_id 进键 → 只称"窗口级"，
        # **不**称"事件级"。
        # 注入位语义（`_BUDGET_LEDGER_DEFAULT`）：缺省 → 建默认账本；
        # 显式 None → 关闭（旧行为逐字节不变，仅对照/测试用）；对象 → 用该本。
        if isinstance(l3_budget_ledger, _BudgetLedgerDefault):
            l3_budget_ledger = L3TaskBudgetLedger()
        self.l3_window_budget_ledger = l3_budget_ledger
        self._l3_budget_coverage = {}          # 窗口封口后的账目（有界）
        self._l3_budget_coverage_cap = 64
        # C153-R1 §2：预算计划 → runtime 终态的一一对应账（每窗一份，有界）：
        # {window_key: [{plan_seq, branch_index, disposition, reason,
        #                branch_key, terminal, settled, owned_by}]}
        self._l3_plan_accounting = {}
        self._l3_plan_accounting_cap = 64
        # 已处理的计划账目键（(plan_seq, branch_index)）——保证"恰一次"结算
        self._l3_plan_settled = {}
        # 计划账目专用锁（锁序 plan→win 单向；snapshot 侧先取 plan 再取 win，
        # 绝不反序）
        self._plan_lock = threading.Lock()
        self._l3_queues = {cam: deque() for cam in self.camera_ids}
        self._l3_rr = 0              # 跨相机轮转游标（公平取队首）
        self._l3_dropped = 0
        self._l3_lock = threading.Lock()
        self._l3_stop = None
        self._l3_thread = None
        # C-139 §2 A3：专用发布锁——保存前门禁与持久化在同一锁段（锁内
        # 二次复核身份+stop 后落笔）；锁序 publish→l3→win 单向（C-140 §1：
        # 最终裁决段经 _l3_lock 与停机提交定序），全仓无反序嵌套。
        self._publish_lock = threading.Lock()
        # C-139-R1：发布裁决世代——身份/停止变化即递增；发布门禁捕获世代，
        # 磁盘写入前锁内重检（世代变→stale 拒收，不写当前有效理解）
        self._identity_epoch = 0
        # C-140 §1：停机提交原子计数器——stop 提交（``_commit_stop``）与
        # 发布最终裁决段（``_publish_l3_record``）同一把 _l3_lock 定序：
        # 谁先取得提交权谁确定先后语义（stop 先提交→此后不再授予新
        # branch_ok；发布先授予→已授予结果作为完整身份历史保存不追回）
        self._commit_epoch = 0
        # C-139 §2 A1 测试插桩：入队最终提交点（取得 _l3_lock 之前、初步
        # 门禁之后）回调；None=无插桩。仅测试注入，生产路径恒 None。
        self._l3_enqueue_gate = None
        # C153-R1 §3：停机事实报告 + **在途执行记录的冻结副本**。停机/关闭
        # 不清空仍在执行的占用；报告把「调度已停止／执行仍在途（数量+身份）
        # ／资源关闭未完成」三件事分列。冻结副本保证对象被替换/退休（引用
        # 释放）后在途记录不丢（不因"读不到"就冒充"已释放"）。
        self._exec_report_lock = threading.Lock()
        self._stop_report = None
        self._unfinished_records = {}          # {(身份键, 同身份序号): 记录}
        self._retired = False
        # C-140 §1 测试插桩：发布门禁初检通过后、最终裁决段前的回调；
        # None=无插桩。仅测试注入，生产路径恒 None。
        self._publish_gate_probe = None
        # C-141 B2：L4 短临界区授权锁（专用短锁，绝不复用 _publish_lock；
        # 全仓锁序 publish→l3→win→l4_auth 单向——本锁处于最末，锁内只做
        # 注册表/世代纯内存判定，零磁盘 I/O/模型/join）。
        self._l4_auth_lock = threading.Lock()
        # C-141 B2 测试插桩：身份检查→授权之间（生产恒 None，不等待）。
        self._l4_auth_gate_probe = None
        # C-141 B1：真实裁图提交工作者（依赖注入，鸭子类型
        # submit(image_bgr, provenance) -> ref；status(ref)/find(...) 只读；
        # None=未配置持久化 → 纯 no-op 绝不报错；不 import 裁图仓模块）。
        self.crop_worker = crop_worker
        self.event_progress = event_progress
        # C154 车道 G：同事件跨窗选材池（生产默认生效；`None`=关闭）。
        # 绑定来源缺省取 `event_progress` 的**只读**查询
        # （`resolve_material_binding`）——事实链快照，先于选材点写入；
        # 无绑定来源时池不聚合（如实记原因），继续旧窗口路径。
        # 作用域：只有明确唯一 event_id 且 camera/run/config/object 绑定成立
        # 才跨窗汇聚；共享预算仍归 C153 `L3TaskBudgetLedger`，本池只做有界
        # 选材，**不申请第二份预算**。
        if isinstance(event_materials, _EventMaterialsDefault):
            from .win11_event_materials import EventMaterialPool
            event_materials = EventMaterialPool(binding_source=event_progress)
        self.event_materials = event_materials
        # ---- C154 车道 Q F1：取包点观察的最小有界移交 ------------------------
        # 诊断 M1：带对象的材料在进池前被窗口折叠（`store.release`），池的
        # 观察点（`_process_handle`）永远看不到它们。这里给窗口调度器挂一个
        # **可选**回调：恰在"折叠/丢弃/取消/关闭"这四条 release 路径**之前**
        # 通知一次。回调在调度器锁内同步执行，只做 O(1) 入队与计数（不复制
        # 像素、不查库、不调模型、不做 I/O、不等待）；真正的观察由 L2 消费
        # 线程在 `_pump_harvest_handoff()` 里于锁外完成。队列**有界**，满时
        # 明确拒绝并计数（禁止无界积压），且不改变任何既有释放语义。
        # `event_materials is None`（显式关闭选材池）时不挂回调——默认关闭
        # 路径与旧行为逐字节一致。
        self._harvest_lock = threading.Lock()
        self._harvest_capacity = int(_HARVEST_HANDOFF_CAP)
        self._harvest_queue = deque()
        self._harvest_observed_cap = int(_HARVEST_OBSERVED_KEYS_CAP)
        self._harvest_observed = OrderedDict()   # 幂等键（有界 LRU）
        self._harvest_records_cap = int(_HARVEST_RECORDS_CAP)
        self._harvest_records = deque(maxlen=self._harvest_records_cap)
        self._harvest_failures = {}
        self._harvest_counts = {
            "handoff_enqueued": 0,
            "handoff_rejected_full": 0,
            "handoff_observed": 0,
            "handoff_observe_failed": 0,
            "handoff_identity_rejected": 0,
            "handoff_duplicate_skipped": 0,
            "handoff_dropped_stopped": 0,
        }
        # ---- C154 车道 U F1：队列**外部引用**账目（第三本账，独立分列）----
        # 队列 `append(pkg)` 不复制像素，但确实是包内像素缓冲的**外部强引用**：
        # 只要包还在队列/在途批次里，其像素缓冲就不会被回收。本账本按
        # **独立缓冲去重**（同一缓冲被多个包引用只计一次）给出"队列当前真实
        # 持有多少独立像素字节"，并与另两本账**互不混算**：
        #   - 池像素持有账 = `EventMaterialPool.accounting()` 的 `held_bytes`
        #     （池自己 copy 出来的入池帧，与本题移交的租约副本**不是同一批
        #     数组**）；
        #   - 复制预留账 = 池的 `reserved_temp_bytes` 与材料仓租约的
        #     `consumer_alive_bytes`（`win11_materials` 侧的口径）；
        #   - 队列外部引用账 = 本账（`_harvest_ref_ledger`）。
        # 锁内**只做整数加减**：不扫描像素、不复制、不做 I/O、不等待。
        # 需要看"哪些缓冲"时，弱引用缓存 `_harvest_ref_cache` 提供可核的
        # `id()` + 存活证据；缓存是有界的，被逐出只少一份证据，不改账目。
        self._harvest_ref_ledger = OrderedDict()   # key -> [bytes, refs, billed]
        self._harvest_ref_cache = OrderedDict()    # key -> (bytes, weakref)
        self._harvest_ref_reclaimed = {}           # key -> True（弱引用回调写）
        # 入队凭据：`id(pkg)` → 该条目已计费的独立缓冲键集合（有界）。归还
        # 时按此结算，因此账目**不依赖"出队时还能从包里读到什么"**。
        self._harvest_ref_by_pkg = OrderedDict()
        self._harvest_ref_enqueued = OrderedDict()  # id(pkg) → True（有界）
        self._harvest_external_bytes = 0            # 当前计费的外部引用字节
        self._harvest_external_buffers = 0          # 当前计费的独立缓冲数
        self._harvest_queue_depth = 0               # 纯整数深度（锁内 O(1) 判定）
        self._harvest_external_bytes_peak = 0
        self._harvest_external_buffers_peak = 0
        self._harvest_queue_depth_peak = 0
        self._harvest_refs_released = {
            "items": 0,          # 已归零的包条目数
            "buffers": 0,        # 累计归零的独立缓冲数
            "bytes": 0,          # 累计归零的计费字节
            "full": 0,           # 因队列满而未计费（未新增外部引用）
            "identity": 0,       # 身份围栏拒绝后归零
            "failed": 0,         # 观察失败后归零
            "skipped_stop": 0,   # 停机丢弃后归零
            "duplicate": 0,      # 幂等命中后归零
            "missing": 0,        # 无账目（缓存逐出/未计费）——如实计数
        }
        if self.event_materials is not None:
            self._attach_harvest_observer()
        # 每窗选材账目（有界；供健康面复核"实际送入的是什么"）
        self._material_selection = {}
        # C-142：源帧捕获钩子（可选注入；None=零行为、无默认全帧归档）。
        # 仅显式验收运行接线；触发点见 _capture_source_frames。
        self.source_capture = source_capture
        self.l4_factory = l4_factory
        from .win11_l3_contract import L3Budget
        self.l3_budget = L3Budget()
        # C-138 §3：理解历史统一经 UnderstandingStore（runtime 不再自持
        # _persist/_load_history/_rewrite_history）；persist_dir=None →
        # 纯内存实例，查看能力保留
        self.understanding = understanding
        if self.understanding is None:
            self.understanding = UnderstandingStore(
                root=persist_dir, max_per_camera=self.HISTORY_MAX)
        self.persist_dir = persist_dir
        # C-137 §4：当前有效身份注册表（由生产接线更新；发布门禁据此复核）
        self._registry = {cam: (None, None) for cam in self.camera_ids}
        # C-138 §2：窗口状态机登记（window_key → 状态；锁保护）
        self._win_lock = threading.Lock()
        self._open_windows = {}
        self._l4_lock = threading.Lock()
        self._l4_stages = OrderedDict()   # window_key → L4Stage（有界）
        self._lock = threading.Lock()
        self._last = {}
        self._status_counts = {}
        self._counts = {cam: {"processed": 0, "expired": 0, "failed": 0,
                              "identity_rejected": 0, "crops_produced": 0,
                              "l1_gate_blocked": 0, "l1_wait_timeout": 0,
                              "l3_enqueued": 0, "l3_dropped": 0,
                              "l3_completed": 0, "l4_versions": 0,
                              "persist_failed": 0,
                              "rejected_stale": 0,
                              "l4_auth_rejected": 0,
                              "crop_submit_dropped": 0,
                              "windows_settled": 0,
                              "settled_branch_ok": 0,
                              "settled_model_failed": 0,
                              "settled_expired": 0,
                              "settled_stale_identity": 0,
                              "settled_queue_evicted": 0,
                              "settled_stop_cancelled": 0}
                        for cam in self.camera_ids}
        self._mono = mono_clock if mono_clock is not None else time.monotonic
        # C-144：深度准入状态（每相机单槽，有界零增长）
        self._last_admission = {}
        # C-144-R2：已准入窗口接纳状态（真实生命周期：准入登记→入队
        # 更新→结算移除；有界 Ordered，超限丢最老）
        self._admitted_windows = OrderedDict()
        self._ADMITTED_WINDOWS_CAP = 64
        # C147：可选轻量内存 trace（默认全关零行为；事件词表与约束见
        # 模块 docstring C147 节——sink 异常吞并计数、不持锁投递、无 IO）
        self._trace_sink = trace_sink if callable(trace_sink) else None
        if trace_events_cap is not None and (isinstance(trace_events_cap, bool)
                or not 1 <= int(trace_events_cap) <= 4096):
            raise ValueError("trace ring capacity outside bounds")
        self._trace_events = (
            deque(maxlen=int(trace_events_cap))
            if self._trace_sink is None and trace_events_cap is not None
            else None)
        self._trace_errors = 0
        self._trace_thread = None
        self._trace_domain = trace_clock_domain or f"{os.getpid()}:{uuid.uuid4().hex}"
        self._trace_clock = trace_clock or self._mono
        self._trace_clock_kind = trace_clock_kind
        if trace_clock_kind not in ("real", "simulated"):
            raise ValueError("invalid trace clock kind")
        if self._trace_sink is not None or self._trace_events is not None:
            self._init_trace(trace_queue_cap)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="scam-l2",
                                        daemon=True)

    # ---- 单调钟 ------------------------------------------------------------

    def _mono_ms(self):
        return self._mono() * 1000.0

    # ---- C-137 §4：当前有效身份注册表 ---------------------------------------

    def set_camera_identity(self, camera_id, run_id, config_version):
        """生产接线在 Monitor 构造/区域切换时更新当前有效身份。

        C-139-R1 §1：注册表写入与发布世代（``_identity_epoch``）递增在同一
        发布锁段完成（锁序 publish→lock 单向，全仓无反序嵌套）——发布裁决
        段内重检身份/世代时不会被并发身份更新插队（裁决要么看到旧身份并
        完整走完，要么看到新身份直接拒收，不存在半程）。"""
        with self._publish_lock:
            with self._lock:
                if self._registry.get(camera_id) == (run_id, config_version):
                    return
                self._registry[camera_id] = (run_id, config_version)
                self._identity_epoch += 1

    def update_camera_identity(self, camera_id, run_id, config_version):
        """帧循环廉价调用：身份无变化零写入；变化（区域切换）即更新并递增
        发布世代（C-139-R1）。提交语义同 ``set_camera_identity``。"""
        self.set_camera_identity(camera_id, run_id, config_version)

    def _identity_ok(self, camera_id, run_id, config_version):
        """发布门禁：与注册表当前有效身份比对（不比较任务自带副本）。"""
        with self._lock:
            expected = self._registry.get(camera_id)
        return expected is not None and expected == (run_id, config_version)

    # ---- 生命周期 ---------------------------------------------------------

    def start(self):
        self._start_trace()
        if self.event_progress is not None:
            self.event_progress.start()
        self._thread.start()
        if self.l3_stage is not None:
            self._l3_stop = threading.Event()
            self._l3_thread = threading.Thread(target=self._l3_run,
                                               name="scam-l3", daemon=True)
            self._l3_thread.start()

    def material_pool_status(self):
        """C154-R1：材料池关闭事实（**与 L3 执行资源账目分列**）。

        - `closed`：准入已封；`complete`：本池收尾是否完成；
        - `held_pixels`/`reserved_temp_*`：当前持有与在途预留（真实值）；
        - `incomplete_reason`：未完成受控原因；`history.counts`：历史计数（不清零）。
        池未接线时返回 `{"available": False, ...}`，**不**把它当"已释放"。
        """
        report = getattr(self, "_material_pool_report", None)
        if report is not None:
            return {"available": True, **dict(report)}
        pool = getattr(self, "event_materials", None)
        if pool is None or not hasattr(pool, "close_report"):
            return {"available": False, "reason": "pool_unavailable"}
        try:
            return {"available": True, **dict(pool.close_report())}
        except Exception as exc:                    # 诊断路径不得影响运行时
            return {"available": False, "reason": type(exc).__name__}

    def stop(self, timeout=5.0):
        self._stop.set()
        # C-140 §1：停机提交（_l3_stop 置位 + _commit_epoch 锁内递增）先于
        # join/清队列/窗口收口/模型关闭——后四者全部在提交锁之外进行
        self._commit_stop()
        # C154 Q F1：**先**把取包点已移交、尚未观察的材料在池仍开放时结算
        # （此时它们由本次移交的引用保活，且尚未被判定失效）；随后才封准入。
        # 结算失败只计数（`_harvest_handoff_stats()`），不改变关机语义。
        try:
            self._pump_harvest_handoff()
        except Exception as exc:
            print(f"[NVR] L2 停机前取包点观察异常: {type(exc).__name__}",
                  flush=True)
        # C154-R1 §A 步骤1：停止开始**立即**封材料池准入——拒绝新材料，
        # 不等消费线程 join 后才封（池侧 close_begin 为幂等、0.0ms 返回）。
        _pool = getattr(self, "event_materials", None)
        if _pool is not None and hasattr(_pool, "close_begin"):
            try:
                _pool.close_begin(reason="runtime-stop")
            except Exception:
                pass
        # C153-R1 §3：停止即"实例退休"（不再取新任务/新提交被拒），但**不**
        # 因此释放仍在执行的占用（见下方回收段）。
        with self._exec_report_lock:
            self._retired = True
        if self._l3_thread is not None and self._l3_thread.is_alive():
            self._l3_thread.join(timeout=timeout)
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)
        thread_done = not self._thread.is_alive() and (
            self._l3_thread is None or not self._l3_thread.is_alive())
        # 停机收口：排队任务与在开窗口全部按 stop_cancelled 终态收口
        #（幂等；已终态分支/已 settled 窗口不重复计）
        self._drain_queue_on_stop()
        self._close_all_windows_on_stop()
        scheduler_done = True
        if hasattr(self.scheduler, "close"):
            try:
                self.scheduler.close()
            except Exception:
                scheduler_done = False
        # C154 Q F1：`scheduler.close()` 会取消剩余待处理窗（同样是 release
        # 路径，同样会移交）；再排空一次，保证停机的观察账目**不漏项**。
        # 此时池准入已封，池侧如实按 `pool_closed` 记录（不假装观察成功）。
        try:
            self._pump_harvest_handoff()
        except Exception as exc:
            print(f"[NVR] L2 停机收尾取包点观察异常: {type(exc).__name__}",
                  flush=True)
        backends = []
        if self.adapter is not None and hasattr(self.adapter, "close"):
            try:
                backends.append(self.adapter.close(timeout_s=timeout))
            except Exception as exc:
                backends.append({"closed": False, "close_incomplete": True,
                                 "error": type(exc).__name__})
        # C-137 B4：L2 与 L3 backend 同一收尾合同，都不能只关一个
        if self.l3_backend is not None and hasattr(self.l3_backend, "close"):
            try:
                backends.append(self.l3_backend.close(timeout_s=timeout))
            except Exception as exc:
                backends.append({"closed": False, "close_incomplete": True,
                                 "error": type(exc).__name__})
        # C154-R1 §A 步骤3–5：**锁外**有界等待在途复制预留归还 → 释放池持有
        # 像素 → 冻结有界无像素摘要。材料池释放**不等于** L3 模型执行资源
        # 释放：此处只动池账目，模型在途仍按上方真实证据记账。
        _pool = getattr(self, "event_materials", None)
        self._material_pool_done = True          # 池不存在=不适用，按合法关闭处理
        if _pool is not None and hasattr(_pool, "close_report"):
            # C154-R1 验收修正①：**不得**无条件声明依赖已结束——按实际结束证据
            # 判断池像素依赖是否终止（join/close 被调用过 ≠ 已完成）。
            _consumer_alive = bool(getattr(self._thread, "is_alive", lambda: False)())
            _l3_alive = bool(self._l3_thread is not None
                             and getattr(self._l3_thread, "is_alive",
                                         lambda: False)())
            # 死守 2：backend 依赖未完成 = close_incomplete **或** error
            # **或** 明确 closed=False；非字典/未知坏结构**不得**默认为已结束。
            _backend_incomplete = any(
                (not isinstance(b, dict)) or bool(b.get("close_incomplete"))
                or bool(b.get("error")) or (b.get("closed") is False)
                for b in backends)
            # 死守 1（主协调验收）：**只**接受明确的非负整数 in_flight；
            # 缺字段/空字典/坏类型/bool 一律记"不可确认"（不得折叠成已结束）。
            # `l3_stage is None` = 合法无 L3 配置，单独处理、不与"有 stage 但状态缺失"混同。
            _stage_present = self.l3_stage is not None
            _in_flight = None                     # None = 不可确认
            if _stage_present:
                try:
                    _res = self.l3_stage.execution_resources()
                    _cand = _res.get("in_flight") if isinstance(_res, dict) else None
                    if (isinstance(_cand, int) and not isinstance(_cand, bool)
                            and _cand >= 0):
                        _in_flight = _cand
                except Exception:
                    _in_flight = None
            if not _stage_present:
                _inflight_ok = True               # 合法无 L3：不适用
                _in_flight_state = "no_l3_stage"
            elif _in_flight == 0:
                _inflight_ok = True
                _in_flight_state = "confirmed_zero"
            else:
                _inflight_ok = False
                _in_flight_state = "unconfirmed"
            _deps_done = (not _consumer_alive and not _l3_alive
                          and not _backend_incomplete and _inflight_ok)
            self._material_pool_dependencies = {
                "consumer_alive": _consumer_alive, "l3_alive": _l3_alive,
                "backend_close_incomplete": _backend_incomplete,
                "in_flight": _in_flight,
                "in_flight_state": _in_flight_state,
                "dependencies_done": _deps_done}
            try:
                if hasattr(_pool, "await_reservations"):
                    _pool.await_reservations(timeout_s=timeout)
                if hasattr(_pool, "release_pixels"):
                    # 依赖未确认 → 传 False（池将拒绝释放并保真持有量），
                    # 绝不以"调用过 join/close"代替完成证据。
                    _pool.release_pixels(dependencies_done=_deps_done)
                self._material_pool_report = _pool.close_report()
            except Exception as exc:
                self._material_pool_report = {
                    "closed": None, "complete": False,
                    "incomplete_reason": type(exc).__name__}
            # 修正②：池完成状态进入 stop() 判据；缺字段/坏报告**不得**默认成功。
            _report = self._material_pool_report or {}
            self._material_pool_done = bool(_report.get("complete") is True)
        # C153-R1 §3：停机收口**只按真实执行结束证据**回收执行占用（并发槽 +
        # 在途 gauge）。旧行为无条件 `release_held_executions` 把仍在执行的
        # 占用清空/归零——等于把"丢掉引用"当"释放资源"，与 `backend.close`
        # 返回 `close_incomplete=True` 的事实自相矛盾（并发上限因此失真）。
        # 现在：执行未结束 → 挂起记录与占用**保留**；数量+身份、以及资源关闭
        # 是否完成，经 `execution_status()` / `stop_report()` 分列如实上报。
        released_now = 0
        release_error = None
        if self.l3_stage is not None and hasattr(self.l3_stage,
                                                 "release_held_executions"):
            try:
                released_now = int(self.l3_stage.release_held_executions(
                    reason="runtime_stop") or 0)
            except Exception as exc:
                release_error = type(exc).__name__
        progress_done = True
        if self.event_progress is not None:
            try:
                progress_done = self.event_progress.close(timeout=timeout)
            except Exception:
                progress_done = False
        trace_done = self._close_trace(timeout, producers_done=thread_done)
        # 停机事实冻结（含"资源关闭未完成"的完整事实）：重复 stop 幂等覆盖，
        # 记录只按真实结束证据收敛。
        self._freeze_stop_report(backends=backends,
                                 scheduler_done=scheduler_done,
                                 thread_done=thread_done,
                                 released_now=released_now,
                                 release_error=release_error,
                                 progress_done=progress_done,
                                 trace_done=trace_done)
        for b in backends:
            # 死守 2b（主协调验收）：**未知/坏返回结构不得默认为依赖已结束**，
            # 且不得因非字典结果抛异常——一律按"未完成"处理并如实返回 False。
            if ((not isinstance(b, dict)) or bool(b.get("close_incomplete"))
                    or bool(b.get("error")) or (b.get("closed") is False)):
                return False
        return (thread_done and scheduler_done and progress_done
                and trace_done
                and all(b.get("closed", True) for b in backends)
                and getattr(self, "_material_pool_done", True))

    def _commit_stop(self):
        """C-140 §1：停机提交点——``_l3_stop`` 置位后在 ``_l3_lock`` 内
        递增 ``_commit_epoch``。发布最终裁决段（``_publish_l3_record``）
        用同一把 ``_l3_lock`` 捕获基线并授予成功权：谁先取得提交权谁确定
        先后语义——stop 先提交→此后不再授予新 branch_ok（裁决段基线比对
        失败改判结构化拒收）；发布先授予→授予后提交的 stop 不追回，已
        授予结果作为完整身份历史保存。锁内只做内存计数（无 join/磁盘/
        模型/backend 关闭）；join/清队列/窗口收口/模型关闭均在调用方
        （``stop``）本提交之后的锁外进行。"""
        if self._l3_stop is not None:
            self._l3_stop.set()
        with self._l3_lock:
            self._commit_epoch += 1

    # ---- C153-R1 §3：停机三件事分列报告 + 在途记录冻结 -----------------------

    def _l3_queue_state(self):
        """L3 队列状态（持 ``_l3_lock`` 读；调用方不得在其它状态锁内调用）。"""
        with self._l3_lock:
            queues = {cam: len(q) for cam, q in self._l3_queues.items()}
            return queues, sum(queues.values()), self._commit_epoch

    def _l3_execution_view(self):
        """执行资源**如实视图**：stage 在位→现场读；缺失/退休→available=False。

        绝不把"读不到"当"已释放"（那是同一类假释放）：不可读时调用方退回
        冻结记录，并如实标注来源。
        """
        stage = self.l3_stage
        reader = getattr(stage, "execution_resources", None)
        if not callable(reader):
            return {"available": False, "reason": "stage_unavailable",
                    "items": [], "held_unfinished": None, "in_flight": None,
                    "reclaimed_total": None}
        try:
            res = dict(reader())
        except Exception as exc:
            return {"available": False,
                    "reason": f"execution_resources_failed:{type(exc).__name__}",
                    "items": [], "held_unfinished": None, "in_flight": None,
                    "reclaimed_total": None}
        items = res.get("held")
        if not isinstance(items, list):
            items = []
        return {"available": True, "reason": None,
                "items": [dict(item) for item in items if isinstance(item, dict)],
                "held_unfinished": res.get("held_unfinished"),
                "in_flight": res.get("in_flight"),
                "reclaimed_total": res.get("reclaimed_total"),
                "concurrency": res.get("concurrency"),
                "slot_wait_timeout_s": res.get("slot_wait_timeout_s"),
                "retired": res.get("retired")}

    def _freeze_unfinished_records(self, live_view):
        """冻结在途执行记录（对象被替换/退休后仍可查询；不丢记录）。

        只在**现场可读**时按现场结果整体收敛（读到"已不在途"=真实结束证据，
        记录随之消失）；现场不可读（stage 被替换/退休）→ **保留**既有记录，
        绝不当成已释放。
        """
        if not live_view.get("available"):
            return
        fresh = {}
        for index, item in enumerate(live_view.get("items") or ()):
            fresh[(_execution_record_key(item), index)] = dict(item)
        with self._exec_report_lock:
            self._unfinished_records = fresh

    def _frozen_unfinished_records(self):
        with self._exec_report_lock:
            return [dict(record)
                    for _key, record in sorted(self._unfinished_records.items(),
                                               key=lambda kv: kv[0])]

    def _resources_close_state(self, backends=(), scheduler_done=None,
                               thread_done=None, attempted=None,
                               progress_done=None, trace_done=None):
        """资源关闭状态（第三条）：`backend.close` 未完成就是未完成。"""
        rows = [dict(b) if isinstance(b, dict) else {"result": b}
                for b in backends]
        incomplete = any(row.get("close_incomplete") or row.get("error")
                         for row in rows)
        return {"attempted": bool(attempted if attempted is not None else rows),
                "incomplete": bool(incomplete),
                "closed": bool(rows) and not incomplete and all(
                    row.get("closed", True) for row in rows),
                "backends": rows,
                "scheduler_closed": (None if scheduler_done is None
                                     else bool(scheduler_done)),
                "threads_joined": (None if thread_done is None
                                   else bool(thread_done)),
                "progress_closed": (None if progress_done is None
                                    else bool(progress_done)),
                "trace_closed": (None if trace_done is None
                                 else bool(trace_done))}

    def _freeze_stop_report(self, *, backends, scheduler_done, thread_done,
                            released_now, release_error=None,
                            progress_done=None, trace_done=None):
        """停机事实冻结：三件事分列 + 当次回收数量（重复 stop 幂等覆盖）。"""
        live = self._l3_execution_view()
        self._freeze_unfinished_records(live)
        with self._exec_report_lock:
            prior = self._stop_report
            prior_count = ((prior or {}).get("executions_unfinished") or {}).get(
                "count")
            frozen = [dict(record)
                      for _key, record in sorted(self._unfinished_records.items(),
                                                 key=lambda kv: kv[0])]
        if live.get("available"):
            items, source, available = live["items"], "live", True
            reason = None
        else:
            items, source, available = frozen, "stop_report", False
            reason = live.get("reason")
        queues, queue_depth, stop_commits = self._l3_queue_state()
        report = {
            "retired": True,
            "scheduler": {
                "stopped": bool(self._stop.is_set()),
                "l3_worker_running": (None if self._l3_thread is None
                                      else bool(self._l3_thread.is_alive())),
                "queue_depth": queue_depth,
                "queues": queues,
                "stop_commits": stop_commits,
            },
            "executions_unfinished": {
                "available": available,
                "source": source,
                "reason": reason,
                "count": len(items),
                "items": items,
                "in_flight": live.get("in_flight"),
                "reclaimed_total": live.get("reclaimed_total"),
                "reclaimed_this_stop": int(released_now or 0),
                "release_error": release_error,
                "prior_count": prior_count,
            },
            "resources_close_incomplete": self._resources_close_state(
                backends=backends, scheduler_done=scheduler_done,
                thread_done=thread_done, attempted=True,
                progress_done=progress_done, trace_done=trace_done),
        }
        with self._exec_report_lock:
            self._stop_report = report
            self._unfinished_records = {
                (_execution_record_key(record), index): dict(record)
                for index, record in enumerate(items)}
        return report

    def stop_report(self):
        """最近一次停机的**冻结事实报告**（未停机 → None；可重复查询）。

        含三件事分列：调度已停止 / 执行仍在途（数量+身份）/ 资源关闭未完成。
        冻结副本不因对象被替换/退休而丢失。
        """
        with self._exec_report_lock:
            report = self._stop_report
            if report is None:
                return None
            return json.loads(json.dumps(report, ensure_ascii=False,
                                         default=str))

    def execution_status(self):
        """三件事**分列**如实报告（可重复查询、幂等）。

        1. ``scheduler``：调度/worker 是否已停止（不再取新任务）；
        2. ``executions_unfinished``：执行仍在途的数量 + 可识别身份
           （window/branch/task 键）；现场不可读（stage 退休/被替换）时退回
           停机冻结记录（``source="stop_report"``），不丢在途记录；
        3. ``resources_close_incomplete``：资源关闭未完成的事实
           （``backend.close`` 返回的 closed/close_incomplete/pending_calls）。
        """
        live = self._l3_execution_view()
        if live.get("available"):
            self._freeze_unfinished_records(live)
            unfinished = {
                "available": True, "source": "live", "reason": None,
                "count": live.get("held_unfinished"),
                "items": live.get("items") or [],
                "in_flight": live.get("in_flight"),
                "reclaimed_total": live.get("reclaimed_total"),
                "reclaimed_this_stop": None, "release_error": None,
            }
        else:
            frozen = self._frozen_unfinished_records()
            unfinished = {
                "available": False, "source": "stop_report",
                "reason": live.get("reason"),
                "count": len(frozen), "items": frozen,
                "in_flight": None, "reclaimed_total": None,
                "reclaimed_this_stop": None, "release_error": None,
            }
        with self._exec_report_lock:
            frozen_report = self._stop_report
            retired = self._retired
        queues, queue_depth, stop_commits = self._l3_queue_state()
        close_state = ((dict(frozen_report["resources_close_incomplete"]))
                       if frozen_report else {"attempted": False,
                                              "incomplete": False,
                                              "closed": False,
                                              "backends": [],
                                              "scheduler_closed": None,
                                              "threads_joined": None})
        return {
            "retired": bool(retired),
            "scheduler": {
                "stopped": bool(self._stop.is_set()),
                "l3_worker_running": (None if self._l3_thread is None
                                      else bool(self._l3_thread.is_alive())),
                "queue_depth": queue_depth,
                "queues": queues,
                "stop_commits": stop_commits,
            },
            "executions_unfinished": unfinished,
            "resources_close_incomplete": close_state,
            "live_stage_available": bool(live.get("available")),
            "concurrency": live.get("concurrency"),
            "slot_wait_timeout_s": live.get("slot_wait_timeout_s"),
        }

    # ---- 观测 --------------------------------------------------------------

    def snapshot(self):
        with self._lock:
            base = {"enabled": True,
                    "cameras": {cam: dict(self._counts.get(cam, {}))
                                for cam in self.camera_ids},
                    "counts": dict(self._status_counts),
                    "last": {cam: {k: v for k, v in dict(d).items()
                                   if k != "output"}
                             for cam, d in self._last.items()}}
        with self._win_lock:
            states = {"producing": 0, "sealed": 0}
            for entry in self._open_windows.values():
                state = entry["state"]
                states[state] = states.get(state, 0) + 1
        base["open_windows"] = states
        backend = None
        if self.adapter is not None and hasattr(self.adapter, "diagnostic"):
            try:
                backend = self.adapter.diagnostic()
            except Exception:
                backend = {"error": "diagnostic_unavailable"}
        if backend is not None:
            base["backend"] = backend
        if hasattr(self.scheduler, "snapshot"):
            try:
                base["windows"] = self.scheduler.snapshot()
            except Exception:
                base["windows"] = {"error": "snapshot_unavailable"}
        with self._l3_lock:
            base["l3"] = {"queue_depth": sum(len(q) for q
                                             in self._l3_queues.values()),
                          "dropped": self._l3_dropped,
                          "stop_commits": self._commit_epoch,
                          "queues": {cam: len(q) for cam, q
                                     in self._l3_queues.items()}}
        if self.l3_window_budget_ledger is not None:
            # C153-R1：账目/终态对账独立于 event_progress 暴露（健康面可查
            # "被预算覆盖/未分析"的窗口与逐分支终态一一对应）。
            with self._plan_lock:
                accounting = {k: [dict(row) for row in rows]
                              for k, rows in list(
                                  self._l3_plan_accounting.items())[-4:]}
            base["l3_shared_budget"] = {
                "windows_registered": len(
                    self.l3_window_budget_ledger.window_keys()),
                "recent_coverage": {
                    "|".join(str(p) for p in k): v
                    for k, v in list(self._l3_budget_coverage.items())[-4:]},
                "recent_plan_settlement": {
                    "|".join(str(p) for p in k): rows
                    for k, rows in accounting.items()}}
        if self.event_materials is not None:
            # C154 G：同事件跨窗选材池（有界）+ 每窗选材账目（"实际送入模型
            # 的帧集合"与"声明保留的开始/转折/最新"对齐证据）。
            try:
                base["event_materials"] = self.event_materials.snapshot()
            except Exception:
                base["event_materials"] = {"status": "unavailable"}
            # C154 Q F1：取包点（折叠/丢弃/取消/关闭**之前**）观察的账目——
            # 有界移交的容量、深度、计数、失败原因与逐材料去向。
            try:
                base["event_materials_harvest"] = {
                    **self._harvest_handoff_stats(),
                    "recent": self.harvest_handoff_records(limit=8)}
            except Exception:
                base["event_materials_harvest"] = {"status": "unavailable"}
            with self._plan_lock:
                recent = list(self._material_selection.items())[-4:]
            base["material_selection"] = {
                "|".join(str(p) for p in key): row for key, row in recent}
        if self.event_progress is not None:
            base["event_progress"] = self.event_progress.snapshot()
            # C153 整合（主会话范围）：把**未关联观察**的具体原因带到既有
            # /api/health 的 l2.event_progress 里——页面/健康接口无需改 server
            # 即可看到"为什么这些窗口没有并入任何事件"。索引为有界内存视图，
            # 持久全量仍在既有 L4 理解历史（version_id 可复查）。
            try:
                base["event_progress"]["recent_unassociated"] = \
                    self.event_progress.unassociated(limit=8)
            except Exception:
                # snapshot 是诊断路径：任何取数失败都不得影响运行时
                base["event_progress"]["recent_unassociated"] = []
        if self._trace_sink is not None or self._trace_events is not None:
            with self._trace_lock:
                base["trace"] = dict(self._trace_counts,
                    pending=self._trace_queue.qsize(), in_flight=self._trace_in_flight,
                    clock_domain=self._trace_domain,
                    delivery_complete=self._trace_closed and not self._trace_in_flight
                    and self._trace_queue.empty() and self._trace_producers_done
                    and not any(self._trace_counts.get(k, 0) for k in
                        ("dropped", "callback_errors", "clock_errors", "after_close_dropped")))
        # C153-R1 §3：健康面如实分列「调度已停止／执行仍在途（数量+身份）／
        # 资源关闭未完成」，无需改 server 即可查看（snapshot 是诊断路径：
        # 取数失败不得影响运行时；也绝不因此编造"已释放"）。
        try:
            base["execution_status"] = self.execution_status()
        except Exception as exc:
            base["execution_status"] = {
                "error": "execution_status_unavailable",
                "reason": type(exc).__name__}
        if self.event_materials is not None:
            base["refbudget"] = self.refbudget_snapshot()
        return base

    def refbudget_snapshot(self):
        """C154 车道 U F1：**三本账并列**的只读快照（诊断路径）。

        - `pool`：池像素持有（`EventMaterialPool.accounting()` 的 `held_bytes`
          / `held_pixels`，含容量上界）与**复制预留**（`reserved_temp_bytes`
          / `reserved_temp_pixels`）——两者是池侧**两本**独立账；
        - `lease`：材料仓消费者侧存活字节（`consumer_alive_bytes`）与其全局
          预算 `lease_cap`——租约副本是队列外部引用的**承载对象**，故这一本
          是"队列引用所指向的字节从哪来"的口径；
        - `queue`：**队列外部引用**账（第三本账，独立分列，见
          `_harvest_external_stats`）。

        三者**互不混算**：池持有的帧是池自己 copy 出来的数组，与本题移交的
        租约副本不是同一批对象；队列账只统计"队列/在途批次当前真正持有的
        独立缓冲"。取数失败一律记 `unavailable` + 原因，**绝不填 0 冒充**。
        """
        pool = self.event_materials
        out = {
            "account": "f1_refbudget",
            "queue": self._harvest_external_stats(),
            "pool": {"status": "unavailable", "reason": "pool_unavailable"},
            "lease": {"status": "unavailable", "reason": "pool_unavailable"},
            "store": {"status": "unavailable", "reason": "store_unavailable"},
        }
        if pool is not None and hasattr(pool, "accounting"):
            try:
                accounting = pool.accounting()
                limits = accounting.get("limits") or {}
                out["pool"] = {
                    "status": "ok",
                    "held_bytes": accounting.get("held_bytes"),
                    "held_pixels": accounting.get("held_pixels"),
                    "held_frames": accounting.get("held_frames"),
                    "held_bytes_book": accounting.get("held_bytes_book"),
                    "drift_bytes": accounting.get("drift_bytes"),
                    "drift_pixels": accounting.get("drift_pixels"),
                    "reserved_temp_bytes": accounting.get("reserved_temp_bytes"),
                    "reserved_temp_pixels": accounting.get(
                        "reserved_temp_pixels"),
                    "copy_count": accounting.get("copy_count"),
                    "copy_reservations": accounting.get("copy_reservations"),
                    "max_total_bytes": limits.get("max_total_bytes"),
                    "max_total_pixels": limits.get("max_total_pixels"),
                    "max_frame_pixels": limits.get("max_frame_pixels"),
                }
            except Exception as exc:              # 诊断：不编数、不冒充
                out["pool"] = {"status": "unavailable",
                               "reason": type(exc).__name__}
        store = getattr(self, "store", None)
        if store is not None and hasattr(store, "snapshot"):
            try:
                snap = store.snapshot()
                out["lease"] = {
                    "status": "ok",
                    "consumer_alive_bytes": snap.get("consumer_alive_bytes"),
                    "lease_bytes": snap.get("lease_bytes"),
                    "active_leases": snap.get("active_leases"),
                    "released_leases": snap.get("released_leases"),
                    "lease_cap": getattr(store, "max_lease_bytes", None),
                }
                out["store"] = {
                    "status": "ok",
                    "store_bytes": snap.get("store_bytes"),
                    "total_bytes": snap.get("total_bytes"),
                    "store_cap": getattr(store, "max_total_bytes", None),
                    "total_packages": snap.get("total_packages"),
                }
            except Exception as exc:              # 诊断：不编数、不冒充
                out["lease"] = {"status": "unavailable",
                                "reason": type(exc).__name__}
                out["store"] = {"status": "unavailable",
                                "reason": type(exc).__name__}
        return out

    def last_output(self, camera):
        with self._lock:
            entry = self._last.get(camera)
            return entry.get("output") if entry else None

    @property
    def understanding_store(self):
        """C-138 §5 server 回退契约别名：``state.l2.understanding_store``
        即本 runtime 持有的 UnderstandingStore 实例（``self.understanding``
        ——append/history/summary/snapshot 冻结接口）。注意 ``self.store``
        是材料仓（MaterialsStore，无 summary/history）不得错指——server
        两处调用点（/api/health 理解块与 /api/understanding/<camera>）的
        ``hasattr(ustore, "summary") and hasattr(ustore, "history")`` 门禁
        只有本别名可满足；缺别名即静默降级到过渡兼容形状（enriched 当前/
        历史分列 branches/fusion_history/is_current/current_identity 全部
        不可达）。"""
        return self.understanding

    def history(self, camera, kind=None):
        """理解历史（经 UnderstandingStore；persist_dir=None 也可用）。"""
        if kind is not None:
            return list(self.understanding.history(camera, kind))
        return {k: list(self.understanding.history(camera, k))
                for k in self._PERSIST_KINDS}

    def summary_line(self, camera):
        """工作台「理解进展」单行摘要（中文；无路径无大图）。

        C-141 B4：身份感知收口——文本经模块级纯函数
        ``compose_current_summary`` 组装，只呈现**当前完整身份**（权威
        注册表 run/config）的结果；无当前结果→「正在分析/暂无当前结果」；
        历史文本必标「历史」；分支类别如实（局部≠全景）；persist 失败
        在此单独如实可见（branch_ok≠保存成功；摘要不得冒充"理解已保存"
        ——内存可见≠已落盘，文本只来自真实保存的历史行）。"""
        with self._lock:
            entry = dict(self._last.get(camera) or {})
            persist_failed = (self._counts.get(camera, {})
                              .get("persist_failed", 0))
            current_identity = self._registry.get(camera)
        try:
            records_by_kind = {kind: list(self.understanding.history(
                camera, kind)) for kind in self._PERSIST_KINDS}
        except Exception:
            records_by_kind = {kind: [] for kind in self._PERSIST_KINDS}
        extra = []
        if entry:
            gate = entry.get("gate_reason")
            status = entry.get("status")
            if gate:
                extra.append(f"关系识别不可用（{gate}），已保留画面补充理解")
            elif status == "ok":
                extra.append(f"关系候选 {entry.get('candidates', 0)} 条"
                             "（模型推断，未经校准）")
            elif status:
                extra.append(f"状态 {status}")
        return compose_current_summary(
            camera, records_by_kind, current_identity,
            persist_failed=persist_failed, extra_parts=extra)

    def understanding_summary(self, camera):
        """C-141 集成补口：C 代理 enriched 视图的摘要优先来源（server
        ``getattr(l2, "understanding_summary", None)``，非空字符串原文
        采用、不改写）。直接委托 ``summary_line``（单一事实来源，语义
        恒一致）：只呈现当前完整身份（权威注册表 run/config）的文本；
        无当前结果→「正在分析，当前身份暂无已完成结果」；历史文本必标
        「历史」；「保存失败」提示保留（内存可见≠已落盘）。"""
        return self.summary_line(camera)

    # ---- 内部：记录 ---------------------------------------------------------

    def _record(self, camera, output=None, fallback=None, error=None):
        with self._lock:
            counts = self._counts.setdefault(camera, {})
            counts["processed"] = counts.get("processed", 0) + 1
            entry = {"camera": camera, "at": time.time()}
            if output is not None:
                status = getattr(output.status, "value", str(output.status))
                counts["crops_produced"] = counts.get(
                    "crops_produced", 0) + len(output.crops or ())
                self._status_counts[status] = \
                    self._status_counts.get(status, 0) + 1
                entry.update({
                    "status": status,
                    "candidates": len(output.candidates or ()),
                    "crops": len(output.crops or ()),
                    "calibrated": bool(getattr(output, "calibrated", False)),
                    "model_ref": getattr(output, "model_ref", ""),
                    "timings_ms": dict(
                        getattr(output, "timings_ms", {}) or {})})
                self._last[camera] = entry
            elif fallback is not None:
                status = self.FALLBACK_STATUS_MAP.get(
                    fallback, "l1_gate_blocked")
                if fallback == "l1_wait_timeout":
                    counts["l1_wait_timeout"] = \
                        counts.get("l1_wait_timeout", 0) + 1
                elif fallback != "empty":
                    counts["l1_gate_blocked"] = \
                        counts.get("l1_gate_blocked", 0) + 1
                self._status_counts[status] = \
                    self._status_counts.get(status, 0) + 1
                entry.update({"status": status, "gate_reason": fallback,
                              "candidates": 0, "calibrated": False})
                self._last[camera] = entry
            else:
                counts["failed"] = counts.get("failed", 0) + 1
                entry.update({"status": "error"})
                self._last[camera] = entry
        if output is not None or fallback is not None:
            persisted = dict(entry)
            persisted["camera"] = camera
            self._append_history(camera, "l2", persisted)

    def _count(self, camera, key):
        with self._lock:
            counts = self._counts.setdefault(camera, {})
            counts[key] = counts.get(key, 0) + 1

    def _init_trace(self, capacity):
        if isinstance(capacity, bool) or not 1 <= int(capacity) <= 4096:
            raise ValueError("trace capacity outside bounds")
        self._trace_lock = threading.Lock()
        self._trace_queue = queue.Queue(maxsize=int(capacity))
        self._trace_counts = {}
        self._trace_closed = False
        self._trace_producers_done = False
        self._trace_in_flight = False
        self._trace_sequence = 0

    def configure_trace(self, observer, *, clock_domain, clock=None, clock_kind="real"):
        """Explicit shared-domain configuration before runtime/bridge use."""
        if self._thread.ident is not None or self._trace_sink is not None or self._trace_events is not None:
            raise RuntimeError("trace configuration must precede use")
        if not callable(observer) or not isinstance(clock_domain, str) or not clock_domain:
            raise ValueError("observer and process-instance clock domain required")
        if clock_kind not in ("real", "simulated") or (clock is not None and not callable(clock)):
            raise ValueError("invalid trace clock")
        if self.event_progress is not None:
            self.event_progress.set_trace_observer(observer, clock_domain=clock_domain,
                clock=clock or self._mono, clock_kind=clock_kind)
        self._trace_sink = observer
        self._trace_domain = clock_domain
        self._trace_clock = clock or self._mono
        self._trace_clock_kind = clock_kind
        self._init_trace(128)

    def _start_trace(self):
        if self._trace_sink is not None:
            with self._trace_lock:
                if self._trace_thread is None and not self._trace_closed:
                    self._trace_thread = threading.Thread(target=self._run_trace,
                        name="scam-runtime-observer", daemon=True)
                    self._trace_thread.start()

    def _run_trace(self):
        while True:
            try:
                record = self._trace_queue.get(timeout=0.05)
            except queue.Empty:
                with self._trace_lock:
                    if self._trace_closed:
                        return
                continue
            with self._trace_lock:
                self._trace_in_flight = True
            try:
                self._trace_sink(record)
                key = "delivered"
            except Exception:
                key = "callback_errors"
                self._trace_errors += 1
            finally:
                with self._trace_lock:
                    self._trace_counts[key] = self._trace_counts.get(key, 0) + 1
                    self._trace_in_flight = False
                self._trace_queue.task_done()

    def _close_trace(self, timeout, *, producers_done=True):
        if self._trace_sink is None and self._trace_events is None:
            return True
        with self._trace_lock:
            self._trace_producers_done = producers_done
            if producers_done:
                self._trace_closed = True
        if self._trace_thread is not None:
            self._trace_thread.join(timeout=max(0.0, timeout))
        return producers_done and not (self._trace_thread and self._trace_thread.is_alive()) and self._trace_queue.empty()

    def _trace_emit(self, kind, **fields):
        """C147：trace 事件投递（调用方须在锁外；异常吞并计数不向上抛）。

        两通道全关时仅做两次属性判断即返回——不构造事件 dict、不取钟，
        快路径零行为（模块 docstring C147 节合同）。"""
        if self._trace_sink is None and self._trace_events is None:
            return
        try:
            stamp = float(self._trace_clock()) * 1000.0
            if not math.isfinite(stamp):
                raise ValueError("nonfinite trace time")
            event = {"kind": kind, "stage": kind, "mono_ns": int(round(stamp * 1e6)),
                "schema": "scam.trace/v1", "component": "runtime",
                "t_mono_ms": stamp, "time_unit": "ms", "clock_kind": "host_monotonic",
                "clock": self._trace_clock_kind, "clock_domain": self._trace_domain,
                "process_id": os.getpid(), "event_id": None, "description_version": None}
            for key, value in fields.items():
                event[key] = _trace_json_value(value)
            if len(json.dumps(event, allow_nan=False).encode("utf-8")) > 65536:
                raise ValueError("trace record byte budget exceeded")
            window = fields.get("window_key") or ()
            for i, key in enumerate(("camera_id", "run_id", "config_version", "window_id")):
                event[key] = window[i] if len(window) > i else fields.get(key)
            event["camera_id"] = event["camera_id"] or fields.get("camera")
            event["source_version_id"] = fields.get("version_id")
            branch = fields.get("branch")
            if isinstance(branch, (list, tuple)) and len(branch) == 7:
                event["task_key"] = list(branch)
                event["internal_material_id"] = branch[6]
            with self._trace_lock:
                self._trace_sequence += 1
                event["attempt"] = self._trace_sequence
                event["trace_id"] = f"{self._trace_domain}:runtime:{self._trace_sequence}"
                if self._trace_closed:
                    self._trace_counts["after_close_dropped"] = self._trace_counts.get("after_close_dropped", 0) + 1
                    return
                if self._trace_sink is not None:
                    self._trace_queue.put_nowait(event)
                else:
                    if len(self._trace_events) == self._trace_events.maxlen:
                        self._trace_counts["dropped"] = self._trace_counts.get("dropped", 0) + 1
                    self._trace_events.append(event)
                self._trace_counts["queued"] = self._trace_counts.get("queued", 0) + 1
            if self._trace_sink is not None:
                self._start_trace()
        except queue.Full:
            with self._trace_lock:
                self._trace_counts["dropped"] = self._trace_counts.get("dropped", 0) + 1
        except Exception:
            with self._trace_lock:
                self._trace_errors += 1
                self._trace_counts["clock_errors"] = self._trace_counts.get("clock_errors", 0) + 1

    def _append_history(self, camera, kind, payload):
        """经 UnderstandingStore 保存（线程同步在 store 内）；失败计数。"""
        try:
            ok = self.understanding.append(camera, kind, payload)
        except Exception:
            print(f"[NVR] 理解结果保存异常（{camera}/{kind}）:", flush=True)
            traceback.print_exc()
            ok = False
        if not ok:
            self._count(camera, "persist_failed")
        if kind == "l4" and self.event_progress is not None:
            self._trace_emit("l4_handoff", camera=camera,
                window_key=[payload.get(k) for k in
                    ("camera_id", "run_id", "config_version", "window_id")],
                version_id=payload.get("version_id"))
            try:
                if not self.event_progress.submit(payload):
                    self._count(camera, "event_progress_rejected")
            except Exception:
                # L4 history remains available as an unassociated observation;
                # an adapter failure must not kill understanding or tracking.
                self._count(camera, "event_progress_failed")
        return ok

    # ---- C-138 §2：窗口状态机 -----------------------------------------------

    def _register_window(self, handle):
        """acquire 后登记窗口（producing）；身份不符 → 整窗拒收结算。

        窗口 key 的 run/config 取自窗内材料包（调度器句柄不携带身份）；
        窗内混杂或与注册表当前身份不符 → 不登记，整窗拒收（租约如实
        归还、占用解除、计数），返回 None。
        """
        cam = handle.camera_id
        packages = tuple(handle.packages)
        if not packages:
            try:
                handle.release()
                handle.mark_window_settled()
            except Exception:
                pass
            return None
        run_id = packages[0].run_id
        config_version = packages[0].config_version
        mixed = any(p.run_id != run_id or p.config_version != config_version
                    for p in packages)
        if mixed or not self._identity_ok(cam, run_id, config_version):
            self._count(cam, "rejected_stale")
            self._trace_emit("rejected_stale", camera=cam,
                             window_key=[cam, run_id, config_version,
                                         handle.window_id],
                             branch=None, reason="window_identity_mismatch")
            try:
                handle.release()
                handle.mark_window_settled()
            except Exception:
                pass
            return None
        window_key = (cam, run_id, config_version, handle.window_id)
        with self._win_lock:
            self._open_windows[window_key] = {
                "handle": handle, "camera": cam, "state": "producing",
                "branches": {}, "born_mono_ms": self._mono_ms(),
                "done": False}
        return window_key

    def _register_branch(self, window_key, branch_key):
        """分支登记（producing 且未收口态内；重复键=接线缺陷，拒收第二次
        登记）。C-139 A1：已收口（done）窗口一律拒登——收口后不得再长出
        新 pending 分支（否则 TTL/停机收口的终态快照不完整）。"""
        with self._win_lock:
            entry = self._open_windows.get(window_key)
            if entry is None or entry["done"]:
                return False
            if entry["state"] != "producing":
                return False
            if branch_key in entry["branches"]:
                return False
            entry["branches"][branch_key] = "pending"
            return True

    def _seal_window(self, window_key):
        """封口：L2 对该窗口的生产结束（handle.release 后调用）。"""
        with self._win_lock:
            entry = self._open_windows.get(window_key)
            if entry is None:
                return False
            entry["state"] = "sealed"
        self._settle_l3_shared_budget(window_key)
        self._maybe_settle_window(window_key)
        return True

    def _settle_l3_shared_budget(self, window_key):
        """C153：窗口封口时把共享预算**覆盖账目**留档（被覆盖/未分析分列），
        并 forget 该窗口防账本无界增长。执行期失败/超时**不**归还额度
        （计划额度 ≠ 执行资源 ≠ 已执行消费）。"""
        ledger = self.l3_window_budget_ledger
        key = tuple(window_key)
        if ledger is None:
            if self.event_materials is not None:
                # 账本关闭（对照路径）不阻断选材池的窗口索引清理（C154 G）
                try:
                    self.event_materials.forget_window(key)
                except Exception:
                    pass
            return
        try:
            coverage = ledger.coverage(window_key)
        except Exception:
            coverage = None
        if coverage is not None:
            with self._plan_lock:
                accounting = self._l3_plan_accounting.get(key)
                accounting = (None if not accounting
                              else [dict(row) for row in accounting])
            if accounting:
                # 计划账目与终态一一对应随覆盖账目一起留档（封口后仍可查）
                coverage = dict(coverage)
                coverage["plan_settlement"] = accounting
            self._l3_budget_coverage[key] = coverage
            while len(self._l3_budget_coverage) > self._l3_budget_coverage_cap:
                self._l3_budget_coverage.pop(
                    next(iter(self._l3_budget_coverage)))
        # 该窗计划账目已留档 → 清运行时活页（防无界；归属已冻结）
        with self._plan_lock:
            self._l3_plan_accounting.pop(key, None)
            self._l3_plan_settled.pop(key, None)
        if self.event_materials is not None:
            # C154 G：只清该窗口→事件的索引（材料池按**事件**保留关键材料，
            # 不因窗口封口丢失开始/转折/最新归属）；池自身另有硬上限。
            try:
                self.event_materials.forget_window(key)
            except Exception:
                pass
        try:
            ledger.forget(window_key)
        except Exception:
            pass

    def _settle_l3_plan(self, camera, window_key, plan):
        """C153-R1 §2：把预算计划的 **kept/merged/dropped** 落进 runtime 状态机。

        - 每个**预期分支恰一次**终态：merged/dropped 行在此登记并结算
          （`budget_merged` / `budget_dropped`），已处理键（plan_seq,index）
          记录在 `_l3_plan_settled`，重复回调一律跳过；
        - `merged` 明确**复用对象/来源**（detail 带 into 分支与来源键），
          终态码不是 `branch_ok` → 不冒充执行过推理；
        - `dropped` 明确"未分析 + 受控原因"；
        - 非 `branch_ok` 走 `_settle_branch_terminal` → 缺失因素进该窗 L4
          （L4 保留未知/未分析，不编造内容）；
        - 与 kept 任务**同身份**的 merged 行由该任务持有该分支键 → 不重复
          结算（`owned_by_kept_task`），完成后由正常路径结算一次。

        返回本次新增的账目行列表（诊断/证据用）。
        """
        if plan is None or self.l3_window_budget_ledger is None:
            return []
        key = tuple(window_key)
        # 锁序 plan→win 单向：本方法持 `_plan_lock` 期间只经由
        # `_register_branch`/`_settle_branch_terminal` 短暂取 `_win_lock`；
        # 全仓不存在 win→plan 的反序嵌套（`snapshot` 也先 plan 后 win）。
        with self._plan_lock:
            plan_seq = None
            records = []
            settled = self._l3_plan_settled.setdefault(key, set())
            for entry in tuple(plan.get("entries") or ()):
                disposition = entry.get("disposition")
                if disposition not in ("merged_into", "dropped"):
                    continue
                branch_index = entry.get("index")
                plan_seq = entry.get("plan_seq", plan_seq)
                token = (plan_seq, branch_index)
                if token in settled:
                    continue
                settled.add(token)
                branch_key = tuple(entry.get("branch_key") or ())
                row = {
                    "plan_seq": plan_seq,
                    "branch_index": branch_index,
                    "disposition": disposition,
                    "reason": entry.get("reason"),
                    "branch_key": list(branch_key),
                    "terminal": None,
                    "settled": False,
                    "owned_by": None,
                }
                if len(branch_key) != 7:
                    row["owned_by"] = "malformed_branch_key"
                    records.append(row)
                    continue
                if disposition == "merged_into":
                    into = entry.get("merged_into")
                    into_key = tuple(entry.get("merged_into_branch_key") or ())
                    row["merged_into"] = into
                    row["merged_into_branch_key"] = list(into_key)
                    terminal = self.TERMINAL_BUDGET_MERGED
                    detail = ("reused_branch_index={} reason={} into={}".format(
                        into, entry.get("reason"),
                        ":".join(str(part) for part in into_key[4:]) or "-"))
                else:
                    terminal = self.TERMINAL_BUDGET_DROPPED
                    detail = "not_analyzed reason={}".format(
                        entry.get("reason"))
                if not self._register_branch(key, branch_key):
                    # 同身份已由 kept 任务持有（或已终态）：不重复结算
                    with self._win_lock:
                        entry_state = self._open_windows.get(key)
                        state = (None if entry_state is None
                                 else entry_state["branches"].get(branch_key))
                    row["owned_by"] = ("kept_task" if state == "pending"
                                       else str(state or "window_not_open"))
                    records.append(row)
                    continue
                applied = self._settle_branch_terminal(
                    camera, key, branch_key, terminal, detail=detail,
                    sources=("l3_window_budget", str(entry.get("reason"))))
                row["terminal"] = terminal
                row["settled"] = bool(applied)
                row["detail"] = detail
                records.append(row)
            if records:
                bucket = self._l3_plan_accounting.setdefault(key, [])
                bucket.extend(records)
                while (len(self._l3_plan_accounting)
                       > self._l3_plan_accounting_cap):
                    oldest = next(iter(self._l3_plan_accounting))
                    if oldest == key:
                        break
                    self._l3_plan_accounting.pop(oldest, None)
                    self._l3_plan_settled.pop(oldest, None)
            return records

    @staticmethod
    def _release_l3_task_budget(ledger, window_key, plan_index, reason):
        """设计丢弃/淘汰时归还**计划额度**（执行期失败/超时不归还）。

        归还对象是**该任务自己**的计划分支下标（`plan_out` 绑定，随入队
        上下文传递）——绝不再靠"猜任务对象上的下标属性"（L3Task 是
        `__slots__` 冻结形状，旧实现因此永远找不到下标 = 归还从未生效）。
        """
        if ledger is None or not isinstance(plan_index, int) \
                or isinstance(plan_index, bool):
            return False
        try:
            return bool(ledger.release(window_key, plan_index, reason=reason))
        except Exception:
            return False

    def _settle_branch_terminal(self, camera, window_key, branch_key,
                                terminal, detail=None, settle_window=True,
                                sources=()):
        """分支终态唯一提交点（C-139 §2；恰好一次；幂等）。返回是否本次
        发生转移。

        结算四件事：计数、缺失因素（非 branch_ok 经 accumulate 注入该窗
        L4——重复回调不重复 gap/版本/提醒，幂等由分支字典终态标记保证）、
        handle 分支登记、（若已 sealed 且全终态）窗口 settled。TTL 到期与
        停机收口同样经本点结算（settle_window=False 由调用方收口整窗）。
        sources：受控证据键（冻结签名第 6 参；随缺失因素入账，供追溯）。
        """
        with self._win_lock:
            entry = self._open_windows.get(window_key)
            if entry is None:
                return False
            if entry["branches"].get(branch_key) != "pending":
                return False
            entry["branches"][branch_key] = terminal
            handle = entry["handle"]
        try:
            handle.mark_branch_done(branch_key)
        except Exception:
            pass
        self._count(camera, "settled_" + terminal)
        # C147：终态 trace（expired/拒收/淘汰独立事件；branch_ok/model_
        # failed 以 stage_finished 收口——stage 起止配对）
        if terminal == "expired":
            self._trace_emit("expired", camera=camera,
                             window_key=list(window_key), branch=branch_key,
                             reason=str(detail) if detail else None)
        elif terminal == "queue_evicted":
            self._trace_emit("queue_evicted", camera=camera,
                             window_key=list(window_key), branch=branch_key,
                             reason=str(detail) if detail else None)
        elif terminal in ("stale_identity", "stop_cancelled"):
            self._trace_emit("rejected_stale", camera=camera,
                             window_key=list(window_key), branch=branch_key,
                             reason=terminal,
                             detail=str(detail) if detail else None)
        elif terminal in ("branch_ok", "model_failed"):
            self._trace_emit("stage_finished", camera=camera,
                             window_key=list(window_key), branch=branch_key,
                             status=terminal)
        if terminal != self.TERMINAL_OK and self.l4_factory is not None:
            self._accumulate_window_gap(camera, window_key, branch_key,
                                        terminal, detail,
                                        sources=tuple(sources))
        if settle_window:
            self._maybe_settle_window(window_key)
        return True

    def _maybe_settle_window(self, window_key):
        """sealed 且未终态分支集合为空 → settled（幂等）。

        settled=mark_window_settled（解除逻辑占用）+ L4 stage cleanup
        （证据已保存）+ open_windows 引用清理，一致完成。
        C-144-R2：同步移除窗口接纳登记；若启用 L3 且该窗零入队成功
        （处理失败/队列拒收/材料过期/停机拒收），把参考回滚到准入前快照并
        计一次有界重试——同签名真实变化下一窗可重新准入，不被永久压制。
        仅当当前参考仍是本窗产出（无后续窗推进）时回滚；重试超限
        （ADMIT_RETRY_MAX）后放弃（等真实新变化），防风暴。"""
        with self._win_lock:
            entry = self._open_windows.get(window_key)
            if entry is None or entry["done"]:
                return False
            if entry["state"] != "sealed":
                return False
            if any(state == "pending"
                   for state in entry["branches"].values()):
                return False
            entry["done"] = True
            del self._open_windows[window_key]
            handle = entry["handle"]
            camera = entry["camera"]
            adm = self._admitted_windows.pop(window_key, None)
        try:
            handle.mark_window_settled()
        except Exception:
            pass
        self._cleanup_l4(window_key)
        self._count(camera, "windows_settled")
        self._trace_emit("l4_final", camera=camera,
                         window_key=list(window_key))
        self._rollback_admission_if_unfulfilled(camera, adm)
        return True

    def _rollback_admission_if_unfulfilled(self, camera, adm):
        """C-144-R2 冻结 §2.3：L3 准入未兑现（零入队成功，包括入队前
        处理失败）时，把场景参考回滚到准入前快照并计一次有界
        重试——同签名真实变化下一窗可重新准入，不被永久压制。仅当当前
        参考仍是本窗产出（无后续窗推进）时回滚；超过 ADMIT_RETRY_MAX
        后放弃（等真实新变化），防风暴。幂等。"""
        if adm is None or adm.get("enqueued_ok") or self.l3_stage is None:
            return
        retry = adm.get("retry_count", 0) or 0
        prev = adm.get("prev_ref")
        if (retry < ADMIT_RETRY_MAX and (prev is None or isinstance(prev, dict))
                and self._last_admission.get(camera) is adm.get("new_ref")):
            # An unfulfilled very first admission has no prior scene. A bounded
            # retry marker preserves that absence without losing retry debt.
            restored = dict(prev) if prev is not None else {}
            restored["retry_count"] = retry + 1
            self._last_admission[camera] = restored
            self._count(camera, "admission_retries")

    def _sweep_open_windows(self):
        """窗口 TTL sweep：超限时 open_windows/队列中该窗任务/handle 引用
        一并收口（不能只减 scheduler frozen 数）。"""
        now_ms = self._mono_ms()
        limit_ms = self.window_ttl_s * 1000.0
        with self._win_lock:
            expired = [key for key, entry in self._open_windows.items()
                       if not entry["done"]
                       and now_ms - entry["born_mono_ms"] > limit_ms]
        for window_key in expired:
            self._expire_window(window_key)

    def _expire_window(self, window_key):
        """TTL 到期整窗收口：未终态分支经唯一终态提交点结算为 expired；
        队列中该窗任务清除；租约/占用/引用同步收口（幂等，重复到期不重
        复计）。done 先置位（堵住收口后新分支登记），分支结算在锁外走
        ``_settle_branch_terminal``（计数/gap/登记一次完成，不重复注入）。"""
        with self._win_lock:
            entry = self._open_windows.get(window_key)
            if entry is None or entry["done"]:
                return
            entry["done"] = True
            pending = [key for key, state in entry["branches"].items()
                       if state == "pending"]
            camera = entry["camera"]
            handle = entry["handle"]
        for branch_key in pending:
            self._settle_branch_terminal(
                camera, window_key, branch_key, "expired",
                detail="window_ttl_exceeded", settle_window=False)
        purged = []
        with self._l3_lock:
            for cam, queue in self._l3_queues.items():
                kept = deque()
                for item in queue:
                    if item[1]["window_key"] == window_key:
                        purged.append((cam, item))
                    else:
                        kept.append(item)
                self._l3_queues[cam] = kept
            self._l3_dropped += len(purged)
        for cam, _item in purged:
            self._count(cam, "l3_dropped")
        try:
            handle.release()
        except Exception:
            pass
        try:
            handle.mark_window_settled()
        except Exception:
            pass
        with self._win_lock:
            self._open_windows.pop(window_key, None)
            adm = self._admitted_windows.pop(window_key, None)
        self._cleanup_l4(window_key)
        self._count(camera, "windows_settled")
        self._rollback_admission_if_unfulfilled(camera, adm)

    def _drain_queue_on_stop(self):
        """停机：队列中全部任务按 stop_cancelled 结算（分支已终态者跳过）。

        锁序（C-139 §2 A1，与入队一致：先 _l3_lock 后 _win_lock）：持
        _l3_lock 只做弹队（内存操作不等待），结算在锁外经唯一终态提交点
        完成（其内取 _win_lock，方向单向不反序）。"""
        with self._l3_lock:
            remaining = []
            for queue in self._l3_queues.values():
                while queue:
                    remaining.append(queue.popleft())
        for task, context in remaining:
            self._settle_branch_terminal(
                context["camera"], context["window_key"],
                context["branch_key"], "stop_cancelled",
                detail="stop_drain")

    def _close_all_windows_on_stop(self):
        """停机：在开窗口剩余 pending 分支经唯一终态提交点按 stop_cancelled
        收口并清理（锁内只做终态快照与 done 置位，结算/释放/清理在锁外）。"""
        with self._win_lock:
            keys = [key for key, entry in self._open_windows.items()
                    if not entry["done"]]
        for window_key in keys:
            with self._win_lock:
                entry = self._open_windows.get(window_key)
                if entry is None or entry["done"]:
                    continue
                entry["done"] = True
                pending = [key for key, state
                           in entry["branches"].items()
                           if state == "pending"]
                camera = entry["camera"]
                handle = entry["handle"]
            for branch_key in pending:
                self._settle_branch_terminal(
                    camera, window_key, branch_key, "stop_cancelled",
                    detail="stop_close", settle_window=False)
            try:
                handle.release()
            except Exception:
                pass
            try:
                handle.mark_window_settled()
            except Exception:
                pass
            with self._win_lock:
                self._open_windows.pop(window_key, None)
                adm = self._admitted_windows.pop(window_key, None)
            self._cleanup_l4(window_key)
            self._count(camera, "windows_settled")
            self._rollback_admission_if_unfulfilled(camera, adm)

    # ---- 主循环（窗口调度消费） ---------------------------------------------

    def _harvest_identity_ok(self, camera, run_id, config_version):
        """取包点观察的身份围栏（**不改变既有注册表语义**）。

        - 相机**已登记**身份：要求包的 (run, config) 与之**全等**——不同
          run/config 的包绝不借用（陈旧身份的包在既有路径里同样被
          `identity_rejected` 丢弃，这里只是把丢弃**提前到释放之前**，
          材料一旦 release 就再也无法形成任何绑定）；
        - 相机**尚未登记**（捕获线程还没推进过注册表）：不拒绝。池的事件键
          以包自带身份三元为第一段，跨身份在结构上不可能借到帧
          （`test_cross_run_and_cross_config_never_share_material`），因此
          "未登记"不等于"身份可疑"，不得当成拒绝理由而白白丢掉材料。
        """
        with self._lock:
            expected = self._registry.get(camera)
        if expected is None or expected == (None, None):
            return True
        return expected == (run_id, config_version)

    def _run(self):
        while not self._stop.is_set():
            if self._stop.wait(self.poll_interval_s):
                return
            if not self.camera_ids:
                continue
            self._sweep_open_windows()
            # C154 Q F1：先排空取包点移交（两把锁之外完成像素复制/绑定查询）。
            # 安静期同样排空——否则移交会一直等到下一次开窗才被处理。
            try:
                self._pump_harvest_handoff()
            except Exception as exc:
                print(f"[NVR] L2 取包点观察移交异常: {type(exc).__name__}",
                      flush=True)
            try:
                handle = self.scheduler.acquire()
            except Exception as exc:
                print(f"[NVR] L2 窗口调度异常: {type(exc).__name__}",
                      flush=True)
                self._stop.wait(self.poll_interval_s)
                continue
            if handle is None:
                continue
            # acquire 期间新摘的包可能刚被折叠：立刻再排空一次，保证在
            # `_process_handle` 之前完成观察（顺序确定，不靠等时间）。
            try:
                self._pump_harvest_handoff()
            except Exception as exc:
                print(f"[NVR] L2 取包点观察移交异常: {type(exc).__name__}",
                      flush=True)
            self._process_handle(handle)

    def _det_status_of(self, pkg):
        """C-144-R2 冻结 §1.1：由真实 L1 结果推导检测状态三态。

        - l1_status=="ok" 且有有效检测框 → detected；
        - l1_status=="ok" 无框或 =="empty"（推理成功零对象）→
          confirmed_empty；
        - 其余（infer_failed/timeout/model_unavailable/缺失）→
          unavailable（失败/超时≠离开）。"""
        status = getattr(pkg, "l1_status", None)
        if getattr(pkg, "l1_terminal_reason", None) not in (None, "empty"):
            return "unavailable"
        if status == "ok":
            detections = list(getattr(pkg, "detections", None) or ())
            if admission_det_signature(detections) is not None:
                return "detected"
            if detections:
                return "unavailable"  # Malformed observations are not valid empty.
            return "confirmed_empty"
        if status == "empty":
            return "confirmed_empty"
        return "unavailable"

    def _admit_window(self, camera, handle, window_key):
        """C-144-R2：整窗有界深度准入（冻结 §2.1）。

        按时间序遍历窗口内**全部**材料包（先剔除过期与身份不符），逐包
        调用 decide（场景参考链式推进）；**任一有效包 moved ⇒ 整窗准
        入**（首包静止、后包移动的漏触发在此关闭）；全部抑制 ⇒ 整窗抑制。
        无有效信息的材料（无变化框且 L1 不可用）结构上不可能触发 admit，
        但照常推进状态（失败/超时重置离开计数）。

        抑制窗口由调用方照常完成材料释放/封口；fallback 同受此约束。
        返回 True=准许执行 L2/L3；False=抑制。"""
        ref = self._last_admission.get(camera)
        prev_ref = ref
        now_s = self._mono() if callable(self._mono) else None
        admitted = False
        first_admit = None
        last_decision = None
        base_ident = None
        for pkg in handle.packages:
            # 剔除：过期材料不参与准入（处理阶段照常计 expired）
            if (self._mono_ms() - pkg.created_mono_ms
                    > self.max_age_s * 1000.0):
                self._count(camera, "admission_skipped_expired")
                continue
            ident = (getattr(pkg, "run_id", None),
                     getattr(pkg, "config_version", None))
            if not self._package_identity_ok(camera, pkg, window_key):
                self._count(camera, "admission_skipped_identity_mismatch")
                continue
            if base_ident is None:
                base_ident = ident
            elif ident != base_ident:
                self._count(camera, "admission_skipped_identity_mismatch")
                continue
            decision, reason_code, new_ref = admission_decide(
                material_reason=getattr(pkg, "material_reason", None),
                change_boxes=list(getattr(pkg, "change_boxes", None) or ()),
                gate_w=getattr(pkg, "gate_w", None),
                gate_h=getattr(pkg, "gate_h", None),
                identity={"camera_id": camera, "run_id": ident[0],
                          "config_version": ident[1]},
                scene_ref=ref,
                now_s=now_s,
                det_status=self._det_status_of(pkg),
                detections=list(getattr(pkg, "detections", None) or ()))
            ref = new_ref
            last_decision = decision
            if (decision in ("admit_initial", "admit_change",
                             "admit_recovery") and not admitted):
                admitted = True
                first_admit = decision
        self._last_admission[camera] = ref
        if admitted:
            # 任务接纳状态登记（真实生命周期：入队更新、结算移除；
            # prev_ref 留作拒收/过期后的有界回滚基准）
            self._admitted_windows[window_key] = {
                "camera": camera,
                "identity": {"camera_id": camera, "run_id": base_ident[0],
                             "config_version": base_ident[1]},
                "admitted_mono_s": now_s,
                "prev_ref": prev_ref,
                "new_ref": ref,
                "retry_count": (prev_ref or {}).get(
                    "retry_count", 0) if isinstance(prev_ref, dict) else 0,
                "attempted": False, "enqueued_ok": False,
                "enqueued_tasks": 0}
            while len(self._admitted_windows) > self._ADMITTED_WINDOWS_CAP:
                self._admitted_windows.popitem(last=False)
            key = ("admission_admitted_initial"
                   if first_admit == "admit_initial"
                   else "admission_admitted_recovery"
                   if first_admit == "admit_recovery"
                   else "admission_admitted_change")
            self._count(camera, key)
            self._trace_emit("window_admitted", camera=camera,
                             window_key=list(window_key),
                             run_id=base_ident[0],
                             config_version=base_ident[1],
                             materials=len(handle.packages),
                             first_decision=first_admit)
        elif last_decision is not None:
            # 窗口级抑制计一次；suppress_duplicate（重复抑制）单列
            self._count(camera,
                        "admission_suppressed_duplicate"
                        if last_decision == "suppress_duplicate"
                        else "admission_suppressed_no_new_info")
            self._trace_emit("window_suppressed", camera=camera,
                             window_key=list(window_key),
                             run_id=(base_ident or (None, None))[0],
                             config_version=(base_ident or (None, None))[1],
                             reason=last_decision)
        return admitted

    def _package_identity_ok(self, camera, pkg, window_key):
        return (getattr(pkg, "camera_id", camera) == camera
                and (pkg.run_id, pkg.config_version) == tuple(window_key[1:3])
                and self._identity_ok(camera, pkg.run_id, pkg.config_version))

    def _process_handle(self, handle):
        """处理一个窗口任务组：登记→准入→逐包处理（闸门/兜底）→封口。"""
        window_key = self._register_window(handle)
        if window_key is None:
            return
        cam = handle.camera_id
        try:
            # C-144-R1/R2：窗口级深度准入——在 stage.process 之前，对
            # 整窗全部有效材料有界扫描判一次（首包静止、后包移动的漏
            # 触发在此关闭）。抑制时跳过全部 L2/L3（材料照常在 finally
            # 释放、窗口照常封口——诚实收口，无空事件/悬挂 pending）。
            admitted = self._admit_window(cam, handle, window_key)
            for pkg in handle.packages:
                if self._stop.is_set():
                    break
                try:
                    # M3：过期以包创建单调钟判断（不刷新续命）
                    if (self._mono_ms() - pkg.created_mono_ms
                            > self.max_age_s * 1000.0):
                        self._count(cam, "expired")
                        continue
                    if not self._package_identity_ok(cam, pkg, window_key):
                        self._count(cam, "identity_rejected")
                        continue
                    # C154 G：选材点**先**把本包材料并入同事件有界池
                    # （只读事实绑定；无绑定即不聚合并记原因）。写在 L2 之前，
                    # 保证**每个**进入理解阶段的窗口都留下开始/最新材料，
                    # 且只使用当帧已成立的事实（不倒用未来结果）。
                    # C154 Q F1：同一材料在取包点（折叠/丢弃/取消/关闭之前）
                    # 已被观察过时**不重复观察**（恰一次；见
                    # `_pump_harvest_handoff` 与 `_harvest_obs_key`）。
                    obs_key = self._harvest_obs_key(cam, pkg)
                    if obs_key is not None:
                        self._mark_observed(obs_key)
                    self._observe_event_materials(cam, pkg, window_key)
                    if pkg.l1_terminal_reason is None:
                        if not admitted:
                            # 抑制：不执行 L2 关系推理、不建 L3 任务
                            continue
                        output = self.stage.process(
                            self._build_task(pkg))
                        self._record(cam, output=output)
                        self._maybe_enqueue_l3(cam, pkg, output,
                                               window_key=window_key)
                    else:
                        # M2 闸门：关系模型调用次数=0；全景补充理解任务
                        # 照常（统一转换携带真实原因），不冒充 no_objects。
                        # C-144-R1：fallback 同受窗口准入约束——无变化且
                        # 无对象的静止窗口不得经 fallback 持续重理解。
                        if not admitted:
                            self._count(cam, "l2_suppressed_fallback")
                            continue
                        self._record(cam, fallback=pkg.l1_terminal_reason)
                        self._enqueue_l3_fallback(cam, pkg,
                                                  window_key=window_key)
                except Exception as exc:
                    # M1：单包异常结构化记录后继续服务后续包
                    print(f"[NVR] L2 处理异常（{cam}）:", flush=True)
                    traceback.print_exc()
                    self._record(cam, error=exc)
        finally:
            # 材料租约立即归还；随后封口（C-138：L2 完成≠窗口完成）
            try:
                handle.release()
            except Exception as exc:
                print(f"[NVR] L2 窗口释放异常（{cam}）: "
                      f"{type(exc).__name__}", flush=True)
            self._seal_window(window_key)

    # ---- C154 车道 G：同事件跨窗选材（观察 → 有界池 → 任务帧序） ------------

    def _attach_harvest_observer(self):
        """把取包点观察回调挂到调度器（**只在调度器未挂过任何回调时**）。

        兼容旧调度器/测试替身：没有该注入位（或已有属主）时**不动**它，也
        不报错——旧调用方继续按原语义工作（本车道不改别人的接线）。
        """
        if not hasattr(self.scheduler, "on_packages_released"):
            return False
        if getattr(self.scheduler, "on_packages_released", None) is not None:
            return False
        self.scheduler.on_packages_released = self._on_packages_released
        return True

    def _observe_event_materials(self, camera, pkg, window_key):
        """选材点观察：把本包（prev/cur/nxt）并入同事件有界池。

        只用选材点**已成立**的事实（身份四元/材料触发原因/门控变化框/事实链
        里已落库的对象-事件绑定）；无唯一绑定时池不聚合，并把受控原因记入
        `event_materials.snapshot()["refusals"]`（继续旧窗口路径，不猜事件）。
        任何异常吞并计数，绝不阻塞既有 L2/L3 路径。
        """
        if self.event_materials is None:
            return None
        # 无材料包 = 零行为（保持既有"包缺席即 no-op"语义，不生成空拒绝记录）
        if pkg is None:
            return None
        try:
            from .win11_event_materials import observe_window_materials
            record = observe_window_materials(
                self.event_materials, pkg=pkg, window_key=window_key,
                camera=camera)
        except Exception:
            self._count(camera, "event_materials_observe_failed")
            return None
        if record is None:
            return None
        if record.get("status") == "aggregated_allowed":
            self._count(camera, "event_materials_bound")
        else:
            self._count(camera, "event_materials_window_only")
        return record

    def _observe_harvested_materials(self, camera, pkg, *, harvest_id):
        """C154 车道 Q F1：取包点观察（窗口尚未分配，`window_key=None`）。

        与窗口内观察共用同一个池与同一套绑定守卫；区别只有两点：窗口槽位
        如实写 `None`（不借用别的窗口身份），并带 `harvest_id` 说明来源。
        """
        record = None
        failure = None
        try:
            from .win11_event_materials import observe_window_materials
            record = observe_window_materials(
                self.event_materials, pkg=pkg, window_key=None,
                camera=camera, harvest_id=harvest_id)
        except Exception as exc:                 # 观察失败不得影响既有路径
            failure = type(exc).__name__
        if failure is None and record is not None:
            reason = str(record.get("reason") or "")
            if reason.startswith("observe_failed:"):
                # 池侧已按受控原因吞并（选材不得影响既有路径）——这里如实
                # 折算成"观察失败"，不冒充成功观察。
                failure = reason.split(":", 1)[1] or "observe_failed"
        if failure is not None:
            with self._harvest_lock:
                self._harvest_counts["handoff_observe_failed"] += 1
                self._harvest_failures[failure] = (
                    self._harvest_failures.get(failure, 0) + 1)
            self._count(camera, "event_materials_observe_failed")
            return None
        if record is None:
            with self._harvest_lock:
                self._harvest_counts["handoff_observe_failed"] += 1
                self._harvest_failures["no_record"] = (
                    self._harvest_failures.get("no_record", 0) + 1)
            self._count(camera, "event_materials_observe_failed")
            return None
        if record.get("status") == "aggregated_allowed":
            self._count(camera, "event_materials_bound")
            self._count(camera, "event_materials_harvest_bound")
        else:
            self._count(camera, "event_materials_window_only")
            self._count(camera, "event_materials_harvest_window_only")
        return record

    # ---- C154 车道 U F1：队列**外部引用**账目（第三本账） -------------------

    def _harvest_ref_dead(self, key):
        """弱引用回调：记录"该底层缓冲**真被回收**"（有界）。

        纪律与 `win11_materials` 的 finalize 入队一致：**不取任何锁、不改任何
        账目、不做 I/O**——回调可能在持锁路径内被 GC 触发，取锁即自锁死。
        这里只往一个普通 dict 写一个键；"账目归零"与"对象真被回收"因此是两条
        **互相独立**的证据（前者由 `_harvest_ref_release_*` 给出，后者由本
        回调给出）。
        """
        try:
            self._harvest_ref_reclaimed[key] = True
        except Exception:                         # 解释器收尾期：绝不外抛
            pass

    def _harvest_buffers_of(self, pkg):
        """列出一个包的像素缓冲 **唯一键**（**锁外**调用；不复制、不扫描像素）。

        只读 `frame_bgr` 的对象身份（`id()`）与 `nbytes` 属性；numpy 视图由
        `base` 折叠到底层数组，因此"同一块内存的多个视图"与"同一个数组对象被
        多个包引用"都会收敛到同一个键——去重的根据是**对象身份**，不是"包的
        平均大小"估算。返回 `[(key, nbytes, array), ...]`，`array` 仅供锁外
        建弱引用用，调用方**不得**把它存进任何账本（账本只存弱引用）。
        """
        items = []
        seen = set()
        for frame in (getattr(pkg, "prev", None), getattr(pkg, "cur", None),
                      getattr(pkg, "nxt", None)):
            if frame is None:
                continue
            buf = getattr(frame, "frame_bgr", None)
            if buf is None:
                continue
            base = getattr(buf, "base", None)
            owner = buf if base is None else base
            key = id(owner)
            if key in seen:
                continue
            seen.add(key)
            try:
                nbytes = int(buf.nbytes)
            except Exception:                     # 形态异常：不猜字节，不建账
                continue
            if nbytes <= 0:
                continue
            items.append((key, nbytes, buf))
        return items

    def _harvest_ref_charge(self, items, *, pkg=None):
        """入队登记的统一入口（**锁外**建弱引用，锁内登记）。

        生产路径（调度器回调）用 `_harvest_ref_prepare` + `_harvest_ref_charge_locked`
        在同一次临界区内完成"入队 + 登记"；本方法是给**其他调用点/测试**用的
        便捷封装，语义与之一致（绝不重复计费同一条目）。
        """
        prepared = self._harvest_ref_prepare(items)
        if prepared is None:
            return pkg
        with self._harvest_lock:
            self._harvest_queue_depth += 1
            if self._harvest_queue_depth > self._harvest_queue_depth_peak:
                self._harvest_queue_depth_peak = self._harvest_queue_depth
            self._harvest_ref_charge_locked(prepared, pkg=pkg)
        return pkg

    def _harvest_external_items_added(self, entry, refs):
        """把本条目的缓冲字节并进账目（**调用方持锁**；只在首见时加字节）。

        `entry` 形如 `[bytes, refs, billed]`，`billed` 是本条目已计费的独立
        缓冲键集合——"首见"即"该缓冲此前未被本条目计费过"。同一缓冲在**同一
        条目**内重复出现只加一次字节；跨条目共享由 `entry[1]`（引用计数）表达，
        最后一个引用归还时账目才归零——因此"同一缓冲被多个包引用只计一次"
        在账目上同时有**去重键**与**引用计数**两条证据。
        """
        billed = entry[2]
        for key, nbytes, _ref in refs:
            if key in billed:
                continue
            billed.add(key)
            entry[0] += int(nbytes)
            self._harvest_external_bytes += int(nbytes)
            self._harvest_external_buffers += 1

    def _harvest_ref_release(self, items, *, kind="observed",
                             observe_failed=0, known=True):
        """按包内缓冲归还外部引用（便捷封装；生产路径用 `_harvest_ref_release_pkg`）。

        - 未在账且 `known=True` → 记 `missing` 并计数，绝不凭空减记；
        - 引用计数递减到 0 才真正从账目移除并减字节——因此"同一缓冲被多个
          包引用"在最后一个包释放时才归零（引用计数证据）。
        """
        return self._harvest_ref_release_billed(
            {buf_key for buf_key, _n, _b in items}, kind=kind,
            observe_failed=observe_failed, known=known)

    def _harvest_external_stats(self):
        """队列外部引用账目（有界只读快照；**独立于池与租约口径**）。"""
        with self._harvest_lock:
            return {
                "queue_capacity": self._harvest_capacity,
                "queue_depth": self._harvest_queue_depth,
                "queue_depth_peak": self._harvest_queue_depth_peak,
                "external_buffers": self._harvest_external_buffers,
                "external_bytes": self._harvest_external_bytes,
                "external_buffers_peak": self._harvest_external_buffers_peak,
                "external_bytes_peak": self._harvest_external_bytes_peak,
                "ledger_entries": len(self._harvest_ref_ledger),
                "ledger_refs": sum(entry[1]
                                   for entry in self._harvest_ref_ledger.values()),
                "cache_entries": len(self._harvest_ref_cache),
                "cache_cap": _HARVEST_REF_CACHE_CAP,
                "released": dict(self._harvest_refs_released),
                "account": "queue_external_reference",
            }

    def _harvest_external_probe(self):
        """**诊断路径**（显式调用，不在锁内）：逐条目的身份 + 存活证据。

        返回当前在账条目：`buffers`（独立缓冲数）、`bytes`、`refs`（引用计数）、
        `alive_buffers` / `dead_buffers`（弱引用证据：仍活着 / **已被回收**）、
        `reclaimed`（该条目内已由回调确认回收的缓冲数）。`dead_buffers > 0`
        而账目仍计费 = **异常信号**（账实不符），如实暴露、不隐藏。
        本方法在锁内只读整数、集合与弱引用对象，**不触碰像素数据**（不读
        `frame_bgr`、不调 `nbytes`），因此锁持有时间与像素量无关。
        """
        with self._harvest_lock:
            rows = []
            for entry_key, entry in self._harvest_ref_ledger.items():
                alive = dead = 0
                for buf_key in sorted(entry[2]):
                    cached = self._harvest_ref_cache.get(buf_key)
                    ref = cached[1] if cached else None
                    if ref is None:
                        continue                  # 无证据：不计入死活（不冒充）
                    if ref() is None:
                        dead += 1
                    else:
                        alive += 1
                rows.append({
                    "buffers": len(entry[2]),
                    "bytes": entry[0],
                    "refs": entry[1],
                    "alive_buffers": alive,
                    "dead_buffers": dead,
                    "reclaimed": sum(1 for buf_key in entry[2]
                                     if buf_key in self._harvest_ref_reclaimed),
                    "entry_key_len": len(entry_key),
                })
            return {
                "entries": rows,
                "external_bytes": self._harvest_external_bytes,
                "external_buffers": self._harvest_external_buffers,
                "reclaimed_keys": len(self._harvest_ref_reclaimed),
                "reclaimed_cap": _HARVEST_REF_CACHE_CAP,
                "cache_cap": _HARVEST_REF_CACHE_CAP,
            }

    # ---- C154 车道 Q F1：取包点观察的最小有界移交 ---------------------------

    def _harvest_obs_key(self, camera, pkg):
        """材料观察幂等键（同一材料任何路径只观察一次）。

        生产材料包 `material_id` 由材料仓单调分配且全局唯一；缺该字段时
        退化为 `frame_id`（同一源帧在 prev/cur/nxt 里可能重复出现，因此
        仅作兜底）。两者都缺 → None（不做幂等判定，由池自身逐帧去重兜底）。
        """
        material_id = getattr(pkg, "material_id", None)
        if material_id is None:
            cur = getattr(pkg, "cur", None)
            material_id = getattr(cur, "frame_id", None)
        if material_id is None:
            return None
        return (camera, getattr(pkg, "run_id", None),
                getattr(pkg, "config_version", None), str(material_id))

    def _on_packages_released(self, packages):
        """调度器回调：**在 `store.release()` 之前、调度器锁内**被调用。

        本方法只做 O(1) 的事：关闭检查、有界队列的入队、**外部引用登记**与
        计数。**不复制像素、不查库、不调模型、不做磁盘 I/O、不等待**——因此
        不阻塞生产者与相机，也不把调度锁的持有时间拉长到与像素量相关。观察
        本身由 L2 消费线程在 `_pump_harvest_handoff()` 里于两把锁之外完成
        （此时材料仍由本次移交的引用保活，且尚未被判定为失效）。

        C154 车道 U：本方法登记"队列**确实**持有了这些独立像素缓冲"这一
        事实（第三本账）。登记只发生在**真正入队之后**：队列满被拒的包
        **绝不新增外部引用**（否则账目会凭空变大）。缓冲键是 `id()` 身份、
        字节是 `nbytes` 属性——两者都只读属性、不触碰像素内容。
        """
        entries = []
        for pkg in tuple(packages or ()):
            if self._stop.is_set():
                break
            # 已进入理解阶段的既有路径（`_process_handle`）会自行观察；这里
            # 只挑"没有 L1 终态原因"的包（= 该帧有真实对象结论的候选）——
            # 兜底/超时造成的空结论材料即使被看到也无法形成绑定，白花复制。
            if getattr(pkg, "l1_terminal_reason", None) is not None:
                continue
            entries.append(pkg)
        if not entries:
            return
        # 锁外只读属性（对象身份 + nbytes）并预建弱引用；锁内只做整数加减与
        # 入队。预建弱引用放在锁外，是为了让"锁内不触碰像素对象"这条纪律
        # 在代码上直接可见。
        prepared = {}
        for pkg in entries:
            prepared[id(pkg)] = self._harvest_ref_prepare(
                self._harvest_buffers_of(pkg))
        overflow = 0
        seen = set()
        with self._harvest_lock:
            if self._stop.is_set():
                return
            for pkg in entries:
                if id(pkg) in seen:
                    # 同一次通知里重复出现**同一个包对象**：按对象身份只登记
                    # 一个条目、一次引用——不重复计费，也不制造"一个包两个
                    # 引用计数"的错配。
                    continue
                if self._harvest_queue_depth >= self._harvest_capacity:
                    # 深度以**纯整数计数器**判定（锁内不取容器长度、不扫描
                    # 容器）——本计数器的加一与出队减一分别与入队、归还严格
                    # 配对，故与"在队条目数"恒等（含 `cur=None` 这类无缓冲包：
                    # 它们照样占一个队列槽位）。
                    overflow += 1                   # 拒绝：不登记外部引用
                    continue
                seen.add(id(pkg))
                self._harvest_queue.append(pkg)
                self._harvest_queue_depth += 1
                self._harvest_ref_charge_locked(prepared.get(id(pkg)), pkg=pkg)
            if self._harvest_queue_depth > self._harvest_queue_depth_peak:
                self._harvest_queue_depth_peak = self._harvest_queue_depth
            self._harvest_counts["handoff_enqueued"] += len(entries) - overflow
            if overflow:
                # 队列满：**明确拒绝并计数**（无界积压被禁止）；被拒材料
                # 仍在调度器手里按既有语义 release，路径与旧行为一致。
                self._harvest_counts["handoff_rejected_full"] += overflow
                self._harvest_refs_released["full"] += overflow

    def _harvest_ref_prepare(self, items):
        """**锁外**把 `(key, nbytes, array)` 备成 `(dedup_key, refs)`。

        弱引用对象在这里创建（`weakref.ref` 只读对象身份，不触碰像素内容）；
        账本只保存弱引用，故账目**不会**延长任何像素缓冲的存活。
        """
        if not items:
            return None
        refs = []
        for key, nbytes, buf in items:
            try:
                ref = weakref.ref(buf, self._harvest_ref_dead)
            except TypeError:                     # 不支持弱引用的缓冲类型
                ref = None
            refs.append((key, int(nbytes), ref))
        return (tuple(sorted(key for key, _n, _r in refs)), refs)

    def _harvest_ref_charge_locked(self, prepared, *, pkg=None):
        """入队段的**持锁**登记（调用方已持 `_harvest_lock`）。

        与 `_harvest_ref_charge` 的差别只有弱引用的构建位置：这里直接消费
        `_harvest_ref_prepare` 在锁外备好的 `(dedup_key, refs)`，锁内只做
        整数加减、集合成员判定与字典写入——绝不触碰像素数据、不做 I/O。
        传入 `pkg` 时同时登记入队凭据（`id(pkg)` → 已计费缓冲集合）。
        """
        if not prepared:
            return
        dedup_key, refs = prepared
        entry = self._harvest_ref_ledger.get(dedup_key)
        if entry is None:
            entry = [0, 0, set()]
            self._harvest_ref_ledger[dedup_key] = entry
        entry[1] += 1                              # 条目引用计数 +1
        self._harvest_external_items_added(entry, refs)
        if pkg is not None:
            key = id(pkg)
            self._harvest_ref_by_pkg[key] = frozenset(
                buf_key for buf_key, _n, _r in refs)
            self._harvest_ref_enqueued[key] = True
            cap = _HARVEST_REF_CACHE_CAP
            while len(self._harvest_ref_by_pkg) > cap:
                self._harvest_ref_by_pkg.popitem(last=False)
            while len(self._harvest_ref_enqueued) > cap:
                self._harvest_ref_enqueued.popitem(last=False)
        if self._harvest_external_bytes > self._harvest_external_bytes_peak:
            self._harvest_external_bytes_peak = self._harvest_external_bytes
        if (self._harvest_external_buffers
                > self._harvest_external_buffers_peak):
            self._harvest_external_buffers_peak = \
                self._harvest_external_buffers
        for key, nbytes, ref in refs:
            if ref is not None:
                self._harvest_ref_cache[key] = (nbytes, ref)
        while len(self._harvest_ref_cache) > _HARVEST_REF_CACHE_CAP:
            oldest = next(iter(self._harvest_ref_cache))
            if oldest in self._harvest_ref_ledger:
                break                             # 绝不逐出仍在计费的键
            self._harvest_ref_cache.popitem(last=False)

    def _harvest_ref_release_pkg(self, pkg, *, kind="observed",
                                 observe_failed=0):
        """凭**账目**归还一个出队条目的外部引用（不重新读包）。

        凭据来源优先级：
        1. `_harvest_ref_by_pkg`（入队时登记的 `id(pkg)` → 已计费缓冲集合）
           ——权威；即便包出队后被改写（`frame_bgr` 置 None 等）也照样精确
           归零；
        2. 包当前形态（`_harvest_buffers_of`）——仅当入队凭据已被有界缓存
           逐出时兜底。

        两者都取不到且该包**确实入过队**时记 `missing`（账实不符，如实暴露）；
        从未登记的包（无缓冲 / 未入队）不计 `missing`。
        """
        key = id(pkg)
        with self._harvest_lock:
            billed = self._harvest_ref_by_pkg.get(key)
            enqueued = key in self._harvest_ref_enqueued
        if billed is None:
            items = self._harvest_buffers_of(pkg)
            billed = {buf_key for buf_key, _n, _b in items}
        if not billed:
            return None
        return self._harvest_ref_release_billed(
            billed, kind=kind, observe_failed=observe_failed,
            known=enqueued, pkg_key=key)

    def _harvest_ref_release_billed(self, billed, *, kind="observed",
                                    observe_failed=0, known=True,
                                    pkg_key=None):
        """按"已计费独立缓冲集合"归还（**引用计数归零才减字节**）。

        `pkg_key` 给出时，条目真正归零后一并清掉该包的入队凭据——缩小
        `id(pkg)` 被后续对象复用的窗口（残留凭据只会让归一化路径多发一次
        no-op，不会凭空减记，但清掉更干净）。
        """
        dedup_key = tuple(sorted(billed))
        with self._harvest_lock:
            entry = self._harvest_ref_ledger.get(dedup_key)
            if entry is None:
                if known:
                    self._harvest_refs_released["missing"] += 1
                if pkg_key is not None:
                    self._harvest_ref_by_pkg.pop(pkg_key, None)
                return None
            entry[1] -= 1
            if entry[1] > 0:
                # 同一缓冲仍被别的条目引用：不归零、不减字节（只计一次）
                return None
            del self._harvest_ref_ledger[dedup_key]
            buffers = len(entry[2])
            self._harvest_external_bytes -= entry[0]
            self._harvest_external_buffers -= buffers
            if pkg_key is not None:
                self._harvest_ref_by_pkg.pop(pkg_key, None)
            stats = self._harvest_refs_released
            stats["items"] += 1
            stats["buffers"] += buffers
            stats["bytes"] += entry[0]
            stats[kind] = stats.get(kind, 0) + 1
            if observe_failed:
                stats["failed"] += int(observe_failed)
            if self._harvest_external_bytes < 0:   # 账实不符：如实暴露
                stats["negative_bytes"] = stats.get("negative_bytes", 0) + 1
            return {
                "external_bytes": self._harvest_external_bytes,
                "external_buffers": self._harvest_external_buffers,
            }

    def _harvest_handoff_stats(self):
        """取包点移交的**有界**账目（只读；容量 + 深度 + 计数 + 失败原因
        + **队列外部引用账目**，后者见 `_harvest_external_stats`）。"""
        with self._harvest_lock:
            return {
                "capacity": self._harvest_capacity,
                "queued": len(self._harvest_queue),
                "counts": dict(self._harvest_counts),
                "failures": dict(self._harvest_failures),
                "observed_keys": len(self._harvest_observed),
                "observed_keys_cap": self._harvest_observed_cap,
            }

    def harvest_handoff_records(self, limit=16):
        """最近若干次取包点观察的逐材料去向（有界；窗口槽位如实 None）。

        每条给出：`material_id` / `frame_id` / `window_slot`（恒 None=窗口
        未分配）/ `harvest_id` / 池返回的 `status` 与 `reason` / 保留与拒绝
        计数。这是"原先被折叠的材料去了哪里"的逐条依据。
        """
        with self._harvest_lock:
            rows = [dict(row) for row in self._harvest_records]
        if limit is None:
            return rows
        return rows[-int(limit):]

    def _pump_harvest_handoff(self):
        """L2 消费线程在两把锁**之外**排空取包点移交并完成观察。

        - 只观察尚未关闭、身份仍匹配的包；身份不符**明确拒绝并计数**；
        - 每包恰一次（幂等键见 `_harvest_obs_key`）；
        - 观察失败只计数（计数在池/运行时两侧分别可查），不抛、不阻塞；
        - 队列本身有界（容量固定），满时由 `_on_packages_released` 显式拒绝。

        C154 车道 U：本方法同时是**外部引用归还**的唯一出口——批内每个包在
        离开作用域前都经由对应的 `kind` 归还一次外部引用（观察成功 / 身份
        拒绝 / 幂等命中 / 停机丢弃 / 观察失败）。因此"排空后账目归零"与
        "引用真被丢弃"是同一条路径的两面，不靠 `handoff_depth=0` 推断。

        **归还不读包**：入队时已把"该包登记了哪些独立缓冲"记进账目
        （`_harvest_ref_by_pkg`），归还按该记录结算。因此即便包在出队后被
        改写（例如把 `frame_bgr` 置 None）或事件页已被淘汰，账目仍能精确
        归零——账目是权威，不依赖"出队时还能从包里重新读到什么"。
        """
        if self.event_materials is None:
            return 0
        with self._harvest_lock:
            if not self._harvest_queue:
                return 0
            batch = list(self._harvest_queue)
            self._harvest_queue.clear()
            self._harvest_queue_depth = 0
        observed = 0
        for pkg in batch:
            camera = getattr(pkg, "camera_id", None)
            run_id = getattr(pkg, "run_id", None)
            config_version = getattr(pkg, "config_version", None)
            kind = "observed"
            if self._stop.is_set():
                with self._harvest_lock:
                    self._harvest_counts["handoff_dropped_stopped"] += 1
                kind = "skipped_stop"
            elif not self._harvest_identity_ok(camera, run_id, config_version):
                # 跨 run/config：身份围栏**先**拒绝（不借材料、不观察）
                with self._harvest_lock:
                    self._harvest_counts["handoff_identity_rejected"] += 1
                if camera is not None:
                    self._count(camera, "event_materials_harvest_identity_rejected")
                kind = "identity"
            elif self._is_duplicate_material(camera, pkg):
                with self._harvest_lock:
                    self._harvest_counts["handoff_duplicate_skipped"] += 1
                if camera is not None:
                    self._count(camera, "event_materials_harvest_deduped")
                kind = "duplicate"
            observe_failed = 0
            if kind == "observed":
                record = self._observe_harvested_materials(
                    camera, pkg, harvest_id="harvest_handoff")
                observed += 1
                observe_failed = 0 if record is not None else 1
                cur = getattr(pkg, "cur", None)
                with self._harvest_lock:
                    self._harvest_counts["handoff_observed"] += 1
                    self._harvest_records.append({
                        "material_id": getattr(pkg, "material_id", None),
                        "frame_id": getattr(cur, "frame_id", None),
                        "window_slot": None,
                        "harvest_id": "harvest_handoff",
                        "status": (record or {}).get("status"),
                        "reason": (record or {}).get("reason"),
                        "retained": (record or {}).get("retained"),
                        "refused": (record or {}).get("refused"),
                        "l1_terminal_reason": getattr(pkg,
                                                      "l1_terminal_reason",
                                                      None),
                    })
            # 每个出队条目**恰归还一次**（凭据取自账目，不取自包）
            self._harvest_ref_release_pkg(pkg, kind=kind,
                                          observe_failed=observe_failed)
        return observed

    def _is_duplicate_material(self, camera, pkg):
        """幂等判定（返回 True=此前已观察过该材料，本次跳过观察）。"""
        obs_key = self._harvest_obs_key(camera, pkg)
        if obs_key is None:
            return False
        return bool(self._mark_observed(obs_key))

    def _mark_observed(self, obs_key):
        """登记"该材料已被观察过"（有界 LRU）。返回 True=此前已登记。"""
        with self._harvest_lock:
            if obs_key in self._harvest_observed:
                self._harvest_observed.move_to_end(obs_key)
                return True
            self._harvest_observed[obs_key] = True
            while len(self._harvest_observed) > self._harvest_observed_cap:
                self._harvest_observed.popitem(last=False)
            return False

    def _plan_event_materials(self, camera, pkg, window_key, output=None):
        """有界选材：本窗口任务的帧序（主序位帧 + 同事件保留帧）。

        返回 `FramePlan`（`None`=池关闭）。未聚合时 `status="window_only"`
        且 `reason` 如实——调用方照旧只送本窗口帧（旧路径不变）。
        """
        if self.event_materials is None:
            return None
        try:
            from .win11_event_materials import primary_frame_rows
            # 帧数上限取**共享预算派生档**（C153 账本的窗口档），不是任务档
            # 默认值：选材与任务构造用同一个上限，绝不靠"多送几帧"绕过预算。
            limit = None
            ledger = self.l3_window_budget_ledger
            budget = getattr(ledger, "budget", None)
            if budget is not None:
                limit = max(1, int(getattr(budget, "max_frames_per_task", 3)))
            return self.event_materials.plan_frames(
                window_key=window_key, window_id=window_key[3],
                material_id=getattr(pkg, "material_id", None),
                primary=primary_frame_rows(
                    pkg, window_id=window_key[3],
                    material_id=getattr(pkg, "material_id", None)),
                limit=limit,
                # 来源事实缺省：L1 材料触发原因 + 门控变化框 + 本窗事件键
                primary_reason=getattr(pkg, "material_reason", None),
                primary_change_boxes=getattr(pkg, "change_boxes", None),
                primary_event_id=(self.event_materials.window_event_id(
                    window_key)),
                # P0-3(a) 生产接线：**主序位帧 = 本包 cur 帧**（真实包角色，
                # 不用 latest、不用第一条记录、不用时间近邻或任意邻帧替代）。
                # 缺此参数 ⇒ 逐帧接口 `reason="primary_frame_id_missing"` ⇒
                # 主帧事件键恒为 null ⇒ 事件页不可达（real-p3 实测断点）。
                primary_frame_id=getattr(getattr(pkg, "cur", None),
                                         "frame_id", None))
        except Exception:
            self._count(camera, "event_materials_plan_failed")
            return None

    def _record_material_selection(self, camera, window_key, plan,
                                   selection):
        """留档本窗选材账目（有界）：声明保留 ↔ 实际送入模型的对齐证据。"""
        key = tuple(window_key)
        row = {
            "camera": camera,
            "window_key": list(key),
            "plan": None if plan is None else plan.as_ledger(),
            "selection": None if selection is None else dict(selection),
        }
        with self._plan_lock:
            self._material_selection[key] = row
            while len(self._material_selection) > self._l3_budget_coverage_cap:
                self._material_selection.pop(
                    next(iter(self._material_selection)))

    def _carried_for_task(self, camera, plan):
        """`FramePlan` → **跨窗口**保留帧（本窗口帧不重复送，幂等口径）。

        取 `plan.window_key`（选材时刻的本窗口身份）逐帧比较 `frame.window_key`
        ——绝不依赖调用方传入的行内容，因此"搬运的帧"与"声明保留"始终一致。

        C155-R1 起生产路径改用 `_event_task_frames`（计划帧集同源子集）；
        本方法保留给非 aggregated 口径与既有测试（aggregated 时生产调用方
        不再取 carried，避免二次合并）。
        """
        if plan is None or not plan.aggregated:
            return ()
        carried = []
        for frame in plan.frames:
            if tuple(frame.window_key) != tuple(plan.window_key):
                carried.append(frame)
        return tuple(carried)

    @staticmethod
    def _event_task_frames(plan):
        """C155-R1 修复①②：aggregated 计划 → 事件汇聚任务的**帧源**。

        返回计划帧集整体（已去重、已时序、已限幅）；「只送自身严格绑定帧」
        由任务构造层 `_panorama_frames` 强制（任务层防线，换调用方不失守）。
        非 aggregated → None（旧路径）；空 aggregated → ()（不得回退）。
        """
        if plan is None or not getattr(plan, "aggregated", False):
            return None
        return tuple(plan.frames)

    def last_material_selection(self, window_key):
        """本窗最近一次选材账目（只读拷贝；未登记 → None）。"""
        with self._plan_lock:
            row = self._material_selection.get(tuple(window_key))
            if row is None:
                return None
            return {"camera": row["camera"],
                    "window_key": list(row["window_key"]),
                    "plan": (None if row["plan"] is None
                             else dict(row["plan"])),
                    "selection": (None if row["selection"] is None
                                  else dict(row["selection"]))}

    # ---- L3 任务入队（有效路径 + 兜底路径，统一经 D 的转换） -------------------

    def _fallback_branch_spec(self, pkg):
        """兜底全景分支规格（合成；身份=M1 四元+material_id，与包一致）。"""
        from .win11_l2_contract import FrameIdentity, L3BranchSpec
        cur = pkg.cur
        identity = FrameIdentity(
            camera_id=pkg.camera_id, run_id=pkg.run_id,
            config_version=pkg.config_version, frame_id=cur.frame_id,
            material_id=pkg.material_id, t_capture_ms=cur.t_capture_ms,
            timestamp_kind=cur.timestamp_kind)
        return L3BranchSpec(
            branch_kind="panorama", identity=identity, crop_ref=None,
            cur_present=True, prev_present=pkg.prev is not None,
            next_present=pkg.nxt is not None, cur_gap_ms=0.0,
            prev_gap_ms=None, next_gap_ms=None, cur_detections=(),
            prev_detections=None, next_detections=None, candidates=(),
            crop_id=None, region_only=False, frame_sequence=())

    def _enqueue_l3_fallback(self, camera, pkg, window_key):
        """M2：兜底包的全景 L3 补充任务——统一三序位转换（tasks_from_
        package，gate_reason=真实原因进 prompt；缺帧显式占位；与关系模型
        无关——L3 是独立模型，关系不可用时画面补充理解照常）。"""
        if self.l3_stage is None or window_key is None:
            return
        reason = pkg.l1_terminal_reason or "unknown"
        plans = []
        frame_plan = self._plan_event_materials(camera, pkg, window_key)
        # C155-R1 修复①②：aggregated → 事件任务同源取计划帧集（严格绑定
        # 过滤在任务构造层强制）；非 aggregated → 旧三序位路径不变。
        event_frames = self._event_task_frames(frame_plan)
        carried = (() if event_frames is not None
                   else self._carried_for_task(camera, frame_plan))
        selections = []
        tasks = tasks_from_package(
            pkg=pkg, branches=(self._fallback_branch_spec(pkg),),
            crop_images_by_crop_id={},
            vocabulary_id=self.vocabulary_id, vocabulary=self.vocabulary,
            budget=self.l3_budget, window_id=window_key[3],
            budget_ledger=self.l3_window_budget_ledger, plan_out=plans,
            gate_reason=reason,
            # C154 G → C155-R1：事件任务帧源（计划同源；与 carried 互斥）
            carried_frames=carried,
            plan_frames=event_frames,
            plan_event_key=(None if event_frames is None else frame_plan.event_key),
            carried_limit=(None if frame_plan is None else frame_plan.limit),
            carried_reason=getattr(pkg, "material_reason", None),
            material_selection_out=selections.append)
        if selections:
            self._record_material_selection(camera, window_key, frame_plan,
                                            selections[-1])
        plan = plans[0] if plans else None
        for task, plan_index in self._with_plan_index(tasks, plan):
            self._enqueue_l3_task(camera, pkg, window_key=window_key,
                                  task=task, l1_refs=(), l2_candidates=(),
                                  plan_index=plan_index)
        if plan is not None:
            # **入队之后**才结算计划：kept 任务先认领自己的分支身份，被合并的
            # 重复分支因此如实记为"复用既有任务"，绝不抢走 kept 任务的身份。
            self._settle_l3_plan(camera, window_key, plan)

    @staticmethod
    def _with_plan_index(tasks, plan):
        """任务 ↔ 计划分支下标配对（`plan["kept"]` 与任务同序）。

        无计划（账本关闭）→ 下标恒 None（release 随之成为 no-op，与旧行为
        一致）；有计划 → 逐任务绑定**自己的**下标（task 是 `__slots__` 冻结
        形状，下标只能走出参，绝不靠属性猜）。"""
        if plan is None:
            return [(task, None) for task in tasks]
        kept = list(plan.get("kept") or ())
        pairs = []
        for index, task in enumerate(tasks):
            row = kept[index] if index < len(kept) else None
            pairs.append((task, None if row is None else row.get("index")))
        return pairs

    def _maybe_enqueue_l3(self, camera, pkg, output, window_key):
        """有效结果路径：全景多帧 + 关系裁图分支任务（经 C 的统一转换，
        固定 prev/cur/next 序位、局部=同区域三帧真实切片、逐帧身份绑定）。

        C-141 B1：拿到 crop_images_by_crop_id 与分支规格后，先对局部分支
        的实际裁图序位逐个 submit 裁图证据（增强/编码前，原图 as-is；
        像素在手即提交，不等待 L3），再统一转换入队。

        C-144：深度理解准入（win11_admission.decide）——patrol 且无新
        信息/同签名重复 → 抑制（不建任务，计数如实）；admit_* 才建。
        已接纳任务的后续帧=完成既有分支（update_continued 分开计数）。
        准入状态按相机单槽（last admission），有界零增长。"""
        if self.l3_stage is None or window_key is None:
            return
        if not output.l3_branches:
            return
        # C-144-R1：深度准入已前移至 _process_handle 窗口级
        # （_admit_window，stage.process 之前）——此处不再判别。
        crop_images = output.crop_images or ()
        crop_by_id = {}
        for crop, image in zip(output.crops or (), crop_images):
            crop_by_id[crop.crop_id] = image
        self._submit_crop_evidence(camera, pkg, output, window_key,
                                   crop_by_id)
        self._capture_source_frames(camera, pkg, output, window_key)
        l1_refs = [f"{pkg.camera_id}:{pkg.run_id}:track:{d['trackId']}"
                   for d in (pkg.detections or ())
                   if d.get("trackId") is not None]
        # C154 G → C155-R1 修复①②：有界选材——aggregated 计划帧集**同源**
        # 直达事件任务（只送自身严格绑定帧，过滤在任务构造层强制）；非
        # aggregated → 旧三序位路径不变。任务构造后仍用真实帧序生成对齐
        # 账目（声明保留 ↔ 实际送入模型）。
        frame_plan = self._plan_event_materials(camera, pkg, window_key,
                                                output=output)
        event_frames = self._event_task_frames(frame_plan)
        carried = (() if event_frames is not None
                   else self._carried_for_task(camera, frame_plan))
        selections = []
        plans = []
        tasks = tasks_from_package(
            pkg=pkg, branches=output.l3_branches,
            crop_images_by_crop_id=crop_by_id,
            vocabulary_id=self.vocabulary_id,
            vocabulary=self.vocabulary,
            budget=self.l3_budget, window_id=window_key[3],
            budget_ledger=self.l3_window_budget_ledger, plan_out=plans,
            carried_frames=carried,
            plan_frames=event_frames,
            plan_event_key=(None if event_frames is None else frame_plan.event_key),
            carried_limit=(None if frame_plan is None else frame_plan.limit),
            carried_reason=getattr(pkg, "material_reason", None),
            material_selection_out=selections.append)
        if selections:
            self._record_material_selection(camera, window_key, frame_plan,
                                            selections[-1])
        plan = plans[0] if plans else None
        for task, plan_index in self._with_plan_index(tasks, plan):
            self._enqueue_l3_task(
                camera, pkg, window_key=window_key, task=task,
                l1_refs=l1_refs,
                l2_candidates=list(output.candidates or ()),
                plan_index=plan_index)
        # Rejected inputs never consumed a model/budget allocation. Register
        # and settle each rejected branch once, preserving valid queued work.
        for row in (selections[-1].get("rejected_branches", ()) if selections else ()):
            branch_key = window_key + (row["branch"], row["crop_id"], pkg.material_id)
            if self._register_branch(window_key, branch_key):
                self._settle_branch_terminal(
                    camera, window_key, branch_key, "input_rejected",
                    detail="not_analyzed: " + row["reason"],
                    sources=("local_crop_attribution",))
        if plan is not None:
            # C153-R1 §2：被预算 merged/dropped 的分支 → runtime 终态（未分析/
            # 复用来源如实入账并进 L4 缺失因素），窗口照常封口。
            # 必须在 kept 任务入队**之后**：kept 先认领身份，被合并的重复
            # 分支才如实记为"复用既有任务"，不抢走 kept 的身份。
            self._settle_l3_plan(camera, window_key, plan)

    # ---- C-141 B1：真实裁图提交（crop_worker 依赖注入；纯内存入队） --------

    _SLOT_NAMES = {0: "previous", 1: "current", 2: "next"}

    def _capture_source_frames(self, camera, pkg, output, window_key):
        """C-142：源帧捕获钩子（可选注入；None=零行为、无默认归档）。

        触发点与 _submit_crop_evidence 同点（增强/编码前、原始全帧在手、
        发布锁之外）；绑定推导与逐帧分发委托给捕获器模块的
        ``dispatch_source_frame_capture``（惰性导入——仅显式验收运行
        接线时才触达该模块）；任何异常吞并计数，绝不阻塞快系统/L1。
        """
        if self.source_capture is None:
            return
        try:
            from scripts.win11_source_frame_capture import (
                dispatch_source_frame_capture)
            dispatch_source_frame_capture(
                self.source_capture, pkg, output, window_key)
        except Exception:
            self._count(camera, "source_capture_dropped")

    def _submit_crop_evidence(self, camera, pkg, output, window_key,
                              crop_by_id):
        """局部分支实际裁图 → crop_worker.submit（C-141 B1 真实接线）。

        - 提交点=L2→L3 入队处（``_maybe_enqueue_l3``）：增强/编码前、
          原图 as-is、像素在手即提交（不等待 L3）；
        - 只提交**局部分支**（relation_crop/change_region）中帧存在且
          真实切片在手的序位（previous/current/next）；全景分支/零对象
          不提交——全景兜底与缺失说明保留，不借用他相机/最新画面；
        - ``crop_worker`` 鸭子类型依赖注入；None=未配置持久化 → 纯
          no-op（零调用零计数零异常，绝不 import 裁图仓模块）；
        - 单张提交异常/返回 dropped 一律吞并为 ``crop_submit_dropped``
          计数（含 provenance 构建异常），绝不阻塞快系统/L1/L2/L3 路径；
          submit 是纯内存入队（零磁盘 I/O），且本调用在任何发布锁之外，
          发布锁内零磁盘 I/O 语义不受影响。
        """
        worker = self.crop_worker
        if worker is None:
            return
        records_by_id = {getattr(crop, "crop_id", None): crop
                         for crop in (output.crops or ())}
        for branch in tuple(output.l3_branches or ()):
            kind = getattr(branch, "branch_kind", None)
            if kind is None or kind == "panorama":
                continue   # 全景分支不提交（合法兜底与缺失说明保留）
            record = records_by_id.get(getattr(branch, "crop_id", None))
            try:
                self._submit_branch_slots(camera, worker, pkg, branch,
                                          window_key, crop_by_id, record)
            except Exception:
                self._count(camera, "crop_submit_dropped")

    def _submit_branch_slots(self, camera, worker, pkg, branch, window_key,
                             crop_by_id, record):
        """单局部分支的逐序位提交（帧存在的 previous/current/next）。

        - 常规路径：L3BranchSpec.frame_sequence（同区域三帧真实切片，
          C-136 C1/C2）——present=True 且像素在手的序位逐个提交；
        - 旧分支兼容路径（无 frame_sequence，测试手工构造形状）：仅
          cur 位（crop_id 显式映射取图，身份取分支 identity，像素框取
          crop_ref.bbox_px，源帧尺寸取材料包 cur 帧实际尺寸）；
        - 每序位独立吞错：一个序位的 provenance 构建/提交失败不影响
          其它序位，全部落 crop_submit_dropped 计数。"""
        sequence = tuple(getattr(branch, "frame_sequence", None) or ())
        if sequence:
            for sl in sequence:
                if not getattr(sl, "present", False):
                    continue   # 缺帧序位：显式缺失说明保留，绝不冒充
                image = getattr(sl, "frame_bgr", None)
                if image is None:
                    continue
                slot = self._SLOT_NAMES.get(
                    int(getattr(sl, "position", -1)))
                if slot is None:
                    continue   # 未知序位：不猜测，不提交
                try:
                    provenance = self._crop_provenance(
                        pkg, branch, window_key, slot=slot,
                        frame_id=getattr(sl, "frame_id", None),
                        t_capture_ms=getattr(sl, "t_capture_ms", None),
                        timestamp_kind=getattr(sl, "timestamp_kind", None),
                        source_size=(getattr(sl, "width", None),
                                     getattr(sl, "height", None)),
                        bbox_px=self._slice_bbox_px(branch, sl),
                        record=record)
                    self._submit_one_crop(camera, worker, image, provenance)
                except Exception:
                    self._count(camera, "crop_submit_dropped")
            return
        # 旧分支兼容路径：仅 cur 位（同 crop_id 显式映射，不按位置猜）
        crop_id = getattr(branch, "crop_id", None)
        image = crop_by_id.get(crop_id) if crop_id is not None else None
        if image is None:
            return   # 裁图像素不在手：不提交不伪造
        ident = getattr(branch, "identity", None)
        cur = getattr(pkg, "cur", None)
        source_size = None
        if cur is not None and getattr(cur, "frame_bgr", None) is not None:
            shape = getattr(cur.frame_bgr, "shape", None)
            if shape is not None and len(shape) >= 2:
                source_size = (shape[1], shape[0])
        transform = getattr(branch, "crop_ref", None)
        bbox_px = getattr(transform, "bbox_px", None)
        try:
            provenance = self._crop_provenance(
                pkg, branch, window_key, slot="current",
                frame_id=(getattr(ident, "frame_id", None)
                          if ident is not None else None),
                t_capture_ms=(getattr(ident, "t_capture_ms", None)
                              if ident is not None else None),
                timestamp_kind=(getattr(ident, "timestamp_kind", None)
                                if ident is not None else None),
                source_size=source_size, bbox_px=bbox_px, record=record)
            self._submit_one_crop(camera, worker, image, provenance)
        except Exception:
            self._count(camera, "crop_submit_dropped")

    @staticmethod
    def _slice_bbox_px(branch, sl):
        """序位切片的像素框（与切图同一确定性换算的重建，非伪造）。

        cur 位=分支 crop_ref.bbox_px（冻结在 CropTransform）；prev/next
        位=crop_ref.bbox_norm 按该帧自身尺寸经 norm_box_to_px 换算——
        与 ``_local_frame_sequence`` 切图时完全相同的纯函数与输入。
        取不到（无 crop_ref/换算退化/尺寸缺失）→ None（由调用方按
        提交失败计数处理，不编造像素框）。"""
        transform = getattr(branch, "crop_ref", None)
        if transform is None:
            return None
        if int(getattr(sl, "position", -1)) == 1:
            bbox = getattr(transform, "bbox_px", None)
            if isinstance(bbox, (list, tuple,)) and len(bbox) == 4:
                return tuple(int(v) for v in bbox)
            return None
        bbox_norm = getattr(transform, "bbox_norm", None)
        width = getattr(sl, "width", None)
        height = getattr(sl, "height", None)
        if (not isinstance(bbox_norm, (list, tuple)) or len(bbox_norm) != 4
                or not width or not height):
            return None
        from .win11_l2_crops import norm_box_to_px
        pixels = norm_box_to_px(tuple(float(v) for v in bbox_norm),
                                width, height)
        return None if pixels is None else tuple(int(v) for v in pixels)

    @staticmethod
    def _crop_provenance(pkg, branch, window_key, *, slot, frame_id,
                         t_capture_ms, timestamp_kind, source_size,
                         bbox_px, record):
        """冻结 §1 完整 9 元身份 + 既有 10 键字段 + 在手扩展段。

        - 9 元：camera_id/run_id/config_version/material_id/window_id/
          branch/crop_id/frame_id/slot（slot ∈ {previous,current,next}，
          三时间位置显式枚举；branch 取冻结值域 panorama|local——局部
          分支（relation_crop/change_region）统一 local，精确子类可由
          crop_id 约定追溯（":chg:"=变化区域））；frame_seq=数值序位
          0/1/2（frame 序位语义，可选补键如实携带）；
        - 既有 10 键字段：t_capture_ms/timestamp_kind/source_size/bbox_px
          （camera/run/config/material/frame/crop 六键与 9 元同字段同值，
          不重复携带）；
        - 扩展段只携带 L2 输出实际在手的数据，取不到的字段直接省略
          （不伪造）：participants（CropRecord.participants 的 ObjectRef
          与分支 cur_detections 的框一一配对；长度不一致时只带框不带
          object_id——绝不猜配对）、relation_candidates（subject/obj
          object_id + 关系/图 + 冻结键 score/vocab_id + 候选不确定性）、
          box_notes（CropRecord.omitted 原因 + CropTransform 夹取/容量
          标记，≤8 条）。分支级 uncertainty 段在 L2 输出结构中不存在
          ——直接省略（L2Output/L3BranchSpec/CropRecord 均无该字段）。
        字段不合法（缺像素框/尺寸/时间等）→ ValueError（由调用方吞并
        为 crop_submit_dropped 计数，不组装不完整 provenance）。"""
        if (not isinstance(source_size, (list, tuple))
                or len(source_size) != 2
                or not source_size[0] or not source_size[1]):
            raise ValueError("crop provenance: source_size unavailable")
        if (not isinstance(bbox_px, (list, tuple,)) or len(bbox_px) != 4):
            raise ValueError("crop provenance: bbox_px unavailable")
        if frame_id is None:
            raise ValueError("crop provenance: frame_id unavailable")
        if timestamp_kind is None:
            raise ValueError("crop provenance: timestamp_kind unavailable")
        if t_capture_ms is None:
            raise ValueError("crop provenance: t_capture_ms unavailable")
        kind = str(getattr(branch, "branch_kind", ""))
        position = {"previous": 0, "current": 1, "next": 2}.get(str(slot))
        provenance = {
            "camera_id": pkg.camera_id,
            "run_id": pkg.run_id,
            "config_version": pkg.config_version,
            "material_id": pkg.material_id,
            "window_id": window_key[3],
            # 冻结 v2 值域：非全景即 local（精确子类经 crop_id 追溯）
            "branch": "panorama" if kind == "panorama" else "local",
            "crop_id": str(getattr(branch, "crop_id", "")),
            "frame_id": int(frame_id),
            "slot": str(slot),
            "t_capture_ms": float(t_capture_ms),
            "timestamp_kind": str(timestamp_kind),
            "source_size": [int(source_size[0]), int(source_size[1])],
            "bbox_px": [int(v) for v in bbox_px],
        }
        if position is not None:
            provenance["frame_seq"] = position
        refs = tuple(getattr(record, "participants", ()) or ())
        detections = tuple(getattr(branch, "cur_detections", ()) or ())
        paired = bool(refs) and len(refs) == len(detections)
        participants = []
        for index, det in enumerate(detections):
            entry = {"cls": getattr(det, "cls", None),
                     "conf": float(getattr(det, "conf", 0.0) or 0.0)}
            bbox_norm = getattr(det, "bbox_norm", None)
            if bbox_norm is not None:
                entry["bbox_norm"] = [float(v) for v in bbox_norm]
            track_id = getattr(det, "track_id", None)
            if track_id is not None:
                entry["track_id"] = track_id
                entry["stable"] = bool(getattr(det, "stable", False))
            if paired:
                ref = refs[index]
                entry["object_id"] = getattr(ref, "object_id", None)
                entry["frame_id"] = getattr(ref, "frame_id", None)
            participants.append(entry)
        candidates = []
        for cand in tuple(getattr(branch, "candidates", ()) or ())[:16]:
            entry = {"subject": getattr(
                         getattr(cand, "subject", None), "object_id", None),
                     "obj": getattr(
                         getattr(cand, "obj", None), "object_id", None),
                     "relation": getattr(cand, "relation", None),
                     "graph": getattr(cand, "graph", None),
                     # 冻结 v2 候选键：score + vocab_id（原始分透传）
                     "score": float(getattr(cand, "score_raw", 0.0) or 0.0),
                     "vocab_id": str(getattr(cand, "vocabulary_id", "")
                                     or "")}
            unc = getattr(cand, "uncertainty", None)
            if unc is not None:
                entry["uncertainty"] = {
                    "frame_missing_prev": bool(
                        getattr(unc, "frame_missing_prev", False)),
                    "frame_missing_next": bool(
                        getattr(unc, "frame_missing_next", False)),
                    "identity_uncertain": bool(
                        getattr(unc, "identity_uncertain", False)),
                    "drift": bool(getattr(unc, "drift", False)),
                    "pair_overlap_high": bool(
                        getattr(unc, "pair_overlap_high", False)),
                    "low_confidence": bool(
                        getattr(unc, "low_confidence", False))}
            candidates.append(entry)
        box_notes = []
        for item in tuple(getattr(record, "omitted", ()) or ()):
            box_notes.append(str(item))
        transform = getattr(branch, "crop_ref", None)
        if transform is not None:
            if getattr(transform, "clamped", False):
                box_notes.append("bbox_clamped")
            if getattr(transform, "context_capped", False):
                box_notes.append("context_capped")
        if participants:
            provenance["participants"] = participants[:16]
        if candidates:
            provenance["relation_candidates"] = candidates[:16]
        if box_notes:
            provenance["box_notes"] = box_notes[:8]
        return provenance

    def _submit_one_crop(self, camera, worker, image_bgr, provenance):
        """单张提交（纯内存入队，零磁盘 I/O）；异常/拒绝一律吞并为
        ``crop_submit_dropped`` 计数——绝不阻塞快系统/L1/L2/L3 路径。
        提交前持有图像的可写副本（worker 按冻结 §2 持任务内唯一副本，
        运行时侧不再共享可变像素）。"""
        dropped = False
        try:
            import numpy as np
            payload = np.asarray(image_bgr).copy()
            ref = worker.submit(payload, provenance)
            if isinstance(ref, dict):
                if str(ref.get("status", "")).startswith("dropped"):
                    dropped = True
            elif ref is not None and str(ref).startswith("dropped"):
                dropped = True
        except Exception:
            dropped = True
        if dropped:
            self._count(camera, "crop_submit_dropped")

    def _enqueue_l3_task(self, camera, pkg, *, window_key, task,
                         l1_refs=(), l2_candidates=(), plan_index=None):
        """入队（C-138 §5 + C-139 §2 A1）：分支登记（producing）→ 门禁
        （锁外初检）→ **最终提交点锁内重检**（stop/窗口有效/分支资格）→
        容量收敛 → 排队。

        门禁拒收=该分支立即结算（stale_identity/stop_cancelled/expired），
        不是 worker 退出理由；提交点拒收（初检通过后 stop/停机收口/TTL
        抢先取得提交权）同样在锁外结算，**绝不追加无人消费的孤儿任务**。
        容量不足按窗口整组淘汰（被淘汰窗口的相机/分支/原因进该窗口 L4
        缺失因素）。锁序：先 _l3_lock 后 _win_lock（单向，不反序）；状态
        锁内只做内存判定与弹队/追加，结算（含 L4/磁盘）一律在锁外。"""
        branch_value = getattr(task.branch, "value", str(task.branch))
        branch_key = window_key + (branch_value,
                                   getattr(task, "crop_id", None),
                                   pkg.material_id)
        # C-144-R2：窗口接纳状态登记——attempted（有过入队尝试）供结算
        # 时的拒收回滚判定；enqueued_ok/update_continued 只反映真实入队。
        adm = self._admitted_windows.get(window_key)
        if adm is not None:
            adm["attempted"] = True
        if not self._register_branch(window_key, branch_key):
            self._count(camera, "l3_dropped")
            return False
        # 入队门禁初检（C-137 §4 + C-138 §5）：身份/停止/材料年龄（单调钟）
        if not self._identity_ok(camera, pkg.run_id, pkg.config_version):
            self._count(camera, "rejected_stale")
            self._settle_branch_terminal(camera, window_key, branch_key,
                                         "stale_identity")
            return False
        if self._stop.is_set():
            self._count(camera, "rejected_stale")
            self._settle_branch_terminal(camera, window_key, branch_key,
                                         "stop_cancelled", detail="enqueue")
            return False
        if (self._mono_ms() - pkg.created_mono_ms
                > self.max_age_s * 1000.0):
            self._count(camera, "expired")
            self._settle_branch_terminal(camera, window_key, branch_key,
                                         "expired",
                                         detail="material_age_exceeded")
            return False
        context = {"camera": camera,
                   "window_key": window_key,
                   "branch_key": branch_key,
                   "l1_refs": list(l1_refs),
                   "l2_candidates": list(l2_candidates),
                   "l1_status": pkg.l1_status,
                   "gate_reason": pkg.l1_terminal_reason,
                   # C-139 生产血缘：材料 bbox 原始值域×帧实际尺寸推导的
                   # 坐标体系声明（L4 FusionInput 用，不恒默认 normalized）
                   "coord_space": self._derive_coord_space(pkg),
                   # C153-R1：该任务的**计划分支下标**（设计丢弃/淘汰时按此
                   # 精确归还计划额度；None=账本关闭或无计划，release no-op）
                   "plan_index": plan_index,
                   "enqueue_mono_ms": self._mono_ms()}
        # C-139 A1 测试插桩点：已过初步门禁、尚未取得提交锁（生产恒 None）
        gate = self._l3_enqueue_gate
        if gate is not None:
            gate()
        # 最终队列提交点：锁内重检（stop / 窗口仍有效 / 分支仍 pending）。
        # 锁内不结算（不等待模型/磁盘）；拒收在锁外经唯一终态提交点收口。
        rejected = None        # None=已入队；(terminal, detail)=提交点拒收
        evicted = []
        with self._l3_lock:
            if self._stop.is_set():
                rejected = ("stop_cancelled", "enqueue")
            else:
                with self._win_lock:
                    entry = self._open_windows.get(window_key)
                    window_valid = (entry is not None
                                    and not entry["done"]
                                    and entry["branches"].get(branch_key)
                                    == "pending")
                if not window_valid:
                    # 分支已被合法路径终态（TTL/停机收口/淘汰）：
                    # 不重复结算、不追加孤儿任务
                    rejected = (None, None)
                else:
                    evicted = self._evict_for_capacity_locked(window_key)
                    for ev_task, ev_context in evicted:
                        self._release_l3_task_budget(
                            self.l3_window_budget_ledger,
                            ev_context.get("window_key", window_key),
                            ev_context.get("plan_index"),
                            "queue_capacity_evicted")
                    self._l3_queues[camera].append((task, context))
        if rejected is None:
            self._count(camera, "l3_enqueued")
            adm = self._admitted_windows.get(window_key)
            if adm is not None:
                # C-144-R2：update_continued 只表示有目标、真实发生的
                # 已有任务补充（同窗第 2+ 个任务真实入队）；首个入队
                # 清除重试债务（任务落地）。
                if adm.get("enqueued_tasks"):
                    self._count(camera, "admission_update_continued")
                adm["enqueued_tasks"] = adm.get("enqueued_tasks", 0) + 1
                adm["enqueued_ok"] = True
                ref = self._last_admission.get(camera)
                if ref is adm.get("new_ref") and isinstance(ref, dict) and ref.get("retry_count"):
                    ref["retry_count"] = 0
        else:
            r_terminal, r_detail = rejected
            if r_terminal is not None:
                self._count(camera, "rejected_stale")
                self._settle_branch_terminal(camera, window_key, branch_key,
                                             r_terminal, detail=r_detail)
            else:
                self._count(camera, "l3_dropped")
        for ev_task, ev_context in evicted:
            self._count(ev_context["camera"], "l3_dropped")
            self._settle_branch_terminal(
                ev_context["camera"], ev_context["window_key"],
                ev_context["branch_key"], "queue_evicted",
                detail="queue_capacity_evicted")
        if rejected is not None:
            self._release_l3_task_budget(self.l3_window_budget_ledger,
                                         window_key, plan_index,
                                         "enqueue_rejected")
        self._trace_emit("l3_enqueued" if rejected is None
                         else "l3_rejected",
                         camera=camera, window_key=list(window_key),
                         branch=branch_key,
                         material_id=getattr(pkg, "material_id", None),
                         reason=(None if rejected is None
                                 else str(rejected[0] or "window_invalid")))
        return rejected is None

    def _evict_for_capacity_locked(self, incoming_window_key):
        """容量收敛（调用方持 _l3_lock）：按窗口组整组淘汰，优先淘汰最旧
        的其它窗口组；只剩本窗组时组内最旧先淘汰（窗口收敛保新）。
        返回被淘汰条目列表（结算在锁外完成，锁序 win→l3 单向）。"""
        evicted = []

        def total():
            return sum(len(q) for q in self._l3_queues.values())

        while total() >= self.l3_max_queue:
            groups = OrderedDict()
            for queue in self._l3_queues.values():
                for item in queue:
                    groups.setdefault(item[1]["window_key"], []).append(item)
            if not groups:
                break
            others = [key for key in groups if key != incoming_window_key]
            if others:
                target = min(others, key=lambda key: (
                    groups[key][0][1]["enqueue_mono_ms"], str(key)))
                victims = list(groups[target])
            else:
                # 只剩本窗组：组内最旧单条先淘汰（保最新分支）
                members = sorted(groups[incoming_window_key],
                                 key=lambda item: (item[1]["enqueue_mono_ms"],
                                                   id(item[0])))
                victims = [members[0]]
            for queue in self._l3_queues.values():
                for victim in victims:
                    try:
                        queue.remove(victim)
                    except ValueError:
                        pass
            evicted.extend(victims)
            self._l3_dropped += len(victims)
        return evicted

    def _l3_dequeue(self):
        """跨相机公平轮转取队首（每相机独立 FIFO；安静返回 None）。"""
        cameras = self.camera_ids
        n = len(cameras)
        entry = None
        with self._l3_lock:
            for step in range(n):
                idx = (self._l3_rr + step) % n
                queue = self._l3_queues.get(cameras[idx])
                if queue:
                    entry = queue.popleft()
                    self._l3_rr = (idx + 1) % n
                    break
        if entry is not None:
            context = entry[1]
            wait_ms = self._mono_ms() - context.get("enqueue_mono_ms", 0)
            self._trace_emit("l3_dequeued", camera=context["camera"],
                             window_key=list(context["window_key"]),
                             branch=context["branch_key"],
                             queue_wait_ms=round(wait_ms, 3))
        return entry

    # ---- L3 worker -----------------------------------------------------------

    def _l3_run(self):
        """L3 worker：旧 config/停止后任务=拒收该任务并结算该分支后
        continue——不是退出理由；只有 stop 才结束循环（C-138 §5 修复）。"""
        while not self._l3_stop.is_set():
            if self._l3_stop.wait(self.poll_interval_s):
                return
            entry = self._l3_dequeue()
            if entry is None:
                continue
            try:
                self._l3_process_entry(entry[0], entry[1])
            except Exception:
                # 防御：单任务处理入口自身异常不结束 worker（分支终态在
                # process_entry 内部已结算；此处兜底防回归）
                print("[NVR] L3 worker 入口异常:", flush=True)
                traceback.print_exc()
                with self._lock:
                    self._status_counts["l3:error"] = \
                        self._status_counts.get("l3:error", 0) + 1

    def _l3_process_entry(self, task, context):
        """单任务：出队门禁 → 推理 → 发布裁决段（锁内三检+终态裁决）→
        锁外磁盘 append → 终态收口。

        C-139 §2 A2（一次性终态）：唯一终态提交点是
        ``_settle_branch_terminal``——失败/拒收路径在对应门禁点结算
        （gap 只在该点注入一次）；成功路径的终态登记在发布裁决段内完成
        （分支字典 pending→branch_ok 与门禁通过同一锁段）。本方法不再
        二次注入缺失因素。
        C-139 §2 A3 + R1 §1（发布裁决）：保存前门禁在发布锁段内二次复核
        stop/身份/发布时效，通过即同锁段裁决分支终态；磁盘 append 在锁外
        （已裁决的历史事实可以写，不冒充当前有效）。
        """
        camera = context["camera"]
        window_key = context["window_key"]
        branch_key = context["branch_key"]
        self._trace_emit("stage_started", camera=camera,
                         window_key=list(window_key), branch=branch_key,
                         crop_id=getattr(task, "crop_id", None),
                         gate_reason=context.get("gate_reason"))
        # 出队门禁：停止 / 身份失效 → 结算该分支并继续（不退出循环）
        if self._stop.is_set():
            self._count(camera, "rejected_stale")
            self._settle_branch_terminal(camera, window_key, branch_key,
                                         "stop_cancelled", detail="dequeue")
            return
        if not self._identity_ok(camera, task.window.run_id,
                                 task.window.config_version):
            self._count(camera, "rejected_stale")
            self._settle_branch_terminal(camera, window_key, branch_key,
                                         "stale_identity", detail="dequeue")
            return
        # 排队年龄门禁（入队时记 mono；单调钟，不续命）
        if (self._mono_ms() - context["enqueue_mono_ms"]
                > self.max_queue_wait_s * 1000.0):
            self._count(camera, "expired")
            self._settle_branch_terminal(camera, window_key, branch_key,
                                         "expired",
                                         detail="queue_wait_exceeded")
            return
        try:
            measured_process = getattr(self.l3_stage, "process_measured", None)
            if (self._trace_sink is not None or self._trace_events is not None) and callable(measured_process):
                from .win11_l3 import L3MeasurementContext
                out = measured_process(task, L3MeasurementContext(self, branch_key))
            else:
                out = self.l3_stage.process(task)
        except Exception:
            print("[NVR] L3 处理异常:", flush=True)
            traceback.print_exc()
            with self._lock:
                self._status_counts["l3:error"] = \
                    self._status_counts.get("l3:error", 0) + 1
            self._settle_branch_terminal(camera, window_key, branch_key,
                                         "model_failed",
                                         detail="stage_exception")
            return
        status = getattr(out.status, "value", str(out.status))
        if status == "identity_rejected":
            terminal = "stale_identity"
        elif status in self._L3_FAILURE_STATUSES:
            terminal = "model_failed"
        else:
            terminal = self.TERMINAL_OK
        if terminal != self.TERMINAL_OK:
            # 失败/拒收路径：对应门禁点唯一结算（缺失因素只在此注入一次，
            # detail=受控失败态词表；重复回调幂等不重复）
            if not self._settle_branch_terminal(
                    camera, window_key, branch_key, terminal, detail=status,
                    settle_window=False):
                return   # 已被其它路径终态（TTL/停机收口）：不重复不发布
        # 发布裁决段（A3/R1）：锁内三检+分支终态裁决（成功记录另核分支仍
        # pending，通过即 pending→branch_ok，发布权一次授予）；磁盘 append
        # 在锁外。不符 → (terminal, detail) 由调用方在发布门禁点结算。
        payload, reject = self._publish_l3_record(
            camera, task, window_key, branch_key, out, status,
            require_pending=(terminal == self.TERMINAL_OK))
        if reject is not None:
            r_terminal, r_detail = reject
            if r_terminal is not None:
                if r_terminal == "expired":
                    self._count(camera, "expired")
                else:
                    self._count(camera, "rejected_stale")
                # 失败路径二次回调：幂等不重复结算；成功路径在发布门禁点结算
                self._settle_branch_terminal(camera, window_key, branch_key,
                                             r_terminal, detail=r_detail)
            else:
                self._maybe_settle_window(window_key)
            return
        # 锁外持久化：已裁决的历史事实落盘（记录自带完整身份，不冒充当前
        # 有效；store 内线程同步，append 失败如实计数）
        self._append_history(camera, "l3", payload)
        if terminal == self.TERMINAL_OK and (self._trace_sink is not None or self._trace_events is not None):
            for result in payload.get("results", ()):
                texts = {name: result.get(name) for name in ("observation", "inference")}
                if any(isinstance(value, dict) and value.get("text") for value in texts.values()):
                    self._trace_emit("semantic_understanding", camera=camera,
                        window_key=list(window_key), branch=branch_key,
                        task_key=list(branch_key), first_useful_candidate=True,
                        semantic_output=texts, status=status,
                        meaning="accepted_model_interpretation_not_confirmed_fact")
        with self._lock:
            counts = self._counts[camera]
            counts["l3_completed"] = counts.get("l3_completed", 0) + 1
            self._status_counts["l3:" + status] = \
                self._status_counts.get("l3:" + status, 0) + 1
        if terminal == self.TERMINAL_OK:
            # 成功路径：分支已在裁决段终态（branch_ok），保存后累计 L4
            #（窗口收口会清理 L4 缓存，累计须在前），再尝试窗口收口
            self._accumulate_branch_result(camera, task, context, out,
                                           window_key)
        self._maybe_settle_window(window_key)

    def _publish_l3_record(self, camera, task, window_key, branch_key,
                           out, status, *, require_pending):
        """发布裁决段（C-139 §2 A3 + R1 §1 + C-140 §1/R1 A1，专用发布锁）：
        保存前门禁与分支终态裁决在同一锁段——初检复核 stop/身份/发布时效，
        最终裁决段（pending→terminal 之前）经 ``_l3_lock`` 锁内重检
        stop/身份/发布年龄（C-140-R1 A1：初检通过后结果可能在等待
        ``_l3_lock`` 期间越过时效；重检与授予原子，无中间态），通过即
        **同锁段内把分支字典 pending→branch_ok**（裁决与门禁原子）。
        C-140 §1：门禁入口捕获停机提交基线 ``_commit_epoch``；最终裁决段
        （pending→terminal 之前）经``_l3_lock``——与 stop 提交
        （``_commit_stop``）同一把锁——比对基线后才授予：stop 提交无法插入
        "重检→授予"之间，先后语义由锁取得顺序唯一确定。stop 先提交→拒绝
        成功权，改返回结构化拒收（不返回成功值，detail=
        stop_committed_after_gate，由调用方在发布门禁点按 stop_cancelled
        恰好结算一次）；锁内年龄重检超期→detail=publish_age_exceeded_
        in_lock（由调用方按 expired 恰好结算一次）；发布先授予→授予后
        提交的 stop 不追回，已授予结果作为完整身份历史保存（不重复终态
        结算）。锁内只做内存复核与纯 CPU 的 payload 组装，不做磁盘 I/O/
        模型/join——裁决产物返回调用方，由其在锁外 append（已裁决的历史
        事实可以写，但不能冒充当前有效；记录自带完整身份：window_key/
        branch_key/run/config，与当前结果分列由消费方按身份过滤）。

        返回 (payload, reject)：
        - (payload, None)：裁决通过（成功路径分支已终态 branch_ok）；
        - (None, (terminal, detail))：门禁拒收——调用方在发布门禁点结算，
          不写历史（含 stop 提交竞态拒收 stop_committed_after_gate 与锁内
          时效重检拒收 publish_age_exceeded_in_lock）；
        - (None, (None, None))：分支已被合法路径终态（不重复结算不发布）。
        """
        run_id = task.window.run_id
        config_version = task.window.config_version
        payload = None
        reject = None
        handle = None
        adjudicated = False
        with self._publish_lock:
            captured_epoch = self._identity_epoch
            # C-140 §1：停机提交基线（初检之前捕获）——若 stop 在初检与
            # 最终裁决之间提交，基线比对即暴露（初检只能看到提交前的
            # Event 置位，这是竞态窗口本体）
            captured_commit = self._commit_epoch
            if self._stop.is_set():
                reject = ("stop_cancelled", "publish")
            elif not self._identity_ok(camera, run_id, config_version):
                reject = ("stale_identity", "publish")
            elif (self._mono_ms() - task.created_mono_ms
                    > self.max_publish_age_s * 1000.0):
                reject = ("expired", "publish_age_exceeded")
            elif require_pending:
                # C-140 §1 测试插桩：初检通过后、最终裁决段前（生产恒 None）
                probe = self._publish_gate_probe
                if probe is not None:
                    probe()
                # 最终裁决段：与 stop 提交（_commit_stop）同一把 _l3_lock
                # 定序（锁序 publish→l3→win 单向）。基线比对在 pending→
                # terminal 之前、授予同锁段完成——"裁决完成后、返回调用方
                # 前"的重检由此收紧为"授予前锁内重检且重检与授予原子"，
                # 不存在已授予再回滚的中间态。锁内只做内存判定与分支字典
                # 转移（无磁盘/模型/join/backend 关闭）。
                with self._l3_lock:
                    stop_committed = (self._commit_epoch != captured_commit)
                    with self._win_lock:
                        entry = self._open_windows.get(window_key)
                        if (entry is None or entry["done"]
                                or entry["branches"].get(branch_key)
                                != "pending"):
                            reject = (None, None)
                        elif stop_committed:
                            # stop 已提交：拒绝成功权（stop 已提交后不再
                            # 授予新 branch_ok）；该分支由调用方按
                            # stop_cancelled 结算，停机诊断与模型成功分列
                            reject = ("stop_cancelled",
                                      "stop_committed_after_gate")
                        elif (self._identity_epoch != captured_epoch
                                or not self._identity_ok(
                                    camera, run_id, config_version)):
                            reject = ("stale_identity",
                                      "identity_epoch_changed")
                        elif (self._mono_ms() - task.created_mono_ms
                                > self.max_publish_age_s * 1000.0):
                            # C-140-R1 A1：授予前锁内重检发布年龄——初检
                            # 通过后结果可能在等待 _l3_lock 期间越过时效；
                            # 与 stop/身份同段重检（单调钟，纯内存判定，
                            # 无磁盘 I/O/模型调用/join/backend 关闭）。
                            # 超期不授予成功权、不发布成功结果，由调用方
                            # 在发布门禁点按 expired 恰好结算一次（一次性
                            # 终态，不重复结算）。
                            reject = ("expired",
                                      "publish_age_exceeded_in_lock")
                        else:
                            # 同锁段裁决：pending→branch_ok（发布权一次
                            # 授予；此后提交的 stop 不追回，历史完整保存；
                            # 后续帧到达时分支已 terminal→不重复发布也不
                            # 重复结算）
                            entry["branches"][branch_key] = self.TERMINAL_OK
                            handle = entry["handle"]
                            adjudicated = True
            if reject is None:
                results = results_from_output(out)
                payload = {"window_key": list(window_key),
                           "window": window_key[3],
                           "branch": branch_key[4],
                           "branch_key": list(branch_key),
                           "run_id": run_id,
                           "config_version": config_version,
                           "status": status,
                           "results": results,
                           "at": time.time()}
        if adjudicated:
            # 锁外裁决侧账：handle 分支登记与结算计数（不锁内等待）
            try:
                handle.mark_branch_done(branch_key)
            except Exception:
                pass
            self._count(camera, "settled_" + self.TERMINAL_OK)
            self._trace_emit("stage_finished", camera=camera,
                             window_key=list(window_key), branch=branch_key,
                             status=self.TERMINAL_OK)
        return payload, reject

    # ---- L4 同窗累计（C-138 §5：accumulate，非单次 fuse） ---------------------

    def _l4_output_allowed(self, camera, window_key):
        """L4 产出门禁（C-139 §2 A3 + R1 §1 同一身份边界的 L4 侧）：
        L3 已保存、L4 生成前重检身份+发布世代——门禁通过后到版本落盘前
        切配置，旧窗口不再产出新的融合版本（含缺失因素注入路径）；已算
        未存版本随窗口收口清理。只检身份不检 stop：停机缺失因素是当前
        身份窗口的如实诊断，照常入账（stop_cancelled 结算路径不变）。
        返回捕获的世代值；拒收返回 None。"""
        captured_epoch = self._identity_epoch
        if not self._identity_ok(camera, window_key[1], window_key[2]):
            return None
        return captured_epoch

    def _authorize_l4_write(self, camera, window_key, captured_epoch):
        """C-141 B2：L4 短临界区身份授权（专用短锁 ``_l4_auth_lock``）。

        最终落盘前的接受授权：锁内比对「注册表 run/config == 待写版本
        身份」且「发布世代 == 累计入口捕获世代」——一致→授权（返回 True，
        授权令牌即本锁段内的一致性确认）；不一致→结构化拒绝（调用方
        不写盘；本方法计 ``l4_auth_rejected``，调用方保持既有
        ``rejected_stale`` 口径）。授权后磁盘写在**锁外**执行：写的是
        已授权旧身份的历史事实（记录自带完整身份，消费方按身份过滤
        ——冻结语义）；写入期间身份变化不追回。

        - 专用短锁：绝不复用 ``_publish_lock``（发布裁决与 L4 授权解耦，
          两个临界区各自极短且互不嵌套）；全仓锁序 publish→l3→win→
          l4_auth 单向（本锁最末；锁内经 _lock 读取注册表/世代快照，
          方向 auth→lock 单向无反序嵌套）；锁内零磁盘 I/O/模型/join，
          慢盘不持本锁（磁盘写在授权返回之后的锁外进行）。
        - 终止例外（冻结 §5 显式说明）：授权只检身份不检 stop——stop
          已提交后，stop 提交前已授权的最后一个版本允许完成写入（写入
          的是授权时点的旧身份历史事实）；stop 的缺失因素诊断
          （stop_cancelled 结算路径，发生在 stop 提交之后）同样经本授权
          照常入账——二者都是如实诊断，消费方按身份过滤，不冒充当前。
        """
        # C-141 B2 测试插桩：身份检查→授权之间（生产恒 None，纯内存
        # 回调，不等待磁盘/模型）
        probe = self._l4_auth_gate_probe
        if probe is not None:
            probe()
        with self._l4_auth_lock:
            with self._lock:
                expected = self._registry.get(camera)
                epoch = self._identity_epoch
            authorized = (epoch == captured_epoch
                          and expected is not None
                          and expected == (window_key[1], window_key[2]))
        if not authorized:
            self._count(camera, "l4_auth_rejected")
        return authorized

    @staticmethod
    def _derive_coord_space(pkg):
        """材料 bbox 原始值域 × 帧实际尺寸 → COORD_SPACES 声明（确定性
        推导，不恒默认 normalized，C-139 生产血缘）：

        - 任一检出框分量 > 1.0（归一化 0..1 域之外）且框落在 cur 帧像素
          域内 → "pixels"（bbox 原始坐标系=像素）；
        - 其余（全部分量在 0..1 域内或无框证据）→ "normalized"（L1 合同：
          检出框整帧归一化；两种解释均合法时按合同声明，不猜像素）。
        """
        dets = getattr(pkg, "detections", None) or []
        cur = getattr(pkg, "cur", None)
        frame_w = frame_h = None
        frame_bgr = getattr(cur, "frame_bgr", None)
        if frame_bgr is not None and getattr(frame_bgr, "shape", None) is not None:
            frame_h, frame_w = frame_bgr.shape[:2]
        for det in dets:
            if not isinstance(det, dict):
                continue
            bbox = det.get("bbox")
            if not isinstance(bbox, (list, tuple)) or len(bbox) != 4:
                continue
            try:
                x, y, bw, bh = (float(bbox[0]), float(bbox[1]),
                                float(bbox[2]), float(bbox[3]))
            except (TypeError, ValueError):
                continue
            if max(x, y, bw, bh) > 1.0:
                if frame_w is None or (x + bw <= frame_w
                                       and y + bh <= frame_h):
                    return "pixels"
        return "normalized"

    @staticmethod
    def _branch_frame_refs(out, coord_space):
        """分支实际使用帧 → FusionFrameRef（C-139 生产血缘：从
        L3Output.results sources/L3SourceRef 逐条提取——全景=三帧、局部=
        同区域三帧切片各自绑定的帧 ID；frame_id/时间值/时间类型取真实值
        不缺不造）。缺帧序位（present=False / frame_id None）不伪造引用；
        时间类型不在 FUSION_TIME_KINDS 值域时如实 unknown；局部分支以
        crop_ref（crop_id）锚定区域，bbox 不猜。"""
        refs = {}
        for result in tuple(getattr(out, "results", None) or ()):
            crop_ref = getattr(result, "crop_id", None)
            for source in tuple(getattr(result, "sources", None) or ()):
                frame_id = getattr(source, "frame_id", None)
                if frame_id is None or not getattr(source, "present", False):
                    continue
                t_ms = getattr(source, "t_capture_ms", None)
                time_kind = getattr(source, "timestamp_kind", None)
                if time_kind not in FUSION_TIME_KINDS:
                    time_kind = "unknown"
                key = (str(frame_id), None if t_ms is None else float(t_ms),
                       time_kind)
                if key in refs:
                    continue
                refs[key] = FusionFrameRef(
                    frame_id=str(frame_id), t_ms=t_ms, time_kind=time_kind,
                    crop_ref=crop_ref, coord_space=coord_space)
        return tuple(refs.values())

    def _l4_history_payload(self, window_key, fused):
        """L4 版本 → 历史记录：经 B 交付的 ``fusion_version_to_json`` 完整
        序列化（全 window 身份/逐条 items 含 sources/frame_refs/coord_space
        /缺失因素/archived），再补 window_key 列表与墙钟 at（消费方分列与
        排序用）。不手工拼 kind/text/certainty 缩水字典（C-139 §3）。"""
        payload = fusion_version_to_json(fused)
        payload["window_key"] = list(window_key)
        payload["at"] = time.time()
        return payload

    def _accumulate_branch_result(self, camera, task, context, out,
                                  window_key):
        """有效分支 → L4 同窗累计（真实 results/时间类型/来源/帧血缘，不恒
        host_receive/不恒空/不恒 normalized；失败因素随窗口缺失路径注入，
        不在此编造）。L3 保存后、累计前身份重检（切配置→L4 不产出）。"""
        if self.l4_factory is None:
            return
        captured_epoch = self._l4_output_allowed(camera, window_key)
        if captured_epoch is None:
            self._count(camera, "rejected_stale")
            return
        coord_space = context.get("coord_space") or "normalized"
        clock_kinds = sorted({
            source.timestamp_kind
            for branch in (getattr(out, "results", None) or ())
            for source in (getattr(branch, "sources", None) or ())
            if getattr(source, "timestamp_kind", None)})
        try:
            stage = self._l4_stage_for(window_key)
            fused = stage.accumulate(window_key, FusionInput(
                camera_id=window_key[0], run_id=window_key[1],
                config_version=window_key[2], window_id=window_key[3],
                l1_object_refs=tuple(context.get("l1_refs") or ()),
                l2_candidates=tuple(context.get("l2_candidates") or ()),
                l3_branches=tuple(getattr(out, "results", None) or ()),
                failures=(), gaps=(), clock_kinds=tuple(clock_kinds),
                coord_space=coord_space,
                frame_refs=self._branch_frame_refs(out, coord_space)))
        except FusionIdentityRejected as exc:
            details = getattr(exc, "details", None)
            print("[NVR] L4 融合身份拒绝:", type(exc).__name__,
                  json.dumps(details, ensure_ascii=False,
                             default=str)[:400], flush=True)
            with self._lock:
                self._status_counts["l4:identity_rejected"] = \
                    self._status_counts.get("l4:identity_rejected", 0) + 1
            return
        except Exception as exc:
            details = getattr(exc, "details", None)
            print("[NVR] L4 融合异常:", type(exc).__name__,
                  json.dumps(details, ensure_ascii=False,
                             default=str)[:400], flush=True)
            traceback.print_exc()
            return
        # C-141 B2：L4 短临界区授权（专用 _l4_auth_lock 锁内身份+世代
        # 重检授权；授权后锁外磁盘写——已授权旧身份的历史事实，消费方
        # 按身份过滤）。拒绝=结构化（l4_auth_rejected+rejected_stale），
        # 不写盘。
        if not self._authorize_l4_write(camera, window_key, captured_epoch):
            self._count(camera, "rejected_stale")
            return
        self._append_history(camera, "l4",
                             self._l4_history_payload(window_key, fused))
        with self._lock:
            counts = self._counts[camera]
            counts["l4_versions"] = counts.get("l4_versions", 0) + 1
            self._status_counts["l4:" + fused.status] = \
                self._status_counts.get("l4:" + fused.status, 0) + 1
        self._trace_emit("l4_partial", camera=camera,
                         window_key=list(window_key),
                         status=getattr(fused, "status", None),
                         version_id=getattr(fused, "version_id", None))

    def _l4_stage_for(self, window_key):
        """每窗一次 l4_factory（缓存 window_key→stage，有界 16，超限最旧
        cleanup——证据已保存者可安全回收）。"""
        with self._l4_lock:
            stage = self._l4_stages.get(window_key)
            if stage is not None:
                self._l4_stages.move_to_end(window_key)
                return stage
        stage = self.l4_factory(window_key[0], window_key[1], window_key[2])
        evicted = None
        with self._l4_lock:
            self._l4_stages[window_key] = stage
            while len(self._l4_stages) > self._L4_MAX_WINDOWS:
                oldest_key, oldest = next(iter(self._l4_stages.items()))
                if oldest_key == window_key:
                    break
                self._l4_stages.pop(oldest_key)
                evicted = (oldest, oldest_key)
        if evicted is not None:
            try:
                evicted[0].cleanup(evicted[1])
            except Exception:
                pass
        return stage

    def _accumulate_window_gap(self, camera, window_key, branch_key,
                               terminal, detail=None, sources=()):
        """缺失因素注入该窗口 L4 accumulate（队列淘汰/过期/拒收/失败/
        停止/TTL——经缺失因素进 L4，不悄悄丢账）。detail 含 branch 键段，
        保证逐分支指纹可区分（不因同因合并丢分支）；sources=受控证据键
        （C-139 §2 冻结签名第 6 参，随缺失因素入账供追溯）——L4 的
        normalize_gap 只保 (kind, detail)，故 sources 并入 gap detail
        （无路径/凭据的安全键文本；空 sources 不追加，文本与旧版一致）。
        L3 侧同款身份门禁：身份/世代已变的旧窗口不再产出新版本（缺失
        因素随旧窗收口丢弃，不写当前历史）。保存经
        ``_l4_history_payload``（fusion_version_to_json 完整序列化）。"""
        if self.l4_factory is None:
            return
        captured_epoch = self._l4_output_allowed(camera, window_key)
        if captured_epoch is None:
            self._count(camera, "rejected_stale")
            return
        branch_label = ":".join(str(part) for part in branch_key[4:])
        reason_text = "branch={} reason={}".format(
            branch_label, detail or terminal)
        if sources:
            reason_text += " sources=" + ",".join(
                str(s) for s in sources)
        gap = {"kind": str(terminal),
               "detail": reason_text}
        try:
            stage = self._l4_stage_for(window_key)
            fused = stage.accumulate(window_key, FusionInput(
                camera_id=window_key[0], run_id=window_key[1],
                config_version=window_key[2], window_id=window_key[3],
                l1_object_refs=(), l2_candidates=(), l3_branches=(),
                failures=(), gaps=(gap,), clock_kinds=()))
        except FusionIdentityRejected as exc:
            print("[NVR] L4 缺失因素注入被拒:", type(exc).__name__,
                  json.dumps(getattr(exc, "details", None),
                             ensure_ascii=False, default=str)[:200],
                  flush=True)
            return
        except Exception as exc:
            print("[NVR] L4 缺失因素注入异常:", type(exc).__name__,
                  flush=True)
            return
        # C-141 B2：缺失因素路径同样经 L4 短临界区授权（授权后锁外落盘；
        # 拒绝不写盘，计数见 _authorize_l4_write）
        if not self._authorize_l4_write(camera, window_key, captured_epoch):
            self._count(camera, "rejected_stale")
            return
        self._append_history(camera, "l4",
                             self._l4_history_payload(window_key, fused))
        with self._lock:
            counts = self._counts[camera]
            counts["l4_versions"] = counts.get("l4_versions", 0) + 1

    def _cleanup_l4(self, window_key):
        """窗口终结：清理该窗 L4 累计状态与缓存（证据已保存）。"""
        with self._l4_lock:
            stage = self._l4_stages.pop(window_key, None)
        if stage is None:
            return
        try:
            stage.cleanup(window_key)
        except Exception:
            pass

    # ---- 任务构建（生产接线专用） -------------------------------------------

    def _build_task(self, pkg):
        from .win11_l2_contract import (ChangeRegion, DetectionView,
                                        FrameIdentity, L2TaskInput)
        cur = pkg.cur

        def _identity(fr):
            return FrameIdentity(
                camera_id=pkg.camera_id, run_id=pkg.run_id,
                config_version=pkg.config_version, frame_id=fr.frame_id,
                material_id=pkg.material_id, t_capture_ms=fr.t_capture_ms,
                timestamp_kind=fr.timestamp_kind)

        def _detections(dets):
            views = []
            for d in dets or ():
                bbox = d.get("bbox") or [0, 0, 0, 0]
                views.append(DetectionView(
                    cls=d.get("cls", ""), conf=float(d.get("conf") or 0.0),
                    bbox_norm=(float(bbox[0]), float(bbox[1]),
                               float(bbox[2]), float(bbox[3])),
                    track_id=d.get("trackId"), stable="trackId" in d))
            return tuple(views)

        def _side(fr):
            # 前后帧各自的检测本批不存在——显式缺失，绝不复制当前帧框
            return L2TaskInput(
                identity=_identity(fr), frame_bgr=fr.frame_bgr,
                width=fr.frame_bgr.shape[1], height=fr.frame_bgr.shape[0],
                detections=(), l1_status=None, change_regions=(),
                prev=None, next=None, prev_gap_ms=None, next_gap_ms=None,
                vocabulary_id=self.vocabulary_id,
                relation_vocabulary=self.vocabulary, budget=None)

        h, w = cur.frame_bgr.shape[:2]
        regions = []
        for b in (pkg.change_original_boxes() or []):
            if isinstance(b, dict):
                bx, by, bw, bh = b["x"], b["y"], b["w"], b["h"]
            else:
                bx, by, bw, bh = b[0], b[1], b[2], b[3]
            regions.append(ChangeRegion(x=bx / w, y=by / h,
                                        w=bw / w, h=bh / h))
        return L2TaskInput(
            identity=_identity(cur), frame_bgr=cur.frame_bgr, width=w,
            height=h, detections=_detections(pkg.detections),
            l1_status=pkg.l1_status, change_regions=tuple(regions),
            prev=_side(pkg.prev) if pkg.prev is not None else None,
            next=_side(pkg.nxt) if pkg.nxt is not None else None,
            prev_gap_ms=getattr(pkg, "prev_gap_ms", None),
            next_gap_ms=getattr(pkg, "nxt_gap_ms", None),
            vocabulary_id=self.vocabulary_id,
            relation_vocabulary=self.vocabulary,
            budget=self.stage.budget)
