"""win11_understanding_store.py —— 理解结果统一保存与摘要（C-138 §3/§6；
C-139 §4 保存三态与隔离；C-139-R2 §3 流式有界加载强化；
C-140 §2 关键嵌套字段浅校验）。

职责边界（冻结）：
- 有界存储：每相机每 kind ≤ max_per_camera 条，超限**真删最旧行**（rotated
  计数），并原子重写文件（tmp + Path.replace）；
- 纯内存模式（root=None）：用户查看能力不得因不落盘而消失；
- 线程同步（单锁覆盖 内存历史/计数/懒加载/相机 LRU）；
- 根目录校验=真实父子关系（Path.resolve + is_relative_to），绝不用
  startswith 字符串前缀（``store-a`` 与 ``store-ab`` 必须互不冒认）；
- append 深拷贝隔离（C-139 §4）：入口经 json round-trip（allow_nan=False）
  生成完全隔离副本——嵌套 sources/results/items 全隔离；调用方事后改原
  对象、改 history()/summary() 返回值，均不污染内部历史与已存文件
  （副作用冻结：非字符串 dict 键序列化为字符串、tuple 变 list——记录
  本就按 JSON 落盘，读回即此形状）；
- 加载预算（C-139 §4 + R2，**从文件尾部向前分块倒读，最新优先**：绝不
  整文件 read、绝不把超长行整行读入内存、扫描过程中即时实施预算）：
  1) 文件字节上限 max_load_file_bytes（默认 8MB）：stat 即超限 → 整体拒
     载该 kind 文件（内存已有内容保留）+ load_file_too_large 计数；stat
     之后文件再增长 → 只读 stat 时的快照大小（end=min(实际, stat)），
     绝不无界分配；
  2) 行字节上限=复用 max_record_bytes：单行超限跳过 + load_oversized_lines
     计数（append 与加载共用同一单条上限）；拼行缓冲超过
     max_record_bytes×2 仍见不到行边界 → 判定巨行：立即停止缓冲、直接
     跳过到该行起点边界（同一行只计一次数）——内存绝不超过
     max_record_bytes×2 + 单块读取量；
  3) 记录数上限 load_budget_records：**共享总预算 + 按 kind 轮转取最新**
     （每轮按 l2→l3→l4 各取一条最新记录；单一 kind 无法耗尽其他 kind 的
     预算，语义上即各 kind 独立份额上限=总预算）。扫描过程中每个 kind
     的预算池达 load_budget_records+1 即停（最新优先倒读，第 budget+1 条
     仅确认截断发生并作轮转备用，轮转总量仍受总预算约束）——绝不为
     预算外的旧行继续解析。预算截断保留最新、丢弃最旧 +
     load_truncated_oldest 计数（=已解析 - 实际载入）；
  4) 解析预算：坏 JSON（bad_lines）/ 顶层非 dict 或关键字段类型不合规
     （load_bad_lines）/ NaN-Inf（load_non_finite）跳过+计数，绝不拖垮
     接口。load_parsed_records 计「通过解析与浅校验、计入预算池」的记录
     数（扫描提前停止的过程证据：单 kind ≤ load_budget_records+1）；
- 数值校验（C-139 §4）：NaN/Inf float（含 1e400 溢出）出现在顶层或嵌套
  → 拒绝该记录：append 返回 False + non_finite_rejected 计数；加载跳过
  + load_non_finite 计数。record 顶层必须是 dict；
- 关键字段浅校验（C-139-R1 §3「顶层 dict + kind 值域」）：加载行若携带
  ``status`` 必须是 str、携带 ``kind`` 必须是 str 且 ∈ {l2,l3,l4}——不符
  → 跳过 + load_bad_lines。字段**存在才校验**（存储层按 kind 文件分桶，
  runtime 记录不冗余携带 kind；legacy 记录缺字段如实放行）；
- 关键嵌套浅校验（C-140 §2，只一层、不做深度递归）：``items``/``results``/
  ``frame_refs``/``sources`` 存在必须是 list、``version_id`` 必须是 str、
  window 四元字段（camera_id/run_id/config_version/window_id）必须是
  str/int（bool 不算）——不符**整条拒绝** + bad_structure（不冒充完整
  历史）；items/results 为 list 时逐条必须是 dict，非 dict 条目**就地剔
  除**（逐条计入 bad_structure，记录保留）。**存在才校验**：显式 null 与
  缺字段同视（旧格式兼容放行）——只拒绝「字段存在但类型错误」；
- 旧格式兼容：加载的记录若缺当前格式锚点（l2: status；l3: results/
  branch/status；l4: version_id，锚点集冻结于 _KIND_ANCHORS）→ 标
  ``legacy=True`` 字段（存储层在加载副本上标注，不伪装成当前完整记录；
  append 侧不判定——runtime 恒写当前格式）；
- 未知相机缓存有界（C-139 §4）：max_known_cameras=32，LRU 按**最近一次
  append**排序，超上限淘汰最久未写相机的**内存历史与计数**；磁盘文件
  不动——被淘汰相机再次被访问时按哈希键重新懒加载恢复。磁盘模式的懒
  加载（读路径）以「不在驻留集才插入」的方式准入，读洪水同样有界；
- 单条超 max_record_bytes：append 拒绝 + record_too_large 计数，不入历史；
- 摘要组装（模块级 build_summary）：完全由 runtime 侧 append 的记录结构
  驱动——store 不解释语义、不改写模型文本；缺失/未知字段如实为空。

持久化布局：``root/<sha256(camera)[:16]>/<kind>.jsonl``（摘要目录键，同
evidence.py 的做法：用户输入不进入文件路径）；相机目录在首次访问该相机
时懒加载（存储层不持有相机名单，也不做哈希反查）。

snapshot() 诊断字段（冻结）：
- appended：已接受进历史的记录数（含纯内存模式；含落盘失败的记录——
  记录仍在内存历史中可查看）；
- rotated：append 触发轮转真删的最旧行数（加载期截断不计）；
- record_too_large：超单条上限被拒绝的记录数；
- non_finite_rejected：含 NaN/Inf 被 append 拒绝的记录数；
- bad_lines：加载时 JSON 解码失败被跳过的行数；
- load_bad_lines：加载时 JSON 合法但结构不合规（顶层非 dict，或 status/
  kind 关键字段类型/值域不过）被跳过的记录数；
- bad_structure：加载时关键嵌套字段类型违规被拒的计数（C-140 §2）——
  items/results/frame_refs/sources 存在但非 list、version_id 非 str、
  window 四元字段非 str/int 而**整条跳过**的记录数，加 items/results 中
  被就地剔除的非 dict**条目数**（记录不冒充完整历史）；
- load_oversized_lines：加载时超单条字节上限被跳过的行数（含巨行）；
- load_non_finite：加载时含非有限数被跳过的记录数；
- load_parsed_records：加载时通过解析与浅校验、计入预算池的记录数
  （预算提前停止的过程证据；单 kind ≤ load_budget_records+1）；
- load_file_too_large：超文件字节上限被整体拒载的 kind 文件数；
- load_truncated_oldest：加载预算截断丢弃的记录数（=已解析 - 实际载入；
  max_per_camera 收敛不计——磁盘未动，后续 append 触发重写时自然收敛）；
- persist_failed：落盘失败次数（查看不受影响）；
- cameras_evicted：LRU 淘汰的相机数（仅淘汰内存历史/计数；磁盘不动；
  只计写路径淘汰——懒加载恢复触发的置换不计）；
- memory_only：root=None 时 True；
- cameras：{camera: {仅发生过的计数键}}（LRU 淘汰后一并移除）。

摘要格式（C-138 §3 冻结，/api/understanding 与健康面共同消费）：
``{camera, summary, window_state,
   branches: [{branch_key, kind, status, text, sources, missing}],
   fusion: {version_id, status, items} | None}``
"""

import copy
import hashlib
import json
import math
import os
import threading
from collections import OrderedDict
from pathlib import Path

KINDS = ("l2", "l3", "l4")

# 加载文件字节上限默认值（C-139 §4 冻结：8MB）。
DEFAULT_MAX_LOAD_FILE_BYTES = 8 * 1024 * 1024
# 未知相机 LRU 上限默认值（C-139 §4 冻结：32）。
DEFAULT_MAX_KNOWN_CAMERAS = 32
# 尾部倒读的单块字节数（R2）：巨行防护与有界拼行的读取粒度。
_SCAN_CHUNK_BYTES = 65536

# 旧格式锚点（冻结）：加载记录缺全部锚点字段 → 标 legacy=True。
_KIND_ANCHORS = {
    "l2": ("status",),
    "l3": ("results", "branch", "status"),
    "l4": ("version_id",),
}

# 关键嵌套容器字段（C-140 §2）：加载记录携带时必须是 list（缺字段=旧格
# 式照常兼容；显式 null 视同缺字段）。按键存在性判定，不按 kind 分桶限
# 定——kind 文件里的 legacy 行同样覆盖。
_NESTED_LIST_FIELDS = ("items", "results", "frame_refs", "sources")
# window 四元身份字段（C-140 §2）：携带时必须是 str/int（bool 不算 int）。
_WINDOW_ID_FIELDS = ("camera_id", "run_id", "config_version", "window_id")

# 摘要分支行数上限（与默认 max_per_camera 同量级；多窗多材料包下防无界）。
_MAX_SUMMARY_BRANCHES = 50

# 分支状态 → 展示类别（C-138 §2 终态集 + L3 §8 八值；未知如实归 other）。
_BRANCH_DONE = frozenset({"ok", "partial"})
_BRANCH_FAILED = frozenset({"model_failed", "infer_failed",
                            "model_unavailable", "timeout",
                            "backend_isolated", "unsupported", "error"})
_BRANCH_EVICTED = frozenset({"expired", "queue_evicted", "stale_identity",
                             "identity_rejected", "stop_cancelled"})
_BRANCH_PENDING = frozenset({"pending", "waiting", "producing"})

BRANCH_FIELDS = ("branch_key", "kind", "status", "text", "sources", "missing")


class _NonFiniteNumber(ValueError):
    """JSON 文本含 NaN/Infinity 或溢出为非有限 float 的内部信号。"""


def _reject_json_constant(token):
    """json.loads 的 parse_constant 钩子：NaN/Infinity 字面量即拒绝。"""
    raise _NonFiniteNumber(token)


def _finite_float(text):
    """json.loads 的 parse_float 钩子：1e400 这类溢出同样按非有限拒绝。"""
    value = float(text)
    if not math.isfinite(value):
        raise _NonFiniteNumber(text)
    return value


def branch_category(status):
    """分支状态 → done|failed|evicted|pending|other（未知不冒充分类）。"""
    s = str(status or "").strip().lower()
    if s in _BRANCH_DONE:
        return "done"
    if s in _BRANCH_FAILED:
        return "failed"
    if s in _BRANCH_EVICTED:
        return "evicted"
    if s in _BRANCH_PENDING:
        return "pending"
    return "other"


def branch_counts(branches):
    """按展示类别计数（固定五键，健康面与摘要行共用）。"""
    counts = {"pending": 0, "done": 0, "failed": 0, "evicted": 0, "other": 0}
    for row in branches or ():
        status = row.get("status") if isinstance(row, dict) else row
        counts[branch_category(status)] += 1
    return counts


def latest_source_fields(l2_recs, l3_recs):
    """健康面来源标注字段：最新 model_ref 与 calibrated。

    model_ref 优先取 L3 分支结果（描述文本的真实来源），逐条 results 内
    查不到再退回记录顶层，最后退回 L2 记录；calibrated 取最近一条带该
    字段的 L2 记录（False=模型推断未经校准，必须如实标注）。都没有时
    model_ref=""、calibrated=None——绝不编造身份。
    """
    model_ref = ""
    for rec in reversed(list(l3_recs or ())):
        if not isinstance(rec, dict):
            continue
        results = rec.get("results")
        if isinstance(results, list):
            for entry in reversed(results):
                if isinstance(entry, dict) and entry.get("model_ref"):
                    model_ref = str(entry["model_ref"])
                    break
        if not model_ref and rec.get("model_ref"):
            model_ref = str(rec["model_ref"])
        if model_ref:
            break
    if not model_ref:
        for rec in reversed(list(l2_recs or ())):
            if isinstance(rec, dict) and rec.get("model_ref"):
                model_ref = str(rec["model_ref"])
                break
    calibrated = None
    for rec in reversed(list(l2_recs or ())):
        if isinstance(rec, dict) and "calibrated" in rec:
            calibrated = bool(rec["calibrated"])
            break
    return {"model_ref": model_ref, "calibrated": calibrated}


def _resolve_within(root, *parts):
    """root + parts 的解析路径；越出 root 即拒绝（真实父子，非前缀串）。

    ``store-a`` 与 ``store-ab`` 这类前缀同名目录靠 is_relative_to 的真实
    父子判定区分；``..`` 逃逸与落到 root 本身的路径都拒绝。
    """
    root_path = Path(root)
    resolved = root_path.joinpath(*parts).resolve()
    root_resolved = root_path.resolve()
    if resolved == root_resolved or \
            not resolved.is_relative_to(root_resolved):
        raise ValueError("understanding path escaped store root")
    return resolved


def _camera_key(camera):
    """摘要目录键：sha256 前 16 位 hex（用户输入不进入文件路径）。"""
    key = hashlib.sha256(camera.encode("utf-8")).hexdigest()[:16]
    if not len(key) == 16:
        raise ValueError("understanding camera key must be 16 hex chars")
    return key


def _validate_camera(camera):
    if not isinstance(camera, str) or not camera or len(camera) > 200:
        raise ValueError(
            "camera must be a non-empty string of at most 200 chars")
    return camera


def _clip(text, limit=60):
    s = " ".join(str(text).split())
    return s if len(s) <= limit else s[:limit] + "…"


def _norm_branch_key(value):
    """branch_key 归一为显示字符串（list/tuple 逐段拼接，None 段留空）。"""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "|".join("" if p is None else str(p) for p in value)
    return str(value)


def _entry_text(entry):
    """分支描述文本：观察+推断原文拼接；失败条目退回 reason；绝不编造。"""
    parts = []
    for item in (entry.get("observation"), entry.get("inference")):
        text = item.get("text") if isinstance(item, dict) else item
        if isinstance(text, str) and text.strip():
            parts.append(_clip(text, 400))
    model_unknown = entry.get("model_unknown")
    unknown_text = (model_unknown.get("text")
                    if isinstance(model_unknown, dict) else None)
    if isinstance(unknown_text, str) and unknown_text.strip():
        parts.append("模型未确认：" + _clip(unknown_text, 400))
    if parts:
        return "；".join(parts)
    reason = entry.get("reason")
    if isinstance(reason, str) and reason.strip():
        return _clip(reason, 400)
    return ""


def _branch_row(entry, rec):
    """单条分支结果 → 冻结六字段行；不可解释的条目返回 None。"""
    if not isinstance(entry, dict):
        return None
    kind = entry.get("branch") or rec.get("branch") or "unknown"
    status = entry.get("status") or rec.get("status") or "unknown"
    key = _norm_branch_key(entry.get("branch_key"))
    if not key:
        key = _norm_branch_key([rec.get("window"), kind,
                                entry.get("crop_id")]) or str(kind)
    sources = entry.get("sources")
    missing = entry.get("missing")
    return {
        "branch_key": key,
        "kind": str(kind),
        "status": str(status),
        "text": _entry_text(entry),
        "sources": list(sources) if isinstance(sources, list) else [],
        "missing": dict(missing) if isinstance(missing, dict) else {},
    }


def _latest_gate_reason(l2_recs):
    """最近一条 L1 门控未产出原因（兜底路径的真实淘汰/等待原因）。"""
    for rec in reversed(l2_recs):
        gate = rec.get("gate_reason")
        if isinstance(gate, str) and gate:
            return gate
    return None


def _latest_text(branches, kind):
    """最新一条有文本的分支描述；kind=None 表示任意非全景（局部）。"""
    for row in reversed(branches):
        if not row.get("text"):
            continue
        if kind is None:
            if row.get("kind") != "panorama":
                return row["text"]
        elif row.get("kind") == kind:
            return row["text"]
    return ""


def build_summary(camera, l2_recs, l3_recs, l4_recs):
    """C-138 §3 冻结摘要：记录驱动、只读、无语义改写。

    - branches：来自 l3 记录（``results`` 列表逐条；记录自身为扁平分支
      条目时按单条处理）；同 branch_key 后写覆盖（重试/更新取最新）；
    - window_state：最近一条带 ``window_state`` 的 l2/l3 记录；没有如实
      None（等待中分支不在已保存记录里，由 runtime 活跃面提供）；
    - fusion：最近一条带 version_id 的 l4 记录 → {version_id,status,items}；
    - summary：给人看的中文一行（计数+门控原因+全景/局部最新文本+融合
      版本），有界截断，不改写模型文本语义。
    """
    l2 = [r for r in (l2_recs or ()) if isinstance(r, dict)]
    l3 = [r for r in (l3_recs or ()) if isinstance(r, dict)]
    l4 = [r for r in (l4_recs or ()) if isinstance(r, dict)]

    window_state = None
    for rec in reversed(l2 + l3):
        ws = rec.get("window_state")
        if isinstance(ws, str) and ws:
            window_state = ws
            break

    rows = {}
    for rec in l3:
        results = rec.get("results")
        if isinstance(results, list) and results:
            entries = results
        elif any(k in rec for k in ("branch", "branch_key", "status")):
            entries = [rec]
        else:
            continue
        for entry in entries:
            row = _branch_row(entry, rec)
            if row is not None:
                rows[row["branch_key"]] = row
    branches = list(rows.values())[-_MAX_SUMMARY_BRANCHES:]

    fusion = None
    for rec in reversed(l4):
        version_id = rec.get("version_id")
        if version_id is None:
            continue
        items = rec.get("items")
        fusion = {"version_id": str(version_id),
                  "status": str(rec.get("status") or "unknown"),
                  "items": ([it for it in items if isinstance(it, dict)]
                            if isinstance(items, list) else [])}
        break

    counts = branch_counts(branches)
    parts = []
    if branches:
        parts.append("分支 完成 {done} / 失败 {failed} / 淘汰 {evicted}"
                     " / 等待 {pending}".format(**counts))
    gate = _latest_gate_reason(l2)
    if gate:
        parts.append("关系识别不可用（{}）".format(gate))
    panorama = _latest_text(branches, "panorama")
    local = _latest_text(branches, None)
    if panorama:
        parts.append("全景：" + _clip(panorama))
    if local:
        parts.append("局部：" + _clip(local))
    if fusion is not None:
        parts.append("融合版本 {}（{}）".format(fusion["version_id"][:12],
                                               fusion["status"]))
    summary = "；".join(parts) if parts else "暂无已完成的分支结果"
    return {"camera": camera, "summary": summary,
            "window_state": window_state,
            "branches": branches, "fusion": fusion}


def _nested_shallow_check(record, count):
    """C-140 §2 关键嵌套浅校验（只一层，不做深度递归；加载路径专用）。

    返回 False = 整条拒绝（bad_structure 已计数，调用方跳过该记录，不冒
    充完整历史）；返回 True = 可入预算池——items/results 中的非 dict 条
    目已就地剔除（逐条计入 bad_structure），记录本身保留。只拒绝「字段
    存在但类型错误」：缺字段与显式 null 都是旧格式，兼容放行。
    """
    for field in _NESTED_LIST_FIELDS:
        value = record.get(field)
        if value is not None and not isinstance(value, list):
            count("bad_structure")
            return False
    version_id = record.get("version_id")
    if version_id is not None and not isinstance(version_id, str):
        count("bad_structure")
        return False
    for field in _WINDOW_ID_FIELDS:
        value = record.get(field)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            count("bad_structure")
            return False
    for field in ("items", "results"):
        entries = record.get(field)
        if isinstance(entries, list):
            kept = [entry for entry in entries if isinstance(entry, dict)]
            dropped = len(entries) - len(kept)
            if dropped:
                count("bad_structure", dropped)
                record[field] = kept
    return True


class UnderstandingStore:
    """理解结果有界存储（线程安全；root=None 为纯内存模式）。

    runtime 持实例并在分支终态/融合版本产出时 ``append(camera, kind,
    record)``；工作台经 ``summary``/``history`` 只读消费。记录结构由
    runtime 定义（自带 branch_key/results/window_state 等字段），本类
    只负责有界存储、原子落盘与诊断计数，不解释语义。

    C-139 §4：append 即深拷贝隔离；读取返回深拷贝副本；加载流式逐行
    且受 文件字节/行字节/记录数/解析 四类预算约束；未知相机 LRU 有界。
    """

    def __init__(self, root=None, *, max_per_camera=50,
                 max_record_bytes=64 * 1024, load_budget_records=400,
                 max_load_file_bytes=DEFAULT_MAX_LOAD_FILE_BYTES,
                 max_known_cameras=DEFAULT_MAX_KNOWN_CAMERAS):
        if max_per_camera < 1:
            raise ValueError("max_per_camera must be >= 1")
        if max_record_bytes < 1:
            raise ValueError("max_record_bytes must be >= 1")
        if load_budget_records < 0:
            raise ValueError("load_budget_records must be >= 0")
        if max_load_file_bytes < 1:
            raise ValueError("max_load_file_bytes must be >= 1")
        if max_known_cameras < 1:
            raise ValueError("max_known_cameras must be >= 1")
        self._root = Path(root) if root is not None else None
        self._max_per_camera = int(max_per_camera)
        self._max_record_bytes = int(max_record_bytes)
        self._load_budget = int(load_budget_records)
        self._max_load_file_bytes = int(max_load_file_bytes)
        self._max_known_cameras = int(max_known_cameras)
        self._lock = threading.RLock()
        self._history = {}            # camera -> {kind: [record, ...]}
        self._loaded = set()          # 已懒加载过的相机（仅磁盘模式有意义）
        self._cam_counters = {}       # camera -> 逐相机诊断计数
        self._cam_order = OrderedDict()  # camera -> True（末尾=最近写入）
        self._diag = {"appended": 0, "rotated": 0, "record_too_large": 0,
                      "non_finite_rejected": 0,
                      "bad_lines": 0, "bad_structure": 0,
                      "load_bad_lines": 0,
                      "load_oversized_lines": 0, "load_non_finite": 0,
                      "load_parsed_records": 0,
                      "load_file_too_large": 0, "load_truncated_oldest": 0,
                      "persist_failed": 0, "cameras_evicted": 0}

    # ---- 写入 --------------------------------------------------------------

    def append(self, camera, kind, record: dict) -> bool:
        """追加一条记录；落盘失败返回 False + persist_failed 计数。

        C-139 §4 隔离与校验（决策冻结）：
        - 入口 json round-trip 深拷贝（allow_nan=False）：嵌套结构全隔离，
          顶层/嵌套含 NaN/Inf → 拒绝（False + non_finite_rejected）；
        - 记录超单条字节上限 → 拒绝（False + record_too_large），不入历史；
        - 接口误用（相机/kind/记录类型不合法、记录不可序列化）当场
          ValueError——这是接线缺陷，不得静默吞掉。
        副作用：非字符串 dict 键序列化为字符串、tuple 变 list（记录本就
        按 JSON 落盘，读回即此形状）。
        """
        _validate_camera(camera)
        if kind not in KINDS:
            raise ValueError("kind must be one of {}".format(KINDS))
        if not isinstance(record, dict):
            raise ValueError("record must be a dict")
        non_finite = False
        line = None
        try:
            line = json.dumps(record, ensure_ascii=False,
                              allow_nan=False) + "\n"
        except TypeError as exc:
            raise ValueError(
                "record must be JSON-serializable") from exc
        except ValueError:
            # allow_nan=False：顶层或嵌套含 NaN/Inf → 校验拒绝，不入历史
            non_finite = True
        payload = None if non_finite else line.encode("utf-8")
        with self._lock:
            self._note_write_locked(camera)
            if non_finite:
                self._diag["non_finite_rejected"] += 1
                self._bump_cam(camera, "non_finite_rejected")
                return False
            if len(payload) > self._max_record_bytes:
                self._diag["record_too_large"] += 1
                self._bump_cam(camera, "record_too_large")
                return False
            isolated = json.loads(line)   # 完全独立的副本（json round-trip）
            self._ensure_loaded_locked(camera)
            history = self._history.setdefault(
                camera, {k: [] for k in KINDS}).setdefault(kind, [])
            history.append(isolated)
            self._diag["appended"] += 1
            self._bump_cam(camera, "appended")
            rotated = 0
            while len(history) > self._max_per_camera:
                history.pop(0)
                rotated += 1
            if rotated:
                self._diag["rotated"] += rotated
                self._bump_cam(camera, "rotated", rotated)
            if self._root is None:
                return True
            try:
                self._write_file_locked(camera, kind, history)
            except (OSError, ValueError, TypeError):
                # 落盘失败不回滚内存：查看能力不因磁盘故障消失
                self._diag["persist_failed"] += 1
                self._bump_cam(camera, "persist_failed")
                return False
            return True

    # ---- 读取 --------------------------------------------------------------

    def history(self, camera, kind) -> list:
        """有界读取：该相机该 kind 记录的深拷贝副本（旧→新）。

        改返回值（含嵌套 sources/results/items）不污染内部历史。
        """
        _validate_camera(camera)
        if kind not in KINDS:
            raise ValueError("kind must be one of {}".format(KINDS))
        with self._lock:
            self._ensure_loaded_locked(camera)
            return [copy.deepcopy(record)
                    for record in self._history.get(camera, {}).get(kind, ())]

    def summary(self, camera) -> dict:
        """C-138 §3 冻结摘要（build_summary 组装；供 /api/understanding）。

        输入记录先深拷贝再组装：改返回值（branches[].sources、
        fusion.items 等）不污染内部历史与已存文件。
        """
        _validate_camera(camera)
        with self._lock:
            self._ensure_loaded_locked(camera)
            cams = self._history.get(camera, {})
            l2 = [copy.deepcopy(r) for r in cams.get("l2", ())]
            l3 = [copy.deepcopy(r) for r in cams.get("l3", ())]
            l4 = [copy.deepcopy(r) for r in cams.get("l4", ())]
        return build_summary(camera, l2, l3, l4)

    def snapshot(self) -> dict:
        """诊断快照（冻结字段集；不含路径、凭据或记录内容）。"""
        with self._lock:
            return {
                "appended": self._diag["appended"],
                "rotated": self._diag["rotated"],
                "record_too_large": self._diag["record_too_large"],
                "non_finite_rejected": self._diag["non_finite_rejected"],
                "bad_lines": self._diag["bad_lines"],
                "bad_structure": self._diag["bad_structure"],
                "load_bad_lines": self._diag["load_bad_lines"],
                "load_oversized_lines": self._diag["load_oversized_lines"],
                "load_non_finite": self._diag["load_non_finite"],
                "load_parsed_records": self._diag["load_parsed_records"],
                "load_file_too_large": self._diag["load_file_too_large"],
                "load_truncated_oldest": self._diag["load_truncated_oldest"],
                "persist_failed": self._diag["persist_failed"],
                "cameras_evicted": self._diag["cameras_evicted"],
                "memory_only": self._root is None,
                "cameras": {cam: dict(counters)
                            for cam, counters in self._cam_counters.items()},
            }

    # ---- 内部 --------------------------------------------------------------

    def _bump_cam(self, camera, key, delta=1):
        counters = self._cam_counters.setdefault(camera, {})
        counters[key] = counters.get(key, 0) + delta

    def _admit_camera_locked(self, camera, *, count_eviction=True):
        """相机进入驻留集（读写路径共用）；超上限淘汰最久未写者。

        只淘汰**内存**（历史/计数/懒加载标记）；磁盘文件不动——被淘汰
        相机再次被访问时按哈希键重新懒加载恢复（读路径以「不在驻留集
        才插入」准入，读洪水同样有界；写路径另触碰最近序）。只有写路径
        的淘汰计入 cameras_evicted：读路径懒加载恢复触发的置换不计数
        ——该诊断反映「最久未写相机被淘汰」的次数，恢复不算新的写侧
        淘汰（冻结语义：懒加载恢复不计淘汰）。
        """
        if camera in self._cam_order:
            return
        self._cam_order[camera] = True
        while len(self._cam_order) > self._max_known_cameras:
            eldest = self._cam_order.popitem(last=False)[0]
            self._history.pop(eldest, None)
            self._cam_counters.pop(eldest, None)
            self._loaded.discard(eldest)
            if count_eviction:
                self._diag["cameras_evicted"] += 1

    def _note_write_locked(self, camera):
        """写路径准入 + 触碰 LRU（最近写者排末尾；淘汰目标=最久未写）。"""
        self._admit_camera_locked(camera)
        self._cam_order.move_to_end(camera)

    def _record_path(self, camera, kind):
        return _resolve_within(self._root, _camera_key(camera),
                               kind + ".jsonl")

    def _ensure_loaded_locked(self, camera):
        """首次访问某相机时懒加载其磁盘历史（预算内取最新；坏行跳过）。

        存储层不持有相机名单：磁盘目录键是哈希，懒加载按请求相机的键
        精确读取，不做哈希反查，也不扫描陌生目录。加载经
        ``_scan_kind_locked`` 从文件尾部向前分块倒读（绝不整文件 read，
        绝不整行缓冲超长行），记录级预算在扫描过程中即时生效；跨 kind
        预算按「共享总预算 + 轮转取最新」分配——每 kind 的预算池上限为
        load_budget_records+1，轮转总量受总预算约束，单一 kind 无法耗尽
        其他 kind 的份额。
        """
        if self._root is None or camera in self._loaded:
            return
        # 读路径准入：懒加载恢复触发的置换不计入 cameras_evicted
        self._admit_camera_locked(camera, count_eviction=False)
        self._loaded.add(camera)
        buckets = self._history.setdefault(camera, {k: [] for k in KINDS})
        valid = {kind: self._scan_kind_locked(camera, kind) for kind in KINDS}
        budget = self._load_budget
        cursors = {kind: len(valid[kind]) for kind in KINDS}
        kept = {kind: [] for kind in KINDS}
        taken = 0
        while taken < budget:
            progressed = False
            for kind in KINDS:
                if taken >= budget:
                    break
                cursor = cursors[kind]
                if cursor > 0:
                    cursor -= 1
                    cursors[kind] = cursor
                    kept[kind].append(valid[kind][cursor])
                    taken += 1
                    progressed = True
            if not progressed:
                break
        truncated = sum(len(valid[kind]) - len(kept[kind]) for kind in KINDS)
        if truncated:
            self._diag["load_truncated_oldest"] += truncated
            self._bump_cam(camera, "load_truncated_oldest", truncated)
        for kind in KINDS:
            bucket = buckets.setdefault(kind, [])
            bucket.extend(reversed(kept[kind]))
            # 加载期截断不计 rotated（磁盘未动；后续 append 触发重写时收敛）
            del bucket[:-self._max_per_camera]

    def _scan_kind_locked(self, camera, kind):
        """尾部向前分块倒读单个 kind 文件 → 有效记录（旧→新；预算内最新）。

        C-139-R2：扫描过程中即时实施全部预算——
        - 文件字节：先 stat，stat 即超 max_load_file_bytes → 整体拒载 +
          load_file_too_large（内存已有内容保留）；读取端
          end=min(实际大小, stat 大小)——stat 后文件被追加也只读 stat 时
          快照，绝不无界分配；总读取字节 ≤ max_load_file_bytes 由构造
          保证（超限者已在 stat 处拒载）。
        - 行字节：拼行缓冲（当前行尚未见左边界 \n 的尾部段）超过
          max_record_bytes×2 → 判定巨行：停止缓冲 + load_oversized_lines
          计一次，直接丢弃直至该行起点边界（同一行绝不重复计数，也绝不
          整行读入内存）；完整行超 max_record_bytes（但 ≤ 硬上限，可完整
          缓冲）→ 同样跳过 + 计数。内存峰值 ≤ max_record_bytes×2 + 单块。
        - 记录数：倒读=最新优先，预算池达 load_budget_records+1 即停止
          扫描（第 budget+1 条仅确认截断发生并作轮转备用）；跨 kind 由
          外层轮转按共享总预算取最新，单一 kind 无法耗尽其他 kind。
        - 解析：坏 JSON → bad_lines；顶层非 dict 或 status/kind 关键字段
          类型/值域不过 → load_bad_lines；关键嵌套字段存在但类型错误 →
          bad_structure（C-140 §2：整条拒绝，items/results 内非 dict 条
          目就地剔除并逐条计数）；NaN/Inf（含 1e400 溢出）→
          load_non_finite；通过者计入 load_parsed_records（预算池证据）。
          旧格式（缺 _KIND_ANCHORS[kind] 全部锚点）→ 标 legacy=True。
        任何一步失败只损失该行/该文件，绝不拖垮接口；读中途 OSError →
        整个文件放弃（不可读文件不产生部分历史）。
        """
        try:
            path = self._record_path(camera, kind)
        except ValueError:
            return []
        try:
            if not path.exists():
                return []
            size = path.stat().st_size
        except OSError:
            return []
        if size > self._max_load_file_bytes:
            self._diag["load_file_too_large"] += 1
            self._bump_cam(camera, "load_file_too_large")
            return []

        hard_cap = self._max_record_bytes * 2
        budget_stop = self._load_budget + 1
        newest_first = []

        def count(key, delta=1):
            self._diag[key] = self._diag.get(key, 0) + delta
            self._bump_cam(camera, key, delta)

        def admit(raw):
            """单行 bytes → 记录 dict（各类预算内跳过均在此计数）→ None。"""
            if len(raw) > self._max_record_bytes:
                count("load_oversized_lines")
                return None
            try:
                obj = json.loads(raw, parse_float=_finite_float,
                                 parse_constant=_reject_json_constant)
            except _NonFiniteNumber:
                count("load_non_finite")
                return None
            except ValueError:
                # 含坏 JSON 与非法 UTF-8（UnicodeDecodeError）
                count("bad_lines")
                return None
            if not isinstance(obj, dict):
                count("load_bad_lines")
                return None
            # 关键字段浅校验（存在才校验；字段缺失交由 legacy 锚点逻辑）
            if ("status" in obj and not isinstance(obj["status"], str)) or \
                    ("kind" in obj and (not isinstance(obj["kind"], str)
                                        or obj["kind"] not in KINDS)):
                count("load_bad_lines")
                return None
            # 关键嵌套浅校验（C-140 §2）：items/results/frame_refs/sources
            # 存在但非 list、version_id 非 str、window 四元字段非 str/int
            # → 整条跳过 + bad_structure；items/results 内非 dict 条目就地
            # 剔除。缺字段与 null 的旧格式照常兼容放行。
            if not _nested_shallow_check(obj, count):
                return None
            count("load_parsed_records")
            if not any(anchor in obj for anchor in _KIND_ANCHORS[kind]):
                obj = dict(obj)
                obj["legacy"] = True
            return obj

        try:
            with path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                end = min(handle.tell(), size)   # stat 后增长：只读快照大小
                pos = end
                buf = b""
                skipping = False   # 正在跳过一条超硬上限的巨行
                stop = False
                while pos > 0 and not stop:
                    step = min(_SCAN_CHUNK_BYTES, pos)
                    pos -= step
                    handle.seek(pos)
                    chunk = handle.read(step)
                    if not chunk:
                        break
                    buf = chunk + buf
                    while buf:
                        if skipping:
                            # 巨行内容无换行，倒序扫描中其**起点**是 buf 里
                            # 最后一个 \n（rfind）：该边界之后是巨行在本块的
                            # 尾段（丢弃），边界之前是更旧记录的完整行（必须
                            # 保留，交回正常 rfind 循环最新优先逐条提取）。
                            # 取 find（第一个 \n）会把两条边界之间的完整
                            # 合法行当巨行内容误吞（C-140-R1 修复）。
                            nl = buf.rfind(b"\n")
                            if nl == -1:
                                buf = b""      # 整块都是巨行内容：整段丢弃
                                break
                            buf = buf[:nl]
                            skipping = False
                            continue
                        nl = buf.rfind(b"\n")
                        if nl == -1:
                            if len(buf) > hard_cap:
                                # 拼行超硬上限仍无行边界 → 巨行：停缓冲
                                count("load_oversized_lines")
                                skipping = True
                                buf = b""
                                continue
                            break
                        line = buf[nl + 1:]    # 当前未决行中最新的一条
                        buf = buf[:nl]
                        if not line.strip():
                            continue
                        obj = admit(line)
                        if obj is not None:
                            newest_first.append(obj)
                            if len(newest_first) >= budget_stop:
                                stop = True    # 预算池满：停止扫描
                                break
                if not stop and not skipping and buf.strip():
                    # 文件首行（最旧；无前导边界），预算未满则照常入池
                    obj = admit(buf)
                    if obj is not None:
                        newest_first.append(obj)
        except OSError:
            return []
        newest_first.reverse()   # 旧→新（预算池，≤ load_budget_records+1）
        return newest_first

    def _write_file_locked(self, camera, kind, history):
        """全量原子重写（tmp + Path.replace）：轮转后磁盘同步收敛。"""
        path = self._record_path(camera, kind)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        try:
            with tmp.open("w", encoding="utf-8") as handle:
                for item in history:
                    handle.write(json.dumps(item, ensure_ascii=False) + "\n")
            tmp.replace(path)
        except Exception:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise
