"""win11_l4.py —— L4 结构化渐进融合（C-136 §四 + C-137 §5 + C-138 §4）：
纯规则。

职责与语义（零模型依赖、零 cv2、零 I/O）：
- fuse(input) -> FusionVersion：单次结构化融合。身份校验（窗口前三元与
  构造绑定不符→FusionIdentityRejected；材料对象引用内嵌 {cam}:{run}: 前缀
  与输入身份不符同判拒绝；L3 分支结果自带 window 与输入顶层四元逐字段
  核对，不符→拒绝并带逐分支原因清单，C-137 D2；拒绝不产版本不产 items）
  → 指纹（sha256(输入指纹序 v3)，同指纹幂等返回同一版本对象）→ 逐条
  结构化融合（不拼接文本冒充）。
- accumulate(window_key, input) -> FusionVersion（C-137 D3 + C-138 B1/B2，
  runtime 接线入口）：同窗累计**结构化材料集**（非渲染条目）——原始 L1
  引用/L2 候选/L3 分支结果/失败/缺失清单按材料身份（指纹行）入累计集，
  每次新材料到达针对**累计集**重新计算冲突与条目：先"1个人"后"2个人"、
  先关系候选后否定叙事（或任意反序/交错到达），最终 items/conflict/
  sources 一致（确定性；created_mono 允许不同；累计指纹行按字节排序去
  重，同累计集必同 version_id）。后版本携带前版本全部 frame_refs 并集
  （各帧自带 coord_space 声明）/sources/对象引用/缺失因素+新材料；坐标
  体系/时钟不可比显式标记，不继承新声明、不覆盖旧材料。相同累计材料集
  （同累计指纹）重复提交→返回既有版本不追加；window_key 前三元与绑定、
  四元与输入顶层不符→拒绝；已归档窗口只读（再累计 ValueError）；
  versions(window_key) 只读时间序。
- 缓存预算（C-138 B3）：窗口级硬上限 max_active_windows（默认
  MAX_ACTIVE_WINDOWS=16，构造可覆盖）——活跃+归档窗口总数超限**真淘汰**
  最旧活跃窗（从缓存删除，versions(key) 不可达；正在累计的窗口绝不自淘
  汰；无活跃窗可淘汰时才淘汰最旧归档窗）。淘汰契约：被淘汰窗的版本必须
  已持久化——调用方在淘汰前保存，或构造时提供 evict_callback(window_key,
  versions) 由本阶段在删除前回调交出数据（回调异常原样抛出：正在淘汰的
  窗保持未删，此前已成功淘汰的窗保持已删，本次累计不产版本）。淘汰/
  cleanup 只影响活跃缓存，不影响调用方持久化历史；淘汰后同指纹重提交
  视为新材料（如实计数，防重复提醒是 runtime 责任）。每窗版本上限
  MAX_WINDOW_VERSIONS=32 的 archived 标记语义保留；窗口两态
  active/archived（archive_window(key) 终结归档、仍占缓存直到 cleanup）
  同在 max_active_windows 预算内。
- 确定性三级：L1 对象事实引用→observation/observed；L2 候选与 L3 文本→
  observation|inference/model_inferred（模型自报 confirmed/安全不升级为
  系统核实）；缺失/失败/冲突/时钟不可比→gap|conflict/unknown。
- 对齐与去重（同窗口内）：对象引用对齐（object_id 全等才可合并；无稳定
  身份的帧内引用绝不跨引用合并为同一对象）；重复结论合并（同文本合并为
  一条展示，来源并集保留全部 crop/分支/model 来源，C-137 D4；来源引用为
  内容身份 branch_kind[@crop_id][|model_ref]，纯数据可 JSON 持久化）；
  时空对齐字段（coord_space/frame_refs，C-137 D5 + C-138 B2）只声明不
  换算——空间重叠绝不合并对象；同坐标体系内无共同稳定身份的重叠区域
  保留双方+不确定性 gap（进入 partial）；跨坐标体系不比较不换算（多体
  系并存 → "坐标体系不一致"标记，各自声明保留）；不可比时钟不做任何
  时间排序。
- 冲突保留双方：人数描述不一致（确定性中文/数字计数抽取）与关系候选 vs
  叙事否定（确定性否定线索+关系词同现）→ 双方条目并存 + conflict 记录；
  不投票、不按最高分强选、不抹掉任何一方；冲突检测在累计集上重算
  （C-138 B1），跨批次到达的矛盾必被检出。
- 渐进版本：部分结果先成版本；材料集变化→新版本追加（versions 时间序，
  旧版本原样保留，不重新打开已结束事件——本模块无任何事件生命周期 API）。
- 因素透传（C-137 D6）：failures/gaps/取消/预算淘汰逐项进入版本 gap
  条目；clock_kinds 原样传播（是什么 propagated 什么，绝不恒传空清单、
  绝不写死 host_receive）；不确定因素进入 status 判定（partial）。
- 模型"安全/无异常"文本→仅 observation 记录；本模块无"关闭事件/撤销
  提醒/压制告警"类 API，输出形状也不携带动作语义（固定回归）。
- 状态：ok=有观察/推断且无 gap/conflict 因素；partial=有内容但存在缺失/
  失败/冲突/时钟不可比/对齐不确定因素；insufficient=无任何观察与推断。

生产调用顺序示例（C-138 §4，Agent A runtime 接线；与
tests/test_win11_l4.py 构造方式一致，逐行可运行）：

    from scam.win11_l4 import L4Stage
    from scam.win11_l4_contract import FusionInput

    # 1) 构造：绑定窗口前三元；可选缓存预算与淘汰回调（回调在删除前收到
    #    (window_key, versions)，供调用方持久化后再淘汰）：
    stage = L4Stage("cam-1", "run-1", "cfg-1")
    # 或： L4Stage("cam-1", "run-1", "cfg-1", max_active_windows=16,
    #              evict_callback=lambda key, versions: store.save(key, versions))

    key = ("cam-1", "run-1", "cfg-1", "w-1")      # window_key 四元

    # 2) 每批材料到达即累计（L1 引用/L2 候选/L3 分支结果按冻结合同形态
    #    传入；失败/取消/缺失随 failures/gaps 逐项入账）——返回该窗最新
    #    FusionVersion（version_id/status/items/frame_refs 等，确定性）：
    v1 = stage.accumulate(key, FusionInput(
        "cam-1", "run-1", "cfg-1", "w-1",
        l3_branches=(l3_result,),                 # L3BranchResult 元组
        clock_kinds=("source_capture",)))
    v2 = stage.accumulate(key, FusionInput(
        "cam-1", "run-1", "cfg-1", "w-1",
        l3_branches=(late_result,),               # 累计集自动含前版本材料
        failures=({"source": "l3", "code": "cancelled",
                   "detail": "分支取消"},),
        clock_kinds=("source_capture",)))

    # 3) 只读查询：
    versions = stage.versions(key)                # (v1, v2) 只读时间序
    counts = stage.snapshot()                     # 计数面（含窗口/淘汰计数）

    # 4) 窗口终结（版本已持久化后）：可选先归档（仍占缓存），再清理：
    stage.archive_window(key)                     # -> True；归档后再累计 ValueError
    summary = stage.cleanup(key)                  # -> {"removed_versions": 2, "archived": 0}
    stage.versions(key)                           # -> ()
"""

from __future__ import annotations

import re
import time

from scam.win11_l4_contract import (
    COMPARABLE_CLOCK_KIND,
    DEFAULT_COORD_SPACE,
    FUSION_KINDS,
    MAX_ACTIVE_WINDOWS,
    MAX_WINDOW_VERSIONS,
    WINDOW_STATES,
    FusionIdentityRejected,
    FusionInput,
    FusionItem,
    FusionSource,
    FusionVersion,
    clock_fingerprint_row,
    combine_coord_spaces,
    coords_fingerprint_row,
    cumulative_fingerprint_rows,
    enum_value,
    failure_fingerprint_row,
    fusion_fingerprint,
    frameref_fingerprint_row,
    gap_fingerprint_row,
    l1_fingerprint_rows,
    l2_fingerprint_rows,
    l3_fingerprint_rows,
    normalize_failure,
    normalize_gap,
    object_ref_camera_run,
    object_ref_id,
    object_ref_stable,
    rows_digest,
    window_fingerprint_row,
)

__all__ = [
    "FAILURE_STATUS_VALUES",
    "L4Stage",
    "NEGATION_CUES",
    "PERSON_COUNT_RE",
]

# L3 失败态冻结值（win11_l3_contract.L3Status 失败侧；与成功侧互斥不互冒充）
FAILURE_STATUS_VALUES = frozenset({
    "unsupported", "model_unavailable", "infer_failed", "timeout",
    "backend_isolated", "identity_rejected",
})

# 叙事否定线索（确定性子串；小写比较，中文不受影响；"not "带尾空格避免
# "nothing" 误报）。误报只多留一条 conflict 记录，绝不抑制任何一方——
# 失败方向是保守的（保留双方）。
NEGATION_CUES = ("没有", "未见", "并未", "并非", "未检测到", "未观察到",
                 "未出现", "no ", "not ", "without", "n't")

# 人数计数抽取（确定性；"没有人"无数词不命中）
PERSON_COUNT_RE = re.compile(r"([0-9]+|[一二两三四五六七八九十]+)\s*个?\s*人")
_CN_DIGIT = {"一": 1, "二": 2, "两": 2, "三": 3, "四": 4, "五": 5,
             "六": 6, "七": 7, "八": 8, "九": 9}

# L3 分支不确定性→缺失条目（unenhanced 是如实标注非缺失，不入 gap）
_L3_FACTOR_TEXTS = (
    ("frame_missing", "缺帧：前后帧缺失，无法确认拿起/放下/带走的完整过程"),
    ("frames_truncated", "帧数被预算截断：内容不完整"),
    ("pixels_downscaled", "输入降采样：细节受限"),
)

# L2 候选不确定性标注名（与合同指纹同源）
_CANDIDATE_UNCERTAINTY_FLAGS = (
    "frame_missing_prev", "frame_missing_next", "identity_uncertain",
    "drift", "pair_overlap_high", "low_confidence")


def _person_count(text):
    """叙事文本→人数声明（首个命中；无命中 None；非十/单字组合保守 None）。"""
    if not text:
        return None
    match = PERSON_COUNT_RE.search(text)
    if match is None:
        return None
    token = match.group(1)
    if token.isdigit():
        return int(token)
    if token == "十":
        return 10
    if token.startswith("十"):
        rest = _CN_DIGIT.get(token[1:])
        return 10 + rest if rest is not None else None
    if token.endswith("十"):
        head = _CN_DIGIT.get(token[0])
        return head * 10 if head is not None else None
    if len(token) == 1:
        return _CN_DIGIT.get(token)
    return None


def _narrative_negates(relation, text):
    """确定性规则：文本同时含否定线索与关系词（大小写不敏感）→ 叙事否定。"""
    token = str(relation).strip().lower()
    if not token:
        return False
    low = text.lower()
    return token in low and any(cue in low for cue in NEGATION_CUES)


def _candidate_flags_text(cand):
    """候选不确定性→确定性格式化后缀（无标注为空串）。"""
    unc = getattr(cand, "uncertainty", None)
    if unc is None:
        return ""
    active = [name for name in _CANDIDATE_UNCERTAINTY_FLAGS
              if getattr(unc, name, False)]
    return "；不确定性: " + "+".join(active) if active else ""


def _branch_ref(branch):
    """L3 分支来源引用（内容身份，非列表序；C-137 D4）：
    branch_kind[@crop_id][|model_ref]。

    同窗同类型不同裁图（不同 crop_id）→ 不同 ref——来源并集才能保留全部
    crop/分支/model 来源；crop_id/model_ref 缺省时退化为 branch_kind
    （不伪造来源细分）。
    """
    ref = str(enum_value(getattr(branch, "branch", "")))
    crop_id = getattr(branch, "crop_id", None)
    if crop_id not in (None, ""):
        ref += f"@{crop_id}"
    model_ref = getattr(branch, "model_ref", None)
    if model_ref not in (None, ""):
        ref += f"|{model_ref}"
    return ref


def _boxes_overlap(a, b):
    """归一化 [x,y,w,h] 区域对是否正面积重叠（确定性；边界相接不算）。"""
    ax, ay, aw, ah = (float(v) for v in a)
    bx, by, bw, bh = (float(v) for v in b)
    overlap_w = min(ax + aw, bx + bw) - max(ax, bx)
    overlap_h = min(ay + ah, by + bh) - max(ay, by)
    return overlap_w > 0 and overlap_h > 0


class _WindowState:
    """单窗累计状态（C-138 B1/B3）：**累计结构化材料集**——原始 L1 引用/
    L2 候选/L3 分支结果/失败/缺失清单/逐帧引用按材料身份（指纹行组字节）
    存集（非渲染条目），外加时钟类型并集、坐标体系声明集、窗口两态
    （active/archived）、版本时间序与指纹索引。每次累计针对累计集全量
    重算 items/conflict——跨批次到达的矛盾必被检出，任意到达顺序结果
    一致（确定性）。"""

    __slots__ = ("archived", "l1_refs", "l2_candidates", "l3_branches",
                 "failures", "gaps", "frame_refs", "clock_kinds",
                 "coord_spaces", "versions", "by_version_id")

    def __init__(self):
        self.archived = False
        self.l1_refs = {}
        self.l2_candidates = {}
        self.l3_branches = {}
        self.failures = {}
        self.gaps = {}
        self.frame_refs = {}
        self.clock_kinds = set()
        self.coord_spaces = set()
        self.versions = []
        self.by_version_id = {}

    def add_materials(self, input):
        """新输入材料并入累计集（键=材料指纹行组字节，内容身份；同身份
        再到达为无操作——集合语义）。"""
        for ref in input.l1_object_refs:
            self.l1_refs[_material_key(l1_fingerprint_rows(ref))] = ref
        for cand in input.l2_candidates:
            key = _material_key(l2_fingerprint_rows(cand))
            self.l2_candidates[key] = cand
        for branch in input.l3_branches:
            key = _material_key(l3_fingerprint_rows(branch))
            self.l3_branches[key] = branch
        for entry in input.failures:
            key = _material_key((failure_fingerprint_row(entry),))
            self.failures[key] = entry
        for entry in input.gaps:
            key = _material_key((gap_fingerprint_row(entry),))
            self.gaps[key] = entry
        for ref in input.frame_refs:
            key = _material_key((frameref_fingerprint_row(ref),))
            self.frame_refs[key] = ref
        self.clock_kinds.update(str(kind) for kind in input.clock_kinds)
        self.coord_spaces.add(str(input.coord_space))

    def identity_rows(self, window_row):
        """累计集指纹行（C-138 B1，确定性）：版本标记行 + 窗口行 + 全部
        材料身份行 + 时钟并集行 + 各坐标体系声明行，经
        cumulative_fingerprint_rows 排序去重——同累计集必同指纹，与到达
        顺序无关。"""
        rows = set(self.l1_refs)
        rows.update(self.l2_candidates)
        rows.update(self.l3_branches)
        rows.update(self.failures)
        rows.update(self.gaps)
        rows.update(self.frame_refs)
        rows.add(clock_fingerprint_row(self.clock_kinds))
        for space in self.coord_spaces:
            rows.add(coords_fingerprint_row(space))
        return cumulative_fingerprint_rows(window_row, rows)


def _material_key(rows):
    """材料身份键：指纹行组字节连接（确定性；即累计集的集合元素）。"""
    return b"".join(rows)


def _sorted_materials(mapping):
    """按身份键字节序取材料（确定性——与到达顺序无关）。"""
    return [mapping[key] for key in sorted(mapping)]


class L4Stage:
    """L4 融合阶段：fuse(input) 与 accumulate(window_key, input)（纯规则，
    构造绑定身份）。

    - 构造绑定 (camera_id, run_id, config_version)：输入窗口前三元任一不符
      → FusionIdentityRejected（identity_rejected），不产版本不产 items。
    - 幂等：同指纹重复提交返回同一版本对象，不重复追加。
    - fuse：单次融合（不累计前版本材料；幂等索引在阶段级）。
    - accumulate：同窗累计（C-137 D3 + C-138 B1/B2）——累计**结构化材料
      集**并针对累计集重算条目与冲突（任意到达顺序最终结果一致）；后版本
      携带前版本全部材料与时空声明；已归档窗口只读（再累计 ValueError）。
    - 缓存预算（C-138 B3，淘汰契约）：窗口总数（active+archived）硬上限
      max_active_windows——超限**真淘汰**最旧活跃窗。**淘汰前被淘汰窗的
      版本必须已持久化**：调用方在淘汰前保存，或构造时提供
      evict_callback(window_key, versions) 由本阶段在删除前回调交出数据
      （回调异常原样抛出：正在淘汰的窗保持未删，此前已成功淘汰的窗保持
      已删，本次累计不产版本）。淘汰/cleanup 只影响活跃缓存，不影响调用
      方持久化历史；淘汰后同指纹重提交视为新材料（如实计数，防重复提醒
      是 runtime 责任）。
    - 窗口两态（C-138 B3）：active ↔ archived（archive_window）；两态同在
      max_active_windows 预算内；cleanup 终结清理（两态皆可）。
    """

    def __init__(self, camera_id, run_id, config_version,
                 max_active_windows=MAX_ACTIVE_WINDOWS, evict_callback=None):
        max_active_windows = int(max_active_windows)
        if max_active_windows < 1:
            raise ValueError("max_active_windows must be >= 1, got "
                             f"{max_active_windows}")
        self.camera_id = camera_id
        self.run_id = run_id
        self.config_version = config_version
        self.max_active_windows = max_active_windows
        self._evict_callback = evict_callback
        self._versions = []
        self._by_version_id = {}
        self._windows = {}
        self._evicted_windows = 0
        self._counters = {"fused": 0, "accumulated": 0, "idempotent_hits": 0,
                          "identity_rejected": 0}

    # ---- 只读面 ------------------------------------------------------------

    def versions(self, window_key=None):
        """只读版本序列（时间序）。

        - window_key=None：fuse() 直融路径的阶段级版本（C-136 语义）；
        - 给定 window_key=(camera, run, config, window)：该窗口累计版本
          （C-137 D3；含 archived 标记版本；未累计过的窗口返回空）。
        """
        if window_key is None:
            return tuple(self._versions)
        state = self._windows.get(tuple(window_key))
        return tuple(state.versions) if state is not None else ()

    def snapshot(self):
        """运行面计数（含拒绝与幂等命中，不静默）。fused/versions 为 fuse
        直融路径；accumulated/windows*/archived_versions 为累计路径
        （windows_active+windows_archived=windows；windows_evicted 为累计
        真淘汰窗数——淘汰后 versions(key) 不可达）。"""
        archived = sum(
            sum(1 for v in state.versions if v.archived)
            for state in self._windows.values())
        archived_windows = sum(1 for state in self._windows.values()
                               if state.archived)
        return {
            "camera_id": self.camera_id,
            "run_id": self.run_id,
            "config_version": self.config_version,
            "fused": self._counters["fused"],
            "accumulated": self._counters["accumulated"],
            "idempotent_hits": self._counters["idempotent_hits"],
            "identity_rejected": self._counters["identity_rejected"],
            "versions": len(self._versions),
            "version_ids": tuple(v.version_id for v in self._versions),
            "windows": len(self._windows),
            "windows_active": len(self._windows) - archived_windows,
            "windows_archived": archived_windows,
            "windows_evicted": self._evicted_windows,
            "archived_versions": archived,
        }

    # ---- 融合入口 -----------------------------------------------------------

    def fuse(self, input):
        """单次结构化融合：身份校验 → 幂等检查 → 逐条 items → 版本
        （不累计前版本材料；累计走 accumulate）。"""
        self._check_binding(input)
        self._check_material_identity(input)
        version_id = fusion_fingerprint(input)
        existing = self._by_version_id.get(version_id)
        if existing is not None:
            self._counters["idempotent_hits"] += 1
            return existing
        items = tuple(item for _, item in self._build_entries(input))
        version = self._new_version(version_id, items, input)
        self._versions.append(version)
        self._by_version_id[version_id] = version
        self._counters["fused"] += 1
        return version

    def accumulate(self, window_key, input):
        """同窗累计融合（C-137 §5/D3 + C-138 §4 B1/B2，runtime 接线入口）。

        - window_key=(camera_id, run_id, config_version, window_id)：前三元
          与阶段绑定、四元与输入顶层任一不符 → FusionIdentityRejected
          （不产版本；D2 材料身份校验同 fuse）。
        - 累计**结构化材料集**（按材料身份存原始 L1/L2/L3/失败/缺失/逐帧
          引用）：每次调用针对累计集重算 items 与冲突——任意到达顺序最终
          items/conflict/sources 一致；后版本携带前版本全部材料、
          frame_refs 并集（各帧自带 coord_space 声明）与缺失因素；坐标
          体系/时钟不可比显式标记，不覆盖旧材料。
        - 相同累计材料集（同累计指纹）重复提交 → 返回既有版本，不追加。
        - 版本父子（C-139-R1 §2）：该窗首版 parent_version_id=None，后续
          新版本指向前一版本（同窗链内，跨窗绝不串链；幂等命中不追加、
          不改链）。
        - 已归档（archive_window）窗口只读：再累计 ValueError。
        - 缓存预算：窗口总数超 max_active_windows → 真淘汰最旧活跃窗
          （淘汰契约见类 docstring：调用方须已持久化或提供 evict_callback）；
          本窗口绝不自淘汰。
        """
        key = tuple(window_key)
        if len(key) != 4:
            self._counters["identity_rejected"] += 1
            raise FusionIdentityRejected(
                "identity_rejected: window_key 必须为 "
                "(camera_id, run_id, config_version, window_id) 四元",
                details={"window_key": tuple(str(k) for k in key)})
        if key[:3] != (self.camera_id, self.run_id, self.config_version):
            self._counters["identity_rejected"] += 1
            raise FusionIdentityRejected(
                "identity_rejected: window_key 前三元与阶段绑定不符，"
                "拒绝融合（不产版本、不产 items）",
                details={"window_key": tuple(str(k) for k in key),
                         "bound": (str(self.camera_id), str(self.run_id),
                                   str(self.config_version))})
        if key != (input.camera_id, input.run_id, input.config_version,
                   input.window_id):
            self._counters["identity_rejected"] += 1
            raise FusionIdentityRejected(
                "identity_rejected: 融合输入窗口四元与 window_key 不符，"
                "拒绝融合（不产版本、不产 items）",
                details={"window_key": tuple(str(k) for k in key),
                         "input": (str(input.camera_id), str(input.run_id),
                                   str(input.config_version),
                                   str(input.window_id))})
        self._check_material_identity(input)
        state = self._windows.get(key)
        fresh = state is None
        if fresh:
            state = _WindowState()
            self._windows[key] = state
        elif state.archived:
            raise ValueError(
                f"window archived: {key} 已归档（终结只读），拒绝新增累计"
                "（如需重启累计请先 cleanup 或使用新 window_id）")
        try:
            self._enforce_window_budget(key)
        except Exception:
            if fresh:
                self._windows.pop(key, None)   # 新窗不留空壳
            raise
        state.add_materials(input)
        version_id = rows_digest(state.identity_rows(window_fingerprint_row(
            input.camera_id, input.run_id, input.config_version,
            input.window_id)))
        existing = state.by_version_id.get(version_id)
        if existing is not None:
            self._counters["idempotent_hits"] += 1
            return existing
        entries = self._entries_from_materials(
            _sorted_materials(state.l1_refs),
            _sorted_materials(state.l2_candidates),
            _sorted_materials(state.l3_branches),
            _sorted_materials(state.failures),
            _sorted_materials(state.gaps),
            _sorted_materials(state.frame_refs),
            tuple(sorted(state.clock_kinds)),
            state.coord_spaces)
        items = tuple(item for _, item in entries)
        version = self._new_version(
            version_id, items, input,
            coord_space=combine_coord_spaces(state.coord_spaces),
            frame_refs=tuple(_sorted_materials(state.frame_refs)),
            parent_version_id=(state.versions[-1].version_id
                               if state.versions else None))
        state.versions.append(version)
        state.by_version_id[version_id] = version
        self._counters["accumulated"] += 1
        self._archive_overflow(state)
        return version

    def cleanup(self, window_key):
        """窗口终结清理（C-137 §5 D3；runtime 在窗口终结/停机时接线）：
        移除该窗全部累计状态与版本缓存（只影响活跃缓存——已持久化历史
        不受影响；active/archived 两态皆可清理）。返回清理摘要（未累计过
        的窗口返回零摘要，不报错）。"""
        state = self._windows.pop(tuple(window_key), None)
        if state is None:
            return {"removed_versions": 0, "archived": 0}
        return {"removed_versions": len(state.versions),
                "archived": sum(1 for v in state.versions if v.archived)}

    def archive_window(self, window_key):
        """窗口终结归档（C-138 B3）：active → archived（WINDOW_STATES）；
        仍占缓存直到 cleanup。幂等（已归档再归档返回 True）；未累计过的
        窗口返回 False（不报错、不建窗）。归档后该窗只读：再累计
        ValueError。"""
        state = self._windows.get(tuple(window_key))
        if state is None:
            return False
        state.archived = True
        return True

    def window_state(self, window_key):
        """窗口缓存态只读查询（C-138 B3 冻结值域 WINDOW_STATES）：
        "active" | "archived"；未缓存（含已淘汰/已清理）→ None。"""
        state = self._windows.get(tuple(window_key))
        if state is None:
            return None
        return "archived" if state.archived else "active"

    def _enforce_window_budget(self, keep_key):
        """缓存硬上限（C-138 B3）：窗口总数超 max_active_windows → 真淘汰
        （从活跃缓存删除）。淘汰序：先最旧活跃窗（插入序），无活跃可淘汰
        时才最旧归档窗；keep_key（正在累计的窗）绝不淘汰。返回被淘汰键
        元组（淘汰契约见类 docstring）。"""
        overflow = len(self._windows) - self.max_active_windows
        if overflow <= 0:
            return ()
        evicted = []
        for want_archived in (False, True):
            candidates = [wkey for wkey, wstate in self._windows.items()
                          if wstate.archived == want_archived
                          and wkey != keep_key]
            for wkey in candidates:
                if overflow <= 0:
                    break
                self._evict_window(wkey)
                evicted.append(wkey)
                overflow -= 1
            if overflow <= 0:
                break
        return tuple(evicted)

    def _evict_window(self, key):
        """真淘汰单窗（内存口径：versions(key) 不可达、窗口计数下降）。
        淘汰契约：先经 evict_callback 交出 (window_key, versions) 供调用方
        持久化，再删除——回调异常原样抛出，本窗保持未删（不丢证据）。"""
        state = self._windows[key]
        if self._evict_callback is not None:
            self._evict_callback(key, tuple(state.versions))
        del self._windows[key]
        self._evicted_windows += 1

    def _new_version(self, version_id, items, input, coord_space=None,
                     frame_refs=None, parent_version_id=None):
        """版本构造（确定性字段来自输入/累计集；created_mono 单调钟打点
        不参与 version_id）。coord_space/frame_refs：fuse 缺省取本输入
        声明；accumulate 显式传入累计并集（各帧自带声明 + 联合声明，
        C-138 B2）。parent_version_id（C-139-R1 §2）：仅同窗累计链内传递
        ——首版 None、后续指向前一版本（跨窗绝不串链）；fuse 单次融合
        恒 None。"""
        return FusionVersion(
            version_id=version_id, status=self._derive_status(items),
            items=items, created_mono=time.monotonic(),
            camera_id=input.camera_id, run_id=input.run_id,
            config_version=input.config_version, window_id=input.window_id,
            coord_space=(input.coord_space if coord_space is None
                         else coord_space),
            frame_refs=(tuple(getattr(input, "frame_refs", ()) or ())
                        if frame_refs is None else frame_refs),
            parent_version_id=parent_version_id)

    @staticmethod
    def _archive_overflow(state):
        """每窗缓存有界：超出 MAX_WINDOW_VERSIONS 的最旧版本标 archived
        （证据保留；终结内存回收由 cleanup 完成）。"""
        overflow = len(state.versions) - MAX_WINDOW_VERSIONS
        if overflow > 0:
            for version in state.versions[:overflow]:
                version.archived = True

    # ---- 身份（红线：跨 camera/run/config 拒绝融合） -------------------------

    def _check_binding(self, input):
        if (input.camera_id != self.camera_id
                or input.run_id != self.run_id
                or input.config_version != self.config_version):
            self._counters["identity_rejected"] += 1
            raise FusionIdentityRejected(
                "identity_rejected: 融合输入窗口 camera/run/config 与阶段绑定"
                "不符，拒绝融合（不产版本、不产 items）",
                details={"input": (str(input.camera_id), str(input.run_id),
                                   str(input.config_version)),
                         "bound": (str(self.camera_id), str(self.run_id),
                                   str(self.config_version))})

    def _check_material_identity(self, input):
        """材料身份复核（C-136 红线 + C-137 D2）：

        - 对象引用内嵌 {cam}:{run}: 前缀与输入身份复核（引用形态不可判则
          不猜——不伪造拒绝也不伪造放行）；
        - 逐条核对 L3 分支结果自带 window（窗口四元）与输入顶层四元，任一
          字段不符 → 拒绝融合，异常 details 携带逐分支原因清单（分支序位/
          分支标签/其自报窗口/不符字段），不产版本、不产 items；
        - 分支未携带 window（缺身份字段）不猜——不伪造拒绝也不伪造放行。
        """
        refs = list(input.l1_object_refs)
        for cand in input.l2_candidates:
            refs.append(getattr(cand, "subject", ""))
            refs.append(getattr(cand, "obj", ""))
        for ref in refs:
            prefix = object_ref_camera_run(object_ref_id(ref))
            if prefix is None:
                continue
            if prefix != (input.camera_id, input.run_id):
                self._counters["identity_rejected"] += 1
                raise FusionIdentityRejected(
                    "identity_rejected: 对象引用内嵌身份与输入窗口不符，"
                    "拒绝融合（不产版本、不产 items）",
                    details={"object_ref_prefix": prefix,
                             "input": (str(input.camera_id),
                                       str(input.run_id))})
        want = (input.camera_id, input.run_id, input.config_version,
                input.window_id)
        field_names = ("camera_id", "run_id", "config_version", "window_id")
        reasons = []
        for index, branch in enumerate(input.l3_branches):
            window = getattr(branch, "window", None)
            if window is None:
                continue
            got = tuple(getattr(window, name, None) for name in field_names)
            mismatched = [name for name, got_v, want_v
                          in zip(field_names, got, want) if got_v != want_v]
            if mismatched:
                reasons.append({
                    "index": index,
                    "branch": str(enum_value(getattr(branch, "branch", ""))),
                    "window": tuple(str(v) for v in got),
                    "mismatched_fields": mismatched})
        if reasons:
            self._counters["identity_rejected"] += 1
            raise FusionIdentityRejected(
                "identity_rejected: L3 分支结果自带窗口身份与输入窗口不符，"
                "拒绝融合（不产版本、不产 items）",
                details={"input": tuple(str(v) for v in want),
                         "reasons": reasons})

    # ---- 逐条融合（不拼接文本冒充；每条带来源与合并键） ----------------------

    def _build_entries(self, input):
        """单输入条目构建（fuse 路径，输入序）：交由
        _entries_from_materials（累计路径按累计集身份序调用同一实现，
        C-138 B1）。"""
        return self._entries_from_materials(
            input.l1_object_refs, input.l2_candidates, input.l3_branches,
            input.failures, input.gaps,
            tuple(getattr(input, "frame_refs", ()) or ()),
            tuple(input.clock_kinds or ()),
            (getattr(input, "coord_space", DEFAULT_COORD_SPACE),))

    def _entries_from_materials(self, l1_refs, l2_candidates, l3_branches,
                                failures, gaps, frame_refs, clock_kinds,
                                coord_spaces):
        """由材料集构建 (合并键, FusionItem) 条目序（确定性，C-138 B1）：
        材料序由调用方决定——fuse 按输入序；accumulate 按累计集身份键
        字节序（与到达顺序无关，同材料集必得同条目序，冲突检测跨批次
        重算）。合并键为内容身份：同键合并、来源并集保留全部 crop/分支/
        model 来源（C-137 D3/D4）。"""
        entries = []
        index_by_key = {}

        def merge_append(key, kind, text, sources, certainty,
                         unstructured=False):
            """重复项合并：同键合并为一条，来源并集保留双方（顺序=首现序）。"""
            pos = index_by_key.get(key)
            if pos is None:
                index_by_key[key] = len(entries)
                entries.append((key, FusionItem(kind=kind, text=text,
                                                sources=tuple(sources),
                                                certainty=certainty,
                                                unstructured=unstructured)))
                return
            _, existing = entries[pos]
            extra = tuple(s for s in sources if s not in existing.sources)
            if extra:
                entries[pos] = (key, FusionItem(
                    kind=kind, text=existing.text,
                    sources=existing.sources + extra,
                    certainty=existing.certainty,
                    unstructured=existing.unstructured))

        # A) L1 对象事实引用 → observation/observed（结构化，非自由文本）
        for ref in l1_refs:
            oid = object_ref_id(ref)
            stable = object_ref_stable(ref)
            note = ("稳定跟踪身份" if stable else
                    "帧内引用，稳定身份缺失，不与其他观察合并为同一对象")
            merge_append(("l1", oid), "observation",
                         f"对象在场：{oid}（{note}）",
                         (FusionSource("l1_object", oid),), "observed")

        # B) L2 关系候选 → inference/model_inferred（原始分未校准，声明随行；
        #    来源引用携带材料在传入序中的位次——同一三元组重复提交时来源
        #    并集保留双方；累计路径位次=累计集身份序，与到达顺序无关）
        for cand_index, cand in enumerate(l2_candidates):
            subj = object_ref_id(getattr(cand, "subject", ""))
            obj = object_ref_id(getattr(cand, "obj", ""))
            relation = getattr(cand, "relation", "")
            graph = getattr(cand, "graph", "")
            score = getattr(cand, "score_raw", 0.0)
            score_repr = (f"{float(score):.6f}"
                          if isinstance(score, (int, float)) else str(score))
            merge_append(
                ("l2", subj, relation, obj, graph), "inference",
                f"关系候选：{subj} —{relation}→ {obj}（图 {graph}，原始分 "
                f"{score_repr}，未校准、非系统核实"
                f"{_candidate_flags_text(cand)}）",
                (FusionSource("l2_candidate",
                              f"{cand_index}:{subj}->{relation}->{obj}"
                              f"@{graph}"),),
                "model_inferred")

        # C) L3 分支：观察/推断（自由文本原样保留 unstructured=True）+
        #    不确定性缺因子→gap；失败态→分支不可用 gap（绝不冒充成功）。
        #    来源引用=内容身份 branch_kind[@crop_id][|model_ref]（D4：同类型
        #    不同裁图可区分，合并后来源并集保留全部裁图/模型来源）。
        branch_labels = []
        for branch in l3_branches:
            label = _branch_ref(branch)
            status = str(enum_value(getattr(branch, "status", "")))
            source = FusionSource("l3_branch", label)
            if status in FAILURE_STATUS_VALUES:
                err = getattr(branch, "error_code", None)
                merge_append(
                    ("l3fail", label, status,
                     "" if err is None else str(err)), "gap",
                    f"分支不可用：{label} 状态 {status}"
                    + (f"（{err}）" if err else "")
                    + "；无观察/推断产出，不冒充成功",
                    (source,), "unknown")
                continue
            branch_labels.append((label, branch))
            observation = getattr(branch, "observation", None)
            inference = getattr(branch, "inference", None)
            if observation:
                merge_append(("l3obs", observation), "observation",
                             observation, (source,), "model_inferred", True)
            if inference:
                merge_append(("l3inf", inference), "inference",
                             inference, (source,), "model_inferred", True)
            model_unknown = getattr(branch, "model_unknown", None)
            if model_unknown is not None and model_unknown != "":
                merge_append(("l3unknown", model_unknown), "gap",
                             "模型未确认：" + model_unknown, (source,), "unknown")
            unc = getattr(branch, "uncertainty", None)
            for flag, desc in _L3_FACTOR_TEXTS:
                if getattr(unc, flag, False):
                    merge_append(("l3gap", label, flag), "gap",
                                 f"分支不完整：{label} {desc}", (source,),
                                 "unknown")

        # D) 失败清单 → gap（只记账，不冒充观察/推断；逐项透传，D6）
        for entry in failures:
            f_source, f_code, f_detail = normalize_failure(entry)
            merge_append(("failure", f_source, f_code, f_detail), "gap",
                         f"失败：{f_source} {f_code}"
                         + (f"：{f_detail}" if f_detail else ""),
                         (FusionSource("failure", f"{f_source}:{f_code}"),),
                         "unknown")

        # E) 缺失清单 → gap（逐项透传，D6）
        for entry in gaps:
            g_kind, g_detail = normalize_gap(entry)
            merge_append(("gap", g_kind, g_detail), "gap",
                         f"缺失：{g_kind} {g_detail}".rstrip(),
                         (FusionSource("gap", f"{g_kind}:{g_detail}"),),
                         "unknown")

        # F) 冲突检测（确定性纯规则）：双方条目已在上面并存，这里只追加
        #    conflict 记录——不投票、不强选、不删除任何一方。
        # F1) 人数描述不一致（逐对比较，输入序）
        counts = [(label, _person_count(getattr(branch, "observation", None)))
                  for label, branch in branch_labels]
        counts = [(label, count) for label, count in counts
                  if count is not None]
        for i in range(len(counts)):
            for j in range(i + 1, len(counts)):
                if counts[i][1] != counts[j][1]:
                    merge_append(
                        ("conflict_count", counts[i][0], counts[i][1],
                         counts[j][0], counts[j][1]), "conflict",
                        f"冲突保留：人数描述不一致"
                        f"（{counts[i][0]}={counts[i][1]}人 vs "
                        f"{counts[j][0]}={counts[j][1]}人）；"
                        f"双方证据并存，不作裁定",
                        (FusionSource("l3_branch", counts[i][0]),
                         FusionSource("l3_branch", counts[j][0])),
                        "unknown")
        # F2) 关系候选 vs 叙事否定（每候选×分支至多一条 conflict 记录；
        #     累计路径在累计集上重算——先候选后否定叙事（或反序）必检出）
        for cand_index, cand in enumerate(l2_candidates):
            subj = object_ref_id(getattr(cand, "subject", ""))
            obj = object_ref_id(getattr(cand, "obj", ""))
            relation = getattr(cand, "relation", "")
            score = getattr(cand, "score_raw", 0.0)
            score_repr = (f"{float(score):.6f}"
                          if isinstance(score, (int, float)) else str(score))
            cand_source = FusionSource(
                "l2_candidate", f"{cand_index}:{subj}->{relation}->{obj}"
                                f"@{getattr(cand, 'graph', '')}")
            for label, branch in branch_labels:
                texts = [getattr(branch, "observation", None),
                         getattr(branch, "inference", None)]
                if any(t and _narrative_negates(relation, t) for t in texts):
                    merge_append(
                        ("conflict_neg", subj, relation, obj,
                         getattr(cand, "graph", ""), label), "conflict",
                        f"冲突保留：关系候选 {subj} —{relation}→ {obj}"
                        f"（原始分 {score_repr}，未校准）与分支 {label} "
                        f"叙事否定并存；双方证据保留，不作裁定",
                        (cand_source, FusionSource("l3_branch", label)),
                        "unknown")

        # G) 坐标体系一致性（C-138 B2）：材料集出现多体系声明 → 显式标记
        #    （gap）；各帧引用保留各自 coord_space 声明，绝不换算、绝不让
        #    新声明覆盖旧材料。
        spaces = sorted({str(space) for space in (coord_spaces or ())})
        if len(spaces) > 1:
            joined = "/".join(spaces)
            merge_append(
                ("coords_mismatch", joined), "gap",
                f"坐标体系不一致：{joined}；各材料保留各自坐标声明，"
                "未换算未合并，空间对齐仅在同体系内进行",
                (FusionSource("gap", "coords:" + joined),), "unknown")

        # H) 时空对齐（C-137 D5 + C-138 B2）：仅在明确可比条件下对齐——
        #    同坐标体系且稳定引用全等才合并为同一对象（合并键=引用本身，
        #    天然满足）；跨坐标体系不比较不换算（多体系标记见 G）；空间
        #    重叠绝不作为合并对象的依据；无共同稳定身份的重叠区域 → 保留
        #    双方 + 不确定性 gap 标注（进入 partial）；不可比时钟不做任何
        #    时间排序（时钟缺口见 I）。
        for i in range(len(frame_refs)):
            for j in range(i + 1, len(frame_refs)):
                ref_a, ref_b = frame_refs[i], frame_refs[j]
                if (getattr(ref_a, "coord_space", DEFAULT_COORD_SPACE)
                        != getattr(ref_b, "coord_space",
                                   DEFAULT_COORD_SPACE)):
                    continue          # 跨坐标体系：不换算、不比较
                bbox_a = getattr(ref_a, "bbox_norm", None)
                bbox_b = getattr(ref_b, "bbox_norm", None)
                if bbox_a is None or bbox_b is None:
                    continue
                if not _boxes_overlap(bbox_a, bbox_b):
                    continue
                stable_a = getattr(ref_a, "stable_ref", None)
                stable_b = getattr(ref_b, "stable_ref", None)
                if stable_a and stable_a == stable_b:
                    continue          # 已按稳定引用对齐为同一对象
                frame_a = getattr(ref_a, "frame_id", "")
                frame_b = getattr(ref_b, "frame_id", "")
                merge_append(
                    ("align", str(frame_a), str(frame_b)), "gap",
                    f"对齐不确定：帧 {frame_a} 与 {frame_b} 空间区域重叠"
                    f"但无共同稳定对象引用；保留双方，不合并为同一对象"
                    f"（时间类型 {getattr(ref_a, 'time_kind', '')}/"
                    f"{getattr(ref_b, 'time_kind', '')}）",
                    (FusionSource("gap", f"align:{frame_a}|{frame_b}"),),
                    "unknown")

        # I) 时钟类型不可比 → 时间项 unknown，不按时间排序/合并（不强排）；
        #    未携带标注则不做任何时间断言（不伪造可比性）。累计路径按累计
        #    并集判定（C-138 B2：不继承新声明）。
        kinds = sorted({str(kind) for kind in (clock_kinds or ())})
        if kinds and kinds != [COMPARABLE_CLOCK_KIND]:
            merge_append(("clock", ",".join(kinds)), "gap",
                         "时钟类型不可比：" + ",".join(kinds)
                         + "；跨来源时间顺序未知，未按时间排序或合并，"
                           "相关时间项为 unknown",
                         (FusionSource("gap", "clock:" + ",".join(kinds)),),
                         "unknown")
        return entries

    # ---- 状态（互斥不互冒充） -------------------------------------------------

    @staticmethod
    def _derive_status(items):
        """ok=有观察/推断且无 gap/conflict 因素；partial=有内容但有因素；
        insufficient=无任何观察与推断可融合（只有 gap/conflict）。"""
        has_content = any(item.kind in ("observation", "inference")
                          for item in items)
        if not has_content:
            return "insufficient"
        has_factors = any(item.kind in ("gap", "conflict") for item in items)
        return "partial" if has_factors else "ok"
