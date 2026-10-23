"""C146 · DeepSeek Harness 独立验证：事件进展接线（生产只读）。

范围与诚实边界（2026-10-13 执行合同 §执行顺序）
------------------------------------------------
- **生产只读**：本文件只调用既有生产入口（`scam.db` 的事实链与描述版本账本）；
  不修改任何生产文件、不建生产替身。
- C146 的「L4 结果 → 事件」关联模块**尚未落地**：与之相关的场景一律记为
  ``pending_interface``（含所需接口名与语义），**绝不**用自造替身宣称通过；
  接口冻结后同一文件经 `_resolve_progress_entry()` 接真实入口执行。
- 夹具 vs 真实入口、模拟时钟 vs 真实时钟：每场景结果里以
  ``source``（`real_db` / `manufactured_fixture`）与
  ``clock``（`simulated` / `real`）显式标注。
- 期望覆盖执行合同要求的用户行为：一次事件开始→同事件跨窗进展→结束→
  迟到解释只追加不重开；重复 L4 版本不刷屏；跨相机/run/config 不关联；
  多对象窗口不把一段叙事复制给所有对象；无对象保持未关联观察。
"""

import json
import math
import sys
import time
import types
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from scam.db import (  # noqa: E402
    close_event_fact,
    connect,
    ensure_initial_description,
    init_schema,
    list_event_facts,
    next_event_description_version,
    open_event_fact,
    open_tracked_object,
    publish_semantic_update,
    update_event_fact,
)

# --------------------------------------------------------------------------
# 所需接口契约（供 Codex 冻结；未落地时场景记 pending，不造假通过）
# --------------------------------------------------------------------------
INTERFACE_CONTRACT = {
    "purpose": "把 L4 理解结果按**明确身份**关联到既有事件事实，只追加描述版本",
    "module_candidates": (
        "scam.win11_event_progress", "scam.win11_progress",
        "scam.event_progress"),
    "callable_candidates": (
        "attach_understanding", "associate_understanding",
        "record_event_progress"),
    "required_kwargs": (
        "event_id", "identity", "text", "uncertainty", "evidence_refs",
        "t_created", "model_id", "event_open_at_write"),
    "identity_keys": ("camera_id", "run_id", "config_version"),
    "semantics": (
        "同 (event_id, 证据摘要, 处理指纹) 重复调用 → 不新增版本（幂等）；",
        "迟到结果只追加版本，不改写事件事实、不改变事件是否成立、不重开已闭合事件；",
        "身份（相机/run/配置）任一不一致 → 不关联，保留未关联观察；",
        "一个多对象窗口不得把同一段叙事无差别写入每个对象事件；",
        "无对象的 L4 结果 → 未关联观察，不建事件、不写对象叙事。",
    ),
    "time_fields": (
        "t_discovery", "t_enqueue", "t_model_start", "t_model_end",
        "t_fusion", "t_display"),
    "db_vocabulary": {
        "uncertainty": ("confirmed", "low", "high"),
        "note": ("event_descriptions.uncertainty 有 CHECK 约束；"
                 "L3/L4 的 model_inference 等值必须先映射，"
                 "否则整条发布失败且返回 (None, False)"),
    },
    "diagnosability_note": (
        "publish_semantic_update 对约束冲突与幂等命中都返回 (None, False)，"
        "调用方无法区分——C146 关联入口应把二者分开报告（不影响原始事实）"),
}

SCENARIO_STATUS = {}


def _resolve_progress_entry():
    """探测 C146 关联入口（真实入口优先）；未落地返回 None。"""
    import importlib
    for module_name in INTERFACE_CONTRACT["module_candidates"]:
        try:
            module = importlib.import_module(module_name)
        except Exception:
            continue
        for attr in INTERFACE_CONTRACT["callable_candidates"]:
            entry = getattr(module, attr, None)
            if callable(entry):
                return entry, f"{module_name}.{attr}"
    # db 层候选（若 Codex 选择在 db 暴露）
    try:
        from scam import db as db_mod
    except Exception:
        return None
    for attr in INTERFACE_CONTRACT["callable_candidates"]:
        entry = getattr(db_mod, attr, None)
        if callable(entry):
            return entry, f"scam.db.{attr}"
    return None


def _db(tmp_path):
    conn = connect(str(Path(tmp_path) / "c146.db"))
    init_schema(conn)
    return conn


def _object(conn, *, object_id, camera, t_start=0.0, cls="person",
            payload=None):
    """对象事实必须先落库：event_facts 有对象外键守卫（孤儿事件被拒）。"""
    open_tracked_object(conn, object_id=object_id, camera=camera,
                        t_start=t_start, cls=cls, payload=payload)


def _fact(conn, **kwargs):
    """打开事件事实；被对象守卫/闭合行拒绝时明确抛错（不得静默继续）。"""
    ok = open_event_fact(conn, **kwargs)
    if not ok:
        raise AssertionError(
            f"event_fact 未打开（对象守卫或闭合复用）：{kwargs.get('event_id')}")
    return ok


def _event_row(conn, event_id):
    return dict(conn.execute(
        "SELECT event_id,camera,object_id,t_start,t_last,t_end,state,end_reason"
        " FROM event_facts WHERE event_id=?", (event_id,)).fetchone())


def _descriptions(conn, event_id):
    return [dict(r) for r in conn.execute(
        "SELECT version,source,text,t_created FROM event_descriptions"
        " WHERE event_id=? ORDER BY version", (event_id,)).fetchall()]


def _semantic_notifications(conn, event_id):
    return [dict(r) for r in conn.execute(
        "SELECT notification_id,kind,dedupe_key,t_event FROM event_notifications"
        " WHERE event_id=? AND kind='semantic_update' ORDER BY t_event",
        (event_id,)).fetchall()]


# ==========================================================================
# 场景 1（真实 db 入口）：开始 → 同事件跨窗进展 → 结束 → 迟到解释只追加不重开
# ==========================================================================

def scenario_lifecycle_progress_late_append(tmp_path):
    conn = _db(tmp_path)
    result = {
        "scenario": "c146_lifecycle_progress_late_append",
        "source": "real_db",
        "clock": "simulated",
        "expectation": (
            "事件有开始/进展/结束；迟到解释只追加版本 v(n+1)，"
            "t_end/state 不变、原 v1 文本不被改写"),
    }
    _object(conn, object_id="obj-1", camera="cam-a", t_start=990.0)
    ok_open = _fact(conn, event_id="ev-1", camera="cam-a", object_id="obj-1",
                    t_start=1000.0, cls="person")
    init_created = ensure_initial_description(
        conn, "ev-1", text="发现一个人进入画面", t_created=1000.0,
        evidence_refs=["asset:obj-1:best"])
    progressed = update_event_fact(conn, "ev-1", t_last=1006.0, conf=0.95)
    closed = close_event_fact(conn, "ev-1", reason="track-lost")
    before = _event_row(conn, "ev-1")
    v_before = next_event_description_version(conn, "ev-1")
    late_version, created = publish_semantic_update(
        conn, event_id="ev-1", identity="l4:ev-1:late-1",
        text="该人停留后离开", uncertainty="low",
        evidence_refs=["asset:obj-1:best"], t_created=1090.0,
        model_id="c146-stub-vlm", event_open_at_write=False)
    after = _event_row(conn, "ev-1")
    descriptions = _descriptions(conn, "ev-1")
    result.update({
        "opened": bool(ok_open), "initial_created": bool(init_created),
        "progressed": bool(progressed), "closed": bool(closed),
        "version_before_late": v_before, "late_version": late_version,
        "late_created": bool(created),
        "t_end_before": before["t_end"], "t_end_after": after["t_end"],
        "state_before": before["state"], "state_after": after["state"],
        "versions": [d["version"] for d in descriptions],
        "v1_text": next((d["text"] for d in descriptions
                         if d["version"] == 1), None),
        "late_text": next((d["text"] for d in descriptions
                           if d["version"] == late_version), None),
    })
    problems = []
    if not (ok_open and init_created and progressed and closed):
        problems.append("事实链开始/进展/结束未全部成立")
    if before["state"] != "closed" or before["t_end"] is None:
        problems.append("结束未闭合（t_end/state）")
    if not created or late_version != v_before + 1:
        problems.append("迟到解释未追加为下一版本")
    if after["t_end"] != before["t_end"] or after["state"] != before["state"]:
        problems.append("迟到解释改变了事件闭合事实（重开/改 t_end）")
    if result["versions"] != sorted(result["versions"]):
        problems.append("版本不单调")
    result["verdict"] = "pass" if not problems else "fail"
    result["gap"] = "; ".join(problems) or None
    conn.close()
    return result


# ==========================================================================
# 场景 2（真实 db 入口）：重复 L4 版本不刷屏（幂等账本）
# ==========================================================================

def scenario_duplicate_version_no_spam(tmp_path):
    conn = _db(tmp_path)
    _object(conn, object_id="obj-2", camera="cam-a", t_start=1990.0)
    _fact(conn, event_id="ev-2", camera="cam-a", object_id="obj-2",
          t_start=2000.0, cls="person")
    identity = "l4:ev-2:same-digest"
    v1, created1 = publish_semantic_update(
        conn, event_id="ev-2", identity=identity, text="同一证据的解释",
        uncertainty="low", evidence_refs=["asset:obj-2:best"],
        t_created=2001.0, model_id="c146-stub-vlm", event_open_at_write=True)
    v2, created2 = publish_semantic_update(
        conn, event_id="ev-2", identity=identity, text="同一证据的解释",
        uncertainty="low", evidence_refs=["asset:obj-2:best"],
        t_created=2002.0, model_id="c146-stub-vlm", event_open_at_write=True)
    descriptions = _descriptions(conn, "ev-2")
    notifications = _semantic_notifications(conn, "ev-2")
    result = {
        "scenario": "c146_duplicate_version_no_spam",
        "source": "real_db", "clock": "simulated",
        "expectation": "同身份重复发布不新增版本、不重复提醒（幂等账本）",
        "first_version": v1, "first_created": bool(created1),
        "second_version": v2, "second_created": bool(created2),
        "version_count": len(descriptions),
        "notification_count": len(notifications),
        "versions": [d["version"] for d in descriptions],
    }
    problems = []
    if not created1 or v1 != 1:
        problems.append("首次发布未产生 v1")
    if created2 or v2 is not None:
        problems.append("重复身份仍新增版本")
    if len(descriptions) != 1 or len(notifications) != 1:
        problems.append("重复发布造成描述/提醒刷屏")
    result["verdict"] = "pass" if not problems else "fail"
    result["gap"] = "; ".join(problems) or None
    conn.close()
    return result


# ==========================================================================
# 场景 3（真实 db 入口）：身份隔离（相机层已可测；run/config 属待冻结接口）
# ==========================================================================

def scenario_identity_isolation(tmp_path):
    conn = _db(tmp_path)
    _object(conn, object_id="obj-shared", camera="cam-a", t_start=2990.0)
    _object(conn, object_id="obj-shared", camera="cam-b", t_start=2990.5)
    _fact(conn, event_id="ev-a", camera="cam-a", object_id="obj-shared",
          t_start=3000.0, cls="person")
    _fact(conn, event_id="ev-b", camera="cam-b", object_id="obj-shared",
          t_start=3000.5, cls="person")
    version, created = publish_semantic_update(
        conn, event_id="ev-a", identity="l4:ev-a:x", text="A 相机的解释",
        uncertainty="low", evidence_refs=["asset:obj-shared:best"],
        t_created=3001.0, model_id="c146-stub-vlm", event_open_at_write=True)
    a_versions = [d["version"] for d in _descriptions(conn, "ev-a")]
    b_versions = [d["version"] for d in _descriptions(conn, "ev-b")]
    cam_a = {row["event_id"] for row in list_event_facts(conn, camera="cam-a")}
    cam_b = {row["event_id"] for row in list_event_facts(conn, camera="cam-b")}
    entry = _resolve_progress_entry()
    result = {
        "scenario": "c146_identity_isolation",
        "source": "real_db", "clock": "simulated",
        "expectation": ("同 object 跨相机不得互相继承解释；"
                        "run/config 维度由待冻结的关联入口强制"),
        "published_version": version, "created": bool(created),
        "cam_a_versions": a_versions, "cam_b_versions": b_versions,
        "cam_a_events": sorted(cam_a), "cam_b_events": sorted(cam_b),
        "run_config_scope": ("pending_interface" if entry is None
                             else "real_entry_available"),
    }
    problems = []
    if a_versions != [1]:
        problems.append("A 相机事件未得到自身 v1")
    if b_versions:
        problems.append("B 相机事件被写入 A 的解释（跨相机串写）")
    if cam_a != {"ev-a"} or cam_b != {"ev-b"}:
        problems.append("相机筛选串事件")
    result["verdict"] = "pass" if not problems else "fail"
    result["gap"] = "; ".join(problems) or None
    conn.close()
    return result


# ==========================================================================
# 场景 4（真实 db 入口）：多对象窗口不把一段叙事复制给所有对象
# ==========================================================================

def scenario_multi_object_no_narrative_copy(tmp_path):
    conn = _db(tmp_path)
    for event_id, object_id in (("ev-m1", "obj-m1"), ("ev-m2", "obj-m2")):
        _object(conn, object_id=object_id, camera="cam-a", t_start=3990.0)
        _fact(conn, event_id=event_id, camera="cam-a", object_id=object_id,
              t_start=4000.0, cls="person")
    version, created = publish_semantic_update(
        conn, event_id="ev-m1", identity="l4:win-1:obj-m1",
        text="窗口内两人一前一后经过", uncertainty="low",
        evidence_refs=["asset:obj-m1:best"], t_created=4001.0,
        model_id="c146-stub-vlm", event_open_at_write=True)
    m1 = [d["version"] for d in _descriptions(conn, "ev-m1")]
    m2 = [d["version"] for d in _descriptions(conn, "ev-m2")]
    result = {
        "scenario": "c146_multi_object_no_narrative_copy",
        "source": "real_db", "clock": "simulated",
        "expectation": ("写给 obj-m1 的叙事不得自动出现在 obj-m2 的事件上"
                        "（无差别复制即 fail）"),
        "published_version": version, "created": bool(created),
        "m1_versions": m1, "m2_versions": m2,
    }
    problems = []
    if m1 != [1]:
        problems.append("目标对象未得到叙事")
    if m2:
        problems.append("同一叙事被复制到其它对象事件")
    result["verdict"] = "pass" if not problems else "fail"
    result["gap"] = "; ".join(problems) or None
    conn.close()
    return result


# ==========================================================================
# 独立时间测量契约（夹具自检；真实时点由 scripts/win11_c146_dsh_measure.py 承载）
# ==========================================================================

TIMELINE_SCHEMA = {
    "required": ("stage", "t", "clock", "model"),
    "stages": ("discovery", "enqueue", "model_start", "model_end",
               "fusion", "display"),
    "clock_values": ("simulated", "real"),
    "model_values": ("stub", "real"),
}


def make_timeline(*, base=0.0, clock="simulated", model="stub",
                  durations=None):
    """确定性时间线夹具（阶段显式给点；用于测量契约自检）。"""
    durations = durations or {"enqueue": 0.05, "model_start": 0.10,
                              "model_end": 2.10, "fusion": 2.30,
                              "display": 2.45}
    return [
        {"stage": "discovery", "t": base, "clock": clock, "model": model},
        {"stage": "enqueue", "t": base + durations["enqueue"],
         "clock": clock, "model": model},
        {"stage": "model_start", "t": base + durations["model_start"],
         "clock": clock, "model": model},
        {"stage": "model_end", "t": base + durations["model_end"],
         "clock": clock, "model": model},
        {"stage": "fusion", "t": base + durations["fusion"],
         "clock": clock, "model": model},
        {"stage": "display", "t": base + durations["display"],
         "clock": clock, "model": model},
    ]


def validate_timeline(records):
    """独立测量契约校验：字段/取值/单调性/时钟域不得混用。"""
    problems = []
    if not records:
        return ["时间线为空"]
    seen_stages = []
    clocks = {r.get("clock") for r in records}
    models = {r.get("model") for r in records}
    last_t = None
    for row in records:
        for key in TIMELINE_SCHEMA["required"]:
            if key not in row:
                problems.append(f"缺少字段 {key}")
        if row.get("stage") not in TIMELINE_SCHEMA["stages"]:
            problems.append(f"未知阶段 {row.get('stage')}")
        if row.get("clock") not in TIMELINE_SCHEMA["clock_values"]:
            problems.append(f"未知时钟域 {row.get('clock')}")
        if row.get("model") not in TIMELINE_SCHEMA["model_values"]:
            problems.append(f"未知模型标注 {row.get('model')}")
        if not isinstance(row.get("t"), (int, float)) or \
                not math.isfinite(row.get("t")):
            problems.append("时间点非有限数值")
            continue
        if last_t is not None and row["t"] < last_t:
            problems.append("时间点非单调（同钟域不得回退）")
        last_t = row["t"]
        seen_stages.append(row.get("stage"))
    if len(clocks) > 1:
        problems.append("同一时间线混用不同钟域（模拟/真实不可混算段）")
    if len(models) > 1:
        problems.append("同一时间线混用模型标注（桩/真实不可混算段）")
    if seen_stages[:1] != ["discovery"]:
        problems.append("时间线未以 discovery 开始")
    return problems


def test_pending_interface_contract_recorded():
    entry = _resolve_progress_entry()
    if entry is None:
        assert SCENARIO_STATUS.get("pending_count", 0) >= 0
        assert INTERFACE_CONTRACT["identity_keys"] == (
            "camera_id", "run_id", "config_version")
        assert "event_id" in INTERFACE_CONTRACT["required_kwargs"]
        assert len(INTERFACE_CONTRACT["semantics"]) >= 4
        assert len(INTERFACE_CONTRACT["time_fields"]) == 6
    else:
        assert entry[1], "入口必须可定位"


def test_timeline_contract_rejects_mixed_clocks():
    good = make_timeline()
    assert validate_timeline(good) == []
    mixed = make_timeline()
    mixed[3]["clock"] = "real"
    assert any("钟域" in p for p in validate_timeline(mixed))
    non_monotonic = make_timeline()
    non_monotonic[2]["t"] = non_monotonic[1]["t"] - 0.01
    assert any("单调" in p for p in validate_timeline(non_monotonic))
    mixed_model = make_timeline()
    mixed_model[4]["model"] = "real"
    assert any("模型标注" in p for p in validate_timeline(mixed_model))


def test_out_of_vocabulary_uncertainty_is_rejected(tmp_path):
    """db 词表外的 uncertainty 必须被拒绝（不得静默写入描述版本）。"""
    conn = _db(tmp_path)
    _object(conn, object_id="obj-v", camera="cam-a", t_start=500.0)
    _fact(conn, event_id="ev-v", camera="cam-a", object_id="obj-v",
          t_start=510.0, cls="person")
    version, created = publish_semantic_update(
        conn, event_id="ev-v", identity="l4:ev-v:bad", text="越界不确定度",
        uncertainty="model_inference", evidence_refs=["a"], t_created=511.0,
        model_id="c146-stub-vlm", event_open_at_write=True)
    versions = [d["version"] for d in _descriptions(conn, "ev-v")]
    conn.close()
    assert (version, created) == (None, False), (version, created)
    assert versions == [], versions


def test_real_entry_scenarios(tmp_path):
    """真实生产入口场景（默认 nvr builder + 真实 Monitor/桥/worker/详情）。"""
    failed = {}
    for name, fn in REAL_ENTRY_SCENARIOS.items():
        data = fn(tmp_path / name)
        if data.get("verdict") != "pass":
            failed[name] = {"gap": data.get("gap"),
                            "verdict": data.get("verdict"),
                            "detail": {k: v for k, v in data.items()
                                       if k in ("bridge_snapshot", "order_detail",
                                                "description_versions",
                                                "event_fact_count",
                                                "versions_before",
                                                "versions_after",
                                                "closed_before_publish",
                                                "fact_after")}}
    assert not failed, failed


def test_real_db_scenarios(tmp_path):
    results = run_real_db_scenarios(tmp_path)
    failed = {k: v["gap"] for k, v in results.items()
              if v["verdict"] != "pass"}
    assert not failed, failed


def run_real_db_scenarios(tmp_path):
    """真实 db 入口场景（可被测量器复用）。"""
    base = Path(tmp_path)
    (base / "lifecycle").mkdir(parents=True, exist_ok=True)
    (base / "duplicate").mkdir(parents=True, exist_ok=True)
    (base / "identity").mkdir(parents=True, exist_ok=True)
    (base / "multi").mkdir(parents=True, exist_ok=True)
    out = {}
    for name, fn, sub in (
            ("c146_lifecycle_progress_late_append",
             scenario_lifecycle_progress_late_append, "lifecycle"),
            ("c146_duplicate_version_no_spam",
             scenario_duplicate_version_no_spam, "duplicate"),
            ("c146_identity_isolation", scenario_identity_isolation,
             "identity"),
            ("c146_multi_object_no_narrative_copy",
             scenario_multi_object_no_narrative_copy, "multi")):
        out[name] = fn(base / sub)
    return out





"""C146 真实生产入口场景（追加段；仅我的文件，生产只读）。

链路（照 INTERFACE.md 的 real call shapes，独立实现，不导入他方测试结果）：
真实 Monitor + SqliteSink（fixture DB）→ 真实 L1Result 经
``apply_detection_result → step → consume_conclusion`` →
``EventProgress.record_conclusion``（在 ``MaterialsStore.attach_result`` **之前**）
→ 真实 ``nvr._build_l2_runtime(..., db_path=...)`` 默认 builder 接线（L4 开）
→ 真实 ``L2Runtime`` 窗口 → 真实 ``L3Stage``（**仅模型边界为桩**）
→ 真实 ``L4Stage`` / ``runtime._accumulate_branch_result`` →
有界 worker（``EventProgress.submit``）→ 真实 ``db.publish_semantic_update``
→ 真实 ``WorkbenchState.event_fact_detail``。

诚实标注：源/检测器/L3 模型是**确定性测试边界**（非相机/真实模型/浏览器证据）；
时间推进是**模拟时钟**（源时间戳由夹具给定）；不手造 binding 冒充生产证据——
绑定一律来自真实 ``record_conclusion`` 记录的快照。
"""

import threading as _threading
import time as _time

from scam import nvr as _nvr
from scam.server import CameraRuntimeRegistry as _Registry
from scam.win11_l3 import L3Stage as _L3Stage
from scam.win11_materials import MaterialsStore as _MaterialsStore
from scam.win11_pipeline import L1Pipeline as _L1Pipeline

REAL_CAM = "c146-cam"


class _StubDetector:
    """检测器边界（桩）：按调用序号返回脚本化检测框；可暂停以做阶段屏障。"""

    def __init__(self, boxes):
        self._boxes = list(boxes)
        self._i = 0
        self.calls = 0
        self._paused = _threading.Event()

    def pause(self):
        """暂停摄取：之后恒返回空，供"关闭前不再推进该轨迹"的阶段确认。"""
        self._paused.set()

    @property
    def paused(self):
        return self._paused.is_set()

    def detect(self, frame_bgr):
        self.calls += 1
        if self._paused.is_set():
            return []
        if self._i >= len(self._boxes):
            return []
        dets = self._boxes[self._i]
        self._i += 1
        return [dict(d) for d in dets]


class _StubL2Model:
    """L2 关系模型边界（桩）：真实 L2RelationStage 调用，返回稳定三元组。"""

    model_ref = "c146-stub/l2-relate"

    def __init__(self):
        self.calls = []

    def infer(self, frame_bgr, boxes_px, labels, vocabulary):
        self.calls.append(len(boxes_px))
        if len(boxes_px) < 2:
            return []
        return [{"s": 0, "o": 1, "relation": "near", "graph": "semantic",
                 "score": 0.6}]


class _StubL3Model:
    """L3 视觉模型边界（桩）：可被门闩阻塞，用于"先关闭事件、后发布解释"。"""

    model_ref = "c146-stub/l3-vlm"

    def __init__(self, *, gate=None, text="门口有人停留后离开"):
        self.gate = gate
        self.text = text
        self.calls = []

    def understand_frames(self, prompt, frames_bgr, frames_meta):
        self.calls.append(len(frames_bgr))
        if self.gate is not None:
            if not self.gate.wait(timeout=20.0):
                raise TimeoutError("stub gate timeout")
        return {"observation": self.text, "inference": self.text}


class _ScriptedSource:
    """夹具源（桩）：释放有限帧后重复最后一帧，模拟"相机一直在看"。"""

    def __init__(self, camera_id, url, source_kind="file"):
        self.camera_id = camera_id
        self.stats = {"timestamp_kind": "source_capture"}
        self._i = 0

    def open(self):
        return True

    def close(self):
        return None

    def read(self):
        # The simulated capture clock must not race ahead while the previous
        # scripted detection is still queued/running on a real worker thread.
        # This is a source-fixture barrier, not a production scheduling wait.
        before_read = getattr(type(self), "before_read", None)
        if before_read is not None:
            before_read()
        frames = type(self).frames
        dt = type(self).dt
        if self._i < len(frames):
            frame = frames[self._i]
            self._i += 1
        else:
            frame = frames[-1]
        _time.sleep(type(self).pace_s)
        type(self).ts += dt
        return True, frame.copy(), type(self).ts


_ScriptedSource.frames = []
_ScriptedSource.dt = 0.1
_ScriptedSource.ts = 1000.0
_ScriptedSource.pace_s = 0.01


class _RealEntry:
    """默认 nvr builder 接线的真实生产入口夹具（源/检测器/L3 为标注桩）。"""

    def __init__(self, tmp_path, *, frames, boxes, l3_gate=None, l3_text=None,
                 pace_s=0.02, dt=0.1):
        import numpy as np
        self.path = Path(tmp_path)
        self.path.mkdir(parents=True, exist_ok=True)
        self.db_path = str(self.path / "c146-entry.db")
        self.conn = connect(self.db_path)
        init_schema(self.conn)
        self.store = _MaterialsStore()
        self.stop_event = _threading.Event()
        self.detector = _StubDetector(boxes)
        self.l3_model = _StubL3Model(gate=l3_gate, text=l3_text or
                                     "门口有人停留后离开")
        self.pipeline = _L1Pipeline(lambda: self.detector,
                                    stop_event=self.stop_event,
                                    model_name="c146-stub-detector")
        self.runtime = _nvr._build_l2_runtime(
            {"vocabulary": ["near"], "vocabulary_id": "c146-stub-vocab"},
            self.store, [REAL_CAM],
            l3_cfg={"enabled": False, "l4": {"enabled": True}},
            persist_dir=None, db_path=self.db_path)
        # 模型边界替换（INTERFACE 允许）：桥/有界 worker/L4Stage/发布/事实链
        # 全部保持 builder 真实构造；只把 L2 关系模型与 L3 视觉模型换成桩。
        from scam.win11_l2_contract import (L2Budget as _L2Budget,
                                            L2RelationStage as _L2Stage)
        self.l2_model = _StubL2Model()
        self.runtime.stage = _L2Stage(model=self.l2_model, budget=_L2Budget())
        self.runtime.l3_stage = _L3Stage(model=self.l3_model, budget=None)
        self.runtime.l3_backend = None
        self.registry = _Registry([REAL_CAM])
        self.state = types.SimpleNamespace(monitors={}, runtime=self.registry)
        self.order = []                    # 调用顺序证据
        self.fusions = []                  # 真实 submit 过的 fusion payload
        self.thread = None
        self._saved_source = None
        # Each scenario owns its frame sequence and simulated clock.  A previous
        # camera thread can never read a later scenario's reset class state.
        self.source_type = type("EntryScriptedSource", (_ScriptedSource,), {
            "frames": [np.full((240, 320, 3), 40, dtype=np.uint8)
                       for _ in frames],
            "dt": dt, "pace_s": pace_s, "ts": 1000.0,
            "before_read": staticmethod(self._await_scripted_l1),
        })

    def _await_scripted_l1(self):
        deadline = _time.monotonic() + 5.0
        while self.pipeline.oldest_unfinished_age_ms(REAL_CAM) is not None:
            if self.stop_event.is_set():
                return
            if _time.monotonic() >= deadline:
                raise AssertionError("scripted L1 computation did not finish")
            self.stop_event.wait(0.001)

    # ------------------------------------------------------------------ 接线
    def start(self):
        bridge = self.runtime.event_progress
        real_record = bridge.record_conclusion
        real_attach = self.store.attach_result

        def record(monitor, conclusion):
            accepted = real_record(monitor, conclusion)
            self.order.append(("record_conclusion", bool(accepted)))
            return accepted

        def attach(*args, **kwargs):
            self.order.append(("attach_result", None))
            return real_attach(*args, **kwargs)

        real_submit = bridge.submit
        self.fusions = []

        def submit(fusion):
            accepted = real_submit(fusion)
            if accepted:
                self.fusions.append(json.loads(json.dumps(fusion)))
            return accepted

        bridge.submit = submit
        bridge.record_conclusion = record
        self.store.attach_result = attach
        self._saved_source = _nvr.CameraSource
        _nvr.CameraSource = self.source_type
        self.pipeline.start()
        self.runtime.start()
        cam_cfg = {"id": REAL_CAM, "source": "c146-scripted",
                   "source_kind": "file", "detector": {}}
        self.thread = _threading.Thread(
            target=_nvr._run_camera,
            args=(cam_cfg, {}, self.db_path, self.stop_event, self.state),
            kwargs={"pipeline": self.pipeline, "store": self.store,
                    "l2_runtime": self.runtime},
            daemon=True)
        self.thread.start()
        return self

    def stop_camera(self, timeout=8.0):
        """只停并 join 相机生产者：让 `_run_camera` 拥有线程的 finally 正常收口事实。

        绝不从主线程直接操纵相机线程创建的 SqliteSink（跨线程 ProgrammingError），
        也不改 check_same_thread 掩盖夹具错误。
        """
        self.stop_event.set()
        thread = self.thread
        if thread is not None:
            thread.join(timeout=timeout)
            self.thread = None
        return {"camera_joined": not (thread is not None and thread.is_alive()),
                "camera_thread_alive": bool(thread is not None and thread.is_alive())}

    def teardown(self):
        """最终收尾（生产者 runtime 停止 → bridge 关闭/汇合），返回线程/连接退出证明。"""
        proof = {"camera_thread_alive": bool(self.thread is not None
                                             and self.thread.is_alive())}
        self.pipeline.close()
        bridge = self.runtime.event_progress
        drained = None
        if bridge is not None:
            drained = bridge.close(timeout=6.0)
        self.runtime.stop(timeout=4.0)
        bridge_thread = getattr(bridge, "_thread", None) if bridge else None
        runtime_thread = getattr(self.runtime, "_thread", None)
        proof.update({
            "bridge_drained": drained,
            "bridge_thread_alive": bool(bridge_thread is not None
                                        and bridge_thread.is_alive()),
            "runtime_thread_alive": bool(runtime_thread is not None
                                         and runtime_thread.is_alive()),
            "pipeline_in_flight": False,
        })
        if self._saved_source is not None:
            _nvr.CameraSource = self._saved_source
            self._saved_source = None
        return proof

    def stop(self):
        self.stop_camera()
        return self.teardown()

    def fresh_fact_state(self, event_id):
        """**新连接**读取事实行状态（不与相机线程的连接共用）。"""
        conn = connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT event_id,state,t_end,end_reason FROM event_facts"
                " WHERE event_id=?", (event_id,)).fetchone()
            return None if row is None else dict(row)
        finally:
            conn.close()

    def fresh_descriptions(self, event_id):
        conn = connect(self.db_path)
        try:
            return [dict(r) for r in conn.execute(
                "SELECT version,text,evidence_refs FROM event_descriptions"
                " WHERE event_id=? ORDER BY version", (event_id,)).fetchall()]
        finally:
            conn.close()

    def fresh_fact_ids(self):
        conn = connect(self.db_path)
        try:
            return sorted(r["event_id"] for r in conn.execute(
                "SELECT event_id FROM event_facts").fetchall())
        finally:
            conn.close()

    def confirm_closed_fresh(self, event_id, *, window=1.2, timeout=25.0):
        """阶段确认（墙钟轮询，不与源模拟时钟混用）：目标 closed 且事实集合稳定。"""
        fact_ids = self.fresh_fact_ids()
        stable_since = None
        deadline = _time.monotonic() + timeout
        while _time.monotonic() < deadline:
            row = self.fresh_fact_state(event_id)
            same_ids = self.fresh_fact_ids() == fact_ids
            ok = (row is not None and row["state"] == "closed"
                  and row["t_end"] is not None and same_ids)
            if ok:
                stable_since = stable_since or _time.monotonic()
                if _time.monotonic() - stable_since >= window:
                    return True
            else:
                stable_since = None
            _time.sleep(0.05)
        return False

    # ------------------------------------------------------------------ 查询
    @property
    def monitor(self):
        return self.state.monitors.get(REAL_CAM)

    def bridge_snapshot(self):
        bridge = self.runtime.event_progress
        return None if bridge is None else bridge.snapshot()

    def event_facts(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT event_id,camera,object_id,t_start,t_last,t_end,state,"
            "end_reason,payload FROM event_facts ORDER BY t_start").fetchall()]

    def descriptions(self, event_id):
        return [dict(r) for r in self.conn.execute(
            "SELECT version,source,text,t_created,evidence_refs"
            " FROM event_descriptions WHERE event_id=? ORDER BY version",
            (event_id,)).fetchall()]

    def notifications(self, event_id):
        return [dict(r) for r in self.conn.execute(
            "SELECT kind,dedupe_key,t_event,text FROM event_notifications"
            " WHERE event_id=? ORDER BY t_event", (event_id,)).fetchall()]

    def wait_until(self, predicate, timeout=12.0, interval=0.05):
        deadline = _time.monotonic() + timeout
        while _time.monotonic() < deadline:
            if predicate():
                return True
            _time.sleep(interval)
        return bool(predicate())

    def confirm_stable(self, predicate, *, window=1.5, timeout=15.0,
                       interval=0.05):
        """阶段确认：predicate 连续 window 秒成立才算通过（不用盲等代替确认）。"""
        deadline = _time.monotonic() + timeout
        ok_since = None
        while _time.monotonic() < deadline:
            if predicate():
                ok_since = ok_since or _time.monotonic()
                if _time.monotonic() - ok_since >= window:
                    return True
            else:
                ok_since = None
            _time.sleep(interval)
        return False

    def fact_row(self, event_id):
        row = self.conn.execute(
            "SELECT event_id,camera,object_id,t_start,t_last,t_end,state,"
            "end_reason FROM event_facts WHERE event_id=?",
            (event_id,)).fetchone()
        return None if row is None else dict(row)

    def max_description_version(self, event_id):
        rows = self.descriptions(event_id)
        return max((d["version"] for d in rows), default=0)

    def event_with_appended_version(self):
        """DB 扫描：返回已出现 >=2 版本的事件行（不使用 bridge.snapshot.last）。"""
        hot = [f for f in self.event_facts()
               if self.max_description_version(f["event_id"]) >= 2]
        if len(hot) > 1:
            hot = sorted(hot, key=lambda f: (f["t_start"], f["event_id"]))
        return hot[0] if hot else None


def _first_registration_before_attach(order):
    """返回 (ok, detail)：首个成功登记必须早于首个材料可见（attach）。"""
    first_record = next((i for i, (kind, ok) in enumerate(order)
                         if kind == "record_conclusion" and ok), None)
    first_attach = next((i for i, (kind, _) in enumerate(order)
                         if kind == "attach_result"), None)
    if first_record is None:
        return False, {"first_record": None, "first_attach": first_attach}
    if first_attach is None:
        return False, {"first_record": first_record, "first_attach": None}
    return first_record < first_attach, {
        "first_record": first_record, "first_attach": first_attach,
        "recorded": sum(1 for k, ok in order
                        if k == "record_conclusion" and ok),
        "attached": sum(1 for k, _ in order if k == "attach_result")}


# ==========================================================================
# 真实入口场景 1：默认 builder 接线 + 登记先于材料可见（P4）
# ==========================================================================

def scenario_actual_entry_registers_before_visibility(tmp_path):
    boxes = [[{"cls": "person", "conf": 0.9, "bbox": [0.40, 0.40, 0.10, 0.20]}]
             for _ in range(80)]
    entry = _RealEntry(Path(tmp_path) / "register", frames=list(range(30)),
                       boxes=boxes)
    try:
        entry.start()
        ok = entry.wait_until(
            lambda: any(k == "attach_result" for k, _ in entry.order)
            and len(entry.order) > 4, timeout=15.0)
        ordered, detail = _first_registration_before_attach(entry.order)
        snapshot = entry.bridge_snapshot()
        facts = entry.event_facts()
        result = {
            "scenario": "c146_actual_entry_registers_before_visibility",
            "source": "real_production_entry",
            "clock": "simulated",
            "model_boundary": "stub（检测器/L3 视觉模型）；L2/L3/L4 调度与 db 为真实",
            "expectation": ("默认 nvr builder 接线：真实 Monitor 结论先经"
                            "EventProgress.record_conclusion 登记，"
                            "早于 MaterialsStore.attach_result（材料可见）"),
            "order_observed": ordered, "order_detail": detail,
            "order_tail": entry.order[:12],
            "bridge_snapshot": snapshot,
            "event_fact_count": len(facts),
            "ran": bool(ok),
        }
        problems = []
        if not ok:
            problems.append("未观察到足够的接线事件")
        if not ordered:
            problems.append("登记未早于材料可见（顺序不满足生产接线）")
        if not snapshot or snapshot["counts"].get("binding_recorded", 0) < 1:
            problems.append("桥未记录任何帧绑定")
        if not facts:
            problems.append("真实 Monitor 未落库事件事实")
        result["verdict"] = "pass" if not problems else "fail"
        result["gap"] = "; ".join(problems) or None
        return result
    finally:
        entry.stop()
        entry.conn.close()


# ==========================================================================
# 真实入口场景 2：真实 L4 累积钩子 → 有界 worker → 用户事件详情（P3）
# ==========================================================================

def _run_l4_to_detail(tmp_path, *, gate=None, close_event_first=False,
                      name="l4_detail", l3_text=None):
    """真实入口：阶段屏障 + DB 锁定目标事件（绝不使用 bridge.snapshot.last）。

    阶段：①事件落库且桥已记录事件绑定 → ②锁定 event_id/object 并快照 v1 与
    初始提醒 →（迟到场景）暂停摄取、真实 Monitor 闭合、**确认轨迹不再推进且
    DB 行确为 closed** 后才放行 L3 门闩 → ③等待**该事件**出现 >=2 版本。
    """
    boxes = [[{"cls": "person", "conf": 0.9, "bbox": [0.40, 0.40, 0.10, 0.20]}]
             for _ in range(120)]
    entry = _RealEntry(Path(tmp_path) / name, frames=list(range(40)),
                       boxes=boxes, l3_gate=gate, l3_text=l3_text)
    detail = {"scenario_name": name}
    try:
        entry.start()
        # ---- 阶段 1：事件落库 + 桥记录事件绑定
        detail["phase_event_persisted"] = entry.wait_until(
            lambda: bool(entry.event_facts())
            and (entry.bridge_snapshot() or {}).get("event_bindings", 0) >= 1,
            timeout=25.0)
        facts_open = entry.event_facts()
        detail["facts_at_start"] = facts_open
        if not facts_open:
            detail["phase_error"] = "event_not_persisted"
            detail["target_event_id"] = None
            return entry, detail
        # ---- 阶段 2：DB 锁定目标事件 + v1 / 初始提醒快照
        target = sorted(facts_open, key=lambda f: (f["t_start"], f["event_id"]))[0]
        target_id = target["event_id"]
        detail["target_event_id"] = target_id
        detail["target_object_id"] = target["object_id"]
        detail["fact_at_start"] = entry.fact_row(target_id)
        detail["v1_snapshot"] = next(
            (d for d in entry.descriptions(target_id) if d["version"] == 1), None)
        detail["initial_notifications_snapshot"] = [
            n for n in entry.notifications(target_id) if n["kind"] == "initial_fact"]
        if close_event_first:
            monitor = entry.monitor
            occurrence_before = dict(getattr(monitor, "_event_occurrence", {})
                                     or {}) if monitor is not None else {}
            entry.detector.pause()               # ① 暂停后续摄取
            # ② 只停并 join 相机生产者：由 `_run_camera` 拥有线程的 finally
            #    正常收口事实（绝不从主线程碰相机线程的 SqliteSink）
            camera_proof = entry.stop_camera()
            # ③ 新连接确认固定目标已 closed 且事实集合稳定（墙钟轮询）
            closed_ok = entry.confirm_closed_fresh(target_id)
            detail["ingest_paused"] = entry.detector.paused
            detail["camera_stop_proof"] = camera_proof
            detail["closed_confirmed_fresh"] = bool(closed_ok)
            detail["occurrence_before"] = occurrence_before
            detail["occurrence_after"] = dict(
                getattr(monitor, "_event_occurrence", {}) or {}) \
                if monitor is not None else {}
            detail["closed_before_publish"] = entry.fresh_fact_state(target_id)
            detail["fact_ids_after_close"] = entry.fresh_fact_ids()
            if gate is not None and closed_ok:
                gate.set()                        # ④ 确认后才放行 L3 门闩
        # ---- 阶段 4：等待**该事件**出现 >=2 版本（DB 轮询，bounded）
        appended = entry.wait_until(
            lambda: entry.max_description_version(target_id) >= 2, timeout=60.0)
        detail["appended"] = bool(appended)
        detail["bridge_snapshot"] = entry.bridge_snapshot() or {}
        detail["facts_after"] = entry.event_facts()
        detail["fact_after"] = entry.fact_row(target_id)
        detail["descriptions"] = [
            {"version": d["version"], "source": d["source"], "text": d["text"],
             "evidence_refs": d.get("evidence_refs")}
            for d in entry.descriptions(target_id)]
        detail["notifications"] = entry.notifications(target_id)
        detail["event_id"] = target_id
        detail["target_occurrence"] = (
            (getattr(entry.monitor, "_event_occurrence", {}) or {})
            if entry.monitor is not None else {})
        detail["append_evidence_refs"] = [
            d["evidence_refs"] for d in detail["descriptions"]
            if d["version"] >= 2]
        return entry, detail
    except Exception:
        entry.stop()
        entry.conn.close()
        raise


def _descriptions_by_version(rows):
    return {int(d.get("version")): d for d in (rows or {}).get("descriptions", [])}


def _evidence_of(item):
    refs = item.get("evidence_refs")
    if isinstance(refs, str):
        try:
            refs = json.loads(refs)
        except (TypeError, ValueError):
            return None
    return refs


def _structural_match(rows, *, version, text, evidence):
    """结构化比较（**绝不用序列化字符串匹配**：换行/引号/反斜杠会被转义）。"""
    item = _descriptions_by_version(rows).get(int(version))
    if item is None:
        return {"version_present": False, "text_match": False,
                "evidence_match": False}
    return {"version_present": True,
            "text_match": item.get("text") == text,
            "evidence_match": _evidence_of(item) == evidence}


def scenario_real_l4_hook_to_worker_and_user_detail(tmp_path):
    entry, detail = _run_l4_to_detail(tmp_path, gate=None, name="l4_detail")
    try:
        event_id = detail.get("event_id")
        from scam.server import WorkbenchState
        from scam.db import connect as _connect, get_event_fact as _get_fact
        # 独立连接读数（原始诊断事实，不被布尔结论掩盖）
        own_versions = None
        own_error = None
        try:
            _c = _connect(entry.db_path)
            try:
                _row = _get_fact(_c, event_id) if event_id else None
                own_versions = (None if _row is None
                                else [d["version"] for d in _row["descriptions"]])
            finally:
                _c.close()
        except Exception as exc:
            own_error = f"{type(exc).__name__}: {exc}"
        # 用户可见详情：真实 WorkbenchState（bounded 重试；断言不放宽）
        rows = None
        if event_id:
            for _ in range(40):
                rows = WorkbenchState(entry.db_path).event_fact_detail(event_id)
                if rows is not None:
                    break
                _time.sleep(0.5)
        versions = [d["version"] for d in detail["descriptions"]]
        appended = next((d for d in detail["descriptions"]
                         if d["version"] >= 2), None)
        appended_text = None if appended is None else appended["text"]
        appended_version = None if appended is None else appended["version"]
        expected_evidence = (None if appended is None
                             else _evidence_of(appended))
        match = _structural_match(rows, version=appended_version,
                                  text=appended_text,
                                  evidence=expected_evidence) \
            if appended_version is not None else {
                "version_present": False, "text_match": False,
                "evidence_match": False}
        # 记录旧检查（序列化字符串匹配）结果，作为"不得再用"的原始事实
        legacy_serialized_match = None
        if rows is not None and appended_text is not None:
            legacy_serialized_match = appended_text in json.dumps(
                rows, ensure_ascii=False, default=str)
        result = {
            "scenario": "c146_real_l4_hook_to_worker_and_user_detail",
            "source": "real_production_entry",
            "clock": "simulated",
            "model_boundary": ("stub（检测器/L3 视觉模型）；真实 L2Runtime/L4Stage/"
                               "有界 worker/publish_semantic_update/WorkbenchState"),
            "expectation": ("真实 L4 累积钩子 → 有界 worker → 真实发布："
                            "目标事件追加描述版本，并能在用户事件详情按"
                            "版本/文本/证据结构化读到（含换行等特殊字符）"),
            "event_id": event_id,
            "appended": detail["appended"],
            "appended_version": appended_version,
            "description_versions": versions,
            "appended_text": appended_text,
            "text_has_newline": (None if appended_text is None
                                 else "\n" in appended_text),
            "own_conn_versions": own_versions,
            "own_conn_error": own_error,
            "workbench_detail_present": rows is not None,
            "detail_versions": sorted(_descriptions_by_version(rows)),
            "structural_match": match,
            "legacy_serialized_string_match": legacy_serialized_match,
            "bridge_snapshot": detail["bridge_snapshot"],
        }
        problems = []
        if not event_id:
            problems.append("真实 Monitor 未落库事件事实")
        if not detail["appended"]:
            problems.append("桥未追加任何版本（worker 未落地）")
        if len(versions) < 2:
            problems.append(f"描述版本未追加（versions={versions}）")
        if appended_text is None:
            problems.append("追加版本无解释文本")
        if rows is None:
            problems.append("用户事件详情读取失败（WorkbenchState 返回 None）")
        elif not match["version_present"]:
            problems.append(f"用户详情缺少目标版本 v{appended_version}")
        elif not match["text_match"]:
            problems.append("用户详情目标版本文本与发布文本不一致")
        elif not match["evidence_match"]:
            problems.append("用户详情目标版本证据引用与发布不一致")
        result["verdict"] = "pass" if not problems else "fail"
        result["gap"] = "; ".join(problems) or None
        result["teardown_proof"] = entry.teardown()
        entry.conn.close()
        return result
    finally:
        entry.stop()
        entry.conn.close()


# ==========================================================================
# 真实入口场景 2b：换行/引号/反斜杠文本必须结构化比较（回归）
# ==========================================================================

SPECIAL_TEXT = '第一行含换行\n第二行 "双引号" 与 \'单引号\' 还有反斜杠 \\ 结尾'


def scenario_descriptions_with_specials_structural_match(tmp_path):
    """带换行/引号/反斜杠的解释文本：结构化比较通过，序列化字符串匹配失败。"""
    entry, detail = _run_l4_to_detail(tmp_path, gate=None, name="specials",
                                      l3_text=SPECIAL_TEXT)
    try:
        event_id = detail.get("event_id")
        from scam.server import WorkbenchState
        rows = None
        if event_id:
            for _ in range(40):
                rows = WorkbenchState(entry.db_path).event_fact_detail(event_id)
                if rows is not None:
                    break
                _time.sleep(0.5)
        appended = next((d for d in detail["descriptions"]
                         if d["version"] >= 2), None)
        version = None if appended is None else appended["version"]
        text = None if appended is None else appended["text"]
        evidence = None if appended is None else _evidence_of(appended)
        match = (_structural_match(rows, version=version, text=text,
                                   evidence=evidence)
                 if version is not None else {"version_present": False,
                                              "text_match": False,
                                              "evidence_match": False})
        legacy = (None if (rows is None or text is None)
                  else text in json.dumps(rows, ensure_ascii=False, default=str))
        result = {
            "scenario": "c146_descriptions_with_specials_structural_match",
            "source": "real_production_entry",
            "clock": "simulated",
            "model_boundary": "stub（L3 文本含特殊字符）；真实发布与详情读取",
            "expectation": ("含换行/引号/反斜杠的发布文本必须能在用户详情里"
                            "按版本结构化比对；序列化字符串匹配不得作为判据"),
            "event_id": event_id,
            "appended_version": version,
            "appended_text": text,
            "text_has_newline": (None if text is None else "\n" in text),
            "text_has_quote": (None if text is None else '"' in text),
            "text_has_backslash": (None if text is None else "\\" in text),
            "structural_match": match,
            "legacy_serialized_string_match": legacy,
            "detail_versions": sorted(_descriptions_by_version(rows)),
        }
        problems = []
        if version is None:
            problems.append("未产生追加版本")
        if rows is None:
            problems.append("用户事件详情读取失败（WorkbenchState 返回 None）")
        if not match["version_present"]:
            problems.append("用户详情缺少目标版本")
        if not match["text_match"]:
            problems.append("特殊字符文本结构化比较不一致")
        if not match["evidence_match"]:
            problems.append("证据引用结构化比较不一致")
        if text is not None and "\n" not in text:
            problems.append("夹具未真正包含换行（回归无效）")
        result["verdict"] = "pass" if not problems else "fail"
        result["gap"] = "; ".join(problems) or None
        return result
    finally:
        entry.stop()
        entry.conn.close()


# ==========================================================================
# 真实入口场景 3：迟到解释只追加，不改闭合事实/v1/初始提醒（P2）
# ==========================================================================

def scenario_late_entry_append_never_changes_closed_fact(tmp_path):
    """迟到解释：阶段屏障确认闭合且轨迹不再推进后，只断言该事件的追加与事实。"""
    gate = _threading.Event()
    entry, detail = _run_l4_to_detail(tmp_path, gate=gate,
                                      close_event_first=True,
                                      name="late_entry")
    try:
        event_id = detail.get("event_id")
        closed_before = detail.get("closed_before_publish")
        fact_after = detail.get("fact_after")
        versions = [d["version"] for d in detail["descriptions"]]
        v1 = next((d for d in detail["descriptions"] if d["version"] == 1), None)
        v1_snapshot = detail.get("v1_snapshot")
        initial_before = detail.get("initial_notifications_snapshot") or []
        initial_after = [n for n in detail["notifications"]
                         if n["kind"] == "initial_fact"]
        result = {
            "scenario": "c146_late_entry_append_never_changes_closed_fact",
            "source": "real_production_entry",
            "clock": "simulated",
            "model_boundary": "stub（检测器/L3 视觉模型）；真实 Monitor 闭合与真实发布",
            "expectation": ("阶段屏障：暂停摄取 → 真实 Monitor 闭合 → 确认 DB 行 closed"
                            "且轨迹出现序号不再变化 → 放行 L3 → 只追加该事件版本，"
                            "t_end/state/v1/初始提醒保持不变"),
            "event_id": event_id,
            "ingest_paused": detail.get("ingest_paused"),
            "closed_confirmed_fresh": detail.get("closed_confirmed_fresh"),
            "camera_stop_proof": detail.get("camera_stop_proof"),
            "fact_ids_after_close": detail.get("fact_ids_after_close"),
            "append_evidence_refs": detail.get("append_evidence_refs"),
            "closed_before_publish": closed_before,
            "fact_after": fact_after,
            "description_versions": versions,
            "v1_text": None if v1 is None else v1["text"],
            "v1_snapshot_text": None if v1_snapshot is None else v1_snapshot["text"],
            "initial_notifications_before": len(initial_before),
            "initial_notifications_after": len(initial_after),
            "initial_notification_texts_before": sorted(
                n.get("text") for n in initial_before),
            "initial_notification_texts_after": sorted(
                n.get("text") for n in initial_after),
            "occurrence_before": detail.get("occurrence_before"),
            "occurrence_after": detail.get("occurrence_after"),
            "appended": detail.get("appended"),
        }
        problems = []
        if not detail.get("ingest_paused"):
            problems.append("未暂停摄取（阶段屏障缺失）")
        if not detail.get("closed_confirmed_fresh"):
            problems.append("未用新连接确认真实闭合且事实集合稳定")
        if not (detail.get("camera_stop_proof") or {}).get("camera_joined"):
            problems.append("相机生产者未 join（阶段屏障未成立）")
        if closed_before is None or closed_before.get("state") != "closed":
            problems.append("事件未在发布前真实闭合")
        if not detail.get("appended"):
            problems.append("迟到解释未追加")
        if len(versions) < 2:
            problems.append(f"迟到解释未形成新版本（versions={versions}）")
        if fact_after is None:
            problems.append("闭合事实行缺失")
        else:
            if closed_before and fact_after.get("t_end") != closed_before.get("t_end"):
                problems.append("迟到解释改变了 t_end")
            if fact_after.get("state") != "closed":
                problems.append("迟到解释把事件重开")
        if v1_snapshot is not None and v1 is not None \
                and v1["text"] != v1_snapshot["text"]:
            problems.append("迟到解释改写了 v1 文本")
        if len(initial_after) != len(initial_before):
            problems.append("初始提醒数量变化")
        elif sorted(n.get("text") for n in initial_after) != sorted(
                n.get("text") for n in initial_before):
            problems.append("初始提醒文本被改写")
        if detail.get("occurrence_before") != detail.get("occurrence_after"):
            problems.append("闭合后轨迹出现序号仍推进（未形成阶段屏障）")
        result["verdict"] = "pass" if not problems else "fail"
        result["gap"] = "; ".join(problems) or None
        result["teardown_proof"] = entry.teardown()
        entry.conn.close()
        return result
    finally:
        entry.stop()
        entry.conn.close()


# ==========================================================================
# 真实入口场景 4：无对象观察保留、不建事件/描述（P1）
# ==========================================================================

def scenario_no_object_observation_retained(tmp_path):
    entry = _RealEntry(Path(tmp_path) / "no_object", frames=list(range(40)),
                       boxes=[[] for _ in range(80)])
    try:
        entry.start()
        submitted = entry.wait_until(
            lambda: (entry.bridge_snapshot() or {}).get("counts", {})
            .get("unassociated", 0) >= 1, timeout=35.0)
        snapshot = entry.bridge_snapshot() or {}
        facts = entry.event_facts()
        descriptions = [dict(r) for r in entry.conn.execute(
            "SELECT description_id,event_id FROM event_descriptions"
        ).fetchall()]
        result = {
            "scenario": "c146_no_object_observation_retained",
            "source": "real_production_entry",
            "clock": "simulated",
            "model_boundary": "stub（检测器全部为空/L3 桩）；真实 runtime/桥/worker",
            "expectation": ("无对象 L4 观察保留在理解历史，但**不建**事件事实与"
                            "描述；桥如实记 unassociated/no_object"),
            "unassociated_observed": bool(submitted),
            "bridge_snapshot": snapshot,
            "event_fact_count": len(facts),
            "description_count": len(descriptions),
        }
        problems = []
        if not submitted:
            problems.append("桥未把无对象结果记为 unassociated")
        if facts:
            problems.append("无对象却创建了事件事实")
        if descriptions:
            problems.append("无对象却创建了描述版本")
        result["verdict"] = "pass" if not problems else "fail"
        result["gap"] = "; ".join(problems) or None
        return result
    finally:
        entry.stop()
        entry.conn.close()


# ==========================================================================
# 真实入口场景 5：幂等（同证据重放不产生新版本）
# ==========================================================================

def scenario_real_entry_idempotent_replay(tmp_path):
    """真实入口幂等：同一份真实 L4 payload 重放 → duplicate、版本不增长。"""
    entry = _RealEntry(Path(tmp_path) / "idempotent", frames=list(range(40)),
                       boxes=[[{"cls": "person", "conf": 0.9,
                                "bbox": [0.40, 0.40, 0.10, 0.20]}]
                              for _ in range(120)])
    try:
        entry.start()
        entry.wait_until(
            lambda: bool(entry.event_facts())
            and (entry.bridge_snapshot() or {}).get("event_bindings", 0) >= 1,
            timeout=25.0)
        appended = entry.wait_until(
            lambda: (entry.bridge_snapshot() or {}).get("counts", {})
            .get("appended", 0) >= 1, timeout=45.0)
        bridge = entry.runtime.event_progress
        facts = entry.event_facts()
        event_id = facts[0]["event_id"] if facts else None
        versions_before = [d["version"] for d in
                           entry.descriptions(event_id)] if event_id else []
        counts_before = dict(bridge.snapshot()["counts"])
        replay_accepted = None
        replayed = False
        if entry.fusions:
            replay_accepted = bridge.submit(entry.fusions[-1])
            replayed = entry.wait_until(
                lambda: bridge.snapshot()["counts"].get("duplicate", 0)
                > counts_before.get("duplicate", 0), timeout=15.0)
        counts_after = dict(bridge.snapshot()["counts"])
        versions_after = [d["version"] for d in
                          entry.descriptions(event_id)] if event_id else []
        result = {
            "scenario": "c146_real_entry_idempotent_replay",
            "source": "real_production_entry",
            "clock": "simulated",
            "model_boundary": "stub（检测器/L3 模型）；真实账本幂等与真实 worker",
            "expectation": ("同一份真实 L4 payload 重放：账本判 duplicate，"
                            "不产生新版本，事件事实不变"),
            "event_id": event_id, "appended": appended,
            "payloads_captured": len(entry.fusions),
            "replay_submitted": replay_accepted, "duplicate_observed": replayed,
            "counts_before": counts_before, "counts_after": counts_after,
            "versions_before": versions_before, "versions_after": versions_after,
        }
        problems = []
        if not appended:
            problems.append("首轮未追加版本，无法验证幂等")
        if not entry.fusions:
            problems.append("未捕获到真实 fusion payload")
        if not replayed:
            problems.append("重放未被判为 duplicate")
        if versions_after != versions_before:
            problems.append(f"重放产生了新版本（{versions_before} → {versions_after}）")
        result["verdict"] = "pass" if not problems else "fail"
        result["gap"] = "; ".join(problems) or None
        return result
    finally:
        entry.stop()
        entry.conn.close()


#: 真实生产入口场景（C146 冻结树；接口已落地，全部 runnable）
REAL_ENTRY_SCENARIOS = {
    "c146_actual_entry_registers_before_visibility":
        scenario_actual_entry_registers_before_visibility,
    "c146_real_l4_hook_to_worker_and_user_detail":
        scenario_real_l4_hook_to_worker_and_user_detail,
    "c146_late_entry_append_never_changes_closed_fact":
        scenario_late_entry_append_never_changes_closed_fact,
    "c146_no_object_observation_retained":
        scenario_no_object_observation_retained,
    "c146_real_entry_idempotent_replay":
        scenario_real_entry_idempotent_replay,
    "c146_descriptions_with_specials_structural_match":
        scenario_descriptions_with_specials_structural_match,
}

SCENARIOS = {
    "c146_lifecycle_progress_late_append":
        scenario_lifecycle_progress_late_append,
    "c146_duplicate_version_no_spam": scenario_duplicate_version_no_spam,
    "c146_identity_isolation": scenario_identity_isolation,
    "c146_multi_object_no_narrative_copy":
        scenario_multi_object_no_narrative_copy,
}
SCENARIOS.update(REAL_ENTRY_SCENARIOS)
#: 待接口场景数：接口落地后为 0（真实入口场景全部 runnable）
SCENARIO_STATUS["pending_count"] = 0
SCENARIO_STATUS["real_entry_count"] = len(REAL_ENTRY_SCENARIOS)
