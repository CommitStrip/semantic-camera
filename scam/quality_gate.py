"""scam.quality_gate —— T 线质量判定器（冻结版）。

只读三层真值表 + 冻结标注集 → 混淆表 / 误报漏报率 / 告警延迟分位数 /
慢系统趋势位。fail-closed：样本不足或六场景任一缺失时输出
insufficient_data，所有门禁结论保持 null——绝不把样本不足的数据
编成"准"的门禁结论（T 线合同）。

可复现：报告携带判定器版本常量与输入哈希（标注集+数据库），同一输入
任何人复跑得到同一份报告。
"""

import hashlib
import json
import math

GATE_VERSION = "scam.quality-gate/v3"
ANNOTATION_SCHEMA = "scam.quality-annotations/v1"

# 冻结的场景维度（T 线合同：昼夜/遮挡/进出/滞留/跨区/无目标）
REQUIRED_SCENARIOS = ("day", "night", "occlusion", "enter", "dwell",
                      "cross-zone", "no-target")

# 冻结判定参数（改动=新版本，不允许静默调参）
MATCH_WINDOW_S = 5.0        # 标注时刻与告警时刻的匹配窗
MIN_SAMPLES_PER_SCENARIO = 3
LATENCY_PERCENTILES = (50, 95, 99)


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_annotations(path):
    """加载并校验标注集；schema 不符抛 ValueError（fail-closed，不猜格式）。"""
    with open(path, "rb") as handle:
        raw = handle.read()
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict) or \
            data.get("schema") != ANNOTATION_SCHEMA:
        raise ValueError(f"标注集 schema 必须为 {ANNOTATION_SCHEMA}")
    annotations = data.get("annotations")
    if not isinstance(annotations, list) or not annotations:
        raise ValueError("标注集 annotations 必须为非空数组")
    for item in annotations:
        if not isinstance(item, dict) or \
                not isinstance(item.get("camera"), str) or \
                not isinstance(item.get("expect"), str) or \
                item["expect"] not in ("alarm", "no_alarm") or \
                not isinstance(item.get("scenario"), str):
            raise ValueError(f"标注条目字段不合法: {item!r}")
        _finite_time(item.get("t_start"), "annotation.t_start")
    return data, _sha256_bytes(raw)


def _percentile(sorted_values, pct):
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (len(sorted_values) - 1) * (pct / 100.0)
    low = int(rank)
    high = min(low + 1, len(sorted_values) - 1)
    frac = rank - low
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * frac


def _finite_time(value, what):
    """P0-B 输入守卫：有限实数时间——拒绝 bool/非数值/NaN/±Inf（fail-closed）。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{what} 必须为有限实数（拒绝 bool/非数值）")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{what} 必须为有限实数（拒绝 NaN/±Inf）")
    return number


def _canonical_key(item, index):
    """与数组位置无关的规范标注键。

    前六段全部来自语义字段（含完整标注对象的稳定 canonical JSON）；
    原始数组序号仅作为'语义完全相同的重复标注'的最终内部身份。
    """
    cls = item.get("cls")
    cls_key = cls if isinstance(cls, str) else ""
    canonical = json.dumps(item, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":"))
    return (str(item.get("camera")), _finite_time(item.get("t_start"),
                                                   "annotation.t_start"),
            str(item.get("expect")), str(item.get("scenario")),
            cls_key, canonical, index)


def _events_of(conn, camera):
    """稳定事件读取：标识/时间/类别/区域，排序确定（t_start, event_id）。

    P0-B：事件 t_start 必须为有限实数——坏类型/NaN/±Inf 结构化失败，
    绝不进入排序或匹配（拒绝依赖平台偶然顺序）。
    """
    rows = conn.execute(
        "SELECT semantic_event_id,t_start,t_end,cls,zone_id"
        " FROM semantic_events WHERE camera=?"
        " ORDER BY t_start, semantic_event_id", (camera,)).fetchall()
    events = []
    for row in rows:
        item = dict(row)
        try:
            item["t_start"] = _finite_time(item.get("t_start"),
                                           "event.t_start")
        except ValueError as exc:
            raise ValueError(
                f"事件 {item.get('semantic_event_id')!r} 的 t_start 非法："
                f"{exc}") from exc
        events.append(item)
    return events


def evaluate(conn, annotations, *, annotation_sha256, db_sha256=None):
    """冻结判定：标注 vs 语义事件 → 报告 dict。只读，绝不写库。"""
    report = {
        "gate_version": GATE_VERSION,
        "annotation_schema": ANNOTATION_SCHEMA,
        "input_hashes": {"annotations": annotation_sha256,
                         "database": db_sha256},
        "scenarios_present": [],
        "scenarios_missing": [],
        "counts": {}, "confusion": {},
        "rates": {}, "latency_ms": {},
        "vlm_trend": None,          # T 线约束：S2 真实运行计数前保持 null
        "vlm_trend_reason": "requires_s2_runtime_counters",
        "gates": {"accuracy": None},  # 门禁结论：fail-closed 时永远 null
        "status": None,
    }

    # 场景覆盖检查（fail-closed）
    present = {item["scenario"] for item in annotations["annotations"]}
    report["scenarios_present"] = sorted(present & set(REQUIRED_SCENARIOS))
    report["scenarios_missing"] = \
        sorted(set(REQUIRED_SCENARIOS) - present)

    # ===== P0-B 两阶段：先全局最大基数一对一匹配，后对未匹配事件计 FP =====
    # 阶段一：alarm 标注 × semantic_event 的确定性最大基数匹配
    #   （Kuhn 增广路径；左按 (camera,t_start,原始序号)、候选右按
    #   (latency,t_start,event_id) 稳定排序 → 同输入同输出）
    # 阶段二：未匹配事件按"相关 annotation 窗口"计 FP（全局每事件一次，
    #   归属 annotation 唯一确定）；no_alarm 的 TN 只要求窗口内无任何
    #   符合类别条件的事件（已匹配事件也阻止 TN，但不重复计 FP）。
    per_scenario = {}
    latencies = []
    events_cache = {}
    ordered = sorted(
        enumerate(annotations["annotations"]),
        key=lambda pair: _canonical_key(pair[1], pair[0]))
    rank_of = {idx: rank for rank, (idx, _) in enumerate(ordered)}
    for _, item in ordered:
        per_scenario.setdefault(item["scenario"], {"n": 0})["n"] += 1

    def events_of(camera):
        if camera not in events_cache:
            events_cache[camera] = _events_of(conn, camera)
        return events_cache[camera]

    def _candidates(ann):
        w0 = float(ann["t_start"])
        w1 = w0 + MATCH_WINDOW_S
        cands = [e for e in events_of(ann["camera"])
                 if w0 <= float(e["t_start"]) <= w1
                 and (ann.get("cls") is None or e["cls"] == ann.get("cls"))]
        cands.sort(key=lambda e: (float(e["t_start"]) - w0,
                                  float(e["t_start"]),
                                  e["semantic_event_id"]))
        return cands

    alarms = [(idx, it) for idx, it in ordered if it["expect"] == "alarm"]
    ann_by_idx = {idx: it for idx, it in alarms}
    match_ann = {}          # alarm 原始序号 -> event（匹配边）
    match_ev = {}           # event_id -> alarm 原始序号

    def _augment(ann_idx, visited):
        for e in _candidates(ann_by_idx[ann_idx]):
            eid = e["semantic_event_id"]
            if eid in visited:
                continue
            visited.add(eid)
            if eid not in match_ev:
                match_ann[ann_idx] = e
                match_ev[eid] = ann_idx
                return True
            other = match_ev[eid]
            if _augment(other, visited):
                match_ann[ann_idx] = e
                match_ev[eid] = ann_idx
                return True
        return False

    for ann_idx, _ann in alarms:              # 稳定序左节点，逐个增广
        _augment(ann_idx, set())

    tp = fn = 0
    for ann_idx, ann in alarms:
        bucket = per_scenario[ann["scenario"]]
        if ann_idx in match_ann:
            e = match_ann[ann_idx]
            tp += 1
            bucket["tp"] = bucket.get("tp", 0) + 1
            latencies.append(max(0.0, float(e["t_start"])
                                 - float(ann["t_start"])) * 1000.0)
        else:
            fn += 1
            bucket["fn"] = bucket.get("fn", 0) + 1

    # 阶段二：未匹配事件的 FP（全局每事件最多一次，归属唯一确定）
    fp = 0
    matched_eids = set(match_ev)
    fp_counted = set()
    for camera in list(dict.fromkeys(it["camera"] for _, it in ordered)):
        cam_anns = [(idx, it) for idx, it in ordered
                    if it["camera"] == camera]
        for e in events_of(camera):
            eid = e["semantic_event_id"]
            if eid in matched_eids or eid in fp_counted:
                continue
            t = float(e["t_start"])
            related = []
            for idx, ann in cam_anns:
                if ann.get("cls") is not None and \
                        e["cls"] != ann.get("cls"):
                    continue
                ts = float(ann["t_start"])
                if ts - MATCH_WINDOW_S <= t <= ts + MATCH_WINDOW_S:
                    related.append((abs(t - ts), ts, rank_of[idx], ann))
            if not related:
                continue                       # 所有窗口之外：不扩大评估范围
            related.sort()
            owner = related[0][3]
            bucket = per_scenario[owner["scenario"]]
            bucket["fp"] = bucket.get("fp", 0) + 1
            fp += 1
            fp_counted.add(eid)

    # no_alarm TN：窗口内不存在任何符合类别条件的事件才计（含已匹配事件
    # 也阻止 TN；该事件不因此重复计第二次 FP）
    for _, ann in ordered:
        if ann["expect"] == "alarm":
            continue
        ts = float(ann["t_start"])
        has_any = any(
            ts - MATCH_WINDOW_S <= float(e["t_start"]) <= ts + MATCH_WINDOW_S
            and (ann.get("cls") is None or e["cls"] == ann.get("cls"))
            for e in events_of(ann["camera"]))
        if not has_any:
            bucket = per_scenario[ann["scenario"]]
            bucket["tn"] = bucket.get("tn", 0) + 1

    report["counts"] = {"annotations": len(annotations["annotations"]),
                        "tp": tp, "fp": fp, "fn": fn,
                        "tn": per_scenario and sum(
                            b.get("tn", 0) for b in per_scenario.values())}
    report["confusion"] = per_scenario
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    report["rates"] = {"precision": precision, "recall": recall,
                       "false_alarm_rate": fp / (fp + sum(
                           b.get("tn", 0) for b in per_scenario.values()))
                       if (fp + report["counts"]["tn"]) else None}
    latencies.sort()
    for pct in LATENCY_PERCENTILES:
        report["latency_ms"][f"p{pct}"] = \
            round(_percentile(latencies, pct), 1) if latencies else None
    report["latency_ms"]["samples"] = len(latencies)

    # fail-closed 判定：场景缺失或样本不足 → 不出任何门禁结论
    insufficient = bool(report["scenarios_missing"]) or any(
        b["n"] < MIN_SAMPLES_PER_SCENARIO for b in per_scenario.values())
    if insufficient:
        report["status"] = "insufficient_data"
        report["insufficient_reason"] = {
            "missing_scenarios": report["scenarios_missing"],
            "min_samples_per_scenario": MIN_SAMPLES_PER_SCENARIO,
            "scenario_counts": {k: v["n"] for k, v in per_scenario.items()},
        }
    else:
        report["status"] = "evaluated"
        # 门禁结论留空：真实阈值由发布门禁表在 T 线拿到冻结标注集后填入；
        # 本判定器只负责可复现地出数，不替门禁表做通过判断。
        report["gates"]["accuracy"] = "pending_threshold_definition"
    return report
