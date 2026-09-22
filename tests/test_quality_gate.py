"""LZ-051 T 线质量判定器测试：混淆/延迟/fail-closed/可复现哈希。"""

import json

import pytest

import scam.db as db
from scam.quality_gate import (GATE_VERSION, MIN_SAMPLES_PER_SCENARIO,
                               evaluate, load_annotations)


def _conn(tmp_path):
    conn = db.connect(str(tmp_path / "q.db"))
    db.init_schema(conn)
    return conn


def _annotate(tmp_path, items):
    """items: [(camera, t_start, expect, scenario)] → 标注集文件路径。"""
    payload = {"schema": "scam.quality-annotations/v1",
               "dataset": "test-set",
               "annotations": [
                   {"camera": c, "t_start": t, "expect": e, "scenario": s}
                   for c, t, e, s in items]}
    path = tmp_path / "annotations.json"
    path.write_text(json.dumps(payload, ensure_ascii=False),
                    encoding="utf-8")
    return path


def _alarm(conn, rid, camera, t_start, cls="person"):
    # semantic_events 有外键：先建真实审查段与对象
    db.open_review_segment(conn, review_id=f"{rid}:rev", camera=camera,
                           t_start=t_start - 2.0)
    db.close_review_segment(conn, f"{rid}:rev", t_end=t_start + 30.0,
                            reason="quiet")
    db.open_tracked_object(conn, object_id=f"{rid}:obj", camera=camera,
                           t_start=t_start, cls=cls)
    db.close_tracked_object(conn, f"{rid}:obj", t_end=t_start + 20.0,
                            reason="gone")
    db.open_semantic_event(
        conn, semantic_event_id=rid, camera=camera, review_id=f"{rid}:rev",
        object_id=f"{rid}:obj", t_start=t_start, template="enter-dwell",
        zone_id="z1", cls=cls)
    db.close_semantic_event(conn, rid, t_end=t_start + 5.0, reason="left")


def _full_scenarios(base_t=1000.0, step=100.0, per=MIN_SAMPLES_PER_SCENARIO):
    """六场景 × 每场景最小样本的完整标注（全部期望告警）。"""
    scenarios = ("day", "night", "occlusion", "enter", "dwell",
                 "cross-zone", "no-target")
    items = []
    t = base_t
    for s in scenarios:
        for i in range(per):
            expect = "no_alarm" if s == "no-target" else "alarm"
            items.append(("front", t, expect, s))
            t += step
    return items


# ---------- 混淆与延迟 ----------

def test_confusion_and_latency(tmp_path):
    conn = _conn(tmp_path)
    items = _full_scenarios()
    for idx, (camera, t, expect, _s) in enumerate(items):
        if expect == "alarm" and idx % 3 != 2:   # 2/3 告警按时出现
            _alarm(conn, f"ev-{idx}", camera, t + 1.0)   # 延迟 1s
    conn.commit()

    ann_path = _annotate(tmp_path, items)
    annotations, sha = load_annotations(ann_path)
    report = evaluate(conn, annotations, annotation_sha256=sha)

    n_alarm = sum(1 for i in items if i[2] == "alarm")
    per_scenario_n = {i[3] for i in items}
    assert report["status"] == "evaluated"
    assert report["counts"]["fn"] == n_alarm // 3
    assert report["latency_ms"]["samples"] == n_alarm - n_alarm // 3
    assert report["latency_ms"]["p50"] == 1000.0      # 全部 1s 延迟
    assert report["latency_ms"]["p95"] == 1000.0
    assert report["vlm_trend"] is None                # T 线约束：null
    conn.close()


def test_false_alarm_counted(tmp_path):
    conn = _conn(tmp_path)
    items = _full_scenarios()
    # 期望告警的全给；另加 2 条无标注窗口内的告警（无目标场景时段）
    for idx, (camera, t, expect, _s) in enumerate(items):
        if expect == "alarm":
            _alarm(conn, f"ev-{idx}", camera, t)
    no_target_ts = [t for c, t, e, s in items if s == "no-target"]
    _alarm(conn, "fp-1", "front", no_target_ts[0] + 0.5)
    _alarm(conn, "fp-2", "front", no_target_ts[1] + 0.5)
    conn.commit()

    annotations, sha = load_annotations(_annotate(tmp_path, items))
    report = evaluate(conn, annotations, annotation_sha256=sha)
    assert report["counts"]["fp"] == 2
    assert report["rates"]["precision"] < 1.0
    conn.close()


# ---------- fail-closed ----------

def test_missing_scenario_fails_closed(tmp_path):
    conn = _conn(tmp_path)
    items = [i for i in _full_scenarios() if i[3] != "occlusion"]
    annotations, sha = load_annotations(_annotate(tmp_path, items))
    report = evaluate(conn, annotations, annotation_sha256=sha)

    assert report["status"] == "insufficient_data"
    assert report["scenarios_missing"] == ["occlusion"]
    assert report["gates"]["accuracy"] is None, \
        "fail-closed 时门禁结论必须为 null"
    conn.close()


def test_insufficient_samples_fail_closed(tmp_path):
    conn = _conn(tmp_path)
    items = _full_scenarios()
    items = items[:len(items) - 1]        # 抽掉一条 → 某场景样本不足
    annotations, sha = load_annotations(_annotate(tmp_path, items))
    report = evaluate(conn, annotations, annotation_sha256=sha)

    assert report["status"] == "insufficient_data"
    assert report["gates"]["accuracy"] is None
    conn.close()


def test_bad_schema_rejected(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"schema": "wrong", "annotations": []}),
                    encoding="utf-8")
    with pytest.raises(ValueError):
        load_annotations(path)


# ---------- 可复现 ----------

def test_report_is_reproducible(tmp_path):
    conn = _conn(tmp_path)
    items = _full_scenarios()
    for idx, (camera, t, expect, _s) in enumerate(items):
        if expect == "alarm":
            _alarm(conn, f"ev-{idx}", camera, t)
    conn.commit()

    annotations, sha = load_annotations(_annotate(tmp_path, items))
    r1 = evaluate(conn, annotations, annotation_sha256=sha)
    r2 = evaluate(conn, annotations, annotation_sha256=sha)
    assert r1 == r2, "同一输入必须逐字节一致（他人可复跑）"
    assert r1["gate_version"] == GATE_VERSION
    assert r1["input_hashes"]["annotations"] == sha
    conn.close()


# ---------- LZ-065 P1-6：窗口多告警与超前匹配口径 ----------

def test_multiple_alarms_in_window_count_excess_as_fp(tmp_path):
    conn = _conn(tmp_path)
    items = _full_scenarios()
    # 给第一个 alarm 标注塞两条同时刻告警：1 TP + 1 FP
    first_alarm_t = next(t for c, t, e, s in items if e == "alarm")
    _alarm(conn, "ev-multi-1", "front", first_alarm_t)
    _alarm(conn, "ev-multi-2", "front", first_alarm_t + 0.5)
    conn.commit()
    annotations, sha = load_annotations(_annotate(tmp_path, items))
    report = evaluate(conn, annotations, annotation_sha256=sha)
    assert report["counts"]["fp"] >= 1, "窗口内第二条告警必须计 FP"
    conn.close()


def test_early_alarm_is_fp_not_zero_latency_tp(tmp_path):
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_alarm_t = next(t for c, t, e, s in items if e == "alarm")
    _alarm(conn, "ev-early", "front", first_alarm_t - 3.0)  # 超前于标注
    conn.commit()
    annotations, sha = load_annotations(_annotate(tmp_path, items))
    report = evaluate(conn, annotations, annotation_sha256=sha)
    assert report["counts"]["fp"] >= 1, "超前匹配必须计 FP"
    assert report["latency_ms"]["samples"] == 0 or         report["latency_ms"]["p50"] != 0.0
    conn.close()


# ============ SC-A-R1 P0-3：一对一确定性匹配 ============

# fixture 中相邻标注间隔 100s（step=100）：所有本组用例把新事件与标注放在
# first_t+50 的隔离基准域，确保争用只发生在本用例新增的标注之间。
BASE_OFFSET = 50.0


def test_one_event_cannot_satisfy_two_positive_annotations(tmp_path):
    """一条事件 + 两条相近 alarm 标注：只能 tp=1、另一条 fn，绝不 tp=2。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    _alarm(conn, "ev-single", "front", base + 0.5)
    conn.commit()
    items.append(("front", base, "alarm", "enter"))
    items.append(("front", base + 1.0, "alarm", "enter"))

    annotations, sha = load_annotations(_annotate(tmp_path, items))
    report = evaluate(conn, annotations, annotation_sha256=sha)

    assert report["counts"]["tp"] == 1, "唯一事件只能满足一条正标注"
    assert report["counts"]["fn"] >= 1, "未能获得事件的 alarm 标注计 fn"
    conn.close()


def test_two_events_two_annotations_match_one_to_one_deterministically(
        tmp_path):
    """两条相近标注 + 两条候选事件：稳定一对一，重复执行报告全等。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    # 两条标注各自窗口（±5s）只含自己的事件——一对一确定分配
    _alarm(conn, "ev-d1", "front", base + 1.0)
    _alarm(conn, "ev-d2", "front", base + 9.0)
    conn.commit()
    items.append(("front", base, "alarm", "enter"))
    items.append(("front", base + 8.0, "alarm", "enter"))

    annotations, sha = load_annotations(_annotate(tmp_path, items))
    r1 = evaluate(conn, annotations, annotation_sha256=sha)
    r2 = evaluate(conn, annotations, annotation_sha256=sha)

    assert r1 == r2, "不受数据库返回偶然顺序影响的确定性匹配"
    assert r1["counts"]["tp"] == 2, "两条事件稳定一对一两 TP"
    conn.close()


def test_overlapping_windows_count_excess_event_only_once(tmp_path):
    """两条重叠标注：不可匹配的额外事件只能计一次 FP（不因两窗口计两次）。

    v2 口径说明：额外事件放在 base+1.5——只落入 A1(base) 窗口、在 A2
    (base+2) 的 on-time 下界之外，因此最大匹配后确实无标注可配它，
    才会进入 FP 口径；FP 归属唯一、恰一次。
    """
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    _alarm(conn, "ev-pick", "front", base + 0.5)    # 选中为 TP
    _alarm(conn, "ev-extra", "front", base + 1.5)   # 不可匹配的额外事件
    conn.commit()
    items.append(("front", base, "alarm", "enter"))
    items.append(("front", base + 2.0, "alarm", "enter"))

    annotations, sha = load_annotations(_annotate(tmp_path, items))
    report = evaluate(conn, annotations, annotation_sha256=sha)

    assert report["counts"]["tp"] == 1
    assert report["counts"]["fp"] == 1, \
        "额外事件恰好一次 FP（重叠窗口不重复计）"
    conn.close()


def test_early_event_counts_as_fp_once_across_overlapping_annotations(
        tmp_path):
    """超前事件：FP 一次；不得随后被另一条重叠标注计 TP。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    _alarm(conn, "ev-early2", "front", base - 3.0)   # 超前
    conn.commit()
    items.append(("front", base, "alarm", "enter"))
    items.append(("front", base + 2.0, "alarm", "enter"))

    annotations, sha = load_annotations(_annotate(tmp_path, items))
    report = evaluate(conn, annotations, annotation_sha256=sha)

    assert report["counts"]["fp"] == 1, "超前事件恰好一次 FP"
    assert report["counts"]["tp"] == 0, "超前事件不得计为 TP"
    conn.close()


def test_no_alarm_overlaps_do_not_double_count_same_event(tmp_path):
    """两条重叠 no_alarm + 一条事件：FP=1 而不是 2。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    _alarm(conn, "ev-na", "front", base + 1.0)
    conn.commit()
    items.append(("front", base, "no_alarm", "no-target"))
    items.append(("front", base + 2.0, "no_alarm", "no-target"))

    annotations, sha = load_annotations(_annotate(tmp_path, items))
    report = evaluate(conn, annotations, annotation_sha256=sha)

    assert report["counts"]["fp"] == 1, \
        "同一事件不得因重叠 no_alarm 重复计 FP"
    conn.close()


# ============ SC-A-R2 P0-B：全局最大匹配后计 FP ============

def test_overlapping_annotations_preserve_two_valid_matches(tmp_path):
    """LZ-070 贪心失败场景：A/B 标注 + A/B 事件必须 tp=2/fp=0/fn=0。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    _alarm(conn, "ev-A", "front", base + 0.5)
    _alarm(conn, "ev-B", "front", base + 1.5)
    conn.commit()
    items.append(("front", base, "alarm", "enter"))
    items.append(("front", base + 1.0, "alarm", "enter"))

    annotations, sha = load_annotations(_annotate(tmp_path, items))
    report = evaluate(conn, annotations, annotation_sha256=sha)

    assert report["counts"]["tp"] == 2, "合法一对一解必须被找到"
    # 该基准域内只有本用例的两条标注与两条事件：fp/fn 增量为 0
    assert report["counts"]["fp"] == 0
    assert report["latency_ms"]["samples"] == 2
    conn.close()


def test_maximum_matching_can_reassign_first_annotation_event(tmp_path):
    """贪心会让 A 抢 event1 致 B 失配；增广路径必须重排 A→event2。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    # A(base) 可配 ev-1 与 ev-2；B(base+8.5) 只可配 ev-2。
    # 贪心（A 先抢 ev-2 或就近抢 ev-1）与最大匹配的差别由增广路径闭合。
    _alarm(conn, "ev-1", "front", base + 0.5)
    _alarm(conn, "ev-2", "front", base + 9.0)
    conn.commit()
    base_items = list(items)
    items.append(("front", base, "alarm", "enter"))        # A
    items.append(("front", base + 8.5, "alarm", "enter"))  # B

    ann_base, sha_base = load_annotations(_annotate(tmp_path, base_items))
    r_base = evaluate(conn, ann_base, annotation_sha256=sha_base)
    annotations, sha = load_annotations(_annotate(tmp_path, items))
    report = evaluate(conn, annotations, annotation_sha256=sha)

    assert report["counts"]["tp"] - r_base["counts"]["tp"] == 2, \
        "增广重排后两条新标注必须都 TP"
    assert report["counts"]["fn"] == r_base["counts"]["fn"], \
        "新增标注不得引入任何 FN"
    conn.close()


def test_matching_is_deterministic_under_annotation_input_order(tmp_path):
    """交换 annotation 输入顺序：tp/fp/fn 与延迟多重集必须一致。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    _alarm(conn, "ev-x", "front", base + 0.5)
    _alarm(conn, "ev-y", "front", base + 1.5)
    conn.commit()
    extra = [("front", base, "alarm", "enter"),
             ("front", base + 1.0, "alarm", "enter")]

    ann1, sha1 = load_annotations(_annotate(tmp_path, items + extra))
    r1 = evaluate(conn, ann1, annotation_sha256=sha1)
    ann2, sha2 = load_annotations(
        _annotate(tmp_path, items + list(reversed(extra))))
    r2 = evaluate(conn, ann2, annotation_sha256=sha2)

    assert r1["counts"]["tp"] == r2["counts"]["tp"] == 2
    assert r1["counts"]["fp"] == r2["counts"]["fp"]
    assert r1["counts"]["fn"] == r2["counts"]["fn"]
    lat1 = sorted(v for k, v in r1["latency_ms"].items() if k != "samples")
    lat2 = sorted(v for k, v in r2["latency_ms"].items() if k != "samples")
    assert lat1 == lat2, "延迟多重集必须一致"
    conn.close()


def test_unmatched_event_is_counted_fp_only_after_global_matching(tmp_path):
    """两条正标注三条事件：先完成两个 TP，剩余事件才计 FP。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    _alarm(conn, "ev-m1", "front", base + 0.5)
    _alarm(conn, "ev-m2", "front", base + 1.5)
    _alarm(conn, "ev-left", "front", base + 4.0)   # 两条标注都够不到？
    conn.commit()
    items.append(("front", base, "alarm", "enter"))
    items.append(("front", base + 1.0, "alarm", "enter"))

    annotations, sha = load_annotations(_annotate(tmp_path, items))
    report = evaluate(conn, annotations, annotation_sha256=sha)

    # ev-left(base+4) 在 A2(base+1) 窗口 [base+1, base+6] 内——但已被匹配的
    # ev-m1/ev-m2 占位，两条标注各得其一；ev-left 未匹配 → FP 恰一次
    assert report["counts"]["tp"] == 2
    assert report["counts"]["fp"] == 1, "剩余事件恰一次 FP"
    conn.close()


def test_matched_event_prevents_overlapping_no_alarm_tn_without_duplicate_fp(
        tmp_path):
    """alarm 与 no_alarm 重叠：事件被 alarm 匹配 → 不得让 no_alarm 计 TN，
    也不得重复计 FP；冲突数据的结果必须固定。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    _alarm(conn, "ev-cf", "front", base + 0.5)
    conn.commit()
    base_items = list(items)
    items.append(("front", base, "alarm", "enter"))
    items.append(("front", base, "no_alarm", "no-target"))

    ann_base, sha_base = load_annotations(_annotate(tmp_path, base_items))
    r_base = evaluate(conn, ann_base, annotation_sha256=sha_base)
    annotations, sha = load_annotations(_annotate(tmp_path, items))
    r1 = evaluate(conn, annotations, annotation_sha256=sha)
    r2 = evaluate(conn, annotations, annotation_sha256=sha)

    assert r1["counts"]["tp"] - r_base["counts"]["tp"] == 1
    assert r1["counts"]["fp"] - r_base["counts"]["fp"] == 0, \
        "已匹配事件不得再计 FP"
    assert r1 == r2, "冲突数据结果必须固定"
    # no_alarm TN：窗口内含符合类别的事件（虽已被匹配）→ 不得为此新增 TN
    tn_base = r_base["confusion"].get("no-target", {}).get("tn", 0)
    tn_now = r1["confusion"].get("no-target", {}).get("tn", 0)
    assert tn_now == tn_base, "已匹配事件必须阻止重叠 no_alarm 计 TN"
    conn.close()


def test_early_event_is_fp_once_and_never_tp(tmp_path):
    """超前事件：仅一次 FP、绝不 TP、不出现在延迟样本。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    _alarm(conn, "ev-early3", "front", base - 3.0)
    conn.commit()
    items.append(("front", base, "alarm", "enter"))
    items.append(("front", base + 2.0, "alarm", "enter"))

    annotations, sha = load_annotations(_annotate(tmp_path, items))
    report = evaluate(conn, annotations, annotation_sha256=sha)

    assert report["counts"]["fp"] == 1, "超前事件恰一次 FP"
    assert report["counts"]["tp"] == 0
    assert report["latency_ms"]["samples"] == 0, "延迟样本不得包含超前事件"
    conn.close()


def test_same_timestamp_events_remain_distinct_by_event_id(tmp_path):
    """同 t_start 的两个不同 event_id：不得按时间去重，可分别匹配。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    _alarm(conn, "ev-same-1", "front", base + 1.0)
    _alarm(conn, "ev-same-2", "front", base + 1.0)   # 同时间、不同 id
    conn.commit()
    items.append(("front", base, "alarm", "enter"))
    items.append(("front", base + 0.5, "alarm", "enter"))

    annotations, sha = load_annotations(_annotate(tmp_path, items))
    report = evaluate(conn, annotations, annotation_sha256=sha)

    assert report["counts"]["tp"] == 2, \
        "同时间不同事件必须按 event_id 保持独立（不得时间去重）"
    assert report["counts"]["fp"] == 0
    conn.close()


# ============ SC-A-R3 P0-B：规范顺序与输入 fail-closed ============


def _annotate_dicts(tmp_path, ann_dicts):
    """直接传标注 dict 列表（支持 cls 等扩展字段）。"""
    payload = {"schema": "scam.quality-annotations/v1",
               "dataset": "test-set", "annotations": ann_dicts}
    path = tmp_path / "annotations-dicts.json"
    path.write_text(json.dumps(payload, ensure_ascii=False),
                    encoding="utf-8")
    return path


def _report_without_hashes(report):
    trimmed = dict(report)
    trimmed.pop("input_hashes", None)
    return trimmed


def test_same_time_different_scenario_single_event_reversed_arrays(tmp_path):
    """A. 同 t 不同场景、单事件：反转数组后除输入哈希外报告全等。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    _alarm(conn, "ev-one", "front", base + 0.5)
    conn.commit()
    extra = [("front", base, "alarm", "day"),
             ("front", base, "alarm", "night")]

    ann1, sha1 = load_annotations(_annotate(tmp_path, items + extra))
    r1 = evaluate(conn, ann1, annotation_sha256=sha1)
    ann2, sha2 = load_annotations(
        _annotate(tmp_path, items + list(reversed(extra))))
    r2 = evaluate(conn, ann2, annotation_sha256=sha2)

    assert _report_without_hashes(r1) == _report_without_hashes(r2), \
        "场景归属不得随数组位置变化"
    assert r1["counts"]["tp"] == 1, "单事件只满足一条正标注"
    conn.close()


def test_same_time_different_cls_two_events_reversed_arrays(tmp_path):
    """B. 同 t 不同 cls、两事件：反转数组后仍 tp=2/fp=0/fn=0 且分场景不变。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    _alarm(conn, "ev-p", "front", base + 0.5, cls="person")
    _alarm(conn, "ev-c", "front", base + 0.5, cls="car")
    conn.commit()
    extra = [{"camera": "front", "t_start": base, "expect": "alarm",
              "scenario": "enter", "cls": "person"},
             {"camera": "front", "t_start": base, "expect": "alarm",
              "scenario": "enter", "cls": "car"}]

    ann1, sha1 = load_annotations(_annotate_dicts(tmp_path, items_as_dicts(
        items) + extra))
    r1 = evaluate(conn, ann1, annotation_sha256=sha1)
    ann2, sha2 = load_annotations(_annotate_dicts(
        tmp_path, items_as_dicts(items) + list(reversed(extra))))
    r2 = evaluate(conn, ann2, annotation_sha256=sha2)

    assert r1["counts"]["tp"] - r2["counts"]["tp"] == 0
    assert _report_without_hashes(r1) == _report_without_hashes(r2)
    conn.close()


def items_as_dicts(items):
    return [{"camera": c, "t_start": t, "expect": e, "scenario": s}
            for c, t, e, s in items]


def test_same_time_two_events_maximum_matching_stable(tmp_path):
    """C. 同 t 两事件、两标注（同 cls 不同场景）：归属由 canonical 决定且稳定。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    _alarm(conn, "ev-1", "front", base + 0.5)
    _alarm(conn, "ev-2", "front", base + 1.5)
    conn.commit()
    extra = [{"camera": "front", "t_start": base, "expect": "alarm",
              "scenario": "day"},
             {"camera": "front", "t_start": base, "expect": "alarm",
              "scenario": "night"}]

    ann1, sha1 = load_annotations(
        _annotate_dicts(tmp_path, items_as_dicts(items) + extra))
    r1 = evaluate(conn, ann1, annotation_sha256=sha1)
    ann2, sha2 = load_annotations(_annotate_dicts(
        tmp_path, items_as_dicts(items) + list(reversed(extra))))
    r2 = evaluate(conn, ann2, annotation_sha256=sha2)

    assert r1["counts"]["tp"] == 2, "两条事件应被最大匹配全部利用"
    assert _report_without_hashes(r1) == _report_without_hashes(r2), \
        "分场景归属必须与数组顺序无关"
    conn.close()


def test_duplicate_annotations_swap_stable(tmp_path):
    """D. 完全相同的重复标注：交换后除输入哈希外报告相同。"""
    conn = _conn(tmp_path)
    items = _full_scenarios()
    first_t = next(t for c, t, e, s in items if e == "alarm")
    base = first_t + BASE_OFFSET
    _alarm(conn, "ev-dup", "front", base + 0.5)
    conn.commit()
    dup = {"camera": "front", "t_start": base, "expect": "alarm",
           "scenario": "enter"}

    ann1, sha1 = load_annotations(_annotate_dicts(
        tmp_path, items_as_dicts(items) + [dict(dup), dict(dup)]))
    r1 = evaluate(conn, ann1, annotation_sha256=sha1)
    ann2, sha2 = load_annotations(_annotate_dicts(
        tmp_path,
        items_as_dicts(items) + [dict(dup), dict(dup)][::-1]))
    r2 = evaluate(conn, ann2, annotation_sha256=sha2)

    assert _report_without_hashes(r1) == _report_without_hashes(r2), \
        "完全重复标注的内部身份互换不得改变统计"
    conn.close()


def test_non_finite_annotation_times_fail_closed(tmp_path):
    """E. 非有限/布尔标注时间：load_annotations 必须 fail-closed。"""
    for bad in (True, False, float("nan"), float("inf"), float("-inf")):
        payload = {"schema": "scam.quality-annotations/v1",
                   "annotations": [{"camera": "front", "t_start": bad,
                                    "expect": "alarm",
                                    "scenario": "enter"}]}
        path = tmp_path / "bad-time.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(ValueError):
            load_annotations(path)


def test_non_finite_event_times_fail_closed(tmp_path):
    """F. 数据库事件时间非有限/坏类型：evaluate 必须结构化失败。"""
    conn = _conn(tmp_path)
    _alarm(conn, "ev-bad", "front", 100.5)
    conn.execute(
        "UPDATE semantic_events SET t_start=?, t_last=?, t_end=NULL"
        " WHERE semantic_event_id='ev-bad'",
        (float("inf"), float("inf")))
    conn.commit()
    ann_path = _annotate_dicts(tmp_path, [
        {"camera": "front", "t_start": 100.0, "expect": "alarm",
         "scenario": "enter"}])
    annotations, sha = load_annotations(ann_path)
    with pytest.raises(ValueError):
        evaluate(conn, annotations, annotation_sha256=sha)
    conn.close()
