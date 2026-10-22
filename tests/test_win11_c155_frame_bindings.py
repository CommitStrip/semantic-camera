"""C155-A：逐帧只读归属接口（`EventProgress.resolve_frame_bindings`）决定性用例。

边界与口径（与车道交付一致）：

- 只驱动**生产事实链**（真实 `Monitor` + `SqliteSink` + `EventProgress`），不加载模型、
  不接相机、不开浏览器、不联网。
- 只**新增**断言：不修改任何既有测试、产品文件或配置。池侧
  `scam/win11_event_materials.py` 由**车道 B 并发持有**，本文件只按只读方式驱动其公开
  `observe()` 返回值做"多对象二次闸门惰性"的负例，不断言其内部结构。
- 原整包 `resolve_material_binding` 在本文件中被**反向锁定**：签名、结果键集、帧行键集、
  拒因与计数命名空间都按"一个字符不改"断言（对照证明）。
- 逐帧口径标记：`mode == "frame_level"`、`historical_counts_comparable is False`，
  包级 `status` **没有** `unique` 取值。
"""
from copy import deepcopy
import inspect

import numpy as np
import pytest

from scam.monitor import Monitor, to_gray
from scam.sinks import SqliteSink
from scam.win11_event_materials import EventMaterialPool
from scam.win11_event_progress import (FRAME_BINDING_CLASSES,
                                       FRAME_BINDING_MODE, FRAME_REASON_PRIORITY,
                                       EventProgress, frame_event_key)
from scam.win11_pipeline import L1Result, L1Task

TRACK_ONE = "cam:r1:track:1"
TRACK_TWO = "cam:r1:track:2"

RESULT_KEYS = {
    "status", "mode", "reason", "historical_counts_comparable",
    "object_declaration", "identity", "frame_time_kind", "object_ids", "frames",
    "bound_frames", "context_frames", "ambiguous_or_rejected", "event_ids",
    "event_keys", "counts", "reason_counts", "primary",
}
FRAME_ROW_KEYS = {
    "frame_id", "classification", "reason", "snapshot_present", "t_ms",
    "time_kind", "row_time_kind", "refs", "refs_source", "bound", "object_id",
    "track_id", "event_id", "event_occurrence", "event_t_start",
    "event_t_last", "event_key", "event_key_tuple", "binding_reason",
    "association_frame_id", "camera_id", "run_id", "config_version",
    "object_declaration",
}
COUNT_KEYS = {"rows", "distinct_frames", "duplicate_rows", "unidentified_rows",
              "bound", "context", "ambiguous", "rejected"}
PRIMARY_KEYS = {"requested_frame_id", "selection", "frame_id", "found",
                "classification", "snapshot_present", "bound", "qualified",
                "reason", "event_key", "event_key_tuple", "binding_frame_id",
                "borrowed_from_other_frame", "source", "other_bound_frames"}
OLD_BINDING_KEYS = {"camera_id", "run_id", "config_version", "object_id",
                    "track_id", "event_id", "event_occurrence",
                    "event_t_start", "event_t_last", "time_kind", "t_ms",
                    "association_frame_id", "frame_id", "binding_reason"}


def _frame():
    return np.zeros((16, 24, 3), dtype=np.uint8)


def _det(x=0.2):
    return {"cls": "person", "conf": 0.9, "bbox": [x, 0.2, 0.15, 0.3]}


def _result(monitor, fid, t_ms, dets):
    task = L1Task(monitor.camera_id, monitor.run_id, fid, t_ms, _frame(),
                  "patrol", [], 24, 16, monitor.zone_revision, False)
    return L1Result(task, deepcopy(dets), "ok" if dets else "empty", None,
                    ["person"], 0, 0)


def _consume(monitor, bridge, fid, t_ms, dets=None):
    result = _result(monitor, fid, t_ms, [_det()] if dets is None else dets)
    monitor.apply_detection_result(result, t_ms)
    monitor.step(_frame(), to_gray(_frame()), t_ms)
    conclusion = monitor.consume_conclusion()
    assert conclusion["accepted"]
    assert bridge.record_conclusion(monitor, conclusion)
    return conclusion


def _monitor(sink):
    monitor = Monitor({"id": "cam", "zones": [], "grid": {}}, None, [sink],
                      run_id="r1", detection_mode="async")
    monitor.timestamp_kind = "host_receive"
    return monitor


@pytest.fixture
def live(tmp_path):
    """帧 1：有 L1 快照但**无**事件绑定（轨迹确认前）；帧 2：已绑定事件 1。"""
    path = str(tmp_path / "events.db")
    sink = SqliteSink(path)
    monitor = _monitor(sink)
    bridge = EventProgress(path)
    _consume(monitor, bridge, 1, 1000)
    _consume(monitor, bridge, 2, 1100)
    event_id = monitor._event_facts[1]["event_id"]
    yield monitor, sink.conn, bridge, event_id
    bridge.close()
    sink.conn.close()


def _row(fid, kind="host_receive"):
    return {"frame_id": fid, "timestamp_kind": kind}


def _resolve(bridge, frames, *, object_ids=(TRACK_ONE,), primary=None,
             camera_id="cam", run_id="r1", config_version=0,
             frame_time_kind="host_receive"):
    return bridge.resolve_frame_bindings(
        camera_id=camera_id, run_id=run_id, config_version=config_version,
        frames=frames, object_ids=object_ids, frame_time_kind=frame_time_kind,
        primary_frame_id=primary)


# ---------------------------------------------------------------------------
# ① 对照证明：原整包 resolver 零改动（签名 / 结果形状 / 帧行形状 / 拒因）
# ---------------------------------------------------------------------------

def test_old_package_resolver_signature_and_shapes_are_locked(live):
    """旧方法签名、结果键集、绑定键集、帧行键集逐字锁定（不得被本批改变）。"""
    monitor, conn, bridge, event_id = live
    signature = inspect.signature(bridge.resolve_material_binding)
    assert list(signature.parameters) == [
        "camera_id", "run_id", "config_version", "object_ids", "frames",
        "frame_time_kind"]
    assert all(parameter.kind is inspect.Parameter.KEYWORD_ONLY
               for parameter in signature.parameters.values())
    assert signature.parameters["object_ids"].default == ()
    assert signature.parameters["frames"].default == ()
    assert signature.parameters["frame_time_kind"].default is None
    unique = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=(TRACK_ONE,), frames=(_row(2),))
    assert set(unique) == {"status", "reason", "binding", "frames"}
    assert unique["status"] == "unique" and unique["reason"] is None
    assert set(unique["binding"]) == OLD_BINDING_KEYS
    assert unique["binding"]["event_id"] == event_id
    assert len(unique["frames"]) == 1
    for row in unique["frames"]:
        # 生产帧行**不含** `refs`：池侧多对象二次闸门在生产行上不可能触发
        assert set(row) == {"frame_id", "t_ms", "time_kind"}
    refused = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0, object_ids=(),
        frames=(_row(2),))
    assert set(refused) == {"status", "reason", "binding", "frames"}
    assert refused["status"] == "not_aggregatable"
    assert refused["reason"] == "object_ids_missing"
    assert refused["binding"] is None and refused["frames"] == ()
    assert bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=(TRACK_ONE,), frames=(_row(999),))["reason"] \
        == "frame_binding_missing"


def test_old_unique_projects_to_every_frame_bound_with_the_same_event(live):
    """凡旧方法 `unique` ⇒ 新接口每帧 `bound`，且事件键与旧 `binding.event_id` 相同。"""
    monitor, conn, bridge, event_id = live
    _consume(monitor, bridge, 3, 1200)
    frames = (_row(2), _row(3))
    old = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=(TRACK_ONE,), frames=frames)
    assert old["status"] == "unique"
    new = _resolve(bridge, frames, primary=3)
    assert new["status"] == "ok" and new["reason"] is None
    assert new["mode"] == FRAME_BINDING_MODE
    assert new["status"] != "unique"
    assert [row["classification"] for row in new["frames"]] == ["bound", "bound"]
    assert {row["event_id"] for row in new["frames"]} \
        == {old["binding"]["event_id"]} == {event_id}
    assert new["bound_frames"] == ["2", "3"]
    assert new["context_frames"] == [] and new["ambiguous_or_rejected"] == []
    key = frame_event_key(new["primary"])
    assert key["event_id"] == old["binding"]["event_id"]
    assert key["object_id"] == TRACK_ONE and key["track_id"] == 1
    assert key["event_occurrence"] == 1 and key["frame_id"] == "3"
    assert key["binding_reason"] == "at_consumption"
    assert new["primary"]["borrowed_from_other_frame"] is False
    assert new["primary"]["source"] == "own_frame_snapshot"


def test_persisted_interval_and_binding_frame_guards_are_per_frame(live):
    """持久区间/绑定帧守卫逐帧硬生效（畸形内存状态，写入侧不会产生）。"""
    monitor, conn, bridge, event_id = live
    snapshot = bridge._frames[("cam", "r1", "0", "2")]
    binding = snapshot["bindings"][TRACK_ONE]
    assert binding["event_t_start"] == 1.0 and binding["event_t_last"] == 1.1
    assert binding["frame_id"] == "2"
    # 1) 观测点落到**该帧自己的**持久区间之外
    snapshot["t_ms"] = 1200.0
    binding["t_ms"] = 1200.0
    assert bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=(TRACK_ONE,), frames=(_row(2),))["status"] == "unique"
    outside = _resolve(bridge, (_row(2),), primary=2)
    assert outside["status"] == "unbound"
    assert outside["reason"] == "event_binding_ambiguous"
    assert outside["frames"][0]["classification"] == "ambiguous"
    assert outside["frames"][0]["reason"] == "event_binding_ambiguous"
    assert outside["frames"][0]["event_id"] is None
    assert frame_event_key(outside["primary"]) is None
    # 2) 区间恢复自洽，但绑定记录属于别的帧（“绑定帧=本帧”守卫）
    snapshot["t_ms"] = 1100.0
    binding["t_ms"] = 1100.0
    binding["frame_id"] = "999"
    foreign = _resolve(bridge, (_row(2),), primary=2)
    assert foreign["status"] == "unbound"
    assert foreign["reason"] == "event_binding_ambiguous"
    assert frame_event_key(foreign["primary"]) is None
    # 3) 恢复后仍可正常判定（证明前面两例都是守卫命中，而不是判定被破坏）
    binding["frame_id"] = "2"
    restored = _resolve(bridge, (_row(2),), primary=2)
    assert restored["status"] == "ok"
    assert frame_event_key(restored["primary"])["event_id"] == event_id


def test_frame_level_never_backfills_confirmed_after_source_frame(live):
    """F2′ 未实施：L4 的 `confirmed_after_source_frame` 回填只读副本，不改逐帧口径。"""
    monitor, conn, bridge, event_id = live
    key = ("cam", "r1", "0")
    with bridge._lock:
        snapshots = bridge._snapshot_frames(key, ({"frame_id": "1"},))
    backfill = snapshots["1"]["bindings"][TRACK_ONE]
    assert backfill["binding_reason"] == "confirmed_after_source_frame"
    assert backfill["event_id"] == event_id
    # 帧自己的原始快照仍然没有绑定（回填绝不写回，逐帧接口也不读回填）
    assert bridge._frames[key + ("1",)]["bindings"] == {}
    result = _resolve(bridge, (_row(1),), primary=1)
    assert result["frames"][0]["classification"] == "context"
    assert result["frames"][0]["reason"] == "no_event_binding"
    assert result["bound_frames"] == []
    assert frame_event_key(result["primary"]) is None


# ---------------------------------------------------------------------------
# ② 决定性用例一：仅 `cur` 合法绑定、`prev`/`next` 未知
# ---------------------------------------------------------------------------

def test_only_cur_bound_unknown_neighbours_never_disqualify_the_package(live):
    monitor, conn, bridge, event_id = live
    frames = (_row(100), _row(2), _row(101))
    old = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=(TRACK_ONE,), frames=frames)
    assert old["status"] == "unbound"          # 旧口径：整包因未知邻帧失去准入
    assert old["reason"] == "frame_binding_missing"
    new = _resolve(bridge, frames, primary=2)
    assert new["status"] == "ok"               # 新口径：有效帧不再被拖垮
    assert new["status"] in ("ok", "unbound", "rejected")   # 词表里没有 unique
    assert new["status"] != "unique"           # 部分成功绝不伪装整包唯一
    assert new["reason"] is None
    assert new["bound_frames"] == ["2"]
    assert new["context_frames"] == []
    assert new["ambiguous_or_rejected"] == ["100", "101"]
    assert new["counts"] == {"rows": 3, "distinct_frames": 3,
                             "duplicate_rows": 0, "unidentified_rows": 0,
                             "bound": 1, "context": 0, "ambiguous": 2,
                             "rejected": 0}
    assert frame_event_key(new["primary"])["event_id"] == event_id
    for row in new["frames"]:
        if row["frame_id"] == "2":
            continue
        # 未知帧如实记"没有自己的权威事实"，绝不借 cur 的绑定
        assert row["classification"] == "ambiguous"
        assert row["reason"] == "frame_binding_missing"
        assert row["snapshot_present"] is False and row["refs"] == []
        assert row["event_id"] is None and row["event_key"] is None
        assert row["bound"] is False


def test_context_neighbour_is_explicitly_unattributed_not_evidence(live):
    """包内一帧已绑定、另一帧**明确未归属**：只保留绑定帧，未归属帧可作参考。"""
    monitor, conn, bridge, event_id = live
    frames = (_row(1), _row(2))
    old = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=(TRACK_ONE,), frames=frames)
    assert old["status"] == "not_aggregatable"
    assert old["reason"] == "no_event_binding"
    new = _resolve(bridge, frames, primary=2)
    assert new["status"] == "ok"
    assert new["bound_frames"] == ["2"] and new["context_frames"] == ["1"]
    assert new["ambiguous_or_rejected"] == []
    context = new["frames"][0]
    assert context["classification"] == "context"
    assert context["reason"] == "no_event_binding"
    assert context["snapshot_present"] is True
    assert context["refs"] == [TRACK_ONE]
    assert context["refs_source"] == "frame_snapshot"
    assert context["bound"] is False and context["event_key"] is None
    assert context["object_id"] is None and context["event_id"] is None


# ---------------------------------------------------------------------------
# ③ 决定性用例二：主帧无绑定但邻帧已绑定 → 不得借邻帧挑事件键
# ---------------------------------------------------------------------------

def test_unbound_primary_never_borrows_a_bound_neighbour_event_key(live):
    monitor, conn, bridge, event_id = live
    result = _resolve(bridge, (_row(1), _row(2)), primary=1)
    primary = result["primary"]
    assert primary["found"] is True and primary["selection"] == "explicit"
    assert primary["frame_id"] == "1" and primary["classification"] == "context"
    assert primary["qualified"] is False and primary["bound"] is False
    assert primary["reason"] == "no_event_binding"
    assert primary["event_key"] is None and primary["event_key_tuple"] is None
    assert primary["binding_frame_id"] is None
    assert primary["borrowed_from_other_frame"] is False
    assert primary["source"] == "own_frame_snapshot"
    assert primary["other_bound_frames"] == ["2"]   # 邻帧确实已绑定，但被忽略
    assert frame_event_key(primary) is None
    # 接口如实列出合格帧；"用哪一帧"由调用方（runtime）按主序位决定
    assert result["bound_frames"] == ["2"]
    assert result["event_ids"] == [event_id]


def test_primary_answer_is_explicit_and_never_guessed(live):
    monitor, conn, bridge, event_id = live
    two_frames = _resolve(bridge, (_row(1), _row(2)))
    assert two_frames["primary"]["selection"] is None
    assert two_frames["primary"]["qualified"] is False
    assert two_frames["primary"]["reason"] == "primary_frame_id_missing"
    assert two_frames["primary"]["event_key"] is None
    sole = _resolve(bridge, (_row(2),))
    assert sole["primary"]["selection"] == "sole_identified_frame"
    assert sole["primary"]["qualified"] is True
    assert frame_event_key(sole["primary"])["event_id"] == event_id
    absent = _resolve(bridge, (_row(1), _row(2)), primary=99)
    assert absent["primary"]["found"] is False
    assert absent["primary"]["reason"] == "primary_frame_not_in_request"
    assert absent["primary"]["event_key"] is None
    unknown = _resolve(bridge, (_row(1), _row(100)), primary=100)
    assert unknown["primary"]["found"] is True
    assert unknown["primary"]["qualified"] is False
    assert unknown["primary"]["reason"] == "frame_binding_missing"
    assert frame_event_key(unknown["primary"]) is None
    assert unknown["primary"]["other_bound_frames"] == []


# ---------------------------------------------------------------------------
# ④ 决定性用例三：同包两个事件 / 多对象 / 跨 run·config·clock
# ---------------------------------------------------------------------------

def test_two_event_keys_in_one_package_refuse_aggregation_without_mixing(live):
    monitor, conn, bridge, old_event = live
    monitor._close_event_fact(1, "fixture-occurrence-end", 1100)
    _consume(monitor, bridge, 3, 1200)
    new_event = monitor._event_facts[1]["event_id"]
    assert new_event != old_event
    frames = (_row(2), _row(3))
    old = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=(TRACK_ONE,), frames=frames)
    assert old["status"] == "not_aggregatable"
    assert old["reason"] == "conflicting_events"
    new = _resolve(bridge, frames, primary=3)
    assert [row["classification"] for row in new["frames"]] == ["bound", "bound"]
    assert new["event_ids"] == [old_event, new_event]
    assert new["status"] == "rejected" and new["reason"] == "conflicting_events"
    assert len(new["event_keys"]) == 2
    assert {key[3] for key in new["event_keys"]} == {old_event, new_event}
    # 每帧只给自己的事件键；没有任何跨事件混合的键
    assert new["frames"][0]["event_id"] == old_event
    assert new["frames"][1]["event_id"] == new_event
    assert new["frames"][0]["event_key"]["event_id"] \
        != new["frames"][1]["event_key"]["event_id"]
    # P0-3(a)：主帧自己的键仍可核验；包级"拒绝聚合"不等于主帧无绑定
    assert frame_event_key(new["primary"])["event_id"] == new_event
    assert new["primary"]["other_bound_frames"] == ["2"]


def test_multi_object_frame_is_ambiguous_and_never_narrowed(live):
    monitor, conn, bridge, event_id = live
    _consume(monitor, bridge, 4, 1300, [_det(), _det(0.8)])
    assert monitor._object_id(1) == TRACK_ONE
    assert monitor._object_id(2) == TRACK_TWO
    both = _resolve(bridge, (_row(4),), object_ids=(TRACK_ONE, TRACK_TWO),
                    primary=4)
    assert both["status"] == "unbound" and both["reason"] == "multi_object"
    assert both["frames"][0]["classification"] == "ambiguous"
    assert both["frames"][0]["reason"] == "multi_object"
    assert both["frames"][0]["refs"] == [TRACK_ONE, TRACK_TWO]
    assert both["frames"][0]["event_key"] is None
    assert both["bound_frames"] == [] and both["event_ids"] == []
    assert frame_event_key(both["primary"]) is None
    # 只声明一个对象也**不缩窄**：帧自己的对象集合才是权威事实
    single = _resolve(bridge, (_row(4),), object_ids=(TRACK_ONE,), primary=4)
    assert single["reason"] == "multi_object"
    assert single["frames"][0]["classification"] == "ambiguous"
    assert single["frames"][0]["refs"] == [TRACK_ONE, TRACK_TWO]
    assert frame_event_key(single["primary"]) is None


def test_cross_run_config_and_clock_fences_never_mix(live):
    monitor, conn, bridge, event_id = live
    frames = (_row(2),)
    cross_run = _resolve(bridge, frames, run_id="other")
    assert cross_run["status"] == "unbound"
    assert cross_run["reason"] == "frame_binding_missing"
    assert cross_run["frames"][0]["classification"] == "ambiguous"
    assert cross_run["frames"][0]["event_id"] is None
    assert cross_run["event_ids"] == []
    assert frame_event_key(cross_run["primary"]) is None
    cross_config = _resolve(bridge, frames, config_version=99)
    assert cross_config["status"] == "unbound"
    assert cross_config["reason"] == "frame_binding_missing"
    assert frame_event_key(cross_config["primary"]) is None
    cross_clock = _resolve(bridge, frames, frame_time_kind="wall_clock")
    assert cross_clock["status"] == "unbound"
    assert cross_clock["reason"] == "time_kind_mismatch"
    assert cross_clock["frames"][0]["classification"] == "ambiguous"
    assert cross_clock["frames"][0]["reason"] == "time_kind_mismatch"
    assert cross_clock["frames"][0]["row_time_kind"] == "host_receive"
    assert frame_event_key(cross_clock["primary"]) is None
    row_clock = _resolve(bridge, (_row(2, "wall_clock"),))
    assert row_clock["status"] == "unbound"
    assert row_clock["reason"] == "time_kind_mismatch"
    # 任何跨身份/跨时基请求都拿不到事件键，原身份事件键绝不外借
    assert event_id not in cross_run["event_ids"]
    assert event_id not in cross_clock["event_ids"]


# ---------------------------------------------------------------------------
# ⑤ 决定性用例四：闭合后迟到 / 重复帧 / 启动无事件 / 关闭
# ---------------------------------------------------------------------------

def test_late_after_close_keeps_its_own_event_key_and_never_reopens(live):
    monitor, conn, bridge, event_id = live
    monitor.close_all_event_facts("camera-stopped")
    fact = dict(conn.execute("SELECT * FROM event_facts WHERE event_id=?",
                             (event_id,)).fetchone())
    assert fact["state"] == "closed" and fact["end_reason"] == "camera-stopped"
    closed_frame = _resolve(bridge, (_row(2),), primary=2)
    assert closed_frame["status"] == "ok"
    assert frame_event_key(closed_frame["primary"])["event_id"] == event_id
    assert dict(conn.execute("SELECT * FROM event_facts WHERE event_id=?",
                             (event_id,)).fetchone()) == fact   # 不重开、不写库
    _consume(monitor, bridge, 5, 1400)
    late = _resolve(bridge, (_row(5),), primary=5)
    late_key = frame_event_key(late["primary"])
    assert late_key["event_id"] != event_id          # 迟到帧只给自己的新事件键
    assert late["event_ids"] == [late_key["event_id"]]
    mixed = _resolve(bridge, (_row(2), _row(5)), primary=5)
    assert mixed["status"] == "rejected"
    assert mixed["reason"] == "conflicting_events"   # 闭合事件与迟到事件不混合
    assert len(mixed["event_ids"]) == 2


def test_duplicate_frame_rows_are_idempotent_and_counted(live):
    monitor, conn, bridge, event_id = live
    single = _resolve(bridge, (_row(2),), primary=2)
    twice = _resolve(bridge, (_row(2), _row(2)), primary=2)
    assert twice["bound_frames"] == ["2"]
    assert twice["counts"]["rows"] == 2
    assert twice["counts"]["distinct_frames"] == 1
    assert twice["counts"]["duplicate_rows"] == 1
    assert twice["frames"][0] == twice["frames"][1] == single["frames"][0]
    assert twice["event_ids"] == single["event_ids"] == [event_id]


def test_startup_frame_without_any_event_is_context_not_evidence(tmp_path):
    """启动阶段：先有 L1 事实、还没有事件身份 → `context`，且不阻断观察。"""
    path = str(tmp_path / "startup.db")
    sink = SqliteSink(path)
    monitor = _monitor(sink)
    bridge = EventProgress(path)
    try:
        _consume(monitor, bridge, 1, 1000)
        assert not monitor._event_facts            # 轨迹未确认：事件身份尚不存在
        result = _resolve(bridge, (_row(1),), primary=1)
        assert result["status"] == "unbound"
        assert result["reason"] == "no_event_binding"
        assert result["context_frames"] == ["1"]
        assert result["bound_frames"] == [] and result["event_ids"] == []
        row = result["frames"][0]
        assert row["classification"] == "context"
        assert row["snapshot_present"] is True
        assert row["refs"] == [TRACK_ONE]          # L1 事实已在（无需先有解释）
        assert row["bound"] is False and row["event_key"] is None
        assert result["primary"]["qualified"] is False
        assert len(bridge._frames) == 1
    finally:
        bridge.close()
        sink.conn.close()


def test_closed_bridge_rejects_every_frame(live):
    monitor, conn, bridge, event_id = live
    assert bridge.close()
    result = _resolve(bridge, (_row(1), _row(2)), primary=2)
    assert result["status"] == "rejected" and result["reason"] == "closed"
    assert all(row["classification"] == "rejected" and row["reason"] == "closed"
               for row in result["frames"])
    assert result["frames"][0]["snapshot_present"] is False
    assert result["bound_frames"] == [] and result["event_ids"] == []
    assert result["ambiguous_or_rejected"] == ["1", "2"]
    assert result["primary"]["qualified"] is False
    assert result["primary"]["found"] is True
    assert result["primary"]["reason"] == "closed"


def test_frame_level_uses_the_same_retention_prune_as_the_package_resolver(live):
    monitor, _, original, event_id = live
    now = [0.0]
    bridge = EventProgress(original.db_path, binding_retention_s=10,
                           mono_clock=lambda: now[0])
    try:
        _consume(monitor, bridge, 3, 1200)
        before = _resolve(bridge, (_row(3),), primary=3)
        assert before["bound_frames"] == ["3"]
        now[0] = 11.0
        after = _resolve(bridge, (_row(3),), primary=3)
        assert after["status"] == "unbound"
        assert after["reason"] == "frame_binding_missing"
        assert after["frames"][0]["classification"] == "ambiguous"
        snapshot = bridge.snapshot()
        assert snapshot["frames"] == 0 and snapshot["event_bindings"] == 0
        assert snapshot["counts"]["frame_expired"] == 1
        assert snapshot["counts"]["event_binding_expired"] == 1
        # 同一清理后旧整包 resolver 同样拒绝：两套口径共用同一守卫
        old = bridge.resolve_material_binding(
            camera_id="cam", run_id="r1", config_version=0,
            object_ids=(TRACK_ONE,), frames=(_row(3),))
        assert old["status"] == "unbound"
        assert old["reason"] == "frame_binding_missing"
    finally:
        bridge.close()


# ---------------------------------------------------------------------------
# ⑥ 分账、只读与加法兼容
# ---------------------------------------------------------------------------

def test_frame_level_query_is_readonly_and_keeps_accounting_separate(live):
    monitor, conn, bridge, event_id = live
    facts_before = [dict(row) for row in
                    conn.execute("SELECT * FROM event_facts").fetchall()]
    descriptions_before = [dict(row) for row in
                           conn.execute("SELECT * FROM event_descriptions")
                           .fetchall()]
    frames_before = deepcopy(bridge._frames)
    events_before = deepcopy(bridge._events)
    counts_before = dict(bridge.snapshot()["counts"])
    old_namespace = {key: value for key, value in counts_before.items()
                     if key.startswith("material_binding")}
    result = _resolve(bridge, (_row(1), _row(2), _row(100)), primary=2)
    assert result["mode"] == FRAME_BINDING_MODE
    assert result["historical_counts_comparable"] is False
    counts_after = dict(bridge.snapshot()["counts"])
    for key, value in counts_before.items():
        if key.startswith(("material_binding", "material_frame")):
            continue
        assert counts_after.get(key) == value, f"只读查询不得改变业务计数 {key}"
    assert {key: value for key, value in counts_after.items()
            if key.startswith("material_binding")} == old_namespace, \
        "逐帧口径不得写整包命名空间（历史计数不可直接横比）"
    assert counts_after["material_frame_binding_calls"] == 1
    assert counts_after["material_frame_binding_frames"] == 3
    assert counts_after["material_frame_binding_frames_bound"] == 1
    assert counts_after["material_frame_binding_frames_context"] == 1
    assert counts_after["material_frame_binding_frames_ambiguous"] == 1
    assert counts_after["material_frame_binding_frames_rejected"] == 0
    assert counts_after["material_frame_binding_packages_resolved"] == 1
    assert counts_after["material_frame_reason_no_event_binding"] == 1
    assert counts_after["material_frame_reason_frame_binding_missing"] == 1
    assert counts_after.get("material_frame_package_reason_no_event_binding") \
        is None
    assert [dict(row) for row in
            conn.execute("SELECT * FROM event_facts").fetchall()] \
        == facts_before
    assert [dict(row) for row in
            conn.execute("SELECT * FROM event_descriptions").fetchall()] \
        == descriptions_before
    assert bridge._frames == frames_before and bridge._events == events_before


def test_result_and_frame_row_keys_are_additive_and_stable(live):
    monitor, conn, bridge, event_id = live
    result = _resolve(bridge, (_row(1), _row(2), _row(100)), primary=2)
    assert result["status"] in ("ok", "unbound", "rejected")
    assert set(result) == RESULT_KEYS
    assert set(result["counts"]) == COUNT_KEYS
    assert set(result["primary"]) == PRIMARY_KEYS
    assert all(set(row) == FRAME_ROW_KEYS for row in result["frames"])
    assert [row["classification"] for row in result["frames"]] \
        == ["context", "bound", "ambiguous"]
    assert all(row["classification"] in FRAME_BINDING_CLASSES
               for row in result["frames"])
    bound = result["frames"][1]
    assert result["object_declaration"] == "declared"
    assert bound["classification"] == "bound" and bound["bound"] is True
    assert bound["event_id"] == event_id            # 与旧 resolver 同一事件键
    assert bound["binding_reason"] == "at_consumption"
    assert bound["refs"] == [TRACK_ONE]
    # 帧身份三元显式给出（加法字段；调用方可据此复核该行属于哪个身份）
    assert (bound["camera_id"], bound["run_id"], bound["config_version"]) \
        == ("cam", "r1", "0")
    assert bound["object_declaration"] == "declared"
    assert bound["event_key_tuple"] == ["cam", "r1", "0", event_id, TRACK_ONE]
    assert bound["event_key"]["frame_id"] == "2"
    assert bound["event_key"]["t_ms"] == 1100.0
    assert bound["event_key"]["event_t_start"] == 1.0
    assert bound["event_key"]["event_t_last"] == 1.1
    assert frame_event_key(bound) == bound["event_key"]


def test_request_level_failures_and_line_level_rejects_are_structured(live):
    monitor, conn, bridge, event_id = live
    incomplete = _resolve(bridge, (_row(2),), config_version=None, primary=2)
    assert incomplete["status"] == "rejected"
    assert incomplete["reason"] == "identity_incomplete"
    assert incomplete["frames"] == [] and incomplete["bound_frames"] == []
    assert incomplete["primary"]["reason"] == "identity_incomplete"
    assert incomplete["primary"]["qualified"] is False
    invalid_ids = _resolve(bridge, (_row(2),), object_ids=("",), primary=2)
    assert invalid_ids["status"] == "rejected"
    assert invalid_ids["reason"] == "object_ids_invalid"
    assert invalid_ids["primary"]["reason"] == "object_ids_invalid"
    no_frames = _resolve(bridge, (), primary=2)
    assert no_frames["status"] == "rejected"
    assert no_frames["reason"] == "frames_invalid"
    assert no_frames["primary"]["reason"] == "frames_invalid"
    assert no_frames["primary"]["qualified"] is False
    # 缺序位行（无可用 frame_id）只拒绝本行，**不牵连**同请求的有效帧
    mixed = _resolve(bridge, ({"frame_id": None, "timestamp_kind": "host_receive"},
                              _row(2)), primary=2)
    assert mixed["status"] == "ok"
    assert mixed["bound_frames"] == ["2"]
    assert mixed["ambiguous_or_rejected"] == []
    assert mixed["counts"]["unidentified_rows"] == 1
    assert mixed["counts"]["rejected"] == 1
    assert mixed["frames"][0]["classification"] == "rejected"
    assert mixed["frames"][0]["reason"] == "frames_invalid"
    assert mixed["frames"][0]["frame_id"] is None
    all_bad = _resolve(bridge, ({"frame_id": None}, {"frame_id": True}))
    assert all_bad["status"] == "unbound"
    assert all_bad["reason"] == "frames_invalid"
    assert all_bad["counts"]["unidentified_rows"] == 2
    assert all_bad["bound_frames"] == []


def test_package_dominant_reason_follows_the_frozen_priority(live):
    monitor, conn, bridge, event_id = live
    _consume(monitor, bridge, 4, 1300, [_det(), _det(0.8)])
    result = _resolve(bridge, (_row(100), _row(4)),
                      object_ids=(TRACK_ONE, TRACK_TWO), primary=4)
    assert result["status"] == "unbound"
    assert result["reason"] == "multi_object"      # 优先级高于 frame_binding_missing
    assert FRAME_REASON_PRIORITY.index("multi_object") \
        < FRAME_REASON_PRIORITY.index("frame_binding_missing")
    assert result["reason_counts"] == {"frame_binding_missing": 1,
                                       "multi_object": 1}
    assert result["counts"]["ambiguous"] == 2
    unsupported = _resolve(bridge, (_row(1), _row(2)), primary=2,
                           object_ids=(TRACK_ONE,))
    assert unsupported["status"] == "ok"


def test_undeclared_objects_use_the_frames_own_object_but_never_pick_one(live):
    """未声明对象集合：以该帧**自身唯一**对象为守卫（P0-3(a) 的主帧查询），
    多对象帧仍 `ambiguous` —— 绝不代调用方在帧内挑一个对象。"""
    monitor, conn, bridge, event_id = live
    result = _resolve(bridge, (_row(2),), object_ids=(), primary=2)
    assert result["object_declaration"] == "absent"
    assert result["object_ids"] == []
    assert result["status"] == "ok"
    assert result["frames"][0]["object_declaration"] == "absent"
    assert result["frames"][0]["classification"] == "bound"
    assert result["frames"][0]["object_id"] == TRACK_ONE    # 帧自身唯一对象
    assert result["frames"][0]["refs"] == [TRACK_ONE]
    assert frame_event_key(result["primary"])["event_id"] == event_id
    # 声明了对象时守卫照旧：帧自身对象必须落在声明里
    declared = _resolve(bridge, (_row(2),), object_ids=(TRACK_TWO,), primary=2)
    assert declared["object_declaration"] == "declared"
    assert declared["status"] == "unbound"
    assert declared["reason"] == "object_mismatch"
    assert declared["frames"][0]["reason"] == "object_mismatch"
    assert frame_event_key(declared["primary"]) is None
    # 未声明 + 多对象帧：仍然不挑（该帧没有唯一对象身份）
    _consume(monitor, bridge, 4, 1300, [_det(), _det(0.8)])
    multi = _resolve(bridge, (_row(4),), object_ids=(), primary=4)
    assert multi["object_declaration"] == "absent"
    assert multi["status"] == "unbound" and multi["reason"] == "multi_object"
    assert multi["frames"][0]["refs"] == [TRACK_ONE, TRACK_TWO]
    assert multi["frames"][0]["object_id"] is None
    assert frame_event_key(multi["primary"]) is None


# ---------------------------------------------------------------------------
# ⑦ 负例：多对象二次闸门惰性（不得仅凭报告推断已发生错误归属）
# ---------------------------------------------------------------------------

class _DoubleBindingSource:
    """测试替身：返回 `unique` 且帧行**带 `refs`**（生产行没有这个键）。"""

    def __init__(self, refs):
        self._refs = tuple(refs)

    def resolve_material_binding(self, *, camera_id, run_id, config_version,
                                 object_ids=(), frames=(),
                                 frame_time_kind=None):
        return {"status": "unique",
                "reason": None,
                "binding": {"camera_id": camera_id, "run_id": run_id,
                            "config_version": config_version,
                            "object_id": self._refs[0], "track_id": 1,
                            "event_id": "cam:r1:event:1", "event_occurrence": 1,
                            "event_t_start": 1.0, "event_t_last": 9.9,
                            "time_kind": frame_time_kind, "t_ms": 1300.0,
                            "association_frame_id": "4", "frame_id": "4",
                            "binding_reason": "at_consumption"},
                "frames": tuple({"frame_id": str(row["frame_id"]),
                                 "t_ms": 1300.0, "time_kind": frame_time_kind,
                                 "refs": list(self._refs)} for row in frames)}


def test_multi_object_second_gate_is_inert_on_production_rows(live):
    """负例：生产行没有 `refs` ⇒ 二次闸门永不触发；多对象包零归属、零保留。"""
    monitor, conn, bridge, event_id = live
    _consume(monitor, bridge, 4, 1300, [_det(), _det(0.8)])
    assert monitor._object_id(2) == TRACK_TWO
    unique = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=(TRACK_ONE,), frames=(_row(2),))
    assert unique["status"] == "unique"
    assert all("refs" not in row for row in unique["frames"])
    multi = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=(TRACK_ONE, TRACK_TWO), frames=(_row(4),))
    assert multi["status"] == "not_aggregatable"
    assert multi["reason"] == "multi_object"
    frame_row = {"frame_id": "4", "timestamp_kind": "host_receive",
                 "t_capture_ms": 1300.0, "frame_bgr": _frame()}
    # 生产路径：多对象包在**解析器**处即被拒，池侧不产生任何事件页/像素
    pool = EventMaterialPool(binding_source=bridge)
    try:
        record = pool.observe(
            camera_id="cam", run_id="r1", config_version=0,
            window_key=("cam", "r1", 0, 7), window_id=7, material_id="m-7",
            frames=(frame_row,), object_ids=(TRACK_ONE, TRACK_TWO),
            frame_time_kind="host_receive")
        assert record["status"] == "window_only"
        assert record["reason"] == "multi_object"
        assert record["event_id"] is None and record["object_id"] is None
        assert record["retained"] == 0 and record["retained_ids"] == []
        assert record["resolved"]["status"] == "not_aggregatable"
    finally:
        pool.close()
    # 对照：同样的多对象 `refs` 只在"替身返回 unique + refs"时才能让二次闸门生效
    double = EventMaterialPool(binding_source=_DoubleBindingSource(
        (TRACK_ONE, TRACK_TWO)))
    try:
        doubled = double.observe(
            camera_id="cam", run_id="r1", config_version=0,
            window_key=("cam", "r1", 0, 8), window_id=8, material_id="m-8",
            frames=(dict(frame_row),), object_ids=(TRACK_ONE, TRACK_TWO),
            frame_time_kind="host_receive")
        assert doubled["reason"] == "multi_object"
        assert doubled["retained"] == 0
    finally:
        double.close()
    # 新逐帧口径同一结论：多对象帧 ambiguous、无事件键 → 新路径也不会错误归属
    per_frame = _resolve(bridge, (_row(4),),
                         object_ids=(TRACK_ONE, TRACK_TWO), primary=4)
    assert per_frame["frames"][0]["classification"] == "ambiguous"
    assert per_frame["frames"][0]["reason"] == "multi_object"
    assert frame_event_key(per_frame["primary"]) is None
    assert per_frame["event_ids"] == []
