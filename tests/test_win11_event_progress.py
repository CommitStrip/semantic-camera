"""Deterministic production wiring, not camera/model/browser evidence."""
from copy import deepcopy
import json
import threading
from types import SimpleNamespace

import numpy as np
import pytest

from scam import db, nvr
from scam.monitor import Monitor, to_gray
from scam.sinks import SqliteSink
from scam.win11_event_progress import EventProgress, attach_understanding
from scam.win11_l2_runtime import L2Runtime
from scam.win11_l3_contract import (L3BranchKind, L3BranchResult, L3Omission,
                                    L3Output, L3SourceRef, L3Status, L3Task,
                                    L3Uncertainty, L3WindowIdentity)
from scam.win11_l4 import L4Stage
from scam.win11_materials import MaterialsStore
from scam.win11_pipeline import L1Result, L1Task


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


@pytest.fixture
def live(tmp_path):
    path = str(tmp_path / "events.db")
    sink = SqliteSink(path)
    monitor = Monitor({"id": "cam", "zones": [], "grid": {}}, None,
                      [sink], run_id="r1", detection_mode="async")
    monitor.timestamp_kind = "host_receive"
    bridge = EventProgress(path)
    _consume(monitor, bridge, 1, 1000)
    _consume(monitor, bridge, 2, 1100)
    event_id = monitor._event_facts[1]["event_id"]
    yield monitor, sink.conn, bridge, event_id
    bridge.close()
    sink.conn.close()


def _fusion(fid=2, t_ms=1100, text="人在门口停留", **changes):
    value = {"camera_id": "cam", "run_id": "r1", "config_version": 0,
             "window_id": 1, "version_id": "v1", "at": 10.0,
             "items": [{"kind": "observation", "text": "对象在场",
                        "sources": [{"kind": "l1_object", "ref": "cam:r1:track:1"}]},
                       {"kind": "observation", "text": text,
                        "sources": [{"kind": "l3_branch", "ref": "panorama"}]}],
             "frame_refs": [{"frame_id": str(fid), "t_ms": float(t_ms),
                             "time_kind": "host_receive", "stable_ref": None}]}
    value.update(changes)
    return value


def _write(bridge, fusion):
    key = (fusion["camera_id"], fusion["run_id"], str(fusion["config_version"]))
    with bridge._lock:
        snapshots = bridge._snapshot_frames(key, fusion["frame_refs"])
    conn = db.connect(bridge.db_path)
    try:
        return bridge._associate(conn, fusion, snapshots)
    finally:
        conn.close()


def test_real_tracker_mapping_append_cross_window_and_restart_idempotence(live):
    monitor, conn, bridge, event = live
    assert _write(bridge, _fusion())["status"] == "appended"
    _consume(monitor, bridge, 4, 1300, [_det(0.22)])
    assert _write(bridge, _fusion(4, 1300, "人向门内移动", window_id=2))["version"] == 3
    assert _write(bridge, _fusion(4, 1300, "人向门内移动", window_id=999,
                                 version_id="other", at=99))["status"] == "duplicate"
    # Ledger persists independently of the process-local registry.
    restarted = EventProgress(bridge.db_path)
    restarted._frames = deepcopy(bridge._frames)
    assert _write(restarted, _fusion(4, 1300, "人向门内移动", window_id=4))["status"] == "duplicate"
    detail = db.get_event_fact(conn, event)
    assert [d["version"] for d in detail["descriptions"]] == [1, 2, 3]
    assert len([n for n in detail["notifications"] if n["kind"] == "initial_fact"]) == 1
    assert len([n for n in detail["notifications"] if n["kind"] == "semantic_update"]) == 2
    assert detail["descriptions"][0]["text"] == "cam 画面中出现 person"
    payload = json.loads(detail["descriptions"][-1]["payload"])
    assert payload["binding"]["event_id"] == event
    assert payload["window_id"] == 2


def test_late_entry_append_never_changes_closed_fact_or_v1(live):
    monitor, conn, bridge, event = live
    before = db.get_event_fact(conn, event)["descriptions"][0]
    monitor.close_all_event_facts("camera-stopped")
    closed = dict(conn.execute("SELECT * FROM event_facts WHERE event_id=?", (event,)).fetchone())
    assert _write(bridge, _fusion())["status"] == "appended"
    assert dict(conn.execute("SELECT * FROM event_facts WHERE event_id=?", (event,)).fetchone()) == closed
    detail = db.get_event_fact(conn, event)
    assert detail["descriptions"][0] == before
    assert json.loads(detail["descriptions"][-1]["payload"])["event_open_at_write"] is False


@pytest.mark.parametrize("change,reason", [
    ({"camera_id": "other"}, "frame_binding_missing"),
    ({"run_id": "r2"}, "frame_binding_missing"),
    ({"config_version": 1}, "frame_binding_missing"),
    ({"frame_refs": [{"frame_id": "99", "t_ms": 1100, "time_kind": "host_receive"}]}, "frame_binding_missing"),
    ({"frame_refs": [{"frame_id": "2", "t_ms": 1101, "time_kind": "host_receive"}]}, "frame_time_mismatch"),
    ({"frame_refs": [{"frame_id": "2", "t_ms": 1100, "time_kind": "source_capture"}]}, "frame_time_mismatch"),
])
def test_full_identity_and_comparable_time_fail_closed(live, change, reason):
    _, conn, bridge, _ = live
    result = _write(bridge, _fusion(**change))
    assert result == {"status": "unassociated", "reason": reason}
    assert conn.execute("SELECT count(*) FROM event_descriptions WHERE source='vlm'").fetchone()[0] == 0


def test_no_object_observation_retained_without_event_creation(live):
    _, conn, bridge, _ = live
    fusion = _fusion()
    fusion["items"] = fusion["items"][1:]
    runtime = L2Runtime(["cam"], None, None, event_progress=bridge)
    assert runtime._append_history("cam", "l4", fusion)
    bridge.start()
    assert bridge.close()
    assert bridge.snapshot()["last"] == {"status": "unassociated", "reason": "no_object"}
    assert runtime.understanding.history("cam", "l4")[-1]["items"] == fusion["items"]
    assert conn.execute("SELECT count(*) FROM event_facts").fetchone()[0] == 1


def test_multi_object_never_fans_out_and_unconfirmed_object_blocks_scene(live):
    monitor, conn, bridge, event = live
    fusion = _fusion()
    fusion["items"][0]["sources"].append({"kind": "l1_object", "ref": "cam:r1:track:2"})
    assert _write(bridge, fusion)["reason"] == "multi_object"
    _consume(monitor, bridge, 4, 1300, [_det(), _det(0.8)])
    assert _write(bridge, _fusion(4, 1300))["reason"] == "multi_object_frame"
    assert len(db.get_event_fact(conn, event)["descriptions"]) == 1


def test_preconfirmation_frame_uses_unique_real_mapping_without_rewriting_frame(live):
    _, conn, bridge, event = live
    original = deepcopy(bridge._frames[("cam", "r1", "0", "1")])
    assert not original["bindings"]
    assert _write(bridge, _fusion(1, 1000))["status"] == "appended"
    assert bridge._frames[("cam", "r1", "0", "1")] == original
    binding = json.loads(db.get_event_fact(conn, event)["descriptions"][-1]["payload"])["binding"]
    assert binding["frame_id"] == "1" and binding["association_frame_id"] == "2"
    assert binding["event_occurrence"] == 1
    assert binding["binding_reason"] == "confirmed_after_source_frame"
    assert conn.execute("SELECT count(*) FROM event_facts").fetchone()[0] == 1


def test_same_track_new_occurrence_preserves_old_mapping_and_rejects_ambiguous_early_frame(live):
    monitor, conn, bridge, old_event = live
    monitor._close_event_fact(1, "fixture-occurrence-end", 1100)
    _consume(monitor, bridge, 3, 1200)
    new_event = monitor._event_facts[1]["event_id"]
    assert new_event != old_event
    assert len(bridge._events) == 2
    # Actual Monitor occurrence ranges overlap at bornAt. No latest-event guess.
    assert _write(bridge, _fusion(1, 1000))["reason"] == "event_binding_ambiguous"
    assert _write(bridge, _fusion(2, 1100, "此前观察"))["event_id"] == old_event
    assert _write(bridge, _fusion(3, 1200, "新出现的观察"))["event_id"] == new_event
    assert db.get_event_fact(conn, old_event)["state"] == "closed"
    new_payload = json.loads(db.get_event_fact(conn, new_event)["descriptions"][-1]["payload"])
    assert new_payload["binding"]["event_occurrence"] == 2


def test_failed_confirmation_does_not_create_mapping(tmp_path):
    path = str(tmp_path / "failed-confirmation.db")
    sink = SqliteSink(path)
    sink.update_event_fact = lambda *a, **kw: False
    monitor = Monitor({"id": "cam", "zones": [], "grid": {}}, None,
                      [sink], run_id="r1", detection_mode="async")
    monitor.timestamp_kind = "host_receive"
    bridge = EventProgress(path)
    _consume(monitor, bridge, 1, 1000)
    _consume(monitor, bridge, 2, 1100)
    assert not bridge._events
    assert _write(bridge, _fusion(1, 1000))["reason"] == "event_unpersisted"
    assert _write(bridge, _fusion(2, 1100))["reason"] == "event_unpersisted"
    sink.conn.close()


@pytest.mark.parametrize("clock,observed", [("source_capture", 1000),
                                             ("host_receive", 999),
                                             ("host_receive", 1101)])
def test_early_binding_never_uses_incomparable_future_or_outside_range(live, clock, observed):
    _, _, bridge, _ = live
    # Explicit malformed source metadata, with the original unconfirmed frame.
    snap = bridge._frames[("cam", "r1", "0", "1")]
    snap.update(t_ms=observed, time_kind=clock)
    fusion = _fusion(1, observed)
    fusion["frame_refs"][0]["time_kind"] = clock
    assert _write(bridge, fusion)["reason"] == "event_unpersisted"


def test_frame_and_occurrence_evidence_expires_without_fabricating_missing_source(live):
    monitor, _, original, _ = live
    now = [0.0]
    bridge = EventProgress(original.db_path, binding_retention_s=10,
                           mono_clock=lambda: now[0])
    _consume(monitor, bridge, 3, 1200)
    assert bridge.snapshot()["event_bindings"] == 1
    now[0] = 11.0
    snapshot = bridge.snapshot()
    assert snapshot["frames"] == snapshot["event_bindings"] == 0
    assert snapshot["counts"]["frame_expired"] == 1
    assert snapshot["counts"]["event_binding_expired"] == 1
    assert _write(bridge, _fusion(3, 1200))["reason"] == "frame_binding_missing"


def test_entry_rejects_confirmed_prose_and_mismatched_binding(live):
    _, conn, bridge, event = live
    binding = bridge._frames[("cam", "r1", "0", "2")]["bindings"]["cam:r1:track:1"]
    kwargs = dict(event_id=event, identity={"camera_id": "cam", "run_id": "r1", "config_version": 0},
                  text="模型文本", uncertainty="confirmed", evidence_refs=[],
                  t_created=1.2, model_id="test", binding=binding)
    assert attach_understanding(conn, **kwargs)["reason"] == "uncertainty_invalid"
    kwargs["uncertainty"] = "high"
    kwargs["identity"]["config_version"] = 1
    assert attach_understanding(conn, **kwargs)["reason"] == "identity_mismatch"


def test_new_model_provenance_is_a_new_processing_fingerprint(live):
    _, conn, bridge, event = live
    fusion = _fusion()
    assert _write(bridge, fusion)["status"] == "appended"
    fusion["items"][1]["sources"][0]["ref"] = "panorama|new-model-version"
    assert _write(bridge, fusion)["version"] == 3
    assert len(db.get_event_fact(conn, event)["descriptions"]) == 3


def test_item_and_source_order_is_not_new_evidence(live):
    _, _, bridge, _ = live
    fusion = _fusion()
    assert _write(bridge, fusion)["status"] == "appended"
    fusion["items"].reverse()
    assert _write(bridge, fusion)["status"] == "duplicate"


def test_all_bound_frames_checked_against_persisted_fact(live):
    monitor, conn, bridge, event = live
    _consume(monitor, bridge, 3, 1200)
    fusion = _fusion()
    fusion["frame_refs"].append(dict(fusion["frame_refs"][0], frame_id="3", t_ms=1200.0))
    # Simulated corrupt/stale persisted range: first frame alone would pass.
    conn.execute("UPDATE event_facts SET t_last=1.1 WHERE event_id=?", (event,))
    conn.commit()
    assert _write(bridge, fusion)["reason"] == "fact_binding_mismatch"
    assert len(db.get_event_fact(conn, event)["descriptions"]) == 1


def test_public_entry_distinguishes_constraint_failure_from_duplicate(live, monkeypatch):
    _, conn, bridge, _ = live
    monkeypatch.setattr(db, "publish_semantic_update", lambda *a, **kw: (None, False))
    assert _write(bridge, _fusion()) == {
        "status": "rejected", "reason": "publish_rejected", "event_id": "cam:r1:event:1"}


def test_metadata_cache_budget_rejected_binding_and_invalid_payload(live):
    monitor, _, original, _ = live
    bridge = EventProgress(original.db_path, max_frames=2, max_payload_bytes=500)
    for fid in range(4, 9):
        _consume(monitor, bridge, fid, 1100 + fid * 100)
    assert bridge.snapshot()["frames"] == 2
    assert bridge.snapshot()["counts"]["frame_evicted"] == 3
    assert not bridge.record_conclusion(monitor, {"accepted": False})
    fusion = _fusion()
    fusion["items"][1]["text"] = "x" * 1000
    assert not bridge.submit(fusion)
    assert bridge.snapshot()["counts"]["invalid"] == 1


def test_queue_budget_close_and_no_db_on_producer(live, monkeypatch):
    _, _, existing, _ = live
    bridge = EventProgress(existing.db_path, max_queue=1, max_frames=1)
    bridge._frames = deepcopy(existing._frames)
    monkeypatch.setattr(db, "connect", lambda *a: pytest.fail("producer must not open DB"))
    assert bridge.submit(_fusion())
    assert not bridge.submit(_fusion())
    assert not bridge.close(timeout=0)  # Unstarted pending jobs aren't 'saved'.
    assert not bridge.submit(_fusion())
    assert bridge.snapshot()["counts"]["queue_full"] == 1


def test_slow_database_worker_never_holds_registry_lock(live, monkeypatch):
    monitor, _, bridge, _ = live
    entered, release = threading.Event(), threading.Event()
    original = bridge._associate

    def slow(*args):
        entered.set()
        assert release.wait(3)
        return original(*args)

    monkeypatch.setattr(bridge, "_associate", slow)
    bridge.start()
    assert bridge.submit(_fusion())
    assert entered.wait(2)
    try:
        # This uses the same metadata path as the actual camera loop; blocked
        # SQLite work must not prevent registration or new nonblocking submit.
        _consume(monitor, bridge, 3, 1200)
        assert bridge.submit(_fusion(3, 1200, text="人向内移动"))
        assert bridge.snapshot()["pending"] == 1
        assert not bridge.close(timeout=0)
    finally:
        release.set()
        assert bridge.close(timeout=3)
    assert bridge.snapshot()["counts"]["appended"] == 2


def test_real_l4_accumulation_hook_to_worker_and_user_event_detail(live):
    monitor, conn, bridge, event = live
    runtime = L2Runtime(["cam"], None, None, l4_factory=L4Stage,
                        event_progress=bridge)
    runtime.set_camera_identity("cam", monitor.run_id, 0)
    window = L3WindowIdentity("cam", "r1", 0, 7)
    task = L3Task(window, L3BranchKind.PANORAMA, (), "test", 0, None)
    branch = L3BranchResult(branch=L3BranchKind.PANORAMA, status=L3Status.OK,
                            error_code=None, observation="人在门口停留", inference=None,
                            uncertainty=L3Uncertainty(),
                            sources=(L3SourceRef(1, 2, True, 1100.0, "host_receive"),),
                            window=window, crop_id=None, model_ref="deterministic-test",
                            region_only=False)
    out = L3Output(window=window, branch=L3BranchKind.PANORAMA, status=L3Status.OK,
                   error_code=None, results=(branch,), omission=L3Omission(0, ""),
                   model_ref="deterministic-test", timings_ms={})
    bridge.start()
    runtime._accumulate_branch_result("cam", task, {
        "l1_refs": [monitor._object_id(1)], "l2_candidates": [],
        "coord_space": "normalized"}, out, ("cam", "r1", 0, 7))
    assert bridge.close()
    assert bridge.snapshot()["counts"]["appended"] == 1
    # Existing user-visible production detail method, no browser/service.
    state = nvr.WorkbenchState(bridge.db_path)
    detail = state.event_fact_detail(event)
    assert any(d["text"] == "人在门口停留" for d in detail["descriptions"])
    assert runtime.snapshot()["event_progress"]["counts"]["appended"] == 1


def test_default_runtime_builder_constructs_bridge_only_with_l4(tmp_path):
    kwargs = dict(db_path=str(tmp_path / "events.db"))
    runtime = nvr._build_l2_runtime({}, MaterialsStore(), ["cam"],
                                   l3_cfg={"l4": {"enabled": True}}, **kwargs)
    assert isinstance(runtime.event_progress, EventProgress)
    assert nvr._build_l2_runtime({}, MaterialsStore(), ["cam"], **kwargs).event_progress is None


@pytest.mark.parametrize("adapter_fault", [False, True])
def test_actual_camera_entry_registers_before_material_visibility(tmp_path, monkeypatch, adapter_fault):
    path = str(tmp_path / "camera.db")
    state = SimpleNamespace(monitors={}, runtime=None)
    stop = threading.Event()

    class Source:
        n = 0
        stats = {"timestamp_kind": "source_capture"}

        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def read(self):
            self.n += 1
            if self.n == 4:
                stop.set()
            return True, _frame(), 1.0 + (self.n - 1) * 1.6

        def close(self):
            pass

    class Pipeline:
        jobs = []

        def submit(self, task):
            self.jobs.append(task)
            return True

        def take_result(self, camera):
            if self.jobs:
                return L1Result(self.jobs.pop(0), [_det()], "ok", None, ["person"], 0, 0)

        def oldest_unfinished_age_ms(self, camera):
            return 0

    class Store(MaterialsStore):
        attached = 0

        def attach_result(self, camera, run, config, fid, *args, **kwargs):
            assert (camera, run, str(config), str(fid)) in bridge._frames
            self.attached += 1
            return super().attach_result(camera, run, config, fid, *args, **kwargs)

    store = Store()
    # Same builder and db_path argument as the default Win11 main entry.
    runtime = nvr._build_l2_runtime({}, store, ["cam"], db_path=path,
                                   l3_cfg={"l4": {"enabled": True}})
    bridge = runtime.event_progress
    if adapter_fault:
        record = bridge.record_conclusion

        def fault_after_registration(*args):
            record(*args)
            raise RuntimeError("injected metadata fault")

        monkeypatch.setattr(bridge, "record_conclusion", fault_after_registration)
    monkeypatch.setattr(nvr, "CameraSource", Source)
    nvr._run_camera({"id": "cam", "source": "fixture-local", "detector": {}},
                    [], path, stop, state, pipeline=Pipeline(), store=store,
                    l2_runtime=runtime)
    assert store.attached == 3, "metadata faults must not suppress material attachment"
    assert any(f["bindings"] for f in bridge._frames.values())
    frame_key, snap = next((k, v) for k, v in reversed(bridge._frames.items()) if v["bindings"])
    binding = next(iter(snap["bindings"].values()))
    window_key = (frame_key[0], frame_key[1], 0, 99)
    window = L3WindowIdentity(*window_key)
    task = L3Task(window, L3BranchKind.PANORAMA, (), "fixture-model-boundary", 0, None)
    branch = L3BranchResult(
        branch=L3BranchKind.PANORAMA, status=L3Status.OK, error_code=None,
        observation="人移动到门口", inference=None, uncertainty=L3Uncertainty(),
        sources=(L3SourceRef(1, frame_key[3], True, snap["t_ms"], snap["time_kind"]),),
        window=window, crop_id=None, model_ref="deterministic-test", region_only=False)
    out = L3Output(window=window, branch=L3BranchKind.PANORAMA, status=L3Status.OK,
                   error_code=None, results=(branch,), omission=L3Omission(0, ""),
                   model_ref="deterministic-test", timings_ms={})
    bridge.start()
    # Camera finally already closed the actual event. L4 still appends only.
    runtime._accumulate_branch_result("cam", task,
                                      {"l1_refs": [binding["object_id"]]}, out, window_key)
    assert bridge.close()
    assert bridge.snapshot()["counts"]["appended"] == 1
    detail = nvr.WorkbenchState(path).event_fact_detail(binding["event_id"])
    assert detail["state"] == "closed"
    assert detail["descriptions"][-1]["text"] == "人移动到门口"
    conn = db.connect(path)
    assert conn.execute("SELECT count(*) FROM event_facts").fetchone()[0] >= 1
    conn.close()


# ---------------------------------------------------------------------------
# C153 agent B: one event across many technical windows (INTERFACE-B).
# Deterministic production-wiring regression; no camera, model, or browser.
# ---------------------------------------------------------------------------


def _window(fid=2, t_ms=1100.0, text="人在门口停留", *, camera="cam", run="r1",
            config=0, time_kind="host_receive", object_ref="cam:r1:track:1",
            window_id=1, version_id="v1", at=10.0):
    return {"camera_id": camera, "run_id": run, "config_version": config,
            "window_id": window_id, "version_id": version_id, "at": at,
            "items": [{"kind": "observation", "text": "对象在场",
                       "sources": [{"kind": "l1_object", "ref": object_ref}]},
                      {"kind": "observation", "text": text,
                       "sources": [{"kind": "l3_branch", "ref": "panorama"}]}],
            "frame_refs": [{"frame_id": str(fid), "t_ms": float(t_ms),
                            "time_kind": time_kind, "stable_ref": None}]}


def _rows(conn, event):
    return [dict(r) for r in conn.execute(
        "SELECT version,source,text,uncertainty,evidence_refs,t_created,payload"
        " FROM event_descriptions WHERE event_id=? ORDER BY version", (event,))]


def test_three_windows_one_event_from_start_to_late_close(live):
    """Start -> progress -> end stays one event_id; late window only appends."""
    monitor, conn, bridge, event = live
    results = [_write(bridge, _window())]
    for fid, t_ms, text in ((3, 1200.0, "人向门内移动"), (4, 1300.0, "人进入门内")):
        _consume(monitor, bridge, fid, t_ms)
        results.append(_write(bridge, _window(fid, t_ms, text, window_id=fid - 1,
                                              version_id=f"v{fid - 1}")))
    assert [r["status"] for r in results] == ["appended"] * 3
    assert [r["version"] for r in results] == [2, 3, 4]
    assert conn.execute("SELECT count(*) FROM event_facts").fetchone()[0] == 1
    detail = db.get_event_fact(conn, event)
    assert [d["version"] for d in detail["descriptions"]] == [1, 2, 3, 4]
    assert detail["descriptions"][0]["source"] == "initial_observation"
    appended = [json.loads(d["payload"]) for d in detail["descriptions"][1:]]
    assert [p["progress"]["phase"] for p in appended] == [
        "first_update", "continuing", "continuing"]
    assert {p["binding"]["event_id"] for p in appended} == {event}
    assert [p["window_id"] for p in appended] == [1, 2, 3]
    assert [p["progress"]["evidence_t_max"] for p in appended] == [
        1.1, 1.2, 1.3]
    assert all(p["progress"]["event_state_at_write"] == "open"
               and p["event_open_at_write"] for p in appended)
    # The end belongs to the fact chain, never to a model conclusion.
    monitor.close_all_event_facts("camera-stopped")
    closed = dict(conn.execute("SELECT * FROM event_facts WHERE event_id=?",
                               (event,)).fetchone())
    assert closed["state"] == "closed" and closed["end_reason"] == "camera-stopped"
    late = _write(bridge, _window(4, 1300.0, "人已离开门口", window_id=4,
                                  version_id="late"))
    assert late == {"status": "appended", "event_id": event, "version": 5}
    assert dict(conn.execute("SELECT * FROM event_facts WHERE event_id=?",
                             (event,)).fetchone()) == closed
    payload = json.loads(db.get_event_fact(conn, event)["descriptions"][-1]["payload"])
    assert payload["progress"]["phase"] == "after_close"
    assert payload["progress"]["event_t_end"] == closed["t_end"]
    assert payload["progress"]["event_end_reason"] == "camera-stopped"
    assert payload["event_open_at_write"] is False


def test_replayed_window_never_rewrites_history(live):
    monitor, conn, bridge, event = live
    _consume(monitor, bridge, 3, 1200.0)
    assert _write(bridge, _window(3, 1200.0, "人向门内移动",
                                  window_id=2))["version"] == 2
    before = _rows(conn, event)
    # Same evidence and content in another window: still the same submission.
    assert _write(bridge, _window(3, 1200.0, "人向门内移动", window_id=7,
                                  version_id="other", at=99.0)) == {
        "status": "duplicate", "reason": "ledger_hit", "event_id": event}
    assert _rows(conn, event) == before
    assert len(db.get_event_fact(conn, event)["notifications"]) == 2


def test_multi_object_window_never_splits_narrative_to_each_object(live):
    monitor, conn, bridge, event_one = live
    _consume(monitor, bridge, 3, 1200.0, [_det(), _det(0.8)])
    _consume(monitor, bridge, 4, 1300.0, [_det(), _det(0.8)])
    event_two = monitor._event_facts[2]["event_id"]
    assert event_two != event_one
    ref_one, ref_two = monitor._object_id(1), monitor._object_id(2)
    shared = _window(4, 1300.0, "两人在门口交谈", window_id=1)
    shared["items"].append({"kind": "observation", "text": "第二个人在场",
                            "sources": [{"kind": "l1_object", "ref": ref_two}]})
    assert _write(bridge, shared)["reason"] == "multi_object"
    # A single-object narrative in a frame that tracked two objects is still
    # not attributable: nothing is written to either event.
    assert _write(bridge, _window(4, 1300.0, "两人在门口交谈", object_ref=ref_one,
                                  window_id=2))["reason"] == "multi_object_frame"
    assert len(db.get_event_fact(conn, event_one)["descriptions"]) == 1
    assert len(db.get_event_fact(conn, event_two)["descriptions"]) == 1
    # The same object alone later appends to its own event only.
    _consume(monitor, bridge, 5, 1400.0, [_det()])
    assert _write(bridge, _window(5, 1400.0, "人向门内走", object_ref=ref_one,
                                  window_id=3))["version"] == 2
    assert len(db.get_event_fact(conn, event_one)["descriptions"]) == 2
    assert len(db.get_event_fact(conn, event_two)["descriptions"]) == 1


def test_cross_run_window_updates_only_its_own_event(live):
    monitor, conn, bridge, event_r1 = live
    sink2 = SqliteSink(bridge.db_path)
    monitor2 = Monitor({"id": "cam", "zones": [], "grid": {}}, None,
                       [sink2], run_id="r2", detection_mode="async")
    monitor2.timestamp_kind = "host_receive"
    try:
        _consume(monitor2, bridge, 1, 1000)
        _consume(monitor2, bridge, 2, 1100)
        event_r2 = monitor2._event_facts[1]["event_id"]
        assert event_r2 != event_r1
        assert _write(bridge, _window(2, 1100.0, "甲处观察"))["version"] == 2
        assert _write(bridge, _window(2, 1100.0, "乙处观察", run="r2",
                                      object_ref="cam:r2:track:1",
                                      version_id="r2v1")) == {
            "status": "appended", "event_id": event_r2, "version": 2}
        assert len(db.get_event_fact(conn, event_r1)["descriptions"]) == 2
        assert len(db.get_event_fact(conn, event_r2)["descriptions"]) == 2
        assert conn.execute("SELECT count(*) FROM event_facts").fetchone()[0] == 2
        before = _rows(conn, event_r1) + _rows(conn, event_r2)
        # Another config, or another run's object ref, may not borrow an event.
        assert _write(bridge, _window(2, 1100.0, "借关联", config=1)) == {
            "status": "unassociated", "reason": "frame_binding_missing"}
        assert _write(bridge, _window(2, 1100.0, "借关联",
                                      object_ref="cam:r2:track:1",
                                      version_id="borrow")) == {
            "status": "unassociated", "reason": "multi_object_frame"}
        assert _rows(conn, event_r1) + _rows(conn, event_r2) == before
    finally:
        sink2.conn.close()


def test_append_never_takes_the_initial_observation_slot(live):
    """The confirmed start stays the fact chain's; a missing v1 defers, not fills."""
    _, conn, bridge, event = live
    conn.execute("DELETE FROM event_descriptions WHERE event_id=? AND version=1",
                 (event,))
    conn.commit()
    assert _write(bridge, _window()) == {"status": "unassociated",
                                         "reason": "initial_description_missing"}
    assert _rows(conn, event) == []
    assert db.ensure_initial_description(conn, event, text="cam 画面中出现 person",
                                         t_created=1.0)
    assert _write(bridge, _window()) == {"status": "appended", "event_id": event,
                                         "version": 2}
    assert [d["source"] for d in _rows(conn, event)] == [
        "initial_observation", "vlm"]


def test_unassociated_index_retains_reason_and_is_queryable(live):
    monitor, conn, bridge, event = live
    bridge.start()
    assert bridge.submit(_window(1, 1000.0, run="r2", object_ref="cam:r2:track:1",
                                 version_id="unassoc-1", window_id=41))
    two = _window(2, 1100.0, version_id="unassoc-2", window_id=42)
    two["items"].append({"kind": "observation", "text": "第二个人在场",
                         "sources": [{"kind": "l1_object",
                                      "ref": "cam:r1:track:2"}]})
    assert bridge.submit(two)
    assert bridge.submit(_window(2, 1100.0, "人在门口停留", version_id="ok",
                                 window_id=43))
    assert bridge.close()
    assert bridge.snapshot()["last"] == {"status": "appended", "event_id": event,
                                         "version": 2}
    entries = bridge.unassociated()
    assert [e["reason"] for e in entries] == ["multi_object", "frame_binding_missing"]
    assert entries[0]["window_id"] == 42 and entries[0]["version_id"] == "unassoc-2"
    assert entries[0]["camera_id"] == "cam" and entries[0]["status"] == "unassociated"
    assert entries[0]["evidence_frames"] == [
        {"frame_id": "2", "t_ms": 1100.0, "time_kind": "host_receive"}]
    assert entries[1]["evidence_ref_total"] == 1
    assert bridge.unassociated(reason="frame_binding_missing") == [entries[1]]
    assert bridge.unassociated(camera="other") == []
    assert bridge.unassociated(limit=1) == [entries[0]]
    assert bridge.snapshot()["unassociated"] == {
        "retained": 2, "capacity": 256, "dropped": 0,
        "by_reason": {"multi_object": 1, "frame_binding_missing": 1}}
    assert len(db.get_event_fact(conn, event)["descriptions"]) == 2
    with pytest.raises(ValueError):
        bridge.unassociated(limit=0)


def test_unassociated_index_is_bounded_and_counts_drops(live):
    _, _, existing, _ = live
    bridge = EventProgress(existing.db_path, max_unassociated=1)
    bridge._frames = deepcopy(existing._frames)
    bridge.start()
    for i in range(3):
        assert bridge.submit(_window(1, 1000.0, run=f"rx{i}",
                                     object_ref=f"cam:rx{i}:track:1",
                                     version_id=f"u{i}", window_id=i))
    assert bridge.close()
    assert bridge.snapshot()["unassociated"] == {
        "retained": 1, "capacity": 1, "dropped": 2,
        "by_reason": {"frame_binding_missing": 3}}
    assert bridge.unassociated()[0]["version_id"] == "u2"


def test_workbench_existing_detail_reads_appended_versions_and_evidence(live):
    monitor, conn, bridge, event = live
    _consume(monitor, bridge, 3, 1200.0)
    assert _write(bridge, _window(3, 1200.0, "人在门口停留",
                                  window_id=2))["version"] == 2
    detail = nvr.WorkbenchState(bridge.db_path).event_fact_detail(event)
    assert [d["version"] for d in detail["descriptions"]] == [1, 2]
    latest = detail["descriptions"][-1]
    assert latest["text"] == "人在门口停留"
    assert latest["uncertainty"] == "high"
    assert latest["model_id"] == "l4-fusion"
    assert latest["evidence_refs"] == [{"frame_id": "3", "t_ms": 1200.0,
                                        "time_kind": "host_receive",
                                        "stable_ref": None}]
    # Reported gap, not patched here: the workbench response above cannot yet
    # express window/version provenance; the stored payload carries it.
    payload = json.loads(_rows(conn, event)[-1]["payload"])
    assert payload["progress"]["phase"] == "first_update"
    assert payload["binding"]["event_id"] == event
    assert payload["window_id"] == 2


def test_runtime_three_window_handoff_keeps_one_event_and_progress(live):
    """Production L4 hook (submit -> bounded worker -> append) over 3 windows."""
    monitor, conn, bridge, event = live
    runtime = L2Runtime(["cam"], None, None, l4_factory=L4Stage,
                        event_progress=bridge)
    runtime.set_camera_identity("cam", monitor.run_id, 0)

    def handoff(index, fid, t_ms, text):
        window = L3WindowIdentity("cam", "r1", 0, 100 + index)
        task = L3Task(window, L3BranchKind.PANORAMA, (), "test", 0, None)
        branch = L3BranchResult(
            branch=L3BranchKind.PANORAMA, status=L3Status.OK, error_code=None,
            observation=text, inference=None, uncertainty=L3Uncertainty(),
            sources=(L3SourceRef(1, fid, True, t_ms, "host_receive"),),
            window=window, crop_id=None, model_ref="deterministic-test",
            region_only=False)
        out = L3Output(window=window, branch=L3BranchKind.PANORAMA,
                       status=L3Status.OK, error_code=None, results=(branch,),
                       omission=L3Omission(0, ""),
                       model_ref="deterministic-test", timings_ms={})
        runtime._accumulate_branch_result("cam", task,
                                          {"l1_refs": [monitor._object_id(1)]},
                                          out, (window.camera_id, window.run_id,
                                                window.config_version,
                                                window.window_id))

    bridge.start()
    handoff(1, 2, 1100.0, "人在门口停留")
    for index, (fid, t_ms, text) in enumerate(((3, 1200.0, "人向门内移动"),
                                               (4, 1300.0, "人进入门内")),
                                              start=2):
        _consume(monitor, bridge, fid, t_ms)
        handoff(index, fid, t_ms, text)
    assert bridge.close()
    assert bridge.snapshot()["counts"]["appended"] == 3
    assert runtime.snapshot()["event_progress"]["counts"]["appended"] == 3
    detail = db.get_event_fact(conn, event)
    assert [d["version"] for d in detail["descriptions"]] == [1, 2, 3, 4]
    assert conn.execute("SELECT count(*) FROM event_facts").fetchone()[0] == 1
    phases = [json.loads(d["payload"])["progress"]["phase"]
              for d in detail["descriptions"][1:]]
    assert phases == ["first_update", "continuing", "continuing"]
    assert len([n for n in detail["notifications"]
                if n["kind"] == "semantic_update"]) == 3
    # End of event, then one more window: history only, one event still.
    monitor.close_all_event_facts("camera-stopped")
    closed = dict(conn.execute("SELECT * FROM event_facts WHERE event_id=?",
                               (event,)).fetchone())
    bridge = EventProgress(bridge.db_path)
    bridge._frames = deepcopy(runtime.event_progress._frames)
    runtime.event_progress = bridge
    bridge.start()
    handoff(4, 4, 1300.0, "人已离开")
    assert bridge.close()
    detail = db.get_event_fact(conn, event)
    assert [d["version"] for d in detail["descriptions"]] == [1, 2, 3, 4, 5]
    assert json.loads(detail["descriptions"][-1]["payload"])["progress"]["phase"] \
        == "after_close"
    assert dict(conn.execute("SELECT * FROM event_facts WHERE event_id=?",
                             (event,)).fetchone()) == closed


# ---------------------------------------------------------------------------
# C154 G：选材点只读绑定查询（`resolve_material_binding`）
# ---------------------------------------------------------------------------

def test_material_binding_resolver_is_readonly_and_returns_unique_event(live):
    """唯一事件 → 返回事实链事件键；只读（前后持久状态与业务快照不变）。"""
    monitor, conn, bridge, event_id = live
    before_facts = [dict(row) for row in
                    conn.execute("SELECT * FROM event_facts").fetchall()]
    before_desc = [dict(row) for row in
                   conn.execute("SELECT * FROM event_descriptions").fetchall()]
    before_counts = dict(bridge.snapshot()["counts"])
    result = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=("cam:r1:track:1",),
        frames=({"frame_id": 2, "timestamp_kind": "host_receive"},))
    assert result["status"] == "unique"
    assert result["binding"]["event_id"] == event_id
    assert result["binding"]["object_id"] == "cam:r1:track:1"
    assert result["binding"]["time_kind"] == "host_receive"
    assert [row["frame_id"] for row in result["frames"]] == ["2"]
    assert [dict(row) for row in
            conn.execute("SELECT * FROM event_facts").fetchall()] == before_facts
    assert [dict(row) for row in
            conn.execute("SELECT * FROM event_descriptions").fetchall()] \
        == before_desc
    after = bridge.snapshot()["counts"]
    for key, value in before_counts.items():
        assert after.get(key) == value, f"只读查询不得改变业务计数 {key}"


def test_material_binding_resolver_refuses_with_controlled_reasons(live):
    """四类不可聚合：无绑定 / 多对象 / 跨 run / 跨 config / 时间域不符。"""
    monitor, conn, bridge, event_id = live
    # 无绑定：未知帧
    missing = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=("cam:r1:track:1",),
        frames=({"frame_id": 999, "timestamp_kind": "host_receive"},))
    assert missing["status"] == "unbound"
    assert missing["reason"] == "frame_binding_missing"
    # 跨 run / 跨 config：身份不符（不借关联）
    assert bridge.resolve_material_binding(
        camera_id="cam", run_id="other", config_version=0,
        object_ids=("cam:r1:track:1",),
        frames=({"frame_id": 2, "timestamp_kind": "host_receive"},),
    )["status"] == "unbound"
    assert bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=99,
        object_ids=("cam:r1:track:1",),
        frames=({"frame_id": 2, "timestamp_kind": "host_receive"},),
    )["status"] == "unbound"
    # 多对象：请求的对象集合与帧内对象集合不符（不猜、不缩窄成一个对象）
    multi = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=("cam:r1:track:1", "cam:r1:track:9"),
        frames=({"frame_id": 2, "timestamp_kind": "host_receive"},))
    assert multi["status"] == "not_aggregatable"
    assert multi["reason"] == "object_mismatch"
    # 时间域不符
    kind = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=("cam:r1:track:1",),
        frames=({"frame_id": 2, "timestamp_kind": "wall_clock"},))
    assert kind["status"] == "not_aggregatable"
    assert kind["reason"] == "time_kind_mismatch"
    # 不声明对象 → 帧内对象身份不明，按受控原因拒绝（不代调用方挑一个对象）
    empty_ids = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0, object_ids=(),
        frames=({"frame_id": 2, "timestamp_kind": "host_receive"},))
    assert empty_ids["status"] == "not_aggregatable"
    assert empty_ids["reason"] == "object_ids_missing"


def test_material_binding_resolver_never_reads_l4_results(live):
    """不依赖 L4/未来结果：写入 L4 版本前后，解析结果不因"最新"改变。"""
    monitor, conn, bridge, event_id = live
    _write(bridge, _fusion(2, 1100))
    first = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=("cam:r1:track:1",),
        frames=({"frame_id": 2, "timestamp_kind": "host_receive"},))
    _write(bridge, _fusion(2, 1200, text="人仍在门口"))
    second = bridge.resolve_material_binding(
        camera_id="cam", run_id="r1", config_version=0,
        object_ids=("cam:r1:track:1",),
        frames=({"frame_id": 2, "timestamp_kind": "host_receive"},))
    assert first["binding"] == second["binding"], \
        "绑定只由事实链快照决定，不随 L4 版本/latest 改变"
    assert second["binding"]["event_id"] == event_id
