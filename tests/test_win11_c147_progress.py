"""Event trace measurement contracts; synthetic input/model, no native resources."""
from collections import defaultdict
import itertools
import threading

import pytest

from scam import db
from scam.win11_event_progress import EventProgress
from scam.win11_l2_runtime import L2Runtime
from scam.win11_l3_contract import (L3BranchKind, L3BranchResult, L3Omission,
                                    L3Output, L3SourceRef, L3Status, L3Task,
                                    L3Uncertainty, L3WindowIdentity)
from scam.win11_l4 import L4Stage
from test_win11_event_progress import live, _consume, _fusion


def _traced(live, observer):
    monitor, conn, original, event = live
    ticks = itertools.count(10000)
    bridge = EventProgress(original.db_path, trace_observer=observer,
                           trace_clock=lambda: next(ticks) / 1000.0,
                           trace_clock_domain="simulated-process-instance:fixture-1",
                           trace_clock_kind="simulated")
    # Fixture registry copies retain actual real Monitor bindings, no fabricated IDs.
    bridge._frames = original._frames.copy()
    bridge._frame_times = original._frame_times.copy()
    bridge._events = original._events.copy()
    bridge._event_times = original._event_times.copy()
    return monitor, conn, bridge, event


def test_none_has_no_sampling_observer_queue_thread_or_trace_snapshot(live):
    _, _, original, _ = live
    bridge = EventProgress(original.db_path, trace_observer=None,
                           trace_clock=lambda: pytest.fail("disabled trace sampled time"))
    bridge._frames = original._frames.copy()
    assert not hasattr(bridge, "_trace_queue")
    assert bridge.submit(_fusion())
    bridge.start()
    assert bridge.close()
    assert bridge._trace_thread is None
    assert "trace" not in bridge.snapshot()
    assert bridge.snapshot()["counts"]["appended"] == 1


def test_precise_order_identity_source_and_real_description_version(live):
    records = []
    _, _, bridge, event = _traced(live, records.append)
    assert bridge.submit(_fusion())
    bridge.start()
    assert bridge.close()
    assert [r["stage"] for r in records] == [
        "l4_received", "progress_queued", "write_start", "commit_success"]
    assert [r["t_mono_ms"] for r in records] == [10000.0, 10001.0, 10002.0, 10003.0]
    assert len({r["trace_id"] for r in records}) == 1
    assert all(r["schema"] == "scam.trace/v1" and r["component"] == "event_progress" for r in records)
    assert all((r["camera_id"], r["run_id"], r["config_version"], r["window_id"]) == ("cam", "r1", 0, 1) for r in records)
    assert all(r["source_version_id"] == "v1" and r["source_frame_ids"] == ("2",) for r in records)
    assert all(r["clock"] == "simulated" and r["clock_kind"] == "host_monotonic" for r in records)
    assert all(r["time_unit"] == "ms" for r in records)
    assert len({r["process_id"] for r in records}) == 1
    assert records[0]["event_id"] is None and records[1]["event_id"] is None
    assert records[2]["event_id"] == records[3]["event_id"] == event
    assert records[2]["event_occurrence"] == records[3]["event_occurrence"] == 1
    assert records[2]["description_version"] is None
    assert records[3]["description_version"] == 2
    assert bridge.snapshot()["trace"]["delivery_complete"] is True
    assert not any("display" in r["stage"] or "t_display" in r or "text" in r or "db_path" in r for r in records)


def test_commit_success_observed_only_after_existing_publisher_returns(live, monkeypatch):
    records = []
    _, conn, bridge, event = _traced(live, records.append)
    entered, release = threading.Event(), threading.Event()
    original = db.publish_semantic_update

    def blocked(conn, **kwargs):
        entered.set()
        assert release.wait(2)
        return original(conn, **kwargs)

    monkeypatch.setattr(db, "publish_semantic_update", blocked)
    bridge.start()
    assert bridge.submit(_fusion())
    assert entered.wait(2)
    try:
        assert not any(r["stage"] == "commit_success" for r in records)
        assert len(db.get_event_fact(conn, event)["descriptions"]) == 1
    finally:
        release.set()
        assert bridge.close()
    assert records[-1]["stage"] == "commit_success"
    assert len(db.get_event_fact(conn, event)["descriptions"]) == 2


def test_duplicate_and_unknown_never_become_commit_success(live):
    records = []
    _, _, bridge, _ = _traced(live, records.append)
    bridge.start()
    assert bridge.submit(_fusion())
    assert bridge.submit(_fusion(window_id=99))
    unassociated = _fusion()
    unassociated["items"] = unassociated["items"][1:]
    assert bridge.submit(unassociated)
    assert bridge.close()
    by_attempt = defaultdict(list)
    for record in records:
        by_attempt[record["trace_id"]].append(record)
    ends = [rows[-1] for rows in by_attempt.values()]
    assert sorted(r["stage"] for r in ends) == ["commit_success", "write_skipped", "write_skipped"]
    assert {r.get("status") for r in ends} == {"appended", "duplicate", "unassociated"}
    assert next(r for r in ends if r.get("status") == "unassociated")["event_id"] is None
    assert bridge.snapshot()["counts"]["appended"] == 1


@pytest.mark.parametrize("kind", ["raise", "reject", "connect"])
def test_actual_publication_failure_reported_without_success(live, monkeypatch, kind):
    records = []
    _, _, bridge, _ = _traced(live, records.append)
    if kind == "reject":
        monkeypatch.setattr(db, "publish_semantic_update", lambda *a, **k: (None, False))
    else:
        def fail(*args, **kwargs):
            raise RuntimeError("injected database call failure")
        monkeypatch.setattr(db, "connect" if kind == "connect" else "publish_semantic_update", fail)
    bridge.start()
    assert bridge.submit(_fusion())
    assert bridge.close()
    assert not any(r["stage"] == "commit_success" for r in records)
    assert records[-1]["stage"] == "commit_failed"
    if kind == "raise":
        assert records[-1]["publication_outcome"] == "unconfirmed"
        assert records[-1]["write_attempted"] is True
    if kind == "connect":
        assert records[-1]["event_id"] is None
        assert records[-1]["publication_outcome"] == "not_attempted"


def test_callback_raises_without_changing_success_or_fact(live):
    def broken(record):
        raise ValueError("observer failure")
    _, conn, bridge, event = _traced(live, broken)
    bridge.start()
    assert bridge.submit(_fusion())
    assert bridge.close()
    assert bridge.snapshot()["counts"]["appended"] == 1
    assert bridge.snapshot()["trace"]["counts"]["callback_errors"] == 4
    assert bridge.snapshot()["trace"]["delivery_complete"] is False
    assert len(db.get_event_fact(conn, event)["descriptions"]) == 2


def test_slow_callback_does_not_block_business_or_fast_metadata_close_is_bounded(live):
    entered, release = threading.Event(), threading.Event()

    def slow(record):
        entered.set()
        assert release.wait(3)

    monitor, conn, bridge, event = _traced(live, slow)
    bridge.start()
    assert bridge.submit(_fusion())
    assert entered.wait(2)
    try:
        _consume(monitor, bridge, 3, 1200)
        assert bridge.submit(_fusion(3, 1200, "进展"))
        # Join only the business worker; observer is deliberately blocked.
        assert not bridge.close(timeout=0.5)
        assert len(db.get_event_fact(conn, event)["descriptions"]) == 3
        assert bridge.snapshot()["counts"]["appended"] == 2
        assert bridge.snapshot()["trace"]["in_flight"]
    finally:
        release.set()
        assert bridge.close(timeout=2)


def test_trace_queue_hard_bound_drop_does_not_change_core_capacity(live):
    records = []
    _, _, bridge, _ = _traced(live, records.append)
    # No workers yet: accept 64 core jobs; then reject, never grow either queue.
    accepted = [bridge.submit(_fusion()) for _ in range(1000)]
    assert sum(accepted) == 64
    assert bridge._trace_queue.qsize() == 128
    assert bridge.snapshot()["trace"]["counts"]["dropped"] > 0
    assert bridge.snapshot()["trace"]["delivery_complete"] is False
    bridge.start()
    assert bridge.close()
    assert bridge.snapshot()["counts"]["appended"] == 1
    assert bridge.snapshot()["counts"]["duplicate"] == 63
    assert bridge.snapshot()["counts"]["queue_full"] == 936
    # Collector must reject complete-measurement claims when dropped > 0.
    assert bridge.snapshot()["trace"]["counts"]["dropped"] > 0


def test_invalid_input_and_bad_trace_clock_never_change_business_return(live):
    _, _, original, _ = live
    bridge = EventProgress(original.db_path, trace_observer=lambda r: None,
                           trace_clock=lambda: float("nan"), trace_clock_kind="simulated",
                           trace_clock_domain="simulated-process-instance:bad-clock")
    bridge._frames = original._frames.copy()
    assert not bridge.submit({"frame_refs": None})
    assert bridge.submit(_fusion())
    bridge.start()
    assert bridge.close()
    assert bridge.snapshot()["counts"]["appended"] == 1
    assert bridge.snapshot()["trace"]["counts"]["clock_or_record_errors"] > 0


def test_submission_after_close_never_refills_stopped_observer_queue(live):
    records = []
    _, _, bridge, _ = _traced(live, records.append)
    bridge.start()
    assert bridge.submit(_fusion())
    assert bridge.close()
    assert not bridge.submit(_fusion())
    assert bridge.close()
    trace = bridge.snapshot()["trace"]
    assert trace["pending"] == 0
    assert trace["counts"]["after_close_dropped"] == 2
    assert trace["delivery_complete"] is False


def test_observer_registration_requires_explicit_domain_before_use(live):
    _, _, original, _ = live
    with pytest.raises(ValueError):
        EventProgress(original.db_path, trace_observer=lambda r: None)
    bridge = EventProgress(original.db_path)
    bridge.set_trace_observer(lambda r: None, clock_domain="process-instance:one")
    with pytest.raises(RuntimeError):
        bridge.set_trace_observer(lambda r: None, clock_domain="process-instance:two")
    assert bridge.close()


def test_real_l4_partial_then_later_branch_append_without_reopening(live):
    records = []
    monitor, conn, original, event = live
    bridge = EventProgress(original.db_path)
    bridge._frames = original._frames.copy()
    bridge._frame_times = original._frame_times.copy()
    bridge._events = original._events.copy()
    bridge._event_times = original._event_times.copy()
    runtime = L2Runtime(["cam"], None, None, l4_factory=L4Stage, event_progress=bridge)
    ticks = itertools.count(10000)
    runtime.configure_trace(records.append, clock_domain="process-instance:joint",
        clock=lambda: next(ticks) / 1000.0, clock_kind="simulated")
    runtime.set_camera_identity("cam", "r1", 0)
    window = L3WindowIdentity("cam", "r1", 0, 71)
    task = L3Task(window, L3BranchKind.PANORAMA, (), "fixture", 0, None)

    def publish(text):
        branch = L3BranchResult(branch=L3BranchKind.PANORAMA, status=L3Status.OK,
                                error_code=None, observation=text, inference=None,
                                uncertainty=L3Uncertainty(),
                                sources=(L3SourceRef(1, 2, True, 1100.0, "host_receive"),),
                                window=window, crop_id=None, model_ref="stub/test", region_only=False)
        out = L3Output(window=window, branch=L3BranchKind.PANORAMA, status=L3Status.OK,
                       error_code=None, results=(branch,), omission=L3Omission(0, ""),
                       model_ref="stub/test", timings_ms={})
        runtime._accumulate_branch_result("cam", task, {"l1_refs": [monitor._object_id(1)]},
                                          out, ("cam", "r1", 0, 71))

    first_done = threading.Event()
    collector = bridge._trace_observer

    def collected(record):
        collector(record)
        if record["stage"] == "commit_success":
            first_done.set()

    bridge._trace_observer = collected  # Fixture wrapping, before start.
    bridge.start()
    publish("先到的有用解释")
    assert first_done.wait(2), "Must commit first branch before the second even exists"
    assert len(db.get_event_fact(conn, event)["descriptions"]) == 2
    monitor.close_all_event_facts("camera-stopped")
    closed = dict(conn.execute("SELECT * FROM event_facts WHERE event_id=?", (event,)).fetchone())
    publish("晚到的补充解释")
    assert bridge.close()
    assert runtime._close_trace(1)
    assert dict(conn.execute("SELECT * FROM event_facts WHERE event_id=?", (event,)).fetchone()) == closed
    successes = [r for r in records if r["stage"] == "commit_success"]
    assert [r["description_version"] for r in successes] == [2, 3]
    assert all(r["event_id"] == event for r in successes)
    assert len({r["source_version_id"] for r in successes}) == 2
    handoffs = {r["source_version_id"]: r for r in records if r["stage"] == "l4_handoff"}
    assert set(handoffs) == {r["source_version_id"] for r in successes}
    assert all(r["clock_domain"] == "process-instance:joint" for r in records)
    assert len({r["process_id"] for r in records}) == 1
    for result in successes:
        handoff = handoffs[result["source_version_id"]]
        assert handoff["t_mono_ms"] <= result["t_mono_ms"]
        assert handoff["event_id"] is None
    assert runtime.snapshot()["trace"]["delivery_complete"]
