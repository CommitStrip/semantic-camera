"""Nonblocking observer contracts; synthetic clocks are not performance evidence."""
import threading
import pytest
from test_win11_l2_runtime import _R2Probe, _person


@pytest.mark.xfail(
    strict=False, run=True,
    reason="时序敏感：低负载本机稳定通过；CI 运行器负载下单次 pump 内 L3 可能未完成，"
           "已知限制见 RELEASE_NOTES")
def test_slow_observer_does_not_block_actual_business():
    entered, release = threading.Event(), threading.Event()
    def observer(record):
        entered.set()
        assert release.wait(3)
    probe = _R2Probe(trace_sink=observer)
    try:
        probe.feed(change_boxes=[dict(x=120, y=90, w=40, h=60)], detections=_person(.4))
        assert probe.pump()
        assert entered.wait(1)
        probe.drain()
        assert probe.counts()["l3_completed"] > 0
        assert not probe.runtime._close_trace(.01)
        assert not probe.runtime.snapshot()["trace"]["delivery_complete"]
    finally:
        release.set()
        assert probe.runtime._close_trace(1)


def test_overflow_is_visible_and_never_blocks():
    entered, release = threading.Event(), threading.Event()
    probe = _R2Probe(trace_sink=lambda _: (entered.set(), release.wait(3)))
    rt = probe.runtime
    try:
        rt._trace_emit("stage_started")
        assert entered.wait(1)
        for _ in range(1000):
            rt._trace_emit("stage_finished")
        assert rt._trace_queue.qsize() <= 128
        assert rt.snapshot()["trace"]["dropped"] > 0
    finally:
        release.set()
        assert rt._close_trace(1)
    assert not rt.snapshot()["trace"]["delivery_complete"]


@pytest.mark.parametrize("fault", ["callback", "clock"])
def test_observation_errors_never_claim_complete(fault):
    def bad(_):
        raise RuntimeError("observer")
    rt = _R2Probe(trace_sink=bad if fault == "callback" else lambda _: None).runtime
    if fault == "clock":
        rt._trace_clock = lambda: float("nan")
    rt._trace_emit("stage_started")
    assert rt._close_trace(1)
    assert not rt.snapshot()["trace"]["delivery_complete"]


def test_shared_domain_explicit_registration_and_unknown_identity():
    from scam.win11_event_progress import EventProgress
    records = []
    bridge = EventProgress("unused.sqlite")
    rt = _R2Probe().runtime
    rt.event_progress = bridge
    rt.configure_trace(records.append, clock_domain="process-instance-test",
                       clock=lambda: 12.5, clock_kind="simulated")
    rt._trace_emit("l4_partial", window_key=("cam", "run", 2, "w"), version_id="v1")
    assert rt._close_trace(1)
    assert bridge._trace_domain == "process-instance-test"
    record = records[0]
    assert record["schema"] == "scam.trace/v1"
    assert record["t_mono_ms"] == 12500
    assert record["clock"] == "simulated"
    assert record["camera_id"] == "cam" and record["window_id"] == "w"
    assert record["event_id"] is None
    assert record["source_version_id"] == "v1"
    rt._trace_emit("stage_started")
    assert rt.snapshot()["trace"]["after_close_dropped"] == 1
    assert not rt.snapshot()["trace"]["delivery_complete"]


def test_none_samples_no_observation_clock_and_allocates_no_queue():
    rt = _R2Probe().runtime
    rt._trace_clock = lambda: (_ for _ in ()).throw(AssertionError("sampled"))
    rt._trace_emit("stage_started")
    assert not hasattr(rt, "_trace_queue")
    assert rt._trace_thread is None


def test_record_budget_and_unjoined_producer_are_incomplete():
    rt = _R2Probe(trace_sink=lambda _: None).runtime
    rt._trace_emit("stage_started", materials=list(range(513)))
    assert rt.snapshot()["trace"]["clock_errors"] == 1
    assert not rt._close_trace(.01, producers_done=False)
    assert not rt.snapshot()["trace"]["delivery_complete"]
    assert rt._close_trace(1, producers_done=True)
    assert not rt.snapshot()["trace"]["delivery_complete"]
