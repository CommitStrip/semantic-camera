import pytest

from scam.health import (CameraWatchdog, HealthRegistry, RuntimeResourceSampler,
                         _parse_proc_status)


def test_camera_watchdog_lifecycle_and_stall_transition():
    health = CameraWatchdog("front", stall_after_s=30)
    health.started(now=0)
    health.opened(now=1)
    assert health.snapshot(now=2)["state"] == "starting"

    health.frame(now=3, source_ts=1000.0, timestamp_kind="source_capture")
    live = health.snapshot(now=20)
    assert live["state"] == "online"
    assert live["last_frame_age_s"] == pytest.approx(17)
    assert live["timestamp_kind"] == "source_capture"

    stalled = health.snapshot(now=33)
    assert stalled["state"] == "stalled"
    assert stalled["frames"] == 1


def test_camera_watchdog_failure_recovery_and_counters():
    health = CameraWatchdog("side", stall_after_s=5)
    health.failure("open", "timeout", now=1)
    failed = health.snapshot(now=2)
    assert failed["state"] == "recovering"
    assert failed["open_failures"] == 1
    assert failed["last_error"] == "timeout"

    health.opened(now=3, reconnect=True)
    health.frame(now=4, timestamp_kind="host_receive")
    recovered = health.snapshot(now=4)
    assert recovered["state"] == "online"
    assert recovered["reconnects"] == 1
    assert recovered["last_error"] is None
    assert recovered["last_error_age_s"] is None

    health.failure("read", "eof", now=5)
    assert health.snapshot(now=6)["read_failures"] == 1
    health.stopped(now=7)
    assert health.snapshot(now=99)["state"] == "stopped"


def test_camera_watchdog_rejects_invalid_contracts():
    with pytest.raises(ValueError):
        CameraWatchdog("cam", stall_after_s=0)
    health = CameraWatchdog("cam")
    with pytest.raises(ValueError):
        health.failure("detector", "bad", now=0)


def test_parse_proc_status():
    parsed = _parse_proc_status(
        "Name:\tpython\nVmRSS:\t  1234 kB\nThreads:\t7\n")
    assert parsed == {"rss_bytes": 1234 * 1024, "threads": 7}
    assert _parse_proc_status("Name:\tpython\n") == {
        "rss_bytes": None, "threads": None}


def test_resource_sampler_reports_disk_and_delta_cpu(tmp_path, monkeypatch):
    sampler = RuntimeResourceSampler(str(tmp_path))
    monkeypatch.setattr(
        sampler, "_process_metrics",
        lambda: {"rss_bytes": 1024, "threads": 3, "open_fds": 4})

    first = sampler.sample(now=10, process_time_s=2)
    second = sampler.sample(now=20, process_time_s=3.5)
    assert first["cpu_percent"] is None
    assert second["cpu_percent"] == pytest.approx(15.0)
    assert second["rss_bytes"] == 1024
    assert second["threads"] == 3
    assert second["open_fds"] == 4
    assert second["disk"]["total_bytes"] > 0
    assert 0 <= second["disk"]["used_percent"] <= 100


def test_health_registry_is_bounded_sorted_and_rejects_unknown(tmp_path):
    registry = HealthRegistry(["side", "front"], str(tmp_path),
                              stall_after_s=10)
    registry.camera("front").started(now=0)
    registry.camera("front").frame(now=1, timestamp_kind="host_receive")

    snapshot = registry.snapshot(now=5, include_resources=False)
    assert snapshot["count"] == 2
    assert [item["camera"] for item in snapshot["cameras"]] == [
        "front", "side"]
    assert snapshot["cameras"][0]["state"] == "online"
    assert snapshot["resources"] is None
    with pytest.raises(KeyError):
        registry.camera("missing")


def test_health_registry_rejects_duplicate_camera_ids(tmp_path):
    with pytest.raises(ValueError):
        HealthRegistry(["front", "front"], str(tmp_path))
