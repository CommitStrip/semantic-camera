import threading

import pytest

from scam.health import CameraWatchdog
from scam import nvr as nvr_mod


class _Monitor:
    GRAY_W = 8

    def __init__(self, *args, **kwargs):
        self.frames = []

    def step(self, frame, gray, now):
        self.frames.append((frame, now))


class _State:
    def __init__(self):
        self.monitors = {}


def _patch_runtime(monkeypatch, source_cls):
    monkeypatch.setattr(nvr_mod, "CameraSource", source_cls)
    monkeypatch.setattr(nvr_mod, "Monitor", _Monitor)
    monkeypatch.setattr(nvr_mod, "build_sinks", lambda *a, **k: [])
    monkeypatch.setattr(nvr_mod, "to_gray", lambda frame, width: None)


def test_camera_thread_reports_open_failure_recovery_and_stop(monkeypatch):
    stop = threading.Event()

    class Source:
        opens = 0

        def __init__(self, *args, **kwargs):
            self.closed = False

        def open(self):
            Source.opens += 1
            return Source.opens >= 2

        def read(self):
            stop.set()
            return True, "frame", 123.0

        @property
        def stats(self):
            return {"timestamp_kind": "source_capture"}

        def close(self):
            self.closed = True

    _patch_runtime(monkeypatch, Source)
    watchdog = CameraWatchdog("front", stall_after_s=30)
    state = _State()

    nvr_mod._run_camera(
        {"id": "front", "source": "rtsp://camera"}, [], "events.db",
        stop, state, watchdog)

    snapshot = watchdog.snapshot()
    assert snapshot["state"] == "stopped"
    assert snapshot["frames"] == 1
    assert snapshot["open_failures"] == 1
    assert snapshot["reconnects"] == 1
    assert snapshot["timestamp_kind"] == "source_capture"
    assert state.monitors == {}


def test_camera_thread_reports_read_recovery_without_blocking_frames(
        monkeypatch):
    stop = threading.Event()

    class Source:
        reads = 0

        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def read(self):
            Source.reads += 1
            if Source.reads == 1:
                return False, None, None
            stop.set()
            return True, "recovered-frame", 456.0

        @property
        def stats(self):
            return {"timestamp_kind": "host_receive"}

        def close(self):
            pass

    _patch_runtime(monkeypatch, Source)
    watchdog = CameraWatchdog("side", stall_after_s=30)

    nvr_mod._run_camera(
        {"id": "side", "source": "rtsp://camera"}, [], "events.db",
        stop, None, watchdog)

    snapshot = watchdog.snapshot()
    assert snapshot["state"] == "stopped"
    assert snapshot["frames"] == 1
    assert snapshot["read_failures"] == 1
    assert snapshot["reconnects"] == 1
    assert snapshot["timestamp_kind"] == "host_receive"


def test_camera_thread_stops_cleanly_during_open_retry(monkeypatch):
    stop = threading.Event()

    class Source:
        closed = False

        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            stop.set()
            return False

        def close(self):
            Source.closed = True

    _patch_runtime(monkeypatch, Source)
    watchdog = CameraWatchdog("offline")

    nvr_mod._run_camera(
        {"id": "offline", "source": "rtsp://camera"}, [], "events.db",
        stop, None, watchdog)

    snapshot = watchdog.snapshot()
    assert snapshot["state"] == "stopped"
    assert snapshot["open_failures"] == 1
    assert snapshot["frames"] == 0
    assert Source.closed is True


def test_camera_thread_closes_source_when_monitor_setup_fails(monkeypatch):
    stop = threading.Event()

    class Source:
        closed = False

        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def close(self):
            Source.closed = True

    class BrokenMonitor:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("monitor setup failed")

    _patch_runtime(monkeypatch, Source)
    monkeypatch.setattr(nvr_mod, "Monitor", BrokenMonitor)
    watchdog = CameraWatchdog("broken")

    with pytest.raises(RuntimeError, match="monitor setup failed"):
        nvr_mod._run_camera(
            {"id": "broken", "source": "rtsp://camera"}, [], "events.db",
            stop, None, watchdog)

    assert Source.closed is True
    assert watchdog.snapshot()["state"] == "stopped"
