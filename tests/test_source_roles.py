"""Z2 源角色契约：detect/record 双角色配置（兼容旧 source）+ cv2 回退源确定性恢复。

公开测试（跨平台）。vus 在场与否不影响断言——用 sys.modules 注入 None 强制走
cv2 回退路径，保证确定性。
"""

import json
import sys
import threading
import time

import pytest

from scam.config import validate_venue
from scam.nvr import _run_camera
from scam.source import CameraSource


def _venue(**extra):
    cam = {"id": "c1", "source": "rtsp://u:p@192.168.1.64:554/x",
           "detector": {"engine": "none"},
           "zones": [], "schedule": [{"from": "00:00", "to": "23:59"}]}
    cam.update(extra)
    return {"version": "0.3", "cameras": [cam]}


# ---------- 配置：双角色与向后兼容 ----------

def test_legacy_source_only_config_still_valid():
    assert validate_venue(_venue()) == []


def test_role_overrides_and_kind_are_valid():
    errs = validate_venue(_venue(
        source_kind="file", detect_source="file:///a.avi",
        record_source="rtsp://u:p@192.168.1.64:554/main",
        record_enabled=False))
    assert errs == []


def test_source_kind_enum_validated():
    errs = validate_venue(_venue(source_kind="http"))
    assert any("source_kind" in e for e in errs)


def test_role_sources_must_be_nonempty_strings():
    errs = validate_venue(_venue(detect_source=""))
    assert any("detect_source" in e for e in errs)
    errs = validate_venue(_venue(record_source=123))
    assert any("record_source" in e for e in errs)


def test_recording_defaults_off():
    v = _venue()
    assert v["cameras"][0].get("record_enabled", False) is False, \
        "配置缺省绝不开启 24/7 录像"
    assert validate_venue(v) == []


def test_record_enabled_must_be_bool():
    errs = validate_venue(_venue(record_enabled="yes"))
    assert any("record_enabled" in e for e in errs)


# ---------- 源接线：_run_camera 传 source_kind 与 detect 角色 ----------

def test_run_camera_uses_detect_role_and_kind(tmp_path, monkeypatch):
    import scam.nvr as nvr_mod

    captured = {}

    class SpySource:
        def __init__(self, camera_id, url, source_kind="rtsp", **kw):
            captured.update(camera_id=camera_id, url=url,
                            source_kind=source_kind)

        def open(self):
            return False

        def close(self):
            pass

    monkeypatch.setattr(nvr_mod, "CameraSource", SpySource)
    stop = threading.Event()
    stop.set()  # 预置停机：_run_camera 构建源后立即返回，不进值守循环
    _run_camera({"id": "cam", "source": "rtsp://u:p@x/1",
                 "source_kind": "file",
                 "detect_source": "/tmp/a.avi"},
                [], str(tmp_path / "d.db"), stop, None)
    assert captured == {"camera_id": "cam", "url": "/tmp/a.avi",
                        "source_kind": "file"}


def test_run_camera_defaults_to_source_and_rtsp(tmp_path, monkeypatch):
    import scam.nvr as nvr_mod

    captured = {}

    class SpySource:
        def __init__(self, camera_id, url, source_kind="rtsp", **kw):
            captured.update(url=url, source_kind=source_kind)

        def open(self):
            return False

        def close(self):
            pass

    monkeypatch.setattr(nvr_mod, "CameraSource", SpySource)
    stop = threading.Event()
    stop.set()
    _run_camera({"id": "cam", "source": "rtsp://u:p@x/1"},
                [], str(tmp_path / "d.db"), stop, None)
    assert captured == {"url": "rtsp://u:p@x/1", "source_kind": "rtsp"}


# ---------- cv2 回退源：读失败必须重建，绝不原地永久失败 ----------

def _force_cv2_fallback(monkeypatch):
    monkeypatch.setitem(sys.modules, "vus", None)
    monkeypatch.setitem(sys.modules, "vus.source", None)


def _make_avi(tmp_path, frames=8):
    import cv2
    import numpy as np

    path = tmp_path / "gate.avi"
    writer = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"MJPG"),
                             20.0, (320, 240))
    assert writer.isOpened()
    for i in range(frames):
        frame = np.zeros((240, 320, 3), dtype=np.uint8)
        cv2.rectangle(frame, ((i * 8) % 280, 80), ((i * 8) % 280 + 40, 120),
                      (0, 255, 0), -1)
        writer.write(frame)
    writer.release()
    return str(path)


def test_cv2_fallback_reopens_after_eof(tmp_path, monkeypatch):
    _force_cv2_fallback(monkeypatch)
    src = CameraSource("cam", _make_avi(tmp_path), source_kind="file")
    assert src.open() is True

    got = 0
    for _ in range(20):            # 远超 8 帧片长：EOF 后必须回绕继续出帧
        ok, frame, ts = src.read()
        if ok:
            got += 1
            assert frame is not None and ts is not None
    assert got == 20, f"读失败后未重建，20 次读取只得到 {got} 帧"

    stats = src.stats
    assert stats["reconnects"] >= 1
    assert stats["read_failures"] >= 1
    assert stats["last_frame_ts"] is not None
    assert stats["timestamp_kind"] == "host_receive"


def test_cv2_fallback_open_failure_is_counted(tmp_path, monkeypatch):
    _force_cv2_fallback(monkeypatch)
    src = CameraSource("cam", str(tmp_path / "missing.avi"),
                       source_kind="file")
    assert src.open() is False
    assert src.stats["open_failures"] == 1
    assert src.stats["timestamp_kind"] == "host_receive"


def test_vus_without_timestamp_attestation_remains_unknown(monkeypatch):
    class StubVusSource:
        stats = {"frames": 3}

        def open(self):
            return True

        def close(self):
            pass

    src = CameraSource("cam", "rtsp://example/stream")
    monkeypatch.setattr(src, "_build", lambda: StubVusSource())
    assert src.open() is True
    assert src.stats == {"frames": 3, "timestamp_kind": "unknown"}


# ---------- 源时间戳贯穿：只有 source_capture 溯源才能进 Monitor ----------

def test_run_camera_uses_attested_source_timestamp(tmp_path, monkeypatch):
    """源显式证明 source_capture 时，Monitor.step 的 now 必须是采集时刻。"""
    import scam.nvr as nvr_mod

    captured = {}
    stop = threading.Event()

    class SpyMonitor:
        GRAY_W = 96                  # nvr 循环里会引用 Monitor.GRAY_W

        def __init__(self, cfg, detect_fn=None, sinks=None):
            pass

        def step(self, frame, gray, now):
            captured["now"] = now

    class Src:
        stats = {"timestamp_kind": "source_capture"}

        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def read(self):
            if "now" in captured:
                stop.set()
                return False, None, None
            return True, "frame", 12345.6

        def close(self):
            pass

    monkeypatch.setattr(nvr_mod, "Monitor", SpyMonitor)
    monkeypatch.setattr(nvr_mod, "build_sinks", lambda *a, **k: [])
    monkeypatch.setattr(nvr_mod, "to_gray", lambda frame, w: None)
    monkeypatch.setattr(nvr_mod, "CameraSource", Src)
    _run_camera({"id": "cam", "source": "rtsp://u:p@x/1"},
                [], str(tmp_path / "d.db"), stop, None)
    assert captured["now"] == pytest.approx(12345600.0)


def test_run_camera_falls_back_to_wallclock_without_attestation(
        tmp_path, monkeypatch):
    """host_receive/unknown 溯源不得冒充采集时刻——退回墙钟处理时间。"""
    import scam.nvr as nvr_mod

    captured = {}
    stop = threading.Event()

    class SpyMonitor:
        GRAY_W = 96                  # nvr 循环里会引用 Monitor.GRAY_W

        def __init__(self, cfg, detect_fn=None, sinks=None):
            pass

        def step(self, frame, gray, now):
            captured["now"] = now

    class Src:
        stats = {"timestamp_kind": "host_receive"}

        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def read(self):
            if "now" in captured:
                stop.set()
                return False, None, None
            return True, "frame", 12345.6     # 诱饵：不可信的"源时间"

        def close(self):
            pass

    monkeypatch.setattr(nvr_mod, "Monitor", SpyMonitor)
    monkeypatch.setattr(nvr_mod, "build_sinks", lambda *a, **k: [])
    monkeypatch.setattr(nvr_mod, "to_gray", lambda frame, w: None)
    monkeypatch.setattr(nvr_mod, "CameraSource", Src)
    before = time.time() * 1000.0
    _run_camera({"id": "cam", "source": "rtsp://u:p@x/1"},
                [], str(tmp_path / "d.db"), stop, None)
    assert "now" in captured
    assert captured["now"] != pytest.approx(12345600.0)
    assert captured["now"] >= before - 2000   # 墙钟附近


# ---------- vus 单调时钟锚定：直播时间戳映射回墙钟序列 ----------

def test_vus_monotonic_timestamp_anchored_to_wallclock(tmp_path, monkeypatch):
    """vus 源（time.monotonic 打点）的读帧时刻经锚点映射为墙钟，溯源
    标签诚实为 host_receive，跨读帧保持墙钟域单调。"""
    import time as time_mod

    class MonoVusSource:
        stats = {}

        def open(self):
            return True

        def read(self):
            return True, "frame", time_mod.monotonic()

        def close(self):
            pass

    src = CameraSource("cam", "rtsp://x", source_kind="rtsp")

    def fake_build():
        src._vus_monotonic = True
        return MonoVusSource()

    monkeypatch.setattr(src, "_build", fake_build)
    assert src.open() is True

    before = time.time()
    ok, frame, ts = src.read()
    after = time.time()

    assert ok is True
    assert before - 1 <= ts <= after + 1, "单调时间戳必须锚定到墙钟邻域"
    assert src.stats["timestamp_kind"] == "host_receive"

    ok2, _, ts2 = src.read()
    assert ok2 is True and ts2 >= ts, "锚定后的墙钟序列保持单调"
