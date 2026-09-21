"""质量门禁脚本的时间戳与分位数口径 + LC-009 诚实边界与异常清理。"""

import json
import time

import pytest

import scripts.acceptance as acceptance
from scripts.acceptance import (_percentile, _source_seconds,
                                UNEVALUATED_GATES)


def test_source_seconds_accepts_epoch_seconds_and_milliseconds():
    now = 1_800_000_000.0
    assert _source_seconds(now - 0.2, wall_now=now) == now - 0.2
    assert _source_seconds((now - 0.3) * 1000, wall_now=now) == \
        pytest.approx(now - 0.3)


def test_source_seconds_rejects_missing_or_relative_pts():
    now = time.time()
    with pytest.raises(ValueError, match="数值时间戳"):
        _source_seconds(None, wall_now=now)
    with pytest.raises(ValueError, match="不在墙钟域"):
        _source_seconds(12.5, wall_now=now)


def test_percentiles_report_distribution_not_only_average():
    values = list(range(1, 101))
    assert _percentile([], 0.95) is None
    assert _percentile([42], 0.95) == 42
    assert _percentile(values, 0.50) == pytest.approx(50.5)
    assert _percentile(values, 0.95) == pytest.approx(95.05)
    assert _percentile(values, 0.99) == pytest.approx(99.01)


# ---------- LC-009：单相机实验探针诚实边界 + 相机源异常释放 ----------

class _FakeSource:
    """CameraSource 替身：记录 open/close，read 行为可编程。"""

    read_error = None
    close_error = None

    def __init__(self, camera_id, source):
        self.stats = {"timestamp_kind": "source_capture"}
        self.closed = False
        self._reads = 0
        _created_sources.append(self)

    def open(self):
        return True

    def read(self):
        self._reads += 1
        if type(self).read_error is not None:
            raise type(self).read_error
        return True, object(), time.time()

    def close(self):
        self.closed = True
        if type(self).close_error is not None:
            raise type(self).close_error


class _FakeMonitor:
    """Monitor 替身：step 行为可编程，gate 比例恒 0。"""

    GRAY_W = 8
    step_error = None

    def __init__(self, cam, detect_fn=None, sinks=None):
        pass

    def step(self, frame, gray, ts_ms):
        if type(self).step_error is not None:
            raise type(self).step_error

    class gate:
        last_ratio = 0.0


class _FakeDetector:
    def detect(self, frame):
        return []


_created_sources = []


def _cfg(detector=None):
    return {"cameras": [{"id": "probe", "source": "rtsp://host/stream",
                         "detector": detector if detector is not None
                         else {}}]}


def _install_fakes(monkeypatch, *, read_error=None, detector=None):
    _created_sources.clear()
    _FakeSource.read_error = read_error
    _FakeSource.close_error = None
    _FakeMonitor.step_error = None
    monkeypatch.setattr(acceptance, "CameraSource", _FakeSource)
    monkeypatch.setattr(acceptance, "Monitor", _FakeMonitor)
    monkeypatch.setattr(acceptance, "to_gray", lambda frame, w: None)
    if detector is not None:
        monkeypatch.setattr(acceptance, "_make_detector",
                            lambda det_cfg: (detector, None))


def test_report_marks_scope_and_release_gate_stays_null(tmp_path,
                                                        monkeypatch):
    _install_fakes(monkeypatch)
    report_path = str(tmp_path / "report.json")

    with pytest.raises(SystemExit) as excinfo:
        acceptance.run("probe", 0, _cfg(), report_path=report_path,
                       min_alert_samples=1)

    assert excinfo.value.code == 1  # 局部未达标即退出非零
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["scope"] == "single_camera_lab_probe"
    assert report["release_gate_passed"] is None
    assert report["unevaluated_gates"] == list(UNEVALUATED_GATES)
    assert len(report["unevaluated_gates"]) == 9
    assert report["schema_version"] == 2


def test_local_gate_pass_never_derives_release_pass(tmp_path, monkeypatch):
    _install_fakes(monkeypatch, detector=_FakeDetector())
    model_file = tmp_path / "model.onnx"
    model_file.write_bytes(b"weights")
    report_path = str(tmp_path / "report.json")

    with pytest.raises(SystemExit):
        acceptance.run("probe", 0,
                       _cfg(detector={"engine": "onnx",
                                      "model": str(model_file)}),
                       report_path=report_path, min_alert_samples=1)

    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    # 局部子门禁可以成立
    assert report["gates"]["detector"] is True
    assert report["gates"]["source_timestamps"] is True
    assert report["gates"]["source_timestamp_provenance"] is True
    assert report["model_sha256"]  # 哈希溯源保留
    # 但顶层发布门禁仍为 null：局部通过不得推导正式发布通过
    assert report["release_gate_passed"] is None


def test_step_loop_reads_source_error_closes_source_and_propagates(
        tmp_path, monkeypatch):
    _install_fakes(monkeypatch, read_error=RuntimeError("stream exploded"))
    report_path = str(tmp_path / "report.json")

    with pytest.raises(RuntimeError, match="stream exploded"):
        acceptance.run("probe", 0.05, _cfg(), report_path=report_path,
                       min_alert_samples=1)

    assert _created_sources[0].closed is True  # 异常路径仍释放相机源
    assert not (tmp_path / "report.json").exists()  # 不伪造成功报告


def test_close_error_does_not_mask_original_error(tmp_path, monkeypatch):
    _install_fakes(monkeypatch, read_error=RuntimeError("stream exploded"))
    _FakeSource.close_error = OSError("close also failed")

    with pytest.raises(RuntimeError, match="stream exploded"):
        acceptance.run("probe", 0.05, _cfg(),
                       report_path=str(tmp_path / "report.json"),
                       min_alert_samples=1)

    assert _created_sources[0].closed is True


def test_detector_build_error_closes_source_and_propagates(tmp_path,
                                                           monkeypatch):
    _install_fakes(monkeypatch)

    def _boom(det_cfg):
        raise ImportError("detector backend missing")

    monkeypatch.setattr(acceptance, "_make_detector", _boom)

    with pytest.raises(ImportError, match="detector backend missing"):
        acceptance.run("probe", 0, _cfg(),
                       report_path=str(tmp_path / "report.json"))

    assert _created_sources[0].closed is True
    assert not (tmp_path / "report.json").exists()


def test_report_write_failure_closes_source_and_propagates(tmp_path,
                                                           monkeypatch):
    _install_fakes(monkeypatch)
    report_path = str(tmp_path / "report.json")

    def _boom(src, dst):
        raise OSError("replace failed")

    monkeypatch.setattr(acceptance.os, "replace", _boom)

    with pytest.raises(OSError, match="replace failed"):
        acceptance.run("probe", 0, _cfg(), report_path=report_path,
                       min_alert_samples=1)

    assert _created_sources[0].closed is True
    assert not (tmp_path / "report.json").exists()  # 不留下伪造成功报告
    assert not list(tmp_path.glob("report.json.*.tmp"))
