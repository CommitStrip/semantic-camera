import json
from pathlib import Path

from scam import win11_acceptance as acceptance


def _venue(source="rtsp://admin:secret@camera/live", detector=None):
    return {
        "venue": {"name": "test"},
        "cameras": [{
            "id": "front-door",
            "source_kind": "rtsp",
            "source": source,
            "detector": detector or {"engine": "none"},
            "record_enabled": False,
            "zones": [],
        }],
    }


def _all_dependencies(_name):
    return object()


def test_preflight_monitor_only_is_honest_and_redacts_source(
        tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    config = tmp_path / "semantic-camera" / "cameras.json"
    config.parent.mkdir()
    config.write_text(json.dumps(_venue()), encoding="utf-8")

    report = acceptance.collect_preflight(
        config, current_platform="win32", find_spec=_all_dependencies,
        ffmpeg_path="ffmpeg.exe")

    assert report["summary"] == {
        "launch_ready": True,
        "alerting_ready": False,
        "monitor_only": True,
    }
    assert report["evidence_level"] == "automated_preflight"
    assert "real_rtsp_stream" in report["not_verified"]
    serialized = json.dumps(report, ensure_ascii=False)
    assert "admin:secret" not in serialized
    assert "camera/live" not in serialized
    assert report["cameras"][0]["recording_enabled"] is False


def test_preflight_blocks_missing_model_and_external_config(
        tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "profile"))
    config = tmp_path / "outside.json"
    config.write_text(json.dumps(_venue(detector={
        "engine": "onnx", "model": str(tmp_path / "missing.onnx"),
        "classes": ["person"],
    })), encoding="utf-8")

    report = acceptance.collect_preflight(
        config, current_platform="win32", find_spec=_all_dependencies,
        ffmpeg_path="ffmpeg.exe")

    assert report["summary"]["launch_ready"] is False
    failed = {item["name"] for item in report["checks"]
              if item["blocking"] and not item["passed"]}
    assert "per_user_config" in failed
    assert "camera:front-door:model" in failed


def test_preflight_blocks_non_windows_missing_dependencies_and_bad_config(
        tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    config = tmp_path / "semantic-camera" / "cameras.json"
    config.parent.mkdir()
    config.write_text("{}", encoding="utf-8")

    report = acceptance.collect_preflight(
        config, current_platform="linux", find_spec=lambda name: None,
        ffmpeg_path="")

    assert report["summary"]["launch_ready"] is False
    failed = {item["name"] for item in report["checks"]
              if not item["passed"]}
    assert {"native_windows", "config_valid", "ffmpeg"} <= failed
    assert "dependency:onnxruntime" in failed


def test_report_write_is_atomic_and_cli_returns_gate_status(
        tmp_path, monkeypatch):
    report_path = tmp_path / "evidence" / "preflight.json"
    report = {"summary": {"launch_ready": True, "monitor_only": False}}
    acceptance.write_report(report_path, report)
    assert json.loads(report_path.read_text(encoding="utf-8")) == report
    assert not Path(str(report_path) + ".tmp").exists()

    monkeypatch.setattr(
        acceptance, "collect_preflight",
        lambda path: {
            "summary": {"launch_ready": False, "monitor_only": False}})
    monkeypatch.setattr(acceptance, "write_report", lambda path, value: None)
    assert acceptance.main([
        "--config", str(tmp_path / "missing.json"),
        "--report", str(report_path),
    ]) == 1
