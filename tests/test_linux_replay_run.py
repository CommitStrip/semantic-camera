"""LC-022/025 单视频确定性 replay 执行器测试（M-R2 fail-closed）。

注入 capture/detector 的合成接线测试：manifest 先验、绑定、EOF 判定
（有限正总帧数）、发布原子 no-clobber、输入身份快照与内容复核、失败
无正式库。合成接线证据，不代表真实 Linux、真实媒体或模型质量。
"""

import errno
import json
import os
import sqlite3
from pathlib import Path

import numpy as np
import pytest

import scam.linux_replay_compare as compare_mod
import scam.linux_replay_export as export_mod
import scam.linux_replay_manifest as manifest_mod
import scam.linux_replay_run as run_mod
from scam.linux_replay_run import main, run_replay


class _FakeCapture:
    """注入式捕获：状态协议 (frame/eof/error, frame)；可编程错误与副作用。"""

    def __init__(self, frames, fps=25.0, frame_count=None, error_at=None,
                 on_read=None, premature_eof=False, overread=False):
        self._frames = list(frames)
        self._fps = fps
        self._count = frame_count
        self._error_at = error_at
        self._on_read = on_read
        self._premature_eof = premature_eof
        self._overread = overread
        self._reads = 0
        self._premature_len = len(frames)
        self.released = False

    def get_fps(self):
        return self._fps

    def get_frame_count(self):
        if self._count is not None:
            return self._count
        return float(len(self._frames))

    def read_frame(self, frames_read):
        self._reads += 1
        if self._on_read is not None:
            self._on_read(self._reads)
        if self._error_at is not None and self._reads >= self._error_at:
            return "error", None
        if self._premature_eof and frames_read > self._premature_len:
            return "eof", None  # 提前 EOF：总帧数尚未读满
        if self._frames:
            return "frame", self._frames.pop(0)
        if self._overread:
            return "frame", _frame()  # 超出总帧数仍供帧：fail-closed
        return "eof", None

    def release(self):
        self.released = True


def _frames(count=12):
    return [np.full((32, 32, 3), (i * 37) % 255, dtype=np.uint8)
            for i in range(count)]


class _FakeDetector:
    def detect(self, frame):
        return [{"cls": "person", "conf": 0.9,
                 "bbox": [0.4, 0.4, 0.2, 0.2]}]


def _make_bundle(tmp_path, *, camera_id="probe", enabled=True):
    video = tmp_path / "clip.mp4"
    video.write_bytes(b"\x00\x01fake-video")
    model = tmp_path / "person.onnx"
    model.write_bytes(b"weights")
    cfg = {
        "version": "0.3",
        "venue": "replay-lab",
        "cameras": [{
            "id": camera_id,
            "enabled": enabled,
            "source": "rtsp://host/stream",
            "detector": {"engine": "onnx", "model": str(model),
                         "classes": ["person"], "conf": 0.4},
            "grid": {"rows": 4, "cols": 4},
            "zones": [{"id": "yard", "cells": list(range(16)),
                       "rules": [{"cls": "person",
                                  "template": "immediate"}]}],
            "schedule": [{"from": "00:00", "to": "23:59"}],
        }],
    }
    config = tmp_path / "cameras.json"
    config.write_bytes(json.dumps(cfg, ensure_ascii=False).encode("utf-8"))
    manifest, errors = manifest_mod.build_manifest(
        str(video), str(config), str(model), "sw-1")
    assert errors == []
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8") + b"\n")
    return str(video), str(config), str(model), str(manifest_path), cfg


def _capture_factory(frames, fps=25.0, **kwargs):
    def _factory(path):
        return _FakeCapture(frames, fps, **kwargs)
    return _factory


def _detector_factory():
    def _factory(det_cfg):
        return _FakeDetector()
    return _factory


# ---------- 1. 成功路径：接线 + EOF 保守闭合 + M→L→K 链路 ----------

def test_successful_run_persists_closed_events_and_feeds_l_and_k(tmp_path):
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    output_db = str(tmp_path / "replay-out.db")

    result, errors = run_replay(
        manifest_path, video, config, model, "probe", output_db,
        capture_factory=_capture_factory(_frames(12)),
        detector_factory=_detector_factory())

    assert errors == []
    assert result["replay_executed"] is True
    assert result["frames"] == 12
    assert result["duration_s"] == pytest.approx(0.48)
    assert result["quality_gate_passed"] is None
    assert result["release_gate_passed"] is None
    assert Path(output_db).is_file()
    assert not (tmp_path / "evidence").exists()

    # EOF 保守闭合：数据库内不再有开放行
    connection = sqlite3.connect(output_db)
    open_reviews = connection.execute(
        "SELECT COUNT(*) FROM review_segments WHERE t_end IS NULL"
    ).fetchone()[0]
    open_events = connection.execute(
        "SELECT COUNT(*) FROM semantic_events WHERE t_end IS NULL"
    ).fetchone()[0]
    open_objects = connection.execute(
        "SELECT COUNT(*) FROM tracked_objects WHERE t_end IS NULL"
    ).fetchone()[0]
    connection.close()
    assert (open_reviews, open_events, open_objects) == (0, 0, 0)

    # M→L：队列 L 导出器可直接读取产物（根数组）
    export, export_errors = export_mod.export_events(output_db)
    assert export_errors == []
    assert len(export) == 1
    # L→K：导出事实与确定性预期完全一致
    expected = [{"camera": "probe", "template": "immediate",
                 "zone_id": "yard", "cls": "person", "state": "closed",
                 "t_start": 0.4, "t_end": 0.48, "end_reason": "replay_eof"}]
    outcome, compare_errors = compare_mod.compare_event_lists(
        expected, export)
    assert compare_errors == []
    assert outcome["match"] is True


# ---------- 2. manifest 先验：不一致时在任何输出前拒绝 ----------

def test_manifest_mismatch_rejects_before_any_output(tmp_path):
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    Path(video).write_bytes(b"tampered-after-manifest")
    output_db = str(tmp_path / "out.db")

    def _forbidden(path):
        raise AssertionError("manifest 未过验不得打开视频")

    result, errors = run_replay(
        manifest_path, video, config, model, "probe", output_db,
        capture_factory=_forbidden)

    assert result["replay_executed"] is False
    assert not Path(output_db).exists()


# ---------- 3. 配置/相机/模型绑定失败 ----------

def test_binding_failures_reject_without_output(tmp_path):
    video, config, model, manifest_path, cfg = _make_bundle(tmp_path)

    # 相机不存在
    result, errors = run_replay(
        manifest_path, video, config, model, "ghost",
        str(tmp_path / "a.db"), capture_factory=_capture_factory(_frames()))
    assert result["replay_executed"] is False
    assert any("恰好出现一次" in err for err in errors)

    # 相机未启用（manifest 按启用前配置构建以通过先验，从而测到绑定层）
    cfg2 = json.loads(Path(config).read_text(encoding="utf-8"))
    cfg2["cameras"][0]["enabled"] = False
    disabled_config = tmp_path / "disabled.json"
    disabled_config.write_text(json.dumps(cfg2, ensure_ascii=False),
                               encoding="utf-8")
    m2, _ = manifest_mod.build_manifest(video, str(disabled_config), model,
                                        "sw-1")
    m2_path = tmp_path / "m2.json"
    m2_path.write_bytes(
        json.dumps(m2, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8"))
    result, errors = run_replay(
        m2_path, video, str(disabled_config), model, "probe",
        str(tmp_path / "b.db"), capture_factory=_capture_factory(_frames()))
    assert result["replay_executed"] is False
    assert any("未启用" in err for err in errors)

    # 检测器引擎非 onnx
    cfg3 = json.loads(Path(config).read_text(encoding="utf-8"))
    cfg3["cameras"][0]["detector"]["engine"] = "none"
    bad_engine = tmp_path / "engine.json"
    bad_engine.write_text(json.dumps(cfg3, ensure_ascii=False),
                          encoding="utf-8")
    m3, _ = manifest_mod.build_manifest(video, str(bad_engine), model, "sw-1")
    m3_path = tmp_path / "m3.json"
    m3_path.write_bytes(
        json.dumps(m3, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8"))
    result, errors = run_replay(
        m3_path, video, str(bad_engine), model, "probe",
        str(tmp_path / "c.db"), capture_factory=_capture_factory(_frames()))
    assert result["replay_executed"] is False
    assert any("onnx" in err for err in errors)

    # 相对模型路径以 config 目录解析：指向不同文件时绑定层拦截
    other = tmp_path / "other.onnx"
    other.write_bytes(b"other")
    cfg4 = json.loads(Path(config).read_text(encoding="utf-8"))
    cfg4["cameras"][0]["detector"]["model"] = "other.onnx"
    rel_config = tmp_path / "rel.json"
    rel_config.write_text(json.dumps(cfg4, ensure_ascii=False),
                          encoding="utf-8")
    m4, _ = manifest_mod.build_manifest(video, str(rel_config), str(other),
                                        "sw-1")
    m4_path = tmp_path / "m4.json"
    m4_path.write_bytes(
        json.dumps(m4, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8"))
    result, errors = run_replay(
        m4_path, video, str(rel_config), str(other), "probe",
        str(tmp_path / "e.db"), capture_factory=_capture_factory(_frames(3)),
        detector_factory=_detector_factory())
    assert result["replay_executed"] is True  # 解析走 config 目录而非 cwd

    # 反向：同名相对名解析后与 --model 不同 → 绑定层拦截
    m5, _ = manifest_mod.build_manifest(video, str(rel_config), model,
                                        "sw-1")
    m5_path = tmp_path / "m5.json"
    m5_path.write_bytes(
        json.dumps(m5, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8"))
    result, errors = run_replay(
        m5_path, video, str(rel_config), model, "probe",
        str(tmp_path / "f.db"), capture_factory=_capture_factory(_frames()))
    assert result["replay_executed"] is False
    assert any("--model 不一致" in err for err in errors)

    for leftover in ("a.db", "b.db", "c.db", "f.db"):
        assert not (tmp_path / leftover).exists()


# ---------- 4. 输出不覆盖 + FPS/总帧数/提前终止/零帧 fail-closed ----------

def test_output_db_must_not_exist(tmp_path):
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    output_db = tmp_path / "out.db"
    output_db.write_bytes(b"existing")

    result, errors = run_replay(
        manifest_path, video, config, model, "probe", str(output_db),
        capture_factory=_capture_factory(_frames()))

    assert result["replay_executed"] is False
    assert any("拒绝覆盖" in err for err in errors)


def test_bad_fps_fails_closed(tmp_path):
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    result, errors = run_replay(
        manifest_path, video, config, model, "probe",
        str(tmp_path / "out.db"),
        capture_factory=_capture_factory(_frames(), fps=0.0))
    assert result["replay_executed"] is False
    assert any("FPS" in err for err in errors)


def test_frame_count_unavailable_fails_closed(tmp_path):
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    result, errors = run_replay(
        manifest_path, video, config, model, "probe",
        str(tmp_path / "out.db"),
        capture_factory=_capture_factory(_frames(3),
                                         frame_count=float("nan")))
    assert result["replay_executed"] is False
    assert any("总帧数不可用" in err for err in errors)


def test_non_integer_frame_count_fails_closed(tmp_path):
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    result, errors = run_replay(
        manifest_path, video, config, model, "probe",
        str(tmp_path / "out.db"),
        capture_factory=_capture_factory(_frames(3), frame_count=3.5))
    assert result["replay_executed"] is False
    assert any("非整数" in err for err in errors)


def test_premature_termination_rejected(tmp_path):
    # 3 帧后报告 EOF，但总帧数为 8：提前终止≠成功 EOF
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    result, errors = run_replay(
        manifest_path, video, config, model, "probe",
        str(tmp_path / "out.db"),
        capture_factory=_capture_factory(_frames(3), frame_count=8.0,
                                         premature_eof=True),
        detector_factory=_detector_factory())
    assert result["replay_executed"] is False
    assert any("提前终止 3/8" in err for err in errors)


def test_overread_rejected(tmp_path):
    # 总帧数 3 却持续给出新帧：fail-closed
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    result, errors = run_replay(
        manifest_path, video, config, model, "probe",
        str(tmp_path / "out.db"),
        capture_factory=_capture_factory(_frames(5), frame_count=3.0,
                                         overread=True),
        detector_factory=_detector_factory())
    assert result["replay_executed"] is False
    assert any("超出总帧数" in err for err in errors)


def test_zero_frames_rejected(tmp_path):
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    result, errors = run_replay(
        manifest_path, video, config, model, "probe",
        str(tmp_path / "out.db"),
        capture_factory=_capture_factory([], fps=25.0),
        detector_factory=_detector_factory())
    assert result["replay_executed"] is False
    assert any("总帧数不可用" in err for err in errors)


# ---------- 5. 中途解码错误 / 覆盖 / 输入变更 fail-closed ----------

def test_mid_stream_decode_error_rejected(tmp_path):
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    result, errors = run_replay(
        manifest_path, video, config, model, "probe",
        str(tmp_path / "out.db"),
        capture_factory=_capture_factory(_frames(8), error_at=3),
        detector_factory=_detector_factory())
    assert result["replay_executed"] is False
    assert any("中途解码失败" in err for err in errors)
    assert not Path(str(tmp_path / "out.db")).exists()


def test_publish_never_clobbers_concurrent_target(tmp_path):
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    output_db = tmp_path / "out.db"

    def _concurrent_write(read_no):
        if read_no == 8:  # 发布前一刻另一进程先占了目标路径
            output_db.write_bytes(b"concurrent-writer-data")

    result, errors = run_replay(
        manifest_path, video, config, model, "probe", str(output_db),
        capture_factory=_capture_factory(_frames(12),
                                         on_read=_concurrent_write),
        detector_factory=_detector_factory())

    assert result["replay_executed"] is False
    assert any("并发出现，拒绝覆盖" in err for err in errors)
    assert output_db.read_bytes() == b"concurrent-writer-data"  # 绝不覆盖


def test_link_unsupported_fails_closed(tmp_path, monkeypatch):
    def _unsupported(src, dst):
        raise OSError(errno.EOPNOTSUPP, "hard links unsupported")

    monkeypatch.setattr(os, "link", _unsupported)
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    output_db = tmp_path / "out.db"

    result, errors = run_replay(
        manifest_path, video, config, model, "probe", output_db,
        capture_factory=_capture_factory(_frames(3)),
        detector_factory=_detector_factory())

    assert result["replay_executed"] is False
    assert any("平台不支持原子 no-clobber" in err for err in errors)
    assert not output_db.exists()


def test_temp_unlink_failure_does_not_report_false_publish_failure(
        tmp_path, monkeypatch):
    original_unlink = os.unlink
    failed_once = False

    def _unlink(path, *args, **kwargs):
        nonlocal failed_once
        if ".replay-tmp-" in str(path) and not failed_once:
            failed_once = True
            raise PermissionError("transient cleanup failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", _unlink)
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    output_db = tmp_path / "out.db"
    result, errors = run_replay(
        manifest_path, video, config, model, "probe", output_db,
        capture_factory=_capture_factory(_frames(3)),
        detector_factory=_detector_factory())

    assert errors == []
    assert result["replay_executed"] is True
    assert output_db.is_file()
    assert not list(tmp_path.glob("*.replay-tmp-*"))


# ---------- 6. 输入身份快照：换入/换出/还原全部拒绝 ----------

def test_config_swap_in_rejected_by_identity_snapshot(tmp_path):
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    original = Path(config).read_bytes()

    def _swap_config(read_no):
        if read_no == 2:  # 换入另一份合法配置（新 inode，内容也合法）
            swapped = json.loads(original.decode("utf-8"))
            swapped["venue"] = "swapped"
            Path(config).write_bytes(
                json.dumps(swapped, ensure_ascii=False).encode("utf-8"))

    result, errors = run_replay(
        manifest_path, video, config, model, "probe",
        str(tmp_path / "out.db"),
        capture_factory=_capture_factory(_frames(6), on_read=_swap_config),
        detector_factory=_detector_factory())

    assert result["replay_executed"] is False
    assert any("身份" in err and ("config" in err or "inputs" in err)
                   for err in errors)


def test_config_swap_restore_still_rejected(tmp_path):
    # C-031 场景：换入后还原内容与 mtime——inode 变化仍被身份快照拒绝
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    original = Path(config).read_bytes()
    before = os.stat(config)

    def _swap_and_restore(read_no):
        if read_no == 2:
            Path(config).write_bytes(b'{"hacked": true}')
        if read_no == 5:  # 还原内容与 mtime，但 inode 已是新的
            Path(config).write_bytes(original)
            os.utime(config, ns=(before.st_atime_ns, before.st_mtime_ns))

    result, errors = run_replay(
        manifest_path, video, config, model, "probe",
        str(tmp_path / "out.db"),
        capture_factory=_capture_factory(_frames(8),
                                         on_read=_swap_and_restore),
        detector_factory=_detector_factory())

    assert result["replay_executed"] is False
    assert any("身份" in err and ("config" in err or "inputs" in err)
                   for err in errors)


def test_manifest_verify_to_open_swap_is_rejected(tmp_path, monkeypatch):
    """验证返回后、受控fd打开前的换入也不能成为实际运行输入。"""
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    real_verify = manifest_mod.verify_manifest_against_inputs

    def _verify_then_swap(*args, **kwargs):
        outcome = real_verify(*args, **kwargs)
        changed = json.loads(Path(config).read_text(encoding="utf-8"))
        changed["venue"] = "swapped-after-verify"
        Path(config).write_text(json.dumps(changed), encoding="utf-8")
        return outcome

    monkeypatch.setattr(run_mod, "verify_manifest_against_inputs",
                        _verify_then_swap)
    result, errors = run_replay(
        manifest_path, video, config, model, "probe",
        str(tmp_path / "out.db"),
        capture_factory=lambda path: pytest.fail("不得进入capture"))

    assert result["replay_executed"] is False
    assert any("manifest 复核后输入发生变化" in err for err in errors)
    assert not (tmp_path / "out.db").exists()


def test_default_detector_consumes_verified_model_bytes_and_resolved_path(
        tmp_path, monkeypatch):
    video, config, model, manifest_path, cfg = _make_bundle(tmp_path)
    cfg["cameras"][0]["detector"]["model"] = Path(model).name
    Path(config).write_text(json.dumps(cfg), encoding="utf-8")
    manifest, manifest_errors = manifest_mod.build_manifest(
        video, config, model, "sw-1")
    assert manifest_errors == []
    Path(manifest_path).write_text(json.dumps(manifest), encoding="utf-8")
    observed = {}

    def _verified_factory(det_cfg, model_bytes):
        observed["path"] = det_cfg["model"]
        observed["bytes"] = model_bytes
        return _FakeDetector()

    monkeypatch.setattr(run_mod, "_default_detector_factory",
                        _verified_factory)
    result, errors = run_replay(
        manifest_path, video, config, model, "probe",
        str(tmp_path / "out.db"),
        capture_factory=_capture_factory(_frames(3)))

    assert errors == []
    assert result["replay_executed"] is True
    assert observed["path"] == os.path.abspath(model)
    assert observed["bytes"] == Path(model).read_bytes()


# ---------- 7. CLI 诚实字段（生产路径真实 OpenCV，失败如实非零） ----------

def test_cli_reports_failure_honestly(tmp_path):
    video, config, model, manifest_path, _ = _make_bundle(tmp_path)
    output_db = str(tmp_path / "out.db")
    code = main(["--manifest", manifest_path, "--video", video,
                 "--config", config, "--model", model,
                 "--camera-id", "probe", "--output-db", output_db])
    assert code == 1
    assert not Path(output_db).exists()
