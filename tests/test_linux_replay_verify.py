"""LC-028 一键 replay 事实判定器测试：M→L→K 顺序组合的注入式合成接线。

覆盖成功链路、预期不匹配非零且 DB 保留、M 失败短路、预期文件安全读取、
导出失败阶段语义、重复事件多重集、三诚实字段、生产 CLI 未注入 fake。
失败按 LC-034 原样暴露（无重试掩盖）。合成接线证据，不代表真实 Linux、
真实视频/ONNX、模型质量或发布门禁通过。
"""

import errno
import json
import os
import sqlite3
from pathlib import Path

import numpy as np
import pytest

import scam.linux_replay_verify as verify_mod
from scam.linux_replay_manifest import build_manifest
from scam.linux_replay_verify import SCHEMA, main, run_verify


class _FakeCapture:
    def __init__(self, frames, fps=25.0):
        self._frames = list(frames)
        self._fps = fps
        self.released = False

    def get_fps(self):
        return self._fps

    def get_frame_count(self):
        return float(len(self._frames))

    def read_frame(self, frames_read):
        if self._frames:
            return "frame", self._frames.pop(0)
        return "eof", None

    def release(self):
        self.released = True


class _FakeDetector:
    def detect(self, frame):
        return [{"cls": "person", "conf": 0.9,
                 "bbox": [0.4, 0.4, 0.2, 0.2]}]


def _capture_factory(frames, fps=25.0):
    def _factory(path):
        return _FakeCapture(frames, fps)
    return _factory


def _detector_factory():
    def _factory(det_cfg):
        return _FakeDetector()
    return _factory


def _frames(count=12):
    return [np.full((32, 32, 3), (i * 37) % 255, dtype=np.uint8)
            for i in range(count)]


def _make_bundle(tmp_path, *, camera_id="probe"):
    video = tmp_path / "clip.mp4"
    video.write_bytes(b"\x00\x01fake-video")
    model = tmp_path / "person.onnx"
    model.write_bytes(b"weights")
    cfg = {
        "version": "0.3",
        "venue": "replay-lab",
        "cameras": [{
            "id": camera_id,
            "enabled": True,
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
    manifest, errors = build_manifest(str(video), str(config), str(model),
                                      "sw-1")
    assert errors == []
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8") + b"\n")
    # 返回顺序与 run_verify 形参一致：manifest, video, config, model
    return str(manifest_path), str(video), str(config), str(model)


EXPECTED_FACT = [{"camera": "probe", "template": "immediate",
                  "zone_id": "yard", "cls": "person", "state": "closed",
                  "t_start": 0.4, "t_end": 0.48, "end_reason": "replay_eof"}]


def _expected_file(tmp_path, events, name="expected.json"):
    target = Path(tmp_path) / name
    target.write_bytes(json.dumps(events, ensure_ascii=False).encode("utf-8"))
    return str(target)


def _facts_from_db(output_db):
    connection = sqlite3.connect(output_db)
    try:
        rows = connection.execute(
            "SELECT camera, template, zone_id, cls, state, t_start, "
            "t_end, end_reason FROM semantic_events").fetchall()
    finally:
        connection.close()
    return [dict(zip(("camera", "template", "zone_id", "cls", "state",
                      "t_start", "t_end", "end_reason"), row))
            for row in rows]


def _run_verify(tmp_path, *, expected=None, **kwargs):
    # 单次执行，失败原样暴露（LC-034：不得用重试掩盖确定性缺陷）
    manifest_path, video, config, model = _make_bundle(tmp_path)
    output_db = str(tmp_path / "replay-out.db")
    if expected is None:
        expected = _expected_file(tmp_path, EXPECTED_FACT)
    result, errors = run_verify(manifest_path, video, config, model,
                                "probe", expected, output_db,
                                capture_factory=kwargs.pop(
                                    "capture_factory",
                                    _capture_factory(_frames(12))),
                                detector_factory=kwargs.pop(
                                    "detector_factory",
                                    _detector_factory()),
                                **kwargs)
    return result, errors, output_db, (manifest_path, video, config, model)


# ---------- 1. 成功链路：M→L→K 全 ok，比较匹配 ----------

def test_successful_chain_runs_all_three_stages(tmp_path):
    result, errors, output_db, _ = _run_verify(tmp_path)

    assert errors == []
    assert result["stages"] == {"replay": "ok", "export": "ok",
                                "compare": "ok"}
    assert result["replay_executed"] is True
    assert result["comparison_match"] is True
    assert result["counts"] == {"matched": 1, "missing": 0, "unexpected": 0}
    assert result["expected_count"] == 1 and result["actual_count"] == 1
    # 三诚实字段：事实匹配绝不等于质量/发布通过
    assert result["quality_gate_passed"] is None
    assert result["release_gate_passed"] is None
    # 正式 replay 库作为证据保留
    assert Path(output_db).is_file()


def test_exported_facts_match_database_records(tmp_path):
    result, errors, output_db, _ = _run_verify(tmp_path)
    assert result["replay_executed"] is True

    facts = _facts_from_db(output_db)
    assert len(facts) == 1
    fact = facts[0]
    # 身份字段确定；EOF 保守闭合语义确定
    assert fact["camera"] == "probe"
    assert fact["template"] == "immediate"
    assert fact["zone_id"] == "yard" and fact["cls"] == "person"
    assert fact["state"] == "closed" and fact["end_reason"] == "replay_eof"
    assert 0 < fact["t_start"] <= fact["t_end"]


# ---------- 2. 预期不匹配：非零语义 + DB 保留 ----------

def test_expected_mismatch_reports_and_preserves_db(tmp_path):
    empty_file = _expected_file(tmp_path, [], name="empty-expected.json")
    result, errors, output_db, _ = _run_verify(
        tmp_path, expected=empty_file)  # 预期为空 → 实际事件即意外事件

    assert result["replay_executed"] is True  # replay 本身成功
    assert result["comparison_match"] is False
    # 非时间字段确定；时间字段漂移属 M 检测节奏，不在此绑死
    assert len(result["unexpected"]) == 1 and not result["missing"]
    unexpected = result["unexpected"][0]
    for field in ("camera", "template", "zone_id", "cls", "state",
                  "end_reason"):
        assert unexpected[field] == EXPECTED_FACT[0][field]
    assert result["counts"]["unexpected"] == 1
    assert Path(output_db).is_file()  # 证据库不因不匹配删除


def test_duplicate_expected_events_counted_as_multiset(tmp_path):
    # t_start=999 的事实实际事件永不产生：缺失按多重集计数
    sentinel = dict(EXPECTED_FACT[0], t_start=999.0)
    doubled = _expected_file(tmp_path, [sentinel, sentinel],
                             name="doubled.json")
    result, errors, _, _ = _run_verify(tmp_path, expected=doubled)

    assert result["replay_executed"] is True
    assert result["comparison_match"] is False
    assert result["missing"] == [sentinel, sentinel]
    assert result["counts"] == {"matched": 0, "missing": 2, "unexpected": 1}


# ---------- 3. M 失败短路：不继续 L/K ----------

def test_m_failure_short_circuits_remaining_stages(tmp_path):
    # 按真实顺序解包：_make_bundle 返回 (manifest, video, config, model)
    manifest_path, video, config, model = _make_bundle(tmp_path)
    Path(video).write_bytes(b"tampered-after-manifest")  # 篡改视频而非清单
    expected = _expected_file(tmp_path, EXPECTED_FACT)
    output_db = str(tmp_path / "out.db")

    def _forbidden(path):
        raise AssertionError("M 失败后不得继续导出/比较")

    result, errors = run_verify(
        manifest_path, video, config, model, "probe", expected, output_db,
        capture_factory=_forbidden)

    assert result["replay_executed"] is False
    assert result["stages"]["replay"] == "failed"
    assert result["stages"]["export"] == "skipped"
    assert result["stages"]["compare"] == "skipped"
    assert result["comparison_match"] is None
    # 错误原因须来自 manifest 与当前输入不一致
    assert any("不一致" in err for err in errors)
    assert not Path(output_db).exists()


# ---------- 4. 预期文件安全读取 ----------

def test_expected_file_missing_rejected(tmp_path):
    _make_bundle(tmp_path)
    result, errors, output_db, _ = _run_verify(
        tmp_path, expected=str(tmp_path / "gone.json"))

    assert result["replay_executed"] is False
    assert "expected: missing" in errors
    assert not Path(output_db).exists()


def test_expected_file_directory_rejected(tmp_path):
    _make_bundle(tmp_path)
    (tmp_path / "as-dir.json").mkdir()
    result, errors, _, _ = _run_verify(
        tmp_path, expected=str(tmp_path / "as-dir.json"))
    assert result["replay_executed"] is False
    assert any("not a regular file" in err for err in errors)


def test_expected_file_root_object_rejected(tmp_path):
    result, errors, output_db, _ = _run_verify(
        tmp_path, expected=_expected_file(tmp_path, {"events": []},
                                          name="obj.json"))
    assert result["replay_executed"] is False
    assert any("root must be a JSON array" in err for err in errors)
    assert not Path(output_db).exists()


# ---------- LC-029：lstat→open 换入与读后消失/替换的真实 TOCTOU 回归 ----------

def test_expected_swap_in_between_lstat_and_open_rejected(
        tmp_path, monkeypatch):
    manifest_path, video, config, model = _make_bundle(tmp_path)
    good = tmp_path / "expected.json"
    good.write_bytes(json.dumps(EXPECTED_FACT).encode("utf-8"))
    stale = os.lstat(str(good))  # 换入前的身份快照
    hacked = tmp_path / "hacked.json"
    hacked.write_bytes(json.dumps([{"hacked": True}]).encode("utf-8"))
    os.replace(hacked, good)  # open 前换入：路径已是另一 inode
    expected = str(good)
    output_db = str(tmp_path / "out.db")
    real_lstat = verify_mod._lstat_now

    def _lstat_returning_stale_identity(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if str(path) == str(good):
            return stale  # 确定性模拟：lstat 仍返回换入前身份
        return info

    monkeypatch.setattr(verify_mod, "_lstat_now",
                        _lstat_returning_stale_identity)

    result, errors = run_verify(
        manifest_path, video, config, model, "probe", expected, output_db,
        capture_factory=_capture_factory(_frames(3)),
        detector_factory=_detector_factory())

    assert result["replay_executed"] is False
    assert result["stages"]["replay"] == "skipped"
    assert any("identity changed between check and open" in err
               for err in errors)
    assert not Path(output_db).exists()


def test_expected_disappear_after_read_rejected(tmp_path, monkeypatch):
    # 读后路径身份复核时文件消失：第二次 lstat 抛 OSError（确定性模拟）
    good = tmp_path / "expected.json"
    good.write_bytes(json.dumps(EXPECTED_FACT).encode("utf-8"))
    real_lstat = verify_mod._lstat_now
    state = {"calls": 0}

    def _lstat_then_disappear(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        state["calls"] += 1
        if str(path) == str(good) and state["calls"] >= 2:
            os.unlink(good)
            raise OSError(errno.ENOENT, "gone")
        return info

    monkeypatch.setattr(verify_mod, "_lstat_now", _lstat_then_disappear)

    result, errors, _, _ = _run_verify(tmp_path, expected=str(good))

    assert result["replay_executed"] is False
    assert any("replaced while reading" in err for err in errors)


@pytest.mark.parametrize("failure_point", ["read", "post_read_fstat"])
def test_expected_fd_read_errors_are_structured(
        tmp_path, monkeypatch, failure_point):
    manifest_path, video, config, model = _make_bundle(tmp_path)
    expected = _expected_file(tmp_path, EXPECTED_FACT)
    output_db = str(tmp_path / "out.db")

    if failure_point == "read":
        def _read_failure(fd):
            raise OSError(errno.EIO, "injected read failure")

        monkeypatch.setattr(verify_mod, "_read_fd_all", _read_failure)
    else:
        real_fstat = os.fstat
        calls = {"count": 0}

        def _post_read_fstat_failure(fd):
            calls["count"] += 1
            if calls["count"] == 2:
                raise OSError(errno.EIO, "injected fstat failure")
            return real_fstat(fd)

        monkeypatch.setattr(verify_mod.os, "fstat",
                            _post_read_fstat_failure)

    result, errors = run_verify(
        manifest_path, video, config, model, "probe", expected, output_db,
        capture_factory=_capture_factory(_frames(3)),
        detector_factory=_detector_factory())

    assert result["replay_executed"] is False
    assert result["stages"]["replay"] == "skipped"
    assert any("expected: read failed (OSError" in err for err in errors)
    assert not Path(output_db).exists()


def test_expected_file_symlink_rejected(tmp_path):
    real = tmp_path / "real.json"
    real.write_bytes(b"[]")
    link = tmp_path / "link.json"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("当前环境不允许创建符号链接")
    result, errors, _, _ = _run_verify(tmp_path, expected=str(link))
    assert result["replay_executed"] is False
    assert any("symlink" in err for err in errors)


# ---------- 5. 导出失败：阶段语义诚实（replay 仍算已执行） ----------

def test_export_failure_stage_semantics(tmp_path, monkeypatch):
    def _boom(db_path):
        raise RuntimeError("export exploded")

    monkeypatch.setattr(verify_mod, "export_events", _boom)
    result, errors, output_db, _ = _run_verify(tmp_path)

    assert result["stages"]["replay"] == "ok"
    assert result["stages"]["export"] == "failed"
    assert result["stages"]["compare"] == "skipped"
    assert result["replay_executed"] is True  # replay 确实执行过
    assert result["comparison_match"] is None
    assert any("export exploded" in err for err in errors)
    # 正式 replay DB（证据）在导出失败后仍保留
    assert Path(output_db).is_file()


# ---------- 6. 重复预期事件按多重集计数 ----------

def test_duplicate_unexpected_events_counted(tmp_path):
    # 预期为空：实际事件全部记意外（本用例不依赖事件时间值）
    result, errors, _, _ = _run_verify(tmp_path,
                                       expected=_expected_file(tmp_path, []))
    assert result["replay_executed"] is True
    assert result["comparison_match"] is False
    assert result["counts"]["unexpected"] >= 1

# ---------- 7. 生产 CLI 未注入 fake：真实路径失败诚实非零 ----------

def test_production_cli_rejects_unknown_flag_and_reports_honestly(tmp_path):
    manifest_path, video, config, model = _make_bundle(tmp_path)
    expected = _expected_file(tmp_path, EXPECTED_FACT)
    output_db = str(tmp_path / "out.db")

    with pytest.raises(SystemExit) as excinfo:
        main(["--manifest", manifest_path, "--video", video,
              "--config", config, "--model", model,
              "--camera-id", "probe", "--expected", expected,
              "--output-db", output_db, "--capture-factory", "fake"])
    assert excinfo.value.code != 0  # CLI 无注入口：未知参数即非零

    code = main(["--manifest", manifest_path, "--video", video,
                 "--config", config, "--model", model,
                 "--camera-id", "probe", "--expected", expected,
                 "--output-db", output_db])
    assert code == 1  # 真实 OpenCV 打不开合成视频：如实失败非零
    assert not Path(output_db).exists()
