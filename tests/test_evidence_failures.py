"""R2 证据失败门禁：失败必须诚实、可清理，且不能阻断告警事实。"""

import os

import cv2
import numpy as np
import pytest

from scam.db import connect, init_schema, open_tracked_object
from scam.evidence import EvidenceStore
from scam.monitor import Monitor, to_gray
from scam.sinks import SqliteSink


def _frame(value=80):
    return np.full((54, 96, 3), value, dtype=np.uint8)


def _store_with_object(tmp_path):
    conn = connect(str(tmp_path / "evidence.db"))
    init_schema(conn)
    open_tracked_object(
        conn, object_id="obj-1", camera="front", t_start=1.0, cls="person")
    return conn, EvidenceStore(str(tmp_path / "evidence"))


def test_jpeg_encode_failure_creates_no_asset(monkeypatch, tmp_path):
    conn, store = _store_with_object(tmp_path)
    monkeypatch.setattr(cv2, "imencode", lambda *_a, **_k: (False, None))

    with pytest.raises(RuntimeError, match="编码失败"):
        store.save_best_frame(
            conn, object_id="obj-1", camera="front", frame_bgr=_frame(),
            t_source=2.0, conf=0.9, bbox=[0.1, 0.1, 0.2, 0.3])

    assert conn.execute(
        "SELECT COUNT(*) FROM evidence_assets").fetchone()[0] == 0
    assert conn.execute(
        "SELECT best_frame_path FROM tracked_objects"
        " WHERE object_id='obj-1'").fetchone()[0] is None


def test_atomic_replace_failure_removes_temp_and_creates_no_asset(
        monkeypatch, tmp_path):
    conn, store = _store_with_object(tmp_path)

    def fail_replace(_source, _target):
        raise PermissionError("disk denied")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(PermissionError, match="disk denied"):
        store.save_best_frame(
            conn, object_id="obj-1", camera="front", frame_bgr=_frame(),
            t_source=2.0, conf=0.9, bbox=[0.1, 0.1, 0.2, 0.3])

    assert conn.execute(
        "SELECT COUNT(*) FROM evidence_assets").fetchone()[0] == 0
    evidence_root = tmp_path / "evidence"
    leftovers = list(evidence_root.rglob("*")) if evidence_root.exists() else []
    assert not [path for path in leftovers if path.is_file()]


def test_best_frame_failure_does_not_block_semantic_alarm(monkeypatch, tmp_path):
    db_path = str(tmp_path / "runtime.db")
    sink = SqliteSink(db_path)

    def fail_evidence(**_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(sink.evidence, "save_best_frame", fail_evidence)
    cfg = {
        "id": "front", "grid": {"rows": 18, "cols": 22},
        "zones": [{"id": "z1", "cells": [209],
                   "rules": [{"cls": "person", "template": "immediate"}]}],
    }

    def detect(_image):
        return [{"cls": "person", "conf": 0.9,
                 "bbox": [0.45, 0.45, 0.1, 0.2], "cx": 0.5, "cy": 0.55}]

    monitor = Monitor(cfg, detect_fn=detect, sinks=[sink], run_id="fault")
    monitor.MOTION_DET_INTERVAL = 1
    monitor.PATROL_INTERVAL = 1
    image = np.zeros((360, 640, 3), dtype=np.uint8)
    gray = to_gray(image, monitor.GRAY_W)
    monitor.step(image, gray, 0)
    alarms = monitor.step(image, gray, 100)

    conn = connect(db_path)
    event = conn.execute("SELECT * FROM semantic_events").fetchone()
    conn.close()
    assert len(alarms) == 1
    assert event is not None
    assert event["evidence_state"] == "metadata_only"
    assert event["best_frame_path"] is None
    assert monitor.stats()["sink_failures"] >= 1
