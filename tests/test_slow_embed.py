"""LZ-049 V-JEPA 嵌入接线测试：段代表帧→嵌入→联合匹配，缺席诚实降级。"""

import json
import os
import time

import pytest

import scam.db as db
from scam.config import validate_venue
from scam.embed import FakeEmbedder
from scam.slow_core import SlowCore
from scam.slow_worker import SlowWorker


def _conn(tmp_path):
    conn = db.connect(str(tmp_path / "e.db"))
    db.init_schema(conn)
    return conn


def _seed_segment_with_best_frame(tmp_path, conn, *, rid="rev-1",
                                  camera="front", t0=1000.0, t1=1120.0,
                                  with_frame=True, frame_bytes=None):
    """闭合段 + 段内对象 + 对象的 clean_best_frame 证据（真实 JPEG 文件）。"""
    db.open_review_segment(conn, review_id=rid, camera=camera, t_start=t0)
    db.close_review_segment(conn, rid, t_end=t1, reason="quiet")
    oid = f"{rid}:obj"
    db.open_tracked_object(conn, object_id=oid, camera=camera,
                           t_start=t0 + 10, cls="person", zones=["z1"])
    db.close_tracked_object(conn, oid, t_end=t1 - 10, reason="gone")
    if with_frame:
        import cv2
        import numpy as np
        frame = np.zeros((64, 64, 3), dtype=np.uint8)
        frame[:, :, 1] = 128
        ok, encoded = cv2.imencode(".jpg", frame)
        assert ok
        content = frame_bytes if frame_bytes is not None \
            else encoded.tobytes()
        rel = f"front/{rid}.jpg"
        evidence_dir = tmp_path / "evidence" / "front"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (tmp_path / "evidence" / rel).write_bytes(content)
        conn.execute(
            "INSERT INTO evidence_assets"
            " (asset_id,owner_type,owner_id,camera,kind,path,state,mime,"
            "  t_start,t_end,score,size_bytes,sha256,created_at,updated_at,"
            "  metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"best:{rid}", "tracked_object", oid, camera,
             "clean_best_frame", rel, "available", "image/jpeg",
             t0 + 50, None, 1.0, len(content), "0" * 64, t0, t0, "{}"))
    conn.commit()


def _wait_until(predicate, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return False


# ---------- 1. 注入 embedder：帧→嵌入→联合匹配，档案带嵌入 ----------

def test_embedder_feeds_joint_matching(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment_with_best_frame(tmp_path, conn, rid="rev-a")
    conn.close()
    db_path = str(tmp_path / "e.db")

    embedder = FakeEmbedder(dim=8)
    worker = SlowWorker(db_path, ["front"], interval_s=0.5,
                        embedder=embedder)
    worker.start()
    try:
        assert _wait_until(lambda: worker.totals["processed"] >= 1)
        snap = worker.snapshot()
        assert snap["embedding"] == "on"
    finally:
        assert worker.stop(timeout=5.0)

    check = db.connect(db_path)
    rows = check.execute(
        "SELECT pattern_id FROM pattern_embeddings").fetchall()
    assert rows, "嵌入必须随模式入档（pattern_embeddings 有质心）"
    check.close()


# ---------- 2. 无 embedder：诚实披露 structural_only ----------

def test_no_embedder_discloses_structural_only(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment_with_best_frame(tmp_path, conn, rid="rev-b")
    conn.close()

    worker = SlowWorker(str(tmp_path / "e.db"), ["front"], interval_s=0.5)
    worker.start()
    try:
        assert _wait_until(lambda: worker.totals["processed"] >= 1)
        assert worker.snapshot()["embedding"] == "structural_only"
    finally:
        assert worker.stop(timeout=5.0)


# ---------- 3. 无帧证据：降级纯结构，处理不失败 ----------

def test_missing_frame_degrades_to_structural(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment_with_best_frame(tmp_path, conn, rid="rev-c",
                                  with_frame=False)
    conn.close()

    embedder = FakeEmbedder(dim=8)
    worker = SlowWorker(str(tmp_path / "e.db"), ["front"], interval_s=0.5,
                        embedder=embedder)
    worker.start()
    try:
        assert _wait_until(lambda: worker.totals["processed"] >= 1), \
            "无帧证据的段仍必须被处理（纯结构），不得失败"
        assert worker.totals["failed"] == 0
    finally:
        assert worker.stop(timeout=5.0)


# ---------- 4. 帧损坏：解码失败降级纯结构 ----------

def test_corrupt_frame_degrades_to_structural(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment_with_best_frame(tmp_path, conn, rid="rev-d",
                                  frame_bytes=b"\x00not-a-jpeg")
    conn.close()

    core = SlowCore(conn := db.connect(str(tmp_path / "e.db")),
                    camera="front")
    frame = core.frame_for({"t_start": 1000.0, "t_end": 1120.0})
    assert frame is None, "损坏 JPEG 必须解码失败返回 None"
    conn.close()


# ---------- 5. 证据路径围栏：越界路径拒绝 ----------

def test_frame_for_rejects_escape_path(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment_with_best_frame(tmp_path, conn, rid="rev-e",
                                  with_frame=False)
    oid = "rev-e:obj"
    conn.execute(
        "INSERT INTO evidence_assets"
        " (asset_id,owner_type,owner_id,camera,kind,path,state,mime,"
        "  t_start,t_end,score,size_bytes,sha256,created_at,updated_at,"
        "  metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("best:evil", "tracked_object", oid, "front",
         "clean_best_frame", "../../escape.jpg", "available",
         "image/jpeg", 1050.0, None, 1.0, 10, "0" * 64,
         1000.0, 1000.0, "{}"))
    conn.commit()

    core = SlowCore(conn, camera="front")
    frame = core.frame_for({"t_start": 1000.0, "t_end": 1120.0})
    assert frame is None, "证据路径越出根目录必须拒绝"
    conn.close()


# ---------- 6. config 校验 ----------

def test_config_slow_embed_model_validation():
    base = {"version": "0.3", "cameras": [{
        "id": "c1", "source": "rtsp://u:p@x/1",
        "detector": {"engine": "none"}, "zones": [],
        "schedule": [{"from": "00:00", "to": "23:59"}]}]}
    assert validate_venue(base) == []                     # 缺省合法
    base["cameras"][0]["slow_embed_model"] = "models/jepa.onnx"
    assert validate_venue(base) == []                     # 字符串合法
    base["cameras"][0]["slow_embed_model"] = 123
    errs = validate_venue(base)
    assert any("slow_embed_model" in e for e in errs)
