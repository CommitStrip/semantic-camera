"""最佳帧证据资产测试：干净原图、评分替换、索引与路径安全。"""

import hashlib
import os

import cv2
import numpy as np
import pytest

from scam.db import (close_semantic_event, connect, init_schema,
                     open_review_segment, open_semantic_event,
                     open_tracked_object)
from scam.evidence import EvidenceStore, best_frame_score


def _setup(tmp_path):
    conn = connect(str(tmp_path / "evidence.db"))
    init_schema(conn)
    open_tracked_object(
        conn, object_id="front:run:track:1", camera="前门:一号",
        t_start=1.0, cls="person")
    return conn, EvidenceStore(str(tmp_path / "evidence"))


def _frame(value, width=96, height=54):
    return np.full((height, width, 3), value, dtype=np.uint8)


def test_best_frame_is_full_size_indexed_and_windows_safe(tmp_path):
    conn, store = _setup(tmp_path)
    relative = store.save_best_frame(
        conn, object_id="front:run:track:1", camera="前门:一号",
        frame_bgr=_frame(80), t_source=2.0, conf=0.8,
        bbox=[0.2, 0.2, 0.3, 0.4])

    assert ":" not in relative and "前门" not in relative
    absolute = store.resolve(relative)
    # Windows版默认数据根可能包含中文用户名。OpenCV的imread在部分Windows
    # 构建中不能打开Unicode路径；产品读取链本来就是Python字节IO，因此测试也按
    # 实际产品边界先读字节，再交给OpenCV解码。
    encoded = np.frombuffer(open(absolute, "rb").read(), dtype=np.uint8)
    image = cv2.imdecode(encoded, cv2.IMREAD_COLOR)
    assert image is not None
    assert image.shape[:2] == (54, 96), "证据必须保留输入原图尺寸"
    content = open(absolute, "rb").read()
    row = conn.execute("SELECT * FROM evidence_assets").fetchone()
    assert row["path"] == relative
    assert row["size_bytes"] == len(content)
    assert row["sha256"] == hashlib.sha256(content).hexdigest()
    assert row["state"] == "available"


def test_only_higher_score_replaces_and_removes_old_file(tmp_path):
    conn, store = _setup(tmp_path)
    first = store.save_best_frame(
        conn, object_id="front:run:track:1", camera="front",
        frame_bgr=_frame(40), t_source=2.0, conf=0.8,
        bbox=[0.2, 0.2, 0.2, 0.2])
    unchanged = store.save_best_frame(
        conn, object_id="front:run:track:1", camera="front",
        frame_bgr=_frame(90), t_source=3.0, conf=0.5,
        bbox=[0.2, 0.2, 0.2, 0.2])
    assert unchanged == first and os.path.isfile(store.resolve(first))

    replaced = store.save_best_frame(
        conn, object_id="front:run:track:1", camera="front",
        frame_bgr=_frame(160), t_source=4.0, conf=0.95,
        bbox=[0.2, 0.2, 0.4, 0.4])
    assert replaced != first
    assert os.path.isfile(store.resolve(replaced))
    assert not os.path.exists(store.resolve(first))
    assert conn.execute(
        "SELECT COUNT(*) FROM evidence_assets").fetchone()[0] == 1


def test_event_link_reuses_file_and_resolve_rejects_escape(tmp_path):
    conn, store = _setup(tmp_path)
    relative = store.save_best_frame(
        conn, object_id="front:run:track:1", camera="front",
        frame_bgr=_frame(100), t_source=2.0, conf=0.9,
        bbox=[0.2, 0.2, 0.3, 0.3])
    linked = store.link_object_frame_to_event(
        conn, object_id="front:run:track:1", event_id="event:1",
        camera="front")
    assert linked == relative
    rows = conn.execute(
        "SELECT owner_type,path FROM evidence_assets ORDER BY owner_type"
    ).fetchall()
    assert {row["owner_type"] for row in rows} == {
        "tracked_object", "semantic_event"}
    assert {row["path"] for row in rows} == {relative}
    with pytest.raises(ValueError, match="越出"):
        store.resolve("../outside.jpg")


def test_open_event_follows_better_frame_but_closed_event_keeps_evidence(
        tmp_path):
    conn, store = _setup(tmp_path)
    first = store.save_best_frame(
        conn, object_id="front:run:track:1", camera="front",
        frame_bgr=_frame(60), t_source=2.0, conf=0.7,
        bbox=[0.2, 0.2, 0.2, 0.2])
    open_review_segment(
        conn, review_id="review-1", camera="front", t_start=1.0)
    store.link_object_frame_to_event(
        conn, object_id="front:run:track:1", event_id="event-open",
        camera="front")
    open_semantic_event(
        conn, semantic_event_id="event-open", camera="front",
        review_id="review-1", object_id="front:run:track:1", t_start=2.0,
        template="immediate", best_frame_path=first,
        evidence_state="image_only")

    second = store.save_best_frame(
        conn, object_id="front:run:track:1", camera="front",
        frame_bgr=_frame(120), t_source=3.0, conf=0.9,
        bbox=[0.2, 0.2, 0.3, 0.3])
    event = conn.execute(
        "SELECT best_frame_path FROM semantic_events"
        " WHERE semantic_event_id='event-open'").fetchone()
    assert event["best_frame_path"] == second
    assert os.path.isfile(store.resolve(second))
    assert not os.path.exists(store.resolve(first))

    assert close_semantic_event(
        conn, "event-open", t_end=3.5, reason="zone-leave")
    third = store.save_best_frame(
        conn, object_id="front:run:track:1", camera="front",
        frame_bgr=_frame(180), t_source=4.0, conf=1.0,
        bbox=[0.2, 0.2, 0.5, 0.5])
    frozen = conn.execute(
        "SELECT path,state FROM evidence_assets"
        " WHERE owner_type='semantic_event' AND owner_id='event-open'"
    ).fetchone()
    assert frozen["path"] == second and frozen["state"] == "available"
    assert os.path.isfile(store.resolve(second))
    assert os.path.isfile(store.resolve(third))


def test_best_frame_score_is_bounded_and_deterministic():
    assert best_frame_score(2.0, [0, 0, 1, 1]) == 2.0
    assert best_frame_score(-1.0, [0, 0, 1, 1]) == 0.0
    assert best_frame_score(0.5, None) == 0.5
