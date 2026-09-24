"""SQLite 持久层测试（事件事实、迁移、生命周期和幂等）。"""

import json
import sqlite3

import pytest

import scam.db as db


def test_init_schema_and_event_roundtrip(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    db.init_schema(conn)
    db.insert_event(conn, event_id="cam:alert:1", camera="front-door",
                    kind="alert", t_processed="2026-09-17T22:00:00",
                    t_source=12.5, cls="person", conf=0.9, zone_id="z1",
                    template="enter-dwell", short_name="可疑人员翻墙入院",
                    detail="凌晨一名穿深色连帽衫者自围墙东侧翻入",
                    rationale="区域滞留达标", payload='{"k": 1}')
    row = conn.execute(
        "SELECT * FROM events WHERE event_id = ?", ("cam:alert:1",)).fetchone()
    assert row is not None
    assert row["kind"] == "alert"
    assert row["short_name"] == "可疑人员翻墙入院"
    db.insert_event(conn, event_id="cam:alert:1", camera="front-door",
                    kind="alert", t_processed="x")
    cnt = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert cnt == 1, "event_id 幂等（重复写入被忽略）"


def test_schema_tables_exist(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    db.init_schema(conn)
    names = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {
        "events", "tracked_objects", "review_segments", "semantic_events",
        "segments", "patterns", "pattern_embeddings", "meta",
    } <= names
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 3


def test_schema_migrates_legacy_database_without_losing_events(tmp_path):
    path = str(tmp_path / "legacy.db")
    conn = db.connect(path)
    conn.execute(
        "CREATE TABLE events (event_id TEXT PRIMARY KEY, camera TEXT NOT NULL,"
        " kind TEXT NOT NULL, t_processed TEXT NOT NULL, t_source REAL,"
        " cls TEXT, conf REAL, zone_id TEXT, template TEXT, short_name TEXT,"
        " detail TEXT, rationale TEXT, payload TEXT)")
    conn.execute(
        "INSERT INTO events(event_id,camera,kind,t_processed) VALUES(?,?,?,?)",
        ("legacy-1", "front", "alert", "2026-09-19T00:00:00"))
    conn.commit()

    db.init_schema(conn)
    db.init_schema(conn)

    assert conn.execute(
        "SELECT camera FROM events WHERE event_id=?", ("legacy-1",)
    ).fetchone()[0] == "front"
    assert conn.execute(
        "SELECT COUNT(*) FROM tracked_objects").fetchone()[0] == 0
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 3


def test_schema_rejects_database_from_newer_program(tmp_path):
    conn = db.connect(str(tmp_path / "future.db"))
    conn.execute("PRAGMA user_version=99")
    with pytest.raises(RuntimeError, match="高于当前程序支持"):
        db.init_schema(conn)


def test_tracked_object_lifecycle_preserves_closed_truth(tmp_path):
    conn = db.connect(str(tmp_path / "objects.db"))
    db.init_schema(conn)
    db.open_tracked_object(
        conn, object_id="obj-1", camera="front", t_start=10.0,
        cls="person", conf=0.7, zones=["gate"])
    assert db.update_tracked_object(
        conn, "obj-1", t_last=12.0, conf=0.9,
        zones=["gate", "yard"], review_id="review-1",
        best_frame_path="frames/obj-1.jpg", best_frame_t=11.5)
    assert db.close_tracked_object(
        conn, "obj-1", t_end=11.0, reason="tracker_lost")
    assert not db.close_tracked_object(
        conn, "obj-1", t_end=20.0, reason="second_close")

    # 重复 open 不得重开或篡改已经闭合的事实。
    db.open_tracked_object(
        conn, object_id="obj-1", camera="front", t_start=30.0,
        cls="vehicle", conf=1.0, zones=["road"])
    row = conn.execute(
        "SELECT * FROM tracked_objects WHERE object_id=?", ("obj-1",)
    ).fetchone()
    assert row["t_start"] == 10.0
    assert row["t_last"] == 12.0
    assert row["t_end"] == 12.0
    assert row["end_reason"] == "tracker_lost"
    assert row["cls"] == "person"
    assert row["max_conf"] == 0.9
    assert json.loads(row["zones"]) == ["gate", "yard"]


def test_review_segment_is_unique_per_camera_and_only_escalates(tmp_path):
    conn = db.connect(str(tmp_path / "reviews.db"))
    db.init_schema(conn)
    db.open_review_segment(
        conn, review_id="review-1", camera="front", t_start=1.0,
        severity="motion", object_ids=["obj-1"])
    with pytest.raises(sqlite3.IntegrityError):
        db.open_review_segment(
            conn, review_id="review-2", camera="front", t_start=2.0)

    assert db.update_review_segment(
        conn, "review-1", t_last=3.0, severity="alert",
        object_ids=["obj-1", "obj-2"], semantic_event_ids=["sem-1"])
    assert db.update_review_segment(
        conn, "review-1", t_last=4.0, severity="motion",
        semantic_event_ids=["sem-1", "sem-2"])
    assert db.set_reviewed(conn, "review-1")
    assert db.close_review_segment(
        conn, "review-1", t_end=3.5, reason="activity_quiet")
    db.open_review_segment(
        conn, review_id="review-2", camera="front", t_start=5.0)

    row = conn.execute(
        "SELECT * FROM review_segments WHERE review_id='review-1'"
    ).fetchone()
    assert row["severity"] == "alert"
    assert row["reviewed"] == 1
    assert row["t_end"] == 4.0
    assert json.loads(row["object_ids"]) == ["obj-1", "obj-2"]
    assert json.loads(row["semantic_event_ids"]) == ["sem-1", "sem-2"]


def test_semantic_event_keeps_admin_verdict_while_evidence_improves(tmp_path):
    conn = db.connect(str(tmp_path / "semantic.db"))
    db.init_schema(conn)
    db.open_tracked_object(
        conn, object_id="obj-1", camera="front", t_start=1.0, cls="person")
    db.open_review_segment(
        conn, review_id="review-1", camera="front", t_start=1.0)
    db.open_semantic_event(
        conn, semantic_event_id="sem-1", camera="front",
        review_id="review-1", object_id="obj-1", t_start=2.0,
        template="enter-and-dwell", zone_id="yard", severity="high",
        cls="person", conf=0.8, short_name="有人进入院子")
    assert db.update_semantic_event(
        conn, "sem-1", t_last=3.0, detail="停留约 10 秒",
        rationale="规则命中后补充图像证据", evidence_state="image_only",
        best_frame_path="frames/sem-1.jpg")
    assert db.close_semantic_event(
        conn, "sem-1", t_end=4.0, reason="rule_cleared")

    # 相同 id 的迟到消息不能覆盖管理员模板、区域或重新打开事件。
    db.open_semantic_event(
        conn, semantic_event_id="sem-1", camera="front",
        review_id="review-1", object_id="obj-1", t_start=99.0,
        template="other-rule", zone_id="street", severity="low")
    row = conn.execute(
        "SELECT * FROM semantic_events WHERE semantic_event_id='sem-1'"
    ).fetchone()
    assert row["template"] == "enter-and-dwell"
    assert row["zone_id"] == "yard"
    assert row["severity"] == "high"
    assert row["state"] == "closed"
    assert row["evidence_state"] == "image_only"
    assert row["detail"] == "停留约 10 秒"


def test_semantic_event_rejects_missing_evidence_links(tmp_path):
    conn = db.connect(str(tmp_path / "fk.db"))
    db.init_schema(conn)
    with pytest.raises(sqlite3.IntegrityError):
        db.open_semantic_event(
            conn, semantic_event_id="sem-orphan", camera="front",
            review_id="missing-review", object_id="missing-object",
            t_start=1.0, template="enter")


def test_recovery_closes_only_stale_open_records_and_is_idempotent(tmp_path):
    conn = db.connect(str(tmp_path / "recovery.db"))
    db.init_schema(conn)
    db.open_tracked_object(
        conn, object_id="stale", camera="front", t_start=1.0, cls="person")
    db.open_review_segment(
        conn, review_id="stale-review", camera="front", t_start=1.0)
    db.open_semantic_event(
        conn, semantic_event_id="stale-event", camera="front",
        review_id="stale-review", object_id="stale", t_start=1.0,
        template="enter")
    db.open_tracked_object(
        conn, object_id="fresh", camera="side", t_start=95.0, cls="person")
    db.open_review_segment(
        conn, review_id="fresh-review", camera="side", t_start=95.0)

    assert db.recover_stale_records(
        conn, now=100.0, stale_after_s=30.0) == {
            "tracked_objects": 1,
            "review_segments": 1,
            "semantic_events": 1,
        }
    assert db.recover_stale_records(
        conn, now=100.0, stale_after_s=30.0) == {
            "tracked_objects": 0,
            "review_segments": 0,
            "semantic_events": 0,
        }
    assert conn.execute(
        "SELECT end_reason FROM tracked_objects WHERE object_id='stale'"
    ).fetchone()[0] == "recovered_after_restart"
    assert conn.execute(
        "SELECT state FROM semantic_events WHERE semantic_event_id='stale-event'"
    ).fetchone()[0] == "closed"
    assert conn.execute(
        "SELECT t_end FROM tracked_objects WHERE object_id='fresh'"
    ).fetchone()[0] is None

# ---------- F8：宽限窗遗留记录的一次性延迟收口（启动快照 + CAS） ----------

def _open_three_layers(conn, suffix, t_last, *, camera=None):
    """三层各造一条开放记录，并把 t_last 推到指定时刻。返回三把主键。

    同一相机只能有一个开放审查段，所以每组数据集默认用自己的相机 id；
    需要"启动后新建"的场景显式传不同相机。
    """
    cam = camera or f"cam-{suffix}"
    oid, rid, sid = f"obj-{suffix}", f"rev-{suffix}", f"sem-{suffix}"
    db.open_tracked_object(conn, object_id=oid, camera=cam,
                           t_start=1.0, cls="person")
    db.open_review_segment(conn, review_id=rid, camera=cam, t_start=1.0)
    db.open_semantic_event(conn, semantic_event_id=sid, camera=cam,
                           review_id=rid, object_id=oid, t_start=2.0,
                           template="enter-and-dwell", zone_id="yard")
    db.update_tracked_object(conn, oid, t_last=t_last)
    db.update_review_segment(conn, rid, t_last=t_last)
    db.update_semantic_event(conn, sid, t_last=t_last)
    return oid, rid, sid


def _row_state(conn, suffix):
    """三层各自的 (t_end, end_reason[, state]) 快照。"""
    oid, rid, sid = f"obj-{suffix}", f"rev-{suffix}", f"sem-{suffix}"
    return (
        list(conn.execute("SELECT t_end,end_reason FROM tracked_objects"
                          " WHERE object_id=?", (oid,)).fetchone()[:]),
        list(conn.execute("SELECT t_end,end_reason FROM review_segments"
                          " WHERE review_id=?", (rid,)).fetchone()[:]),
        list(conn.execute("SELECT t_end,end_reason,state FROM semantic_events"
                          " WHERE semantic_event_id=?", (sid,)).fetchone()[:]),
    )


def test_grace_window_records_are_snapshotted_then_closed_by_delayed_pass(
        tmp_path):
    """场景1+6：宽限窗内启动不误关，延迟复核把三层遗留记录正确闭合。"""
    conn = db.connect(str(tmp_path / "f8-a.db"))
    db.init_schema(conn)
    _open_three_layers(conn, "fresh", t_last=95.0)

    # 启动收口（宽限窗 30s、now=100 → 只关 t_last<=70 的记录）不动新鲜记录
    assert db.recover_stale_records(conn, now=100.0, stale_after_s=30.0) == {
        "tracked_objects": 0, "review_segments": 0, "semantic_events": 0}

    snapshot = db.snapshot_pending_recovery(conn, now=100.0, stale_after_s=30.0)
    assert len(snapshot) == 3, "三层都要进快照"
    assert {item["layer"] for item in snapshot} == set(db.RECOVERY_LAYERS)

    # 宽限窗过后一次性复核：三层全部闭合，t_end=t_last、固定原因
    assert db.finalize_snapshot_records(conn, snapshot) == {
        "tracked_objects": 1, "review_segments": 1, "semantic_events": 1}
    obj, rev, sem = _row_state(conn, "fresh")
    assert obj == [95.0, "recovered_after_restart"]
    assert rev == [95.0, "recovered_after_restart"]
    assert sem[:2] == [95.0, "recovered_after_restart"]
    assert sem[2] == "closed"
    assert conn.execute(
        "SELECT state FROM semantic_events WHERE semantic_event_id='sem-fresh'"
    ).fetchone()[0] == "closed"


def test_records_updated_after_snapshot_are_never_closed(tmp_path):
    """场景3：快照之后 t_last 被推进（新实例续写）→ CAS 失败，不得关闭。"""
    conn = db.connect(str(tmp_path / "f8-b.db"))
    db.init_schema(conn)
    oid, _rid, _sid = _open_three_layers(conn, "live", t_last=95.0)
    snapshot = db.snapshot_pending_recovery(conn, now=100.0, stale_after_s=30.0)

    db.update_tracked_object(conn, oid, t_last=120.0)     # 新实例仍在写

    counts = db.finalize_snapshot_records(conn, snapshot)
    assert counts["tracked_objects"] == 0, "被更新过的记录不得被恢复任务命中"
    row = conn.execute("SELECT t_end,t_last FROM tracked_objects"
                       " WHERE object_id=?", (oid,)).fetchone()
    assert row["t_end"] is None and row["t_last"] == 120.0


def test_records_closed_by_admin_keep_their_reason(tmp_path):
    """场景4：快照后被正常关闭 → 不得改写既有 end_reason。"""
    conn = db.connect(str(tmp_path / "f8-c.db"))
    db.init_schema(conn)
    oid, rid, sid = _open_three_layers(conn, "admin", t_last=95.0)
    snapshot = db.snapshot_pending_recovery(conn, now=100.0, stale_after_s=30.0)

    db.close_tracked_object(conn, oid, t_end=96.0, reason="tracker_lost")
    db.close_review_segment(conn, rid, t_end=97.0, reason="quiet")
    db.close_semantic_event(conn, sid, t_end=98.0, reason="rule_cleared")

    assert db.finalize_snapshot_records(conn, snapshot) == {
        "tracked_objects": 0, "review_segments": 0, "semantic_events": 0}
    assert list(_row_state(conn, "admin")) == [
        [96.0, "tracker_lost"], [97.0, "quiet"], [98.0, "rule_cleared", "closed"]]


def test_records_created_after_snapshot_are_not_touched(tmp_path):
    """场景5：启动后新建的三层事实不得被旧恢复计划命中。"""
    conn = db.connect(str(tmp_path / "f8-d.db"))
    db.init_schema(conn)
    _open_three_layers(conn, "old", t_last=95.0)
    snapshot = db.snapshot_pending_recovery(conn, now=100.0, stale_after_s=30.0)

    # 启动后新事实（独立相机：同一相机只能有一个开放审查段）
    _open_three_layers(conn, "new", t_last=101.0, camera="cam-front-new")

    assert db.finalize_snapshot_records(conn, snapshot) == {
        "tracked_objects": 1, "review_segments": 1, "semantic_events": 1}
    for row in _row_state(conn, "new"):
        assert row[0] is None and row[1] is None
    assert conn.execute(
        "SELECT t_end FROM semantic_events WHERE semantic_event_id='sem-new'"
    ).fetchone()[0] is None


def test_snapshot_finalize_is_idempotent(tmp_path):
    """场景7：重复执行同一份计划幂等（第二次零改动、不改动已闭合事实）。"""
    conn = db.connect(str(tmp_path / "f8-e.db"))
    db.init_schema(conn)
    _open_three_layers(conn, "idem", t_last=95.0)
    snapshot = db.snapshot_pending_recovery(conn, now=100.0, stale_after_s=30.0)

    first = db.finalize_snapshot_records(conn, snapshot)
    after_first = _row_state(conn, "idem")
    second = db.finalize_snapshot_records(conn, snapshot)

    assert first == {"tracked_objects": 1, "review_segments": 1,
                     "semantic_events": 1}
    assert second == {"tracked_objects": 0, "review_segments": 0,
                      "semantic_events": 0}
    assert _row_state(conn, "idem") == after_first


def test_outside_grace_window_closes_immediately_and_leaves_empty_snapshot(
        tmp_path):
    """场景2+8：宽限窗外立即关闭；Linux 零宽限行为不变（快照必为空）。"""
    conn = db.connect(str(tmp_path / "f8-f.db"))
    db.init_schema(conn)
    _open_three_layers(conn, "stale", t_last=10.0)

    assert db.recover_stale_records(conn, now=100.0, stale_after_s=30.0) == {
        "tracked_objects": 1, "review_segments": 1, "semantic_events": 1}
    assert db.snapshot_pending_recovery(
        conn, now=100.0, stale_after_s=30.0) == []

    # 零宽限（Linux）：任何开放记录都立即闭合，快照因此必为空
    _open_three_layers(conn, "linux", t_last=100.0, camera="cam-linux")
    assert db.recover_stale_records(conn, now=100.0, stale_after_s=0.0) == {
        "tracked_objects": 1, "review_segments": 1, "semantic_events": 1}
    assert db.snapshot_pending_recovery(
        conn, now=100.0, stale_after_s=0.0) == []
