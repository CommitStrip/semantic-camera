import sqlite3

import pytest

from scam import db
from scam.win11_feedback import get_feedback, record_feedback


def _conn(tmp_path):
    conn = db.connect(str(tmp_path / "feedback.db"))
    db.init_schema(conn)
    return conn


def _event(conn, *, review_id="rev-1", eid="ev-1", camera="front"):
    db.open_review_segment(conn, review_id=review_id, camera=camera,
                           t_start=1000.0)
    db.close_review_segment(conn, review_id, t_end=1120.0, reason="quiet")
    db.open_tracked_object(conn, object_id=f"{review_id}:obj", camera=camera,
                           t_start=1010.0, cls="person", zones=["z1"])
    db.close_tracked_object(conn, f"{review_id}:obj", t_end=1110.0,
                            reason="gone")
    db.open_semantic_event(
        conn, semantic_event_id=eid, camera=camera, review_id=review_id,
        object_id=f"{review_id}:obj", t_start=1020.0, template="enter-dwell",
        zone_id="z1", cls="person")
    db.close_semantic_event(conn, eid, t_end=1100.0, reason="left")


def _has_table(conn, name):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,)).fetchone() is not None


def test_get_feedback_is_pure_read_and_record_is_append_only(tmp_path):
    conn = _conn(tmp_path)
    assert get_feedback(conn, "ev-1") is None
    assert not _has_table(conn, "win11_event_feedback")
    _event(conn)

    result = record_feedback(conn, "ev-1", display_name="门口送快递",
                             request_id="req-1")
    assert result == {"status": "recorded", "request_id": "req-1"}
    assert get_feedback(conn, "ev-1") == [{
        "semantic_event_id": "ev-1",
        "display_name": "门口送快递",
        "misreport": None,
        "request_id": "req-1",
        "created_at": get_feedback(conn, "ev-1")[0]["created_at"],
    }]
    conn.commit()

    fresh = db.connect(str(tmp_path / "feedback.db"))
    rows = get_feedback(fresh, "ev-1")
    assert rows[0]["display_name"] == "门口送快递"
    assert rows[0]["misreport"] is None
    with pytest.raises(sqlite3.IntegrityError):
        fresh.execute("UPDATE win11_event_feedback SET display_name='x'")
    with pytest.raises(sqlite3.IntegrityError):
        fresh.execute("DELETE FROM win11_event_feedback")
    fresh.close()
    conn.close()


def test_idempotence_cross_event_conflict_and_invalid_inputs(tmp_path):
    conn = _conn(tmp_path)
    _event(conn)
    assert record_feedback(conn, "ev-1", display_name="A",
                           request_id="req")["status"] == "recorded"
    assert record_feedback(conn, "ev-1", display_name="A",
                           request_id="req")["status"] == "idempotent"
    _event(conn, review_id="rev-2", eid="ev-2")
    assert record_feedback(conn, "ev-2", display_name="B",
                           request_id="req")["status"] == "request_id_conflict"
    assert record_feedback(conn, "ev-1", misreport="true")["status"] == "invalid_feedback"
    assert record_feedback(conn, "ev-1")["status"] == "invalid_feedback"
    assert record_feedback(conn, "ev-1", display_name="x" * 17)["status"] == "invalid_feedback"
    assert record_feedback(conn, "ev-1", display_name="a\x00")["status"] == "invalid_feedback"
    assert record_feedback(conn, "missing", display_name="A")["status"] == "event_not_found"
    assert record_feedback(conn, "ev-1", display_name="A", request_id="")["status"] == "invalid_request_id"
    conn.close()


def test_caller_transaction_is_not_committed_or_rolled_back(tmp_path):
    conn = _conn(tmp_path)
    _event(conn)
    conn.execute("CREATE TEMP TABLE caller_probe (id INTEGER)")
    conn.execute("BEGIN")
    conn.execute("INSERT INTO caller_probe VALUES (1)")
    result = record_feedback(conn, "ev-1", misreport=True, request_id="probe")
    assert result["status"] == "recorded"
    assert conn.in_transaction is True
    assert conn.execute("SELECT COUNT(*) FROM caller_probe").fetchone()[0] == 1
    assert get_feedback(conn, "ev-1")[0]["misreport"] is True
    conn.rollback()
    assert conn.execute("SELECT COUNT(*) FROM caller_probe").fetchone()[0] == 0
    conn.close()


def test_feedback_never_changes_facts_or_alerts(tmp_path):
    conn = _conn(tmp_path)
    _event(conn)
    semantic_before = [tuple(row) for row in conn.execute(
        "SELECT * FROM semantic_events ORDER BY semantic_event_id")]
    facts_before = [tuple(row) for row in conn.execute(
        "SELECT * FROM event_facts ORDER BY event_id")]
    alerts_before = [tuple(row) for row in conn.execute(
        "SELECT * FROM event_notifications ORDER BY notification_id")]
    record_feedback(conn, "ev-1", display_name="门口送快递", misreport=True)
    conn.commit()
    semantic_after = [tuple(row) for row in conn.execute(
        "SELECT * FROM semantic_events ORDER BY semantic_event_id")]
    facts_after = [tuple(row) for row in conn.execute(
        "SELECT * FROM event_facts ORDER BY event_id")]
    alerts_after = [tuple(row) for row in conn.execute(
        "SELECT * FROM event_notifications ORDER BY notification_id")]
    assert semantic_after == semantic_before
    assert facts_after == facts_before
    assert alerts_after == alerts_before
    conn.close()


def test_idempotent_and_conflict_release_their_savepoints(tmp_path):
    conn = _conn(tmp_path)
    _event(conn)
    _event(conn, review_id="rev-2", eid="ev-2")

    conn.execute("BEGIN")
    assert record_feedback(conn, "ev-1", display_name="A",
                           request_id="idem")["status"] == "recorded"
    assert record_feedback(conn, "ev-1", display_name="A",
                           request_id="idem")["status"] == "idempotent"
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("RELEASE SAVEPOINT c235_feedback")
    conn.rollback()

    conn.execute("BEGIN")
    assert record_feedback(conn, "ev-1", display_name="A",
                           request_id="collide")["status"] == "recorded"
    assert record_feedback(conn, "ev-2", display_name="B",
                           request_id="collide")["status"] == "request_id_conflict"
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("RELEASE SAVEPOINT c235_feedback")
    conn.rollback()
    conn.close()


def test_fact_owner_is_isolated_from_semantic_owner(tmp_path):
    conn = _conn(tmp_path)
    db.open_review_segment(conn, review_id="rev-f", camera="front",
                           t_start=1000.0)
    db.close_review_segment(conn, "rev-f", t_end=1120.0, reason="quiet")
    db.open_tracked_object(conn, object_id="rev-f:obj", camera="front",
                           t_start=1010.0, cls="person", zones=["z1"])
    db.close_tracked_object(conn, "rev-f:obj", t_end=1110.0, reason="gone")
    db.open_semantic_event(
        conn, semantic_event_id="shared", camera="front", review_id="rev-f",
        object_id="rev-f:obj", t_start=1020.0, template="enter-dwell",
        zone_id="z1", cls="person")
    db.close_semantic_event(conn, "shared", t_end=1100.0, reason="left")
    assert db.open_event_fact(
        conn, event_id="shared", camera="front", object_id="rev-f:obj",
        t_start=1020.0, cls="person", review_id="rev-f")

    semantic = record_feedback(conn, "shared", display_name="semantic",
                               request_id="shared-request")
    fact = record_feedback(conn, "shared", owner_kind="fact",
                           display_name="fact", request_id="shared-request")
    assert semantic["status"] == "recorded"
    assert fact == {"status": "request_id_conflict",
                    "owner_kind": "fact", "event_id": "shared"}
    assert record_feedback(conn, "missing", owner_kind="fact",
                           display_name="x")["status"] == "event_not_found"

    fact_ok = record_feedback(conn, "shared", owner_kind="fact",
                              display_name="fact", request_id="fact-1")
    assert fact_ok == {"status": "recorded", "owner_kind": "fact",
                       "event_id": "shared", "request_id": "fact-1"}
    rows = get_feedback(conn, "shared", owner_kind="fact")
    assert rows[0]["owner_kind"] == "fact"
    assert rows[0]["event_id"] == "shared"
    assert rows[0]["misreport"] is None
    conn.close()


def test_read_window_returns_latest_rows_in_ascending_order(tmp_path):
    conn = _conn(tmp_path)
    _event(conn)
    for i in range(25):
        result = record_feedback(conn, "ev-1", display_name=f"n{i}",
                                 request_id=f"latest-{i}")
        assert result["status"] == "recorded"
        conn.commit()
    rows = get_feedback(conn, "ev-1", limit=20)
    assert [row["request_id"] for row in rows] == [
        f"latest-{i}" for i in range(5, 25)
    ]
    assert rows[0]["display_name"] == "n5"
    conn.close()
