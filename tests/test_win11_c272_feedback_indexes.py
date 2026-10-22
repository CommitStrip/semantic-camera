from __future__ import annotations

import sqlite3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scam import win11_feedback


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE semantic_events (semantic_event_id TEXT PRIMARY KEY)")
    conn.execute("CREATE TABLE event_facts (event_id TEXT PRIMARY KEY)")
    conn.execute("INSERT INTO semantic_events VALUES ('sem-1')")
    conn.execute("INSERT INTO event_facts VALUES ('fact-1')")
    return conn


def _insert_feedback(conn: sqlite3.Connection, owner: str, event: str,
                     count: int = 80) -> None:
    for index in range(count):
        conn.execute(
            "INSERT INTO win11_event_feedback"
            " (semantic_event_id, fact_event_id, display_name, misreport,"
            " request_id, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (
                event if owner == "semantic" else None,
                event if owner == "fact" else None,
                f"name-{index}" if index % 2 == 0 else None,
                int(index % 3 == 0) if index % 2 else None,
                f"{owner}-{index}",
                float(index),
            ),
        )


def test_semantic_summary_query_uses_partial_owner_index():
    conn = _db()
    assert win11_feedback.record_feedback(
        conn, "sem-1", owner_kind="semantic", display_name="seed"
    )["status"] == "recorded"
    _insert_feedback(conn, "semantic", "sem-1")
    plan = "\n".join(
        row[3] for row in conn.execute(
            "EXPLAIN QUERY PLAN SELECT display_name"
            " FROM win11_event_feedback"
            " WHERE semantic_event_id=? AND display_name IS NOT NULL"
            " ORDER BY feedback_id DESC LIMIT 1",
            ("sem-1",),
        )
    )
    assert "USING INDEX" in plan
    assert "SCAN" not in plan


def test_fact_summary_query_uses_partial_owner_index():
    conn = _db()
    assert win11_feedback.record_feedback(
        conn, "fact-1", owner_kind="fact", misreport=True
    )["status"] == "recorded"
    _insert_feedback(conn, "fact", "fact-1")
    plan = "\n".join(
        row[3] for row in conn.execute(
            "EXPLAIN QUERY PLAN SELECT misreport"
            " FROM win11_event_feedback"
            " WHERE fact_event_id=? AND misreport IS NOT NULL"
            " ORDER BY feedback_id DESC LIMIT 1",
            ("fact-1",),
        )
    )
    assert "USING INDEX" in plan
    assert "SCAN" not in plan


def test_get_feedback_summary_does_not_create_indexes():
    conn = _db()
    conn.execute(
        "CREATE TABLE win11_event_feedback ("
        " feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " semantic_event_id TEXT, fact_event_id TEXT,"
        " display_name TEXT, misreport INTEGER,"
        " request_id TEXT NOT NULL, created_at REAL NOT NULL)"
    )
    conn.execute(
        "INSERT INTO win11_event_feedback"
        " (semantic_event_id, display_name, request_id, created_at)"
        " VALUES ('sem-1', 'visible', 'r1', 1.0)"
    )
    assert win11_feedback.get_feedback_summary(
        conn, "sem-1", owner_kind="semantic"
    ) == {"display_name": "visible", "misreport": None}
    indexes = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'"
        " AND tbl_name='win11_event_feedback'"
    ).fetchall()
    assert indexes == []


def test_old_semantic_table_without_fact_column_is_precise_failure():
    conn = _db()
    conn.execute(
        "CREATE TABLE win11_event_feedback ("
        " feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " semantic_event_id TEXT,"
        " display_name TEXT, misreport INTEGER,"
        " request_id TEXT NOT NULL, created_at REAL NOT NULL)"
    )
    columns_before = [
        row[1] for row in conn.execute(
            "PRAGMA table_info(win11_event_feedback)"
        )
    ]
    semantic_result = win11_feedback.record_feedback(
        conn,
        "sem-1",
        owner_kind="semantic",
        display_name="legacy",
        request_id="legacy-semantic-1",
    )
    assert semantic_result == {
        "status": "recorded",
        "request_id": "legacy-semantic-1",
    }
    assert win11_feedback.get_feedback_summary(
        conn, "sem-1", owner_kind="semantic"
    ) == {"display_name": "legacy", "misreport": None}
    assert win11_feedback.record_feedback(
        conn, "fact-1", owner_kind="fact", misreport=True
    ) == {"status": "schema_incompatible"}
    columns_after = [
        row[1] for row in conn.execute(
            "PRAGMA table_info(win11_event_feedback)"
        )
    ]
    assert columns_after == columns_before
