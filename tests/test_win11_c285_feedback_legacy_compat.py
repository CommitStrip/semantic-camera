from __future__ import annotations

import sqlite3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scam import win11_feedback


def _legacy_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE semantic_events (semantic_event_id TEXT PRIMARY KEY)")
    conn.execute("CREATE TABLE event_facts (event_id TEXT PRIMARY KEY)")
    conn.execute("INSERT INTO semantic_events VALUES ('legacy-sem')")
    conn.execute("INSERT INTO event_facts VALUES ('legacy-fact')")
    conn.execute(
        "CREATE TABLE win11_event_feedback ("
        " feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " semantic_event_id TEXT,"
        " display_name TEXT,"
        " misreport INTEGER,"
        " request_id TEXT NOT NULL,"
        " created_at REAL NOT NULL)"
    )
    conn.execute(
        "INSERT INTO win11_event_feedback"
        " (semantic_event_id, display_name, misreport, request_id, created_at)"
        " VALUES ('legacy-sem', 'old-name', 1, 'old-1', 1.0)"
    )
    return conn


def _columns(conn: sqlite3.Connection) -> list[str]:
    return [
        row[1] for row in conn.execute(
            "PRAGMA table_info(win11_event_feedback)"
        )
    ]


def test_legacy_semantic_history_reads_without_fact_column():
    conn = _legacy_db()
    assert win11_feedback.get_feedback_summary(
        conn, "legacy-sem", owner_kind="semantic"
    ) == {"display_name": "old-name", "misreport": True}
    rows = win11_feedback.get_feedback(
        conn, "legacy-sem", owner_kind="semantic"
    )
    assert rows is not None
    assert [row["display_name"] for row in rows] == ["old-name"]


def test_legacy_semantic_append_and_idempotency_use_existing_columns():
    conn = _legacy_db()
    result = win11_feedback.record_feedback(
        conn,
        "legacy-sem",
        owner_kind="semantic",
        display_name="new-name",
        request_id="new-1",
    )
    assert result == {"status": "recorded", "request_id": "new-1"}
    repeat = win11_feedback.record_feedback(
        conn,
        "legacy-sem",
        owner_kind="semantic",
        display_name="new-name",
        request_id="new-1",
    )
    assert repeat == {"status": "idempotent"}
    assert _columns(conn) == [
        "feedback_id", "semantic_event_id", "display_name",
        "misreport", "request_id", "created_at",
    ]
    rows = conn.execute(
        "SELECT semantic_event_id, display_name, request_id"
        " FROM win11_event_feedback ORDER BY feedback_id"
    ).fetchall()
    assert [tuple(row) for row in rows] == [
        ("legacy-sem", "old-name", "old-1"),
        ("legacy-sem", "new-name", "new-1"),
    ]


def test_legacy_fact_owner_remains_schema_incompatible():
    conn = _legacy_db()
    assert win11_feedback.record_feedback(
        conn, "legacy-fact", owner_kind="fact", misreport=True
    ) == {"status": "schema_incompatible"}


def test_legacy_schema_and_history_are_not_migrated():
    conn = _legacy_db()
    before = _columns(conn)
    old_rows = conn.execute(
        "SELECT feedback_id, semantic_event_id, display_name, misreport,"
        " request_id, created_at FROM win11_event_feedback"
        " ORDER BY feedback_id"
    ).fetchall()
    win11_feedback.record_feedback(
        conn, "legacy-sem", owner_kind="semantic", display_name="new"
    )
    win11_feedback.record_feedback(
        conn, "legacy-fact", owner_kind="fact", misreport=True
    )
    assert _columns(conn) == before
    current_old_rows = conn.execute(
        "SELECT feedback_id, semantic_event_id, display_name, misreport,"
        " request_id, created_at FROM win11_event_feedback"
        " WHERE request_id='old-1'"
    ).fetchall()
    assert [tuple(row) for row in current_old_rows] == [
        tuple(row) for row in old_rows
    ]
