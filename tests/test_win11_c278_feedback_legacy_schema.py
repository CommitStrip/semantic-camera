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


def test_legacy_semantic_history_is_readable_through_both_reads():
    conn = _legacy_db()
    assert win11_feedback.get_feedback_summary(
        conn, "legacy-sem", owner_kind="semantic"
    ) == {"display_name": "old-name", "misreport": True}
    rows = win11_feedback.get_feedback(
        conn, "legacy-sem", owner_kind="semantic"
    )
    assert rows is not None
    assert len(rows) == 1
    assert rows[0]["display_name"] == "old-name"


def test_legacy_semantic_append_and_idempotency_are_business_compatible():
    conn = _legacy_db()
    result = win11_feedback.record_feedback(
        conn,
        "legacy-sem",
        owner_kind="semantic",
        display_name="new-name",
        request_id="new-1",
    )
    assert result == {
        "status": "recorded",
        "request_id": "new-1",
    }
    repeat = win11_feedback.record_feedback(
        conn,
        "legacy-sem",
        owner_kind="semantic",
        display_name="new-name",
        request_id="new-1",
    )
    # 幂等重放只回状态（不回显 request_id）——后续合同已收紧为该形状。
    assert repeat == {"status": "idempotent"}


def test_legacy_fact_owner_is_explicitly_incompatible():
    conn = _legacy_db()
    assert win11_feedback.record_feedback(
        conn, "legacy-fact", owner_kind="fact", misreport=True
    ) == {"status": "schema_incompatible"}


def test_legacy_schema_and_rows_remain_unchanged_after_failures():
    conn = _legacy_db()
    columns_before = [
        row[1] for row in conn.execute(
            "PRAGMA table_info(win11_event_feedback)"
        )
    ]
    rows_before = conn.execute(
        "SELECT feedback_id, semantic_event_id, display_name, misreport,"
        " request_id, created_at FROM win11_event_feedback"
        " ORDER BY feedback_id"
    ).fetchall()
    # 只验证失败路径不改结构/历史行：
    #   ① 无任何反馈字段 → invalid_feedback（不落库）；
    #   ② legacy 库不支持 fact 归属 → schema_incompatible。
    win11_feedback.record_feedback(conn, "legacy-sem", owner_kind="semantic")
    win11_feedback.record_feedback(
        conn, "legacy-fact", owner_kind="fact", misreport=True
    )
    columns_after = [
        row[1] for row in conn.execute(
            "PRAGMA table_info(win11_event_feedback)"
        )
    ]
    rows_after = conn.execute(
        "SELECT feedback_id, semantic_event_id, display_name, misreport,"
        " request_id, created_at FROM win11_event_feedback"
        " ORDER BY feedback_id"
    ).fetchall()
    assert columns_after == columns_before
    assert [tuple(row) for row in rows_after] == [
        tuple(row) for row in rows_before
    ]
