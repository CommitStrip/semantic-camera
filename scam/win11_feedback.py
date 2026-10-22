"""Append-only user feedback for current semantic events.

This module deliberately does not alter event facts, administrator alerts,
L4 fusion, or the legacy SlowCore path. It only records user intent in a
component-owned table.
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from typing import Any

_TABLE = "win11_event_feedback"
_MAX_ID = 128
_MAX_NAME = 16
_OWNER_KINDS = ("semantic", "fact")
_REQUIRED_COLUMNS = {
    "semantic": {
        "feedback_id", "semantic_event_id", "display_name", "misreport",
        "request_id", "created_at",
    },
    "fact": {
        "feedback_id", "fact_event_id", "semantic_event_id", "display_name",
        "misreport", "request_id", "created_at",
    },
}


def _fixed_error(status: str) -> dict[str, Any]:
    return {"status": status}


def _owner_result(status: str, owner_kind: str,
                  event_id: str | None = None,
                  request_id: str | None = None) -> dict[str, Any]:
    if owner_kind == "semantic":
        if request_id is None:
            return _fixed_error(status)
        return {"status": status, "request_id": request_id}
    result = {"status": status, "owner_kind": owner_kind}
    if event_id is not None:
        result["event_id"] = event_id
    if request_id is not None:
        result["request_id"] = request_id
    return result


def _valid_id(value: Any, field: str) -> bool:
    if not isinstance(value, str) or not value or len(value) > _MAX_ID:
        return False
    return all(char.isprintable() for char in value)


def _valid_feedback(*, display_name, misreport) -> bool:
    if display_name is None and misreport is None:
        return False
    if misreport is not None and type(misreport) is not bool:
        return False
    if display_name is not None:
        if not isinstance(display_name, str):
            return False
        if not 1 <= len(display_name) <= _MAX_NAME:
            return False
        if any(not char.isprintable() for char in display_name):
            return False
    return True


def _table_exists(conn: sqlite3.Connection) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (_TABLE,)).fetchone() is not None


def _table_columns(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute(
        "SELECT name FROM pragma_table_info(?)", (_TABLE,))}


def _ensure_table(conn: sqlite3.Connection, owner_kind: str) -> bool:
    """Create the new table, or accept an old table only for semantic rows."""
    if _table_exists(conn):
        missing = _REQUIRED_COLUMNS[owner_kind] - _table_columns(conn)
        if missing:
            return False
        _ensure_indexes(conn)
        return True
    conn.execute(
        "CREATE TABLE IF NOT EXISTS win11_event_feedback ("
        " feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " semantic_event_id TEXT,"
        " fact_event_id TEXT,"
        " display_name TEXT,"
        " misreport INTEGER,"
        " request_id TEXT NOT NULL,"
        " created_at REAL NOT NULL,"
        " CHECK ((semantic_event_id IS NOT NULL)"
        "   + (fact_event_id IS NOT NULL) = 1),"
        " FOREIGN KEY(semantic_event_id)"
        " REFERENCES semantic_events(semantic_event_id),"
        " FOREIGN KEY(fact_event_id)"
        " REFERENCES event_facts(event_id)"
        ")"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_win11_event_feedback_request"
        " ON win11_event_feedback(request_id)"
    )
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS trg_win11_event_feedback_no_update"
        " BEFORE UPDATE ON win11_event_feedback"
        " BEGIN SELECT RAISE(ABORT, 'win11_event_feedback_append_only'); END"
    )
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS trg_win11_event_feedback_no_delete"
        " BEFORE DELETE ON win11_event_feedback"
        " BEGIN SELECT RAISE(ABORT, 'win11_event_feedback_append_only'); END"
    )
    _ensure_indexes(conn)
    return True


def _ensure_indexes(conn: sqlite3.Connection) -> None:
    """Create bounded lookup indexes only from the write path."""
    columns = _table_columns(conn)
    if "semantic_event_id" in columns:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS"
            " idx_win11_event_feedback_semantic_name"
            " ON win11_event_feedback(semantic_event_id, feedback_id DESC)"
            " WHERE semantic_event_id IS NOT NULL"
            "   AND display_name IS NOT NULL"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS"
            " idx_win11_event_feedback_semantic_misreport"
            " ON win11_event_feedback(semantic_event_id, feedback_id DESC)"
            " WHERE semantic_event_id IS NOT NULL"
            "   AND misreport IS NOT NULL"
        )
    if "fact_event_id" in columns:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS"
            " idx_win11_event_feedback_fact_name"
            " ON win11_event_feedback(fact_event_id, feedback_id DESC)"
            " WHERE fact_event_id IS NOT NULL"
            "   AND display_name IS NOT NULL"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS"
            " idx_win11_event_feedback_fact_misreport"
            " ON win11_event_feedback(fact_event_id, feedback_id DESC)"
            " WHERE fact_event_id IS NOT NULL"
            "   AND misreport IS NOT NULL"
        )


def _row(row: sqlite3.Row, owner_kind: str) -> dict[str, Any]:
    event_id = row["fact_event_id"] if owner_kind == "fact" \
        else row["semantic_event_id"]
    result = {
        "display_name": row["display_name"],
        "misreport": (None if row["misreport"] is None
                      else bool(row["misreport"])),
        "request_id": row["request_id"],
        "created_at": row["created_at"],
    }
    if owner_kind == "semantic":
        result["semantic_event_id"] = row["semantic_event_id"]
    else:
        result.update({"owner_kind": owner_kind, "event_id": event_id,
                       "fact_event_id": row["fact_event_id"]})
    return result


def _event_exists(conn: sqlite3.Connection, owner_kind: str,
                  event_id: str) -> bool | None:
    table = "event_facts" if owner_kind == "fact" else "semantic_events"
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,)).fetchone()
    if exists is None:
        return None
    return conn.execute(
        f"SELECT 1 FROM {table} WHERE "
        + ("event_id" if owner_kind == "fact" else "semantic_event_id")
        + "=?", (event_id,)).fetchone() is not None


def record_feedback(conn: sqlite3.Connection, event_id: str, *,
                    owner_kind: str = "semantic",
                    display_name: str | None = None,
                    misreport: bool | None = None,
                    request_id: str | None = None) -> dict[str, Any]:
    """Append user feedback without committing the caller's transaction."""
    if owner_kind not in _OWNER_KINDS:
        return _fixed_error("invalid_owner_kind")
    if not _valid_id(event_id, "event_id"):
        return _fixed_error("invalid_event_id")
    if not _valid_feedback(display_name=display_name, misreport=misreport):
        return _fixed_error("invalid_feedback")
    if request_id is not None and not _valid_id(request_id, "request_id"):
        return _fixed_error("invalid_request_id")
    if request_id is None:
        request_id = uuid.uuid4().hex

    event_found = _event_exists(conn, owner_kind, event_id)
    if event_found is None:
        return _fixed_error("schema_incompatible")
    if not event_found:
        return _fixed_error("event_not_found")

    conn.execute("SAVEPOINT c235_feedback")
    try:
        if not _ensure_table(conn, owner_kind):
            return _fixed_error("schema_incompatible")
        columns = _table_columns(conn)
        lookup_columns = ["semantic_event_id"]
        if "fact_event_id" in columns:
            lookup_columns.append("fact_event_id")
        existing = conn.execute(
            "SELECT " + ", ".join(lookup_columns)
            + " FROM win11_event_feedback WHERE request_id=?",
            (request_id,)).fetchone()
        if existing is not None:
            existing_kind = ("semantic" if owner_kind == "semantic"
                             else "fact")
            existing_event = (
                existing["fact_event_id"] if existing_kind == "fact"
                else existing["semantic_event_id"])
            if existing_kind == owner_kind and existing_event == event_id:
                # 幂等重放不回显 request_id：与 recorded 分支形状区分，
                # 调用方据 status 判重（c285 起的最新合同）。
                return _owner_result("idempotent", owner_kind, event_id)
            return _owner_result("request_id_conflict", owner_kind, event_id)
        semantic_value = event_id if owner_kind == "semantic" else None
        fact_value = event_id if owner_kind == "fact" else None
        if owner_kind == "semantic" and "fact_event_id" not in columns:
            conn.execute(
                "INSERT INTO win11_event_feedback"
                " (semantic_event_id, display_name, misreport,"
                "  request_id, created_at)"
                " VALUES (?,?,?,?,?)",
                (semantic_value, display_name,
                 None if misreport is None else int(misreport),
                 request_id, time.time()))
        else:
            conn.execute(
                "INSERT INTO win11_event_feedback"
                " (semantic_event_id, fact_event_id, display_name,"
                "  misreport, request_id, created_at)"
                " VALUES (?,?,?,?,?,?)",
                (semantic_value, fact_value, display_name,
                 None if misreport is None else int(misreport),
                 request_id, time.time()))
        return _owner_result("recorded", owner_kind, event_id, request_id)
    except Exception:
        conn.execute("ROLLBACK TO SAVEPOINT c235_feedback")
        return _fixed_error("feedback_write_failed")
    finally:
        try:
            conn.execute("RELEASE SAVEPOINT c235_feedback")
        except sqlite3.Error:
            pass


def get_feedback(conn: sqlite3.Connection, event_id: str, *,
                 owner_kind: str = "semantic",
                 limit: int = 20) -> list[dict[str, Any]] | None:
    """Pure read; a missing component table returns None and never creates it."""
    if owner_kind not in _OWNER_KINDS:
        return None
    if not _valid_id(event_id, "event_id"):
        return None
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("limit must be 1..100")
    if not _table_exists(conn):
        return None
    columns = _table_columns(conn)
    if _REQUIRED_COLUMNS[owner_kind] - columns:
        return None
    owner_column = ("fact_event_id" if owner_kind == "fact"
                    else "semantic_event_id")
    select_columns = [
        "semantic_event_id", "display_name", "misreport",
        "request_id", "created_at", "feedback_id",
    ]
    if "fact_event_id" in columns:
        select_columns.insert(0, "fact_event_id")
    selected = ", ".join(select_columns)
    rows = conn.execute(
        f"SELECT {selected} FROM ("
        f"   SELECT {selected}"
        "     FROM win11_event_feedback"
        f"    WHERE {owner_column}=?"
        "    ORDER BY feedback_id DESC LIMIT ?"
        ") AS feedback_window ORDER BY feedback_id ASC",
        (event_id, limit)).fetchall()
    return [_row(row, owner_kind) for row in rows]


def get_feedback_summary(conn: sqlite3.Connection, event_id: str, *,
                         owner_kind: str = "semantic"
                         ) -> dict[str, Any] | None:
    """Read the latest non-null name and misreport for one owner."""
    if owner_kind not in _OWNER_KINDS:
        return None
    if not _valid_id(event_id, "event_id"):
        return None
    if not _table_exists(conn):
        return None
    if _REQUIRED_COLUMNS[owner_kind] - _table_columns(conn):
        return None
    owner_column = ("fact_event_id" if owner_kind == "fact"
                    else "semantic_event_id")
    name_row = conn.execute(
        "SELECT display_name FROM win11_event_feedback"
        f" WHERE {owner_column}=? AND display_name IS NOT NULL"
        " ORDER BY feedback_id DESC LIMIT 1", (event_id,)).fetchone()
    misreport_row = conn.execute(
        "SELECT misreport FROM win11_event_feedback"
        f" WHERE {owner_column}=? AND misreport IS NOT NULL"
        " ORDER BY feedback_id DESC LIMIT 1", (event_id,)).fetchone()
    return {
        "display_name": name_row[0] if name_row is not None else None,
        "misreport": (None if misreport_row is None
                      else bool(misreport_row[0])),
    }
