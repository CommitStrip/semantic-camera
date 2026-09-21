"""Linux replay frozen SQLite semantic event exporter.

Read-only export of the eight fact fields from ``semantic_events`` in a
frozen replay SQLite database, as a deterministic UTF-8 JSON array that
``scam.linux_replay_compare`` can consume directly.  Strictly read-only:
immutable/query-only connection, fail-closed on ``-wal``/``-shm``
companions, no subprocess, no network, no file writes.  Exporting facts
never implies replay execution or any gate passing.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sqlite3
import stat
import sys
from pathlib import Path

SCHEMA = "scam.linux-replay-export/v1"
FACT_FIELDS = ("camera", "template", "zone_id", "cls", "state",
               "t_start", "t_end", "end_reason")
TEXT_FIELDS = ("camera", "template", "state")
NULLABLE_TEXT_FIELDS = ("zone_id", "cls", "end_reason")
TIME_FIELDS = ("t_start", "t_end")


def _check_db_file(path, errors):
    """The database must be a plain regular file with no -wal/-shm
    companions: only a fully checkpointed frozen snapshot is accepted."""
    try:
        info = os.lstat(path)
    except OSError:
        errors.append("db: missing")
        return None
    if stat.S_ISLNK(info.st_mode):
        errors.append("db: symlink is not accepted")
        return None
    if not stat.S_ISREG(info.st_mode):
        errors.append("db: not a regular file")
        return None
    for suffix in ("-wal", "-shm"):
        companion = str(path) + suffix
        try:
            os.lstat(companion)
            errors.append(
                f"db: uncheckpointed {suffix} companion exists; "
                "refusing to treat the database as frozen")
            return None
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(
                f"db: cannot inspect {suffix} companion "
                f"({type(exc).__name__})")
            return None
    return info


def _snapshot(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _open_readonly_nofollow(path):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags)


def _connect_readonly(path, before, errors):
    """Keep a verified descriptor open while SQLite reads the snapshot.

    Linux connects through /proc/self/fd so SQLite cannot follow a path
    swapped after lstat.  Other platforms retain the descriptor and use
    before/after identity checks (Windows also prevents replacement of the
    open file in the ordinary case).
    """
    try:
        fd = _open_readonly_nofollow(path)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) \
                or _snapshot(opened) != _snapshot(before):
            errors.append("db: changed while opening")
            os.close(fd)
            return None, None
        connect_path = (f"/proc/self/fd/{fd}"
                        if sys.platform == "linux" else os.path.abspath(path))
        uri = Path(connect_path).as_uri() + "?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True)
        connection.execute("PRAGMA query_only = ON")
        return connection, fd
    except (OSError, sqlite3.DatabaseError) as exc:
        errors.append(f"db: cannot open frozen SQLite ({type(exc).__name__})")
        try:
            os.close(fd)
        except (OSError, UnboundLocalError):
            pass
        return None, None


def _export_rows(path, before, errors):
    connection, fd = _connect_readonly(path, before, errors)
    if connection is None:
        return None
    try:
        table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='semantic_events'").fetchone()
        if table is None:
            errors.append("db: table semantic_events missing")
            return None
        columns = {row[1] for row in
                   connection.execute("PRAGMA table_info(semantic_events)")}
        missing = [field for field in FACT_FIELDS if field not in columns]
        if missing:
            errors.append(
                "db: semantic_events missing columns " + "/".join(missing))
            return None
        selected = ", ".join(FACT_FIELDS)
        rows = connection.execute(
            f"SELECT {selected} FROM semantic_events").fetchall()
        try:
            after = os.lstat(path)
        except OSError as exc:
            errors.append(f"db: changed while reading ({type(exc).__name__})")
            return None
        if _snapshot(after) != _snapshot(before):
            errors.append("db: changed while reading")
            return None
    except sqlite3.DatabaseError as exc:
        errors.append(f"db: unreadable SQLite ({type(exc).__name__})")
        return None
    finally:
        connection.close()
        os.close(fd)

    events = []
    for index, row in enumerate(rows):
        record = dict(zip(FACT_FIELDS, row))
        where = f"db: row[{index}]"
        for field in TEXT_FIELDS:
            value = record[field]
            if value is None:
                errors.append(f"{where}: {field} must not be null")
                return None
            if not isinstance(value, str):
                errors.append(f"{where}: {field} must be text")
                return None
            record[field] = value
        for field in NULLABLE_TEXT_FIELDS:
            value = record[field]
            if value is not None and not isinstance(value, str):
                errors.append(f"{where}: {field} must be text or null")
                return None
            record[field] = value
        for field in TIME_FIELDS:
            value = record[field]
            if value is None:
                if field != "t_end":
                    errors.append(f"{where}: {field} must not be null")
                    return None
                continue
            if not isinstance(value, (int, float)) \
                    or isinstance(value, bool) or not math.isfinite(value):
                errors.append(
                    f"{where}: {field} must be a finite number or null")
                return None
            record[field] = float(value)
        events.append(record)
    return events


def export_events(db_path):
    """Export the frozen fact array; returns (events, errors)."""
    errors = []
    before = _check_db_file(db_path, errors)
    if before is None:
        return None, errors
    events = _export_rows(db_path, before, errors)
    if errors:
        return None, errors
    events.sort(key=lambda event: json.dumps(
        event, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return events, errors


def _error_payload(errors):
    return {
        "schema": SCHEMA,
        "kind": "semantic_event_export_error",
        "errors": errors,
        "replay_executed": False,
        "quality_gate_passed": None,
        "release_gate_passed": None,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="只读导出冻结SQLite中的语义事件事实（零子进程/零网络/"
                    "零写文件；不代表任何门禁通过）")
    parser.add_argument("--db", required=True)
    args = parser.parse_args(argv)

    events, errors = export_events(args.db)
    if events is None:
        json.dump(_error_payload(errors), sys.stderr, ensure_ascii=False)
        sys.stderr.write("\n")
        return 1
    print(json.dumps(events, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
