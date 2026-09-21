"""LC-020 冻结 SQLite 语义事件导出器测试。

覆盖确定性导出、重复/null 保留、运行期 ID 不外泄、缺表/缺列/坏类型/
非有限时间拒绝、WAL/SHM 与软链接 fail-closed、输入数据库哈希与 mtime
不变、CLI 退出码与诚实字段。合成数据库，不代表任何真实 Linux 主机、
replay 执行或门禁通过。
"""

import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest

from scam.linux_replay_export import SCHEMA, main
from scam.linux_replay_compare import main as compare_main

_CREATE_TABLE = """
CREATE TABLE semantic_events (
    semantic_event_id TEXT PRIMARY KEY,
    review_id TEXT,
    object_id TEXT,
    camera TEXT,
    template TEXT NOT NULL,
    zone_id TEXT,
    cls TEXT,
    state TEXT NOT NULL,
    t_start REAL NOT NULL,
    t_end REAL,
    end_reason TEXT
)
"""

_INSERT_SQL = (
    "INSERT INTO semantic_events (semantic_event_id, review_id, object_id, "
    "camera, template, zone_id, cls, state, t_start, t_end, end_reason) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")


def _default_rows():
    fact_a = ("front", "person_enter_yard", "yard", "person", "active",
              100.0, 145.5, "ended")
    fact_b = ("back", "person_loiter", "gate", "person", "active",
              200.0, None, None)
    return [("ev:1", "rev:1", "obj:1", *fact_a),
            ("ev:2", "rev:2", "obj:2", *fact_a),  # 与 ev:1 事实完全相同
            ("ev:3", "rev:3", "obj:3", *fact_b)]


def _make_db(tmp_path, name="run.db", rows=None, create=True):
    db_path = Path(tmp_path) / name
    connection = sqlite3.connect(str(db_path))
    if create:
        connection.executescript(_CREATE_TABLE)
        connection.executemany(_INSERT_SQL,
                               rows if rows is not None else _default_rows())
        connection.commit()
    connection.close()
    return str(db_path)


def _snapshot(path):
    info = os.stat(path)
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return digest, info.st_mtime_ns


def _run_main(args):
    import contextlib
    import io
    out_buf, err_buf = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out_buf), \
            contextlib.redirect_stderr(err_buf):
        code = main(args)
    return code, out_buf.getvalue(), err_buf.getvalue()


def _run_json(args):
    code, out, _ = _run_main(args)
    return code, (json.loads(out) if out else None)


def _run_error(args):
    code, _, err = _run_main(args)
    return code, (json.loads(err) if err else None)


# ---------- 1. 确定性导出：重复保留、null 保留、运行期 ID 不外泄 ----------

def test_export_deterministic_with_duplicates_nulls_and_no_runtime_ids(
        tmp_path):
    db_path = _make_db(tmp_path)

    code, facts = _run_json(["--db", db_path])
    assert code == 0
    assert len(facts) == 3
    assert facts[0]["t_end"] is None and facts[0]["end_reason"] is None
    duplicates = [f for f in facts if f["camera"] == "front"]
    assert len(duplicates) == 2
    text = json.dumps(facts, ensure_ascii=False)
    assert "semantic_event_id" not in text
    assert "review_id" not in text and "object_id" not in text
    assert str(tmp_path) not in text  # 只输出事实字段与文件名，无绝对路径

    # 顺序确定：两次导出（除时间戳）逐字段一致
    code2, out2, _ = _run_main(["--db", db_path])
    assert code2 == 0
    second = json.loads(out2)
    assert second == facts

    # CLI output is the array contract consumed directly by queue K.
    exported = tmp_path / "exported.json"
    exported.write_text(out2, encoding="utf-8")
    assert compare_main(
        ["--expected", str(exported), "--actual", str(exported)]) == 0


def test_nullable_zone_class_and_open_event_are_preserved(tmp_path):
    db_path = _make_db(tmp_path, name="nullable.db", rows=[
        ("ev:1", None, None, "front", "motion", None, None, "open",
         1.0, None, None)])

    code, facts = _run_json(["--db", db_path])

    assert code == 0
    assert facts == [{"camera": "front", "template": "motion",
                      "zone_id": None, "cls": None, "state": "open",
                      "t_start": 1.0, "t_end": None,
                      "end_reason": None}]


# ---------- 2. 输入数据库哈希与 mtime 不变 ----------

def test_input_database_unchanged_after_export(tmp_path):
    db_path = _make_db(tmp_path)
    before = _snapshot(db_path)

    code, _ = _run_json(["--db", db_path])
    assert code == 0

    assert _snapshot(db_path) == before


# ---------- 3. 缺表 / 缺列 / 坏类型 / 非有限时间 / 非法 null ----------

def test_missing_table_rejected(tmp_path):
    db_path = _make_db(tmp_path, name="empty.db", create=False)
    code, error = _run_error(["--db", db_path])
    assert code == 1
    assert "db: table semantic_events missing" in error["errors"]
    assert error["quality_gate_passed"] is None


def test_missing_column_rejected(tmp_path):
    db_path = str(tmp_path / "nocol.db")
    connection = sqlite3.connect(db_path)
    connection.executescript(
        "CREATE TABLE semantic_events (camera TEXT, template TEXT)")
    connection.commit()
    connection.close()

    code, error = _run_error(["--db", db_path])
    assert code == 1
    assert any("missing columns" in err for err in error["errors"])


def test_bad_type_and_nonfinite_and_illegal_null_rejected(tmp_path):
    db_path = _make_db(tmp_path, name="badtype.db", rows=[
        ("ev:1", "rev:1", "obj:1", sqlite3.Binary(b"\x00blob"), "t", "z",
         "person", "active", 1.0, None, None)])
    code, error = _run_error(["--db", db_path])
    assert code == 1
    assert any("camera must be text" in err for err in error["errors"])

    db_path = _make_db(tmp_path, name="nonfinite.db", rows=[
        ("ev:1", "rev:1", "obj:1", "front", "t", "z", "person", "active",
         float("inf"), None, None)])
    code, error = _run_error(["--db", db_path])
    assert code == 1
    assert any("t_start must be a finite number" in err
               for err in error["errors"])

    db_path = _make_db(tmp_path, name="illegalnull.db", rows=[
        ("ev:1", "rev:1", "obj:1", None, "t", "z", "person", "active",
         1.0, None, None)])
    code, error = _run_error(["--db", db_path])
    assert code == 1
    assert any("camera must not be null" in err for err in error["errors"])


# ---------- 4. WAL/SHM 伴随文件 fail-closed 与软链接拒绝 ----------

def test_wal_and_shm_companions_fail_closed(tmp_path):
    db_path = _make_db(tmp_path, name="wal.db")
    Path(db_path + "-wal").write_bytes(b"pending")
    code, error = _run_error(["--db", db_path])
    assert code == 1
    assert any("-wal" in err and "frozen" in err for err in error["errors"])

    db_path = _make_db(tmp_path, name="shm.db")
    Path(db_path + "-shm").write_bytes(b"index")
    code, error = _run_error(["--db", db_path])
    assert code == 1
    assert any("-shm" in err and "frozen" in err for err in error["errors"])


def test_symlink_db_rejected(tmp_path):
    real = tmp_path / "real.db"
    real.write_bytes(b"not-a-real-db-but-regular")
    link = tmp_path / "link.db"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("当前环境不允许创建符号链接")
    code, error = _run_error(["--db", str(link)])
    assert code == 1
    assert any("symlink" in err for err in error["errors"])


def test_missing_db_rejected(tmp_path):
    code, error = _run_error(["--db", str(tmp_path / "gone.db")])
    assert code == 1
    assert "db: missing" in error["errors"]


def test_invalid_regular_file_reports_structured_error(tmp_path):
    invalid = tmp_path / "invalid.db"
    invalid.write_bytes(b"not sqlite")

    code, error = _run_error(["--db", str(invalid)])

    assert code == 1
    assert error["kind"] == "semantic_event_export_error"
    assert any("SQLite" in message for message in error["errors"])


# ---------- 5. CLI 参数错误 ----------

def test_cli_missing_argument_fails_nonzero():
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code != 0
