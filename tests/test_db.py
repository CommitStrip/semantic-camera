"""SQLite 持久层测试（参数绑定/建表/幂等）。"""

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
    assert {"events", "segments", "patterns", "pattern_embeddings", "meta"} <= names
