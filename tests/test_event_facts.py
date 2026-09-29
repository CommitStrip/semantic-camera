"""事件事实层（event_facts）测试：迁移加固、幂等 CRUD、迟后关联、恢复层、证据诚实。

对应事件合同 v1.1 五条硬边界的存储层部分。全部为进程内合成测试，
不代表 Win11/Linux 真实输入、质量或发布证据。
"""

import sqlite3

import pytest

import scam.db as db
from scam.db import (
    SCHEMA_VERSION,
    close_event_fact,
    connect,
    event_evidence_from_assets,
    finalize_snapshot_records,
    init_schema,
    link_event_escalation,
    link_event_review,
    open_event_fact,
    recover_stale_records,
    refresh_event_fact_evidence,
    snapshot_pending_recovery,
    update_event_fact,
)

# 真实 v3 形状的四张核心表（迁移的旧库夹具）；其余 v3 表由迁移自建。
_LEGACY_V3_DDL = """
CREATE TABLE events (
  event_id TEXT PRIMARY KEY, camera TEXT NOT NULL, kind TEXT NOT NULL,
  t_processed TEXT NOT NULL, t_source REAL, cls TEXT, conf REAL,
  zone_id TEXT, template TEXT, short_name TEXT, detail TEXT,
  rationale TEXT, payload TEXT);
CREATE TABLE tracked_objects (
  object_id TEXT PRIMARY KEY, camera TEXT NOT NULL, t_start REAL NOT NULL,
  t_last REAL NOT NULL, t_end REAL, end_reason TEXT, cls TEXT NOT NULL,
  max_conf REAL, zones TEXT NOT NULL DEFAULT '[]', review_id TEXT,
  best_frame_path TEXT, best_frame_t REAL, payload TEXT,
  CHECK (t_last >= t_start), CHECK (t_end IS NULL OR t_end >= t_start));
CREATE INDEX idx_legacy_to_ct ON tracked_objects (camera, t_start DESC);
CREATE INDEX idx_legacy_to_open ON tracked_objects (camera, t_end)
  WHERE t_end IS NULL;
CREATE TABLE review_segments (
  review_id TEXT PRIMARY KEY, camera TEXT NOT NULL, t_start REAL NOT NULL,
  t_last REAL NOT NULL, t_end REAL, end_reason TEXT,
  severity TEXT NOT NULL DEFAULT 'detection',
  reviewed INTEGER NOT NULL DEFAULT 0,
  object_ids TEXT NOT NULL DEFAULT '[]',
  semantic_event_ids TEXT NOT NULL DEFAULT '[]', payload TEXT,
  CHECK (severity IN ('motion','detection','alert')),
  CHECK (t_last >= t_start), CHECK (t_end IS NULL OR t_end >= t_start));
CREATE UNIQUE INDEX idx_legacy_rs_one ON review_segments (camera)
  WHERE t_end IS NULL;
CREATE TABLE semantic_events (
  semantic_event_id TEXT PRIMARY KEY, camera TEXT NOT NULL, review_id TEXT,
  object_id TEXT, t_start REAL NOT NULL, t_last REAL NOT NULL, t_end REAL,
  end_reason TEXT, state TEXT NOT NULL DEFAULT 'open', zone_id TEXT,
  template TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'medium',
  cls TEXT, conf REAL, short_name TEXT, detail TEXT, rationale TEXT,
  evidence_state TEXT NOT NULL DEFAULT 'metadata_only',
  best_frame_path TEXT, payload TEXT,
  CHECK (state IN ('open','closed')), CHECK (t_last >= t_start),
  CHECK (t_end IS NULL OR t_end >= t_start));
INSERT INTO tracked_objects VALUES
  ('old-obj', 'front', 1.0, 2.0, NULL, NULL, 'person', 0.7, '[]',
   NULL, NULL, NULL, NULL);
INSERT INTO semantic_events VALUES
  ('old-sem', 'front', NULL, 'old-obj', 1.0, 2.0, NULL, NULL, 'open',
   NULL, 'enter-dwell', 'medium', 'person', 0.7, NULL, NULL, NULL,
   'metadata_only', NULL, NULL);
"""


def _conn(tmp_path, name="t.db"):
    conn = connect(str(tmp_path / name))
    return conn


def _seed_object(conn, object_id, camera="front"):
    """事件必须引用已落库的对象事实（边界2强约束）；测试统一先种对象行。"""
    db.open_tracked_object(conn, object_id=object_id, camera=camera,
                           t_start=1.0, cls="person")


# ---------- 迁移加固（合同 v1.1 边界5） ----------

def test_init_creates_v4_schema_with_event_tables(tmp_path):
    conn = _conn(tmp_path)
    init_schema(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    tables = {row["name"] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"event_facts", "event_descriptions", "event_notifications",
            "event_escalations"} <= tables


def test_legacy_v3_database_upgrades_without_touching_rows(tmp_path):
    path = str(tmp_path / "legacy.db")
    legacy = sqlite3.connect(path)
    legacy.executescript(_LEGACY_V3_DDL + "\nPRAGMA user_version=3;")
    legacy.commit()
    legacy.close()

    conn = connect(path)
    init_schema(conn)

    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    obj = conn.execute(
        "SELECT * FROM tracked_objects WHERE object_id='old-obj'").fetchone()
    assert obj["t_start"] == 1.0 and obj["t_last"] == 2.0
    assert obj["cls"] == "person" and obj["t_end"] is None
    sem = conn.execute(
        "SELECT template,state FROM semantic_events"
        " WHERE semantic_event_id='old-sem'").fetchone()
    assert sem["template"] == "enter-dwell" and sem["state"] == "open"
    # 旧数据零回填：不拿旧规则告警冒充事件事实
    assert conn.execute("SELECT COUNT(*) c FROM event_facts").fetchone()["c"] == 0


def test_reinit_is_idempotent(tmp_path):
    conn = _conn(tmp_path)
    init_schema(conn)
    _seed_object(conn, "o1")
    open_event_fact(conn, event_id="e1", camera="front", object_id="o1",
                    t_start=1.0, cls="person")
    init_schema(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_facts").fetchone()["c"] == 1


def test_higher_schema_version_refused(tmp_path):
    conn = _conn(tmp_path)
    conn.execute("PRAGMA user_version=99")
    with pytest.raises(RuntimeError, match="拒绝降级"):
        init_schema(conn)


def test_malformed_table_fails_loudly_and_rolls_back(tmp_path):
    path = str(tmp_path / "bad.db")
    raw = sqlite3.connect(path)
    raw.execute("CREATE TABLE event_facts (event_id TEXT PRIMARY KEY)")
    raw.execute("PRAGMA user_version=3")
    raw.commit()
    raw.close()

    conn = connect(path)
    with pytest.raises(Exception):
        init_schema(conn)
    # 回滚核验：旧库原样——版本未动、残缺表未被半改
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
    cols = [row["name"] for row in conn.execute(
        "SELECT name FROM pragma_table_info('event_facts')")]
    assert cols == ["event_id"]


def test_missing_column_after_migration_caught_by_verification(tmp_path):
    """结构校验直接命中：表存在但缺列时启动报错，不得静默成功。"""
    conn = _conn(tmp_path)
    init_schema(conn)
    conn.execute("CREATE TABLE event_facts_broken (event_id TEXT PRIMARY KEY)")
    # 偷换校验目标不可行；直接构造缺列表替换真表路径
    conn.execute("DROP TABLE event_escalations")
    conn.execute(
        "CREATE TABLE event_escalations (event_id TEXT NOT NULL)")
    conn.commit()
    with pytest.raises(RuntimeError, match="结构校验失败"):
        init_schema(conn)


# ---------- 幂等 CRUD ----------

def test_open_event_fact_is_idempotent_and_never_resets_start(tmp_path):
    conn = _conn(tmp_path)
    init_schema(conn)
    _seed_object(conn, "o1")
    open_event_fact(conn, event_id="e1", camera="front", object_id="o1",
                    t_start=100.0, cls="person", conf=0.8,
                    bbox_first=[1, 2, 3, 4], bbox_last=[1, 2, 3, 4])
    _seed_object(conn, "o1")
    open_event_fact(conn, event_id="e1", camera="front", object_id="o1",
                    t_start=50.0, cls="person", conf=0.9,
                    bbox_last=[5, 6, 7, 8])
    row = conn.execute(
        "SELECT * FROM event_facts WHERE event_id='e1'").fetchone()
    assert row["t_start"] == 100.0, "重复 open 不得重置起点"
    assert row["t_last"] == 100.0
    assert row["max_conf"] == 0.9
    assert row["bbox_last"] == "[5,6,7,8]"


def test_close_pins_end_to_last_observation(tmp_path):
    """合同边界3：t_end 固定取记录自身 t_last，不接受更晚处理时间冒充。"""
    conn = _conn(tmp_path)
    init_schema(conn)
    _seed_object(conn, "o1")
    open_event_fact(conn, event_id="e1", camera="front", object_id="o1",
                    t_start=100.0, cls="person")
    update_event_fact(conn, "e1", t_last=110.0)
    assert close_event_fact(conn, "e1", reason="track-lost") is True
    row = conn.execute(
        "SELECT t_end,t_last,end_reason,state FROM event_facts"
        " WHERE event_id='e1'").fetchone()
    assert row["t_end"] == 110.0 == row["t_last"]
    assert row["state"] == "closed" and row["end_reason"] == "track-lost"
    # 幂等：二次闭合零改动
    assert close_event_fact(conn, "e1", reason="other") is False


def test_link_event_review_is_deferred_and_fill_once(tmp_path):
    """合同边界1：事件先落库，审查段后落库时只填空、不覆写。"""
    conn = _conn(tmp_path)
    init_schema(conn)
    _seed_object(conn, "o1")
    open_event_fact(conn, event_id="e1", camera="front", object_id="o1",
                    t_start=1.0, cls="person")
    row = conn.execute(
        "SELECT review_id FROM event_facts WHERE event_id='e1'").fetchone()
    assert row["review_id"] is None
    assert link_event_review(conn, "e1", "rev-1") is True
    assert link_event_review(conn, "e1", "rev-2") is False, "已有关联不得覆写"
    row = conn.execute(
        "SELECT review_id FROM event_facts WHERE event_id='e1'").fetchone()
    assert row["review_id"] == "rev-1"


def test_link_event_escalation_is_idempotent(tmp_path):
    conn = _conn(tmp_path)
    init_schema(conn)
    _seed_object(conn, "o1")
    open_event_fact(conn, event_id="e1", camera="front", object_id="o1",
                    t_start=1.0, cls="person")
    link_event_escalation(conn, event_id="e1", semantic_event_id="s1",
                          t_linked=2.0)
    link_event_escalation(conn, event_id="e1", semantic_event_id="s1",
                          t_linked=3.0)
    rows = conn.execute("SELECT * FROM event_escalations").fetchall()
    assert len(rows) == 1 and rows[0]["semantic_event_id"] == "s1"


# ---------- 恢复层（F8 同一纪律扩展到事件事实） ----------

def test_recovery_covers_event_facts(tmp_path):
    conn = _conn(tmp_path)
    init_schema(conn)
    # 陈旧开放事件：直接收口
    _seed_object(conn, "o1")
    open_event_fact(conn, event_id="stale", camera="front", object_id="o1",
                    t_start=10.0, cls="person")
    update_event_fact(conn, "stale", t_last=20.0)
    # 新鲜开放事件：进快照、CAS 收口
    _seed_object(conn, "o2")
    open_event_fact(conn, event_id="fresh", camera="front", object_id="o2",
                    t_start=200.0, cls="person")
    update_event_fact(conn, "fresh", t_last=990.0)

    counts = recover_stale_records(conn, now=1000.0, stale_after_s=30.0)
    assert counts["event_facts"] == 1
    snapshot = snapshot_pending_recovery(conn, now=1000.0, stale_after_s=30.0)
    event_keys = {item["key"] for item in snapshot
                  if item["layer"] == "event_facts"}
    assert event_keys == {"fresh"}

    assert finalize_snapshot_records(conn, snapshot)["event_facts"] == 1
    assert finalize_snapshot_records(conn, snapshot)["event_facts"] == 0, \
        "重复复核必须幂等"
    row = conn.execute(
        "SELECT state,end_reason FROM event_facts WHERE event_id='fresh'"
    ).fetchone()
    assert row["state"] == "closed"
    assert row["end_reason"] == "recovered_after_restart"


def test_snapshot_cas_survives_only_unchanged_records(tmp_path):
    """快照后被续写的事件是活事实：CAS 不匹配，复核不得收口。"""
    conn = _conn(tmp_path)
    init_schema(conn)
    _seed_object(conn, "o1")
    open_event_fact(conn, event_id="live", camera="front", object_id="o1",
                    t_start=1.0, cls="person")
    update_event_fact(conn, "live", t_last=95.0)
    snapshot = snapshot_pending_recovery(conn, now=100.0, stale_after_s=30.0)

    update_event_fact(conn, "live", t_last=99.0)   # 新实例续写

    assert finalize_snapshot_records(conn, snapshot)["event_facts"] == 0
    assert conn.execute(
        "SELECT t_end FROM event_facts WHERE event_id='live'"
    ).fetchone()["t_end"] is None


# ---------- 证据诚实（合同 v1.1 边界5） ----------

def _seed_asset(conn, *, asset_id, state, path="/evidence/a.jpg"):
    conn.execute(
        "INSERT INTO evidence_assets (asset_id,owner_type,owner_id,camera,"
        " kind,path,state,mime,size_bytes,sha256,created_at,updated_at)"
        " VALUES (?,'tracked_object','o1','front','clean_best_frame',"
        " ?,?,'image/jpeg',10,'ab',1.0,1.0)"
        " ON CONFLICT(owner_type,owner_id,kind) DO UPDATE SET"
        " asset_id=excluded.asset_id, path=excluded.path,"
        " state=excluded.state",
        (asset_id, path, state))
    conn.commit()


def test_evidence_state_requires_available_asset(tmp_path):
    conn = _conn(tmp_path)
    init_schema(conn)
    _seed_object(conn, "o1")
    open_event_fact(conn, event_id="e1", camera="front", object_id="o1",
                    t_start=1.0, cls="person")
    assert event_evidence_from_assets(conn, "o1") == ("metadata_only", None)

    _seed_asset(conn, asset_id="a-missing", state="missing")
    assert event_evidence_from_assets(conn, "o1") == ("metadata_only", None), \
        "路径存在但资产缺失时不得声称图片可用"
    # 证据缺失的事件行本身也不得携带可回看图片引用
    _seed_object(conn, "o1")
    open_event_fact(conn, event_id="e-noev", camera="front", object_id="o1",
                    t_start=2.0, cls="person")
    noev = conn.execute(
        "SELECT evidence_state,best_frame_path FROM event_facts"
        " WHERE event_id='e-noev'").fetchone()
    assert noev["evidence_state"] == "metadata_only"
    assert noev["best_frame_path"] is None, "无可用资产就没有可回看图片"

    _seed_asset(conn, asset_id="a-ok", state="available")
    state, path = event_evidence_from_assets(conn, "o1")
    assert state == "image_only" and path == "/evidence/a.jpg"

    assert refresh_event_fact_evidence(
        conn, "e1", evidence_state="image_only",
        best_frame_path=path) is True
    # 只升不降：metadata_only 的重放不得降级已有证据
    assert refresh_event_fact_evidence(
        conn, "e1", evidence_state="metadata_only") is False
    row = conn.execute(
        "SELECT evidence_state,best_frame_path FROM event_facts"
        " WHERE event_id='e1'").fetchone()
    assert row["evidence_state"] == "image_only"
    assert row["best_frame_path"] == "/evidence/a.jpg"


# ---------- 对象外键守卫（复验边界2：等价可验证强约束） ----------

def test_object_guard_rejects_orphan_event(tmp_path):
    """对象事实不存在时，事件不得落库且连接不残留事务——不允许孤儿事件。"""
    conn = _conn(tmp_path)
    init_schema(conn)
    # 守卫拒绝：如实返回 False（内部回滚，无残留事务），而非抛异常
    assert open_event_fact(conn, event_id="e-orphan", camera="front",
                           object_id="ghost-object", t_start=1.0,
                           cls="person") is False
    assert conn.in_transaction is False, "失败路径不得留下未结束事务"
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_facts").fetchone()["c"] == 0

    _seed_object(conn, "o1")
    assert open_event_fact(conn, event_id="e-ok", camera="front",
                           object_id="o1", t_start=1.0, cls="person") is True
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_facts").fetchone()["c"] == 1


def test_legacy_v4_database_gains_guard_triggers_without_rebuild(tmp_path):
    """复验边界2：既有 v4 候选库打开即获得守卫触发器——不重建表、数据零搬移。"""
    path = str(tmp_path / "v4.db")
    raw = sqlite3.connect(path)
    raw.execute("PRAGMA user_version=4")   # 只造版本号：表由 v5 SCHEMA 补齐
    raw.commit()
    raw.close()
    conn = connect(path)
    init_schema(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION

    # 建一条真实数据后再升级路径核验：先回退触发器模拟旧 v4 库形态
    db.open_tracked_object(conn, object_id="o1", camera="front",
                           t_start=1.0, cls="person")
    _seed_object(conn, "o1")
    open_event_fact(conn, event_id="e1", camera="front", object_id="o1",
                    t_start=1.0, cls="person")
    conn.execute("DROP TRIGGER trg_event_facts_object_guard_ins")
    conn.execute("DROP TRIGGER trg_event_facts_object_guard_upd")
    conn.execute("PRAGMA user_version=4")
    conn.commit()

    init_schema(conn)   # v4 形态再次被 v5 程序打开
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    row = conn.execute(
        "SELECT event_id,object_id FROM event_facts"
        " WHERE event_id='e1'").fetchone()
    assert row["event_id"] == "e1" and row["object_id"] == "o1", \
        "升级不得改动既有数据"
    assert open_event_fact(conn, event_id="e-orphan", camera="front",
                           object_id="still-ghost", t_start=1.0,
                           cls="person") is False, "守卫对升级后的库同样生效"


def test_dropped_trigger_is_restored_by_next_init(tmp_path):
    """守卫触发器缺失（被人为删除）时，下一次启动必须自愈补齐。"""
    conn = _conn(tmp_path)
    init_schema(conn)
    conn.execute("DROP TRIGGER trg_event_facts_object_guard_ins")
    conn.commit()
    init_schema(conn)
    present = {row["name"] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger'")}
    assert "trg_event_facts_object_guard_ins" in present
