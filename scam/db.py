"""db.py —— SQLite 持久层（事件/分段/模式/嵌入档案/元数据）。

纪律：全部查询参数绑定（禁止拼接/format/f-string 组装 SQL）；
每事件独立行、即用即归档——上下文永不堆积在内存。
"""

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  event_id   TEXT PRIMARY KEY,
  camera     TEXT NOT NULL,
  kind       TEXT NOT NULL,            -- alert | record | misreport-mark
  t_processed TEXT NOT NULL,
  t_source   REAL,
  cls        TEXT,
  conf       REAL,
  zone_id    TEXT,
  template   TEXT,
  short_name TEXT,
  detail     TEXT,                     -- 细节描述（不设字数上限）
  rationale  TEXT,
  payload    TEXT                      -- 完整证据 JSON
);
CREATE INDEX IF NOT EXISTS idx_events_camera_time
  ON events (camera, t_processed);

CREATE TABLE IF NOT EXISTS segments (
  segment_id TEXT PRIMARY KEY,
  camera     TEXT NOT NULL,
  t_start    TEXT NOT NULL,
  t_end      TEXT,
  signature  TEXT,
  detail     TEXT,
  payload    TEXT
);

CREATE TABLE IF NOT EXISTS patterns (
  pattern_id TEXT PRIMARY KEY,
  camera     TEXT,
  signature  TEXT,
  name       TEXT,
  detail     TEXT,                     -- 首次细节描述，习惯化命中复用
  state      TEXT NOT NULL DEFAULT 'draft',  -- draft | model-verified | human-verified
  count      INTEGER NOT NULL DEFAULT 0,
  version    INTEGER NOT NULL DEFAULT 1,
  payload    TEXT
);

CREATE TABLE IF NOT EXISTS pattern_embeddings (
  pattern_id TEXT NOT NULL,
  modality   TEXT NOT NULL,            -- DAY-COLOR | NIGHT-BW | NIGHT-LIT
  centroid   BLOB NOT NULL,            -- float32 向量字节
  dim        INTEGER NOT NULL,
  n          INTEGER NOT NULL,
  PRIMARY KEY (pattern_id, modality),
  FOREIGN KEY (pattern_id) REFERENCES patterns(pattern_id)
);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS zones (
  camera TEXT PRIMARY KEY,
  data   TEXT NOT NULL                -- JSON 序列化的区域配置
);
"""


def connect(path):
    """打开 SQLite 连接（行以 dict 访问）。"""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_schema(conn):
    """建表（幂等）。"""
    conn.executescript(SCHEMA)
    conn.commit()


def insert_event(conn, *, event_id, camera, kind, t_processed, t_source=None,
                 cls=None, conf=None, zone_id=None, template=None,
                 short_name=None, detail=None, rationale=None, payload=None):
    """写入事件（全部参数绑定）。event_id 冲突时忽略（幂等）。"""
    conn.execute(
        "INSERT OR IGNORE INTO events"
        " (event_id, camera, kind, t_processed, t_source, cls, conf,"
        "  zone_id, template, short_name, detail, rationale, payload)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (event_id, camera, kind, t_processed, t_source, cls, conf,
         zone_id, template, short_name, detail, rationale, payload),
    )
    conn.commit()
