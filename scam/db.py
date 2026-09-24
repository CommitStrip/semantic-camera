"""db.py —— SQLite 持久层（事件真值/分段/模式/嵌入档案/元数据）。

纪律：全部查询参数绑定（禁止拼接/format/f-string 组装 SQL）；
每事件独立行、即用即归档——上下文永不堆积在内存。

共享事件真值分三层（Linux NVR 与 Win11 值守工作站共用）：
- tracked_objects：检测和跟踪的原始对象生命周期；
- review_segments：同一相机不重叠的活动审查时段；
- semantic_events：管理员区域和规则裁决出的业务事件。

三层不可互相冒充。录像和模型描述只增强证据，不决定语义事件是否成立。
"""

import json
import sqlite3

SCHEMA_VERSION = 3

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

CREATE TABLE IF NOT EXISTS tracked_objects (
  object_id       TEXT PRIMARY KEY,
  camera          TEXT NOT NULL,
  t_start         REAL NOT NULL,
  t_last          REAL NOT NULL,
  t_end           REAL,
  end_reason      TEXT,
  cls             TEXT NOT NULL,
  max_conf        REAL,
  zones           TEXT NOT NULL DEFAULT '[]',
  review_id       TEXT,
  best_frame_path TEXT,
  best_frame_t    REAL,
  payload         TEXT,
  CHECK (t_last >= t_start),
  CHECK (t_end IS NULL OR t_end >= t_start)
);
CREATE INDEX IF NOT EXISTS idx_tracked_objects_camera_time
  ON tracked_objects (camera, t_start DESC);
CREATE INDEX IF NOT EXISTS idx_tracked_objects_open
  ON tracked_objects (camera, t_end) WHERE t_end IS NULL;

CREATE TABLE IF NOT EXISTS review_segments (
  review_id          TEXT PRIMARY KEY,
  camera             TEXT NOT NULL,
  t_start            REAL NOT NULL,
  t_last             REAL NOT NULL,
  t_end              REAL,
  end_reason         TEXT,
  severity           TEXT NOT NULL DEFAULT 'detection',
  reviewed           INTEGER NOT NULL DEFAULT 0,
  object_ids         TEXT NOT NULL DEFAULT '[]',
  semantic_event_ids TEXT NOT NULL DEFAULT '[]',
  payload            TEXT,
  CHECK (severity IN ('motion', 'detection', 'alert')),
  CHECK (reviewed IN (0, 1)),
  CHECK (t_last >= t_start),
  CHECK (t_end IS NULL OR t_end >= t_start)
);
CREATE INDEX IF NOT EXISTS idx_review_segments_camera_time
  ON review_segments (camera, t_start DESC);
-- 一台相机最多一个开放审查段，从存储层阻止重叠活动容器。
CREATE UNIQUE INDEX IF NOT EXISTS idx_review_segments_one_open_per_camera
  ON review_segments (camera) WHERE t_end IS NULL;

CREATE TABLE IF NOT EXISTS semantic_events (
  semantic_event_id TEXT PRIMARY KEY,
  camera            TEXT NOT NULL,
  review_id         TEXT,
  object_id         TEXT,
  t_start           REAL NOT NULL,
  t_last            REAL NOT NULL,
  t_end             REAL,
  end_reason        TEXT,
  state             TEXT NOT NULL DEFAULT 'open',
  zone_id           TEXT,
  template          TEXT NOT NULL,
  severity          TEXT NOT NULL DEFAULT 'medium',
  cls               TEXT,
  conf              REAL,
  short_name        TEXT,
  detail            TEXT,
  rationale         TEXT,
  evidence_state    TEXT NOT NULL DEFAULT 'metadata_only',
  best_frame_path   TEXT,
  payload           TEXT,
  FOREIGN KEY (review_id) REFERENCES review_segments(review_id),
  FOREIGN KEY (object_id) REFERENCES tracked_objects(object_id),
  CHECK (state IN ('open', 'closed')),
  CHECK (severity IN ('low', 'medium', 'high')),
  CHECK (evidence_state IN ('metadata_only', 'image_only', 'full')),
  CHECK (t_last >= t_start),
  CHECK (t_end IS NULL OR t_end >= t_start)
);
CREATE INDEX IF NOT EXISTS idx_semantic_events_camera_time
  ON semantic_events (camera, t_start DESC);
CREATE INDEX IF NOT EXISTS idx_semantic_events_open
  ON semantic_events (camera, t_end) WHERE t_end IS NULL;

CREATE TABLE IF NOT EXISTS evidence_assets (
  asset_id    TEXT PRIMARY KEY,
  owner_type TEXT NOT NULL,
  owner_id   TEXT NOT NULL,
  camera     TEXT NOT NULL,
  kind       TEXT NOT NULL,
  path       TEXT NOT NULL,
  state      TEXT NOT NULL DEFAULT 'available',
  mime       TEXT NOT NULL,
  t_start    REAL,
  t_end      REAL,
  score      REAL,
  size_bytes INTEGER NOT NULL,
  sha256     TEXT NOT NULL,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  metadata   TEXT,
  UNIQUE (owner_type, owner_id, kind),
  CHECK (owner_type IN ('tracked_object', 'review_segment', 'semantic_event')),
  CHECK (kind IN ('clean_best_frame', 'recording_segment', 'event_clip')),
  CHECK (state IN ('available', 'missing', 'corrupt')),
  CHECK (size_bytes >= 0)
);
CREATE INDEX IF NOT EXISTS idx_evidence_owner
  ON evidence_assets (owner_type, owner_id);
CREATE INDEX IF NOT EXISTS idx_evidence_camera_time
  ON evidence_assets (camera, t_start DESC);

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
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_schema(conn):
    """幂等建表/迁移；拒绝打开由更高版本创建的数据库。"""
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    if current > SCHEMA_VERSION:
        raise RuntimeError(
            f"数据库版本 {current} 高于当前程序支持的 {SCHEMA_VERSION}，拒绝降级写入")
    conn.executescript(SCHEMA)
    conn.execute("PRAGMA user_version=3")
    conn.commit()


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def _merge_ids(raw, values):
    """合并 JSON id 数组，保持首次出现顺序并去重。"""
    try:
        current = json.loads(raw or "[]")
    except (TypeError, ValueError):
        current = []
    if not isinstance(current, list):
        current = []
    for value in values or []:
        if value and value not in current:
            current.append(value)
    return current


def open_tracked_object(conn, *, object_id, camera, t_start, cls, conf=None,
                        zones=None, review_id=None, payload=None):
    """幂等打开对象；重复调用只推进最近时间/置信度和证据，不重置起点。"""
    conn.execute(
        "INSERT INTO tracked_objects"
        " (object_id,camera,t_start,t_last,cls,max_conf,zones,review_id,payload)"
        " VALUES (?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(object_id) DO UPDATE SET"
        " t_last=MAX(tracked_objects.t_last,excluded.t_last),"
        " max_conf=MAX(COALESCE(tracked_objects.max_conf,0),"
        "              COALESCE(excluded.max_conf,0)),"
        " zones=excluded.zones,"
        " review_id=COALESCE(tracked_objects.review_id,excluded.review_id),"
        " payload=COALESCE(excluded.payload,tracked_objects.payload)"
        " WHERE tracked_objects.t_end IS NULL",
        (object_id, camera, t_start, t_start, cls, conf, _json(zones or []),
         review_id, _json(payload) if payload is not None else None))
    conn.commit()


def update_tracked_object(conn, object_id, *, t_last, conf=None, zones=None,
                          review_id=None, best_frame_path=None,
                          best_frame_t=None, payload=None):
    """更新开放对象。对象不存在或已闭合时返回 False。"""
    row = conn.execute(
        "SELECT zones FROM tracked_objects"
        " WHERE object_id=? AND t_end IS NULL", (object_id,)).fetchone()
    if row is None:
        return False
    merged_zones = _merge_ids(row["zones"], zones)
    cur = conn.execute(
        "UPDATE tracked_objects SET"
        " t_last=MAX(t_last,?),"
        " max_conf=MAX(COALESCE(max_conf,0),COALESCE(?,0)),"
        " zones=?, review_id=COALESCE(review_id,?),"
        " best_frame_path=COALESCE(?,best_frame_path),"
        " best_frame_t=COALESCE(?,best_frame_t),"
        " payload=COALESCE(?,payload)"
        " WHERE object_id=? AND t_end IS NULL",
        (t_last, conf, _json(merged_zones), review_id, best_frame_path,
         best_frame_t, _json(payload) if payload is not None else None,
         object_id))
    conn.commit()
    return cur.rowcount == 1


def close_tracked_object(conn, object_id, *, t_end, reason):
    """幂等闭合对象；已闭合记录保持第一次闭合事实。"""
    cur = conn.execute(
        "UPDATE tracked_objects SET t_last=MAX(t_last,?),"
        " t_end=MAX(t_last,?),end_reason=?"
        " WHERE object_id=? AND t_end IS NULL",
        (t_end, t_end, reason, object_id))
    conn.commit()
    return cur.rowcount == 1


def open_review_segment(conn, *, review_id, camera, t_start,
                        severity="detection", object_ids=None, payload=None):
    """打开同相机唯一审查段。数据库唯一索引阻止两个开放段并存。"""
    conn.execute(
        "INSERT INTO review_segments"
        " (review_id,camera,t_start,t_last,severity,object_ids,payload)"
        " VALUES (?,?,?,?,?,?,?)"
        " ON CONFLICT(review_id) DO UPDATE SET"
        " t_last=MAX(review_segments.t_last,excluded.t_last),"
        " severity=CASE"
        "   WHEN review_segments.severity='alert' THEN 'alert'"
        "   WHEN excluded.severity='alert' THEN 'alert'"
        "   WHEN review_segments.severity='detection' THEN 'detection'"
        "   ELSE excluded.severity END,"
        " payload=COALESCE(excluded.payload,review_segments.payload)"
        " WHERE review_segments.t_end IS NULL",
        (review_id, camera, t_start, t_start, severity,
         _json(object_ids or []),
         _json(payload) if payload is not None else None))
    conn.commit()


def update_review_segment(conn, review_id, *, t_last, severity=None,
                          object_ids=None, semantic_event_ids=None,
                          payload=None):
    """推进审查段，严重度只允许 motion→detection→alert 升级。"""
    row = conn.execute(
        "SELECT severity,object_ids,semantic_event_ids FROM review_segments"
        " WHERE review_id=? AND t_end IS NULL", (review_id,)).fetchone()
    if row is None:
        return False
    rank = {"motion": 0, "detection": 1, "alert": 2}
    next_severity = severity or row["severity"]
    if next_severity not in rank:
        raise ValueError(f"非法审查严重度: {next_severity}")
    upgraded = max((row["severity"], next_severity), key=rank.get)
    objects = _merge_ids(row["object_ids"], object_ids)
    events = _merge_ids(row["semantic_event_ids"], semantic_event_ids)
    cur = conn.execute(
        "UPDATE review_segments SET t_last=MAX(t_last,?),severity=?,"
        " object_ids=?,semantic_event_ids=?,payload=COALESCE(?,payload)"
        " WHERE review_id=? AND t_end IS NULL",
        (t_last, upgraded, _json(objects), _json(events),
         _json(payload) if payload is not None else None, review_id))
    conn.commit()
    return cur.rowcount == 1


def close_review_segment(conn, review_id, *, t_end, reason):
    """幂等闭合审查段。"""
    cur = conn.execute(
        "UPDATE review_segments SET t_last=MAX(t_last,?),"
        " t_end=MAX(t_last,?),end_reason=?"
        " WHERE review_id=? AND t_end IS NULL",
        (t_end, t_end, reason, review_id))
    conn.commit()
    return cur.rowcount == 1


def set_reviewed(conn, review_id, reviewed=True):
    cur = conn.execute(
        "UPDATE review_segments SET reviewed=? WHERE review_id=?",
        (1 if reviewed else 0, review_id))
    conn.commit()
    return cur.rowcount == 1


def open_semantic_event(conn, *, semantic_event_id, camera, review_id,
                        object_id, t_start, template, zone_id=None,
                        severity="medium", cls=None, conf=None,
                        short_name=None, detail=None, rationale=None,
                        evidence_state="metadata_only", best_frame_path=None,
                        payload=None):
    """写入管理员规则裁决结果；模型文本只能写描述字段，不能改原始证据。"""
    conn.execute(
        "INSERT INTO semantic_events"
        " (semantic_event_id,camera,review_id,object_id,t_start,t_last,"
        "  template,zone_id,severity,cls,conf,short_name,detail,rationale,"
        "  evidence_state,best_frame_path,payload)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(semantic_event_id) DO UPDATE SET"
        " t_last=MAX(semantic_events.t_last,excluded.t_last),"
        " conf=MAX(COALESCE(semantic_events.conf,0),COALESCE(excluded.conf,0)),"
        " payload=COALESCE(excluded.payload,semantic_events.payload)"
        " WHERE semantic_events.t_end IS NULL",
        (semantic_event_id, camera, review_id, object_id, t_start, t_start,
         template, zone_id, severity, cls, conf, short_name, detail, rationale,
         evidence_state, best_frame_path,
         _json(payload) if payload is not None else None))
    conn.commit()


def update_semantic_event(conn, semantic_event_id, *, t_last,
                          short_name=None, detail=None, rationale=None,
                          evidence_state=None, best_frame_path=None,
                          payload=None):
    """事后增补语义或证据，不允许覆盖规则、区域、类别和原始起点。"""
    cur = conn.execute(
        "UPDATE semantic_events SET t_last=MAX(t_last,?),"
        " short_name=COALESCE(?,short_name),detail=COALESCE(?,detail),"
        " rationale=COALESCE(?,rationale),"
        " evidence_state=COALESCE(?,evidence_state),"
        " best_frame_path=COALESCE(?,best_frame_path),"
        " payload=COALESCE(?,payload)"
        " WHERE semantic_event_id=? AND t_end IS NULL",
        (t_last, short_name, detail, rationale, evidence_state,
         best_frame_path, _json(payload) if payload is not None else None,
         semantic_event_id))
    conn.commit()
    return cur.rowcount == 1


def close_semantic_event(conn, semantic_event_id, *, t_end, reason):
    """幂等闭合语义事件。"""
    cur = conn.execute(
        "UPDATE semantic_events SET t_last=MAX(t_last,?),"
        " t_end=MAX(t_last,?),"
        " end_reason=?,state='closed'"
        " WHERE semantic_event_id=? AND t_end IS NULL",
        (t_end, t_end, reason, semantic_event_id))
    conn.commit()
    return cur.rowcount == 1


def recover_stale_records(conn, *, now, stale_after_s=30.0):
    """闭合上次异常退出遗留且已超时的开放记录。

    使用每条记录最后一次真实活动时间作为结束时间，不伪造崩溃后的活动；返回各层
    闭合数量。新鲜记录不动，方便同进程内重复调用保持幂等。
    """
    cutoff = now - stale_after_s
    tracked = conn.execute(
        "UPDATE tracked_objects SET t_end=t_last,end_reason=?"
        " WHERE t_end IS NULL AND t_last<=?",
        ("recovered_after_restart", cutoff))
    reviews = conn.execute(
        "UPDATE review_segments SET t_end=t_last,end_reason=?"
        " WHERE t_end IS NULL AND t_last<=?",
        ("recovered_after_restart", cutoff))
    semantic = conn.execute(
        "UPDATE semantic_events SET t_end=t_last,end_reason=?,state='closed'"
        " WHERE t_end IS NULL AND t_last<=?",
        ("recovered_after_restart", cutoff))
    counts = {
        "tracked_objects": tracked.rowcount,
        "review_segments": reviews.rowcount,
        "semantic_events": semantic.rowcount,
    }
    conn.commit()
    return counts


RECOVERY_LAYERS = ("tracked_objects", "review_segments", "semantic_events")


def snapshot_pending_recovery(conn, *, now, stale_after_s=30.0):
    """启动快照：宽限窗内仍未闭合的遗留记录（层 + 主键 + t_last）。

    宽限窗内的记录启动时不能立即闭合（它可能仍属活跃数据），但也不能就此
    不管——启动收口只跑一次，跳过的记录若无复核就会永远悬挂。这里把它们的
    身份与"启动那一刻的 t_last"定格下来，交给宽限窗结束后的一次性复核，
    复核时用 CAS 确认记录未被新事实改写。
    """
    cutoff = now - stale_after_s
    snapshot = []
    for row in conn.execute(
            "SELECT object_id, t_last FROM tracked_objects"
            " WHERE t_end IS NULL AND t_last>?", (cutoff,)):
        snapshot.append({"layer": "tracked_objects", "key": row["object_id"],
                         "t_last": row["t_last"]})
    for row in conn.execute(
            "SELECT review_id, t_last FROM review_segments"
            " WHERE t_end IS NULL AND t_last>?", (cutoff,)):
        snapshot.append({"layer": "review_segments", "key": row["review_id"],
                         "t_last": row["t_last"]})
    for row in conn.execute(
            "SELECT semantic_event_id, t_last FROM semantic_events"
            " WHERE t_end IS NULL AND t_last>?", (cutoff,)):
        snapshot.append({"layer": "semantic_events",
                         "key": row["semantic_event_id"],
                         "t_last": row["t_last"]})
    return snapshot


def finalize_snapshot_records(conn, snapshot):
    """按启动快照做一次性 CAS 收口；返回各层闭合数量。

    每条记录的三重条件全部满足才闭合，缺一不动：
    - 仍开放（`t_end IS NULL`）；
    - 主键与快照一致；
    - `t_last` 与快照完全一致（快照之后被任何一方更新过就说明它仍是活事实）。

    因此新实例续写、管理员关闭、状态机改写都会让 CAS 失败——恢复任务绝不
    覆盖新事实，也绝不改写已有的 `end_reason`。重复执行幂等（第一次闭合后
    `t_end` 非空，第二次自然零改动）。
    """
    counts = {layer: 0 for layer in RECOVERY_LAYERS}
    reason = "recovered_after_restart"
    for item in snapshot:
        layer = item["layer"]
        key = item["key"]
        t_last = item["t_last"]
        if layer == "tracked_objects":
            cur = conn.execute(
                "UPDATE tracked_objects SET t_end=t_last,end_reason=?"
                " WHERE object_id=? AND t_end IS NULL AND t_last=?",
                (reason, key, t_last))
        elif layer == "review_segments":
            cur = conn.execute(
                "UPDATE review_segments SET t_end=t_last,end_reason=?"
                " WHERE review_id=? AND t_end IS NULL AND t_last=?",
                (reason, key, t_last))
        elif layer == "semantic_events":
            cur = conn.execute(
                "UPDATE semantic_events SET t_end=t_last,end_reason=?,"
                " state='closed'"
                " WHERE semantic_event_id=? AND t_end IS NULL AND t_last=?",
                (reason, key, t_last))
        else:
            raise ValueError(f"未知恢复层: {layer}")
        if cur.rowcount == 1:
            counts[layer] += 1
    conn.commit()
    return counts


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
