"""db.py —— SQLite 持久层（事件真值/分段/模式/嵌入档案/元数据）。

纪律：全部查询参数绑定（禁止拼接/format/f-string 组装 SQL）；
每事件独立行、即用即归档——上下文永不堆积在内存。

共享事件真值分四层（Linux NVR 与 Win11 值守工作站共用）：
- tracked_objects：检测和跟踪的原始对象生命周期；
- review_segments：同一相机不重叠的活动审查时段；
- semantic_events：管理员区域和规则裁决出的业务事件（规则命中才产生，含义不变）；
- event_facts：用户可见事件事实——一个已确认目标的一次出现，无规则也建立；
  配套 event_descriptions（描述版本，只追加）、event_notifications（提醒送达账）、
  event_escalations（规则告警 ↔ 事件显式关联）。

四层不可互相冒充。录像和模型描述只增强证据，不决定事件是否成立；
事件事实不依赖审查段写入成功（review_id 可空、迟后回填）。
"""

import json
import sqlite3

SCHEMA_VERSION = 7
# init_schema 的迁移整体在一个事务里执行：SCHEMA 以 BEGIN IMMEDIATE 开头、
# 不含 COMMIT，由调用方校验结构后提交或回滚（executescript 会隐式提交外部
# 待挂起事务，所以事务边界必须写在脚本字面量内）。

SCHEMA = """
BEGIN IMMEDIATE;
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

CREATE TABLE IF NOT EXISTS environment_baselines (
  baseline_id        TEXT PRIMARY KEY,
  camera             TEXT NOT NULL,
  version            INTEGER NOT NULL,
  status             TEXT NOT NULL DEFAULT 'valid',
  established_at     REAL NOT NULL,
  established_via    TEXT NOT NULL DEFAULT 'first-use',
  scene_summary      TEXT,
  machine_state      TEXT NOT NULL DEFAULT 'unknown',
  profile_json       TEXT,
  model_id           TEXT NOT NULL DEFAULT 'unknown',
  config_fingerprint TEXT NOT NULL DEFAULT 'unknown',
  evidence_path      TEXT,               -- 证据根内相对路径（本机路径不下发）
  evidence_sha256    TEXT,               -- 原始画面完整性
  evidence_size      INTEGER,            -- 原始画面字节数
  integrity_json     TEXT,
  payload            TEXT,
  UNIQUE (camera, version),
  CHECK (status IN ('valid', 'superseded')),
  CHECK (established_via IN ('first-use', 'review'))
);
CREATE INDEX IF NOT EXISTS idx_env_baselines_camera
  ON environment_baselines (camera, version DESC);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS zones (
  camera TEXT PRIMARY KEY,
  data   TEXT NOT NULL                -- JSON 序列化的区域配置
);

CREATE TABLE IF NOT EXISTS event_facts (
  event_id       TEXT PRIMARY KEY,
  camera         TEXT NOT NULL,
  object_id      TEXT NOT NULL,
  review_id      TEXT,             -- 可空：事件建立不依赖审查段落库，落库后迟后回填
  t_start        REAL NOT NULL,
  t_last         REAL NOT NULL,
  t_end          REAL,
  end_reason     TEXT,
  state          TEXT NOT NULL DEFAULT 'open',
  cls            TEXT NOT NULL,
  max_conf       REAL,
  bbox_first     TEXT,             -- JSON [x,y,w,h]：首次确认位置
  bbox_last      TEXT,             -- JSON [x,y,w,h]：最近观察位置
  evidence_state TEXT NOT NULL DEFAULT 'metadata_only',
  best_frame_path TEXT,
  payload        TEXT,
  CHECK (state IN ('open', 'closed')),
  CHECK (evidence_state IN ('metadata_only', 'image_only', 'full')),
  CHECK (t_last >= t_start),
  CHECK (t_end IS NULL OR t_end >= t_start)
);
CREATE INDEX IF NOT EXISTS idx_event_facts_camera_time
  ON event_facts (camera, t_start DESC);
CREATE INDEX IF NOT EXISTS idx_event_facts_open
  ON event_facts (camera, t_end) WHERE t_end IS NULL;
CREATE INDEX IF NOT EXISTS idx_event_facts_object
  ON event_facts (object_id);

-- 对象事实先于事件事实落库的强约束（合同边界2）：object_id 外键的等价可验证
-- 守卫——触发器对已存在的 v4 候选库同样生效，无需重建表即可安全迁移。
CREATE TRIGGER IF NOT EXISTS trg_event_facts_object_guard_ins
BEFORE INSERT ON event_facts
WHEN NEW.object_id NOT IN (SELECT object_id FROM tracked_objects)
BEGIN
  SELECT RAISE(ABORT, 'event_facts.object_id 不存在对应对象事实');
END;
CREATE TRIGGER IF NOT EXISTS trg_event_facts_object_guard_upd
BEFORE UPDATE OF object_id ON event_facts
WHEN NEW.object_id NOT IN (SELECT object_id FROM tracked_objects)
BEGIN
  SELECT RAISE(ABORT, 'event_facts.object_id 不存在对应对象事实');
END;

CREATE TABLE IF NOT EXISTS event_descriptions (
  description_id TEXT PRIMARY KEY,
  event_id       TEXT NOT NULL,
  version        INTEGER NOT NULL,
  source         TEXT NOT NULL,    -- initial_observation | pattern | vlm | human
  text           TEXT NOT NULL,
  uncertainty    TEXT NOT NULL DEFAULT 'confirmed',
  evidence_refs  TEXT NOT NULL DEFAULT '[]',
  t_created      REAL NOT NULL,
  payload        TEXT,
  FOREIGN KEY (event_id) REFERENCES event_facts(event_id),
  UNIQUE (event_id, version),
  CHECK (source IN ('initial_observation', 'pattern', 'vlm', 'human')),
  CHECK (uncertainty IN ('confirmed', 'low', 'high'))
);

CREATE TABLE IF NOT EXISTS event_notifications (
  notification_id TEXT PRIMARY KEY,
  event_id        TEXT NOT NULL,
  kind            TEXT NOT NULL,   -- initial_fact | escalation | semantic_update
  dedupe_key      TEXT NOT NULL DEFAULT '',
  channel         TEXT NOT NULL DEFAULT 'workbench',
  t_event         REAL,
  created_at      REAL NOT NULL,
  acknowledged_at REAL,             -- 仅在拿到客户端展示回执时写入
  user_confirmed_at REAL,           -- 仅在用户主动点击确认时写入（≠已读）
  state           TEXT NOT NULL DEFAULT 'generated',
  text            TEXT NOT NULL,
  payload         TEXT,
  FOREIGN KEY (event_id) REFERENCES event_facts(event_id),
  UNIQUE (event_id, kind, dedupe_key),
  CHECK (kind IN ('initial_fact', 'escalation', 'semantic_update')),
  CHECK (state IN ('generated', 'available', 'acknowledged'))
);

CREATE TABLE IF NOT EXISTS event_escalations (
  event_id          TEXT NOT NULL,
  semantic_event_id TEXT NOT NULL,  -- 普通引用：不改写历史 semantic_events 行
  t_linked          REAL NOT NULL,
  payload           TEXT,
  PRIMARY KEY (event_id, semantic_event_id),
  FOREIGN KEY (event_id) REFERENCES event_facts(event_id)
);
"""

# 迁移后逐表校验的实际结构（表 → 必需列）。新建表全列钉住；既有表钉住锚点列，
# 防止"建表脚本跑过但结果残缺"被 user_version 掩盖。
def _notifications_has_user_confirmed(conn):
    cols = {row["name"] for row in conn.execute(
        "SELECT name FROM pragma_table_info('event_notifications')")}
    return "user_confirmed_at" in cols


def _migrate_notifications_v7(conn):
    """v6→v7：event_notifications 补 user_confirmed_at 列（幂等）。

    SQLite ALTER TABLE ADD COLUMN 幂等（列存在即报错 → 捕获跳过）；
    值全 NULL，旧客户端不读取此列即可兼容。
    """
    if _notifications_has_user_confirmed(conn):
        return
    conn.execute(
        "ALTER TABLE event_notifications"
        " ADD COLUMN user_confirmed_at REAL")


_REQUIRED_COLUMNS = {
    "tracked_objects": ("object_id", "camera", "t_start", "t_last", "cls"),
    "review_segments": ("review_id", "camera", "t_start", "t_last"),
    "semantic_events": ("semantic_event_id", "camera", "template", "state"),
    "event_facts": ("event_id", "camera", "object_id", "review_id", "t_start",
                    "t_last", "t_end", "end_reason", "state", "cls", "max_conf",
                    "bbox_first", "bbox_last", "evidence_state",
                    "best_frame_path", "payload"),
    "event_descriptions": ("description_id", "event_id", "version", "source",
                           "text", "uncertainty", "evidence_refs", "t_created"),
    "event_notifications": ("notification_id", "event_id", "kind", "dedupe_key",
                            "channel", "t_event", "created_at",
                            "acknowledged_at", "user_confirmed_at",
                            "state", "text"),
    "event_escalations": ("event_id", "semantic_event_id", "t_linked"),
    "environment_baselines": ("baseline_id", "camera", "version", "status",
                              "established_at", "established_via",
                              "scene_summary", "machine_state", "profile_json",
                              "model_id", "config_fingerprint",
                              "evidence_path", "evidence_sha256",
                              "evidence_size", "integrity_json"),
}

# 对象→事件强约束的守卫触发器（对既有 v4 候选库同样生效，缺了会被校验抓住）。
_REQUIRED_TRIGGERS = ("trg_event_facts_object_guard_ins",
                      "trg_event_facts_object_guard_upd")


def _missing_required_columns(conn):
    missing = []
    for table, columns in _REQUIRED_COLUMNS.items():
        # pragma_table_info 是表值函数，表名可安全参数绑定（不拼接 PRAGMA 文本）。
        present = {row["name"] for row in conn.execute(
            "SELECT name FROM pragma_table_info(?)", (table,))}
        for column in columns:
            if column not in present:
                missing.append(f"{table}.{column}")
    return missing


def _missing_required_triggers(conn):
    present = {row["name"] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger'")}
    return [name for name in _REQUIRED_TRIGGERS if name not in present]


def connect(path):
    """打开 SQLite 连接（行以 dict 访问）。"""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_schema(conn):
    """幂等建表/迁移；拒绝打开由更高版本创建的数据库。

    v4 起迁移在显式事务内执行（SCHEMA 以 BEGIN IMMEDIATE 开头、不含 COMMIT）：
    建表 → 逐表校验实际结构与守卫触发器 → 通过后才写 user_version。任何一步
    失败整体回滚，旧库原样、启动报错；校验机制防止"建表脚本跑过但结果残缺"
    被版本号掩盖。v5 的对象外键守卫触发器对既有 v4 候选库同样生效（IF NOT
    EXISTS 挂到表名上，无需重建表，数据零搬移）。重复启动幂等。
    """
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    if current > SCHEMA_VERSION:
        raise RuntimeError(
            f"数据库版本 {current} 高于当前程序支持的 {SCHEMA_VERSION}，拒绝降级写入")
    try:
        conn.executescript(SCHEMA)
        _migrate_notifications_v7(conn)
        missing = _missing_required_columns(conn)
        if missing:
            raise RuntimeError(
                "数据库迁移后结构校验失败，缺少必需列: " + ", ".join(missing))
        missing_triggers = _missing_required_triggers(conn)
        if missing_triggers:
            raise RuntimeError(
                "数据库迁移后结构校验失败，缺少对象外键守卫触发器: "
                + ", ".join(missing_triggers))
        _migrate_notifications_v7(conn)
        # PRAGMA 不支持参数绑定；此字面量与 SCHEMA_VERSION 同步修改。
        conn.execute("PRAGMA user_version=7")
        conn.commit()
    except Exception:
        conn.rollback()
        raise


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


def event_evidence_from_assets(conn, object_id):
    """从受控证据资产推导事件证据状态（合同 v1.1 边界5）。

    只认 evidence_assets 里 state='available' 的真实资产；路径字段存在但资产
    缺失/损坏时仍返回 metadata_only，绝不因路径存在就声称图片可用。
    'full' 留给录像证据（本阶段不产出）。
    """
    row = conn.execute(
        "SELECT path FROM evidence_assets"
        " WHERE owner_type='tracked_object' AND owner_id=?"
        " AND kind='clean_best_frame' AND state='available'"
        " ORDER BY t_start DESC LIMIT 1", (object_id,)).fetchone()
    if row is None:
        return "metadata_only", None
    return "image_only", row["path"]


def open_event_fact(conn, *, event_id, camera, object_id, t_start, cls,
                    conf=None, bbox_first=None, bbox_last=None, review_id=None,
                    evidence_state="metadata_only", best_frame_path=None,
                    payload=None):
    """幂等打开用户可见事件事实（无规则也建立）。

    - 同 event_id 重复调用只推进观察事实：t_last/conf 取最大，不重置 t_start，
      不改 evidence_state（证据走 refresh 单向升级，重放不降级）。
    - review_id 可空：事件建立不依赖审查段落库（v1.1 边界1）；冲突路径上用
      COALESCE 只填空，已有值不被覆盖。
    - evidence_state/best_frame_path 由调用方按受控资产实际状态推导后传入，
      仅在首次插入时生效。
    返回"语句执行后该事件确实处于 open 状态"：撞上已闭合行（同 track 复用
    旧 id）或对象守卫拒绝（孤儿事件）时如实返回 False，由调用方换新身份或
    等对象落库后重试；失败路径必须回滚，绝不给连接留下未结束的事务。
    """
    try:
        conn.execute(
            "INSERT INTO event_facts"
            " (event_id,camera,object_id,review_id,t_start,t_last,cls,max_conf,"
            "  bbox_first,bbox_last,evidence_state,best_frame_path,payload)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,COALESCE(?, 'metadata_only'),?,?)"
            " ON CONFLICT(event_id) DO UPDATE SET"
            " t_last=MAX(event_facts.t_last,excluded.t_last),"
            " max_conf=MAX(COALESCE(event_facts.max_conf,0),"
            "              COALESCE(excluded.max_conf,0)),"
            " bbox_last=COALESCE(excluded.bbox_last,event_facts.bbox_last),"
            " review_id=COALESCE(event_facts.review_id,excluded.review_id),"
            " payload=COALESCE(excluded.payload,event_facts.payload)"
            " WHERE event_facts.t_end IS NULL",
            (event_id, camera, object_id, review_id, t_start, t_start, cls,
             conf,
             _json(bbox_first) if bbox_first is not None else None,
             _json(bbox_last) if bbox_last is not None else None,
             evidence_state, best_frame_path,
             _json(payload) if payload is not None else None))
        row = conn.execute(
            "SELECT 1 FROM event_facts WHERE event_id=? AND t_end IS NULL",
            (event_id,)).fetchone()
        conn.commit()
    except sqlite3.IntegrityError:
        # 守卫触发器 RAISE(ABORT) / 约束拒绝：回滚清掉隐式事务（残留会把
        # 后续读写困在旧快照里），如实返回 False 交由调用方重试。
        conn.rollback()
        return False
    except Exception:
        conn.rollback()
        raise
    return row is not None


def update_event_fact(conn, event_id, *, t_last, conf=None, bbox_last=None,
                      payload=None):
    """推进开放事件事实（仅当仍开放）；不存在或已闭合返回 False。"""
    row = conn.execute(
        "SELECT 1 FROM event_facts WHERE event_id=? AND t_end IS NULL",
        (event_id,)).fetchone()
    if row is None:
        return False
    conn.execute(
        "UPDATE event_facts SET t_last=MAX(t_last,?),"
        " max_conf=MAX(COALESCE(max_conf,0),COALESCE(?,0)),"
        " bbox_last=COALESCE(?,bbox_last),"
        " payload=COALESCE(?,payload)"
        " WHERE event_id=? AND t_end IS NULL",
        (t_last, conf, _json(bbox_last) if bbox_last is not None else None,
         _json(payload) if payload is not None else None, event_id))
    conn.commit()
    return True


def refresh_event_fact_evidence(conn, event_id, *, evidence_state,
                                best_frame_path=None):
    """按受控资产实际状态刷新事件证据；只升不降（metadata→image→full）。"""
    rank = {"metadata_only": 0, "image_only": 1, "full": 2}
    row = conn.execute(
        "SELECT evidence_state FROM event_facts WHERE event_id=?",
        (event_id,)).fetchone()
    if row is None:
        return False
    if rank.get(evidence_state, 0) <= rank.get(row["evidence_state"], 0):
        return False
    conn.execute(
        "UPDATE event_facts SET evidence_state=?,"
        " best_frame_path=COALESCE(?,best_frame_path) WHERE event_id=?",
        (evidence_state, best_frame_path, event_id))
    conn.commit()
    return True


def link_event_review(conn, event_id, review_id):
    """审查段落库成功后迟后回填关联；幂等，只填空、不覆写已有值。"""
    cur = conn.execute(
        "UPDATE event_facts SET review_id=?"
        " WHERE event_id=? AND review_id IS NULL",
        (review_id, event_id))
    conn.commit()
    return cur.rowcount == 1


def close_event_fact(conn, event_id, *, reason):
    """闭合事件；t_end 固定取记录自身 t_last（最后一次可信观察）。

    不接受调用方传入"现在"的处理时间冒充事件结束时间（v1.1 边界3）。
    """
    cur = conn.execute(
        "UPDATE event_facts SET t_end=t_last, end_reason=?, state='closed'"
        " WHERE event_id=? AND t_end IS NULL",
        (reason, event_id))
    conn.commit()
    return cur.rowcount == 1


def link_event_escalation(conn, *, event_id, semantic_event_id, t_linked,
                          payload=None):
    """幂等写"规则告警 ↔ 事件"显式关联（v1.1 边界4）。

    不改写 semantic_events 任何行；event_id 外键指向不存在的事件事实时
    由调用方按 IntegrityError 处理（挂起等事实落库后补写）。
    """
    conn.execute(
        "INSERT OR IGNORE INTO event_escalations"
        " (event_id,semantic_event_id,t_linked,payload) VALUES (?,?,?,?)",
        (event_id, semantic_event_id, t_linked,
         _json(payload) if payload is not None else None))
    conn.commit()


def semantic_update_ledger_hit_prefix(conn, event_id, digest):
    """静态预算门：该事件是否已有同证据摘要（任意处理指纹）的语义更新。"""
    like = digest + ":%"
    row = conn.execute(
        "SELECT 1 FROM event_notifications"
        " WHERE event_id=? AND kind='semantic_update' AND dedupe_key LIKE ?"
        " LIMIT 1", (event_id, like)).fetchone()
    return row is not None


def next_event_description_version(conn, event_id):
    """该事件当前最大描述版本（无描述为 0）。"""
    row = conn.execute(
        "SELECT MAX(version) AS v FROM event_descriptions WHERE event_id=?",
        (event_id,)).fetchone()
    return int(row["v"] or 0)


def semantic_update_ledger_hit(conn, event_id, identity):
    """幂等账本：同 (事件, 证据摘要, 处理指纹) 的 semantic_update 是否已存在。"""
    row = conn.execute(
        "SELECT 1 FROM event_notifications"
        " WHERE event_id=? AND kind='semantic_update' AND dedupe_key=?",
        (event_id, identity)).fetchone()
    return row is not None


def publish_semantic_update(conn, *, event_id, identity, text, uncertainty,
                            evidence_refs, t_created, model_id,
                            event_open_at_write, payload=None):
    """单事务发布语义更新：追加描述 v(n+1) + semantic_update 提醒。

    合同 v1（第一切片）：
    - 只追加：version = MAX+1，绝不覆盖 v1 或既有描述；
    - 幂等：identity 已在账本（UNIQUE(event_id,kind,dedupe_key)）→ 不产生
      新版本，返回 created=False；
    - 与提醒同事务：崩溃后两者皆无，重启重新调度仍恰一次；
    - 不改写事件原始事实、不改变事件是否成立。
    返回 (version|None, created)；并发撞账本时 version=None。
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        if semantic_update_ledger_hit(conn, event_id, identity):
            conn.rollback()
            return None, False
        version = next_event_description_version(conn, event_id) + 1
        conn.execute(
            "INSERT INTO event_descriptions"
            " (description_id,event_id,version,source,text,uncertainty,"
            "  evidence_refs,t_created,payload)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (f"desc:{event_id}:v{version}", event_id, version, "vlm", text,
             uncertainty, _json(list(evidence_refs or [])), t_created,
             _json(payload) if payload is not None else None))
        conn.execute(
            "INSERT INTO event_notifications"
            " (notification_id,event_id,kind,dedupe_key,channel,t_event,"
            "  created_at,acknowledged_at,state,text,payload)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (f"notif:{event_id}:semantic_update:v{version}", event_id,
             "semantic_update", identity, "workbench", t_created,
             t_created, None, "generated", text,
             _json(payload) if payload is not None else None))
        conn.commit()
        return version, True
    except sqlite3.IntegrityError:
        conn.rollback()
        return None, False
    except Exception:
        conn.rollback()
        raise


def event_evidence_asset(conn, object_id):
    """取对象事实当前可用的最佳帧受控资产（asset_id 优先，路径仅内部使用）。"""
    row = conn.execute(
        "SELECT asset_id,path FROM evidence_assets"
        " WHERE owner_type='tracked_object' AND owner_id=?"
        " AND kind='clean_best_frame' AND state='available'"
        " ORDER BY t_start DESC LIMIT 1", (object_id,)).fetchone()
    if row is None:
        return None, None, None
    return row["asset_id"], row["path"], "image_only"


def ensure_initial_description(conn, event_id, *, text, t_created,
                               evidence_refs=None, payload=None):
    """幂等写 initial_observation 描述 v1（UNIQUE(event_id, version) 兜底）。

    只在事件事实真正落库后调用；文本只使用已核实的观察字段。
    返回是否本次新建（重复调用零改动）。
    """
    cur = conn.execute(
        "INSERT OR IGNORE INTO event_descriptions"
        " (description_id,event_id,version,source,text,uncertainty,"
        "  evidence_refs,t_created,payload)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (f"desc:{event_id}:v1", event_id, 1, "initial_observation", text,
         "confirmed", _json(list(evidence_refs or [])), t_created,
         _json(payload) if payload is not None else None))
    conn.commit()
    return cur.rowcount == 1


def ensure_initial_notification(conn, event_id, *, text, t_event, created_at,
                                payload=None):
    """幂等建 initial_fact 工作台提醒（UNIQUE(event_id,kind,dedupe_key) 兜底）。

    事件事实落库后调用；初始状态 generated，工作台读取后转 available，
    客户端渲染回执才 acknowledged。返回是否本次新建（恰一次）。
    """
    cur = conn.execute(
        "INSERT OR IGNORE INTO event_notifications"
        " (notification_id,event_id,kind,dedupe_key,channel,t_event,"
        "  created_at,acknowledged_at,state,text,payload)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (f"notif:{event_id}:initial_fact", event_id, "initial_fact", "",
         "workbench", t_event, created_at, None, "generated", text,
         _json(payload) if payload is not None else None))
    conn.commit()
    return cur.rowcount == 1


def mark_notification_available(conn, notification_id, *, at):
    """generated → available（工作台可读取）；幂等，不覆盖已确认状态。"""
    cur = conn.execute(
        "UPDATE event_notifications SET state='available'"
        " WHERE notification_id=? AND state='generated'", (notification_id,))
    conn.commit()
    return cur.rowcount == 1


def acknowledge_notification(conn, notification_id, *, at):
    """客户端渲染回执：→ acknowledged；幂等，重复回执零改动、不改时间。"""
    cur = conn.execute(
        "UPDATE event_notifications SET state='acknowledged',acknowledged_at=?"
        " WHERE notification_id=? AND state IN ('available','generated')",
        (at, notification_id))
    conn.commit()
    return cur.rowcount == 1


def confirm_notification_by_user(conn, notification_id, *, at):
    """用户主动确认（≠自动渲染回执≠人工已读）：幂等，首次写 user_confirmed_at。

    独立持久化事实：刷新/重启保持；重复确认零改动、不覆盖首次时间；
    acknowledged_at（首次显示回执）不受影响。
    """
    row = conn.execute(
        "SELECT 1 FROM event_notifications WHERE notification_id=?",
        (notification_id,)).fetchone()
    if row is None:
        return None
    cur = conn.execute(
        "UPDATE event_notifications SET user_confirmed_at=?"
        " WHERE notification_id=? AND user_confirmed_at IS NULL",
        (at, notification_id))
    conn.commit()
    return cur.rowcount == 1


def count_events_missing_pairs(conn):
    """缺描述 v1 或缺 initial_fact 的事件数（补账待补真值，零模型调用）。"""
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM event_facts f WHERE"
        " NOT EXISTS (SELECT 1 FROM event_descriptions d"
        "  WHERE d.event_id=f.event_id AND d.version=1)"
        " OR NOT EXISTS (SELECT 1 FROM event_notifications n"
        "  WHERE n.event_id=f.event_id AND n.kind='initial_fact')"
    ).fetchone()
    return int(row["n"])


_BACKFILL_CURSOR_KEY = "backfill_scan_cursor"


def read_backfill_cursor(conn):
    """补账扫描进度（meta 持久化，跨进程重启可续跑）；缺失按空串（起点）。"""
    row = conn.execute(
        "SELECT value FROM meta WHERE key=?", (_BACKFILL_CURSOR_KEY,)
    ).fetchone()
    if row is None:
        return ""
    return row["value"] or ""


def _write_backfill_cursor(conn, cursor):
    conn.execute(
        "INSERT INTO meta (key,value) VALUES (?,?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (_BACKFILL_CURSOR_KEY, cursor))
    conn.commit()


def backfill_initial_fact_pairs(conn, *, created_at, batch=200):
    """补账（可续跑扫描）：只为缺描述 v1 或缺 initial_fact 的事件补齐一对。

    扫描进度持久化于 meta（`backfill_scan_cursor`）：每轮从上次位置**向前**
    取一批（`event_id > 游标`，稳定键 ORDER BY event_id，单批工作量有上界），
    批内单条失败如实计数、**不中断也不阻塞其后待补事件**（游标照常推进，失败
    条目留在待补、下一次回绕时再试）；扫到末尾（本批取不满）**回绕到起点**，
    保证持续失败条目仍会被周期重试、故障解除后补齐。并发新增事件：id 大于
    游标者随当前扫描可见，id 小于等于游标者在回绕批次可见——都不丢失。
    UNIQUE 兜底恰一次：已补过零增行、不改原始事实、证据缺失不造假。返回本轮
    补建/失败/扫描数、扫描游标位置与剩余待补数——"值守已启动"绝不等于
    "积压已清零"，持续失败也不会显示成已清零。
    """
    cursor = read_backfill_cursor(conn)
    counts = {"descriptions": 0, "notifications": 0, "failed": 0,
              "scanned": 0, "remaining": 0, "cursor_before": cursor,
              "wrapped": False}
    rows = conn.execute(
        "SELECT f.event_id,f.camera,f.cls,f.t_start,f.object_id"
        " FROM event_facts f WHERE"
        " (NOT EXISTS (SELECT 1 FROM event_descriptions d"
        "  WHERE d.event_id=f.event_id AND d.version=1)"
        " OR NOT EXISTS (SELECT 1 FROM event_notifications n"
        "  WHERE n.event_id=f.event_id AND n.kind='initial_fact'))"
        " AND f.event_id > ?"
        " ORDER BY f.event_id LIMIT ?", (cursor, batch)).fetchall()
    for row in rows:
        counts["scanned"] += 1
        try:
            asset_id, _path, _state = event_evidence_asset(
                conn, row["object_id"])
            text = f"{row['camera']} 画面中出现 {row['cls']}"
            refs = [asset_id] if asset_id else []
            if ensure_initial_description(
                    conn, row["event_id"], text=text,
                    t_created=row["t_start"], evidence_refs=refs):
                counts["descriptions"] += 1
            if ensure_initial_notification(
                    conn, row["event_id"], text=text,
                    t_event=row["t_start"], created_at=created_at,
                    payload={"evidence_asset_ids": refs}):
                counts["notifications"] += 1
        except Exception:
            counts["failed"] += 1
    if len(rows) >= batch and rows:
        # 本批取满：游标推进到本批末条（含失败条目——不因失败卡住后续）
        _write_backfill_cursor(conn, rows[-1]["event_id"])
    else:
        # 扫到末尾：回绕起点，让失败/新增条目进入下一轮扫描
        counts["wrapped"] = True
        _write_backfill_cursor(conn, "")
    counts["cursor_after"] = read_backfill_cursor(conn)
    counts["remaining"] = count_events_missing_pairs(conn)
    return counts


_EVENT_LIST_SQL = (
    "SELECT f.event_id,f.camera,f.t_start,f.t_last,f.t_end,f.end_reason,"
    " f.state,f.cls,f.max_conf,f.evidence_state,"
    " (SELECT a.asset_id FROM evidence_assets a"
    "  WHERE a.owner_type='tracked_object' AND a.owner_id=f.object_id"
    "  AND a.kind='clean_best_frame' AND a.state='available'"
    "  ORDER BY a.t_start DESC LIMIT 1) AS best_frame_asset_id,"
    " (SELECT COUNT(*) FROM event_escalations e"
    "  WHERE e.event_id=f.event_id) AS escalation_count,"
    " (SELECT n.notification_id FROM event_notifications n"
    "  WHERE n.event_id=f.event_id AND n.kind='initial_fact'"
    "  ORDER BY n.created_at LIMIT 1) AS initial_notification_id,"
    " (SELECT n.state FROM event_notifications n"
    "  WHERE n.event_id=f.event_id AND n.kind='initial_fact'"
    "  ORDER BY n.created_at LIMIT 1) AS initial_notification_state,"
    " (SELECT n.text FROM event_notifications n"
    "  WHERE n.event_id=f.event_id AND n.kind='initial_fact'"
    "  ORDER BY n.created_at LIMIT 1) AS initial_fact_text"
    " FROM event_facts f"
    " WHERE (? IS NULL OR f.camera=?) AND (? IS NULL OR f.state=?)"
    " ORDER BY f.t_start DESC LIMIT ?")


def list_event_facts(conn, *, camera=None, state=None, limit=50):
    """事件事实列表（时间倒序稳定排序、限量、相机/状态筛选）。

    返回行不含本机路径；证据以受控 asset_id 暴露。
    """
    limit = max(1, min(int(limit), 200))
    rows = conn.execute(
        _EVENT_LIST_SQL,
        (camera, camera, state, state, limit)).fetchall()
    return [dict(row) for row in rows]


def list_initial_notifications(conn, *, limit=20, cursor=None,
                               kind="initial_fact"):
    """提醒列表（游标分页，未确认积压不饿死）；kind 区分两类提醒流。

    initial_fact=初始事实提醒；semantic_update=语义更新提醒（"有新描述可
    查看"，非管理员规则告警）。稳定排序 (created_at DESC, notification_id
    DESC)：第二关键字让同创建时间的多条各有确定顺序；游标=(上一页末行
    created_at, notification_id)，下一页取严格更旧的行——新数据插入在排序
    头，不影响后续页边界（并发插入语义）。cursor=None 从最新开始；非法游标
    由调用方拒绝。不含路径/凭据。
    """
    limit = max(1, min(int(limit), 100))
    base = ("SELECT n.notification_id,n.event_id,n.kind,n.state,n.t_event,"
            " n.created_at,n.acknowledged_at,n.user_confirmed_at,n.text,"
            " f.camera,f.cls"
            " FROM event_notifications n"
            " LEFT JOIN event_facts f ON f.event_id=n.event_id"
            " WHERE n.kind=?")
    if cursor is None:
        rows = conn.execute(
            base + " ORDER BY n.created_at DESC, n.notification_id DESC"
            " LIMIT ?", (kind, limit)).fetchall()
    else:
        cursor_time, cursor_id = cursor
        rows = conn.execute(
            base + " AND (n.created_at < ?"
            " OR (n.created_at = ? AND n.notification_id < ?))"
            " ORDER BY n.created_at DESC, n.notification_id DESC"
            " LIMIT ?",
            (kind, cursor_time, cursor_time, cursor_id, limit)).fetchall()
    return [dict(row) for row in rows]


def get_event_fact(conn, event_id):
    """事件事实详情：原始观察、描述版本、规则升级、提醒状态。

    任何字段缺失如实缺省；不含本机路径与凭据。找不到返回 None。
    """
    row = conn.execute(
        "SELECT f.event_id,f.camera,f.object_id,f.review_id,f.t_start,"
        " f.t_last,f.t_end,f.end_reason,f.state,f.cls,f.max_conf,"
        " f.bbox_first,f.bbox_last,f.evidence_state,f.payload,"
        " (SELECT a.asset_id FROM evidence_assets a"
        "  WHERE a.owner_type='tracked_object' AND a.owner_id=f.object_id"
        "  AND a.kind='clean_best_frame' AND a.state='available'"
        "  ORDER BY a.t_start DESC LIMIT 1) AS best_frame_asset_id"
        " FROM event_facts f WHERE f.event_id=?", (event_id,)).fetchone()
    if row is None:
        return None
    detail = dict(row)
    detail["descriptions"] = [dict(r) for r in conn.execute(
        "SELECT description_id,version,source,text,uncertainty,evidence_refs,"
        " t_created,payload FROM event_descriptions"
        " WHERE event_id=? ORDER BY version",
        (event_id,)).fetchall()]
    detail["escalations"] = [dict(r) for r in conn.execute(
        "SELECT e.semantic_event_id,e.t_linked,s.template,s.zone_id,"
        " s.short_name,s.severity,s.state"
        " FROM event_escalations e"
        " LEFT JOIN semantic_events s"
        " ON s.semantic_event_id=e.semantic_event_id"
        " WHERE e.event_id=? ORDER BY e.t_linked", (event_id,)).fetchall()]
    detail["notifications"] = [dict(r) for r in conn.execute(
        "SELECT notification_id,kind,dedupe_key,state,t_event,created_at,"
        " acknowledged_at,user_confirmed_at,text FROM event_notifications"
        " WHERE event_id=? ORDER BY created_at", (event_id,)).fetchall()]
    return detail


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
    facts = conn.execute(
        "UPDATE event_facts SET t_end=t_last,end_reason=?,state='closed'"
        " WHERE t_end IS NULL AND t_last<=?",
        ("recovered_after_restart", cutoff))
    counts = {
        "tracked_objects": tracked.rowcount,
        "review_segments": reviews.rowcount,
        "semantic_events": semantic.rowcount,
        "event_facts": facts.rowcount,
    }
    conn.commit()
    return counts


RECOVERY_LAYERS = ("tracked_objects", "review_segments", "semantic_events",
                   "event_facts")


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
    for row in conn.execute(
            "SELECT event_id, t_last FROM event_facts"
            " WHERE t_end IS NULL AND t_last>?", (cutoff,)):
        snapshot.append({"layer": "event_facts", "key": row["event_id"],
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
        elif layer == "event_facts":
            cur = conn.execute(
                "UPDATE event_facts SET t_end=t_last,end_reason=?,"
                " state='closed'"
                " WHERE event_id=? AND t_end IS NULL AND t_last=?",
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


# ---------- 环境基线（版本化可追溯；只追加版本，不改写历史） ----------

def _baseline_pointer_key(camera):
    return f"env_baseline:{camera}"


def _baseline_error_key(camera):
    return f"env_baseline_error:{camera}"


def environment_baseline_status(conn, camera):
    """当前相机基线状态（只读，零模型调用）。

    返回 dict：state∈ready/baseline_required/failed + 当前版本摘要
    （版本号/建立时间/建立方式/画面 asset 与可得性/模型与配置标识）。
    指针或版本行缺失 → required；有失败摘要 → failed。
    """
    row = conn.execute(
        "SELECT value FROM meta WHERE key=?",
        (_baseline_pointer_key(camera),)).fetchone()
    if row is None or row["value"] is None:
        state = "baseline_required"
        error = conn.execute(
            "SELECT value FROM meta WHERE key=?",
            (_baseline_error_key(camera),)).fetchone()
        if error is not None and error["value"]:
            state = "failed"
        return {"state": state, "camera": camera, "reason": "no_pointer",
                "error": error["value"] if error else None}
    try:
        version = int(row["value"])
    except (TypeError, ValueError):
        return {"state": "baseline_required", "camera": camera,
                "reason": "pointer_not_integer", "error": None}
    current = conn.execute(
        "SELECT baseline_id,camera,version,status,established_at,"
        " established_via,scene_summary,machine_state,model_id,"
        " config_fingerprint,evidence_path,evidence_sha256,evidence_size"
        " FROM environment_baselines WHERE camera=? AND version=?",
        (camera, version)).fetchone()
    if current is None or current["status"] != "valid":
        return {"state": "baseline_required", "camera": camera,
                "reason": "pointer_version_missing", "error": None}
    summary = dict(current)
    summary["state"] = "ready"
    summary["evidence_present"] = bool(summary.get("evidence_path"))
    # 失败摘要作为提示保留：已建立的版本仍权威（失败不得抹去旧版本），
    # 但最近一次建立/复核失败必须可见（UI 显示后可重试）。
    error = conn.execute(
        "SELECT value FROM meta WHERE key=?",
        (_baseline_error_key(camera),)).fetchone()
    summary["error"] = error["value"] if error else None
    if summary["error"]:
        summary["reason"] = "last_attempt_failed"
    return summary


def get_environment_baseline(conn, baseline_id):
    """按受控版本身份读取一行基线；找不到返回 None。绝不接受文件路径。"""
    row = conn.execute(
        "SELECT baseline_id,camera,version,status,established_at,"
        " established_via,scene_summary,machine_state,profile_json,"
        " model_id,config_fingerprint,evidence_path,evidence_sha256,"
        " evidence_size"
        " FROM environment_baselines WHERE baseline_id=?", (baseline_id,)
    ).fetchone()
    return dict(row) if row is not None else None


def environment_baseline_history(conn, camera, limit=20):
    """基线历史（只追加版本的时间线）；不含本机路径。"""
    limit = max(1, min(int(limit), 100))
    rows = conn.execute(
        "SELECT baseline_id,version,status,established_at,established_via,"
        " scene_summary,machine_state,model_id,config_fingerprint"
        " FROM environment_baselines WHERE camera=?"
        " ORDER BY version DESC LIMIT ?", (camera, limit)).fetchall()
    return [dict(row) for row in rows]


def establish_environment_baseline(
        conn, *, camera, baseline_id, established_at, established_via,
        scene_summary, machine_state, profile, model_id, config_fingerprint,
        evidence_path=None, evidence_sha256=None, evidence_size=None,
        payload=None):
    """单事务追加基线版本并 CAS 切换当前指针（合同3）。

    - 只追加：新版本 status='valid'，旧 valid→superseded；历史与原始证据保留。
    - 指针 CAS：仅当当前指针与本次读取值一致（或为空）才切换；竞争时返回
      None 由调用方重试，绝不覆盖别人的建立结果。
    - 失败整体回滚：旧版本、指针、失败摘要都不被半改。
    返回新版本号；指针竞争返回 None。
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        pointer = conn.execute(
            "SELECT value FROM meta WHERE key=?",
            (_baseline_pointer_key(camera),)).fetchone()
        current = pointer["value"] if pointer else None
        top = conn.execute(
            "SELECT MAX(version) AS v FROM environment_baselines WHERE camera=?",
            (camera,)).fetchone()["v"]
        version = int(top or 0) + 1
        conn.execute(
            "UPDATE environment_baselines SET status='superseded'"
            " WHERE camera=? AND status='valid'", (camera,))
        conn.execute(
            "INSERT INTO environment_baselines"
            " (baseline_id,camera,version,status,established_at,"
            "  established_via,scene_summary,machine_state,profile_json,"
            "  model_id,config_fingerprint,evidence_path,evidence_sha256,"
            "  evidence_size,integrity_json,payload)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (baseline_id, camera, version, "valid", established_at,
             established_via, scene_summary,
             machine_state or "unknown", _json(profile or {}),
             model_id or "unknown", config_fingerprint or "unknown",
             evidence_path, evidence_sha256, evidence_size,
             _json({"sha256": evidence_sha256, "size_bytes": evidence_size,
                    "generated_at": established_at}),
             _json(payload) if payload is not None else None))
        key = _baseline_pointer_key(camera)
        if current is None:
            if pointer is not None:
                raise RuntimeError("基线指针读取与写入不一致")
            conn.execute(
                "INSERT INTO meta (key,value) VALUES (?,?)",
                (key, str(version)))
        else:
            cur = conn.execute(
                "UPDATE meta SET value=? WHERE key=? AND value=?",
                (str(version), key, current))
            if cur.rowcount != 1:
                conn.rollback()
                return None
        # 成功建立即清除失败摘要（重试成功的体现）
        conn.execute(
            "DELETE FROM meta WHERE key=?", (_baseline_error_key(camera),))
        conn.commit()
        return version
    except Exception:
        conn.rollback()
        raise


def record_environment_baseline_failure(conn, camera, *, summary):
    """记录建立失败摘要（固定中文文案，非异常原文）；不触碰既有基线。"""
    conn.execute(
        "INSERT INTO meta (key,value) VALUES (?,?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (_baseline_error_key(camera), summary))
    conn.commit()


def clear_environment_baseline_failure(conn, camera):
    cur = conn.execute(
        "DELETE FROM meta WHERE key=?", (_baseline_error_key(camera),))
    conn.commit()
    return cur.rowcount == 1
