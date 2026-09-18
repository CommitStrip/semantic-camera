"""sinks.py —— 告警出口：横幅（控制台）+ events.jsonl + SQLite。"""

import json
import os
import sqlite3
import time


class BannerSink:
    """控制台横幅（值守可见，即 print；编码安全——Windows GBK 不崩）。"""

    def __call__(self, alarm):
        ts = time.strftime("%H:%M:%S")
        try:
            print(f"\n[ALARM] [{ts}] {alarm['camera']} {alarm['short_name']} "
                  f"({alarm['zone']}) latency={alarm.get('latency_ms', '?')}ms")
        except UnicodeEncodeError:
            print(f"[ALARM] [{ts}] {alarm['camera']} alarm")


class JsonlSink:
    """events.jsonl 追加写（一行一告警，含完整三层文本）。"""

    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def __call__(self, alarm):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alarm, ensure_ascii=False) + "\n")


class SqliteSink:
    """写入 SQLite events 表（参数绑定，event_id 幂等）。"""

    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        from .db import init_schema
        init_schema(self.conn)

    def __call__(self, alarm):
        self.conn.execute(
            "INSERT OR IGNORE INTO events"
            " (event_id, camera, kind, t_processed, t_source, cls, conf,"
            "  zone_id, template, short_name, detail, rationale, payload)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (alarm["event_id"], alarm["camera"], "alert",
             time.strftime("%Y-%m-%dT%H:%M:%S"), alarm.get("t_source"),
             alarm.get("cls"), alarm.get("conf"), alarm.get("zone"),
             alarm.get("rule"), alarm.get("short_name"),
             alarm.get("detail"), alarm.get("rationale"),
             json.dumps(alarm, ensure_ascii=False)),
        )
        self.conn.commit()


def build_sinks(paths):
    """按路径组装默认出口组：横幅 + jsonl + sqlite。"""
    sinks = [BannerSink()]
    if paths.get("jsonl"):
        sinks.append(JsonlSink(paths["jsonl"]))
    if paths.get("sqlite"):
        sinks.append(SqliteSink(paths["sqlite"]))
    return sinks
