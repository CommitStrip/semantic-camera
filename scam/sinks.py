"""sinks.py —— 告警出口：横幅（控制台）+ events.jsonl + SQLite。"""

import json
import os
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
    """SQLite 真值出口。

    ``events`` 保留兼容告警流；对象、审查段和管理员语义事件分别写入三层
    真值表。Monitor 通过可选方法调用生命周期能力，其他出口无需实现。
    """

    def __init__(self, db_path):
        from .db import connect, init_schema
        from .evidence import EvidenceStore
        self.conn = connect(db_path)
        init_schema(self.conn)
        self.evidence = EvidenceStore(
            os.path.join(os.path.dirname(os.path.abspath(db_path)), "evidence"))

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

        # 只有管理员规则已命中的 alarm 才能成为 semantic_event；检测活动本身
        # 只进入 tracked_objects/review_segments，不能在这里偷换成告警。
        best_frame_path = None
        if alarm.get("object_id"):
            best_frame_path = self.evidence.link_object_frame_to_event(
                self.conn, object_id=alarm["object_id"],
                event_id=alarm["event_id"], camera=alarm["camera"])
        from .db import open_semantic_event
        open_semantic_event(
            self.conn,
            semantic_event_id=alarm["event_id"],
            camera=alarm["camera"],
            review_id=alarm.get("review_id"),
            object_id=alarm.get("object_id"),
            t_start=alarm.get("t_source", 0.0),
            template=alarm.get("rule", "enter-dwell"),
            zone_id=alarm.get("zone"),
            severity=alarm.get("severity", "medium"),
            cls=alarm.get("cls"),
            conf=alarm.get("conf"),
            short_name=alarm.get("short_name"),
            detail=alarm.get("detail"),
            rationale=alarm.get("rationale"),
            evidence_state=("image_only" if best_frame_path
                            else "metadata_only"),
            best_frame_path=best_frame_path,
            payload=alarm,
        )

    def observe_object(self, *, object_id, camera, t_start, t_last, cls,
                       conf, zones, review_id, payload=None, frame_bgr=None,
                       bbox=None):
        from .db import open_tracked_object, update_tracked_object
        open_tracked_object(
            self.conn, object_id=object_id, camera=camera, t_start=t_start,
            cls=cls, conf=conf, zones=zones, review_id=review_id,
            payload=payload)
        update_tracked_object(
            self.conn, object_id, t_last=t_last, conf=conf, zones=zones,
            review_id=review_id, payload=payload)
        if frame_bgr is not None:
            self.evidence.save_best_frame(
                self.conn, object_id=object_id, camera=camera,
                frame_bgr=frame_bgr, t_source=t_last, conf=conf, bbox=bbox)

    def close_object(self, object_id, *, t_end, reason):
        from .db import close_tracked_object
        close_tracked_object(self.conn, object_id, t_end=t_end, reason=reason)

    def open_review(self, *, review_id, camera, t_start, object_ids,
                    payload=None):
        from .db import open_review_segment
        open_review_segment(
            self.conn, review_id=review_id, camera=camera, t_start=t_start,
            severity="detection", object_ids=object_ids, payload=payload)

    def update_review(self, review_id, *, t_last, severity, object_ids,
                      semantic_event_ids, payload=None):
        from .db import update_review_segment
        update_review_segment(
            self.conn, review_id, t_last=t_last, severity=severity,
            object_ids=object_ids, semantic_event_ids=semantic_event_ids,
            payload=payload)

    def close_review(self, review_id, *, t_end, reason):
        from .db import close_review_segment
        close_review_segment(self.conn, review_id, t_end=t_end, reason=reason)

    def close_semantic_events(self, event_ids, *, t_end, reason):
        from .db import close_semantic_event
        for event_id in event_ids:
            close_semantic_event(
                self.conn, event_id, t_end=t_end, reason=reason)


def build_sinks(paths):
    """按路径组装默认出口组：横幅 + jsonl + sqlite。"""
    sinks = [BannerSink()]
    if paths.get("jsonl"):
        sinks.append(JsonlSink(paths["jsonl"]))
    if paths.get("sqlite"):
        sinks.append(SqliteSink(paths["sqlite"]))
    return sinks
