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
        """兼容告警流 + 三层真值；返回真值是否写入成功。

        真值写入依赖审查段已落库（外键）。开段失败时这里返回 False 而不是抛错：
        上层据此把告警挂起、等审查段落库后补写，绝不把"没写进去"当成写成功。
        """
        self._write_compat_alarm(alarm)
        return self.write_semantic_event(alarm)

    def _write_compat_alarm(self, alarm):
        """兼容告警流（无外键）：先落，保证运维侧至少有一条告警痕迹。"""
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

    def write_semantic_event(self, alarm):
        """写管理员语义事件（同 event_id 幂等，可被上层补写重放）。

        只有管理员规则已命中的 alarm 才能成为 semantic_event；检测活动本身
        只进入 tracked_objects/review_segments，不能在这里偷换成告警。
        审查段尚未落库时外键会拒绝写入——如实返回 False（不吞其它数据库错误）。
        """
        best_frame_path = None
        if alarm.get("object_id"):
            best_frame_path = self.evidence.link_object_frame_to_event(
                self.conn, object_id=alarm["object_id"],
                event_id=alarm["event_id"], camera=alarm["camera"])
        from .db import open_semantic_event
        try:
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
        except sqlite3.IntegrityError:
            # 外键/唯一约束：审查段尚未落库或该事件已写过 → 由调用方决定是否补写
            return False
        return True

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

    def open_event_fact(self, *, event_id, camera, object_id, t_start, cls,
                        conf=None, bbox_first=None, bbox_last=None,
                        review_id=None, payload=None):
        """写用户可见事件事实（无规则也建立；同 event_id 幂等可重放）。

        证据状态只从受控证据资产（evidence_assets）的实际 state 推导——
        不因路径字段存在就声称图片可用。review_id 为空表示审查段尚未落库，
        事件照常建立，落库后由 link_event_review 迟后回填。
        事件真正落库后，幂等建立 initial_observation 描述 v1 与 initial_fact
        工作台提醒（文本只用已核实字段，不等待慢模型）；UNIQUE 兜底恰一次，
        崩溃窗口由启动补账兜底。
        """
        from .db import (open_event_fact as _open,
                         event_evidence_from_assets, event_evidence_asset,
                         ensure_initial_description,
                         ensure_initial_notification)
        evidence_state, best_frame_path = event_evidence_from_assets(
            self.conn, object_id)
        established = _open(self.conn, event_id=event_id, camera=camera,
                            object_id=object_id, t_start=t_start, cls=cls,
                            conf=conf, bbox_first=bbox_first,
                            bbox_last=bbox_last, review_id=review_id,
                            evidence_state=evidence_state,
                            best_frame_path=best_frame_path, payload=payload)
        if established:
            asset_id, _path, _asset_state = event_evidence_asset(
                self.conn, object_id)
            text = f"{camera} 画面中出现 {cls}"
            refs = [asset_id] if asset_id else []
            ensure_initial_description(
                self.conn, event_id, text=text, t_created=t_start,
                evidence_refs=refs)
            ensure_initial_notification(
                self.conn, event_id, text=text, t_event=t_start,
                created_at=time.time(),
                payload={"evidence_asset_ids": refs})
        return established

    def update_event_fact(self, event_id, *, t_last, conf=None, bbox_last=None,
                          payload=None):
        """推进开放事件事实；顺带按受控资产现状单向升级证据字段。"""
        from .db import (update_event_fact as _update,
                         refresh_event_fact_evidence,
                         event_evidence_from_assets)
        updated = _update(self.conn, event_id, t_last=t_last, conf=conf,
                          bbox_last=bbox_last, payload=payload)
        if updated:
            row = self.conn.execute(
                "SELECT object_id FROM event_facts WHERE event_id=?",
                (event_id,)).fetchone()
            if row is not None:
                evidence_state, best_frame_path = event_evidence_from_assets(
                    self.conn, row["object_id"])
                refresh_event_fact_evidence(
                    self.conn, event_id, evidence_state=evidence_state,
                    best_frame_path=best_frame_path)
        return updated

    def close_event_fact(self, event_id, *, reason):
        """闭合事件事实；t_end 由存储层固定为记录自身 t_last（最后可信观察）。"""
        from .db import close_event_fact as _close
        return _close(self.conn, event_id, reason=reason)

    def link_event_review(self, event_id, review_id):
        """审查段落库后迟后回填事件与审查段的关联；幂等只填空。"""
        from .db import link_event_review as _link
        return _link(self.conn, event_id, review_id)

    def link_event_escalation(self, *, event_id, semantic_event_id, t_linked,
                              payload=None):
        """写"规则告警 ↔ 事件"显式关联；事件事实未落库（外键拒绝）时返回 False。"""
        from .db import link_event_escalation as _link
        try:
            _link(self.conn, event_id=event_id,
                  semantic_event_id=semantic_event_id, t_linked=t_linked,
                  payload=payload)
        except sqlite3.IntegrityError:
            return False
        return True


def build_sinks(paths):
    """按路径组装默认出口组：横幅 + jsonl + sqlite。"""
    sinks = [BannerSink()]
    if paths.get("jsonl"):
        sinks.append(JsonlSink(paths["jsonl"]))
    if paths.get("sqlite"):
        sinks.append(SqliteSink(paths["sqlite"]))
    return sinks
