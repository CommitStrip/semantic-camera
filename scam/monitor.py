"""monitor.py —— 单相机快系统值守循环（T0 门控 → T1 检测 → 裁决 → 告警）。

报警路径零慢层：本循环全程不碰 JEPA/VLM。
按区域独立判定与滞留计时；边沿触发锁存（同一驻留事件只报一次，
离区自动复位）；轨迹消亡即清理滞留表与锁存（防长期值守慢泄漏）。
"""

import threading
import time
import uuid

from .gate import MotionGate
from .track import Tracker
from .verdict import ZoneRuntime, rule_fires
from .zones import Grid, normalize_zones


def to_gray(frame_bgr, gw=96):
    """帧 → 降采样扁平灰度序列（快系统口径，纯 cv2）。"""
    import cv2
    h, w = frame_bgr.shape[:2]
    gh = max(1, round(gw * h / w))
    small = cv2.resize(frame_bgr, (gw, gh))
    gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)
    return gray.reshape(-1).tolist()


class Monitor:
    """单相机快系统值守。

    camera_cfg: {id, zones:[{id,name,cells,rules[]}], grid:{rows,cols}}
    detect_fn:  frame_bgr → dets（生产=NanoDet.detect，测试=注入脚本）
    sinks:      告警出口列表（callable(alarm)）
    """

    MOTION_DET_INTERVAL = 400
    PATROL_INTERVAL = 5000
    GRAY_W = 96
    REVIEW_IDLE_CUTOFF = 20.0

    def __init__(self, camera_cfg, detect_fn, sinks, seq=0, run_id=None):
        self.camera_id = camera_cfg["id"]
        self.detect_fn = detect_fn
        self.sinks = sinks
        self.grid = Grid(**(camera_cfg.get("grid") or {}))
        self.zones = self._runtime_zones(normalize_zones(
            camera_cfg.get("zones") or [], self.grid))
        self._zone_lock = threading.Lock()
        self._pending_zones = None
        self._zone_requested_revision = 0
        self.zone_revision = 0
        self.gate = MotionGate()
        self.tracker = Tracker()
        self.zone_rt = ZoneRuntime()
        self.last_det = None
        self.seq = seq
        self.run_id = run_id or uuid.uuid4().hex[:12]
        self.violations = 0
        self._alarm_fired = set()   # (track_id, zone_id, cls, template) 边沿锁存
        self._occurrence = {}       # 同键第几次驻留事件（event_id 稳定键）
        self._prev_live = set()     # 上一帧活跃轨迹 id（消亡检测）
        self._open_events = {}      # 规则锁存键 → semantic_event_id
        self._review = None
        self._review_seq = 0
        self.frames = 0
        self.motion_frames = 0
        self.det_calls = 0
        self.alarms = 0
        self.last_alarm_ms = None
        self.max_latency_ms = 0
        self.sink_failures = 0
        self.last_sink_error = None
        self.latest_frame_bgr = None

    def step(self, frame_bgr, gray, now):
        """推进一帧；返回本步产生的告警列表。"""
        self._apply_pending_zones(now)
        # 仅原子替换引用；JPEG缩放/编码由工作台请求线程按需完成，不占报警快路径。
        self.latest_frame_bgr = frame_bgr
        self.frames += 1
        gw = self.GRAY_W
        gh = max(1, round(len(gray) / gw))
        self.gate.detect(gray, gw, gh)
        if self.gate.last_ratio > 0:
            self.motion_frames += 1
        interval = (self.MOTION_DET_INTERVAL if self.gate.last_ratio > 0
                    else self.PATROL_INTERVAL)
        observed_ids = None
        if self.last_det is None or now - self.last_det >= interval:
            self.last_det = now
            self.det_calls += 1
            self.gate.reset_background(gray)
            dets = self.detect_fn(frame_bgr) or []
            observed = self.tracker.update(dets, now)
            observed_ids = {track["id"] for track in observed
                            if track.get("confirmed")}

        alarms = []
        live_ids = set()
        activity_ids = set()
        active_zones = {}
        for t in self.tracker.tracks.values():
            if not t.get("confirmed"):
                continue
            live_ids.add(t["id"])
            # 没有到检测节奏时沿用现有轨迹；本轮检测明确未观察到的旧轨迹
            # 只等待 Tracker 老化，不继续累计活动、滞留或审查时长。
            if observed_ids is not None and t["id"] not in observed_ids:
                continue
            activity_ids.add(t["id"])
            cx = t.get("cx", t["bbox"][0] + t["bbox"][2] / 2.0)
            cy = t.get("cy", t["bbox"][1] + t["bbox"][3] / 2.0)
            cell = self.grid.cell_of(cx, cy)
            for zone in self.zones:
                zid = zone["id"]
                if cell in zone["cells"]:
                    active_zones.setdefault(t["id"], []).append(zid)
                    dwell = self.zone_rt.update(t["id"], zid, True, now)
                    for r in zone["rules"]:
                        skey = self._skey(t, zid, r)
                        if skey in self._alarm_fired:
                            continue
                        if rule_fires(r, t["cls"], True, dwell):
                            self._alarm_fired.add(skey)
                            alarm = self._alarm(t, r, dwell, now,
                                                zid, frame_bgr)
                            self._open_events[skey] = alarm["event_id"]
                            alarms.append(alarm)
                            break
                else:
                    # 离区：滞留表复位 + 锁存复位（再次进入视为新事件）
                    self.zone_rt.leave(t["id"], zid)
                    self._release(t["id"], zid, now, "zone-leave")

        # 轨迹消亡：滞留表与锁存全量清理（track id 单调递增，不清理会慢泄漏）
        for tid in self._prev_live - live_ids:
            for zone in self.zones:
                self.zone_rt.leave(tid, zone["id"])
            self._release(tid, None, now, "track-lost")
            self._call_sinks(
                "close_object", self._object_id(tid),
                t_end=now / 1000.0, reason="track-lost")
        self._prev_live = live_ids

        review_id = self._review_step(
            now, activity_ids, active_zones, alarms, frame_bgr)
        for alarm in alarms:
            alarm["review_id"] = review_id
            alarm["object_id"] = self._object_id(alarm["track_id"])

        self.alarms += len(alarms)
        for a in alarms:
            self.max_latency_ms = max(
                self.max_latency_ms, a.get("latency_ms", 0))
            for sink in self.sinks:
                try:
                    sink(a)
                except Exception as exc:
                    self._record_sink_error(sink, "alarm", exc)
        if alarms:
            self.last_alarm_ms = now
        return alarms

    def stats(self):
        """工作台可读的运行计数；不把模块存在冒充为主机质量证据。"""
        return {
            "camera": self.camera_id,
            "frames": self.frames,
            "motion_frames": self.motion_frames,
            "det_calls": self.det_calls,
            "alarms": self.alarms,
            "max_latency_ms": self.max_latency_ms,
            "last_alarm_ms": self.last_alarm_ms,
            "motion_ratio": round(self.gate.last_ratio, 4),
            "tracks": len(self.tracker.get_confirmed()),
            "open_events": len(self._open_events),
            "review_open": self._review is not None,
            "sink_failures": self.sink_failures,
            "last_sink_error": self.last_sink_error,
            "zone_revision": self.zone_revision,
            "zone_update_pending": self._pending_zones is not None,
        }

    @staticmethod
    def _runtime_zones(zones):
        return tuple({"id": zone["id"], "name": zone.get("name", zone["id"]),
                      "cells": set(zone["cells"]),
                      "rules": [dict(rule) for rule in zone["rules"]]}
                     for zone in zones)

    def request_zone_update(self, zones):
        """从工作台排队一份已校验区域；只在下个视频帧边界切换。"""
        prepared = self._runtime_zones(normalize_zones(zones, self.grid))
        with self._zone_lock:
            self._zone_requested_revision += 1
            revision = self._zone_requested_revision
            self._pending_zones = (revision, prepared)
        return revision

    def _apply_pending_zones(self, now):
        with self._zone_lock:
            pending = self._pending_zones
            self._pending_zones = None
        if pending is None:
            return False
        revision, zones = pending
        # 旧规则的开放事件必须在同一帧边界关闭，不能成为配置变更后的幽灵事件。
        keys = set(self._alarm_fired) | set(self._open_events)
        for track_id in {key[0] for key in keys}:
            self._release(track_id, None, now, "zone-reconfigured")
        self._alarm_fired.clear()
        self._open_events.clear()
        self.zone_rt = ZoneRuntime()
        self.zones = zones
        self.zone_revision = revision
        return True

    def _object_id(self, track_id):
        return f"{self.camera_id}:{self.run_id}:track:{track_id}"

    def _release(self, track_id, zone_id, now, reason):
        keys = [key for key in self._alarm_fired
                if key[0] == track_id and
                (zone_id is None or key[1] == zone_id)]
        event_ids = []
        for key in keys:
            self._alarm_fired.discard(key)
            event_id = self._open_events.pop(key, None)
            if event_id:
                event_ids.append(event_id)
        if event_ids:
            self._call_sinks(
                "close_semantic_events", event_ids,
                t_end=now / 1000.0, reason=reason)

    def _review_step(self, now, live_ids, active_zones, alarms, frame_bgr):
        """每相机聚合一个活动段；检测开段，管理员规则告警只负责升级。"""
        if live_ids:
            if self._review is None:
                self._review_seq += 1
                review_id = (f"{self.camera_id}:{self.run_id}:review:"
                             f"{self._review_seq}")
                self._review = {
                    "review_id": review_id,
                    "t_start": now / 1000.0,
                    "last_active_ms": now,
                    "severity": "detection",
                    "objects": set(),
                    "events": set(),
                    "zones": set(),
                    "detections": {},
                    "alarms": 0,
                }
                self._call_sinks(
                    "open_review", review_id=review_id,
                    camera=self.camera_id, t_start=now / 1000.0,
                    object_ids=[], payload={"zones": [], "alarms": 0})
            review = self._review
            review["last_active_ms"] = now
            review["alarms"] += len(alarms)
            if alarms:
                review["severity"] = "alert"
                review["events"].update(a["event_id"] for a in alarms)
            for track_id in live_ids:
                track = self.tracker.tracks.get(track_id) or {}
                object_id = self._object_id(track_id)
                zones = active_zones.get(track_id, [])
                review["objects"].add(object_id)
                review["zones"].update(zones)
                review["detections"][object_id] = track.get("cls", "")
                self._call_sinks(
                    "observe_object", object_id=object_id,
                    camera=self.camera_id,
                    t_start=track.get("bornAt", now) / 1000.0,
                    t_last=now / 1000.0, cls=track.get("cls", ""),
                    conf=track.get("conf"), zones=zones,
                    review_id=review["review_id"],
                    payload={"track_id": track_id}, frame_bgr=frame_bgr,
                    bbox=track.get("bbox"))
            payload = {
                "zones": sorted(review["zones"]),
                "detections": review["detections"],
                "alarms": review["alarms"],
            }
            self._call_sinks(
                "update_review", review["review_id"],
                t_last=now / 1000.0, severity=review["severity"],
                object_ids=sorted(review["objects"]),
                semantic_event_ids=sorted(review["events"]), payload=payload)
            return review["review_id"]

        if self._review is not None and (
                now - self._review["last_active_ms"] >=
                self.REVIEW_IDLE_CUTOFF * 1000.0):
            review = self._review
            self._call_sinks(
                "close_review", review["review_id"],
                t_end=review["last_active_ms"] / 1000.0,
                reason="idle-timeout")
            self._review = None
        return self._review["review_id"] if self._review else None

    def _call_sinks(self, method, *args, **kwargs):
        for sink in self.sinks:
            callback = getattr(sink, method, None)
            if callback is None:
                continue
            try:
                callback(*args, **kwargs)
            except Exception as exc:
                self._record_sink_error(sink, method, exc)

    def _record_sink_error(self, sink, operation, exc):
        self.sink_failures += 1
        self.last_sink_error = {
            "sink": type(sink).__name__,
            "operation": operation,
            "error": str(exc),
        }

    @staticmethod
    def _skey(t, zone_id, rule):
        return (t["id"], zone_id, rule.get("cls", ""),
                rule.get("template", "enter-dwell"))

    def _alarm(self, t, rule, dwell, now, zone_id, frame_bgr=None):
        self.seq += 1
        self.violations += 1
        thumb_b64 = None
        if frame_bgr is not None:
            import cv2
            import base64
            h, w = frame_bgr.shape[:2]
            tw = 320
            th = max(1, round(tw * h / w))
            thumb = cv2.resize(frame_bgr, (tw, th))
            ok, buf = cv2.imencode(".jpg", thumb, [cv2.IMWRITE_JPEG_QUALITY, 70])
            if ok:
                thumb_b64 = base64.b64encode(buf.tobytes()).decode()
        skey = self._skey(t, zone_id, rule)
        occ = self._occurrence.get(skey, 0) + 1
        self._occurrence[skey] = occ
        template = rule.get("template", "enter-dwell")
        wall_ms = time.time() * 1000.0
        return {
            # 稳定键：不含毫秒时间戳——同一次驻留事件幂等（INSERT OR IGNORE 生效）；
            # 驻留序号区分离区再入的新事件
            "event_id": f"{self.camera_id}:{self.run_id}:alert:{t['id']}:{zone_id}:"
                        f"{template}:{occ}",
            "camera": self.camera_id,
            "zone": zone_id,
            "rule": template,
            "cls": t["cls"],
            "conf": t["conf"],
            "track_id": t["id"],
            "t_source": now / 1000.0,
            "short_name": f"重点区域{rule.get('cls', '目标')}触发",
            "detail": (f"{rule.get('cls', '目标')}进入重点管理区域，"
                       f"滞留 {dwell:.0f} 秒触发规则"),
            "rationale": f"模板 {template} 命中",
            "thumbnail": thumb_b64,
            "latency_ms": round(max(0.0, wall_ms - now)),
        }
