"""monitor.py —— 单相机快系统值守循环（T0 门控 → T1 检测 → 裁决 → 告警）。

报警路径零慢层：本循环全程不碰 JEPA/VLM。
按区域独立判定与滞留计时；边沿触发锁存（同一驻留事件只报一次，
离区自动复位）；轨迹消亡即清理滞留表与锁存（防长期值守慢泄漏）。
"""

import time

from .gate import MotionGate
from .track import Tracker
from .verdict import ZoneRuntime, rule_fires
from .zones import Grid


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

    def __init__(self, camera_cfg, detect_fn, sinks, seq=0):
        self.camera_id = camera_cfg["id"]
        self.detect_fn = detect_fn
        self.sinks = sinks
        self.grid = Grid(**(camera_cfg.get("grid") or {}))
        self.zones = []
        for z in camera_cfg.get("zones") or []:
            self.zones.append({
                "id": z["id"],
                "cells": set(z.get("cells") or []),
                "rules": z.get("rules") or [],
            })
        self.gate = MotionGate()
        self.tracker = Tracker()
        self.zone_rt = ZoneRuntime()
        self.last_det = None
        self.seq = seq
        self.violations = 0
        self._alarm_fired = set()   # (track_id, zone_id, cls, template) 边沿锁存
        self._occurrence = {}       # 同键第几次驻留事件（event_id 稳定键）
        self._prev_live = set()     # 上一帧活跃轨迹 id（消亡检测）

    def step(self, frame_bgr, gray, now):
        """推进一帧；返回本步产生的告警列表。"""
        gw = self.GRAY_W
        gh = max(1, round(len(gray) / gw))
        self.gate.detect(gray, gw, gh)
        interval = (self.MOTION_DET_INTERVAL if self.gate.last_ratio > 0
                    else self.PATROL_INTERVAL)
        if self.last_det is None or now - self.last_det >= interval:
            self.last_det = now
            self.gate.reset_background(gray)
            dets = self.detect_fn(frame_bgr) or []
            self.tracker.update(dets, now)

        alarms = []
        live_ids = set()
        for t in self.tracker.tracks.values():
            if not t.get("confirmed"):
                continue
            live_ids.add(t["id"])
            cx = t.get("cx", t["bbox"][0] + t["bbox"][2] / 2.0)
            cy = t.get("cy", t["bbox"][1] + t["bbox"][3] / 2.0)
            cell = self.grid.cell_of(cx, cy)
            for zone in self.zones:
                zid = zone["id"]
                if cell in zone["cells"]:
                    dwell = self.zone_rt.update(t["id"], zid, True, now)
                    for r in zone["rules"]:
                        skey = self._skey(t, zid, r)
                        if skey in self._alarm_fired:
                            continue
                        if rule_fires(r, t["cls"], True, dwell):
                            self._alarm_fired.add(skey)
                            alarms.append(self._alarm(t, r, dwell, now,
                                                      zid, frame_bgr))
                            break
                else:
                    # 离区：滞留表复位 + 锁存复位（再次进入视为新事件）
                    self.zone_rt.leave(t["id"], zid)
                    self._alarm_fired = {
                        k for k in self._alarm_fired
                        if not (k[0] == t["id"] and k[1] == zid)}

        # 轨迹消亡：滞留表与锁存全量清理（track id 单调递增，不清理会慢泄漏）
        for tid in self._prev_live - live_ids:
            for zone in self.zones:
                self.zone_rt.leave(tid, zone["id"])
            self._alarm_fired = {k for k in self._alarm_fired if k[0] != tid}
        self._prev_live = live_ids

        for a in alarms:
            for sink in self.sinks:
                sink(a)
        return alarms

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
            "event_id": f"{self.camera_id}:alert:{t['id']}:{zone_id}:"
                        f"{template}:{occ}",
            "camera": self.camera_id,
            "zone": zone_id,
            "rule": template,
            "cls": t["cls"],
            "conf": t["conf"],
            "t_source": now / 1000.0,
            "short_name": f"重点区域{rule.get('cls', '目标')}触发",
            "detail": (f"{rule.get('cls', '目标')}进入重点管理区域，"
                       f"滞留 {dwell:.0f} 秒触发规则"),
            "rationale": f"模板 {template} 命中",
            "thumbnail": thumb_b64,
            "latency_ms": round(max(0.0, wall_ms - now)),
        }
