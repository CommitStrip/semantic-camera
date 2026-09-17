"""segments.py —— 事件分段 + 行为签名（快系统活动 → 语义段记录）。

止段：20s 静默或 120s 上限强制切分（忙碌场景保护命名管线）。
签名：廉价结构分量（类别/数量档/区域/越线/模态/时段/时长/滞留）——
      习惯化匹配的结构层；嵌入分量由 V-JEPA 慢系统提供（v0.4 §8.1）。
"""

SEGMENT_SILENCE_MS = 20000
SEGMENT_MAX_MS = 120000


def tod_bucket(dt):
    """时段桶：晨/昼/暮/夜（按小时）。"""
    h = dt.hour
    if h < 6:
        return "夜"
    if h < 10:
        return "晨"
    if h < 17:
        return "昼"
    if h < 20:
        return "暮"
    return "夜"


def dur_bucket(ms):
    """时长档：<30s / <2min / <10min / 更长。"""
    if ms < 30000:
        return "短"
    if ms < 120000:
        return "中"
    if ms < 600000:
        return "长"
    return "超长"


def count_bucket(n):
    """数量档：0 / 1 / 2-3 / 4+。"""
    if n <= 0:
        return "0"
    if n == 1:
        return "1"
    if n <= 3:
        return "2-3"
    return "4+"


def build_signature(*, classes, peak_count, zones, lines, modality, tod,
                    dur_ms, dwell_max_ms=0):
    """行为签名（结构分量）：全排序保证同输入同签名。"""
    return {
        "cls": sorted(classes),
        "count": count_bucket(peak_count),
        "zones": sorted(zones),
        "lines": sorted(lines),
        "modality": modality,
        "tod": tod,
        "dur": dur_bucket(dur_ms),
        "dwell": "有" if (dwell_max_ms or 0) >= 10000 else "无",
    }


class Segmenter:
    """事件分段：活动开段 → 静默/上限止段 → 产出段记录（含签名）。"""

    def __init__(self, camera_id, silence_ms=SEGMENT_SILENCE_MS,
                 max_ms=SEGMENT_MAX_MS, modality="DAY-COLOR"):
        self.camera_id = camera_id
        self.silence_ms = silence_ms
        self.max_ms = max_ms
        self.modality = modality
        self.active = None

    def feed(self, now, *, motion=False, detections=0, zones=None, lines=None):
        """喂入一帧的活动状态；段关闭时返回段记录，否则 None。

        motion: T0 门控运动；detections: 本帧检出数（确认轨迹计 peak）。
        """
        activity = bool(motion or detections)
        seg = self.active
        if seg is None:
            if activity:
                self._open(now)
            return None
        if activity:
            seg["last_ms"] = now
            seg["peak"] = max(seg["peak"], detections)
            seg["dwell_max_ms"] = max(seg["dwell_max_ms"],
                                      now - seg["t_start_ms"])
        if now - seg["last_ms"] >= self.silence_ms or \
                now - seg["t_start_ms"] >= self.max_ms:
            rec = self._close(now, "silence" if now - seg["last_ms"] >=
                              self.silence_ms else "max")
            if activity:
                self._open(now)
            return rec
        return None

    def _open(self, now):
        self.active = {"t_start_ms": now, "last_ms": now, "peak": 0,
                       "classes": set(), "zones": set(), "lines": set(),
                       "dwell_max_ms": 0}

    def observe(self, *, cls=None, zone=None, line=None):
        """观测累积（检测/规则命中时调用，充实签名）。"""
        if self.active is None:
            return
        if cls:
            self.active["classes"].add(cls)
        if zone:
            self.active["zones"].add(zone)
        if line:
            self.active["lines"].add(line)

    def _close(self, t_end_ms, reason):
        seg = self.active
        self.active = None
        dur_ms = t_end_ms - seg["t_start_ms"]
        import datetime
        dt = datetime.datetime.fromtimestamp(t_end_ms / 1000.0)
        signature = build_signature(
            classes=sorted(seg["classes"]), peak_count=seg["peak"],
            zones=sorted(seg["zones"]), lines=sorted(seg["lines"]),
            modality=self.modality, tod=tod_bucket(dt), dur_ms=dur_ms,
            dwell_max_ms=seg["dwell_max_ms"])
        return {
            "segment_id": f"{self.camera_id}:{seg['t_start_ms']}",
            "camera": self.camera_id,
            "t_start": seg["t_start_ms"],
            "t_end": t_end_ms,
            "reason": reason,
            "signature": signature,
            "peak": seg["peak"],
            "dwell_max_ms": seg["dwell_max_ms"],
        }
