"""verdict.py —— 四态裁决的报警判定：识别结果对比管理员自定义模板。

报警路径零慢层：本模块只做纯规则判定（检测+网格+模板条件），
全程不碰 JEPA/VLM——报警速度就是检测速度。
"""

PRESET_TEMPLATES = ("enter-dwell", "loiter", "immediate")


def rule_fires(rule, cls, in_zone, dwell_s):
    """结构条件比对：rule（模板/规则字典）与识别结果比对，符合即 True。

    rule: {cls, template?, dwell_s?}
      enter-dwell（默认）: 进入区域且滞留 ≥ dwell_s
      loiter:             区域内滞留 ≥ dwell_s（默认 30）
      immediate:          进入区域即报
    """
    if rule.get("cls") != cls:
        return False
    template = rule.get("template", "enter-dwell")
    if template == "immediate":
        return in_zone
    need = rule.get("dwell_s", 30 if template == "loiter" else 5)
    return bool(in_zone) and dwell_s is not None and dwell_s >= need


class ZoneRuntime:
    """区域滞留运行时：每轨迹的进区时刻与滞留时长（跨帧状态）。"""

    def __init__(self):
        self._enter = {}     # (track_id, zone_id) → 进入时刻

    def update(self, track_id, zone_id, in_zone, now):
        """返回该轨迹在本区域的滞留秒数；不在区域内时清除并返回 None。"""
        key = (track_id, zone_id)
        if in_zone:
            if key not in self._enter:
                self._enter[key] = now
            return (now - self._enter[key]) / 1000.0
        self._enter.pop(key, None)
        return None

    def evaluate(self, track_id, zone_id, now, rules, cls):
        """按规则表裁决：返回命中的规则字典，无命中返回 None。"""
        dwell = self.update(track_id, zone_id, True, now)
        for r in rules or []:
            if rule_fires(r, cls, True, dwell):
                out = dict(r)
                out["dwell_s"] = dwell
                return out
        return None

    def leave(self, track_id, zone_id):
        self._enter.pop((track_id, zone_id), None)
