"""track.py —— 目标跟踪确认（IoU+中心距硬闸门，恒速预测，分级老化，类别守卫）。

移植自 vus 已验证实现（web/core.js Tracker），含 QA 修复语义：
- 中心距硬闸门：超 matchMaxDist 即新目标，IoU 只作候选内排序；
- 类别守卫：异类检出不改写轨迹身份。
"""

CONFIRM_COUNT = 2
MATCH_MAX_DIST = 0.35
MAX_AGE = 2000            # 未确认目标老化 ms
CONFIRMED_MAX_AGE = 12000  # 已确认目标老化 ms（必须 > 巡检间隔）


def _iou(a, b):
    x1 = max(a[0], b[0])
    y1 = max(a[1], b[1])
    x2 = min(a[0] + a[2], b[0] + b[2])
    y2 = min(a[1] + a[3], b[1] + b[3])
    iw = x2 - x1
    ih = y2 - y1
    if iw <= 0 or ih <= 0:
        return 0.0
    inter = iw * ih
    union = a[2] * a[3] + b[2] * b[3] - inter
    return inter / union if union > 0 else 0.0


class Tracker:
    def __init__(self, confirm_count=CONFIRM_COUNT, match_max_dist=MATCH_MAX_DIST):
        self.tracks = {}
        self.next_id = 1
        self.confirm_count = confirm_count
        self.match_max_dist = match_max_dist

    def update(self, dets, now):
        """dets: [{cls, conf, bbox:[x,y,w,h] 归一化, cx, cy}]；返回本轮活跃轨迹。"""
        active = set()
        for d in dets:
            best, best_score, best_dist = None, 1e9, 1e9
            for tid, t in self.tracks.items():
                if tid in active:
                    continue
                if t["cls"] != d["cls"]:
                    continue          # 类别守卫：异类不改写轨迹身份
                dt = (now - t["last"]) / 1000.0
                px = t["cx"] + t.get("vx", 0.0) * dt
                py = t["cy"] + t.get("vy", 0.0) * dt
                dist = ((px - d["cx"]) ** 2 + (py - d["cy"]) ** 2) ** 0.5
                if dist >= self.match_max_dist:
                    continue          # 中心距硬闸门
                shift_x = px - t["cx"]
                shift_y = py - t["cy"]
                pred = [t["bbox"][0] + shift_x, t["bbox"][1] + shift_y,
                        t["bbox"][2], t["bbox"][3]]
                score = dist - _iou(pred, d["bbox"]) * 200
                if score < best_score:
                    best_score, best, best_dist = score, tid, dist

            if best is not None and best_score < self.match_max_dist and \
                    best_dist < self.match_max_dist:
                t = self.tracks[best]
                dt = (now - t["last"]) / 1000.0
                if dt > 0.01:
                    vx = (d["cx"] - t["cx"]) / dt
                    vy = (d["cy"] - t["cy"]) / dt
                    t["vx"] = t.get("vx", 0.0) * 0.6 + vx * 0.4
                    t["vy"] = t.get("vy", 0.0) * 0.6 + vy * 0.4
                t["bbox"] = list(d["bbox"])
                t["cx"], t["cy"] = d["cx"], d["cy"]
                t["cls"], t["conf"] = d["cls"], d["conf"]
                t["last"] = now
                t["count"] = t.get("count", 0) + 1
                hist = t.setdefault("hist", [{"x": t["cx"], "y": t["cy"], "t": t["last"]}])
                hist.append({"x": t["cx"], "y": t["cy"], "t": now})
                if len(hist) > 32:
                    del hist[0]
                active.add(best)
                if t["count"] >= self.confirm_count:
                    t["confirmed"] = True
                d["trackId"] = best
            else:
                tid = self.next_id
                self.next_id += 1
                self.tracks[tid] = {"id": tid, "bbox": list(d["bbox"]),
                                    "cx": d["cx"], "cy": d["cy"], "vx": 0.0, "vy": 0.0,
                                    "cls": d["cls"], "conf": d["conf"], "last": now,
                                    "count": 1, "confirmed": False, "bornAt": now,
                                    "hist": [{"x": d["cx"], "y": d["cy"], "t": now}]}
                active.add(tid)
                d["trackId"] = tid

        # 分级老化：未确认噪声快速消亡；已确认目标更长存活窗
        for tid in list(self.tracks):
            t = self.tracks[tid]
            ttl = CONFIRMED_MAX_AGE if t.get("confirmed") else MAX_AGE
            if now - t["last"] > ttl:
                del self.tracks[tid]

        return [self.tracks[i] for i in active]

    def get_confirmed(self):
        return [t for t in self.tracks.values() if t.get("confirmed")]
