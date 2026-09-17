"""gate.py —— T0 帧差门控（快系统，常驻逐帧）。

移植自 vus 已验证实现（web/core.js MotionGate）：降采样灰度逐像素帧差，
阈值+面积双闸，输出运动框与 motion_ratio；软重置用于成像突变抑制。

纯 Python 实现（P0 可测）；生产如需提速可换 numpy 向量化，行为不变。
"""

MOTION_THRESH = 25          # 帧差阈值（vus 边界实测：25 不触发、26 触发）
MIN_AREA_RATIO = 0.003      # 运动面积门槛（占门控网格比例）


class MotionGate:
    def __init__(self, thresh=MOTION_THRESH, min_area_ratio=MIN_AREA_RATIO):
        self.thresh = thresh
        self.min_area_ratio = min_area_ratio
        self.prev = None
        self.last_ratio = 0.0

    def detect(self, gray, gw, gh):
        """gray: 扁平灰度序列（行优先）；返回运动框列表（降采样坐标系）。

        首帧仅建立基准不触发；motion_ratio 逐帧更新（漂移监控输入）。
        """
        self.last_ratio = 0.0
        if self.prev is None or len(self.prev) != len(gray):
            self.prev = list(gray) if not isinstance(gray, list) else gray[:]
            return []
        cnt = 0
        min_x, max_x = gw, 0
        min_y, max_y = gh, 0
        thresh = self.thresh
        prev = self.prev
        for i in range(len(gray)):
            d = gray[i] - prev[i]
            if d < 0:
                d = -d
            if d > thresh:
                cnt += 1
                x = i % gw
                y = i // gw
                if x < min_x:
                    min_x = x
                if x > max_x:
                    max_x = x
                if y < min_y:
                    min_y = y
                if y > max_y:
                    max_y = y
        self.prev = list(gray)
        self.last_ratio = cnt / gw / gh
        if not cnt or self.last_ratio <= self.min_area_ratio:
            return []
        return [{"x": min_x, "y": min_y, "w": max_x - min_x, "h": max_y - min_y}]

    def reset_background(self, gray=None):
        """软重置（成像突变窗专用）：以当前帧为新背景基准，抑制帧差爆炸。"""
        if gray is not None:
            self.prev = list(gray) if not isinstance(gray, list) else gray[:]
        self.last_ratio = 0.0
