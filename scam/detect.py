"""detect.py —— T1 检测：NanoDet-Plus ONNX（onnxruntime）。

预处理/解码移植自已验证实现（网关验证脚本 + web/core.js decodeNanoDetHead）：
RGB/255、letterbox 416、GFL 分布投影（strides 8/16/32/64、reg_bins 8）。
P0 阶段 decode 可独立测试（合成张量）；onnxruntime 懒加载。
"""

import numpy as np

STRIDES = (8, 16, 32, 64)
REG_BINS = 8


def decode_nanodet(data, num_anchors, num_classes, opts):
    """GFL 导出头解码。

    data:  [N, nc + 4*bins]（cls 已在图内 sigmoid；reg 为 bins-bin logits）
    opts:  {conf, keep_indices, input_size, strides, reg_bins}
    返回:  [{mcls, conf, x1, y1, x2, y2}]（input_size 像素坐标系）
    """
    cols = num_classes + 4 * opts["reg_bins"]
    keep = opts.get("keep_indices")
    pts, strd = _anchors(opts["input_size"], opts["strides"])
    proj = list(range(opts["reg_bins"]))
    dets = []
    for i in range(num_anchors):
        base = i * cols
        best_cls, best_score = -1, -1.0
        for k in range(num_classes):
            if keep and k not in keep:
                continue
            sc = data[base + k]
            if sc > best_score:
                best_score, best_cls = sc, k
        if best_cls < 0 or best_score < opts["conf"]:
            continue
        dist = []
        for g in range(4):
            raw = data[base + num_classes + g * opts["reg_bins"]:
                       base + num_classes + (g + 1) * opts["reg_bins"]]
            mx = raw.max()
            e = np.exp(raw - mx)
            e = e / e.sum()
            dist.append(float((e * proj).sum()) * strd[i])
        gx, gy = pts[i]
        dets.append({"mcls": best_cls, "conf": float(best_score),
                     "x1": gx - dist[0], "y1": gy - dist[1],
                     "x2": gx + dist[2], "y2": gy + dist[3]})
    return dets


_ANCHOR_CACHE = {}


def _anchors(input_size, strides):
    key = (input_size, tuple(strides))
    if key in _ANCHOR_CACHE:
        return _ANCHOR_CACHE[key]
    pts, strd = [], []
    for s in strides:
        hs = -(-input_size // s)          # ceil
        for r in range(hs):
            for c in range(hs):
                pts.append(((c + 0.5) * s, (r + 0.5) * s))
                strd.append(s)
    val = (pts, strd)
    _ANCHOR_CACHE[key] = val
    return val


class NanoDet:
    """NanoDet-Plus ONNX 检测器（onnxruntime 懒加载；NVR 本机推理）。"""

    def __init__(self, model_path, classes, conf=0.4, input_size=416,
                 num_classes=80, keep_indices=(0,), strides=STRIDES, reg_bins=REG_BINS):
        import onnxruntime as ort
        self.classes = list(classes)
        self.conf = conf
        self.input_size = input_size
        self.num_classes = num_classes
        self.keep_indices = tuple(keep_indices)
        self.strides = tuple(strides)
        self.reg_bins = reg_bins
        avail = ort.get_available_providers()
        providers = (["CUDAExecutionProvider", "CPUExecutionProvider"]
                     if "CUDAExecutionProvider" in avail else ["CPUExecutionProvider"])
        self.sess = ort.InferenceSession(model_path, providers=providers)

    def _prep(self, frame_bgr):
        import cv2
        h, w = frame_bgr.shape[:2]
        size = self.input_size
        r = min(size / w, size / h)
        nw, nh = round(w * r), round(h * r)
        canvas = np.full((size, size, 3), 114, np.uint8)
        top, left = (size - nh) // 2, (size - nw) // 2
        canvas[top:top + nh, left:left + nw] = cv2.resize(frame_bgr, (nw, nh))
        x = cv2.cvtColor(canvas, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
        return x.transpose(2, 0, 1)[np.newaxis]

    def detect(self, frame_bgr):
        """frame_bgr: cv2 帧；返回归一化 [{cls, conf, bbox:[x,y,w,h]}]。"""
        import cv2
        x = self._prep(frame_bgr)
        out = self.sess.run(None, {"data": x})[0][0]
        num_anchors = out.shape[0]
        opts = {"conf": self.conf, "keep_indices": list(self.keep_indices),
                "input_size": self.input_size, "strides": list(self.strides),
                "reg_bins": self.reg_bins}
        dets = decode_nanodet(out.reshape(-1), num_anchors, self.num_classes, opts)
        h, w = frame_bgr.shape[:2]
        results = []
        for d in dets:
            if d["conf"] < self.conf:
                continue
            x1, y1 = max(0.0, d["x1"] / w), max(0.0, d["y1"] / h)
            x2, y2 = min(1.0, d["x2"] / w), min(1.0, d["y2"] / h)
            results.append({"cls": self.classes[d["mcls"]] if d["mcls"] < len(self.classes)
                            else str(d["mcls"]),
                            "conf": round(d["conf"], 4),
                            "bbox": [x1, y1, x2 - x1, y2 - y1]})
        return results
