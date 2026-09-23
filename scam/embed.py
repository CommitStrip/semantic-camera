"""embed.py —— T2a 段嵌入：V-JEPA ONNX（预处理按 parity 1.0 结论平移）。

预处理（与 HF 处理器 parity=1.000000）：短边 292 BILINEAR → 中心裁 256² →
/255 → ImageNet mean/std，RGB，自然帧序（无反转），[1,T,3,256,256] 帧优先；
导出图内含 all-token mean 池化，embed() 返回 L2 归一化向量。
"""

import numpy as np


class JepaEmbedder:
    def __init__(self, onnx_path):
        import onnxruntime as ort
        avail = ort.get_available_providers()
        providers = (["CUDAExecutionProvider", "CPUExecutionProvider"]
                     if "CUDAExecutionProvider" in avail
                     else ["CPUExecutionProvider"])
        from .detect import session_options
        self.sess = ort.InferenceSession(onnx_path, session_options(),
                                        providers=providers)
        self.input_name = self.sess.get_inputs()[0].name

    def embed(self, frames_bgr):
        """frames_bgr: BGR ndarray 列表（自然顺序，老→新）→ L2 归一化 list[float]。"""
        from PIL import Image
        xs = []
        for f in frames_bgr:
            img = Image.fromarray(cv2_color(f))
            w, h = img.size
            sc = 292 / min(w, h)
            img = img.resize((max(256, round(w * sc)),
                              max(256, round(h * sc))), Image.BILINEAR)
            left = (img.width - 256) // 2
            top = (img.height - 256) // 2
            a = np.asarray(img.crop((left, top, left + 256, top + 256)),
                           np.float32) / 255.0
            a = (a - np.array([0.485, 0.456, 0.406], np.float32)) / \
                np.array([0.229, 0.224, 0.225], np.float32)
            xs.append(a.transpose(2, 0, 1))
        blob = np.stack(xs)[np.newaxis].astype(np.float32)
        vec = self.sess.run(None, {self.input_name: blob})[0][0]
        nrm = float(np.linalg.norm(vec)) or 1.0
        return [round(float(v) / nrm, 5) for v in vec]


def cv2_color(frame_bgr):
    import cv2
    return cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)


class FakeEmbedder:
    """测试用确定性嵌入：同输入同向量，不同输入正交倾向。"""

    def __init__(self, dim=8):
        self.dim = dim
        self.calls = 0

    def embed(self, frames):
        self.calls += 1
        import hashlib
        h = hashlib.sha256(str(len(frames)).encode()).digest()
        v = [(b % 16) / 16.0 for b in h[:self.dim]]
        n = sum(x * x for x in v) ** 0.5 or 1.0
        return [round(x / n, 5) for x in v]
