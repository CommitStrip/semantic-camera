"""source.py —— 相机源接入：优先薄封装 vus FrameSource（RTSP/文件/相机）。

vus 缺席时自动回退 cv2.VideoCapture 本地实现（断流重连由本模块承担）——
快系统安装不依赖 vus。read 失败计数供看门狗；统一开关接口。
"""

import time


class _Cv2Source:
    """vus 缺席时的本地回退源：cv2.VideoCapture + 简单重连。"""

    stats = {}

    def __init__(self, url, reconnect_delay=2.0):
        self.url = url
        self.reconnect_delay = reconnect_delay
        self.cap = None

    def open(self):
        import cv2
        target = int(self.url) if str(self.url).isdigit() else self.url
        self.cap = cv2.VideoCapture(target)
        return bool(self.cap.isOpened())

    def read(self):
        if self.cap is None or not self.cap.isOpened():
            time.sleep(self.reconnect_delay)
            if not self.open():
                return False, None, None
        ok, frame = self.cap.read()
        if not ok:
            return False, None, None
        return True, frame, time.time()

    def close(self):
        if self.cap is not None:
            self.cap.release()
        self.cap = None


class CameraSource:
    """一路相机源。source_kind: rtsp | file | camera。"""

    def __init__(self, camera_id, source_url, source_kind="rtsp",
                 reconnect_delay=2.0, max_reconnects=0):
        self.camera_id = camera_id
        self.source_url = source_url
        self.source_kind = source_kind
        self.reconnect_delay = reconnect_delay
        self.max_reconnects = max_reconnects
        self._src = None
        self.read_failures = 0

    def _build(self):
        try:
            from vus.source import (RTSPSource, FileSource,
                                    CameraSource as VusCamera)
        except ImportError:
            return _Cv2Source(self.source_url, self.reconnect_delay)
        if self.source_kind == "rtsp":
            return RTSPSource(self.source_url,
                              reconnect_delay=self.reconnect_delay,
                              max_reconnects=self.max_reconnects)
        if self.source_kind == "file":
            return FileSource(self.source_url)
        if self.source_kind == "camera":
            return VusCamera(self.source_url)
        raise ValueError("未知源类型: " + self.source_kind)

    def open(self) -> bool:
        self._src = self._build()
        ok = self._src.open()
        self.ok = bool(ok)
        return self.ok

    def read(self):
        """返回 (ok, frame_bgr, ts)；断流/失败时计一次失败并返回 (False, None, None)。"""
        ok, frame, ts = self._src.read()
        if not ok:
            self.read_failures += 1
            self.ok = False
            return False, None, None
        self.ok = True
        return True, frame, ts

    def close(self):
        if self._src is not None:
            try:
                self._src.close()
            except Exception:
                pass
        self._src = None
        self.ok = False

    @property
    def stats(self):
        return getattr(self._src, "stats", {}) if self._src else {}
