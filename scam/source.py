"""source.py —— 相机源接入：薄封装 vus FrameSource（RTSP/文件/相机）。

断流守护由 vus RTSPSource 内建（最新帧背压 + 自动重连，max_reconnects=0
为无限重连）；本封装补：read 失败计数（供看门狗）与统一开关接口。
"""

import time


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
        from vus.source import RTSPSource, FileSource, CameraSource as VusCamera
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
