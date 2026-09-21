"""source.py —— 相机源接入：优先薄封装 vus FrameSource（RTSP/文件/相机）。

vus 缺席时自动回退 cv2.VideoCapture 本地实现（断流重连由本模块承担）——
快系统安装不依赖 vus。read 失败计数供看门狗；统一开关接口。
"""

import time


class _Cv2Source:
    """vus 缺席时的本地回退源：cv2.VideoCapture + 有界退避重连。

    读失败（含文件 EOF、设备掉线）必须 release 后重建，绝不原地永久失败；
    重连退避指数增长但封顶 30s，文件源重建成功不额外等待（EOF 循环回放）。
    stats 暴露确定性计数：open_failures / reconnects / read_failures / last_frame_ts。
    """

    def __init__(self, url, reconnect_delay=2.0):
        self.url = url
        self.reconnect_delay = reconnect_delay
        self.cap = None
        self.open_failures = 0
        self.reconnects = 0
        self.read_failures = 0
        self.last_frame_ts = None
        self._backoff_step = 0

    def open(self):
        import cv2
        raw = str(self.url)
        target = int(raw) if raw.isdigit() else self.url
        self.cap = cv2.VideoCapture(target)
        ok = bool(self.cap.isOpened())
        if not ok:
            self.open_failures += 1
            self.cap.release()
            self.cap = None
        return ok

    def _release(self):
        if self.cap is not None:
            self.cap.release()
        self.cap = None

    def read(self):
        if self.cap is None:
            time.sleep(min(self.reconnect_delay * (2 ** self._backoff_step),
                           30.0))
            if not self.open():
                self._backoff_step = min(self._backoff_step + 1, 5)
                return False, None, None
            self._backoff_step = 0
        ok, frame = self.cap.read()
        if not ok:
            # 读失败：释放重建。重建成功立即补读一次（文件 EOF 即回绕到首帧）；
            # 重建失败按有界指数退避等待，退避封顶 30s。
            self.read_failures += 1
            self._release()
            self.reconnects += 1
            if not self.open():
                self._backoff_step = min(self._backoff_step + 1, 5)
                time.sleep(min(self.reconnect_delay * (2 ** self._backoff_step),
                               30.0))
                return False, None, None
            ok, frame = self.cap.read()
            if not ok:
                return False, None, None
        self.last_frame_ts = time.time()
        return True, frame, self.last_frame_ts

    def close(self):
        self._release()

    @property
    def stats(self):
        return {"open_failures": self.open_failures,
                "reconnects": self.reconnects,
                "read_failures": self.read_failures,
                "last_frame_ts": self.last_frame_ts,
                # OpenCV only timestamps after the host receives the frame.
                # This must never be presented as capture-time latency evidence.
                "timestamp_kind": "host_receive"}


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
        # vus 三类源全部用 time.monotonic() 打点（直播语义、抗时钟跳变）；
        # 首次成功读帧时锚定 (单调, 墙钟) 原点，把单调时间映射回墙钟序列。
        self._vus_monotonic = False
        self._mono_anchor = None
        self._wall_anchor = None

    def _build(self):
        self._vus_monotonic = False
        try:
            from vus.source import (RTSPSource, FileSource,
                                    CameraSource as VusCamera)
        except ImportError:
            return _Cv2Source(self.source_url, self.reconnect_delay)
        self._vus_monotonic = True
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
        self._mono_anchor = None
        self._wall_anchor = None
        ok = self._src.open()
        self.ok = bool(ok)
        return self.ok

    def read(self):
        """返回 (ok, frame_bgr, ts)；断流/失败时计一次失败并返回 (False, None, None)。

        vus 源的单调时间戳经锚点映射为墙钟序列（跨重连稳定，NTP 跳变不扭曲
        事件时间）；溯源仍是 host_receive——主机读帧时刻不冒充相机采集时刻。
        """
        ok, frame, ts = self._src.read()
        if not ok:
            self.read_failures += 1
            self.ok = False
            return False, None, None
        self.ok = True
        if self._vus_monotonic and isinstance(ts, (int, float)):
            if self._mono_anchor is None:
                self._mono_anchor = time.monotonic()
                self._wall_anchor = time.time()
            ts = self._wall_anchor + (ts - self._mono_anchor)
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
        if not self._src:
            return {"timestamp_kind": "unknown"}
        raw = getattr(self._src, "stats", {}) or {}
        stats = dict(raw) if isinstance(raw, dict) else {}
        # VUS adapters may explicitly attest source_capture. An adapter that
        # does not declare provenance gets host_receive: vus 时间戳全部为
        # 主机单调时钟读帧时刻（本类已锚定转换回墙钟），绝不冒充采集时间。
        if self._vus_monotonic:
            stats.setdefault("timestamp_kind", "host_receive")
        else:
            stats.setdefault("timestamp_kind", "unknown")
        return stats
