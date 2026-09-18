"""recorder.py —— 录像分段（ffmpeg 子进程流拷贝，零 CPU）+ 保留策略。"""

import os
import signal
import subprocess
import time


class SegmentRecorder:
    """每相机一个 ffmpeg 子进程，流拷贝分段录像（10 分钟/段）。

    零转码（-c copy），按日期目录落盘，保留策略双闸（天数+容量）。
    """

    def __init__(self, camera_id, rtsp_url, storage_root="storage/cameras",
                 segment_seconds=600, retention_days=7, cap_gb=None):
        self.camera_id = camera_id
        self.rtsp_url = rtsp_url
        self.storage_root = os.path.join(storage_root, camera_id)
        self.segment_seconds = segment_seconds
        self.retention_days = retention_days
        self.cap_gb = cap_gb
        self.proc = None

    def start(self):
        """启动 ffmpeg 分段录像子进程。"""
        os.makedirs(self.storage_root, exist_ok=True)
        out_pattern = os.path.join(
            self.storage_root,
            "%Y-%m-%d", f"seg_%Y%m%d-%H%M%S.mp4")
        self.proc = subprocess.Popen(
            ["ffmpeg",
             "-loglevel", "error",
             "-i", self.rtsp_url,
             "-c", "copy",                    # 流拷贝零 CPU
             "-f", "segment",
             "-segment_time", str(self.segment_seconds),
             "-reset_timestamps", "1",
             "-strftime", "1",
             out_pattern],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=5)
            self.proc = None

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None


class RetentionPolicy:
    """保留策略：按天数 + 按容量双闸清理旧录像。"""

    def __init__(self, storage_root, retention_days=7, cap_gb=None):
        self.root = storage_root
        self.retention_days = retention_days
        self.cap_gb = cap_gb

    def enforce(self):
        """执行清理，返回删除的文件数。"""
        import glob
        removed = 0
        cutoff = time.time() - self.retention_days * 86400
        for fp in glob.glob(os.path.join(self.root, "**", "*.mp4"), recursive=True):
            if os.path.getmtime(fp) < cutoff:
                os.remove(fp)
                removed += 1
        # 容量水位：如果设置 cap_gb，从最旧开始删直到低于水位
        if self.cap_gb:
            total = sum(os.path.getsize(f)
                        for f in glob.glob(os.path.join(self.root, "**", "*.mp4"),
                                          recursive=True))
            cap_bytes = self.cap_gb * 1024 ** 3
            if total > cap_bytes:
                files = sorted(glob.glob(os.path.join(self.root, "**", "*.mp4")),
                               key=os.path.getmtime)
                for fp in files:
                    os.remove(fp)
                    total -= os.path.getsize(fp)
                    removed += 1
                    if total <= cap_bytes:
                        break
        return removed
