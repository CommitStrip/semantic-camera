"""recorder.py —— 录像分段（ffmpeg 子进程流拷贝，零 CPU）+ 保留策略。"""

import os
import re
import subprocess
import time

_SEG_RE = re.compile(
    r"seg_(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})\.mp4$")


def seg_start_time(path):
    """按本地时区解析分段文件名的起始时间戳；非分段名返回 None。"""
    match = _SEG_RE.search(str(path).replace("\\", "/"))
    if not match:
        return None
    y, mo, d, h, mi, s = (int(g) for g in match.groups())
    return time.mktime((y, mo, d, h, mi, s, 0, 0, -1))


_DAY_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def valid_day_segments(root):
    """目录围栏（Z4.2）：只枚举 root 下**单层有效 YYYY-MM-DD 目录**中、
    目录日期与分段文件名日期一致的 seg_*.mp4。

    任意子目录（如 not-a-date/）、目录日≠文件名日的分段一律排除——
    保留策略与活动段判定共用本围栏，绝不按裸 glob 清理。
    """
    import glob
    root = str(root)
    if not os.path.isdir(root):
        return []
    hits = []
    try:
        entries = os.listdir(root)
    except OSError:
        return []
    for day_dir in entries:
        if not _DAY_DIR_RE.match(day_dir):
            continue
        try:
            dir_date = time.strptime(day_dir, "%Y-%m-%d")
        except ValueError:
            continue
        for fp in glob.glob(os.path.join(root, day_dir, "seg_*.mp4")):
            t = seg_start_time(fp)
            if t is None:
                continue
            file_date = time.localtime(t)
            if (file_date.tm_year, file_date.tm_mon, file_date.tm_mday) == \
                    (dir_date.tm_year, dir_date.tm_mon, dir_date.tm_mday):
                hits.append(fp)
    return hits


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
        self._day = None

    def start(self, now=None):
        """启动 ffmpeg 分段录像子进程。找不到 ffmpeg 时抛 RuntimeError（不静默）。"""
        from .platform import find_ffmpeg
        ffmpeg = find_ffmpeg()
        if not ffmpeg:
            raise RuntimeError(
                "未找到 ffmpeg——请安装并加入 PATH（录像功能不可用）")
        if self.running:
            return
        now = time.time() if now is None else now
        self._day = time.strftime("%Y-%m-%d", time.localtime(now))
        day_root = os.path.join(self.storage_root, self._day)
        os.makedirs(day_root, exist_ok=True)
        out_pattern = os.path.join(day_root, "seg_%Y%m%d-%H%M%S.mp4")
        self.proc = subprocess.Popen(
            [ffmpeg,
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
            try:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
            finally:
                self.proc = None

    def maintain(self, now=None):
        """进程退出或跨日时重启；新日期目录在启动前明确创建。"""
        now = time.time() if now is None else now
        desired_day = time.strftime("%Y-%m-%d", time.localtime(now))
        if self.proc is not None and not self.running:
            self.proc = None
        if self.running and self._day == desired_day:
            return False
        if self.running:
            self.stop()
        self.start(now=now)
        return True

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None

    @property
    def current_segment(self):
        """ffmpeg 分段复用器当前正在写的分段：文件名时间最新的 seg_*.mp4。

        按文件名而非 mtime 判定——进程卡死不再滚动分段时，文件名最新者仍是
        当前段（mtime 会老化，不足以保护长卡死场景）。保留策略经由
        RecordingManager 把该文件列入显式豁免集合，构成强契约。
        目录围栏与保留策略共用 valid_day_segments。空返回 None。
        """
        best = None
        best_t = None
        for path in valid_day_segments(self.storage_root):
            t = seg_start_time(path)
            if t is not None and (best_t is None or t > best_t):
                best, best_t = path, t
        return best


class RetentionPolicy:
    """保留策略：按天数 + 按容量双闸清理旧分段。

    三层保护契约（Z4.1）：
    1. 只枚举 seg_*.mp4——clips/手工 mp4 结构性不可清理；
    2. 显式豁免集合 protected——Manager 传入每相机当前活动段（按文件名判定，
       不依赖 mtime，进程卡死 mtime 老化也绝不删除）；
    3. min_age_s 纵深防御——刚写完不久的分段一律跳过。
    clips 与数据库不在清理根（策略根=单相机分段目录）。
    """

    def __init__(self, storage_root, retention_days=7, cap_gb=None,
                 min_age_s=120):
        self.root = storage_root
        self.retention_days = retention_days
        self.cap_gb = cap_gb
        self.min_age_s = max(0, int(min_age_s))

    def _segments(self):
        """目录围栏枚举：仅单层有效日期目录、目录日=文件名日的 seg_*.mp4。"""
        return valid_day_segments(self.root)

    def enforce(self, protected=None):
        """执行清理，返回删除的文件数。

        强契约三层：
        1. 只枚举 seg_*.mp4（clips/手工 mp4 结构性不可清理）；
        2. 显式豁免集合 protected（绝对路径；Manager 传入每相机当前活动段，
           按文件名判定、不依赖 mtime——进程卡死 mtime 老化也绝不删除）；
        3. min_age_s 纵深防御（过新段一律跳过）。

        确定性顺序：先年龄闸（mtime 升序，遇首个未过期即停），再容量闸
        （剩余分段最旧优先删到水位下）。单文件删除失败不中断本轮对其余
        分段的清理；存在失败时最后抛 RuntimeError，由调用方降级为该相机
        录像健康事件，绝不影响告警链。
        """
        removed = 0
        failures = 0
        now = time.time()
        cutoff = now - self.retention_days * 86400
        protected_set = {
            os.path.normcase(os.path.abspath(p))
            for p in (protected or [])}

        def _skip(fp):
            if os.path.normcase(os.path.abspath(fp)) in protected_set:
                return True
            return now - os.path.getmtime(fp) < self.min_age_s

        for fp in sorted(self._segments(), key=os.path.getmtime):
            if os.path.getmtime(fp) >= cutoff:
                break
            if _skip(fp):
                continue
            try:
                os.remove(fp)
                removed += 1
            except OSError:
                failures += 1

        if self.cap_gb:
            cap_bytes = self.cap_gb * 1024 ** 3
            total = 0
            for fp in self._segments():
                try:
                    total += os.path.getsize(fp)
                except OSError:
                    continue
            if total > cap_bytes:
                for fp in sorted(self._segments(), key=os.path.getmtime):
                    if total <= cap_bytes:
                        break
                    if _skip(fp):
                        continue
                    try:
                        size = os.path.getsize(fp)
                        os.remove(fp)
                        total -= size
                        removed += 1
                    except OSError:
                        failures += 1
        if failures:
            raise RuntimeError(
                f"{failures} 个分段清理失败（磁盘/权限），本轮其余分段已处理")
        return removed
