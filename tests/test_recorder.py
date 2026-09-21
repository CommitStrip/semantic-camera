"""分段录像器的 Windows 目录、跨日轮转和停止恢复测试。"""

import os
import subprocess
import time
from pathlib import Path

from scam.recorder import SegmentRecorder, seg_start_time


class _Proc:
    def __init__(self, timeout_once=False):
        self.returncode = None
        self.terminated = False
        self.killed = False
        self.timeout_once = timeout_once

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        if self.timeout_once:
            self.timeout_once = False
            raise subprocess.TimeoutExpired("ffmpeg", timeout)
        self.returncode = self.returncode if self.returncode is not None else 0
        return self.returncode


def _timestamp(text):
    return time.mktime(time.strptime(text, "%Y-%m-%d %H:%M:%S"))


def test_start_creates_current_day_directory_and_safe_pattern(
        monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr("scam.platform.find_ffmpeg", lambda: "ffmpeg.exe")
    monkeypatch.setattr(
        subprocess, "Popen",
        lambda args, **kwargs: calls.append((args, kwargs)) or _Proc())
    recorder = SegmentRecorder("front", "rtsp://camera", str(tmp_path))
    now = _timestamp("2026-09-19 23:59:00")

    recorder.start(now=now)

    pattern = calls[0][0][-1]
    assert os.path.isdir(tmp_path / "front" / "2026-09-19")
    assert pattern.endswith(
        os.path.join("front", "2026-09-19", "seg_%Y%m%d-%H%M%S.mp4"))


def test_maintain_rolls_to_new_day(monkeypatch, tmp_path):
    processes = []
    monkeypatch.setattr("scam.platform.find_ffmpeg", lambda: "ffmpeg.exe")
    monkeypatch.setattr(
        subprocess, "Popen",
        lambda *_a, **_k: processes.append(_Proc()) or processes[-1])
    recorder = SegmentRecorder("front", "rtsp://camera", str(tmp_path))
    recorder.start(now=_timestamp("2026-09-19 23:59:00"))

    assert recorder.maintain(
        now=_timestamp("2026-09-20 00:01:00")) is True
    assert len(processes) == 2 and processes[0].terminated
    assert os.path.isdir(tmp_path / "front" / "2026-09-20")


def test_stop_kills_ffmpeg_after_grace_timeout(tmp_path):
    recorder = SegmentRecorder("front", "rtsp://camera", str(tmp_path))
    proc = _Proc(timeout_once=True)
    recorder.proc = proc

    recorder.stop()

    assert proc.terminated and proc.killed


# ---------- Z4：保留策略双闸、活动段保护与故障降级 ----------

import pytest

from scam.recorder import RetentionPolicy, SegmentRecorder


def _seg(root, name, size=256, age_s=None, day_dir=None):
    """分段夹具：目录围栏契约下，文件必须落在与文件名日期一致的日期目录。"""
    t = seg_start_time(name)
    auto_day = time.strftime(
        "%Y-%m-%d", time.localtime(t)) if t is not None else "2026-09-19"
    path = Path(root) / (day_dir or auto_day) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(b"\x00" * size)
    if age_s is not None:
        stamp = time.time() - age_s
        os.utime(path, (stamp, stamp))
    return path


def test_retention_deletes_by_age_keeps_recent(tmp_path):
    _seg(tmp_path, "seg_20260911-000000.mp4", age_s=8 * 86400)
    mid = _seg(tmp_path, "seg_20260917-000000.mp4", age_s=2 * 86400)
    fresh = _seg(tmp_path, "seg_20260919-120000.mp4", age_s=60)

    removed = RetentionPolicy(str(tmp_path), retention_days=7).enforce()

    assert removed == 1
    assert not (tmp_path / "seg_20260911-000000.mp4").exists()
    assert mid.exists() and fresh.exists()


def test_retention_capacity_deletes_oldest_closed_first(tmp_path):
    old = _seg(tmp_path, "seg_20260916-000000.mp4", size=100,
               age_s=3 * 86400)
    mid = _seg(tmp_path, "seg_20260917-000000.mp4", size=100,
               age_s=2 * 86400)
    active = _seg(tmp_path, "seg_20260919-115900.mp4", size=100,
                  age_s=30)

    removed = RetentionPolicy(str(tmp_path), retention_days=7,
                              cap_gb=250 / 1024 ** 3,
                              min_age_s=120).enforce()

    assert removed == 1
    assert not old.exists()   # 最旧闭合段先删
    assert mid.exists()       # 达到水位即停
    assert active.exists()    # 活动段（过新）绝不动


def test_retention_protects_active_segment_even_over_cap(tmp_path):
    active = _seg(tmp_path, "seg_20260919-115500.mp4", size=10_000, age_s=5)

    removed = RetentionPolicy(str(tmp_path), retention_days=7,
                              cap_gb=1 / 1024 ** 3,
                              min_age_s=120).enforce()

    assert removed == 0
    assert active.exists()


def test_retention_both_gates_combined_deterministic(tmp_path):
    d8 = _seg(tmp_path, "seg_20260911-000000.mp4", size=300,
              age_s=8 * 86400)
    d3 = _seg(tmp_path, "seg_20260916-000000.mp4", size=300,
              age_s=3 * 86400)
    d1 = _seg(tmp_path, "seg_20260918-000000.mp4", size=300,
              age_s=1 * 86400)
    act = _seg(tmp_path, "seg_20260919-115900.mp4", size=300, age_s=30)

    removed = RetentionPolicy(str(tmp_path), retention_days=7,
                              cap_gb=700 / 1024 ** 3,
                              min_age_s=120).enforce()

    assert removed == 2
    assert not d8.exists()    # 年龄闸
    assert not d3.exists()    # 容量闸接着删到水位
    assert d1.exists()        # 600B ≤ 700B 保留
    assert act.exists()


def test_retention_delete_failure_degrades_but_still_cleans(tmp_path):
    stuck_seg = _seg(tmp_path, "seg_20260911-000000.mp4", size=100,
                     age_s=8 * 86400)
    other = _seg(tmp_path, "seg_20260910-000000.mp4", size=100,
                 age_s=9 * 86400)
    stuck = str(stuck_seg)
    real_remove = os.remove

    def failing_remove(path, *args, **kwargs):
        if os.path.abspath(str(path)) == os.path.abspath(stuck):
            raise PermissionError(13, "模拟占用")
        return real_remove(path, *args, **kwargs)

    import scam.recorder as recorder_mod
    original_remove = recorder_mod.os.remove
    recorder_mod.os.remove = failing_remove
    try:
        with pytest.raises(RuntimeError):
            RetentionPolicy(str(tmp_path), retention_days=7).enforce()
    finally:
        recorder_mod.os.remove = original_remove

    assert not other.exists()   # 其余分段本轮仍被清理
    assert stuck_seg.exists()     # 失败文件保留待下轮


# ---------- Z4.1 强契约：seg_* 限定 + 显式活动段豁免 ----------

def _named_seg(root, day_dir, name, size=256, age_s=None):
    path = Path(root) / day_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(b"\x00" * size)
    if age_s is not None:
        stamp = time.time() - age_s
        os.utime(path, (stamp, stamp))
    return path


def test_current_segment_is_newest_by_filename_not_mtime(tmp_path):
    recorder = SegmentRecorder("front", "rtsp://camera", str(tmp_path))
    assert recorder.current_segment is None          # 空目录

    old = _named_seg(tmp_path, "front/2026-09-19",
                     "seg_20260919-080000.mp4", age_s=3600)   # mtime 较新
    new = _named_seg(tmp_path, "front/2026-09-19",
                     "seg_20260919-090000.mp4", age_s=7200)   # mtime 较旧

    current = recorder.current_segment
    assert current is not None and os.path.normcase(new) == \
        os.path.normcase(current), "活动段按文件名时间判定，不被 mtime 干扰"
    assert os.path.normcase(old) != os.path.normcase(current)


def test_retention_never_deletes_non_seg_mp4(tmp_path):
    bonus = _seg(tmp_path, "bonus.mp4", size=100, age_s=8 * 86400,
                 day_dir="not-a-date")   # 非分段命名，放非日期目录
    keep = _seg(tmp_path, "seg_20260919-120000.mp4", size=100, age_s=60)

    removed = RetentionPolicy(str(tmp_path), retention_days=7,
                              cap_gb=50 / 1024 ** 3).enforce()

    assert removed == 0
    assert bonus.exists(), "非 seg_*.mp4 资产绝不进入清理"
    assert keep.exists()


def test_retention_explicit_protected_set_guards_aged_active(tmp_path):
    """长卡死场景：活动段文件名与 mtime 都已老化，显式豁免集合仍保它。"""
    aged_active = _named_seg(tmp_path, "2026-09-19",
                             "seg_20260919-080000.mp4", size=10_000,
                             age_s=2 * 86400)
    fresh = _seg(tmp_path, "fresh.mp4", size=100, age_s=30)

    policy = RetentionPolicy(str(tmp_path), retention_days=7,
                             cap_gb=1 / 1024 ** 3, min_age_s=120)
    assert policy.enforce(
        protected={aged_active}) == 0
    assert aged_active.exists(), "显式豁免的活动段即使 mtime 老化也不得删除"
    assert fresh.exists()

    # 对照：无豁免时同一老化段会被容量闸删除（证明保护来自显式集合）
    policy.enforce()
    assert not aged_active.exists()


def test_retention_ignores_non_date_directory(tmp_path):
    """任意非日期子目录（not-a-date/）绝不被保留策略触碰。"""
    rogue = _named_seg(tmp_path, "not-a-date", "seg_20200101-000000.mp4",
                       size=100, age_s=8 * 86400)
    legit = _seg(tmp_path, "seg_20260911-000000.mp4", size=100,
                 age_s=8 * 86400)

    removed = RetentionPolicy(str(tmp_path), retention_days=7,
                              min_age_s=120).enforce()

    assert removed == 1
    assert legit.exists() is False
    assert rogue.exists(), "非日期目录内的文件绝不进入清理"


def test_retention_ignores_dir_date_mismatch(tmp_path):
    """目录日期与分段文件名日期不一致时，该分段不在清理范围内。"""
    mismatch = _named_seg(tmp_path, "2026-09-11", "seg_20200101-000000.mp4",
                          size=100, age_s=8 * 86400)
    legit = _seg(tmp_path, "seg_20260911-000000.mp4", size=100,
                 age_s=8 * 86400)

    removed = RetentionPolicy(str(tmp_path), retention_days=7,
                              min_age_s=120).enforce()

    assert removed == 1
    assert legit.exists() is False
    assert mismatch.exists(), "目录日≠文件名日的分段绝不进入清理"
