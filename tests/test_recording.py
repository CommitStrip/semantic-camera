"""Z3 录像证据链测试：窗口定位、证据登记、导出幂等、降级隔离、围栏读取。

除真 ffmpeg 守护测试外全部确定性（不依赖 ffmpeg 存在）。
文件操作统一走 pathlib（.open()），路径段显式校验。
"""

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

import scam.db as db
from scam.recording import (RecordingManager, RecordingStore,
                            config_hash, export_event_clip,
                            export_pending_clips, find_segments)


def _conn(tmp_path):
    conn = db.connect(str(tmp_path / "r.db"))
    db.init_schema(conn)
    return conn


def _safe_name(value):
    if ".." in value or "/" in value or "\\" in value:
        raise ValueError("测试名称不得含路径段")
    return value


def _mk_segment(root, camera, ts, size=2048):
    """造一个文件名时间戳合法的分段文件（内容任意，登记/读取测试够用）。"""
    root = Path(root)
    camera = _safe_name(camera)
    day_dir = root / camera / time.strftime("%Y-%m-%d", time.localtime(ts))
    day_dir.mkdir(parents=True, exist_ok=True)
    name = time.strftime("seg_%Y%m%d-%H%M%S.mp4", time.localtime(ts))
    path = day_dir / name
    header = b"\x00\x00\x00\x18ftypmp42" + b"\x01" * (size - 20)
    with path.open("wb") as handle:
        handle.write(header)
    return str(path)


def _mp4_bytes(size=4096):
    return b"\x00\x00\x00\x18ftypmp42" + b"\x02" * (size - 20)


# ---------- 窗口定位 ----------

def test_find_segments_window_intersects(tmp_path):
    now = time.time()
    root = str(tmp_path)
    seg_now = _mk_segment(root, "cam-a", now - 60)     # 1 分钟前开始的段
    _mk_segment(root, "cam-a", now - 3600)             # 1 小时前的旧段
    _mk_segment(root, "cam-b", now - 60)               # 其他相机

    hits = find_segments(root, "cam-a", now - 30, now)
    assert seg_now in hits and all("cam-a" in p for p in hits)
    assert len(hits) == 1

    # 窗口越过段尾（1 分钟前的段按 600s 段长覆盖到 now+540，之后不相交）
    assert find_segments(root, "cam-a", now + 545, now + 560) == []


# ---------- 证据登记与围栏读取 ----------

def test_register_segment_and_fenced_read(tmp_path):
    conn = _conn(tmp_path)
    store = RecordingStore(str(tmp_path), str(tmp_path / "r.db"))
    now = time.time()
    seg = _mk_segment(tmp_path, "cam-a", now - 60)

    asset = store.register(
        conn, asset_id="seg:1", owner_type="review_segment",
        owner_id="rev-1", camera="cam-a", kind="recording_segment",
        path=seg, t_start=now - 60, t_end=now,
        metadata={"config_hash": "abc"})
    assert asset == "seg:1"

    state, content = store.read_recording("seg:1")
    assert state == "available"
    assert content.startswith(b"\x00\x00\x00\x18ftyp")
    row = conn.execute(
        "SELECT size_bytes,sha256,metadata FROM evidence_assets"
        " WHERE asset_id='seg:1'").fetchone()
    assert row["size_bytes"] == os.path.getsize(seg)
    assert row["sha256"] == hashlib.sha256(
        Path(seg).read_bytes()).hexdigest()
    assert json.loads(row["metadata"])["config_hash"] == "abc"
    conn.close()


def test_register_missing_file_marks_missing(tmp_path):
    conn = _conn(tmp_path)
    store = RecordingStore(str(tmp_path), str(tmp_path / "r.db"))
    # 相对路径登记：文件不存在 → 诚实 missing（不构造绝对路径）
    store.register(conn, asset_id="seg:2", owner_type="review_segment",
                   owner_id="rev-2", camera="cam-a",
                   kind="recording_segment", path="gone.mp4",
                   t_start=1.0, t_end=2.0, metadata={})
    state = conn.execute(
        "SELECT state FROM evidence_assets WHERE asset_id='seg:2'"
    ).fetchone()[0]
    assert state == "missing"
    conn.close()


def test_read_recording_detects_corrupt(tmp_path):
    conn = _conn(tmp_path)
    store = RecordingStore(str(tmp_path), str(tmp_path / "r.db"))
    seg = Path(_mk_segment(tmp_path, "cam-a", time.time() - 60))
    store.register(conn, asset_id="seg:3", owner_type="review_segment",
                   owner_id="rev-3", camera="cam-a",
                   kind="recording_segment", path=str(seg),
                   t_start=1.0, t_end=2.0, metadata={})
    with seg.open("ab") as handle:
        handle.write(b"appended")        # 破坏 SHA-256/大小
    state, _ = store.read_recording("seg:3")
    assert state == "corrupt"
    marked = conn.execute(
        "SELECT state FROM evidence_assets WHERE asset_id='seg:3'"
    ).fetchone()[0]
    assert marked == "corrupt"
    conn.close()


def test_unknown_and_unsupported_assets(tmp_path):
    conn = _conn(tmp_path)
    store = RecordingStore(str(tmp_path), str(tmp_path / "r.db"))
    assert store.read_recording("no-such") == ("unknown", None)
    seg = _mk_segment(tmp_path, "cam-a", time.time() - 60)
    store.register(conn, asset_id="jpeg:1", owner_type="tracked_object",
                   owner_id="obj-1", camera="cam-a",
                   kind="clean_best_frame", path=seg,
                   t_start=1.0, t_end=2.0, metadata={})
    assert store.read_recording("jpeg:1") == ("unsupported", None)
    conn.close()


# ---------- 事件片段导出（ffmpeg 替身，确定性） ----------

class FakeFFmpeg:
    """替身：在目标路径写合法 mp4 头文件，模拟导出成功。"""

    def __call__(self, args):
        out = Path(args[-1])
        with out.open("wb") as handle:
            handle.write(_mp4_bytes())


@pytest.fixture
def fake_ffmpeg(monkeypatch):
    import scam.recording as rec
    fake = FakeFFmpeg()
    monkeypatch.setattr(rec, "_run", lambda args: fake(args) or b"")
    return fake


def test_export_event_clip_registers_once(tmp_path, fake_ffmpeg):
    conn = _conn(tmp_path)
    store = RecordingStore(str(tmp_path), str(tmp_path / "r.db"))
    now = time.time()
    _mk_segment(store.segments_root, "cam-a", now - 120)

    asset = export_event_clip(
        conn, store=store, ffmpeg="fake", camera_id="cam-a", camera="cam-a",
        review_id="rev-9", t_start=now - 60, t_end=now - 30,
        config_hash="cfg-1", model_hash="mdl-1", ffprobe=None)
    assert asset and asset.startswith("clip:")
    row = conn.execute(
        "SELECT kind,owner_type,metadata FROM evidence_assets"
        " WHERE asset_id=?", (asset,)).fetchone()
    assert row["kind"] == "event_clip"
    meta = json.loads(row["metadata"])
    assert meta["config_hash"] == "cfg-1"
    assert meta["model_hash"] == "mdl-1"
    assert meta["ffprobe"] == "absent"       # ffprobe 缺席诚实降级

    # 幂等：UNIQUE(owner,owner,kind) 之下再次登记不产生第二行
    export_event_clip(conn, store=store, ffmpeg="fake", camera_id="cam-a",
                      camera="cam-a", review_id="rev-9",
                      t_start=now - 60, t_end=now - 30,
                      ffprobe=None)
    count = conn.execute("SELECT COUNT(*) FROM evidence_assets"
                         " WHERE kind='event_clip'").fetchone()[0]
    assert count == 1
    conn.close()


def test_export_without_coverage_is_honest_none(tmp_path, fake_ffmpeg):
    conn = _conn(tmp_path)
    store = RecordingStore(str(tmp_path), str(tmp_path / "r.db"))
    asset = export_event_clip(
        conn, store=store, ffmpeg="fake", camera_id="cam-a", camera="cam-a",
        review_id="rev-0", t_start=time.time() - 10, t_end=time.time(),
        ffprobe=None)
    assert asset is None                      # 无录像覆盖：诚实返回 None
    conn.close()


def test_export_pending_clips_skips_recovered(tmp_path, fake_ffmpeg):
    conn = _conn(tmp_path)
    store = RecordingStore(str(tmp_path), str(tmp_path / "r.db"))
    now = time.time()
    db.open_review_segment(conn, review_id="rev-ok", camera="cam-a",
                           t_start=now - 120)
    db.close_review_segment(conn, "rev-ok", t_end=now - 60, reason="quiet")
    db.open_review_segment(conn, review_id="rev-stale", camera="cam-a",
                           t_start=now - 300)
    db.close_review_segment(conn, "rev-stale", t_end=now - 240,
                            reason="recovered_after_restart")
    _mk_segment(store.segments_root, "cam-a", now - 120)

    done = export_pending_clips(conn, store=store, ffmpeg="fake",
                                camera_map={"cam-a": "cam-a"},
                                config_hashes={"cam-a": "c"},
                                ffprobe=None)
    assert done == 1                          # 恢复段不导出，正常段导出 1 条
    done = export_pending_clips(conn, store=store, ffmpeg="fake",
                                camera_map={"cam-a": "cam-a"},
                                config_hashes={}, ffprobe=None)
    assert done == 0                          # 第二轮无新待办
    conn.close()


def test_export_pending_waits_for_complete_post_buffer(tmp_path, fake_ffmpeg):
    conn = _conn(tmp_path)
    store = RecordingStore(str(tmp_path), str(tmp_path / "r.db"))
    now = time.time()
    db.open_review_segment(conn, review_id="rev-fresh", camera="cam-a",
                           t_start=now - 60)
    db.close_review_segment(conn, "rev-fresh", t_end=now - 5,
                            reason="quiet")
    _mk_segment(store.segments_root, "cam-a", now - 120)

    assert export_pending_clips(
        conn, store=store, ffmpeg="fake", camera_map={"cam-a": "cam-a"},
        config_hashes={}, post_s=10, now=now, ffprobe=None) == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM evidence_assets WHERE kind='event_clip'"
    ).fetchone()[0] == 0

    assert export_pending_clips(
        conn, store=store, ffmpeg="fake", camera_map={"cam-a": "cam-a"},
        config_hashes={}, post_s=10, now=now + 5, ffprobe=None) == 1
    row = conn.execute(
        "SELECT t_end,metadata FROM evidence_assets WHERE kind='event_clip'"
    ).fetchone()
    assert row["t_end"] == pytest.approx(now + 5)
    assert json.loads(row["metadata"])["window"][1] == pytest.approx(now + 5)
    conn.close()


# ---------- 降级隔离 ----------

def test_recording_manager_failure_is_degraded_not_fatal(tmp_path, monkeypatch):
    from scam.recorder import SegmentRecorder

    def broken_start(self):
        raise RuntimeError("ffmpeg missing")

    monkeypatch.setattr(SegmentRecorder, "start", broken_start)
    manager = RecordingManager(str(tmp_path))
    ok = manager.enable("cam-a", "rtsp://u:p@x/1")
    assert ok is False                        # 失败不抛出，值守不受影响
    assert manager.status() == [{"camera": "cam-a", "recording": False,
                                 "error": "ffmpeg missing"}]


def test_recording_manager_enforces_retention(tmp_path, monkeypatch):
    from scam.recorder import RetentionPolicy, SegmentRecorder

    class Proc:
        def poll(self):
            return None

    monkeypatch.setattr(
        SegmentRecorder, "start", lambda self: setattr(self, "proc", Proc()))
    monkeypatch.setattr(SegmentRecorder, "maintain", lambda self, now=None: False)
    calls = []
    monkeypatch.setattr(
        RetentionPolicy, "enforce",
        lambda self, protected=None:
            calls.append((self.retention_days, self.cap_gb)) or 0)

    manager = RecordingManager(str(tmp_path))
    assert manager.enable("cam-a", "rtsp://x", retention_days=3, cap_gb=2)
    assert manager.maintain() == 1
    assert calls == [(3, 2)]
    assert manager.status() == [
        {"camera": "cam-a", "recording": True, "error": None}]


def test_retention_failure_is_visible_without_stopping_recording(
        tmp_path, monkeypatch):
    from scam.recorder import RetentionPolicy, SegmentRecorder

    class Proc:
        def poll(self):
            return None

    monkeypatch.setattr(
        SegmentRecorder, "start", lambda self: setattr(self, "proc", Proc()))
    monkeypatch.setattr(SegmentRecorder, "maintain", lambda self, now=None: False)

    def fail_cleanup(self):
        raise OSError("disk busy")

    monkeypatch.setattr(RetentionPolicy, "enforce", fail_cleanup)
    manager = RecordingManager(str(tmp_path))
    assert manager.enable("cam-a", "rtsp://x")
    assert manager.maintain() == 1
    status = manager.status()[0]
    assert status["recording"] is True
    assert "保留清理失败" in status["error"]


def test_config_hash_is_deterministic():
    a = config_hash({"id": "c", "source": "rtsp://x", "b": 1, "a": 2})
    b = config_hash({"a": 2, "b": 1, "id": "c", "source": "rtsp://x"})
    assert a == b and len(a) == 64


# ---------- 真 ffmpeg 端到端（有 ffmpeg 才跑） ----------

def test_real_ffmpeg_clip_export(tmp_path):
    import shutil
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        pytest.skip("本机无 ffmpeg，真导出测试跳过（CI 有则执行）")
    import subprocess
    conn = _conn(tmp_path)
    store = RecordingStore(str(tmp_path), str(tmp_path / "r.db"))
    now = time.time()
    seg = Path(_mk_segment(store.segments_root, "cam-a", now - 120))
    # 把假头文件换成真 mp4（1 秒纯色视频）
    subprocess.run(
        [ffmpeg, "-v", "error", "-f", "lavfi", "-i", "color=c=red:d=1",
         "-c:v", "mpeg4", "-y", str(seg)],
        check=True)

    asset = export_event_clip(
        conn, store=store, ffmpeg=ffmpeg, camera_id="cam-a", camera="cam-a",
        review_id="rev-real", t_start=now - 60, t_end=now - 55,
        ffprobe=shutil.which("ffprobe"))
    assert asset
    state, content = store.read_recording(asset)
    assert state == "available" and content[4:8] == b"ftyp"
    conn.close()


# ---------- 接线级根契约（Z3 根目录错位事故的回归锁） ----------

def test_nvr_wiring_root_contract(tmp_path, fake_ffmpeg):
    """nvr 的真实配对必须让导出循环找到录像器实际写出的分段。

    事故回顾：Manager 曾指向 <db>/cameras 而 Store 以 <db> 找段——单元测试
    （两根同目录）看不见，生产路径上片段永远导不出。本测试按 nvr 的真实
    配对构造，锁死 `store.segments_root == manager.storage_root` 契约。
    """
    storage = tmp_path / "storage"
    storage.mkdir()
    db_path = storage / "scam.db"
    conn = db.connect(str(db_path))
    db.init_schema(conn)

    manager = RecordingManager(str(storage / "cameras"))   # nvr 配对
    store = RecordingStore(str(storage), str(db_path))     # segments_root 缺省
    assert store.segments_root == manager.storage_root

    now = time.time()
    day = time.strftime("%Y-%m-%d", time.localtime(now - 120))
    seg_dir = Path(manager.storage_root) / "cam-a" / day
    seg_dir.mkdir(parents=True, exist_ok=True)
    seg = seg_dir / time.strftime(
        "seg_%Y%m%d-%H%M%S.mp4", time.localtime(now - 120))
    with seg.open("wb") as handle:
        handle.write(_mp4_bytes())

    db.open_review_segment(conn, review_id="rev-wire", camera="cam-a",
                           t_start=now - 120)
    db.close_review_segment(conn, "rev-wire", t_end=now - 60, reason="quiet")

    done = export_pending_clips(conn, store=store, ffmpeg="fake",
                                camera_map={"cam-a": "cam-a"},
                                config_hashes={"cam-a": "c"}, ffprobe=None)
    assert done == 1, "按 nvr 真实配对，导出循环必须找到录像器写出的分段"
    conn.close()


# ---------- L3 故障注入：ffmpeg 崩溃重启与降级可见 ----------

class _FakeProc:
    def __init__(self, alive=True):
        self._alive = alive
        self.terminated = False

    def poll(self):
        return None if self._alive else -9

    def terminate(self):
        self.terminated = True

    def kill(self):
        pass

    def wait(self, timeout=None):
        return 0


def test_maintain_restarts_after_ffmpeg_exit(tmp_path, monkeypatch):
    """ffmpeg 进程崩溃后 maintain() 必须自动重启（与跨日轮转同一路径）。"""
    import scam.platform as platform_mod
    import scam.recorder as recorder_mod
    from scam.recorder import SegmentRecorder

    started = {"count": 0}

    class CrashOnceProc(_FakeProc):
        def poll(self):
            return -9 if started["count"] == 1 else None

    def fake_popen(*args, **kwargs):
        started["count"] += 1
        return CrashOnceProc()

    monkeypatch.setattr(recorder_mod.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(platform_mod, "find_ffmpeg", lambda: "ffmpeg")
    recorder = SegmentRecorder("cam-a", "rtsp://u:p@x/1",
                               storage_root=str(tmp_path))
    recorder.start()
    assert not recorder.running             # 首个进程已崩溃
    assert recorder.maintain() is True      # 崩溃被维护循环发现并重启
    assert started["count"] == 2
    assert recorder.running                 # 新进程存活


def test_manager_maintain_failure_is_visible(tmp_path, monkeypatch):
    """ffmpeg 消失后维护失败必须降级可见（status.error），不得抛出或静默。"""
    import scam.platform as platform_mod
    import scam.recorder as recorder_mod
    from scam.recording import RecordingManager

    state = {"has_ffmpeg": True}
    monkeypatch.setattr(platform_mod, "find_ffmpeg",
                        lambda: "ffmpeg" if state["has_ffmpeg"] else None)
    monkeypatch.setattr(recorder_mod.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(alive=True))
    manager = RecordingManager(str(tmp_path))
    assert manager.enable("cam-a", "rtsp://u:p@x/1") is True

    state["has_ffmpeg"] = False             # 之后 ffmpeg 消失且进程崩溃
    manager._recorders["cam-a"].proc = _FakeProc(alive=False)
    healthy = manager.maintain()
    assert healthy == 0
    status = manager.status()
    assert status[0]["recording"] is False
    assert "维护失败" in status[0]["error"]
