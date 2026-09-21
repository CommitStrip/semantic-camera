"""scam.recording —— L2 录像证据链：分段登记 → 事件片段导出 → 独立读取契约。

产品约束（LINUX-CONTEXT §3.3 / 交接单 Z3）：
- 录像默认关闭（record_enabled），是证据增强，不是告警成立前提；
- ffmpeg/磁盘/文件故障只降级证据完整度并可见，不阻断告警落库；
- 片段可追溯：相机、绝对时间窗、审查段、配置哈希、模型哈希；
- 读取走独立于 JPEG 的录像契约（mp4 魔数 + 大小 + SHA-256 + 围栏），
  与 /api/evidence 的 JPEG 契约互不冒充。

存储布局（相对数据库所在目录）：
  cameras/<相机>/<日期>/seg_YYYYmmdd-HHMMSS.mp4   连续分段（SegmentRecorder 产物）
  clips/<相机>/clip_<审查段8>_<序>.mp4            事件片段（本模块导出）
"""

import glob
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import time

from .recorder import (RetentionPolicy, SegmentRecorder, _SEG_RE,
                       seg_start_time)

_CAMERA_ID_RE = re.compile(r"[^A-Za-z0-9_-]+")


def _safe_part(value, fallback="camera"):
    cleaned = _CAMERA_ID_RE.sub("-", str(value)).strip("-_")[:48]
    return cleaned or fallback


def sha256_file(path, chunk=1 << 20):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def config_hash(cam_cfg):
    """确定性配置哈希：排序 JSON，供录像证据追溯"当时的配置"。"""
    blob = json.dumps(cam_cfg, sort_keys=True,
                      ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _rel_posix(path, root):
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    if rel.startswith("../") or rel == "..":
        raise ValueError("路径越出存储根目录")
    return rel


def _seg_start(path):
    """按本地时区解析分段文件名的起始时间戳（单一真值：recorder.seg_start_time）。"""
    return seg_start_time(path)


def find_segments(root, camera_id, t_start, t_end, segment_seconds=600):
    """返回文件名时间与 [t_start, t_end] 窗口相交的分段绝对路径（按时间升序）。

    以文件名起始时间为准、按 segment_seconds 近似段长——足够定位导出窗口，
    不冒充精确到帧的时间线。
    """
    camera_dir = os.path.join(root, _safe_part(camera_id))
    hits = []
    pattern = os.path.join(camera_dir, "*", "seg_*.mp4")
    for path in glob.glob(pattern):
        seg_start = _seg_start(path)
        if seg_start is None:
            continue
        if seg_start <= t_end and seg_start + segment_seconds >= t_start:
            hits.append((seg_start, path))
    hits.sort()
    return [path for _, path in hits]


class RecordingStore:
    """录像证据的登记与围栏读取：只认数据库索引，绝不按路径裸读。"""

    def __init__(self, root, db_path, segments_root=None):
        self.root = os.path.abspath(root)
        self.segments_root = os.path.abspath(
            segments_root or os.path.join(self.root, "cameras"))
        self.db_path = db_path

    def resolve(self, relative_path):
        candidate = os.path.normcase(os.path.abspath(
            os.path.join(self.root, relative_path)))
        fenced = os.path.normcase(self.root)
        if os.path.commonpath((fenced, candidate)) != fenced:
            raise ValueError("录像路径越出存储根目录")
        return os.path.abspath(os.path.join(self.root, relative_path))

    def register(self, conn, *, asset_id, owner_type, owner_id, camera,
                 kind, path, t_start, t_end, metadata, state="available"):
        """登记录像资产；path 转为相对根目录的 POSIX 路径；文件缺失记 missing。"""
        full = path if os.path.isabs(path) else os.path.join(self.root, path)
        if state == "available" and not os.path.isfile(full):
            state = "missing"
        size = sha = None
        if state == "available":
            size = os.path.getsize(full)
            sha = sha256_file(full)
        # evidence_assets 的 size/sha 为 NOT NULL：缺失资产以 0/"" 占位，
        # 真实状态由 state='missing' 表达
        size = int(size or 0)
        sha = sha or ""
        rel = _rel_posix(full, self.root)
        now = time.time()
        conn.execute(
            "INSERT INTO evidence_assets"
            " (asset_id,owner_type,owner_id,camera,kind,path,state,mime,"
            "  t_start,t_end,score,size_bytes,sha256,created_at,updated_at,"
            "  metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(asset_id) DO UPDATE SET"
            " path=excluded.path,state=excluded.state,"
            " t_start=excluded.t_start,t_end=excluded.t_end,"
            " size_bytes=excluded.size_bytes,sha256=excluded.sha256,"
            " updated_at=excluded.updated_at,metadata=excluded.metadata",
            (asset_id, owner_type, owner_id, camera, kind, rel, state,
             "video/mp4", t_start, t_end, None, size, sha, now, now,
             json.dumps(metadata, ensure_ascii=False, separators=(",", ":"))))
        conn.commit()
        return asset_id

    def read_recording(self, asset_id):
        """独立录像读取契约：kind 限定录像类、mp4 魔数、大小与 SHA-256 校验，
        缺失/损坏如实回写状态。返回 (state, bytes)。"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT kind,mime,path,size_bytes,sha256,state"
                " FROM evidence_assets WHERE asset_id=?", (asset_id,)
            ).fetchone()
            if row is None:
                return "unknown", None

            def mark(state):
                conn.execute(
                    "UPDATE evidence_assets SET state=?,updated_at=?"
                    " WHERE asset_id=?", (state, time.time(), asset_id))
                conn.commit()

            if row["kind"] not in ("recording_segment", "event_clip") \
                    or row["mime"] != "video/mp4":
                return "unsupported", None
            try:
                full_path = self.resolve(row["path"])
            except (TypeError, ValueError, OSError):
                mark("corrupt")
                return "corrupt", None
            try:
                with open(full_path, "rb") as handle:
                    content = handle.read()
            except FileNotFoundError:
                mark("missing")
                return "missing", None
            except OSError:
                mark("corrupt")
                return "corrupt", None
            valid = len(content) > 12 and content[4:8] == b"ftyp"
            if row["size_bytes"] is not None:
                valid = valid and len(content) == int(row["size_bytes"])
            if row["sha256"]:
                valid = valid and \
                    hashlib.sha256(content).hexdigest() == row["sha256"]
            if not valid:
                mark("corrupt")
                return "corrupt", None
            mark("available")
            return "available", content
        finally:
            conn.close()


def _run(args):
    proc = subprocess.run(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(
            f"命令失败 rc={proc.returncode}: "
            f"{proc.stderr.decode('utf-8', 'replace')[-400:]}")
    return proc.stdout


def _probe_duration(ffprobe, path):
    """ffprobe 校验时长；ffprobe 缺席时返回 None（诚实降级，不假装验证过）。"""
    if not ffprobe:
        return None
    out = _run([ffprobe, "-v", "error", "-show_entries", "format=duration",
                "-of", "csv=p=0", str(path)])
    return float(out.decode("ascii", "replace").strip() or 0)


def export_event_clip(conn, *, store, ffmpeg, camera_id, camera, review_id,
                      t_start, t_end, semantic_event_ids=None,
                      config_hash=None, model_hash=None,
                      pre_s=10.0, post_s=10.0, ffprobe=None):
    """把 [t_start-pre, t_end+post] 的录像切成事件片段并登记。

    无覆盖分段返回 None（诚实：录像未覆盖该时刻）；导出/校验失败抛
    RuntimeError，由调用方降级——绝不阻断告警链。
    """
    window_start = t_start - pre_s
    # The scheduler must wait for the complete post-buffer before calling us.
    # Truncating to ``time.time()`` would create a final asset early, after
    # which the idempotency check prevents the missing tail from ever being
    # exported.
    window_end = t_end + post_s
    if window_end <= window_start:
        return None
    segments = find_segments(
        store.segments_root, camera_id, window_start, window_end)
    if not segments:
        return None

    camera_part = _safe_part(camera_id)
    review_part = _safe_part(review_id, "review")[:16]
    clip_dir = os.path.join(store.root, "clips", camera_part)
    os.makedirs(clip_dir, exist_ok=True)
    asset_id = "clip:" + hashlib.sha256(
        str(review_id).encode("utf-8")).hexdigest()[:24]
    out_path = os.path.join(
        clip_dir, f"clip_{review_part}_{asset_id[-8:]}.mp4")
    tmp_paths = []

    def cut(src, offset_start, offset_end, dst):
        _run([ffmpeg, "-v", "error", "-ss", f"{max(0.0, offset_start):.3f}",
              "-to", f"{max(0.0, offset_end):.3f}", "-i", src, "-c", "copy",
              "-movflags", "+faststart", "-y", dst])

    try:
        starts = [_seg_start(seg) for seg in segments]
        if None in starts:
            raise RuntimeError("分段文件名时间解析失败")
        if len(segments) == 1:
            cut(segments[0], window_start - starts[0],
                window_end - starts[0], out_path)
        else:
            parts = []
            for idx, (seg, seg_t) in enumerate(zip(segments, starts)):
                part = os.path.join(
                    clip_dir, f"_part{idx}_{asset_id[-8:]}.mp4")
                cut(seg, window_start - seg_t, window_end - seg_t, part)
                tmp_paths.append(part)
                parts.append(part)
            listing = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, encoding="utf-8")
            try:
                for part in parts:
                    listing.write("file '" + part.replace("'", "'\\''") + "'\n")
                listing.close()
                _run([ffmpeg, "-v", "error", "-f", "concat", "-safe", "0",
                      "-i", listing.name, "-c", "copy",
                      "-movflags", "+faststart", "-y", out_path])
            finally:
                os.unlink(listing.name)
        for part in tmp_paths:
            try:
                os.unlink(part)
            except OSError:
                pass

        duration = _probe_duration(ffprobe, out_path)
        if duration is not None and duration <= 0:
            raise RuntimeError("导出片段时长校验为 0")
        metadata = {"camera_id": camera_id, "review_id": review_id,
                    "semantic_event_ids": list(semantic_event_ids or []),
                    "window": [window_start, window_end],
                    "config_hash": config_hash, "model_hash": model_hash,
                    "ffprobe": "checked" if ffprobe else "absent",
                    "segments": len(segments)}
        store.register(conn, asset_id=asset_id,
                       owner_type="review_segment", owner_id=review_id,
                       camera=camera, kind="event_clip", path=out_path,
                       t_start=window_start, t_end=window_end,
                       metadata=metadata)
        return asset_id
    except Exception:
        for leftover in tmp_paths + [out_path]:
            try:
                if os.path.isfile(leftover):
                    os.unlink(leftover)
            except OSError:
                pass
        raise


def export_pending_clips(conn, *, store, ffmpeg, camera_map, config_hashes,
                         model_hashes=None, pre_s=10.0, post_s=10.0,
                         ffprobe=None, now=None):
    """扫描已闭合且尚无事件片段的审查段，逐个导出（at-least-once 幂等）。

    camera_map: {camera: camera_id}（录像开启的相机）；返回导出成功的片段数。
    单个失败只计数不中断——下一轮会重试（UNIQUE 约束保证不重复登记）。
    """
    if not camera_map:
        return 0
    now = time.time() if now is None else float(now)
    rows = conn.execute(
        "SELECT review_id,camera,t_start,t_end,semantic_event_ids"
        " FROM review_segments"
        " WHERE t_end IS NOT NULL AND end_reason != 'recovered_after_restart'"
        " ORDER BY t_start DESC LIMIT 50").fetchall()
    done = 0
    model_hashes = model_hashes or {}
    for row in rows:
        camera = row["camera"]
        if camera not in camera_map:
            continue
        # A closed review is not export-ready until its full post-buffer has
        # elapsed. Leave it pending so a later scan exports the exact window.
        if now < float(row["t_end"]) + post_s:
            continue
        existing = conn.execute(
            "SELECT 1 FROM evidence_assets WHERE owner_type='review_segment'"
            " AND owner_id=? AND kind='event_clip'", (row["review_id"],)
        ).fetchone()
        if existing:
            continue
        try:
            semantic_ids = json.loads(row["semantic_event_ids"] or "[]")
        except (TypeError, ValueError):
            semantic_ids = []
        asset = export_event_clip(
            conn, store=store, ffmpeg=ffmpeg, camera_id=camera_map[camera],
            camera=camera, review_id=row["review_id"],
            t_start=float(row["t_start"]), t_end=float(row["t_end"]),
            semantic_event_ids=semantic_ids,
            config_hash=config_hashes.get(camera),
            model_hash=model_hashes.get(camera),
            pre_s=pre_s, post_s=post_s, ffprobe=ffprobe)
        if asset:
            done += 1
    return done


class RecordingManager:
    """每相机 0/1 个分段录像器的薄管理壳：启停、降级状态、健康快照。

    ffmpeg 缺失/启动失败只记降级原因，绝不抛出阻断值守。
    """

    def __init__(self, storage_root):
        self.storage_root = os.path.abspath(storage_root)
        self._recorders = {}
        self._policies = {}
        self._errors = {}

    def enable(self, camera_id, rtsp_url, **kwargs):
        camera_id = _safe_part(camera_id)
        if camera_id in self._recorders:
            return True
        try:
            recorder = SegmentRecorder(
                camera_id, rtsp_url, storage_root=self.storage_root, **kwargs)
            recorder.start()
        except Exception as e:
            self._errors[camera_id] = str(e)
            return False
        self._recorders[camera_id] = recorder
        self._policies[camera_id] = RetentionPolicy(
            recorder.storage_root,
            retention_days=recorder.retention_days,
            cap_gb=recorder.cap_gb,
            # 活动段保护窗口：覆盖一个完整段周期以上，正在写/刚写完的段绝不删
            min_age_s=max(120, 2 * recorder.segment_seconds))
        self._errors.pop(camera_id, None)
        return True

    def status(self):
        items = []
        for camera_id, recorder in self._recorders.items():
            items.append({"camera": camera_id,
                          "recording": recorder.running,
                          "error": self._errors.get(camera_id)})
        for camera_id, error in self._errors.items():
            if camera_id not in self._recorders:
                items.append({"camera": camera_id, "recording": False,
                              "error": error})
        return items

    def maintain(self, now=None):
        """维持录像进程、跨日轮转并执行容量双闸；故障只降级单相机。"""
        healthy = 0
        for camera_id, recorder in list(self._recorders.items()):
            try:
                recorder.maintain(now=now)
            except Exception as exc:
                self._errors[camera_id] = f"录像进程维护失败: {exc}"
                continue
            healthy += 1
            # 强契约：当前活动段（文件名最新 seg_*）显式豁免——不依赖 mtime，
            # 进程卡死 mtime 老化时容量闸也绝不能删正在写的分段。
            current = recorder.current_segment
            protected = {current} if current else None
            try:
                self._policies[camera_id].enforce(protected=protected)
            except Exception as exc:
                # 清理失败不能让告警链或录像进程停摆，但必须在健康接口可见。
                self._errors[camera_id] = f"录像保留清理失败: {exc}"
            else:
                self._errors.pop(camera_id, None)
        return healthy

    def stop_all(self):
        for recorder in self._recorders.values():
            try:
                recorder.stop()
            except Exception:
                pass
        self._recorders.clear()
        self._policies.clear()
