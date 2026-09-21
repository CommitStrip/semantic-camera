"""Linux L4 single-video deterministic replay executor (M-R2, fail-closed).

Offline replay wiring: frozen manifest -> fixed detector -> Monitor
adjudication -> fresh SQLite event database.  Fail-closed guarantees:

- publish is atomic no-clobber via ``os.link`` only; platforms without
  atomic hard-link publish fail structurally (no racy rename fallback);
- all three inputs are opened and fingerprint-bound after manifest checking;
  config/model are consumed from those held descriptors and Linux video decode
  is bound through ``/proc/self/fd``; identity plus content are re-checked
  before publish (swap-in/swap-restore rejected);
- EOF is accepted only when the capture reports a finite positive total
  frame count and the read count reaches it; premature termination,
  over-reads and mid-stream decode errors fail the run.

No subprocess, no network.  Success reports ``replay_executed=true``
with quality/release gates null; any failure reports ``false`` and never
leaves a database that could be mistaken for the official output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone

from scam.config import validate_venue
from scam.linux_replay_manifest import verify_manifest_against_inputs
from scam.monitor import Monitor, to_gray
from scam.sinks import SqliteSink

SCHEMA = "scam.linux-replay-run/v1"
_CAP_PROP_FPS = 5
_CAP_PROP_FRAME_COUNT = 6


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ReplayFailure(Exception):
    """结构化失败：消息进入机器可读 errors，退出非零。"""


class _Cv2Capture:
    """生产捕获适配器：真实 OpenCV VideoCapture。

    ``read_frame`` 返回 ``(state, frame)``，state ∈ {"frame", "eof",
    "error"}。EOF 仅在已读帧数达到有限正总帧数时成立；其余任何读取失败
    都是 ``error``（fail-closed）。
    """

    def __init__(self, path):
        import cv2
        self._cap = cv2.VideoCapture(path)
        if not self._cap.isOpened():
            self._cap.release()
            raise ReplayFailure("capture: 无法打开视频文件")

    def get_fps(self):
        return float(self._cap.get(_CAP_PROP_FPS))

    def get_frame_count(self):
        return float(self._cap.get(_CAP_PROP_FRAME_COUNT))

    def read_frame(self, frames_read):
        ok, frame = self._cap.read()
        if ok:
            return "frame", frame
        total = float(self._cap.get(_CAP_PROP_FRAME_COUNT))
        if math.isfinite(total) and total > 0 and frames_read >= int(total):
            return "eof", None
        return "error", None

    def release(self):
        self._cap.release()


def _default_detector_factory(det_cfg, model_bytes):
    from scam.detect import NanoDet
    if not model_bytes:
        raise ReplayFailure("detector: 已验证模型为空")
    # onnxruntime accepts serialized model bytes.  Loading the exact bytes read
    # from the held, fingerprint-checked descriptor closes the path TOCTOU gap:
    # the detector cannot silently reopen a swapped pathname.
    return NanoDet(model_bytes, det_cfg.get("classes", ["person"]),
                   conf=det_cfg.get("conf", 0.4))


def _default_sink_factory(db_path):
    sink = SqliteSink(db_path)
    # Queue M compares database facts only.  The shared SqliteSink normally
    # writes best-frame JPEGs to a sibling ``evidence`` directory, which would
    # escape the temporary database transaction and survive a failed replay.
    # Suppress those side effects for this offline verifier; evidence quality is
    # a separate gate and is deliberately not promoted here.
    sink.evidence = _ReplayNoopEvidenceStore()
    return sink


class _ReplayNoopEvidenceStore:
    def save_best_frame(self, *args, **kwargs):
        return None

    def link_object_frame_to_event(self, *args, **kwargs):
        return None


def _input_identity(path):
    """身份快照含 ctime_ns：原地改写后 ctime 无法由用户态还原。快照以打开
    句柄的 fstat 为权威（Windows 目录枚举的 lstat 时间戳可能滞后）。"""
    fd = _open_hold(path)
    try:
        info = os.fstat(fd)
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                info.st_ctime_ns)
    finally:
        os.close(fd)


def _fd_identity(fd):
    info = os.fstat(fd)
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns)


def _open_hold(path):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) \
        | getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags)


def _read_fd_all(fd):
    chunks = []
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _hash_fd(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def _close_open_rows(db_path, sink, end_s):
    """EOF 保守闭合：按数据库真值找出仍开放的行并逐一闭合。"""
    connection = sqlite3.connect(db_path)
    try:
        reviews = [row[0] for row in connection.execute(
            "SELECT review_id FROM review_segments WHERE t_end IS NULL")]
        events = [row[0] for row in connection.execute(
            "SELECT semantic_event_id FROM semantic_events "
            "WHERE t_end IS NULL")]
        objects = [row[0] for row in connection.execute(
            "SELECT object_id FROM tracked_objects WHERE t_end IS NULL")]
    finally:
        connection.close()
    for review_id in reviews:
        sink.close_review(review_id, t_end=end_s, reason="replay_eof")
    if events:
        sink.close_semantic_events(events, t_end=end_s, reason="replay_eof")
    for object_id in objects:
        sink.close_object(object_id, t_end=end_s, reason="replay_eof")
    return {"reviews": len(reviews), "semantic_events": len(events),
            "objects": len(objects)}


def _publish_no_clobber(temp_db, output_db):
    """原子 no-clobber 发布：仅 os.link。平台不支持硬链接时结构化
    fail-closed——绝不使用带竞态的 rename 退化路径。"""
    try:
        os.link(temp_db, output_db)
    except FileExistsError as exc:
        raise ReplayFailure("output_db: 并发出现，拒绝覆盖") from exc
    except OSError as exc:
        raise ReplayFailure(
            "output_db: 平台不支持原子 no-clobber 发布，"
            f"fail-closed（{exc}）") from exc
    try:
        os.unlink(temp_db)
        return True
    except OSError:
        # The hard link is already the official, complete database.  A failure
        # to remove the private temporary name must not turn a successful
        # publication into a false failure while leaving output_db behind.
        # The caller's finally block retries cleanup.
        return False


def _bind_camera(cfg, camera_id, model, config_dir, errors):
    cams = [c for c in cfg.get("cameras", []) if c.get("id") == camera_id]
    if len(cams) != 1:
        errors.append(
            f"camera_id: {camera_id} 在配置中必须恰好出现一次"
            f"（实际 {len(cams)} 次）")
        return None
    cam = cams[0]
    if cam.get("enabled") is False:
        errors.append(f"camera_id: {camera_id} 未启用")
        return None
    det = cam.get("detector") or {}
    if det.get("engine") != "onnx":
        errors.append("detector: 必须为 onnx 检测器")
        return None
    configured_model = det.get("model")
    if not configured_model:
        errors.append("detector: 缺少 model 路径")
        return None
    # 相对模型路径以 config 所在目录解析，而非进程工作目录
    resolved = (configured_model if os.path.isabs(configured_model)
                else os.path.join(config_dir, configured_model))
    if os.path.realpath(resolved) != os.path.realpath(model):
        errors.append(
            f"detector: 配置模型路径（解析为 {resolved}）与 --model 不一致")
        return None
    # Downstream injected factories also see the resolved path.  The production
    # factory does not reopen it; it consumes the verified bytes instead.
    bound = dict(cam)
    bound["detector"] = dict(det)
    bound["detector"]["model"] = os.path.abspath(resolved)
    return bound


def run_replay(manifest_path, video, config_path, model, camera_id,
               output_db, *, capture_factory=None, detector_factory=None,
               sink_factory=None):
    """Run one deterministic replay; returns (result, errors)."""
    errors = []
    held_fds = []
    capture = sink = detector = None
    temp_db = None

    def failure():
        return {
            "schema": SCHEMA,
            "kind": "replay_run_result",
            "created_at": _utc_now(),
            "camera_id": camera_id,
            "replay_executed": False,
            "errors": list(errors),
            "quality_gate_passed": None,
            "release_gate_passed": None,
        }

    try:
        # 1) manifest 先验：任何输出（含临时库）写入前完成
        verify, verify_errors = verify_manifest_against_inputs(
            str(manifest_path), video, config_path, model)
        errors.extend(verify_errors or [])
        if verify is None or not verify.get("inputs_match"):
            if not verify_errors:
                errors.append(
                    "manifest: 与当前输入不一致，replay 拒绝执行")
            return failure(), errors

        # 2) 三输入打开后与刚完成的 manifest 指纹绑定；config/model 直接从
        #    持有句柄消费，生产视频通过 Linux /proc 描述符路径解码。
        verified_hashes = {
            item["role"]: item["current"]["sha256"]
            for item in verify.get("comparisons", [])
            if item.get("match") and isinstance(item.get("current"), dict)
        }
        if set(verified_hashes) != {"video", "config", "model"}:
            errors.append("manifest: 缺少可绑定的三输入指纹")
            return failure(), errors

        video_fd = _open_hold(video)
        held_fds.append(video_fd)
        identities = {"video": _fd_identity(video_fd)}
        config_fd = _open_hold(config_path)
        held_fds.append(config_fd)
        identities["config"] = _fd_identity(config_fd)
        model_fd = _open_hold(model)
        held_fds.append(model_fd)
        identities["model"] = _fd_identity(model_fd)
        config_bytes = _read_fd_all(config_fd)
        model_bytes = _read_fd_all(model_fd)
        held_hashes = {
            "video": _hash_fd(video_fd),
            "config": _sha256_bytes(config_bytes),
            "model": _sha256_bytes(model_bytes),
        }
        if held_hashes != verified_hashes:
            errors.append(
                "inputs: manifest 复核后输入发生变化，拒绝执行")
            return failure(), errors
        for name, path, fd in (("video", video, video_fd),
                               ("config", config_path, config_fd),
                               ("model", model, model_fd)):
            if _input_identity(path) != _fd_identity(fd):
                errors.append(
                    f"inputs: {name} 路径与已验证句柄不一致，拒绝执行")
                return failure(), errors

        # 3) 配置/相机/模型绑定（config 内容来自快照 fd）
        try:
            cfg = json.loads(config_bytes.decode("utf-8"))
        except UnicodeError as exc:
            errors.append(f"config: 非 UTF-8（{type(exc).__name__}）")
            return failure(), errors
        except ValueError as exc:
            errors.append(f"config: 非 JSON（{type(exc).__name__}）")
            return failure(), errors
        venue_errors = validate_venue(cfg)
        if venue_errors:
            errors.append("config: 场所档案校验失败: "
                          + "；".join(venue_errors))
            return failure(), errors
        config_dir = os.path.dirname(os.path.abspath(config_path))
        cam = _bind_camera(cfg, camera_id, model, config_dir, errors)
        if cam is None:
            return failure(), errors

        # 4) 输出库必须原先不存在；临时库放同目录以便原子发布
        if os.path.lexists(output_db):
            errors.append("output_db: 已存在，拒绝覆盖")
            return failure(), errors
        temp_db = os.path.join(
            os.path.dirname(os.path.abspath(output_db)),
            f".{os.path.basename(output_db)}"
            f".replay-tmp-{uuid.uuid4().hex[:8]}")

        # 5) 执行：一遍读完；EOF 需有限正总帧数与已读数一致
        if capture_factory is None:
            descriptor_path = f"/proc/self/fd/{video_fd}"
            if os.name != "posix" or not os.path.exists(descriptor_path):
                raise ReplayFailure(
                    "capture: 生产回放要求 Linux /proc 描述符绑定")
            capture = _Cv2Capture(descriptor_path)
        else:
            capture = capture_factory(video)
        fps = float(capture.get_fps())
        if not math.isfinite(fps) or fps <= 0:
            raise ReplayFailure("capture: FPS 非有限或非正，拒绝回放")
        total = capture.get_frame_count()
        if total is None or not math.isfinite(total) or total <= 0 \
                or not float(total).is_integer():
            raise ReplayFailure(
                "capture: 总帧数不可用或非整数（fail-closed，"
                "拒绝以读取失败冒充EOF）")
        total = int(total)

        detector_cfg = cam.get("detector") or {}
        detector = (detector_factory(detector_cfg)
                    if detector_factory is not None
                    else _default_detector_factory(detector_cfg, model_bytes))
        sink = (sink_factory or _default_sink_factory)(temp_db)
        monitor = Monitor({**cam, "zones": cam.get("zones") or []},
                          detect_fn=(detector.detect
                                     if detector is not None
                                     else (lambda frame: [])),
                          sinks=[sink])

        frames = 0
        while True:
            state, frame = capture.read_frame(frames)
            if state == "eof":
                break
            if state == "error":
                raise ReplayFailure(
                    "capture: 中途解码失败（提前终止≠成功EOF）")
            if frames >= total:
                raise ReplayFailure(
                    "capture: 读取超出总帧数（fail-closed）")
            now_ms = frames * 1000.0 / fps
            monitor.step(frame, to_gray(frame, Monitor.GRAY_W), now_ms)
            frames += 1
        if frames == 0:
            raise ReplayFailure("capture: 零帧视频，拒绝回放")
        if frames < total:
            raise ReplayFailure(
                f"capture: 提前终止 {frames}/{total} 帧（非成功EOF）")
        duration_s = total * 1000.0 / fps / 1000.0

        closed = _close_open_rows(temp_db, sink, duration_s)

        # 6) 发布前再复核：路径身份与持有 fd 身份都必须仍等于快照，且
        #    三输入内容哈希与启动时一致（换入/换出/原地改写全拒绝）
        for name, path in (("video", video), ("config", config_path),
                           ("model", model)):
            if _input_identity(path) != identities[name]:
                raise ReplayFailure(
                    f"inputs: {name} 在 replay 期间身份变化，拒绝发布")
        if any(_fd_identity(fd) != identities[name]
               for name, fd in (("video", video_fd),
                                ("config", config_fd),
                                ("model", model_fd))):
            raise ReplayFailure(
                "inputs: 持有句柄与身份快照不一致，拒绝发布")
        for name, fd in (("video", video_fd), ("config", config_fd),
                         ("model", model_fd)):
            if _hash_fd(fd) != held_hashes[name]:
                raise ReplayFailure(
                    f"inputs: {name} 内容快照复核失败")

        detector_release = getattr(detector, "release", None)
        if callable(detector_release):
            detector_release()
        detector = None
        capture.release()
        capture = None
        sink.conn.close()
        sink = None

        # 7) 原子 no-clobber 发布
        temp_removed = _publish_no_clobber(temp_db, output_db)
        if temp_removed:
            temp_db = None
        return {
            "schema": SCHEMA,
            "kind": "replay_run_result",
            "created_at": _utc_now(),
            "camera_id": camera_id,
            "frames": frames,
            "duration_s": round(duration_s, 3),
            "output_db": os.path.basename(output_db),
            "closed_at_eof": closed,
            "replay_executed": True,
            "errors": [],
            "quality_gate_passed": None,
            "release_gate_passed": None,
            "result_note": (
                "Deterministic replay executed; quality and release gates "
                "are not evaluated here."),
        }, []
    except ReplayFailure as exc:
        errors.append(str(exc))
        return failure(), errors
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
        return failure(), errors
    finally:
        for fd in held_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        if capture is not None:
            try:
                capture.release()
            except Exception:
                pass
        if detector is not None:
            detector_release = getattr(detector, "release", None)
            if callable(detector_release):
                try:
                    detector_release()
                except Exception:
                    pass
        if sink is not None:
            try:
                sink.conn.close()
            except Exception:
                pass
        if temp_db is not None and os.path.exists(temp_db):
            for suffix in ("", "-journal", "-wal", "-shm"):
                try:
                    os.unlink(temp_db + suffix)
                except OSError:
                    continue


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="单视频确定性离线 replay（质量/发布门禁不在本步评估）")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--video", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--camera-id", required=True)
    parser.add_argument("--output-db", required=True)
    args = parser.parse_args(argv)

    result, errors = run_replay(
        args.manifest, args.video, args.config, args.model, args.camera_id,
        args.output_db)
    if errors:
        result = dict(result)
        result["errors"] = errors
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["replay_executed"] else 1


if __name__ == "__main__":
    sys.exit(main())
