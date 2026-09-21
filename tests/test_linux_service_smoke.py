"""Z1 Linux 服务级 smoke：原生子进程默认入口闭环（仅 Linux 运行）。

证明档位=接线：临时 MJPG AVI + engine=none 配置 + 预置开放三层记录的 SQLite，
启动 python -u -m scam.linux_nvr 子进程，验证——
  1. 进程不早退，/api/health /api/stats /api/review /api/events 可读；
  2. 视频帧真实推进（file 源 EOF 后由读失败重建回绕持续出帧）；
  3. 启动恢复把旧开放记录标记 recovered_after_restart 且不删除；
  4. SIGTERM 后 10s 内退出码 0；
  5. 日志不泄露源凭证。

不代表真实 RTSP、原生主机质量验证或 24h 稳定性。
"""

import http.client
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import time

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux",
                                reason="服务级 smoke 仅在 Linux 运行")


def _free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _make_avi(path, frames=48, fps=20):
    import cv2
    import numpy as np

    writer = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"MJPG"),
                             float(fps), (320, 240))
    assert writer.isOpened()
    for i in range(frames):
        frame = np.zeros((240, 320, 3), dtype=np.uint8)
        x = (i * 8) % 280
        cv2.rectangle(frame, (x, 80), (x + 40, 120), (0, 255, 0), -1)
        writer.write(frame)
    writer.release()


def _get(port, path, timeout=3.0):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read().decode("utf-8"))
    finally:
        conn.close()


def test_linux_service_smoke(tmp_path):
    import scam.db as db

    avi = tmp_path / "gate.avi"
    _make_avi(avi)
    db_path = tmp_path / "smoke.db"
    port = _free_port()

    # 预置"上次实例遗留"的开放三层记录：启动恢复必须闭合并保留
    conn = db.connect(str(db_path))
    db.init_schema(conn)
    old = time.time() - 600.0
    db.open_tracked_object(conn, object_id="front:old:track:1",
                           camera="front", t_start=old, cls="person")
    db.open_review_segment(conn, review_id="front:old:review",
                           camera="front", t_start=old)
    db.open_semantic_event(conn, semantic_event_id="front:old:sem",
                           camera="front", review_id="front:old:review",
                           object_id="front:old:track:1", t_start=old,
                           template="enter-dwell")
    conn.close()

    cfg = tmp_path / "cameras.json"
    cfg.write_text(json.dumps({
        "version": "0.3",
        "cameras": [
            {"id": "front", "enabled": True, "source": str(avi),
             "source_kind": "file", "detector": {"engine": "none"},
             "zones": [], "schedule": [{"from": "00:00", "to": "23:59"}]},
            {"id": "leak", "enabled": True,
             "source": "rtsp://admin:SECRETPASS@127.0.0.1:9/x",
             "detector": {"engine": "none"},
             "zones": [], "schedule": [{"from": "00:00", "to": "23:59"}]},
        ],
    }, ensure_ascii=False), encoding="utf-8")

    out_path = tmp_path / "stdout.log"
    err_path = tmp_path / "stderr.log"
    exit_code = None
    with out_path.open("wb") as out, err_path.open("wb") as err:
        proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "scam.linux_nvr",
             "--config", str(cfg), "--db", str(db_path), "--port", str(port)],
            cwd=str(tmp_path), stdout=out, stderr=err,
            env={**os.environ, "PYTHONUNBUFFERED": "1"})
        try:
            # 1) 进程不早退，工作台 30s 内就绪
            deadline = time.time() + 30.0
            ready = False
            while time.time() < deadline:
                if proc.poll() is not None:
                    raise AssertionError(
                        f"nvr 提前退出 rc={proc.returncode}")
                try:
                    status, body = _get(port, "/api/health", timeout=2.0)
                    if status == 200 and body.get("count", 0) >= 1:
                        ready = True
                        break
                except OSError:
                    pass
                time.sleep(0.5)
            assert ready, "30s 内工作台未就绪（无注册中的相机监视器）"

            # 2) 视频帧真实推进
            _, stats_a = _get(port, "/api/stats")
            time.sleep(2.5)
            _, stats_b = _get(port, "/api/stats")
            frames_a = stats_a["cameras"][0]["frames"]
            frames_b = stats_b["cameras"][0]["frames"]
            assert frames_b > frames_a, \
                f"帧计数未推进：{frames_a} -> {frames_b}"

            # 3) 审查与事件 API 可读
            for api in ("/api/review", "/api/events"):
                status, _ = _get(port, api)
                assert status == 200, f"{api} 不可读"

            # 4) 启动恢复：闭合且保留，不删历史
            check = sqlite3.connect(str(db_path))
            try:
                for table in ("tracked_objects", "review_segments",
                              "semantic_events"):
                    recovered = check.execute(
                        f"SELECT COUNT(*) FROM {table} "
                        "WHERE end_reason='recovered_after_restart'"
                    ).fetchone()[0]
                    assert recovered >= 1, f"{table} 缺少启动恢复标记"
                    total = check.execute(
                        f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    assert total >= recovered, f"{table} 历史记录被删除"
            finally:
                check.close()
        finally:
            # 5) SIGTERM → 10s 内退出码 0
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    exit_code = proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
                    raise AssertionError("SIGTERM 后 10s 未退出")
            else:
                exit_code = proc.returncode

    assert exit_code == 0, f"退出码非 0：{exit_code}"

    # 6) 日志不泄露源凭证
    logs = (out_path.read_text(encoding="utf-8", errors="replace")
            + err_path.read_text(encoding="utf-8", errors="replace"))
    assert "SECRETPASS" not in logs, "日志泄露 RTSP 凭证"
