"""共享运行时的启动恢复与值守状态测试（由 Win11 发布要求驱动）。

值守状态断言只针对接线后的结构化真值：合成替身不含真实 RTSP、真实模型或
原生主机证据，不代表 Win11 端到端验收。
"""

import errno
import json
import signal
import threading
import time
from types import SimpleNamespace

import scam.db as db
from scam.nvr import _recover_event_truth
from scam import detect as detect_mod
from scam import nvr as nvr_mod
from scam.server import CameraRuntimeRegistry


def test_startup_reports_recovered_event_truth(tmp_path, capsys):
    conn = db.connect(str(tmp_path / "startup.db"))
    db.init_schema(conn)
    db.open_tracked_object(
        conn, object_id="obj-1", camera="front", t_start=1.0, cls="person")

    counts = _recover_event_truth(conn, now=100.0, stale_after_s=30.0)

    assert counts["tracked_objects"] == 1
    output = capsys.readouterr().out
    assert "对象 1" in output
    assert "审查段 0" in output
    assert "语义事件 0" in output


def test_startup_stays_quiet_when_no_recovery_is_needed(tmp_path, capsys):
    conn = db.connect(str(tmp_path / "startup.db"))
    db.init_schema(conn)

    counts = _recover_event_truth(conn, now=100.0, stale_after_s=30.0)

    assert sum(counts.values()) == 0
    assert capsys.readouterr().out == ""


# ---------- 检测能力判定：仅预览 vs 检测不可用 ----------

def test_detector_plan_separates_monitor_only_from_missing_model(tmp_path):
    """管理员选仅预览与配置了ONNX却缺模型，必须给出不同能力与固定code。"""
    assert nvr_mod._detector_plan({}) == ("monitor_only", None)
    assert nvr_mod._detector_plan({"engine": "none"}) == ("monitor_only", None)
    assert nvr_mod._detector_plan({
        "engine": "onnx", "model": str(tmp_path / "missing.onnx"),
        "classes": ["person"]}) == ("detector_unavailable", "detector_missing")

    present = tmp_path / "present.onnx"
    present.write_bytes(b"not-a-real-model")
    assert nvr_mod._detector_plan({
        "engine": "onnx", "model": str(present),
        "classes": ["person"]}) == ("alerting", None)


# ---------- 值守线程 → 结构化状态 ----------

class _FastStop(threading.Event):
    """把源重试等待压到毫秒级；测试不替生产重试节奏背书。"""

    def wait(self, timeout=None):
        return super().wait(0.01 if timeout else timeout)


def _patch_runtime(monkeypatch, source_cls, on_step=None, on_init=None):
    class _Monitor:
        GRAY_W = 8

        def __init__(self, *args, **kwargs):
            self.frames = []
            if on_init is not None:
                on_init()

        def step(self, frame, gray, now):
            self.frames.append(now)
            if on_step is not None:
                on_step()

    monkeypatch.setattr(nvr_mod, "CameraSource", source_cls)
    monkeypatch.setattr(nvr_mod, "Monitor", _Monitor)
    monkeypatch.setattr(nvr_mod, "build_sinks", lambda *a, **k: [])
    monkeypatch.setattr(nvr_mod, "to_gray", lambda frame, width: None)


def _camera_state(registry, camera_id="front-door"):
    for camera in registry.snapshot()["cameras"]:
        if camera["camera"] == camera_id:
            return camera
    return None


def test_camera_thread_reports_open_failure_then_recovery(
        monkeypatch, capsys):
    """打开失败到恢复来帧的完整状态迁移必须如实上报，且不泄露源凭据。"""
    stop = _FastStop()
    seen = []
    registry = CameraRuntimeRegistry(["front-door"])
    state = SimpleNamespace(monitors={}, runtime=registry)

    class Source:
        opens = 0
        reads = 0

        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            Source.opens += 1
            if Source.opens == 1:
                return False
            seen.append(_camera_state(registry))
            return True

        def read(self):
            Source.reads += 1
            stop.set()
            seen.append(_camera_state(registry))
            return True, "frame", 1000.0

        @property
        def stats(self):
            return {"timestamp_kind": "host_receive"}

        def close(self):
            pass

    _patch_runtime(monkeypatch, Source)
    nvr_mod._run_camera(
        {"id": "front-door", "source": "rtsp://admin:secret@camera/live",
         "detector": {"engine": "none"}},
        [], "events.db", stop, state)

    # open#2 之前的状态：打开失败已进入 degraded 并挂固定 code
    failed, online = seen
    assert failed["state"] == "degraded"
    assert failed["issue"]["code"] == "source_open_failed"
    assert "重连" in failed["issue"]["action"]
    # 帧可读后收回 online，且能力仍是管理员选择的仅预览
    assert online["state"] == "online" and online["issue"] is None
    assert online["capability"] == "monitor_only"
    assert state.monitors == {}
    assert _camera_state(registry)["state"] == "stopped"

    output = capsys.readouterr().out
    assert "源打开失败" in output
    serialized = json.dumps(seen, ensure_ascii=False)
    for leaked in ("rtsp://", "admin:secret", "camera/live"):
        assert leaked not in serialized, f"值守状态泄露了 {leaked}"


def test_camera_thread_marks_degraded_then_online_on_read_recovery(monkeypatch):
    """读失败必须进入 degraded+固定code，恢复来帧后回到 online 并清空issue。"""
    stop = _FastStop()
    reads_seen = []
    steps_seen = []
    registry = CameraRuntimeRegistry(["side"])
    state = SimpleNamespace(monitors={}, runtime=registry)

    def record_step():
        steps_seen.append(_camera_state(registry, "side"))

    class Source:
        reads = 0

        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def read(self):
            Source.reads += 1
            reads_seen.append(_camera_state(registry, "side"))
            if Source.reads == 1:
                return False, None, None
            stop.set()
            return True, "frame", 2000.0

        @property
        def stats(self):
            return {"timestamp_kind": "host_receive"}

        def close(self):
            pass

    _patch_runtime(monkeypatch, Source, on_step=record_step)
    nvr_mod._run_camera(
        {"id": "side", "source": "rtsp://camera",
         "detector": {"engine": "none"}},
        [], "events.db", stop, state)

    # 读#1之前仍是在线；读#2之前已因上一轮失败进入 degraded
    assert [camera["state"] for camera in reads_seen] == ["online", "degraded"]
    assert reads_seen[1]["issue"] == {
        "code": "source_read_failed",
        "action": "检查网络与相机供电；持续失败请重启相机"}
    # 恢复来帧后先收回 online，才把该帧交给值守快路径
    assert len(steps_seen) == 1
    assert steps_seen[0]["state"] == "online"
    assert steps_seen[0]["issue"] is None


def test_file_source_uses_file_wording_for_failures(monkeypatch):
    """文件源故障给文件口径提示：不得套用网络相机的“检查网络与供电”。"""
    stop = _FastStop()
    seen = []
    reads = []

    class Source:
        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def read(self):
            reads.append(1)
            seen.append(_camera_state(registry, "clip"))
            if len(reads) == 1:
                return False, None, None
            stop.set()
            return True, "frame", 2000.0

        @property
        def stats(self):
            return {"timestamp_kind": "host_receive", "eof_reopens": 0}

        def close(self):
            pass

    registry = CameraRuntimeRegistry(["clip"])
    state = SimpleNamespace(monitors={}, runtime=registry)
    _patch_runtime(monkeypatch, Source)
    nvr_mod._run_camera(
        {"id": "clip", "source": "clip.mp4", "source_kind": "file",
         "detector": {"engine": "none"}},
        [], "events.db", stop, state)

    assert seen[1]["state"] == "degraded"
    assert seen[1]["issue"] == {
        "code": "file_source_read_failed",
        "action": "检查视频文件是否完整可解码；读完会自动从头继续"}
    assert "网络" not in seen[1]["issue"]["action"]
    assert "供电" not in seen[1]["issue"]["action"]


def test_detector_construction_keeps_state_connecting_until_online(
        tmp_path, monkeypatch):
    """C-051/C-052：源已打开但检测器尚未构造成功时，工作台必须保持保守状态。

    首次 online 只能推迟到 NanoDet 实际加载与 Monitor 构造都成功之后；能力也
    只能在检测器真实构造成功后才写成 alerting——模型在位但仍在加载的窗口里，
    工作台既不显示“在线”，也不提前宣称“检测告警已启用”。
    """
    stop = _FastStop()
    model = tmp_path / "present.onnx"
    model.write_bytes(b"stub")     # 文件在位 → 真实走 _make_detector 的加载分支
    seen = []
    online_seen = []
    registry = CameraRuntimeRegistry(["gate"])
    state = SimpleNamespace(monitors={}, runtime=registry)

    def probe(stage):
        camera = _camera_state(registry, "gate")
        seen.append((stage, camera["state"], camera["capability"]))

    class NanoDet:
        """替身只替换真实推理器构造（onnxruntime 是可选依赖）。"""

        def __init__(self, *args, **kwargs):
            probe("detector")

        def detect(self, frame):
            return []

    class Source:
        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def read(self):
            # 首次 online 之后的第一处观测点（线程仍在运行）：在线必须与真实
            # 加载结果同时成立，且没有挂着任何源侧或检测侧故障。
            camera = _camera_state(registry, "gate")
            online_seen.append((camera["state"], camera["capability"],
                                camera["issue"]))
            stop.set()
            return True, "frame", 1000.0

        @property
        def stats(self):
            return {"timestamp_kind": "host_receive"}

        def close(self):
            pass

    monkeypatch.setattr(detect_mod, "NanoDet", NanoDet)
    _patch_runtime(monkeypatch, Source, on_init=lambda: probe("monitor"))
    nvr_mod._run_camera(
        {"id": "gate", "source": "rtsp://camera",
         "detector": {"engine": "onnx", "model": str(model),
                      "classes": ["person"]}},
        [], "events.db", stop, state)

    # 加载窗口内：状态仍是保守的 connecting，能力也没被提前写成 alerting；
    # 加载返回后才写入真实能力，但 Monitor 构造期间依旧没有 online。
    assert seen == [("detector", "connecting", "monitor_only"),
                    ("monitor", "connecting", "alerting")]
    # 两件事都成功之后才进入 online，并按真实加载结果给出 alerting
    assert online_seen == [("online", "alerting", None)]
    # 线程退出后源侧状态收口为 stopped（与既有生命周期语义一致），检测能力
    # 事实保留，不被停机改写。
    camera = _camera_state(registry, "gate")
    assert camera["state"] == "stopped"
    assert camera["capability"] == "alerting"
    assert camera["issue"] is None
    assert state.monitors == {}


def test_camera_thread_reports_detector_unavailable_without_model_path(
        tmp_path, monkeypatch):
    """ONNX模型缺失进入 detector_unavailable，且状态出口不含模型绝对路径。"""
    stop = _FastStop()
    model = tmp_path / "missing.onnx"

    class Source:
        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def read(self):
            stop.set()
            return True, "frame", 3000.0

        @property
        def stats(self):
            return {"timestamp_kind": "host_receive"}

        def close(self):
            pass

    _patch_runtime(monkeypatch, Source)
    registry = CameraRuntimeRegistry(["yard"])
    state = SimpleNamespace(monitors={}, runtime=registry)

    nvr_mod._run_camera(
        {"id": "yard", "source": "rtsp://camera",
         "detector": {"engine": "onnx", "model": str(model),
                      "classes": ["person"]}},
        [], "events.db", stop, state)

    camera = _camera_state(registry, "yard")
    assert camera["capability"] == "detector_unavailable"
    assert camera["issue"] == {
        "code": "detector_missing",
        "action": "把检测模型放到配置路径后重启值守"}
    serialized = json.dumps(registry.snapshot(), ensure_ascii=False)
    for leaked in ("missing.onnx", str(tmp_path), str(model)):
        assert leaked not in serialized, f"状态出口泄露了模型路径: {leaked}"


def test_camera_thread_reports_detector_load_failure(tmp_path, monkeypatch):
    """模型在位但加载失败同样是检测不可用，绝不留下声称 alerting 的假状态。"""
    stop = _FastStop()
    model = tmp_path / "broken.onnx"
    model.write_bytes(b"not-a-real-model")

    class Source:
        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def read(self):
            stop.set()
            return True, "frame", 3500.0

        @property
        def stats(self):
            return {"timestamp_kind": "host_receive"}

        def close(self):
            pass

    _patch_runtime(monkeypatch, Source)
    registry = CameraRuntimeRegistry(["gate"])
    state = SimpleNamespace(monitors={}, runtime=registry)

    nvr_mod._run_camera(
        {"id": "gate", "source": "rtsp://camera",
         "detector": {"engine": "onnx", "model": str(model),
                      "classes": ["person"]}},
        [], "events.db", stop, state)

    camera = _camera_state(registry, "gate")
    assert camera["capability"] == "detector_unavailable"
    assert camera["issue"] == {
        "code": "detector_load_failed",
        "action": "确认模型文件完整且 onnxruntime 可用后重启值守"}
    assert "broken.onnx" not in json.dumps(registry.snapshot(),
                                           ensure_ascii=False)


def test_camera_thread_without_runtime_registry_still_runs(monkeypatch):
    """未接线注册表时不得报错——既有调用方（含Linux入口）保持兼容。"""
    stop = _FastStop()

    class Source:
        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def read(self):
            stop.set()
            return True, "frame", 4000.0

        @property
        def stats(self):
            return {"timestamp_kind": "host_receive"}

        def close(self):
            pass

    _patch_runtime(monkeypatch, Source)

    nvr_mod._run_camera(
        {"id": "cam", "source": "rtsp://camera"}, [], "events.db",
        stop, SimpleNamespace(monitors={}))


# ---------- 工作台绑定失败：Win11门禁 vs Linux降级 ----------

def _write_venue(path):
    path.write_text(json.dumps({
        "venue": {"name": "test"},
        "cameras": [{"id": "front-door", "source_kind": "rtsp",
                     "source": "rtsp://admin:secret@camera/live",
                     "detector": {"engine": "none"},
                     "record_enabled": False, "zones": []}],
    }), encoding="utf-8")
    return str(path)


class _BusyServer:
    """模拟端口已被占用：绑定即失败，绝不返回可用工作台。"""

    def __init__(self, state, host="127.0.0.1", port=8600):
        raise OSError(errno.EADDRINUSE, "Address already in use")


def _drive_with_captured_signals(monkeypatch, calls):
    """把信号注册换成可驱动句柄，避免测试改全局信号处理器。"""
    handlers = {}
    monkeypatch.setattr(
        nvr_mod.signal, "signal",
        lambda signum, handler: handlers.setdefault(signum, handler))

    def fake_run_camera(cam_cfg, *args, **kwargs):
        calls.append(cam_cfg["id"])
        handlers[signal.SIGINT](None, None)

    monkeypatch.setattr(nvr_mod, "_run_camera", fake_run_camera)


def test_win11_workbench_bind_failure_aborts_before_camera_threads(
        tmp_path, monkeypatch, capsys):
    """Win11端口占用必须明确失败并返回非零，不得无工作台继续运行。"""
    calls = []
    _drive_with_captured_signals(monkeypatch, calls)
    config = _write_venue(tmp_path / "cameras.json")
    monkeypatch.setattr(nvr_mod, "WorkbenchServer", _BusyServer)

    code = nvr_mod.main(
        ["--config", config, "--db", str(tmp_path / "win11.db"),
         "--host", "127.0.0.1", "--port", "8600"],
        edition="win11")

    assert code != 0, "Win11工作台绑定失败必须返回非零"
    assert calls == [], "绑定失败后不得启动任何相机线程"
    output = capsys.readouterr().out
    assert "工作台启动失败" in output
    assert "端口已被其它程序占用" in output
    assert "已中止启动" in output


def test_linux_workbench_bind_failure_keeps_standalone_degradation(
        tmp_path, monkeypatch, capsys):
    """Linux无工作台降级语义保持不变：如实提示并继续值守。"""
    calls = []
    _drive_with_captured_signals(monkeypatch, calls)
    config = _write_venue(tmp_path / "cameras.json")
    monkeypatch.setattr(nvr_mod, "WorkbenchServer", _BusyServer)

    code = nvr_mod.main(
        ["--config", config, "--db", str(tmp_path / "linux.db"),
         "--host", "127.0.0.1", "--port", "8600"],
        edition="linux-nvr")

    assert code == 0, "Linux绑定失败后必须继续值守"
    assert calls == ["front-door"], "Linux仍须启动相机线程"
    output = capsys.readouterr().out
    assert "值守继续，无工作台" in output
    assert "已中止启动" not in output

# ---------- F8：宽限窗后一次性遗留收口的调度语义 ----------

def _seed_open_three_layers(db_path, t_last):
    conn = db.connect(db_path)
    db.init_schema(conn)
    db.open_tracked_object(conn, object_id="obj-x", camera="front",
                           t_start=1.0, cls="person")
    db.open_review_segment(conn, review_id="rev-x", camera="front", t_start=1.0)
    db.open_semantic_event(conn, semantic_event_id="sem-x", camera="front",
                           review_id="rev-x", object_id="obj-x", t_start=2.0,
                           template="enter-and-dwell", zone_id="yard")
    db.update_tracked_object(conn, "obj-x", t_last=t_last)
    db.update_review_segment(conn, "rev-x", t_last=t_last)
    db.update_semantic_event(conn, "sem-x", t_last=t_last)
    snapshot = db.snapshot_pending_recovery(conn, now=100.0, stale_after_s=30.0)
    conn.close()
    return snapshot


def test_pending_recovery_scheduler_noop_without_snapshot():
    """空快照不起线程（Linux 零宽限路径因此完全不受影响）。"""
    assert nvr_mod._schedule_pending_recovery("unused.db", [], delay_s=0.0) is None


def test_pending_recovery_scheduler_closes_snapshot_once(tmp_path):
    """一次性复核：按快照把宽限窗内遗留的三层记录收口，且线程是守护线程。"""
    db_path = str(tmp_path / "pending.db")
    snapshot = _seed_open_three_layers(db_path, t_last=95.0)
    assert len(snapshot) == 3
    done = []
    thread = nvr_mod._schedule_pending_recovery(
        db_path, snapshot, delay_s=0.0, on_done=done.append)

    assert thread is not None and thread.daemon is True, "退出不得被定时器阻塞"
    thread.join(5.0)
    assert not thread.is_alive()
    assert done and sum(done[0].values()) == 3

    conn = db.connect(db_path)
    for table, key in (("tracked_objects", "obj-x"),
                       ("review_segments", "rev-x"),
                       ("semantic_events", "sem-x")):
        row = conn.execute(
            f"SELECT t_end,end_reason FROM {table}"            # noqa: S608
            f" WHERE t_end IS NOT NULL").fetchone()
        assert row is not None and row["end_reason"] == "recovered_after_restart"
    conn.close()


def test_pending_recovery_scheduler_exits_early_on_stop(tmp_path):
    """停机事件到来时立即返回：不把长延时睡满（退出不被定时器阻塞）。"""
    db_path = str(tmp_path / "pending-stop.db")
    snapshot = _seed_open_three_layers(db_path, t_last=95.0)
    stop = threading.Event()
    stop.set()

    started = time.monotonic()
    thread = nvr_mod._schedule_pending_recovery(
        db_path, snapshot, delay_s=30.0, stop_event=stop)
    thread.join(5.0)
    elapsed = time.monotonic() - started

    assert not thread.is_alive()
    assert elapsed < 5.0, f"停机后不得等满 30 秒（实测 {elapsed:.1f}s）"
    conn = db.connect(db_path)
    assert conn.execute(
        "SELECT COUNT(*) FROM tracked_objects WHERE t_end IS NOT NULL"
    ).fetchone()[0] == 0, "停机路径不得写库"
    conn.close()
