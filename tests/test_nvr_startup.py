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

import pytest

import scam.db as db
from scam.nvr import _recover_event_truth
from scam import detect as detect_mod
from scam import nvr as nvr_mod
from scam.win11_materials import MaterialsStore
from scam.server import CameraRuntimeRegistry


def test_startup_reports_recovered_event_truth(tmp_path, capsys):
    conn = db.connect(str(tmp_path / "startup.db"))
    db.init_schema(conn)
    db.open_tracked_object(
        conn, object_id="obj-1", camera="front", t_start=1.0, cls="person")
    db.open_event_fact(conn, event_id="front:run1:event:1", camera="front",
                       object_id="obj-1", t_start=1.0, cls="person")
    db.update_event_fact(conn, "front:run1:event:1", t_last=2.0)

    counts = _recover_event_truth(conn, now=100.0, stale_after_s=30.0)

    assert counts["tracked_objects"] == 1
    assert counts["event_facts"] == 1
    output = capsys.readouterr().out
    assert "对象 1" in output
    assert "审查段 0" in output
    assert "语义事件 0" in output
    assert "事件 1" in output


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


def _patch_runtime(monkeypatch, source_cls, on_step=None, on_init=None,
                   persistence_degraded=False):
    class _Monitor:
        GRAY_W = 8
        # 由 _patch_runtime 注入：新用例可驱动数据面故障
        persistence_degraded = False
        timestamp_kind = None

        def __init__(self, *args, **kwargs):
            self.frames = []
            self.stream_lost = False
            if on_init is not None:
                on_init()

        def step(self, frame, gray, now):
            self.frames.append(now)
            if on_step is not None:
                on_step()

        def persistence_state(self):
            degraded = bool(self.persistence_degraded)
            return {"review_open_failures": int(degraded),
                    "review_unpersisted": degraded, "deferred_alarms": 0,
                    "event_open_failures": 0, "event_facts_unpersisted": 0,
                    "sink_failures": 0, "degraded": degraded}

        def on_stream_lost(self, now):
            self.stream_lost = True

        def on_stream_recovered(self):
            self.stream_lost = False

        def close_all_event_facts(self, reason="camera-stopped"):
            pass

    _Monitor.persistence_degraded = bool(persistence_degraded)
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
    db.open_event_fact(conn, event_id="front:run-x:event:1", camera="front",
                       object_id="obj-x", t_start=1.0, cls="person")
    db.update_tracked_object(conn, "obj-x", t_last=t_last)
    db.update_review_segment(conn, "rev-x", t_last=t_last)
    db.update_semantic_event(conn, "sem-x", t_last=t_last)
    db.update_event_fact(conn, "front:run-x:event:1", t_last=t_last)
    snapshot = db.snapshot_pending_recovery(conn, now=100.0, stale_after_s=30.0)
    conn.close()
    return snapshot


def test_pending_recovery_scheduler_noop_without_snapshot():
    """空快照不起线程（Linux 零宽限路径因此完全不受影响）。"""
    assert nvr_mod._schedule_pending_recovery("unused.db", [], delay_s=0.0) is None


def test_pending_recovery_scheduler_closes_snapshot_once(tmp_path):
    """一次性复核：按快照把宽限窗内遗留的四层记录收口，且线程是守护线程。"""
    db_path = str(tmp_path / "pending.db")
    snapshot = _seed_open_three_layers(db_path, t_last=95.0)
    assert len(snapshot) == 4
    done = []
    thread = nvr_mod._schedule_pending_recovery(
        db_path, snapshot, delay_s=0.0, on_done=done.append)

    assert thread is not None and thread.daemon is True, "退出不得被定时器阻塞"
    thread.join(5.0)
    assert not thread.is_alive()
    assert done and sum(done[0].values()) == 4

    conn = db.connect(db_path)
    for table, key in (("tracked_objects", "obj-x"),
                       ("review_segments", "rev-x"),
                       ("semantic_events", "sem-x"),
                       ("event_facts", "front:run-x:event:1")):
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

def test_camera_reports_persistence_degraded_then_clears(monkeypatch):
    """F9：审查段/告警写不进库必须在健康面可见，恢复后自动清除。

    源可以在线出图，同时数据面写不进去——两者必须能同时表达，不能被源侧
    提示遮住。
    """
    stop = _FastStop()
    seen = []
    registry = CameraRuntimeRegistry(["cam"])
    state = SimpleNamespace(monitors={}, runtime=registry)

    def record_step():
        # on_step 在 monitor.step 内部触发，早于本帧的数据面上报，
        # 所以第 0 帧采样看不到当帧上报结果——从第 1 帧起断言。
        seen.append(_camera_state(registry, "cam"))
        if len(seen) >= 3:
            stop.set()

    class Source:
        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def read(self):
            return True, "frame", 2000.0

        @property
        def stats(self):
            return {"timestamp_kind": "host_receive", "eof_reopens": 0}

        def close(self):
            pass

    _patch_runtime(monkeypatch, Source, on_step=record_step,
                   persistence_degraded=True)
    nvr_mod._run_camera(
        {"id": "cam", "source": "clip.mp4", "source_kind": "file",
         "detector": {"engine": "none"}},
        [], "events.db", stop, state)

    # 第 1 帧起健康面应稳定携带数据面故障，且状态不被改成 degraded（源是好的）
    assert len(seen) == 3
    for snapshot in seen[1:]:
        assert snapshot["state"] == "online", "数据面故障不得改写源状态"
        assert snapshot["persistence_issue"] == {
            "code": "persistence_degraded",
            "action": "审查段或告警未能写入本机数据库；检查磁盘空间与数据库可写性"}
        assert "未能写入本机数据库" in snapshot["hint"]


# ---------- 复验边界3：退出收口不被 source.close() 异常跳过 ----------

def _patch_exit_fixtures(monkeypatch, *, source_close_error=None,
                         frame_error=None, closeout_error=None,
                         closeout_pending=0):
    """局部替身：Source.close / 看门狗主链路 / 事件收口均可注入失败。

    主异常用 watchdog.frame 注入——monitor.step 的单帧异常按既有纪律被
    帧级守卫吞掉（不杀线程），不适合充当主异常。
    """
    calls = []
    stop = _FastStop()
    registry = CameraRuntimeRegistry(["cam"])
    state = SimpleNamespace(monitors={}, runtime=registry)

    class Source:
        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def read(self):
            if "frame" not in calls:
                calls.append("frame")
                return True, "frame", 2000.0
            stop.set()
            return False, None, None

        @property
        def stats(self):
            return {"timestamp_kind": "host_receive"}

        def close(self):
            calls.append("source-close")
            if source_close_error is not None:
                raise source_close_error

    class MonitorDouble:
        GRAY_W = 8
        timestamp_kind = None

        def __init__(self, *args, **kwargs):
            pass

        def step(self, frame, gray, now):
            pass

        def on_stream_lost(self, now):
            pass

        def on_stream_recovered(self):
            pass

        def persistence_state(self):
            return {"review_open_failures": 0, "review_unpersisted": False,
                    "deferred_alarms": 0, "event_open_failures": 0,
                    "event_facts_unpersisted": 0, "sink_failures": 0,
                    "degraded": False}

        def close_all_event_facts(self, reason="camera-stopped"):
            calls.append("event-closeout")
            if closeout_error is not None:
                raise closeout_error
            return closeout_pending

    def _watchdog_frame(**kwargs):
        if frame_error is not None:
            raise frame_error

    watchdog = SimpleNamespace(
        started=lambda: calls.append("watchdog-start"),
        failure=lambda *a, **k: None,
        opened=lambda **k: None,
        frame=_watchdog_frame,
        stopped=lambda: calls.append("watchdog-stop"))

    monkeypatch.setattr(nvr_mod, "CameraSource", Source)
    monkeypatch.setattr(nvr_mod, "Monitor", MonitorDouble)
    monkeypatch.setattr(nvr_mod, "build_sinks", lambda *a, **k: [])
    monkeypatch.setattr(nvr_mod, "to_gray", lambda frame, width: None)
    return calls, stop, state, registry, watchdog


def _run_exit_camera(calls, stop, state, watchdog):
    nvr_mod._run_camera(
        {"id": "cam", "source": "clip.mp4", "source_kind": "file",
         "detector": {"engine": "none"}},
        [], "events.db", stop, state, watchdog=watchdog)


def test_source_close_failure_does_not_skip_event_closeout(
        monkeypatch, capsys):
    """source.close() 抛错：事件收口/看门狗/运行状态清理仍各自执行；
    主异常（step 内）原样上抛，不被清理异常掩盖。"""
    calls, stop, state, registry, watchdog = _patch_exit_fixtures(
        monkeypatch, source_close_error=RuntimeError("disk gone"),
        frame_error=RuntimeError("boom"))

    with pytest.raises(RuntimeError, match="boom"):
        _run_exit_camera(calls, stop, state, watchdog)

    assert "source-close" in calls and "event-closeout" in calls
    assert "watchdog-stop" in calls, "看门狗清理必须得到执行机会"
    cam_state = registry.snapshot()["cameras"][0]
    assert cam_state["state"] == "stopped", "运行状态清理必须执行"
    out = capsys.readouterr().out
    assert "退出清理异常（source-close）" in out
    assert "退出清理异常（event-closeout）" not in out
    assert "值守结束" in out, "收尾日志必须完整"


def test_closeout_failure_recorded_and_does_not_mask_primary(
        monkeypatch, capsys):
    """事件收口抛错：异常被记录，主异常原样上抛，其余清理照常执行。"""
    calls, stop, state, registry, watchdog = _patch_exit_fixtures(
        monkeypatch, frame_error=RuntimeError("boom"),
        closeout_error=RuntimeError("event db locked"))

    with pytest.raises(RuntimeError, match="boom"):
        _run_exit_camera(calls, stop, state, watchdog)

    assert "event-closeout" in calls and "watchdog-stop" in calls
    out = capsys.readouterr().out
    assert "退出清理异常（event-closeout）" in out
    assert "值守结束" in out


def test_both_closeout_and_source_close_failures_all_executed(
        monkeypatch, capsys):
    """两者同时失败：两项清理都执行、都记录，主异常仍原样上抛。"""
    calls, stop, state, registry, watchdog = _patch_exit_fixtures(
        monkeypatch, source_close_error=RuntimeError("disk gone"),
        frame_error=RuntimeError("boom"),
        closeout_error=RuntimeError("event db locked"))

    with pytest.raises(RuntimeError, match="boom"):
        _run_exit_camera(calls, stop, state, watchdog)

    assert "source-close" in calls and "event-closeout" in calls
    out = capsys.readouterr().out
    assert "退出清理异常（source-close）" in out
    assert "退出清理异常（event-closeout）" in out


def test_exit_reports_unpersisted_event_count(monkeypatch, capsys):
    """退出前仍有事件没写进去：必须如实报"未保存"，绝不宣称已保存。"""
    calls, stop, state, registry, watchdog = _patch_exit_fixtures(
        monkeypatch, closeout_pending=2)

    _run_exit_camera(calls, stop, state, watchdog)   # 无主异常，正常返回

    out = capsys.readouterr().out
    assert "2 条事件未能写入数据库（未保存）" in out
    assert "值守结束" in out


def test_cleanup_error_without_primary_exception_is_reraised(
        monkeypatch, capsys):
    """无主异常时清理失败不得静默吞掉：第一条清理异常原样上抛。"""
    calls, stop, state, registry, watchdog = _patch_exit_fixtures(
        monkeypatch, source_close_error=RuntimeError("disk gone"))

    with pytest.raises(RuntimeError, match="disk gone"):
        _run_exit_camera(calls, stop, state, watchdog)

    assert "event-closeout" in calls, "后续清理仍必须执行"
    out = capsys.readouterr().out
    assert "退出清理异常（source-close）" in out


# ---------- Win11 L1 异步接线（合同 C-131 §3/§4） ----------

class _FakeFrame:
    """最小帧替身：L1Task/材料仓只读 shape/nbytes 并要求 copy() 出独立副本。"""

    nbytes = 48

    def __init__(self):
        self.shape = (6, 8, 3)

    def copy(self):
        return _FakeFrame()


def _patch_async_runtime(monkeypatch, *, l1_health_state):
    """async 模式局部替身：记录构造参数/材料出口/结果消费，不加载任何模型。

    step 内模拟一次材料机会（真实 Monitor 在门控后调材料出口），使
    sink → L1Task → submit 的完整链路在帧循环内被真实执行。
    """
    captures = {"monitor": None, "applied": [],
                "material_rejected_after_step": None}
    frame = _FakeFrame()

    class AsyncMonitor:
        GRAY_W = 8
        timestamp_kind = None

        def __init__(self, camera_cfg, detect_fn, sinks, seq=0, run_id=None,
                     **kwargs):
            self.init_kwargs = {"detect_fn": detect_fn, **kwargs}
            self.material_sink = None
            self.material_rejected = 0
            self.l1_health = None
            self.submit_returns = []
            captures["monitor"] = self

        def set_material_sink(self, fn):
            self.material_sink = fn

        def set_progress_probe(self, fn):
            self.progress_probe = fn

        def consume_conclusion(self):
            return None

        def apply_detection_result(self, result, now):
            captures["applied"].append((result, now))
            self.l1_health = {"state": l1_health_state,
                              "code": getattr(result, "error_code", None),
                              "at": now}

        def step(self, frame_bgr, gray, now):
            if self.material_sink is not None:
                # 与真实 _select_material 同语义：拒收计数唯一责任方=monitor
                accepted = self.material_sink({
                    "camera_id": "cam1", "run_id": "run-1", "frame_id": 7,
                    "t_capture_ms": now, "frame_bgr": frame,
                    "reason": "change_start", "change_boxes": [[0, 0, 2, 2]],
                    "gate_w": 8, "gate_h": 6, "config_version": 3,
                    "prev_available": True})
                if accepted is False:
                    self.material_rejected += 1
                self.submit_returns.append(accepted)
            captures["material_rejected_after_step"] = self.material_rejected

        def persistence_state(self):
            return {"review_open_failures": 0, "review_unpersisted": False,
                    "deferred_alarms": 0, "event_open_failures": 0,
                    "event_facts_unpersisted": 0, "sink_failures": 0,
                    "degraded": False}

        def on_stream_lost(self, now):
            pass

        def on_stream_recovered(self):
            pass

        def close_all_event_facts(self, reason="camera-stopped"):
            return 0

    monkeypatch.setattr(nvr_mod, "Monitor", AsyncMonitor)
    monkeypatch.setattr(nvr_mod, "build_sinks", lambda *a, **k: [])
    monkeypatch.setattr(nvr_mod, "to_gray", lambda frame, width: None)
    return captures, frame


class _StubL1Pipeline:
    """记录调用的管道替身：不加载模型、不产真实结果。"""

    def __init__(self):
        self.submitted = []
        self.take_calls = []
        self.results = []
        self.submit_returns = True

    def submit(self, task):
        self.submitted.append(task)
        return self.submit_returns

    def take_result(self, camera_id):
        self.take_calls.append(camera_id)
        if self.results:
            return self.results.pop(0)
        return None


def _run_async_camera(stop, state, pipeline, model_path):
    # 生产接线（合同 C-132 F10）：Win11 相机必有材料仓——main 按相机传同一
    # 个 store 并挂 state.materials；测试与生产一致用真实 MaterialsStore。
    # 模型在位：main 只给 _detector_plan==alerting 的相机建管道，启动声明走
    # monitor_only 保守路径，能力由 L1 真实结果决定。
    store = MaterialsStore()
    state.materials = store
    nvr_mod._run_camera(
        {"id": "cam1", "source": "rtsp://camera",
         "detector": {"engine": "onnx", "model": str(model_path),
                      "classes": ["person"]}},
        [], "events.db", stop, state, pipeline=pipeline, store=store)


def _async_source_cls(stop):
    class Source:
        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def read(self):
            stop.set()
            return True, "frame", 1000.0

        @property
        def stats(self):
            # source_capture：now=ts*1000，测试可断言确定性的时间线
            return {"timestamp_kind": "source_capture"}

        def close(self):
            pass

    return Source


def _fake_l1_result(error_code=None):
    return SimpleNamespace(
        camera_id="cam1", run_id="run-1", frame_id=7, t_capture_ms=1000000.0,
        reason="change_start", config_version=3, frame_bgr=None,
        detections=[], status="ok", error_code=error_code,
        classes=["person"], queued_ms=1.0, infer_ms=2.0,
        t_done_mono_ms=1000001.0)


def test_win11_camera_thread_wires_l1_pipeline_async(tmp_path, monkeypatch):
    """pipeline 非 None：Monitor 走 async 构造（detect_fn=None），材料出口与
    结果消费被帧循环实际使用，首次 ready 后能力才置为可用。"""
    stop = _FastStop()
    model = tmp_path / "async.onnx"
    model.write_bytes(b"stub")
    registry = CameraRuntimeRegistry(["cam1"])
    state = SimpleNamespace(monitors={}, runtime=registry)
    pipeline = _StubL1Pipeline()
    fake_result = _fake_l1_result()
    pipeline.results.append(fake_result)
    captures, frame = _patch_async_runtime(monkeypatch,
                                           l1_health_state="ready")
    monkeypatch.setattr(nvr_mod, "CameraSource", _async_source_cls(stop))

    _run_async_camera(stop, state, pipeline, model)

    monitor = captures["monitor"]
    assert monitor.init_kwargs["detection_mode"] == "async"
    assert monitor.init_kwargs["detect_fn"] is None, \
        "async 模式绝不向 Monitor 传同步 detect_fn"
    assert callable(monitor.material_sink), "材料出口必须被注册"
    assert pipeline.take_calls == ["cam1"], "帧循环必须逐帧取 L1 结果"
    assert captures["applied"] == [(fake_result, 1000000.0)]
    # step 内的真实材料机会 → submit 收到字段完整的 L1Task，帧是任务独占副本
    assert len(pipeline.submitted) == 1
    task = pipeline.submitted[0]
    assert isinstance(task, nvr_mod.L1Task)
    assert task.camera_id == "cam1" and task.run_id == "run-1"
    assert task.frame_id == 7 and task.t_capture_ms == 1000000.0
    assert task.reason == "change_start"
    assert task.change_boxes == [[0, 0, 2, 2]]
    assert (task.gate_w, task.gate_h) == (8, 6)
    assert task.config_version == 3 and task.prev_available is True
    assert task.frame_bgr is not frame, "材料帧必须复制，任务独占副本"
    # 启动时保守声明 monitor_only，首次 ready 后才由既有能力出口置 alerting
    camera = _camera_state(registry, "cam1")
    assert camera["capability"] == "alerting"
    assert camera["issue"] is None


def test_material_submit_rejection_counts_and_stays_conservative(
        tmp_path, monkeypatch):
    """submit 未受理（False）：material_rejected 计数，材料机会不阻塞快系统；
    没有 ready 结果时能力保持保守声明，绝不提前宣称 alerting。"""
    stop = _FastStop()
    model = tmp_path / "reject.onnx"
    model.write_bytes(b"stub")
    registry = CameraRuntimeRegistry(["cam1"])
    state = SimpleNamespace(monitors={}, runtime=registry)
    pipeline = _StubL1Pipeline()
    pipeline.submit_returns = False
    captures, frame = _patch_async_runtime(monkeypatch,
                                           l1_health_state="ready")
    monkeypatch.setattr(nvr_mod, "CameraSource", _async_source_cls(stop))

    _run_async_camera(stop, state, pipeline, model)

    monitor = captures["monitor"]
    assert pipeline.submitted, "未受理也必须真的提交过（由管道计数归类）"
    assert captures["material_rejected_after_step"] == 1
    assert monitor.material_rejected == 1
    camera = _camera_state(registry, "cam1")
    assert camera["capability"] == "monitor_only", \
        "没有 ready 结果不得宣称检测告警已启用"


def test_l1_model_unavailable_reports_detector_unavailable(
        tmp_path, monkeypatch):
    """l1_health 变 model_unavailable：复用既有词表置检测不可用，不发明新码。"""
    stop = _FastStop()
    model = tmp_path / "broken.onnx"
    model.write_bytes(b"stub")
    registry = CameraRuntimeRegistry(["cam1"])
    state = SimpleNamespace(monitors={}, runtime=registry)
    pipeline = _StubL1Pipeline()
    pipeline.results.append(_fake_l1_result(error_code="detector_load_failed"))
    captures, frame = _patch_async_runtime(
        monkeypatch, l1_health_state="model_unavailable")
    monkeypatch.setattr(nvr_mod, "CameraSource", _async_source_cls(stop))

    _run_async_camera(stop, state, pipeline, model)

    camera = _camera_state(registry, "cam1")
    assert camera["capability"] == "detector_unavailable"
    assert camera["issue"]["code"] == "detector_load_failed"


def test_sync_path_construction_unchanged_without_pipeline(monkeypatch):
    """pipeline=None（Linux/无共享管道）：Monitor 保持 sync 构造，零改动。"""
    stop = _FastStop()
    registry = CameraRuntimeRegistry(["side"])
    state = SimpleNamespace(monitors={}, runtime=registry)
    init_kwargs = []

    class SyncMonitor:
        GRAY_W = 8
        timestamp_kind = None

        def __init__(self, camera_cfg, detect_fn, sinks, seq=0, run_id=None,
                     **kwargs):
            init_kwargs.append({"detect_fn": detect_fn, **kwargs})

        def set_material_sink(self, fn):
            raise AssertionError("sync 路径绝不能注册材料出口")

        def step(self, frame, gray, now):
            pass

        def persistence_state(self):
            return {"review_open_failures": 0, "review_unpersisted": False,
                    "deferred_alarms": 0, "event_open_failures": 0,
                    "event_facts_unpersisted": 0, "sink_failures": 0,
                    "degraded": False}

        def on_stream_lost(self, now):
            pass

        def on_stream_recovered(self):
            pass

        def close_all_event_facts(self, reason="camera-stopped"):
            return 0

    class Source:
        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            return True

        def read(self):
            stop.set()
            return True, "frame", 2000.0

        @property
        def stats(self):
            return {"timestamp_kind": "host_receive"}

        def close(self):
            pass

    monkeypatch.setattr(nvr_mod, "Monitor", SyncMonitor)
    monkeypatch.setattr(nvr_mod, "CameraSource", Source)
    monkeypatch.setattr(nvr_mod, "build_sinks", lambda *a, **k: [])
    monkeypatch.setattr(nvr_mod, "to_gray", lambda frame, width: None)

    nvr_mod._run_camera(
        {"id": "side", "source": "rtsp://camera",
         "detector": {"engine": "none"}},
        [], "events.db", stop, state)

    assert len(init_kwargs) == 1
    assert "detection_mode" not in init_kwargs[0], \
        "无管道时不得引入 async 模式参数"
    assert callable(init_kwargs[0]["detect_fn"]), \
        "sync 路径必须照旧传入 detect_fn"


def test_nvr_source_has_no_narrative_sink_references():
    """NarrativeSink 假接线清除：nvr 源码不得再出现任何 narrative_sink 引用。"""
    from pathlib import Path
    source = Path(nvr_mod.__file__).read_text(encoding="utf-8")
    assert "narrative_sink" not in source
    assert "NarrativeSink" not in source


class _StubMainL1Pipeline:
    """main() 级替身：记录构造/启动/关闭与相机线程完成次序，不起任何线程。"""

    events = []
    instances = []

    def __init__(self, detector_factory, *, stop_event, model_name="unknown",
                 **kwargs):
        self.detector_factory = detector_factory
        self.model_name = model_name
        self.started = False
        self.closed = False
        _StubMainL1Pipeline.instances.append(self)
        _StubMainL1Pipeline.events.append(("construct", model_name))

    def start(self):
        self.started = True
        _StubMainL1Pipeline.events.append(("start", self.model_name))

    def close(self):
        self.closed = True
        _StubMainL1Pipeline.events.append(("close", self.model_name))
        # 契约对齐（C152-R3 批准的最小收尾扩围）：真实 L1Pipeline.close() 成功
        # 返回 True；桩不返回 True 会被 nvr 如实计为"未完成收尾"，从而触发
        # 未完成 → 退出码 3 的新合同。此处让桩与真实合同一致（本测试关注
        # 检测器分组，不关注停机语义）。
        return True


class _RecordingServer:
    """可工作的工作台替身：只抓 state，不绑端口。"""

    states = []

    def __init__(self, state, host="127.0.0.1", port=8600):
        self.state = state
        _RecordingServer.states.append(state)

    def serve_forever(self):
        pass

    def shutdown(self):
        pass


class _StubSemanticUpdater:
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        pass

    def stop(self, timeout=None):
        pass


def test_win11_main_groups_detectors_into_shared_l1_pipelines(
        tmp_path, monkeypatch):
    """win11+检测器：按检测配置组建共享管道，state.l1 形状正确（合同 §4），
    相机线程拿到本组管道；close 在全部相机线程 join 之后。"""
    from scam import semantic_updater as semantic_updater_mod

    shared = tmp_path / "shared.onnx"
    shared.write_bytes(b"stub")
    other = tmp_path / "other.onnx"
    other.write_bytes(b"stub")
    config = tmp_path / "cameras.json"
    config.write_text(json.dumps({
        "venue": {"name": "test"},
        "cameras": [
            {"id": "cam-a", "source_kind": "rtsp", "source": "rtsp://a",
             "detector": {"engine": "onnx", "model": str(shared),
                          "classes": ["person"], "conf": 0.4},
             "record_enabled": False, "zones": []},
            {"id": "cam-b", "source_kind": "rtsp", "source": "rtsp://b",
             "detector": {"engine": "onnx", "model": str(shared),
                          "classes": ["person"], "conf": 0.4},
             "record_enabled": False, "zones": []},
            {"id": "cam-c", "source_kind": "rtsp", "source": "rtsp://c",
             "detector": {"engine": "onnx", "model": str(other),
                          "classes": ["person"], "conf": 0.4},
             "record_enabled": False, "zones": []},
        ],
    }), encoding="utf-8")

    _StubMainL1Pipeline.events = []
    _StubMainL1Pipeline.instances = []
    _RecordingServer.states = []
    monkeypatch.setattr(nvr_mod, "L1Pipeline", _StubMainL1Pipeline)
    monkeypatch.setattr(nvr_mod, "WorkbenchServer", _RecordingServer)
    monkeypatch.setattr(semantic_updater_mod, "SemanticUpdater",
                        _StubSemanticUpdater)
    handlers = {}
    monkeypatch.setattr(
        nvr_mod.signal, "signal",
        lambda signum, handler: handlers.setdefault(signum, handler))
    pipeline_by_cam = {}

    def fake_run_camera(cam_cfg, *args, **kwargs):
        # 第 7 个位置参数是 pipeline（cam_cfg 已绑定命名参数，args 从第 2 个起）
        pipeline_by_cam[cam_cfg["id"]] = (args[5] if len(args) > 5
                                          else kwargs.get("pipeline"))
        _StubMainL1Pipeline.events.append(("cam-done", cam_cfg["id"]))
        handlers[signal.SIGINT](None, None)

    monkeypatch.setattr(nvr_mod, "_run_camera", fake_run_camera)

    code = nvr_mod.main(
        ["--config", str(config), "--db", str(tmp_path / "l1.db"),
         "--host", "127.0.0.1", "--port", "8631"],
        edition="win11")

    assert code == 0
    state = _RecordingServer.states[-1]
    l1 = state.l1
    assert isinstance(l1, list) and len(l1) == 2
    for group in l1:
        assert set(group.keys()) == {"cameras", "pipeline"}
        assert isinstance(group["cameras"], list) and group["cameras"]
        assert isinstance(group["pipeline"], _StubMainL1Pipeline)
    # 同检测配置共享一个管道；不同配置各自独立
    group_ab = next(g for g in l1 if "cam-a" in g["cameras"])
    assert group_ab["cameras"] == ["cam-a", "cam-b"]
    assert pipeline_by_cam["cam-a"] is group_ab["pipeline"]
    assert pipeline_by_cam["cam-b"] is group_ab["pipeline"]
    group_c = next(g for g in l1 if "cam-c" in g["cameras"])
    assert group_c["cameras"] == ["cam-c"]
    assert group_c["pipeline"] is not group_ab["pipeline"]
    assert pipeline_by_cam["cam-c"] is group_c["pipeline"]
    # 每组建即启动；模型短名进 model_name（不含路径）
    assert all(p.started for p in _StubMainL1Pipeline.instances)
    assert sorted(p.model_name for p in _StubMainL1Pipeline.instances) == \
        ["other.onnx", "shared.onnx"]
    # 关闭发生在全部相机线程结束之后（join 提供先后保证）
    assert all(p.closed for p in _StubMainL1Pipeline.instances)
    positions = {name: [i for i, (kind, _)
                        in enumerate(_StubMainL1Pipeline.events)
                        if kind == name]
                 for name in ("cam-done", "close")}
    assert len(positions["cam-done"]) == 3
    assert max(positions["cam-done"]) < min(positions["close"]), \
        "L1 管道必须在相机线程全部结束之后才关闭"


# ---------- C-132 生产接线（真 Monitor + 真 L1Pipeline + 真 MaterialsStore） ----------

def _wait_until(pred, timeout_s=2.0, step=0.01):  # noqa: 保留默认
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(step)
    return pred()


class _Det:
    """检测器替身：真实 L1Pipeline 在 worker 线程内调用它。"""

    classes = ["person"]

    def detect(self, frame_bgr):
        return [{"cls": "person", "conf": 0.9,
                 "bbox": [0.4, 0.4, 0.2, 0.2], "cx": 0.5, "cy": 0.5}]


class _ArraySource:
    """帧源替身：复用同一缓冲区对象逐帧改写（生产图像所有权语义）；
    带节流，让 L1 worker 真实被调度（生产节奏 30fps 的缩影）。"""

    def __init__(self, stop, buffer, total, pace_s=0.003):
        self._stop = stop
        self._buffer = buffer
        self._total = total
        self._i = 0
        self._pace_s = pace_s

    def open(self):
        return True

    def read(self):
        if self._i >= self._total:
            self._stop.set()
            return False, None, None
        time.sleep(self._pace_s)
        self._buffer[:] = 0
        x = 20 + (self._i % 8) * 8
        self._buffer[x:x + 30, 40:70] = 255
        self._i += 1
        return True, self._buffer, 1000.0 + self._i * 0.033

    @property
    def stats(self):
        return {"timestamp_kind": "source_capture"}

    def close(self):
        pass


def _run_production_chain(tmp_path, monkeypatch, total=90, with_pipeline=True):
    import numpy as np
    stop = _FastStop()
    buffer = np.zeros((240, 320, 3), dtype=np.uint8)
    monkeypatch.setattr(nvr_mod, "CameraSource",
                        lambda *a, **k: _ArraySource(stop, buffer, total))
    registry = CameraRuntimeRegistry(["cam"])
    state = SimpleNamespace(monitors={}, runtime=registry)
    store = MaterialsStore()
    state.materials = store
    pipeline = None
    if with_pipeline:
        # 模型文件在位（_detector_plan 依据）：与生产判定一致
        (tmp_path / "stub.onnx").write_bytes(b"stub")
        pipeline = nvr_mod.L1Pipeline(lambda: _Det(), stop_event=stop,
                                      poll_timeout_s=0.02)
        pipeline.start()
    captures = {"monitors": []}

    real_monitor = nvr_mod.Monitor

    class MonitorProbe(real_monitor):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            captures["monitors"].append(self)

    monkeypatch.setattr(nvr_mod, "Monitor", MonitorProbe)
    cam_cfg = {"id": "cam", "source": "unused"}
    if with_pipeline:
        cam_cfg["detector"] = {"engine": "onnx",
                               "model": str(tmp_path / "stub.onnx"),
                               "classes": ["person"]}
    try:
        nvr_mod._run_camera(cam_cfg, [], str(tmp_path / "events.db"), stop,
                            state, pipeline=pipeline, store=store)
    finally:
        monkeypatch.setattr(nvr_mod, "Monitor", real_monitor)
    return {"stop": stop, "state": state, "store": store,
            "pipeline": pipeline, "captures": captures, "buffer": buffer,
            "registry": registry}


def test_production_async_chain_real_components(tmp_path, monkeypatch):
    """生产链路（合同 C-132 F10）：真 Monitor(async) + 真 L1Pipeline +
    真 MaterialsStore 经 _run_camera 完整跑通——材料双投、结果附包、
    上游缓冲区改写不污染已留档材料。"""
    env = _run_production_chain(tmp_path, monkeypatch)
    store, pipeline = env["store"], env["pipeline"]
    try:
        assert env["captures"]["monitors"], "Monitor 必须被真实构造"
        monitor = env["captures"]["monitors"][0]
        assert monitor.detection_mode == "async"
        assert monitor.detect_fn is None
        assert _wait_until(lambda: store.snapshot()["cameras"].get("cam", {})
                           .get("last_l1_status") == "ok"), \
            "L1 结果必须真实回到材料仓（attach_result 生产接线）"
        snap = store.snapshot()["cameras"]["cam"]
        assert snap["consumed"] + snap["ready"] > 0
        assert snap["ready_with_prev"] > 0, "前一帧必须真实留档"
        assert snap["ready_with_next"] > 0, "后一帧必须真实回填"
        camera = _camera_state(env["registry"], "cam")
        assert camera["capability"] == "alerting"
        # 生产图像所有权：跑完后把复用缓冲区整体写满 255，已留档材料
        # 必须仍是独立副本（留档帧含黑背景，min=0；被污染则 min=255）
        env["buffer"][:] = 255
        package = store.take_ready("cam")
        assert package is not None
        assert package.cur.frame_bgr.min() != 255, \
            "留档帧必须是独立副本，不被上游缓冲区后续改写污染"
        assert monitor.material_rejected == 0
    finally:
        if pipeline is not None:
            pipeline.close()
        store.close()


def test_preview_camera_materials_without_pipeline(tmp_path, monkeypatch):
    """仅预览/缺模型相机（合同 C-132 九.3）：统一轻量材料路径——材料照常
    留档，但不建管道、不启动检测、能力保持 monitor_only、永不产生对象结果。"""
    env = _run_production_chain(tmp_path, monkeypatch, total=60,
                                with_pipeline=False)
    store = env["store"]
    monitor = env["captures"]["monitors"][0]
    assert monitor.detection_mode == "async"
    assert monitor.detect_fn is None
    assert env["pipeline"] is None
    # C-135 状态机：无 L1 的预览相机材料进入 waiting_l1，超时 sweep 转
    # fallback(l1_wait_timeout)——诚实兜底可消费，绝不伪造 L1 状态
    # （兜底门槛 L1_WAIT_S=3.0s，等待窗口须覆盖之）
    assert _wait_until(lambda: store.snapshot()["cameras"].get("cam", {})
                       .get("fallback", 0) > 0,
                       timeout_s=6.0), \
        "变化材料必须照常留档（超时兜底后可消费）"
    snap = store.snapshot()["cameras"]["cam"]
    assert snap["last_l1_status"] is None, "无管道不得伪造 L1 状态"
    assert snap["waiting_l1"] + snap["fallback"] + snap["consumed"] > 0
    camera = _camera_state(env["registry"], "cam")
    assert camera["capability"] == "monitor_only"
    assert monitor.det_calls == 0
    store.close()


def test_stop_l1_components_reports_incomplete_honestly():
    """停机收尾（合同 C-132 F10）：close False/异常如实入列，成功组不误报；
    材料仓必然被收口；全成时返回空列表（调用方才可宣称已停机）。"""

    class _P:
        def __init__(self, ret):
            self._ret = ret
            self.closed = False

        def close(self, timeout_s=5.0):
            self.closed = True
            return self._ret

    class _X:
        def close(self, timeout_s=5.0):
            raise RuntimeError("join exploded")

    ok_p, bad_p = _P(True), _P(False)
    store = MaterialsStore()
    incomplete = nvr_mod._stop_l1_components(
        [{"cameras": ["a"], "pipeline": ok_p},
         {"cameras": ["b"], "pipeline": bad_p}], store)
    assert ok_p.closed and bad_p.closed
    assert len(incomplete) == 1 and "b" in incomplete[0], \
        "worker 仍活时必须报告停止未完成"
    final = store.snapshot()
    assert final["cameras"] == {}
    for key in ("total_bytes", "lease_bytes", "consumer_alive_bytes",
                "store_bytes", "total_packages", "active_leases",
                "released_leases", "expired_leases"):
        assert final[key] == 0, f"close 后 {key} 必须归零"
    inc2 = nvr_mod._stop_l1_components(
        [{"cameras": ["c"], "pipeline": _X()}], None)
    assert len(inc2) == 1 and "c" in inc2[0] and "RuntimeError" in inc2[0]
    assert nvr_mod._stop_l1_components([], None) == []


# ---------- C-133 联合回归：统一消费结论 × 材料仓（R1/R4） ----------

class _ResultLike:
    """最小 L1Result 替身（鸭子类型，供 monitor 判定与结论提取）。"""

    def __init__(self, camera_id, run_id, config_version, frame_id,
                 t_capture_ms, status="ok", detections=None, error_code=None,
                 frame_bgr=None):
        self.camera_id = camera_id
        self.run_id = run_id
        self.config_version = config_version
        self.frame_id = frame_id
        self.t_capture_ms = t_capture_ms
        self.status = status
        self.detections = detections or []
        self.error_code = error_code
        self.frame_bgr = frame_bgr


def _make_async_monitor(tmp_path, zones=None):
    monitor = nvr_mod.Monitor(
        {"id": "cam", "zones": zones or []}, detect_fn=None, sinks=[],
        detection_mode="async")
    return monitor


def test_rejected_result_attaches_as_diagnostic_not_ok(tmp_path):
    """R1×M1（合同 C-133）：同身份但被 Monitor 复核拒收（超龄）的结果，
    材料只作诊断（accepted=False+原因），不冒充有效 ok；随后有效结果
    正常接受。旧 run 结果（四元不符）被材料仓独立拒收（rejected_attach），
    包不被污染。"""
    import numpy as np
    from scam.win11_materials import MaterialsStore
    monitor = _make_async_monitor(tmp_path)
    store = MaterialsStore()
    run = monitor.run_id  # 生产语义：材料/结果 run_id 来自 monitor 自身
    frame = np.zeros((24, 32, 3), dtype=np.uint8)
    # 材料在仓：monitor.run_id / config 0（monitor 初始 zone_revision）/ frame 7
    assert store.ingest("cam", run, 0, 7, frame, 1000.0, "host_receive",
                        [], 8, 6)
    # 同身份但超龄（now 远晚于采集）→ Monitor 消费复核拒收 expired
    now = 1000.0 + 9000.0
    stale = _ResultLike("cam", run, 0, 7, 1000.0, status="ok")
    assert monitor.apply_detection_result(stale, now) is True  # apply 只验身份
    monitor.step(frame, [0] * (8 * 6), now)  # 消费复核拒：expired
    c = monitor.consume_conclusion()
    assert c["accepted"] is False and c["reason"] == "expired"
    store.attach_result(c["camera_id"], c["run_id"], c["config_version"],
                        c["frame_id"], c["status"], c.get("error_code"),
                        c.get("detections") or [], accepted=c["accepted"],
                        reject_reason=c.get("reason"))
    snap = store.snapshot()["cameras"]["cam"]
    assert snap["last_l1_accepted"] is False
    assert snap["last_reject_reason"] == "expired"
    # 旧 run 结果：四元不符 → 材料仓独立拒收，包不被污染
    old_run = _ResultLike("cam", "run-OLD", 0, 7, now, status="ok")
    monitor2 = _make_async_monitor(tmp_path)
    monitor2.apply_detection_result(old_run, now)
    monitor2.step(frame, [0] * (8 * 6), now)
    c2 = monitor2.consume_conclusion()
    assert c2["accepted"] is False and c2["reason"] == "identity"
    before = store.snapshot()["cameras"]["cam"]
    store.attach_result(c2["camera_id"], c2["run_id"], c2["config_version"],
                        c2["frame_id"], c2["status"], None, [],
                        accepted=c2["accepted"], reject_reason=c2["reason"])
    after = store.snapshot()["cameras"]["cam"]
    assert after["rejected_attach"] == before["rejected_attach"] + 1
    assert after["last_l1_accepted"] is False
    assert after["last_reject_reason"] == "expired", "包不得被旧 run 污染"
    # 有效结果（身份四元匹配、新鲜）→ 正常接受
    good = _ResultLike("cam", run, 0, 8, now,
                       detections=[{"cls": "person", "conf": 0.9,
                                    "bbox": [0.1, 0.1, 0.2, 0.2]}],
                       frame_bgr=frame)
    assert store.ingest("cam", run, 0, 8, frame, now, "host_receive",
                        [], 8, 6)
    monitor.apply_detection_result(good, now + 33.0)
    monitor.step(frame, [0] * (8 * 6), now + 33.0)
    c3 = monitor.consume_conclusion()
    assert c3["accepted"] is True and c3["reason"] is None
    store.attach_result(c3["camera_id"], c3["run_id"], c3["config_version"],
                        c3["frame_id"], c3["status"], None,
                        c3.get("detections") or [], accepted=True,
                        reject_reason=None)
    snap = store.snapshot()["cameras"]["cam"]
    assert snap["last_l1_accepted"] is True
    assert snap["last_reject_reason"] is None
    store.close()


def test_conclusion_consumed_exactly_once_across_normal_frames(tmp_path):
    """C-134 主会话缺陷修复（D-P0#4）：同一真实结果的结论只下行一次——
    消费后连续多个普通帧不再重放；包取走后普通帧不增加 attach_missed；
    拒收结论同样一次性；last_conclusion 仅诊断不改变消费状态。"""
    import numpy as np
    from scam.win11_materials import MaterialsStore
    monitor = _make_async_monitor(tmp_path)
    store = MaterialsStore()
    run = monitor.run_id
    frame = np.zeros((24, 32, 3), dtype=np.uint8)
    assert store.ingest("cam", run, 0, 7, frame, 1000.0, "host_receive",
                        [], 8, 6)
    good = _ResultLike("cam", run, 0, 7, 1000.0, status="ok", frame_bgr=frame)
    now = 1000.0
    monitor.apply_detection_result(good, now)
    monitor.step(frame, [0] * (8 * 6), now)
    first = monitor.consume_conclusion()
    assert first is not None and first["accepted"] is True
    store.attach_result(first["camera_id"], first["run_id"],
                        first["config_version"], first["frame_id"],
                        first["status"], None, first.get("detections") or [],
                        accepted=True, reject_reason=None)
    pkg = store.take_ready("cam")
    assert pkg is not None
    baseline = store.snapshot()["cameras"]["cam"]
    # 消费后连续多个普通帧：结论不重放
    for i in range(6):
        assert monitor.consume_conclusion() is None
        monitor.step(frame, [0] * (8 * 6), now + 33.0 * (i + 1))
    for _ in range(6):
        assert monitor.consume_conclusion() is None
    after = store.snapshot()["cameras"]["cam"]
    assert after["attach_missed"] == baseline["attach_missed"], \
        "包取走后普通帧不得重复关联历史结论（attach_missed 不虚增）"
    assert after["rejected_attach"] == baseline["rejected_attach"]
    # last_conclusion 仅诊断：可读但不改变一次性状态
    assert monitor.last_conclusion() is not None
    assert monitor.consume_conclusion() is None
    # 拒收结论同样一次性：超龄→expired 只下行一次
    stale = _ResultLike("cam", run, 0, 8, 1000.0, status="ok", frame_bgr=frame)
    later = now + 9000.0
    assert store.ingest("cam", run, 0, 8, frame, later, "host_receive",
                        [], 8, 6)
    monitor.apply_detection_result(stale, later)
    monitor.step(frame, [0] * (8 * 6), later)
    rej = monitor.consume_conclusion()
    assert rej is not None and rej["accepted"] is False \
        and rej["reason"] == "expired"
    assert monitor.consume_conclusion() is None
    assert monitor.last_conclusion()["reason"] == "expired"
    store.close()


def test_conclusion_not_replayed_after_zone_switch_or_supersede(tmp_path):
    """C-134：配置切换失效与结果顶替的结论各只下行一次，不重放历史。"""
    import numpy as np
    monitor = _make_async_monitor(tmp_path)
    run = monitor.run_id
    frame = np.zeros((24, 32, 3), dtype=np.uint8)
    gray = [0] * (8 * 6)
    r1 = _ResultLike("cam", run, 0, 7, 1000.0, status="ok", frame_bgr=frame)
    monitor.apply_detection_result(r1, 1000.0)
    monitor.step(frame, gray, 1000.0)
    c1 = monitor.consume_conclusion()
    assert c1 is not None and monitor.consume_conclusion() is None
    # 待消费结果在途时切换区域 → invalidated_config 结论一次
    r2 = _ResultLike("cam", run, 0, 8, 1033.0, status="ok", frame_bgr=frame)
    assert monitor.apply_detection_result(r2, 1033.0) is True
    monitor.request_zone_update([])
    monitor.step(frame, gray, 1066.0)  # 帧边界切换 + 旧配置结果失效
    c2 = monitor.consume_conclusion()
    assert c2 is not None and c2["reason"] == "invalidated_config"
    assert monitor.consume_conclusion() is None
    # 顶替：r3 在途时 r4 到来 → r3 永不产生结论（不重放），r4 正常一次
    r3 = _ResultLike("cam", run, 0, 9, 1099.0, status="ok", frame_bgr=frame)
    r4 = _ResultLike("cam", run, 0, 10, 1132.0, status="ok", frame_bgr=frame)
    monitor.apply_detection_result(r3, 1099.0)
    monitor.apply_detection_result(r4, 1132.0)
    monitor.step(frame, gray, 1132.0)
    c4 = monitor.consume_conclusion()
    assert c4 is not None and c4["frame_id"] == 10
    assert monitor.consume_conclusion() is None


# ---------- C-134 L2 接线（开关门控/独立线程/租约消费/健康面） ----------

class _FakeL2Model:
    """确定性关系模型替身（注入 stage；生产入口禁 fake 的边界在 nvr 默认
    配置与真实 adapter，本替身只用于运行面行为测试）。"""

    model_ref = "fake-relations/test"

    def __init__(self, triples=None, error=None):
        self.triples = triples if triples is not None else [
            {"s": 0, "o": 1, "relation": "walking past",
             "graph": "semantic", "score": 0.6}]
        self.error = error
        self.calls = 0

    def infer(self, frame_bgr, boxes_px, labels, vocabulary):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.triples


def _make_l2_runtime(store, model, **kwargs):
    import numpy as np
    from scam.win11_l2_contract import L2RelationStage
    stage = L2RelationStage(model=model)
    kwargs.setdefault("max_age_s", 30.0)
    runtime = nvr_mod.L2Runtime(["cam"], store, stage,
                                vocabulary=("walking past",),
                                poll_interval_s=0.05, **kwargs)
    frame = np.zeros((240, 320, 3), dtype=np.uint8)
    frame[100:140, 60:110] = 255
    return runtime, frame


def _ingest_l2_package(store, frame, run, frame_id=7, t_ms=None):
    import time as _t
    t_ms = t_ms if t_ms is not None else _t.time() * 1000.0
    assert store.ingest("cam", run, 0, frame_id, frame, t_ms,
                        "host_receive", [], 8, 6)
    return t_ms


def test_l2_runtime_processes_package_counts_and_releases(tmp_path):
    """L2 运行面（合同 §4）：独立消费材料包→关系候选→裁图计数→租约
    release；快系统/L1 语义零牵连。"""
    import time as _t
    import numpy as np
    from scam.win11_materials import MaterialsStore
    store = MaterialsStore()
    runtime, frame = _make_l2_runtime(store, _FakeL2Model())
    runtime.set_camera_identity("cam", "run-a", 0)
    assert store.ingest("cam", "run-a", 0, 7, frame, _t.time() * 1000.0,
                        "host_receive", [], 8, 6)
    store.attach_result("cam", "run-a", 0, 7, "ok", None,
                        [{"cls": "person", "conf": 0.9,
                          "bbox": [0.2, 0.3, 0.2, 0.3], "trackId": 1},
                         {"cls": "person", "conf": 0.8,
                          "bbox": [0.6, 0.35, 0.2, 0.3], "trackId": 2}],
                        accepted=True, reject_reason=None)
    runtime.start()
    try:
        deadline = _t.monotonic() + 5.0
        while _t.monotonic() < deadline:
            snap = runtime.snapshot()
            if snap["cameras"]["cam"]["processed"] >= 1:
                break
            _t.sleep(0.02)
        snap = runtime.snapshot()
        assert snap["cameras"]["cam"]["processed"] == 1
        assert snap["cameras"]["cam"]["crops_produced"] >= 1, \
            "有关系候选就必须产出互动裁图（双方联合框）"
        last = snap["last"]["cam"]
        assert last["status"] == "ok" and last["candidates"] >= 1
        assert last["calibrated"] is False, "关系分数未经校准必须如实标注"
    finally:
        assert runtime.stop() is True, "L2 线程必须能干净停止"
    assert store.snapshot()["cameras"]["cam"]["leased"] == 0, \
        "处理后租约必须释放（不占消费者预算）"
    store.close()


def test_l2_runtime_expires_stale_package_honestly(tmp_path):
    """过期材料（M3 单调钟）：显式取消+expired 计数，不进入推理、不冒充
    处理完成。过期判据=包创建单调钟年龄（不与日历时间相减）。"""
    import time as _t
    from scam.win11_materials import MaterialsStore
    store = MaterialsStore()
    model = _FakeL2Model()
    runtime, frame = _make_l2_runtime(store, model, max_age_s=0.05)
    runtime.set_camera_identity("cam", "run-a", 0)
    _ingest_l2_package(store, frame, "run-a", frame_id=7)
    store.attach_result("cam", "run-a", 0, 7, "ok", None,
                        [{"cls": "person", "conf": 0.9,
                          "bbox": [0.2, 0.3, 0.2, 0.3], "trackId": 1},
                         {"cls": "person", "conf": 0.8,
                          "bbox": [0.6, 0.35, 0.2, 0.3], "trackId": 2}],
                        accepted=True, reject_reason=None)
    _t.sleep(0.2)  # mono 年龄 0.2s > max_age 0.05s
    runtime.start()
    try:
        deadline = _t.monotonic() + 5.0
        while _t.monotonic() < deadline:
            if runtime.snapshot()["cameras"]["cam"]["expired"] >= 1:
                break
            _t.sleep(0.02)
        snap = runtime.snapshot()["cameras"]["cam"]
        assert snap["expired"] == 1 and snap["processed"] == 0
        assert model.calls == 0, "过期材料不得进入关系推理"
    finally:
        assert runtime.stop() is True
    assert store.snapshot()["cameras"]["cam"]["leased"] == 0
    store.close()


def test_l2_runtime_failure_counted_without_blocking(tmp_path):
    """模型异常：failed 计数+last 状态如实，线程存活继续消费（不阻塞）。"""
    import time as _t
    from scam.win11_materials import MaterialsStore
    store = MaterialsStore()
    model = _FakeL2Model(error=RuntimeError("upstream boom"))
    runtime, frame = _make_l2_runtime(store, model)
    runtime.set_camera_identity("cam", "run-a", 0)
    _ingest_l2_package(store, frame, "run-a", frame_id=7)
    store.attach_result("cam", "run-a", 0, 7, "ok", None,
                        [{"cls": "person", "conf": 0.9,
                          "bbox": [0.2, 0.3, 0.2, 0.3], "trackId": 1},
                         {"cls": "person", "conf": 0.8,
                          "bbox": [0.6, 0.35, 0.2, 0.3], "trackId": 2}],
                        accepted=True, reject_reason=None)
    runtime.start()
    try:
        deadline = _t.monotonic() + 5.0
        while _t.monotonic() < deadline:
            if runtime.snapshot()["cameras"]["cam"]["failed"] >= 1:
                break
            _t.sleep(0.02)
        snap = runtime.snapshot()
        assert snap["cameras"]["cam"]["processed"] == 1
        assert snap["last"]["cam"]["status"] == "infer_failed", \
            "模型异常经 stage 四分类如实呈现，不冒充成功也不崩溃"
        assert runtime._thread.is_alive(), "单次失败不得杀死 L2 线程"
    finally:
        assert runtime.stop() is True
    store.close()


def test_production_chain_wires_progress_probe(tmp_path, monkeypatch):
    """T2 探针生产接线：nvr 必须把管道最老未完结任务年龄喂给 Monitor——
    探针存在且返回管道侧真值（提交后非 None），持续提交不重置卡死判定基础。"""
    env = _run_production_chain(tmp_path, monkeypatch, total=60)
    monitor = env["captures"]["monitors"][0]
    pipeline = env["pipeline"]
    try:
        assert monitor._progress_probe is not None, "进展探针必须接线"
        # 探针与管道侧真值一致（同为 None 或同一年龄）——生产接线正确性：
        # 探针必须透传管道最老未完结任务年龄，不得另立基准。
        probe_value = monitor._progress_probe()
        pipe_value = pipeline.oldest_unfinished_age_ms("cam")
        assert probe_value == pipe_value
    finally:
        if pipeline is not None:
            pipeline.close()
        env["store"].close()


def test_l2_runtime_entry_wiring_accepts_crop_worker(tmp_path):
    """C-141 主会话接线：入口构建 L2 运行面时注入裁图证据工作者。

    - 注入后 runtime.crop_worker 即所注入实例（生产提交与 state.crop_service
      同一对象）；
    - 未注入（仅内存口径）时 crop_worker 为 None，构建照常；
    - nvr 停机序（close→join）对工作者有界收束：线程必须结束。
    仅合成接线验证，不含真实模型/浏览器/重启回看。
    """
    from scam.win11_crop_evidence import CropEvidenceStore
    from scam.win11_crop_worker import CropWorker

    worker = CropWorker(CropEvidenceStore(tmp_path / "crops"))
    # 产品合同：l2.enabled 必须显式 repo_path（无内置默认）；本用例只验
    # crop_worker 注入接线，adapter 构造不加载任何文件。
    runtime = nvr_mod._build_l2_runtime(
        {"enabled": True, "repo_path": str(tmp_path / "relate")},
        None, ["front-door"], crop_worker=worker)
    assert runtime.crop_worker is worker
    # C154 G：生产入口缺省即建**有界**同事件跨窗选材池；无事件桥（无
    # db_path/l4）时绑定来源为 None → 池只记原因、不聚合（旧窗口路径不变）
    from scam.win11_event_materials import EventMaterialPool
    assert isinstance(runtime.event_materials, EventMaterialPool)
    assert runtime.event_materials.binding_source is None
    limits = runtime.event_materials.snapshot()["limits"]
    assert limits["max_events"] >= 1 and limits["max_frames_per_event"] >= 1
    assert limits["max_total_pixels"] >= 1 and limits["max_frame_pixels"] >= 1
    assert runtime.snapshot()["event_materials"]["events_held"] == 0

    plain = nvr_mod._build_l2_runtime(
        {"enabled": True, "repo_path": str(tmp_path / "relate")},
        None, ["front-door"])
    assert plain.crop_worker is None

    worker.start()
    worker.close(timeout_s=5.0)
    assert worker.join(timeout_s=5.0) is True


def test_win11_entry_enables_protected_slot_and_shared_default_is_zero():
    """W1：Win11 生产入口显式 latest_protected_slots=1；共享默认仍为 0；快照可查。

    - 入口级：`nvr.main` 的 L1 分组构建点显式传 1（非实验驱动注入）；
    - 共享级：`L1Pipeline` 构造默认仍为 0（其他调用方与 Linux 不自动改变）；
    - 可查：快照暴露当前保护位策略。
    """
    import inspect
    import re as _re
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    src = (root / "scam" / "nvr.py").read_text(encoding="utf-8")
    call = _re.search(r"L1Pipeline\((?:[^()]|\([^()]*\))*\)", src, _re.S)
    assert call, "nvr.py 必须存在 L1Pipeline 生产构建点"
    assert "latest_protected_slots=1" in call.group(0), \
        "Win11 生产入口必须显式启用一个受保护槽位"

    from scam.win11_pipeline import L1Pipeline
    sig = inspect.signature(L1Pipeline.__init__)
    assert sig.parameters["latest_protected_slots"].default == 0, \
        "共享 L1Pipeline 默认必须保持 0"

    # 策略可查 + 不允许"静默扩队列"：影响通过 counters["dispositions"] 暴露，
    # 且构造参数只接受 0/1（bool 与更大值一律拒绝）。
    snap_src = (root / "scam" / "win11_pipeline.py").read_text(encoding="utf-8")
    assert "protected_retained" in snap_src and "dropped_oldest_latest" in snap_src, \
        "保护位影响必须以受控终态码暴露（protected_retained / dropped_oldest_latest）"
    assert "latest_protected_slots not in (0, 1)" in snap_src, \
        "保护位只允许 0/1，必须拒绝更大值以杜绝静默扩队列"
