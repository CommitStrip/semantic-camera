"""LC-005 Linux L3 health API 契约测试：watchdog/资源快照附加语义。

覆盖三类契约：有 registry 附加快照、无 registry 兼容（字段与语义不变）、
采样异常结构化降级（端点绝不 500、主链字段不受影响）。
进程内驱动 Handler（不联网、不起端口、不起子进程）；合成证据，
不代表 Linux 主机、真实 RTSP 断流或 24 小时证据。
"""

from types import SimpleNamespace

from scam.db import connect, init_schema
from scam.health import HealthRegistry
from scam.server import WorkbenchHandler, WorkbenchState


class _H(WorkbenchHandler):
    """绕过网络栈的最小 Handler 驱动：只走 do_GET 业务逻辑。"""

    def __init__(self, path, state):
        self.command = "GET"
        self.path = path
        self.headers = {"Content-Length": "0"}
        self.rfile = SimpleNamespace(read=lambda n: b"")
        self.wfile = SimpleNamespace(write=lambda b: None)
        self.status = None
        self.response_headers = {}
        self._state = state
        self._body = []

    @property
    def server(self):
        return SimpleNamespace(state=self._state)

    def send_response(self, code, message=None):
        self.status = code

    def send_header(self, key, value):
        self.response_headers[key] = value

    def end_headers(self):
        pass

    def _json(self, obj, status=200):
        self.status = status
        self._body.append(obj)


def _get(state, path):
    h = _H(path, state)
    h.do_GET()
    return h.status, h._body[-1] if h._body else {}


def _state(tmp_path):
    db_path = str(tmp_path / "health_api.db")
    conn = connect(db_path)
    init_schema(conn)
    conn.close()
    return WorkbenchState(db_path)


# ---------- 1. 有 registry：附加逐相机 watchdog 与资源快照 ----------

def test_health_with_registry_appends_watchdog_and_resources(tmp_path):
    state = _state(tmp_path)
    registry = HealthRegistry(["front"], str(tmp_path / "storage"))
    watchdog = registry.camera("front")
    watchdog.started()
    watchdog.frame()
    state.health = registry

    st, body = _get(state, "/api/health")

    assert st == 200
    # 原有字段与语义不变（无在线相机时的基线形状）
    assert body["cameras"] == [] and body["count"] == 0
    assert body["recording"] == []
    # 附加：逐相机 watchdog 快照
    assert body["watchdog"]["count"] == 1
    cam = body["watchdog"]["cameras"][0]
    assert cam["camera"] == "front"
    assert cam["state"] == "online" and cam["frames"] == 1
    # 附加：RuntimeResourceSampler 资源快照（结构化、best-effort）
    for key in ("sampled_at", "cpu_percent", "rss_bytes", "threads",
                "open_fds", "disk"):
        assert key in body["resources"]


# ---------- 2. 无 registry：现有字段与语义完全不变 ----------

def test_health_without_registry_keeps_legacy_shape(tmp_path):
    state = _state(tmp_path)

    st, body = _get(state, "/api/health")

    assert st == 200
    assert set(body) == {"cameras", "count", "recording"}

    # 显式 None 同样视为无 registry
    state.health = None
    st, body = _get(state, "/api/health")
    assert st == 200
    assert set(body) == {"cameras", "count", "recording"}


# ---------- 3. 资源采样异常：结构化降级，watchdog 与主链不受影响 ----------

def test_health_resource_sampling_failure_degrades_honestly(tmp_path):
    state = _state(tmp_path)
    registry = HealthRegistry(["front"], str(tmp_path / "storage"))
    registry.camera("front").frame()

    class _Boom:
        def sample(self, *args, **kwargs):
            raise RuntimeError("sampler exploded")

    registry.resources = _Boom()
    state.health = registry

    st, body = _get(state, "/api/health")

    assert st == 200  # 绝不 500
    assert body["watchdog"]["cameras"][0]["camera"] == "front"
    assert body["resources"]["state"] == "unavailable"
    assert body["resources"]["error"] == "RuntimeError"
    assert body["cameras"] == [] and body["recording"] == []


# ---------- 4. watchdog 快照异常：结构化降级，资源快照不受影响 ----------

def test_health_watchdog_snapshot_failure_degrades_honestly(tmp_path):
    state = _state(tmp_path)

    def _boom(*args, **kwargs):
        raise ValueError("registry exploded")

    state.health = SimpleNamespace(
        snapshot=_boom,
        resources=SimpleNamespace(
            sample=lambda *args, **kwargs: {"sampled_at": 1.0}))

    st, body = _get(state, "/api/health")

    assert st == 200
    assert body["watchdog"]["state"] == "unavailable"
    assert body["watchdog"]["error"] == "ValueError"
    assert body["resources"]["sampled_at"] == 1.0
    assert body["cameras"] == [] and body["recording"] == []
