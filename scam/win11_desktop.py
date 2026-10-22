"""桌面壳协议与会话状态（Python 侧）。

职责边界（冻结接口，见 desktop/win11/README.md）：
- stdio JSONL v1 编解码与校验（schema=`scam.desktop/v1`，单行 ≤16KiB）；
- 后端握手状态机：**`ready` 只表示 HTTP 入口就绪**，不得由等待时长推断；
- 导航白名单：仅允许后端实际登记的 `127.0.0.1` origin；
- 停止握手：`stop`/EOF → 等 `stopped`；**超时不强杀、不标已完成**；
- 单实例 IPC 名称与身份校验（当前用户）；
- 路径/版本常量（唯一用户入口、内部后端、AppId、数据根）。

本模块不启动进程、不碰注册表、不读写用户数据；进程与窗口由桌面壳负责。
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

SCHEMA = "scam.desktop/v1"
MAX_LINE_BYTES = 16 * 1024

# 安装布局（冻结；安装器与壳共用，不得各自发明）
APP_ID = "{BBA9D479-0BB1-4AF0-961A-CE9D645639B9}"
USER_ENTRY_EXE = "语义摄像头.exe"
BACKEND_RELATIVE = Path("backend") / "semantic-camera-backend.exe"
INSTALL_DIR_ENV = "SEMANTIC_CAMERA_INSTALL_DIR"
DEFAULT_INSTALL_DIR = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "SemanticCamera"
# 用户数据根沿用现有，不新建第二套配置/数据库
DATA_ROOT_RELATIVE = Path("semantic-camera")

PAGE_SETUP = "setup"
PAGE_WORKBENCH = "workbench"
PAGES = (PAGE_SETUP, PAGE_WORKBENCH)

# 固定失败码（不外发异常原文/配置/命令行）
FAIL_WEBVIEW_MISSING = "webview2_unavailable"
FAIL_BACKEND_SPAWN = "backend_spawn_failed"
FAIL_BACKEND_EXIT = "backend_exited"
FAIL_HANDSHAKE_TIMEOUT = "handshake_timeout"

_VERSION_RE = re.compile(r'(?m)^\s*version\s*=\s*"([^"]+)"\s*$')


class DesktopProtocolError(Exception):
    """协议/安全违规；code 固定可判别，消息可给用户看。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def encode_event(event: str, **fields: Any) -> str:
    """后端 → 壳事件（单行 JSON，无换行）。"""
    known = {"starting", "navigate", "ready", "stopping", "stopped",
             "failed", "state"}
    if event not in known:
        raise DesktopProtocolError("unknown_event", f"未定义事件：{event}")
    payload = {"schema": SCHEMA, "event": event}
    payload.update(fields)
    line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    _check_size(line)
    return line


def parse_line(line: str) -> dict:
    """壳 → 后端命令行 或 后端 → 壳事件行 的统一解析与校验。"""
    if not isinstance(line, str):
        raise DesktopProtocolError("bad_line", "行必须是字符串")
    _check_size(line)
    stripped = line.strip()
    if not stripped:
        raise DesktopProtocolError("empty_line", "空行不是协议帧")
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise DesktopProtocolError("bad_json", "协议帧不是合法 JSON") from exc
    if not isinstance(payload, dict):
        raise DesktopProtocolError("bad_json", "协议帧必须是 JSON 对象")
    if payload.get("schema") != SCHEMA:
        raise DesktopProtocolError("bad_schema", f"schema 必须为 {SCHEMA}")
    if "command" in payload:
        command = payload["command"]
        if command != "stop":
            raise DesktopProtocolError("unknown_command", f"未定义命令：{command}")
    elif "event" not in payload:
        raise DesktopProtocolError("bad_frame", "帧既无 command 也无 event")
    return payload


def _check_size(line: str) -> None:
    size = len(line.encode("utf-8"))
    if size > MAX_LINE_BYTES:
        raise DesktopProtocolError("line_too_long",
                                   f"单行超过 {MAX_LINE_BYTES} 字节（实际 {size}）")


def stop_request_line() -> str:
    return json.dumps({"schema": SCHEMA, "command": "stop"},
                      separators=(",", ":"))


# --------------------------------------------------------------------------- #
# 导航安全
# --------------------------------------------------------------------------- #

_LOCAL_HOSTS = ("127.0.0.1", "localhost")


def validate_navigate(url: str, *, allowed_origins: Iterable[str]) -> str:
    """校验后端移交的页面地址；返回规范化后的 URL。

    规则（冻结）：仅 http、仅本机回环、端口必须显式且在后端登记集合内、
    禁止 userinfo、禁止查询/片段夹带其他 origin 的跳转意图。
    """
    if not isinstance(url, str) or not url.strip():
        raise DesktopProtocolError("bad_url", "页面地址为空")
    parts = urlsplit(url.strip())
    if parts.scheme != "http":
        raise DesktopProtocolError("bad_scheme", "仅允许 http 本机地址")
    if parts.username or parts.password:
        raise DesktopProtocolError("userinfo_forbidden", "地址不得含凭据")
    if parts.hostname not in _LOCAL_HOSTS:
        raise DesktopProtocolError("foreign_host", "仅允许本机回环地址")
    if parts.port is None:
        raise DesktopProtocolError("port_required", "地址必须显式端口")
    origin = f"http://{parts.hostname}:{parts.port}"
    allowed = {o.rstrip("/") for o in allowed_origins}
    if origin not in allowed:
        raise DesktopProtocolError("origin_not_registered",
                                   "该来源未经后端登记")
    path = parts.path or "/"
    return origin + path


def _origin_of(url: str) -> str | None:
    """从 URL 提取 http 本机 origin（仅用于后端登记；非法返回 None）。"""
    try:
        parts = urlsplit(str(url).strip())
    except (ValueError, AttributeError):
        return None
    if parts.scheme != "http" or parts.hostname not in _LOCAL_HOSTS:
        return None
    if parts.port is None or parts.username or parts.password:
        return None
    return f"http://{parts.hostname}:{parts.port}"


def is_external_help_link(url: str) -> bool:
    """外部帮助链接：仅 https 且非本机 —— 只能在用户显式点击后交系统浏览器。"""
    if not isinstance(url, str) or not url.strip():
        return False
    parts = urlsplit(url.strip())
    return parts.scheme == "https" and parts.hostname not in _LOCAL_HOSTS


# --------------------------------------------------------------------------- #
# 握手状态机
# --------------------------------------------------------------------------- #

STARTING = "starting"
READY_HTTP = "ready_http"
FAILED = "failed"
STOPPING = "stopping"
STOPPED = "stopped"


@dataclass
class Handshake:
    """后端握手状态；`ready` 仅由事件驱动，绝不按等待时长推断。"""

    state: str = STARTING
    failure_code: str | None = None
    navigate: dict | None = None
    exit_code: int | None = None
    incomplete: list[str] = field(default_factory=list)
    allowed_origins: set[str] = field(default_factory=set)
    events: list[str] = field(default_factory=list)

    @property
    def ready_http(self) -> bool:
        """HTTP 入口就绪 ≠ 相机/模型就绪。"""
        return self.state == READY_HTTP

    def feed(self, line: str) -> dict:
        payload = parse_line(line)
        event = payload.get("event")
        if event is None:
            raise DesktopProtocolError("not_an_event", "预期后端事件行")
        self.events.append(event)
        if event == "starting":
            if self.state not in (STARTING,):
                raise DesktopProtocolError("bad_transition", "starting 顺序错误")
        elif event == "navigate":
            page = payload.get("page")
            if page not in PAGES:
                raise DesktopProtocolError("bad_page", f"未定义页面：{page}")
            raw = payload.get("url", "")
            # 后端 navigate 即**来源登记**（信任通道）；本机性/端口/凭据仍严格校验，
            # 页面自身发起的跳转依旧被外壳白名单拦下。
            candidate = _origin_of(raw)
            allowed = set(self.allowed_origins)
            if candidate:
                allowed.add(candidate)
            url = validate_navigate(raw, allowed_origins=allowed)
            self.allowed_origins.add(candidate)
            self.navigate = {"page": page, "url": url}
        elif event == "ready":
            origin = payload.get("origin")
            if not isinstance(origin, str) or not origin:
                raise DesktopProtocolError("bad_origin", "ready 必须带 origin")
            self.allowed_origins.add(origin.rstrip("/"))
            self.state = READY_HTTP
        elif event == "stopping":
            self.state = STOPPING
        elif event == "stopped":
            code = payload.get("exit_code")
            if isinstance(code, bool) or not isinstance(code, int):
                raise DesktopProtocolError("bad_exit_code",
                                           "stopped 必须带整数 exit_code")
            if "incomplete" not in payload:
                raise DesktopProtocolError("bad_incomplete",
                                           "stopped 必须带 incomplete 数组")
            incomplete = payload["incomplete"]
            if not isinstance(incomplete, list) or any(
                    not isinstance(x, str) or not x.strip()
                    for x in incomplete):
                # 非法结构不得静默当 []，也不得据此确认正常停止
                raise DesktopProtocolError(
                    "bad_incomplete", "incomplete 必须是字符串数组（成员非空）")
            self.exit_code = code
            self.incomplete = list(incomplete)
            self.state = STOPPED
        elif event == "failed":
            code = payload.get("code")
            if not isinstance(code, str) or not code:
                raise DesktopProtocolError("bad_failure_code", "failed 必须带固定 code")
            self.failure_code = code
            self.state = FAILED
        return payload


# --------------------------------------------------------------------------- #
# 停止握手（不强杀）
# --------------------------------------------------------------------------- #

STOP_PENDING = "pending"
STOP_CONFIRMED = "confirmed"
STOP_TIMED_OUT = "timed_out"
STOP_INCOMPLETE = "incomplete_finalization"
STOP_ALIVE = "stopped_but_alive"
STOP_ABNORMAL = "abnormal_exit"


@dataclass
class StopController:
    """正常停止请求与确认；超时保持"未停止"，不提供强杀路径。"""

    timeout_s: float = 20.0
    requested_at: float | None = None
    state: str = STOP_PENDING
    exit_code: int | None = None

    def request_stop(self, now: float) -> str:
        self.requested_at = now
        self.state = STOP_PENDING
        return stop_request_line()

    def on_eof(self, now: float) -> str:
        """EOF 视为正常停止请求（冻结）。"""
        return self.request_stop(now)

    def on_stopped(self, exit_code: int) -> str:
        self.exit_code = exit_code
        self.state = STOP_CONFIRMED
        return self.state

    def poll(self, now: float) -> str:
        if self.state == STOP_CONFIRMED:
            return self.state
        if self.requested_at is not None and \
                now - self.requested_at > self.timeout_s:
            self.state = STOP_TIMED_OUT
        return self.state

    @property
    def must_keep_window(self) -> bool:
        return self.state != STOP_CONFIRMED

    def user_message(self) -> str:
        if self.state == STOP_CONFIRMED:
            return f"后台已正常停止（退出码 {self.exit_code}）"
        if self.state == STOP_TIMED_OUT:
            return "后台尚未确认停止，请稍候或稍后重试；未强制结束进程。"
        return "正在停止后台…"


# --------------------------------------------------------------------------- #
# 单实例 IPC 与身份
# --------------------------------------------------------------------------- #

IPC_PREFIX = "SemanticCamera.Desktop"


def ipc_channel_name(install_dir: str | os.PathLike | None = None,
                     user: str | None = None) -> str:
    """当前用户限定的 IPC 通道名（同用户同安装根唯一）。"""
    who = user or getpass.getuser()
    root = str(install_dir or DEFAULT_INSTALL_DIR).lower()
    digest = hashlib.sha256(root.encode("utf-8")).hexdigest()[:12]
    return f"{IPC_PREFIX}.{who}.{digest}"


def ipc_identity_ok(requester_user: str, current_user: str | None = None) -> bool:
    """唤起请求必须来自当前用户；跨用户/未知一律拒绝。"""
    if not isinstance(requester_user, str) or not requester_user:
        return False
    return requester_user == (current_user or getpass.getuser())


# --------------------------------------------------------------------------- #
# 安装/数据路径与版本
# --------------------------------------------------------------------------- #

def user_entry_path(install_dir: str | os.PathLike | None = None) -> Path:
    return Path(install_dir or DEFAULT_INSTALL_DIR) / USER_ENTRY_EXE


def backend_path(install_dir: str | os.PathLike | None = None) -> Path:
    return Path(install_dir or DEFAULT_INSTALL_DIR) / BACKEND_RELATIVE


def data_root(local_appdata: str | os.PathLike | None = None) -> Path:
    """用户数据根：沿用现有根，不新建第二套。"""
    base = Path(local_appdata) if local_appdata else \
        Path(os.environ.get("LOCALAPPDATA", ""))
    return base / DATA_ROOT_RELATIVE


def project_version(pyproject_path: str | os.PathLike) -> str:
    """版本唯一来源：pyproject.toml 的 project.version（构建期显式传入）。"""
    text = Path(pyproject_path).read_text(encoding="utf-8")
    match = _VERSION_RE.search(text)
    if not match:
        raise DesktopProtocolError("version_missing",
                                   "pyproject.toml 未声明 project.version")
    return match.group(1)


REQUIRED_RUNTIME_COMPONENTS: Sequence[Mapping[str, str]] = (
    {"id": "windows_x64", "note": "Windows x64"},
    {"id": "dotnet_desktop_runtime",
     "note": ".NET 8 Desktop Runtime（self-contained 时不需另装，不假定）"},
    {"id": "webview2_runtime", "note": "WebView2 Evergreen Runtime"},
    {"id": "webview2_sdk", "note": "Microsoft.Web.WebView2 开发包（编译期）"},
    {"id": "python_frozen_deps", "note": "后端冻结基础依赖（构建期打入后端）"},
)


# --------------------------------------------------------------------------- #
# 后端监督器（壳侧）：真实子进程 + JSONL 协议 + 正常停止握手
# --------------------------------------------------------------------------- #

import subprocess  # noqa: E402
import threading  # noqa: E402
import time as _time  # noqa: E402


def backend_argv(backend_exe: str | os.PathLike,
                 extra: Sequence[str] = ()) -> list[str]:
    """后端启动参数（冻结：内部 exe，参数由壳固定，不给页面可控项）。"""
    return [str(backend_exe), *extra]


def _read_bounded_lines(stream, limit: int = MAX_LINE_BYTES):
    """按 UTF-8 字节有界地产生 (line, truncated)。

    - 增量解码 + `read1`（返回**立即可用**的数据，不因等满 n 个字符而阻塞）；
    - 超过 limit 的行：不继续累积，丢弃到行尾，产出 ("", True)；
    - EOF 时的超长残行同样产出 truncated=True（不静默接受）。
    """
    import codecs
    raw = getattr(stream, "buffer", None)
    if raw is None:
        raw = stream
    reader = getattr(raw, "read1", None) or getattr(raw, "read", None)
    if reader is None:                      # 兜底：可迭代流（逐行）
        for item in stream:
            text = item if isinstance(item, str) else str(item)
            if len(text.encode("utf-8")) > limit:
                yield "", True
            else:
                yield text.rstrip("\n"), False
        return
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    buffer = ""
    overlong = False
    while True:
        chunk = reader(4096)
        if not chunk:
            break
        if isinstance(chunk, bytes):
            chunk = decoder.decode(chunk)
        buffer += chunk
        while "\n" in buffer:
            head, buffer = buffer.split("\n", 1)
            if overlong or len(head.encode("utf-8")) > limit:
                overlong = False
                yield "", True
            else:
                yield head.rstrip("\r"), False
        if not overlong and len(buffer.encode("utf-8")) > limit:
            overlong = True
            buffer = ""
    tail = decoder.decode(b"", final=True)
    if tail:
        buffer += tail
    if overlong or len(buffer.encode("utf-8")) > limit:
        yield "", True
    elif buffer:
        yield buffer.rstrip("\r"), False


def _extract_desktop_port(args: Sequence[str],
                          default: int) -> tuple[int, list[str]]:
    """Consume one --port N/--port=N; reject repeats and malformed values."""
    occurrences: list[str] = []
    remaining: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--port":
            if index + 1 >= len(args) or args[index + 1].startswith("--"):
                raise ValueError("port value missing")
            occurrences.append(args[index + 1])
            index += 2
            continue
        if arg.startswith("--port="):
            occurrences.append(arg.split("=", 1)[1])
            index += 1
            continue
        remaining.append(arg)
        index += 1
    if len(occurrences) > 1:
        raise ValueError("port repeated")
    if not occurrences:
        return default, remaining
    try:
        return int(occurrences[0]), remaining
    except (TypeError, ValueError):
        raise ValueError("port invalid") from None


class BackendSupervisor:
    """以真实子进程运行后端；协议外输出进诊断，绝不当协议或就绪证据。

    **不提供强杀接口**：无法正常停止时如实报告"未停止"。
    """

    def __init__(self, argv: Sequence[str], *,
                 handshake_timeout_s: float = 30.0,
                 stop_timeout_s: float = 20.0,
                 popen_factory=subprocess.Popen, env=None) -> None:
        self.argv = list(argv)
        # 协议流按 UTF-8 解码；env 允许调用方（测试/诊断）显式要求子进程 UTF-8 输出。
        self._env = env
        self.handshake = Handshake()
        self.stop = StopController(timeout_s=stop_timeout_s)
        self.handshake_timeout_s = handshake_timeout_s
        self.diagnostics: list[str] = []
        self.protocol_errors: list[str] = []
        self._popen_factory = popen_factory
        self._proc = None
        self._reader: threading.Thread | None = None
        self._lock = threading.Lock()

    # ---- 生命周期 ----
    def start(self) -> None:
        if self._proc is not None:
            raise DesktopProtocolError("already_started", "后端已启动")
        self._proc = self._popen_factory(
            self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8",
            errors="replace", bufsize=1, env=self._env)
        self._reader = threading.Thread(target=self._pump, name="desktop-reader",
                                        daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        """有界读取（按 UTF-8 字节）：超长行不读完即判错，EOF 截断同样记错。"""
        stream = self._proc.stdout
        if stream is None:
            return
        pending = ""
        for line_text, truncated in _read_bounded_lines(stream):
            if truncated:
                with self._lock:
                    self.protocol_errors.append("line_too_long")
                continue
            line = line_text
            if not line.strip():
                continue
            try:
                self.handshake.feed(line)
            except DesktopProtocolError as exc:
                with self._lock:
                    if line.lstrip().startswith("{"):
                        self.protocol_errors.append(exc.code)
                    else:
                        self.diagnostics.append(line)
            pending = ""
        del pending

    def wait_ready(self, timeout_s: float | None = None) -> bool:
        """等真实 `ready` 事件；超时返回 False（绝不按等待时长伪造就绪）。"""
        limit = self.handshake_timeout_s if timeout_s is None else timeout_s
        deadline = _time.monotonic() + limit
        while _time.monotonic() < deadline:
            if self.handshake.ready_http or self.handshake.state == FAILED:
                return self.handshake.ready_http
            if self._proc is not None and self._proc.poll() is not None:
                return False
            _time.sleep(0.02)
        return False

    # ---- 停止（只有正常通道）----
    def request_stop(self) -> None:
        self.stop.request_stop(now=_time.monotonic())
        self._write(stop_request_line())

    def close_stdin_eof(self) -> None:
        """EOF 视为正常停止请求（冻结）。"""
        self.stop.on_eof(now=_time.monotonic())
        if self._proc is not None and self._proc.stdin is not None:
            try:
                self._proc.stdin.close()
            except OSError:
                pass

    def _write(self, line: str) -> None:
        if self._proc is None or self._proc.stdin is None:
            raise DesktopProtocolError("not_started", "后端未启动")
        self._proc.stdin.write(line + "\n")
        self._proc.stdin.flush()

    def poll_stop(self) -> str:
        """正常停止判据（与 C# 侧一致）：**握手成功 + 无未完成项 +
        子进程实际退出 + 实际退出码成功** 才算 confirmed。

        只见握手不得宣称停止；收尾不完整/仍存活/异常退出分别如实返回。
        """
        state = self.stop.poll(now=_time.monotonic())
        hs = self.handshake
        if hs.state == STOPPED:
            code = hs.exit_code
            exited = self.backend_exited()
            if hs.incomplete:
                state = STOP_INCOMPLETE
            elif code not in (0, None):
                state = STOP_ABNORMAL
            elif not exited:
                if state == STOP_TIMED_OUT:
                    state = STOP_ALIVE
            elif code == 0:
                state = self.stop.on_stopped(0)
            else:
                state = STOP_ABNORMAL
        return state

    def backend_exited(self) -> bool:
        return self._proc is not None and self._proc.poll() is not None

    def join(self, timeout_s: float = 5.0) -> bool:
        if self._reader is not None:
            self._reader.join(timeout=timeout_s)
        return not (self._reader is not None and self._reader.is_alive())


# --------------------------------------------------------------------------- #
# 桌面后端桥：把 nvr 的事实性生命周期事件转换为壳协议事件；stdin 正常停止
# --------------------------------------------------------------------------- #

_UNSET = object()      # stdin 未指定（生产：用真实 stdin）


class DesktopBackendBridge:
    """运行于**后端进程内**：`lifecycle_hook` → stdout JSONL；stdin → stop_event。

    - 只转发事实事件，未知事件不猜、不发明；
    - 不发异常原文/配置/命令行；不打印凭据或带凭据 URL；
    - 浏览器打开不由后端负责：桌面模式下 `navigate` 只告知外壳地址。
    """

    def __init__(self, stop_event, *, host: str, port: int, page: str,
                 write=None) -> None:
        if page not in PAGES:
            raise DesktopProtocolError("bad_page", f"未定义页面：{page}")
        self.stop_event = stop_event
        self.host = host
        self.port = port
        self.page = page
        self._write = write or self._stdout_write
        self.emitted: list[str] = []
        self.protocol_errors: list[str] = []
        self._origin = None

    @staticmethod
    def _stdout_write(line: str) -> None:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    def _emit(self, event: str, **fields) -> None:
        line = encode_event(event, **fields)
        self.emitted.append(event)
        self._write(line)

    def emit_navigate(self, page: str, url: str) -> None:
        """把页面地址交给外壳（首用向导/工作台共用；不打开浏览器）。"""
        if page not in PAGES:
            raise DesktopProtocolError("bad_page", f"未定义页面：{page}")
        self._emit("navigate", page=page, url=url)

    # ---- nvr lifecycle_hook ----
    def hook(self, event: str, **fields) -> None:
        if event == "http_ready":
            host = fields.get("host", self.host)
            port = fields.get("port", self.port)
            self._origin = f"http://{host}:{port}"
            self._emit("navigate", page=self.page, url=self._origin + "/")
            self._emit("ready", origin=self._origin)
        elif event == "stopping":
            self._emit("stopping")
        elif event == "stopped":
            self._emit("stopped", exit_code=int(fields.get("exit_code", 0)),
                       incomplete=list(fields.get("incomplete", [])))
        elif event == "runtime_state":
            # 只转发可核实字段；模型就绪无来源则保持 unknown，不冒充
            self._emit("state",
                       cameras=int(fields.get("cameras", 0)),
                       camera_health_source=str(
                           fields.get("camera_health_source", "unavailable")),
                       models=str(fields.get("models", "unknown")))
        # 其余（含非协议事件）一律忽略：不得发明状态

    # ---- 壳 → 后端 ----
    def handle_command_line(self, line: str) -> bool:
        """返回 True 表示收到停止请求（含 EOF 由调用方传空串）。"""
        if line == "":
            self.stop_event.set()
            return True
        payload = parse_line(line)
        if payload.get("command") == "stop":
            self.stop_event.set()
            return True
        return False

    def watch_stdin(self, stream=None) -> "threading.Thread":
        import threading as _th
        src = stream if stream is not None else sys.stdin

        def _loop():
            try:
                for text, truncated in _read_bounded_lines(src):
                    if truncated:
                        self.protocol_errors.append("line_too_long")
                        continue
                    if self.handle_command_line(text.strip()):
                        return
            except (OSError, ValueError):
                # stdin 不可读（关闭/被重定向）：等同 EOF —— 正常停止请求
                pass
            self.handle_command_line("")     # EOF 视为正常停止请求

        thread = _th.Thread(target=_loop, name="desktop-command", daemon=True)
        thread.start()
        return thread


def desktop_main(argv, *, edition=None, runtime_main=None,
                 setup_runner=None, stdin=_UNSET) -> int:
    """桌面模式后端入口：不发浏览器，走 stdio 协议与外部 stop_event。"""
    import threading

    from . import nvr as _nvr
    from .editions import WIN11_WORKSTATION, get_edition
    from .win11_launcher import (EXIT_HOST_NOT_ALLOWED, HostArgsNotAllowed,
                                 HostNotAllowed, extract_host_args)

    run = runtime_main or _nvr.main
    stop_event = threading.Event()
    try:
        endpoint_args = list(argv)
        default_edition = get_edition(edition or "win11")
        if not any(
            arg == "--host" or arg.startswith("--host=")
            for arg in endpoint_args
        ):
            endpoint_args = [
                "--host", default_edition.default_host, *endpoint_args
            ]
        host, endpoint_rest = extract_host_args(endpoint_args)
        port, endpoint_rest = _extract_desktop_port(
            endpoint_rest, default_edition.default_port
        )
    except (HostArgsNotAllowed, HostNotAllowed):
        return EXIT_HOST_NOT_ALLOWED
    except ValueError:
        return 2
    page = PAGE_WORKBENCH
    rest = []
    recovery_requested = False
    skip = set()
    for index, arg in enumerate(list(endpoint_rest)):
        if index in skip:
            continue
        if arg == "--recover-config":
            recovery_requested = True
            continue
        if arg == "--port" and index + 1 < len(endpoint_rest):
            skip.add(index + 1); continue
        if arg.startswith("--port="):
            continue
        if arg == "--host" and index + 1 < len(endpoint_rest):
            skip.add(index + 1); continue
        if arg.startswith("--host="):
            continue
        if arg.startswith("--page="):
            page = arg.split("=", 1)[1]; continue
        rest.append(arg)
    bridge = DesktopBackendBridge(stop_event, host=host, port=port, page=page)
    if stdin is _UNSET:
        bridge.watch_stdin()                 # 生产：真实 stdin（stop/EOF 即停止请求）
    elif stdin is not None:
        bridge.watch_stdin(stream=stdin)     # 注入流（测试/诊断）

    # 首用向导（桌面模式）：地址交外壳；不开浏览器；未完成即失败，不假装成功。
    default_config = WIN11_WORKSTATION.default_config()
    config_path, skip = default_config, set()
    for index, arg in enumerate(list(rest)):
        if index in skip:
            continue
        if arg == "--config" and index + 1 < len(rest):
            config_path = rest[index + 1]
        elif arg.startswith("--config="):
            config_path = arg.split("=", 1)[1]
    try:
        need_setup = recovery_requested or not Path(config_path).is_file()
    except OSError:
        need_setup = True
    if need_setup:
        if setup_runner is None:
            from .win11_setup import run_first_use_setup as setup_runner
        try:
            kwargs = {}
            try:
                import inspect as _inspect
                parameters = _inspect.signature(setup_runner).parameters
                if recovery_requested:
                    if "recovery_source" not in parameters:
                        raise ValueError("recovery_not_supported")
                    kwargs["recovery_source"] = config_path
                if "stop_event" in parameters:
                    kwargs["stop_event"] = stop_event
                if "default_model_path" in parameters:
                    from .win11_launcher import bundled_model_path
                    default_model = bundled_model_path()
                    if default_model is None:
                        # 嵌套后端的_MEIPASS位于_internal；仅正式安装根的
                        # 标准models锚点补查，不搜索任意父目录或改变cwd。
                        from .config import _frozen_install_root
                        try:
                            candidate = _frozen_install_root() / "models" / "person-detector.onnx"
                            if candidate.is_file():
                                default_model = str(candidate)
                        except ValueError:
                            pass  # 普通源码/未打包安装：保持无预填的诚实行为。
                    kwargs["default_model_path"] = default_model
            except (TypeError, ValueError):
                kwargs = {}
            if recovery_requested and "recovery_source" not in kwargs:
                raise ValueError("recovery_not_supported")
            configured = setup_runner(
                config_path,
                browser_opener=lambda url: bridge.emit_navigate(PAGE_SETUP, url),
                **kwargs)
            if recovery_requested and isinstance(configured, bool):
                raise ValueError("setup_result_invalid")
            if not isinstance(configured, bool):
                outcome = configured
                configured = getattr(outcome, "configured", None) is True
                if configured:
                    replacement = Path(getattr(outcome, "config_path", ""))
                    if not replacement.is_absolute() or not replacement.is_file():
                        raise ValueError("setup_result_invalid")
                    if recovery_requested:
                        try:
                            same_original = replacement.samefile(config_path)
                        except OSError:
                            raise ValueError("setup_result_invalid") from None
                        if same_original:
                            raise ValueError("setup_result_invalid")
                    config_path = str(replacement)
                    clean_rest = []
                    skip_value = False
                    for value in rest:
                        if skip_value:
                            skip_value = False
                            continue
                        if value == "--config":
                            skip_value = True
                        elif not value.startswith("--config="):
                            clean_rest.append(value)
                    rest = clean_rest
        except BaseException:
            try:
                bridge._emit("failed", code=FAIL_BACKEND_SPAWN)
            except Exception:
                pass
            raise
        if not configured:
            if stop_event.is_set():
                # 桌面 stop/EOF：向导未保存即取消 → 按正常关闭收尾（不等待用户保存）
                bridge._emit("stopping")
                bridge._emit("stopped", exit_code=0, incomplete=[])
                return 0
            bridge._emit("failed", code="setup_not_completed")
            return 1
    run_argv = list(rest)
    has_config_arg = any(
        arg == "--config" or arg.startswith("--config=")
        for arg in run_argv
    )
    if not has_config_arg:
        run_argv.extend(("--config", config_path))
    run_argv.extend(("--host", host, "--port", str(port)))
    try:
        return run(run_argv, edition=edition, stop_event=stop_event,
                   lifecycle_hook=bridge.hook)
    except BaseException:
        # 固定失败码；不外发异常原文
        try:
            bridge._emit("failed", code=FAIL_BACKEND_EXIT)
        except Exception:
            pass
        raise


# --------------------------------------------------------------------------- #
# 单实例唤起（当前用户限定；Windows 命名对象，非 Windows 平台明确不可用）
# --------------------------------------------------------------------------- #

ACTIVATE_SUFFIX = "activate"
_ERROR_ALREADY_EXISTS = 183


class SingleInstanceGuard:
    """第二次启动通过命名事件请求原窗口唤起；**不重复启动后端**。

    仅在 Windows 可用（命名 mutex/event）。非 Windows 明确报不可用，
    不静默降级成"每次都能启动"。
    """

    def __init__(self, name: str | None = None, *,
                 user: str | None = None,
                 install_dir: str | os.PathLike | None = None) -> None:
        self.name = name or ipc_channel_name(install_dir, user)
        self.event_name = f"{self.name}.{ACTIVATE_SUFFIX}"
        self.is_primary = False
        self.available = sys.platform == "win32"
        self._mutex = None
        self._event = None

    # ---- 主实例 ----
    def acquire(self) -> bool:
        """True = 本进程是主实例；False = 已有实例在运行。"""
        if not self.available:
            raise DesktopProtocolError("ipc_unavailable",
                                       "单实例通道仅 Windows 可用")
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL,
                                          wintypes.LPCWSTR]
        self._mutex = kernel32.CreateMutexW(None, False, self.name)
        if not self._mutex:
            raise DesktopProtocolError("ipc_unavailable", "无法创建单实例互斥体")
        already = ctypes.get_last_error() == _ERROR_ALREADY_EXISTS
        self.is_primary = not already
        if self.is_primary:
            kernel32.CreateEventW.restype = wintypes.HANDLE
            kernel32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL,
                                              wintypes.BOOL, wintypes.LPCWSTR]
            self._event = kernel32.CreateEventW(None, False, False,
                                                self.event_name)
            if not self._event:
                raise DesktopProtocolError("ipc_unavailable",
                                           "无法创建唤起事件")
        return self.is_primary

    # ---- 第二实例 ----
    def request_activate(self) -> bool:
        """请求主实例唤起原窗口；主实例不在则 False（不新开后台）。"""
        if not self.available:
            raise DesktopProtocolError("ipc_unavailable",
                                       "单实例通道仅 Windows 可用")
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenEventW.restype = wintypes.HANDLE
        kernel32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL,
                                        wintypes.LPCWSTR]
        EVENT_MODIFY_STATE = 0x0002
        handle = kernel32.OpenEventW(EVENT_MODIFY_STATE, False,
                                     self.event_name)
        if not handle:
            return False
        try:
            return bool(kernel32.SetEvent(handle))
        finally:
            kernel32.CloseHandle(handle)

    # ---- 主实例轮询 ----
    def wait_activate(self, timeout_ms: int = 0) -> bool:
        if self._event is None:
            return False
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        return kernel32.WaitForSingleObject(self._event, timeout_ms) == 0

    def close(self) -> None:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        for handle in (self._event, self._mutex):
            if handle:
                kernel32.CloseHandle(handle)
        self._event = self._mutex = None
        self.is_primary = False


# --------------------------------------------------------------------------- #
# 关闭询问（三选一；未选择前不改变运行状态）
# --------------------------------------------------------------------------- #

CLOSE_KEEP_BACKGROUND = "keep_background"
CLOSE_STOP_AND_EXIT = "stop_and_exit"
CLOSE_CANCEL = "cancel"
CLOSE_OPTIONS = (CLOSE_KEEP_BACKGROUND, CLOSE_STOP_AND_EXIT, CLOSE_CANCEL)
CLOSE_LABELS = {
    CLOSE_KEEP_BACKGROUND: "继续后台值守",
    CLOSE_STOP_AND_EXIT: "停止值守并退出",
    CLOSE_CANCEL: "取消",
}


class ClosePrompt:
    """关闭窗口时的显式决策；**未选择前不偷偷改变运行状态**。"""

    def __init__(self) -> None:
        self.choice: str | None = None

    @staticmethod
    def options() -> tuple[str, ...]:
        return CLOSE_OPTIONS

    @staticmethod
    def label(choice: str) -> str:
        return CLOSE_LABELS[choice]

    def decide(self, choice: str) -> str:
        if choice not in CLOSE_OPTIONS:
            raise DesktopProtocolError("bad_close_choice",
                                       f"未定义的关闭选项：{choice}")
        self.choice = choice
        return choice

    # ---- 决策效果（壳据此执行；不自行推断） ----
    @property
    def undecided(self) -> bool:
        return self.choice is None

    @property
    def hide_window(self) -> bool:
        return self.choice == CLOSE_KEEP_BACKGROUND

    @property
    def request_backend_stop(self) -> bool:
        return self.choice == CLOSE_STOP_AND_EXIT

    @property
    def backend_keeps_running(self) -> bool:
        """取消/继续值守都不得停止后端；未决策时同样保持原状。"""
        return self.choice != CLOSE_STOP_AND_EXIT
