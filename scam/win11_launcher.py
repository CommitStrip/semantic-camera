"""win11_launcher.py —— Win11 双击入口（发行包唯一用户入口）。

职责边界（不做值守逻辑本身，值守仍由 `scam.win11` 执行）：
- 回环边界：工作台只允许绑定本机回环地址；任何其它 `--host`（0.0.0.0、局域网 IP、
  主机名…）在打开数据库/相机/工作台**之前**以固定中文提示和非零退出码拒绝；
- 单实例：命名互斥体 fail-closed——拿不到保护就拒绝启动，绝不放行第二个实例；
- 端口预检：工作台端口被占用时给固定中文原因与可操作动作，绝不出现"启动成功"假象；
- 浏览器：仅在本机回环页面真正可连之后才打开（轮询端口，不是盲等）；
- ffmpeg 缺失：明确提示"录像/片段导出不可用"，但不阻断预览与管理员规则告警；
- 错误出口：只给**固定错误码 + 阶段 + 下一步动作**，异常原文（可能夹带 RTSP 凭据）
  绝不进入控制台、浏览器提示、报告或默认日志。

安全边界：只监听 127.0.0.1；日志不打印 RTSP 凭据或完整敏感 URL；不默认上传任何内容。
"""

import argparse
import os
import socket
import sys
import threading
import time

from .editions import WIN11_WORKSTATION
from .platform import find_ffmpeg, fix_console_encoding, open_browser, safe_print

MUTEX_NAME = "Local\\semantic-camera-win11-single-instance"
BROWSER_WAIT_S = 20.0

# 首版只接受这一个字面量。主机名（含 localhost）与 IPv6 字面量（::1）一并拒绝：
# 前者解析结果可被 hosts/DNS 改写；后者的端口预检、工作台绑定、浏览器打开与重启
# 验收尚未全链路验证——宁可不支持，也不保留"校验放行、随后崩溃"的中间状态。
LOOPBACK_HOSTS = ("127.0.0.1",)

# 退出码（固定，便于排查与脚本判断）
EXIT_OK = 0
EXIT_STARTUP_FAILED = 1
EXIT_PORT_IN_USE = 1
EXIT_SECOND_INSTANCE = 3
EXIT_MUTEX_UNAVAILABLE = 4
EXIT_HOST_NOT_ALLOWED = 5
EXIT_WIZARD_FAILED = 6

# 固定错误码 → (阶段, 下一步动作)。异常原文一律不出现在这里。
ERROR_CODES = {
    "E-W11-001": ("值守启动失败",
                  "请重试；仍失败时把本错误码与用户数据目录下的日志交给维护者"),
    "E-W11-002": ("首次接入向导启动失败", "请确认本机 127.0.0.1 端口可绑定后重新双击启动"),
    "E-W11-003": ("配置保存失败", "请重试；或改用本机已有模型 / 勾选“仅预览、不告警”"),
}

HOST_REJECT_HINT = (
    "拒绝启动：工作台只允许绑定 127.0.0.1。局域网 IP、0.0.0.0、主机名、"
    "IPv6（::1 暂不支持）等取值一律拒绝，也不会打开数据库或相机。"
    "请去掉 --host，或显式改为 --host 127.0.0.1。")
HOST_DUPLICATE_HINT = (
    "拒绝启动：--host 只能出现一次，且不能混用 --host X 与 --host=X 两种写法。"
    "重复或混用会让入口校验的地址与运行时实际采用的地址不一致，因此直接拒绝。"
    "请只保留一处，或干脆去掉 --host（默认即 127.0.0.1）。")
MUTEX_UNAVAILABLE_HINT = (
    "拒绝启动：无法取得单实例保护（命名互斥体不可用）。"
    "没有单实例保护时两个实例会争用同一个数据库，因此不放行。"
    "请检查安全软件是否阻止命名对象，或重启后再试；不会打开数据库或相机。")


class HostNotAllowed(ValueError):
    """非回环 / 非法 --host：入口层直接拒绝（不携带原始取值，避免进入日志）。"""

    def __init__(self, stage="entry"):
        super().__init__("host 不是允许的回环地址")
        self.stage = stage


class HostRepeated(HostNotAllowed):
    """--host 重复或混用写法：拒绝（否则入口校验与运行时取值不一致）。"""

    def __init__(self):
        super().__init__(stage="repeated")


class HostArgsNotAllowed(HostNotAllowed):
    """重复或混用 --host：拒绝。"""

    def __init__(self):
        super().__init__(stage="repeated")


def extract_host_args(args_list):
    """扫描 `--host X` 与 `--host=X`：返回 (host, 规范化后的参数列表)。

    必须恰好出现一次——重复或混用会让"入口校验的值"与"运行时采用的最后一个值"
    不一致（入口看第一个、argparse 取最后一个，等于绕过回环校验），因此直接拒绝。
    规范化后的参数列表里只保留唯一一处 `--host <已校验值>`，保证两处用同一个值。
    """
    occurrences = []
    remaining = []
    index = 0
    while index < len(args_list):
        arg = args_list[index]
        if arg == "--host":
            if index + 1 >= len(args_list) or args_list[index + 1].startswith("--"):
                raise HostNotAllowed(stage="missing-value")
            occurrences.append(args_list[index + 1])
            index += 2
            continue
        if arg.startswith("--host="):
            occurrences.append(arg.split("=", 1)[1])
            index += 1
            continue
        remaining.append(arg)
        index += 1
    if len(occurrences) > 1:
        raise HostArgsNotAllowed()
    if not occurrences:
        return WIN11_WORKSTATION.default_host, remaining
    host = assert_loopback_host(occurrences[0], stage="entry")
    return host, [*remaining, "--host", host]


def assert_loopback_host(host, *, stage="entry"):
    """只允许回环字面量；其它取值一律拒绝。返回规范化后的 host。"""
    if host not in LOOPBACK_HOSTS:
        raise HostNotAllowed(stage=stage)
    return host


def release_single_instance(handle):
    """显式释放互斥体句柄（正常退出用；进程消亡时系统也会回收）。"""
    if handle is None or sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    try:
        kernel32.CloseHandle(handle)
    except OSError:
        pass


def acquire_single_instance(name=MUTEX_NAME):
    """尝试占用命名互斥体，返回 (状态, 句柄)。

    状态取值：
    - ``"held"``：本进程持有保护（句柄需在退出时显式释放）；
    - ``"already_running"``：已有实例持有；
    - ``"unavailable"``：**拿不到保护**（创建失败）——调用方必须拒绝启动（fail-closed），
      绝不以"允许启动"处理；否则两个实例会争用同一个数据库。

    非 Windows 平台不启用（本入口只服务 Win11 发行包），返回 ``"held"``。
    """
    if sys.platform != "win32":
        return "held", None
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = (wintypes.LPCVOID, wintypes.BOOL,
                                      wintypes.LPCWSTR)
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    handle = kernel32.CreateMutexW(None, False, name)
    if not handle:
        return "unavailable", None
    ERROR_ALREADY_EXISTS = 183
    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        release_single_instance(handle)
        return "already_running", None
    return "held", handle


def port_in_use(host, port, timeout=0.6):
    """探测回环端口是否已被占用（只连本机回环，无凭据、无外部请求）。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, int(port))) == 0


def _open_browser_when_ready(url, host, port, *, opener=open_browser,
                             stop_event=None, wait_s=BROWSER_WAIT_S):
    """等回环页面真正可连再打开浏览器；超时则不打开（不谎报已打开）。"""
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        if stop_event is not None and stop_event.is_set():
            return False
        if port_in_use(host, port):
            opener(url)
            return True
        time.sleep(0.25)
    return False


def _pause_on_error(enabled):
    """双击启动的窗口在报错后不要瞬间消失（仅在真正的控制台里等待）。"""
    if not enabled or not sys.stdin or not sys.stdin.isatty():
        return
    try:
        input("按回车键关闭本窗口…")
    except (EOFError, KeyboardInterrupt):
        pass


def report_error(code, *, diagnostics_path=None):
    """按固定错误码报告：阶段 + 错误码 + 下一步动作，绝不回显异常原文。

    可选地把错误码追加到用户数据目录下的诊断文件，便于用户连同日志一起提供；
    写不进去也不影响报告本身（诊断不能反过来制造新故障）。
    """
    stage, action = ERROR_CODES.get(code, ("运行失败", "请重试并保留日志"))
    safe_print(f"[语义摄像头] {stage}（错误码 {code}）。{action}")
    if not diagnostics_path:
        return
    try:
        os.makedirs(os.path.dirname(diagnostics_path), exist_ok=True)
        with open(diagnostics_path, "a", encoding="utf-8") as handle:
            handle.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {code} {stage}\n")
    except OSError:
        pass


def bundled_model_path():
    """发行包随附模型的绝对路径；不存在则返回 None（绝不猜路径）。

    one-dir 布局：模型放在可执行文件同级的 models/ 下；源码运行时自然不存在。
    """
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(
        os.path.abspath(sys.executable))
    candidate = os.path.join(base, "models", "person-detector.onnx")
    return candidate if os.path.isfile(candidate) else None


def build_parser():
    parser = argparse.ArgumentParser(
        prog="语义摄像头",
        description="语义摄像头 Win11 值守工作站（双击即可运行）")
    parser.add_argument("--config", default=WIN11_WORKSTATION.default_config(),
                        help="场所配置文件路径（默认放在本机应用数据目录）")
    parser.add_argument("--db", default=None, help="数据库路径")
    parser.add_argument("--host", default=WIN11_WORKSTATION.default_host,
                        help="工作台监听地址：只允许 127.0.0.1（IPv6 暂不支持；"
                             "不接受重复或混用写法）")
    parser.add_argument("--port", type=int,
                        default=WIN11_WORKSTATION.default_port,
                        help="工作台端口（默认 8600）")
    parser.add_argument("--no-workbench", action="store_true",
                        help="不启动工作台（仅值守；发行包请勿使用）")
    parser.add_argument("--no-browser", action="store_true",
                        help="不自动打开浏览器")
    return parser


# 启动器独有的开关：只影响双击行为，绝不能转发给运行时（否则 argparse 报错退出）
LAUNCHER_ONLY_FLAGS = ("--no-browser",)


def _runtime_args(args_list):
    """剥离启动器独有的开关，其余原样转发给 `scam.win11`。"""
    return [arg for arg in args_list if arg not in LAUNCHER_ONLY_FLAGS]


def main(argv=None):
    fix_console_encoding()
    args_list = list(sys.argv[1:] if argv is None else argv)
    try:
        # parse_known_args：运行时自己的开关（例如 --no-slow）不在本解析器里，
        # 这里不做拒绝，交给下游解释。
        options, _unknown = build_parser().parse_known_args(args_list)
    except SystemExit as exc:                     # --help 等
        return int(exc.code or 0)

    # ① 回环边界：最先做，早于互斥体 / 端口 / 数据库 / 相机。
    # 同时规范化 --host，保证运行时采用的**就是**这里校验过的值。
    try:
        host, runtime_args = extract_host_args(args_list)
    except HostArgsNotAllowed:
        safe_print(f"[语义摄像头] {HOST_DUPLICATE_HINT}")
        _pause_on_error(True)
        return EXIT_HOST_NOT_ALLOWED
    except HostNotAllowed:
        safe_print(f"[语义摄像头] {HOST_REJECT_HINT}")
        _pause_on_error(True)
        return EXIT_HOST_NOT_ALLOWED
    options.host = host

    safe_print(f"[语义摄像头] {WIN11_WORKSTATION.display_name}")
    safe_print(f"[语义摄像头] 数据目录：{os.path.dirname(options.config)}"
               "（配置、数据库、证据与日志都写在这里，发行包目录保持只读即可）")

    # ② 单实例：拿不到保护就拒绝（fail-closed）
    state, handle = acquire_single_instance()
    if state == "already_running":
        safe_print("[语义摄像头] 已有一个实例在运行，本次不再启动。")
        safe_print(f"[语义摄像头] 请使用已打开的工作台页面："
                   f"http://{options.host}:{options.port}")
        safe_print("[语义摄像头] 重复启动会争用同一个数据库，因此被主动拒绝。")
        return EXIT_SECOND_INSTANCE
    if state == "unavailable":
        safe_print(f"[语义摄像头] {MUTEX_UNAVAILABLE_HINT}")
        _pause_on_error(True)
        return EXIT_MUTEX_UNAVAILABLE

    try:
        if not options.no_workbench and port_in_use(options.host, options.port):
            safe_print(f"[语义摄像头] 端口 {options.port} 已被占用，无法启动工作台。")
            safe_print("[语义摄像头] 请关闭占用该端口的程序，或用 --port 8601 "
                       "改用其它端口后重新双击启动。")
            safe_print("[语义摄像头] 未启动值守（不会有任何相机线程运行）。")
            _pause_on_error(True)
            return EXIT_PORT_IN_USE

        if find_ffmpeg() is None:
            safe_print("[语义摄像头] 录像/片段导出不可用：未找到 ffmpeg。")
            safe_print("[语义摄像头] 预览与管理员规则告警不受影响，录像保持关闭。")

        stop_event = threading.Event()
        if not options.no_workbench and not options.no_browser:
            url = f"http://{options.host}:{options.port}"
            threading.Thread(
                target=_open_browser_when_ready,
                args=(url, options.host, options.port),
                kwargs={"stop_event": stop_event}, daemon=True,
                name="open-workbench").start()

        from .win11 import main as win11_main
        try:
            return int(win11_main(_runtime_args(runtime_args)) or 0)
        except KeyboardInterrupt:
            safe_print("[语义摄像头] 已按用户请求停止。")
            return EXIT_OK
        except Exception:                          # noqa: BLE001
            # 异常原文可能夹带 RTSP 凭据或主机路径：只报固定错误码与下一步动作。
            report_error("E-W11-001",
                         diagnostics_path=os.path.join(
                             os.path.dirname(options.config),
                             "logs", "win11-errors.log"))
            _pause_on_error(True)
            return EXIT_STARTUP_FAILED
        finally:
            stop_event.set()
    finally:
        release_single_instance(handle)            # 正常退出显式释放，不留假锁


if __name__ == "__main__":
    sys.exit(main())
