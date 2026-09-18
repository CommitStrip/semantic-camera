"""platform.py —— Win11 / Linux 双平台适配层。

解决的平台差异：
- 控制台编码：Windows cmd 默认 GBK/CP936，中文/emoji 可能 UnicodeEncodeError
- 信号处理：Windows 无 SIGTERM/SIGHUP，用 threading.Event 替代
- 浏览器打开：webbrowser 模块跨平台
- 路径：全部 os.path（本仓已遵守）
"""

import os
import sys
import webbrowser


def is_windows():
    return sys.platform == "win32"


def fix_console_encoding():
    """Windows 控制台编码修复：确保 UTF-8 输出不崩。"""
    if is_windows():
        os.environ.setdefault("PYTHONIOENCODING", "utf-8")
        # Python 3.15 前 Windows 控制台默认非 UTF-8
        if hasattr(sys.stdout, "reconfigure"):
            try:
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def safe_print(*args, **kwargs):
    """编码安全的 print（Windows GBK 控制台不会因 emoji/中文崩）。"""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        safe_args = tuple(
            str(a).encode("ascii", errors="replace").decode("ascii")
            for a in args
        )
        print(*safe_args, **kwargs)


def open_browser(url):
    """跨平台打开浏览器。"""
    webbrowser.open(url)


def find_ffmpeg():
    """查找 ffmpeg 可执行文件路径；找不到返回 None。"""
    import shutil
    path = shutil.which("ffmpeg")
    return path


def app_data_dir(app_name="semantic-camera"):
    """获取应用数据目录（跨平台）。"""
    if is_windows():
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
        return os.path.join(base, app_name)
    return os.path.join(os.path.expanduser("~"), ".local", "share", app_name)


def default_data_root():
    """数据根目录默认值：Windows 用 %LOCALAPPDATA%（仓库目录可能不可写）；
    Linux 保持相对 cwd（systemd WorkingDirectory 控制落点，行为不变）。"""
    if is_windows():
        return app_data_dir()
    return "."
