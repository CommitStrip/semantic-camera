"""Win11 值守工作站版独立入口：python -m scam.win11。"""

import os
import sys

from .editions import WIN11_WORKSTATION, platform_error
from .nvr import main as run_runtime
from .win11_setup import run_first_use_setup


def _has_config_arg(argv):
    return any(arg == "--config" or arg.startswith("--config=")
               for arg in argv)


def _config_arg_value(argv, default):
    for index, arg in enumerate(argv):
        if arg.startswith("--config="):
            return arg.split("=", 1)[1]
        if arg == "--config" and index + 1 < len(argv):
            return argv[index + 1]
    return default


def main(argv=None):
    error = platform_error(WIN11_WORKSTATION)
    if error:
        print(f"[Win11] {error}")
        return 2
    args = list(sys.argv[1:] if argv is None else argv)
    if "--help" in args or "-h" in args:
        return run_runtime(args, edition=WIN11_WORKSTATION.key)

    default_config = WIN11_WORKSTATION.default_config()
    if not _has_config_arg(args):
        args = ["--config", default_config, *args]
    config_path = _config_arg_value(args, default_config)
    if not os.path.isfile(config_path):
        print("[Win11] 尚未配置摄像头，正在打开本机首次接入向导…")
        if not run_first_use_setup(config_path):
            print("[Win11] 未完成摄像头配置，值守未启动")
            return 1
    return run_runtime(args, edition=WIN11_WORKSTATION.key)


if __name__ == "__main__":
    sys.exit(main())
