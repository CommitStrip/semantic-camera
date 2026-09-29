"""Win11 值守工作站版独立入口：python -m scam.win11。"""

import os
import sys

from .editions import WIN11_WORKSTATION, platform_error
from .nvr import main as run_runtime
from .win11_launcher import (HostArgsNotAllowed, HostNotAllowed,
                             bundled_model_path, extract_host_args)
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

    # 回环边界（本产品入口层，先于数据库/相机/工作台）：Win11 工作台只在本机
    # 回环上监听，任何其它 --host 取值一律拒绝——不依赖 Linux 侧改造，也不引入
    # 鉴权系统。重复或混用写法同样拒绝：否则入口校验的值与运行时最终采用的
    # 最后一个值不一致，等于绕过校验。
    try:
        host, args = extract_host_args(args)
    except HostArgsNotAllowed:
        print("[Win11] 拒绝启动：--host 只能出现一次，且不能混用 --host X 与"
              " --host=X；请只保留一处或去掉该参数。")
        return 5
    except HostNotAllowed:
        print("[Win11] 拒绝启动：工作台只允许绑定 127.0.0.1；局域网 IP、"
              "0.0.0.0、主机名、IPv6（::1 暂不支持）等取值一律拒绝，"
              "也不会打开数据库或相机。")
        return 5

    default_config = WIN11_WORKSTATION.default_config()
    if not _has_config_arg(args):
        args = ["--config", default_config, *args]
    config_path = _config_arg_value(args, default_config)
    if not os.path.isfile(config_path):
        print("[Win11] 尚未配置摄像头，正在打开本机首次接入向导…")
        # 发行包随附模型时预填路径；用户仍可清空并显式选择"仅预览、不告警"。
        bundled = bundled_model_path()
        try:
            configured = run_first_use_setup(config_path,
                                             default_model_path=bundled)
        except Exception:                          # noqa: BLE001
            # 向导异常原文可能夹带路径或凭据：只报固定错误码。
            from .win11_launcher import report_error
            report_error("E-W11-002")
            configured = False
        if not configured:
            # 用户取消或向导异常：保持既有退出码契约（1），异常只留固定错误码
            print("[Win11] 未完成摄像头配置，值守未启动")
            return 1
    return run_runtime(args, edition=WIN11_WORKSTATION.key)


if __name__ == "__main__":
    sys.exit(main())
