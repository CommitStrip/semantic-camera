"""scam.linux_unit —— systemd unit 单一真值渲染源（Linux NVR）。

静态模板与安装脚本不得各写一份 unit 逻辑：装机用的、CI 校验的、测试断言的
都来自本模块的同一渲染函数。本模块只渲染不落盘；写入文件由调用方用 shell
重定向完成（install.sh / CI），本模块因此不持有任何文件写路径。用法：

    python -m scam.linux_unit render --workdir /opt/scam [--user u] [--python p]
"""

import argparse
import getpass
import os
import posixpath
import sys


def render_unit(*, user, workdir, python=None,
                description="语义摄像头 NVR 语义值守"):
    """渲染 unit 文本。workdir 必须绝对；user 禁空禁模板占位符。

    python 缺省取 workdir/.venv/bin/python（install.sh 的 venv 布局）。
    网络就绪等待用 network-online.target；RestartSec=5 给崩溃重启留退避；
    PYTHONUNBUFFERED=1 保证 journalctl 实时可见值守日志。
    """
    # systemd 只消费 POSIX 路径：按 / 字符串校验，绝不过本地系统的路径机
    # （Windows 的 abspath 会把 /opt/scam 改写成 D:\opt\scam，渲染必须免疫）。
    raw = (workdir or "").replace("\\", "/")
    if ".." in raw.split("/"):
        raise ValueError("workdir 不允许包含 .. 路径段")
    if not raw.startswith("/") or len(raw) < 2:
        raise ValueError("workdir 必须为以 / 开头的 POSIX 绝对路径")
    workdir = posixpath.normpath(raw)
    user = (user or "").strip()
    if not user or "%" in user:
        raise ValueError("user 必须为非空且不含 systemd 模板占位符")
    if python is None:
        python = posixpath.join(workdir, ".venv", "bin", "python")
    python = python.replace("\\", "/")
    if not python.startswith("/") or ".." in python.split("/"):
        raise ValueError("python 必须为以 / 开头且不含 .. 的 POSIX 绝对路径")
    return "\n".join([
        "[Unit]",
        f"Description={description}",
        "Wants=network-online.target",
        "After=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        f"User={user}",
        f"WorkingDirectory={workdir}",
        f"ExecStart={python} -m scam.linux_nvr",
        "Restart=always",
        "RestartSec=5",
        "Environment=PYTHONUNBUFFERED=1",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ])


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="渲染 scam-nvr systemd unit（单一真值源，只输出 stdout）")
    sub = ap.add_subparsers(dest="command", required=True)
    r = sub.add_parser("render", help="渲染 unit 到 stdout（落盘由调用方重定向）")
    r.add_argument("--user", default=None,
                   help="服务运行用户（缺省当前用户；禁止模板占位符）")
    r.add_argument("--workdir", required=True, help="部署目录绝对路径")
    r.add_argument("--python", default=None,
                   help="解释器绝对路径（缺省 workdir/.venv/bin/python）")
    args = ap.parse_args(argv)
    user = args.user or os.environ.get("USER") or getpass.getuser()
    try:
        unit = render_unit(user=user, workdir=args.workdir, python=args.python)
    except ValueError as e:
        print(f"[linux-unit] {e}", file=sys.stderr)
        return 2
    sys.stdout.write(unit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
