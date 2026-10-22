"""win11_exe_entry.py —— 发行包 exe 的顶层入口（PyInstaller 打包用）。

包内模块使用相对导入（`from .editions import ...`），不能直接作为顶层脚本运行；
因此 exe 的入口放在包外，只做一件事：把控制权交给 `scam.win11_launcher.main`。

这个文件不包含业务逻辑：双击行为的全部实现都在 `scam/win11_launcher.py`，
测试也针对该模块，避免"打包入口与源码入口行为不一致"。
"""

import sys

from scam.editions import WIN11_WORKSTATION
from scam.win11_config_check import main as config_check_main
from scam.win11_launcher import main


def _desktop(argv):
    """C152 桌面模式：本 exe 作为**内部后端**运行，由外壳经 stdio 协议驱动。

    不打开浏览器；正常停止走 stop 命令/EOF；就绪为事实性握手。
    """
    from scam.win11_desktop import desktop_main
    return desktop_main(argv, edition=WIN11_WORKSTATION.key)


def _check_config(argv):
    """Offline static diagnostics only; never enters launcher or desktop."""
    return config_check_main(argv)


if __name__ == "__main__":
    _argv = sys.argv[1:]
    if "--check-config" in _argv:
        if "--desktop" in _argv:
            sys.exit(2)
        sys.exit(_check_config([a for a in _argv if a != "--check-config"]))
    if "--desktop" in _argv:
        sys.exit(_desktop([a for a in _argv if a != "--desktop"]))
    sys.exit(main())
