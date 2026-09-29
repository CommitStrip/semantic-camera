"""win11_exe_entry.py —— 发行包 exe 的顶层入口（PyInstaller 打包用）。

包内模块使用相对导入（`from .editions import ...`），不能直接作为顶层脚本运行；
因此 exe 的入口放在包外，只做一件事：把控制权交给 `scam.win11_launcher.main`。

这个文件不包含业务逻辑：双击行为的全部实现都在 `scam/win11_launcher.py`，
测试也针对该模块，避免"打包入口与源码入口行为不一致"。
"""

import sys

from scam.win11_launcher import main

if __name__ == "__main__":
    sys.exit(main())
