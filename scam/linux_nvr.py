"""Linux NVR 版独立入口：python -m scam.linux_nvr。"""

import sys

from .editions import LINUX_NVR, platform_error
from .nvr import main as run_runtime


def main(argv=None):
    error = platform_error(LINUX_NVR)
    if error:
        print(f"[Linux NVR] {error}")
        return 2
    return run_runtime(argv, edition=LINUX_NVR.key)


if __name__ == "__main__":
    sys.exit(main())
