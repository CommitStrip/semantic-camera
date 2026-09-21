"""产品版本边界：Linux NVR 与 Win11 值守工作站。

两个版本共享检测、跟踪、裁决、存储等领域核心，但入口、默认值、部署和
验收独立。这里是版本档案的唯一真值，禁止在业务模块里散落平台判断。
"""

from dataclasses import dataclass
import os
import sys

from .platform import app_data_dir


@dataclass(frozen=True)
class Edition:
    key: str
    display_name: str
    platform: str
    default_host: str = "127.0.0.1"
    default_port: int = 8600

    def default_db(self):
        if self.key == "win11":
            root = app_data_dir()
        else:
            # Linux 服务由 systemd WorkingDirectory 决定数据落点。
            root = "."
        return os.path.join(root, "storage", "scam.db")

    def default_config(self):
        """产品默认配置路径；Win11 不要求安装目录可写。"""
        if self.key == "win11":
            return os.path.join(app_data_dir(), "cameras.json")
        return "cameras.json"


LINUX_NVR = Edition(
    key="linux-nvr",
    display_name="语义摄像头 Linux NVR 版",
    platform="linux",
)

WIN11_WORKSTATION = Edition(
    key="win11",
    display_name="语义摄像头 Win11 值守工作站版",
    platform="win32",
)

EDITIONS = {
    LINUX_NVR.key: LINUX_NVR,
    WIN11_WORKSTATION.key: WIN11_WORKSTATION,
}


def get_edition(key=None):
    """解析版本；兼容入口未指定时按当前操作系统选择。"""
    if key is None:
        return WIN11_WORKSTATION if sys.platform == "win32" else LINUX_NVR
    try:
        return EDITIONS[key]
    except KeyError as exc:
        raise ValueError(f"未知产品版本: {key}") from exc


def platform_error(edition, current=None):
    """返回平台不匹配错误；匹配时返回 None，便于入口和测试共用。"""
    current = current or sys.platform
    if edition.platform == "win32" and current != "win32":
        return "Win11 版只能在 Windows 11 上启动"
    if edition.platform == "linux" and not current.startswith("linux"):
        return "Linux NVR 版只能在 Linux 上启动"
    return None
