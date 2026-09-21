"""scam —— 语义摄像头共享领域核心。

Linux NVR 与 Win11 值守工作站是两个独立产品版本，分别从
``scam.linux_nvr`` 和 ``scam.win11`` 启动；检测、跟踪、裁决、存储等
领域模块共享。旧的 ``scam.nvr`` 仅保留为兼容入口。

层栈（详见 设计稿-v0.4-快慢系统帧差门控.md）：
  T0 门控（逐帧 1.6ms）→ T1 检测（运动触发）→ 裁决（≤1s，零慢层）
  → T2a 嵌入比对（毫秒级自命名）→ T2b VLM 深理解（仅新异事件）
  → T3 沉淀（习惯化批处理）
"""

from .config import load_venue, validate_venue
from .db import connect, init_schema
from .zones import Grid
from .gate import MotionGate
from .track import Tracker
from .detect import decode_nanodet, NanoDet
from .verdict import rule_fires, ZoneRuntime

__all__ = [
    "load_venue", "validate_venue",
    "connect", "init_schema",
    "Grid",
    "MotionGate",
    "Tracker",
    "decode_nanodet", "NanoDet",
    "rule_fires", "ZoneRuntime",
]
