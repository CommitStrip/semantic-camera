"""scam —— 语义摄像头 v2：Linux NVR 上的场所语义值守层。

唯一上游：VUS（video-understanding-skill）。感知/流服务/预算机制复用 vus，
本包只做场所语义：规则、四态裁决、事件分段、习惯化、证据事件、工作台。

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
