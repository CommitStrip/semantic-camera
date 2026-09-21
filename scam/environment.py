"""scam.environment —— R3 环境档案核心（先识别、后圈选）。

硬红线（ZCODE-WIN11-CONTEXT ZW-001 / 设计稿 §8）：
- 环境识别只由管理员显式触发，绝不自动后台调用；
- 云端 provider 必须逐次显式 cloud_confirmed=True，否则零调用；
- 模型输出视为不可信数据：字段/类型/长度全量校验，非法即 invalid；
- 失败绝不覆盖既有有效档案；只存输入 JPEG 的 SHA-256，绝不存图片/base64；
- suggested_zones 永远只是建议——不写 zones 表、不自动成为报警规则；
- 相机 id 严格白名单，注入即拒绝；相机间档案严格隔离。
"""

import base64
import hashlib
import json
import re
import sqlite3
import time

_CAMERA_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_MAX = {"scene_type": 64, "lighting": 64, "risk_notes": 500,
        "elements": 32, "element_len": 64, "suggested_zones": 64,
        "suggested_zone_len": 200, "provider": 32}
_STATUS_OK = "ok"


def validate_camera_id(camera_id):
    """严格相机 id：字母/数字/下划线/连字符，≤64；注入即拒绝。"""
    if not isinstance(camera_id, str) or not _CAMERA_ID_RE.match(camera_id):
        raise ValueError(f"非法 camera_id: {camera_id!r}")
    return camera_id


def _meta_key(camera_id):
    return "env:" + validate_camera_id(camera_id)


def _extract_json(raw):
    """模型输出 → dict。接受 dict 或含 JSON 的文本（容忍代码围栏）；否则 None。"""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE)
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _check_text(value, limit):
    return isinstance(value, str) and 0 < len(value) <= limit


def _validate_profile(raw):
    """把不可信模型输出校验为环境档案；任何字段缺失/超限 → None。"""
    if not isinstance(raw, dict):
        return None
    if not _check_text(raw.get("scene_type"), _MAX["scene_type"]):
        return None
    if not _check_text(raw.get("lighting"), _MAX["lighting"]):
        return None
    if not _check_text(raw.get("risk_notes"), _MAX["risk_notes"]):
        return None
    elements = raw.get("elements")
    if not isinstance(elements, list) or len(elements) > _MAX["elements"]:
        return None
    if not all(_check_text(e, _MAX["element_len"]) for e in elements):
        return None
    zones = raw.get("suggested_zones")
    if not isinstance(zones, list) or len(zones) > _MAX["suggested_zones"]:
        return None
    # 当前提示词只允许区域描述字符串。拒绝任意 dict，避免模型把无界嵌套
    # JSON 混入档案；坐标/网格必须由管理员在圈选步骤明确产生。
    if not all(_check_text(z, _MAX["suggested_zone_len"]) for z in zones):
        return None
    return {"scene_type": raw["scene_type"],
            "elements": elements,
            "lighting": raw["lighting"],
            "risk_notes": raw["risk_notes"],
            "suggested_zones": zones}


def build_prompt():
    """环境识别提示词：只要求严格 JSON，字段与上限显式给出。"""
    return (
        "你是监控场景分析员。只输出一个 JSON 对象，不要输出任何其他文字。\n"
        '字段：{"scene_type": "场景类型，≤64字", '
        '"elements": ["画面要素，每条≤64字，最多32条"], '
        '"lighting": "照明情况，≤64字", '
        '"risk_notes": "风险提示，≤500字", '
        '"suggested_zones": ["建议重点关注的区域描述（仅建议）"]}\n'
        "所有内容必须来自画面本身，不得虚构。"
    )


class EnvironmentStore:
    """每相机环境档案：meta 表持久化（键=env:<camera_id>），原子覆盖。"""

    def __init__(self, conn):
        self.conn = conn
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError("conn 必须是 sqlite3.Connection")

    def load(self, camera_id):
        """读取环境档案；不存在或存档损坏返回 None（读取永不调用模型）。"""
        key = _meta_key(camera_id)
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if row is None:
            return None
        try:
            stored = json.loads(row[0])
        except (TypeError, ValueError):
            return None
        if not isinstance(stored, dict):
            return None
        profile = _validate_profile(stored)
        provider = stored.get("provider")
        analyzed_at = stored.get("analyzed_at")
        frame_sha256 = stored.get("frame_sha256")
        if profile is None or provider not in ("local", "cloud"):
            return None
        if not isinstance(analyzed_at, (int, float)) or analyzed_at <= 0:
            return None
        if not isinstance(frame_sha256, str) or not re.fullmatch(
                r"[0-9a-f]{64}", frame_sha256):
            return None
        return stored

    def analyze(self, camera_id, *, provider, frame_bgr,
                cloud_confirmed=False):
        """管理员触发的环境识别。返回 (status, profile|None)。

        status: ok | unavailable | invalid | confirmation_required。
        只有 ok 才写库（原子覆盖）；任何失败都保留既有有效档案。
        """
        key = _meta_key(camera_id)
        if provider is None:
            return "unavailable", None
        provider_name = getattr(provider, "name", "")
        # 只接受项目定义的两个通道。未知 provider 不能借名称绕过云端逐次确认。
        if provider_name not in ("local", "cloud"):
            return "unavailable", None
        if provider_name == "cloud" and not cloud_confirmed:
            # 云端必须逐次显式确认——在任何调用发生前拒绝
            return "confirmation_required", None

        import cv2
        try:
            ok, encoded = cv2.imencode(".jpg", frame_bgr,
                                       [cv2.IMWRITE_JPEG_QUALITY, 85])
        except (cv2.error, TypeError, ValueError):
            return "unavailable", None
        if not ok:
            return "unavailable", None
        jpeg = encoded.tobytes()
        frame_sha256 = hashlib.sha256(jpeg).hexdigest()

        try:
            raw = provider.understand(
                build_prompt(),
                [base64.b64encode(jpeg).decode("ascii")],
                context={"camera_id": camera_id})
        except Exception:
            # Provider 属于慢系统；故障必须诚实降级，不能打断工作台或快路径。
            return "unavailable", None
        if raw is None:
            return "unavailable", None
        profile = _validate_profile(_extract_json(raw))
        if profile is None:
            return "invalid", None

        profile["provider"] = provider_name
        profile["analyzed_at"] = time.time()
        profile["frame_sha256"] = frame_sha256
        # 原子覆盖：单条 REPLACE，成功才生效；失败保持旧档案
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(profile, ensure_ascii=False,
                             separators=(",", ":"))))
        self.conn.commit()
        return _STATUS_OK, profile
