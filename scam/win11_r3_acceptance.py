"""win11_r3_acceptance.py —— Win11 R3 两阶段原生重启验收驱动。

把“本机配置 → 识别 → 圈选 → 保存 → 用户重启进程 → 事实仍成立”变成目标 Win11 上
可执行、可复核、去凭据的两阶段证据采集，而不是继续依赖人工口述：

- ``before``：只在精确 Win32 上访问**回环**工作台，要求 health 可达、至少一相机
  在线、环境档案 ready、至少一个管理员区域且当前帧为 JPEG，然后以固定 schema
  **独占**写状态文件（绝不覆盖已有文件）。
- ``after``：安全读取状态，重新采集同一组事实，要求运行实例标识变化、相机集合与
  环境/区域规范摘要一致且仍有在线 JPEG 帧，再以同目录临时文件 + fsync + 原子
  **no-clobber** 发布最终报告（不覆盖已有报告）。

证据完整性围栏（状态文件是外部输入，必须当作不可信数据）：
- 读取把**读取前路径身份**、**已打开 fd 身份**、**读取前后 fd 身份与稳定元数据**和
  **读取后路径身份**绑成同一个普通文件；跨 API（路径 stat ↔ fd stat）只比身份
  （设备号/文件索引/类型），因为 Windows 上同一文件的这两个 API 可以给出不同的
  size/mtime/ctime 表示；同一 API 的前后比对才连大小与时间一起比，就地改写与换出
  换入都逃不掉。任何 stat/open/读取异常或不一致都结构化失败，不重开、不重试、
  绝不产出半可信状态。
- 固定 schema 逐层校验：顶层与每个证据承载对象的键集、固定词汇表、回环端口、UTC
  时间、定长小写十六进制标识与摘要，并从相机集合**重算**计数、检查项与
  facts/persistence 摘要。未知字段、自由文本、路径注入、计数或摘要篡改一律拒绝。

诚实边界（勿高估本文件能证明什么）：
- 只读工作台既有事实：不启动/停止进程、不改配置或区域、不访问非回环网络、不内置
  任何 fake 通道（假 HTTP 只在测试里注入，生产入口没有“模拟模式”）。
- 判定只声称 R3 原生重启**候选**证据：``process_restart_verified`` 仅在运行实例标识
  变化时为 ``true``，``r3_persistence_verified`` 仅在实例变化**且**相机集合、环境、
  区域与在线 JPEG 全部成立时才为 ``true``（同实例时两个结论都必须为 ``false``）；
  真实模型质量、干净安装、告警延迟、长稳与发布门禁恒为 ``null`` 并列入未验证。
- 状态与报告只保存相机 ID、固定状态、计数、时间的规范 JSON/JPEG SHA-256——绝不包含
  source、RTSP 凭据、模型路径、环境自由文本、区域名称/规则文本、绝对路径或原始帧。
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import stat
import sys
from urllib.parse import quote, urlsplit

from .server import CAPABILITY_STATES, ISSUE_ACTIONS, RUNTIME_STATES

STATE_SCHEMA = "scam.win11-r3-state/v1"
REPORT_SCHEMA = "scam.win11-r3-report/v1"
EVIDENCE_LEVEL = "r3_native_restart_candidate"
DEFAULT_BASE_URL = "http://127.0.0.1:8600"

# 只允许的回环工作台主机字面量。localhost 通过 DNS 解析，解析结果必须**全部**
# 是回环地址，且真正连接的是回环字面量——主机名只作别名，绝不作可配置目标。
ALLOWED_HOSTS = ("127.0.0.1", "localhost", "::1")
JPEG_MAGIC = b"\xff\xd8\xff"
MAX_STATE_BYTES = 1 << 20          # 状态文件上限：合法状态只有数 KB
HTTP_TIMEOUT_S = 5.0
EXCLUSIVE_WRITE_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_BINARY", 0))
READ_FLAGS = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
              | getattr(os, "O_NOFOLLOW", 0))

# 状态文件是外部输入：固定词汇表、定长小写十六进制标识与摘要、安全相机 ID。
ENVIRONMENT_STATES = ("ready", "required")
ENVIRONMENT_CHANNELS = ("local", "cloud")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_INSTANCE_ID_RE = re.compile(r"[0-9a-f]{32}")
# 与工作台 environment 端点接受的相机 ID 同一约束（字母/数字/下划线/连字符，≤64）：
# 越界的 ID 根本取不到环境/区域事实，因此合法状态里不可能出现。
_CAMERA_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
# 严格 UTC 时间戳：只认驱动器与工作台 ``isoformat()`` 会写出的规范形式。数字显式
# 写成 0-9：``\d`` 会接受其它 Unicode 数字，那就等于放自由文本进证据。
_UTC_TIMESTAMP_RE = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,6}))?(?:\+00:00|Z)")

# 固定 schema 的逐层键集：多一个键少一个键都拒绝，未知字段绝不进最终报告。
STATE_KEYS = frozenset((
    "schema", "phase", "evidence_level", "captured_at", "platform",
    "workbench", "runtime", "cameras", "counters", "checks",
    "facts_sha256", "persistence_sha256",
))
WORKBENCH_KEYS = frozenset(("host", "port"))
RUNTIME_KEYS = frozenset(("runtime_instance_id", "started_at"))
CAMERA_KEYS = frozenset(("camera", "runtime_state", "capability", "issue_code",
                         "environment", "zones", "frame"))
ENVIRONMENT_KEYS = frozenset(("state", "channel", "profile_sha256"))
ZONES_KEYS = frozenset(("grid", "zone_count", "zones_sha256"))
GRID_KEYS = frozenset(("rows", "cols"))
FRAME_KEYS = frozenset(("available", "bytes", "jpeg_sha256"))
COUNTERS_KEYS = frozenset(("camera_count", "online_camera_count",
                           "subject_camera_count"))
CHECK_KEYS = frozenset(("name", "passed", "detail"))

# 恒为 null 的门禁：本驱动永远不声称这些已通过，且必须逐条出现在未验证清单里。
FIXED_NULL_VERDICTS = (
    "real_detector_quality_verified",
    "clean_install_verified",
    "latency_gate_passed",
    "stability_gate_passed",
    "release_gate_passed",
)
NOT_VERIFIED = ("real_rtsp_stream",) + FIXED_NULL_VERDICTS


class R3Failure(Exception):
    """结构性失败：环境/平台/文件/协议等前置条件不成立，产不出任何证据。"""

    def __init__(self, message, code="r3_precondition_failed"):
        super().__init__(message)
        self.code = code


def current_platform_name():
    """精确平台标识。测试可替换；生产等价于 ``sys.platform``。"""
    return sys.platform


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _canonical_sha256(payload):
    """规范 JSON 的 SHA-256：键序与空白不参与摘要，跨进程可复核。"""
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _is_utc_timestamp(value):
    """严格 UTC 时间戳：只有规范 ISO 形式且偏移为零才算，自由文本一律拒绝。"""
    if not isinstance(value, str):
        return False
    match = _UTC_TIMESTAMP_RE.fullmatch(value)
    if match is None:
        return False
    year, month, day, hour, minute, second, fraction = match.groups()
    try:
        datetime(int(year), int(month), int(day), int(hour), int(minute),
                 int(second), int((fraction or "0").ljust(6, "0")),
                 tzinfo=timezone.utc)
    except ValueError:
        return False
    return True


def _is_int(value):
    """真正的整数：bool 是 int 的子类，端口/计数里的 True 必须被拒绝。"""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_sha256(value):
    """定长小写十六进制摘要：大写、短写、非十六进制或带任何其它字符都不算。"""
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _is_instance_id(value):
    """运行实例标识：工作台写入的 ``uuid4().hex``，即 32 位小写十六进制。"""
    return isinstance(value, str) and _INSTANCE_ID_RE.fullmatch(value) is not None


def _is_camera_id(value):
    """安全非空相机 ID：字母/数字/下划线/连字符且 ≤64，注入路径或自由文本即拒绝。"""
    return isinstance(value, str) \
        and _CAMERA_ID_RE.fullmatch(value) is not None


def _is_loopback_literal(address):
    try:
        return ipaddress.ip_address(str(address)).is_loopback
    except ValueError:
        return False


def parse_workbench_url(url):
    """校验工作台地址只能是 ``http://`` 加回环字面量，并回传固定词汇表。

    拒绝 https、用户信息、路径/查询/片段与任何非回环主机（含私有/保留地址）。
    """
    def _reject(message):
        raise R3Failure(message, code="unsafe_workbench")

    parts = urlsplit(str(url))
    if parts.scheme != "http":
        _reject("workbench: 只允许 http 回环地址")
    if parts.username or parts.password:
        _reject("workbench: 地址不得携带用户信息")
    host = parts.hostname
    if host not in ALLOWED_HOSTS:
        _reject("workbench: 主机必须是 127.0.0.1、localhost 或 ::1")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        _reject("workbench: 地址不得携带路径、查询或片段")
    try:
        port = parts.port
    except ValueError as exc:
        raise R3Failure("workbench: 端口不合法",
                        code="unsafe_workbench") from exc
    if port is None or not 1 <= port <= 65535:
        _reject("workbench: 端口必须是 1..65535")
    return {"host": host, "port": port}


def _loopback_connect_host(host):
    """把回环别名解析为可连接的回环字面量；任何非回环解析结果一律拒绝。"""
    if host in ("127.0.0.1", "::1"):
        return host
    try:
        infos = socket.getaddrinfo("localhost", None,
                                   proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise R3Failure(
            f"workbench: 回环别名不可解析（{type(exc).__name__}）",
            code="unsafe_workbench") from exc
    addresses = sorted({info[4][0] for info in infos if info[4]})
    if not addresses or not all(_is_loopback_literal(a) for a in addresses):
        raise R3Failure("workbench: 回环别名解析结果含非回环地址，已拒绝",
                        code="unsafe_workbench")
    for preferred in ("127.0.0.1", "::1"):
        if preferred in addresses:
            return preferred
    return addresses[0]


def _http_get(connect_host, port, path, *, timeout=HTTP_TIMEOUT_S):
    """单次回环 GET：不跟随重定向（3xx 只是状态码），不拼接任何外部主机。"""
    connection = http.client.HTTPConnection(connect_host, port, timeout=timeout)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read()
        content_type = (response.getheader("Content-Type") or "")
        return {
            "status": response.status,
            "content_type": content_type.split(";")[0].strip().lower(),
            "body": body,
        }
    finally:
        connection.close()


def format_workbench_url(workbench):
    """把回环工作台重新拼成可解析地址；IPv6 字面量必须加方括号。"""
    host = workbench["host"]
    if ":" in host:
        host = f"[{host}]"
    return f"http://{host}:{workbench['port']}"


def make_loopback_fetch(workbench, *, timeout=HTTP_TIMEOUT_S):
    """构造回环 fetch：解析一次，之后每个请求只发往该回环字面量。"""
    connect_host = _loopback_connect_host(workbench["host"])
    port = workbench["port"]

    def fetch(method, path):
        if method != "GET":
            raise R3Failure("workbench: 本驱动只发起只读 GET")
        return _http_get(connect_host, port, path, timeout=timeout)

    return fetch


def _fetch_json(fetch, path, problems, label):
    """取一个 JSON 文档；失败只记结构化问题，绝不回显底层异常正文。"""
    try:
        response = fetch("GET", path)
    except R3Failure:
        raise
    except Exception as exc:      # 连接/超时/DNS：一律结构化，不外传正文
        problems.append(f"{label}: 工作台不可达（{type(exc).__name__}）")
        return None
    if response.get("status") != 200:
        problems.append(f"{label}: HTTP {response.get('status')}")
        return None
    try:
        document = json.loads(response.get("body") or b"")
    except (TypeError, ValueError):
        problems.append(f"{label}: JSON 解析失败")
        return None
    if not isinstance(document, dict):
        problems.append(f"{label}: JSON 顶层不是对象")
        return None
    return document


def _environment_facts(fetch, camera_id, problems):
    path = f"/api/environment/{quote(camera_id, safe='')}"
    document = _fetch_json(fetch, path, problems, f"environment:{camera_id}")
    if document is None:
        return None
    state = document.get("state")
    if state not in ENVIRONMENT_STATES:
        problems.append(f"environment:{camera_id}: 状态不在固定词汇表")
        return None
    profile = document.get("profile")
    channel = document.get("channel")
    # 环境档案可能含自由文本与路径：只留规范摘要，原文绝不落盘。工作台以“档案为
    # 真值”判定 ready，因此摘要的有无必须与状态一一对应：不一致就是结构性缺口，
    # 绝不让一份自相矛盾的环境事实落进状态文件。
    profile_sha256 = _canonical_sha256(profile) if profile else None
    if (state == "ready") != (profile_sha256 is not None):
        problems.append(f"environment:{camera_id}: 状态与档案摘要不一致")
        return None
    return {
        "state": state,
        "channel": channel if channel in ENVIRONMENT_CHANNELS else None,
        "profile_sha256": profile_sha256,
    }


def _zone_facts(fetch, camera_id, problems):
    path = f"/api/zones/{quote(camera_id, safe='')}"
    document = _fetch_json(fetch, path, problems, f"zones:{camera_id}")
    if document is None:
        return None
    grid = document.get("grid")
    zones = document.get("zones")
    if not isinstance(grid, dict) or not isinstance(zones, list):
        problems.append(f"zones:{camera_id}: 结构不符（grid/zones）")
        return None
    rows, cols = grid.get("rows"), grid.get("cols")
    if not (_is_int(rows) and rows >= 1 and _is_int(cols) and cols >= 1):
        problems.append(f"zones:{camera_id}: 网格行列必须是正整数")
        return None
    if any(not isinstance(zone, dict) for zone in zones):
        problems.append(f"zones:{camera_id}: 区域条目结构不符")
        return None
    return {
        # 网格是配置派生值（监视器尚未建立时工作台回落默认网格），因此不进守恒
        # 摘要；区域条目本身才是落盘真值，重启前后必须逐字节一致。
        "grid": {"rows": rows, "cols": cols},
        "zone_count": len(zones),
        # 区域名称与规则是自由文本：只留规范摘要，原文绝不落盘。
        "zones_sha256": _canonical_sha256(zones),
    }


def _frame_facts(fetch, camera_id):
    """当前帧是否可取 JPEG。取不到是事实（离线/编码失败），不是结构性问题。"""
    path = f"/api/frame/{quote(camera_id, safe='')}"
    try:
        response = fetch("GET", path)
    except Exception:
        return {"available": False, "bytes": 0, "jpeg_sha256": None}
    body = response.get("body") or b""
    if response.get("status") == 200 \
            and response.get("content_type") == "image/jpeg" \
            and body[:3] == JPEG_MAGIC:
        return {"available": True, "bytes": len(body),
                "jpeg_sha256": hashlib.sha256(body).hexdigest()}
    return {"available": False, "bytes": 0, "jpeg_sha256": None}


def _is_subject(camera):
    """R3 主体相机：在线 + 环境 ready + 至少一个区域 + 当前帧为 JPEG。"""
    return (camera["runtime_state"] == "online"
            and camera["environment"]["state"] == "ready"
            and camera["zones"]["zone_count"] >= 1
            and camera["frame"]["available"])


def _persistence_summary(cameras):
    """跨重启必须守恒的事实：相机集合 + 环境档案规范摘要 + 区域规范摘要。

    刻意不含运行状态、检测能力与帧摘要——重启后重新连接与重新构造检测器是
    正常过程，把它们纳入守恒会把“事实持久”偷换成“瞬时状态相同”。
    """
    zones = {camera["camera"]: {"zone_count": camera["zones"]["zone_count"],
                                "zones_sha256":
                                    camera["zones"]["zones_sha256"]}
             for camera in cameras}
    return {
        "camera_set": sorted(camera["camera"] for camera in cameras),
        "environments": {camera["camera"]: camera["environment"]
                         for camera in cameras},
        "zones": zones,
    }


def collect_facts(workbench, *, fetch):
    """采集一组只读事实：运行实例、逐相机运行状态、环境档案、区域与当前帧。

    返回 ``(facts, problems)``。``problems`` 非空表示结构性缺口（不可达、非 200、
    JSON/schema 不符），此时不得据此宣称任何 R3 证据。
    """
    problems = []
    health = _fetch_json(fetch, "/api/health", problems, "health")
    if health is None:
        return None, problems

    instance = health.get("runtime_instance")
    runtime = health.get("runtime")
    if not isinstance(runtime, dict) \
            or not isinstance(runtime.get("cameras"), list):
        problems.append("health: 缺少值守运行快照，相机集合不可得")
        return None, problems

    instance_id = started_at = None
    if isinstance(instance, dict):
        instance_id = instance.get("runtime_instance_id")
        started_at = instance.get("started_at")
    # 实例身份只认工作台写出的 uuid4().hex：自由文本或路径绝不允许流进状态文件。
    if not _is_instance_id(instance_id) or not _is_utc_timestamp(started_at):
        problems.append("health: 未声明运行实例身份（runtime_instance）")
        return None, problems

    cameras = []
    seen_ids = set()
    for entry in runtime["cameras"]:
        if not isinstance(entry, dict):
            problems.append("health: 相机条目结构不符")
            return None, problems
        camera_id = entry.get("camera")
        # 相机 ID 是唯一会原样落盘的标识：必须是安全非空标识且互不重复，
        # 否则状态文件无法与相机集合一一对应。
        if not _is_camera_id(camera_id):
            problems.append("health: 相机 ID 不是安全非空标识")
            return None, problems
        if camera_id in seen_ids:
            problems.append(f"health: 相机 ID 重复（{camera_id}）")
            return None, problems
        seen_ids.add(camera_id)
        state = entry.get("state")
        capability = entry.get("capability")
        if state not in RUNTIME_STATES or capability not in CAPABILITY_STATES:
            problems.append(f"health: 相机 {camera_id} 状态不在固定词汇表")
            return None, problems
        issue = entry.get("issue")
        issue_code = issue.get("code") if isinstance(issue, dict) else None
        # 故障码同样只认固定词汇表：将来若夹带路径或自由文本，这里直接拒绝落盘。
        # 先判类型再查词表（JSON 数组/对象不可哈希，直接查会抛异常而不是结构化拒绝）。
        if issue_code is not None and (not isinstance(issue_code, str)
                                       or issue_code not in ISSUE_ACTIONS):
            problems.append(f"health: 相机 {camera_id} 故障码不在固定词汇表")
            return None, problems
        environment = _environment_facts(fetch, camera_id, problems)
        zones = _zone_facts(fetch, camera_id, problems)
        if environment is None or zones is None:
            return None, problems
        cameras.append({
            "camera": camera_id,
            "runtime_state": state,
            "capability": capability,
            "issue_code": issue_code,
            "environment": environment,
            "zones": zones,
            "frame": _frame_facts(fetch, camera_id),
        })

    summary = _persistence_summary(cameras)
    return {
        "workbench": dict(workbench),
        "runtime": {"runtime_instance_id": instance_id,
                    "started_at": started_at},
        "cameras": cameras,
        "counters": {
            "camera_count": len(cameras),
            "online_camera_count": sum(
                1 for camera in cameras
                if camera["runtime_state"] == "online"),
            "subject_camera_count": sum(1 for camera in cameras
                                        if _is_subject(camera)),
        },
        "facts_sha256": _canonical_sha256(cameras),
        "persistence_sha256": _canonical_sha256(summary),
    }, problems


def _check(name, passed, detail):
    return {"name": name, "passed": bool(passed), "detail": str(detail)}


def evaluate_before(facts):
    """before 门槛：至少一相机在线、环境 ready、有区域且当前帧为 JPEG。"""
    cameras = facts["cameras"]
    counters = facts["counters"]
    online = counters["online_camera_count"]
    ready = sum(1 for camera in cameras
                if camera["environment"]["state"] == "ready")
    zoned = sum(1 for camera in cameras if camera["zones"]["zone_count"] >= 1)
    frames = sum(1 for camera in cameras if camera["frame"]["available"])
    return [
        _check("camera_online", online >= 1, f"在线相机 {online} 台"),
        _check("environment_ready", ready >= 1, f"环境档案 ready {ready} 台"),
        _check("zone_configured", zoned >= 1, f"已有区域 {zoned} 台"),
        _check("frame_jpeg", frames >= 1, f"当前帧为 JPEG {frames} 台"),
        _check("r3_subject_present", counters["subject_camera_count"] >= 1,
               "在线 + 环境 ready + 有区域 + JPEG 齐全的相机 "
               f"{counters['subject_camera_count']} 台"),
    ]


def evaluate_after(state_facts, facts):
    """after 门槛：实例变化、相机集合与环境/区域规范摘要一致、仍有在线 JPEG。"""
    before = _persistence_summary(state_facts["cameras"])
    after = _persistence_summary(facts["cameras"])
    instance_changed = (facts["runtime"]["runtime_instance_id"]
                        != state_facts["runtime"]["runtime_instance_id"])
    camera_set_equal = before["camera_set"] == after["camera_set"]
    environment_equal = before["environments"] == after["environments"]
    zones_equal = before["zones"] == after["zones"]
    online_jpeg = any(camera["runtime_state"] == "online"
                      and camera["frame"]["available"]
                      for camera in facts["cameras"])
    checks = [
        _check("runtime_instance_changed", instance_changed,
               "运行实例已变化（进程已重启）" if instance_changed
               else "运行实例未变化：进程未重启，本次不得声称重启"),
        _check("camera_set_unchanged", camera_set_equal,
               f"相机集合 {'一致' if camera_set_equal else '不一致'}"
               f"（共 {facts['counters']['camera_count']} 台）"),
        _check("environment_summary_unchanged", environment_equal,
               "环境档案规范摘要" + ("一致" if environment_equal else "漂移")),
        _check("zone_summary_unchanged", zones_equal,
               "区域规范摘要" + ("一致" if zones_equal else "漂移")),
        _check("online_jpeg_present", online_jpeg,
               "重启后仍有在线 JPEG 帧" if online_jpeg
               else "重启后无在线 JPEG 帧"),
    ]
    # 持久化结论只有在“确已重启”**且**四项事实检查全过时才成立：实例未变化时
    # 两个 R3 结论都必须为 false——同实例下的一致性只证明“没重启”，不证明持久。
    verdict = {
        "process_restart_verified": instance_changed,
        "r3_persistence_verified": bool(
            instance_changed and camera_set_equal and environment_equal
            and zones_equal and online_jpeg),
    }
    for name in FIXED_NULL_VERDICTS:
        verdict[name] = None
    return checks, verdict


def build_state(facts, checks):
    """before 状态文件（固定 schema）：只含 ID、固定状态、计数、时间与 SHA-256。"""
    return {
        "schema": STATE_SCHEMA,
        "phase": "before",
        "evidence_level": EVIDENCE_LEVEL,
        "captured_at": _now_iso(),
        "platform": "win32",
        "workbench": dict(facts["workbench"]),
        "runtime": dict(facts["runtime"]),
        "cameras": facts["cameras"],
        "counters": dict(facts["counters"]),
        "facts_sha256": facts["facts_sha256"],
        "persistence_sha256": facts["persistence_sha256"],
        "checks": checks,
    }


def build_report(state, state_sha256, facts, checks, verdict):
    """after 最终报告（固定 schema）：不写路径、不写自由文本，只写判定与摘要。"""
    before_counters = state.get("counters", {})
    return {
        "schema": REPORT_SCHEMA,
        "phase": "after",
        "evidence_level": EVIDENCE_LEVEL,
        "generated_at": _now_iso(),
        "platform": "win32",
        "workbench": dict(facts["workbench"]),
        "before": {
            "schema": state.get("schema"),
            "captured_at": state.get("captured_at"),
            "started_at": state["runtime"]["started_at"],
            "runtime_instance_id": state["runtime"]["runtime_instance_id"],
            "state_sha256": state_sha256,
            "persistence_sha256": state.get("persistence_sha256"),
            "counters": dict(before_counters),
        },
        "after": {
            "captured_at": _now_iso(),
            "started_at": facts["runtime"]["started_at"],
            "runtime_instance_id": facts["runtime"]["runtime_instance_id"],
            "persistence_sha256": facts["persistence_sha256"],
            "counters": dict(facts["counters"]),
        },
        "checks": checks,
        "verdict": verdict,
        "not_verified": list(NOT_VERIFIED),
        "boundary": ("只声称 R3 原生重启候选证据：不证明真实 RTSP、真实模型质量、"
                     "告警延迟、干净安装、长稳或发布门禁，也不代表已经控制或"
                     "重启过任何进程。"),
    }


def write_state_exclusive(path, state):
    """独占创建一个固定 schema 状态文件：绝不覆盖、绝不跟随软链接。"""
    target = os.path.abspath(path)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    data = (json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2)
            + "\n").encode("utf-8")
    fd = None
    created = False
    written = False
    try:
        fd = os.open(target, EXCLUSIVE_WRITE_FLAGS, 0o600)
        created = True
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        written = True
    except FileExistsError as exc:
        raise R3Failure("state: 已存在同名状态文件，拒绝覆盖",
                        code="state_write_refused") from exc
    except OSError as exc:
        raise R3Failure(f"state: 状态文件写入失败（{type(exc).__name__}）",
                        code="state_write_refused") from exc
    finally:
        if fd is not None:
            os.close(fd)
        # 只清理由本次独占创建出的半文件；已有文件因 O_EXCL 从未被打开。
        if created and not written:
            try:
                if os.path.isfile(target):
                    os.unlink(target)
            except OSError:
                pass


def _file_identity(info):
    """一个普通文件的**身份**：设备号 + 文件索引（节点号）+ 文件类型。

    只回答“这是不是同一个文件”。刻意不含大小与时间：正常 NTFS 文件经路径
    ``lstat`` 与经已打开 fd ``fstat`` 取到的 size/mtime/ctime 可以是同一事实的
    不同表示，把元数据当身份会把合法状态误判成“换入”。
    """
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


def _file_metadata(info):
    """同一 stat 口径内必须稳定的元数据：大小 + 修改/变更时间。

    只用于**同一种 API 的前后比对**（fd 前 vs fd 后、路径前 vs 路径后）——那里两次
    读数出自同一来源，任何差异都是真实的就地改写。刻意不含访问时间：读文件本身
    会刷新它，纳进来会把正常读取判成异常。
    """
    return (info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _same_file_identity(left, right):
    """跨 API（路径 stat ↔ fd stat）判定“同一个文件”：只比身份，不比元数据。"""
    return (os.path.samestat(left, right)
            and _file_identity(left) == _file_identity(right))


def _same_unchanged_file(left, right):
    """同一 stat 口径内判定“同一个未被改写的文件”：身份 + 稳定元数据。"""
    return (_same_file_identity(left, right)
            and _file_metadata(left) == _file_metadata(right))


def _state_unreadable(message):
    raise R3Failure(f"state: {message}", code="state_unreadable")


def read_state(path, *, limit=MAX_STATE_BYTES):
    """安全读取 before 状态：路径、已打开 fd 与读取前后身份必须是同一普通文件。

    顺序固定为 lstat 路径 → 以安全标志打开 → fstat 打开后的 fd（必须是普通文件
    且与路径身份**同一文件**）→ 只通过该 fd 读取 → fstat 复核同一 fd 身份与稳定
    元数据 → lstat 路径复核身份与稳定元数据。任何 stat/open/读取异常或不一致都
    收敛为结构化 ``state_unreadable``：不重开、不重试、绝不留下半可信状态。

    比对口径按 API 分层：路径 stat 与 fd stat 之间**只比身份**（设备号/文件索引/
    文件类型，经 ``samestat``）——Windows/NTFS 上同一文件的路径 stat 与句柄 stat
    可以给出不同的 size/mtime/ctime 表示，把元数据当身份会让合法状态读不回来；
    而读取前后同一 fd、以及读取前后同一路径各自出于同一 API，继续比“身份 + 大小 +
    修改/变更时间”，就地改写与换出换入都逃不掉。
    """
    target = os.path.abspath(path)
    try:
        before = os.lstat(target)
    except OSError as exc:
        raise R3Failure(f"state: 状态文件不可读（{type(exc).__name__}）",
                        code="state_unreadable") from exc
    if stat.S_ISLNK(before.st_mode):
        _state_unreadable("拒绝软链接")
    if not stat.S_ISREG(before.st_mode):
        _state_unreadable("不是常规文件（目录或设备被拒绝）")
    if before.st_size == 0:
        _state_unreadable("文件为空")
    if before.st_size > limit:
        _state_unreadable("超过大小上限")

    fd = None
    try:
        fd = os.open(target, READ_FLAGS)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            _state_unreadable("打开后不是常规文件")
        # 已打开 fd 必须与读取前的路径身份是同一个文件：路径在检查与打开之间
        # 被换入（随后又被换回）时，只有这一步能把差异暴露出来。跨 API 只比身份，
        # 不比大小/时间——那两个字段在 Windows 上可以只是不同的表示。
        if not _same_file_identity(before, opened):
            _state_unreadable("打开的身份与路径身份不一致（疑似换入）")
        raw = b""
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            raw += chunk
            remaining -= len(chunk)
        closed = os.fstat(fd)
    except OSError as exc:
        raise R3Failure(f"state: 状态文件不可读（{type(exc).__name__}）",
                        code="state_unreadable") from exc
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    # 同一 fd 的读取前后：身份与稳定元数据都必须不变，就地改写必须被抓住。
    if not _same_unchanged_file(opened, closed):
        _state_unreadable("读取期间 fd 身份或元数据漂移，拒绝使用")
    if len(raw) > limit:
        _state_unreadable("超过大小上限")
    try:
        after = os.lstat(target)
    except OSError as exc:
        raise R3Failure(f"state: 状态文件不可读（{type(exc).__name__}）",
                        code="state_unreadable") from exc
    # 同一路径的读取前后：同样要比身份与稳定元数据，换出换入或就地改写都拒绝。
    if not _same_unchanged_file(before, after):
        _state_unreadable("读取期间被替换，拒绝使用")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise R3Failure("state: 不是合法 JSON", code="state_unreadable") from exc
    return _validate_state(document), hashlib.sha256(raw).hexdigest()


def _require(condition, message):
    if not condition:
        raise R3Failure(f"state: schema 不符（{message}）",
                        code="state_unreadable")


def _require_keys(document, keys, label):
    """键集必须**恰好**相等：缺键拒绝，未知键同样拒绝（未知字段绝不进报告）。"""
    _require(isinstance(document, dict), f"{label} 不是对象")
    _require(set(document) == keys, f"{label} 键集不符（未知或缺失字段）")


def _validate_environment(environment):
    _require_keys(environment, ENVIRONMENT_KEYS, "环境条目")
    _require(environment["state"] in ENVIRONMENT_STATES,
             "环境状态不在固定词汇表")
    channel = environment["channel"]
    _require(channel is None or channel in ENVIRONMENT_CHANNELS,
             "环境通道不在固定词汇表")
    profile_sha256 = environment["profile_sha256"]
    if environment["state"] == "ready":
        _require(_is_sha256(profile_sha256),
                 "环境 ready 必须带小写十六进制档案摘要")
    else:
        _require(profile_sha256 is None, "环境 required 不得携带档案摘要")
    return {"state": environment["state"], "channel": channel,
            "profile_sha256": profile_sha256}


def _validate_zones(zones):
    _require_keys(zones, ZONES_KEYS, "区域条目")
    grid = zones["grid"]
    _require_keys(grid, GRID_KEYS, "网格")
    for side in ("rows", "cols"):
        _require(_is_int(grid[side]) and grid[side] >= 1,
                 "网格行列必须是正整数（bool 不算整数）")
    zone_count = zones["zone_count"]
    _require(_is_int(zone_count) and zone_count >= 0, "区域计数必须是非负整数")
    _require(_is_sha256(zones["zones_sha256"]),
             "区域摘要必须是小写十六进制")
    return {"grid": {"rows": grid["rows"], "cols": grid["cols"]},
            "zone_count": zone_count,
            "zones_sha256": zones["zones_sha256"]}


def _validate_frame(frame):
    _require_keys(frame, FRAME_KEYS, "帧条目")
    available = frame["available"]
    _require(isinstance(available, bool), "frame.available 必须是布尔值")
    if available:
        _require(_is_int(frame["bytes"]) and frame["bytes"] > 0
                 and _is_sha256(frame["jpeg_sha256"]),
                 "帧可用时必须给出正字节数与小写十六进制摘要")
    else:
        _require(_is_int(frame["bytes"]) and frame["bytes"] == 0
                 and frame["jpeg_sha256"] is None,
                 "帧不可用时字节数必须为 0 且没有摘要")
    return {"available": available, "bytes": frame["bytes"],
            "jpeg_sha256": frame["jpeg_sha256"]}


def _validate_camera(camera):
    _require_keys(camera, CAMERA_KEYS, "相机条目")
    _require(_is_camera_id(camera["camera"]),
             "相机 ID 不是安全非空标识（字母/数字/下划线/连字符且 ≤64）")
    _require(camera["runtime_state"] in RUNTIME_STATES,
             "runtime_state 不在固定词汇表")
    _require(camera["capability"] in CAPABILITY_STATES,
             "capability 不在固定词汇表")
    issue_code = camera["issue_code"]
    # 先判类型再查词表：JSON 里的数组/对象不可哈希，直接做字典成员判断会抛异常，
    # 而不是结构化拒绝。
    _require(issue_code is None or (isinstance(issue_code, str)
                                    and issue_code in ISSUE_ACTIONS),
             "issue_code 不在固定词汇表")
    return {
        "camera": camera["camera"],
        "runtime_state": camera["runtime_state"],
        "capability": camera["capability"],
        "issue_code": issue_code,
        "environment": _validate_environment(camera["environment"]),
        "zones": _validate_zones(camera["zones"]),
        "frame": _validate_frame(camera["frame"]),
    }


def _validate_state(document):
    """校验固定 schema；任何缺口都拒绝，绝不“尽力而为”地继续比较。

    逐层校验每一处证据承载对象（顶层、工作台、运行实例、逐相机、环境、区域、
    网格、帧、计数、检查项），并从相机集合**重算**计数、固定检查项与
    facts/persistence 摘要。未知键、自由文本、路径注入、计数或摘要篡改一律拒绝；
    只有全部通过时才回传显式重建的规范文档，未知字段绝无可能流进最终报告。
    """
    _require_keys(document, STATE_KEYS, "顶层")
    _require(document["schema"] == STATE_SCHEMA, "schema 不匹配")
    _require(document["phase"] == "before", "phase 必须是 before")
    _require(document["evidence_level"] == EVIDENCE_LEVEL,
             "evidence_level 不匹配")
    _require(document["platform"] == "win32", "platform 必须是 win32")
    _require(_is_utc_timestamp(document["captured_at"]),
             "captured_at 必须是 UTC 时间戳")

    workbench = document["workbench"]
    _require_keys(workbench, WORKBENCH_KEYS, "workbench")
    _require(workbench["host"] in ALLOWED_HOSTS, "workbench.host 非回环字面量")
    port = workbench["port"]
    _require(_is_int(port) and 1 <= port <= 65535,
             "workbench.port 必须是 1..65535 的整数（bool 不算整数）")

    runtime = document["runtime"]
    _require_keys(runtime, RUNTIME_KEYS, "runtime")
    _require(_is_instance_id(runtime["runtime_instance_id"]),
             "runtime_instance_id 必须是 32 位小写十六进制")
    _require(_is_utc_timestamp(runtime["started_at"]),
             "started_at 必须是 UTC 时间戳")

    raw_cameras = document["cameras"]
    _require(isinstance(raw_cameras, list) and bool(raw_cameras),
             "cameras 必须是非空数组")
    cameras = []
    ids = set()
    for camera in raw_cameras:
        validated = _validate_camera(camera)
        _require(validated["camera"] not in ids, "相机 ID 重复")
        ids.add(validated["camera"])
        cameras.append(validated)

    counters = document["counters"]
    _require_keys(counters, COUNTERS_KEYS, "counters")
    expected_counters = {
        "camera_count": len(cameras),
        "online_camera_count": sum(1 for camera in cameras
                                   if camera["runtime_state"] == "online"),
        "subject_camera_count": sum(1 for camera in cameras
                                    if _is_subject(camera)),
    }
    for name, value in expected_counters.items():
        _require(_is_int(counters[name]) and counters[name] == value,
                 f"counters.{name} 与相机集合重算不符")

    _require(document["facts_sha256"] == _canonical_sha256(cameras),
             "facts_sha256 与相机集合重算不符")
    _require(document["persistence_sha256"]
             == _canonical_sha256(_persistence_summary(cameras)),
             "persistence_sha256 与守恒摘要重算不符")

    checks = document["checks"]
    _require(isinstance(checks, list), "checks 非数组")
    expected_checks = evaluate_before({"cameras": cameras,
                                       "counters": expected_counters})
    _require(len(checks) == len(expected_checks), "检查项数量不符")
    for stored, wanted in zip(checks, expected_checks):
        _require_keys(stored, CHECK_KEYS, "检查项")
        _require(stored["name"] == wanted["name"], "检查项名称与固定项不符")
        # 结论必须是真正的布尔值（1/0/其它真值一律拒绝），且与重算一致。
        _require(stored["passed"] is wanted["passed"], "检查项结论与重算不符")
        _require(stored["detail"] == wanted["detail"],
                 "检查项说明必须与重算一致（不得夹带自由文本）")

    return {
        "schema": STATE_SCHEMA,
        "phase": "before",
        "evidence_level": EVIDENCE_LEVEL,
        "captured_at": document["captured_at"],
        "platform": "win32",
        "workbench": {"host": workbench["host"], "port": port},
        "runtime": {"runtime_instance_id": runtime["runtime_instance_id"],
                    "started_at": runtime["started_at"]},
        "cameras": cameras,
        "counters": expected_counters,
        "checks": [dict(check) for check in expected_checks],
        "facts_sha256": document["facts_sha256"],
        "persistence_sha256": document["persistence_sha256"],
    }


def publish_report(path, report):
    """同目录临时文件 + fsync + 原子 no-clobber 发布；失败清理临时文件。"""
    target = os.path.abspath(path)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    if os.path.lexists(target):
        raise R3Failure("report: 已存在同名报告，拒绝覆盖",
                        code="report_not_published")
    data = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2)
            + "\n").encode("utf-8")
    temp = f"{target}.tmp-{os.urandom(8).hex()}"
    fd = None
    try:
        fd = os.open(temp, EXCLUSIVE_WRITE_FLAGS, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temp, target)
        except FileExistsError as exc:
            raise R3Failure("report: 并发出现同名报告，拒绝覆盖",
                            code="report_not_published") from exc
        except OSError as exc:
            # 平台不支持硬链接时 fail-closed：绝不用带竞态的 rename 退化。
            raise R3Failure(
                "report: 平台不支持原子 no-clobber 发布，fail-closed"
                f"（{type(exc).__name__}）",
                code="report_not_published") from exc
    finally:
        if fd is not None:
            os.close(fd)
        try:
            if os.path.isfile(temp):
                os.unlink(temp)
        except OSError:
            pass


def _report_error(phase, failure):
    document = {"schema": REPORT_SCHEMA, "phase": phase, "ok": False,
                "error_code": failure.code, "error": str(failure)}
    sys.stderr.write(json.dumps(document, ensure_ascii=False,
                                sort_keys=True) + "\n")
    return 2


def _print_checks(checks):
    for check in checks:
        if not check["passed"]:
            print(f"      - {check['name']}: {check['detail']}")


def run_before(*, state_path, base_url=DEFAULT_BASE_URL, fetch=None,
               current_platform=None):
    """before 阶段：验本机事实并独占写状态文件；任何门禁不过都不落盘。"""
    platform_name = current_platform or current_platform_name()
    if platform_name != "win32":
        raise R3Failure(f"platform: 需要精确 win32（当前 {platform_name}）",
                        code="unsafe_platform")
    workbench = parse_workbench_url(base_url)
    facts, problems = collect_facts(
        workbench, fetch=fetch or make_loopback_fetch(workbench))
    if problems:
        raise R3Failure("; ".join(problems), code="workbench_unreadable")
    checks = evaluate_before(facts)
    passed = all(check["passed"] for check in checks)
    print("[OK] before 阶段通过：本机事实已就绪" if passed
          else "[FAIL] before 阶段未通过：工作台事实不满足 R3 前置条件")
    _print_checks(checks)
    if not passed:
        print("[边界] 未写状态文件；请先完成配置、识别、圈选与在线出图后重跑")
        return 1
    # 落盘的必须是 after 阶段能原样读回的规范文档：写盘前先用同一道固定 schema
    # 自检，绝不留下一份读不回来的“证据”。自检失败说明本机事实凑不出合法状态
    # （不是状态文件坏了），因此用专属错误码，避免误报成“读不回”。
    try:
        state = _validate_state(build_state(facts, checks))
    except R3Failure as exc:
        raise R3Failure(f"state: 本机事实构成不了合法状态文件（自检未过：{exc}）",
                        code="state_schema_invalid") from exc
    write_state_exclusive(state_path, state)
    print(f"[证据] before 状态已独占写入（不覆盖）：{state_path}")
    print("[下一步] 请人工重启值守进程，再运行 after 阶段")
    print("[边界] 本阶段只证明重启前事实，不代表重启后仍成立")
    return 0


def run_after(*, state_path, report_path, fetch=None, current_platform=None):
    """after 阶段：安全读状态、重采事实、按门禁判定并原子发布报告。"""
    platform_name = current_platform or current_platform_name()
    if platform_name != "win32":
        raise R3Failure(f"platform: 需要精确 win32（当前 {platform_name}）",
                        code="unsafe_platform")
    state, state_sha256 = read_state(state_path)
    workbench = parse_workbench_url(format_workbench_url(state["workbench"]))
    facts, problems = collect_facts(
        workbench, fetch=fetch or make_loopback_fetch(workbench))
    if problems:
        raise R3Failure("; ".join(problems), code="workbench_unreadable")
    checks, verdict = evaluate_after(state, facts)
    publish_report(report_path, build_report(state, state_sha256, facts,
                                             checks, verdict))
    passed = all(check["passed"] for check in checks)
    print("[OK] after 阶段通过：重启后事实仍成立" if passed
          else "[FAIL] after 阶段未通过：重启后事实不满足 R3 门禁")
    _print_checks(checks)
    print(f"[证据] 最终报告已原子发布（不覆盖）：{report_path}")
    print("[边界] 只声称 R3 原生重启候选证据；真实模型质量、告警延迟、"
          "干净安装与长稳未验证")
    return 0 if passed else 1


def main(argv=None, *, fetch=None, current_platform=None):
    parser = argparse.ArgumentParser(
        prog="scam-win11-r3-acceptance",
        description="Win11 R3 两阶段原生重启验收：before 采集重启前事实，"
                    "after 复核重启后事实是否仍成立（只读回环工作台，"
                    "不控制进程、不改配置，不代表真实模型质量与长稳）")
    subparsers = parser.add_subparsers(dest="command", required=True)

    before_parser = subparsers.add_parser(
        "before", allow_abbrev=False,
        help="在精确 Win32 上采集重启前事实并独占写状态文件（不覆盖）")
    before_parser.add_argument("--state", required=True, metavar="FILE")
    before_parser.add_argument("--base-url", default=DEFAULT_BASE_URL,
                               metavar="URL")

    after_parser = subparsers.add_parser(
        "after", allow_abbrev=False,
        help="重启后复核事实是否仍成立，并原子发布最终报告（不覆盖）")
    after_parser.add_argument("--state", required=True, metavar="FILE")
    after_parser.add_argument("--report", required=True, metavar="FILE")

    args = parser.parse_args(argv)
    try:
        if args.command == "before":
            return run_before(state_path=args.state, base_url=args.base_url,
                              fetch=fetch, current_platform=current_platform)
        return run_after(state_path=args.state, report_path=args.report,
                         fetch=fetch, current_platform=current_platform)
    except R3Failure as exc:
        # 平台/文件/协议等前置条件不成立：结构化失败，绝不产出半份证据。
        return _report_error(args.command, exc)


if __name__ == "__main__":
    sys.exit(main())
