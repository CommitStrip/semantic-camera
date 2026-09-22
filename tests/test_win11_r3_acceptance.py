"""ZW-006 测试：R3 两阶段重启驱动的回环围栏、门禁、隐私与文件围栏。

全部用例使用纯本机假 HTTP（函数注入），不联网、不开端口、不控制任何进程；
假 HTTP 只存在于测试内——生产入口没有模拟通道，也没有 fake 分支。
"""

import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import socket
from urllib.parse import unquote, urlsplit

import pytest

import scam.win11_r3_acceptance as r3

REPO = Path(__file__).resolve().parents[1]
SOURCE = (REPO / "scam" / "win11_r3_acceptance.py").read_text(encoding="utf-8")

JPEG = b"\xff\xd8\xff\xe0" + bytes(24) + b"\xff\xd9"
PNG = b"\x89PNG\r\n\x1a\n" + bytes(16)
INSTANCE_BEFORE = "1" * 32
INSTANCE_AFTER = "2" * 32
STARTED_BEFORE = "2026-09-21T09:00:00+00:00"
STARTED_AFTER = "2026-09-21T10:00:00+00:00"

# 夹具里真实存在的敏感值：摄像头 source（含用户名密码）、模型/DB/JSON 绝对路径、
# 环境/区域/规则自由文本与原始帧。证据里只许有固定状态、计数、摘要与时间。
SOURCE_URL = "rtsp://admin:s3cr3t@192.168.1.10:554/stream1"
SOURCE_PARTS = urlsplit(SOURCE_URL)
MODEL_PATH = "C:\\Models\\person.onnx"
DB_PATH = "C:\\Data\\scam.db"
CONFIG_PATH = "C:\\Data\\cameras.json"
_PATH_NAMES = tuple(PureWindowsPath(path).name
                    for path in (MODEL_PATH, DB_PATH, CONFIG_PATH))
SCENE_TEXT = "前门通道 夜间模式"
ZONE_NAME = "卸货区"
RULE_TEXT = "person"
# source 按组成部分逐项断言：只查整串会漏掉“只落盘主机名或口令”的部分泄露。
SENSITIVE_VALUES = (
    SOURCE_URL,
    f"{SOURCE_PARTS.username}:{SOURCE_PARTS.password}",
    SOURCE_PARTS.password,
    SOURCE_PARTS.hostname,
    MODEL_PATH, DB_PATH, CONFIG_PATH,
    *_PATH_NAMES,
    SCENE_TEXT, ZONE_NAME, RULE_TEXT,
)


def _profile():
    """环境档案：故意夹带自由文本与模型/DB/JSON 绝对路径，用来证明它们不落盘。"""
    return {
        "scene": SCENE_TEXT,
        "provider": "local",
        "model": MODEL_PATH,
        "db": DB_PATH,
        "config": CONFIG_PATH,
        "analyzed_at": 1758000000.0,
        "frame_sha256": "a" * 64,
    }


def _zones():
    """区域：故意夹带区域名称与规则文本，用来证明它们不落盘。"""
    return [{"id": "zone-1", "name": ZONE_NAME, "cells": [1, 2, 3],
             "rules": [RULE_TEXT]}]


class FakeWorkbench:
    """纯本机假工作台：只按固定路由回放文档（其中夹带 source、凭据与 DB/JSON
    绝对路径），并记录每一次请求。"""

    def __init__(self, *, instance_id=INSTANCE_BEFORE,
                 started_at=STARTED_BEFORE):
        self.instance_id = instance_id
        self.started_at = started_at
        self.calls = []
        self.cameras = {}

    def add_camera(self, camera_id, *, state="online", capability="alerting",
                   issue_code=None, profile="ready", zones="ready",
                   jpeg=True):
        self.cameras[camera_id] = {
            "state": state,
            "capability": capability,
            "issue_code": issue_code,
            # profile=None 表示没有环境档案（工作台报 required）
            "profile": _profile() if profile == "ready" else profile,
            "zones": _zones() if zones == "ready" else zones,
            "jpeg": jpeg,
        }
        return self.cameras[camera_id]

    def restart(self, *, instance_id=INSTANCE_AFTER,
                started_at=STARTED_AFTER):
        """模拟“用户重启进程”：只有运行实例身份变化，事实由调用方决定。"""
        self.instance_id = instance_id
        self.started_at = started_at

    @staticmethod
    def _json(document, status=200):
        return {"status": status, "content_type": "application/json",
                "body": json.dumps(document, ensure_ascii=False).encode()}

    def fetch(self, method, path):
        self.calls.append((method, path))
        if method != "GET":
            raise AssertionError("R3 驱动只允许只读 GET")
        if path == "/api/health":
            entries = [{
                "camera": camera_id,
                "state": camera["state"],
                "capability": camera["capability"],
                "issue": ({"code": camera["issue_code"], "action": "固定动作"}
                          if camera["issue_code"] else None),
                "hint": "固定提示",
                # 夹带 source：驱动只能取固定字段，URL 与凭据一律不得进证据。
                "source": SOURCE_URL,
            } for camera_id, camera in sorted(self.cameras.items())]
            return self._json({
                "cameras": [], "count": 0,
                # 录像/索引快照里夹带 DB 与 cameras.json 绝对路径。
                "recording": [{"camera": camera_id, "index_db": DB_PATH,
                               "config": CONFIG_PATH}
                              for camera_id in sorted(self.cameras)],
                "runtime": {"cameras": entries, "count": len(entries)},
                "runtime_instance": {"runtime_instance_id": self.instance_id,
                                     "started_at": self.started_at},
            })
        for prefix in ("/api/environment/", "/api/zones/", "/api/frame/"):
            if not path.startswith(prefix):
                continue
            camera_id = unquote(path[len(prefix):])
            camera = self.cameras.get(camera_id)
            if camera is None:
                return self._json({"error": "camera not found"}, 404)
            if prefix == "/api/environment/":
                profile = camera["profile"]
                # 与工作台同一条规则（scam/server.py：档案为真值即 ready）。
                return self._json({
                    "camera": camera_id, "profile": profile,
                    "state": "ready" if profile else "required",
                    "channel": "local",
                })
            if prefix == "/api/zones/":
                return self._json({
                    "camera": camera_id, "grid": {"rows": 18, "cols": 22},
                    "zones": camera["zones"], "runtime": "active",
                    "revision": 1, "pending": False,
                })
            if camera["jpeg"] is True:
                return {"status": 200, "content_type": "image/jpeg",
                        "body": JPEG}
            if camera["jpeg"] == "png":
                return {"status": 200, "content_type": "image/png",
                        "body": PNG}
            if camera["jpeg"] == "bad-magic":
                return {"status": 200, "content_type": "image/jpeg",
                        "body": bytes(32)}
            return self._json({"error": "frame unavailable", "state": "offline"},
                              503)
        return self._json({"error": "not found"}, 404)


def _default_workbench():
    workbench = FakeWorkbench()
    workbench.add_camera("front")
    return workbench


def _before(state_path, workbench, *, platform="win32"):
    return r3.main(["before", "--state", str(state_path)],
                   fetch=workbench.fetch, current_platform=platform)


def _after(state_path, report_path, workbench, *, platform="win32"):
    return r3.main(["after", "--state", str(state_path),
                    "--report", str(report_path)],
                   fetch=workbench.fetch, current_platform=platform)


def _values(node):
    """文档里所有字符串**值**。

    键名与固定词汇表标识（如未验证清单里的 ``real_rtsp_stream``）是 schema 词汇，
    不是被采集的事实；协议名出现在其中只说明边界诚实，不构成泄露。
    """
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _values(value)
    elif isinstance(node, list):
        for item in node:
            yield from _values(item)


def _served_values(response):
    """假工作台一次响应里解码后的全部字符串值（按值判定，不看原始转义文本）。"""
    return set(_values(json.loads(response["body"].decode("utf-8"))))


def _assert_no_secrets(path):
    """证据里只许有固定状态、计数、摘要与时间：夹具里真实的敏感值一个都不许有。"""
    raw = Path(path).read_bytes()
    assert JPEG not in raw, "证据文件不得内嵌原始帧"
    document = json.loads(raw.decode("utf-8"))
    for text in _values(document):
        for sensitive in SENSITIVE_VALUES:
            assert sensitive not in text, f"证据泄露了 {sensitive!r}: {text!r}"
        # 结构性围栏：值里不得出现绝对路径、Windows 分隔符或 URL。
        assert not re.search(r"[A-Za-z]:[\\/]", text), text
        assert "\\" not in text and "://" not in text, text


def _state_path(tmp_path):
    return tmp_path / "r3-state.json"


def _report_path(tmp_path):
    return tmp_path / "r3-report.json"


def _passing_before(tmp_path):
    """跑通一次 before，返回 (工作台, 状态文件路径)。"""
    workbench = _default_workbench()
    state_path = _state_path(tmp_path)
    assert _before(state_path, workbench) == 0
    return workbench, state_path


# ---------- 1. 回环围栏：只允许 http 加回环字面量 ----------

@pytest.mark.parametrize("url", [
    "http://192.168.1.10:8600",     # 私有地址
    "http://10.0.0.5:8600",
    "http://8.8.8.8:8600",          # 公网地址
    "http://[::2]:8600",            # 非回环 IPv6
    "http://example.com:8600",      # 任意主机名
    "https://127.0.0.1:8600",       # 非 http
    "http://user:secret@127.0.0.1:8600",   # 携带凭据
    "http://127.0.0.1:8600/api/health",    # 携带路径
    "http://127.0.0.1:8600/?x=1",          # 携带查询
    "http://127.0.0.1:0",                  # 端口越界
    "http://127.0.0.1:99999",
    "file:///etc/passwd",
])
def test_workbench_url_fence_rejects_everything_but_loopback(url):
    with pytest.raises(r3.R3Failure) as info:
        r3.parse_workbench_url(url)
    assert info.value.code == "unsafe_workbench"


@pytest.mark.parametrize("url", ["http://127.0.0.1:8600",
                                 "http://localhost:8600",
                                 "http://[::1]:8600",
                                 "http://127.0.0.1:8600/"])
def test_workbench_url_fence_accepts_only_the_three_loopback_forms(url):
    workbench = r3.parse_workbench_url(url)
    assert workbench["host"] in r3.ALLOWED_HOSTS
    # 状态文件里存的是固定词汇表，重新拼回地址仍必须过同一道围栏：
    # IPv6 字面量少一个方括号就会被解析成别的主机（或直接拒绝）。
    assert r3.parse_workbench_url(
        r3.format_workbench_url(workbench)) == workbench


def test_off_loopback_target_is_rejected_before_any_request(tmp_path):
    """非回环地址必须在发请求前就被拒绝：注入的 fetch 一次也不许被调用。"""
    def _forbidden_fetch(method, path):
        raise AssertionError("非回环目标不得发起任何请求")

    code = r3.main(["before", "--state", str(_state_path(tmp_path)),
                    "--base-url", "http://192.168.1.10:8600"],
                   fetch=_forbidden_fetch, current_platform="win32")
    assert code == 2
    assert not _state_path(tmp_path).exists()


def test_loopback_alias_requires_every_resolved_address_to_be_loopback(
        monkeypatch):
    def _mixed(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]

    monkeypatch.setattr(r3.socket, "getaddrinfo", _mixed)
    with pytest.raises(r3.R3Failure) as info:
        r3._loopback_connect_host("localhost")
    assert info.value.code == "unsafe_workbench"

    def _all_loopback(host, port, **kwargs):
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(r3.socket, "getaddrinfo", _all_loopback)
    assert r3._loopback_connect_host("localhost") == "127.0.0.1"


def test_loopback_transport_is_get_only_and_never_follows_redirects(
        monkeypatch):
    """连通层只发 GET、只连回环字面量，并把 3xx 当普通状态码回传。"""
    seen = {}

    class _FakeResponse:
        status = 302
        def getheader(self, name):
            return "text/html"

        def read(self):
            return b"moved"

    class _FakeConnection:
        def __init__(self, host, port, timeout=None):
            seen["target"] = (host, port)

        def request(self, method, path):
            seen["request"] = (method, path)

        def getresponse(self):
            return _FakeResponse()

        def close(self):
            seen["closed"] = True

    monkeypatch.setattr(r3.http.client, "HTTPConnection", _FakeConnection)
    fetch = r3.make_loopback_fetch({"host": "localhost", "port": 8600})
    response = fetch("GET", "/api/health")

    assert seen["target"] == ("127.0.0.1", 8600), "只许连回环字面量"
    assert seen["request"] == ("GET", "/api/health")
    assert response["status"] == 302, "重定向只能作为状态码回传，绝不跟随"
    assert seen["closed"] is True

    with pytest.raises(r3.R3Failure):
        fetch("POST", "/api/zones/save")


# ---------- 2. 两阶段成功：实例变化 + 事实守恒 ----------

def test_two_phase_restart_verifies_instance_change_and_persistence(tmp_path):
    workbench, state_path = _passing_before(tmp_path)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["schema"] == r3.STATE_SCHEMA
    assert state["phase"] == "before"
    assert state["runtime"]["runtime_instance_id"] == INSTANCE_BEFORE
    assert state["counters"]["camera_count"] == 1
    assert state["counters"]["subject_camera_count"] == 1

    workbench.restart()
    report_path = _report_path(tmp_path)
    assert _after(state_path, report_path, workbench) == 0

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["schema"] == r3.REPORT_SCHEMA
    assert report["verdict"]["process_restart_verified"] is True
    assert report["verdict"]["r3_persistence_verified"] is True
    for name in r3.FIXED_NULL_VERDICTS:
        assert report["verdict"][name] is None, "五项固定门禁恒为 null"
        assert name in report["not_verified"], "恒为 null 的门禁必须列入未验证"
    assert report["before"]["runtime_instance_id"] == INSTANCE_BEFORE
    assert report["after"]["runtime_instance_id"] == INSTANCE_AFTER
    assert report["before"]["state_sha256"] == r3.hashlib.sha256(
        state_path.read_bytes()).hexdigest()
    assert all(check["passed"] for check in report["checks"])


def test_two_phase_only_issues_read_only_gets(tmp_path):
    """全程只读：没有任何写配置、改区域或控制进程的请求。"""
    workbench, state_path = _passing_before(tmp_path)
    workbench.restart()
    assert _after(state_path, _report_path(tmp_path), workbench) == 0

    assert workbench.calls, "必须真的采集过事实"
    assert {method for method, _ in workbench.calls} == {"GET"}
    paths = {path for _, path in workbench.calls}
    assert all(path.startswith("/api/") for path in paths)
    assert not any(segment in path for path in paths
                   for segment in ("save", "analyze", "feedback", "reviewed"))


def test_after_requires_facts_and_state_across_a_user_restart(tmp_path):
    """重启后事实仍成立才叫 R3 候选证据；实例身份必须来自状态文件而非重报。"""
    workbench, state_path = _passing_before(tmp_path)
    workbench.restart(instance_id=INSTANCE_AFTER,
                      started_at=STARTED_AFTER)
    report_path = _report_path(tmp_path)
    assert _after(state_path, report_path, workbench) == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["before"]["started_at"] == STARTED_BEFORE
    assert report["after"]["started_at"] == STARTED_AFTER


# ---------- 3. 同实例拒绝：进程没重启就不许声称重启 ----------

def test_after_rejects_unchanged_runtime_instance(tmp_path):
    workbench, state_path = _passing_before(tmp_path)
    report_path = _report_path(tmp_path)

    assert _after(state_path, report_path, workbench) == 1
    report = json.loads(report_path.read_text(encoding="utf-8"))
    # 同实例下两个 R3 结论必须同时为 false：事实一致只说明“没重启过”，
    # 证明不了“重启后事实仍成立”。
    assert report["verdict"]["process_restart_verified"] is False
    assert report["verdict"]["r3_persistence_verified"] is False
    failed = {check["name"] for check in report["checks"]
              if not check["passed"]}
    assert failed == {"runtime_instance_changed"}


def test_persistence_verdict_requires_instance_change_and_every_fact_leg(
        tmp_path):
    """持久化结论是“确已重启”与四项事实检查的**合取**，缺一不可。"""
    workbench, state_path = _passing_before(tmp_path)

    # 同一份状态、同一份事实：实例未变化 → 双双 false。
    document, _ = r3.read_state(state_path)
    facts, problems = r3.collect_facts(document["workbench"],
                                      fetch=workbench.fetch)
    assert problems == []
    _, verdict = r3.evaluate_after(document, facts)
    assert verdict["process_restart_verified"] is False
    assert verdict["r3_persistence_verified"] is False

    # 换成重启后的实例、事实不动：两个结论才随之成立。
    workbench.restart()
    restarted, problems = r3.collect_facts(document["workbench"],
                                           fetch=workbench.fetch)
    assert problems == []
    _, verdict = r3.evaluate_after(document, restarted)
    assert verdict["process_restart_verified"] is True
    assert verdict["r3_persistence_verified"] is True


# ---------- 4. 事实漂移拒绝：相机集合 / 环境 / 区域 ----------

def test_after_rejects_zone_drift(tmp_path):
    workbench, state_path = _passing_before(tmp_path)
    workbench.cameras["front"]["zones"] = [
        {"id": "zone-1", "name": ZONE_NAME, "cells": [3, 4, 5],
         "rules": [RULE_TEXT]}]
    workbench.restart()
    report_path = _report_path(tmp_path)

    assert _after(state_path, report_path, workbench) == 1
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["verdict"]["process_restart_verified"] is True
    assert report["verdict"]["r3_persistence_verified"] is False
    failed = {check["name"] for check in report["checks"]
              if not check["passed"]}
    assert failed == {"zone_summary_unchanged"}


def test_after_rejects_environment_drift(tmp_path):
    workbench, state_path = _passing_before(tmp_path)
    workbench.cameras["front"]["profile"]["analyzed_at"] = 1758999999.0
    workbench.restart()
    report_path = _report_path(tmp_path)

    assert _after(state_path, report_path, workbench) == 1
    failed = {check["name"] for check in
              json.loads(report_path.read_text(encoding="utf-8"))["checks"]
              if not check["passed"]}
    assert failed == {"environment_summary_unchanged"}


@pytest.mark.parametrize("drift", ["camera_added", "camera_removed"])
def test_after_rejects_camera_set_drift(tmp_path, drift):
    workbench, state_path = _passing_before(tmp_path)
    if drift == "camera_added":
        workbench.add_camera("yard")
    else:
        del workbench.cameras["front"]
    workbench.restart()
    report_path = _report_path(tmp_path)

    assert _after(state_path, report_path, workbench) == 1
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["verdict"]["r3_persistence_verified"] is False
    failed = {check["name"] for check in report["checks"]
              if not check["passed"]}
    # 相机集合变了，逐相机摘要自然也不再一一对应：三者必须一起报出来。
    assert "camera_set_unchanged" in failed
    assert "environment_summary_unchanged" in failed
    assert "zone_summary_unchanged" in failed


def test_after_rejects_missing_online_jpeg_frame(tmp_path):
    """重启后相机没回来/没有 JPEG 帧：事实守恒但“仍在线出图”不成立。"""
    workbench, state_path = _passing_before(tmp_path)
    workbench.cameras["front"]["state"] = "connecting"
    workbench.cameras["front"]["jpeg"] = False
    workbench.restart()
    report_path = _report_path(tmp_path)

    assert _after(state_path, report_path, workbench) == 1
    report = json.loads(report_path.read_text(encoding="utf-8"))
    # 实例确实变了（重启成立），但持久化结论被在线出图这一条否掉。
    assert report["verdict"]["process_restart_verified"] is True
    assert report["verdict"]["r3_persistence_verified"] is False
    failed = {check["name"] for check in report["checks"]
              if not check["passed"]}
    assert failed == {"online_jpeg_present"}


# ---------- 5. before 门禁：离线 / 无环境 / 无区域 / 非 JPEG ----------

@pytest.mark.parametrize("fault,expected", [
    ({"state": "stopped"}, "camera_online"),
    ({"profile": None}, "environment_ready"),
    ({"zones": []}, "zone_configured"),
    ({"jpeg": False}, "frame_jpeg"),
    ({"jpeg": "png"}, "frame_jpeg"),
    ({"jpeg": "bad-magic"}, "frame_jpeg"),
])
def test_before_gate_requires_full_facts_and_writes_nothing(
        tmp_path, capsys, fault, expected):
    workbench = FakeWorkbench()
    workbench.add_camera("front", **fault)
    state_path = _state_path(tmp_path)

    assert _before(state_path, workbench) == 1
    assert not state_path.exists(), "门禁未过绝不写状态文件"
    assert f"- {expected}:" in capsys.readouterr().out, "必须点名未过的门禁"


def test_before_gate_requires_at_least_one_online_camera(tmp_path):
    workbench = FakeWorkbench()
    workbench.add_camera("front", state="connecting")
    workbench.add_camera("yard", state="degraded",
                         issue_code="source_open_failed")
    assert _before(_state_path(tmp_path), workbench) == 1
    assert not _state_path(tmp_path).exists()


def test_non_native_platform_is_structurally_refused(tmp_path):
    """精确 Win32 是前置条件：别的平台连状态文件都不许产生。"""
    workbench = _default_workbench()
    state_path = _state_path(tmp_path)
    assert _before(state_path, workbench, platform="linux") == 2
    assert not state_path.exists()
    assert workbench.calls == [], "平台不对时不得访问工作台"


# ---------- 6. 隐私：状态与报告只留固定状态、计数、时间与摘要 ----------

def test_evidence_never_contains_sources_credentials_paths_or_free_text(tmp_path):
    workbench, state_path = _passing_before(tmp_path)
    workbench.restart()
    report_path = _report_path(tmp_path)
    assert _after(state_path, report_path, workbench) == 0

    # 非真空性：工作台文档确实把 source（含凭据）、DB/JSON 绝对路径与自由文本交给了
    # 驱动——“证据里没有”的断言只有在这个前提成立时才有意义。
    health = _served_values(workbench.fetch("GET", "/api/health"))
    assert {SOURCE_URL, DB_PATH, CONFIG_PATH} <= health
    profile = _served_values(workbench.fetch("GET", "/api/environment/front"))
    assert {SCENE_TEXT, MODEL_PATH} <= profile
    served_zones = _served_values(workbench.fetch("GET", "/api/zones/front"))
    assert {ZONE_NAME, RULE_TEXT} <= served_zones
    assert workbench.fetch("GET", "/api/frame/front")["body"] == JPEG

    _assert_no_secrets(state_path)
    _assert_no_secrets(report_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    # 固定未验证标识里含协议名（real_rtsp_stream）：它是诚实边界词汇，必须原样保留。
    # 正因值域里存在它，隐私判定只能按实际敏感值断言，不能扫协议名或 schema 键。
    for name in r3.NOT_VERIFIED:
        assert name in report["not_verified"], "合法未验证字段不得删除"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    environment = state["cameras"][0]["environment"]
    assert set(environment) == {"state", "channel", "profile_sha256"}
    assert re.fullmatch(r"[0-9a-f]{64}", environment["profile_sha256"])
    zones = state["cameras"][0]["zones"]
    assert set(zones) == {"grid", "zone_count", "zones_sha256"}
    assert zones["zone_count"] == 1
    assert re.fullmatch(r"[0-9a-f]{64}", zones["zones_sha256"])


def test_health_payload_of_driver_facts_carries_no_camera_free_text(tmp_path):
    """驱动保存的相机事实只有固定状态与摘要：没有环境/区域原文的字段名。"""
    workbench, state_path = _passing_before(tmp_path)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    camera = state["cameras"][0]
    assert set(camera) == {"camera", "runtime_state", "capability",
                           "issue_code", "environment", "zones", "frame"}
    assert camera["runtime_state"] == "online"
    assert camera["capability"] == "alerting"


# ---------- 7. 文件围栏：状态文件与报告的读写安全 ----------

def test_state_read_fence_rejects_missing_directory_oversize_and_bad_schema(
        tmp_path):
    workbench = _default_workbench()
    report_path = _report_path(tmp_path)

    missing = tmp_path / "nope.json"
    assert _after(missing, report_path, workbench) == 2
    assert not report_path.exists()

    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")
    assert _after(empty, report_path, workbench) == 2

    directory = tmp_path / "dir.json"
    directory.mkdir()
    assert _after(directory, report_path, workbench) == 2

    oversize = tmp_path / "big.json"
    oversize.write_bytes(b"a" * (r3.MAX_STATE_BYTES + 1))
    assert _after(oversize, report_path, workbench) == 2

    truncated = tmp_path / "truncated.json"
    truncated.write_bytes(b'{"schema": "scam.win11-r3-state/v1"')
    assert _after(truncated, report_path, workbench) == 2

    assert not report_path.exists(), "状态不可读时绝不发布报告"


@pytest.mark.parametrize("mutation", [
    {"schema": "other/v1"},
    {"phase": "after"},
    {"runtime": {"runtime_instance_id": "", "started_at": STARTED_BEFORE}},
    {"runtime": {"runtime_instance_id": INSTANCE_BEFORE, "started_at": "2026-09-21T09:00:00"}},
    {"workbench": {"host": "192.168.1.10", "port": 8600}},
    {"cameras": "not-a-list"},
])
def test_state_schema_fence_rejects_tampered_documents(tmp_path, mutation):
    workbench, state_path = _passing_before(tmp_path)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state.update(mutation)
    state_path.write_text(json.dumps(state, ensure_ascii=False),
                          encoding="utf-8")

    report_path = _report_path(tmp_path)
    assert _after(state_path, report_path, workbench) == 2
    assert not report_path.exists()


def test_state_counters_must_match_camera_set(tmp_path):
    workbench, state_path = _passing_before(tmp_path)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["counters"]["camera_count"] = 99
    state_path.write_text(json.dumps(state, ensure_ascii=False),
                          encoding="utf-8")
    assert _after(state_path, _report_path(tmp_path), workbench) == 2


def test_state_read_fence_rejects_symlink(tmp_path):
    target = tmp_path / "real-state.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link-state.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("当前环境不允许创建符号链接")

    with pytest.raises(r3.R3Failure) as info:
        r3.read_state(link)
    assert info.value.code == "state_unreadable"


def test_before_never_overwrites_existing_state(tmp_path):
    state_path = _state_path(tmp_path)
    state_path.write_text("既有状态：绝不覆盖", encoding="utf-8")

    assert _before(state_path, _default_workbench()) == 2
    assert state_path.read_text(encoding="utf-8") == "既有状态：绝不覆盖"


def test_report_publish_never_overwrites_and_leaves_no_temp(tmp_path):
    workbench, state_path = _passing_before(tmp_path)
    workbench.restart()
    report_path = _report_path(tmp_path)
    report_path.write_text("既有报告：绝不覆盖", encoding="utf-8")

    assert _after(state_path, report_path, workbench) == 2
    assert report_path.read_text(encoding="utf-8") == "既有报告：绝不覆盖"
    assert list(tmp_path.glob("r3-report.json.tmp-*")) == [], "临时文件必须清理"


def test_report_publish_failure_is_fail_closed_and_cleans_temp(tmp_path,
                                                              monkeypatch):
    """平台不支持原子发布时 fail-closed：绝不退化成覆盖式 rename。"""
    workbench, state_path = _passing_before(tmp_path)
    workbench.restart()

    def _unsupported(source, target):
        raise OSError("hardlink unsupported")

    monkeypatch.setattr(r3.os, "link", _unsupported)
    report_path = _report_path(tmp_path)
    assert _after(state_path, report_path, workbench) == 2
    assert not report_path.exists()
    assert list(tmp_path.glob("r3-report.json.tmp-*")) == [], "临时文件必须清理"


# ---------- 8. CLI 退出码与只读边界 ----------

def test_cli_exit_codes_cover_pass_gate_failure_and_precondition(tmp_path):
    workbench, state_path = _passing_before(tmp_path)
    report_path = _report_path(tmp_path)

    # 门禁不过 → 1（同实例）
    assert _after(state_path, report_path, workbench) == 1
    report_path.unlink()

    # 事实成立 + 实例变化 → 0
    workbench.restart()
    assert _after(state_path, report_path, workbench) == 0

    # 平台不精确 win32 → 2
    assert _after(state_path, tmp_path / "other.json", workbench,
                  platform="darwin") == 2


def test_cli_requires_an_explicit_phase_and_prints_help(capsys):
    with pytest.raises(SystemExit) as info:
        r3.main([], current_platform="win32")
    assert info.value.code == 2

    with pytest.raises(SystemExit) as info:
        r3.main(["--help"], current_platform="win32")
    assert info.value.code == 0
    assert "before" in capsys.readouterr().out


def test_driver_never_controls_processes_or_ships_a_fake_mode():
    """只读边界是文本契约：没有子进程、没有网络库、没有模拟开关。"""
    for forbidden in ("subprocess", "os.system", "Popen", "shutil.which",
                      "socket.create_connection", "requests",
                      "--fake", "--simulate", "--dry-run", "POST"):
        assert forbidden not in SOURCE, f"驱动不得出现 {forbidden!r}"


def test_driver_only_writes_the_two_declared_artifacts():
    """写入点收敛：只允许独占创建状态文件与原子发布报告。"""
    assert SOURCE.count("os.open(") == 3          # 状态写、状态读、报告写
    for forbidden in ("os.replace", "os.rename", "shutil.copy"):
        assert forbidden not in SOURCE, f"不得使用可覆盖的发布路径 {forbidden!r}"
    assert "os.link" in SOURCE, "报告发布必须是原子 no-clobber"


# ---------- 9. 状态读取身份：路径与 fd 必须始终绑定同一个文件 ----------

def _decoy_state(tmp_path, state_path):
    """另存一份同样合法的状态副本：内容一样，身份不同。"""
    decoy = tmp_path / "decoy-state.json"
    decoy.write_bytes(state_path.read_bytes())
    return decoy


def test_state_read_binds_the_opened_fd_to_the_checked_path(tmp_path,
                                                            monkeypatch):
    """打开出来的 fd 不是刚被复核过的那个文件：必须结构化拒绝。

    真实竞态里攻击者会在“复核路径身份”与“打开”之间把状态文件换成伪造件，读完
    再换回原文件——换回之后前后两次 lstat 完全一致，路径级检查一律通过，只有
    “已打开 fd 是否仍是被检查过的那个文件”这一步能把差异暴露出来。Windows 不允许
    重命名一个正被句柄打开的文件，所以这里直接把打开重定向到另一份同内容的伪造件
    （路径本身前后不变，等价于“已换回”的终态），验证的正是同一条 fd 身份围栏；
    整个读取窗口里只许打开一次，不许重试。
    """
    workbench, state_path = _passing_before(tmp_path)
    decoy = _decoy_state(tmp_path, state_path)
    real_open = r3.os.open
    opens = []

    def _swapping_open(path, flags, mode=0o777):
        if os.path.abspath(str(path)) == str(state_path):
            opens.append(str(path))
            return real_open(str(decoy), flags, mode)
        return real_open(path, flags, mode)

    monkeypatch.setattr(r3.os, "open", _swapping_open)
    report_path = _report_path(tmp_path)
    assert _after(state_path, report_path, workbench) == 2
    assert not report_path.exists(), "状态身份不一致时绝不发布报告"
    assert len(opens) == 1, "身份不一致必须立即失败，不许重开或重试"


def test_state_read_accepts_windows_path_and_fd_metadata_divergence(
        tmp_path, monkeypatch):
    """Windows/NTFS：路径 stat 与句柄 stat 共享身份，但元数据的表示可以不同。

    同一文件的 ``lstat(path)`` 与 ``fstat(fd)`` 可能报出不同的 size/mtime/ctime
    表示（设备号/文件索引/类型仍然一致）。这不是“换文件”，合法状态必须读得回来：
    把跨 API 的元数据当成身份，正常 after 会直接变成 ``state_unreadable``（本用例
    即该失败的回归）。同一套表示差异之下，换入另一个文件依旧必须拒绝，证明身份
    围栏没有被一起放宽。
    """
    workbench, state_path = _passing_before(tmp_path)
    real_lstat, real_fstat = r3.os.lstat, r3.os.fstat
    path_stats, fd_stats = [], []

    def _divergent_lstat(path):
        info = real_lstat(path)
        if os.path.abspath(str(path)) != str(state_path):
            return info
        fields = list(info)
        fields[6] += 1                  # 路径口径的大小表示差 1 字节
        fields[8] -= 0.5                # 路径口径的 mtime 表示差半秒
        fields[9] += 0.5                # 路径口径的 ctime 表示差半秒
        shifted = type(info)(fields)
        path_stats.append(shifted)
        return shifted

    def _watched_fstat(fd):
        info = real_fstat(fd)
        fd_stats.append(info)
        return info

    monkeypatch.setattr(r3.os, "lstat", _divergent_lstat)
    monkeypatch.setattr(r3.os, "fstat", _watched_fstat)

    # 集成面：这条差异必须不再把正常的 after 打成“状态不可读”。
    workbench.restart()
    report_path = _report_path(tmp_path)
    assert _after(state_path, report_path, workbench) == 0, \
        "身份一致而元数据表示不同时，after 必须通过"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["verdict"]["r3_persistence_verified"] is True

    # 先证明这条回归真的在模拟“身份相同、元数据表示不同”，否则断言是空洞的。
    assert len(path_stats) == 2 and len(fd_stats) == 2, \
        "一次读取只做读取前后各一次路径/句柄复核"
    assert r3._file_identity(path_stats[0]) == r3._file_identity(fd_stats[0])
    assert r3._file_metadata(path_stats[0]) != r3._file_metadata(fd_stats[0])

    # 直接读 API：内容与摘要不受表示差异影响，schema 键集依旧精确。
    document, state_sha256 = r3.read_state(state_path)
    assert state_sha256 == hashlib.sha256(
        state_path.read_bytes()).hexdigest()
    assert document["schema"] == r3.STATE_SCHEMA
    assert document["phase"] == "before"
    assert set(document) == r3.STATE_KEYS

    # 同一套差异之下换入另一个同内容文件：身份不同，必须结构化拒绝。
    decoy = _decoy_state(tmp_path, state_path)
    real_open = r3.os.open

    def _swapping_open(path, flags, mode=0o777):
        if os.path.abspath(str(path)) == str(state_path):
            return real_open(str(decoy), flags, mode)
        return real_open(path, flags, mode)

    monkeypatch.setattr(r3.os, "open", _swapping_open)
    with pytest.raises(r3.R3Failure) as info:
        r3.read_state(state_path)
    assert info.value.code == "state_unreadable"


def test_state_read_rejects_path_metadata_drift_after_read(tmp_path,
                                                           monkeypatch):
    """同一路径的读取前后仍比“身份 + 大小 + 时间”：身份不变而元数据漂移必须拒绝。

    Windows 的表示差异只允许存在于**跨 API**的比对里；读取前后两次 lstat 出自同一
    口径，任何差异都是真实的就地改写，不能被这条兼容性放宽顺带放过。
    """
    workbench, state_path = _passing_before(tmp_path)
    real_lstat = r3.os.lstat
    calls = []

    def _mutating_lstat(path):
        info = real_lstat(path)
        if os.path.abspath(str(path)) != str(state_path):
            return info
        calls.append(info)
        if len(calls) == 1:
            return info
        fields = list(info)
        fields[6] += 1                  # 读取后：同一个文件在读取窗口里被就地改写
        return type(info)(fields)

    monkeypatch.setattr(r3.os, "lstat", _mutating_lstat)
    with pytest.raises(r3.R3Failure) as info:
        r3.read_state(state_path)
    assert info.value.code == "state_unreadable"
    assert len(calls) == 2, "读取前后各复核一次路径，绝不多查一次"


def test_state_read_rejects_path_replacement_after_read(tmp_path, monkeypatch):
    """读取后的路径复核换成另一个文件：身份不同，必须拒绝（换出换入的终态）。"""
    workbench, state_path = _passing_before(tmp_path)
    decoy = _decoy_state(tmp_path, state_path)
    real_lstat = r3.os.lstat
    calls = []

    def _foreign_lstat(path):
        info = real_lstat(path)
        if os.path.abspath(str(path)) != str(state_path):
            return info
        calls.append(info)
        if len(calls) == 1:
            return info
        return os.stat(decoy)           # 读取后：路径已指向另一个文件

    monkeypatch.setattr(r3.os, "lstat", _foreign_lstat)
    with pytest.raises(r3.R3Failure) as info:
        r3.read_state(state_path)
    assert info.value.code == "state_unreadable"
    assert len(calls) == 2, "读取前后各复核一次路径，绝不多查一次"


def test_state_read_rejects_fd_metadata_drift_after_read(tmp_path,
                                                         monkeypatch):
    """同一个 fd 在读取后被就地改写（大小/时间漂移）：结构化拒绝。"""
    workbench, state_path = _passing_before(tmp_path)
    real_fstat = r3.os.fstat
    calls = []

    def _drifting_fstat(fd):
        info = real_fstat(fd)
        calls.append(info.st_size)
        if len(calls) == 1:
            return info
        fields = list(info)
        fields[6] += 1                      # st_size：读取后复核必须发现差异
        return type(info)(fields)

    monkeypatch.setattr(r3.os, "fstat", _drifting_fstat)
    with pytest.raises(r3.R3Failure) as info:
        r3.read_state(state_path)
    assert info.value.code == "state_unreadable"
    assert len(calls) == 2, "读取前后各复核一次 fd，绝不多读一次"


def test_state_read_rejects_fd_identity_change_after_read(tmp_path,
                                                          monkeypatch):
    """读取后的 fd 身份变成另一个文件：即使同目录同卷也必须拒绝。"""
    workbench, state_path = _passing_before(tmp_path)
    decoy = _decoy_state(tmp_path, state_path)
    real_fstat = r3.os.fstat
    calls = []

    def _foreign_fstat(fd):
        calls.append(fd)
        if len(calls) == 1:
            return real_fstat(fd)
        return os.stat(decoy)

    monkeypatch.setattr(r3.os, "fstat", _foreign_fstat)
    with pytest.raises(r3.R3Failure) as info:
        r3.read_state(state_path)
    assert info.value.code == "state_unreadable"


@pytest.mark.parametrize("fault", ["open", "fstat_open", "read", "fstat_close",
                                   "lstat_close"])
def test_state_read_fails_closed_on_stat_open_and_read_errors(tmp_path,
                                                              monkeypatch,
                                                              fault):
    """stat/open/读取任一步报错都收敛为结构化状态不可读，不重开不重试。"""
    workbench, state_path = _passing_before(tmp_path)
    real_open, real_read = r3.os.open, r3.os.read
    real_fstat, real_lstat = r3.os.fstat, r3.os.lstat
    opens = []
    calls = {"fstat": 0, "lstat": 0, "read": 0}

    def _open(path, flags, mode=0o777):
        if os.path.abspath(str(path)) == str(state_path):
            opens.append(str(path))
            if fault == "open":
                raise OSError("injected open failure")
        return real_open(path, flags, mode)

    def _fstat(fd):
        calls["fstat"] += 1
        if (fault == "fstat_open" and calls["fstat"] == 1) \
                or (fault == "fstat_close" and calls["fstat"] == 2):
            raise OSError("injected fstat failure")
        return real_fstat(fd)

    def _read(fd, size):
        calls["read"] += 1
        if fault == "read" and calls["read"] == 1:
            raise OSError("injected read failure")
        return real_read(fd, size)

    def _lstat(path):
        calls["lstat"] += 1
        if fault == "lstat_close" and calls["lstat"] == 2:
            raise OSError("injected lstat failure")
        return real_lstat(path)

    monkeypatch.setattr(r3.os, "open", _open)
    monkeypatch.setattr(r3.os, "fstat", _fstat)
    monkeypatch.setattr(r3.os, "read", _read)
    monkeypatch.setattr(r3.os, "lstat", _lstat)

    with pytest.raises(r3.R3Failure) as info:
        r3.read_state(state_path)
    assert info.value.code == "state_unreadable"
    assert len(opens) == 1, "任何读取失败都不许重开状态文件"


def test_after_never_publishes_a_report_when_the_read_is_interrupted(
        tmp_path, monkeypatch):
    """集成面：读取被中途打断时退出码 2、不发布报告、不残留临时文件。"""
    workbench, state_path = _passing_before(tmp_path)
    workbench.restart()
    real_read = r3.os.read

    def _interrupted_read(fd, size):
        raise OSError("injected read failure")

    monkeypatch.setattr(r3.os, "read", _interrupted_read)
    report_path = _report_path(tmp_path)
    assert _after(state_path, report_path, workbench) == 2
    assert not report_path.exists()
    monkeypatch.setattr(r3.os, "read", real_read)
    assert list(tmp_path.glob("r3-report.json.tmp-*")) == []


# ---------- 10. 固定 schema：未知字段、敏感注入与摘要/计数篡改 ----------

def _set(document, path, value):
    """按路径改写状态文档里的一个字段（仅测试篡改使用）。"""
    node = document
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value


def _tampered_state(tmp_path, mutate):
    """跑通一次 before，按 mutate 篡改状态文件，并把工作台切换到“已重启”。"""
    workbench, state_path = _passing_before(tmp_path)
    document = json.loads(state_path.read_text(encoding="utf-8"))
    mutate(document)
    state_path.write_text(json.dumps(document, ensure_ascii=False),
                          encoding="utf-8")
    workbench.restart()
    return workbench, state_path


def _assert_state_refused(tmp_path, mutate):
    """被篡改的状态必须结构化拒绝，且绝不发布任何报告。"""
    workbench, state_path = _tampered_state(tmp_path, mutate)
    report_path = _report_path(tmp_path)
    assert _after(state_path, report_path, workbench) == 2
    assert not report_path.exists(), "状态不可信时绝不发布报告"


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda s: _set(s, ("unknown",), SOURCE_URL), id="root-extra"),
    pytest.param(lambda s: s.pop("counters"), id="root-missing"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "note"), SCENE_TEXT),
                 id="camera-extra"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "environment", "scene"),
                                SCENE_TEXT), id="environment-extra"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "zones", "name"), ZONE_NAME),
                 id="zones-extra"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "zones", "grid", "unit"),
                                "cell"), id="grid-extra"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "frame", "path"),
                                MODEL_PATH), id="frame-extra"),
    pytest.param(lambda s: _set(s, ("counters", "note"), RULE_TEXT),
                 id="counters-extra"),
    pytest.param(lambda s: _set(s, ("runtime", "pid"), 4242),
                 id="runtime-extra"),
    pytest.param(lambda s: _set(s, ("workbench", "url"), SOURCE_URL),
                 id="workbench-extra"),
    pytest.param(lambda s: _set(s, ("checks", 0, "detail_extra"), RULE_TEXT),
                 id="check-extra"),
])
def test_state_schema_rejects_unknown_fields_anywhere(tmp_path, mutate):
    """顶层与每个证据承载对象的键集必须精确：未知字段一律拒绝。"""
    _assert_state_refused(tmp_path, mutate)


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda s: _set(s, ("cameras", 0, "camera"), MODEL_PATH),
                 id="camera-id-path"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "camera"), "../../etc/passwd"),
                 id="camera-id-traversal"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "camera"), ""),
                 id="camera-id-empty"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "camera"), "a" * 65),
                 id="camera-id-oversize"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "camera"), SCENE_TEXT),
                 id="camera-id-free-text"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "runtime_state"), MODEL_PATH),
                 id="runtime-state-free-text"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "capability"), SOURCE_URL),
                 id="capability-not-in-vocabulary"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "issue_code"), DB_PATH),
                 id="issue-code-not-in-vocabulary"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "environment", "state"),
                                CONFIG_PATH), id="environment-state-free-text"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "environment", "channel"),
                                SOURCE_URL), id="channel-free-text"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "environment", "state"),
                                "required"), id="environment-required-with-digest"),
    pytest.param(lambda s: _set(s, ("checks", 3, "detail"), SOURCE_URL),
                 id="check-detail-injection"),
    pytest.param(lambda s: _set(s, ("checks", 0, "name"), RULE_TEXT),
                 id="check-name-not-fixed"),
    pytest.param(lambda s: _set(s, ("runtime", "runtime_instance_id"), SOURCE_URL),
                 id="instance-id-injection"),
    pytest.param(lambda s: _set(s, ("captured_at",), SCENE_TEXT),
                 id="captured-at-free-text"),
    pytest.param(lambda s: _set(s, ("facts_sha256",), SOURCE_URL),
                 id="facts-digest-injection"),
])
def test_state_schema_rejects_free_text_and_path_injection(tmp_path, mutate):
    """自由文本、绝对路径、URL 与凭据注入：一律拒绝，绝不落进报告。"""
    _assert_state_refused(tmp_path, mutate)


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda s: _set(s, ("workbench", "port"), 0), id="port-zero"),
    pytest.param(lambda s: _set(s, ("workbench", "port"), 65536),
                 id="port-oversize"),
    pytest.param(lambda s: _set(s, ("workbench", "port"), True),
                 id="port-bool"),
    pytest.param(lambda s: _set(s, ("workbench", "port"), "8600"),
                 id="port-string"),
    pytest.param(lambda s: _set(s, ("workbench", "port"), 8600.0),
                 id="port-float"),
    pytest.param(lambda s: _set(s, ("workbench", "host"), "192.168.1.10"),
                 id="host-off-loopback"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "zones", "grid", "rows"), 0),
                 id="grid-rows-zero"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "zones", "grid", "cols"), -4),
                 id="grid-cols-negative"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "zones", "grid", "rows"),
                                True), id="grid-rows-bool"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "zones", "zone_count"), -1),
                 id="zone-count-negative"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "zones", "zone_count"), True),
                 id="zone-count-bool"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "frame", "available"), 1),
                 id="frame-available-int"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "frame", "bytes"), True),
                 id="frame-bytes-bool"),
])
def test_state_schema_rejects_bad_types_ports_and_vocabulary(tmp_path, mutate):
    """端口/网格/计数的整数语义（bool 不算整数）与固定词表逐条拒绝。"""
    _assert_state_refused(tmp_path, mutate)


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda s: _set(s, ("runtime", "runtime_instance_id"),
                                "A" * 32), id="instance-id-uppercase"),
    pytest.param(lambda s: _set(s, ("runtime", "runtime_instance_id"),
                                "z" * 32), id="instance-id-not-hex"),
    pytest.param(lambda s: _set(s, ("runtime", "runtime_instance_id"),
                                "1" * 31), id="instance-id-short"),
    pytest.param(lambda s: _set(s, ("runtime", "started_at"),
                                "2026-09-21T09:00:00+08:00"), id="started-at-offset"),
    pytest.param(lambda s: _set(s, ("runtime", "started_at"),
                                "2026-09-21 09:00:00"), id="started-at-space"),
    pytest.param(lambda s: _set(s, ("runtime", "started_at"),
                                "2026-13-45T99:99:99+00:00"),
                 id="started-at-out-of-range"),
    pytest.param(lambda s: _set(s, ("captured_at",), "2026-09-21T09:00:00"),
                 id="captured-at-naive"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "environment", "profile_sha256"),
                                "A" * 64), id="profile-digest-uppercase"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "environment", "profile_sha256"),
                                None), id="profile-digest-missing"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "environment", "profile_sha256"),
                                "a" * 63), id="profile-digest-short"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "zones", "zones_sha256"),
                                "not-a-digest"), id="zones-digest-not-hex"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "frame", "jpeg_sha256"), None),
                 id="jpeg-digest-missing"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "frame", "jpeg_sha256"),
                                "b" * 63), id="jpeg-digest-short"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "frame", "bytes"), 0),
                 id="jpeg-bytes-zero-while-available"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "frame", "available"), False),
                 id="jpeg-unavailable-with-digest"),
])
def test_state_schema_rejects_bad_timestamps_identifiers_and_hashes(
        tmp_path, mutate):
    """定长小写十六进制标识/摘要、UTC 时间戳与帧可用性一致性逐条拒绝。"""
    _assert_state_refused(tmp_path, mutate)


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda s: _set(s, ("counters", "camera_count"), 2),
                 id="camera-count-mismatch"),
    pytest.param(lambda s: _set(s, ("counters", "online_camera_count"), 0),
                 id="online-count-mismatch"),
    pytest.param(lambda s: _set(s, ("counters", "subject_camera_count"), 0),
                 id="subject-count-mismatch"),
    pytest.param(lambda s: _set(s, ("counters", "camera_count"), True),
                 id="camera-count-bool"),
    pytest.param(lambda s: _set(s, ("checks", 0, "passed"), 1),
                 id="check-passed-int"),
    pytest.param(lambda s: _set(s, ("checks", 4, "passed"), False),
                 id="check-verdict-flipped"),
    pytest.param(lambda s: s["checks"].pop(), id="check-missing"),
    pytest.param(lambda s: s["checks"].append(
        {"name": "extra_verified", "passed": True, "detail": "自行补写"}),
        id="check-appended"),
    pytest.param(lambda s: _set(s, ("cameras",), []), id="cameras-empty"),
])
def test_state_schema_rejects_count_and_check_tampering(tmp_path, mutate):
    """计数必须与相机集合重算一致，检查项必须是固定项且结论/说明一致。"""
    _assert_state_refused(tmp_path, mutate)


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda s: _set(s, ("facts_sha256",), "e" * 64),
                 id="facts-digest-tampered"),
    pytest.param(lambda s: _set(s, ("facts_sha256",),
                                s["facts_sha256"][:-1]
                                + ("0" if s["facts_sha256"][-1] != "0"
                                   else "1")), id="facts-digest-flipped"),
    pytest.param(lambda s: _set(s, ("persistence_sha256",), "e" * 64),
                 id="persistence-digest-tampered"),
    pytest.param(lambda s: _set(s, ("persistence_sha256",),
                                s["facts_sha256"]),
                 id="persistence-digest-swapped"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "environment",
                                    "profile_sha256"), "c" * 64),
                 id="profile-digest-tampered"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "zones", "zones_sha256"),
                                "d" * 64), id="zones-digest-tampered"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "frame", "jpeg_sha256"),
                                "e" * 64), id="jpeg-digest-tampered"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "issue_code"), []),
                 id="issue-code-unhashable"),
    pytest.param(lambda s: _set(s, ("cameras", 0, "issue_code"), {}),
                 id="issue-code-object"),
])
def test_state_schema_rejects_digest_tampering(tmp_path, mutate):
    """层内摘要即被聚合摘要覆盖：facts/persistence 从相机集合重算，改一处即拒绝。

    非字符串故障码（JSON 数组/对象）也必须被结构化拒绝——不可哈希的值直接做词表
    成员判断会抛异常而不是 fail-closed。
    """
    _assert_state_refused(tmp_path, mutate)


def test_valid_state_round_trips_and_digests_are_recomputed(tmp_path):
    """合法状态必须读得回来，且计数/守恒摘要能与相机集合**独立重算**对上。

    这里的规范 JSON 与守恒定义刻意在测试里重写一遍（不复用驱动内部函数）：若驱动
    悄悄改了规范形式或改了“什么算守恒事实”，即便自洽也会在这里被抓住。
    """
    workbench, state_path = _passing_before(tmp_path)
    document, state_sha256 = r3.read_state(state_path)

    assert set(document) == r3.STATE_KEYS
    assert state_sha256 == hashlib.sha256(
        state_path.read_bytes()).hexdigest()
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    cameras = raw["cameras"]

    def _canonical(payload):
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    assert document["facts_sha256"] == _canonical(cameras)
    # 守恒事实的定义：相机集合 + 环境档案规范摘要 + 区域规范摘要。
    assert document["persistence_sha256"] == _canonical({
        "camera_set": sorted(camera["camera"] for camera in cameras),
        "environments": {camera["camera"]: camera["environment"]
                         for camera in cameras},
        "zones": {camera["camera"]: {"zone_count":
                                     camera["zones"]["zone_count"],
                                     "zones_sha256":
                                     camera["zones"]["zones_sha256"]}
                  for camera in cameras},
    })
    # 计数：逐项独立重算（主体相机 = 在线 + 环境 ready + 有区域 + 当前帧为 JPEG）。
    assert document["counters"] == {
        "camera_count": len(cameras),
        "online_camera_count": sum(1 for camera in cameras
                                   if camera["runtime_state"] == "online"),
        "subject_camera_count": sum(
            1 for camera in cameras
            if camera["runtime_state"] == "online"
            and camera["environment"]["state"] == "ready"
            and camera["zones"]["zone_count"] >= 1
            and camera["frame"]["available"]),
    }
    assert [check["name"] for check in document["checks"]] == [
        check["name"] for check in raw["checks"]]
    assert all(set(camera) == r3.CAMERA_KEYS
               for camera in document["cameras"])
    assert set(document["workbench"]) == r3.WORKBENCH_KEYS
    assert set(document["runtime"]) == r3.RUNTIME_KEYS

    # 读回的重建文档再交给同一道 schema 也必须通过（幂等）。
    assert set(r3._validate_state(document)) == r3.STATE_KEYS


def test_workbench_side_unhashable_issue_code_is_refused_structurally(tmp_path):
    """工作台把故障码写成非字符串：结构化拒绝（退出码 2），不许抛异常、不落盘。"""
    workbench = _default_workbench()
    real_fetch = workbench.fetch

    def _bad_fetch(method, path):
        response = real_fetch(method, path)
        if path != "/api/health":
            return response
        document = json.loads(response["body"].decode("utf-8"))
        document["runtime"]["cameras"][0]["issue"] = {"code": [], "action": "x"}
        return {"status": 200, "content_type": "application/json",
                "body": json.dumps(document, ensure_ascii=False).encode()}

    state_path = _state_path(tmp_path)
    assert r3.main(["before", "--state", str(state_path)],
                   fetch=_bad_fetch, current_platform="win32") == 2
    assert not state_path.exists()
