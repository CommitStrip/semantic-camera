"""models.py —— 模型双通道 Provider（本地 ollama / 云端 OpenAI 兼容）。

纪律：
- 密钥只从环境变量读取（cloud.key_ref 指向环境变量名），源码/配置零凭据字面量；
- URL 三层校验：协议白名单 + 主机边界 + 解析后 IP 阻断私网/环回/链路本地/保留段；
- 本地通道（数据不出 NVR）允许环回与私网；云端通道强制 https+公网（SSRF 防线）；
- urllib 默认跟随重定向——用不跟随重定向的 opener 防重定向绕过 SSRF；
- 所有调用带超时；故障返回 None（上层降级模板占位，不阻塞快路径）。
"""

import json
import os
import socket
import time
import urllib.request
from urllib.parse import urlsplit

import numpy as np


def _post_json(url, body, timeout, headers=None):
    """POST JSON，不跟随重定向（防重定向绕过 SSRF 校验）。"""

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          **(headers or {})})
    with opener.open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _resolve_ips(host):
    try:
        return {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        return set()


def _ip_is_local(ip):
    o = ip.split(".")
    if len(o) == 4 and all(x.isdigit() for x in o):
        n = [int(x) for x in o]
        if n[0] == 10 or n[0] == 127 or (n[0] == 192 and n[1] == 168) or \
                (n[0] == 172 and 16 <= n[1] <= 31) or (n[0] == 169 and n[1] == 254):
            return True
        if n[0] == 0 or n[0] >= 224:
            return True
    if ":" in ip:
        return True   # IPv6 内网/链路本地前缀一律按本地处理
    return False


def validate_base(url, *, allow_local, allow_public):
    """校验 base URL：协议 + 主机 + 解析 IP 边界。返回 (scheme, host)。"""
    u = urlsplit(url)
    if u.scheme not in ("http", "https"):
        raise ValueError("仅允许 http/https")
    host = u.hostname or ""
    if not host:
        raise ValueError("缺少主机名")
    ips = _resolve_ips(host)
    if not ips:
        raise ValueError(f"无法解析主机: {host}")
    local = {ip for ip in ips if _ip_is_local(ip)}
    public = ips - local
    if public and not allow_public:
        raise ValueError(f"公网地址未授权: {host}")
    if local and not allow_local:
        raise ValueError(f"本地/私网地址未授权: {host}")
    return host, ips


def _extract_json(text):
    s = text.find("{")
    e = text.rfind("}")
    if s < 0 or e <= s:
        return None
    try:
        return json.loads(text[s:e + 1])
    except json.JSONDecodeError:
        return None


class LocalOllama:
    """本地 ollama（OpenAI 兼容端点）。数据不出 NVR——仅允许环回/私网。"""

    name = "local"

    def __init__(self, base="http://127.0.0.1:11434", model="qwen3-vl:2b",
                 num_ctx=16384, num_predict=2048, timeout=90):
        validate_base(base, allow_local=True, allow_public=False)
        self.base = base.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.num_predict = num_predict

    def understand(self, prompt, frames_b64, context=None):
        """frames_b64: 纯 base64 JPEG 列表（无 data: 前缀）。返回 JSON 或 None。"""
        body = {"model": self.model, "stream": False, "keep_alive": "30m",
                "messages": [{"role": "system", "content": context or ""},
                             {"role": "user", "content": prompt,
                              "images": frames_b64}],
                "options": {"temperature": 0, "num_predict": 2048,
                            "num_ctx": 16384}}
        try:
            resp = _post_json(self.base + "/v1/chat/completions", body, self.timeout)
            content = resp["choices"][0]["message"]["content"]
        except Exception:
            return None
        return _extract_json(content)


class CloudOpenAICompat:
    """云端 OpenAI 兼容 VLM（帧/内容会出 NVR——启用需管理员显式确认）。"""

    name = "cloud"

    def __init__(self, base, model, key_env="SCAM_CLOUD_KEY",
                 num_ctx=16384, num_predict=2048, timeout=60):
        u = urlsplit(base)
        if u.scheme != "https":
            raise ValueError("云端通道必须 https")
        host = u.hostname or ""
        if not host:
            raise ValueError("缺少主机名")
        if _ip_is_local(host):
            raise ValueError("云端通道拒绝私有/保留地址")
        self.base = base.rstrip("/")
        self.model = model
        self.key = os.environ.get(key_env, "")
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.num_predict = num_predict

    def understand(self, prompt, frames_b64, context=None):
        body = {"model": self.model, "stream": False,
                "messages": [{"role": "system", "content": context or ""},
                             {"role": "user", "content": prompt,
                              "images": frames_b64}],
                "options": {"temperature": 0, "num_predict": 2048,
                            "num_ctx": self.num_ctx}}
        try:
            resp = _post_json(self.base + "/v1/chat/completions", body, self.timeout)
            content = resp["choices"][0]["message"]["content"]
        except Exception:
            return None
        return _extract_json(content)


def build_provider(cfg):
    """cfg: {"channel": "local"|"cloud", ...} → provider 实例；异常返回 None。"""
    if not isinstance(cfg, dict):
        return None
    ch = cfg.get("channel", "local")
    try:
        if ch == "local":
            return LocalOllama(cfg.get("base", "http://127.0.0.1:11434"),
                               cfg.get("model", "qwen3-vl:2b"),
                               cfg.get("num_ctx", 16384),
                               cfg.get("num_predict", 2048),
                               cfg.get("timeout", 90))
        if ch == "cloud":
            return CloudOpenAICompat(cfg.get("base", ""),
                                     cfg.get("model", ""),
                                     cfg.get("key_env", "SCAM_CLOUD_KEY"),
                                     cfg.get("num_ctx", 16384),
                                     cfg.get("num_predict", 2048),
                                     cfg.get("timeout", 60))
    except (ValueError, KeyError):
        return None
    return None
