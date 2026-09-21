"""Win11 首次摄像头接入向导。

只在配置不存在时绑定 127.0.0.1 临时端口；浏览器提交一次后原子创建配置并退出。
向导不自动发现、不自动上传、不自动布防。未提供检测模型时，用户必须明确选择
“仅预览不告警”，避免把无检测能力伪装成可值守状态。
"""

import json
import os
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .config import validate_venue
from .platform import open_browser


_CAMERA_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_MAX_BODY = 16 * 1024


def _clean_source(kind, source):
    if kind not in ("rtsp", "file", "camera"):
        raise ValueError("来源类型必须为 RTSP、本地文件或本机摄像头")
    if not isinstance(source, str) or not source.strip() or len(source) > 2048:
        raise ValueError("来源地址不能为空且不能超过 2048 个字符")
    source = source.strip()
    if any(ord(char) < 32 for char in source):
        raise ValueError("来源地址含有非法控制字符")
    if kind == "rtsp":
        parsed = urlsplit(source)
        if parsed.scheme not in ("rtsp", "rtsps") or not parsed.hostname:
            raise ValueError("RTSP 地址必须以 rtsp:// 或 rtsps:// 开头并包含主机")
    elif kind == "camera" and not source.isdigit():
        raise ValueError("本机摄像头编号必须是 0、1、2 等非负整数")
    return source


def build_initial_venue(payload):
    """把不可信浏览器输入转换为最小场所档案；失败即拒绝。"""
    if not isinstance(payload, dict):
        raise ValueError("请求必须是对象")
    camera_id = payload.get("camera_id")
    if not isinstance(camera_id, str) or not _CAMERA_ID_RE.fullmatch(camera_id):
        raise ValueError("相机 ID 只能包含字母、数字、下划线和连字符")
    kind = payload.get("source_kind")
    source = _clean_source(kind, payload.get("source"))
    model = payload.get("detector_model", "")
    if not isinstance(model, str) or len(model) > 1024:
        raise ValueError("检测模型路径非法")
    model = model.strip()
    monitor_only = payload.get("monitor_only") is True
    if not model and not monitor_only:
        raise ValueError("未提供检测模型时，必须明确选择“仅预览不告警”")

    detector = ({"engine": "onnx", "model": model,
                 "classes": ["person"], "conf": 0.4}
                if model else {"engine": "none"})
    venue = {
        "version": "0.3",
        "venue": "win11-workstation",
        "cameras": [{
            "id": camera_id,
            "enabled": True,
            "source": source,
            "source_kind": kind,
            "detector": detector,
            "record_enabled": False,
            "grid": {"rows": 18, "cols": 22},
            "zones": [],
            "schedule": [{"from": "00:00", "to": "23:59"}],
        }],
    }
    errors = validate_venue(venue)
    if errors:
        raise ValueError("；".join(errors))
    return venue


def write_initial_config(path, venue):
    """独占创建配置，绝不覆盖已有文件；异常时不留下半文件。"""
    target = os.path.abspath(path)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    data = (json.dumps(venue, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8")
    fd = None
    created = False
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        if fd is not None:
            os.close(fd)
        # 仅清理由本次独占创建出的半文件；已有文件因 O_EXCL 从未被打开。
        try:
            if created and os.path.isfile(target):
                os.unlink(target)
        except OSError:
            pass
        raise


def _html(token):
    token_js = json.dumps(token)
    return f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>语义摄像头 · 首次接入</title><style>
:root{{color-scheme:dark;--bg:#09101a;--panel:#121d2b;--line:#31445d;--accent:#35d5a4;
--text:#edf5ff;--muted:#a6b6ca;--danger:#ff7d89}}*{{box-sizing:border-box}}body{{margin:0;
min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 20% 0,#19304a,var(--bg) 45%);
font-family:"Segoe UI","Microsoft YaHei",sans-serif;color:var(--text)}}main{{width:min(720px,100%);
background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:28px;box-shadow:0 28px 90px #0009}}
h1{{margin:.2em 0}}.eyebrow{{color:var(--accent);font-weight:700}}p{{color:var(--muted)}}.grid{{display:grid;
grid-template-columns:1fr 1fr;gap:14px}}label{{display:grid;gap:6px;color:var(--muted)}}.wide{{grid-column:1/-1}}
input,select{{width:100%;padding:11px;border-radius:9px;border:1px solid var(--line);background:#09121e;color:var(--text)}}
.check{{display:flex;align-items:start;gap:9px}}.check input{{width:auto;margin-top:4px}}button{{margin-top:18px;padding:12px 18px;
border:0;border-radius:10px;background:var(--accent);color:#06130f;font-weight:800;cursor:pointer}}#message{{min-height:24px}}
.error{{color:var(--danger)}}@media(max-width:620px){{.grid{{grid-template-columns:1fr}}.wide{{grid-column:auto}}}}</style></head>
<body><main><div class="eyebrow">Windows 11 · 本机设置</div><h1>接入第一路摄像头</h1>
<p>配置只保存到当前 Windows 用户的数据目录。此页面只在本机临时开放，保存后立即关闭。</p>
<div class="grid"><label>相机 ID<input id="camera-id" value="front-door" maxlength="64"></label>
<label>来源类型<select id="source-kind"><option value="rtsp">RTSP 摄像头</option><option value="camera">本机摄像头</option><option value="file">本地视频文件</option></select></label>
<label class="wide">来源地址<input id="source" placeholder="rtsp://用户名:密码@相机地址:554/..."></label>
<label class="wide">人物检测模型路径（ONNX）<input id="model" placeholder="例如 D:\\models\\person-detector.onnx"></label>
<label class="wide check"><input id="monitor-only" type="checkbox"><span>我确认暂时只预览画面、不产生目标告警（未配置检测模型时必须勾选）</span></label></div>
<button id="save">保存并启动值守</button><p id="message" role="status"></p></main><script>
const token={token_js};const message=document.getElementById('message');
document.getElementById('save').onclick=async()=>{{message.className='';message.textContent='正在校验并保存…';
const body={{camera_id:document.getElementById('camera-id').value,source_kind:document.getElementById('source-kind').value,
source:document.getElementById('source').value,detector_model:document.getElementById('model').value,
monitor_only:document.getElementById('monitor-only').checked}};
try{{const response=await fetch('/api/setup',{{method:'POST',headers:{{'Content-Type':'application/json','X-Setup-Token':token}},body:JSON.stringify(body)}});
const data=await response.json();if(!response.ok)throw new Error(data.error||'保存失败');message.textContent='配置已保存，值守正在启动；可以关闭此页面。';
document.getElementById('save').disabled=true}}catch(error){{message.className='error';message.textContent=error.message}}}};
</script></body></html>'''


class SetupState:
    def __init__(self, config_path, token):
        self.config_path = config_path
        self.token = token
        self.saved = threading.Event()


class SetupHandler(BaseHTTPRequestHandler):
    server_version = "SemanticCameraSetup/1"

    def log_message(self, format_, *args):
        return

    def _headers(self, status, content_type, length):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; frame-ancestors 'none'")
        self.end_headers()

    def _json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/":
            self._json({"error": "not found"}, 404)
            return
        body = _html(self.server.state.token).encode("utf-8")
        self._headers(200, "text/html; charset=utf-8", len(body))
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/api/setup":
            self._json({"error": "not found"}, 404)
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip() != \
                "application/json":
            self._json({"error": "只接受 JSON"}, 415)
            return
        if not secrets.compare_digest(
                self.headers.get("X-Setup-Token", ""), self.server.state.token):
            self._json({"error": "设置会话已失效，请重新启动"}, 403)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > _MAX_BODY:
            self._json({"error": "请求大小非法"}, 413)
            return
        try:
            payload = json.loads(self.rfile.read(length))
            venue = build_initial_venue(payload)
            write_initial_config(self.server.state.config_path, venue)
        except FileExistsError:
            self._json({"error": "配置已经存在，未做覆盖"}, 409)
            return
        except (ValueError, OSError, json.JSONDecodeError) as error:
            self._json({"error": str(error)}, 400)
            return
        self.server.state.saved.set()
        self._json({"ok": True})
        threading.Thread(target=self.server.shutdown, daemon=True).start()


class SetupServer(ThreadingHTTPServer):
    def __init__(self, state):
        self.state = state
        super().__init__(("127.0.0.1", 0), SetupHandler)
        self.daemon_threads = True


def run_first_use_setup(config_path, browser_opener=open_browser):
    """运行一次本机设置会话；保存成功返回 True，中断/失败返回 False。"""
    token = secrets.token_urlsafe(32)
    state = SetupState(os.path.abspath(config_path), token)
    try:
        server = SetupServer(state)
    except OSError as error:
        print(f"[Win11] 首次接入向导启动失败: {error}")
        return False
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"[Win11] 首次接入向导: {url}")
    try:
        browser_opener(url)
        server.serve_forever()
    except KeyboardInterrupt:
        return False
    finally:
        server.server_close()
    return state.saved.is_set()
