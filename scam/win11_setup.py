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
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .config import validate_venue, validate_l3_config
from .platform import open_browser


_CAMERA_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class SetupRejected(ValueError):
    """向导校验失败：文案由本模块固定产出，可以安全回显给浏览器。"""
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
        # New setup expresses the user's unchecked option explicitly; missing
        # l3 remains a legacy-configuration signal in the runtime.
        "l3": {"enabled": False},
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
    if "l3" in payload:
        l3 = payload["l3"]
        errors = validate_l3_config(l3)
        if errors:
            raise SetupRejected("；".join(errors))
        # 向导只保存已公开的字段；密钥值没有输入框，也不读取环境变量值。
        keys = (("enabled", "provider", "base_url", "model", "key_env",
                 "image_upload_consent", "vision_capable")
                if l3.get("provider", "local") == "cloud" else
                ("enabled", "provider", "model_path"))
        venue["l3"] = {key: l3[key] for key in keys if key in l3}
    errors = validate_venue(venue)
    if errors:
        raise SetupRejected("；".join(errors))
    return venue


def write_initial_config(path, venue):
    """独占创建配置，绝不覆盖已有文件；异常时不留下半文件。"""
    target = os.path.abspath(path)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    data = (json.dumps(venue, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8")
    fd = None
    created = False
    created_identity = None
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        opened = os.fstat(fd)
        created_identity = (opened.st_dev, opened.st_ino)
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
            if created and created_identity is not None:
                current = os.lstat(target)
                if (current.st_dev, current.st_ino) == created_identity:
                    os.unlink(target)
        except OSError:
            pass
        raise


def _html(token, default_model="", ffmpeg_missing=False, recovery=False):
    token_js = json.dumps(token)
    model_value_js = json.dumps(default_model or "")
    model_hint = ("发行包已随附已核验的检测模型（默认填入，可直接使用）；也可改填本机 "
                  "ONNX 文件路径；若要预览模式，请清空本字段并勾选下方勾选框。"
                  if default_model else
                  "请填写本机 ONNX 文件路径（例如 person-detector.onnx）；没有模型文件时，"
                  "必须勾选下方的“仅预览、不告警”。")
    ffmpeg_note = ("<p class=\"field-note error\">录像/片段导出不可用：未找到 ffmpeg。"
                   "预览与管理员规则告警不受影响，录像保持关闭。</p>"
                   if ffmpeg_missing else "")
    recovery_note = ("<p class=\"field-note\">本次将新建替代配置，原配置保留不变。"
                     "仅本次后台使用新配置；重新启动应用仍使用原配置。</p>"
                     if recovery else "")
    return f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>语义摄像头 · 首次接入</title><style>
:root{{color-scheme:dark;--bg:#0b1220;--panel:#131c2b;--line:#2c3d54;--accent:#35d5a4;
--text:#eaf2fc;--muted:#9db0c6;--danger:#ff8b96;--step:#5b718f}}
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:start center;
padding:20px;background:var(--bg);font-family:"Segoe UI","Microsoft YaHei",sans-serif;
color:var(--text);font-size:15px;line-height:1.5}}main{{width:min(640px,100%);margin:auto;
background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px}}
.eyebrow{{color:var(--accent);font-weight:700;font-size:13px}}h1{{margin:.15em 0 .35em;font-size:22px}}
.lead{{color:var(--muted);margin:.2em 0 .9em}}fieldset{{border:1px solid var(--line);border-radius:10px;
margin:0 0 12px;padding:12px 14px}}legend{{padding:0 8px;color:var(--step);font-weight:700;font-size:13px}}
legend .n{{display:inline-block;min-width:20px;height:20px;line-height:20px;text-align:center;border-radius:50%;
background:var(--accent);color:#06130f;font-weight:800;margin-right:6px;font-size:12px}}
label{{display:grid;gap:5px;color:var(--muted);margin-top:10px;font-size:14px}}
label:first-of-type{{margin-top:2px}}input,select{{width:100%;max-width:100%;padding:10px;border-radius:8px;
border:1px solid var(--line);background:#0a1422;color:var(--text);font:inherit}}
input:focus-visible,select:focus-visible,button:focus-visible,a:focus-visible,summary:focus-visible,
input[type="checkbox"]:focus-visible{{outline:2px solid var(--accent);outline-offset:2px}}
.hint{{color:var(--muted);font-size:12.5px;margin:4px 0 0}}.field-note{{font-size:12.5px;margin:4px 0 0}}
.error{{color:var(--danger)}}.err-slot{{display:block;min-height:0;color:var(--danger);font-size:12.5px;margin-top:4px}}
.err-slot:empty{{display:none}}.check{{display:flex;align-items:flex-start;gap:9px;margin-top:12px}}
.check input{{width:auto;margin-top:3px}}.check span{{color:var(--muted);font-size:14px}}
details{{margin-top:14px;border:1px dashed var(--line);border-radius:8px;padding:8px 12px}}
summary{{cursor:pointer;color:var(--muted);font-size:13px}}details p{{color:var(--muted);font-size:13px;margin:8px 0 2px}}
button{{margin-top:6px;padding:12px 20px;border:0;border-radius:9px;background:var(--accent);
color:#06130f;font-weight:800;cursor:pointer;font-size:15px}}button:hover{{filter:brightness(1.08)}}
button:disabled{{opacity:.55;cursor:default;filter:none}}#message{{min-height:22px;margin:12px 0 0}}
#message.ok{{color:var(--accent)}}#message.error{{color:var(--danger)}}
@media(max-width:620px){{body{{padding:10px}}main{{padding:16px}}}}
</style></head>
<body><main>
<div class="eyebrow">Windows 11 · 本机设置</div>
<h1>接入第一路摄像头</h1>
<p class="lead">四步完成接入：选择来源 → 填写连接信息 → 配置检测与理解 → 保存并继续。
本页只在本机临时开放，保存后立即关闭。</p>
{recovery_note}
<form id="setup-form" novalidate>
<fieldset><legend><span class="n">1</span>选择画面来源</legend>
<label>来源类型<select id="source-kind">
<option value="rtsp">RTSP 摄像头（网络摄像头）</option>
<option value="camera">本机摄像头（USB / 内置）</option>
<option value="file">本地视频文件</option></select></label>
<p class="hint" id="kind-hint">网络摄像头填写摄像头的 RTSP 地址。</p>
</fieldset>
<fieldset><legend><span class="n">2</span>填写连接信息</legend>
<label>相机 ID（字母、数字、下划线或连字符）<input id="camera-id" value="front-door" maxlength="64" autocomplete="off"></label>
<span class="err-slot" id="err-camera-id"></span>
<label class="source-label" id="source-label">来源地址<input id="source" placeholder="rtsp://用户名:密码@相机地址:554/Streaming/Channels/101" autocomplete="off" spellcheck="false"></label>
<span class="err-slot" id="err-source"></span>
<p class="hint">凭据只写入本机配置文件，不会出现在本页提示或错误信息里。</p>
</fieldset>
<fieldset><legend><span class="n">3</span>指定已有本地模型（检测）与理解方式</legend>
<label>人物检测模型路径（ONNX，可选）<input id="model" placeholder="例如 D:\\models\\person-detector.onnx" autocomplete="off" spellcheck="false"></label>
<p id="model-hint" class="hint">{model_hint}</p>{ffmpeg_note}
<label class="check"><input id="monitor-only" type="checkbox"><span>我确认暂时只预览画面、不产生目标告警（未配置检测模型时必须勾选）</span></label>
<span class="err-slot" id="err-monitor-only"></span>
<label class="check"><input id="l3-enabled" type="checkbox"><span>启用图片理解（可选；不启用时保持原本地检测 / 预览）</span></label>
<label>理解提供方<select id="l3-provider"><option value="local">本地模型（默认，不外发）</option><option value="cloud">云端图片理解 API（会外发图片）</option></select></label>
<div id="l3-local"><label>本地 L3 模型目录（仅启用本地理解时必填）<input id="l3-model-path" autocomplete="off" spellcheck="false"></label></div>
<div id="l3-cloud" hidden>
<p class="field-note error">云端启用后会把采样图片与理解提示发送给所填服务；可能产生费用。请先确认隐私与服务政策。本页只保存配置，不会测试 API 或上传图片。</p>
<label>HTTPS API 前缀（含 /v1 等完整前缀）<input id="cloud-base-url" placeholder="https://服务地址/v1" autocomplete="off" spellcheck="false"></label>
<label>服务提供的图片模型名称<input id="cloud-model" autocomplete="off" spellcheck="false"></label>
<label>密钥环境变量名（不是密钥内容）<input id="cloud-key-env" placeholder="SEMANTIC_CAMERA_API_KEY" autocomplete="off" spellcheck="false"></label>
<p class="hint">只保存环境变量名；请在启动程序前于本机设置密钥。不在此页填写密钥，也不会读取或回显密钥。并非所有服务模型都支持图片，云端更新不保证答案准确。</p>
<label class="check"><input id="cloud-vision" type="checkbox"><span>我已核对所选服务与模型支持图片输入（本程序尚未验证）</span></label>
<label class="check"><input id="cloud-consent" type="checkbox"><span>我明确同意向所填服务外发采样图片与提示，并知晓可能产生费用</span></label>
</div>
<span class="err-slot" id="err-l3"></span>
</fieldset>
<fieldset><legend><span class="n">4</span>保存并继续</legend>
<button id="save" type="button">保存并启动值守</button>
<p id="message" role="status"></p>
<details><summary>保存与安全说明（点击展开）</summary>
<p>· 配置只保存到当前 Windows 用户的数据目录，不上传。</p>
<p>· 默认本地、不外发；只有显式启用云端理解并同意后，运行时才可按配置发送图片。保存配置不是模型能力或准确性验证。</p>
<p>· 本页只在本机 127.0.0.1 临时开放，保存成功后向导端口立即关闭。</p>
<p>· “配置已保存”表示配置文件已写入并由程序继续启动值守；“相机是否连通”以启动后的工作台画面为准。</p>
<p>· 保存失败时：检查上方标红的字段；若提示配置已存在，直接重新运行程序即可进入值守；若会话失效，请关闭本页并重新运行程序。</p>
</details>
</fieldset>
</form>
</main><script>
const token={token_js};
const message=document.getElementById('message');
const saveBtn=document.getElementById('save');
const form=document.getElementById('setup-form');
const kindSel=document.getElementById('source-kind');
const sourceInput=document.getElementById('source');
const KIND_HINTS={{rtsp:'网络摄像头填写摄像头的 RTSP 地址。',camera:'本机摄像头填写编号：0 是第一个摄像头，1 是第二个，以此类推。',file:'本地视频文件填写完整文件路径（例如 D:\\\\videos\\\\entrance.mp4）。'}};
const PLACEHOLDERS={{rtsp:'rtsp://用户名:密码@相机地址:554/Streaming/Channels/101',camera:'0',file:'D:\\\\videos\\\\entrance.mp4'}};
const SOURCE_LABELS={{rtsp:'RTSP 地址',camera:'本机摄像头编号',file:'视频文件路径'}};
function setErr(id,text){{const slot=document.getElementById('err-'+id);if(slot)slot.textContent=text||'';}}
function clearErrs(){{['camera-id','source','monitor-only','l3'].forEach(k=>setErr(k,''));}}
function localValidate(body){{
  const errs=[];
  if(!/^[A-Za-z0-9_-]{{1,64}}$/.test(body.camera_id)){{errs.push(['camera-id','相机 ID 只能包含字母、数字、下划线和连字符（1–64 位）']);}}
  const src=body.source||'';
  const trimmed=src.trim();
  if(!trimmed){{errs.push(['source','来源地址不能为空']);}}
  else if(src.length>2048){{errs.push(['source','来源地址不能超过 2048 个字符']);}}
  else if(/[\\x00-\\x1f]/.test(trimmed)){{errs.push(['source','来源地址含有非法控制字符']);}}
  else if(body.source_kind==='rtsp'&&!/^rtsps?:\\/\\//i.test(trimmed)){{errs.push(['source','RTSP 地址必须以 rtsp:// 或 rtsps:// 开头']);}}
  else if(body.source_kind==='rtsp'&&!/^rtsps?:\\/\\/[^\\/?#]+/i.test(trimmed)){{errs.push(['source','RTSP 地址必须包含主机']);}}
  else if(body.source_kind==='rtsp'){{try{{const u=new URL(trimmed.replace(/^rtsps?:/i,'http:'));if(!u.hostname)errs.push(['source','RTSP 地址必须包含主机']);}}catch(e){{errs.push(['source','RTSP 地址必须包含主机']);}}}}
  else if(body.source_kind==='camera'&&!/^\\d+$/.test(src.trim())){{errs.push(['source','本机摄像头编号必须是 0、1、2 等非负整数']);}}
  if((body.detector_model||'').length>1024){{errs.push(['monitor-only','检测模型路径非法（过长）']);}}
  if(!body.detector_model.trim()&&!body.monitor_only){{errs.push(['monitor-only','未提供检测模型时，必须勾选“仅预览、不告警”']);}}
  if(body.l3&&body.l3.enabled){{
    if(body.l3.provider==='local'&&!body.l3.model_path.trim()){{errs.push(['l3','启用本地图片理解时需填写本地 L3 模型目录']);}}
    if(body.l3.provider==='cloud'){{
      const c=body.l3;
      let valid=false;
      try{{const u=new URL(c.base_url);valid=u.protocol==='https:'&&!!u.hostname&&!u.username&&!u.password&&!/[\\s?#\\\\]/.test(c.base_url);}}catch(e){{}}
      if(!valid||!c.model.trim()||!/^[A-Za-z_][A-Za-z0-9_]{{0,127}}$/.test(c.key_env)){{errs.push(['l3','请检查 HTTPS API 前缀、图片模型名与密钥环境变量名']);}}
      if(!c.vision_capable||!c.image_upload_consent){{errs.push(['l3','请确认图片能力并明确同意外发图片；不同意请保留本地或关闭图片理解']);}}
    }}
  }}
  return errs;
}}
const l3Provider=document.getElementById('l3-provider');
function resetCloudConsent(){{document.getElementById('cloud-consent').checked=false;}}
function syncL3Options(){{
  const enabled=document.getElementById('l3-enabled').checked;
  const cloud=enabled&&l3Provider.value==='cloud';
  l3Provider.disabled=!enabled;
  document.getElementById('l3-local').hidden=!enabled||cloud;
  document.getElementById('l3-cloud').hidden=!cloud;
  resetCloudConsent();document.getElementById('cloud-vision').checked=false;
}}
l3Provider.addEventListener('change',syncL3Options);
document.getElementById('l3-enabled').addEventListener('change',syncL3Options);
syncL3Options();
['cloud-base-url','cloud-model','cloud-key-env'].forEach(id=>document.getElementById(id).addEventListener('input',resetCloudConsent));
kindSel.addEventListener('change',()=>{{
  document.getElementById('kind-hint').textContent=KIND_HINTS[kindSel.value]||'';
  document.getElementById('source-label').firstChild.textContent=(SOURCE_LABELS[kindSel.value]||'来源地址');
  sourceInput.placeholder=PLACEHOLDERS[kindSel.value]||'';
  setErr('source','');
}});
form.addEventListener('submit',e=>e.preventDefault());
saveBtn.addEventListener('click',async()=>{{
  if(saveBtn.disabled)return;
  clearErrs();
  const body={{camera_id:document.getElementById('camera-id').value,
    source_kind:kindSel.value,source:sourceInput.value,
    detector_model:document.getElementById('model').value,
    monitor_only:document.getElementById('monitor-only').checked}};
  if(document.getElementById('l3-enabled').checked){{
    body.l3={{enabled:true,provider:l3Provider.value}};
    if(l3Provider.value==='cloud'){{Object.assign(body.l3,{{
      base_url:document.getElementById('cloud-base-url').value,
      model:document.getElementById('cloud-model').value,
      key_env:document.getElementById('cloud-key-env').value,
      vision_capable:document.getElementById('cloud-vision').checked,
      image_upload_consent:document.getElementById('cloud-consent').checked}});}}
    else{{body.l3.model_path=document.getElementById('l3-model-path').value;}}
  }}
  const errs=localValidate(body);
  if(errs.length){{
    errs.forEach(([id,text])=>setErr(id,text));
    const first=document.getElementById('err-'+errs[0][0]);
    const target=document.getElementById(errs[0][0]);
    if(target)target.focus();
    message.className='error';
    message.textContent='请先修正标红的字段，再保存。';
    return;
  }}
  saveBtn.disabled=true;
  message.className='';
  message.textContent='保存中…';
  try{{
    const response=await fetch('/api/setup',{{method:'POST',
      headers:{{'Content-Type':'application/json','X-Setup-Token':token}},
      body:JSON.stringify(body)}});
    let data={{}};try{{data=await response.json();}}catch(e){{}}
    if(response.ok){{
      message.className='ok';
      message.textContent='配置已保存，值守正在启动；此向导已完成，可以关闭此页面。';
      saveBtn.disabled=true;
      return;
    }}
    saveBtn.disabled=false;
    message.className='error';
    if(response.status===403){{
      message.textContent='设置会话已失效：请关闭此页面，重新运行程序打开新的设置向导。';
      saveBtn.disabled=true;
    }}else if(response.status===409){{
      message.textContent='配置已存在，本向导未做修改：直接重新运行程序即可进入值守。';
    }}else{{
      const safeErrors=new Set([
        '云端密钥缺失：请设置本机环境变量后重新运行程序。',
        '云端服务拒绝请求：请核对密钥与模型权限后重试。',
        '云端请求超时：请检查网络或稍后重试。']);
      const detail=safeErrors.has(data.error)?data.error:'保存失败（错误码 E-W11-003）：请重试，或改用本机已有模型 / 勾选“仅预览、不告警”';
      message.textContent=detail+' 请检查上方字段后重试。';
    }}
  }}catch(error){{
    saveBtn.disabled=false;
    message.className='error';
    message.textContent='无法连接本机设置服务：请确认本页地址为本机运行程序弹出，然后重试。';
  }}
}});
document.getElementById('model').value={model_value_js};
</script></body></html>'''


class SetupState:
    def __init__(self, config_path, token, *, default_model_path=None,
                 ffmpeg_available=True, recovery_source=None):
        self.config_path = config_path
        self.token = token
        self.default_model_path = default_model_path
        self.ffmpeg_available = ffmpeg_available
        self.saved = threading.Event()
        self.recovery_source = recovery_source
        self.saved_config_path = None


@dataclass(frozen=True)
class SetupOutcome:
    configured: bool
    config_path: object = None


def create_alternate_config(source, payload):
    # Lazy import avoids the recovery service's setup-validation dependency.
    from .win11_recovery import create_alternate_config as create
    return create(source, payload)


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
        state = self.server.state
        body = _html(state.token,
                     default_model=state.default_model_path or "",
                     ffmpeg_missing=not state.ffmpeg_available,
                     recovery=state.recovery_source is not None).encode("utf-8")
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
            if self.server.state.recovery_source is not None:
                result = create_alternate_config(
                    self.server.state.recovery_source, payload)
                self.server.state.saved_config_path = result.candidate_path
            else:
                venue = build_initial_venue(payload)
                write_initial_config(self.server.state.config_path, venue)
                self.server.state.saved_config_path = self.server.state.config_path
        except FileExistsError:
            self._json({"error": "配置已经存在，未做覆盖"}, 409)
            return
        except (ValueError, OSError, RuntimeError, json.JSONDecodeError) as error:
            if isinstance(error, SetupRejected):
                # 校验文案由本模块自己产出（固定中文），不含外部输入原文
                self._json({"error": str(error)}, 400)
            else:
                # 其它异常原文（可能夹带路径/凭据）不得进入浏览器
                self._json({"error": "保存失败（错误码 E-W11-003）："
                                    "请重试，或改用本机已有模型 / 勾选“仅预览、不告警”"}, 400)
            return
        self.server.state.saved.set()
        self._json({"ok": True})
        if getattr(self.server, "shutdown_on_saved", True):
            threading.Thread(target=self.server.shutdown, daemon=True).start()


class SetupServer(ThreadingHTTPServer):
    def __init__(self, state):
        self.state = state
        super().__init__(("127.0.0.1", 0), SetupHandler)
        self.daemon_threads = True


def run_first_use_setup(config_path, browser_opener=open_browser, *,
                        default_model_path=None, ffmpeg_available=None,
                        stop_event=None, recovery_source=None):
    """运行一次本机设置会话；保存成功返回 True，中断/失败返回 False。

    default_model_path：发行包随附模型的绝对路径（预填；用户仍可清空改用预览模式）。
    ffmpeg_available：显式告知录像能力，None 时按本机探测；缺失不阻断预览与告警。
    stop_event：可选（默认 None → 与既有行为完全一致）。桌面壳请求停止时置位，
    向导不再等待用户保存，正常关闭并释放临时 HTTP 服务（不强杀、不落盘）。
    """
    if ffmpeg_available is None:
        from .platform import find_ffmpeg
        ffmpeg_available = find_ffmpeg() is not None
    token = secrets.token_urlsafe(32)
    state = SetupState(os.path.abspath(config_path), token,
                       default_model_path=default_model_path,
                       ffmpeg_available=ffmpeg_available,
                       recovery_source=recovery_source)
    try:
        server = SetupServer(state)
    except OSError as error:
        # 异常原文可能夹带路径或端口细节：只报固定错误码。
        from .win11_launcher import report_error
        report_error("E-W11-002")
        return False
    # handle_request polling exits on state.saved; shutdown() is only valid
    # against serve_forever, otherwise its waiter never completes.
    server.shutdown_on_saved = stop_event is None
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"[Win11] 首次接入向导: {url}")
    if not ffmpeg_available:
        print("[Win11] 录像/片段导出不可用：未找到 ffmpeg（预览与告警不受影响）")
    try:
        browser_opener(url)
        if stop_event is None:
            server.serve_forever()          # 旧路径：行为不变
        else:
            server.timeout = 0.2            # 可取消：保存或停止请求都立即结束
            while not state.saved.is_set() and not stop_event.is_set():
                server.handle_request()
    except KeyboardInterrupt:
        return False
    finally:
        server.server_close()               # 释放临时端口（不等用户保存）
    if recovery_source is not None:
        return SetupOutcome(state.saved.is_set(), state.saved_config_path)
    return state.saved.is_set()
