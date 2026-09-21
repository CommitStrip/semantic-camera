"""server.py —— 工作台 HTTP 服务：API + 审查时间线 + 告警出口。

内嵌 HTML 零文件 I/O 零路径构造；前端 3 秒轮询刷新。
camera_id 白名单校验（alphanumeric + dash + underscore）——防路径注入。
默认只绑 127.0.0.1（远程访问交 SSH 隧道/反向代理）；
所有状态（区域/事件/模式）均存 SQLite，server 零文件写入。
"""

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import quote, unquote

from .environment import EnvironmentStore
from .evidence import EvidenceStore
from .models import build_provider
from .zones import Grid, normalize_zones

CAMERA_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")

_INDEX_HTML = r'''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>语义摄像头 · 工作台</title>
<style>
:root{color-scheme:dark;--bg:#090d14;--panel:#121a27;--line:#2a3950;
--text:#edf5ff;--muted:#9fb0c5;--accent:#35d5a4;--warn:#ffbf5a;--danger:#ff6b7a}
*{box-sizing:border-box}body{font-family:"Segoe UI","Microsoft YaHei",system-ui,sans-serif;
background:radial-gradient(circle at 20% 0,#16243a 0,var(--bg) 38%);color:var(--text);
margin:0;padding:24px;min-height:100vh}button,input,select{font:inherit}
header{display:flex;justify-content:space-between;gap:16px;align-items:end;margin-bottom:18px}
h1,h2,h3,p{margin-top:0}.eyebrow{color:var(--accent);font-weight:700;letter-spacing:.12em;
text-transform:uppercase;font-size:12px}.subtle,.status{color:var(--muted)}
.layout{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(310px,.75fr);gap:16px}
.card{background:color-mix(in srgb,var(--panel) 92%,transparent);border:1px solid var(--line);
border-radius:16px;padding:18px;box-shadow:0 18px 50px #0005;margin-bottom:16px}
.toolbar,.form-row,.actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
label{display:grid;gap:6px;color:var(--muted);font-size:13px;flex:1;min-width:120px}
input,select{width:100%;background:#0b111c;color:var(--text);border:1px solid var(--line);
border-radius:9px;padding:9px 10px}button{border:1px solid var(--line);background:#18263a;
color:var(--text);border-radius:9px;padding:9px 13px;cursor:pointer}button:hover{border-color:var(--accent)}
button.primary{background:var(--accent);border-color:var(--accent);color:#06120f;font-weight:750}
button.danger{color:#ffd9de}.stage{position:relative;min-height:340px;background:#05080d;border-radius:12px;
overflow:hidden;border:1px solid var(--line);margin-top:14px;display:grid;place-items:center}
.stage img{display:block;width:100%;height:auto;max-height:68vh;object-fit:contain;user-select:none}
.stage .empty{position:absolute;text-align:center;padding:24px;color:var(--muted)}
#zone-grid{position:absolute;inset:0;display:grid;touch-action:none;cursor:crosshair}
.grid-cell{border:1px solid #ffffff16;background:transparent;min-width:0;min-height:0}
.grid-cell.selected{background:#35d5a455;border-color:#7fffd4aa}
.legend{display:flex;justify-content:space-between;gap:12px;margin-top:10px;font-size:13px;color:var(--muted)}
.zone-list{display:grid;gap:8px;margin:12px 0}.zone-item{display:flex;justify-content:space-between;
gap:8px;align-items:center;border:1px solid var(--line);border-radius:10px;padding:9px 10px}
.zone-item.active{border-color:var(--accent);background:#15362f}.pill{border-radius:999px;padding:2px 8px;
background:#223047;color:var(--muted);font-size:12px}.message{min-height:22px;margin-top:10px;color:var(--muted)}
.message.ok{color:var(--accent)}.message.error{color:var(--danger)}
.environment-gate{position:fixed;inset:0;z-index:1000;display:grid;place-items:center;
padding:24px;background:#07101acc;backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px)}
.environment-gate[hidden]{display:none}.environment-panel{width:min(620px,100%);padding:28px;
border:1px solid #5b718f;background:#111b2a;border-radius:18px;box-shadow:0 30px 100px #000b}
.environment-panel ul{margin:10px 0 18px;padding-left:20px;color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:8px 6px;
border-bottom:1px solid var(--line);text-align:left}a{color:#77d9ff}
@media(max-width:900px){body{padding:14px}.layout{grid-template-columns:1fr}.stage{min-height:260px}}
</style></head><body>
<header><div><div class="eyebrow">Windows 11 local-first</div><h1>语义摄像头 · 工作台</h1>
<div class="subtle">先由管理员定义区域和规则，再进入值守。模型建议不会自动成为告警。</div></div>
<div id="health" class="status">本机工作台</div></header>
<main class="layout"><section>
<div class="card" id="zone-editor"><div class="toolbar"><div><h2>区域与规则</h2>
<div class="subtle">点击或拖动网格刷选；绿色格子仅在点击“保存并应用”后生效。</div></div>
<label>相机<select id="camera-select" aria-label="选择相机"></select></label></div>
<div class="stage" id="frame-stage"><img id="zone-frame" alt="当前相机画面">
<div id="frame-empty" class="empty">正在读取当前画面…</div><div id="zone-grid" aria-label="区域网格"></div></div>
<div class="legend"><span id="grid-summary">网格加载中</span><span id="runtime-state">尚未连接运行时</span></div></div>
<div class="card"><h2>审查时间线</h2><table id="review"><thead><tr><th>开始</th><th>相机</th>
<th>级别</th><th>目标数</th><th>状态</th></tr></thead><tbody></tbody></table></div>
<div class="card"><h2>语义事件</h2><table id="events"><thead><tr><th>时间</th><th>短名</th>
<th>详情</th><th>最佳帧</th><th>录像</th></tr></thead><tbody></tbody></table></div>
</section><aside>
<div class="card"><h2>区域配置</h2><div id="zone-list" class="zone-list"></div>
<div class="actions"><button id="new-zone" type="button">新建区域</button>
<button id="clear-cells" type="button" class="danger">清空选格</button>
<button id="delete-zone" type="button" class="danger">删除当前区域</button></div>
<div class="form-row"><label>区域 ID<input id="zone-id" maxlength="48" placeholder="例如 front-door"></label>
<label>区域名称<input id="zone-name" maxlength="48" placeholder="例如 大门口"></label></div>
<div class="form-row"><label>类别<input id="rule-class" maxlength="32" value="person"></label>
<label>规则模板<select id="rule-template"><option value="immediate">进入即告警</option>
<option value="enter-dwell">进入并滞留</option><option value="loiter">持续徘徊</option></select></label></div>
<div class="form-row"><label>滞留秒数<input id="rule-dwell" type="number" min="0" max="86400" step="0.5" value="0"></label>
<label>严重度<select id="rule-severity"><option value="low">低</option><option value="medium">中</option>
<option value="high">高</option><option value="critical">严重</option></select></label></div>
<button id="save-zone" class="primary" type="button">保存并应用管理员规则</button>
<div id="zone-message" class="message" role="status"></div></div>
<div class="card"><h2>模式库</h2><div id="patterns" class="subtle">加载中</div></div>
</aside></main>
<div id="environment-gate" class="environment-gate" role="dialog" aria-modal="true">
<div class="environment-panel"><div class="eyebrow">首次使用 · 必须完成</div>
<h2>先识别环境，再定义报警区域</h2>
<p id="environment-message">正在检查当前相机的环境档案…</p>
<div id="environment-result" hidden><h3>识别建议（不会自动成为报警规则）</h3>
<p id="environment-summary"></p><ul id="environment-suggestions"></ul></div>
<button id="analyze-environment" class="primary" type="button">开始环境识别</button>
<p class="subtle">本地模型默认不上传画面；如选择云模型，本次操作会再次明确确认。</p>
</div></div>
<script>
const ui={camera:document.getElementById('camera-select'),frame:document.getElementById('zone-frame'),
empty:document.getElementById('frame-empty'),grid:document.getElementById('zone-grid'),
summary:document.getElementById('grid-summary'),runtime:document.getElementById('runtime-state'),
list:document.getElementById('zone-list'),message:document.getElementById('zone-message'),
gate:document.getElementById('environment-gate'),envMessage:document.getElementById('environment-message'),
envResult:document.getElementById('environment-result'),envSummary:document.getElementById('environment-summary'),
envSuggestions:document.getElementById('environment-suggestions'),analyze:document.getElementById('analyze-environment')};
let zoneConfig=null,zones=[],active=-1,selected=new Set(),painting=false,paintValue=true,frameTimer=null;
function message(text,kind=''){ui.message.textContent=text;ui.message.className='message '+kind}
function activeZone(){return active>=0?zones[active]:null}
function formToZone(){const id=document.getElementById('zone-id').value.trim();
const name=document.getElementById('zone-name').value.trim();const cls=document.getElementById('rule-class').value.trim();
const template=document.getElementById('rule-template').value;const dwell=Number(document.getElementById('rule-dwell').value||0);
const severity=document.getElementById('rule-severity').value;
return{id,name,cells:[...selected].sort((a,b)=>a-b),rules:[{cls,template,dwell_s:dwell,severity}]}}
function fillForm(zone){document.getElementById('zone-id').value=zone?.id||'';
document.getElementById('zone-name').value=zone?.name||'';const rule=zone?.rules?.[0]||{};
document.getElementById('rule-class').value=rule.cls||'person';
document.getElementById('rule-template').value=rule.template||'immediate';
document.getElementById('rule-dwell').value=rule.dwell_s??0;
document.getElementById('rule-severity').value=rule.severity||'medium';selected=new Set(zone?.cells||[]);renderGrid()}
function renderZones(){ui.list.replaceChildren();zones.forEach((zone,index)=>{const row=document.createElement('button');
row.type='button';row.className='zone-item'+(index===active?' active':'');
const name=document.createElement('span');name.textContent=zone.name||zone.id;
const count=document.createElement('span');count.className='pill';count.textContent=(zone.cells||[]).length+' 格';
row.append(name,count);row.onclick=()=>{active=index;fillForm(zone);renderZones()};ui.list.appendChild(row)});
if(!zones.length){const note=document.createElement('div');note.className='subtle';note.textContent='还没有区域，请新建并由管理员保存。';ui.list.appendChild(note)}}
function renderGrid(){if(!zoneConfig)return;const {rows,cols}=zoneConfig.grid;ui.grid.style.gridTemplateColumns=`repeat(${cols},1fr)`;
ui.grid.style.gridTemplateRows=`repeat(${rows},1fr)`;ui.grid.replaceChildren();
for(let i=0;i<rows*cols;i++){const cell=document.createElement('div');cell.className='grid-cell'+(selected.has(i)?' selected':'');
cell.dataset.cell=String(i);cell.onpointerdown=e=>{e.preventDefault();painting=true;paintValue=!selected.has(i);paintCell(i,paintValue)};
cell.onpointerenter=()=>{if(painting)paintCell(i,paintValue)};ui.grid.appendChild(cell)}
ui.summary.textContent=`${rows} × ${cols} 网格 · 已选 ${selected.size} 格`}
function paintCell(index,value){value?selected.add(index):selected.delete(index);const cell=ui.grid.children[index];
if(cell)cell.classList.toggle('selected',value);if(zoneConfig)ui.summary.textContent=`${zoneConfig.grid.rows} × ${zoneConfig.grid.cols} 网格 · 已选 ${selected.size} 格`}
window.addEventListener('pointerup',()=>painting=false);
function alignGrid(){const stage=document.getElementById('frame-stage');if(ui.frame.hidden||!ui.frame.naturalWidth){ui.grid.style.cssText='';return}
const sw=stage.clientWidth,sh=stage.clientHeight,ratio=ui.frame.naturalWidth/ui.frame.naturalHeight;
const width=Math.min(sw,sh*ratio),height=width/ratio;ui.grid.style.left=((sw-width)/2)+'px';
ui.grid.style.top=((sh-height)/2)+'px';ui.grid.style.right='auto';ui.grid.style.bottom='auto';
ui.grid.style.width=width+'px';ui.grid.style.height=height+'px'}
async function loadFrame(){const camera=ui.camera.value;if(!camera)return;ui.frame.src='/api/frame/'+encodeURIComponent(camera)+'?t='+Date.now();
ui.frame.onload=()=>{ui.frame.hidden=false;ui.empty.hidden=true;alignGrid()};ui.frame.onerror=()=>{ui.frame.hidden=true;ui.empty.hidden=false;ui.empty.textContent='相机离线或尚无可用画面；区域仍可保存，恢复来帧后生效。';alignGrid()}}
async function loadZones(){const camera=ui.camera.value;if(!camera)return;message('');
const response=await fetch('/api/zones/'+encodeURIComponent(camera));if(!response.ok){message('读取区域失败','error');return}
zoneConfig=await response.json();zones=Array.isArray(zoneConfig.zones)?zoneConfig.zones:[];active=zones.length?0:-1;
ui.runtime.textContent=zoneConfig.pending?'配置等待下一帧生效':(zoneConfig.runtime==='active'?'运行时在线':'保存后需重启应用');
fillForm(activeZone());renderZones();loadFrame();clearInterval(frameTimer);frameTimer=setInterval(loadFrame,2500)}
function showEnvironment(profile){ui.envResult.hidden=!profile;ui.envSuggestions.replaceChildren();
if(!profile)return;ui.envSummary.textContent=`${profile.scene_type} · ${profile.lighting} · ${profile.risk_notes}`;
(profile.suggested_zones||[]).forEach(text=>{const item=document.createElement('li');item.textContent=text;ui.envSuggestions.appendChild(item)})}
async function loadEnvironment(){const camera=ui.camera.value;if(!camera){ui.gate.hidden=false;ui.envMessage.textContent='请先配置相机。';ui.analyze.disabled=true;return}
ui.analyze.disabled=false;ui.gate.hidden=false;ui.envMessage.textContent='正在检查当前相机的环境档案…';showEnvironment(null);
const response=await fetch('/api/environment/'+encodeURIComponent(camera));const data=await response.json();
if(response.ok&&data.profile){showEnvironment(data.profile);ui.envMessage.textContent='环境档案已就绪，即将进入管理员圈选。';setTimeout(()=>ui.gate.hidden=true,350);return}
ui.envMessage.textContent=data.channel==='cloud'?'该相机尚未识别。云模型会发送当前帧，每次都必须确认。':'该相机尚未识别。点击后仅调用本机模型。';
ui.gate.hidden=false}
async function loadCameras(){const response=await fetch('/api/cameras');const data=await response.json();ui.camera.replaceChildren();
(data.cameras||[]).forEach(camera=>{const option=document.createElement('option');option.value=camera.id;option.textContent=camera.id;ui.camera.appendChild(option)});
if(!ui.camera.options.length){const option=document.createElement('option');option.textContent='没有已配置相机';option.value='';ui.camera.appendChild(option);ui.empty.textContent='请先在 cameras.json 中配置相机';await loadEnvironment();return}await loadZones();await loadEnvironment()}
document.getElementById('new-zone').onclick=()=>{active=-1;fillForm(null);renderZones();message('正在创建新区域：选择格子并填写规则后保存。')};
document.getElementById('clear-cells').onclick=()=>{selected.clear();renderGrid()};ui.camera.onchange=async()=>{await loadZones();await loadEnvironment()};
ui.analyze.onclick=async()=>{const camera=ui.camera.value;if(!camera)return;let cloudConfirmed=false;
const statusResponse=await fetch('/api/environment/'+encodeURIComponent(camera));const status=await statusResponse.json();
if(status.channel==='cloud'){cloudConfirmed=window.confirm('本次环境识别会把当前相机的一帧发送到已配置的云模型。是否仅授权本次发送？');if(!cloudConfirmed){ui.envMessage.textContent='已取消：没有发送任何画面。';return}}
ui.analyze.disabled=true;ui.envMessage.textContent='正在识别环境，请稍候…';
try{const response=await fetch('/api/environment/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({camera,cloud_confirmed:cloudConfirmed})});
const data=await response.json();if(!response.ok){ui.envMessage.textContent=data.error||'环境识别暂不可用，请检查模型后重试。';return}
showEnvironment(data.profile);ui.envMessage.textContent='识别完成。建议仅供参考，请由管理员圈选并保存报警区域。';setTimeout(()=>ui.gate.hidden=true,900)}
catch(error){ui.envMessage.textContent='环境识别服务不可用，请检查本机工作台。'}finally{ui.analyze.disabled=false}};
document.getElementById('delete-zone').onclick=async()=>{const zone=activeZone();if(!zone){message('请先选择要删除的区域。','error');return}
if(!window.confirm('删除区域“'+(zone.name||zone.id)+'”？保存后该区域规则将停止生效。'))return;
const next=zones.filter((_,index)=>index!==active);const response=await fetch('/api/zones/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({camera:ui.camera.value,zones:next})});
const result=await response.json();if(!response.ok){message(result.error||'删除失败','error');return}zones=result.zones;active=zones.length?0:-1;fillForm(activeZone());renderZones();message(result.runtime==='queued'?'已删除，等待下一视频帧原子应用。':'已删除，重启值守后应用。','ok')};
document.getElementById('save-zone').onclick=async()=>{const zone=formToZone();if(!zone.id||!zone.name||!zone.rules[0].cls||!zone.cells.length){message('区域 ID、名称、类别和至少一个格子不能为空。','error');return}
const next=zones.slice();if(active>=0)next[active]=zone;else{if(next.some(item=>item.id===zone.id)){message('区域 ID 已存在，请编辑原区域或更换 ID。','error');return}next.push(zone)}
message('正在保存…');const response=await fetch('/api/zones/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({camera:ui.camera.value,zones:next})});
const result=await response.json();if(!response.ok){message(result.error||'保存失败','error');return}zones=result.zones;active=zones.findIndex(item=>item.id===zone.id);renderZones();fillForm(activeZone());
ui.runtime.textContent=result.runtime==='queued'?'配置等待下一帧生效':'保存后需重启应用';
message(result.runtime==='queued'?'已保存，等待下一视频帧原子应用。':'已保存，重启值守后应用。','ok')};
async function refreshLists(){try{let response=await fetch('/api/review');let data=await response.json();
const review=document.querySelector('#review tbody');review.replaceChildren();(data.segments||[]).forEach(s=>{const row=review.insertRow();
row.insertCell().textContent=new Date(s.t_start*1000).toLocaleString();row.insertCell().textContent=s.camera||'';
row.insertCell().textContent=s.severity||'';row.insertCell().textContent=(s.object_ids||[]).length;row.insertCell().textContent=s.reviewed?'已读':'待审'});
response=await fetch('/api/events');data=await response.json();const events=document.querySelector('#events tbody');events.replaceChildren();
(data.events||[]).forEach(e=>{const row=events.insertRow();row.insertCell().textContent=e.t_start?new Date(e.t_start*1000).toLocaleString():'';
let link=document.createElement('a');link.textContent=e.short_name||e.event_id;link.href='/api/events/'+encodeURIComponent(e.event_id);link.target='_blank';row.insertCell().appendChild(link);
row.insertCell().textContent=e.detail||'';let cell=row.insertCell();if(e.best_frame_asset_id){link=document.createElement('a');link.textContent='最佳帧';link.href='/api/evidence/'+encodeURIComponent(e.best_frame_asset_id);link.target='_blank';cell.appendChild(link)}
cell=row.insertCell();if(e.clip_asset_id){link=document.createElement('a');link.textContent='录像';link.href='/api/recordings/'+encodeURIComponent(e.clip_asset_id);link.target='_blank';cell.appendChild(link)}});
response=await fetch('/api/patterns');data=await response.json();document.getElementById('patterns').textContent=(data.patterns||[]).map(p=>p.name).join('、')||'暂无已学习模式';
}catch(error){document.getElementById('health').textContent='工作台数据暂不可用'}}
window.addEventListener('resize',alignGrid);loadCameras().catch(()=>message('相机配置读取失败','error'));refreshLists();setInterval(refreshLists,3000);
</script></body></html>'''


class WorkbenchState:
    """工作台共享状态：结构化真值在 SQLite，证据文件只能按索引读取。"""

    def __init__(self, db_path, evidence_root=None, environment_provider=None):
        self.db_path = db_path
        self.evidence = EvidenceStore(
            evidence_root or os.path.join(
                os.path.dirname(os.path.abspath(db_path)), "evidence"))
        self.monitors = {}
        self.recorders = None      # RecordingManager（Z3，未启用时 None）
        self.recording = None      # RecordingStore（Z3，未启用时 None）
        # 默认本地优先。构造 provider 不会发起模型调用；只有管理员点击识别才会调用。
        self.environment_provider = (environment_provider
                                     if environment_provider is not None
                                     else build_provider({"channel": "local"}))
        self._lock = threading.Lock()

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def cameras(self):
        """从 SQLite zones 表读取相机列表（去重）。"""
        conn = self._conn()
        rows = conn.execute(
            "SELECT DISTINCT camera FROM zones").fetchall()
        conn.close()
        return [{"id": r[0]} for r in rows]

    def zones(self, camera_id):
        """从 SQLite zones 表读取指定相机的区域配置。"""
        conn = self._conn()
        row = conn.execute(
            "SELECT data FROM zones WHERE camera = ?", (camera_id,)).fetchone()
        conn.close()
        return json.loads(row["data"]) if row else []

    def environment_status(self, camera_id):
        """环境档案与通道状态；读取不调用模型，也不返回任何本地路径或凭据。"""
        if not CAMERA_ID_RE.match(camera_id or ""):
            return None
        if camera_id not in self.monitors and not any(
                camera["id"] == camera_id for camera in self.cameras()):
            return None
        conn = self._conn()
        try:
            profile = EnvironmentStore(conn).load(camera_id)
        finally:
            conn.close()
        channel = getattr(self.environment_provider, "name", None)
        return {"camera": camera_id, "profile": profile,
                "state": "ready" if profile else "required",
                "channel": channel if channel in ("local", "cloud") else None}

    def analyze_environment(self, camera_id, *, cloud_confirmed=False):
        """用当前帧执行一次管理员触发识别；建议绝不写入 zones。"""
        status = self.environment_status(camera_id)
        if status is None:
            return "unknown", None
        monitor = self.monitors.get(camera_id)
        frame = getattr(monitor, "latest_frame_bgr", None)
        if frame is None:
            return "unavailable", None
        try:
            frame = frame.copy()
        except (AttributeError, TypeError, ValueError):
            return "unavailable", None
        conn = self._conn()
        try:
            return EnvironmentStore(conn).analyze(
                camera_id, provider=self.environment_provider,
                frame_bgr=frame, cloud_confirmed=cloud_confirmed)
        finally:
            conn.close()

    def zone_config(self, camera_id):
        """返回圈选真值及运行时应用状态；未知相机不伪造空配置。"""
        if not CAMERA_ID_RE.match(camera_id or ""):
            return None
        conn = self._conn()
        row = conn.execute(
            "SELECT data FROM zones WHERE camera = ?", (camera_id,)).fetchone()
        conn.close()
        if row is None:
            return None
        monitor = self.monitors.get(camera_id)
        grid = monitor.grid if monitor is not None else Grid()
        try:
            zones = json.loads(row["data"])
        except (TypeError, ValueError):
            zones = []
        return {
            "camera": camera_id,
            "grid": {"rows": grid.rows, "cols": grid.cols},
            "zones": zones,
            "runtime": "active" if monitor is not None else "restart_required",
            "revision": monitor.zone_revision if monitor is not None else None,
            "pending": (monitor._pending_zones is not None
                        if monitor is not None else False),
        }

    def read_recording(self, asset_id):
        """Z3 录像读取契约：未启用录像时诚实返回 unknown，绝不按路径裸读。"""
        if self.recording is None:
            return "unknown", None
        return self.recording.read_recording(asset_id)

    def read_frame(self, camera_id, max_width=1280, quality=85):
        """按需编码在线相机最新帧；不把工作台预览成本放进逐帧快路径。"""
        if not CAMERA_ID_RE.match(camera_id or ""):
            return "unknown", None
        monitor = self.monitors.get(camera_id)
        if monitor is None:
            return "offline", None
        frame = monitor.latest_frame_bgr
        if frame is None:
            return "empty", None
        try:
            import cv2
            height, width = frame.shape[:2]
            if width > max_width:
                target_height = max(1, round(height * max_width / width))
                frame = cv2.resize(frame, (max_width, target_height),
                                   interpolation=cv2.INTER_AREA)
            ok, encoded = cv2.imencode(
                ".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, int(quality)])
            if not ok:
                return "encode_failed", None
            return "available", encoded.tobytes()
        except (AttributeError, TypeError, ValueError, OSError):
            return "encode_failed", None

    def save_zones(self, camera_id, zones):
        """保存区域配置到 SQLite zones 表（JSON 序列化存储）。

        camera_id 必须过白名单（防注入/防脏键）；不合法抛 ValueError。
        """
        if not CAMERA_ID_RE.match(camera_id or ""):
            raise ValueError(f"非法 camera_id: {camera_id!r}")
        monitor = self.monitors.get(camera_id)
        grid = monitor.grid if monitor is not None else Grid()
        zones = normalize_zones(zones, grid)
        conn = self._conn()
        conn.execute(
            "INSERT OR REPLACE INTO zones (camera, data) VALUES (?,?)",
            (camera_id, json.dumps(zones, ensure_ascii=False)))
        conn.commit()
        conn.close()
        revision = monitor.request_zone_update(zones) if monitor is not None \
            else None
        return {"runtime": "queued" if monitor is not None
                else "restart_required", "revision": revision,
                "zones": zones}

    @staticmethod
    def _decode_json_fields(item, fields):
        for field, fallback in fields:
            try:
                item[field] = json.loads(item.get(field) or "null")
            except (TypeError, ValueError):
                item[field] = fallback
            if item[field] is None:
                item[field] = fallback
        return item

    def event_detail(self, event_id):
        """返回三层事实及证据元数据，不暴露本地文件路径。"""
        conn = self._conn()
        try:
            event_row = conn.execute(
                "SELECT * FROM semantic_events WHERE semantic_event_id=?",
                (event_id,)).fetchone()
            if event_row is None:
                return None
            event = self._decode_json_fields(
                dict(event_row), (("payload", {}),))
            event.pop("best_frame_path", None)
            review_row = conn.execute(
                "SELECT * FROM review_segments WHERE review_id=?",
                (event["review_id"],)).fetchone()
            object_row = conn.execute(
                "SELECT * FROM tracked_objects WHERE object_id=?",
                (event["object_id"],)).fetchone()
            assets = conn.execute(
                "SELECT asset_id,owner_type,owner_id,camera,kind,state,mime,"
                " t_start,t_end,score,size_bytes,sha256,created_at,updated_at,"
                " metadata FROM evidence_assets"
                " WHERE owner_type='semantic_event' AND owner_id=?"
                " ORDER BY created_at",
                (event_id,)).fetchall()
        finally:
            conn.close()

        review = None
        if review_row is not None:
            review = self._decode_json_fields(
                dict(review_row), (("object_ids", []),
                                   ("semantic_event_ids", []),
                                   ("payload", {})))
        tracked_object = None
        if object_row is not None:
            tracked_object = self._decode_json_fields(
                dict(object_row), (("payload", {}),))
            tracked_object.pop("best_frame_path", None)
        evidence = []
        for row in assets:
            item = self._decode_json_fields(dict(row), (("metadata", {}),))
            if item["kind"] == "clean_best_frame" and \
                    item["mime"] == "image/jpeg":
                item["content_url"] = "/api/evidence/" + quote(
                    item["asset_id"], safe="")
            evidence.append(item)
        return {"event": event, "review": review,
                "object": tracked_object, "evidence": evidence}

    def read_evidence(self, asset_id):
        """从索引安全读取 JPEG；返回 (state, bytes|None)。"""
        conn = self._conn()
        row = conn.execute(
            "SELECT path,kind,mime,size_bytes,sha256 FROM evidence_assets"
            " WHERE asset_id=?", (asset_id,)).fetchone()
        if row is None:
            conn.close()
            return "unknown", None

        def mark(state):
            conn.execute(
                "UPDATE evidence_assets SET state=?,updated_at=?"
                " WHERE asset_id=?", (state, time.time(), asset_id))
            conn.commit()

        if row["kind"] != "clean_best_frame" or row["mime"] != "image/jpeg":
            conn.close()
            return "unsupported", None
        try:
            full_path = self.evidence.resolve(row["path"])
        except (TypeError, ValueError, OSError):
            mark("corrupt")
            conn.close()
            return "corrupt", None
        try:
            with open(full_path, "rb") as handle:
                content = handle.read()
        except FileNotFoundError:
            mark("missing")
            conn.close()
            return "missing", None
        except OSError:
            mark("corrupt")
            conn.close()
            return "corrupt", None

        valid = content.startswith(b"\xff\xd8") and content.endswith(b"\xff\xd9")
        if row["size_bytes"] is not None:
            valid = valid and len(content) == int(row["size_bytes"])
        if row["sha256"]:
            valid = valid and hashlib.sha256(content).hexdigest() == row["sha256"]
        if not valid:
            mark("corrupt")
            conn.close()
            return "corrupt", None
        mark("available")
        conn.close()
        return "available", content


class WorkbenchHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_index(self):
        body = _INDEX_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _jpeg(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "image/jpeg")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _video(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "video/mp4")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._serve_index()
            return
        if path == "/api/cameras":
            self._json({"cameras": self.server.state.cameras()})
            return
        if path.startswith("/api/environment/"):
            camera_id = unquote(path[len("/api/environment/"):])
            status = self.server.state.environment_status(camera_id)
            if status is None:
                self._json({"error": "camera not found"}, 404)
                return
            self._json(status)
            return
        if path.startswith("/api/zones/"):
            camera_id = unquote(path[len("/api/zones/"):])
            config = self.server.state.zone_config(camera_id)
            if config is None:
                self._json({"error": "camera not found"}, 404)
                return
            self._json(config)
            return
        if path.startswith("/api/frame/"):
            camera_id = unquote(path[len("/api/frame/"):])
            frame_state, content = self.server.state.read_frame(camera_id)
            if frame_state == "unknown":
                self._json({"error": "camera not found", "state": frame_state},
                           404)
                return
            if frame_state in ("offline", "empty"):
                self._json({"error": "frame unavailable", "state": frame_state},
                           503)
                return
            if frame_state == "encode_failed":
                self._json({"error": "frame encode failed",
                            "state": frame_state}, 500)
                return
            self._jpeg(content)
            return
        if path == "/api/health":
            cams = [{"id": cid, "ratio": round(m.gate.last_ratio, 4)}
                    for cid, m in self.server.state.monitors.items()]
            recording = (self.server.state.recorders.status()
                         if self.server.state.recorders is not None else [])
            payload = {"cameras": cams, "count": len(cams),
                       "recording": recording}
            # Linux L3：入口传入 state.health 时才附加 watchdog/资源快照；
            # 采样失败结构化降级，绝不让 health 端点 500 或阻断其他线程。
            health = getattr(self.server.state, "health", None)
            if health is not None:
                try:
                    payload["watchdog"] = health.snapshot(
                        include_resources=False)
                except Exception as exc:
                    payload["watchdog"] = {
                        "state": "unavailable", "error": type(exc).__name__}
                try:
                    payload["resources"] = health.resources.sample()
                except Exception as exc:
                    payload["resources"] = {
                        "state": "unavailable", "error": type(exc).__name__}
            self._json(payload)
            return
        if path == "/api/stats":
            cams = [monitor.stats() for monitor in
                    self.server.state.monitors.values()]
            self._json({"cameras": cams, "count": len(cams)})
            return
        if path == "/api/review":
            conn = self.server.state._conn()
            rows = conn.execute(
                "SELECT review_id,camera,t_start,t_last,t_end,end_reason,"
                " severity,reviewed,object_ids,semantic_event_ids,payload"
                " FROM review_segments ORDER BY t_start DESC LIMIT 100"
            ).fetchall()
            conn.close()
            segments = []
            for row in rows:
                item = dict(row)
                for field, fallback in (("object_ids", []),
                                        ("semantic_event_ids", []),
                                        ("payload", {})):
                    try:
                        item[field] = json.loads(item[field] or "null")
                    except (TypeError, ValueError):
                        item[field] = fallback
                    if item[field] is None:
                        item[field] = fallback
                segments.append(item)
            self._json({"segments": segments})
            return
        if path == "/api/events":
            conn = self.server.state._conn()
            rows = conn.execute(
                "SELECT semantic_event_id AS event_id,camera,review_id,object_id,"
                " t_start,t_last,t_end,end_reason,state,cls,conf,zone_id,template,"
                " short_name,detail,rationale,evidence_state,"
                " (SELECT asset_id FROM evidence_assets"
                "  WHERE owner_type='semantic_event'"
                "  AND owner_id=semantic_events.semantic_event_id"
                "  AND kind='clean_best_frame' LIMIT 1) AS best_frame_asset_id,"
                " (SELECT asset_id FROM evidence_assets"
                "  WHERE owner_type='review_segment'"
                "  AND owner_id=semantic_events.review_id"
                "  AND kind='event_clip' LIMIT 1) AS clip_asset_id"
                " FROM semantic_events ORDER BY t_start DESC LIMIT 100").fetchall()
            conn.close()
            self._json({"events": [dict(r) for r in rows]})
            return
        if path.startswith("/api/events/"):
            event_id = unquote(path[len("/api/events/"):])
            if not event_id or "/" in event_id:
                self._json({"error": "event not found"}, 404)
                return
            detail = self.server.state.event_detail(event_id)
            if detail is None:
                self._json({"error": "event not found"}, 404)
                return
            self._json(detail)
            return
        if path.startswith("/api/evidence/"):
            asset_id = unquote(path[len("/api/evidence/"):])
            if not asset_id or "/" in asset_id:
                self._json({"error": "evidence not found"}, 404)
                return
            state, content = self.server.state.read_evidence(asset_id)
            if state in ("unknown", "missing", "unsupported"):
                self._json({"error": "evidence not found", "state": state}, 404)
                return
            if state == "corrupt":
                self._json({"error": "evidence corrupt", "state": state}, 422)
                return
            self._jpeg(content)
            return
        if path.startswith("/api/recordings/"):
            asset_id = unquote(path[len("/api/recordings/"):])
            if not asset_id or "/" in asset_id:
                self._json({"error": "recording not found"}, 404)
                return
            state_, content = self.server.state.read_recording(asset_id)
            if state_ in ("unknown", "missing", "unsupported"):
                self._json({"error": "recording not found",
                            "state": state_}, 404)
                return
            if state_ == "corrupt":
                self._json({"error": "recording corrupt", "state": state_},
                           422)
                return
            self._video(content)
            return
        if path == "/api/patterns":
            conn = self.server.state._conn()
            rows = conn.execute(
                "SELECT pattern_id, name, detail, state, count, version"
                " FROM patterns ORDER BY count DESC").fetchall()
            conn.close()
            self._json({"patterns": [dict(r) for r in rows]})
            return
        self.send_error(404)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            self._json({"error": "invalid json"}, 400)
            return
        if path == "/api/zones/save":
            try:
                result = self.server.state.save_zones(
                    body.get("camera", ""), body.get("zones", []))
            except ValueError as e:
                self._json({"error": str(e)}, 400)
                return
            self._json({"ok": True, **result})
            return
        if path == "/api/environment/analyze":
            camera_id = body.get("camera", "")
            confirmed = body.get("cloud_confirmed", False)
            if not isinstance(confirmed, bool):
                self._json({"error": "cloud_confirmed must be boolean"}, 400)
                return
            env_status, profile = self.server.state.analyze_environment(
                camera_id, cloud_confirmed=confirmed)
            if env_status == "unknown":
                self._json({"error": "camera not found", "state": env_status}, 404)
                return
            if env_status == "confirmation_required":
                self._json({"error": "cloud confirmation required",
                            "state": env_status}, 428)
                return
            if env_status == "invalid":
                self._json({"error": "model returned invalid profile",
                            "state": env_status}, 422)
                return
            if env_status != "ok":
                self._json({"error": "environment analysis unavailable",
                            "state": env_status}, 503)
                return
            self._json({"ok": True, "state": env_status,
                        "profile": profile})
            return
        if path == "/api/events/feedback":
            eid = body.get("event_id", "")
            feedback = body.get("feedback", "")
            conn = self.server.state._conn()
            # 合并进原 payload（证据不可丢）；事件不存在如实报 404 语义
            row = conn.execute(
                "SELECT payload FROM events WHERE event_id = ?",
                (eid,)).fetchone()
            if row is None:
                conn.close()
                self._json({"error": "event not found"}, 404)
                return
            try:
                payload = json.loads(row["payload"]) if row["payload"] else {}
            except (TypeError, ValueError):
                payload = {}
            if not isinstance(payload, dict):
                payload = {"original": payload}
            payload["feedback"] = feedback
            conn.execute(
                "UPDATE events SET payload = ? WHERE event_id = ?",
                (json.dumps(payload, ensure_ascii=False), eid))
            conn.commit()
            conn.close()
            self._json({"ok": True})
            return
        if path == "/api/review/reviewed":
            review_id = body.get("review_id") or body.get("seg_id", "")
            from .db import set_reviewed
            conn = self.server.state._conn()
            changed = set_reviewed(conn, review_id)
            conn.close()
            if not changed:
                self._json({"error": "review segment not found"}, 404)
                return
            self._json({"ok": True})
            return
        self.send_error(404)


class WorkbenchServer(ThreadingHTTPServer):
    """工作台 HTTP 服务（ThreadingHTTPServer，随 NVR 常驻）。

    默认只绑 127.0.0.1：告警流与配置不含鉴权，不暴露局域网；
    远程访问走 SSH 隧道（ssh -L 8600:127.0.0.1:8600 nvr）或加鉴权的反代。
    """

    def __init__(self, state, host="127.0.0.1", port=8600):
        self.state = state
        super().__init__((host, port), WorkbenchHandler)
        self.daemon_threads = True
