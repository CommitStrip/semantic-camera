"""server.py —— 工作台 HTTP 服务：API + 审查时间线 + 告警出口。

内嵌 HTML 零文件 I/O 零路径构造；前端 3 秒轮询刷新。
camera_id 白名单校验（alphanumeric + dash + underscore）——防路径注入。
默认只绑 127.0.0.1（远程访问交 SSH 隧道/反向代理）；
所有状态（区域/事件/模式）均存 SQLite，server 零文件写入。
"""

import base64
import hashlib
import json
import math
import os
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote, unquote

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
.camera-line{margin-top:4px;font-size:13px}.camera-line.online{color:var(--accent)}
.camera-line.degraded{color:var(--warn)}.camera-line.stopped{color:var(--muted)}
.guard-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.guard-card{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:#0b0e14}
.guard-card img{width:100%;aspect-ratio:16/9;object-fit:cover;display:block;background:#000}
.guard-head{display:flex;align-items:center;gap:6px;padding:6px 8px;font-size:13px}
.guard-dot{width:8px;height:8px;border-radius:50%;background:var(--muted);flex:none}
.guard-dot.online{background:var(--accent)}.guard-dot.degraded{background:var(--warn)}
.guard-badge{margin-left:auto;background:var(--warn);color:#111;border-radius:9px;padding:1px 7px;font-size:12px}
.reminder{display:grid;gap:8px;margin-bottom:10px}
.reminder-item{border:1px solid var(--warn);background:#2a1f10;border-radius:10px;
padding:8px 10px;font-size:13px}.reminder-item .subtle{font-size:12px}
.ev-open{color:var(--accent);font-weight:600}.ev-closed{color:var(--muted)}
.ev-esc{color:var(--warn)}
#event-detail-panel{margin-top:12px;border:1px solid var(--line);border-radius:10px;
padding:10px;background:#0b111c}
.desc-version{border:1px solid var(--line);border-radius:10px;padding:8px 10px;
margin-bottom:8px;font-size:13px}.desc-version .subtle{font-size:12px}
.confirm-btn{margin-top:6px}
.confirm-badge{color:var(--accent);font-weight:600}
.environment-gate{position:fixed;inset:0;z-index:1000;display:grid;place-items:center;
padding:24px;background:#07101acc;backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px)}
.environment-gate[hidden]{display:none}.environment-panel{width:min(620px,100%);padding:28px;
border:1px solid #5b718f;background:#111b2a;border-radius:18px;box-shadow:0 30px 100px #000b}
.environment-panel ul{margin:10px 0 18px;padding-left:20px;color:var(--muted)}
.environment-panel .actions{margin:6px 0 12px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:8px 6px;
border-bottom:1px solid var(--line);text-align:left}a{color:#77d9ff}
@media(max-width:900px){body{padding:14px}.layout{grid-template-columns:1fr}.stage{min-height:260px}}
</style></head><body>
<header><div><div class="eyebrow">Windows 11 local-first</div><h1>语义摄像头 · 工作台</h1>
<div class="subtle">固定机位首次使用须先建立环境基线；事件记录不以圈选或规则为前提，规则决定特别关注与升级告警。模型建议不会自动成为告警。</div></div>
<div class="status"><div id="health">本机工作台</div>
<div id="camera-status">正在读取相机状态…</div></div></header>
<main class="layout"><section>
<div class="card" id="event-timeline-card"><div class="toolbar"><div><h2>事件时间线</h2>
<div class="subtle">无规则也建立事件：开始 / 结束与原因 / 初始事实提醒 / 证据可用性；规则升级为附加标识。</div></div></div>
<div id="reminder-banner" class="reminder" aria-live="polite"></div>
<table id="event-timeline"><thead><tr><th>时间</th><th>相机</th><th>类别</th><th>状态</th>
<th>初始事实</th><th>证据</th><th>升级</th><th>详情</th></tr></thead><tbody></tbody></table>
<div id="event-detail-panel" hidden><h3 id="event-detail-title">事件详情</h3>
<div id="event-detail-body"></div>
<div id="confirm-area"></div></div></div>
<div class="card" id="guard-grid-card"><div class="toolbar"><div><h2>值守网格</h2>
<div class="subtle">每相机一张卡：状态 · 最新画面（3s 刷新）· 最近告警计数。</div></div></div>
<div id="guard-grid" class="guard-grid" aria-label="多相机值守网格">正在读取相机…</div></div>
<div class="card" id="zone-editor"><div class="toolbar"><div><h2>区域与规则</h2>
<div class="subtle">点击或拖动网格刷选；绿色格子仅在点击“保存并应用”后生效。</div></div>
<label>相机<select id="camera-select" aria-label="选择相机"></select></label></div>
<div class="stage" id="frame-stage"><img id="zone-frame" alt="当前相机画面">
<div id="frame-empty" class="empty">正在读取当前画面…</div><div id="zone-grid" aria-label="区域网格"></div></div>
<div class="legend"><span id="grid-summary">网格加载中</span><span id="runtime-state">尚未连接运行时</span></div></div>
<div class="card"><h2>审查时间线</h2><table id="review"><thead><tr><th>开始</th><th>相机</th>
<th>级别</th><th>目标数</th><th>状态</th></tr></thead><tbody></tbody></table></div>
<div class="card"><h2>管理员规则告警</h2><div class="subtle">规则命中产生的告警（旧接口，保持兼容）；事件主线见上方时间线。</div>
<table id="events"><thead><tr><th>时间</th><th>短名</th>
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
<div class="card"><h2>环境基线</h2>
<div class="subtle">固定机位首次使用须先建立可追溯的环境基线再进入值守；圈选与规则保持可选，事件记录不以规则为前提。识别建议不会自动成为区域，也不会改动已记录的事件。</div>
<p id="environment-message" class="subtle">正在检查当前相机的环境基线…</p>
<div id="environment-result" hidden><h3>识别建议（不会自动成为报警规则）</h3>
<p id="environment-summary"></p><ul id="environment-suggestions"></ul></div>
<button id="analyze-environment" type="button">复核环境基线（新版本）</button>
<ul id="baseline-history" class="subtle"></ul>
<p class="subtle">本地模型默认不上传画面；如选择云模型，本次操作会再次明确确认。基线只追加版本，历史与原始画面保留。</p></div>
<div class="card"><h2>模式库</h2><div id="patterns" class="subtle">加载中</div></div>
</aside></main>
<div id="environment-gate" class="environment-gate" role="dialog" aria-modal="true">
<div class="environment-panel"><div class="eyebrow">首次使用 · 必须完成</div>
<h2>先建立环境基线，再进入值守</h2>
<p id="gate-message">正在检查当前相机的环境基线…</p>
<p class="subtle">基线包含完整场景原始画面与识别结果，可追溯、可复核、只追加版本；
事件的发现与记录不以圈选或规则为前提；圈选与规则稍后仍可随时配置。</p>
<div class="actions"><button id="baseline-establish" class="primary" type="button">建立环境基线</button>
<button id="baseline-retry" type="button" hidden>重试</button></div>
<p class="subtle">本地模型默认不上传画面；如选择云模型，本次操作会再次明确确认。
基线不可用时会明确提示原因；仅预览路径会有清楚标注，不会称为正常值守。</p>
</div></div>
<script>
const ui={camera:document.getElementById('camera-select'),frame:document.getElementById('zone-frame'),
empty:document.getElementById('frame-empty'),grid:document.getElementById('zone-grid'),
summary:document.getElementById('grid-summary'),runtime:document.getElementById('runtime-state'),
list:document.getElementById('zone-list'),message:document.getElementById('zone-message'),
envMessage:document.getElementById('environment-message'),
envResult:document.getElementById('environment-result'),envSummary:document.getElementById('environment-summary'),
envSuggestions:document.getElementById('environment-suggestions'),analyze:document.getElementById('analyze-environment'),
cameraStatus:document.getElementById('camera-status'),
timeline:document.querySelector('#event-timeline tbody'),banner:document.getElementById('reminder-banner'),
gate:document.getElementById('environment-gate'),gateMessage:document.getElementById('gate-message'),
baselineEstablish:document.getElementById('baseline-establish'),baselineRetry:document.getElementById('baseline-retry'),
baselineHistory:document.getElementById('baseline-history')};
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
function renderBaselineHistory(camera,rows){ui.baselineHistory.replaceChildren();
(rows||[]).forEach(v=>{const item=document.createElement('li');
item.textContent='v'+v.version+' · '+(v.is_current?'当前':'已替代')+' · '+new Date(v.established_at*1000).toLocaleString()+' · '+(v.scene_summary||'（无摘要）')+' · 模型 '+(v.model_id||'unknown')+(v.comparison_insufficient?'（比较条件不足）':'')+' · '+(v.evidence_available?'可回看':'不可回看')+' ';
if(v.evidence_available){const link=document.createElement('a');link.textContent='查看原始画面';
link.href='/api/environment/'+encodeURIComponent(camera)+'/baselines/'+encodeURIComponent(v.baseline_id)+'/frame';link.target='_blank';item.appendChild(link)}
ui.baselineHistory.appendChild(item)})}
async function loadEnvironment(){const camera=ui.camera.value;
if(!camera){ui.gate.hidden=false;ui.gateMessage.textContent='请先配置相机；没有相机时无法建立基线。';ui.analyze.disabled=true;return}
ui.analyze.disabled=false;ui.envMessage.textContent='正在检查当前相机的环境基线…';showEnvironment(null);
let baseline=null;
try{const response=await fetch('/api/environment/'+encodeURIComponent(camera));const data=await response.json();
if(response.ok&&data.profile){showEnvironment(data.profile)}
baseline=response.ok?data.baseline:null}
catch(error){ui.envMessage.textContent='基线状态读取失败，请稍候重试。';ui.gate.hidden=false;return}
if(!baseline){ui.envMessage.textContent='基线状态暂不可用。';ui.gate.hidden=false;return}
try{const histResponse=await fetch('/api/environment/'+encodeURIComponent(camera)+'/baselines');const hist=await histResponse.json();
if(histResponse.ok){renderBaselineHistory(camera,hist.baselines)}}catch(historyError){ui.baselineHistory.replaceChildren()}
const B=baseline.state;
if(B==='ready'){ui.gate.hidden=true;
ui.envMessage.textContent='环境基线 v'+baseline.version+' 已就绪（建立于 '+new Date(baseline.established_at*1000).toLocaleString()+'）。'+(baseline.error?('最近一次复核失败（'+baseline.error+'），可从下方复核重试。'):'');
if(baseline.comparison_insufficient){ui.envMessage.textContent+='模型标识缺失，跨期比较条件不足。'}return}
ui.gate.hidden=false;ui.baselineRetry.hidden=(B!=='failed'&&B!=='evidence_broken');
const reasonText={no_pointer:'该相机还没有环境基线。',
legacy_profile_without_evidence:'存在旧版环境档案，但缺少版本记录与原始画面，不能作为可追溯基线。',
pointer_version_missing:'基线指针指向的版本已不存在。',
pointer_not_integer:'基线指针记录损坏。',
evidence_missing_or_corrupt:'当前基线的原始画面缺失或损坏：需修复画面文件，或复核建立新有效版本后才能解锁值守。历史版本保留不删。'}[baseline.reason]||'该相机还没有有效的环境基线。';
ui.gateMessage.textContent='先建立环境基线，再进入值守。'+reasonText+(baseline.error?('（上次失败：'+baseline.error+'）'):'');
ui.envMessage.textContent=reasonText}
async function establishBaseline(mode){const camera=ui.camera.value;if(!camera)return;
ui.baselineEstablish.disabled=true;ui.baselineRetry.disabled=true;
ui.gateMessage.textContent='正在采集完整场景并识别，请稍候…';
try{const statusResponse=await fetch('/api/environment/'+encodeURIComponent(camera));
const status=await statusResponse.json();let cloudConfirmed=false;
if(status.channel==='cloud'){cloudConfirmed=window.confirm('本次环境基线会把当前相机的一帧发送到已配置的云模型。是否仅授权本次发送？');
if(!cloudConfirmed){ui.gateMessage.textContent='已取消：没有发送任何画面。';return}}
const response=await fetch('/api/environment/baseline',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({camera,mode,cloud_confirmed:cloudConfirmed})});
const data=await response.json();
if(response.ok&&data.ok){showEnvironment(data.baseline.profile);await loadEnvironment();return}
ui.gateMessage.textContent=(data.error||'基线建立失败')+'，可重试。';ui.baselineRetry.hidden=false}
catch(error){ui.gateMessage.textContent='基线服务暂不可用，请重试。'}
finally{ui.baselineEstablish.disabled=false;ui.baselineRetry.disabled=false}}
ui.baselineEstablish.onclick=()=>establishBaseline('first-use');
ui.baselineRetry.onclick=()=>establishBaseline('review');
async function loadCameras(){const response=await fetch('/api/cameras');const data=await response.json();ui.camera.replaceChildren();
(data.cameras||[]).forEach(camera=>{const option=document.createElement('option');option.value=camera.id;option.textContent=camera.id;ui.camera.appendChild(option)});
if(!ui.camera.options.length){const option=document.createElement('option');option.textContent='没有已配置相机';option.value='';ui.camera.appendChild(option);ui.empty.textContent='请先在 cameras.json 中配置相机';await loadEnvironment();return}await loadZones();await loadEnvironment()}
document.getElementById('new-zone').onclick=()=>{active=-1;fillForm(null);renderZones();message('正在创建新区域：选择格子并填写规则后保存。')};
document.getElementById('clear-cells').onclick=()=>{selected.clear();renderGrid()};ui.camera.onchange=async()=>{await loadZones();await loadEnvironment()};
ui.analyze.onclick=()=>establishBaseline('review');
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
const knownStates=['connecting','online','degraded','stopped'];
let guardEvents={};
const REMINDER_STATE_TEXT={generated:'已生成',available:'工作台可读取',acknowledged:'客户端已显示（回执≠已读）'};
const acked=new Set();const rendered=new Map();const semRendered=new Map();let ackQueue=[];const ackState=new Map();let notifyCursor=null;
async function flushAckQueue(){const now=Date.now();
for(const id of ackQueue.slice()){const st=ackState.get(id)||{done:false,attempts:0,nextAt:0};
if(st.done){continue}
if(now<st.nextAt){continue}
try{const r=await fetch('/api/v2/notifications/ack',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({notification_id:id})});
if(r.ok){st.done=true}else{st.attempts+=1;st.nextAt=now+Math.min(30000,2000*Math.pow(2,st.attempts-1))}}
catch(err){st.attempts+=1;st.nextAt=now+Math.min(30000,2000*Math.pow(2,st.attempts-1))}
ackState.set(id,st)}
if(ackQueue.length>200){ackQueue=ackQueue.filter(id=>!(ackState.get(id)||{}).done)}}
// 人工确认五态：未确认 → 提交中 → 等待核实 → 已核实确认 / 核实失败可重试。
// POST 成功仅=提交成功；「已人工确认」徽标必须以 GET 读回的 user_confirmed=true
// 为准。回读复用 GET /api/v2/events/{id}：其 notifications 为按事件完整列表
// （不分页），不存在「第一页没找到」歧义；非 2xx/网络异常/目标缺失/返回未确认
// 一律回到可重试状态，绝不显示徽标、绝不留在「正在确认…」。
async function verifyConfirmFact(eventId,notificationId,btn,unconfirmedText){
try{
const vr=await fetch('/api/v2/events/'+encodeURIComponent(eventId));
if(!vr.ok){btn.disabled=false;btn.textContent=unconfirmedText;
message('确认请求已提交，但状态暂未核实（服务端 '+vr.status+'），可重试','error');return false}
const vd=await vr.json();
const hit=(vd.notifications||[]).find(x=>x.notification_id===notificationId);
if(!hit){btn.disabled=false;btn.textContent=unconfirmedText;
message('确认请求已提交，但状态暂未核实（回读未含该通知），可重试','error');return false}
if(hit.user_confirmed===true){return true}
btn.disabled=false;btn.textContent=unconfirmedText;
message('确认请求已提交，但状态暂未核实（服务端尚未显示确认），可重试','error');return false}
catch(err){btn.disabled=false;btn.textContent=unconfirmedText;
message('确认请求已提交，但状态暂未核实（网络异常），可重试','error');return false}}
async function pollReminders(kind,cursorKey,renderedMap,prefix){
let cursor=window[cursorKey]||null;
for(let page=0;page<3;page++){
const url='/api/v2/notifications?limit=10&kind='+kind+(cursor?('&cursor='+encodeURIComponent(cursor)):'');
const response=await fetch(url);if(!response.ok){break}
const data=await response.json();
(data.notifications||[]).forEach(n=>{
if(renderedMap.has(n.notification_id)){return}
renderedMap.set(n.notification_id,true);
const item=document.createElement('div');item.className='reminder-item';
item.textContent=prefix+(kind==='semantic_update'?'（模型补充描述，可能有误）：':'：')+(n.text||'');const sub=document.createElement('div');sub.className='subtle';
sub.textContent=(n.camera||'')+' · '+new Date(n.created_at*1000).toLocaleString();item.appendChild(sub);
const openLink=document.createElement('a');openLink.textContent='查看版本详情';openLink.href='#';
openLink.onclick=ev=>{ev.preventDefault();openEventDetail(n.event_id)};
item.appendChild(document.createTextNode(' '));item.appendChild(openLink);
ui.banner.prepend(item);
if(n.state==='available'||n.state==='generated'){ackQueue.push(n.notification_id)}
if(kind==='semantic_update'&&!n.user_confirmed){
const cbtn=document.createElement('button');cbtn.className='confirm-btn';
cbtn.textContent='确认已看到';
cbtn.onclick=async()=>{cbtn.disabled=true;cbtn.textContent='正在确认…';
try{const r2=await fetch('/api/v2/notifications/user-confirm',{method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({notification_id:n.notification_id})});
if(!r2.ok){cbtn.disabled=false;cbtn.textContent='确认已看到';
message('人工确认未成功（服务端 '+r2.status+'），可重试','error');return}
cbtn.textContent='正在核实…';
const ok=await verifyConfirmFact(n.event_id,n.notification_id,cbtn,'确认已看到');
if(ok){cbtn.textContent='已人工确认 ✓';cbtn.classList.add('confirm-badge')}}
catch(err){cbtn.disabled=false;cbtn.textContent='确认已看到';
message('人工确认未成功（网络异常），可重试','error')}};item.appendChild(cbtn)}
});
window[cursorKey]=data.next_cursor||null;
if(!data.next_cursor){window[cursorKey]=null;break}
if(!(data.notifications||[]).length){window[cursorKey]=null;break}}}
async function refreshTimeline(){try{
await pollReminders('initial_fact','notifyCursor',rendered,'初始事实提醒');
await pollReminders('semantic_update','semCursor',semRendered,'新增一版理解');
await flushAckQueue();
response=await fetch('/api/v2/events');data=await response.json();ui.timeline.replaceChildren();
(data.events||[]).forEach(e=>{const row=ui.timeline.insertRow();
row.insertCell().textContent=e.t_start?new Date(e.t_start*1000).toLocaleString():'';
row.insertCell().textContent=e.camera||'';
const clsCell=row.insertCell();if(e.event_id){const link=document.createElement('a');link.textContent=e.cls||'';
link.href='/api/v2/events/'+encodeURIComponent(e.event_id);link.target='_blank';clsCell.appendChild(link)}else{clsCell.textContent=e.cls||''}
const st=row.insertCell();const badge=document.createElement('span');badge.className=e.state==='open'?'ev-open':'ev-closed';
badge.textContent=e.state==='open'?'进行中':('已结束'+(e.end_reason?'（'+e.end_reason+'）':''));st.appendChild(badge);
const detailCell=row.insertCell();const dLink=document.createElement('a');
dLink.textContent='打开详情';dLink.href='#';
dLink.onclick=ev2=>{ev2.preventDefault();openEventDetail(e.event_id);};
detailCell.appendChild(dLink);
const fact=row.insertCell();fact.textContent=(e.initial_fact_text||'')+(e.initial_notification_state?('（'+(REMINDER_STATE_TEXT[e.initial_notification_state]||e.initial_notification_state)+'）'):'');
const evd=row.insertCell();if(e.best_frame){const link=document.createElement('a');link.textContent='最佳帧';link.href=e.best_frame.content_url;link.target='_blank';evd.appendChild(link)}
else{evd.textContent='暂无可回看画面';evd.className='subtle'}
const esc=row.insertCell();if(e.escalation_count){esc.className='ev-esc';esc.textContent='规则升级 ×'+e.escalation_count}else{esc.textContent='—'}})}
catch(error){}}
async function refreshHealth(){try{const response=await fetch('/api/health');const data=await response.json();
const cameras=(data.runtime&&data.runtime.cameras)||[];ui.cameraStatus.replaceChildren();
const grid=document.getElementById('guard-grid');if(grid&&!grid.dataset.built){grid.dataset.built='1';cameras.forEach(camera=>{const card=document.createElement('div');card.className='guard-card';card.dataset.camera=camera.camera||'';
const head=document.createElement('div');head.className='guard-head';const dot=document.createElement('span');dot.className='guard-dot';head.appendChild(dot);
const name=document.createElement('span');name.textContent=camera.camera||'相机';head.appendChild(name);
const badge=document.createElement('span');badge.className='guard-badge';badge.style.display='none';head.appendChild(badge);card.appendChild(head);
const img=document.createElement('img');img.alt='画面';img.loading='lazy';card.appendChild(img);grid.appendChild(card)})}
Array.from(grid?grid.children:[]).forEach(card=>{const id=card.dataset.camera;const state=(cameras.find(c=>c.camera===id)||{}).state||'';
const dot=card.querySelector('.guard-dot');dot.className='guard-dot'+(knownStates.includes(state)?' '+state:'');
const badge=card.querySelector('.guard-badge');const n=guardEvents[id]||0;badge.style.display=n?'':'none';badge.textContent=n+' 告警';
const img=card.querySelector('img');img.src='/api/frame/'+encodeURIComponent(id)+'?t='+Date.now()});
if(!cameras.length){const line=document.createElement('div');line.className='camera-line';
line.textContent='尚未接线相机状态，请在值守运行时查看。';ui.cameraStatus.appendChild(line)}else{
cameras.forEach(camera=>{const line=document.createElement('div');
const state=knownStates.includes(camera.state)?camera.state:'';
line.className='camera-line'+(state?' '+state:'');
line.textContent=(camera.camera||'相机')+'：'+(camera.hint||'状态未知');ui.cameraStatus.appendChild(line)})}}
catch(error){ui.cameraStatus.textContent='相机状态暂不可用：请确认值守工作台仍在运行。'}}
async function refreshLists(){try{let response=await fetch('/api/review');let data=await response.json();
const review=document.querySelector('#review tbody');review.replaceChildren();(data.segments||[]).forEach(s=>{const row=review.insertRow();
row.insertCell().textContent=new Date(s.t_start*1000).toLocaleString();row.insertCell().textContent=s.camera||'';
row.insertCell().textContent=s.severity||'';row.insertCell().textContent=(s.object_ids||[]).length;row.insertCell().textContent=s.reviewed?'已读':'待审'});
response=await fetch('/api/events');data=await response.json();const events=document.querySelector('#events tbody');events.replaceChildren();
guardEvents={};(data.events||[]).forEach(e=>{if(e.camera)guardEvents[e.camera]=(guardEvents[e.camera]||0)+1;
const row=events.insertRow();row.insertCell().textContent=e.t_start?new Date(e.t_start*1000).toLocaleString():'';
let link=document.createElement('a');link.textContent=e.short_name||e.event_id;link.href='/api/events/'+encodeURIComponent(e.event_id);link.target='_blank';row.insertCell().appendChild(link);
row.insertCell().textContent=e.detail||'';let cell=row.insertCell();if(e.best_frame_asset_id){link=document.createElement('a');link.textContent='最佳帧';link.href='/api/evidence/'+encodeURIComponent(e.best_frame_asset_id);link.target='_blank';cell.appendChild(link)}
cell=row.insertCell();if(e.clip_asset_id){link=document.createElement('a');link.textContent='录像';link.href='/api/recordings/'+encodeURIComponent(e.clip_asset_id);link.target='_blank';cell.appendChild(link)}
cell=row.insertCell();const fb=document.createElement('button');fb.textContent='误报';fb.onclick=async()=>{try{const r=await fetch('/api/patterns/feedback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({event_id:e.event_id,misreport:true})});fb.textContent=r.ok?'已标记':'无档案';fb.disabled=true}catch(err){fb.textContent='失败'}};cell.appendChild(fb)});
response=await fetch('/api/patterns');data=await response.json();document.getElementById('patterns').textContent=(data.patterns||[]).map(p=>p.name).join('、')||'暂无已学习模式';
}catch(error){document.getElementById('health').textContent='工作台数据暂不可用'}}
async function openEventDetail(eventId){
const panel=document.getElementById('event-detail-panel');
panel.hidden=false;panel.scrollIntoView({behavior:'smooth',block:'nearest'});
document.getElementById('event-detail-body').replaceChildren();
document.getElementById('event-detail-title').textContent='事件详情：加载中…';
try{const response=await fetch('/api/v2/events/'+encodeURIComponent(eventId));
if(!response.ok){document.getElementById('event-detail-title').textContent='事件详情不可用';return}
const d=await response.json();
document.getElementById('event-detail-title').textContent=
'事件详情 · '+(d.camera||'')+' · '+(d.state==='open'?'进行中':'已结束'+(d.end_reason?'（'+d.end_reason+'）':''));
const body=document.getElementById('event-detail-body');
// 原始事实（时间/类别/状态）
const meta=document.createElement('div');meta.className='subtle';
meta.textContent='首次观察：'+new Date(d.t_start*1000).toLocaleString()+' · 类别：'+(d.cls||'');
body.appendChild(meta);
// 描述版本（v1→v2+ 顺序；观察/推断分栏；纯文本渲染）
(d.descriptions||[]).sort((a,b)=>a.version-b.version).forEach(desc=>{
const box=document.createElement('div');box.className='desc-version';
const head=document.createElement('div');
head.textContent='v'+desc.version+' · '+(desc.source==='vlm'?'模型补充描述（可能有误，待结合证据核对）':'初始事实（系统记录）')
+' · '+new Date(desc.t_created*1000).toLocaleString()
+' · '+(desc.source==='vlm'?'模型自报不确定性：'+(desc.uncertainty||'未知')+'（未经系统核实）':'不确定性：'+(desc.uncertainty||'未知'));
box.appendChild(head);
if(desc.source==='vlm'){const note=document.createElement('div');note.className='subtle';
note.textContent='以下为模型原文，仅供结合证据核对，不作为告警或事实依据；不影响事件事实与提醒。';
box.appendChild(note)}
const obs=document.createElement('div');
if(Array.isArray(desc.observed)&&desc.observed.length){
obs.textContent='观察到（画面可直接确认）：'+desc.observed.join('；');}
else{obs.textContent=desc.text||''}
box.appendChild(obs);
if(desc.inference){const inf=document.createElement('div');inf.className='subtle';
inf.textContent='模型推断（非人工确认）：'+desc.inference;box.appendChild(inf)}
if(desc.source==='vlm'&&Array.isArray(desc.evidence_refs)&&desc.evidence_refs.length){
const ev=document.createElement('div');ev.className='subtle';
ev.textContent='证据：受控资产 '+desc.evidence_refs.join('、');box.appendChild(ev)}
body.appendChild(box)});
// 失败/等待状态
const sem=d.semantic||{};
if(sem.state==='waiting_retry'||sem.state==='failed_terminal'){
const warn=document.createElement('div');warn.className='subtle';
warn.textContent='语义更新：'+(sem.code==='evidence_missing_or_corrupt'?'证据缺失或损坏，可复核后重试。':'模型暂不可用，将自动重试。');
body.appendChild(warn)}
else if(!hasV2(d)){const note=document.createElement('div');note.className='subtle';
note.textContent='暂未生成进一步理解';body.appendChild(note)}
// 人工确认（主动点击；独立持久化事实；刷新/重启保持）。
// 显示回执（ack）≠人工确认（user-confirm）：按钮显隐只由 user_confirmed 事实
// 控制，与通知的 available/acknowledged 显示状态无关；已确认显示固定徽标。
const notifs=d.notifications||[];
const area=document.getElementById('confirm-area');area.replaceChildren();
(notifs.filter(n=>n.kind==='initial_fact'&&n.user_confirmed)).forEach(n=>{
const badge=document.createElement('span');badge.className='confirm-badge';
badge.textContent='已人工确认 ✓';area.appendChild(badge)});
(notifs.filter(n=>n.kind==='initial_fact'&&!n.user_confirmed)).forEach(n=>{
const btn=document.createElement('button');btn.className='confirm-btn';
btn.textContent='确认已看到此事件（人工确认）';
btn.onclick=async()=>{btn.disabled=true;btn.textContent='正在确认…';
try{const r=await fetch('/api/v2/notifications/user-confirm',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({notification_id:n.notification_id})});
if(!r.ok){btn.disabled=false;btn.textContent='确认已看到此事件（人工确认）';
message('人工确认未成功（服务端 '+r.status+'），可重试','error');return}
btn.textContent='正在核实…';
const ok=await verifyConfirmFact(eventId,n.notification_id,btn,'确认已看到此事件（人工确认）');
if(ok){area.replaceChildren();
const badge=document.createElement('span');badge.className='confirm-badge';
badge.textContent='已人工确认 ✓';area.appendChild(badge)}}
catch(err){btn.disabled=false;
btn.textContent='确认已看到此事件（人工确认）';
message('人工确认未成功（网络异常），可重试','error')}};
area.appendChild(btn)})}
catch(err){document.getElementById('event-detail-title').textContent='事件详情加载失败'}}
function hasV2(d){return (d.descriptions||[]).some(x=>x.source==='vlm')}
window.addEventListener('resize',alignGrid);loadCameras().catch(()=>message('相机配置读取失败','error'));refreshLists();setInterval(refreshLists,3000);
refreshTimeline();setInterval(refreshTimeline,3000);
refreshHealth();setInterval(refreshHealth,5000);
</script></body></html>'''


# 逐相机运行状态与检测能力：固定词表，值守线程写入、工作台读取。
RUNTIME_STATES = ("connecting", "online", "degraded", "stopped")
CAPABILITY_STATES = ("alerting", "monitor_only", "detector_unavailable")

# 固定 issue code → 固定中文动作。工作台故障只走这一条出口：不回显 source、
# RTSP 凭据、模型绝对路径或原始异常正文（异常正文可能夹带 URL 与磁盘布局）。
ISSUE_ACTIONS = {
    "source_open_failed": "检查相机电源、网线与地址后等待自动重连",
    "source_read_failed": "检查网络与相机供电；持续失败请重启相机",
    # 文件源（回放/演示）故障原因与网络相机不同：文件不存在、被移动或编码
    # 损坏，套用“检查网络与供电”会把人引到错误方向。
    "file_source_open_failed": "检查视频文件是否存在且可读；修好后等待自动重连",
    "file_source_read_failed": "检查视频文件是否完整可解码；读完会自动从头继续",
    # 数据面故障：审查段或管理员事件没能写进本机数据库。与源/检测故障分开，
    # 因为它的影响是"告警真值缺失"，而快路径本身仍可能在正常出图。
    "persistence_degraded": "审查段或告警未能写入本机数据库；检查磁盘空间与数据库可写性",
    "detector_missing": "把检测模型放到配置路径后重启值守",
    "detector_load_failed": "确认模型文件完整且 onnxruntime 可用后重启值守",
    "workbench_port_in_use": "关闭占用该端口的程序，或用 --port 改用其它端口",
}

_STATE_HINTS = {
    "connecting": "连接中：正在建立视频源连接",
    "online": "在线",
    "degraded": "断流：视频源未能打开或读取失败",
    "stopped": "已停止：值守线程已退出",
}
_CAPABILITY_HINTS = {
    "alerting": "检测告警已启用",
    "monitor_only": "仅预览：管理员未启用检测器",
    "detector_unavailable": "检测不可用：模型缺失或加载失败",
}


def issue(code):
    """固定 issue code → 去凭据的结构化 issue；未知 code 绝不回显原文。"""
    action = ISSUE_ACTIONS.get(code)
    if action is None:
        return None
    return {"code": code, "action": action}


def _hint(state, capability, problem, persistence=None):
    """一句简短可操作中文提示：状态 + 能力，有故障时以动作收尾。

    数据面故障（写不进库）与源/检测故障可以同时存在，因此单独追加，不被
    源侧提示遮住——否则"画面正常但告警没落库"会看不出来。
    """
    if state == "stopped":
        return _STATE_HINTS["stopped"]
    if problem is not None:
        base = f"{_STATE_HINTS[state]}；{problem['action']}"
    else:
        base = f"{_STATE_HINTS[state]}；{_CAPABILITY_HINTS[capability]}"
    if persistence is not None:
        base = f"{base}；{persistence['action']}"
    return base


class CameraRuntimeRegistry:
    """逐相机运行/能力状态的线程安全真值（工作台健康提示的唯一来源）。

    所有已配置相机在构造时即登记为 ``connecting``；检测能力默认取最小能力
    ``monitor_only``——注册表自身绝不推断 ``alerting``，只有值守线程按配置与
    加载结果写入。快照只含固定状态、固定 issue code 与固定中文动作。
    """

    def __init__(self, camera_ids):
        ids = [str(camera_id) for camera_id in camera_ids]
        if len(ids) != len(set(ids)):
            raise ValueError("camera ids must be unique")
        self._lock = threading.Lock()
        self._order = sorted(ids)
        self._cameras = {
            camera_id: {"camera": camera_id, "state": "connecting",
                        "capability": "monitor_only", "issue": None,
                        "detector_issue": None,
                        "persistence_issue": None}
            for camera_id in ids}

    def _write(self, camera_id, **fields):
        with self._lock:
            try:
                entry = self._cameras[str(camera_id)]
            except KeyError as exc:
                raise KeyError(f"unknown camera: {camera_id}") from exc
            entry.update(fields)

    def _set_state(self, camera_id, state, problem):
        if state not in RUNTIME_STATES:
            raise ValueError(f"unknown runtime state: {state!r}")
        self._write(camera_id, state=state, issue=problem)

    def starting(self, camera_id):
        """值守线程已开始建立视频源连接。"""
        self._set_state(camera_id, "connecting", None)

    def online(self, camera_id):
        """视频源已打开且帧可读；清除源侧 issue（读失败恢复也走这里）。"""
        self._set_state(camera_id, "online", None)

    def degraded(self, camera_id, code):
        """源打开或读取失败：进入 degraded 并挂固定 issue。"""
        problem = issue(code)
        if problem is None:
            raise ValueError(f"unknown issue code: {code!r}")
        self._set_state(camera_id, "degraded", problem)

    def detector(self, camera_id, capability, code=None):
        """按配置或加载结果改写检测能力；``code`` 仅在不可用时给出。"""
        if capability not in CAPABILITY_STATES:
            raise ValueError(f"unknown capability: {capability!r}")
        self._write(camera_id, capability=capability,
                    detector_issue=issue(code))

    def persistence(self, camera_id, code=None):
        """数据面故障：审查段/告警写入失败（``code`` 为 None 表示恢复正常）。

        与源状态解耦：源可以在线出图，同时告警真值写不进去。这里的失败必须
        可见——不得只留在监控线程的内部计数里。未知 code 照旧 fail-closed，
        健康面只出固定词表，绝不臆造文案。
        """
        problem = issue(code)
        if code is not None and problem is None:
            raise ValueError(f"unknown issue code: {code!r}")
        self._write(camera_id, persistence_issue=problem)

    def stopped(self, camera_id):
        """值守线程已退出：源侧故障随之消失，检测配置事实保留。"""
        self._set_state(camera_id, "stopped", None)

    def snapshot(self):
        """API 就绪快照：逐相机状态与固定中文提示，不含任何凭据或路径。"""
        with self._lock:
            cameras = []
            for camera_id in self._order:
                entry = self._cameras[camera_id]
                problem = entry["issue"] or entry["detector_issue"]
                persistence = entry.get("persistence_issue")
                cameras.append({
                    "camera": entry["camera"],
                    "state": entry["state"],
                    "capability": entry["capability"],
                    "issue": dict(problem) if problem is not None else None,
                    "persistence_issue": (dict(persistence)
                                          if persistence is not None else None),
                    "hint": _hint(entry["state"], entry["capability"], problem,
                                  persistence),
                })
        return {"cameras": cameras, "count": len(cameras)}


def _encode_notify_cursor(row):
    """游标=上一页末行 (created_at, notification_id) 的不透明编码。"""
    raw = json.dumps([row["created_at"], row["notification_id"]],
                     separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def _decode_notify_cursor(token):
    """非法游标一律 ValueError（路由层 400），绝不进入查询。

    严格校验：编码形态（urlsafe base64 的 JSON 二元组）、大小上限、时间戳
    必须是**有限**数（NaN/±Infinity 一律拒绝，json 扩展面也挡）、标识必须是
    受控字符串（长度上限、无路径分隔符）。任何不合格输入在进数据库之前拒绝。
    """
    if not isinstance(token, str) or not token or len(token) > 512:
        raise ValueError("invalid cursor")
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
    except Exception:
        raise ValueError("invalid cursor")
    try:
        data = json.loads(raw)
    except Exception:
        raise ValueError("invalid cursor")
    if (not isinstance(data, list) or len(data) != 2
            or isinstance(data[0], bool)
            or not isinstance(data[0], (int, float))
            or not isinstance(data[1], str) or not data[1]
            or len(data[1]) > 200
            or "/" in data[1] or "\\" in data[1]):
        raise ValueError("invalid cursor")
    if not math.isfinite(float(data[0])):
        raise ValueError("invalid cursor")
    return (float(data[0]), data[1])


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
        # CameraRuntimeRegistry（值守接线后设置）；未接线时不伪造相机状态。
        self.runtime = None
        # 运行实例身份：每次构造唯一，供 R3 重启验收区分“同一份配置的不同进程
        # 实例”。只含随机标识与 UTC 启动时间——绝不含主机名、路径、PID 或凭据。
        self.runtime_instance_id = uuid.uuid4().hex
        self.started_at = datetime.now(timezone.utc).isoformat()
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

    # ---- 环境基线（工作包 A：值守前置 + 版本化可追溯） ----

    def _record_baseline_failure(self, camera_id, summary):
        from .db import record_environment_baseline_failure
        conn = self._conn()
        try:
            record_environment_baseline_failure(conn, camera_id,
                                                summary=summary)
        finally:
            conn.close()

    def environment_baseline(self, camera_id):
        """当前相机基线状态（零模型调用、零路径外泄）。

        "已存过版本"与"当前可进入正常值守"分开：当前版本原始画面缺失/损坏/
        哈希不符时返回 evidence_broken（需修复或复核），绝不按 ready 解锁。
        历史版本行永不因证据丢失被删除或改写。旧 meta env: 文本档案不算基线。
        """
        if not CAMERA_ID_RE.match(camera_id or ""):
            return None
        from .db import environment_baseline_status
        conn = self._conn()
        try:
            status = environment_baseline_status(conn, camera_id)
        finally:
            conn.close()
        legacy = self._legacy_environment_profile(camera_id)
        status["legacy_profile"] = bool(legacy)
        status["evidence_available"] = False
        if status.get("state") == "baseline_required" and legacy:
            status["reason"] = "legacy_profile_without_evidence"
        if status.get("state") == "ready":
            try:
                self.evidence.read_scene_frame(
                    status["evidence_path"],
                    sha256=status.get("evidence_sha256"),
                    size_bytes=status.get("evidence_size"))
                status["evidence_available"] = True
            except (ValueError, TypeError):
                # 当前版本证据失效：版本行与历史照旧保留，但不得解锁值守
                status["state"] = "evidence_broken"
                status["evidence_available"] = False
                status["reason"] = "evidence_missing_or_corrupt"
        if status.get("model_id") == "unknown":
            status["comparison_insufficient"] = True
        status.pop("evidence_path", None)   # 本机路径绝不下发
        status.pop("evidence_sha256", None)
        status.pop("evidence_size", None)
        return status

    def _legacy_environment_profile(self, camera_id):
        if not CAMERA_ID_RE.match(camera_id or ""):
            return None
        conn = self._conn()
        try:
            return EnvironmentStore(conn).load(camera_id)
        finally:
            conn.close()

    def environment_baseline_history_v2(self, camera_id, limit=20):
        """版本历史：每版逐次完整性复核可回看性，旧版与当前版可辨识。

        evidence_available 为该版本自己的原始画面（绝不拿当前帧冒充旧帧）；
        模型/配置标识缺失时如实 unknown 并标注比较条件不足。
        """
        from .db import environment_baseline_history
        if not CAMERA_ID_RE.match(camera_id or ""):
            return None
        conn = self._conn()
        try:
            rows = environment_baseline_history(conn, camera_id, limit=limit)
        finally:
            conn.close()
        from .db import get_environment_baseline
        conn = self._conn()
        try:
            for row in rows:
                full = get_environment_baseline(conn, row["baseline_id"])
                available = False
                if full is not None and full.get("evidence_path"):
                    try:
                        self.evidence.read_scene_frame(
                            full["evidence_path"],
                            sha256=full.get("evidence_sha256"),
                            size_bytes=full.get("evidence_size"))
                        available = True
                    except (ValueError, TypeError):
                        available = False
                row["evidence_available"] = available
                row["is_current"] = (row.get("status") == "valid")
                if row.get("model_id") == "unknown":
                    row["comparison_insufficient"] = True
        finally:
            conn.close()
        return rows

    def _discard_attempt_file(self, stored):
        """失败清理双证（A-R2）：本次尝试令牌 + 库内零引用才可删。

        不能仅凭"计算出的文件名等于本次路径"认定所有权；引用核验不可用时
        保守不删（宁可留待人工，绝不误删旧版本证据）。
        """
        try:
            check = self._conn()
            try:
                row = check.execute(
                    "SELECT COUNT(*) AS n FROM environment_baselines"
                    " WHERE evidence_path=?", (stored["path"],)).fetchone()
                referenced = int(row["n"])
            finally:
                check.close()
        except Exception:
            referenced = 1   # 无法核验引用 → 保守不删
        if referenced > 0:
            return
        try:
            self.evidence.discard_attempt_file(
                stored["path"], stored.get("owner_token"))
        except (ValueError, OSError):
            pass

    def read_baseline_frame(self, camera_id, baseline_id=None):
        """按受控版本身份读取该版本自己的原始画面；返回 (state, bytes|None)。

        每次读取逐字节校验大小与完整 SHA-256；不存在/损坏 → 明确不可回看，
        绝不以当前帧替代旧帧；不接受任何客户端文件路径。
        """
        from .db import get_environment_baseline, environment_baseline_status
        if baseline_id is not None and ("/" in baseline_id or "\\"
                                        in baseline_id or not baseline_id):
            return "unknown", None
        conn = self._conn()
        try:
            if baseline_id is None:
                status = environment_baseline_status(conn, camera_id)
                row = ({"evidence_path": status.get("evidence_path"),
                        "evidence_sha256": status.get("evidence_sha256"),
                        "evidence_size": status.get("evidence_size"),
                        "camera": camera_id}
                       if status.get("state") in ("ready", "evidence_broken")
                       else None)
            else:
                row = get_environment_baseline(conn, baseline_id)
                if row is not None and row.get("camera") != camera_id:
                    row = None
        finally:
            conn.close()
        if row is None or not row.get("evidence_path"):
            return "unavailable", None
        try:
            content = self.evidence.read_scene_frame(
                row["evidence_path"],
                sha256=row.get("evidence_sha256"),
                size_bytes=row.get("evidence_size"))
        except (ValueError, TypeError):
            return "corrupt", None
        return "available", content

    def establish_environment_baseline(self, camera_id, *, mode="first-use",
                                       cloud_confirmed=False):
        """建立/复核环境基线：采集全屏帧 → 受控落盘 → 识别 → 版本化落库。

        返回 (state, payload)。state: ok | unknown | busy |
        frame_unavailable | confirmation_required | unavailable | invalid |
        conflict。失败只记固定中文摘要，不触碰既有有效版本；云端必须逐次
        确认（在任何外发之前拒绝）。
        """
        if not CAMERA_ID_RE.match(camera_id or ""):
            return "unknown", None
        if camera_id not in self.monitors and not any(
                camera["id"] == camera_id for camera in self.cameras()):
            return "unknown", None
        with self._lock:
            building = getattr(self, "_baseline_building", None)
            if building is None:
                building = set()
                self._baseline_building = building
            if camera_id in building:
                return "busy", None
            building.add(camera_id)
        try:
            monitor = self.monitors.get(camera_id)
            frame = getattr(monitor, "latest_frame_bgr", None)
            if frame is None:
                self._record_baseline_failure(camera_id, "当前相机尚无可用画面")
                return "frame_unavailable", None
            try:
                frame = frame.copy()
            except (AttributeError, TypeError, ValueError):
                self._record_baseline_failure(camera_id, "当前相机尚无可用画面")
                return "frame_unavailable", None
            conn = self._conn()
            try:
                env_state, profile = EnvironmentStore(conn).analyze(
                    camera_id, provider=self.environment_provider,
                    frame_bgr=frame, cloud_confirmed=cloud_confirmed)
            finally:
                conn.close()
            if env_state != "ok" or not isinstance(profile, dict):
                reason = {"confirmation_required": "云端识别需要逐次确认",
                          "invalid": "识别结果不完整，请重试",
                          "unavailable": "识别服务暂不可用"}.get(
                              env_state, "识别失败")
                self._record_baseline_failure(camera_id, reason)
                return env_state, None
            # 原始画面：用与识别完全相同的参数重编码，哈希对齐 profile
            import cv2
            try:
                ok, encoded = cv2.imencode(
                    ".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
            except (cv2.error, TypeError, ValueError):
                ok = False
            if not ok:
                self._record_baseline_failure(camera_id, "画面编码失败")
                return "unavailable", None
            jpeg = encoded.tobytes()
            expected = profile.get("frame_sha256")
            if expected and hashlib.sha256(jpeg).hexdigest() != expected:
                # 画面与识别对象不一致：绝不把对不上号的证据写成基线
                self._record_baseline_failure(camera_id, "画面与识别结果不一致")
                return "unavailable", None
            stored = self.evidence.save_scene_frame(
                camera=camera_id, frame_bytes=jpeg,
                established_at=time.time())
            from .db import establish_environment_baseline
            summary_parts = [str(profile.get("scene_type") or ""),
                             str(profile.get("lighting") or ""),
                             str(profile.get("risk_notes") or "")]
            # 真实可辨认的模型标识与配置指纹；拿不到就写 unknown 并标注
            # "比较条件不足"，绝不用 channel 名或网格尺寸冒充身份。
            model_id = str(getattr(self.environment_provider, "model", "")
                           or "unknown")
            provider_base = getattr(self.environment_provider, "base", None)
            try:
                from .environment import build_prompt
                fingerprint_src = json.dumps(
                    {"model": model_id,
                     "base": str(provider_base) if provider_base else None,
                     "prompt": build_prompt()},
                    sort_keys=True, ensure_ascii=False)
                fingerprint = hashlib.sha256(
                    fingerprint_src.encode("utf-8")).hexdigest()[:16]
            except Exception:
                fingerprint = "unknown"
            if model_id == "unknown" or fingerprint == "unknown":
                fingerprint = "unknown"


            db_conn = self._conn()
            try:
                version = establish_environment_baseline(
                    db_conn,
                    camera=camera_id,
                    baseline_id="baseline:" + camera_id + ":"
                                + uuid.uuid4().hex[:12],
                    established_at=time.time(),
                    established_via=("review" if mode == "review"
                                     else "first-use"),
                    scene_summary=" · ".join(
                        part for part in summary_parts if part),
                    machine_state=str(profile.get("machine_state")
                                      or "unknown"),
                    profile=profile,
                    model_id=model_id,
                    config_fingerprint=fingerprint,
                    evidence_path=stored["path"],
                    evidence_sha256=stored["sha256"],
                    evidence_size=stored["size_bytes"],
                    payload={"frame_sha256": expected,
                             "provider_analyzed_at": profile.get(
                                 "analyzed_at"),
                             "comparison_insufficient": (
                                 model_id == "unknown")})
            except Exception:
                db_conn.close()
                self._discard_attempt_file(stored)
                self._record_baseline_failure(camera_id, "基线写入失败")
                return "unavailable", None
            db_conn.close()
            if version is None:
                # 指针竞争：本次新写文件同样清理，绝不留孤立资产
                self._discard_attempt_file(stored)
                return "conflict", None
            return "ok", {"camera": camera_id, "version": version,
                          "profile": profile,
                          "model_id": model_id,
                          "config_fingerprint": fingerprint,
                          "comparison_insufficient": (
                              model_id == "unknown")}
        finally:
            with self._lock:
                building = getattr(self, "_baseline_building", set())
                building.discard(camera_id)

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

    # ---- 事件事实 v2（用户可见事件；旧 /api/events 语义保持不变） ----

    def list_event_facts_v2(self, camera=None, state=None, limit=50):
        """事件事实列表；服务即"工作台可读取"（generated→available，幂等）。"""
        from .db import list_event_facts, mark_notification_available
        conn = self._conn()
        try:
            rows = list_event_facts(conn, camera=camera, state=state,
                                    limit=limit)
            for row in rows:
                if row.get("initial_notification_state") == "generated" \
                        and row.get("initial_notification_id"):
                    if mark_notification_available(
                            conn, row["initial_notification_id"],
                            at=time.time()):
                        row["initial_notification_state"] = "available"
        finally:
            conn.close()
        for row in rows:
            row["best_frame"] = (
                {"asset_id": row["best_frame_asset_id"],
                 "content_url": "/api/evidence/"
                                + quote(row["best_frame_asset_id"])}
                if row.get("best_frame_asset_id") else None)
            row.pop("best_frame_asset_id", None)
            row.pop("initial_notification_id", None)
        return {"events": rows}

    def event_fact_detail(self, event_id):
        """事件事实详情：原始观察/描述版本/规则升级/提醒状态四类身份分开。

        证据走受控 asset_id 与既有读取端点；来源时间不可信时不给端到端时延。
        找不到返回 None；本机路径与凭据绝不进入响应。
        """
        from .db import get_event_fact
        conn = self._conn()
        try:
            detail = get_event_fact(conn, event_id)
        finally:
            conn.close()
        if detail is None:
            return None
        timestamp_kind = None
        try:
            payload = json.loads(detail.get("payload") or "{}")
            if isinstance(payload, dict):
                timestamp_kind = payload.get("timestamp_kind")
        except (TypeError, ValueError):
            timestamp_kind = None
        detail.pop("payload", None)
        for key in ("bbox_first", "bbox_last"):
            try:
                detail[key] = json.loads(detail[key]) if detail.get(key) \
                    else None
            except (TypeError, ValueError):
                detail[key] = None
        asset_id = detail.pop("best_frame_asset_id", None)
        detail["best_frame"] = (
            {"asset_id": asset_id,
             "content_url": "/api/evidence/" + quote(asset_id)}
            if asset_id else None)
        for item in detail["descriptions"]:
            try:
                item["evidence_refs"] = json.loads(
                    item.get("evidence_refs") or "[]")
            except (TypeError, ValueError):
                item["evidence_refs"] = []
            try:
                payload_d = json.loads(item.get("payload") or "{}")
            except (TypeError, ValueError):
                payload_d = {}
            if not isinstance(payload_d, dict):
                payload_d = {}
            item["observed"] = payload_d.get("observed")
            item["inference"] = payload_d.get("inference")
            item["evidence_digest"] = payload_d.get("evidence_digest")
            item["model_id"] = payload_d.get("model_id")
            item.pop("payload", None)
        for item in detail["notifications"]:
            # 时延字段只说可证实的真话：
            # created_delay_s = 事件时间→提醒创建（须源时间可信、非负）
            # display_delay_s = 创建→客户端显示回执（服务端同钟；仍非人工已读）
            # end_to_end_latency_s 恒 null（已废弃：端到端"用户收到"时延不可测）
            trusted = timestamp_kind == "source_capture"
            created_delay = None
            display_delay = None
            if trusted and item.get("t_event") is not None                     and item.get("created_at") is not None:
                delta = float(item["created_at"]) - float(item["t_event"])
                if delta >= 0:
                    created_delay = round(delta, 3)
            if item.get("acknowledged_at") is not None                     and item.get("created_at") is not None:
                delta = (float(item["acknowledged_at"])
                         - float(item["created_at"]))
                if delta >= 0:
                    display_delay = round(delta, 3)
            item["created_delay_s"] = created_delay
            item["display_delay_s"] = display_delay
            item["end_to_end_latency_s"] = None
            item["user_confirmed"] = item.get("user_confirmed_at") is not None
        # 语义更新状态（第一切片）：v1 恒可看；无 v2/失败/处理中如实区分；
        # 不泄露本机路径、相机凭据或模型内部错误原文（只给固定 reason）。
        updater = getattr(self, "semantic", None)
        if updater is not None and hasattr(updater, "event_state"):
            detail["semantic"] = updater.event_state(event_id)
        else:
            detail["semantic"] = {"state": "none", "reason": None}
        has_v2 = any(d["source"] == "vlm" for d in detail["descriptions"])
        if has_v2 and detail["semantic"]["state"] == "none":
            detail["semantic"] = {"state": "published", "code": None,
                                  "attempts": None}
        if not has_v2:
            detail["semantic_note"] = "暂未生成进一步理解"
        return detail

    def list_initial_notifications_v2(self, limit=20, cursor=None,
                                      kind="initial_fact"):
        """初始事实提醒列表（游标分页）；服务即"可读取"（幂等转 available）。

        排序 (created_at DESC, notification_id DESC)；next_cursor 只在本页
        取满时给出（页尾即遍历尽头）。单条长期未确认不影响其他提醒分页。
        """
        from .db import list_initial_notifications, mark_notification_available
        decoded = None
        if cursor:
            decoded = _decode_notify_cursor(cursor)   # 非法游标 → ValueError
        conn = self._conn()
        try:
            rows = list_initial_notifications(conn, limit=limit,
                                              cursor=decoded, kind=kind)
            for row in rows:
                # 用户主动确认（user_confirmed_at）≠ 客户端已显示回执；
                # 布尔化下发，工作台据此决定是否还提供确认按钮。
                row["user_confirmed"] = row.get("user_confirmed_at") is not None
                if row.get("state") == "generated":
                    if mark_notification_available(
                            conn, row["notification_id"], at=time.time()):
                        row["state"] = "available"
        finally:
            conn.close()
        next_cursor = None
        if len(rows) == limit and rows:
            next_cursor = _encode_notify_cursor(rows[-1])
        return {"notifications": rows, "next_cursor": next_cursor}

    def acknowledge_notification(self, notification_id):
        """客户端渲染回执：幂等确认；未知 id 返回 None（404），重复回执 False。"""
        from .db import acknowledge_notification
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT notification_id FROM event_notifications"
                " WHERE notification_id=?", (notification_id,)).fetchone()
            if row is None:
                return None
            changed = acknowledge_notification(conn, notification_id,
                                               at=time.time())
        finally:
            conn.close()
        return changed


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
        if path.startswith("/api/environment/") and \
                "/baselines/" in path and path.endswith("/frame"):
            rest = path[len("/api/environment/"):]
            camera_id, tail = rest.split("/baselines/", 1)
            baseline_id = unquote(tail[:-len("/frame")])
            if not camera_id or "/" in camera_id or not baseline_id \
                    or "/" in baseline_id or "\\" in baseline_id:
                self._json({"error": "baseline not found"}, 404)
                return
            state_, content = self.server.state.read_baseline_frame(
                camera_id, baseline_id=baseline_id)
            if state_ != "available":
                self._json({"error": "baseline frame unavailable",
                            "state": state_}, 404)
                return
            self._jpeg(content)
            return
        if path.startswith("/api/environment/") and \
                path.endswith("/baseline/frame"):
            camera_id = unquote(
                path[len("/api/environment/"):-len("/baseline/frame")])
            if not camera_id or "/" in camera_id:
                self._json({"error": "camera not found"}, 404)
                return
            state_, content = self.server.state.read_baseline_frame(camera_id)
            if state_ != "available":
                self._json({"error": "baseline frame unavailable",
                            "state": state_}, 404)
                return
            self._jpeg(content)
            return
        if path.startswith("/api/environment/") and \
                path.endswith("/baselines"):
            camera_id = unquote(
                path[len("/api/environment/"):-len("/baselines")])
            if not camera_id or "/" in camera_id:
                self._json({"error": "camera not found"}, 404)
                return
            history = self.server.state.environment_baseline_history_v2(
                camera_id)
            if history is None:
                self._json({"error": "camera not found"}, 404)
                return
            self._json({"camera": camera_id, "baselines": history})
            return
        if path.startswith("/api/environment/"):
            camera_id = unquote(path[len("/api/environment/"):])
            status = self.server.state.environment_status(camera_id)
            if status is None:
                self._json({"error": "camera not found"}, 404)
                return
            # 工作包 A：基线状态随环境档案一并返回（零模型调用）
            status["baseline"] = self.server.state.environment_baseline(
                camera_id)
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
            # 值守接线后才附加逐相机运行/能力状态；未接线时保持既有形状，
            # 快照异常结构化降级，绝不让 health 端点 500。
            runtime = getattr(self.server.state, "runtime", None)
            if runtime is not None:
                try:
                    payload["runtime"] = runtime.snapshot()
                except Exception as exc:
                    payload["runtime"] = {
                        "state": "unavailable", "error": type(exc).__name__}
                # 运行实例身份只在值守已接线时声明：未接线路径（既有 Linux
                # 兼容形状）顶层键集一字不动。值只含随机标识与 UTC 时间。
                instance_id = getattr(
                    self.server.state, "runtime_instance_id", None)
                started_at = getattr(self.server.state, "started_at", None)
                if isinstance(instance_id, str) and instance_id \
                        and isinstance(started_at, str) and started_at:
                    payload["runtime_instance"] = {
                        "runtime_instance_id": instance_id,
                        "started_at": started_at,
                    }
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
            # S2 慢系统：入口传入 state.slow_worker 时披露水位/计数/最近错误；
            # 快照异常结构化降级，绝不让 health 端点 500 或拖慢快路径。
            slow = getattr(self.server.state, "slow_worker", None)
            if slow is not None:
                try:
                    payload["slow"] = slow.snapshot()
                except Exception as exc:
                    payload["slow"] = {
                        "state": "unavailable", "error": type(exc).__name__}
            # 通知出口（可选）：入口配置了 notify 段才披露；快照异常降级。
            notify_hub = getattr(self.server.state, "notify_hub", None)
            if notify_hub is not None:
                try:
                    payload["notify"] = notify_hub.snapshot()
                except Exception as exc:
                    payload["notify"] = {
                        "state": "unavailable", "error": type(exc).__name__}
            # 补账待补数（工作包 B）：值守已启动 ≠ 积压已清零，如实披露
            backfill = getattr(self.server.state, "backfill", None)
            if backfill is not None:
                try:
                    payload["backfill"] = dict(backfill)
                except Exception as exc:
                    payload["backfill"] = {
                        "state": "unavailable", "error": type(exc).__name__}
            # 语义更新后台链（第一切片）：待处理/处理中/失败/最近错误如实显示
            semantic = getattr(self.server.state, "semantic", None)
            if semantic is not None and hasattr(semantic, "snapshot"):
                try:
                    payload["semantic"] = semantic.snapshot()
                except Exception as exc:
                    payload["semantic"] = {
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
        if path == "/api/v2/events":
            query = parse_qs(self.path.split("?", 1)[1]) \
                if "?" in self.path else {}
            camera = (query.get("camera") or [None])[0]
            event_state = (query.get("state") or [None])[0]
            try:
                limit = int((query.get("limit") or ["50"])[0])
            except ValueError:
                limit = 50
            try:
                payload = self.server.state.list_event_facts_v2(
                    camera=camera, state=event_state, limit=limit)
            except Exception:
                self._json({"error": "events unavailable"}, 503)
                return
            self._json(payload)
            return
        if path.startswith("/api/v2/events/"):
            event_id = unquote(path[len("/api/v2/events/"):])
            if not event_id or "/" in event_id:
                self._json({"error": "event not found"}, 404)
                return
            try:
                detail = self.server.state.event_fact_detail(event_id)
            except Exception:
                self._json({"error": "events unavailable"}, 503)
                return
            if detail is None:
                self._json({"error": "event not found"}, 404)
                return
            self._json(detail)
            return
        if path == "/api/v2/notifications":
            query = parse_qs(self.path.split("?", 1)[1]) \
                if "?" in self.path else {}
            try:
                limit = int((query.get("limit") or ["20"])[0])
            except ValueError:
                limit = 20
            cursor = (query.get("cursor") or [None])[0]
            kind = (query.get("kind") or ["initial_fact"])[0]
            if kind not in ("initial_fact", "semantic_update"):
                self._json({"error": "invalid kind"}, 400)
                return
            try:
                payload = self.server.state.list_initial_notifications_v2(
                    limit=limit, cursor=cursor, kind=kind)
            except ValueError:
                self._json({"error": "invalid cursor"}, 400)
                return
            except Exception:
                self._json({"error": "notifications unavailable"}, 503)
                return
            self._json(payload)
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
        if path == "/api/environment/baseline":
            camera_id = body.get("camera", "")
            mode = body.get("mode", "first-use")
            confirmed = body.get("cloud_confirmed", False)
            if not isinstance(confirmed, bool):
                self._json({"error": "cloud_confirmed must be boolean"}, 400)
                return
            if mode not in ("first-use", "review"):
                self._json({"error": "mode must be first-use or review"}, 400)
                return
            state_, payload = self.server.state.establish_environment_baseline(
                camera_id, mode=mode, cloud_confirmed=confirmed)
            if state_ == "unknown":
                self._json({"error": "camera not found", "state": state_}, 404)
                return
            if state_ == "busy":
                self._json({"error": "baseline building in progress",
                            "state": state_}, 409)
                return
            if state_ == "conflict":
                self._json({"error": "baseline pointer changed concurrently",
                            "state": state_}, 409)
                return
            if state_ == "confirmation_required":
                self._json({"error": "cloud confirmation required",
                            "state": state_}, 428)
                return
            if state_ == "frame_unavailable":
                self._json({"error": "camera frame unavailable",
                            "state": state_}, 503)
                return
            if state_ != "ok":
                self._json({"error": "baseline establishment failed",
                            "state": state_}, 503)
                return
            self._json({"ok": True, "state": state_,
                        "baseline": payload})
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
        if path == "/api/v2/notifications/user-confirm":
            notification_id = body.get("notification_id", "")
            if not isinstance(notification_id, str) or not notification_id                     or "/" in notification_id:
                self._json({"error": "notification_id required"}, 400)
                return
            from .db import confirm_notification_by_user
            conn = self.server.state._conn()
            try:
                result = confirm_notification_by_user(
                    conn, notification_id, at=time.time())
            finally:
                conn.close()
            if result is None:
                self._json({"error": "notification not found"}, 404)
                return
            self._json({"ok": True, "first_user_confirmation": result})
            return
        if path == "/api/v2/notifications/ack":
            notification_id = body.get("notification_id", "")
            if not isinstance(notification_id, str) or not notification_id \
                    or "/" in notification_id:
                self._json({"error": "notification_id required"}, 400)
                return
            try:
                result = self.server.state.acknowledge_notification(
                    notification_id)
            except Exception:
                self._json({"error": "notifications unavailable"}, 503)
                return
            if result is None:
                self._json({"error": "notification not found"}, 404)
                return
            # 幂等：首次回执 True；重复回执 False——都不伪造新的送达或重复提醒。
            self._json({"ok": True, "first_acknowledgement": result})
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
        if path == "/api/patterns/feedback":
            # S3 金标反馈：事件→模式（或直给 pattern_id）→ human-verified/
            # 误报降级；只动模式档案，绝不触碰管理员规则告警真值。
            from .slow_core import SlowCore
            pattern_id = body.get("pattern_id") or ""
            event_id = body.get("event_id") or ""
            misreport = bool(body.get("misreport", False))
            name = body.get("name")
            detail = body.get("detail")
            if (not isinstance(pattern_id, str) or
                    ("/" in pattern_id if pattern_id else False)) or \
                    (not isinstance(event_id, str) or "/" in event_id) or \
                    (not pattern_id and not event_id):
                self._json({"error": "pattern_id or event_id required"},
                           400)
                return
            if name is not None and (not isinstance(name, str)
                                     or not 0 < len(name) <= 16):
                self._json({"error": "name must be 1..16 chars"}, 400)
                return
            conn = self.server.state._conn()
            camera = None
            pid = pattern_id
            if event_id:
                if not isinstance(event_id, str) or "/" in event_id:
                    conn.close()
                    self._json({"error": "invalid event_id"}, 400)
                    return
                core = SlowCore(conn, camera="")   # camera 仅作占位
                pid, camera = core.pattern_of_event(event_id)
                if pid is None:
                    conn.close()
                    self._json({"error": "no slow profile for event"}, 404)
                    return
            if camera is None:
                # 直给 pattern_id：从持久化 row_id（pat-<camera>-<N>）精确
                # 反解相机——两侧各取数字尾段全等，杜绝 pat-3 误配 pat-13。
                want_tail = str(pid).rsplit("-", 1)[-1]
                for row in conn.execute(
                        "SELECT pattern_id, camera FROM patterns").fetchall():
                    rid_text = str(row["pattern_id"])
                    if rid_text.startswith("pat-") and \
                            rid_text.rsplit("-", 1)[-1] == want_tail:
                        camera = row["camera"]
                        break
            if camera is None:
                conn.close()
                self._json({"error": "pattern not found"}, 404)
                return
            try:
                core = SlowCore(conn, camera=camera)
                summary = core.confirm_pattern(
                    pid, name=name, detail=detail, misreport=misreport)
            except ValueError as e:
                conn.close()
                self._json({"error": str(e)}, 400)
                return
            conn.close()
            if summary is None:
                self._json({"error": "pattern not found"}, 404)
                return
            self._json({"ok": True, "pattern": summary})
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
