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
from .win11_understanding_store import branch_counts, latest_source_fields
from .zones import Grid, normalize_zones

CAMERA_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")

# ---- C153 车道E：跨窗口追加版本的 progress 白名单（服务端唯一入口） ----
# 只透传 B 车道版本 payload 里这三个键；progress 内部逐字段白名单 + 合法类型 +
# 长度上限，绝不回传原始 payload（items/bindings/processing_fingerprint 等一律
# 丢弃）。字段缺失或坏结构 → 该字段不进响应、键名记入 progress["missing"]，
# phase 缺失/不合法 → "unknown"：**绝不制造阶段**。
_PROGRESS_STRING_FIELDS = {
    "event_end_reason": 64,       # 事件 end_reason（自由文本，仅限长）
    "phase_basis": 64,            # 固定短标识
}
# 版本 payload 自身的身份键（与 progress 同级）：页面按窗口/融合版本号核对来源
_ENVELOPE_PROGRESS_FIELDS = ("window_id", "fusion_version_id")
_PROGRESS_IDENTITY_LIMIT = 128    # fusion.get("window_id"/"version_id")，实测 int 或 str
_PROGRESS_ENUM_FIELDS = {
    "phase": (32, ("first_update", "continuing", "after_close")),
    "event_state_at_write": (16, ("open", "closed")),
}
# 非负整数列（bool 显式拒绝；float 截断为 int，不四舍五入放大）
_PROGRESS_INT_FIELDS = ("prior_understanding_versions", "evidence_ref_count",
                        "bound_frame_count")
# 有限数字或 null（bool 拒绝，NaN/Inf 拒绝）
_PROGRESS_NUMBER_FIELDS = ("event_t_start", "event_t_last", "event_t_end",
                           "evidence_t_min", "evidence_t_max")


def _progress_string(value, limit):
    """长度上限表内的 str（超长截断）；其余类型（含 bool/bytes/容器）→ None。"""
    if isinstance(value, str):
        return value[:limit]
    return None


def _progress_number(value):
    """有限数字 → float；bool / 非数字 / NaN / ±Inf → None。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _is_floatish(value):
    """真浮点（含 NaN/±Inf）——用来区分"显式 null 无此值"与"坏浮点值"。"""
    return isinstance(value, float)


def _is_strish(value):
    """真字符串——用来区分"显式 null 无此值"与"空串/坏字符串值"。"""
    return isinstance(value, str)


def _progress_text(value):
    """窗口/融合版本身份：非空 str（超长截断）或非 bool 的 int；其余 → None。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value:
        return value[:_PROGRESS_IDENTITY_LIMIT]
    return None


def _progress_count(value):
    """非负整数（bool 拒绝；有限 float 截断为 int；字面数字串照收）；其余 → None。"""
    if isinstance(value, str):
        text = value.strip()
        if not text or not re.fullmatch(r"[+-]?\d+", text):
            return None
        value = int(text)
    number = _progress_number(value)
    if number is None or number < 0:
        return None
    return int(number)


def bounded_event_progress(payload):
    """把版本 payload 折成工作台可读的最小 progress（白名单 + 类型 + 限长）。

    只认版本 payload 自身的 `window_id`/`fusion_version_id` 与 `progress` 块；
    没有任何身份键、或 progress 不是对象时返回 None（"没有可用 progress" →
    页面显示明确缺失），绝不退化成某一种阶段。返回 dict 时恒有 `phase`
    （合法值或 "unknown"）与 `missing`（缺失/取值不合法的字段名，排序后，
    只含字段名不含值）；真实写入形态里的显式 null 是"无此值"而非缺失。
    """
    if not isinstance(payload, dict):
        return None
    if not any(name in payload for name in ("window_id", "fusion_version_id")):
        return None
    raw = payload.get("progress")
    if not isinstance(raw, dict):
        return None
    out = {}
    missing = []
    for name in _ENVELOPE_PROGRESS_FIELDS:
        if name not in payload:
            missing.append(name)
            continue
        parsed = _progress_text(payload[name])
        out[name] = parsed                       # 显式 null = "无此值"，不猜
        if parsed is None and _is_strish(payload[name]):
            missing.append(name)                 # 空串/纯空白是坏值，如实记为缺失
    for name, limit in _PROGRESS_STRING_FIELDS.items():
        if name not in raw:
            missing.append(name)
            continue
        parsed = _progress_string(raw[name], limit)
        out[name] = parsed                       # 显式 null = "无此值"，不猜
        if parsed is None and _is_strish(raw[name]):
            missing.append(name)                 # 用字符串冒充缺失 ≠ 真缺失
    for name, (limit, values) in _PROGRESS_ENUM_FIELDS.items():
        if name not in raw:
            missing.append(name)
            continue
        value = raw[name]
        if isinstance(value, str) and value in values:
            out[name] = value[:limit]
        else:
            missing.append(name)
    for name in _PROGRESS_INT_FIELDS:
        if name not in raw:
            missing.append(name)
            continue
        parsed = _progress_count(raw[name])
        if parsed is None:
            missing.append(name)
        else:
            out[name] = parsed
    for name in _PROGRESS_NUMBER_FIELDS:
        if name not in raw:
            missing.append(name)
            continue
        parsed = _progress_number(raw[name])
        out[name] = parsed                       # 显式 null = "无此值"，不猜
        if parsed is None and _is_floatish(raw[name]):
            missing.append(name)                 # NaN/±Inf 是坏值，如实记为缺失
    out.setdefault("phase", "unknown")     # 缺失/坏值一律"未记录"，不猜阶段
    out["missing"] = sorted(missing)
    return out


_INDEX_HTML = r'''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>语义摄像头 · 工作台</title>
<style>
:root{color-scheme:light dark;--bg:#fafafa;--panel:#fff;--line:#dedede;
--text:#202020;--muted:#626262;--accent:#167345;--warn:#925800;--danger:#b42318;
--input:#fff;--soft:#f3f3f3;--primary:#242424;--on-primary:#fff;--focus:#2563eb}
@media(prefers-color-scheme:dark){:root{--bg:#181818;--panel:#202020;--line:#3c3c3c;
--text:#ececec;--muted:#b0b0b0;--accent:#75d6a2;--warn:#f5bf69;--danger:#ff9393;
--input:#252525;--soft:#2b2b2b;--primary:#ececec;--on-primary:#202020;--focus:#90b8ff}}
*{box-sizing:border-box}[hidden]{display:none!important}body{font-family:"Segoe UI","Microsoft YaHei",system-ui,sans-serif;
background:var(--bg);color:var(--text);
margin:0;padding:24px;min-height:100vh}button,input,select{font:inherit}
header{display:flex;justify-content:space-between;gap:16px;align-items:end;margin-bottom:18px}
h1,h2,h3,p{margin-top:0}.eyebrow{color:var(--accent);font-weight:700;letter-spacing:.12em;
text-transform:uppercase;font-size:12px}.subtle,.status{color:var(--muted)}
.layout{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(310px,.75fr);gap:16px}
.card{background:var(--panel);border:1px solid var(--line);
border-radius:8px;padding:16px;margin-bottom:12px}
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
.guard-l1{margin-top:8px;font-size:13px;color:var(--muted)}.l1-line{margin-top:2px}
.und-line,.und-head{margin-top:3px;font-size:13px}.und-head{font-weight:600;color:var(--text)}
.und-note{color:var(--muted);font-size:12px}.und-desc{color:var(--text)}
.und-section{margin-top:10px;color:var(--accent);font-size:12px;font-weight:700;letter-spacing:.08em}
.und-branch{border:1px solid var(--line);border-radius:10px;padding:6px 9px;margin-top:6px}
.und-toggle{padding:2px 9px;font-size:12px;margin-left:8px}
.und-toggle.und-open{border-color:var(--accent)}
.und-sources{margin-top:6px;padding-top:6px;border-top:1px dashed var(--line);
font-size:12px;color:var(--muted);display:grid;gap:2px;word-break:break-all}
.und-crop-thumb{display:block;max-width:160px;max-height:110px;object-fit:contain;
margin-top:3px;border:1px solid var(--line);border-radius:6px;background:#000}
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
/* C145：高级折叠（原生 details，无框架） */
details.advanced>summary{cursor:pointer;font-weight:600;color:var(--muted);
padding:2px 0}
details.advanced>summary::marker{color:var(--accent)}
details.advanced>.card,details.advanced .card{margin-top:10px}
details.advanced>.card:first-of-type{margin-top:12px}
.environment-gate{position:static;display:block;padding:12px 16px;background:var(--panel);
border:1px solid var(--line);border-radius:8px;margin-top:12px}
.environment-gate[hidden]{display:none}.environment-panel{width:100%;padding:0;
background:transparent}
.environment-panel ul{margin:10px 0 18px;padding-left:20px;color:var(--muted)}
.environment-panel .actions{margin:6px 0 12px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:8px 6px;
border-bottom:1px solid var(--line);text-align:left}a{color:#77d9ff}
/* Compact local workbench: no framework, remote fonts or decorative surfaces. */
body{font-size:14px;line-height:1.5;padding:20px;max-width:1600px;margin:auto}
header{align-items:center;border-bottom:1px solid var(--line);padding-bottom:12px;margin-bottom:16px}
h1{font-size:20px;line-height:1.3;margin:0;font-weight:600}h2{font-size:16px;margin:0 0 8px;font-weight:600}
h3{font-size:14px;margin-bottom:8px}.eyebrow{color:var(--muted);font-size:11px;letter-spacing:.03em;font-weight:500}
.layout{grid-template-columns:1fr;gap:0}.layout>section{display:grid;grid-template-columns:minmax(0,1fr);gap:12px;align-items:start}
.layout>section>*{min-width:0}.layout>section>.advanced,.layout>section>.camera-overview{grid-column:1/-1}
.layout>aside{min-width:0;display:grid;grid-template-columns:1fr 1fr;gap:16px}
.toolbar{justify-content:space-between}.toolbar label{flex:0 1 180px;min-width:120px}
.subtle{font-size:12px}.status{font-size:12px;text-align:right;max-width:50%;overflow-wrap:anywhere}
input,select{background:var(--input);border-radius:6px;padding:7px 9px;min-height:36px}
button{background:var(--soft);border-radius:6px;padding:7px 11px;min-height:34px}
button:hover{border-color:var(--muted)}button.primary{background:var(--primary);border-color:var(--primary);color:var(--on-primary);font-weight:600}
button.danger{color:var(--danger)}a{color:var(--text);text-underline-offset:3px}
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible,[tabindex]:focus-visible{outline:2px solid var(--focus);outline-offset:3px}
.stage{min-height:240px;border-radius:6px;margin:10px auto 0;background:#111;max-width:960px}.stage img{width:auto;max-width:100%;max-height:38vh}
#zone-grid[hidden]{display:none!important}.legend{font-size:12px;margin-top:8px;flex-wrap:wrap}
.pill,.zone-item,.und-branch,.guard-card,.desc-version{border-radius:6px}
.pill,.zone-item.active,#event-detail-panel,.guard-card{background:var(--soft)}
.zone-item.active{border-color:var(--text)}.und-section{color:var(--muted);letter-spacing:0;font-weight:600}
.reminder-item{background:var(--soft);border:1px solid var(--line);border-left:3px solid var(--warn);border-radius:6px}
.und-sources{word-break:normal;overflow-wrap:anywhere}.und-desc,.desc-version,#event-detail-body{overflow-wrap:anywhere}
.table-scroll{overflow-x:auto;max-width:100%;margin-top:8px}table{min-width:820px}th{font-size:12px;font-weight:500;color:var(--muted)}
td,th{padding:9px 10px}th{white-space:nowrap}td{word-break:normal}
#event-timeline td:nth-child(1),#event-timeline td:nth-child(2),#event-timeline td:nth-child(3),#event-timeline td:nth-child(4),#event-timeline td:nth-child(7),#event-timeline td:nth-child(8){white-space:nowrap}
#event-timeline td:nth-child(5){width:40%;min-width:260px;overflow-wrap:break-word;line-height:1.6}
#event-timeline td:nth-child(6){min-width:150px}tbody tr:hover{background:var(--soft)}
#understanding-detail{max-height:65vh;overflow:auto}details>summary{cursor:pointer;min-height:32px;padding:4px 0;font-weight:600}
#understanding-line{max-height:6em;overflow:auto;overflow-wrap:anywhere}
.help{margin-top:8px;color:var(--muted);font-size:12px}.help>summary{font-weight:400;min-height:28px}
.settings>summary{font-size:13px}.settings[open]>summary{margin-bottom:12px;border-bottom:1px solid var(--line);padding-bottom:8px}
.environment-panel{width:100%;padding:0;border:0;background:transparent;border-radius:0;box-shadow:none}
.environment-panel .eyebrow{display:none}.environment-panel h2{font-size:14px}.environment-panel p{margin-bottom:8px}
.environment-panel .actions{margin-bottom:0}.workbench-nav{display:flex;gap:16px;font-size:12px;flex-wrap:wrap}
.editing-indicator{color:var(--warn);font-size:12px;margin-top:8px}
.workbench-nav{gap:6px;margin-top:10px}.workbench-nav a{display:inline-flex;align-items:center;gap:6px;text-decoration:none;border:1px solid transparent;border-radius:6px;padding:6px 9px;min-height:34px;background:var(--soft);font-weight:500}
.workbench-nav a:hover{border-color:var(--line);background:var(--panel)}
.ui-icon{width:16px;height:16px;display:inline-block;vertical-align:-3px;flex:none;fill:none;stroke:currentColor;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
button .ui-icon{margin-right:5px}button:disabled{opacity:.6;cursor:not-allowed}
button.danger:hover{border-color:var(--danger);background:color-mix(in srgb,var(--danger) 8%,var(--panel))}
.camera-line::before{content:'';display:inline-block;width:7px;height:7px;border-radius:50%;background:currentColor;margin-right:6px}
.ev-open,.ev-closed,.ev-esc{display:inline-block;border:1px solid var(--line);border-radius:4px;padding:1px 6px;font-size:12px;white-space:nowrap}
.ev-open{background:color-mix(in srgb,var(--accent) 8%,var(--panel))}
.ev-esc{background:color-mix(in srgb,var(--warn) 8%,var(--panel))}
.settings>summary:hover,.advanced>summary:hover{color:var(--text)}
@media(max-width:1000px){.layout>section{grid-template-columns:1fr}.layout>aside{grid-template-columns:1fr}.stage img{max-height:45vh}}
@media(max-width:600px){body{padding:12px}header{align-items:flex-start;gap:10px;flex-wrap:wrap}.status{max-width:100%;text-align:left}h1{font-size:18px}.card{padding:12px}.stage{min-height:200px}.toolbar label{flex:1 1 140px}button{min-height:40px}.workbench-nav{gap:12px}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;animation:none!important;transition:none!important}}
.record-summary{line-height:1.6;white-space:normal;overflow-wrap:anywhere}
.record-summary-note{font-size:12px;color:var(--muted);margin-top:4px}
.record-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.record-actions a{display:inline-flex;align-items:center;gap:4px;border:1px solid var(--line);border-radius:6px;padding:4px 7px;text-decoration:none}
.record-actions a:focus-visible{outline:2px solid currentColor;outline-offset:3px}
.timeline-tools{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:8px 0;font-size:13px}
.timeline-mobile-hint{display:none;color:var(--muted);font-size:12px}
#timeline-status{color:var(--muted)}.detail-head{display:flex;justify-content:space-between;align-items:center;gap:12px}
.detail-head h3{margin:0}.description-history{margin-top:12px}
@media(max-width:600px){.record-summary{max-width:280px}.detail-head{align-items:start}.timeline-mobile-hint{display:block}}
</style></head><body>
<header><div><div class="eyebrow">本机值守</div><h1>语义摄像头 · 工作台</h1>
<nav class="workbench-nav" aria-label="工作台导航">
<a href="#live-card"><svg class="ui-icon" aria-hidden="true" viewBox="0 0 20 20"><rect x="2" y="5" width="11" height="10" rx="2"/><path d="m13 8 5-3v10l-5-3"/></svg>现场</a>
<a href="#observation-card"><svg class="ui-icon" aria-hidden="true" viewBox="0 0 20 20"><rect x="4" y="2" width="12" height="16" rx="2"/><path d="M7 6h6M7 10h6M7 14h4"/></svg>观察记录</a>
<a href="#zone-settings" id="open-zone-settings"><svg class="ui-icon" aria-hidden="true" viewBox="0 0 20 20"><rect x="2" y="2" width="16" height="16" rx="2"/><path d="M8 2v16M2 8h16M13 8v10M8 13h10"/></svg>区域配置</a>
<a href="#baseline-settings" id="open-baseline-settings"><svg class="ui-icon" aria-hidden="true" viewBox="0 0 20 20"><path d="M3 7V3h4m6 0h4v4m0 6v4h-4M7 17H3v-4"/><circle cx="10" cy="10" r="3"/></svg>环境基线</a></nav>
<details class="help"><summary>使用说明</summary><div class="subtle">环境基线为可选增强（可跳过，随时可建）；观察记录不以圈选、规则或基线为前提，规则决定特别关注与升级告警。模型建议不会自动成为告警。</div></details></div>
<div class="status"><div id="health">本机工作台</div>
<div id="camera-status">正在读取相机状态…</div></div></header>
<main class="layout"><section>
<div class="card" id="live-card"><div class="toolbar"><div><h2>现场</h2>
<div class="subtle">实时画面 · 连接与分析状态</div></div>
<label>相机<select id="camera-select" aria-label="选择相机"></select></label></div>
<div id="camera-scope-note" class="subtle" role="status" aria-live="polite" hidden></div>
<div class="stage" id="frame-stage"><img id="zone-frame" alt="当前相机画面">
<div id="frame-empty" class="empty">正在读取当前画面…</div><div id="zone-grid" aria-label="区域网格" hidden></div></div>
<div class="legend"><span id="grid-summary" hidden>网格加载中</span><span id="runtime-state">尚未连接运行时</span></div>
<div id="l1-status" class="guard-l1" hidden></div>
<div id="understanding-line" class="guard-l1" role="status" aria-label="分析状态" tabindex="0" hidden></div>
<div id="editing-indicator" class="editing-indicator" hidden>区域编辑中 · 仅保存后生效</div>
<details class="help"><summary>画面与圈选说明</summary><div class="subtle">圈选为可选增强：打开区域配置后点击画面格子即可刷选；仅点击保存后应用。</div></details></div>
<div class="card" id="observation-card"><div class="toolbar"><div><h2>观察记录</h2>
<details class="help"><summary>记录说明</summary><div class="subtle">画面变化的记录与解释：事件（含规则升级标识）与理解当前/历史分列；选中记录可看解释、时间、原图与可用录像。</div></details></div></div>
<div id="reminder-banner" class="reminder" aria-live="polite"></div>
<div class="timeline-tools"><span id="timeline-status" role="status">正在加载观察记录…</span>
<button id="timeline-latest" type="button" hidden>查看新记录</button></div>
<p class="timeline-mobile-hint">横向滑动记录，可查看理解摘要与证据。</p>
<div class="table-scroll" role="region" aria-label="观察记录列表" tabindex="0"><table id="event-timeline"><thead><tr><th>时间</th><th>相机</th><th>类别</th><th>状态</th>
<th>事实与最新理解</th><th>证据</th><th>升级</th><th>详情</th></tr></thead><tbody></tbody></table></div>
<div id="event-detail-panel" hidden><div class="detail-head"><h3 id="event-detail-title">事件详情</h3>
<button id="close-event-detail" type="button">关闭详情</button></div>
<div id="event-detail-body"></div>
<div id="confirm-area"></div></div>
<div id="understanding-detail" class="guard-l1" hidden></div></div>
<details class="camera-overview"><summary>全部相机</summary><div class="card" id="guard-grid-card"><div class="toolbar"><div><h2>值守网格</h2>
<div class="subtle">每相机一张卡：状态 · 最新画面（3s 刷新）· 最近告警计数。</div></div></div>
<div id="guard-grid" class="guard-grid" aria-label="多相机值守网格">正在读取相机…</div>
<div id="l1-materials" class="guard-l1" hidden></div>
<div id="l2-note" class="subtle" hidden></div></div></details>
<details id="advanced-panel" class="card advanced"><summary>诊断与历史规则</summary>
<div class="card" id="zone-editor"><div class="toolbar"><div><h2>区域与规则（可选增强）</h2>
<div class="subtle">在上方现场画面点击或拖动网格刷选；绿色格子仅在点击“保存并应用”后生效。</div></div></div>
<div class="legend"><span>圈选与规则为可选增强：事件记录不以圈选或规则为前提。</span></div></div>
<div class="card"><h2>审查时间线</h2><table id="review"><thead><tr><th>开始</th><th>相机</th>
<th>级别</th><th>目标数</th><th>状态</th></tr></thead><tbody></tbody></table></div>
<div class="card"><h2>管理员规则告警</h2><div class="subtle">规则命中产生的告警（旧接口，保持兼容）；事件主线见上方观察记录。</div>
<table id="events"><thead><tr><th>时间</th><th>短名</th>
<th>详情</th><th>最佳帧</th><th>录像</th></tr></thead><tbody></tbody></table></div>
<div class="card"><h2>模式库</h2><div id="patterns" class="subtle">加载中</div></div>
</details>
</section><aside>
<details id="zone-settings" class="card settings"><summary>区域配置 · 可选</summary><h2>区域配置</h2><div id="zone-list" class="zone-list"></div>
<div class="actions"><button id="new-zone" type="button"><svg class="ui-icon" aria-hidden="true" viewBox="0 0 20 20"><path d="M10 3v14M3 10h14"/></svg>新建区域</button>
<button id="clear-cells" type="button"><svg class="ui-icon" aria-hidden="true" viewBox="0 0 20 20"><path d="m3 12 8-8 6 6-7 7H7l-4-5Zm5-5 6 6M10 17h7"/></svg>清空选格</button>
<button id="delete-zone" type="button" class="danger"><svg class="ui-icon" aria-hidden="true" viewBox="0 0 20 20"><path d="M3 5h14M7 5V2h6v3M5 5l1 13h8l1-13M8 8v7m4-7v7"/></svg>删除当前区域</button></div>
<div class="form-row"><label>区域 ID<input id="zone-id" maxlength="48" placeholder="例如 front-door"></label>
<label>区域名称<input id="zone-name" maxlength="48" placeholder="例如 大门口"></label></div>
<div class="form-row"><label>类别<input id="rule-class" maxlength="32" value="person"></label>
<label>规则模板<select id="rule-template"><option value="immediate">进入即告警</option>
<option value="enter-dwell">进入并滞留</option><option value="loiter">持续徘徊</option></select></label></div>
<div class="form-row"><label>滞留秒数<input id="rule-dwell" type="number" min="0" max="86400" step="0.5" value="0"></label>
<label>严重度<select id="rule-severity"><option value="low">低</option><option value="medium">中</option>
<option value="high">高</option><option value="critical">严重</option></select></label></div>
<button id="save-zone" class="primary" type="button"><svg class="ui-icon" aria-hidden="true" viewBox="0 0 20 20"><path d="m4 10 4 4 8-8"/></svg>保存并应用管理员规则</button>
<div id="zone-message" class="message" role="status"></div></details>
<details id="baseline-settings" class="card settings"><summary>环境基线 · 可选</summary><h2>环境基线</h2>
<div class="subtle">环境基线为可选增强：可先跳过直接观察，随时可建立以获得更准的理解；圈选与规则保持可选，观察记录不以规则为前提。识别建议不会自动成为区域，也不会改动已记录的事件。</div>
<p id="environment-message" class="subtle">正在检查当前相机的环境基线…</p>
<div id="environment-result" hidden><h3>识别建议（不会自动成为报警规则）</h3>
<p id="environment-summary"></p><ul id="environment-suggestions"></ul></div>
<button id="analyze-environment" type="button"><svg class="ui-icon" aria-hidden="true" viewBox="0 0 20 20"><path d="M16 8a6 6 0 1 0-1 7M16 3v5h-5"/></svg>复核环境基线（新版本）</button>
<ul id="baseline-history" class="subtle"></ul>
<p class="subtle">本地模型默认不上传画面；如选择云模型，本次操作会再次明确确认。基线只追加版本，历史与原始画面保留。</p></details>
</aside></main>
<div id="environment-gate" class="environment-gate">
<div class="environment-panel"><div class="eyebrow">首次使用 · 可选增强（可跳过，随时可建）</div>
<h2>环境基线 · 可选增强</h2>
<p id="gate-message">正在检查当前相机的环境基线…</p>
<details class="help"><summary>基线与隐私说明</summary><p class="subtle">无需“先建立环境基线，再进入值守”；可先观察，稍后补建。基线包含完整场景原始画面与识别结果，可追溯、可复核、只追加版本；
事件的发现与记录不以圈选或规则为前提；圈选与规则稍后仍可随时配置。</p></details>
<div class="actions"><button id="baseline-establish" class="primary" type="button"><svg class="ui-icon" aria-hidden="true" viewBox="0 0 20 20"><path d="M3 7V3h4m6 0h4v4m0 6v4h-4M7 17H3v-4"/><circle cx="10" cy="10" r="3"/></svg>建立环境基线</button><button id="gate-dismiss" class="secondary" type="button">先跳过，稍后再建（观察与证据不受阻）</button>
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
let zoneConfig=null,loadedZoneCamera=null,zones=[],active=-1,selected=new Set(),painting=false,paintValue=true,frameTimer=null;
const zoneSettings=document.getElementById('zone-settings');
function zoneEditing(){return !!zoneSettings?.open}
function syncZoneEditing(){painting=false;ui.grid.hidden=!zoneEditing();ui.summary.hidden=!zoneEditing();
const indicator=document.getElementById('editing-indicator');if(indicator)indicator.hidden=!zoneEditing();alignGrid()}
if(zoneSettings)zoneSettings.addEventListener('toggle',syncZoneEditing);
for(const [linkId,panelId] of [['open-zone-settings','zone-settings'],['open-baseline-settings','baseline-settings']]){
const link=document.getElementById(linkId);if(link)link.addEventListener('click',()=>{
const panel=document.getElementById(panelId);if(panel)panel.open=true;if(panelId==='zone-settings')syncZoneEditing()})}
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
cell.dataset.cell=String(i);cell.onpointerdown=e=>{if(!zoneEditing())return;e.preventDefault();painting=true;paintValue=!selected.has(i);paintCell(i,paintValue)};
cell.onpointerenter=()=>{if(painting)paintCell(i,paintValue)};ui.grid.appendChild(cell)}
ui.summary.textContent=`${rows} × ${cols} 网格 · 已选 ${selected.size} 格`}
function paintCell(index,value){if(!zoneEditing())return;value?selected.add(index):selected.delete(index);const cell=ui.grid.children[index];
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
const incoming=await response.json();if(ui.camera.value!==camera)return;
zoneConfig=incoming;loadedZoneCamera=camera;zones=Array.isArray(zoneConfig.zones)?zoneConfig.zones:[];active=zones.length?0:-1;
ui.runtime.textContent=zoneConfig.pending?'配置等待下一帧生效':(zoneConfig.runtime==='active'?'运行时在线':'保存后需重启应用');
fillForm(activeZone());renderZones();loadFrame();updateSelectedCameraNote();clearInterval(frameTimer);frameTimer=setInterval(loadFrame,2500)}
function showEnvironment(profile){ui.envResult.hidden=!profile;ui.envSuggestions.replaceChildren();
if(!profile)return;ui.envSummary.textContent=`${profile.scene_type} · ${profile.lighting} · ${profile.risk_notes}`;
(profile.suggested_zones||[]).forEach(text=>{const item=document.createElement('li');item.textContent=text;ui.envSuggestions.appendChild(item)})}
function renderBaselineHistory(camera,rows){ui.baselineHistory.replaceChildren();
(rows||[]).forEach(v=>{const item=document.createElement('li');
item.textContent='v'+v.version+' · '+(v.is_current?'当前':'已替代')+' · '+new Date(v.established_at*1000).toLocaleString()+' · '+(v.scene_summary||'（无摘要）')+' · 模型 '+(v.model_id||'unknown')+(v.comparison_insufficient?'（比较条件不足）':'')+' · '+(v.evidence_available?'可回看':'不可回看')+' ';
if(v.evidence_available){const link=document.createElement('a');link.textContent='查看原始画面';
link.href='/api/environment/'+encodeURIComponent(camera)+'/baselines/'+encodeURIComponent(v.baseline_id)+'/frame';link.target='_blank';item.appendChild(link)}
ui.baselineHistory.appendChild(item)})}
// C-144-R2：sessionStorage 安全访问——storage 不可用（隐私模式/禁用）时
// 页面照常操作：读取得 null（视为未跳过），写入失败仅放弃记忆。
function gateSkippedRead(){try{return sessionStorage.getItem('c143-gate-skipped')==='1'}catch(e){return false}}
function gateSkippedWrite(){try{sessionStorage.setItem('c143-gate-skipped','1');return}catch(e){}
try{localStorage.setItem('c143-gate-skipped','1')}catch(e2){}}
async function loadEnvironment(){const camera=ui.camera.value;
// C-144-R2：跳过选择在整个函数内生效——无相机/读取失败/无基线/非 ready
// 各分支都不得把门重新盖回来（用户跳过后环境基线是「可选增强」，
// 不伪造 ready；画面/记录/证据全可操作）。
const gateSkipped=gateSkippedRead();
if(!camera){ui.gate.hidden=gateSkipped;ui.gateMessage.textContent='请先配置相机；没有相机时无法建立基线。';ui.analyze.disabled=true;return}
ui.analyze.disabled=false;ui.envMessage.textContent='正在检查当前相机的环境基线…';showEnvironment(null);
let baseline=null;
try{const response=await fetch('/api/environment/'+encodeURIComponent(camera));const data=await response.json();
if(response.ok&&data.profile){showEnvironment(data.profile)}
baseline=response.ok?data.baseline:null}
catch(error){ui.envMessage.textContent=gateSkipped?'基线状态读取失败（已跳过：观察与证据不受阻，环境增强为可选）。':'基线状态读取失败，请稍候重试。';ui.gate.hidden=gateSkipped;return}
if(!baseline){ui.envMessage.textContent=gateSkipped?'环境基线尚未建立（已跳过：观察与证据不受阻；可随时在下方建立基线以启用环境增强）。':'环境基线状态暂不可用。';ui.gate.hidden=gateSkipped;return}
try{const histResponse=await fetch('/api/environment/'+encodeURIComponent(camera)+'/baselines');const hist=await histResponse.json();
if(histResponse.ok){renderBaselineHistory(camera,hist.baselines)}}catch(historyError){ui.baselineHistory.replaceChildren()}
const B=baseline.state;
if(B==='ready'){ui.gate.hidden=true;
ui.envMessage.textContent='环境基线 v'+baseline.version+' 已就绪（建立于 '+new Date(baseline.established_at*1000).toLocaleString()+'）。'+(baseline.error?('最近一次复核失败（'+baseline.error+'），可从下方复核重试。'):'');
if(baseline.comparison_insufficient){ui.envMessage.textContent+='模型标识缺失，跨期比较条件不足。'}return}
if(gateSkipped){ui.gate.hidden=true;ui.baselineRetry.hidden=true;
ui.envMessage.textContent='环境基线尚未建立（已跳过：观察与证据不受阻；环境基线为可选增强，可随时在下方建立基线）。';return}
ui.gate.hidden=false;ui.baselineRetry.hidden=(B!=='failed'&&B!=='evidence_broken');
const reasonText={no_pointer:'该相机还没有环境基线。',
legacy_profile_without_evidence:'存在旧版环境档案，但缺少版本记录与原始画面，不能作为可追溯基线。',
pointer_version_missing:'基线指针指向的版本已不存在。',
pointer_not_integer:'基线指针记录损坏。',
evidence_missing_or_corrupt:'当前基线画面缺失或损坏；可修复或重新建立。观察不受阻，历史版本保留。'}[baseline.reason]||'该相机还没有有效的环境基线。';
ui.gateMessage.textContent=reasonText+' 可先跳过，持续观察不受影响。'+(baseline.error?('（上次失败：'+baseline.error+'）'):'');
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
let currentRuntimeCameraIds=null;
function updateSelectedCameraNote(){const note=document.getElementById('camera-scope-note');if(!note)return;
const selected=ui.camera.value;note.hidden=!selected;note.textContent='';if(!selected)return;
if(!Array.isArray(currentRuntimeCameraIds)){note.hidden=true;ui.runtime.textContent='当前值守身份尚未核实';return;}
if(!currentRuntimeCameraIds.includes(selected)){note.textContent='历史相机：不在当前值守列表，仅查看已保存配置与历史记录。';ui.runtime.textContent='历史配置 · 不在当前值守';return;}
note.hidden=true;if(zoneConfig&&loadedZoneCamera===selected)ui.runtime.textContent=zoneConfig.pending?'配置等待下一帧生效':(zoneConfig.runtime==='active'?'运行时在线':'保存后需重启应用');}
async function loadCameras(){const response=await fetch('/api/cameras');const data=await response.json();ui.camera.replaceChildren();
(data.cameras||[]).forEach(camera=>{const option=document.createElement('option');option.value=camera.id;option.textContent=camera.id;ui.camera.appendChild(option)});
if(!ui.camera.options.length){const option=document.createElement('option');option.textContent='没有已配置相机';option.value='';ui.camera.appendChild(option);ui.empty.textContent='请先在 cameras.json 中配置相机';updateSelectedCameraNote();await loadEnvironment();return}updateSelectedCameraNote();await loadZones();await loadEnvironment()}
document.getElementById('new-zone').onclick=()=>{active=-1;fillForm(null);renderZones();message('正在创建新区域：选择格子并填写规则后保存。')};
document.getElementById('clear-cells').onclick=()=>{selected.clear();renderGrid()};ui.camera.onchange=async()=>{updateSelectedCameraNote();await loadZones();await loadEnvironment()};
ui.analyze.onclick=()=>establishBaseline('review');
const gateDismiss=document.getElementById('gate-dismiss');
if(gateDismiss){gateDismiss.onclick=()=>{gateSkippedWrite();
const g=document.getElementById('environment-gate');if(g)g.hidden=true;
message('已跳过环境基线：持续观察、事件与证据不受影响（环境基线为可选增强），可随时在下方建立基线。','ok')}};
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
// C153 车道E：逐版本的「窗口落在事件哪一段」。阶段只来自服务端白名单 progress
// （写入时持久化事实推导），页面绝不用墙钟/版本序号/到达次序推断阶段；
// after_close 是"事件结束后才补上的一版"，不是事件重新开始。
// 版本序号只表示追加次序，与语义正确率无关，不得暗示准确率。
const PROGRESS_STAGE_TEXT={first_update:'首次补充',continuing:'持续进展',after_close:'结束后补充'};
function progressStageLabel(phase){
if(typeof phase!=='string')return'阶段未记录（不视为任何阶段）';
return PROGRESS_STAGE_TEXT[phase]||'阶段未记录（未知取值 '+phase.slice(0,32)+'）'}
// 显示白名单：只取能在页面上说清楚的字段，类型不符即丢（不猜、不补默认值）；
// 服务端已做长度上限与类型校验，这里不再二次截断（避免把一个白名单值改写成另一个）。
function progressDisplay(p){
if(!p||typeof p!=='object'||Array.isArray(p))return null;
const out={};let any=false;
for(const name of ['window_id','fusion_version_id']){
const v=p[name];if((typeof v==='string'&&v)||Number.isInteger(v)){out[name]=v;any=true}}
for(const name of ['phase_basis','event_end_reason','event_state_at_write']){
const v=p[name];if(typeof v==='string'&&v){out[name]=v;any=true}}
for(const name of ['prior_understanding_versions','evidence_ref_count','bound_frame_count','event_t_start','event_t_last','event_t_end','evidence_t_min','evidence_t_max']){
const v=p[name];if(!Number.isInteger(v)&&typeof v!=='number')continue;
if(typeof v==='number'&&!Number.isFinite(v))continue;out[name]=v;any=true}
const phase=PROGRESS_STAGE_TEXT[p.phase]?p.phase:'unknown';
return{phase:phase,label:progressStageLabel(p.phase),fields:any?out:null}}
function progressNote(desc){
if(desc.source!=='vlm')return'';   // v1 初始事实没有阶段，也不给假阶段
const shown=progressDisplay(desc.progress);
if(!shown)return' · 阶段未记录（不视为任何阶段）';
return' · '+shown.label}
// C173-C1：evidence_refs 有两类合法形状（语义更新链=字符串受控资产 ID；
// L4 桥=结构化帧引用，含 frame_id/t_ms/time_kind）。按元素类型分型显示：
// 只读白名单字段、缺失字段如实"未知"、绝不渲染任意嵌套字段；帧引用不是
// 资产 ID，不转资产链接；可打开入口只经既有受控通路（best_frame），
// 引用本身只作文本。textContent 渲染，恶意字段不可执行 HTML/脚本。
function evidenceRefLabel(ref){
if(typeof ref==='string')return'受控资产 '+ref;
if(ref&&typeof ref==='object'){
const fid=ref.frame_id;
const fidOk=(typeof fid==='string'&&fid!=='')||
(typeof fid==='number'&&Number.isFinite(fid));
const tms=ref.t_ms;
const tOk=typeof tms==='number'&&Number.isFinite(tms);
const kind=(typeof ref.time_kind==='string'&&ref.time_kind)?
ref.time_kind:'时间种类未知';
return'帧 #'+(fidOk?String(fid):'未知')+' · t='+(tOk?String(tms)+'ms':'未知')+'（'+kind+'）'}
if(ref===null||ref===undefined)return'证据引用（未知）';
return'证据引用 '+String(ref)}
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
if(kind==='semantic_update'){const old=detailSummaryCache.get(n.event_id);if(old)old.at=0;}
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
// C150: bounded exact-event summaries; no per-row request fan-out every poll.
const timelineRows=new Map(),detailSummaryCache=new Map();
const SUMMARY_CACHE_CAP=64,SUMMARY_REQUESTS_PER_POLL=2,SUMMARY_TTL_MS=15000;
let timelineRefreshing=false,timelinePaused=false,timelineSnapshot=[],selectedEventId=null,detailGeneration=0;
let currentUnderstandingCapability=null;
function understandingDisabled(capability){return capability&&capability.configured===false}
function understandingCapabilityState(capability){const configured=capability?.configured;
return configured===true?true:configured===false?false:null}
function timelineNotice(text){const node=document.getElementById('timeline-status');if(node)node.textContent=text}
function readingTimeline(){return timelinePaused||Boolean(selectedEventId)||Boolean(document.activeElement?.closest?.('#event-timeline'))}
function shortEventTime(value){if(!value)return'时间未记录';const date=new Date(value*1000);
return date.toLocaleDateString(undefined,{month:'2-digit',day:'2-digit'})+' '+date.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'})}
function currentUserOpinion(source){
const current=source?.user_feedback_current;
if(current&&typeof current==='object'&&!Array.isArray(current)&&
(current.display_name===null||(typeof current.display_name==='string'&&current.display_name.length>0&&current.display_name.length<=16))&&
(current.misreport===null||current.misreport===true||current.misreport===false))return{display_name:current.display_name,misreport:current.misreport,complete:true};
const rows=Array.isArray(source?.user_feedback)?source.user_feedback:[];
const named=rows.slice().reverse().find(item=>typeof item?.display_name==='string'&&item.display_name.length>0&&item.display_name.length<=16);
const opinion=rows.slice().reverse().find(item=>item?.misreport===true||item?.misreport===false);
return{display_name:named?named.display_name:null,misreport:opinion?opinion.misreport:null,complete:false};}
function rememberSummary(id,value){if(value.detail){const source=value.detail;
const newest=(Array.isArray(source.descriptions)?source.descriptions:[]).filter(d=>Number(d.version)>1&&typeof d.text==='string').sort((a,b)=>Number(b.version)-Number(a.version))[0];
const summary=newest?{version:newest.version,source:newest.source,text:newest.text.slice(0,4096),progress:progressDisplay(newest.progress)}:null;
const named=currentUserOpinion(source).display_name;
const priorName=value.error===true&&typeof source.user_name==='string'&&source.user_name.length<=16?source.user_name:'';
value={...value,detail:{event_id:source.event_id,camera:source.camera,t_last:source.t_last,
semantic:source.semantic,user_name:named||priorName,descriptions:summary?[summary]:[],summary_truncated:Boolean(newest&&newest.text.length>4096)}};}
detailSummaryCache.delete(id);detailSummaryCache.set(id,value);
while(detailSummaryCache.size>SUMMARY_CACHE_CAP)detailSummaryCache.delete(detailSummaryCache.keys().next().value)}
function matchingDetail(e,d){return d&&d.event_id===e.event_id&&d.camera===e.camera}
function eventSummary(e){const cached=detailSummaryCache.get(e.event_id);
const identityMismatch=Boolean(cached?.detail&&!matchingDetail(e,cached.detail));
const d=identityMismatch?null:cached?.detail;const descriptions=Array.isArray(d?.descriptions)?d.descriptions:[];
const latest=descriptions.filter(item=>Number(item.version)>1&&typeof item.text==='string'&&item.text.trim()).sort((a,b)=>Number(b.version)-Number(a.version))[0];
const state=d?.semantic?.state;
let note=latest?(latest.source==='vlm'?'模型补充 · 可能有误，待核对':'补充描述 · 查看来源'):'暂无进一步理解';
if(state==='running')note='分析中 · 结果尚未完成';
else if(state==='waiting_retry')note='理解失败 · 等待重试';
else if(state==='failed_terminal')note='理解失败 · 暂未生成新结果';
else if(state==='queued_backoff')note='等待分析 · 队列繁忙';
else if(state==='no_evidence')note='缺少可用证据 · 尚未分析';
// C173-C2：原 `state==='expired'||code==='expired'`（"素材已过期 · 尚未分析"）
// 分支删除——semantic_updater 状态集（event_state/REASON_TEXT）从不产出
// expired，该映射无生产来源、永不可达；真实过期（材料超龄/分支 TTL/排队
// 超龄）是相机/窗口级技术身份、无可信事件归属，改由健康区 l2 真实计数
// 显示（见 refreshHealth 的 l2-note 段），绝不挂到事件、绝不伪造
// semantic.state=expired。
if(!cached)note='理解状态待读取（未视为已分析）';
if(identityMismatch)note='摘要身份不匹配 · 仅显示当前事实';
if(cached?.error)note='摘要读取失败 · 保留原始事实'+(latest?'与上次描述（非最新）':'');
else if(cached&&Date.now()-cached.at>=SUMMARY_TTL_MS)note='上次状态 · 等待刷新 · '+note;
if(understandingDisabled(currentUnderstandingCapability)){
note='图片理解未启用'+(latest?' · 已保存描述仅供回看'+(latest.source==='vlm'?' · 模型补充 · 可能有误，待核对':' · 补充描述 · 查看来源'):'');
if(identityMismatch)note+=' · 摘要身份不匹配';
if(cached?.error)note+=' · 摘要读取失败';}
if(latest)note+=' · v'+latest.version+(latest.progress?(' · '+latest.progress.label):' · 阶段未记录');
if(d?.summary_truncated)note+=' · 完整原文见详情';
return{text:latest?latest.text:(e.initial_fact_text||'暂无已记录描述'),note,userName:d?.user_name||'',userNameStale:Boolean(cached?.error||(cached&&Date.now()-cached.at>=SUMMARY_TTL_MS))};}
function renderTimelineRow(e,row){
let refs=row._experience;
if(!refs){const cells=Array.from({length:8},()=>row.insertCell());
const fact=document.createElement('div');fact.className='record-summary';
const userName=document.createElement('div');userName.className='record-user-name';userName.hidden=true;
const note=document.createElement('div');note.className='record-summary-note';cells[4].append(userName,fact,note);
const evidence=document.createElement('a');evidence.className='record-evidence';evidence.target='_blank';evidence.rel='noopener';
evidence.textContent='▧ 最佳帧';evidence.title='本事件原始最佳帧；不替代模型输入来源';const missing=document.createElement('span');missing.textContent='暂无可回看画面';missing.className='subtle';
cells[5].className='record-actions';cells[5].append(evidence,missing);
const detail=document.createElement('a');detail.href='#';detail.textContent='↗ 打开详情';
detail.setAttribute('aria-label','打开记录详情 '+e.event_id);detail.onclick=ev=>{ev.preventDefault();openEventDetail(e.event_id)};
cells[7].className='record-actions';cells[7].appendChild(detail);
refs={cells,fact,userName,note,evidence,missing,detail};row._experience=refs;row.dataset.eventId=e.event_id;}
refs.cells[0].textContent=shortEventTime(e.t_start);refs.cells[0].title=e.t_start?new Date(e.t_start*1000).toLocaleString():'';
refs.cells[1].textContent=e.camera||'相机未记录';refs.cells[2].textContent=e.cls||'类别未记录';
refs.cells[3].textContent=e.state==='open'?'进行中':e.state==='closed'?'已结束'+(e.end_reason?'（'+e.end_reason+'）':''):'状态未知';
refs.cells[3].className=e.state==='open'?'ev-open':'ev-closed';
const summary=eventSummary(e);refs.fact.textContent=summary.text.length>200?summary.text.slice(0,200)+'…':summary.text;refs.fact.title=summary.text;
refs.userName.hidden=!summary.userName;refs.userName.textContent=summary.userName?(summary.userNameStale?'上次用户名称：':'用户名称：')+summary.userName:'';
refs.note.textContent=summary.note;
const url=e.best_frame?.content_url;refs.evidence.hidden=!url;refs.missing.hidden=Boolean(url);
if(url){refs.evidence.href=url;refs.evidence.setAttribute('aria-label','打开记录原图 '+e.event_id)}
refs.cells[6].textContent=e.escalation_count?'规则升级 ×'+e.escalation_count:'—';}
function paintTimeline(events){const keep=new Set(events.map(e=>e.event_id));
if(!events.length){timelineRows.clear();ui.timeline.replaceChildren();const row=ui.timeline.insertRow();const cell=row.insertCell();cell.colSpan=8;cell.textContent='暂无观察记录；现场持续观察。';return}
if(!timelineRows.size)ui.timeline.replaceChildren();
for(const [id,row] of timelineRows){if(!keep.has(id)){row.remove();timelineRows.delete(id)}}
events.forEach(e=>{let row=timelineRows.get(e.event_id);if(!row){row=ui.timeline.insertRow();timelineRows.set(e.event_id,row)}renderTimelineRow(e,row);ui.timeline.appendChild(row)});}
function repaintTimelineRows(){timelineSnapshot.forEach(e=>{const row=timelineRows.get(e.event_id);if(row)renderTimelineRow(e,row)})}
async function hydrateTimelineSummaries(events){let requests=0;const now=Date.now();
const candidates=events.slice().sort((a,b)=>(detailSummaryCache.get(a.event_id)?.at||0)-(detailSummaryCache.get(b.event_id)?.at||0));
for(const e of candidates){const old=detailSummaryCache.get(e.event_id);
const changed=Number.isFinite(e.t_last)&&Number.isFinite(old?.detail?.t_last)&&e.t_last!==old.detail.t_last;
if(old&&now-old.at<SUMMARY_TTL_MS&&!changed)continue;
if(requests>=SUMMARY_REQUESTS_PER_POLL)break;requests++;
const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),2500);
try{const response=await fetch('/api/v2/events/'+encodeURIComponent(e.event_id),{signal:controller.signal});
if(!response.ok)throw new Error('detail_unavailable');const detail=await response.json();
if(!matchingDetail(e,detail))throw new Error('detail_identity_mismatch');
rememberSummary(e.event_id,{at:Date.now(),detail,error:false});}
catch(error){rememberSummary(e.event_id,{at:Date.now(),detail:old?.detail||null,error:true});}
finally{clearTimeout(timer)}
const row=timelineRows.get(e.event_id);if(row)renderTimelineRow(e,row);}}
const timelineLatest=document.getElementById('timeline-latest');
if(timelineLatest)timelineLatest.onclick=()=>{timelinePaused=false;selectedEventId=null;paintTimeline(timelineSnapshot);timelineLatest.hidden=true;timelineNotice('已显示最新记录');};
const closeEventDetail=document.getElementById('close-event-detail');
if(closeEventDetail)closeEventDetail.onclick=()=>{detailGeneration++;document.getElementById('event-detail-panel').hidden=true;selectedEventId=null;
const row=timelineRows.get(closeEventDetail.dataset.eventId);row?._experience?.detail.focus();};
const timelineRegion=document.querySelector('#observation-card .table-scroll');
if(timelineRegion){timelineRegion.addEventListener('scroll',()=>{if(timelineRegion.scrollLeft>0)timelinePaused=true});
timelineRegion.addEventListener('pointerdown',()=>{timelinePaused=true});}
window.addEventListener('scroll',()=>{const card=document.getElementById('observation-card');
if(card&&window.scrollY>card.offsetTop+120)timelinePaused=true},{passive:true});
async function refreshTimeline(){if(timelineRefreshing)return;timelineRefreshing=true;
const anchor=document.activeElement?.closest?.('#event-timeline tr, #event-detail-panel')||(selectedEventId?document.getElementById('event-detail-panel'):null);
const anchorTop=anchor?.getBoundingClientRect().top;
try{await pollReminders('initial_fact','notifyCursor',rendered,'初始事实提醒');
await pollReminders('semantic_update','semCursor',semRendered,'新增一版理解');await flushAckQueue();
const response=await fetch('/api/v2/events');if(!response.ok)throw new Error('list_unavailable');const data=await response.json();
if(!Array.isArray(data.events))throw new Error('invalid_list');
timelineSnapshot=data.events.filter(e=>typeof e.event_id==='string'&&e.event_id).slice(0,40);
const pending=timelineSnapshot.filter(e=>!timelineRows.has(e.event_id)).length;
if(readingTimeline()&&timelineRows.size){if(pending){timelineLatest.hidden=false;timelineLatest.textContent='查看 '+pending+' 条新记录';timelineNotice('正在阅读 · 新记录不会打断');}
else timelineNotice('正在阅读 · 记录保留');}
else{paintTimeline(timelineSnapshot);timelineLatest.hidden=true;timelineNotice(timelineSnapshot.length?'最近 '+timelineSnapshot.length+' 条记录':'暂无观察记录');}
await hydrateTimelineSummaries(timelineSnapshot);
if(anchor?.isConnected&&Number.isFinite(anchorTop)&&typeof window.scrollBy==='function'){const delta=anchor.getBoundingClientRect().top-anchorTop;if(Math.abs(delta)>1)window.scrollBy(0,delta);}}
catch(error){timelineNotice('记录连接中断 · 保留上次记录（不是实时结果），稍后重试');}
finally{timelineRefreshing=false}}
// L1 状态梯（C-132 F9）：优先级自上而下，禁止一层状态遮蔽另一层——
// 组级生命周期/失败态必须先于 last_detections 等旧成功文案可见；
// 「变化材料已保留」只在材料面确有 ready 包（真实凭证）时才允许出现；
// 被拒结果（last_l1_accepted===false）显示拒收诊断，不得显示为检测观察。
function l1StatusText(g,det,matReady,mat){
if(g.lifecycle==='closing')return'检测停止中';
if(g.lifecycle==='stop_incomplete')return'检测停止未完成（推理未返回，进程退出时将如实报告）';
if(g.lifecycle==='stopped')return'检测已停止';
if(g.state==='model_unavailable')return'检测不可用，变化仍在记录';
if(det.last_status==='infer_failed')return'检测推理失败（将自动重试）';
if(g.state==='loading')return'检测模型加载中';
if(det.in_flight)return'推理中';
if((det.pending||0)>0)return'发现变化，正在分析';
if(det.last_status==='ok'&&det.last_detections>0&&mat&&mat.last_l1_accepted===false)return'结果已拒收（'+(mat.last_reject_reason||'原因未知')+'），不计为检测观察';
if(det.last_status==='ok'&&(det.last_detections||0)>0)return'已检测到对象 '+det.last_detections;
if(det.last_status==='empty')return matReady>0?'检测成功零对象，变化材料已保留（'+matReady+' 包待交接）':'检测成功零对象';
return'正常等待下一巡检'}
function l1MaterialsNote(status){
return(status==='model_unavailable'||status==='infer_failed')?' · 对象感知不可用，后续理解未接入':''}
// C-139 §5 + R2 D1/D2：当前选中相机的分支与描述区（固定容器，随
// refreshHealth 刷新）。安全文本：模型输出一律 textContent 赋值，绝不经
// innerHTML 进 DOM；模型推断（未经校准）与画面确认（observed）分列标注；
// 当前窗口与历史（旧 run/config）分列——当前区只收 is_current===true 的行
// （身份由服务端 runtime 注册表判定），无当前行时如实显示等待/分析说明；
// 历史行自带其 run/config 短码（无身份如实标「身份未记录」）；每条分支行
// 常显 crop_id/模型短码/帧时间速览；分支行可展开来源区（button +
// classList/hidden 切换，无框架）；融合版本条目显示 frame_refs（帧 id/
// 时间/坐标体系）；证据链接诚实——仅当服务器判定 evidence_available 时给
// /api/evidence 受控入口，未持久化裁图显示「原始裁图尚未保存」，绝不给
// 失效链接。C-140 §3：全景/局部速览与 L4 融合版本同样只取当前身份——
// 全景/局部速览只取 is_current===true 的最新有文本行，无当前结果如实显示
// 「等待分析」（绝不拿历史身份旧文本补位）；融合版本经 fusion_history
// 分列，历史身份版本标「历史 run …」入历史区；身份未知（停止/未接线）→
// 显示未知，不假称正在分析。C142（可访问性锚，格式冻结）：真实用户与
// 自动化必须能按完整身份唯一定位「来源」切换钮与原图链接。锚 anchor 由
// API identity 字段纯客户端派生：W=window_key[3]（window_id）、C=crop_id
// 段、M=material_id 段；段内非 [A-Za-z0-9_-] 字符→'-'；crop_id 含
// ':frame:' 标记（生产形状 cam:run:frame:F:crop:I）→ 取该标记之后整段
// （'F:crop:I'→'F-crop-I'），否则取规范化 crop_id 整段；各段取尾（crop
// 尾 16、material 尾 8、window 全量）；缺省→W/M='x'、C='nocrop'。
// anchor='w'+W+'-c'+C+'-m'+M；同页重复→依渲染顺序（当前区在前、历史区
// 在后，确定性）第 2 次起追加 '-k2'/'-k3'… 保证唯一。冻结派生名（同页
// 唯一，可见文本一律不变）：切换钮 aria-label='来源-'+anchor（例：
// 来源-w11-c7633-crop-0-m610）；展开区 id 与 aria-controls=
// 'src-detail-'+anchor，aria-expanded 随展开同步 true/false；saved 序位
// 「查看原图」链接 aria-label='查看原图 '+anchor+'-'+slot
// （previous/current/next）；缩略图 alt=中文序位+'缩略图 '+anchor+'-'
// +slot；「打开原始裁图」链接 aria-label='打开原始裁图 '+anchor。定位
// （Playwright getByRole 的 name 正则参数）：正则 /来源-w11-c7633/ 唯一
// 命中切换钮、正则 /查看原图.*7633.*current/ 唯一命中原图链接。
function shortCode(v){const t=(v===null||v===undefined)?'':String(v);
return t.length<=14?t:(t.slice(0,9)+'…'+t.slice(-4))}
// C-144-R2：跨轮询保留的展开状态（脚本顶层——轮询重渲染按集合恢复）。
// **状态键 ≠ 显示锚**：显示锚（DOM id/aria-label）保持 C142 冻结短格式
// （wW-cC-mM，页内唯一），状态键=完整身份 camera|run|config|window|
// material|branch|crop——不同身份尾部编号相同不继承展开（不串态）。
// 容器=Map（插入序即 LRU），容量 ≤128，超限淘汰最老（有界生命周期）。
const EXPANDED_SOURCES_CAP=128;
const expandedSources=new Map();
function expandedStateKey(b,camId){
const wk=(Array.isArray(b.window_key)&&b.window_key.length===4)?b.window_key.join('|'):'';
return (camId||'')+'|'+wk+'|'+(b.material_id==null?'':String(b.material_id))
+'|'+(b.branch_key||'')+'|'+(b.crop_id||'')}
function expandedMarkOpen(key){expandedSources.delete(key);expandedSources.set(key,true);
while(expandedSources.size>EXPANDED_SOURCES_CAP){
expandedSources.delete(expandedSources.keys().next().value)}}
function expandedMarkClosed(key){expandedSources.delete(key)}
function undRow(cls,text){const row=document.createElement('div');
row.className=cls;row.textContent=text;return row}
// C142 来源锚派生（格式冻结见上方说明）：undIdSeg 规范化段值（非法字符
// →'-'，取尾 limit 位，空→miss）；undSrcAnchor 组装 'wW-cC-mM' 基础锚并
// 在 used 登记表内消解同页碰撞（第 2 次起 '-k2'/'-k3'…，渲染顺序确定）。
function undIdSeg(v,miss,limit){const t=String(v==null?'':v)
.replace(/[^A-Za-z0-9_-]/g,'-');return t?t.slice(-limit):miss}
function undSrcAnchor(b,used){
const wk=(Array.isArray(b.window_key)&&b.window_key.length===4)
?b.window_key[3]:null;
const raw=(b.crop_id==null)?'':String(b.crop_id);
const fi=raw.indexOf(':frame:');
const base='w'+undIdSeg(wk,'x',16)
+'-c'+undIdSeg(fi>=0?raw.slice(fi+7):raw,'nocrop',16)
+'-m'+undIdSeg(b.material_id,'x',8);
const n=(used.get(base)||0)+1;used.set(base,n);
return n>1?base+'-k'+n:base}
function renderUnderstandingDetail(box,camId,entry,capability=null){
if(!box)return;
// C-144-R2：重渲染保留阅读滚动位置（轮询不打断用户正在读的位置）。
const prevScrollTop=box.scrollTop;
box.replaceChildren();
const disabled=understandingDisabled(capability);
if(!entry||typeof entry!=='object'){
if(disabled){box.appendChild(undRow('und-note','图片理解未启用'));box.hidden=false;box.scrollTop=prevScrollTop}
else box.hidden=true;return}
const counts=entry.counts||{};
const ident=(entry.current_identity&&typeof entry.current_identity==='object')?entry.current_identity:null;
const head=document.createElement('div');head.className='und-head';
head.textContent=disabled?'图片理解未启用（已有记录仍可回看）':'理解分支（'+camId+'）：完成 '+(counts.done||0)+' / 失败 '+(counts.failed||0)
+' / 淘汰 '+(counts.evicted||0)+' / 等待 '+(counts.pending||0)
+(entry.window_state?('（窗口 '+entry.window_state+'）'):'')
+(ident?('（当前 run '+shortCode(ident.run_id)+' · 配置 '+shortCode(ident.config_version)+'）')
:'（当前身份未知）');
box.appendChild(head);
const branches=Array.isArray(entry.branches)?entry.branches:[];
const currentRows=branches.filter(b=>b&&b.is_current===true);
const historyRows=branches.filter(b=>!b||b.is_current!==true);
const fusion=(entry.fusion&&entry.fusion.version_id)?entry.fusion:null;
const conflictItems=(fusion&&Array.isArray(fusion.items))
?fusion.items.filter(it=>it&&it.kind==='conflict'):[];
// C-140 §3：融合版本历史分列（fusion_history 每条带 run/config 短码与
// is_current）；顶层融合只在其 is_current===true 时进当前区——历史身份
// 版本（含身份未记录）一律入历史区，绝不冒充当前。
const fusionHist=(Array.isArray(entry.fusion_history)?entry.fusion_history:[])
.filter(r=>r&&r.version_id!==undefined&&r.version_id!==null);
const fusionIsCurrent=!!(fusion&&fusion.is_current===true);
const fusionCurrentRows=fusionHist.filter(r=>r.is_current===true
&&!(fusionIsCurrent&&String(r.version_id)===String(fusion.version_id)));
const fusionHistoryRows=fusionHist.filter(r=>r.is_current!==true
&&!(fusion&&String(r.version_id)===String(fusion.version_id)));
// C142：本页来源锚登记表（undSrcAnchor 据此保证同页唯一，见格式冻结说明）。
const srcAnchors=new Map();
// 单条分支行：类别/确定性标注 + 描述 + 常显追溯速览 + 可展开来源区。
const branchRow=(b,isCurrent)=>{const wrap=document.createElement('div');
wrap.className='und-branch';
const line=document.createElement('div');line.className='und-line';
const kind=document.createElement('span');kind.className='und-note';
kind.textContent='['+(b.kind_label||b.kind||'未知')+']';
line.appendChild(kind);
line.appendChild(document.createTextNode(' '));
const certainty=document.createElement('span');certainty.className='und-note';
certainty.textContent=b.certainty_label?('['+b.certainty_label+']'):'';
line.appendChild(certainty);
line.appendChild(document.createTextNode(' '));
const text=document.createElement('span');text.className='und-desc';
text.textContent=b.text||'';
line.appendChild(text);
if(!isCurrent){const tag=document.createElement('span');tag.className='und-note';
tag.textContent=(b.run_short||b.config_short)
?('（历史 run '+shortCode(b.run_short)+' · 配置 '+shortCode(b.config_short)+'）')
:'（历史条目：身份未记录）';
line.appendChild(tag)}
wrap.appendChild(line);
// 常显追溯速览（不展开也可见）：crop_id / 模型短码 / 帧时间（缺失如实）。
const srcList=(Array.isArray(b.sources)?b.sources:[]).filter(s=>s&&s.present!==false);
const f0=srcList[0]||null;
wrap.appendChild(undRow('und-note','裁图 '+(b.crop_id?shortCode(b.crop_id):'无')
+' · 模型 '+(b.model_ref?shortCode(b.model_ref):'未记录')
+' · 帧 '+(f0?(String(f0.frame_id===undefined||f0.frame_id===null?'?':f0.frame_id)
+' t='+(f0.t_capture_ms===undefined||f0.t_capture_ms===null?'?':f0.t_capture_ms)+'ms'):'未记录')));
const hasTrace=(Array.isArray(b.sources)&&b.sources.length>0)
||!!b.crop_id||!!b.detail_code||!!b.reason||!!b.branch_key;
if(hasTrace){
const anchor=undSrcAnchor(b,srcAnchors);
// C-144-R2：展开/收起读写完整身份状态键（显示锚只作 DOM 定位）。
const stateKey=expandedStateKey(b,camId);
const toggle=document.createElement('button');toggle.type='button';
toggle.className='und-toggle';toggle.textContent='来源 ▸';
toggle.setAttribute('aria-controls','src-detail-'+anchor);
toggle.setAttribute('aria-label','来源-'+anchor);
// C-144：展开状态跨轮询恢复（键=完整身份，见 expandedStateKey）。
const wasOpen=expandedSources.has(stateKey);
toggle.setAttribute('aria-expanded',wasOpen?'true':'false');
const area=document.createElement('div');area.className='und-sources';
area.hidden=!wasOpen;
area.id='src-detail-'+anchor;
if(wasOpen){toggle.classList.add('und-open');toggle.textContent='来源 ▾'}
toggle.onclick=()=>{area.hidden=!area.hidden;
if(area.hidden){expandedMarkClosed(stateKey)}else{expandedMarkOpen(stateKey)}
toggle.classList.toggle('und-open',!area.hidden);
toggle.textContent=area.hidden?'来源 ▸':'来源 ▾';
toggle.setAttribute('aria-expanded',area.hidden?'false':'true')};
wrap.appendChild(toggle);
const wkey=(Array.isArray(b.window_key)&&b.window_key.length===4)?b.window_key:null;
area.appendChild(undRow('und-note','窗口四元：'+(wkey?wkey.join(' | '):'未记录')));
area.appendChild(undRow('und-note','branch_key：'+(b.branch_key||'未记录')));
area.appendChild(undRow('und-note','crop_id：'+(b.crop_id||'未记录（无裁图映射）')));
area.appendChild(undRow('und-note','模型：'+(b.model_ref||'暂无模型身份记录')));
if(Array.isArray(b.sources)&&b.sources.length){
b.sources.forEach(s=>{if(!s)return;
area.appendChild(undRow('und-note','帧#'+(s.position===undefined?'?':s.position)
+' '+(s.frame_id===undefined||s.frame_id===null?'?':s.frame_id)+' t='+(s.t_capture_ms===undefined||s.t_capture_ms===null?'?':s.t_capture_ms)+'ms'
+'（'+(s.timestamp_kind||'时间类型未知')+'）'+(s.present===false?'（缺帧）':'')))})}
if(Array.isArray(b.missing_frames)&&b.missing_frames.length){
area.appendChild(undRow('und-note','缺帧序位：'+b.missing_frames.join(',')))}
if(Array.isArray(b.bbox_norm)&&b.bbox_norm.length===4){
area.appendChild(undRow('und-note','原图区域（bbox_norm）：'+b.bbox_norm.join(',')))}
if(b.detail_code||b.reason){
area.appendChild(undRow('und-note','失败细分：'+(b.detail_code||'无细分码')
+(b.reason?('（'+b.reason+'）'):'')))}
if(fusion){area.appendChild(undRow('und-note','融合版本 '
+String(fusion.version_id).slice(0,16)+'（'+(fusion.status||'未知')+'）'));
conflictItems.slice(-3).forEach(it=>{area.appendChild(undRow('und-note',
'冲突（双方保留）：'+((it&&it.text)||'')))})}
// 证据诚实：仅有服务器判定可用的磁盘证据才给链接；内存裁图未持久化
// 如实显示「原始裁图尚未保存」，绝不产生失效链接。
if(b.evidence_available&&b.evidence_url){
const ev=document.createElement('div');ev.className='und-note';
const link=document.createElement('a');link.textContent='打开原始裁图';
link.setAttribute('aria-label','打开原始裁图 '+anchor);
link.href=b.evidence_url;link.target='_blank';ev.appendChild(link);
area.appendChild(ev)}
else if(b.crop_id){area.appendChild(undRow('und-note','原始裁图尚未保存'))}
// C141：三序位裁图证据（previous/current/next）——saved→受控 /api/crops
// 图片（带可点原图），pending→保存中，failed→保存失败（原因），dropped→
// 已淘汰（原因），commit_uncertain→提交待确认（C141-R2 冻结 §2：A 的
// 耐久提交不确定态原样透传——绝不映射成缺失/失败/已保存，不显示缩略图、
// 不显示假错误；C141-R3 冻结 §2：find 命中 saved 且内存 uncertain 的合成
// 状态附固定码 index_saved_commit_uncertain→「索引行已可读但耐久未确认」，
// 无索引行只标「提交待确认」绝不显示缺失），missing→缺失（原因）；服务
// 不可用→整体占位文案。文本一律 textContent（绝不 innerHTML 拼接）；图片
// onerror→该序位错误占位，且带相机竞态守卫（切相机后迟到的图片失败不写
// 新页面）——绝不显示假缩略图、绝不弹全局错误、绝不清空页面。历史分支行
// 自带「历史」标注，其证据跟随所在身份，不冒充当前。
if(b.evidence&&typeof b.evidence==='object'){
if(b.evidence.available===false){
area.appendChild(undRow('und-note','裁图证据：裁图服务不可用'))}
else{[['previous','前帧'],['current','当前帧'],['next','后帧']].forEach(sd=>{
const slot=b.evidence[sd[0]];if(!slot||typeof slot!=='object')return;
const label=sd[1]+'裁图';
if(slot.status==='saved'&&slot.asset_id){
const row=document.createElement('div');row.className='und-note';
const tag=document.createElement('span');tag.textContent=label+'：已保存';
row.appendChild(tag);row.appendChild(document.createTextNode(' '));
const link=document.createElement('a');link.textContent='查看原图';link.target='_blank';
link.setAttribute('aria-label','查看原图 '+anchor+'-'+sd[0]);
link.href='/api/crops/'+encodeURIComponent(slot.asset_id)
+'?camera='+encodeURIComponent(camId);row.appendChild(link);
const img=document.createElement('img');img.className='und-crop-thumb';
img.alt=label+'缩略图 '+anchor+'-'+sd[0];img.loading='lazy';img.src=link.href;
img.onerror=()=>{if((document.getElementById('camera-select')||{}).value!==camId)return;
if(img.parentNode)img.parentNode.removeChild(img);
row.appendChild(undRow('und-note',label+'缩略图加载失败'))};
row.appendChild(img);area.appendChild(row)}
else if(slot.status==='pending'){area.appendChild(undRow('und-note',label+'：保存中'))}
else if(slot.status==='commit_uncertain'){area.appendChild(undRow('und-note',label+'：提交待确认'+(slot.reason==='index_saved_commit_uncertain'?'（索引行已可读但耐久未确认）':(slot.reason?('（'+slot.reason+'）'):''))))}
else if(slot.status==='failed'){area.appendChild(undRow('und-note',label+'：保存失败（'+(slot.reason||'原因未知')+'）'))}
else if(slot.status==='dropped'){area.appendChild(undRow('und-note',label+'：已淘汰（'+(slot.reason||'原因未知')+'）'))}
else if(slot.status==='saved'){area.appendChild(undRow('und-note',label+'：已保存（资产标识缺失）'))}
else{area.appendChild(undRow('und-note',label+'：缺失（'+(slot.reason||'原因未知')+'）'))}})}}
wrap.appendChild(area)}
return wrap};
if(currentRows.length){box.appendChild(undRow('und-section','当前窗口进展'));
currentRows.forEach(b=>box.appendChild(branchRow(b,true)))}
else if(branches.length){box.appendChild(undRow('und-note',
disabled?'图片理解未启用':ident?'当前身份暂无已保存结果（等待分析）'
:'当前身份未知（未运行或已停止）：等待分析'))}
// C-140 §3：速览只取当前身份——全景取 is_current===true 的最新 panorama
// 文本，局部取最新非 panorama 文本；无当前结果→如实显示「等待分析」
//（绝不拿历史身份的旧文本补位）；身份未知→标未知，不假称正在分析。
let panoText='';let localText='';
for(let bi=currentRows.length-1;bi>=0;bi--){const b=currentRows[bi];
if(!b||!b.text)continue;
if(!panoText&&b.kind==='panorama')panoText=b.text;
if(!localText&&b.kind!=='panorama')localText=b.text;
if(panoText&&localText)break}
const quickWait=disabled?'图片理解未启用':ident?'等待分析':'等待分析（当前身份未知：未运行或已停止）';
if(panoText)box.appendChild(undRow('und-line','最新全景描述：'+panoText));
else box.appendChild(undRow('und-line','全景速览：'+quickWait));
if(localText)box.appendChild(undRow('und-line','最新局部分支描述：'+localText));
else box.appendChild(undRow('und-line','局部速览：'+quickWait));
// C-140 §3：当前区融合——顶层融合 is_current===true 时显示完整版本行+
// 条目+frame_refs；fusion_history 中同身份的更早窗口版本紧凑列出；无
// 当前身份融合→「等待分析」（不拿历史身份版本补位）。
if(fusionIsCurrent){
const items=Array.isArray(fusion.items)?fusion.items:[];
const frow=document.createElement('div');frow.className='und-line';
frow.textContent='最新融合版本 '+String(fusion.version_id).slice(0,16)
+'（'+(fusion.status||'未知')+'，'+items.length+' 条）';
box.appendChild(frow);
items.slice(-3).forEach(it=>{const irow=document.createElement('div');irow.className='und-line';
const certainty=(it&&it.certainty==='observed')?'画面确认':'模型推断';
irow.textContent='· ['+certainty+'] '+((it&&it.text)||'');box.appendChild(irow)});
// C-139-R2 D2：融合版本条目显示 frame_refs（帧 id/时间/坐标体系；
// 缺失如实不显示，绝不编造帧身份）。
const refs=Array.isArray(fusion.frame_refs)?fusion.frame_refs:[];
refs.slice(0,4).forEach(fr=>{if(!fr)return;
box.appendChild(undRow('und-note','· 帧 '+((fr.frame_id===undefined||fr.frame_id===null)?'?':fr.frame_id)
+' t='+((fr.t_ms===undefined||fr.t_ms===null)?'?':fr.t_ms)+'ms（'
+((fr.coord_space===undefined||fr.coord_space===null)?'坐标体系未声明':fr.coord_space)+'）'))})}
fusionCurrentRows.forEach(r=>{box.appendChild(undRow('und-line',
'当前融合版本 '+shortCode(r.version_id)+'（'+(r.status||'未知')+'）'
+(r.window_id?(' · 窗口 '+r.window_id):'')))});
if(!fusionIsCurrent&&!fusionCurrentRows.length){
box.appendChild(undRow('und-line','融合速览：'+quickWait))}
// C-140 §3：历史区——旧身份分支行 + 旧身份融合版本（每条标「历史 run …」；
// 无身份如实标「身份未记录」）。顶层融合非当前时在历史区完整显示（含
// 条目与 frame_refs，帧引用追溯不断链）；fusion_history 紧凑行与顶层
// 同版本去重（同一版本只出现一次）。
if(historyRows.length||fusionHistoryRows.length||(fusion&&!fusionIsCurrent)){
box.appendChild(undRow('und-section','历史记录（旧 run/config）'));
historyRows.forEach(b=>box.appendChild(branchRow(b,false)));
fusionHistoryRows.forEach(r=>{box.appendChild(undRow('und-line',
'历史融合版本 '+shortCode(r.version_id)+'（'+(r.status||'未知')+'）'
+((r.run_short||r.config_short)
?'（历史 run '+shortCode(r.run_short)+' · 配置 '+shortCode(r.config_short)+'）'
:'（历史条目：身份未记录）')))});
if(fusion&&!fusionIsCurrent){
const items=Array.isArray(fusion.items)?fusion.items:[];
const frow=document.createElement('div');frow.className='und-line';
frow.textContent='历史融合版本 '+shortCode(fusion.version_id)
+'（'+(fusion.status||'未知')+'，'+items.length+' 条）'
+((fusion.run_short||fusion.config_short)
?'（历史 run '+shortCode(fusion.run_short)+' · 配置 '+shortCode(fusion.config_short)+'）'
:'（历史条目：身份未记录）');
box.appendChild(frow);
items.slice(-3).forEach(it=>{const irow=document.createElement('div');irow.className='und-line';
const certainty=(it&&it.certainty==='observed')?'画面确认':'模型推断';
irow.textContent='· ['+certainty+'] '+((it&&it.text)||'');box.appendChild(irow)});
const refs=Array.isArray(fusion.frame_refs)?fusion.frame_refs:[];
refs.slice(0,4).forEach(fr=>{if(!fr)return;
box.appendChild(undRow('und-note','· 帧 '+((fr.frame_id===undefined||fr.frame_id===null)?'?':fr.frame_id)
+' t='+((fr.t_ms===undefined||fr.t_ms===null)?'?':fr.t_ms)+'ms（'
+((fr.coord_space===undefined||fr.coord_space===null)?'坐标体系未声明':fr.coord_space)+'）'))})}}
if(!branches.length){const empty=document.createElement('div');empty.className='und-note';
empty.textContent='暂无分支记录';box.appendChild(empty)}
const src=document.createElement('div');src.className='und-note';
const srcParts=[];
if(entry.model_ref)srcParts.push('模型 '+entry.model_ref);
if(entry.calibrated===false)srcParts.push('calibrated=false（模型推断，未经校准）');
src.textContent=srcParts.length?('来源：'+srcParts.join('；')):'来源：本地理解链（暂无模型身份记录）';
box.appendChild(src);
box.hidden=false;
box.scrollTop=prevScrollTop}
async function refreshHealth(){const reqCam=(document.getElementById('camera-select')||{}).value||'';
try{const response=await fetch('/api/health');const data=await response.json();
const runtimeCameras=data.runtime?.cameras;
currentRuntimeCameraIds=Array.isArray(runtimeCameras)&&runtimeCameras.every(item=>typeof item?.camera==='string'&&item.camera)?runtimeCameras.map(item=>item.camera):null;
updateSelectedCameraNote();
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
const mats=(data.materials&&data.materials.cameras)||{};
const und=(data.understanding||{});
const previousUnderstandingCapability=currentUnderstandingCapability;
currentUnderstandingCapability=(data.understanding_capability&&typeof data.understanding_capability==='object')?data.understanding_capability:null;
if(understandingCapabilityState(previousUnderstandingCapability)!==understandingCapabilityState(currentUnderstandingCapability))repaintTimelineRows();
const undLine=document.getElementById('understanding-line');
const undDetail=document.getElementById('understanding-detail');
const nowCam=(document.getElementById('camera-select')||{}).value||'';
if(nowCam===reqCam){// 相机切换竞态守卫：迟到响应不覆盖新相机的理解区
const entry=und[nowCam];
if(undLine){
if(understandingDisabled(currentUnderstandingCapability)){
undLine.textContent='图片理解未启用；可在配置中启用本地或云端图片理解。';undLine.hidden=false}
else if(entry&&typeof entry==='object'){
undLine.textContent='理解进展（'+nowCam+'）：'+(entry.summary||'暂无已完成的分支结果');undLine.hidden=false}
else if(typeof entry==='string'&&entry){// 过渡兼容：旧 runtime 单行字符串形状
undLine.textContent=entry;undLine.hidden=false}
else{undLine.hidden=true}}
renderUnderstandingDetail(undDetail,nowCam,entry,currentUnderstandingCapability)}
const l1box=document.getElementById('l1-status');if(l1box){l1box.replaceChildren();let l1rows=0;
(data.l1||[]).forEach(g=>{if(!Array.isArray(g.cameras))return;const cams=g.per_camera||{};const ct=g.counters||{};
// 组级计数（合并/过期/关闭拒绝）单独一行组级展示，不伪装成每相机状态。
const grow=document.createElement('div');grow.className='l1-line l1-group-line';
grow.textContent='L1 组：合并 '+(ct.merged_start||0)+' / 过期 '+(ct.dropped_expired||0)+' / 关闭拒绝 '+(ct.rejected_closed||0);
l1box.appendChild(grow);l1rows++;
g.cameras.forEach(cam=>{const det=cams[cam]||{};const m=mats[cam]||{};
const row=document.createElement('div');row.className='l1-line';
row.textContent=cam+'：'+l1StatusText(g,det,m.ready||0,m);l1box.appendChild(row);l1rows++})});
l1box.hidden=!l1rows}
const mbox=document.getElementById('l1-materials');if(mbox){mbox.replaceChildren();let mrows=0;
Object.keys(mats).sort().forEach(cam=>{const m=mats[cam]||{};
const row=document.createElement('div');row.className='l1-line l1-materials-line';
row.textContent=cam+'：材料待交接 '+(m.ready||0)+' / 已过期 '+(m.expired||0)
+' / 预算丢弃 '+(m.dropped_pressure||0)+l1MaterialsNote(m.last_l1_status);
mbox.appendChild(row);mrows++});
mbox.hidden=!mrows}
const l2note=document.getElementById('l2-note');
if(l2note){const l2=data.l2;
if(l2&&typeof l2==='object'&&!l2.error&&l2.cameras
&&typeof l2.cameras==='object'&&!Array.isArray(l2.cameras)){
// C173-C2：真实过期来源显示（L2 分支过期终态计数）。真实字段=runtime
// snapshot()["cameras"][cam]["settled_expired"]（win11_l2_runtime.py 结算
// 恰好一次计数）/["expired"]（门禁点计数）。过期分支只带窗口技术身份、
// 无可信事件归属（预算账本 scope 明文不含 event_id），故归"未关联/未分析
// 范围"按相机显示，绝不挂到最近事件。只在真有非零计数时显示；无 l2 数据
// 时不显示、绝不编造 0。
const cams=l2.cameras;const rows=[];
Object.keys(cams).sort().forEach(cam=>{const c=cams[cam];if(!c||typeof c!=='object')return;
const settled=(typeof c.settled_expired==='number'&&Number.isFinite(c.settled_expired))?c.settled_expired:null;
const gate=(typeof c.expired==='number'&&Number.isFinite(c.expired))?c.expired:null;
const n=settled!==null?settled:gate;
if(n===null||n<=0)return;
const row=document.createElement('div');row.className='l1-line';
row.textContent=cam+'：理解分支过期未分析 '+n+'（窗口级 · 未归属到具体事件）';rows.push(row)});
l2note.replaceChildren();rows.forEach(r=>l2note.appendChild(r));l2note.hidden=!rows.length}
else if(l2&&typeof l2==='object'&&l2.error){l2note.hidden=false;
l2note.textContent='理解状态暂不可用（快照读取失败，未视为已分析）'}
else{const hasL1=(data.l1||[]).some(g=>Array.isArray(g.cameras));
l2note.hidden=!hasL1;l2note.textContent=hasL1?'后续语义理解（L2—L4）尚未接入':''}}
if(!cameras.length){const line=document.createElement('div');line.className='camera-line';
line.textContent='尚未接线相机状态，请在值守运行时查看。';ui.cameraStatus.appendChild(line)}else{
cameras.forEach(camera=>{const line=document.createElement('div');
const state=knownStates.includes(camera.state)?camera.state:'';
line.className='camera-line'+(state?' '+state:'');
line.textContent=(camera.camera||'相机')+'：'+(camera.hint||'状态未知');ui.cameraStatus.appendChild(line)})}}
catch(error){currentRuntimeCameraIds=null;updateSelectedCameraNote();ui.cameraStatus.textContent='相机状态暂不可用：请确认值守工作台仍在运行。';
// 请求失败：清空并隐藏 L1/材料/L2/理解区行，绝不残留上一轮的成功文案。
['l1-status','l1-materials','l2-note','understanding-line','understanding-detail'].forEach(id=>{const n=document.getElementById(id);
if(n){n.replaceChildren();n.hidden=true}})}}
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
function renderUserFeedback(body,d,eventId,generation){
const panel=document.createElement('details');panel.className='user-feedback';
const title=document.createElement('summary');title.textContent='用户意见 · 与原始事实分开记录';panel.appendChild(title);
const note=document.createElement('p');note.className='subtle';
note.textContent='仅记录你的命名或误报意见，不删除事实、不修改管理员告警，也尚不会自动改变后续识别。';panel.appendChild(note);
if(!Array.isArray(d.user_feedback)&&d.user_feedback_write_supported!==true){const unavailable=document.createElement('p');unavailable.textContent='用户意见暂不可用，请稍后重新打开详情。';panel.appendChild(unavailable);body.appendChild(panel);return;}
const rows=Array.isArray(d.user_feedback)?d.user_feedback:[];
const current=currentUserOpinion(d);
const savedName=current.display_name?{display_name:current.display_name}:null;
const savedOpinion=current.misreport===true||current.misreport===false?{misreport:current.misreport}:null;
const saved=document.createElement('p');saved.className='user-feedback-saved';
saved.textContent=(!Array.isArray(d.user_feedback)?'历史用户意见尚未读取到；以下操作仅新增用户意见。':(savedName?'用户名称：'+savedName.display_name:(current.complete?'尚未保存用户名称':'当前名称状态未核实'))+(savedOpinion?(savedOpinion.misreport?' · 用户标记可能误报（未核实）':' · 用户已撤销误报标记'):''));panel.appendChild(saved);
const label=document.createElement('label');label.textContent='用户名称（最多16字，不改模型原文）';
const input=document.createElement('input');input.maxLength=16;input.setAttribute('aria-label','用户名称');input.value=savedName?savedName.display_name:'';label.appendChild(input);panel.appendChild(label);
const status=document.createElement('p');status.className='user-feedback-status';status.setAttribute('role','status');
const controls=[];let busy=false,pending=null;
async function submitOpinion(action){
if(busy||generation!==detailGeneration||selectedEventId!==eventId)return;
const actionKey=JSON.stringify(action);
if(!pending||pending.key!==actionKey){pending={key:actionKey,body:{event_id:eventId,...action,request_id:globalThis.crypto?.randomUUID?.()||('op-'+Date.now().toString(36)+'-'+Math.random().toString(36).slice(2))}};}
busy=true;controls.forEach(control=>control.disabled=true);status.textContent='正在保存用户意见…';
try{const response=await fetch('/api/v2/events/feedback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(pending.body)});
let receipt=null;try{receipt=await response.json()}catch(error){}
if(generation!==detailGeneration||selectedEventId!==eventId)return;
if(response.ok&&receipt?.ok===true){pending=null;status.textContent='用户意见已保存';await openEventDetail(eventId);}
else{status.textContent=response.status===400?'内容无效，请检查名称或意见后重试。':response.status===404?'事件暂不可用，请重新打开记录。':response.status===409?'请求与已保存意见冲突，请重新打开详情再试。':'尚未确认保存成功，可重试；原始事实未改变。';}
}catch(error){if(generation===detailGeneration&&selectedEventId===eventId)status.textContent='未确认保存结果，可重试；原始事实未改变。';}
finally{busy=false;controls.forEach(control=>control.disabled=false);}
}
function addAction(text,callback){const button=document.createElement('button');button.type='button';button.textContent=text;button.onclick=callback;controls.push(button);panel.appendChild(button);}
addAction('保存用户名称',()=>{if(!input.value.trim()||input.value.length>16){status.textContent='请输入1至16字的用户名称。';return;}return submitOpinion({display_name:input.value});});
addAction('标记可能误报',()=>submitOpinion({misreport:true}));
addAction('撤销误报标记',()=>submitOpinion({misreport:false}));
panel.appendChild(status);body.appendChild(panel);
}
async function openEventDetail(eventId){
const generation=++detailGeneration;selectedEventId=eventId;timelinePaused=true;
const closer=document.getElementById('close-event-detail');if(closer?.dataset)closer.dataset.eventId=eventId;
const panel=document.getElementById('event-detail-panel');
panel.hidden=false;panel.scrollIntoView({behavior:'smooth',block:'nearest'});
document.getElementById('event-detail-body').replaceChildren();
document.getElementById('event-detail-title').textContent='事件详情：加载中…';
try{const response=await fetch('/api/v2/events/'+encodeURIComponent(eventId));
if(generation!==detailGeneration)return;
if(!response.ok){document.getElementById('event-detail-title').textContent='事件详情不可用';return}
const d=await response.json();
if(generation!==detailGeneration)return;
if(d.event_id&&d.event_id!==eventId){document.getElementById('event-detail-title').textContent='详情身份不匹配，未显示';return}
if(d.event_id===eventId&&typeof d.camera==='string'){rememberSummary(eventId,{at:Date.now(),detail:d,error:false});repaintTimelineRows();}
document.getElementById('event-detail-title').textContent=
'事件详情 · '+(d.camera||'')+' · '+(d.state==='open'?'进行中':'已结束'+(d.end_reason?'（'+d.end_reason+'）':''));
const body=document.getElementById('event-detail-body');
// 原始事实（时间/类别/状态）
const meta=document.createElement('div');meta.className='subtle';
meta.textContent='首次观察：'+new Date(d.t_start*1000).toLocaleString()+' · 类别：'+(d.cls||'');
body.appendChild(meta);
renderUserFeedback(body,d,eventId,generation);
// 最新版先可读；旧版本保留顺序并默认折叠，不改写任何描述。
const orderedDescriptions=(d.descriptions||[]).slice().sort((a,b)=>a.version-b.version);
const descriptionHistory=document.createElement('details');descriptionHistory.className='description-history';
const historyTitle=document.createElement('summary');historyTitle.textContent='历史描述与来源（'+Math.max(0,orderedDescriptions.length-1)+' 版）';descriptionHistory.appendChild(historyTitle);
orderedDescriptions.forEach((desc,index)=>{
const box=document.createElement('div');box.className='desc-version';
const head=document.createElement('div');
head.textContent='v'+desc.version+' · '+(desc.source==='vlm'?'模型补充描述（可能有误，待结合证据核对）':'初始事实（系统记录）')
+progressNote(desc)
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
ev.appendChild(document.createTextNode('证据：'));
// C173-C1：分型显示（字符串资产/结构化帧引用/未知形状），不 join 对象。
desc.evidence_refs.forEach((ref,index)=>{
if(index)ev.appendChild(document.createTextNode('、'));
const item=document.createElement('span');item.className='subtle';
item.textContent=evidenceRefLabel(ref);ev.appendChild(item)});
box.appendChild(ev)}
if(index===orderedDescriptions.length-1)body.appendChild(box);else descriptionHistory.appendChild(box)});
if(orderedDescriptions.length>1)body.appendChild(descriptionHistory);
// C145：原图与可用录像（诚实——有绑定才给受控链接，无绑定如实说明）。
if(d.best_frame&&d.best_frame.content_url){
const ph=document.createElement('div');ph.className='desc-version';
const phead=document.createElement('div');
phead.textContent='原图（最佳帧）· 点击查看原始画面';
ph.appendChild(phead);
const plink=document.createElement('a');plink.textContent='打开原始画面';
plink.setAttribute('aria-label','打开选中记录原始画面');
plink.href=d.best_frame.content_url;plink.target='_blank';
plink.setAttribute('aria-label','打开选中记录原始画面');
ph.appendChild(plink);body.appendChild(ph)}
const recLine=document.createElement('div');recLine.className='subtle';
recLine.textContent='可用录像：暂无（该记录未绑定录像段）';
body.appendChild(recLine);
// 失败/等待状态
const sem=d.semantic||{};
if(sem.state==='waiting_retry'||sem.state==='failed_terminal'){
const warn=document.createElement('div');warn.className='subtle';
warn.textContent='语义更新：'+(sem.code==='evidence_missing_or_corrupt'?'证据缺失或损坏，可复核后重试。':sem.state==='failed_terminal'?'理解失败，暂未生成新结果。':'模型暂不可用，将自动重试。');
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
catch(err){if(generation===detailGeneration)document.getElementById('event-detail-title').textContent='事件详情加载失败，可重试'}}
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
                hint = _hint(entry["state"], entry["capability"], problem,
                             persistence)
                detector_problem = entry["detector_issue"]
                if (entry["state"] != "stopped" and entry["issue"] is not None
                        and detector_problem is not None):
                    hint += (f"；{_CAPABILITY_HINTS[entry['capability']]}"
                             f"；{detector_problem['action']}")
                cameras.append({
                    "camera": entry["camera"],
                    "state": entry["state"],
                    "capability": entry["capability"],
                    "issue": dict(problem) if problem is not None else None,
                    "detector_issue": (dict(detector_problem)
                                       if detector_problem is not None else None),
                    "persistence_issue": (dict(persistence)
                                          if persistence is not None else None),
                    "hint": hint,
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


# ---- C-139 §5：用户追溯（分支行来源展开 + 当前/历史 + 证据诚实） -------------

# 分支 kind → 中文类别标注（词表外原样展示，不冒充翻译）。
BRANCH_KIND_LABELS = {
    "panorama": "全景理解",
    "relation_crop": "关系局部",
    "change_region": "变化区域",
}


def _norm_branch_key_text(value):
    """与理解仓 _norm_branch_key 同规则（list/tuple 逐段 '|' 连接）。

    摘要分支行的键即此形状；增强回放必须产出同一键才能对上行。
    """
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "|".join("" if p is None else str(p) for p in value)
    return str(value)


def _short_code(value, limit=14):
    """run/config 身份短码：超长截断保留尾 4 位（确定性，不编造）。"""
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text
    return text[:limit - 5] + "…" + text[-4:]


def _branch_entry_fields(entry):
    """单条 l3 记录条目 → 追溯展示字段（C-139 §5 D1/D2）。

    缺失/未知字段如实缺省（None/空表），绝不编造：window_key（四元）、
    crop_id、material_id、model_ref、certainty（模型推断/画面确认）、
    detail_code/reason（失败细分）、bbox_norm（如有）、missing_frames
    （缺帧序位，来自 sources[].present=False）。
    """
    if not isinstance(entry, dict):
        return None
    wkey = entry.get("window_key")
    # C141-R2 冻结 §4：身份键三态规范化（与 _crop_evidence_slots 的身份
    # 门同一判定核心）——int/非空 str 合法（规范化字符串形，R1 兼容不变）；
    # None/空串=未记录（如实 None）；bool/float/容器=**畸形** → None——
    # 绝不 str 化成 "None"/"True"/"1.5"/"[]" 后冒充有效身份（下游裁图
    # 证据门据此零 find/零 read + identity_malformed，展示面据此如实缺省）。
    wkey = ([_crop_identity_scalar(p) for p in wkey]
            if isinstance(wkey, list) and len(wkey) == 4 else [])
    sources = entry.get("sources")
    sources = ([s for s in sources if isinstance(s, dict)]
               if isinstance(sources, list) else [])
    obs = entry.get("observation") \
        if isinstance(entry.get("observation"), dict) else {}
    inf = entry.get("inference") \
        if isinstance(entry.get("inference"), dict) else {}
    certainty = obs.get("certainty") or inf.get("certainty") \
        or "model_inferred"
    bbox = entry.get("bbox_norm")
    bkey = entry.get("branch_key")
    material = bkey[6] if isinstance(bkey, (list, tuple)) and len(bkey) > 6 \
        else None
    reason = entry.get("reason")
    return {
        "window_key": wkey,
        "crop_id": _crop_identity_scalar(entry.get("crop_id")),
        "material_id": _crop_identity_scalar(material),
        "model_ref": str(entry.get("model_ref") or ""),
        "certainty": str(certainty),
        "detail_code": (str(entry["error_code"])
                        if entry.get("error_code") else None),
        "reason": (str(reason)
                   if isinstance(reason, str) and reason.strip() else None),
        "bbox_norm": ([float(x) for x in bbox]
                      if isinstance(bbox, (list, tuple)) and len(bbox) == 4
                      else None),
        "missing_frames": [s.get("position") for s in sources
                           if s.get("present") is False],
    }


def authoritative_camera_identity(state, camera):
    """C-139-R2 D1：当前有效身份的唯一权威来源 = runtime 身份注册表。

    只读 ``state.l2._registry``（C-137 §4 冻结：生产接线经
    update/set_camera_identity 维护，发布门禁据此复核）。注册表缺失、
    相机未登记、身份段不全（None/空）→ None——**绝不从保存历史推断**
    （历史只是已发生事实，最后一条记录不冒充当前有效身份）。
    """
    l2_runtime = getattr(state, "l2", None)
    registry = getattr(l2_runtime, "_registry", None)
    if not isinstance(registry, dict):
        return None
    pair = registry.get(str(camera))
    if not isinstance(pair, (tuple, list)) or len(pair) != 2:
        return None
    run_id, config_version = pair
    if run_id in (None, "") or config_version in (None, ""):
        return None
    return {"run_id": str(run_id), "config_version": str(config_version)}


def _effective_gate_reason(l2_recs):
    """当前有效的 L1 门控兜底原因：只有**最新一条** l2 记录自带的
    gate_reason 才算数（C-139-R2 D1：旧 fallback 原因不得附着到其后的
    成功窗口）。最新记录无 gate_reason → None。"""
    recs = [r for r in (l2_recs or ()) if isinstance(r, dict)]
    if not recs:
        return None
    gate = recs[-1].get("gate_reason")
    if isinstance(gate, str) and gate.strip():
        return gate
    return None


# 冻结摘要行中的门控兜底段（build_summary 固定文案；模型文本段恒带
# 「全景：」「局部：」前缀，不会以此开头）。
_GATE_SEGMENT_RE = re.compile(r"^关系识别不可用（.+）$")


def sanitized_summary(summary, l2_recs):
    """重建摘要行：门控兜底原因只反映当前有效的那条（C-139-R2 D1）。

    store 的 build_summary 取「最新一条带 gate_reason 的记录」，旧失败
    原因会残留在其后成功窗口的摘要里。这里按段拆开、剔除全部门控段，
    再按最新 l2 记录的真实 gate_reason 决定是否原位放回——位置（计数段
    之后）与文案保持冻结形状，绝不改写其它段。
    """
    segments = (summary if isinstance(summary, str) else "").split("；")
    kept = []
    gate_index = None
    for seg in segments:
        if _GATE_SEGMENT_RE.match(seg.strip()):
            if gate_index is None:
                gate_index = len(kept)
            continue
        kept.append(seg)
    gate = _effective_gate_reason(l2_recs)
    if gate is not None:
        if gate_index is None:
            gate_index = 1 if (kept and kept[0].startswith("分支 ")) else 0
        kept.insert(gate_index, "关系识别不可用（" + gate + "）")
    return "；".join(kept)


# 融合版本 frame_refs 白名单（C-139 §3 冻结字段：frame_id/t_ms/time_kind/
# bbox/coord_space/crop_ref/stable_ref）；逐字段类型与长度约束，绝不透传
# 路径/凭据/base64 等非受控负载。
_FRAME_REF_KEYS = ("frame_id", "t_ms", "time_kind", "coord_space",
                   "crop_ref", "stable_ref", "bbox_norm")
_FRAME_REF_TEXT_LIMIT = 160
_FRAME_REF_MAX_ENTRIES = 32


def _sanitize_frame_refs(value, limit=_FRAME_REF_MAX_ENTRIES):
    """l4 记录的 frame_refs → 受控白名单行（JSON-safe；未知字段丢弃）。"""
    if not isinstance(value, (list, tuple)):
        return []
    rows = []
    for ref in list(value)[:limit]:
        if not isinstance(ref, dict):
            continue
        row = {}
        for key in _FRAME_REF_KEYS:
            if key not in ref:
                continue
            raw = ref[key]
            if key == "bbox_norm":
                row[key] = ([float(x) for x in raw]
                            if isinstance(raw, (list, tuple))
                            and len(raw) == 4
                            and all(isinstance(x, (int, float))
                                    and not isinstance(x, bool)
                                    and math.isfinite(float(x))
                                    for x in raw) else None)
            elif raw is None:
                row[key] = None
            elif isinstance(raw, bool):
                continue
            elif isinstance(raw, int):
                row[key] = raw
            elif isinstance(raw, float):
                row[key] = raw if math.isfinite(raw) else None
            elif isinstance(raw, str):
                row[key] = raw[:_FRAME_REF_TEXT_LIMIT]
        rows.append(row)
    return rows


def _fusion_history_rows(l4_hist, cur_pair, limit=32):
    """C-140 §3：l4 原史 → 融合版本历史分列行。

    每条带 version_id 的 l4 记录一行（保持原史顺序，最旧在前，尾部有界）：
    version_id/status/window_id + run/config 短码 + is_current——记录
    window_key 身份与权威身份（runtime 注册表）匹配才 True；记录无
    window_key（身份未记录）或无权威身份 → False，**不冒充当前**。
    """
    rows = []
    for rec in l4_hist:
        if not isinstance(rec, dict) or rec.get("version_id") is None:
            continue
        wkey = rec.get("window_key")
        wkey = ([str(p) for p in wkey]
                if isinstance(wkey, list) and len(wkey) == 4 else [])
        rows.append({
            "version_id": str(rec["version_id"]),
            "status": str(rec.get("status") or "unknown"),
            "window_id": wkey[3] if wkey else None,
            "run_short": _short_code(wkey[1]) if wkey else None,
            "config_short": _short_code(wkey[2]) if wkey else None,
            "is_current": bool(cur_pair is not None and wkey
                               and (wkey[1], wkey[2]) == cur_pair),
        })
    return rows[-limit:] if limit and len(rows) > limit else rows


# ---- C141：独立裁图资产接口 + 分支三序位证据 -------------------------------

# asset_id = 归档内容 sha256（64 位小写 hex）；对外只收 asset_id，绝不收路径。
ASSET_ID_RE = re.compile(r"^[0-9a-f]{64}$")

# evidence 三序位（API/索引 slot 值）→ sources[].position 的规范序位。
# l3 原始记录实测形状：position 是 int 0/1/2（0=previous、1=current、
# 2=next）——符号位 "prev"/"cur"/"next" 在数据里不存在，绝不用其匹配。
_EVIDENCE_SLOTS = (("previous", 0), ("current", 1), ("next", 2))


def _normalized_slot_position(value):
    """sources[].position → 规范序位 int 0/1/2；其余值忽略（None）。

    接受 int 0/1/2 与数字字符串 "0"/"1"/"2"（规范化后等值）；bool 与
    其它值一律忽略——绝不把未知 position 映射到某个序位（否则整序位
    证据失真，宁可 frame_absent/查不到也不误配）。
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value in (0, 1, 2):
        return value
    if isinstance(value, str) and value in ("0", "1", "2"):
        return int(value)
    return None

# 裁图服务未接线哨兵：与显式 None（已接线但不可用）区分。未接线（属性
# 不存在）→ 分支行保持既有形状（无 evidence 键，既有契约一字不动）；
# 已接线但不可用/异常 → evidence 段结构化降级 available=false，页面显示
# 占位文案，绝不崩溃、绝不冒充。
_CROP_SERVICE_NOT_WIRED = object()


def _safe_t_capture(value):
    """t_capture_ms 白名单化：有限数值原样，其余（bool/NaN/类型不符）None。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return value if math.isfinite(float(value)) else None
    except (TypeError, ValueError):
        return None


def _identity_aware_summary(state, camera):
    """C141：B 的身份感知摘要接线（鸭子类型可选）。

    ``state.l2.understanding_summary(camera)`` 存在且返回非空字符串 →
    原文优先（「有 N 条结果保存失败（未持久化）」「正在分析/暂无当前
    结果」等语义由 B 的实现带来，此处不改写、不再做门控段清理）；方法
    缺失/异常/空串 → None（调用方回退既有 ustore 摘要行为）。
    """
    summarizer = getattr(getattr(state, "l2", None),
                         "understanding_summary", None)
    if not callable(summarizer):
        return None
    try:
        text = summarizer(camera)
    except Exception:
        return None
    if isinstance(text, str) and text.strip():
        return text
    return None


# C141 集成修复：A 的索引/v2 校验把 branch 冻结为枚举
# ``"panorama"|"local"``（B 提交侧局部分支统一 "local"，精确子类经
# crop_id 内 ":chg:" 可追溯）。理解仓分支行的 kind 值域含
# relation_crop/change_region 等子类标签——原样透传会与索引的 "local"
# 不相等 → find 永远查不中（branch 词表不一致 = 关联失配）。过滤前必须
# 规范化到冻结枚举；无法归类的 kind 不带 branch 键过滤——宁可不按
# branch 过滤，不得用错误值过滤。不改 A 的枚举、不改 B 的提交侧。
_BRANCH_LOCAL_KINDS = frozenset({"local", "relation_crop", "change_region"})


def _branch_enum_for_filter(kind):
    """理解分支 kind → A 索引冻结枚举（"panorama"|"local"|None）。"""
    text = str(kind or "").strip()
    if text == "panorama":
        return "panorama"
    if text in _BRANCH_LOCAL_KINDS:
        return "local"
    return None


# C141-R1 修阻塞 3/4：归档 provenance ↔ 索引条目 ↔ 查询 三方身份复核。
# 完整冻结身份键「存在即比」；核心键缺一即视为归档身份不完整。B 提交侧
# provenance 携带 int（material_id=610/frame_id=9），服务侧派生字符串——
# 等值必须跨 int/str 形状按规范字符串比较（与 A 侧 find 的过滤等值同一
# 规范：int/str → 字符串形；bool/float/容器绝不可比）。
_CROP_IDENTITY_KEYS = ("run_id", "config_version", "material_id",
                       "window_id", "branch", "crop_id", "frame_id", "slot")
_CROP_IDENTITY_CORE = ("camera_id", "run_id", "config_version",
                       "material_id", "crop_id", "frame_id")


def _crop_identity_scalar(value):
    """身份标量规范化：int/str → 规范字符串形（可比较）；空串/bool/
    float/None/复合类型 → None（未记录、不可比、不可信）。"""
    if type(value) is int:
        return str(value)
    if type(value) is str and value:
        return value
    return None


def _crop_identity_slot_state(value):
    """C141-R2 冻结 §4：身份标量三态分类（与 _crop_identity_scalar 同一
    判定核心——"ok" ⇔ 规范化后可比）：
    - "ok"：int（非 bool）或非空 str → 合法身份（规范化字符串形）；
    - "missing"：键缺省/None/空串 → 未记录（R1 identity_unrecorded 语义
      不变）；
    - "malformed"：bool/float/容器等**在场但类型非法** → 绝不 str 化为
      有效身份（R1 的"不可比"收紧为"非法→零 find/零 read+如实状态"，
      如实 identity_malformed / frame_identity_malformed）。"""
    if type(value) is int or (type(value) is str and value):
        return "ok"
    if value is None or type(value) is str:
        return "missing"
    return "malformed"


def _crop_identity_verdict(provenance, entry, camera_id):
    """三方身份复核 → None（一致）或固定错误码（绝不泄露差异细节）。

    - "asset_incomplete"：归档 provenance 或索引条目缺核心身份键
      （camera_id/run_id/config_version/material_id/crop_id/frame_id）
      ——身份链无法核验，宁可拒绝不冒认；
    - "asset_identity_mismatch"：camera 三方不等值，或任一身份键
      （存在即比）两两值不等/单边缺失（单边缺失 = 另一侧声称的身份
      得不到对方佐证，一律不容）。
    """
    if not isinstance(provenance, dict) or not isinstance(entry, dict):
        return "asset_incomplete"
    if any(_crop_identity_scalar(provenance.get(k)) is None
           for k in _CROP_IDENTITY_CORE):
        return "asset_incomplete"
    if any(_crop_identity_scalar(entry.get(k)) is None
           for k in _CROP_IDENTITY_CORE):
        return "asset_incomplete"
    cam_prov = _crop_identity_scalar(provenance.get("camera_id"))
    cam_entry = _crop_identity_scalar(entry.get("camera_id"))
    cam_query = _crop_identity_scalar(camera_id)
    if cam_prov != cam_entry or cam_prov != cam_query:
        return "asset_identity_mismatch"
    for key in _CROP_IDENTITY_KEYS:
        left = _crop_identity_scalar(provenance.get(key))
        right = _crop_identity_scalar(entry.get(key))
        if left is None and right is None:
            continue          # 双方均未记录该键（v1 旧档合法缺省）→ 无从比对
        if left is None or right is None or left != right:
            return "asset_identity_mismatch"
    return None


def _crop_evidence_slots(camera, row, crop_service):
    """C141 + C141-R1：单分支三序位证据段（previous/current/next）。

    数据源 = ``crop_service.find(camera, 完整身份等值过滤, limit=1)``——
    过滤键与 A 的索引条目身份键对齐（run_id/config_version/window_id/
    branch/crop_id/material_id/slot/frame_id；branch 经
    _branch_enum_for_filter 规范化到冻结枚举 "panorama"|"local"）。规则：
    - 完整身份必备才查询（C141-R1 修阻塞 4）：window_key 四元 + branch
      （规范化枚举）+ crop_id + material_id 齐全；缺任一 → 全序位
      missing（reason=identity_unrecorded），零 find 调用、不借图——
      绝不用部分身份宽松过滤跨身份捞资产；
    - C141-R2 冻结 §4 分支级身份门（先于任何 find/read，零查询）：
      身份键**在场但类型非法**（bool/float/容器——绝不 str 化成 "True"/
      "1.5"/"[]" 后当有效身份）→ 全序位 missing(identity_malformed)；
      window_key[0]（相机）≠ 请求相机 → 全序位 missing(camera_mismatch)
      ——绝不查询他相机索引（同 run/config/窗口也不借）；
    - 该序位帧在分支 sources 里缺席/标记缺失 → missing(frame_absent)，
      绝不以当前帧冒充缺失邻帧（sources[].position 按规范序位 int 0/1/2
      匹配——0=previous、1=current、2=next，数字字符串等值，其它值忽略）；
    - 源帧身份必备（C141-R1）：该序位 source 的 frame_id 缺失/null →
      missing(frame_identity_unrecorded)，不查询——同窗异帧绝不借图；
      frame_id 在场但类型非法 → missing(frame_identity_malformed)
      （C141-R2 收紧，同样零查询）；frame_id 合法 → 作为过滤键传入 find；
    - find 命中 → status 原样透传（saved/pending/failed/dropped 与 A 的
      耐久提交不确定态 commit_uncertain——索引条目/服务真实状态原样并列
      透传，绝不映射成 missing/saved/failed），仅 saved 给 asset_id，
      reason 透传索引固定码；saved 命中后经 crop_service.read（既有验证
      读取）取归档 provenance 做索引↔归档二次全身份复核（相机+身份键+
      frame_id），不符 → 该序位 failed(identity_mismatch)，绝不展示资产；
    - C141-R3 冻结 §2 内存耐久状态并列查询：每序位 find 之后调用
      ``crop_service.commit_status(camera, 九元 identity)``（A 的有界只读
      内存任务表查询，零磁盘；九元=camera/run/config/material/window/
      branch/crop/frame_id/slot，键名与索引条目身份键一致；身份门与帧门
      保证齐备后才调用，缺帧序位不查询）。真实链路 find 永不返回
      commit_uncertain（索引行只存 saved/failed），内存不确定必须由此
      合成对用户可见：
      · 返回 commit_uncertain 且 find 命中 saved → 序位
        commit_uncertain（reason=index_saved_commit_uncertain——「索引行
        已可读但耐久未确认」），不给 asset_id、绝不触发 read；
      · 返回 commit_uncertain 且 find 无命中 → 序位 commit_uncertain
        （reason=None），**绝不降级 not_in_index/missing**；
      · {"status": None}（匹配任务无不确定）/ None（无匹配，或重启后
        内存状态已失去）→ 走既有逻辑（命中展示/not_in_index，重启后
        saved 照常展示，绝不伪造不确定）；
      · 服务无 commit_status 方法（鸭子缺失）→ 跳过该查询，既有逻辑
        不回归（结构化降级不回归）；调用异常随整段结构化降级；
    - 帧在但索引查不到 → missing(not_in_index)（如实缺省；四态接通与
      否以索引/服务真实状态为准，绝不把「索引无」冒充成其它状态）；
    - 服务异常 → 整段 {"available": false,
      "reason": "crop_service_unavailable"}（结构化降级，绝不 500）。

    历史分支身份齐全照常查询展示（行身份标注已有 is_current/历史短码），
    不冒充当前。
    """
    slots = {}
    wkey_raw = row.get("window_key")
    wkey_parts = (list(wkey_raw)
                  if isinstance(wkey_raw, list) and len(wkey_raw) == 4
                  else [])
    # C141-R2 冻结 §4：逐键三态规范化——int/非空 str 合法（规范化字符串
    # 形，R1 兼容不变）；None/空串=未记录；bool/float/容器=畸形（R1 的
    # str() 宽容在此收紧：绝不让 None/True/[]/1.5 变 "None"/"True"/"[]"/
    # "1.5" 后当有效身份去查询索引）。
    wkey = [_crop_identity_scalar(p) for p in wkey_parts]
    branch_enum = _branch_enum_for_filter(row.get("kind"))
    crop_id = _crop_identity_scalar(row.get("crop_id"))
    material_id = _crop_identity_scalar(row.get("material_id"))
    # C141-R1：完整身份四件套（窗口三元 + 规范化 branch + 裁图 + 材料）
    # 缺一 → 本分支身份未记录：全序位 identity_unrecorded，零查询。
    complete = (len(wkey) == 4 and all(p is not None for p in wkey)
                and branch_enum is not None
                and crop_id is not None and material_id is not None)
    # C141-R2 冻结 §4 分支级身份门（先于任何 find/read）：
    # - 畸形（在场但类型非法）→ identity_malformed；
    # - 跨相机（window_key[0] 合法但不等于请求相机）→ camera_mismatch，
    #   绝不查询他相机索引；跨相机优先于缺省（更具体、不可被缺省键掩盖，
    #   零查询结论相同）；
    # - 缺省（键缺省/None/空串）→ identity_unrecorded（R1 语义不变）。
    if any(_crop_identity_slot_state(p) == "malformed"
           for p in wkey_parts) \
            or _crop_identity_slot_state(row.get("crop_id")) == "malformed" \
            or _crop_identity_slot_state(row.get("material_id")) \
            == "malformed":
        gate_reason = "identity_malformed"
    elif len(wkey) == 4 and wkey[0] is not None \
            and wkey[0] != str(camera):
        gate_reason = "camera_mismatch"
    elif not complete:
        gate_reason = "identity_unrecorded"
    else:
        gate_reason = None
    base = ({"run_id": wkey[1], "config_version": wkey[2],
             "window_id": wkey[3], "branch": branch_enum,
             "crop_id": crop_id, "material_id": material_id}
            if complete else {})
    sources = row.get("sources")
    sources = ([s for s in sources if isinstance(s, dict)]
               if isinstance(sources, list) else [])
    by_pos = {}
    for src in sources:
        # C141 集成修复：position 按规范序位（int 0/1/2，数字字符串等值）
        # 匹配——其它值忽略，绝不错配序位。
        pos = _normalized_slot_position(src.get("position"))
        if pos is not None:
            by_pos.setdefault(pos, src)
    try:
        for slot_name, pos in _EVIDENCE_SLOTS:
            src = by_pos.get(pos)
            t_capture = _safe_t_capture(
                src.get("t_capture_ms") if isinstance(src, dict) else None)
            if gate_reason is not None:
                # C141-R2：分支级身份门（畸形/跨相机/缺省）——零 find/
                # 零 read，序位按固定状态如实（绝不借图）。
                slots[slot_name] = {"asset_id": None, "status": "missing",
                                    "reason": gate_reason,
                                    "t_capture_ms": t_capture}
                continue
            if src is None or src.get("present") is False:
                slots[slot_name] = {"asset_id": None, "status": "missing",
                                    "reason": "frame_absent",
                                    "t_capture_ms": t_capture}
                continue
            frame_id = src.get("frame_id") if isinstance(src, dict) else None
            frame_state = _crop_identity_slot_state(frame_id)
            if frame_state != "ok":
                # C141-R1/R2：源帧身份未记录（缺省/None/空串）或畸形
                # （bool/float/容器——绝不 str 化为有效帧身份）——同窗
                # 异帧绝不借图，零查询。
                slots[slot_name] = {"asset_id": None, "status": "missing",
                                    "reason": ("frame_identity_malformed"
                                               if frame_state == "malformed"
                                               else
                                               "frame_identity_unrecorded"),
                                    "t_capture_ms": t_capture}
                continue
            entry = None
            # C141-R3：过滤键整段复用——find 的持久索引事实与
            # commit_status 的内存九元身份同一规范形（过滤键用规范化
            # 字符串形（int 9 → "9"），与 A 侧 int/str 规范化等值同一规范）。
            filters = dict(base, slot=slot_name,
                           frame_id=_crop_identity_scalar(frame_id))
            hits = crop_service.find(camera, dict(filters), limit=1)
            if hits and isinstance(hits[0], dict):
                entry = hits[0]
            status = (str(entry.get("status") or "missing")
                      if entry is not None else None)
            # C141-R3 冻结 §2：内存耐久提交状态查询（A 的有界只读接口，
            # 锁内短临界、零磁盘——find 的持久索引事实与进程内
            # commit_uncertain 可同时诚实表达，互不伪造）。服务无该方法
            # （鸭子缺失）→ 跳过该查询走既有逻辑（结构化降级不回归）；
            # 身份门/帧门已在上方拦截，九元身份到此必齐。
            commit_info = None
            commit_fn = getattr(crop_service, "commit_status", None)
            if callable(commit_fn):
                commit_info = commit_fn(camera,
                                        dict(filters, camera_id=camera))
            if (isinstance(commit_info, dict)
                    and commit_info.get("status") == "commit_uncertain"
                    and (entry is None or status == "saved")):
                # 内存 commit_uncertain 合成可见状态：
                # - 索引行已可读（saved 命中）→ 附注固定码
                #   index_saved_commit_uncertain（DOM 标「索引行已可读但
                #   耐久未确认」），不给 asset_id、绝不触发 read——耐久
                #   未确认前绝不展示像素；
                # - 索引无行 → 同为 commit_uncertain，绝不降级成
                #   not_in_index/missing（内存不确定对用户必须可见）。
                # 索引 failed/pending/dropped 等其它持久事实照既有逻辑
                # 透传（持久事实与内存状态并列，不互相覆盖）。
                slots[slot_name] = {"asset_id": None,
                                    "status": "commit_uncertain",
                                    "reason": ("index_saved_commit_uncertain"
                                               if entry is not None else None),
                                    "t_capture_ms": t_capture}
                continue
            if entry is None:
                slots[slot_name] = {"asset_id": None, "status": "missing",
                                    "reason": "not_in_index",
                                    "t_capture_ms": t_capture}
                continue
            # C141-R2 冻结 §2：索引条目 status 原样透传——含 A 的耐久
            # 提交不确定态 commit_uncertain（与 saved/pending/failed/
            # dropped 并列的可见状态；绝不映射成 missing/saved/failed，
            # 也绝不因此给 asset_id 或触发读取——权威真相=索引文件本身，
            # 页面对其显示「提交待确认」占位而非假错误/假缩略图）。
            reason = entry.get("reason")
            reason = (str(reason) if isinstance(reason, str)
                      and reason.strip() else None)
            asset_id = None
            if status == "saved":
                asset_id = (str(entry["asset_id"])
                            if entry.get("asset_id") else None)
                reason = None
                # C141-R1：索引↔归档二次全身份复核——经既有验证读取取
                # 归档 provenance，与索引条目及本分支相机逐键复核；不符
                # → failed(identity_mismatch)，绝不展示错归属资产。
                record = crop_service.read(asset_id)
                metadata = (record.get("metadata")
                            if isinstance(record, dict) else None)
                prov = (metadata.get("provenance")
                        if isinstance(metadata, dict) else None)
                if _crop_identity_verdict(prov, entry, camera) is not None:
                    slots[slot_name] = {"asset_id": None, "status": "failed",
                                        "reason": "identity_mismatch",
                                        "t_capture_ms": t_capture}
                    continue
            slots[slot_name] = {"asset_id": asset_id, "status": status,
                                "reason": reason, "t_capture_ms": t_capture}
    except Exception:
        return {"available": False, "reason": "crop_service_unavailable"}
    return {"available": True, "previous": slots["previous"],
            "current": slots["current"], "next": slots["next"]}


def enrich_understanding_view(camera, ustore, summarized, evidence_lookup,
                              current_identity=None,
                              crop_service=_CROP_SERVICE_NOT_WIRED,
                              summary_override=None):
    """C-139 §5 + C-139-R2 D1/D2 + C-140 §3：冻结摘要 → 用户追溯视图。

    - 分支行追加追溯字段（_branch_entry_fields；同 branch_key 后写覆盖，
      与 build_summary 同序同规则回放 l3 原始历史，保证对上行一致）；
    - kind_label 中文类别 + certainty_label（画面确认/模型推断）；
    - evidence_available 由 evidence_lookup(crop_id) 判定（磁盘证据索引
      在场）；有则给受控链接 /api/evidence/<id>，无则 evidence_url=None
      ——页面据实显示「原始裁图尚未保存」，绝不产生失效链接；
    - current_identity：调用方传入的权威身份（authoritative_camera_identity，
      来自 runtime 注册表；此处**绝不**从保存历史推断）。每行标
      ``is_current: bool``（行身份 (run, config) 与权威身份匹配才 True；
      无权威身份或行无身份 → False，不冒充当前）；
    - summary：经 sanitized_summary 重建——旧 fallback 原因不附着到其后
      的成功窗口；
    - fusion：items[].sources 透传（未随版本保存时如实空列表）；并回放
      l4 原始记录补 frame_refs（frame_id/时间/坐标体系等受控白名单字段，
      无则空列表——绝不编造帧身份）；同条记录回放窗口身份 → run/config
      短码 + is_current（C-140 §3，与权威身份匹配才 True）；
    - fusion_history：l4 原史逐版本分列行（_fusion_history_rows）——页面
      据此把当前身份版本留当前区、历史身份版本标「历史」入历史区。
    - C141 crop_service：未接线（哨兵）→ 分支行保持既有形状（无 evidence
      键）；接线后每分支附加三序位 evidence 段（_crop_evidence_slots），
      服务不可用/异常 → available=false 结构化降级。
    - C141 summary_override：B 的身份感知摘要（l2.understanding_summary）
      优先原文采用；None/空 → 回退既有 sanitized_summary 行为。
    """
    branches = [dict(row) for row in (summarized.get("branches") or [])
                if isinstance(row, dict)]
    try:
        l2_hist = [r for r in ustore.history(camera, "l2")
                   if isinstance(r, dict)]
    except Exception:
        l2_hist = []
    try:
        l3_hist = [r for r in ustore.history(camera, "l3")
                   if isinstance(r, dict)]
    except Exception:
        l3_hist = []
    try:
        l4_hist = [r for r in ustore.history(camera, "l4")
                   if isinstance(r, dict)]
    except Exception:
        l4_hist = []
    summary = (summary_override
               if isinstance(summary_override, str)
               and summary_override.strip()
               else sanitized_summary(summarized.get("summary"), l2_hist))
    enriched = {}
    for rec in l3_hist:
        results = rec.get("results")
        if isinstance(results, list) and results:
            entries = results
        elif any(k in rec for k in ("branch", "branch_key", "status")):
            entries = [rec]
        else:
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            kind = entry.get("branch") or rec.get("branch") or "unknown"
            key = _norm_branch_key_text(entry.get("branch_key"))
            if not key:
                key = _norm_branch_key_text(
                    [rec.get("window"), kind, entry.get("crop_id")]) \
                    or str(kind)
            fields = _branch_entry_fields(entry)
            if fields is not None:
                enriched[key] = fields
    cur_pair = ((str(current_identity["run_id"]),
                 str(current_identity["config_version"]))
                if isinstance(current_identity, dict)
                and current_identity.get("run_id") is not None
                and current_identity.get("config_version") is not None
                else None)
    any_evidence = False
    for row in branches:
        fields = enriched.get(row.get("branch_key")) or {}
        row.update(fields)
        row["kind_label"] = BRANCH_KIND_LABELS.get(
            str(row.get("kind") or ""), str(row.get("kind") or "未知"))
        certainty = str(fields.get("certainty") or "model_inferred")
        row["certainty_label"] = ("画面确认" if certainty == "observed"
                                  else "模型推断")
        crop_id = fields.get("crop_id")
        available = bool(crop_id)
        if available:
            try:
                available = bool(evidence_lookup(crop_id))
            except Exception:
                available = False
        row["evidence_available"] = available
        row["evidence_url"] = ("/api/evidence/" + quote(crop_id, safe="")
                               if available else None)
        any_evidence = any_evidence or available
        wkey = fields.get("window_key") or []
        row["run_short"] = _short_code(wkey[1]) if len(wkey) == 4 else None
        row["config_short"] = _short_code(wkey[2]) if len(wkey) == 4 else None
        # C-139-R2 D1：is_current 恒为 bool——只认权威身份匹配，绝不
        # 用「最后一条记录」冒充当前（无权威身份 → 全部 False）。
        row["is_current"] = bool(
            cur_pair is not None and len(wkey) == 4
            and (str(wkey[1]), str(wkey[2])) == cur_pair)
        # C141：三序位证据段——仅当裁图服务已接线时附加（未接线保持既有
        # 形状）；未接线即 None → available=false；查询/读取异常在
        # _crop_evidence_slots 内结构化降级，绝不让理解面 500。
        if crop_service is not _CROP_SERVICE_NOT_WIRED:
            row["evidence"] = (
                _crop_evidence_slots(camera, row, crop_service)
                if crop_service is not None else
                {"available": False, "reason": "crop_service_unavailable"})
    # C-140 §3：融合版本历史分列行（先于顶层融合增强构建；二者同源 l4 原史）。
    fusion_history = _fusion_history_rows(l4_hist, cur_pair)
    fusion = summarized.get("fusion")
    if isinstance(fusion, dict):
        fusion = dict(fusion)
        items = []
        for item in (fusion.get("items") or []):
            if isinstance(item, dict):
                item = dict(item)
                if not isinstance(item.get("sources"), list):
                    item["sources"] = []
                items.append(item)
        fusion["items"] = items
        # D2：frame_refs 从 l4 原始记录回放（版本号精确匹配；缺失如实空）。
        # C-140 §3：同条记录回放窗口身份 → run/config 短码 + is_current
        #（与权威身份匹配才 True；记录无 window_key → False 不冒充当前）。
        version_id = fusion.get("version_id")
        fusion["frame_refs"] = []
        fusion["run_short"] = None
        fusion["config_short"] = None
        fusion["is_current"] = False
        if version_id is not None:
            for rec in reversed(l4_hist):
                if rec.get("version_id") is None:
                    continue
                if str(rec["version_id"]) == str(version_id):
                    fusion["frame_refs"] = _sanitize_frame_refs(
                        rec.get("frame_refs"))
                    coord = rec.get("coord_space")
                    if isinstance(coord, str) and coord:
                        fusion["coord_space"] = coord
                    wkey = rec.get("window_key")
                    if isinstance(wkey, list) and len(wkey) == 4:
                        fusion["run_short"] = _short_code(wkey[1])
                        fusion["config_short"] = _short_code(wkey[2])
                        fusion["is_current"] = bool(
                            cur_pair is not None
                            and (str(wkey[1]), str(wkey[2])) == cur_pair)
                    break
    return {"summary": summary, "branches": branches, "fusion": fusion,
            "fusion_history": fusion_history,
            "evidence_available": any_evidence,
            "current_identity": (dict(current_identity)
                                 if isinstance(current_identity, dict)
                                 else None)}


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
        # 仅由Win11入口依据当前配置赋bool；未知/其他产品不猜测已关闭。
        self.understanding_enabled = None
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
        """Prefer current runtime cameras, retaining historical rows for review."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT DISTINCT camera FROM zones").fetchall()
        finally:
            conn.close()
        historical = [r[0] for r in rows]
        current = []
        runtime = getattr(self, "runtime", None)
        if runtime is not None:
            try:
                snapshot = runtime.snapshot()
                cameras = snapshot.get("cameras", []) if isinstance(snapshot, dict) else []
                if isinstance(cameras, list):
                    current = [row["camera"] for row in cameras
                               if isinstance(row, dict)
                               and isinstance(row.get("camera"), str)
                               and row["camera"]]
            except Exception:
                pass  # Unknown runtime identity does not remove historical data.
        return [{"id": camera} for camera in dict.fromkeys(current + historical)]

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

    @staticmethod
    def _user_feedback_rows(conn, event_id, owner_kind="semantic"):
        try:
            from .win11_feedback import get_feedback
            rows = (get_feedback(conn, event_id, owner_kind="fact")
                    if owner_kind == "fact" else get_feedback(conn, event_id))
            return rows
        except Exception:
            return None  # Unavailable is not a false claim of empty history.

    @staticmethod
    def _user_feedback_current(conn, event_id, owner_kind="semantic"):
        try:
            from .win11_feedback import get_feedback_summary
            return get_feedback_summary(conn, event_id, owner_kind=owner_kind)
        except Exception:
            return None

    @staticmethod
    def _user_feedback_supported(owner_kind="semantic"):
        try:
            import inspect
            from .win11_feedback import record_feedback
            return callable(record_feedback) and (owner_kind != "fact" or
                "owner_kind" in inspect.signature(record_feedback).parameters)
        except Exception:
            return False

    def record_user_feedback(self, event_id, *, display_name=None,
                             misreport=None, request_id=None,
                             owner_kind="semantic"):
        from .win11_feedback import record_feedback
        conn = self._conn()
        outer_transaction = conn.in_transaction
        try:
            kwargs = {"display_name": display_name, "misreport": misreport,
                      "request_id": request_id}
            if owner_kind == "fact":
                kwargs["owner_kind"] = "fact"
            result = record_feedback(conn, event_id, **kwargs)
            if result.get("status") in ("recorded", "idempotent") and not outer_transaction:
                conn.commit()
            return result
        except Exception:
            if not outer_transaction:
                conn.rollback()
            return {"status": "feedback_unavailable"}
        finally:
            if not outer_transaction:
                conn.close()

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
            user_feedback = self._user_feedback_rows(conn, event_id)
            user_feedback_current = self._user_feedback_current(conn, event_id)
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
                "object": tracked_object, "evidence": evidence,
                "user_feedback": user_feedback,
                "user_feedback_current": user_feedback_current,
                "user_feedback_write_supported": self._user_feedback_supported()}

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

    def evidence_available(self, asset_id):
        """受控证据键当前能否经 /api/evidence 取到（C-139 §5 D3 诚实判定）。

        只查 evidence_assets 索引中 read_evidence 受理的 JPEG 证据
        （kind=clean_best_frame 且 mime=image/jpeg）并确认文件仍在证据根
        内——只 stat，不读图像、不改状态。理解链的内存裁图未持久化时
        索引无行 → False：页面必须显示「原始裁图尚未保存」，绝不给
        失效链接。
        """
        key = str(asset_id or "")
        if not key or "/" in key:
            return False
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT kind,mime,path FROM evidence_assets"
                " WHERE asset_id=?", (key,)).fetchone()
            if row is None or row["kind"] != "clean_best_frame" \
                    or row["mime"] != "image/jpeg":
                return False
            try:
                full_path = self.evidence.resolve(row["path"])
            except (TypeError, ValueError, OSError):
                return False
            return os.path.isfile(full_path)
        finally:
            conn.close()

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
            if detail is not None:
                detail["user_feedback"] = self._user_feedback_rows(
                    conn, event_id, owner_kind="fact")
                detail["user_feedback_current"] = self._user_feedback_current(
                    conn, event_id, owner_kind="fact")
                detail["user_feedback_write_supported"] = self._user_feedback_supported("fact")
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
            # C153 车道E：跨窗口追加版本所在的事件阶段（逐版本）。白名单折出，
            # 不回传原始 payload；无/坏结构 → None，由页面显示明确缺失。
            item["progress"] = bounded_event_progress(payload_d)
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

    def _png(self, body):
        """C141：裁图 PNG 响应——固定安全头（nosniff + no-store），零缓存。"""
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
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
            configured = getattr(self.server.state, "understanding_enabled", None)
            if type(configured) is bool:
                payload["understanding_capability"] = {"configured": configured}
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
            # L1 检测中间层（C-131 §4）：state.l1 非空时按检测配置组披露
            # snapshot；无 l1 属性或为空 → 响应保持现状（无 l1 键，既有契约
            # 一字不动）。snapshot 每次现调（线程安全只读）；异常结构化降级
            # 为固定码，绝不 500、绝不外泄路径/凭据/异常正文。
            # 归一化：snapshot 自带的逐相机字典让位为 per_camera，组级
            # cameras 恒为相机 id 列表——两种形状不再互相遮蔽。
            l1_groups = getattr(self.server.state, "l1", None)
            if l1_groups:
                try:
                    groups = []
                    for g in l1_groups:
                        snap = dict(g["pipeline"].snapshot())
                        per_camera = snap.pop("cameras", {})
                        snap["cameras"] = list(g["cameras"])
                        snap["per_camera"] = per_camera
                        groups.append(snap)
                    payload["l1"] = groups
                except Exception:
                    payload["l1"] = [{"error": "snapshot_unavailable"}]
            # 材料交接面（C-132 F7/F9）：state.materials 非空时披露 store
            # 快照；无 materials 属性或为空 → 响应无该键（既有契约一字不动）。
            # snapshot 每次请求现调（线程安全只读）；异常结构化降级为固定码，
            # 绝不 500、绝不外泄路径/凭据/异常正文。
            materials_store = getattr(self.server.state, "materials", None)
            if materials_store:
                try:
                    payload["materials"] = materials_store.snapshot()
                except Exception:
                    payload["materials"] = {"error": "materials_unavailable"}
            # L2 关系阶段（C-134）：显式开关启用时披露运行摘要（计数/状态/
            # 最近输出元数据）；裁图图像与模型路径绝不出健康面。未启用→
            # 无该键（既有契约一字不动）。
            l2_runtime = getattr(self.server.state, "l2", None)
            if l2_runtime is not None:
                try:
                    payload["l2"] = l2_runtime.snapshot()
                except Exception:
                    payload["l2"] = {"error": "l2_unavailable"}
            # 理解进展（C-138 §3/§6）：统一从 UnderstandingStore 冻结摘要
            # 生成——分支状态（完成/失败/淘汰/等待）+实际描述文本+最新融合
            # 版本；模型推断（calibrated=false）与画面确认分列标注。store
            # 优先取 state.understanding_store（入口接线），再退 runtime
            # 持有实例（state.l2.understanding_store，C-138 §5）。
            ustore = getattr(self.server.state, "understanding_store", None)
            if ustore is None and l2_runtime is not None:
                ustore = getattr(l2_runtime, "understanding_store", None)
            if ustore is not None and hasattr(ustore, "summary") \
                    and hasattr(ustore, "history"):
                try:
                    cams = [str(cam) for cam in
                            (getattr(l2_runtime, "camera_ids", None) or [])]
                    if not cams:
                        try:
                            cams = sorted(
                                ustore.snapshot().get("cameras", {}))
                        except Exception:
                            cams = []
                    block = {}
                    wb_state = self.server.state
                    for cam in cams:
                        summarized = ustore.summary(cam)
                        src = latest_source_fields(
                            ustore.history(cam, "l2"),
                            ustore.history(cam, "l3"))
                        # C-139 §5 + C-139-R2 D1：分支行来源增强 + 当前/历史
                        # 分列（当前身份只认 runtime 注册表权威值，绝不从
                        # 历史推断）+ 证据诚实判定（裁图未持久化 →
                        # evidence_available=False，页面显示「原始裁图尚未
                        # 保存」，绝不产生失效链接）。
                        # C141：三序位 evidence（裁图服务已接线时）+ B 的
                        # 身份感知 summary 优先（异常/缺失回退既有行为）。
                        view = enrich_understanding_view(
                            cam, ustore, summarized,
                            wb_state.evidence_available,
                            current_identity=authoritative_camera_identity(
                                wb_state, cam),
                            crop_service=getattr(
                                wb_state, "crop_service",
                                _CROP_SERVICE_NOT_WIRED),
                            summary_override=_identity_aware_summary(
                                wb_state, cam))
                        block[cam] = {
                            "summary": view["summary"],
                            "window_state": summarized.get("window_state"),
                            "counts": branch_counts(
                                summarized.get("branches") or []),
                            "branches": view["branches"],
                            "fusion": view["fusion"],
                            "fusion_history": view["fusion_history"],
                            "model_ref": src["model_ref"],
                            "calibrated": src["calibrated"],
                            "evidence_available": view["evidence_available"],
                            "current_identity": view["current_identity"]}
                    payload["understanding"] = block
                except Exception:
                    payload["understanding"] = {}
            elif l2_runtime is not None and \
                    hasattr(l2_runtime, "summary_line"):
                # 过渡兼容：尚未接 UnderstandingStore 的旧 runtime 保持
                # C-136 单行形状（页面 JS 两种形状都认）。
                try:
                    payload["understanding"] = {
                        cam: l2_runtime.summary_line(cam)
                        for cam in l2_runtime.camera_ids}
                except Exception:
                    payload["understanding"] = {}
            self._json(payload)
            return
        if path.startswith("/api/understanding/"):
            # C-138 §3/§6 + C-139 §5/R2 D1 + C-140 §3：按相机返回冻结摘要
            #（camera/summary/window_state/branches/fusion/fusion_history +
            # 分支行追溯增强/evidence_available/current_identity（权威注册
            # 表）+ l2/l3/l4 原始有界历史（无图像无路径）。
            camera_id = unquote(path[len("/api/understanding/"):])
            state = self.server.state
            ustore = getattr(state, "understanding_store", None)
            if ustore is None:
                l2_runtime = getattr(state, "l2", None)
                ustore = (getattr(l2_runtime, "understanding_store", None)
                          if l2_runtime is not None else None)
            if ustore is not None and hasattr(ustore, "summary") \
                    and hasattr(ustore, "history"):
                try:
                    summarized = ustore.summary(camera_id)
                except Exception:
                    self._json({"error": "history_unavailable"}, status=404)
                    return
                payload = dict(summarized)
                # C-139 §5 + C-139-R2 D1/D2：分支行来源增强 + 当前/历史分列
                #（current_identity 只认 runtime 注册表权威值，绝不从历史
                # 推断；旧 fallback 原因不附着到后续成功窗口；frame_refs
                # 从 l4 原始记录回放；enrich 内部对 evidence 判定做异常降级）。
                # C141：三序位 evidence（裁图服务已接线时）+ B 的身份感知
                # summary 优先（异常/缺失回退既有行为）。
                view = enrich_understanding_view(
                    camera_id, ustore, summarized, state.evidence_available,
                    current_identity=authoritative_camera_identity(
                        state, camera_id),
                    crop_service=getattr(state, "crop_service",
                                         _CROP_SERVICE_NOT_WIRED),
                    summary_override=_identity_aware_summary(state,
                                                             camera_id))
                payload["summary"] = view["summary"]
                payload["branches"] = view["branches"]
                payload["fusion"] = view["fusion"]
                # C-140 §3：融合版本历史分列（每条带 run/config 短码与
                # is_current——当前身份版本留当前区，历史版本标「历史」）。
                payload["fusion_history"] = view["fusion_history"]
                payload["evidence_available"] = view["evidence_available"]
                payload["current_identity"] = view["current_identity"]
                for kind in ("l2", "l3", "l4"):
                    try:
                        payload[kind] = ustore.history(camera_id, kind)
                    except Exception:
                        payload[kind] = []
                self._json(payload)
                return
            # 过渡兼容：未接 UnderstandingStore 的旧 runtime 保持 C-136 形状
            l2_runtime = getattr(self.server.state, "l2", None)
            if l2_runtime is None or not hasattr(l2_runtime, "history"):
                self._json({"error": "l2_unavailable"}, status=404)
                return
            try:
                history = l2_runtime.history(camera_id)
            except Exception:
                self._json({"error": "history_unavailable"}, status=404)
                return
            summary = ""
            if hasattr(l2_runtime, "summary_line"):
                summary = l2_runtime.summary_line(camera_id)
            self._json({"camera": camera_id, "summary": summary,
                        "l2": history.get("l2", []),
                        "l3": history.get("l3", []),
                        "l4": history.get("l4", [])})
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
        if path.startswith("/api/crops/"):
            # C141：独立裁图资产接口——只收 asset_id（64 hex）+ camera，
            # 绝不收磁盘路径。顺序：格式 → 相机存在 → 服务可用 → 关联校验
            #（该 asset_id 注册在该 camera 名下；只知哈希不等于可读）→
            # 经 crop_service.read 验证读取 → C141-R1 修阻塞 3：归档
            # metadata.provenance ↔ 索引条目 ↔ 查询相机三方身份复核
            #（不一致/缺失 → 固定 404 码 asset_identity_mismatch /
            # asset_incomplete，绝不输出路径、绝不泄露差异细节）。
            # 未注册/他相机资产与不存在资产同一 404 固定码（不泄露存在性
            # 差异）；失败一律结构化 JSON 固定码，零路径/凭据/异常正文。
            # 既有 /api/evidence、frame、recordings 语义一字不动。
            asset_id = unquote(path[len("/api/crops/"):])
            query = parse_qs(self.path.split("?", 1)[1]) \
                if "?" in self.path else {}
            camera_id = (query.get("camera") or [""])[0]
            wb_state = self.server.state
            if not ASSET_ID_RE.match(asset_id or ""):
                self._json({"error": "invalid_asset",
                            "code": "invalid_asset"}, 404)
                return
            if not CAMERA_ID_RE.match(camera_id or "") or (
                    camera_id not in wb_state.monitors
                    and not any(str(cam.get("id")) == camera_id
                                for cam in wb_state.cameras())):
                self._json({"error": "camera not found",
                            "code": "unknown_camera"}, 404)
                return
            crop_service = getattr(wb_state, "crop_service", None)
            if crop_service is None:
                self._json({"error": "crop_service_unavailable",
                            "code": "crop_service_unavailable"}, 503)
                return
            try:
                hits = crop_service.find(camera_id, {"asset_id": asset_id},
                                         limit=1)
            except Exception:
                self._json({"error": "crop_service_unavailable",
                            "code": "crop_service_unavailable"}, 503)
                return
            if not hits:
                self._json({"error": "asset_not_found",
                            "code": "asset_not_found"}, 404)
                return
            try:
                record = crop_service.read(asset_id)
            except Exception as exc:
                if getattr(exc, "code", None) in ("missing", "corrupt",
                                                  "invalid_id"):
                    self._json({"error": "asset_unreadable",
                                "code": "asset_unreadable"}, 410)
                    return
                self._json({"error": "crop_read_failed",
                            "code": "crop_read_failed"}, 500)
                return
            png = record.get("png") if isinstance(record, dict) else None
            if not isinstance(png, (bytes, bytearray)) or not png:
                self._json({"error": "asset_unreadable",
                            "code": "asset_unreadable"}, 410)
                return
            # C141-R1 修阻塞 3：只信 hits 不够——归档 provenance、索引
            # 条目与查询相机三方身份一致才出图（防错归属/毒索引借出资产）。
            metadata = record.get("metadata") \
                if isinstance(record, dict) else None
            provenance = (metadata.get("provenance")
                          if isinstance(metadata, dict) else None)
            verdict = _crop_identity_verdict(provenance, hits[0], camera_id)
            if verdict is not None:
                self._json({"error": verdict, "code": verdict}, 404)
                return
            self._png(bytes(png))
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
        if path in ("/api/semantic-events/feedback", "/api/v2/events/feedback"):
            if not isinstance(body, dict):
                self._json({"error": "invalid_feedback"}, 400)
                return
            result = self.server.state.record_user_feedback(
                body.get("event_id"), display_name=body.get("display_name"),
                misreport=body.get("misreport"), request_id=body.get("request_id"),
                owner_kind="fact" if path == "/api/v2/events/feedback" else "semantic")
            status = result.get("status")
            if status in ("recorded", "idempotent"):
                self._json({"ok": True, **result})
            else:
                code = (404 if status == "event_not_found" else
                        409 if status == "request_id_conflict" else
                        400 if status in ("invalid_event_id", "invalid_feedback", "invalid_request_id") else 503)
                self._json({"error": status if code != 503 else "feedback_unavailable"}, code)
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
