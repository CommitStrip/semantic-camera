"""C153 车道E：事件进度对用户可见（server 最小扩围 + 页面阶段显示）。

三条独立证据，互不代替：

1. **真实写入形态**：夹具逐字段照抄 B 车道
   `scam/win11_event_progress.py::_associate` 写进版本 payload 的
   `window_id` / `fusion_version_id` / `progress{...}`，并经该模块自己的
   `attach_understanding` 落库；字段清单直接从源码解析，B 增删字段而 server
   白名单没跟上时本文件即失败。
2. **真实 API 读取**：`WorkbenchState.event_fact_detail` 与 HTTP
   `GET /api/v2/events/{id}`（进程内最小 Handler，零网络）读同一份库，断言
   白名单、类型、长度上限与"明确缺失"的表达。
3. **页面消费合同**：真实页面脚本在 node DOM 桩里执行，驱动真实
   `openEventDetail` 渲染路径，断言阶段文案映射、v1 保留、after_close 不显示
   为事件重新开始、坏结构不制造阶段、版本序号不暗示准确率。

浏览器未实测（本机无可用 Playwright 浏览器）：第 3 条是 node DOM 桩行为，
不是浏览器渲染证据，真实浏览器观感未验证。
"""
import io
import json
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scam import db
from scam.server import (_INDEX_HTML, WorkbenchHandler, WorkbenchState,
                         bounded_event_progress)
from scam.win11_event_progress import attach_understanding

_ROOT = Path(__file__).resolve().parent.parent
_PROGRESS_SOURCE = _ROOT / "scam" / "win11_event_progress.py"

_WRITER_KEYS = (
    "phase", "phase_basis", "prior_understanding_versions",
    "event_state_at_write", "event_end_reason", "event_t_start", "event_t_last",
    "event_t_end", "evidence_ref_count", "bound_frame_count", "evidence_t_min",
    "evidence_t_max")
_ENVELOPE_KEYS = ("window_id", "fusion_version_id", "progress")
_ALLOWED_RESPONSE_KEYS = (set(_ENVELOPE_KEYS) | set(_WRITER_KEYS) | {"missing"})


def _writer_progress_keys():
    """B 车道写入的 progress 块字段（源码解析，不靠人工抄写）。"""
    source = _PROGRESS_SOURCE.read_text(encoding="utf-8")
    block = source.split("progress = {", 1)[1].split("\n        }", 1)[0]
    return tuple(re.findall(r'"([a-z_]+)":', block))


def _writer_envelope_keys():
    """B 车道写进版本 payload 的顶层键（window_id / fusion_version_id / …）。"""
    source = _PROGRESS_SOURCE.read_text(encoding="utf-8")
    block = source.split("payload={", 1)[1].split("\n            }", 1)[0]
    return tuple(re.findall(r'"([a-z_]+)":', block))


def _without_comments(script):
    """去掉 JS 注释后的真实代码文本（注释里可以说"不暗示准确率"，代码里不许出现）。"""
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", script, flags=re.S)


# ------------------------------------------------------------------ 真实库夹具

CAMERA, RUN, CONFIG = "cam", "r1", 0
OBJECT = f"{CAMERA}:{RUN}:track:1"


class Story:
    """一个真实事件事实：对象事实 + 事实链 v1 描述 + 追加版本（走 B 的写入函数）。"""

    def __init__(self, path, name):
        self.path = path
        self.event_id = f"{CAMERA}:{RUN}:event:{name}"
        self.t_last = 1000.0
        self.conn = db.connect(path)
        db.init_schema(self.conn)
        # 该函数无返回值（只建行）；后续 open_event_fact 的对象守卫触发器即证此行存在。
        db.open_tracked_object(
            self.conn, object_id=OBJECT, camera=CAMERA, t_start=1000.0,
            cls="person", conf=0.9, payload={"track_id": 1,
                                             "timestamp_kind": "host_receive"})
        assert db.open_event_fact(
            self.conn, event_id=self.event_id, camera=CAMERA, object_id=OBJECT,
            t_start=1000.0, cls="person", conf=0.9,
            payload={"track_id": 1, "timestamp_kind": "host_receive"})
        assert db.ensure_initial_description(
            self.conn, self.event_id, text=f"{CAMERA} 画面中出现 person",
            t_created=1000.0)

    def advance(self, t_last):
        """推进事实链自身区间（与 Monitor 推进同一列）；追加版本须落在区间内。"""
        assert db.update_event_fact(self.conn, self.event_id, t_last=t_last)
        self.t_last = t_last

    def close(self, reason="camera-stopped"):
        assert db.close_event_fact(self.conn, self.event_id, reason=reason)

    def append(self, text, *, window_id, fusion_version_id, progress,
               observed=None, inference=None):
        """真实写入路径：与 B 的 `_associate` 同形 payload 走 attach_understanding。"""
        payload = {"window_id": window_id, "fusion_version_id": fusion_version_id,
                   "progress": progress,
                   "processing_fingerprint": "f" * 64,
                   "items": [{"kind": "observation", "text": text}],
                   "bindings": [], "observed": observed, "inference": inference}
        binding = {"camera_id": CAMERA, "run_id": RUN, "config_version": CONFIG,
                   "object_id": OBJECT, "event_id": self.event_id,
                   "track_id": 1, "time_kind": "host_receive",
                   "frame_id": str(window_id), "t_ms": self.t_last * 1000.0}
        result = attach_understanding(
            self.conn, event_id=self.event_id,
            identity={"camera_id": CAMERA, "run_id": RUN,
                      "config_version": CONFIG},
            text=text, uncertainty="high", t_created=self.t_last,
            evidence_refs=[binding], model_id="l4-fusion", binding=binding,
            payload=payload)
        assert result["status"] == "appended", result
        return result

    def raw_description(self, text, payload_text):
        """绕过写入函数直接落一行描述（只用于构造坏结构/缺字段负例）。"""
        version = db.next_event_description_version(self.conn, self.event_id) + 1
        self.conn.execute(
            "INSERT INTO event_descriptions (description_id,event_id,version,"
            " source,text,uncertainty,evidence_refs,t_created,payload)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (f"desc:{self.event_id}:v{version}", self.event_id, version, "vlm",
             text, "high", "[]", self.t_last, payload_text))
        self.conn.commit()
        return version


def _writer_progress(phase, **changes):
    """照抄 B 车道由持久化事实推导出的 progress 块（值域与真实写入一致）。"""
    closed = phase == "after_close"
    progress = {
        "phase": phase,
        "phase_basis": "persisted_fact_at_write",
        "prior_understanding_versions": 0,
        "event_state_at_write": "closed" if closed else "open",
        "event_end_reason": "camera-stopped" if closed else None,
        "event_t_start": 1000.0,
        "event_t_last": 1300.0,
        "event_t_end": 1300.0 if closed else None,
        "evidence_ref_count": 1,
        "bound_frame_count": 1,
        "evidence_t_min": 1300.0,
        "evidence_t_max": 1300.0,
    }
    progress.update(changes)
    return progress


@pytest.fixture
def story(tmp_path):
    made = []

    def build(name):
        item = Story(str(tmp_path / "c153.db"), name)
        made.append(item)
        return item

    yield build
    for item in made:
        item.conn.close()


def _detail(path, event_id):
    return WorkbenchState(path).event_fact_detail(event_id)


def _progress_of(detail, version):
    return next(d["progress"] for d in detail["descriptions"]
                if d["version"] == version)


# ------------------------------------------------ 1. 真实写入形态与白名单同步

def test_writer_progress_fields_are_all_whitelisted():
    """B 写入的每个非空字段都被 server 白名单接住（不丢真值），且不多不少。"""
    written = _writer_progress_keys()
    assert set(written) == set(_WRITER_KEYS), \
        f"B 车道 progress 字段变化：{written}；请同步 server 白名单与页面合同"
    real = _writer_progress("continuing")
    assert set(real) == set(written), "夹具必须逐字段照抄真实写入形态"
    parsed = bounded_event_progress(
        {"window_id": 2, "fusion_version_id": "v3", "progress": real})
    for name in written:
        if real[name] is None:
            continue
        assert name in parsed, f"白名单漏掉真实写入字段：{name}"
    assert parsed["phase"] == "continuing"
    assert parsed["missing"] == [], \
        "真实写入形态不得被判为缺失（键都在，未闭合事件的 null 不算缺失）"
    assert set(_writer_envelope_keys()) >= {"window_id", "fusion_version_id"}


def test_real_write_then_read_roundtrip_keeps_accounting(story, tmp_path):
    """真实写入 → 真实读取：phase、身份键、计数、时间跨度都原样可读。"""
    item = story("roundtrip")
    item.advance(1300.0)
    item.append("人向门内移动", window_id=2, fusion_version_id="v3",
                progress=_writer_progress("first_update", event_t_last=1300.0))
    detail = _detail(str(tmp_path / "c153.db"), item.event_id)
    progress = _progress_of(detail, 2)
    assert progress["phase"] == "first_update"
    assert progress["window_id"] == 2
    assert progress["fusion_version_id"] == "v3"
    assert progress["evidence_ref_count"] == 1
    assert progress["bound_frame_count"] == 1
    assert progress["event_t_start"] == 1000.0
    assert progress["event_t_last"] == 1300.0
    assert progress["event_t_end"] is None
    assert progress["missing"] == [], "真实写入形态不得出现缺失字段"
    assert "payload" not in detail["descriptions"][-1], \
        "原始 payload 绝不回传（items/bindings/processing_fingerprint 一律不进响应）"
    assert "items" not in progress and "bindings" not in progress


# ------------------------------------------------ 2. 白名单、类型、限长、缺失

def test_progress_whitelist_types_limits_and_explicit_gaps(story, tmp_path):
    """未批准字段丢弃；类型/取值不符即"明确缺失"；超长截断；坏结构不制造阶段。"""
    item = story("validation")
    item.raw_description("坏值版本", json.dumps({
        "window_id": "w" * 300,              # 超长 → 截断到 128
        "fusion_version_id": 7,              # 合法 int
        "unapproved_field": "绝不能出现",
        "progress": {
            "phase": "<script>alert(1)</script>",   # 非枚举 → 不合法
            "phase_basis": "persisted_fact_at_write" * 20,   # 超长 → 截断 64
            "prior_understanding_versions": True,   # bool 拒绝
            "evidence_ref_count": 2.7,              # float → int 截断
            "bound_frame_count": -1,                # 负数拒绝
            "event_state_at_write": "resurrected",  # 非枚举拒绝
            "event_t_start": float("nan"),          # NaN 拒绝
            "event_t_end": float("inf"),            # Inf 拒绝
            "event_t_last": "1300.0",               # 数字串不是数字
            "event_end_reason": "camera-stopped",
            "evidence_t_min": 1100.0,
            "evidence_t_max": 1100.5,
        }}, ensure_ascii=False))
    item.raw_description("坏结构版本", "not-a-json-object")
    item.raw_description("缺 progress 版本", json.dumps({"window_id": 9}))
    item.raw_description("progress 非对象", json.dumps(
        {"window_id": 9, "progress": ["first_update"]}))
    item.raw_description("缺身份键版本", json.dumps(
        {"progress": _writer_progress("continuing")}))
    detail = _detail(str(tmp_path / "c153.db"), item.event_id)

    bad = _progress_of(detail, 2)
    assert bad["window_id"] == "w" * 128, "超长身份键必须截断（上限 128）"
    assert bad["window_id"] != "w" * 300
    assert bad["fusion_version_id"] == 7
    assert bad["phase"] == "unknown", "非枚举 phase 绝不当作某个阶段"
    assert "phase" in bad["missing"]
    assert bad["phase"] not in ("first_update", "continuing", "after_close")
    assert len(bad["phase_basis"]) == 64, "超长字符串按上限截断"
    assert "prior_understanding_versions" in bad["missing"], "bool 不是计数"
    assert bad["evidence_ref_count"] == 2, "有限 float 截断为 int（不四舍五入放大）"
    assert "bound_frame_count" in bad["missing"], "负数计数不合法"
    assert "event_state_at_write" in bad["missing"]
    assert "event_t_start" in bad["missing"] and "event_t_end" in bad["missing"]
    assert bad["event_t_last"] is None, "数字串不是数字（如实为 null）"
    assert bad["event_end_reason"] == "camera-stopped"
    assert bad["evidence_t_min"] == 1100.0 and bad["evidence_t_max"] == 1100.5
    assert bad["missing"] == sorted(bad["missing"])
    assert set(bad) <= _ALLOWED_RESPONSE_KEYS
    assert "unapproved_field" not in json.dumps(bad, ensure_ascii=False)
    assert "绝不能出现" not in json.dumps(detail, ensure_ascii=False)

    for version in (3, 4, 5, 6):
        assert _progress_of(detail, version) is None, \
            f"坏结构/缺 progress/缺身份键（v{version}）必须明确缺失，不得制造阶段"


@pytest.mark.parametrize("payload", [
    None, "raw", 3, ["progress"], {"progress": "continuing"},
    {"progress": {"phase": "continuing"}},          # 缺身份键
    {"window_id": 1},                                # 缺 progress 块
])
def test_no_progress_means_null_not_a_stage(payload):
    """没有可用 progress → None（明确缺失），绝不返回某个阶段。"""
    assert bounded_event_progress(payload) is None


# ------------------------------------------------ 3. 阶段归属、v1 保留、HTTP

def test_phases_and_v1_preserved_through_workbench_and_http(story, tmp_path):
    """首次补充 / 持续进展 / 结束后补充 与版本号、证据一致；v1 仍在。"""
    path = str(tmp_path / "c153.db")
    item = story("three-windows")
    item.advance(1200.0)
    item.append("人走进门内", window_id=1, fusion_version_id="v1",
                progress=_writer_progress("first_update", event_t_last=1200.0,
                                          evidence_t_min=1200.0,
                                          evidence_t_max=1200.0))
    item.advance(1300.0)
    item.append("人在门边停留", window_id=2, fusion_version_id="v2",
                progress=_writer_progress("continuing",
                                          prior_understanding_versions=1,
                                          event_t_last=1300.0))
    item.close()
    item.append("事后补充：人离开画面", window_id=3, fusion_version_id="v3",
                progress=_writer_progress("after_close",
                                          prior_understanding_versions=2))

    detail = WorkbenchState(path).event_fact_detail(item.event_id)
    assert [d["version"] for d in detail["descriptions"]] == [1, 2, 3, 4]
    v1 = detail["descriptions"][0]
    assert v1["source"] == "initial_observation"
    assert v1["text"] == "cam 画面中出现 person"
    assert v1["progress"] is None, "v1 没有阶段，也不得补一个假阶段"
    assert [_progress_of(detail, v)["phase"] for v in (2, 3, 4)] == [
        "first_update", "continuing", "after_close"]
    # 结束后追加的那一版：证据仍指向本次窗口，事件区间不被改写。
    assert _progress_of(detail, 4)["event_state_at_write"] == "closed"
    assert _progress_of(detail, 4)["event_t_end"] == 1300.0
    assert detail["state"] == "closed" and detail["t_end"] == 1300.0

    # 真实 HTTP 读取走同一条业务路径（进程内最小 Handler，零网络）。
    handler = _Handler(WorkbenchState(path), f"/api/v2/events/{item.event_id}")
    handler.do_GET()
    assert handler.status == 200
    body = handler.body_json()
    assert [d["progress"]["phase"] for d in body["descriptions"]
            if d["progress"]] == ["first_update", "continuing", "after_close"]
    assert body["descriptions"][0]["progress"] is None
    json.dumps(body, ensure_ascii=False)      # 响应必须可 JSON 序列化


class _Handler(WorkbenchHandler):
    """进程内最小 Handler 驱动（与既有 server 测试同口径，零网络）。"""

    def __init__(self, state, path):
        self.command = "GET"
        self.path = path
        self.requestline = f"GET {path} HTTP/1.1"
        self.request_version = "HTTP/1.1"
        self.client_address = ("127.0.0.1", 0)
        self.headers = {}
        self.rfile = io.BytesIO(b"")
        self.wfile = io.BytesIO()
        self.status = None
        self.response_headers = {}
        self._state = state

    @property
    def server(self):
        return SimpleNamespace(state=self._state)

    def log_message(self, *_args):
        return None

    def send_response(self, code, message=None):
        self.status = code

    def send_header(self, key, value):
        self.response_headers[key] = value

    def end_headers(self):
        pass

    def body_json(self):
        raw = self.wfile.getvalue()
        start = raw.find(b"{")
        return json.loads(raw[start:]) if start >= 0 else {}


# ------------------------------------------------ 4. 页面真实渲染（node DOM 桩）

_PAGE_HARNESS_JS = r'''
"use strict";
const fs = require("fs");
const pageScript = fs.readFileSync(process.argv[2], "utf8");
const fixtures = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));

function makeElement(tag) {
  const el = {
    tagName: String(tag || "div").toUpperCase(), children: [], parentNode: null,
    className: "", id: "", hidden: false, disabled: false, open: false,
    value: "", textContent: "", innerHTML: "", scrollTop: 0, scrollHeight: 100,
    clientHeight: 100, clientWidth: 600, naturalWidth: 640, naturalHeight: 360,
    src: "", href: "", target: "", alt: "", loading: "", title: "", colSpan: 1,
    type: "", options: [], style: {}, dataset: {}, _attributes: {},
    classList: { _set: new Set(), add() {}, remove() {}, contains() { return false; },
                 toggle() { return false; } },
    setAttribute(n, v) { this._attributes[String(n)] = String(v); },
    getAttribute(n) { const k = String(n);
      return Object.prototype.hasOwnProperty.call(this._attributes, k) ? this._attributes[k] : null; },
    removeAttribute(n) { delete this._attributes[String(n)]; },
    appendChild(c) { if (c) { c.parentNode = this; this.children.push(c); } return c; },
    append(...nodes) { nodes.forEach((c) => this.appendChild(c)); },
    prepend(c) { if (c) { c.parentNode = this; this.children.unshift(c); } },
    replaceChildren(...nodes) { this.children = [];
      nodes.forEach((c) => { if (c) { c.parentNode = this; this.children.push(c); } }); },
    removeChild(c) { const i = this.children.indexOf(c);
      if (i >= 0) { this.children.splice(i, 1); } return c; },
    remove() {}, insertBefore(n) { this.children.unshift(n); return n; },
    insertRow() { const r = makeElement("tr");
      r.insertCell = () => { const c = makeElement("td"); r.children.push(c); return c; };
      this.children.push(r); return r; },
    insertCell() { const c = makeElement("td"); this.children.push(c); return c; },
    addEventListener() {}, removeEventListener() {}, focus() {}, blur() {},
    scrollIntoView() {}, querySelector() { return null; }, querySelectorAll() { return []; },
    getBoundingClientRect() { return { top: 0, left: 0, width: 0, height: 0 }; },
    click() { if (typeof this.onclick === "function") { this.onclick({ target: this }); } },
  };
  return el;
}
function descendants(node, out) {
  out = out || [];
  (node.children || []).forEach((c) => { out.push(c); descendants(c, out); });
  return out;
}
function flatText(node) {
  return descendants(node).map((c) => c.textContent || "").join("|")
    + "|" + (node.textContent || "");
}
const byId = new Map();
function gid(id) {
  const key = String(id);
  if (!byId.has(key)) { const el = makeElement("div"); el.id = key; byId.set(key, el); }
  return byId.get(key);
}
function response(obj, status) {
  status = status || 200;
  return { ok: status >= 200 && status < 300, status: status,
           json: async () => obj, text: async () => JSON.stringify(obj) };
}
const storage = { getItem() { return null; }, setItem() {}, removeItem() {} };
globalThis.window = { addEventListener() {}, confirm: () => false,
                      location: { href: "http://127.0.0.1/" }, scrollBy() {} };
globalThis.location = globalThis.window.location;
globalThis.sessionStorage = storage;
globalThis.localStorage = storage;
globalThis.document = {
  getElementById: gid, createElement: (t) => makeElement(t),
  createTextNode: (t) => { const n = makeElement("#text"); n.textContent = t; return n; },
  querySelector: () => makeElement("div"), querySelectorAll: () => [],
  addEventListener() {}, body: makeElement("body"),
};
globalThis.setInterval = () => 0;
globalThis.clearInterval = () => {};
globalThis.setTimeout = () => 0;
globalThis.clearTimeout = () => {};
globalThis.alert = () => {};
globalThis.confirm = () => false;
globalThis.fetch = async function (url) {
  const u = String(url);
  if (u.indexOf("/api/v2/events/") === 0) {
    const key = decodeURIComponent(u.slice("/api/v2/events/".length));
    return response(fixtures.details[key] || {}, fixtures.details[key] ? 200 : 404);
  }
  if (u === "/api/v2/events") { return response({ events: fixtures.events }); }
  if (u.indexOf("/api/v2/notifications") === 0) { return response({ notifications: [], next_cursor: null }); }
  if (u === "/api/cameras") { return response({ cameras: [{ id: "camera-demo" }] }); }
  if (u.indexOf("/api/zones/") === 0) { return response({ grid: { rows: 4, cols: 6 }, zones: [], runtime: "active" }); }
  if (u.indexOf("/api/environment/") === 0) {
    return response({ baseline: { state: "baseline_required", reason: "no_pointer" }, baselines: [] });
  }
  if (u.indexOf("/api/health") === 0) { return response({ runtime: { cameras: [] } }); }
  if (u.indexOf("/api/review") === 0) { return response({ segments: [] }); }
  if (u.indexOf("/api/events") === 0) { return response({ events: [] }); }
  if (u.indexOf("/api/patterns") === 0) { return response({ patterns: [] }); }
  return response({});
};

let loadError = null;
try {
  eval(pageScript + "\n;globalThis.__c153={progressDisplay:(typeof progressDisplay!=='undefined'?progressDisplay:null),"
    + "progressNote:(typeof progressNote!=='undefined'?progressNote:null),"
    + "openEventDetail:(typeof openEventDetail!=='undefined'?openEventDetail:null)};");
} catch (exc) { loadError = String(exc && exc.stack ? exc.stack : exc); }
const api = globalThis.__c153 || {};
const notes = [];
if (loadError) { notes.push("页面脚本装载失败: " + loadError.slice(0, 800)); }

const STAGE_LABELS = ["首次补充", "持续进展", "结束后补充"];
function stageOf(head) {
  const parts = String(head || "").split(" · ");
  for (let i = 0; i < parts.length; i += 1) {
    if (STAGE_LABELS.indexOf(parts[i]) >= 0) { return parts[i]; }
    if (parts[i].indexOf("阶段未记录") === 0) { return parts[i]; }
  }
  return "";
}
function versionOf(head) {
  const found = String(head || "").match(/^v(\d+)/);
  return found ? Number(found[1]) : null;
}
function entries() {
  return descendants(gid("event-detail-body"))
    .filter((n) => String(n.className || "") === "desc-version")
    .map((box) => {
      const first = (box.children || []).filter(
        (c) => String(c.className || "") !== "subtle")[0] || makeElement("div");
      const head = first.textContent || "";
      return { version: versionOf(head), head: head, stage: stageOf(head),
               text: flatText(box) };
    });
}

const results = {
  page_loaded: loadError === null,
  entries_available: typeof api.progressDisplay === "function"
    && typeof api.progressNote === "function"
    && typeof api.openEventDetail === "function",
  detail_loaded: false, entry_count: 0, entries: [], labels: [],
  stage_mapping: false, v1_preserved: false, after_close_not_restart: false,
  missing_progress_explicit: false, no_fabricated_stage: false,
  prompt_forbidden: [], prompt_accuracy: [],
};
const FORBIDDEN = ["重新开始", "恢复事件", "事件重启", "重新开启"];
const ACCURACY = ["准确率", "正确率"];

(async function main() {
  try {
    if (typeof api.openEventDetail === "function") {
      await api.openEventDetail("camera-demo:r1:event:story");
      const list = entries();
      results.entry_count = list.length;
      results.entries = list.map((e) => ({ version: e.version, stage: e.stage }));
      results.labels = list.map((e) => e.stage);
      const byVersion = {};
      list.forEach((e) => { byVersion[e.version] = e; });
      const v1 = byVersion[1] || { head: "", text: "" };
      const v2 = byVersion[2] || { stage: "" };
      const v3 = byVersion[3] || { stage: "" };
      const v4 = byVersion[4] || { stage: "" };
      const v5 = byVersion[5] || { stage: "" };
      const v6 = byVersion[6] || { head: "", text: "", stage: "x" };
      results.detail_loaded = flatText(gid("event-detail-body")).indexOf("模型补充描述") >= 0;
      results.stage_mapping = v2.stage === "首次补充" && v3.stage === "持续进展"
        && v4.stage === "结束后补充" && v5.stage === "持续进展";
      results.v1_preserved = v1.head.indexOf("初始事实（系统记录）") >= 0
        && v1.text.indexOf("画面中出现 person") >= 0
        && v1.stage === "";
      results.after_close_not_restart = v4.stage === "结束后补充"
        && v4.text.indexOf("事后补充") >= 0
        && FORBIDDEN.every((w) => v4.text.indexOf(w) < 0 && v4.head.indexOf(w) < 0);
      results.missing_progress_explicit =
        v6.stage === "阶段未记录（不视为任何阶段）"
        && v6.text.indexOf("阶段未记录的补充") >= 0;
      // 未批准字段不得出现在任何一版的渲染文本里；有 progress 的版本必须有阶段。
      results.no_fabricated_stage = list.every((e) => e.text.indexOf("<script>") < 0)
        && list.filter((e) => e.version !== 1 && e.version !== 6)
          .every((e) => STAGE_LABELS.indexOf(e.stage) >= 0)
        && list.length === 6;
      const all = list.map((e) => e.text + "|" + e.head).join("\n");
      results.prompt_forbidden = FORBIDDEN.filter((w) => all.indexOf(w) >= 0);
      results.prompt_accuracy = ACCURACY.filter((w) => all.indexOf(w) >= 0);
      // 页面辅助函数的直接值域：缺 progress / 未知取值都不得变成某个阶段。
      results.note_unknown_phase = api.progressNote(
        { source: "vlm", progress: { phase: "resurrected", missing: ["phase"] } });
      results.note_missing_progress = api.progressNote(
        { source: "vlm", progress: null });
      results.note_v1 = api.progressNote({ source: "initial_observation", progress: null });
      results.note_after_close = api.progressNote(
        { source: "vlm", progress: { phase: "after_close" } });
    } else {
      notes.push("页面未定义 openEventDetail（无法驱动真实渲染）");
    }
  } catch (exc) {
    notes.push("驱动异常: " + String(exc && exc.stack ? exc.stack : exc).slice(0, 800));
  }
  results.ok = results.page_loaded && results.entries_available
    && results.detail_loaded && results.entry_count === 6
    && results.stage_mapping && results.v1_preserved
    && results.after_close_not_restart && results.missing_progress_explicit
    && results.no_fabricated_stage
    && results.prompt_forbidden.length === 0
    && results.prompt_accuracy.length === 0
    && results.note_unknown_phase === " · 阶段未记录（未知取值 resurrected）"
    && results.note_missing_progress === " · 阶段未记录（不视为任何阶段）"
    && results.note_v1 === ""
    && results.note_after_close === " · 结束后补充";
  process.stdout.write(JSON.stringify({ ok: results.ok, results: results,
                                        notes: notes }) + "\n");
  process.exit(results.ok ? 0 : 1);
})();
'''


def _page_progress(phase, **fields):
    """服务端表达（白名单折出后的 progress）：phase 合法 + missing 为空。"""
    body = dict(_writer_progress(phase), **fields)
    body["phase"] = phase
    body["missing"] = []
    return body


def _page_descriptions():
    """页面夹具：三种阶段 + 阶段缺失 + 未批准字段（顺序刻意非版本序）。"""
    return [
        {"version": 1, "source": "initial_observation",
         "text": "cam 画面中出现 person", "t_created": 1000.0,
         "uncertainty": "confirmed", "evidence_refs": [], "observed": None,
         "progress": None},
        {"version": 2, "source": "vlm", "text": "人走进门内", "t_created": 1200.0,
         "uncertainty": "high", "evidence_refs": [], "observed": None,
         "progress": _page_progress("first_update", window_id=1,
                                    fusion_version_id="v1")},
        {"version": 3, "source": "vlm", "text": "人在门边停留", "t_created": 1300.0,
         "uncertainty": "high", "evidence_refs": [], "observed": None,
         "progress": _page_progress("continuing", window_id=2,
                                    fusion_version_id="v2",
                                    prior_understanding_versions=1)},
        {"version": 4, "source": "vlm", "text": "事后补充：人离开画面",
         "t_created": 1400.0, "uncertainty": "high", "evidence_refs": [],
         "observed": None,
         "progress": _page_progress("after_close", window_id=3,
                                    fusion_version_id="v3",
                                    prior_understanding_versions=2)},
        # 服务端也没折出身份键 → progress 缺失：页面必须显示明确缺失，不猜阶段。
        {"version": 6, "source": "vlm", "text": "阶段未记录的补充", "t_created": 1600.0,
         "uncertainty": "high", "evidence_refs": [], "observed": None,
         "progress": None},
        # 未批准字段（若 server 透传了原始 payload，页面白名单也必须挡住）。
        {"version": 5, "source": "vlm", "text": "带未批准字段的补充", "t_created": 1500.0,
         "uncertainty": "high", "evidence_refs": [], "observed": None,
         "unapproved_field": "<script>alert(1)</script>", "items": [{"x": 1}],
         "progress": _page_progress("continuing", window_id=5,
                                    fusion_version_id="v5")},
    ]


def _run_page(tmp_path):
    node = shutil.which("node")
    assert node is not None, "node 不可用：本文件要求真实页面脚本行为验收"
    details = {"camera-demo:r1:event:story": {
        "event_id": "camera-demo:r1:event:story", "camera": "camera-demo",
        "state": "closed", "end_reason": "camera-stopped", "t_start": 1000.0,
        "cls": "person", "descriptions": _page_descriptions(),
        "notifications": [], "semantic": {"state": "published"},
        "best_frame": None}}
    fixture = tmp_path / "c153-fixtures.json"
    fixture.write_text(json.dumps({"events": [], "details": details},
                                  ensure_ascii=False), encoding="utf-8")
    page = tmp_path / "c153-page.js"
    page.write_text(re.findall(r"<script>(.*?)</script>", _INDEX_HTML, re.S)[-1],
                    encoding="utf-8")
    harness = tmp_path / "c153-page-harness.js"
    harness.write_text(_PAGE_HARNESS_JS, encoding="utf-8")
    proc = subprocess.run([node, str(harness), str(page), str(fixture)],
                          capture_output=True, text=True, timeout=180,
                          encoding="utf-8", errors="replace")
    assert proc.stdout.strip(), f"harness 无输出\nstderr: {proc.stderr[-1500:]}"
    return json.loads(proc.stdout)


def test_page_stage_mapping_v1_and_after_close_in_real_rendering(tmp_path):
    """真实页面脚本渲染：阶段文案、v1 保留、after_close 不是重新开始。"""
    data = _run_page(tmp_path)
    checks = data["results"]
    assert data["ok"] is True, f"页面阶段消费未通过：{checks} / {data['notes']}"
    stages = {entry["version"]: entry["stage"] for entry in checks["entries"]}
    assert stages[2] == "首次补充", stages
    assert stages[3] == "持续进展", stages
    assert stages[4] == "结束后补充", stages
    assert stages[5] == "持续进展", stages
    assert stages[1] == "", "v1 初始事实没有阶段，也不得补一个假阶段"
    assert stages[6] == "阶段未记录（不视为任何阶段）", stages
    assert set(checks["labels"]) == {"", "首次补充", "持续进展", "结束后补充",
                                     "阶段未记录（不视为任何阶段）"}
    assert checks["v1_preserved"] is True
    assert checks["after_close_not_restart"] is True
    assert checks["prompt_forbidden"] == [] and checks["prompt_accuracy"] == []


def test_page_stage_helpers_never_fabricate_a_stage(tmp_path):
    """辅助函数值域：未知取值/缺 progress/v1 都不得变成三种阶段之一。"""
    data = _run_page(tmp_path)
    checks = data["results"]
    assert data["ok"] is True, f"{checks} / {data['notes']}"
    assert checks["note_unknown_phase"] == " · 阶段未记录（未知取值 resurrected）"
    assert checks["note_missing_progress"] == " · 阶段未记录（不视为任何阶段）"
    assert checks["note_v1"] == ""
    assert checks["note_after_close"] == " · 结束后补充"


def test_page_declares_no_accuracy_claim_and_no_restart_wording():
    """版本序号只表示追加次序：页面代码不得出现准确率或"重新开始"类措辞。"""
    script = re.findall(r"<script>(.*?)</script>", _INDEX_HTML, re.S)[-1]
    code = _without_comments(script)
    for word in ("准确率", "正确率", "重新开始", "恢复事件", "事件重启"):
        assert word not in code, f"页面代码不得出现：{word}"
    mapping = re.search(r"const PROGRESS_STAGE_TEXT=\{(.+?)\};", code, re.S)
    assert mapping, "缺少阶段文案映射"
    body = mapping.group(1)
    assert [part.split(":")[0] for part in body.split(",")] == [
        "first_update", "continuing", "after_close"], "阶段文案只允许 B 车道的三种 phase"
    for label in ("首次补充", "持续进展", "结束后补充"):
        assert f"'{label}'" in body
    # 详情头与时间线摘要两处都要消费服务端 progress，而不是按版本序号推断。
    assert re.search(r"\+progressNote\(desc\)", code), "详情头未消费版本阶段"
    assert "latest.progress" in code, "时间线摘要未消费版本阶段"
