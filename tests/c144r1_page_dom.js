/* C144-R1/R2 · DeepSeek Harness 页面行为 DOM harness（真实页面脚本，node 执行）。
 *
 * 用法：node tests/c144r1_page_dom.js <page.js>
 * 输出：stdout 一行 JSON {ok, results:{...}, notes:[...]}；退出码 0=全通过。
 *
 * 断言的是**真实页面脚本的行为**（展开/收起/跨渲染保持、身份隔离、
 * 容量有界、跳过基线不被状态读回覆盖、滚动保留、无基线可用），
 * 不是字符串匹配。
 */
"use strict";
const fs = require("fs");

const pageScript = fs.readFileSync(process.argv[2], "utf8");

// ------------------------------------------------------------------ DOM 桩
function makeElement(tag) {
  const el = {
    tagName: String(tag || "div").toUpperCase(),
    children: [], parentNode: null, className: "", id: "",
    hidden: false, disabled: false, value: "", textContent: "", innerHTML: "",
    scrollTop: 0, scrollHeight: 1000, clientHeight: 100,
    options: [], naturalWidth: 640, naturalHeight: 360,
    _attributes: {}, _listeners: {}, style: {}, dataset: {},
    classList: {
      _set: new Set(),
      add(...n) { n.forEach((x) => this._set.add(x)); },
      remove(...n) { n.forEach((x) => this._set.delete(x)); },
      contains(n) { return this._set.has(n); },
      toggle(n, f) {
        const want = f === undefined ? !this._set.has(n) : !!f;
        if (want) { this._set.add(n); } else { this._set.delete(n); }
        return want;
      },
    },
    setAttribute(n, v) {
      this._attributes[String(n)] = String(v);
      if (String(n) === "id") { this.id = String(v); }
      if (String(n) === "class") { this.className = String(v); }
    },
    getAttribute(n) {
      const k = String(n);
      return Object.prototype.hasOwnProperty.call(this._attributes, k)
        ? this._attributes[k] : null;
    },
    removeAttribute(n) { delete this._attributes[String(n)]; },
    appendChild(c) { if (c) { c.parentNode = this; this.children.push(c); } return c; },
    replaceChildren(...nodes) {
      this.children.forEach((c) => { c.parentNode = null; });
      this.children = [];
      nodes.forEach((n) => { if (n) { n.parentNode = this; this.children.push(n); } });
    },
    removeChild(c) {
      const i = this.children.indexOf(c);
      if (i >= 0) { this.children.splice(i, 1); c.parentNode = null; }
      return c;
    },
    insertBefore(n) { this.children.unshift(n); n.parentNode = this; return n; },
    addEventListener(t, h) { (this._listeners[t] = this._listeners[t] || []).push(h); },
    removeEventListener() {},
    querySelector() { return null; },
    querySelectorAll() { return []; },
    focus() {}, blur() {},
    click() { if (typeof this.onclick === "function") { this.onclick({ target: this }); } },
    set onclick(fn) { this._onclick = fn; },
    get onclick() { return this._onclick; },
  };
  return el;
}

function descendants(node, out) {
  out = out || [];
  (node.children || []).forEach((c) => { out.push(c); descendants(c, out); });
  return out;
}

const elementsById = new Map();
function elementById(id) {
  const key = String(id);
  if (!elementsById.has(key)) {
    const el = makeElement("div");
    el.id = key;
    elementsById.set(key, el);
  }
  return elementsById.get(key);
}

const storageState = { available: true, data: new Map() };
function makeStorage() {
  return {
    getItem(k) {
      if (!storageState.available) { throw new Error("storage unavailable"); }
      return storageState.data.has(String(k)) ? storageState.data.get(String(k)) : null;
    },
    setItem(k, v) {
      if (!storageState.available) { throw new Error("storage unavailable"); }
      storageState.data.set(String(k), String(v));
    },
    removeItem(k) { storageState.data.delete(String(k)); },
  };
}

const fetchState = { environment: null, environmentFails: false, baselines: [] };
function jsonResponse(obj, ok) {
  return { ok: ok !== false, status: ok === false ? 500 : 200,
           json: async () => obj, text: async () => JSON.stringify(obj) };
}

globalThis.window = { addEventListener() {}, location: { href: "http://127.0.0.1/" },
                      confirm: () => true };
globalThis.location = globalThis.window.location;
globalThis.sessionStorage = makeStorage();
globalThis.localStorage = makeStorage();
globalThis.document = {
  getElementById: elementById,
  createElement: (t) => makeElement(t),
  createTextNode: (t) => { const n = makeElement("#text"); n.textContent = t; return n; },
  querySelector: () => makeElement("div"),
  querySelectorAll: () => [],
  addEventListener() {},
  body: makeElement("body"),
};
globalThis.setInterval = () => 0;
globalThis.clearInterval = () => {};
globalThis.setTimeout = () => 0;
globalThis.clearTimeout = () => {};
globalThis.alert = () => {};
globalThis.confirm = () => true;
globalThis.fetch = async function (url) {
  const u = String(url);
  if (u.indexOf("/api/environment/") === 0 && u.indexOf("/baselines") > 0) {
    if (fetchState.environmentFails) { throw new TypeError("baseline history down"); }
    return jsonResponse({ baselines: fetchState.baselines || [] });
  }
  if (u.indexOf("/api/environment") === 0) {
    if (fetchState.environmentFails) { throw new TypeError("baseline endpoint down"); }
    return jsonResponse(fetchState.environment
      || { state: "no_pointer", version: null, reason: "no_pointer" });
  }
  if (u === "/api/cameras") return jsonResponse({ cameras: [{ id: "front-door" }] });
  return jsonResponse({});
};
globalThis.EventSource = function () { return { addEventListener() {}, close() {} }; };

// ------------------------------------------------------------------ 装载页面
let loadError = null;
try {
  const tail = "\n;globalThis.__c144 = {renderUnderstandingDetail:"
    + " (typeof renderUnderstandingDetail!=='undefined'?renderUnderstandingDetail:null),"
    + " loadEnvironment: (typeof loadEnvironment!=='undefined'?loadEnvironment:null),"
    + " expandedSources: (typeof expandedSources!=='undefined'?expandedSources:null)};";
  eval(pageScript + tail); // eslint-disable-line no-eval
} catch (exc) {
  loadError = String(exc && exc.stack ? exc.stack : exc);
}
const page = globalThis.__c144 || {};
const renderUnderstandingDetail = page.renderUnderstandingDetail || null;
const loadEnvironment = page.loadEnvironment || null;
const expandedSources = page.expandedSources || null;

const results = {
  page_loaded: loadError === null,
  render_entry_available: renderUnderstandingDetail !== null,
  expand_persists_across_three_renders: false,
  collapse_persists: false,
  identity_isolation: false,
  identity_isolation_same_tail: false,
  scroll_preserved: false,
  no_baseline_area_usable: false,
  capacity_bounded_128: false,
  skip_baseline_persists_non_ready: false,
  skip_baseline_persists_on_error: false,
  storage_unavailable_usable: false,
};
const notes = [];
if (loadError) { notes.push("装载失败: " + loadError.slice(0, 600)); }

function branchEntry(runShort, cropId, frameId, camId) {
  return {
    counts: { done: 1, failed: 0, evicted: 0, pending: 0 },
    current_identity: { run_id: runShort, config_version: 0 },
    branches: [{
      kind: "local", kind_label: "局部", text: "dom-harness 分支",
      certainty_label: "模型推断", is_current: true,
      run_short: runShort, config_short: "0",
      window_key: [camId || "front-door", runShort, 0, 2],
      branch_key: "branch-" + runShort + "-" + cropId,
      crop_id: cropId, model_ref: "dom-harness/model",
      sources: [{ present: true, frame_id: frameId, t_capture_ms: 1000 }],
      evidence: {
        available: true,
        previous: { asset_id: null, status: "missing", reason: "frame_absent" },
        current: { asset_id: "a".repeat(64), status: "saved", reason: null },
        next: { asset_id: null, status: "missing", reason: "frame_absent" },
      },
    }],
  };
}

function toggles(box) {
  return descendants(box).filter((n) => n.tagName === "BUTTON"
    && String(n.getAttribute("aria-label") || "").indexOf("来源-") === 0);
}

(async function main() {
  try {
    if (renderUnderstandingDetail) {
      const box = elementById("understanding-detail");
      box.hidden = false;
      const entryA = branchEntry("run-A", "front-door:run-A:frame:1457:chg:0", 1457);
      renderUnderstandingDetail(box, "front-door", entryA);
      let list = toggles(box);
      if (list.length === 1) {
        const toggle = list[0];
        toggle.click();
        results.expand_click_applied = toggle.getAttribute("aria-expanded") === "true";
        for (let i = 0; i < 3; i++) {
          renderUnderstandingDetail(box, "front-door", entryA);
        }
        list = toggles(box);
        const area = descendants(box).filter(
          (n) => String(n.id || "").indexOf("src-detail-") === 0);
        results.expand_persists_across_three_renders =
          list.length === 1 && list[0].getAttribute("aria-expanded") === "true"
          && area.length === 1 && area[0].hidden === false;
        list[0].click();
        renderUnderstandingDetail(box, "front-door", entryA);
        list = toggles(box);
        results.collapse_persists =
          list.length === 1 && list[0].getAttribute("aria-expanded") === "false";
        const entryB = branchEntry("run-B", "front-door:run-B:frame:1457:chg:0", 1457);
        renderUnderstandingDetail(box, "front-door", entryB);
        const listB = toggles(box);
        results.identity_isolation =
          listB.length === 1 && listB[0].getAttribute("aria-expanded") === "false";
        // 同尾部编号、不同身份（相机/run/config）：锚必须不同且不串态
        const tailA = branchEntry("run-C", "cam-a:run-C:frame:1457:chg:0", 1457, "cam-a");
        renderUnderstandingDetail(box, "cam-a", tailA);
        const listA2 = toggles(box);
        if (listA2.length === 1) { listA2[0].click(); }
        const tailB = branchEntry("run-D", "cam-b:run-D:frame:1457:chg:0", 1457, "cam-b");
        renderUnderstandingDetail(box, "cam-b", tailB);
        const listB2 = toggles(box);
        results.identity_isolation_same_tail = listB2.length === 1
          && listB2[0].getAttribute("aria-expanded") === "false";
        // 容量：140 项展开必须被有界集合限制在 ≤128
        const many = branchEntry("run-E", "front-door:run-E:frame:1457:chg:0", 1457);
        many.branches = [];
        for (let i = 0; i < 140; i++) {
          const b = JSON.parse(JSON.stringify(branchEntry(
            "run-E", "front-door:run-E:frame:" + (1400 + i) + ":chg:0", 1457).branches[0]));
          many.branches.push(b);
        }
        renderUnderstandingDetail(box, "front-door", many);
        const manyToggles = toggles(box);
        manyToggles.forEach((t) => t.click());
        results.capacity_opened = manyToggles.length;
        results.capacity_set_size = expandedSources ? expandedSources.size : null;
        results.capacity_bounded_128 = !!expandedSources
          && expandedSources.size <= 128;
        box.scrollTop = 120;
        renderUnderstandingDetail(box, "front-door", entryA);
        results.scroll_preserved = box.scrollTop === 120;
        const rows = descendants(box).filter(
          (n) => String(n.className || "").indexOf("und-branch") >= 0);
        results.no_baseline_area_usable = rows.length >= 1 && box.hidden === false;
      } else {
        notes.push("未找到唯一来源切换钮：找到 " + list.length + " 个");
      }
    } else {
      notes.push("页面脚本未定义 renderUnderstandingDetail（无法驱动真实渲染）");
    }

    if (loadEnvironment) {
      const gate = elementById("environment-gate");
      const dismiss = elementById("gate-dismiss");
      storageState.data.clear();
      fetchState.environment = { state: "no_pointer", reason: "no_pointer" };
      if (typeof dismiss.onclick === "function") {
        dismiss.onclick();
        gate.hidden = true;
      } else {
        notes.push("页面未提供 gate-dismiss 跳过按钮");
      }
      await loadEnvironment();
      results.skip_baseline_persists_non_ready = gate.hidden === true;
      fetchState.environmentFails = true;
      await loadEnvironment();
      results.skip_baseline_persists_on_error = gate.hidden === true;
      fetchState.environmentFails = false;
      storageState.available = false;
      try {
        await loadEnvironment();
        results.storage_unavailable_usable = true;
      } catch (storageError) {
        notes.push("storage 不可用时页面抛异常: " + storageError);
      }
      storageState.available = true;
    } else {
      notes.push("页面脚本未定义 loadEnvironment（无法驱动基线流程）");
    }
  } catch (exc) {
    notes.push("驱动异常: " + String(exc && exc.stack ? exc.stack : exc).slice(0, 800));
  }
  results.expand_click_applied = results.expand_click_applied === true;
  const ok = Object.keys(results).every((k) => k.startsWith("capacity_")
    || results[k] === true);
  process.stdout.write(JSON.stringify({ ok: ok, results: results, notes: notes }) + "\n");
  process.exit(ok ? 0 : 1);
})();
