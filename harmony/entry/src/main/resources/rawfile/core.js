/* ============================================================
   core.js - 语义摄像头 · 纯逻辑核心（零 DOM 依赖，可单测）
   ------------------------------------------------------------
   本文件是领域无关的通用运行时：配置 / 几何 / 跟踪 / 门控 /
   模式包校验 / 布防时间表 / 四态裁决 / 仲裁队列 / 探针学习数学 /
   mock 检测器 / 证据事件。领域词（类别、模型、阈值）只允许出现
   在模式包数据（web/mode-packs.js）中，并有源码洁净度单测把守。
   浏览器端由 index.html 以 <script src> 先行加载；Node 端经
   module.exports 供 node:test 单元测试使用。
   ============================================================ */
"use strict";

// ---------- 运行时配置（领域无关） ----------
const CFG = {
  motionThresh: 25,        // 帧差阈值
  minAreaRatio: 0.003,     // 运动面积门槛(占门控网格)：~15px@96×54，抑制传感器噪声/AE 抖动
  confirmCount: 2,         // 多帧确认次数
  matchMaxDist: 0.35,      // 跟踪匹配的最大中心距(归一化坐标；超过即视为新目标)
  motionDetInterval: 400,  // 快系统检出运动时，慢系统检测的最小间隔(ms)
  patrolInterval: 5000,    // 无运动时巡检间隔(ms)
  reconfirmInterval: 30000,// 已确认目标的重复告警间隔(ms)
  maxAge: 2000,            // 未确认目标老化(ms)：瞬态噪声快速消亡
  confirmedMaxAge: 12000,  // 已确认目标老化(ms)：必须 > 巡检间隔——悬停目标无帧差运动，
                           // 靠巡检续命，若老化窗 < 巡检间隔，确认计数会被反复清零（悬停必丢）
  iouThresh: 0.1,
  focalMeters: 4.4e-3,     // 手机等效焦距(米)
  sensorHM: 3.6e-3,        // 传感器高度(米)
};

// ---------- 几何：距离估算(针孔模型，目标实际尺寸由模式包给出) ----------
function estimateDist(bboxHpx, frameHpx, sizeM){
  // D = (f * H_obj * frameH) / (h_px * sensorH)
  // 注意：数字变焦只是 canvas 中心裁剪，检测始终在全帧上进行，
  // 目标在全帧中的像素高度不随 zoom 变化——故这里不能除以 zoom
  const normalized = bboxHpx / frameHpx;          // 占画面高度比例
  const apparent = normalized * CFG.sensorHM;      // 像平面高度(米)
  if(apparent<=0 || !(sizeM>0)) return null;
  return (CFG.focalMeters * sizeM) / apparent;
}
// 模式包查尺寸：按类取 sizeByClass，缺类回退 defaultSizeM
function sizeForClass(pack, cls){
  const d = pack && pack.detector;
  if(!d) return 0;
  return (d.sizeByClass && d.sizeByClass[cls]) || d.defaultSizeM || 0;
}

// ---------- IoU（框格式统一为 [x,y,w,h] 归一化数组） ----------
function iou(a,b){
  const x1=Math.max(a[0],b[0]),y1=Math.max(a[1],b[1]);
  const x2=Math.min(a[0]+a[2],b[0]+b[2]),y2=Math.min(a[1]+a[3],b[1]+b[3]);
  const iw=Math.max(0,x2-x1),ih=Math.max(0,y2-y1);
  if(iw<=0||ih<=0) return 0;
  const inter=iw*ih, ua=a[2]*a[3]+b[2]*b[3]-inter;
  return ua>0?inter/ua:0;
}

// ---------- 目标跟踪器(IoU+中心距离, 恒速预测, 分级老化) ----------
class Tracker{
  constructor(){ this.tracks=new Map(); this.nextId=1; }
  update(dets,now){
    const active=new Set();
    for(const d of dets){
      let best=null,bestScore=1e9;
      for(const [id,t] of this.tracks){
        if(active.has(id)) continue;
        // 恒速预测：两次检测间隔 0.4~5s，快速目标直接比对新位置必然错配
        const dt=(now-t.last)/1000;
        const px=t.cx+(t.vx||0)*dt, py=t.cy+(t.vy||0)*dt;
        const shiftX=px-t.cx, shiftY=py-t.cy;
        const pred=[t.box[0]+shiftX,t.box[1]+shiftY,t.box[2],t.box[3]];
        const dist=Math.hypot(px-d.cx,py-d.cy);
        const i=iou(pred,d.bbox);
        const score=dist - i*200;   // IoU 优先,中心距离兜底
        if(score<bestScore){bestScore=score;best=id;}
      }
      // 匹配闸门：中心距超 matchMaxDist（归一化）即视为新目标——
      // 否则任意两个检出永远互相匹配（坐标是 0-1，而阈值若是像素口径形同虚设）
      if(best!==null && bestScore<CFG.matchMaxDist){
        const t=this.tracks.get(best);
        const dt=(now-t.last)/1000;
        if(dt>0.01){
          const vx=(d.cx-t.cx)/dt, vy=(d.cy-t.cy)/dt;
          t.vx=(t.vx||0)*0.6+vx*0.4; t.vy=(t.vy||0)*0.6+vy*0.4;  // 速度一阶平滑
        }
        t.box=d.bbox.slice(); t.cx=d.cx; t.cy=d.cy; t.cls=d.cls; t.conf=d.conf;
        t.last=now; t.count++;
        active.add(best);
        if(t.count>=CFG.confirmCount) t.confirmed=true;
        d.trackId=best; d.dup=t.count;
      }else{
        const id=this.nextId++;
        this.tracks.set(id,{id,box:d.bbox.slice(),cx:d.cx,cy:d.cy,vx:0,vy:0,
          cls:d.cls,conf:d.conf,last:now,count:1,confirmed:false});
        active.add(id); d.trackId=id; d.dup=1;
      }
    }
    // 分级老化：未确认噪声快速消亡；已确认目标给更长存活窗
    for(const [id,t] of this.tracks){
      const ttl = t.confirmed ? CFG.confirmedMaxAge : CFG.maxAge;
      if(now-t.last>ttl) this.tracks.delete(id);
    }
    return [...this.tracks.values()].filter(t=>active.has(t.id));
  }
  getConfirmed(){ return [...this.tracks.values()].filter(t=>t.confirmed); }
}

// ---------- 帧差运动门控(快系统)：逐帧廉价运行，有运动才升级慢系统检测 ----------
class MotionGate{
  constructor(){ this.prev=null; this.lastRatio=0; }
  // gray: 扁平灰度数组；返回降采样坐标系运动框，无运动返回 []
  // lastRatio: 本帧运动像素占比（供遥测采集，做离线阈值校准）
  detect(gray,gw,gh){
    this.lastRatio=0;
    if(this.prev===null || this.prev.length!==gray.length){
      this.prev=gray;   // gray 每帧新建，可直接持有
      return [];
    }
    let cnt=0,minX=gw,maxX=0,minY=gh,maxY=0;
    for(let i=0;i<gray.length;i++){
      if(Math.abs(gray[i]-this.prev[i])>CFG.motionThresh){
        cnt++;
        const x=i%gw, y=(i/gw)|0;
        if(x<minX)minX=x; if(x>maxX)maxX=x; if(y<minY)minY=y; if(y>maxY)maxY=y;
      }
    }
    this.prev=gray;
    this.lastRatio=cnt/gw/gh;
    if(!cnt || this.lastRatio<=CFG.minAreaRatio) return [];
    return [{x:minX,y:minY,w:maxX-minX,h:maxY-minY}];
  }
}

// ---------- 模式包校验（fail-closed：坏配置拒绝布防，不带病上线） ----------
// 返回错误串数组；空数组 = 通过。与安全告警的 fail-open 相对：
// 配置与模型装载必须 fail-closed（设计文档 §9 两条红线不混用）。
function validatePack(pack) {
  if (!pack || typeof pack !== 'object') return ['模式包缺失'];
  const errs = [];
  if (!pack.id || !pack.name) errs.push('缺少 id/name');
  if (typeof pack.version !== 'number' || pack.version < 1) errs.push('缺少 version');
  const det = pack.detector;
  if (!det || typeof det !== 'object') errs.push('缺少 detector');
  else {
    if (det.engine !== 'onnx' && det.engine !== 'mock') errs.push('detector.engine 必须为 onnx|mock');
    if (det.engine === 'onnx') {
      if (!det.model || typeof det.model !== 'string')
        errs.push('onnx 检测器必须给出 model 路径');
      if (!det.head || !HEAD_DECODERS[det.head])
        errs.push('detector.head 必须为注册解码器之一：' + Object.keys(HEAD_DECODERS).join('/'));
      if (det.head === 'nanodethead') {
        if (!Array.isArray(det.strides) || det.strides.length < 2 ||
            det.strides.some(s => !(s > 0))) errs.push('nanodethead 需要 strides 数组');
        if (!(det.inputSize > 0)) errs.push('nanodethead 需要 inputSize');
        if (!(det.regBins >= 2)) errs.push('nanodethead 需要 regBins≥2');
      }
    }
    if (det.keepIndices !== undefined &&
        (!Array.isArray(det.keepIndices) || det.keepIndices.some(k => !(k >= 0))))
      errs.push('keepIndices 必须为非负索引数组');
    if (!Array.isArray(det.classes) || det.classes.length === 0 ||
        det.classes.some(c => typeof c !== 'string' || !c)) errs.push('detector.classes 非法');
    if (typeof det.confThresh !== 'number' || !(det.confThresh > 0) || !(det.confThresh < 1))
      errs.push('detector.confThresh 必须在 (0,1)');
    if (!(det.defaultSizeM > 0)) errs.push('detector.defaultSizeM 必须为正数');
    if (det.mockScript !== undefined && !Array.isArray(det.mockScript))
      errs.push('mockScript 必须为时间线数组');
  }
  if (pack.zones !== undefined) {
    const ok = Array.isArray(pack.zones) && pack.zones.length > 0 && pack.zones.every(z =>
      z && typeof z.id === 'string' && z.id &&
      Array.isArray(z.polygon) && z.polygon.length >= 3 &&
      z.polygon.every(p => Array.isArray(p) && p.length === 2 &&
        typeof p[0] === 'number' && p[0] >= 0 && p[0] <= 1 &&
        typeof p[1] === 'number' && p[1] >= 0 && p[1] <= 1) &&
      (z.classes === undefined || (Array.isArray(z.classes) &&
        z.classes.every(c => typeof c === 'string'))) &&
      (z.dwellMs === undefined || (typeof z.dwellMs === 'number' && z.dwellMs >= 0)));
    if (!ok) errs.push('zones 必须为 {id, polygon[[x,y]≥3点(0..1)], classes?, dwellMs?} 数组');
  }
  if (typeof pack.detectorAlertConf !== 'number' ||
      !(pack.detectorAlertConf > 0) || !(pack.detectorAlertConf < 1))
    errs.push('detectorAlertConf 必须在 (0,1)');
  const disc = pack.discriminator;
  if (disc !== null && disc !== undefined) {
    if (typeof disc !== 'object') errs.push('discriminator 非法');
    else {
      if (!Array.isArray(disc.classes) || disc.classes.length !== 2 ||
          disc.classes.some(c => typeof c !== 'string' || !c)) errs.push('判别类别必须为二类');
      if (!disc.probe || typeof disc.probe !== 'string') errs.push('缺少 probe 探针路径');
      if (typeof disc.alertConf !== 'number' || !(disc.alertConf > 0.5) || !(disc.alertConf < 1))
        errs.push('discriminator.alertConf 必须在 (0.5,1)');
    }
  }
  if (det && Array.isArray(det.classes)) {
    if (!pack.alertCls || !det.classes.includes(pack.alertCls))
      errs.push('alertCls 必须在检测类别中');
    if (disc && typeof disc === 'object' && Array.isArray(disc.classes) &&
        !disc.classes.includes(pack.alertCls))
      errs.push('有判别器时 alertCls 必须可被判别器分辨');
  }
  if (!pack.arb || !(pack.arb.budgetPerHour > 0) || !(pack.arb.ttlMs > 0))
    errs.push('arb 预算/去重窗非法');
  const floor = disc && typeof disc === 'object' && typeof disc.alertConf === 'number'
    ? disc.alertConf : 0.5;
  const st = pack.selfTrain;
  if (st !== null && st !== undefined) {
    if (typeof st !== 'object' ||
        (st.enabled !== undefined && typeof st.enabled !== 'boolean') ||
        !(st.minConf > floor) ||
        !(st.marginRatio > 0 && st.marginRatio <= 1) || !(st.cooldownMs > 0) || !(st.lr > 0))
      errs.push('selfTrain 闸门非法或未严于判别告警闸门');
  } else if (disc && typeof disc === 'object' && st === undefined) {
    errs.push('有判别器时必须显式声明 selfTrain（null 禁用，或 {enabled:false,…} 关闭）');
  }
  if (pack.schedule !== undefined) {
    const ok = Array.isArray(pack.schedule) && pack.schedule.length > 0 && pack.schedule.every(w =>
      w && typeof w.from === 'string' && typeof w.to === 'string' &&
      /^([01]\d|2[0-3]):[0-5]\d$/.test(w.from) && /^([01]\d|2[0-3]):[0-5]\d$/.test(w.to));
    if (!ok) errs.push('schedule 必须为 {from,to} "HH:MM" 窗口数组');
  }
  return errs;
}

// ---------- 布防时间表（场所语义：非布防时段告警降级为记录、仲裁不占预算） ----------
// schedule 缺省 = 7×24 布防；from>to 视为跨零点窗口；零长度窗视为全天。
function isArmed(pack, date) {
  if (!pack.schedule || !pack.schedule.length) return true;
  const d = date || new Date();
  const mins = d.getHours() * 60 + d.getMinutes();
  for (const w of pack.schedule) {
    const [fh, fm] = w.from.split(':').map(Number);
    const [th, tm] = w.to.split(':').map(Number);
    const from = fh * 60 + fm, to = th * 60 + tm;
    if (from === to) return true;
    if (from < to ? (mins >= from && mins < to) : (mins >= from || mins < to)) return true;
  }
  return false;
}

// ---------- 四态裁决策略：全自动，流水线无人工判定环节 ----------
// 两条路径：判别路径（有判别头，输入 P(判别正类)）与检测器权威路径
// （无判别头或判别未出，输入检测类别+置信）。目标侧置信不足宁可
// 弃权（escalate 待仲裁）也不虚报；非目标侧一律 clear/suppress。
class JepaPolicy {
  constructor(pack) {
    this.disc = (pack.discriminator && typeof pack.discriminator === 'object')
      ? pack.discriminator : null;
    this.alertCls = pack.alertCls;
    this.detectorAlertConf = pack.detectorAlertConf;
  }
  // 判别路径。score: P(disc.classes[1])
  decideDiscriminated(score) {
    if (!this.disc) return this.decideDetector(this.alertCls, score);
    const neg = this.disc.classes[0], pos = this.disc.classes[1];
    const isPos = score >= 0.5;
    const label = isPos ? pos : neg;
    const conf = isPos ? score : 1 - score;
    return this._fourState(label, conf, 'discriminator');
  }
  // 检测器权威路径（无判别头 / 判别未出——防漏报）
  decideDetector(cls, conf) {
    return this._fourState(cls, conf, 'detector');
  }
  _fourState(label, conf, via) {
    if (label === this.alertCls) {
      const gate = via === 'detector' ? this.detectorAlertConf : this.disc.alertConf;
      if (conf >= gate) return { action: 'alert', label, conf, via };
      return { action: 'escalate', label, conf, via };   // 灰区：弃权待仲裁，不虚报
    }
    return conf >= (via === 'detector' ? this.detectorAlertConf : this.disc.alertConf)
      ? { action: 'clear', label, conf, via }
      : { action: 'suppress', label, conf, via };
  }
}

// ---------- 慢脑仲裁队列：预算硬上限 + 按轨迹 TTL 去重（触发式/单飞合并语义） ----------
class ArbitrationQueue {
  constructor(opts) { this.budget = opts.budgetPerHour; this.ttl = opts.ttlMs; this.items = []; }
  // 返回 'accepted' | 'dup'（同轨迹窗口内已申请）| 'budget'（小时窗预算用尽）
  request(trackId, now) {
    this.items = this.items.filter(e => now - e.at < 3600000);   // 预算按小时窗滚动
    if (this.items.some(e => e.trackId === trackId && now - e.at < this.ttl)) return 'dup';
    if (this.items.length >= this.budget) return 'budget';
    this.items.push({ trackId, at: now });
    return 'accepted';
  }
}

// ---------- 探针在线学习的纯数学（自动自训练与仲裁回灌共用，Node 可单测） ----------
// 探针统一为归一化形态 {logreg_w, logreg_b, protos:[负类质心, 正类质心], ns:[负类样本数, 正类样本数]}
function logregScore(probe, feat) {   // P(正类)
  let s = probe.logreg_b;
  for (let i = 0; i < feat.length; i++) s += probe.logreg_w[i] * feat[i];
  return 1 / (1 + Math.exp(-s));
}
function protoDist(probe, feat) {     // [到负类质心距离, 到正类质心距离]
  let d0 = 0, d1 = 0;
  for (let i = 0; i < feat.length; i++) {
    const a = feat[i] - probe.protos[0][i], b = feat[i] - probe.protos[1][i];
    d0 += a * a; d1 += b * b;
  }
  return [Math.sqrt(d0), Math.sqrt(d1)];
}
function weightedAvg(oldV, feat, n) {
  return oldV.map((v, i) => (v * n + feat[i]) / (n + 1));
}
// label: 0=负类 1=正类。质心增量 + logreg 头单步 SGD（梯度下降）
function probeLearn(probe, feat, label, lr) {
  probe.protos[label] = weightedAvg(probe.protos[label], feat, probe.ns[label]);
  probe.ns[label]++;
  const err = logregScore(probe, feat) - label;   // err = p - y，沿负梯度更新
  for (let i = 0; i < feat.length; i++) probe.logreg_w[i] -= lr * err * feat[i];
  probe.logreg_b -= lr * err;
  return probe;
}
// 自训练门控：logreg 头与原型距离两个独立信号一致且足够确信，才允许自动更新
// 探针（防止"错误但自信"的判决被自我强化）。
function shouldSelfTrain(probe, feat, opts) {
  const s = logregScore(probe, feat);
  const conf = s >= 0.5 ? s : 1 - s;
  if (conf < opts.minConf) return false;
  const d = protoDist(probe, feat);
  const winner = s >= 0.5 ? d[1] : d[0], loser = s >= 0.5 ? d[0] : d[1];
  if (loser <= 0 || winner / loser > opts.marginRatio) return false;
  return true;
}
// 兼容旧版探针字段（类别命名质心）→ 归一化形态；classes[i] 给出第 i 类类名
function normalizeProbe(raw, classes) {
  if (raw.protos && raw.ns) {
    return { logreg_w: raw.logreg_w, logreg_b: raw.logreg_b,
             protos: raw.protos, ns: raw.ns };
  }
  const pick = i => {
    const m = raw['proto_' + classes[i]], n = raw['n_' + classes[i]];
    if (!m) throw new Error('探针缺少类 ' + classes[i] + ' 的原型字段');
    return { m, n: n || 0 };
  };
  const a = pick(0), b = pick(1);
  return { logreg_w: raw.logreg_w, logreg_b: raw.logreg_b,
           protos: [a.m, b.m], ns: [a.n, b.n] };
}
// 学习状态按模式包隔离（场所 A 的伪标签不得污染场所 B），键含 pack.id
function probeStorageKey(packId) { return 'jepa_probe_v2:' + packId; }

// ---------- mock 检测器：确定性时间线脚本（测试/无模型演示用） ----------
// pack.detector.mockScript: [{fromMs, everyMs?, count?, untilMs?,
//   det:{cls, conf, bbox:[x,y,w,h] 归一化}}]
// predict(canvas, nowMs) 返回该时刻所有生效检出（bbox 已换算为画布像素），
// 不读画布像素，Node 端可传 {width,height} 假画布——保证 CI 确定性。
class MockDetector {
  constructor(pack) {
    this.engine = 'mock';
    this.classes = pack.detector.classes;
    this.script = pack.detector.mockScript || [];
    this.loaded = true; this.loading = false;
  }
  async load() { return true; }
  predict(_canvas, nowMs) {
    const now = (nowMs === undefined) ? performance.now() : nowMs;
    const cw = _canvas.width || 1, ch = _canvas.height || 1;
    const dets = [];
    for (const seg of this.script) {
      if (now < (seg.fromMs || 0)) continue;
      if (seg.untilMs !== undefined && now >= seg.untilMs) continue;
      const period = seg.everyMs || 1e9;
      const elapsed = now - (seg.fromMs || 0);
      if (elapsed % period > 50) continue;    // 触发后 50ms 窗口内有效（确定性）
      const fired = Math.floor(elapsed / period);
      if (seg.count !== undefined && fired >= seg.count) continue;
      const d = seg.det;
      dets.push({ cls: d.cls, conf: d.conf,
        bbox: [Math.round(d.bbox[0] * cw), Math.round(d.bbox[1] * ch),
               Math.round(d.bbox[2] * cw), Math.round(d.bbox[3] * ch)] });
    }
    return Promise.resolve(dets);
  }
}

// ---------- 检测头解码器注册表（DetectorProvider 契约的解码侧） ----------
// 解码器输出网络输入像素尺度的 {mcls(模型类索引), conf, x1,y1,x2,y2}，
// NMS 与到源图坐标的逆 letterbox 由调用方处理——核心不含领域类别词。
const HEAD_DECODERS = { yolo8head: null, nanodethead: null };   // 注册表键（先声明后填充）

// 共享 NMS（xyxy 框，按 conf 降序贪心抑制）
function boxIoU(a, b) {
  const x1 = Math.max(a.x1, b.x1), y1 = Math.max(a.y1, b.y1);
  const x2 = Math.min(a.x2, b.x2), y2 = Math.min(a.y2, b.y2);
  const iw = Math.max(0, x2 - x1), ih = Math.max(0, y2 - y1);
  const inter = iw * ih;
  const ua = (a.x2 - a.x1) * (a.y2 - a.y1) + (b.x2 - b.x1) * (b.y2 - b.y1) - inter;
  return ua > 0 ? inter / ua : 0;
}
function nms(dets, iouThresh) {
  const sorted = [...dets].sort((a, b) => b.conf - a.conf);
  const keep = [];
  for (const d of sorted) {
    let ok = true;
    for (const k of keep) if (boxIoU(d, k) > iouThresh) { ok = false; break; }
    if (ok) keep.push(d);
  }
  return keep;
}

// v8 系导出头：输出 [1, 4+nc, N]（CHW）或 [1, N, 4+nc]，无 objectness
function decodeV8Head(data, dims, opts) {
  const conf = opts.conf, keep = opts.keepIndices;
  let nc;
  const CHW = dims[1] < dims[2];
  if (CHW) nc = dims[1] - 4; else nc = dims[2] - 4;
  const N = Math.max(dims[1], dims[2]);
  const dets = [];
  for (let c = 0; c < N; c++) {
    let cx, cy, bw, bh;
    if (CHW) { cx = data[0 * N + c]; cy = data[1 * N + c]; bw = data[2 * N + c]; bh = data[3 * N + c]; }
    else { cx = data[c * dims[2] + 0]; cy = data[c * dims[2] + 1]; bw = data[c * dims[2] + 2]; bh = data[c * dims[2] + 3]; }
    let bi = -1, bs = -1;
    for (let k = 0; k < nc; k++) {
      if (keep && !keep.includes(k)) continue;
      const sc = CHW ? data[(4 + k) * N + c] : data[c * dims[2] + 4 + k];
      if (sc > bs) { bs = sc; bi = k; }
    }
    if (bi < 0 || bs < conf) continue;
    dets.push({ mcls: bi, conf: bs, x1: cx - bw / 2, y1: cy - bh / 2, x2: cx + bw / 2, y2: cy + bh / 2 });
  }
  return dets;
}

// NanoDet(GFL) 导出头：输出 [1, N, nc + 4*(bins)]，cls 已在图内 sigmoid，
// reg 为 bins-bin 分布 logits（softmax → 投影 0..bins-1 → ltrb 距离 × 步长）
const _anchorCache = new Map();
function nanoAnchors(inputSize, strides) {
  const key = inputSize + ':' + strides.join(',');
  if (_anchorCache.has(key)) return _anchorCache.get(key);
  const pts = [], strd = [];
  for (const s of strides) {
    const hs = Math.ceil(inputSize / s);
    for (let r = 0; r < hs; r++)
      for (let c = 0; c < hs; c++) {
        pts.push([(c + 0.5) * s, (r + 0.5) * s]);
        strd.push(s);
      }
  }
  const a = { pts, strd };
  _anchorCache.set(key, a);
  return a;
}
function decodeNanoDetHead(data, dims, opts) {
  const N = dims[1], cols = dims[2];
  const nc = opts.numClasses, bins = opts.regBins;
  const keep = opts.keepIndices;
  const { pts, strd } = nanoAnchors(opts.inputSize, opts.strides);
  const proj = []; for (let b = 0; b < bins; b++) proj.push(b);
  const dets = [];
  for (let i = 0; i < N; i++) {
    const base = i * cols;
    let bi = -1, bs = -1;
    for (let k = 0; k < nc; k++) {
      if (keep && !keep.includes(k)) continue;
      const sc = data[base + k];               // 图内已 sigmoid
      if (sc > bs) { bs = sc; bi = k; }
    }
    if (bi < 0 || bs < opts.conf) continue;
    const d = new Array(4);
    for (let g = 0; g < 4; g++) {
      let mx = -Infinity;
      const raw = new Array(bins);
      for (let b = 0; b < bins; b++) {
        const v = data[base + nc + g * bins + b];
        raw[b] = v; if (v > mx) mx = v;
      }
      let se = 0;
      for (let b = 0; b < bins; b++) { raw[b] = Math.exp(raw[b] - mx); se += raw[b]; }
      let dot = 0;
      for (let b = 0; b < bins; b++) dot += (raw[b] / se) * proj[b];
      d[g] = dot * strd[i];                    // [l, t, r, b] × 步长
    }
    dets.push({ mcls: bi, conf: bs,
      x1: pts[i][0] - d[0], y1: pts[i][1] - d[1],
      x2: pts[i][0] + d[2], y2: pts[i][1] + d[3] });
  }
  return dets;
}
HEAD_DECODERS.yolo8head = decodeV8Head;
HEAD_DECODERS.nanodethead = decodeNanoDetHead;

// ---------- 区域引擎（场所时空语义，详见设计文档 §6） ----------
// 射线法：多边形内 true；顶点/边界的归属由扫描奇偶自然处理，不单独特判
function pointInPolygon(px, py, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const xi = poly[i][0], yi = poly[i][1], xj = poly[j][0], yj = poly[j][1];
    if (((yi > py) !== (yj > py)) && (px < (xj - xi) * (py - yi) / (yj - yi) + xi))
      inside = !inside;
  }
  return inside;
}
// 轨迹进出与滞留计时：centers/ polygon 均为归一化坐标；出区重置计时
class ZoneEngine {
  constructor(zones) { this.zones = zones || []; }
  update(track, now) {
    const hit = this.zones.find(z =>
      (!z.classes || z.classes.includes(track.cls)) &&
      pointInPolygon(track.cx, track.cy, z.polygon));
    if (hit) {
      if (track.zoneId !== hit.id || track.zoneEnterAt === undefined) {
        track.zoneId = hit.id; track.zoneEnterAt = now;
      }
      return { zoneId: hit.id, dwellMs: now - track.zoneEnterAt };
    }
    if (track.zoneId !== undefined) { track.zoneId = undefined; track.zoneEnterAt = undefined; }
    return null;
  }
}
// 区域门控（纯函数）：有 zones 时，alert 须"在区内滞留达标"，区外降级为 record；
// 非 alert 裁决与无 zones 模式原样透传
function applyZonePolicy(dec, zoneHit, zones) {
  if (!zones || !zones.length || dec.action !== 'alert') return dec;
  const z = zones.find(z => zoneHit && z.id === zoneHit.zoneId);
  const need = z && z.dwellMs ? z.dwellMs : 0;
  if (!zoneHit || zoneHit.dwellMs < need)
    return Object.assign({}, dec, { action: 'record', reason: 'outside-zone' });
  return Object.assign({}, dec, { reason: 'zone-intrusion' });
}


// ---------- 证据事件（机器可消费的版本化事件，从"帧"到"有证据的事件"） ----------
const EVIDENCE_SCHEMA = 'sc.evidence/v1';
const POLICY_VERSION = 'four-state/2';

// 稳定序列化（键排序）+ 稳定哈希（FNV-1a，非加密）：用于配置指纹与变更检测，
// 明确不用于防篡改（防篡改哈希见 sha256Hex 与 M5 模型清单）
function stableStringify(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(x => stableStringify(x)).join(',') + ']';
  const keys = Object.keys(v).filter(k => v[k] !== undefined).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + stableStringify(v[k])).join(',') + '}';
}
function stableHash(v) {
  const s = stableStringify(v);
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;          // FNV-1a 32bit，uint 乘法
  }
  return 'fnv1a:' + h.toString(16).padStart(8, '0');
}
// 内容 sha256（十六进制）。crypto.subtle 在 Node 20/22 与现代浏览器均可用；
// 用于模型文件与证据内容的防篡改指纹（文件名不是版本，哈希才是）
async function sha256Hex(bytes) {
  const buf = (bytes instanceof Uint8Array) ? bytes
    : (bytes instanceof ArrayBuffer) ? new Uint8Array(bytes) : bytes;
  const d = await globalThis.crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// o: {kind, timeIso, sourceTs, cameraId, eventId, nowMs,
//     mode, modeVersion, modeHash,
//     trackId, cls, clsConf, bbox, dist,
//     belief:{label,conf,score,probeVersion}|null,      // 判别器置信——独立于检测置信
//     decision:{action, via:'discriminator'|'detector', armed, reason},
//     models:{detector:{engine,name,sha256}, discriminator, probeState},
//     evidence:{videoTs, frame, cropJpeg?, cropSha256?}}
function buildEvidenceEvent(o) {
  const action = o.decision && o.decision.action;
  const ms = o.nowMs === undefined ? Date.now() : o.nowMs;
  return {
    schema: EVIDENCE_SCHEMA,
    // 稳定事件 ID：去重/重放/外部告警幂等的关键（camera:mode:kind:track:毫秒）
    event_id: o.eventId || ((o.cameraId || 'cam') + ':' + o.mode + ':' +
      (o.kind || 'record') + ':' + (o.trackId === undefined ? '-' : o.trackId) + ':' + ms),
    kind: o.kind || 'record',                       // 'alert'|'arbitration'|'record'|'disarm'
    // 双时间戳：source=视频源时间（RTSP 抖动/延迟分析），processed=本地处理完成时间
    time: { source: o.sourceTs === undefined ? null : o.sourceTs, processed: o.timeIso || null },
    camera: o.cameraId || null,
    mode: { id: o.mode, version: o.modeVersion === undefined ? null : o.modeVersion,
            hash: o.modeHash || null },             // mode_hash：证明当时生效的配置快照指纹
    policy_version: POLICY_VERSION,                 // 模型没变、裁决逻辑也可能变——独立版本
    track: { id: o.trackId, cls: o.cls, conf: o.clsConf, bbox: o.bbox || null, dist: o.dist || null },
    belief: o.belief || null,
    decision: o.decision,
    models: o.models || {},
    evidence: o.evidence || null,                   // 证据内容应带 sha256（防替换）
    action_recommended: action === 'alert' ? 'notify' : (action === 'escalate' ? 'review' : 'record'),
  };
}

// ---------- vus 桥客户端链路（纯逻辑：状态机/指数退避/请求关联/超时；传输注入以便单测） ----------
// 语义：state offline→connecting→open；离线请求入队（上限保护），open 后按序发出；
// 案件-裁决按 requestId 关联；超时/断线/拥塞分别以 bridge-timeout/bridge-offline/bridge-busy 拒绝，
// 上层据此降级为边缘自治（灰区弃权语义不变，绝不虚报）。
class BridgeLink {
  constructor(opts) {
    this.url = opts.url || '';
    this.token = opts.token || '';
    this.timeoutMs = opts.timeoutMs || 30000;
    this.maxInFlight = opts.maxInFlight || 2;
    this.backoffBase = opts.backoffBase || 1000;
    this.backoffMax = opts.backoffMax || 30000;
    this.maxQueue = opts.maxQueue || 8;
    this.transportFactory = opts.transportFactory || null; // (url, handlers) => {send, close}
    this.onVerdict = opts.onVerdict || null;               // (verdict) — 关联 promise 之外的旁路通知
    this.onState = opts.onState || null;                   // ('offline'|'connecting'|'open')
    this.state = 'offline';
    this.inFlight = new Map();                              // requestId → {resolve, reject, timer}
    this.queue = [];
    this.attempt = 0;
    this.conn = null;
    this.reconnectTimer = null;
  }
  _setState(s) { this.state = s; if (this.onState) this.onState(s); }
  connect() {
    if (!this.url || !this.transportFactory || this.state !== 'offline' || this.reconnectTimer) return;
    this._setState('connecting');
    this.conn = this.transportFactory(this.url, {
      onOpen: () => {
        this.attempt = 0;
        this._send({ type: 'hello', token: this.token });
        this._setState('open');
        const q = this.queue; this.queue = [];
        for (const p of q) this.request(p.payload).then(p.resolve, p.reject);
      },
      onMessage: (txt) => this._onMessage(txt),
      onClose: () => this._onDown(),
      onError: () => {},
    });
  }
  _send(obj) { this.conn.send(JSON.stringify(obj)); }
  request(payload) {
    if (!this.url) return Promise.reject(new Error('bridge-not-configured'));
    if (this.state !== 'open') {
      this.connect();
      return new Promise((resolve, reject) => {
        if (this.queue.length >= this.maxQueue) {
          const dropped = this.queue.shift();
          dropped.reject(new Error('bridge-queue-overflow'));
        }
        this.queue.push({ payload, resolve, reject });
      });
    }
    if (this.inFlight.size >= this.maxInFlight) return Promise.reject(new Error('bridge-busy'));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.inFlight.delete(payload.requestId);
        reject(new Error('bridge-timeout'));
      }, this.timeoutMs);
      this.inFlight.set(payload.requestId, { resolve, reject, timer });
      try { this._send(payload); }
      catch (e) { clearTimeout(timer); this.inFlight.delete(payload.requestId); reject(e); }
    });
  }
  _onMessage(txt) {
    let m;
    try { m = JSON.parse(txt); } catch (e) { return; }
    if (m.type === 'arb-verdict' && m.requestId && this.inFlight.has(m.requestId)) {
      const e = this.inFlight.get(m.requestId);
      clearTimeout(e.timer);
      this.inFlight.delete(m.requestId);
      e.resolve(m);
      if (this.onVerdict) this.onVerdict(m);
    }
  }
  _onDown() {
    this._setState('offline');
    this.conn = null;
    for (const [, e] of this.inFlight) { clearTimeout(e.timer); e.reject(new Error('bridge-offline')); }
    this.inFlight.clear();
    const delay = Math.min(this.backoffBase * Math.pow(2, this.attempt++), this.backoffMax);
    this.reconnectTimer = setTimeout(() => { this.reconnectTimer = null; this.connect(); }, delay);
  }
  close() {
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
    for (const [, e] of this.inFlight) { clearTimeout(e.timer); e.reject(new Error('bridge-offline')); }
    this.inFlight.clear();
    if (this.conn) { try { this.conn.close(); } catch (e) {} }
    this._setState('offline');
  }
}

// ---------- 场景自识别（场所层开放集，设计文档 §9） ----------
// 边缘场景状态机的纯逻辑部分：
//   applySceneGate —— 未识别/观察态下告警全抑制（检测/跟踪/证据照常，什么都不丢）
//   selectPackFromVerdict —— 慢脑裁决 → 选包收口（高置信自动布防，低置信仅建议）
const SCENE_AUTO_ARM_CONF = 0.85;   // 自动布防闸门；低于此值仅列为候选待人工选择
function applySceneGate(dec, sceneArmed) {
  if (sceneArmed || dec.action !== 'alert') return dec;
  return Object.assign({}, dec, { action: 'record', reason: 'scene-unidentified' });
}
// verdict: {packId, conf}（慢脑 scene-verdict）；catalog: [{id,...}]
// 返回 {packId, source:'auto'|'suggest'} | null（未知包=裁决无效）
function selectPackFromVerdict(verdict, catalog, autoArmConf) {
  if (!verdict || !verdict.packId) return null;
  const hit = (catalog || []).find(p => p.id === verdict.packId);
  if (!hit) return null;
  const conf = typeof verdict.conf === 'number' ? verdict.conf : 0;
  const autoArmConf_ = autoArmConf === undefined ? SCENE_AUTO_ARM_CONF : autoArmConf;
  return { packId: verdict.packId,
           source: conf >= autoArmConf_ ? 'auto' : 'suggest', conf };
}

// ---------- Node 单测入口（浏览器端 module 未定义，此块不执行） ----------
if (typeof module!=='undefined' && module.exports) {
  module.exports = { CFG, estimateDist, sizeForClass, iou, Tracker, MotionGate,
    validatePack, isArmed, JepaPolicy, ArbitrationQueue,
    logregScore, protoDist, weightedAvg, probeLearn, shouldSelfTrain, normalizeProbe,
    probeStorageKey, MockDetector, EVIDENCE_SCHEMA, POLICY_VERSION,
    stableStringify, stableHash, sha256Hex, buildEvidenceEvent,
    HEAD_DECODERS, decodeV8Head, decodeNanoDetHead, boxIoU, nms,
    pointInPolygon, ZoneEngine, applyZonePolicy, BridgeLink,
    SCENE_AUTO_ARM_CONF, applySceneGate, selectPackFromVerdict };
}
