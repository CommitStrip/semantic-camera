/* ============================================================
   core.js - 反无人机监控 · 纯逻辑核心（零 DOM 依赖，可单测）
   ------------------------------------------------------------
   从 index.html 内联脚本抽取：配置 / 距离估算 / IoU / 目标跟踪 /
   帧差运动门控。浏览器端由 index.html 以 <script src> 先行加载
   （经典 script 顶层 const 跨 script 可见）；Node 端经文件尾部的
   module.exports 直接 require，供 node:test 单元测试使用。
   ============================================================ */
"use strict";

// ---------- 配置(与 Python 管线对齐) ----------
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
  droneSizeM: 0.35,        // 兜底目标实际尺寸(米, Mavic级)
  // 距离估算按类别取目标实际尺寸（粗估口径：尺寸假设直接决定绝对距离）
  sizeByClass: { drone: 0.35, bird: 0.20 },
};

// ---------- 几何：距离估算(针孔模型) ----------
function estimateDist(bboxHpx, frameHpx, cls){
  // D = (f * H_obj * frameH) / (h_px * sensorH)
  // 注意：数字变焦只是 canvas 中心裁剪，检测始终在全帧上进行，
  // 目标在全帧中的像素高度不随 zoom 变化——故这里不能除以 zoom
  const sizeM = (cls && CFG.sizeByClass[cls]) || CFG.droneSizeM;
  const normalized = bboxHpx / frameHpx;          // 占画面高度比例
  const apparent = normalized * CFG.sensorHM;      // 像平面高度(米)
  if(apparent<=0) return null;
  return (CFG.focalMeters * sizeM) / apparent;
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
        t.box=d.bbox.slice(); t.cx=d.cx; t.cy=d.cy; t.cls=d.cls;
        t.last=now; t.count++;
        active.add(best);
        if(t.count>=CFG.confirmCount) t.confirmed=true;
        d.trackId=best; d.dup=t.count;
      }else{
        const id=this.nextId++;
        this.tracks.set(id,{id,box:d.bbox.slice(),cx:d.cx,cy:d.cy,vx:0,vy:0,
          cls:d.cls,last:now,count:1,confirmed:false});
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

// ---------- 场所模式包（语义摄像头核心抽象，详见 docs/semantic-camera-design.md） ----------
// 模式包 = 纯数据 + 校验器：换场所不改流水线代码，只换检测模型/判别头/规则。
// 首包 airfield（净空防黑飞）即前身反无人机能力的模式化收编。
// schema：id/name/detector/discriminators.main{classes,probe,alertConf}/alertCls/
//         schedule[{from,to}](布防时间表,可跨零点,缺省7×24)/arb/selfTrain
const MODE_PACKS = {
  airfield: {
    id: 'airfield',
    name: '净空防黑飞',
    detector: './yolov8s-drone.onnx',
    discriminators: {
      main: {
        classes: ['bird', 'drone'],   // [负类, 正类]；探针 logreg 输出 P(正类)
        probe: './jepa_probe_init.json',
        alertConf: 0.80,              // 胜出侧置信 ≥ 此值才允许机器下结论
      },
    },
    alertCls: 'drone',
    arb: { budgetPerHour: 20, ttlMs: 15000 },  // 慢脑仲裁预算 + 按轨迹去重窗
    selfTrain: { minConf: 0.90, marginRatio: 0.80, cooldownMs: 60000, lr: 0.05 },
  },
};

function getModePack(name) {
  return MODE_PACKS[name || 'airfield'] || MODE_PACKS.airfield;
}

// ---------- 模式包校验（fail-closed：坏配置拒绝布防，不带病上线） ----------
// 返回错误串数组；空数组 = 通过。与安全告警的 fail-open 相对：
// 配置与模型装载必须 fail-closed（设计文档 §9 两条红线不混用）。
function validatePack(pack) {
  if (!pack || typeof pack !== 'object') return ['模式包缺失'];
  const errs = [];
  if (!pack.id || !pack.name) errs.push('缺少 id/name');
  if (!pack.detector || typeof pack.detector !== 'string') errs.push('缺少 detector 模型路径');
  const task = pack.discriminators && pack.discriminators.main;
  if (!task) {
    errs.push('缺少 discriminators.main');
  } else {
    if (!Array.isArray(task.classes) || task.classes.length !== 2 ||
        task.classes.some(c => typeof c !== 'string' || !c)) errs.push('判别类别必须为二类');
    if (!task.probe || typeof task.probe !== 'string') errs.push('缺少 probe 探针路径');
    if (typeof task.alertConf !== 'number' || !(task.alertConf > 0.5) || !(task.alertConf < 1))
      errs.push('alertConf 必须在 (0.5,1)');
    if (pack.alertCls && Array.isArray(task.classes) && !task.classes.includes(pack.alertCls))
      errs.push('alertCls 不在判别类别中');
  }
  if (!pack.arb || !(pack.arb.budgetPerHour > 0) || !(pack.arb.ttlMs > 0))
    errs.push('arb 预算/去重窗非法');
  const st = pack.selfTrain;
  const floor = task && typeof task.alertConf === 'number' ? task.alertConf : 0.5;
  if (!st || !(st.minConf > floor) || !(st.marginRatio > 0 && st.marginRatio <= 1) ||
      !(st.cooldownMs > 0) || !(st.lr > 0))
    errs.push('selfTrain 闸门非法或未严于告警闸门');
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

// ---------- 判别裁决策略：四态全自动，流水线无人工判定环节 ----------
// score: 探针输出的 P(正类)。目标侧置信不足宁可弃权（escalate 待仲裁）也不虚报；
// 非目标侧一律 clear/suppress，不告警。
class JepaPolicy {
  constructor(pack) {
    this.task = pack.discriminators.main;
    this.alertCls = pack.alertCls;
  }
  decide(score) {
    const neg = this.task.classes[0], pos = this.task.classes[1];
    const isPos = score >= 0.5;
    const label = isPos ? pos : neg;
    const conf = isPos ? score : 1 - score;
    if (label === this.alertCls) {
      if (conf >= this.task.alertConf) return { action: 'alert', label, conf };
      return { action: 'escalate', label, conf };   // 灰区：弃权待仲裁，不虚报
    }
    return conf >= this.task.alertConf
      ? { action: 'clear', label, conf }
      : { action: 'suppress', label, conf };
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
// 兼容旧版探针字段（proto_bird/proto_drone 等）→ 归一化形态；classes[i] 给出第 i 类类名
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

// ---------- Node 单测入口（浏览器端 module 未定义，此块不执行） ----------
if (typeof module!=='undefined' && module.exports) {
  module.exports = { CFG, estimateDist, iou, Tracker, MotionGate,
    MODE_PACKS, getModePack, validatePack, isArmed, JepaPolicy, ArbitrationQueue,
    logregScore, protoDist, weightedAvg, probeLearn, shouldSelfTrain, normalizeProbe };
}
