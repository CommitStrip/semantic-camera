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
        // 有界轨迹历史（越线/方向/滞留等时空规则的输入；环形截断防膨胀）
        t.hist = t.hist || [{ x: t.cx, y: t.cy, t: t.last }];
        t.hist.push({ x: t.cx, y: t.cy, t: now });
        if (t.hist.length > 32) t.hist.shift();
        active.add(best);
        if(t.count>=CFG.confirmCount) t.confirmed=true;
        d.trackId=best; d.dup=t.count;
      }else{
        const id=this.nextId++;
        this.tracks.set(id,{id,box:d.bbox.slice(),cx:d.cx,cy:d.cy,vx:0,vy:0,
          cls:d.cls,conf:d.conf,last:now,count:1,confirmed:false,bornAt:now,
          hist:[{x:d.cx,y:d.cy,t:now}]});
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
  constructor(){ this.prev=null; this.lastRatio=0;
    this.threshScale=1; this.minAreaScale=1; }
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
      if(Math.abs(gray[i]-this.prev[i])>CFG.motionThresh*this.threshScale){
        cnt++;
        const x=i%gw, y=(i/gw)|0;
        if(x<minX)minX=x; if(x>maxX)maxX=x; if(y<minY)minY=y; if(y>maxY)maxY=y;
      }
    }
    this.prev=gray;
    this.lastRatio=cnt/gw/gh;
    if(!cnt || this.lastRatio<=CFG.minAreaRatio*this.minAreaScale) return [];
    return [{x:minX,y:minY,w:maxX-minX,h:maxY-minY}];
  }
  // 软重置（成像模态切换窗专用）：以当前帧为新背景基准，抑制切换瞬间的
  // 整帧帧差爆炸——重置而非清零（vus 慢系统漂移修复的同族经验）
  resetBackground(gray){ if(gray) this.prev=gray; this.lastRatio=0; }
}

// ---------- 成像模态状态机（ImagingModality，ICR 感知，设计文档 core-loop-v3 §6） ----------
// 监控相机 IR-CUT 滤光片切换使整帧彩色↔黑白（红外）帧级跳变、一夜可振荡多次。
// 多信号 2of3 表决 + N=3 帧候选确认 + 90s 最小驻留 + 10min 滑动窗振荡检测；
// 切换即换参数剖面（错误剖面下每帧都在劣化，等不得）；转换窗内学习冻结。
// 本类为纯逻辑：帧统计（sat/noise/luma）由调用方逐采样提供，硬件日夜事件走
// feedHardwareEvent 优先于图像推断。原生黑白相机声明后常驻 NIGHT-BW 不参与切换。
const MODALITY_PROFILES = {
  // 保守缺省剖面（详析分模态标定后由环境模型覆盖，env_hash 溯源）
  'DAY-COLOR':   { confScale: 1.00, minAreaScale: 1.00, gateThreshScale: 1.00 },
  'NIGHT-BW':    { confScale: 0.85, minAreaScale: 1.40, gateThreshScale: 1.15 },
  'NIGHT-LIT':   { confScale: 0.95, minAreaScale: 1.10, gateThreshScale: 1.05 },
  'OSCILLATION': { confScale: 0.80, minAreaScale: 1.50, gateThreshScale: 1.20 },
};
const ICR_TRANSITION_WINDOW_MS = 1500;   // 切换前后标记窗（学习冻结/告警降级）

function icrVote(prev, cur, th) {
  // 2of3 表决：返回 'night' | 'day' | null（prev/cur: {sat, noise, luma}）
  if (!prev || !cur) return null;
  const night = [], day = [];
  if (prev.sat > 0 && cur.sat < prev.sat * (1 - th.satDrop)) night.push('sat');
  if (prev.sat > 0 && cur.sat > prev.sat * (1 + th.satRise)) day.push('sat');
  if (cur.noise > prev.noise * th.noiseRise) night.push('noise');
  if (cur.noise > 0 && cur.noise < prev.noise * th.noiseFall) day.push('noise');
  if (cur.luma < prev.luma * (1 - th.lumaDrop)) night.push('luma');
  if (cur.luma > prev.luma * (1 + th.lumaRise)) day.push('luma');
  if (night.length >= 2) return 'night';
  if (day.length >= 2) return 'day';
  return null;
}

class ImagingModality {
  constructor(opts) {
    opts = opts || {};
    this.nativeBW = !!opts.nativeBW;                 // 原生黑白相机声明
    this.confirmFrames = opts.confirmFrames || 3;    // N=3 帧候选确认
    this.settleFrames = opts.settleFrames || 3;      // TRANSITION 稳定确认采样
    this.minDwellMs = opts.minDwellMs || 90000;      // 90s 最小驻留
    this.oscWindowMs = opts.oscWindowMs || 600000;   // 10min 滑动窗
    this.oscMaxSwitches = opts.oscMaxSwitches || 3;  // 窗内 ≥3 次切换 → 振荡态
    this.oscExitMs = opts.oscExitMs || 300000;       // 稳定 5min 退出振荡
    this.thresh = Object.assign({
      satDrop: 0.30, satRise: 0.30, satLit: 0.10,    // satLit: 夜间残余饱和度（→NIGHT-LIT）
      noiseRise: 1.5, noiseFall: 1 / 1.5,
      lumaDrop: 0.25, lumaRise: 0.25,
    }, opts.thresholds || {});
    this.state = this.nativeBW ? 'NIGHT-BW' : 'DAY-COLOR';
    this.profile = MODALITY_PROFILES[this.state];
    this.switches = [];            // [{at, from, to}] 持久化（重启恢复）
    this.lastSwitchAt = this.nativeBW ? 0 : -Infinity;
    this._cand = null; this._candCount = 0;
    this._settle = null; this._settleCount = 0;
    this._lastStats = null;
    this._anchor = null; this._prevStats = null;   // 稳定态参考（模态落定时重置）
  }
  // 硬件日夜事件（ONVIF/厂商回调）：直接换剖面 + 记切换，图像表决让位
  feedHardwareEvent(mode, now) {
    if (this.nativeBW || (mode !== 'day' && mode !== 'night')) return [];
    const ev = this._accept(mode === 'day' ? 'DAY-COLOR' : 'NIGHT-BW', now, 'hw');
    this._anchor = null;   // 新模态参考未知，下一采样播种
    return ev;
  }
  // 逐采样推进。stats: {sat,noise,luma}；返回本次产生的事件数组
  // [{type:'switch-begin'|'switch-done'|'oscillation-enter'|'oscillation-exit', ...}]
  feed(stats, now) {
    const ev = this._maybeExitOscillation(now);
    if (this.nativeBW) return ev;
    this._lastStats = stats;
    if (this.state === 'TRANSITION') {
      // 稳定确认：新模态特征持续 settleFrames 采样 → 落定到具体夜间变体/昼
      const vote = icrVote(this._transRef, stats, this.thresh);
      const still = this._transTo === 'night'
        ? (vote !== 'day') : (vote !== 'night');
      this._settleCount = still ? this._settleCount + 1 : 0;
      if (this._settleCount >= this.settleFrames) {
        const to = this._transTo === 'night'
          ? (stats.sat >= this.thresh.satLit ? 'NIGHT-LIT' : 'NIGHT-BW')
          : 'DAY-COLOR';
        ev.push(...this._accept(to, now, 'settle'));
        this._anchor = stats;   // 新模态参考 = 落定时刻统计
      }
      return ev;
    }
    if (this.state === 'OSCILLATION') { this._prevStats = stats; return ev; }  // 振荡态只等稳定计时
    // 稳定态：候选表决——与当前稳定态的参考（anchor）比对，而非相邻采样：
    // 阶跃变化后每个采样都持续投票，N 帧候选才可能确认；无票时参考以 α=0.05
    // 缓慢跟踪模态内漂移（天气等），防止参考陈旧引发假转移
    if (!this._anchor) { this._anchor = stats; return ev; }
    const vote = icrVote(this._anchor, stats, this.thresh);
    // 同族票忽略：DAY 态的 'day' 票 / NIGHT-BW 态的 'night' 票不构成转移
    // （NIGHT-LIT 的 'night' 票有意义=灯光熄灭滑向 NIGHT-BW），锚点照常 EMA 跟踪
    const sameFamily = (this.state === 'DAY-COLOR' && vote === 'day') ||
                       (this.state === 'NIGHT-BW' && vote === 'night');
    if (!vote || sameFamily) {
      const a = this._anchor, k = 0.05;
      this._anchor = { sat: a.sat + (stats.sat - a.sat) * k,
                       noise: a.noise + (stats.noise - a.noise) * k,
                       luma: a.luma + (stats.luma - a.luma) * k };
      this._cand = null; this._candCount = 0;
      return ev;
    }
    // 反向候选落在最小驻留内：参数跟物理事实走——立即换回并记 OSC。
    // backTo 不可用（同态/无历史）时不吞候选，落入常规计数
    if (now - this.lastSwitchAt < this.minDwellMs) {
      const last = this.switches[this.switches.length - 1];
      const backTo = last ? last.from : null;
      if (backTo && backTo !== this.state) {
        ev.push(...this._accept(backTo, now, 'dwell-reverse'));
        this._anchor = stats;
        this._cand = null; this._candCount = 0;
        return ev;
      }
    }
    if (this._cand === vote) this._candCount++; else { this._cand = vote; this._candCount = 1; }
    if (this._candCount >= this.confirmFrames) {
      this._cand = null; this._candCount = 0;
      this._transTo = vote; this._transRef = stats;
      this._settleCount = 0;
      const from = this.state;
      this.state = 'TRANSITION';
      this.profile = MODALITY_PROFILES[vote === 'night' ? 'NIGHT-BW' : 'DAY-COLOR'];
      ev.push({ type: 'switch-begin', from, to: vote, cause: 'image' });
    }
    return ev;
  }
  _stateBefore() { return this.switches.length ? this.switches[this.switches.length - 1].to : 'DAY-COLOR'; }
  _accept(toState, now, cause) {
    if (toState === this.state) return [];   // 同态空转移防御（不污染切换历史）
    const from = this.state === 'TRANSITION' ? this._stateBefore() : this.state;
    this.state = toState;
    this.profile = MODALITY_PROFILES[toState] || this.profile;
    this.lastSwitchAt = now;
    this.switches.push({ at: now, from, to: toState });
    if (this.switches.length > 64) this.switches.shift();   // 有界历史
    const out = [{ type: 'switch-done', from, to: toState, cause }];
    // 振荡检测：滑动窗内切换次数
    const recent = this.switches.filter(sw => now - sw.at <= this.oscWindowMs).length;
    if (recent >= this.oscMaxSwitches && this.state !== 'OSCILLATION') {
      this.state = 'OSCILLATION';
      this.profile = MODALITY_PROFILES['OSCILLATION'];
      out.push({ type: 'oscillation-enter', recent });
    }
    return out;
  }
  // OSCILLATION 退出：单模态稳定 oscExitMs 后回到该模态（简单化：由 feed 的
  // 无候选持续时长判定）
  _maybeExitOscillation(now) {
    if (this.state !== 'OSCILLATION') return [];
    if (now - this.lastSwitchAt < this.oscExitMs) return [];
    const back = this.switches.length ? this.switches[this.switches.length - 1].to : 'DAY-COLOR';
    if (back === 'OSCILLATION') return [];
    const from = this.state;
    this.state = back;
    this.profile = MODALITY_PROFILES[back] || this.profile;
    return [{ type: 'oscillation-exit', from, to: back }];
  }
  // 转换窗：切换前后 ±ICR_TRANSITION_WINDOW_MS
  isTransitionWindow(now) {
    if (this.state === 'TRANSITION') return true;
    return Math.abs(now - this.lastSwitchAt) <= ICR_TRANSITION_WINDOW_MS;
  }
  // 学习冻结：TRANSITION / 振荡态 / 转换窗内一切学习暂停
  learningFrozen(now) {
    if (this.nativeBW) return false;
    return this.state === 'TRANSITION' || this.state === 'OSCILLATION'
      || this.isTransitionWindow(now);
  }
  serialize() {
    return { state: this.state, switches: this.switches.slice(-16),
             lastSwitchAt: this.lastSwitchAt, nativeBW: this.nativeBW, anchor: this._anchor };
  }
  restore(obj) {
    if (!obj || !obj.state) return;
    this.state = obj.state;
    this.switches = obj.switches || [];
    this.lastSwitchAt = obj.lastSwitchAt || 0;
    this._anchor = obj.anchor || null;
    this.profile = MODALITY_PROFILES[this.state] || this.profile;
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
      (z.dwellMs === undefined || (typeof z.dwellMs === 'number' && z.dwellMs >= 0)) &&
      (z.countGte === undefined || (Number.isInteger(z.countGte) && z.countGte >= 1)));
    if (!ok) errs.push('zones 必须为 {id, polygon[[x,y]≥3点(0..1)], classes?, dwellMs?, countGte?} 数组');
  }
  if (pack.rules !== undefined) {
    const lines = pack.rules && pack.rules.lines;
    const bad = !Array.isArray(lines) || lines.some(l => !l || typeof l.id !== 'string' || !l.id ||
      !Array.isArray(l.a) || l.a.length !== 2 || !Array.isArray(l.b) || l.b.length !== 2 ||
      [l.a[0], l.a[1], l.b[0], l.b[1]].some(v => typeof v !== 'number' || v < 0 || v > 1) ||
      (l.dir !== undefined && !['any', 'AB', 'BA'].includes(l.dir)) ||
      (l.classes !== undefined && (!Array.isArray(l.classes) ||
        l.classes.some(c => typeof c !== 'string'))));
    if (bad) errs.push('rules.lines 必须为 {id, a[x,y], b[x,y](0..1), dir?:any|AB|BA, classes?} 数组');
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
  // 当前各 zone 占驻数（传入确认轨迹列表）——聚集/人群类规则的基础
  occupancy(tracks) {
    const counts = {};
    for (const t of tracks) {
      if (t.zoneId === undefined) continue;
      counts[t.zoneId] = (counts[t.zoneId] || 0) + 1;
    }
    return counts;
  }
}
// 区域门控（纯函数）：有 zones 时，alert 须"在区内滞留达标"，区外降级为 record；
// zone 可选 countGte（占驻数门槛）：人数不足降级为 record（聚集/人群类规则基础）；
// 非 alert 裁决与无 zones 模式原样透传
function applyZonePolicy(dec, zoneHit, zones, occupancy) {
  if (!zones || !zones.length || dec.action !== 'alert') return dec;
  const z = zones.find(z => zoneHit && z.id === zoneHit.zoneId);
  const need = z && z.dwellMs ? z.dwellMs : 0;
  if (!zoneHit || zoneHit.dwellMs < need)
    return Object.assign({}, dec, { action: 'record', reason: 'outside-zone' });
  if (z && z.countGte && occupancy !== undefined && occupancy < z.countGte)
    return Object.assign({}, dec, { action: 'record', reason: 'zone-count' });
  return Object.assign({}, dec, { reason: 'zone-intrusion' });
}


// 轨迹段与规则线段相交判定（退化共线不视为越线——端点触碰宁缺勿滥）
function segSide(a, b, p) {
  return (b[0] - a[0]) * (p[1] - a[1]) - (b[1] - a[1]) * (p[0] - a[0]);
}
function segIntersect(p1, p2, a, b) {
  const d1 = segSide(a, b, p1), d2 = segSide(a, b, p2);
  const d3 = segSide(p1, p2, a), d4 = segSide(p1, p2, b);
  return ((d1 > 0 && d2 < 0) || (d1 < 0 && d2 > 0)) &&
         ((d3 > 0 && d4 < 0) || (d3 < 0 && d4 > 0));
}
// ---------- 时空规则引擎：越线（带方向）与区域占驻计数 ----------
// rules.lines: [{id, a:[x,y], b:[x,y], dir:'any'|'AB'|'BA', classes?}]
// dir 语义：以 a→b 向量的左侧为 AB 侧（segSide>0），右侧为 BA 侧
class RuleEngine {
  constructor(rules) {
    this.lines = (rules && rules.lines) || [];
    this.lastCross = new Map();     // trackId:lineId → {dir, at}（同一轨迹不重复告警）
  }
  // 每检测周期调用；返回 Map(trackId → [{ruleId, type:'line-cross', dir}])
  evaluate(tracks, now, reconfirmMs) {
    const hits = new Map();
    const guard = reconfirmMs || 30000;
    for (const t of tracks) {
      const hist = t.hist || [];
      if (hist.length < 2) continue;
      for (const rule of this.lines) {
        if (rule.classes && !rule.classes.includes(t.cls)) continue;
        const key = t.id + ':' + rule.id;
        const last = this.lastCross.get(key);
        if (last && now - last.at < guard) continue;   // 同线冷却，防来回抖动刷告警
        for (let i = 1; i < hist.length; i++) {
          // 历史点是 {x,y,t} 对象——几何函数按数组下标取值，必须先转 [x,y]
          const p1 = [hist[i - 1].x, hist[i - 1].y], p2 = [hist[i].x, hist[i].y];
          if (!segIntersect(p1, p2, rule.a, rule.b)) continue;
          const dir = segSide(rule.a, rule.b, p2) > 0 ? 'AB' : 'BA';
          if (rule.dir !== 'any' && rule.dir !== dir) continue;
          this.lastCross.set(key, { dir, at: now });
          if (!hits.has(t.id)) hits.set(t.id, []);
          hits.get(t.id).push({ ruleId: rule.id, type: 'line-cross', dir });
          break;
        }
      }
    }
    return hits;
  }
}

// ---------- 证据帧环形缓冲（告警前因帧：事件发生前的低频帧序列） ----------
// 渲染 JPEG 属 DOM 操作，留在边缘层；本类只管节流、容量与取用。
class FrameRing {
  constructor(opts) {
    this.max = opts.max || 12;
    this.minIntervalMs = opts.minIntervalMs || 500;
    this.items = [];
    this._lastAt = -Infinity;
  }
  // frame: {jpeg, ts}（调用方渲染）；now: 毫秒时钟。返回是否实际入环。
  push(frame, now) {
    if (now - this._lastAt < this.minIntervalMs) return false;
    this._lastAt = now;
    this.items.push(frame);
    if (this.items.length > this.max) this.items.shift();
    return true;
  }
  peek() { return this.items.slice(); }   // 快照（引用共享，JPEG 字符串不可变）
  clear() { this.items.length = 0; }
}

// ---------- 事件分段（EventSegmenter，core-loop-v3 §3/Phase B） ----------
// 把持续流切成"事件时间段"：起于活动（确认轨迹或规则命中），止于静默
// （缺省 20s）或段上限（缺省 120s，忙碌场景防饿死命名管线）。
// 段是全局时间窗（聚合窗内全部轨迹），跨 ICR 模态切换不关段（记录模态列表）。
const SEGMENT_SCHEMA = 'sc.segment/v1';
const SEGMENT_SILENCE_MS = 20000;
const SEGMENT_MAX_MS = 120000;

function todBucket(date) {
  // 时段桶：晨/昼/暮/夜（本地时区）
  const h = date.getHours();
  if (h >= 5 && h < 11) return 'morning';
  if (h >= 11 && h < 17) return 'day';
  if (h >= 17 && h < 20) return 'evening';
  return 'night';
}
function durBucket(ms) {
  if (ms < 10000) return 's10';
  if (ms < 60000) return 's60';
  if (ms < 300000) return 's300';
  return 's300+';
}
function countBucket(n) {
  if (n <= 1) return 'c1';
  if (n <= 3) return 'c2-3';
  if (n <= 9) return 'c4-9';
  return 'c10+';
}
// 路径形状（粗粒度 v1）：越线→cross；区内长滞留→dwell；多区域→transit；否则 pass
function pathShapeOf(lines, zones, dwellMaxMs) {
  if (lines.length) return 'cross';
  if (zones.length && dwellMaxMs >= 10000) return 'dwell';
  if (zones.length >= 2) return 'transit';
  return 'pass';
}
// signature 结构分量（嵌入分量待 CLIP wasm 引擎接入后叠加，当前结构分量全权重）
function buildSignature(o) {
  // o: {classes, peakCount, zones, lines, modality, tod, durMs}
  return {
    cls: [...o.classes].sort(),
    count: countBucket(o.peakCount),
    zones: [...o.zones].sort(),
    lines: [...o.lines].sort(),
    shape: pathShapeOf(o.lines, o.zones, o.dwellMaxMs || 0),
    modality: o.modality,
    tod: o.tod,
    dur: durBucket(o.durMs || 0),
  };
}
// 加权 Jaccard 相似度（集合分量=|∩|/|∪|，空对空=1；标量分量=相等 1 否则 0）
function segmentSimilarity(a, b, w) {
  const W = Object.assign({ cls: 0.30, count: 0.10, zones: 0.20, lines: 0.10,
                            modality: 0.10, tod: 0.10, dur: 0.10 }, w);
  const jac = (x, y) => {
    const A = new Set(x), B = new Set(y);
    if (!A.size && !B.size) return 1;
    let inter = 0;
    for (const v of A) if (B.has(v)) inter++;
    const uni = A.size + B.size - inter;
    return uni ? inter / uni : 0;
  };
  const eq = (x, y) => (x === y ? 1 : 0);
  return W.cls * jac(a.cls, b.cls)
       + W.count * eq(a.count, b.count)
       + W.zones * jac(a.zones, b.zones)
       + W.lines * jac(a.lines, b.lines)
       + W.modality * eq(a.modality, b.modality)
       + W.tod * eq(a.tod, b.tod)
       + W.dur * eq(a.dur, b.dur);
}

class EventSegmenter {
  constructor(opts) {
    opts = opts || {};
    this.cameraId = opts.cameraId || 'cam';
    this.venueId = opts.venueId || null;
    this.silenceMs = opts.silenceMs || SEGMENT_SILENCE_MS;
    this.maxMs = opts.maxMs || SEGMENT_MAX_MS;
    this.modeHash = opts.modeHash || null;
    this.envHash = opts.envHash || null;
    this.seq = 1;
    this.active = null;
    this.records = [];        // 已关闭段（有界，供上层取用/入库）
  }
  setHashes(modeHash, envHash) { this.modeHash = modeHash; this.envHash = envHash; }
  _open(now, modality) {
    this.active = {
      id: this.cameraId + ':' + now,
      tStart: now, lastActivityAt: now, peakCount: 0,
      classes: new Set(), zones: new Set(), lines: new Set(),
      dwellMaxMs: 0, tracksSeen: 0,
      modalities: [modality], modality: modality,
      density: [],            // [{at, count}] 强制切分时选活动密度最低点
      keyframes: [],          // {t, kind} 首采/峰值/末采时间提示（捕获在边缘层）
    };
  }
  // 逐检测周期喂入。tracks: 确认轨迹快照（含 cls/zoneId/zoneDwellMs/bornAt）；
  // ruleHits: [{ruleId, trackId, dir}]；返回本次关闭的 SegmentRecord 数组
  feed(now, modality, tracks, ruleHits) {
    tracks = tracks || []; ruleHits = ruleHits || [];
    const activity = tracks.length > 0 || ruleHits.length > 0;
    const closed = [];
    if (!this.active) {
      if (activity) this._open(now, modality);
      else return closed;
    }
    const seg = this.active;
    if (activity) seg.lastActivityAt = now;
    // 聚合
    if (tracks.length > seg.peakCount) { seg.peakCount = tracks.length; seg.keyframes.push({ t: now, kind: 'peak' }); }
    for (const t of tracks) {
      seg.classes.add(t.cls);
      if (t.zoneId !== undefined) seg.zones.add(t.zoneId);
      if (t.zoneDwellMs > seg.dwellMaxMs) seg.dwellMaxMs = t.zoneDwellMs;
      seg.tracksSeen++;
    }
    for (const h of ruleHits) seg.lines.add(h.ruleId);
    if (!seg.modalities.includes(modality)) seg.modalities.push(modality);   // 跨 ICR 不关段
    seg.modality = seg.modalities[seg.modalities.length - 1];
    seg.density.push({ at: now, count: tracks.length });
    if (seg.density.length > 240) seg.density.shift();
    // 止段：静默或上限
    if (now - seg.lastActivityAt >= this.silenceMs) {
      closed.push(this._close(now, 'silence'));
    } else if (now - seg.tStart >= this.maxMs) {
      // 强制切分：名义止点取末 20s 内活动密度最低采样（下段从该点起算，活动不丢）
      const tail = seg.density.filter(d => d.at >= now - 20000);
      let splitAt = now, minC = Infinity;
      for (const d of tail) if (d.count < minC) { minC = d.count; splitAt = d.at; }
      closed.push(this._close(splitAt, 'max-duration', { forcedSplit: true, suggestedSplitAt: splitAt }));
      if (activity) this._open(splitAt, modality);   // 仍在活动：新段接续
    }
    return closed;
  }
  forceClose(now, reason) {
    if (!this.active) return [];
    return [this._close(now, reason || 'manual')];
  }
  _close(tEnd, reason, extra) {
    const seg = this.active;
    this.active = null;
    const classes = [...seg.classes], zones = [...seg.zones], lines = [...seg.lines];
    const durMs = tEnd - seg.tStart;
    const signature = buildSignature({
      classes, peakCount: seg.peakCount, zones, lines,
      modality: seg.modalities[seg.modalities.length - 1],
      tod: todBucket(new Date(tEnd)), durMs,
    });
    const rec = {
      schema: SEGMENT_SCHEMA,
      segment_id: this.cameraId + ':' + seg.tStart,
      camera_id: this.cameraId,
      venue_id: this.venueId,
      t_start: new Date(seg.tStart).toISOString(),
      t_end: new Date(tEnd).toISOString(),
      summary: { classes, peakCount: seg.peakCount,
                 zones, lines, dwellMaxMs: seg.dwellMaxMs,
                 tracksSeen: seg.tracksSeen, pathShape: signature.shape },
      signature, modalities: seg.modalities.slice(),
      mode_hash: this.modeHash, env_hash: this.envHash,
      keyframes: seg.keyframes.slice(-8),
      reason, forcedSplit: !!(extra && extra.forcedSplit),
      suggestedSplitAt: extra ? (extra.suggestedSplitAt || null) : null,
    };
    this.records.push(rec);
    if (this.records.length > 16) this.records.shift();
    return rec;
  }
}

// ---------- 命名管线纯逻辑（M2.7，core-loop-v3 §4：预算门控/修订链/降级命名） ----------
const SEGMENT_LABEL_SCHEMA = 'sc.segment-label/v1';

// 命名预算门控：滚动小时窗（缺省 30 次/时）+ 同签名去重（同类段只送一次 LLM）。
// 重要性（0 普通 / 1 新签名 / 2 规则命中）决定发送排序，由调用方使用。
class NamingGate {
  constructor(opts) {
    opts = opts || {};
    this.budgetPerHour = opts.budgetPerHour || 30;
    this.items = [];                       // {at, sigKey}
    this.sigSeen = new Map();              // sigKey → lastAt（窗内去重）
  }
  request(signature, now) {
    const sigKey = stableStringify(signature);
    this.items = this.items.filter(e => now - e.at < 3600000);
    const last = this.sigSeen.get(sigKey);
    if (last !== undefined && now - last < 3600000) return 'dup';   // 同签名窗内只送一次
    if (this.items.length >= this.budgetPerHour) return 'budget';
    this.items.push({ at: now, sigKey });
    this.sigSeen.set(sigKey, now);
    if (this.sigSeen.size > 256) {         // 有界去重表
      const oldest = [...this.sigSeen.entries()].sort((a, b) => a[1] - b[1])[0][0];
      this.sigSeen.delete(oldest);
    }
    return 'accepted';
  }
}

// 降级命名（签名模板占位名）：桥不可达/预算耗尽时事件流仍可读——
// 诚实标注 source:'template'，桥恢复后由 LLM 覆写为新 revision
function templateName(signature, summary) {
  const cls = (signature.cls && signature.cls.join('/')) || '目标';
  const parts = [cls + 'x' + (summary.peakCount || 1)];
  if (summary.zones && summary.zones.length) parts.push('进入 ' + summary.zones.join(','));
  if (summary.lines && summary.lines.length) parts.push('越线 ' + summary.lines.join(','));
  return parts.join(', ');
}

// sc.segment-label/v1 构建：一个段的命名修订记录（不可变，revision 递增）
function buildSegmentLabel(o) {
  // o: {segmentId, source:'llm'|'pattern'|'template'|'admin', name, conf,
  //     matchedBehaviors?, patternRef?, time?, rationale?}
  if (!o.segmentId) throw new Error('label 缺少 segmentId');
  return {
    schema: SEGMENT_LABEL_SCHEMA,
    segment_id: o.segmentId,
    revision: o.revision,
    source: o.source,
    name: o.name,
    conf: typeof o.conf === 'number' ? o.conf : null,
    matchedBehaviors: o.matchedBehaviors || [],
    pattern: o.patternRef || null,
    rationale: o.rationale || null,
    time: o.time || new Date().toISOString(),
  };
}

// 修订链：同段 label 不可变递增（迟到命名/覆写/改名 = 新 revision）。
// apply 显式 revision 冲突时拒绝（返回 null）；省略 revision 则自动 +1。
class LabelChain {
  constructor() { this.map = new Map(); }
  apply(label) {
    if (!label || !label.segment_id) return null;
    const cur = this.map.get(label.segment_id);
    const rev = cur ? cur.revision + 1 : (label.revision === undefined ? 1 : label.revision);
    if (label.revision !== undefined && label.revision !== rev) return null;   // 修订冲突
    const out = Object.assign({}, label, { revision: rev });
    this.map.set(label.segment_id, out);
    return out;
  }
  latest(segmentId) { return this.map.get(segmentId) || null; }
  get size() { return this.map.size; }
}

// ---------- 模式库（PatternLibrary，M3-e，core-loop-v3 §5：习惯化学习主轴） ----------
// 重复事件模式 → 自命名免 LLM。信任分层（v3.4）：model-verified 仅模型自洽
// （只可命名非安全输出），human-verified/deployment-approved 才可背书安全语义。
// 审计抽检 = 降低未经发现的漂移风险，不是"保证准确性"。
const PATTERN_VERIFY_N = 5;        // model-verified 需连续一致命名次数
const PATTERN_HUMAN_N = 3;         // human-verified 需代表性样本数
const PATTERN_AUDIT_RATE = 0.05;   // model-verified 命中的抽检概率

class PatternLibrary {
  constructor(opts) {
    opts = opts || {};
    this.simThreshold = opts.simThreshold !== undefined ? opts.simThreshold : 0.82;
    this.auditRate = opts.auditRate !== undefined ? opts.auditRate : PATTERN_AUDIT_RATE;
    this.verifyN = opts.verifyN || PATTERN_VERIFY_N;
    this.humanN = opts.humanN || PATTERN_HUMAN_N;
    this.maxPatterns = opts.maxPatterns || 500;
    this.random = opts.random || Math.random;    // 测试可注入确定性随机
    this.patterns = new Map();                   // id → pattern
    this.seq = 1;
  }
  // 匹配或建档：相似度 ≥阈值 → 命中；否则新建 draft
  matchOrRecord(signature) {
    let best = null, bestSim = 0;
    for (const p of this.patterns.values()) {
      const sim = segmentSimilarity(signature, p.signature);
      if (sim > bestSim) { bestSim = sim; best = p; }
    }
    if (best && bestSim >= this.simThreshold) return { pattern: best, sim: bestSim, hit: true };
    const p = {
      id: 'pat-' + Date.now().toString(36) + '-' + (this.seq++),
      signature: JSON.parse(JSON.stringify(signature)),
      name: null, count: 0, llmAgree: 0, humanSamples: 0,
      state: 'draft', version: 1, lastAudit: null,
      expectedWindow: { tod: [], modality: [] },   // 命中学到的时段/模态分布
      countHistory: [],                             // 峰值数历史（偏离检测）
    };
    this.patterns.set(p.id, p);
    this._prune();
    return { pattern: p, sim: bestSim, hit: false };
  }
  // 命中统计：先判偏离/窗口（历史与窗口不含本样本），再入档更新
  recordHit(pattern, meta) {
    pattern.count++;
    const deviation = this._deviation(pattern, meta.peakCount || 1);
    const outsideWindow = this._outsideWindow(pattern, meta);
    pattern.countHistory.push(meta.peakCount || 1);
    if (pattern.countHistory.length > 20) pattern.countHistory.shift();
    const ew = pattern.expectedWindow;
    if (!ew.tod.includes(meta.tod)) ew.tod.push(meta.tod);
    if (!ew.modality.includes(meta.modality)) ew.modality.push(meta.modality);
    return { deviation, outsideWindow };
  }
  _deviation(pattern, peakCount) {
    const h = pattern.countHistory;
    if (h.length < 5) return false;                // 样本不足不判偏离
    const sorted = [...h].sort((a, b) => a - b);
    const p5 = sorted[Math.floor(sorted.length * 0.05)];
    const p95 = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))];
    return peakCount < p5 || peakCount > p95;
  }
  _outsideWindow(pattern, meta) {
    if (pattern.count < 5) return false;           // 历史不足不判（窗口未成形）
    const ew = pattern.expectedWindow;
    return !ew.tod.includes(meta.tod) || !ew.modality.includes(meta.modality);
  }
  // LLM 命名结果回写：draft 阶段累计一致次数；一致达 verifyN → model-verified。
  // inconsistent（审计抽检不一致）→ 降级回 draft：保留 count，version+1。
  recordLlmName(patternId, name, consistent) {
    const p = this.patterns.get(patternId);
    if (!p) return null;
    if (!p.name) p.name = name;                    // 首次命名定名
    if (consistent) {
      p.llmAgree++;
      if (p.state === 'draft' && p.llmAgree >= this.verifyN) {
        p.state = 'model-verified';                // 仅模型自洽——非安全输出可用
      }
    } else {
      this._downgrade(p);
    }
    return p;
  }
  // admin 金标：代表性样本确认（≥humanN → human-verified）；改名即金标
  humanConfirm(patternId, name) {
    const p = this.patterns.get(patternId);
    if (!p) return null;
    if (name && name !== p.name) { p.name = name; p.version++; }
    p.humanSamples++;
    p.llmAgree = Math.max(p.llmAgree, p.humanSamples);
    if (p.humanSamples >= this.humanN) p.state = 'human-verified';
    return p;
  }
  shouldAudit(pattern) {
    return pattern.state === 'model-verified' && this.random() < this.auditRate;
  }
  auditResult(patternId, agree) {
    const p = this.patterns.get(patternId);
    if (!p) return null;
    p.lastAudit = { agree, at: Date.now() };
    if (!agree) this._downgrade(p);
    return p;
  }
  _downgrade(p) {
    if (p.state !== 'draft') { p.state = 'draft'; p.version++; p.llmAgree = 0; }
  }
  _prune() {
    if (this.patterns.size <= this.maxPatterns) return;
    const drafts = [...this.patterns.values()].filter(p => p.state === 'draft')
      .sort((a, b) => (a.count * 1) - (b.count * 1));
    for (const d of drafts) {
      this.patterns.delete(d.id);
      if (this.patterns.size <= this.maxPatterns) break;
    }
  }
  // 异常上下文（v3.2）：命中落在预期窗口外——照常命名但标记并提高审计概率
  anomalous(pattern, meta) {
    return this._outsideWindow(pattern, meta) || this._deviation(pattern, meta.peakCount || 1);
  }
  serialize() {
    return [...this.patterns.values()].map(p => JSON.parse(JSON.stringify(p)));
  }
  restore(list) {
    for (const p of list || []) this.patterns.set(p.id, p);
  }
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

// ---------- 告警出口确定性主链（§14）：Outbox（at-least-once + 幂等 + 退避 + 死信） ----------
// 事件经 Outbox 排队投递到出口（webhook 等），可靠性由本类保证：
//   幂等      event_id 去重，同 id 不重复入队
//   退避      失败按 2^n 退避重试，至 maxAttempts 后转死信（保留待人工/复训，不静默丢弃）
// 传输（fetch/webhook）由边缘层注入式完成，本类只管确定性语义。
class Outbox {
  constructor(opts) {
    this.maxAttempts = opts.maxAttempts || 5;
    this.backoffBase = opts.backoffBase || 1000;
    this.backoffMax = opts.backoffMax || 60000;
    this.items = [];               // {ev, attempts, nextAt, delivered, dead}
    this.seen = new Set();         // event_id 幂等集
  }
  enqueue(ev, now) {
    if (!ev || !ev.event_id || this.seen.has(ev.event_id)) return false;
    this.seen.add(ev.event_id);
    this.items.push({ ev, attempts: 0, nextAt: now, delivered: false, dead: false });
    return true;
  }
  // 到期待投递事件（调用方逐个投递后 markDelivered / markFailed）
  due(now) {
    return this.items
      .filter(i => !i.delivered && !i.dead && now >= i.nextAt)
      .map(i => i.ev);
  }
  markDelivered(eventId) {
    const it = this.items.find(i => i.ev.event_id === eventId);
    if (it) it.delivered = true;
  }
  markFailed(eventId, now) {
    const it = this.items.find(i => i.ev.event_id === eventId);
    if (!it) return;
    it.attempts++;
    it.nextAt = now + Math.min(this.backoffBase * Math.pow(2, it.attempts - 1), this.backoffMax);
    if (it.attempts >= this.maxAttempts) it.dead = true;   // 死信：不静默丢弃
  }
  stats() {
    return { pending: this.items.filter(i => !i.delivered && !i.dead).length,
             delivered: this.items.filter(i => i.delivered).length,
             dead: this.items.filter(i => i.dead).length };
  }
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
    SCENE_AUTO_ARM_CONF, applySceneGate, selectPackFromVerdict,
    segSide, segIntersect, RuleEngine, FrameRing, Outbox,
    MODALITY_PROFILES, ICR_TRANSITION_WINDOW_MS, icrVote, ImagingModality,
    SEGMENT_SCHEMA, SEGMENT_SILENCE_MS, SEGMENT_MAX_MS,
    todBucket, durBucket, countBucket, buildSignature, segmentSimilarity, EventSegmenter,
    SEGMENT_LABEL_SCHEMA, NamingGate, templateName, buildSegmentLabel, LabelChain,
    PATTERN_VERIFY_N, PATTERN_AUDIT_RATE, PatternLibrary };
}
