/* core.js 单元测试 —— node:test 零依赖。
   覆盖：iou / estimateDist（模式包给尺寸）/ Tracker（确认、悬停存活、老化分级、
   恒速预测、匹配闸门、置信传递）/ MotionGate / 模式包注册与校验 / 布防时间表 /
   四态裁决（判别路径+检测器权威路径）/ 仲裁队列 / 探针学习数学 / 学习状态隔离 /
   mock 检测器确定性 / 证据事件 schema / 双模式端到端验收 / 核心源码洁净度 /
   index.html 内联脚本语法守护。 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { CFG, estimateDist, sizeForClass, iou, Tracker, MotionGate,
  validatePack, isArmed, JepaPolicy, ArbitrationQueue,
  logregScore, protoDist, weightedAvg, probeLearn, shouldSelfTrain, normalizeProbe,
  probeStorageKey, MockDetector, EVIDENCE_SCHEMA, POLICY_VERSION,
  stableStringify, stableHash, sha256Hex, buildEvidenceEvent,
  HEAD_DECODERS, decodeV8Head, decodeNanoDetHead, boxIoU, nms,
  pointInPolygon, ZoneEngine, applyZonePolicy, BridgeLink,
  SCENE_AUTO_ARM_CONF, applySceneGate, selectPackFromVerdict,
  segSide, segIntersect, RuleEngine, FrameRing, Outbox,
  MODALITY_PROFILES, ICR_TRANSITION_WINDOW_MS, icrVote, ImagingModality,
  SEGMENT_SCHEMA, todBucket, durBucket, countBucket, buildSignature, segmentSimilarity,
  EventSegmenter, SEGMENT_LABEL_SCHEMA, NamingGate, templateName, buildSegmentLabel,
  LabelChain, PATTERN_VERIFY_N, PATTERN_AUDIT_RATE, PatternLibrary } = require('../web/core.js');
const { MODE_PACKS, getModePack } = require('../web/mode-packs.js');
const { createHash } = await import('node:crypto');

// 检出构造器：bbox [x,y,w,h] 归一化，cx/cy 为中心
function mk(x, y, w, h, cls = 'drone', conf = 0.9) {
  return { cls, conf, bbox: [x, y, w, h], cx: x + w / 2, cy: y + h / 2 };
}

// ==================== iou ====================

test('iou 完全重合为 1（浮点容差）', () => {
  assert.ok(Math.abs(iou([0.1, 0.1, 0.2, 0.2], [0.1, 0.1, 0.2, 0.2]) - 1) < 1e-9);
});

test('iou 完全分离为 0', () => {
  assert.equal(iou([0, 0, 0.1, 0.1], [0.5, 0.5, 0.1, 0.1]), 0);
});

test('iou 半重叠为 1/3', () => {
  const v = iou([0, 0, 10, 10], [0, 5, 10, 10]);
  assert.ok(Math.abs(v - 1 / 3) < 1e-9, `半重叠应约为 ${1 / 3}，实际 ${v}`);
});

test('iou 包含关系为 16/100', () => {
  assert.ok(Math.abs(iou([0, 0, 10, 10], [2, 2, 4, 4]) - 0.16) < 1e-9);
});

test('iou 退化框（宽或高为 0）为 0', () => {
  assert.equal(iou([0, 0, 0, 10], [0, 0, 5, 5]), 0);
  assert.equal(iou([0, 0, 5, 5], [0, 0, 5, 0]), 0);
});

// ==================== estimateDist（尺寸由模式包给出） ====================

test('estimateDist 数值回归（针孔模型，0.35m 目标）', () => {
  // apparent=(54/1080)*3.6e-3=1.8e-4；D=(4.4e-3*0.35)/1.8e-4=8.5555…
  const d = estimateDist(54, 1080, 0.35);
  assert.ok(Math.abs(d - 8.5556) < 1e-3, `距离应约为 8.556m，实际 ${d}`);
});

test('estimateDist：距离与目标实际尺寸成正比', () => {
  const small = estimateDist(54, 1080, 0.35);
  const big = estimateDist(54, 1080, 1.7);
  assert.ok(big > small, '同像素高度下大物体更远');
  assert.ok(Math.abs(big / small - 1.7 / 0.35) < 1e-9, '比值等于尺寸比');
});

test('sizeForClass：按类取尺寸，缺类回退 defaultSizeM', () => {
  const p = getModePack('airfield');
  assert.equal(sizeForClass(p, p.detector.classes[0]), p.detector.defaultSizeM);
  assert.equal(sizeForClass(p, 'unknown-class'), p.detector.defaultSizeM);
  const q = getModePack('restricted-area');
  assert.equal(sizeForClass(q, 'person'), 1.7);
});

test('estimateDist 零尺寸框或零尺寸目标返回 null', () => {
  assert.equal(estimateDist(0, 1080, 0.35), null);
  assert.equal(estimateDist(54, 1080, 0), null);
});

// ==================== Tracker ====================

test('Tracker 两次检出达到确认计数', () => {
  const tr = new Tracker();
  tr.update([mk(0.4, 0.4, 0.2, 0.2)], 0);
  const out = tr.update([mk(0.4, 0.4, 0.2, 0.2)], 500);
  assert.equal(out.length, 1);
  const t = tr.tracks.get(out[0].id);
  assert.equal(t.count, 2);
  assert.equal(t.confirmed, true);
});

test('Tracker 置信度随检出传递（检测器权威裁决的输入）', () => {
  const tr = new Tracker();
  tr.update([mk(0.4, 0.4, 0.2, 0.2, 'x', 0.61)], 0);
  const out = tr.update([mk(0.4, 0.4, 0.2, 0.2, 'x', 0.83)], 500);
  assert.equal(tr.tracks.get(out[0].id).conf, 0.83);
});

test('Tracker 悬停存活：巡检 5s 间隔刷新，已确认轨迹不被 2s 老化杀死', () => {
  const tr = new Tracker();
  tr.update([mk(0.4, 0.4, 0.2, 0.2)], 0);
  tr.update([mk(0.4, 0.4, 0.2, 0.2)], 500);
  for (const t of [5000, 10000, 11000]) {
    tr.update([mk(0.4, 0.4, 0.2, 0.2)], t);
    const track = tr.tracks.get(1);
    assert.ok(track, `t=${t}ms：已确认轨迹应存活（分级老化窗 ${CFG.confirmedMaxAge}ms）`);
    assert.equal(track.confirmed, true);
    assert.equal(track.count, 2 + [5000, 10000, 11000].indexOf(t) + 1);
  }
});

test('Tracker 未确认目标 2s 快速老化，远处新检出建新轨迹', () => {
  const tr = new Tracker();
  tr.update([mk(0.05, 0.4, 0.2, 0.2)], 0);          // cx=0.15
  tr.update([mk(0.8, 0.4, 0.2, 0.2)], 2500);        // cx=0.90，距 0.75 > 0.35 闸门
  assert.equal(tr.tracks.get(1), undefined, '未确认轨迹 2500ms 后应被老化删除');
  const t2 = tr.tracks.get(2);
  assert.ok(t2, '应新建轨迹 id=2');
  assert.equal(t2.count, 1);
  assert.equal(t2.confirmed, false);
});

test('Tracker 恒速预测：加速目标在秒级检测间隔下不碎裂', () => {
  const tr = new Tracker();
  tr.update([mk(0.0, 0.4, 0.2, 0.2)], 0);          // cx=0.10
  tr.update([mk(0.1, 0.4, 0.2, 0.2)], 1000);       // cx=0.20 → vx≈0.04（平滑后）
  const out = tr.update([mk(0.2, 0.4, 0.2, 0.2)], 2000); // cx=0.30，预测位 0.24
  assert.equal(out.length, 1);
  assert.equal(out[0].id, 1, '应匹配同一条轨迹而非新建');
  assert.equal(tr.tracks.get(1).count, 3);
});

test('Tracker 匹配闸门：远距检出判为新目标（归一化口径 0.35）', () => {
  const tr = new Tracker();
  tr.update([mk(0.05, 0.4, 0.2, 0.2)], 0);
  tr.update([mk(0.8, 0.4, 0.2, 0.2)], 200);
  assert.equal(tr.tracks.size, 2, '应并存两条轨迹');
  assert.ok(tr.tracks.get(1) && tr.tracks.get(2));
});

// ==================== MotionGate ====================

const GW = 96, GH = 54;
function baseGray() { return new Uint8Array(GW * GH).fill(100); }

test('MotionGate 首帧只预热不触发', () => {
  const g = new MotionGate();
  assert.deepEqual(g.detect(baseGray(), GW, GH), []);
});

test('MotionGate 静止画面不触发，lastRatio 为 0', () => {
  const g = new MotionGate();
  g.detect(baseGray(), GW, GH);
  assert.deepEqual(g.detect(baseGray(), GW, GH), []);
  assert.equal(g.lastRatio, 0);
});

test('MotionGate 单像素运动低于面积门槛不触发', () => {
  const g = new MotionGate();
  g.detect(baseGray(), GW, GH);
  const f = baseGray();
  f[5 * GW + 10] = 130;
  assert.deepEqual(g.detect(f, GW, GH), []);
  assert.ok(g.lastRatio > 0 && g.lastRatio <= CFG.minAreaRatio);
});

test('MotionGate 16 像素块越过面积门槛，运动框覆盖变化区', () => {
  const g = new MotionGate();
  g.detect(baseGray(), GW, GH);
  const f = baseGray();
  for (let dy = 0; dy < 4; dy++)
    for (let dx = 0; dx < 4; dx++)
      f[(5 + dy) * GW + (10 + dx)] = 130;
  const boxes = g.detect(f, GW, GH);
  assert.equal(boxes.length, 1);
  assert.deepEqual(boxes[0], { x: 10, y: 5, w: 3, h: 3 });
  assert.ok(g.lastRatio > CFG.minAreaRatio);
});

test('MotionGate 像素差阈值边界：恰为 25 不触发，26 触发', () => {
  let g = new MotionGate();
  g.detect(new Uint8Array(32).fill(100), 8, 4);
  const f25 = new Uint8Array(32).fill(100); f25[0] = 125;
  assert.deepEqual(g.detect(f25, 8, 4), [], '差值恰为 25 不应触发（严格大于）');
  g = new MotionGate();
  g.detect(new Uint8Array(32).fill(100), 8, 4);
  const f26 = new Uint8Array(32).fill(100); f26[0] = 126;
  assert.equal(g.detect(f26, 8, 4).length, 1, '差值 26 应触发');
});

// ==================== 模式包注册表（领域数据唯一居所） ====================

test('模式包注册表：双包存在；缺省回退首包但未知模式必须 fail-closed', () => {
  assert.ok(MODE_PACKS.airfield && MODE_PACKS['restricted-area'], '必须同时有两个场所包');
  assert.equal(getModePack(undefined), MODE_PACKS.airfield, '缺省（无参数）回退首包');
  assert.equal(getModePack('restricted-area'), MODE_PACKS['restricted-area']);
  assert.equal(getModePack('restricted-arae'), null, '拼错模式名必须失败，严禁静默回退');
  assert.equal(getModePack('nope'), null, '未知模式返回 null，由启动流程拒绝布防');
});

test('模式包不变量（schema v3）：两包差异必须足够大，证明抽象非单场景定制', () => {
  for (const p of Object.values(MODE_PACKS)) {
    assert.deepEqual(validatePack(p), [], p.id + ' 应通过校验');
    assert.ok(Array.isArray(p.detector.classes) && p.detector.classes.length >= 1);
    assert.ok(p.detector.engine === 'onnx' || p.detector.engine === 'mock');
    if (p.discriminator) {
      assert.equal(p.discriminator.classes.length, 2);
      assert.ok(p.discriminator.alertConf > 0.5 && p.discriminator.alertConf < 1);
      assert.ok(p.selfTrain === null || p.selfTrain.minConf > p.discriminator.alertConf,
        '自训练闸门必须严于判别告警闸门');
      // 自训练默认必须关闭：双信号非独立证据，治理栈（M5）完备前不得在线修改判别头
      assert.equal(p.selfTrain.enabled, false, p.id + ' 自训练必须默认关闭');
    } else {
      assert.equal(p.selfTrain, null, '无判别头必须显式 selfTrain:null');
    }
  }
  const air = MODE_PACKS.airfield, ra = MODE_PACKS['restricted-area'];
  assert.notEqual(air.detector.head, ra.detector.head, '解码头必须不同（yolo8head vs nanodethead）');
  assert.notDeepEqual(air.detector.classes, ra.detector.classes, '检测类别必须不同');
  assert.notEqual(!!air.discriminator, !!ra.discriminator, '判别头有无必须不同');
  assert.ok(!!ra.schedule !== !!air.schedule, '布防时间表有无必须不同');
  assert.ok(!air.zones && !!ra.zones, '区域规则有无必须不同');
});

// ==================== validatePack（fail-closed） ====================

test('validatePack：缺字段/越界/错配逐一报错', () => {
  const base = JSON.parse(JSON.stringify(getModePack('airfield')));
  assert.ok(validatePack(null).length > 0);
  for (const mutate of [
    p => { delete p.version; },
    p => { delete p.detector; },
    p => { p.detector.engine = 'magic'; },
    p => { p.detector.model = null; },                     // onnx 必须给模型
    p => { p.detector.classes = []; },
    p => { p.detector.confThresh = 1.2; },
    p => { p.detector.defaultSizeM = 0; },
    p => { p.detector.mockScript = 'x'; },
    p => { p.detector.head = 'magic'; },                   // 未注册解码器
    p => { delete p.detector.head; },
    p => { p.discriminator.classes = ['x']; },
    p => { p.discriminator.alertConf = 0.3; },
    p => { p.alertCls = 'kite'; },                          // 不在检测类别中
    p => { p.detector.classes = ['drone']; p.discriminator.classes = ['bird', 'plane']; }, // alertCls 不可被判别
    p => { p.selfTrain.minConf = 0.7; },                   // 未严于判别告警闸门
    p => { p.arb.budgetPerHour = 0; },
    p => { p.schedule = [{ from: '24:00', to: '06:00' }]; },
    p => { p.schedule = '22:00-06:00'; },
    p => { p.zones = [{ id: 'z', polygon: [[0.5]] }]; },    // 多边形点位非法
    p => { p.zones = [{ id: 'z', polygon: [[1.5, 0], [0, 0], [0, 1]] }]; }, // 越界坐标
    p => { p.zones = [{ id: 'z', polygon: [[0, 0], [1, 1]] }]; },           // 少于 3 点
  ]) {
    const p = JSON.parse(JSON.stringify(base));
    mutate(p);
    assert.ok(validatePack(p).length > 0, '变异应报错：' + mutate.toString().slice(0, 50));
  }
});

test('validatePack：无判别头包合法，且有判别头时 selfTrain 缺失报错', () => {
  const q = JSON.parse(JSON.stringify(getModePack('restricted-area')));
  assert.deepEqual(validatePack(q), [], 'restricted-area（discriminator:null, selfTrain:null）应通过');
  const a = JSON.parse(JSON.stringify(getModePack('airfield')));
  delete a.selfTrain;
  assert.ok(validatePack(a).length > 0, '有判别头必须显式声明 selfTrain');
});

// ==================== 布防时间表 isArmed ====================

test('isArmed：无 schedule = 7×24 布防', () => {
  assert.equal(isArmed(getModePack('airfield'), new Date(2026, 8, 9, 15, 0)), true);
});

test('isArmed：跨零点窗口（restricted-area 夜间布防 22:00–06:00）', () => {
  const p = getModePack('restricted-area');
  assert.equal(isArmed(p, new Date(2026, 8, 9, 23, 0)), true, '深夜在窗内');
  assert.equal(isArmed(p, new Date(2026, 8, 9, 3, 30)), true, '凌晨在窗内');
  assert.equal(isArmed(p, new Date(2026, 8, 9, 12, 0)), false, '白天不在窗内');
  assert.equal(isArmed(p, new Date(2026, 8, 9, 6, 0)), false, 'to 端点开区间');
  assert.equal(isArmed(p, new Date(2026, 8, 9, 22, 0)), true, 'from 端点闭区间');
});

// ==================== JepaPolicy 四态裁决 ====================

const policyAir = new JepaPolicy(getModePack('airfield'));
const policyArea = new JepaPolicy(getModePack('restricted-area'));

test('判别路径 alert：目标侧高置信自动告警', () => {
  const v = policyAir.decideDiscriminated(0.92);
  assert.equal(v.action, 'alert');
  assert.equal(v.label, 'drone');
  assert.equal(v.via, 'discriminator');
  assert.ok(Math.abs(v.conf - 0.92) < 1e-9);
});

test('判别路径阈值边界：恰为 alertConf 判 alert，其下一律 escalate 弃权', () => {
  assert.equal(policyAir.decideDiscriminated(0.80).action, 'alert');
  assert.equal(policyAir.decideDiscriminated(0.799).action, 'escalate');
  assert.equal(policyAir.decideDiscriminated(0.5).action, 'escalate', '目标侧最低置信也不虚报');
});

test('判别路径 clear/suppress：非目标侧永不告警，全区间扫描验证', () => {
  for (let s = 0.0; s < 0.5; s += 0.01) {
    const v = policyAir.decideDiscriminated(s);
    assert.equal(v.label, 'bird', 'score=' + s);
    assert.ok(v.action === 'clear' || v.action === 'suppress', 'score=' + s);
  }
});

test('检测器权威路径：无判别头模式包四态语义一致（restricted-area）', () => {
  const v1 = policyArea.decideDetector('person', 0.82);
  assert.deepEqual([v1.action, v1.via], ['alert', 'detector']);
  const v2 = policyArea.decideDetector('person', 0.45);   // 目标侧低于检测权威阈值
  assert.equal(v2.action, 'escalate', '宁可弃权不虚报');
  const v3 = policyAir.decideDetector('drone', 0.55);      // 判别未出时的防漏报路径
  assert.equal(v3.action, 'escalate');
  const v4 = policyAir.decideDetector('drone', 0.90);
  assert.equal(v4.action, 'alert');
});

// ==================== ArbitrationQueue 仲裁队列 ====================

test('仲裁队列：接受 → TTL 窗口内同轨迹去重 → 窗口过期可再申请', () => {
  const q = new ArbitrationQueue({ budgetPerHour: 5, ttlMs: 15000 });
  assert.equal(q.request(1, 0), 'accepted');
  assert.equal(q.request(1, 10000), 'dup', '15s TTL 内同轨迹去重（单飞合并）');
  assert.equal(q.request(2, 11000), 'accepted', '异轨迹不受去重影响');
  assert.equal(q.request(1, 16000), 'accepted', 'TTL 过后同轨迹可再次申请');
});

test('仲裁队列：小时窗预算硬上限 + 窗口滚动后恢复', () => {
  const q = new ArbitrationQueue({ budgetPerHour: 3, ttlMs: 1000 });
  assert.equal(q.request(1, 0), 'accepted');
  assert.equal(q.request(2, 100), 'accepted');
  assert.equal(q.request(3, 200), 'accepted');
  assert.equal(q.request(4, 300), 'budget', '预算用尽必须拒绝');
  assert.equal(q.request(4, 3600001), 'accepted', '一小时后窗内清空，预算恢复');
});

// ==================== 探针学习纯数学（自训练/仲裁回灌共用） ====================

function mkProbe(dim = 4) {
  return {
    logreg_w: new Array(dim).fill(0),
    logreg_b: 0,
    protos: [new Array(dim).fill(-1), new Array(dim).fill(1)],
    ns: [1, 1],
  };
}
const featPos = [1, 1, 1, 1], featNeg = [-1, -1, -1, -1];

test('logregScore：零权值零偏置输出 0.5；正偏置上移', () => {
  assert.ok(Math.abs(logregScore(mkProbe(), featPos) - 0.5) < 1e-9);
  const p = mkProbe(); p.logreg_b = 2;
  assert.ok(logregScore(p, featPos) > 0.8);
});

test('protoDist：特征到两类质心的距离方向正确', () => {
  const d = protoDist(mkProbe(), featPos);
  assert.ok(d[1] < 1e-9, '正类特征到正类质心距离为 0');
  assert.ok(Math.abs(d[0] - 4) < 1e-9, '到负类质心距离为 2√(dim)≈4');
});

test('probeLearn：质心加权并入 + SGD 朝标签方向修正预测', () => {
  const p = mkProbe();
  probeLearn(p, [1, 0.5, -0.5, -1], 1, 0.5);
  assert.equal(p.ns[1], 2);
  const want = [1, 0.75, 0.25, 0];
  for (let i = 0; i < 4; i++)
    assert.ok(Math.abs(p.protos[1][i] - want[i]) < 1e-9, `质心[${i}]应为 ${want[i]}`);
  const before = logregScore(p, featPos);
  probeLearn(p, featPos, 1, 0.5);
  assert.ok(logregScore(p, featPos) > before, '学习正类后正类特征得分上升');
  probeLearn(p, featNeg, 0, 0.5);
  assert.ok(logregScore(p, featNeg) < 0.5, '学习负类后负类特征得分下降');
});

test('shouldSelfTrain：双信号一致且高置信才放行', () => {
  const opts = { minConf: 0.9, marginRatio: 0.8 };
  const weak = mkProbe();
  for (let k = 0; k < 3; k++) probeLearn(weak, featPos, 1, 0.3);
  assert.ok(logregScore(weak, featPos) < 0.9, '前置：轻训练后置信不足 0.9');
  assert.equal(shouldSelfTrain(weak, featPos, opts), false);
  const strong = mkProbe();
  for (let k = 0; k < 60; k++) probeLearn(strong, featPos, 1, 0.3);
  for (let k = 0; k < 60; k++) probeLearn(strong, featNeg, 0, 0.3);
  assert.equal(shouldSelfTrain(strong, featPos, opts), true);
  assert.equal(shouldSelfTrain(strong, featNeg, opts), true);
  assert.equal(shouldSelfTrain(strong, [0, 0, 0, 0], opts), false, '零特征在原型距离上骑墙，不放行');
});

test('shouldSelfTrain：双信号冲突（logreg 自信但原型距离反向）必须拒绝', () => {
  const p = { logreg_w: [10, 0, 0, 0], logreg_b: 5,
              protos: [[-1, -1, -1, -1], [1, 1, 1, 1]], ns: [1, 1] };
  const f = [0.1, -1, -1, -1];
  assert.ok(logregScore(p, f) > 0.9, '前置：logreg 侧高置信');
  assert.equal(shouldSelfTrain(p, f, { minConf: 0.9, marginRatio: 0.8 }), false,
    '冲突样本不得进入自训练（防错误自我强化）');
});

test('normalizeProbe：旧命名质心 → 归一化形态；已归一化透传；缺字段抛错', () => {
  const raw = { version: 1, dim: 2, logreg_w: [1, 0], logreg_b: -0.5,
    proto_bird: [9, 9], proto_drone: [8, 8], n_bird: 87, n_drone: 75 };
  const p = normalizeProbe(raw, ['bird', 'drone']);
  assert.deepEqual(p.protos, [[9, 9], [8, 8]]);
  assert.deepEqual(p.ns, [87, 75]);
  const norm = { logreg_w: [1], logreg_b: 0, protos: [[0], [1]], ns: [1, 2] };
  assert.deepEqual(normalizeProbe(norm, ['a', 'b']), norm);
  assert.throws(() => normalizeProbe({ logreg_w: [], logreg_b: 0 }, ['a', 'b']));
});

test('学习状态按模式包隔离（场所间不互相污染）', () => {
  assert.notEqual(probeStorageKey('airfield'), probeStorageKey('restricted-area'));
  assert.ok(probeStorageKey('x').startsWith('jepa_probe_v2:'));
});

// ==================== vus 桥客户端链路（BridgeLink） ====================

test('BridgeLink：离线入队→open 后按序发出→裁决按 requestId 关联', async () => {
  let handlers = null; const sent = [];
  const bl = new BridgeLink({
    url: 'ws://x', token: 'tk',
    transportFactory: (url, h) => { handlers = h; return { send: t => sent.push(JSON.parse(t)), close: () => {} }; },
    backoffBase: 10, backoffMax: 20,
  });
  const p = bl.request({ type: 'arb-request', requestId: 'r1' });
  bl.connect();
  handlers.onOpen();
  assert.equal(sent[0].type, 'hello', 'open 后先握手');
  assert.equal(sent[0].token, 'tk');
  assert.equal(sent[1].requestId, 'r1', 'flush 按序发出入队案件');
  handlers.onMessage(JSON.stringify({ type: 'arb-verdict', requestId: 'r1', label: 'drone', conf: 0.9 }));
  const v = await p;
  assert.equal(v.label, 'drone');
});

test('BridgeLink：响应超时拒绝（bridge-timeout）', async () => {
  let handlers = null;
  const bl = new BridgeLink({ url: 'ws://x', token: 'tk', timeoutMs: 30,
    transportFactory: (url, h) => { handlers = h; return { send: () => {}, close: () => {} }; } });
  bl.connect(); handlers.onOpen();
  await assert.rejects(bl.request({ requestId: 't1' }), /bridge-timeout/);
  bl.close();
});

test('BridgeLink：在途拥塞拒绝（bridge-busy）', async () => {
  let handlers = null;
  const bl = new BridgeLink({ url: 'ws://x', token: 'tk', maxInFlight: 1,
    transportFactory: (url, h) => { handlers = h; return { send: () => {}, close: () => {} }; } });
  bl.connect(); handlers.onOpen();
  const first = bl.request({ requestId: 'a' });
  first.catch(() => {});                 // 占位请求：故意不等待，拒绝时静默
  await assert.rejects(bl.request({ requestId: 'b' }), /bridge-busy/);
  bl.close();
});

test('BridgeLink：断线清空在途（bridge-offline）并进入退避', async () => {
  let handlers = null;
  const bl = new BridgeLink({ url: 'ws://x', token: 'tk', backoffBase: 50, backoffMax: 100,
    transportFactory: (url, h) => { handlers = h; return { send: () => {}, close: () => {} }; } });
  bl.connect(); handlers.onOpen();
  const p = bl.request({ requestId: 'z' });
  handlers.onClose();
  await assert.rejects(p, /bridge-offline/);
  assert.equal(bl.state, 'offline');
  bl.close();
});

// ==================== 场景自识别（§9） ====================

test('applySceneGate：观察态告警抑制为记录，布防态与非 alert 透传', () => {
  const alert = { action: 'alert', via: 'detector', conf: 0.9 };
  const gated = applySceneGate(alert, false);
  assert.equal(gated.action, 'record');
  assert.equal(gated.reason, 'scene-unidentified');
  assert.equal(applySceneGate(alert, true).action, 'alert', '布防态透传');
  assert.equal(applySceneGate({ action: 'clear' }, false).action, 'clear', '非 alert 透传');
});

test('selectPackFromVerdict：高置信 auto / 低置信 suggest / 未知包 null', () => {
  const catalog = [{ id: 'airfield' }, { id: 'restricted-area' }];
  const hi = selectPackFromVerdict({ packId: 'airfield', conf: 0.87 }, catalog);
  assert.deepEqual([hi.packId, hi.source], ['airfield', 'auto']);
  const lo = selectPackFromVerdict({ packId: 'airfield', conf: 0.6 }, catalog);
  assert.equal(lo.source, 'suggest');
  assert.equal(selectPackFromVerdict({ packId: 'nope', conf: 0.99 }, catalog), null,
    '未知包=无效裁决（fail-closed）');
  assert.equal(selectPackFromVerdict(null, catalog), null);
});

test('_bootstrap 引导包：通过校验、hidden 不入人工目录、不抢缺省', () => {
  const b = MODE_PACKS['_bootstrap'];
  assert.deepEqual(validatePack(b), []);
  assert.equal(b.bootstrap, true);
  assert.equal(b.hidden, true);
  assert.equal(getModePack(undefined), MODE_PACKS.airfield, '缺省仍回退首包');
  // 场景目录（人工选择列表）必须排除引导包
  const visible = Object.values(MODE_PACKS).filter(p => !p.hidden);
  assert.ok(visible.every(p => !p.bootstrap));
});

// ==================== 时空规则引擎（越线/计数/轨迹历史） ====================

test('Tracker：有界轨迹历史（越线检测的输入）', () => {
  const tr = new Tracker();
  for (let i = 0; i <= 40; i++) tr.update([mk(0.4 + i * 0.001, 0.4, 0.1, 0.1)], i * 100);
  const t = tr.tracks.get(1);
  assert.ok(t.hist.length <= 32, '历史环形截断 ≤32');
  assert.equal(t.hist[t.hist.length - 1].x, t.cx, '最新点与当前位置一致');
});

test('segSide/segIntersect：穿越/平行/端点触碰语义', () => {
  const a = [0.5, 0], b = [0.5, 1];                       // 垂直警戒线 x=0.5
  assert.equal(segIntersect([0.4, 0.2], [0.6, 0.8], a, b), true, '跨越');
  assert.equal(segIntersect([0.1, 0.2], [0.3, 0.8], a, b), false, '未达');
  assert.equal(segIntersect([0.6, 0.2], [0.8, 0.8], a, b), false, '已过');
  assert.equal(segIntersect([0, 0.5], [0.4, 0.5], a, b), false, '共线不视为越线');
});

test('RuleEngine：方向判定 + 冷却去重 + 类别过滤', () => {
  const re = new RuleEngine({ lines: [{ id: 'L', a: [0.5, 0], b: [0.5, 1], dir: 'BA', classes: ['person'] }] });
  const track = (pts, id = 7, cls = 'person') =>
    ({ id, cls, hist: pts.map(p => ({ x: p[0], y: p[1], t: 0 })) });
  // 0.4→0.6 越线：按 a→b 向量左右侧定义，落点在 BA 侧 → dir='BA'
  let hits = re.evaluate([track([[0.4, 0.3], [0.6, 0.3]])], 1000, 30000);
  assert.equal(hits.get(7)[0].dir, 'BA');
  // 冷却：30s 内同轨迹同线不重复告警（防来回抖动刷屏）
  hits = re.evaluate([track([[0.6, 0.3], [0.4, 0.3]])], 5000, 30000);
  assert.equal(hits.size, 0, '冷却期内不重复');
  // 冷却后反向穿越：dir='AB' 与规则 'BA' 不符 → 方向过滤正确拒绝
  hits = re.evaluate([track([[0.6, 0.3], [0.4, 0.3]])], 40000, 30000);
  assert.equal(hits.size, 0, '方向不符不触发');
  // 同样反向、规则改为 any → 命中且方向标记为 AB
  const reAny = new RuleEngine({ lines: [{ id: 'L', a: [0.5, 0], b: [0.5, 1], dir: 'any', classes: ['person'] }] });
  hits = reAny.evaluate([track([[0.6, 0.3], [0.4, 0.3]])], 40000, 30000);
  assert.equal(hits.get(7)[0].dir, 'AB');
  // 类别过滤：规则限定 person，animal 穿越不触发
  hits = re.evaluate([track([[0.4, 0.3], [0.6, 0.3]], 8, 'animal')], 42000, 30000);
  assert.equal(hits.size, 0, '类别不符不触发');
});

test('ZoneEngine.occupancy：占驻计数（聚集规则基础）', () => {
  const ze = new ZoneEngine([{ id: 'z', polygon: [[0, 0], [0.5, 0], [0.5, 0.5], [0, 0.5]] }]);
  const in1 = { cls: 'x', cx: 0.1, cy: 0.1 }, in2 = { cls: 'x', cx: 0.2, cy: 0.2 };
  const out = { cls: 'x', cx: 0.9, cy: 0.9 };
  ze.update(in1, 0); ze.update(in2, 0); ze.update(out, 0);
  const counts = ze.occupancy([in1, in2, out]);
  assert.equal(counts.z, 2);
});

test('applyZonePolicy：countGte 人数不足降级（聚集规则）', () => {
  const zones = [{ id: 'z', polygon: [[0, 0], [1, 0], [1, 1], [0, 1]], dwellMs: 0, countGte: 3 }];
  const alert = { action: 'alert', via: 'detector', conf: 0.9 };
  const hit = { zoneId: 'z', dwellMs: 0 };
  const few = applyZonePolicy(alert, hit, zones, 1);
  assert.equal(few.action, 'record');
  assert.equal(few.reason, 'zone-count');
  const crowd = applyZonePolicy(alert, hit, zones, 3);
  assert.equal(crowd.action, 'alert');
  assert.equal(crowd.reason, 'zone-intrusion');
});

// ==================== 告警出口 Outbox（确定性主链） ====================

test('Outbox：event_id 幂等去重 + 到期投递 + 确认', () => {
  const ob = new Outbox({ maxAttempts: 3, backoffBase: 100, backoffMax: 1000 });
  const ev = { event_id: 'cam:m:alert:1:100', kind: 'alert' };
  assert.equal(ob.enqueue(ev, 0), true);
  assert.equal(ob.enqueue({ event_id: 'cam:m:alert:1:100' }, 100), false, '同 id 幂等拒绝');
  assert.equal(ob.due(0).length, 1, '到期即可投');
  ob.markDelivered('cam:m:alert:1:100');
  assert.equal(ob.due(100).length, 0, '已确认不再投');
  assert.equal(ob.stats().delivered, 1);
});

test('Outbox：失败指数退避 + 死信不静默丢弃', async () => {
  const ob = new Outbox({ maxAttempts: 3, backoffBase: 100, backoffMax: 1000 });
  const ev = { event_id: 'e1' };
  ob.enqueue(ev, 0);
  ob.markFailed('e1', 0);                    // 第 1 次失败 → 100ms 后重试
  assert.equal(ob.due(50).length, 0, '退避期内不到期');
  assert.equal(ob.due(150).length, 1, '退避到期重新可投');
  ob.markFailed('e1', 150);                  // 第 2 次失败 → 200ms
  assert.equal(ob.due(200).length, 0);
  assert.equal(ob.due(400).length, 1);
  ob.markFailed('e1', 400);                  // 第 3 次失败 → maxAttempts 耗尽 → 死信
  assert.equal(ob.due(100000).length, 0, '死信不再投递');
  assert.equal(ob.stats().dead, 1, '死信保留可见，不静默丢弃');
});

test('Outbox：不同事件互不影响', () => {
  const ob = new Outbox({ maxAttempts: 2, backoffBase: 100, backoffMax: 400 });
  ob.enqueue({ event_id: 'a' }, 0);
  ob.enqueue({ event_id: 'b' }, 0);
  ob.markFailed('a', 0);
  assert.equal(ob.due(10).length, 1, 'b 不受 a 退避影响');
  ob.markDelivered('b');
  assert.equal(ob.due(10).length, 0);
});

// ==================== 证据帧环形缓冲（告警前因帧） ====================

test('FrameRing：节流入环 + 容量截断 + 快照语义', () => {
  const ring = new FrameRing({ max: 3, minIntervalMs: 500 });
  assert.equal(ring.push({ jpeg: 'a', ts: 1 }, 0), true, '首帧入环');
  assert.equal(ring.push({ jpeg: 'b', ts: 1.5 }, 200), false, '间隔不足丢弃');
  assert.equal(ring.push({ jpeg: 'c', ts: 2 }, 600), true);
  assert.equal(ring.push({ jpeg: 'd', ts: 3 }, 1200), true);
  assert.equal(ring.push({ jpeg: 'e', ts: 4 }, 1800), true);
  assert.equal(ring.items.length, 3, '容量截断 ≤max');
  assert.equal(ring.items[0].jpeg, 'c', '最旧帧被挤出');
  const snap = ring.peek();
  assert.equal(snap.length, 3);
  assert.notEqual(snap, ring.items, '快照为数组拷贝');
  ring.clear();
  assert.equal(ring.items.length, 0);
});

// ==================== 成像模态状态机（ImagingModality，ICR） ====================

const DAY = { sat: 0.30, noise: 2, luma: 0.50 };
const NIGHT_BW = { sat: 0.01, noise: 4, luma: 0.20 };
const NIGHT_LIT = { sat: 0.20, noise: 3.5, luma: 0.30 };

function feedSeq(m, stats, t0, step = 100) {
  const ev = [];
  stats.forEach((st, i) => ev.push(...m.feed(st, t0 + i * step)));
  return ev;
}
const types = evs => evs.map(e => e.type).join(',');

test('ImagingModality：昼→黑白夜 阶跃切换全链（候选→TRANSITION→落定 NIGHT-BW）', () => {
  const m = new ImagingModality({ confirmFrames: 3, settleFrames: 3 });
  feedSeq(m, [DAY, DAY, DAY, DAY], 0);
  assert.equal(m.state, 'DAY-COLOR');
  const ev = feedSeq(m, [NIGHT_BW, NIGHT_BW, NIGHT_BW], 1000);
  assert.equal(m.state, 'TRANSITION', '3 帧候选确认进入 TRANSITION');
  assert.equal(ev[0].type, 'switch-begin');
  assert.equal(m.profile, MODALITY_PROFILES['NIGHT-BW'], '剖面立即切换（等不得）');
  assert.equal(m.learningFrozen(1100), true, '转换期学习冻结');
  const ev2 = feedSeq(m, [NIGHT_BW, NIGHT_BW, NIGHT_BW], 2000);
  assert.equal(m.state, 'NIGHT-BW', '低饱和落定黑白夜');
  assert.ok(types(ev2).includes('switch-done'));
  assert.equal(m.learningFrozen(12000), false, '稳定后解冻');
});

test('ImagingModality：夜间彩色常亮落定 NIGHT-LIT', () => {
  const m = new ImagingModality({ confirmFrames: 3, settleFrames: 3 });
  feedSeq(m, [DAY, DAY, DAY, DAY], 0);
  feedSeq(m, [NIGHT_LIT, NIGHT_LIT, NIGHT_LIT], 1000);
  feedSeq(m, [NIGHT_LIT, NIGHT_LIT, NIGHT_LIT], 2000);
  assert.equal(m.state, 'NIGHT-LIT', '残余饱和度 ≥0.10 落定彩色夜');
});

test('ImagingModality：90s 最小驻留内反向候选 → 立即换回（dwell-reverse）', () => {
  const m = new ImagingModality({ confirmFrames: 3, settleFrames: 3, minDwellMs: 90000 });
  feedSeq(m, [DAY, DAY, DAY, DAY], 0);
  feedSeq(m, [NIGHT_BW, NIGHT_BW, NIGHT_BW], 1000);   // begin
  feedSeq(m, [NIGHT_BW, NIGHT_BW, NIGHT_BW], 2000);   // settle → NIGHT-BW @~2.9s
  assert.equal(m.state, 'NIGHT-BW');
  const ev = feedSeq(m, [DAY, DAY, DAY, DAY], 5000);  // 驻留内反向
  assert.equal(m.state, 'DAY-COLOR', '立即换回，不进 TRANSITION');
  assert.ok(types(ev).includes('switch-done'));
  assert.equal(ev.find(e => e.type === 'switch-done').cause, 'dwell-reverse');
});

test('ImagingModality：10 分钟滑动窗内 3 次切换 → OSCILLATION，稳定 5 分钟退出', () => {
  const m = new ImagingModality({ confirmFrames: 3, settleFrames: 3, minDwellMs: 90000,
    oscWindowMs: 600000, oscMaxSwitches: 3, oscExitMs: 300000 });
  // 切1（驻留期外的正常候选→落定）
  feedSeq(m, [DAY, DAY, DAY, DAY], 0);
  feedSeq(m, [NIGHT_BW, NIGHT_BW, NIGHT_BW], 1000);       // 候选 → begin
  feedSeq(m, [NIGHT_BW, NIGHT_BW, NIGHT_BW], 2000);       // settle → 切1 done
  assert.equal(m.state, 'NIGHT-BW');
  // 切2：120s 处驻留(90s)已过，反向走正常候选→落定
  feedSeq(m, [DAY, DAY, DAY, DAY], 120000);
  feedSeq(m, [DAY, DAY, DAY], 121000);
  assert.equal(m.state, 'DAY-COLOR');
  // 切3：候选→落定 → 滑动窗内第 3 次 → OSCILLATION
  feedSeq(m, [NIGHT_BW, NIGHT_BW, NIGHT_BW], 240000);
  feedSeq(m, [NIGHT_BW, NIGHT_BW, NIGHT_BW], 241000);
  assert.equal(m.state, 'OSCILLATION', '窗内 ≥3 次切换进入振荡态');
  assert.equal(m.profile, MODALITY_PROFILES['OSCILLATION']);
  feedSeq(m, [NIGHT_BW, NIGHT_BW], 242000);
  assert.equal(m.state, 'OSCILLATION', '振荡态不因投票再切换');
  feedSeq(m, [NIGHT_BW], m.lastSwitchAt + 300001);        // 稳定 5 分钟
  assert.equal(m.state, 'NIGHT-BW', '稳定退出振荡到上一模态');
});

test('ImagingModality：硬件日夜事件优先且立即生效，锚点重播种', () => {
  const m = new ImagingModality({ confirmFrames: 3, settleFrames: 3 });
  feedSeq(m, [DAY, DAY, DAY], 0);
  const ev = m.feedHardwareEvent('night', 500);
  assert.equal(m.state, 'NIGHT-BW', '硬件信号立即切换');
  assert.equal(ev[0].cause, 'hw');
  const after = feedSeq(m, [NIGHT_BW, NIGHT_BW, NIGHT_BW], 600);
  assert.equal(m.state, 'NIGHT-BW', '硬件后图像样本不误触发转移');
  assert.ok(!types(after).includes('switch-begin'));
});

test('ImagingModality：原生黑白相机常驻 NIGHT-BW，不参与切换', () => {
  const m = new ImagingModality({ nativeBW: true });
  feedSeq(m, [DAY, DAY, DAY, DAY, NIGHT_BW, NIGHT_BW], 0);
  assert.equal(m.state, 'NIGHT-BW');
  assert.equal(m.learningFrozen(0), false);
  assert.equal(m.feedHardwareEvent('day', 100).length, 0);
});

test('ImagingModality：serialize/restore 重启恢复（状态+切换历史）', () => {
  const m = new ImagingModality({ confirmFrames: 3, settleFrames: 3 });
  feedSeq(m, [DAY, DAY, DAY, DAY], 0);
  feedSeq(m, [NIGHT_BW, NIGHT_BW, NIGHT_BW], 1000);
  feedSeq(m, [NIGHT_BW, NIGHT_BW, NIGHT_BW], 2000);
  const snap = m.serialize();
  const m2 = new ImagingModality({ confirmFrames: 3, settleFrames: 3 });
  m2.restore(JSON.parse(JSON.stringify(snap)));
  assert.equal(m2.state, 'NIGHT-BW');
  assert.equal(m2.switches.length, m.switches.length);
  assert.equal(m2.isTransitionWindow(snap.lastSwitchAt), true);
});

test('ImagingModality：模态内缓慢漂移不触发切换（锚点 EMA 跟踪）', () => {
  const m = new ImagingModality({ confirmFrames: 3, settleFrames: 3 });
  feedSeq(m, [DAY], 0);
  let st = { sat: 0.30, noise: 2, luma: 0.5 };
  const evs = [];
  for (let i = 1; i <= 40; i++) {          // 每采样饱和度 -0.5%（总 -20%，低于 30% 闸门）
    st = { sat: st.sat - 0.0015, noise: st.noise + 0.01, luma: st.luma - 0.002 };
    evs.push(...m.feed(st, i * 100));
  }
  assert.ok(!types(evs).includes('switch-begin'), '缓慢漂移被锚点 EMA 吸收');
  assert.equal(m.state, 'DAY-COLOR');
});

test('MotionGate.resetBackground：软重置抑制切换瞬间假触发', () => {
  const g = new MotionGate();
  const a = baseGray(), GW2 = 96, GH2 = 54;
  g.detect(a, GW2, GH2);
  const switched = baseGray().map(v => Math.max(0, v - 60));   // 模拟 ICR 全帧变暗
  const burst = g.detect(switched, GW2, GH2);
  assert.ok(burst.length > 0 && g.lastRatio > 0.5, '未重置时切换=全画面假运动');
  g.detect(switched, GW2, GH2);
  g.resetBackground(switched);                                  // 软重置
  const after = g.detect(baseGray().map(v => Math.max(0, v - 60)), GW2, GH2);
  assert.deepEqual(after, [], '重置后同帧不再触发');
});

// ==================== 事件分段（EventSegmenter，v3 Phase B） ====================

const trk = (cls, zoneId, zoneDwellMs = 0) => ({ cls, zoneId, zoneDwellMs, bornAt: 0 });

test('EventSegmenter：空闲不开段；活动开段；静默 20s 止段出 record', () => {
  const seg = new EventSegmenter({ cameraId: 'cam-1', venueId: 'restricted-area',
    modeHash: 'fnv1a:aa', envHash: 'fnv1a:bb' });
  assert.deepEqual(seg.feed(0, 'DAY-COLOR', [], []), [], '空闲不开段');
  seg.feed(1000, 'DAY-COLOR', [trk('person', 'restricted-zone', 3000)], []);
  assert.ok(seg.active, '有确认轨迹即开段');
  const closed = seg.feed(1000 + 20000, 'DAY-COLOR', [], []);   // 静默 20s
  assert.equal(closed.length, 1);
  const rec = closed[0];
  assert.equal(rec.schema, SEGMENT_SCHEMA);
  assert.ok(rec.segment_id.startsWith('cam-1:'), '稳定段 ID');
  assert.equal(rec.venue_id, 'restricted-area');
  assert.deepEqual(rec.summary.classes, ['person']);
  assert.equal(rec.summary.zones[0], 'restricted-zone');
  assert.equal(rec.summary.dwellMaxMs, 3000);
  assert.equal(rec.signature.modality, 'DAY-COLOR');
  assert.equal(rec.mode_hash, 'fnv1a:aa');
  assert.equal(rec.reason, 'silence');
  assert.ok(seg.records.includes(rec));
});

test('EventSegmenter：忙碌场景 120s 强制切分（活动不断也有限段）', () => {
  const seg = new EventSegmenter({ cameraId: 'cam', silenceMs: 20000, maxMs: 120000 });
  const closed = [];
  for (let t = 0; t <= 130000; t += 1000)
    closed.push(...seg.feed(t, 'DAY-COLOR', [trk('person', 'z')], []));
  assert.equal(closed.length, 1, '120s 上限触发第一段强制切分');
  assert.equal(closed[0].forcedSplit, true);
  assert.equal(closed[0].reason, 'max-duration');
  assert.ok(closed[0].suggestedSplitAt >= 100000, '切点取末 20s 低密度采样');
  assert.ok(seg.active, '活动仍在：新段接续');
  for (let t = 131000; t <= 145000; t += 1000)
    closed.push(...seg.feed(t, 'DAY-COLOR', [trk('person', 'z')], []));
  closed.push(...seg.feed(145000 + 20000, 'DAY-COLOR', [], []));   // 活动停后静默 20s
  assert.ok(closed.length >= 2, '接续段随后静默关闭');
});

test('EventSegmenter：跨 ICR 模态切换不关段（modalities 列表记录）', () => {
  const seg = new EventSegmenter({ cameraId: 'cam' });
  seg.feed(0, 'DAY-COLOR', [trk('person', 'z')], []);
  seg.feed(5000, 'NIGHT-BW', [trk('person', 'z')], []);   // 模态切换
  const closed = seg.feed(5000 + 20000, 'NIGHT-BW', [], []);
  assert.equal(closed.length, 1);
  assert.deepEqual(closed[0].modalities, ['DAY-COLOR', 'NIGHT-BW'], '跨 ICR 段连续');
  assert.equal(closed[0].signature.modality, 'NIGHT-BW', '签名取末模态');
});

test('EventSegmenter：规则命中（无轨迹）也开段，lines 进签名', () => {
  const seg = new EventSegmenter({ cameraId: 'cam' });
  seg.feed(0, 'DAY-COLOR', [], [{ ruleId: 'gate-line', trackId: 3, dir: 'AB' }]);
  const closed = seg.feed(0 + 20000, 'DAY-COLOR', [], []);
  assert.equal(closed.length, 1);
  assert.deepEqual(closed[0].summary.lines, ['gate-line']);
  assert.equal(closed[0].signature.shape, 'cross', '越线段路径形状=cross');
});

test('segmentSimilarity：相同=1、不相交=0、0.82 阈值区分能力', () => {
  const sig = o => buildSignature(Object.assign({ classes: [], peakCount: 1, zones: [],
    lines: [], modality: 'DAY-COLOR', tod: 'day', durMs: 5000 }, o));
  const a = sig({ classes: ['person'], zones: ['z1'], lines: [] });
  assert.equal(segmentSimilarity(a, sig({ classes: ['person'], zones: ['z1'], lines: [] })), 1);
  assert.equal(segmentSimilarity(a, sig({ classes: ['animal'], zones: ['z9'], lines: ['L'],
    modality: 'NIGHT-BW', tod: 'night', durMs: 200000, peakCount: 5 })).toFixed(2), '0.00',
    '全分量错开=0（shape 不参与相似度权重）');
  // 同类事件小幅波动（数量档/时长档不变，区域同）→ 高于阈值
  const b = sig({ classes: ['person'], zones: ['z1'], lines: [] });
  assert.ok(segmentSimilarity(a, b) >= 0.82);
  // 数量档+区域齐变 → 低于阈值
  const c = sig({ classes: ['person'], zones: ['z9'], count: 'c4-9' });
  assert.ok(segmentSimilarity(a, sig({ classes: ['person'], zones: ['z9'], peakCount: 5 })) < 0.82);
});

test('时段/时长/数量桶：边界语义', () => {
  assert.equal(todBucket(new Date(2026, 8, 10, 6, 0)), 'morning');
  assert.equal(todBucket(new Date(2026, 8, 10, 12, 0)), 'day');
  assert.equal(todBucket(new Date(2026, 8, 10, 18, 0)), 'evening');
  assert.equal(todBucket(new Date(2026, 8, 10, 23, 0)), 'night');
  assert.equal(durBucket(9000), 's10');
  assert.equal(durBucket(59000), 's60');
  assert.equal(countBucket(4), 'c4-9');
  assert.equal(countBucket(11), 'c10+');
});

// ==================== 命名管线（NamingGate/LabelChain/降级命名） ====================

test('NamingGate：小时窗预算 + 同签名去重', () => {
  const g = new NamingGate({ budgetPerHour: 3 });
  const sigA = buildSignature({ classes: ['person'], peakCount: 1, zones: ['z1'],
    lines: [], modality: 'DAY-COLOR', tod: 'day', durMs: 5000 });
  assert.equal(g.request(sigA, 0), 'accepted');
  assert.equal(g.request(sigA, 1000), 'dup', '同签名窗内只送一次');
  const sigB = buildSignature({ classes: ['vehicle'], peakCount: 4, zones: ['z2'],
    lines: [], modality: 'DAY-COLOR', tod: 'day', durMs: 5000 });
  assert.equal(g.request(sigB, 2000), 'accepted');
  assert.equal(g.request(sigB, 3000), 'dup');
  const sigC = buildSignature({ classes: ['animal'], peakCount: 1, zones: ['z3'],
    lines: [], modality: 'NIGHT-BW', tod: 'night', durMs: 5000 });
  assert.equal(g.request(sigC, 4000), 'accepted');
  assert.equal(g.request(sigC, 5000), 'dup', '同签名去重优先于预算');
  const sigD = buildSignature({ classes: ['x'], peakCount: 2, zones: ['z4'],
    lines: [], modality: 'NIGHT-BW', tod: 'night', durMs: 5000 });
  assert.equal(g.request(sigD, 6000), 'budget', '第 4 个不同签名超小时窗预算');
  assert.equal(g.request(sigA, 3600001), 'accepted', '窗口滚动预算恢复');
});

test('templateName：签名模板占位名（降级命名可读性）', () => {
  const sig = buildSignature({ classes: ['person'], peakCount: 2, zones: ['z1', 'z2'],
    lines: ['gate-line'], modality: 'NIGHT-BW', tod: 'night', durMs: 45000 });
  const name = templateName(sig, { peakCount: 2, zones: ['z1', 'z2'], lines: ['gate-line'] });
  assert.ok(name.includes('personx2'), name);
  assert.ok(name.includes('z1'), name);
  assert.ok(name.includes('gate-line'), name);
});

test('LabelChain：revision 递增不可变 + 显式冲突拒绝', () => {
  const ch = new LabelChain();
  const r1 = ch.apply({ segment_id: 's1', source: 'template', name: '占位' });
  assert.equal(r1.revision, 1, '首修订自动 r1');
  const r2 = ch.apply({ segment_id: 's1', source: 'llm', name: '员工上班刷卡进入', conf: 0.87 });
  assert.equal(r2.revision, 2, 'LLM 覆写递增 r2');
  assert.equal(ch.apply({ segment_id: 's1', source: 'llm', revision: 9, name: 'x' }), null,
    '显式 revision 跳号拒绝');
  assert.equal(ch.latest('s1').name, '员工上班刷卡进入');
  assert.equal(ch.size, 1);
});

test('buildSegmentLabel：schema 契约（字段齐全）', () => {
  const lb = buildSegmentLabel({ segmentId: 'cam:123', source: 'llm', name: '车辆驶过',
    conf: 0.9, matchedBehaviors: ['b1'], patternRef: { id: 'p1', version: 2 },
    time: '2026-09-10T00:00:00Z', rationale: '直线穿越' });
  assert.equal(lb.schema, SEGMENT_LABEL_SCHEMA);
  assert.equal(lb.segment_id, 'cam:123');
  assert.equal(lb.revision, undefined, 'revision 由 LabelChain 分配');
  assert.deepEqual(lb.matchedBehaviors, ['b1']);
  assert.equal(lb.pattern.id, 'p1');
  assert.throws(() => buildSegmentLabel({ source: 'llm', name: 'x' }), /segmentId/);
});

// ==================== 模式库（PatternLibrary，习惯化学习主轴） ====================

function mkSig(cls = 'person', zone = 'z1', modality = 'DAY-COLOR', tod = 'day') {
  return buildSignature({ classes: [cls], peakCount: 1, zones: [zone], lines: [],
    modality, tod, durMs: 5000 });
}

test('PatternLibrary：匹配命中累积 count 与预期窗口；未命中建档', () => {
  const lib = new PatternLibrary();
  const sig = mkSig();
  const first = lib.matchOrRecord(sig);
  assert.equal(first.hit, false, '首次未命中→建档');
  assert.equal(first.pattern.state, 'draft');
  const hit = lib.matchOrRecord(sig);
  assert.equal(hit.hit, true, '同签名命中');
  assert.equal(hit.pattern.id, first.pattern.id);
  const info = lib.recordHit(hit.pattern, { peakCount: 1, tod: 'day', modality: 'DAY-COLOR' });
  assert.equal(hit.pattern.count, 1);
  assert.deepEqual(hit.pattern.expectedWindow.tod, ['day']);
  assert.equal(info.deviation, false);
});

test('PatternLibrary：draft→model-verified 生命周期（5 次一致）', () => {
  const lib = new PatternLibrary();
  const { pattern: p } = lib.matchOrRecord(mkSig());
  for (let i = 1; i < PATTERN_VERIFY_N; i++) lib.recordLlmName(p.id, '员工进门', true);
  assert.equal(p.state, 'draft', '不足 5 次仍为 draft');
  lib.recordLlmName(p.id, '员工进门', true);
  assert.equal(p.state, 'model-verified', '第 5 次一致晋升');
  assert.equal(p.name, '员工进门');
});

test('PatternLibrary：审计不一致降级保留 count 且 version 递增', () => {
  const lib = new PatternLibrary();
  const { pattern: p } = lib.matchOrRecord(mkSig());
  for (let i = 0; i < PATTERN_VERIFY_N; i++)
    lib.recordHit(p, { peakCount: 1, tod: 'day', modality: 'DAY-COLOR' });
  for (let i = 0; i < PATTERN_VERIFY_N; i++) lib.recordLlmName(p.id, '员工进门', true);
  const v0 = p.version;
  assert.equal(p.count, PATTERN_VERIFY_N, '前置：命中计数已累计');
  lib.auditResult(p.id, false);                       // 抽检不一致
  assert.equal(p.state, 'draft', '降级回 draft');
  assert.equal(p.count, PATTERN_VERIFY_N, 'count 保留');
  assert.equal(p.version, v0 + 1, '版本递增');
  assert.equal(p.llmAgree, 0, '一致计数清零（re-verify 补差额）');
});

test('PatternLibrary：human 金标（3 代表样本 → human-verified，改名 version+1）', () => {
  const lib = new PatternLibrary();
  const { pattern: p } = lib.matchOrRecord(mkSig());
  lib.humanConfirm(p.id, '员工上班进门');
  assert.equal(p.name, '员工上班进门');
  assert.equal(p.state, 'draft', '1 样本不足');
  lib.humanConfirm(p.id, '员工上班进门');
  lib.humanConfirm(p.id, '员工上班进门');
  assert.equal(p.state, 'human-verified', '3 代表样本金标');
  assert.ok(p.version >= 1);
});

test('PatternLibrary：审计抽检 5%（注入确定性随机）', () => {
  const lib = new PatternLibrary({ random: () => 0.01 });   // 恒小于 0.05
  const { pattern: p } = lib.matchOrRecord(mkSig());
  for (let i = 0; i < PATTERN_VERIFY_N; i++) lib.recordLlmName(p.id, 'n', true);
  assert.equal(lib.shouldAudit(p), true, '0.01 < 0.05 必抽检');
  const lib2 = new PatternLibrary({ random: () => 0.99 });
  const { pattern: p2 } = lib2.matchOrRecord(mkSig());
  for (let i = 0; i < PATTERN_VERIFY_N; i++) lib2.recordLlmName(p2.id, 'n', true);
  assert.equal(lib2.shouldAudit(p2), false, '0.99 > 0.05 不抽检');
});

test('PatternLibrary：偏离检测（数量超历史 P95/P5）与预期窗口异常', () => {
  const lib = new PatternLibrary();
  const { pattern: p } = lib.matchOrRecord(mkSig());
  for (let i = 0; i < 10; i++)
    lib.recordHit(p, { peakCount: 10, tod: 'night', modality: 'NIGHT-BW' });
  assert.equal(p.expectedWindow.tod.length, 1, '窗口学习');
  const dev = lib.recordHit(p, { peakCount: 1, tod: 'night', modality: 'NIGHT-BW' });
  assert.equal(dev.deviation, true, '数量 1 跌破历史下界 → 偏离');
  const win = lib.recordHit(p, { peakCount: 10, tod: 'day', modality: 'DAY-COLOR' });
  assert.equal(win.outsideWindow, true, '白天出现夜班模式 → 窗口外异常');
  // 窗口学会 day 后，day 样本不再异常（预期窗口语义正确）；改验数量偏离：
  // 历史 10 人档，100 人 = 超历史 P95 → anomalous
  assert.equal(lib.anomalous(p, { peakCount: 100, tod: 'night', modality: 'NIGHT-BW' }), true);
  assert.equal(lib.anomalous(p, { peakCount: 10, tod: 'night', modality: 'NIGHT-BW' }), false);
});

test('PatternLibrary：serialize/restore + draft 逐出上限', () => {
  const lib = new PatternLibrary({ maxPatterns: 3 });
  for (let i = 0; i < 5; i++) lib.matchOrRecord(mkSig('person', 'z' + i));
  assert.ok(lib.patterns.size <= 3, '上限逐出（仅 draft）');
  const lib2 = new PatternLibrary();
  lib2.restore(lib.serialize());
  assert.equal(lib2.patterns.size, lib.patterns.size);
});

// ==================== 检测头解码器（注册表契约） ====================

test('decodeV8Head：CHW 布局合成张量解码 + 置信过滤', () => {
  // [1, 5, 8]：nc=1，8 个锚（5 行 CHW：cx,cy,w,h,cls0）
  const N = 8;
  const data = new Float32Array(5 * N);
  const put = (row, c, v) => { data[row * N + c] = v; };
  put(0, 0, 100); put(1, 0, 50); put(2, 0, 20); put(3, 0, 10); put(4, 0, 0.9);
  put(0, 3, 200); put(1, 3, 60); put(2, 3, 10); put(3, 3, 20); put(4, 3, 0.8);
  const dets = decodeV8Head(data, [1, 5, N], { conf: 0.5 });
  assert.equal(dets.length, 2);
  const top = dets.find(d => Math.abs(d.conf - 0.9) < 1e-6);
  assert.equal(top.mcls, 0);
  assert.deepEqual([top.x1, top.y1, top.x2, top.y2], [90, 45, 110, 55]);
});

test('decodeNanoDetHead：GFL 分布投影 + 网格/步长数学（合成小网格）', () => {
  // inputSize 32, strides [8,16] → 级别 4×4 + 2×2 = 20 锚；2 类、3 bins → 14 列
  const nc = 2, bins = 3, N = 16 + 4, cols = nc + 4 * bins, strides = [8, 16];
  const data = new Float32Array(N * cols);
  const i = 6;                            // level0 (s=8) row=1,col=2 → 中心 (20,12)
  data[i * cols + 0] = 3;                 // 类0 分数（导出图内已 sigmoid，直接当分数）
  data[i * cols + 1] = -1;
  const setBin = (g, bin, v) => { data[i * cols + nc + g * bins + bin] = v; };
  setBin(0, 1, 1);                        // l：单热 bin1 → 投影 1.0
  setBin(1, 0, 5);                        // t：集中 bin0 → 投影 0
  setBin(2, 2, 5);                        // r：集中 bin2 → 投影 2
  setBin(3, 1, 5);                        // b：集中 bin1 → 投影 1
  const opts = { conf: 0.5, numClasses: nc, regBins: bins, keepIndices: [0],
    inputSize: 32, strides };
  const dets = decodeNanoDetHead(data, [1, N, cols], opts);
  assert.equal(dets.length, 1);
  const d = dets[0];
  assert.equal(d.mcls, 0);
  // l=1×8=8, t≈0.16（softmax 非零 bin 的尾部泄漏）, r≈15.84, b=1×8=8；中心 (20,12)
  const want = [12, 11.84, 35.84, 20];
  [d.x1, d.y1, d.x2, d.y2].forEach((v, i) =>
    assert.ok(Math.abs(v - want[i]) < 0.01, `框[${i}]应为 ${want[i]}，实际 ${v}`));
  // keepIndices=[0]：仅类0 高分的锚不输出
  data[7 * cols + 1] = 5;
  const d2 = decodeNanoDetHead(data, [1, N, cols], opts);
  assert.ok(d2.every(x => x.mcls === 0), 'keepIndices 过滤生效');
});

test('nms/boxIoU：重叠抑制、独立保留', () => {
  const a = { mcls: 0, conf: 0.9, x1: 0, y1: 0, x2: 10, y2: 10 };
  const b = { mcls: 0, conf: 0.8, x1: 1, y1: 1, x2: 11, y2: 11 };
  const c = { mcls: 0, conf: 0.7, x1: 100, y1: 100, x2: 110, y2: 110 };
  const kept = nms([a, b, c], 0.45);
  assert.equal(kept.length, 2);
  assert.equal(kept[0].conf, 0.9, '按置信降序保留');
});

// ==================== 区域引擎（时空规则） ====================

test('pointInPolygon：内/外判定', () => {
  const sq = [[0, 0], [10, 0], [10, 10], [0, 10]];
  assert.equal(pointInPolygon(5, 5, sq), true);
  assert.equal(pointInPolygon(-1, 5, sq), false);
  assert.equal(pointInPolygon(11, 5, sq), false);
  assert.equal(pointInPolygon(5, -5, sq), false);
  const tri = [[0, 0], [10, 0], [5, 10]];
  assert.equal(pointInPolygon(5, 3, tri), true);
  assert.equal(pointInPolygon(0.5, 9, tri), false);
});

test('ZoneEngine：滞留计时/类别过滤/出区重置', () => {
  const ze = new ZoneEngine([
    { id: 'z1', polygon: [[0, 0], [0.5, 0], [0.5, 0.5], [0, 0.5]], classes: ['person'] },
  ]);
  const t = { cls: 'person', cx: 0.25, cy: 0.25 };
  let h = ze.update(t, 0);
  assert.equal(h.zoneId, 'z1');
  assert.equal(ze.update(t, 800).dwellMs, 800, '滞留累加');
  const other = { cls: 'animal', cx: 0.25, cy: 0.25 };
  assert.equal(ze.update(other, 900), null, '类别不符不触发');
  const t2 = { cls: 'person', cx: 0.9, cy: 0.9 };
  assert.equal(ze.update(t2, 1000), null, '区外返回 null');
  assert.equal(ze.update({ cls: 'person', cx: 0.25, cy: 0.25 }, 5000).dwellMs, 0, '重进计时重置');
});

test('applyZonePolicy：滞留达标升级告警，区外降级记录，无 zones 透传', () => {
  const zones = [{ id: 'z', polygon: [[0, 0], [1, 0], [1, 1], [0, 1]], dwellMs: 1000 }];
  const alert = { action: 'alert', via: 'detector', conf: 0.9 };
  const down = applyZonePolicy(alert, { zoneId: 'z', dwellMs: 500 }, zones);
  assert.equal(down.action, 'record');
  assert.equal(down.reason, 'outside-zone');
  const ok = applyZonePolicy(alert, { zoneId: 'z', dwellMs: 1000 }, zones);
  assert.equal(ok.action, 'alert');
  assert.equal(ok.reason, 'zone-intrusion');
  assert.equal(applyZonePolicy(alert, null, null).action, 'alert', '无 zones 透传');
  assert.equal(applyZonePolicy({ action: 'clear' }, null, zones).action, 'clear', '非 alert 透传');
});

// ==================== 模型资产清单完整性 ====================

test('模型资产清单完整性：manifest sha256 与文件一致（CI 闸门）', async () => {
  const manifest = JSON.parse(readFileSync(new URL('../assets/manifest.json', import.meta.url), 'utf8'));
  assert.equal(manifest.schema, 'sc.assets/v1');
  assert.ok(manifest.files.length >= 4, '至少含 3 模型 + ort 运行时');
  for (const f of manifest.files) {
    const p = new URL('../' + f.path, import.meta.url);
    assert.ok(existsSync(p), f.path + ' 缺失');
    const hex = createHash('sha256').update(readFileSync(p)).digest('hex');
    assert.equal(hex, f.sha256, f.path + ' 哈希不符——staging 漂移或权重被篡改');
    assert.ok(f.license, f.path + ' 必须声明许可证');
  }
  const person = manifest.files.find(f => f.path.endsWith('person-detector.onnx'));
  assert.match(person.license, /Apache-2\.0/, '人员模型必须为宽松许可证');
});

// ==================== MockDetector 确定性 ====================

test('MockDetector：时间线脚本确定性触发与像素换算', async () => {
  const pack = {
    detector: { engine: 'mock', classes: ['x'], confThresh: 0.5, defaultSizeM: 1,
      mockScript: [
        { fromMs: 500, everyMs: 3000, count: 3,
          det: { cls: 'x', conf: 0.82, bbox: [0.25, 0.25, 0.1, 0.2] } },
      ] },
  };
  const det = new MockDetector(pack);
  await det.load();
  const canvas = { width: 1920, height: 1080 };
  assert.deepEqual(await det.predict(canvas, 100), [], '触发前无检出');
  const d1 = await det.predict(canvas, 500);
  assert.equal(d1.length, 1);
  assert.equal(d1[0].cls, 'x');
  assert.deepEqual(d1[0].bbox, [480, 270, 192, 216], '归一化 bbox 按画布尺寸换算');
  assert.deepEqual(await det.predict(canvas, 600), [], '窗口外不重复');
  assert.equal((await det.predict(canvas, 3500)).length, 1, '第二次周期触发');
  assert.equal((await det.predict(canvas, 9500)).length, 0, 'count=3 次用尽后不再触发');
});

// ==================== 证据事件（sc.evidence/v1） ====================

test('证据事件：溯源字段完整（event_id/双时间戳/配置指纹/策略版本/模型哈希）', () => {
  const ev = buildEvidenceEvent({
    kind: 'alert', timeIso: '2026-09-09T02:32:10.000Z', sourceTs: 12.5,
    eventId: 'cam-01:restricted-area:alert:17:1725856420',
    mode: 'restricted-area', modeVersion: 1, modeHash: 'fnv1a:deadbeef',
    trackId: 17, cls: 'person', clsConf: 0.82, bbox: [0.4, 0.3, 0.12, 0.35], dist: 6.1,
    belief: { label: 'person', conf: 0.82, probeVersion: 3 },
    decision: { action: 'alert', via: 'detector', armed: true, reason: 'detector-authority' },
    models: { detector: { engine: 'mock', name: 'mock-script', sha256: null },
      discriminator: null, probeState: 'jepa_probe_v2:restricted-area' },
    evidence: { videoTs: 12.5, frame: 375, cropJpeg: 'data:image/jpeg;base64,…' },
  });
  assert.equal(ev.schema, EVIDENCE_SCHEMA);
  assert.equal(ev.event_id, 'cam-01:restricted-area:alert:17:1725856420', '稳定事件 ID 用于幂等/去重');
  assert.equal(ev.time.source, 12.5, '视频源时间（RTSP 抖动分析）');
  assert.equal(ev.time.processed, '2026-09-09T02:32:10.000Z', '本地处理时间');
  assert.equal(ev.mode.hash, 'fnv1a:deadbeef', '配置指纹：证明当时生效的模式包内容');
  assert.equal(ev.policy_version, POLICY_VERSION, '裁决逻辑独立版本');
  assert.equal(ev.action_recommended, 'notify');
  assert.equal(ev.track.id, 17);
  assert.equal(ev.belief.probeVersion, 3, '判别置信独立成段');
  assert.ok(ev.evidence.cropJpeg.startsWith('data:image/jpeg'), '告警级事件附裁剪帧');
});

test('证据事件：event_id 自动生成且确定性（注入时钟）', () => {
  const ev = buildEvidenceEvent({ kind: 'arbitration', timeIso: 't',
    nowMs: 1725856420000, mode: 'x', trackId: 7, cls: 'y', clsConf: 0.5,
    decision: { action: 'escalate' } });
  assert.equal(ev.event_id, 'cam:x:arbitration:7:1725856420000');
  assert.equal(ev.time.source, null, '未提供源时间显式为 null');
});

test('证据事件 schema 契约：必需键齐全（兼容性闸门）', () => {
  const ev = buildEvidenceEvent({ kind: 'record', timeIso: 't',
    mode: 'm', trackId: 1, cls: 'c', clsConf: 0.9, decision: { action: 'clear' } });
  for (const k of ['schema', 'event_id', 'kind', 'time', 'camera', 'mode',
    'policy_version', 'track', 'belief', 'decision', 'models', 'evidence',
    'action_recommended']) {
    assert.ok(k in ev, '缺键 ' + k);
  }
  assert.equal(ev.action_recommended, 'record');
});

test('证据事件：action_recommended 按裁决动作映射', () => {
  const mk = (action, extra) => buildEvidenceEvent({ kind: 'record', timeIso: 't',
    mode: 'x', trackId: 1, cls: 'y', clsConf: 0.5,
    decision: Object.assign({ action }, extra || {}) });
  assert.equal(mk('alert', { armed: true }).action_recommended, 'notify');
  assert.equal(mk('escalate').action_recommended, 'review');
  assert.equal(mk('clear').action_recommended, 'record');
  assert.equal(mk('suppress').action_recommended, 'record');
});

// ==================== 溯源哈希（配置指纹 / 内容指纹） ====================

test('stableStringify/stableHash：键序无关、值敏感（配置指纹）', () => {
  const a = { x: 1, y: { b: 2, a: [3, { d: 4, c: 5 }] } };
  const b = { y: { a: [3, { c: 5, d: 4 }], b: 2 }, x: 1 };
  assert.equal(stableStringify(a), stableStringify(b), '键序不影响指纹');
  assert.equal(stableHash(a), stableHash(b));
  const c = JSON.parse(JSON.stringify(a)); c.y.b = 3;
  assert.notEqual(stableHash(a), stableHash(c), '阈值变化必须改变指纹');
  assert.ok(stableHash(a).startsWith('fnv1a:'));
});

test('sha256Hex：标准向量（防篡改内容指纹）', async () => {
  const enc = s => new TextEncoder().encode(s);
  assert.equal(await sha256Hex(enc('')),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(await sha256Hex(enc('abc')),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal((await sha256Hex(enc('abc'))).length, 64);
});

// ==================== 双模式端到端验收（平台抽象的核心证明） ====================
// 同一套核心组件（Tracker/MotionGate/JepaPolicy/ArbitrationQueue/证据事件），
// 分别以 airfield 与 restricted-area 两个模式包驱动，跑通检出→跟踪→确认→裁决
// →证据事件，全程不改核心代码。这是"语义摄像头是否成立"的最低验收标准。

test('双模式端到端：同一核心管线跑通两个完全不同的场所包', async () => {
  for (const packId of ['airfield', 'restricted-area']) {
    const pack = getModePack(packId);
    assert.deepEqual(validatePack(pack), [], packId + ' 配置必须合法');
    const policy = new JepaPolicy(pack);
    const tracker = new Tracker();
    const arb = new ArbitrationQueue(pack.arb);
    const det = new MockDetector(pack);       // 检测器可插拔：CI 用确定性 mock
    await det.load();
    assert.ok(det.classes.includes(pack.detector.classes[0]));
    // 注入两条同位置检出 → 多帧确认
    const cls = pack.detector.classes[0];
    const d = { cls, conf: 0.9, bbox: [0.4, 0.3, 0.12, 0.35], cx: 0.46, cy: 0.475 };
    tracker.update([Object.assign({}, d)], 0);
    tracker.update([Object.assign({}, d)], 500);
    const confirmed = tracker.getConfirmed();
    assert.equal(confirmed.length, 1, packId + '：目标应确认');
    const t = confirmed[0];
    const dec = pack.discriminator
      ? policy.decideDiscriminated(0.92)
      : policy.decideDetector(t.cls, t.conf);
    assert.equal(dec.action, 'alert', packId + '：目标侧高置信应告警');
    // 区域门控：restricted-area 须"进区+滞留达标"才升级告警
    if (pack.zones) {
      const ze = new ZoneEngine(pack.zones);
      const early = applyZonePolicy(dec, ze.update(t, 1000), pack.zones);
      assert.equal(early.action, 'record', '滞留不足不得告警');
      const late = applyZonePolicy(dec, ze.update(t, 3000), pack.zones);
      assert.equal(late.action, 'alert', '滞留达标升级告警');
      assert.equal(late.reason, 'zone-intrusion');
    }
    const ev = buildEvidenceEvent({
      kind: 'alert', timeIso: '2026-09-09T00:00:00.000Z',
      mode: pack.id, modeVersion: pack.version,
      trackId: t.id, cls: t.cls, clsConf: t.conf,
      decision: { action: dec.action, via: dec.via, armed: isArmed(pack, new Date(2026, 8, 9, 23, 0)) },
      models: { detector: pack.detector.engine, discriminator: !!pack.discriminator },
      evidence: { videoTs: 0.5, frame: 30 },
    });
    assert.equal(ev.schema, 'sc.evidence/v1');
    assert.equal(ev.action_recommended, 'notify');
    assert.equal(arb.request(t.id, 1000), 'accepted');
  }
});

// ==================== 核心源码洁净度（领域词只允许在模式包数据） ====================

test('源码洁净度：core.js 与 index.html 内联脚本不出现场所领域词', () => {
  const core = readFileSync(new URL('../web/core.js', import.meta.url), 'utf8');
  assert.ok(!/drone|bird|yolov|helmet|person/i.test(core),
    'core.js 出现领域词——领域概念必须收敛到 mode-packs.js');
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
  const m = html.match(/<script>([\s\S]*?)<\/script>\s*<\/body>/);
  assert.ok(m, '内联脚本块应存在');
  assert.ok(!/drone|bird|yolov8s/i.test(m[1]), 'index.html 内联脚本出现领域词');
});

// ==================== CFG 不变量与产物完整性 ====================

test('CFG 不变量：已确认老化窗必须大于巡检间隔（悬停存活的前提）', () => {
  assert.ok(CFG.confirmedMaxAge > CFG.patrolInterval,
    `confirmedMaxAge(${CFG.confirmedMaxAge}) 必须 > patrolInterval(${CFG.patrolInterval})`);
});

test('index.html 内联脚本语法守护（抽取后不得残留旧定义）', () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
  const m = html.match(/<script>([\s\S]*?)<\/script>\s*<\/body>/);
  assert.ok(m, '内联脚本块应存在');
  assert.doesNotThrow(() => new Function(m[1]), '内联脚本语法应合法');
  assert.match(html, /<script src="\.\/core\.js"><\/script>/, '应引入 core.js');
  assert.match(html, /<script src="\.\/mode-packs\.js"><\/script>/, '应引入模式包注册表');
  for (const legacy of ['const CFG = {', 'function iou(', 'class Tracker', 'class MotionGate',
    'const MODE_PACKS', 'function validatePack', 'function buildEvidenceEvent']) {
    assert.ok(!m[1].includes(legacy), `核心逻辑不应内联定义：${legacy}`);
  }
});
