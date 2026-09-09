/* core.js 单元测试 —— node:test 零依赖。
   覆盖：iou / estimateDist（模式包给尺寸）/ Tracker（确认、悬停存活、老化分级、
   恒速预测、匹配闸门、置信传递）/ MotionGate / 模式包注册与校验 / 布防时间表 /
   四态裁决（判别路径+检测器权威路径）/ 仲裁队列 / 探针学习数学 / 学习状态隔离 /
   mock 检测器确定性 / 证据事件 schema / 双模式端到端验收 / 核心源码洁净度 /
   index.html 内联脚本语法守护。 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { CFG, estimateDist, sizeForClass, iou, Tracker, MotionGate,
  validatePack, isArmed, JepaPolicy, ArbitrationQueue,
  logregScore, protoDist, weightedAvg, probeLearn, shouldSelfTrain, normalizeProbe,
  probeStorageKey, MockDetector, EVIDENCE_SCHEMA, POLICY_VERSION,
  stableStringify, stableHash, sha256Hex, buildEvidenceEvent } = require('../web/core.js');
const { MODE_PACKS, getModePack } = require('../web/mode-packs.js');

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
  assert.notEqual(MODE_PACKS.airfield.detector.engine, MODE_PACKS['restricted-area'].detector.engine,
    '检测引擎必须不同（onnx vs mock）');
  assert.notDeepEqual(MODE_PACKS.airfield.detector.classes, MODE_PACKS['restricted-area'].detector.classes,
    '检测类别必须不同');
  assert.notEqual(!!MODE_PACKS.airfield.discriminator, !!MODE_PACKS['restricted-area'].discriminator,
    '判别头有无必须不同');
  assert.ok(!!MODE_PACKS['restricted-area'].schedule !== !!MODE_PACKS.airfield.schedule,
    '布防时间表有无必须不同');
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
    p => { p.discriminator.classes = ['x']; },
    p => { p.discriminator.alertConf = 0.3; },
    p => { p.alertCls = 'kite'; },                          // 不在检测类别中
    p => { p.detector.classes = ['drone']; p.discriminator.classes = ['bird', 'plane']; }, // alertCls 不可被判别
    p => { p.selfTrain.minConf = 0.7; },                   // 未严于判别告警闸门
    p => { p.arb.budgetPerHour = 0; },
    p => { p.schedule = [{ from: '24:00', to: '06:00' }]; },
    p => { p.schedule = '22:00-06:00'; },
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

// ==================== MockDetector 确定性 ====================

test('MockDetector：时间线脚本确定性触发与像素换算', async () => {
  const pack = getModePack('restricted-area');
  const det = new MockDetector(pack);
  await det.load();
  const canvas = { width: 1920, height: 1080 };
  assert.deepEqual(await det.predict(canvas, 100), [], '触发前无检出');
  const d1 = await det.predict(canvas, 500);
  assert.equal(d1.length, 1);
  assert.equal(d1[0].cls, 'person');
  assert.deepEqual(d1[0].bbox, [768, 324, 230, 378], '归一化 bbox 按画布尺寸换算');
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
