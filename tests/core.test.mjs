/* core.js 单元测试 —— node:test 零依赖。
   覆盖：iou / estimateDist（按类尺寸）/ Tracker（确认、悬停存活、老化分级、
   恒速预测、匹配闸门）/ MotionGate（预热、静态、阈值边界、运动框）/
   CFG 不变量 / index.html 内联脚本语法守护。 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { CFG, estimateDist, iou, Tracker, MotionGate,
  MODE_PACKS, getModePack, validatePack, isArmed, JepaPolicy, ArbitrationQueue,
  logregScore, protoDist, weightedAvg, probeLearn, shouldSelfTrain, normalizeProbe } = require('../web/core.js');

// 检出构造器：bbox [x,y,w,h] 归一化，cx/cy 为中心
function mk(x, y, w, h, cls = 'drone') {
  return { cls, conf: 0.9, bbox: [x, y, w, h], cx: x + w / 2, cy: y + h / 2 };
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

// ==================== estimateDist ====================

test('estimateDist 无人机数值回归（针孔模型）', () => {
  // apparent=(54/1080)*3.6e-3=1.8e-4；D=(4.4e-3*0.35)/1.8e-4=8.5555…
  const d = estimateDist(54, 1080, 'drone');
  assert.ok(Math.abs(d - 8.5556) < 1e-3, `drone 距离应约为 8.556m，实际 ${d}`);
});

test('estimateDist 鸟按 0.20m 尺寸，比无人机近', () => {
  const bird = estimateDist(54, 1080, 'bird');
  assert.ok(Math.abs(bird - 4.8889) < 1e-3, `bird 距离应约为 4.889m，实际 ${bird}`);
  assert.ok(bird < estimateDist(54, 1080, 'drone'));
});

test('estimateDist 未知类别回退默认尺寸（与 drone 一致）', () => {
  assert.equal(estimateDist(54, 1080, 'ufo'), estimateDist(54, 1080, 'drone'));
});

test('estimateDist 零尺寸框返回 null', () => {
  assert.equal(estimateDist(0, 1080, 'drone'), null);
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

test('Tracker 悬停存活：巡检 5s 间隔刷新，已确认轨迹不被 2s 老化杀死', () => {
  // 悬停目标无帧差运动 → 只能靠 patrolInterval=5s 巡检检出；
  // 修复前 maxAge=2s < 5s → 轨迹被反复删除、确认计数清零、永远无法告警。
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
  tr.update([mk(0.1, 0.1, 0.2, 0.2)], 0);          // id1，cx=0.2
  tr.update([mk(0.7, 0.7, 0.2, 0.2)], 2500);       // cx=0.8，距 0.85 > 0.35 闸门
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
  tr.update([mk(0.05, 0.4, 0.2, 0.2)], 0);         // cx=0.15
  tr.update([mk(0.8, 0.4, 0.2, 0.2)], 200);        // cx=0.90，距 0.75 > 0.35
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
  f[5 * GW + 10] = 130;                             // 1/5184 ≈ 0.00019 ≤ 0.003
  assert.deepEqual(g.detect(f, GW, GH), []);
  assert.ok(g.lastRatio > 0 && g.lastRatio <= CFG.minAreaRatio);
});

test('MotionGate 16 像素块越过面积门槛，运动框覆盖变化区', () => {
  const g = new MotionGate();
  g.detect(baseGray(), GW, GH);
  const f = baseGray();
  for (let dy = 0; dy < 4; dy++)
    for (let dx = 0; dx < 4; dx++)
      f[(5 + dy) * GW + (10 + dx)] = 130;           // 16/5184 ≈ 0.00309 > 0.003
  const boxes = g.detect(f, GW, GH);
  assert.equal(boxes.length, 1);
  assert.deepEqual(boxes[0], { x: 10, y: 5, w: 3, h: 3 });
  assert.ok(g.lastRatio > CFG.minAreaRatio);
});

test('MotionGate 像素差阈值边界：恰为 25 不触发，26 触发', () => {
  // 小网格 8×4=32 像素：1 像素变化占比 0.03125 必过面积门槛，只考验差值阈值
  let g = new MotionGate();
  g.detect(new Uint8Array(32).fill(100), 8, 4);
  const f25 = new Uint8Array(32).fill(100); f25[0] = 125;
  assert.deepEqual(g.detect(f25, 8, 4), [], '差值恰为 25 不应触发（严格大于）');
  g = new MotionGate();
  g.detect(new Uint8Array(32).fill(100), 8, 4);
  const f26 = new Uint8Array(32).fill(100); f26[0] = 126;
  assert.equal(g.detect(f26, 8, 4).length, 1, '差值 26 应触发');
});

// ==================== 场所模式包 ====================

test('模式包注册表：airfield 首包存在，未知/缺省模式回退缺省包', () => {
  const p = getModePack('airfield');
  assert.equal(p.id, 'airfield');
  assert.equal(getModePack(undefined), p);
  assert.equal(getModePack('nope'), p);
  assert.ok(Object.keys(MODE_PACKS).length >= 1);
});

test('模式包不变量：告警闸门合法，自训练闸门严于告警闸门', () => {
  for (const p of Object.values(MODE_PACKS)) {
    const task = p.discriminators.main;
    assert.equal(task.classes.length, 2, '判别任务为二类');
    assert.ok(task.alertConf > 0.5 && task.alertConf < 1, 'alertConf 应在 (0.5,1)');
    assert.ok(task.classes.includes(p.alertCls), '告警类别必须在判别类别中');
    assert.ok(p.arb.budgetPerHour > 0 && p.arb.ttlMs > 0);
    assert.ok(p.selfTrain.minConf > task.alertConf, '自训练必须严于告警闸门，防止灰区样本污染探针');
    assert.ok(p.selfTrain.marginRatio > 0 && p.selfTrain.marginRatio <= 1);
    assert.ok(p.selfTrain.cooldownMs > 0 && p.selfTrain.lr > 0);
  }
});

// ==================== JepaPolicy 四态裁决 ====================

const policy = new JepaPolicy(getModePack('airfield'));

test('裁决 alert：目标侧高置信自动告警', () => {
  const v = policy.decide(0.92);
  assert.equal(v.action, 'alert');
  assert.equal(v.label, 'drone');
  assert.ok(Math.abs(v.conf - 0.92) < 1e-9);
});

test('裁决阈值边界：恰为 alertConf 判 alert，其下一律 escalate 弃权', () => {
  assert.equal(policy.decide(0.80).action, 'alert');
  assert.equal(policy.decide(0.799).action, 'escalate');
  assert.equal(policy.decide(0.5).action, 'escalate', '目标侧最低置信也不虚报');
});

test('裁决 escalate：目标侧置信不足 → 弃权待仲裁而非告警', () => {
  const v = policy.decide(0.65);
  assert.equal(v.action, 'escalate');
  assert.equal(v.label, 'drone');
  assert.ok(Math.abs(v.conf - 0.65) < 1e-9);
});

test('裁决 clear/suppress：鸟侧永不告警，全区间扫描验证', () => {
  for (let s = 0.0; s < 0.5; s += 0.01) {
    const v = policy.decide(s);
    assert.equal(v.label, 'bird', 'score=' + s);
    assert.ok(v.action === 'clear' || v.action === 'suppress', 'score=' + s);
  }
  const clear = policy.decide(0.10);   // 鸟侧置信 0.9 → 判明非目标
  assert.equal(clear.action, 'clear');
  assert.equal(policy.decide(0.45).action, 'suppress');
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
    protos: [new Array(dim).fill(-1), new Array(dim).fill(1)],  // [负类质心, 正类质心]
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
  const want = [1, 0.75, 0.25, 0];   // (旧质心·1 + 新样本)/2，逐维加权平均
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
  // 轻训练探针：logreg 置信未达 minConf → 拒绝（置信闸门生效）
  const weak = mkProbe();
  for (let k = 0; k < 3; k++) probeLearn(weak, featPos, 1, 0.3);
  assert.ok(logregScore(weak, featPos) < 0.9, '前置：轻训练后置信不足 0.9');
  assert.equal(shouldSelfTrain(weak, featPos, opts), false);
  // 重训练探针：logreg 自信 + 原型距离一致 → 放行（正负类对称）
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
  const f = [0.1, -1, -1, -1];   // logreg ≈ sigmoid(6) 自信正类，原型上却离负类更近
  assert.ok(logregScore(p, f) > 0.9, '前置：logreg 侧高置信');
  assert.equal(shouldSelfTrain(p, f, { minConf: 0.9, marginRatio: 0.8 }), false,
    '冲突样本不得进入自训练（防错误自我强化）');
});

// ==================== 探针格式归一化 ====================

test('normalizeProbe：旧命名（proto_bird/proto_drone）→ 归一化形态', () => {
  const raw = { version: 1, dim: 2, logreg_w: [1, 0], logreg_b: -0.5,
    proto_bird: [9, 9], proto_drone: [8, 8], n_bird: 87, n_drone: 75 };
  const p = normalizeProbe(raw, ['bird', 'drone']);
  assert.deepEqual(p.protos, [[9, 9], [8, 8]]);
  assert.deepEqual(p.ns, [87, 75]);
  assert.equal(p.logreg_b, -0.5);
});

test('normalizeProbe：已归一化形态透传；缺类字段抛错（模式包与探针错配防线）', () => {
  const norm = { logreg_w: [1], logreg_b: 0, protos: [[0], [1]], ns: [1, 2] };
  assert.deepEqual(normalizeProbe(norm, ['a', 'b']), norm);
  assert.throws(() => normalizeProbe({ logreg_w: [], logreg_b: 0 }, ['a', 'b']));
});

// ==================== 模式包校验（fail-closed） ====================

test('validatePack：内置模式包全部通过校验（发布物不许带病）', () => {
  for (const p of Object.values(MODE_PACKS)) {
    assert.deepEqual(validatePack(p), [], p.id + ' 应通过校验');
  }
});

test('validatePack：缺字段/越界/错配逐一报错', () => {
  const base = JSON.parse(JSON.stringify(getModePack('airfield')));
  assert.ok(validatePack(null).length > 0);
  for (const mutate of [
    p => { delete p.detector; },
    p => { delete p.discriminators; },
    p => { p.discriminators.main.classes = ['drone']; },
    p => { p.discriminators.main.alertConf = 0.3; },       // ≤0.5 拒绝
    p => { p.discriminators.main.alertConf = 1.0; },       // ≥1 拒绝
    p => { p.alertCls = 'kite'; },                          // 不在判别类别中
    p => { p.selfTrain.minConf = 0.7; },                   // 未严于告警闸门
    p => { p.arb.budgetPerHour = 0; },
    p => { p.schedule = [{ from: '24:00', to: '06:00' }]; },// 非法时刻
    p => { p.schedule = '22:00-06:00'; },                   // 必须为数组
  ]) {
    const p = JSON.parse(JSON.stringify(base));
    mutate(p);
    assert.ok(validatePack(p).length > 0, '变异 ' + mutate.toString().slice(0, 40) + ' 应报错');
  }
});

test('validatePack：合法 schedule（含跨零点）通过', () => {
  const p = JSON.parse(JSON.stringify(getModePack('airfield')));
  p.schedule = [{ from: '22:00', to: '06:00' }];
  assert.deepEqual(validatePack(p), []);
});

// ==================== 布防时间表 isArmed ====================

test('isArmed：无 schedule = 7×24 布防', () => {
  assert.equal(isArmed(getModePack('airfield'), new Date(2026, 8, 9, 15, 0)), true);
});

test('isArmed：跨零点窗口（22:00–06:00）三段验证', () => {
  const p = { schedule: [{ from: '22:00', to: '06:00' }] };
  assert.equal(isArmed(p, new Date(2026, 8, 9, 23, 0)), true, '深夜在窗内');
  assert.equal(isArmed(p, new Date(2026, 8, 9, 3, 30)), true, '凌晨在窗内');
  assert.equal(isArmed(p, new Date(2026, 8, 9, 12, 0)), false, '白天不在窗内');
  assert.equal(isArmed(p, new Date(2026, 8, 9, 6, 0)), false, 'to 端点开区间');
  assert.equal(isArmed(p, new Date(2026, 8, 9, 22, 0)), true, 'from 端点闭区间');
});

test('isArmed：常规窗口与零长度窗', () => {
  assert.equal(isArmed({ schedule: [{ from: '09:00', to: '18:00' }] },
    new Date(2026, 8, 9, 10, 0)), true);
  assert.equal(isArmed({ schedule: [{ from: '09:00', to: '18:00' }] },
    new Date(2026, 8, 9, 20, 0)), false);
  assert.equal(isArmed({ schedule: [{ from: '09:00', to: '09:00' }] },
    new Date(2026, 8, 9, 20, 0)), true, '零长度窗视为全天');
  assert.equal(isArmed({ schedule: [] }, new Date(2026, 8, 9, 20, 0)), true, '空表退化为全天');
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
  for (const legacy of ['const CFG = {', 'function iou(', 'class Tracker', 'class MotionGate']) {
    assert.ok(!m[1].includes(legacy), `旧定义不应残留：${legacy}`);
  }
});
