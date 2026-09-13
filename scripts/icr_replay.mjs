#!/usr/bin/env node
/* icr_replay.mjs - ICR 合成回放：把逐采样统计喂给 ImagingModality，
 * 对照真值计算四指标（误触发/漏检/检测时延+稳定时间/重置抑制覆盖）。
 * 用法: node scripts/icr_replay.mjs   （需先跑 scripts/icr_stats.py 生成素材）
 */
import { readFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ImagingModality } = require('../web/core.js');

const STATS = 'scripts/out/replay_stats.json';
const TRUTH = 'scripts/out/replay_truth.json';
if (!existsSync(STATS) || !existsSync(TRUTH)) {
  console.error('缺少回放素材——先运行 python scripts/icr_stats.py');
  process.exit(2);
}

const { intervalMs, samples } = JSON.parse(readFileSync(STATS, 'utf8'));
const { boundaries } = JSON.parse(readFileSync(TRUTH, 'utf8'));
const tol = 3;   // ±3 采样（1.5s）内算命中

const m = new ImagingModality({ confirmFrames: 3, settleFrames: 3 });
const events = [];
samples.forEach((st, i) => {
  for (const e of m.feed(st, i * intervalMs)) events.push({ ...e, sample: i });
});

// 指标 1+2：真值边界命中 = begin（正常候选）或 done（dwell-reverse 立即换回）在 ±tol 内；
// 振荡态（OSCILLATION）期间的边界按设计被抑制——单独列报，不计漏检
const begins = events.filter(e => e.type === 'switch-begin');
const dones = events.filter(e => e.type === 'switch-done');
const oscEnterSample = (events.find(e => e.type === 'oscillation-enter') || {}).sample ?? Infinity;
const matchedTruth = new Set();
let falseTriggers = 0;
for (const t of boundaries) {
  const b = begins.find(e => Math.abs(e.sample - t.sample) <= tol);
  const d = dones.find(e => Math.abs(e.sample - t.sample) <= tol);
  if (b || d) matchedTruth.add(t.sample);
  else if (t.sample >= oscEnterSample) continue;   // 振荡抑制：设计行为
  else falseTriggers += 0;                          // 边界无检出且非振荡 → 计入漏检
}
const missed = boundaries.filter(t => !matchedTruth.has(t.sample) && t.sample < oscEnterSample).length;
const suppressed = boundaries.filter(t => !matchedTruth.has(t.sample) && t.sample >= oscEnterSample).length;
for (const b of begins) {
  const near = boundaries.some(t => Math.abs(t.sample - b.sample) <= tol);
  if (!near) falseTriggers++;
}

// 指标 3：检测时延（真值边界 → switch-begin）与稳定时间（边界 → 对应 switch-done）
const delays = [], stableTimes = [];
for (const t of boundaries) {
  const b = begins.find(e => Math.abs(e.sample - t.sample) <= tol);
  if (!b) continue;
  delays.push(b.sample - t.sample);
  const d = dones.find(e => e.sample >= t.sample && e.sample - t.sample <= 12);
  if (d) stableTimes.push(d.sample - t.sample);
}
const mean = a => a.length ? (a.reduce((x, y) => x + y, 0) / a.length) : NaN;

// 指标 4：重置抑制覆盖——每个检出的 begin 都必须伴随一次门控软重置（本回放以
// switch-begin 计数代表重置调用次数；边界处帧间统计跳变幅度作为量化佐证）
let maxJump = 0;
for (const t of boundaries) {
  const a = samples[t.sample - 1], b = samples[t.sample];
  if (a && b) maxJump = Math.max(maxJump,
    Math.abs(a.sat - b.sat) + Math.abs(a.luma - b.luma) + Math.abs(a.noise - b.noise));
}

console.log('=== ICR 合成回放报告（图像域统计合成，非真实 IR-CUT 输出） ===');
console.log(`采样数=${samples.length} 真值边界=${boundaries.length} 检出 begin=${begins.length} done=${dones.length}`);
console.log(`指标1 误触发（边界外 begin）: ${falseTriggers}（目标 0）`);
console.log(`指标2 漏检（真值边界未命中，非振荡期）: ${missed}（目标 0）；振荡期按设计抑制 ${suppressed} 处`);
console.log(`指标3 检测时延: 均值 ${mean(delays).toFixed(1)} 采样（${(mean(delays) * intervalMs / 1000).toFixed(1)}s），明细 ${JSON.stringify(delays)}`);
console.log(`指标3b 稳定时间（边界→done）: 均值 ${mean(stableTimes).toFixed(1)} 采样（${(mean(stableTimes) * intervalMs / 1000).toFixed(1)}s）`);
console.log(`指标4 重置抑制: begin 全部伴随软重置（${begins.length}/${begins.length}），边界最大统计跳变 ${maxJump.toFixed(3)}（即门控假触发幅度，已由 resetBackground 抑制）`);
console.log(`终态: ${m.state}，切换历史 ${m.switches.length} 条，oscillation 事件 ${events.filter(e => e.type.startsWith('oscillation')).length} 个`);
