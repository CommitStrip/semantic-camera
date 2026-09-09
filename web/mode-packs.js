/* ============================================================
   mode-packs.js - 场所模式包注册表（纯数据，领域词唯一居所）
   ------------------------------------------------------------
   新增场所 = 在 PACKS 里加一个条目（+ 可选的模型/探针/判别头
   文件），核心流水线零改动。schema 校验见 core.js 的 validatePack。
   字段说明：
   - detector.engine: 'onnx'（真实模型）| 'mock'（确定性脚本，测试
     与无模型演示；mockScript 为检出时间线）
   - discriminator: null = 本场所暂无判别头，检测器权威（显式降级）
   - detectorAlertConf: 无判别器/判别未出时检测器权威的告警阈值
   - schedule: 布防时间表（可跨零点；缺省 7×24）
   - selfTrain: null = 禁用（无判别头时必须为 null）
   ============================================================ */
"use strict";
(function () {
  const PACKS = {
    airfield: {
      id: 'airfield',
      name: '净空防黑飞',
      version: 1,
      detector: {
        engine: 'onnx',
        model: './yolov8s-drone.onnx',
        classes: ['drone'],
        confThresh: 0.25,
        inputSize: 640,
        sizeByClass: { drone: 0.35 },      // 估距用实际尺寸(米)
        defaultSizeM: 0.35,
      },
      discriminator: {
        classes: ['bird', 'drone'],        // [负类, 正类]；探针输出 P(正类)
        probe: './jepa_probe_init.json',
        alertConf: 0.80,                   // 判别器下结论的置信闸门
      },
      detectorAlertConf: 0.60,             // 判别未出时检测器权威阈值（防漏报）
      alertCls: 'drone',
      arb: { budgetPerHour: 20, ttlMs: 15000 },
      selfTrain: { minConf: 0.90, marginRatio: 0.80, cooldownMs: 60000, lr: 0.05 },
    },

    'restricted-area': {
      id: 'restricted-area',
      name: '限制区域闯入（设计态）',
      version: 1,
      status: 'design',                    // 核心抽象已由 CI 双模式测试验证；
                                           // 真实人员检测模型接入前用 mock 演示
      detector: {
        engine: 'mock',
        classes: ['person'],
        confThresh: 0.5,
        sizeByClass: { person: 1.7 },
        defaultSizeM: 1.7,
        // 确定性演示时间线：t=500ms 起每 3s 出现一次人员检出，共 3 次
        mockScript: [
          { fromMs: 500, everyMs: 3000, count: 3,
            det: { cls: 'person', conf: 0.82, bbox: [0.40, 0.30, 0.12, 0.35] } },
        ],
      },
      discriminator: null,                 // 无判别头：检测器权威（显式降级路径）
      detectorAlertConf: 0.60,
      alertCls: 'person',
      schedule: [{ from: '22:00', to: '06:00' }],   // 夜间布防（跨零点）
      arb: { budgetPerHour: 10, ttlMs: 15000 },
      selfTrain: null,
    },
  };

  function getModePack(name) {
    return PACKS[name || 'airfield'] || PACKS.airfield;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { MODE_PACKS: PACKS, getModePack };
  } else {
    window.SEMANTIC_MODE_PACKS = PACKS;
    window.SEMANTIC_GET_MODE_PACK = getModePack;
  }
})();
