/* ============================================================
   mode-packs.js - 场所模式包注册表（纯数据，领域词唯一居所）
   ------------------------------------------------------------
   新增场所 = 在 PACKS 里加一个条目（+ 可选的模型/探针/判别头
   文件），核心流水线零改动。schema 校验见 core.js 的 validatePack。
   字段说明：
   - detector.engine: 'onnx'（真实模型）| 'mock'（确定性脚本，测试与无模型演示）
   - detector.head: 解码器注册键（'yolo8head' | 'nanodethead'，见 core.js HEAD_DECODERS）
   - detector.keepIndices/numClasses: 从多类模型里保留的模型类索引（如 COCO person=0）
   - discriminator: null = 本场所暂无判别头，检测器权威（显式降级）
   - detectorAlertConf: 无判别器/判别未出时检测器权威的告警阈值
   - schedule: 布防时间表（可跨零点；缺省 7×24）
   - zones: 多边形区域规则（归一化坐标；enter+dwell 达标才升级告警）
   - selfTrain: null = 禁用（无判别头时必须为 null）
   ============================================================ */
"use strict";
(function () {
  const PACKS = {
    _bootstrap: {
      id: '_bootstrap',
      name: '观察模式（场景未识别）',
      version: 1,
      bootstrap: true,             // 场景自识别前的占位：检测/跟踪/证据照常，告警由场景层全抑制
      hidden: true,                // 不出现在人工场景选择列表
      detector: {
        engine: 'onnx',
        head: 'nanodethead',
        model: './person-detector.onnx',  // 通用人员检测作引导——任何场所都成立，且为场景识别提供素材
        inputSize: 416,
        classes: ['person'],
        keepIndices: [0],
        numClasses: 80,
        strides: [8, 16, 32, 64],
        regBins: 8,
        confThresh: 0.4,
        sizeByClass: { person: 1.7 },
        defaultSizeM: 1.7,
      },
      discriminator: null,
      detectorAlertConf: 0.60,
      alertCls: 'person',
      arb: { budgetPerHour: 10, ttlMs: 15000 },
      selfTrain: null,
    },

    airfield: {
      id: 'airfield',
      name: '净空防黑飞',
      version: 1,
      description: 'an airport airfield with runways, perimeter fences and open sky, aircraft or drones may appear overhead',  // 场所描述：场景自识别匹配素材
      detector: {
        engine: 'onnx',
        head: 'yolo8head',                 // 解码器：[1,4+nc,N] 无 objectness
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
      arbFeedback: true,                   // vus 桥仲裁结论回灌探针（预算受 arb 上限约束；与自训练开关相互独立）
      // 自训练默认关闭：双信号并非独立证据（同一特征空间），在冻结 golden set、
      // 版本化回滚、开放集拒识完备前（M5 治理栈）不得在线修改判别头
      selfTrain: { enabled: false, minConf: 0.90, marginRatio: 0.80, cooldownMs: 60000, lr: 0.05 },
    },

    'restricted-area': {
      id: 'restricted-area',
      name: '限制区域闯入',
      version: 2,
      description: 'a fenced restricted compound or industrial site entrance with gates and perimeter walls, people may approach or enter',  // 场所描述：场景自识别匹配素材
      detector: {
        engine: 'onnx',
        head: 'nanodethead',               // 解码器：[1,N,nc+4*bins] GFL 分布回归
        model: './person-detector.onnx',
        inputSize: 416,
        classes: ['person'],               // 对外类名（与 keepIndices 一一对应）
        keepIndices: [0],                  // COCO person = 模型类 0
        numClasses: 80,                    // 模型总类数（COCO）
        strides: [8, 16, 32, 64],
        regBins: 8,
        confThresh: 0.4,                   // 实测口径：公开街景抽帧 0.4 下 7~58 检出/帧（docs/model-selection.md）
        sizeByClass: { person: 1.7 },
        defaultSizeM: 1.7,
      },
      discriminator: null,                 // 无判别头：检测器权威（显式降级路径）
      detectorAlertConf: 0.60,
      alertCls: 'person',
      schedule: [{ from: '22:00', to: '06:00' }],   // 夜间布防（跨零点）
      zones: [
        { id: 'restricted-zone', polygon: [[0.30, 0.20], [0.72, 0.20], [0.72, 0.78], [0.30, 0.78]], dwellMs: 2000 },
      ],
      arb: { budgetPerHour: 10, ttlMs: 15000 },
      selfTrain: null,
    },
  };

  function getModePack(name) {
    // 缺省首包；未知模式返回 null（fail-closed：调用方必须拒绝布防，
    // 严禁静默回退到别的场所——选错模式比配置非法更危险）
    if (name === undefined || name === null || name === '') return PACKS.airfield;
    return Object.prototype.hasOwnProperty.call(PACKS, name) ? PACKS[name] : null;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { MODE_PACKS: PACKS, getModePack };
  } else {
    window.SEMANTIC_MODE_PACKS = PACKS;
    window.SEMANTIC_GET_MODE_PACK = getModePack;
  }
})();
