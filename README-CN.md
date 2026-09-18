# 语义摄像头 v2

> **预算受控的端侧语义视频事件运行时**
> A budget-aware, mode-configurable edge vision event runtime

监控摄像头只是"眼睛"，看得见但看不懂。我们给它装上大脑——但这个大脑必须同时满足三个苛刻条件：**快**（报警 ≤1 秒）、**省**（长期使用几乎不花钱）、**听话**（一切规则由管理员定义，系统绝不自作主张）。

## 它是什么

Linux NVR 上的语义值守系统。接一路 RTSP 摄像头，自动发现、自动理解场景、按你圈定的区域和规则报警——视频和语义数据全部留在 NVR 本机。

核心思想：**用确定性工程包裹不确定性模型**。快系统（帧差门控+检测+规则）逐帧值守毫秒级响应，慢系统（VLM 命名+JEPA 嵌入比对）只在有新事件时介入，且调用量随习惯化持续衰减。

## 快速开始

```bash
# 发现局域网摄像头
python -m scam.discover

# 编辑 cameras.json（填 RTSP 地址和凭证）

# 启动值守 + 工作台
python -m scam.nvr
# 浏览器打开 http://<NVR-IP>:8600
```

## 核心设计

| 设计 | 说明 |
|---|---|
| **快慢分层** | T0 门控逐帧毫秒级 → T1 检测运动触发 → 裁决 ≤1s → T2 理解预算制 → T3 习惯化批处理 |
| **报警路径零慢层** | 告警 = 检测 + 管理员规则，≤1s，无任何模型前置 |
| **网格圈选** | 海康式小方格点选——管理员画格子定义重点区域 |
| **自定义模板** | 用户自定义"什么情况要报警"，内置模板仅为预设 |
| **习惯化** | 重复事件模式自命名零 VLM，调用量随使用衰减 |
| **事件即用即归档** | 每事件独立有界上下文，段关闭即归档 SQLite，永不堆积 |

## 交付物

```
scam/                    核心包（纯 Python）
  config.py              场所档案 fail-closed 校验
  gate.py                T0 帧差门控（VUS 已论证经验移植）
  detect.py              T1 NanoDet ONNX 检测
  track.py               跟踪确认（恒速预测+分级老化）
  zones.py               网格圈选（海康式 22×18）
  verdict.py             四态裁决 + 区域滞留
  segments.py            事件分段 + 行为签名
  patterns.py            模式库（信任分层 + 双嵌入档案）
  naming.py              命名双车道（T2a 自命名 / T2b VLM）
  embed.py               V-JEPA 段嵌入
  models.py              模型双通道（本地 ollama / 云端 API）
  monitor.py             单相机快系统值守循环
  source.py              相机源（RTSP/文件/相机）
  server.py              工作台 HTTP + SSE
  nvr.py                 NVR 常驻入口
  discover.py            局域网摄像头自动发现
  outbox.py              出口（at-least-once + 幂等）
  sinks.py               告警出口
deploy/                  NVR 部署脚本
scripts/                 工具脚本（验收/发现/导出）
tests/                   pytest 测试
```

## License

MIT
