<div align="center">

<img src="docs/logo.svg" width="480" alt="语义摄像头"/>

# 语义摄像头 v2

**预算受控的端侧语义视频事件运行时**

A budget-aware semantic video event runtime for Linux NVR

[![CI](https://github.com/CommitStrip/semantic-camera/actions/workflows/ci.yml/badge.svg)](https://github.com/CommitStrip/semantic-camera/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-35%20passed-brightgreen)](tests/)

[**简体中文**](README-CN.md) · [**English**](README.md)

</div>

---

监控摄像头只是"眼睛"——看得见但看不懂。我们给它装上大脑，但这个大脑必须同时满足三个苛刻条件：**快**（报警 ≤1 秒）、**省**（长期使用几乎不花钱）、**听话**（一切规则由管理员定义，系统绝不自作主张）。

核心思想：**用确定性工程包裹不确定性模型**。快系统（帧差门控 + NanoDet 检测 + 网格规则）逐帧值守毫秒级响应；慢系统（VLM 命名 + V-JEPA 嵌入比对）只在新异事件时介入，调用量随习惯化持续衰减。

## ✨ 核心特性

- **快慢分层**——T0 门控逐帧 1.6ms → T1 检测运动触发 400ms → 裁决 ≤1s → T2 理解预算制 → T3 习惯化批处理
- **报警路径零慢层**——告警 = 检测 + 管理员规则，全程无任何模型前置
- **网格圈选**——海康式小方格点选，管理员画格子定义重点管理区域
- **自定义报警模板**——用户定义"什么情况要报警"，结构条件实时比对 + 语义描述补充
- **习惯化省 token**——V-JEPA 嵌入比对命中已知模式 → 自命名零 VLM 调用，重复场景趋零
- **双模型通道**——本地 ollama（数据不出 NVR）/ 云端 OpenAI 兼容 API，管理页一键切换
- **事件即用即归档**——每事件独立有界上下文，SQLite 全程可审计，永不堆积
- **安装零特殊工作**——自动发现 + 一条命令启动，工作台浏览器即开

## 🚀 快速开始

```bash
# 1. 安装
git clone https://github.com/CommitStrip/semantic-camera.git
cd semantic-camera
pip install numpy opencv-python-headless onnxruntime pillow

# 2. 发现局域网摄像头
python -m scam.discover

# 3. 编辑 cameras.json（填 RTSP 地址和凭证）

# 4. 启动值守 + 工作台
python -m scam.nvr
# 浏览器打开 http://<NVR-IP>:8600
```

### NVR 部署（systemd）

```bash
bash deploy/install.sh
sudo systemctl enable --now scam-nvr
```

## 🏗️ 架构

```
RTSP 摄像头
   │ FrameSource（vus）
   ▼
┌─────────────────── 快系统（逐帧，零模型） ───────────────────┐
│ T0 帧差门控(1.6ms) → T1 NanoDet(运动触发 400ms/巡检 5s)      │
│ → 跟踪确认 → 网格判定 → 四态裁决 → 告警 ≤1s                 │
└──────────────────────────────────────────────────────────────┘
   ▼ 运动触发
┌─────────────────── 慢系统（预算制，新异才介入） ──────────────┐
│ T2a V-JEPA 嵌入比对 → 已知模式自命名（零 VLM）              │
│ T2b VLM 命名 → 新异事件建档                                  │
└──────────────────────────────────────────────────────────────┘
   ▼
SQLite 全程可审计
```

## 📊 实测数据

| 指标 | 数值 | 条件 |
|---|---|---|
| 告警延迟（结构条件触发） | **≤1s** | NanoDet ONNX CPU，管理格内运动 |
| 帧差门控单帧 | 1.6ms | 降采样灰度 96×54 |
| 检测延迟（NanoDet CPU） | 23-24ms | 416×416 输入 |
| pytest | 35 passed | 含配置校验/网格/门控/跟踪/裁决/嵌入/模式库/命名 |

## 📁 项目结构

```
scam/                    核心包（纯 Python）
  config.py              场所档案 fail-closed 校验
  gate.py                T0 帧差门控
  detect.py              T1 NanoDet ONNX
  track.py               跟踪确认
  zones.py               网格圈选
  verdict.py             四态裁决
  segments.py            事件分段 + 签名
  patterns.py            PatternLibrary 习惯化
  naming.py              命名双车道
  embed.py               V-JEPA 段嵌入
  models.py              模型双通道
  monitor.py             快系统值守循环
  source.py              相机源
  server.py              工作台 HTTP
  nvr.py                 NVR 常驻入口
  discover.py            局域网自动发现
  sinks.py               告警出口
deploy/                  NVR 部署（install.sh + systemd）
scripts/                 工具（验收/发现/导出）
tests/                   pytest 测试
docs/                    设计文档
```

## 📖 设计文档

| 文档 | 内容 |
|---|---|
| [核心循环 v3](docs/core-loop-v3.md) | 环境详析 → 值守 → 分段 → 命名 → 习惯化 |
| [系统设计 v2.7](docs/semantic-camera-design.md) | 机制层全貌（门控/检测/裁决/分段/出口） |
| [模型选型](docs/vlm-selection.md) | V-JEPA / NanoDet 实测数据与淘汰记录 |

## 🙏 致谢

- [VUS](https://github.com/CommitStrip/video-understanding-skill) —— 唯一上游：感知、预算机制、流服务全部复用
- [NanoDet-Plus](https://github.com/RangiLyu/nanodet) —— 人员检测模型（Apache-2.0）
- [ollama](https://ollama.com) —— 本地 VLM 推理
- [Meta AI](https://ai.meta.com) —— V-JEPA 2 视频表征模型（CC-BY-NC 4.0）

## License

MIT
