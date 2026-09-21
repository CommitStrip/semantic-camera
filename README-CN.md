<div align="center">

<img src="docs/logo.svg" width="480" alt="语义摄像头"/>

# 语义摄像头 v2

**预算受控的端侧语义视频事件运行时**

A budget-aware semantic video event runtime for Linux NVR and Windows 11

[![CI](https://github.com/CommitStrip/semantic-camera/actions/workflows/ci.yml/badge.svg)](https://github.com/CommitStrip/semantic-camera/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-116%20passed%2C%201%20skipped-brightgreen)](tests/)

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

## 🧭 两个产品版本

| 版本 | 独立入口 | 产品重点 | 发布门禁 |
|---|---|---|---|
| Linux NVR 版 | `python -m scam.linux_nvr` | 常驻服务、多相机、录像、远程运维、24h 稳态 | Linux CI + systemd + 真机浸泡 |
| Win11 值守工作站版 | `python -m scam.win11` | 本机交互、桌面启动、Windows 数据目录和故障恢复 | Windows CI + 原生 Win11 实机验收 |

两版共享 `scam` 领域核心，但入口、默认值、部署链、功能路线和验收报告分别维护。`python -m scam.nvr` 仅为旧部署兼容入口。

独立路线图：[Linux NVR](docs/linux-nvr-roadmap.md) ·
[Linux 发布实施计划](docs/linux-release-plan.md) ·
[Linux Frigate 借鉴边界](docs/linux-frigate-adoption.md) ·
[Win11 工作站](docs/win11-roadmap.md)

## 🚀 Linux NVR 快速开始

```bash
# 1. 安装
git clone https://github.com/CommitStrip/semantic-camera.git
cd semantic-camera
pip install numpy opencv-python-headless onnxruntime pillow

# 2. 发现局域网摄像头
python -m scam.discover

# 3. 编辑 cameras.json（填 RTSP 地址和凭证）

# 4. 启动值守 + 工作台
python -m scam.linux_nvr
# 浏览器打开 http://127.0.0.1:8600（工作台默认只监听本机，
# 不带鉴权不暴露局域网；远程访问：ssh -L 8600:127.0.0.1:8600 <NVR> 后开同一地址）
```

### NVR 部署（systemd）

```bash
bash deploy/install.sh
sudo systemctl enable --now scam-nvr
```

### Win11 值守工作站

```powershell
powershell -ExecutionPolicy Bypass -File deploy\install-win11.ps1
deploy\start-win11.bat
```

## 🏗️ 架构

```
RTSP 摄像头
   │ FrameSource（vus，缺 vus 自动回退 cv2）
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
| pytest | 116 passed，Windows 跳过 1 项 Linux 服务 smoke | 含双产品入口、事件/证据生命周期、录像、源恢复、部署契约与工作台 |

## 📁 项目结构

```
scam/                    核心包（纯 Python）
  config.py              场所档案 fail-closed 校验
  gate.py                T0 帧差门控
  detect.py              T1 NanoDet ONNX
  track.py               跟踪确认
  zones.py               网格圈选
  verdict.py             四态裁决
  db.py                  SQLite 持久层（事件/分段/模式/区域）
  segments.py            事件分段 + 签名
  patterns.py            PatternLibrary 习惯化
  naming.py              命名双车道
  embed.py               V-JEPA 段嵌入
  models.py              模型双通道
  monitor.py             快系统值守循环
  source.py              相机源（vus / cv2 回退）
  server.py              工作台 HTTP
  nvr.py                 NVR 常驻入口
  discover.py            局域网自动发现
  sinks.py               告警出口
deploy/                  NVR 部署（install.sh + systemd）
scripts/                 工具（验收/发现）
tests/                   pytest 测试
docs/                    对标与路线文档
```

## 📖 对标文档

| 文档 | 内容 |
|---|---|
| [Frigate 差距分析](docs/frigate-gap-analysis.md) | 与目标开源 NVR 的逐项差距 |
| [对齐路线图](docs/frigate-parity-roadmap.md) | 冲刺计划与验收口径 |

## 🙏 致谢

- [VUS](https://github.com/CommitStrip/video-understanding-skill) —— 唯一上游：感知、预算机制、流服务全部复用
- [NanoDet-Plus](https://github.com/RangiLyu/nanodet) —— 人员检测模型（Apache-2.0）
- [ollama](https://ollama.com) —— 本地 VLM 推理
- [Meta AI](https://ai.meta.com) —— V-JEPA 2 视频表征模型（CC-BY-NC 4.0）

## License

MIT
