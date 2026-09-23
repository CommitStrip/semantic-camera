<div align="center">

<img src="docs/logo.svg" width="104" alt="语义摄像头"/>

# 语义摄像头 v2

**预算受控的端侧语义视频事件运行时 —— Linux NVR 与 Windows 11 双版本**

A budget-aware semantic video event runtime for Linux NVR and Windows 11

[![CI](https://github.com/CommitStrip/semantic-camera/actions/workflows/ci.yml/badge.svg)](https://github.com/CommitStrip/semantic-camera/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1109%20passed%2C%2016%20skipped-brightgreen)](tests/)

[**简体中文**](README-CN.md) · [**English**](README.md)

</div>

---

监控摄像头只是"眼睛"——看得见但看不懂。我们给它装上大脑，但这个大脑必须同时满足三个苛刻条件：**快**（报警 ≤ 1 秒）、**省**（长期使用几乎不花钱）、**听话**（一切规则由管理员定义，系统绝不自作主张）。

核心思想：**用确定性工程包裹不确定性模型**。快系统（帧差门控 + NanoDet 检测 + 网格规则）逐帧值守毫秒级响应；慢系统（VLM 命名 + V-JEPA 嵌入比对）只在新异事件时介入，调用量随习惯化持续衰减。

## ✨ 核心特性

- **快慢分层**——T0 门控逐帧 0.4ms → T1 检测运动触发 → 结构条件裁决告警 ≤ 1s → T2 理解预算制 → T3 习惯化批处理
- **报警路径零慢层**——告警 = 检测 + 管理员规则，全程无任何模型前置
- **网格圈选**——方格点选，管理员画格子定义重点管理区域
- **自定义报警模板**——结构条件实时比对 + 语义描述补充
- **习惯化省 token**——V-JEPA 嵌入比对命中已知模式 → 自命名零 VLM 调用，重复场景趋零
- **双模型通道**——本地 ollama（数据不出 NVR）/ 云端 OpenAI 兼容 API，管理页一键切换
- **事件即用即归档**——每事件独立有界上下文，SQLite 全程可审计，永不堆积
- **慢系统单执行核心**——认领用 CAS 互斥、终态单事务写入、待办水位只有一个真值入口；损坏与未知状态一律拒绝触碰（fail-closed）且诚实留在待办里
- **安装零特殊工作**——自动发现 + 一条命令启动，工作台浏览器即开

## 🧭 两个产品版本

| 版本 | 独立入口 | 产品重点 | 发布门禁 |
|---|---|---|---|
| Linux NVR 版 | `python -m scam.linux_nvr` | 常驻服务、多相机、录像、远程运维、24h 稳态 | Linux CI + systemd + 真机浸泡 |
| Win11 值守工作站版 | `python -m scam.win11` | 本机交互、桌面启动、Windows 数据目录和故障恢复 | Windows CI + 原生 Win11 实机验收 |

两版共享 `scam` 领域核心，但入口、默认值、部署链和验收报告分别维护。`python -m scam.nvr` 仅为旧部署兼容入口。

运维（安装 / 升级 / 回滚 / 备份恢复）见[运维 Runbook](docs/linux-operations-runbook.md)。

## 🚀 快速开始

### 安装

```bash
git clone https://github.com/CommitStrip/semantic-camera.git
cd semantic-camera
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[detect,vision]"                   # 领域核心只依赖 numpy；此二者为检测与视频解码
# 可选：pip install -e ".[discover]"   局域网摄像头发现（WS-Discovery）
# 可选：pip install -e ".[mqtt]"       通知出口
```

检测与嵌入**权重不随包分发**，用脚本取用：

```bash
python scripts/fetch_models.py --list                              # 清单与就位状态
python scripts/fetch_models.py --model nanodet                     # 哈希冻结后下载校验入位
python scripts/fetch_models.py --verify-local <路径> --expect <sha256>   # 自行导出的权重校验
```

### Linux NVR

```bash
python -m scam.discover        # 发现局域网摄像头（写入 cameras.json 草稿）
# 编辑 cameras.json：填 RTSP 地址与凭证
python -m scam.linux_nvr       # 启动值守 + 工作台
# 浏览器打开 http://127.0.0.1:8600
# 工作台默认只监听本机、不带鉴权，不暴露局域网；
# 远程访问：ssh -L 8600:127.0.0.1:8600 <NVR> 后开同一地址
```

### NVR 部署（systemd）

```bash
bash deploy/install.sh
sudo systemctl enable --now scam-nvr
```

升级、回滚与备份恢复见[运维 Runbook](docs/linux-operations-runbook.md)（破坏性步骤逐条人工确认）。

### Win11 值守工作站

```powershell
powershell -ExecutionPolicy Bypass -File deploy\install-win11.ps1
deploy\start-win11.bat
```

等价入口：`python -m scam.win11`。

## 🏗️ 架构

```
RTSP 摄像头
   │ FrameSource（VUS 优先，缺 VUS 自动回退 cv2）
   ▼
┌─────────────────── 快系统（逐帧，零模型） ───────────────────┐
│ T0 帧差门控(0.4ms) → T1 NanoDet(运动触发 / 定时巡检)         │
│ → 跟踪确认 → 网格判定 → 四态裁决 → 告警 ≤ 1s                │
└──────────────────────────────────────────────────────────────┘
   ▼ 运动触发
┌─────────────────── 慢系统（预算制，新异才介入） ──────────────┐
│ 唯一执行核心：认领 CAS · 整份快照 CAS · 待办水位单一真值      │
│ T2a V-JEPA 嵌入比对 → 已知模式自命名（零 VLM 调用）          │
│ T2b VLM 命名 → 新异事件建档                                   │
└──────────────────────────────────────────────────────────────┘
   ▼
SQLite 全程可审计
```

## 📊 实测数据

| 指标 | 数值 | 口径与条件 |
|---|---|---|
| 测试 | **1109 passed / 16 skipped**（1125 收集） | 本机 Windows 全量（2026-09-23）；CI 另有 Linux 3.10 / 3.12 与 Windows 三作业 |
| 告警延迟（结构条件触发） | **≤ 1s** | `tests/test_monitor.py` 端到端断言：目标进入管理格后 1 秒内必须告警（合成帧 + 检测判定路径） |
| T0 帧差门控 | **0.39ms/帧**（P95 0.43ms） | 1080p → 96×54 灰度 → 门控判定，纯 Python；本机复测 199 帧 |
| T1 检测 | NanoDet-Plus ONNX，输入 416×416 | 权重不随包分发；单次推理延迟取决于宿主 CPU——早期本机实测 23–24ms，本轮未复测 |

## ✅ 质量门禁

CI 三个作业（[工作流](.github/workflows/ci.yml)）：

- **test（Linux，Python 3.10 与 3.12）**——部署脚本语法（`bash -n`）、systemd unit 单一真值渲染 + `systemd-analyze verify`、全量测试（含 Linux 服务级 smoke）、Linux NVR 版本契约、发布打包门（敏感面双闸 + 可复现打包自检）
- **test-windows**——全量测试（服务级 smoke 自动跳过）、发布打包 dry-run、平台层 smoke（UTF-8 输出与数据目录）、Win11 入口 smoke、部署脚本 PowerShell 5.1 与 7 双解析

最近一次（run #61，2026-09-23）：三作业全绿。

## 📁 项目结构

```
scam/                    领域核心（纯 Python）
  config.py              场所档案 fail-closed 校验
  gate.py                T0 帧差门控
  detect.py              T1 NanoDet-Plus ONNX 检测
  track.py               跟踪确认
  zones.py               网格圈选
  verdict.py             四态裁决
  monitor.py             快系统值守循环
  source.py              相机源（VUS 优先，cv2 回退）
  slow_core.py           慢系统唯一执行核心（认领 CAS / 整份快照 / 统一待办真值）
  slow_worker.py         慢系统有界后台 worker
  linux_slow_path.py     旧 Linux 入口的薄兼容适配器（零写入状态机）
  segments.py            事件分段与签名
  patterns.py            习惯化模式库
  naming.py              命名双车道
  embed.py               V-JEPA 段嵌入
  evidence.py            证据索引与路径围栏
  quality_gate.py        标注对齐质量门
  db.py                  SQLite 持久层（事件 / 分段 / 模式 / 区域）
  server.py              工作台 HTTP（仅回环）
  sinks.py               告警出口
  notify.py              通知出口（webhook / MQTT，可选）
  recording.py recorder.py   录像与分段导出
  health.py              健康水位
  nvr.py linux_nvr.py    常驻入口
  win11*.py              Win11 入口、安装与实机验收
  linux_*.py             运维线：主机体检、备份、升级契约、回放、浸泡、部署单元渲染
  models.py              VLM 双通道（本地 / 云端，显式 opt-in）
deploy/                  NVR（install.sh + systemd unit）与 Win11（install-win11.ps1 / start-win11.bat）
scripts/                 验收、模型获取与校验、发布打包
tests/                   pytest（1125 用例）
docs/                    路线图、对标分析与运维 Runbook
```

## 📖 文档

| 文档 | 内容 |
|---|---|
| [运维 Runbook](docs/linux-operations-runbook.md) | 安装 / 升级 / 回滚 / 备份恢复（含人工确认点） |

## ⚠️ 已知限制（诚实清单）

- 当前全部证据等级为 **Windows 本机合成自动化**：真实 RTSP、真实检测与嵌入推理、原生 Linux 主机运维链路、24 小时浸泡、真实 P95/P99 与隐私网络审计**均未验证**；
- 检测与嵌入权重不随包分发（`scripts/fetch_models.py`），哈希冻结前 fail-closed 拒绝自动下载；
- 慢系统 VLM 通道默认未接线：新异段标记 `pending_naming`，重复场景走纯结构匹配 + 档案复用；
- 工作台为单管理员回环形态：无认证、无多用户，远程访问走 SSH 隧道；
- Win11 版的 Windows CI 只证明自动化兼容，原生实机验收单独记账。

## 🙏 致谢

- [VUS](https://github.com/CommitStrip/video-understanding-skill) —— 唯一上游：感知、预算机制、流服务全部复用
- [NanoDet-Plus](https://github.com/RangiLyu/nanodet) —— 人员检测模型（Apache-2.0）
- [ollama](https://ollama.com) —— 本地 VLM 推理
- [Meta AI](https://ai.meta.com) —— V-JEPA 2 视频表征模型（CC-BY-NC 4.0）

## License

MIT，见 [LICENSE](LICENSE)。
