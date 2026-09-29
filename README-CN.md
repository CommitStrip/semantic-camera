<div align="center">

<img src="docs/logo.svg" width="104" alt="语义摄像头"/>

# 语义摄像头 v2

**预算受控的端侧语义视频事件运行时 —— Linux NVR 与 Windows 11 双版本**

A budget-aware semantic video event runtime for Linux NVR and Windows 11

[![CI](https://github.com/CommitStrip/semantic-camera/actions/workflows/ci.yml/badge.svg)](https://github.com/CommitStrip/semantic-camera/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1379%20passed%2C%2016%20skipped-brightgreen)](tests/)

[**简体中文**](README-CN.md) · [**English**](README.md)

</div>

---

监控摄像头只是"眼睛"——看得见但看不懂。我们给它装上大脑，但这个大脑必须同时满足三个苛刻条件：**快**（报警 ≤ 1 秒）、**省**（长期使用几乎不花钱）、**听话**（一切规则由管理员定义，系统绝不自作主张）。

核心思想：**事件是一等公民；不确定性模型被确定性工程包裹**。快系统（帧差门控 + NanoDet 检测）无论是否配置规则都会发现并记录事件；管理员规则只决定什么值得额外关注与告警。慢系统（本地 VLM）为进行中的事件追加**明确标注的补充描述**——它永远不能改写已记录的事实、压制提醒或解除告警。

## ✨ 核心特性

- **无规则事件发现**——每次出现都成为可追溯的事件事实（开始 / 结束与原因 / 不可变的初始观察），零圈选零规则也照常工作
- **事实性提醒优先**——每个事件产生一条事实性提醒；工作台把「客户端已显示」（自动回执）与「用户确认」（主动点击）分开，两者均持久化、重启保持
- **进行中语义更新，安全标注**——本地 VLM 为进行中事件追加版本化描述（v2、v3…），观察/推断分栏；每个模型版本都呈现为「模型补充描述，可能有误，待结合证据核对」，绝不能取消事件或告警
- **快慢分层**——T0 门控逐帧 0.4ms → T1 检测运动触发 → 告警路径零模型时延；慢系统在预算内工作
- **网格圈选**——方格点选，管理员画格子定义重点管理区域
- **自定义报警模板**——结构条件实时比对
- **双模型通道**——本地 ollama（数据不出本机）/ 云端 OpenAI 兼容 API，每次调用显式确认
- **首次环境基线（Win11）**——向导式版本化场景基线，原始画面哈希核验；识别绝不自动运行、绝不自动变成规则
- **事件即用即归档**——SQLite 全程可审计；工作台仅监听本机回环

## 🧭 两个产品版本

| 版本 | 独立入口 | 产品重点 | 发布门禁 |
|---|---|---|---|
| Linux NVR 版 | `python -m scam.linux_nvr` | 常驻服务、多相机、录像、远程运维、24h 稳态 | Linux CI + systemd + 真机浸泡 |
| Win11 值守工作站版 | `python -m scam.win11` | 本机交互、首次环境基线、事件/确认链、交付打包 | Windows CI + 原生 Win11 验收（文件源闭环已通过；真实 RTSP 待验证） |

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
| 测试 | **1379 passed / 16 skipped** | 本机 Windows 11 全量（2026-09-29）；CI 另有 Linux 3.10 / 3.12 与 Windows 三作业 |
| 告警延迟（结构条件触发） | **≤ 1s** | `tests/test_monitor.py` 端到端断言：目标进入管理格后 1 秒内必须告警（合成帧 + 检测判定路径） |
| T0 帧差门控 | **0.39ms/帧**（P95 0.43ms） | 1080p → 96×54 灰度 → 门控判定，纯 Python；实测 199 帧 |
| T1 检测 | NanoDet-Plus ONNX，输入 416×416 | 权重不随包分发；早期本机实测 23–24ms/次，此后未复测 |
| Win11 文件源闭环 | **79 事件 / 79 提醒 / 79 显示回执 / 1 次用户确认**；事件、版本、回执、确认经真实进程重启全部保持 | 原生 Win11 + 录像素材回放 + 真实 NanoDet ONNX + 真实本地 VLM；**仅文件源，不构成实机摄像头证据** |
| 客户端显示时延（探索性） | 5 样本：2.4–9.5s | 仅统计浏览器页面活跃轮询期间（3s 周期）；样本量不足以出百分位——探索性数据，非稳态结论 |
| 语义描述质量 | **未验证——已记录风险样本** | 5 条模型输出人工帧级比对：1 条忠实、4 条有错（场景误识别、时间戳编造、过度自信标注）。因此界面将全部模型输出标注为未核实补充 |

## ✅ 质量门禁

CI 三个作业（[工作流](.github/workflows/ci.yml)）：

- **test（Linux，Python 3.10 与 3.12）**——部署脚本语法（`bash -n`）、systemd unit 单一真值渲染 + `systemd-analyze verify`、全量测试（含 Linux 服务级 smoke）、Linux NVR 版本契约、发布打包门（敏感面双闸 + 可复现打包自检）
- **test-windows**——全量测试（服务级 smoke 自动跳过）、发布打包 dry-run、平台层 smoke（UTF-8 输出与数据目录）、Win11 入口 smoke、部署脚本 PowerShell 5.1 与 7 双解析

`main` 最近一次 CI：#61（2026-09-23）三作业全绿；本发布提交推送后将重跑同一工作流。

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
  db.py                  SQLite 持久层（事件事实/描述/提醒/升级/基线/区域）
  事件事实层             无规则事件发现、不可变 v1 初始观察、事实性提醒、
                         崩溃窗口启动补账
  semantic_updater.py    进行中语义更新（版本化、安全标注、不可改事实与告警）
  environment.py         首次环境基线（Win11）
  evidence.py            证据索引与路径围栏
  server.py              工作台 HTTP（仅回环）
  sinks.py notify.py     告警出口与通知出口（webhook / MQTT，可选）
  recording.py recorder.py   录像与分段导出
  slow_core.py           慢系统唯一执行核心
  health.py nvr.py       健康水位；常驻入口
  win11*.py              Win11 入口、启动器、安装、环境基线与实机验收
  linux_*.py             运维线：主机体检、备份、升级、回放、浸泡、部署单元渲染
  models.py              VLM 双通道（本地 / 云端，显式 opt-in）
packaging/               Windows 交付：单实例启动器、构建脚本、违禁内容闸门、
                         第三方声明
scripts/                 验收、模型获取与校验、离线测量报告、资源快照
tests/                   pytest（1400+ 用例）
docs/                    运维 Runbook
```

`scripts/measure_report.py` 可把任意事件数据库转为只读的时延/事实测量报告
（时钟来源感知、完整性核对、可重建）。

## 📖 文档

| 文档 | 内容 |
|---|---|
| [运维 Runbook](docs/linux-operations-runbook.md) | 安装 / 升级 / 回滚 / 备份恢复（含人工确认点） |

## ⚠️ 已知限制（诚实清单——v0.1.0-beta）

- **真实 RTSP 摄像头尚未验证**：Win11 全部闭环证据来自录像素材回放。实机摄像头验收需要授权的 RTSP 输入，是下一里程碑；
- **语义描述质量未验证**：5 条模型输出的人工帧级比对中 1 条忠实、4 条有错（场景误识别、时间戳编造、过度自信标注）。界面因此把每个模型版本呈现为未核实补充；模型文本永远不能关闭事件、压制提醒或解除告警；
- Linux 原生运维链路、24 小时浸泡与隐私网络审计**未验证**；双相机与长时间运行证据待补；
- 录像**默认关闭**；需要片段证据时按相机显式开启；
- 检测与嵌入权重不随包分发（`scripts/fetch_models.py`），哈希冻结前 fail-closed 拒绝自动下载；
- 工作台为单管理员回环形态：无认证、无多用户，远程访问走 SSH 隧道；
- Windows CI 只证明自动化兼容；交付 zip 须在真实 Windows 11 机器上构建并验收。

## 🙏 致谢

- [VUS](https://github.com/CommitStrip/video-understanding-skill) —— 唯一上游：感知、预算机制、流服务全部复用
- [NanoDet-Plus](https://github.com/RangiLyu/nanodet) —— 人员检测模型（Apache-2.0）
- [ollama](https://ollama.com) —— 本地 VLM 推理
- [Meta AI](https://ai.meta.com) —— V-JEPA 2 视频表征模型（CC-BY-NC 4.0）

## License

MIT，见 [LICENSE](LICENSE)。
