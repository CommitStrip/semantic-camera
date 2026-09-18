# 语义摄像头 v2 · Frigate 对标路线图

> 基准：[Frigate 0.14+](https://github.com/blakeblackshear/frigate)（36k stars，6287 commits）
> 日期：2026-09-18
> 原则：对齐 Frigate 的**核心 NVR 能力和工程质量**，保留并强化 semantic-camera 独有的语义理解能力

---

## 0. 总体差距

| 维度 | Frigate | semantic-camera v2 | 差距 |
|---|---|---|---|
| 多相机 | 不限数量，YAML 声明式 | cameras.json 但 UI/API 不完整 | **中** |
| 录像 | 24/7 + 事件片段 + 导出 MP4 | ❌ 零录像 | **大** |
| 检测器 | 插件式（Coral/GPU/CPU/OpenVINO） | NanoDet ONNX 固定 | **中** |
| 运动门控 | 精细（阈值/遮罩/区域/帧 skip） | 基础（阈值+面积双闸） | 小 |
| 区域/遮罩 | zones + motion masks + object masks | 仅 zones（网格） | **中** |
| 审查时间线 | 缩略图卡片流+筛选+自动标记已审 | 骨架 HTML | **大** |
| 语义搜索 | CLIP 缩略图+描述嵌入→自然语言查 | V-JEPA 嵌入有产出但无查询接口 | 中 |
| GenAI 描述 | OpenAI/Ollama/Google 自动生成 | VLM 命名已有但无自动场景描述 | 小 |
| 人脸识别 | 内置 | ❌ | 低 |
| 车牌识别 | 内置 | ❌ | 低 |
| 鸟类分类 | 内置 | ❌ | 低 |
| 通知 | MQTT + Webhook + HA + Telegram | 仅 webhook | **中** |
| 语义命名 | ❌（只有"person 80%"） | **三层文本**（短名/细节/理由） | **我们独有** |
| 预算制 | ❌（无成本控制） | **三本分账**（仲裁/命名/判定） | **我们独有** |
| 习惯化 | ❌（重复事件也要 VLM） | **重复场景零 VLM 自命名** | **我们独有** |
| 开放集行为 | ❌（只有预训练类别） | **管理员自然语言定义** | **我们独有** |
| 认证 | 内置 auth + TLS | ❌ | **大** |
| 测试 | 5,000+ 测试，90%+ 覆盖 | 35 测试，37% 覆盖 | **大** |

**结论**：差距不在语义能力（我们独有且更强），而在 **NVR 基础设施**（录像/回放/多相机/审查 UI/认证/通知/测试覆盖）。

---

## 1. 冲刺规划（4 个冲刺，从"能跑"到"Frigate 级"）

### 冲刺一：修 BUG + 录像 + 审查时间线（最紧迫）

| 项 | 修复/新增 | 来源 |
|---|---|---|
| SC-001 nvr.py 缺导入 + signal 线程 | nvr.py | QA |
| SC-002 vus 依赖声明 | pyproject.toml | QA |
| SC-003 复用 Monitor.step() | nvr.py | QA |
| SC-004 NanoDet letterbox 逆变换 | detect.py | QA |
| SC-005 多区域独立判定 | monitor.py | QA |
| SC-006 告警边沿触发+冷却 | monitor.py | QA |
| SC-011 conf 校验字段 | config.py | QA |
| **告警帧缩略图** | monitor.py → events 表 | 新增 |
| **审查时间线 UI** | web/index.html | 新增 |
| **误报标记按钮** | web/index.html | 新增 |
| **录像分段（ffmpeg 流拷贝）** | recorder.py | 新增 |
| **保留策略双闸** | recorder.py | 新增 |

**验收**：35→45+ 测试全绿；告警附带缩略图；误报标记即时生效；录像分段正确产出。

### 冲刺二：多相机 + 工作台实装

| 项 | 内容 |
|---|---|
| 多相机值守网格 | 值守页 N×M 网格，每格一路快照+告警徽章 |
| 六视图导航 | 顶栏 tab：值守/事件/模式库/系统 |
| 事件筛选 | 按相机/时间/类型/严重度 |
| 模式库视图 | 模式列表 + 管理员改名/确认 |
| 系统健康页 | 相机状态/存储水位/模型通道/运行时长 |
| API 认证 | Bearer token |

**验收**：2+ 路相机同时在值守网格；事件筛选正确；模式库与 DB 一致。

### 冲刺三：MQTT + 通知 + 语义搜索

| 项 | 内容 |
|---|---|
| MQTT 出口 | paho-mqtt 告警/事件/状态发布 |
| 语义搜索 UI | V-JEPA 嵌入余弦搜索历史事件 |
| GenAI 场景描述 | VLM 自动生成事件细节描述（已有基础） |
| webhook 通知 | 告警 POST 到管理员指定 URL |

**验收**：MQTT 消息被 HA 收到；语义搜索返回相关事件；webhook 告警可触发外部动作。

### 冲刺四：24h 浸泡 + 五线验收报告

| 项 | 内容 |
|---|---|
| 连续值守 | 接真实 RTSP，运行 acceptance.py --duration 86400 |
| 内存有界 | 每小时采样 RSS，确认平台期 |
| 断流自恢复 | 拔网线 30s 再插，自动重连+告警续发 |
| 快 ≤1s | 告警延迟统计（P50/P95/P99） |
| 私 | 代码审计确认无外部上传 |
| 产出 | 五线验收报告 |

---

## 2. 架构对齐 Frigate（保留差异）

| Frigate 模块 | semantic-camera 对应 | 状态 |
|---|---|---|
| frigate/object_detection | scam/detect.py + gate.py | ✅ 已有 |
| frigate/motion | scam/gate.py | ✅ 已有（基础版） |
| frigate/tracking | scam/track.py | ✅ 已有 |
| frigate/zones | scam/zones.py + verdict.py | ✅ 已有 |
| frigate/events | scam/segments.py | ✅ 已有 |
| frigate/api | scam/server.py | ✅ 已有（需扩充） |
| frigate/review | ❌ 无 | 冲刺一 |
| frigate/recording | ❌ 无 | 冲刺一（可选） |
| frigate/mqtt | ❌ 无 | 冲刺三 |
| frigate/genai | scam/naming.py（VLM 命名） | ✅ 已有（不同实现） |
| frigate/semantic_search | scam/embed.py（嵌入产出，无查询） | 部分已有 |
| frigate/notifications | ❌ 无 | 冲刺三 |
| frigate/auth | ❌ 无 | 冲刺三 |
| frigate/exports | ❌ 无 | 冲刺一（可选） |
| frigate/birdseye | ❌ 无 | 低优先级 |

---

## 3. 差异化定位（不跟 Frigate 卷的功能）

| 能力 | semantic-camera | Frigate |
|---|---|---|
| **语义事件命名** | VLM 三层文本（短名/细节/rationale） | ❌ 只有类别标签 |
| **习惯化** | 重复场景零 VLM 自命名 | ❌ 每次都跑检测+分类 |
| **预算制** | 三本分账（仲裁/命名/判定），成本硬上限 | ❌ 无成本控制 |
| **开放集行为** | admin 自然语言定义"什么算危险" | ❌ 只有预训练类别 |
| **模型双通道** | 本地 ollama / 云端 API 一键切换 | 本地为主 |
| **四态裁决** | 宁可弃权不虚报（escalate 语义） | ❌ 二值（检测到/未检测到） |

**核心差异总结**：Frigate 告诉你"画面里有个人"；semantic-camera 告诉你"有人进了你圈的重点区域，滞留 5 秒，已告警，这是他做的事的细节描述"。前者是检测，后者是语义理解。
