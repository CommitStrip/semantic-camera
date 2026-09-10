# semantic-camera — 语义摄像头 · 场所模式端侧实时视频理解

[![CI](https://github.com/CommitStrip/semantic-camera/actions/workflows/ci.yml/badge.svg)](https://github.com/CommitStrip/semantic-camera/actions/workflows/ci.yml)

[English](README.md) | **简体中文**

**A budget-aware, mode-configurable edge vision event runtime**（预算受控、模式可配置的端侧视觉事件运行时）——**语义摄像头 = NVR 标准件之上的场所语义判别层**。把一路实时视频流（海康 RTSP / 手机相机 / 本地视频）变成端侧实时的语义理解与告警：帧差运动门控 → 触发式检测 → 恒速跟踪 + 多帧确认 → 全自动语义判别 → 按场所模式包决定告警与处置。判别按**场所模式包**组织——扩展新场所只需在 `web/mode-packs.js` 新增数据（+ 可选模型/判别头文件），**核心流水线零改动，且由 CI 双模式验收与源码洁净度测试强制**。平台化设计（多相机调度 / 时空规则引擎 / 开放集 / 隐私合规 / 持续学习治理 / 评测闸门）见 [docs/semantic-camera-design.md](docs/semantic-camera-design.md)。

本仓是库系主线：`vus` 为通用视频理解引擎，`rvs` 为机器人增量层，前身仓 `anti-drone-monitor`（反无人机单场景演示）已冻结并由此仓继承演进。

三条设计红线：**判别流水线全自动运行、无人工判定环节**（判别不等人；但"自动理解 ≠ 自动执行一切"——人工复核不阻塞实时管线，高影响外部效果是否需人工确认由处置策略决定）；**成本有硬上限**（预算制，不随时长线性增长）；**新增场所不改核心逻辑代码**（平台成立判据；模式选择 fail-closed，未知模式拒绝布防、绝不静默回退）。

**宣传口径**：当前算法是"可配置事件摄像头 + 场所判别头"——不宣称自动理解所有场景、零误报、人类级语义理解或"零代码接入"（准确说法：新增场所不改核心逻辑代码，仍需在注册表加数据并部署）；只报告实测数据，未测项标"待回填/设计态"。

当前验证状态：初始化探针头离线精度 **98.15%**（162 张权威 Drone-vs-Bird 样本，证据 `web/jepa_probe_init.json`：acc=0.9815, n_train=162, dim=768，自前身仓实测继承）；**人员检测模型已在真实街景验证**：NanoDet-Plus-m-1.5x@416（Apache-2.0）对 CC 授权的涩谷十字路口视频抽帧检出 person 7~58 个/帧，Python ORT CPU 推理 23-24ms/帧（选型与实测详见 [docs/model-selection.md](docs/model-selection.md)）；WHEP 信令已用本地 MediaMTX v1.20.0 + H.264 测试流完成端到端验证；**57 例单元测试 + GitHub Actions CI 全绿**（含双模式端到端验收、核心源码洁净度、证据事件 schema 契约、模式选择 fail-closed、模型资产完整性闸门）。浏览器 wasm 端到端帧率/延迟实测**待回填**。

## 核心能力

| 能力 | 说明 |
|------|------|
| 实时检测 | 帧差运动门控(快) → 触发式检测(慢)：有运动 400ms 即检、无运动 5s 巡检兜底，运动面积门槛 0.003 抗传感器噪声 |
| 目标跟踪 | IoU + 中心距离关联 + 恒速预测（大检测间隔不丢轨迹），多帧确认(≥2 次)降假阳性；已确认目标 12s 存活窗，悬停不丢 |
| 全自动语义判别 | 四态裁决（判别/检测器权威双路径）：告警 / 待仲裁 / 判明非目标 / 静默——**无人工判定环节**；灰区入仲裁队列（预算硬上限），高置信双信号一致自动自训练探针 |
| 场所模式包 | 模式 = 数据 + 校验器：`?mode=` 选择，新场所零代码接入；领域词只允许存在于 `web/mode-packs.js`（CI 洁净度测试把守）；`validatePack` fail-closed，坏配置拒绝布防 |
| 证据事件 | `sc.evidence/v1` 版本化事件信封：稳定事件 ID、双时间戳（源/处理）、模式包配置指纹、策略版本、模型 sha256、检测置信与判别置信分立、告警附裁剪帧及其内容哈希——从"帧"到"可审计的证据事件" |
| 区域规则引擎 | 多边形 zone（归一化坐标）：进入 + 滞留达标（dwellMs）才升级告警，区外目标降级为记录；overlay 只读叠加展示 |
| 可插拔检测头 | `HEAD_DECODERS` 注册表：`yolo8head`（无 objectness）/ `nanodethead`（GFL 分布回归）/ `mock`（确定性时间线）——解码头是 provider registry 的键，扩展不改核心 |
| vus 桥仲裁（M2） | 灰区案件升级慢脑（CLIP 零样本 / ollama VLM，可插拔）：结论伪标签回灌探针、案件归档 JSONL；桥断即边缘自治，绝不虚报 |
| 资产单源治理 | 模型/运行时单源 `assets/`（manifest 含 sha256/许可证/来源），构建期 staging 到三副本，CI 哈希闸门防静默漂移 |
| 布防时间表 | 模式包可声明布防窗口（支持跨零点）；非布防时段告警降级为记录、仲裁不占预算 |
| 丝滑变焦 | 捏合/滑块/按钮 + **目标跟随**自动居中，平滑插值 1×-8× |
| 距离估算 | 针孔模型按类别尺寸粗估（无人机 0.35m / 鸟 0.20m）；数字变焦是中心裁剪，不影响读数 |
| 数据可追溯 | IndexedDB 落盘 + CSV/JSON 导出 + 原生桥接落盘（Android JSONL / 鸿蒙 CSV）；检出→裁决→仲裁→自训练全链路留痕 |

## 系统组成

```
semantic-camera/
├── web/index.html        # 共享 HTML5 核心（两端 WebView 复用；不含领域词）
├── web/core.js           # 纯逻辑核心（校验/跟踪/门控/裁决/队列/解码头注册表/区域引擎/证据事件）
├── web/mode-packs.js     # 场所模式包注册表（纯数据，领域词唯一居所）
├── assets/models/        # 模型单源（manifest.json 含 sha256/许可证/来源）
├── assets/runtime/       # ORT wasm 运行时单源
├── gateway/              # MediaMTX 网关：海康 RTSP → WebRTC(WHEP)/HLS
├── bridge/               # vus 慢脑仲裁桥（M2）：灰区案件 → CLIP/ollama 仲裁 → 回灌
├── android/              # Android 工程（Kotlin WebView 封装 + 遥测落盘）
├── harmony/              # HarmonyOS(NEXT) 工程（ArkWeb 封装 + 遥测落盘）
└── docs/                 # 平台设计文档 + 模型选型记录
```

> 修改 `web/` 下共享文件后，运行 `bash scripts/sync-web.sh` 同步 android/harmony 打包副本；CI 用 `--check` 强制校验三副本一致性。

## 场所模式包

模式包 = 纯数据：检测模型（可插拔 onnx/mock）+ 可选判别头 + 告警规则 + 布防时间表 + 预算，装载时经 `validatePack` 全量校验（fail-closed：坏配置拒绝布防，不带病上线）。**平台成立判据：新增场所不改核心代码**——`restricted-area` 第二模式包已由 CI 双模式端到端测试验证抽象。首波场所目录：

| 模式包 | 判别任务 | 价值（误报杀手） | 状态 |
|---|---|---|---|
| **airfield 净空防黑飞** | 鸟 / 机 | 鸟群与飘动物不告警，黑飞必报；灰区不虚报 | ✅ 完整落地 |
| **restricted-area 限制区域闯入** | 人员（NanoDet-Plus@416，Apache-2.0；检测器权威，无判别头） | 夜间布防 + 区域规则（进区滞留 2s 升级）+ 弃权语义 | ✅ 真实模型 + zone 规则（真实街景抽帧实测 7~58 检出/帧） |
| **depot 油库烟火** | 烟 / 雾·晚霞 | 烟火误报是行业第一痛点 | M3 |
| **site 工地合规** | 戴盔 / 未盔 | 人形检测无法区分 | M3 |
| **campus 校园周界** | 人 / 影·物 | 夜间低照度误报抑制 | M3 |
| **farm 养殖驱避** | 鸟 / 兽 / 人 | 分类决定驱避策略 | M5 |

## JEPA 全自动判别 + 自动进化（已接入）

在 YOLO 定位之上叠加 **JEPA 风格自监督判别**（`web/dinov2_vits14_feat.onnx`，85MB，DINOv2-ViT-S 特征提取器 + `web/jepa_probe_init.json` 线性探针头）：

- **四态全自动裁决**：探针输出 P(正类)，裁决器给出 `alert`（目标侧高置信 → 告警）/ `escalate`（目标侧置信不足 → **弃权待仲裁**，宁可不报不可虚报）/ `clear`（判明非目标 → 抑制告警）/ `suppress`（静默）；判别结果未出前检测器权威（防漏报）。
- **自动进化（能力已实现，默认关闭）**：在冻结特征上，当 logreg 头与原型距离双信号一致且置信 ≥0.90 时可自动更新探针头（质心滑动平均 + 单步 SGD）。**默认 `enabled:false`**——双信号并非独立证据，在冻结评测集、版本化回滚、开放集拒识等治理栈完备（M5）前，不得默认在线修改判别头；届时按场所显式开启。学习状态按模式包隔离（`jepa_probe_v2:<modeId>`），场所间伪标签不互相污染。"重置学习"恢复初始权重（运维操作）。人工判定按钮已废除。
- **灰区仲裁队列**：`escalate` 案件按预算硬上限（20 件/小时）+ 轨迹去重（15s TTL）排队；M2 接入 vus 慢脑 VLM 仲裁后，结论作为伪标签回灌探针（协议见设计文档 §8）。桥不可达时边缘全功能自治。

## 海康威视监控接入（已验证）

- **分工**：MediaMTX 拉海康 RTSP（`gateway/mediamtx.yml` 配置相机 IP/账号）→ WebRTC/WHEP(8889) 或 HLS(8888)；`whep-client.js` 实现标准 WHEP 信令（指数退避重连），失败自动回退 HLS。
- **接入方式**：App 点"🔌 海康"填网关地址与流路径（如 `http://网关IP:8889` + `cam1`），连接后复用同一套检测+判别管线。
- **海康 RTSP 地址**：主码流 `rtsp://用户:密码@IP:554/Streaming/Channels/101`，子码流 `.../102`；建议主码流（1080p H.264）检测，H.265 相机需转码（见 `gateway/README.md`）。
- 已用本地 MediaMTX v1.20.0 + H.264 测试流完成 **WHEP 信令端到端验证**（OPTIONS→POST→PATCH→DELETE 全通过）。

## 快速体验（浏览器 / 手机）

```bash
cd web && python3 -m http.server 8899
# 手机同网段访问 http://<电脑IP>:8899/index.html
# 或直接浏览器打开 web/index.html
```

- 点击 **开始监控** 调用手机相机；或 **📁 视频** 载入本地视频回放；**🔌 海康** 接入真实监控流。
- 点击 **记录** 打开遥测面板，运行中实时累积事件；**导出 CSV/JSON** 下载记录。
- 变焦滑杆 / ＋－按钮 / 双指捏合直接操作；开启 **目标跟随** 变焦自动锁住已确认目标。

## 双端原生壳

### Android 端

见 `android/README.md`。核心用 WebView 加载共享 `index.html`，`JsBridge` 把遥测以 JSONL 写入应用私有目录便于追溯；相机经 `WebChromeClient.onPermissionRequest` 显式授予。

### 鸿蒙端

见 `harmony/README.md`。核心用 ArkWeb 组件加载，`javaScriptProxy` 把遥测写入沙箱 CSV；相机经 `onPermissionRequest` 授权 + `EntryAbility` 运行时请求 `ohos.permission.CAMERA`。

> 说明：本工程为**可运行的真实推理核心 + 双端原生壳**。`web/` 核心可独立运行于任意手机浏览器验证全部功能；两端原生壳需在 Android Studio / DevEco Studio 中构建安装（仓库不附带构建产物）。

## 开发：测试、CI 与多端副本同步

```bash
node --test tests/core.test.mjs     # 57 例单测（node:test，零依赖）
python scripts/verify_models.py    # 模型资产 sha256 完整性校验（fail-closed）
bash scripts/sync-web.sh            # web/ → android assets + harmony rawfile
bash scripts/sync-web.sh --check    # 只校验一致性（CI 同款）
```

CI（node 20/22 矩阵）：JS 语法检查 → 单元测试 → 三副本一致性校验。纯逻辑（配置/校验/IoU/跟踪器/门控/估距/四态裁决/仲裁队列/布防时间表/探针学习数学/mock 检测器/证据事件）全部抽在 `web/core.js`，零 DOM 依赖可直接单测。两个特色测试：**双模式端到端验收**（同一核心管线跑通 airfield 与 restricted-area 两个模式包，平台抽象的持续证明）与**核心源码洁净度**（core.js 与内联脚本不得出现场所领域词，防止"名字平台化、代码单场景化"回潮）。

## 性能与验证状态

| 项 | 状态 |
|----|------|
| WHEP 信令端到端 | ✅ 已验证（MediaMTX v1.20.0 + H.264 测试流，OPTIONS→POST→PATCH→DELETE 全通过） |
| 探针头离线精度 | ✅ 98.15%（162 样本，`web/jepa_probe_init.json`，自前身仓实测继承） |
| 单元测试 / CI | ✅ 57 例全绿（含双模式验收、洁净度、schema 契约、fail-closed、资产完整性闸门），node 20/22 矩阵 |
| 人员模型真实街景 | ✅ NanoDet-Plus@416 抽帧检出 7~58 person/帧，CPU 23-24ms/帧（[选型记录](docs/model-selection.md)）；浏览器 wasm 帧率 ⏳ 待回填 |
| 真机帧率/延迟 | ⏳ 待回填——遥测已逐帧采集 `detMs/trackMs/motionRatio`，导出 CSV/JSON 即为实测数据 |

模型体积与策略：YOLOv8s fp32 43MB + DINOv2 85MB，wasm 端单次推理为秒级——因此检测是**触发式**（门控+冷却）而非逐帧，JEPA 只对确认目标判别且懒加载。

**int8 量化实测结论（2026-09-06，`scripts/quantize_models.py`）**：现模型为 opset 12 的自定义导出，**量化后不可用**——QOperator 路径体积 42.7→10.9MB、推理 62→34ms（1.8×），但 NMS 后检出数 41→0（输出恒为零）。校验工具已内置任务级闸门（检出数不降 10% 且 IoU≥0.8 才允许切换）防止此类静默失效混入。帧率提升需要以现代 opset 重导出 yolov8n（预期体积/耗时再降一个量级），DINOv2 int8 同样受量化器算子兼容性限制保持 fp32（它只对确认目标运行，开销已可控）。

## 平台路线图

里程碑 M1（判别自动化）→ M1.5（独立建仓+配置治理）→ M1.6（平台化收敛：核心去领域化 + 双模式验收 + 证据事件）→ **M1.7（溯源加固：模式选择 fail-closed + 证据溯源字段 + 自训练默认关闭，本轮）** → **P1-①②（restricted-area 真实模型+区域规则 / 模型资产单源化，本轮）**→ M2（vus 桥仲裁回灌）→ M3（时空规则引擎+开放集+油库烟火包）→ M4（多相机调度+健康监控）→ M5（复训闭环+评测闸门+告警出口+许可决策——自训练开启的前置）→ M6（单盒多路网关）。细节与风险见 [docs/semantic-camera-design.md](docs/semantic-camera-design.md)。

## 平台与硬件

浏览器需支持 WASM 与 WebRTC（Android 8+ WebView / 现代桌面浏览器均可）；鸿蒙端需 HarmonyOS NEXT + ArkWeb。无 GPU 依赖，推理全部 wasm CPU。

## 致谢与版权

- [MediaMTX](https://github.com/bluenviron/mediamtx)——RTSP → WebRTC/HLS 流媒体网关（MIT）。本仓库仅在 `gateway/` 提供配置与启动脚本。
- [onnxruntime-web](https://github.com/microsoft/onnxruntime)——wasm 端推理引擎（MIT）。
- [hls.js](https://github.com/video-dev/hls.js)——HLS 回退播放（Apache-2.0）。
- [NanoDet-Plus](https://github.com/RangiLyu/nanodet)（Apache-2.0）——人员检测模型（person-detector.onnx 为官方 COCO 预训导出，见 docs/model-selection.md）。
- [DINOv2](https://github.com/facebookresearch/dinov2) ViT-S/14（Meta AI）——判别特征提取器；上游代码 Apache-2.0，官方权重为 CC-BY-NC 4.0（非商业）。本仓库的 `dinov2_vits14_feat.onnx` 为其特征塔导出，再分发与商用请自行核实上游条款。
- [YOLOv8 / ultralytics](https://github.com/ultralytics/ultralytics)——检测模型架构（AGPL-3.0）。本仓库的 `yolov8s-drone.onnx` 为在其架构上微调导出的无人机检测权重，再分发与商用须遵守 AGPL-3.0 及上游条款。

## License

MIT © 2026（适用于仓库代码；仓库内捆绑的模型权重 `*.onnx` 许可随上游，见上节）
