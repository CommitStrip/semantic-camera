# 人员检测模型选型记录（P1-①，2026-09-10）

**结论：选用 NanoDet-Plus-m-1.5x@416 官方 ONNX**（`assets/models/person-detector.onnx`，9,893,045 字节）。

- 来源：https://github.com/RangiLyu/nanodet/releases/download/v1.0.0-alpha-1/nanodet-plus-m-1.5x_416.onnx
- 许可证：仓库 Apache-2.0；权重为官方发布资产（COCO 预训，person=类 0）
- 质量：COCO mAP 44.5（NanoDet-Plus-m-1.5x@416，官方模型动物园口径）
- 部署口径：输入 `[1,3,416,416]`，RGB/255，短边等比 + 114 灰底 letterbox；输出 `[1,3598,112]`
- 解码契约（依据 `nanodet/model/head/nanodet_plus_head.py::_forward_onnx`，导出图内已对 cls 过 sigmoid）：
  - 列布局 `[cls80 | reg32]`，级别序 strides `[8,16,32,64]`，锚点数 52²+26²+13²+7²=3598
  - reg：每 4×8 bins softmax → 投影 `[0..7]` → ltrb 距离 × 步长 → `xyxy = [cx-l, cy-t, cx+r, cy+b]`
  - 本仓实现：`web/core.js` `decodeNanoDetHead`（单测覆盖）

## 淘汰记录（淘汰制）

| 候选 | 许可证 | 判定 | 证据 |
|---|---|---|---|
| **YOLOX-nano/tiny（0.1.1rc0）** | Apache-2.0 | ❌ 淘汰 | 官方 .pth 经官方 demo.py、自导 ONNX（opset13）、**官方自带 ONNX** 三路验证：objectness 列在现代栈（torch 2.14 / ORT 1.29）上恒≈0，dog/person 两图均无检出；obj_preds 偏置 -2.16/-0.64/-0.13 与观测 sigmoid(-8) 一致，判为该 release 资产与现行栈不兼容 |
| **RF-DETR-N/S** | 代码与 N/S 权重 Apache-2.0（XL/2XL 为 PML 1.0） | ❌ 淘汰 | 30.5M+ 参数 transformer，ONNX 体积与 wasm CPU 延迟必然超 20MB/1.5s 门槛（未实测即出局，性能架构性） |
| **PP-YOLOE（PaddleDetection）** | Apache-2.0 | ⏸ 备选 | 需 paddle2onnx 工具链，Windows 构建成本高；NanoDet 已满足则不引入 |
| **YOLOv8/v9/v10（ultralytics 系）** | AGPL-3.0 | ❌ 排除 | 许可证传染，违背"零 AGPL 新增"红线 |

## 备选递补顺序

1. NanoDet-Plus-m@416（4.79MB，mAP 41.1，同仓同解码）——若 1.5x 版 wasm 延迟超标
2. PP-YOLOE-s（paddle2onnx）
3. RT-DETRv2（Apache-2.0，lyuwenyu 仓）——transformer，wasm 性能风险同 RF-DETR

## 实测记录（2026-09-10）

| 项 | 结果 |
|---|---|
| Python ORT CPU 推理 | 23-24ms/帧（416×416，桌面 CPU，wasm 代理指标） |
| 真实街景检出 | 涩谷十字路口视频（CC BY-SA 4.0，© Basile Morin，出处 [Commons](https://commons.wikimedia.org/wiki/File:Shibuya_Crossing,_Tokyo,_Japan_(video).webm)）抽帧：person 7~58 个/帧（conf>0.4），跨 1920×1080 三抽样帧 |
| JS 解码等价性 | 真实模型输出张量喂 `web/core.js decodeNanoDetHead` + `nms`：与 numpy 参照逐 conf 一致（0.676），NMS 后单框落位准确 |
| 模式包阈值 | `confThresh: 0.4`（按实测分布取值，远距小目标召回优先；告警仍受 zone/dwell/布防/检测器权威闸门 0.6 层层约束） |
| 浏览器 wasm 帧率/延迟 | ⏳ 待回填（浏览器端到端手测协议见 README 快速体验） |

本地测试素材：`web/test_person.webm`（57.7MB，不入库，`.gitignore` 已覆盖 `web/test_*`）。CC BY-SA 4.0 合规口径：仅本地验证使用；若今后随仓库分发截图/片段，须附带署名与同享声明。
