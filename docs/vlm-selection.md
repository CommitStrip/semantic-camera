# 命名慢脑模型选型记录（2026-09-14）

**结论：默认 `qwen3-vl:2b`（ollama 官方库，Apache-2.0）。** 在本机实测通过命名闭环：
输出严格符合命名规范（`name ≤16 汉字 / conf / matchedBehaviors / undecidable 诚实弃权 /
rationale ≤30 字`），并完成网关帧→命名的全链路验证。

**算力归属（重要更正）**：本机 RTX 3060 Laptop 当前在驱动层不可见（PnP/VideoController
均无此适配器，nvidia-smi 需管理员且报权限错误）——今日全部实测实际运行在
**Intel Iris Xe 核显（Vulkan，共享显存 7.9GB）**；重启用 `OLLAMA_IGPU_ENABLE=1`（默认
丢弃核显）。独显恢复后延迟有望显著低于下表（Vulkan→CUDA）。

## 部署接线

```bash
ollama serve                      # 或安装版开机自启；本机用便携版 %LOCALAPPDATA%\OllamaPortable
ollama pull qwen3-vl:2b           # 1.9GB；4B 备选 3.3GB
cp bridge/config.example.json bridge/config.json   # 填 token
python bridge/server.py           # 仲裁器 = ollama http://127.0.0.1:11434
python scripts/test_local_naming.py qwen3-vl:2b    # 命名探针（抽帧→命名→规范校验+计时）
```

## 实测记录（2026-09-14，Iris Xe 核显 Vulkan，3×320px 关键帧，temperature 0）

| 项 | qwen3-vl:2b | qwen3-vl:4b |
|---|---|---|
| 模型文件 | 1.9 GB（驻留 3.5GB@16k ctx） | 3.3 GB |
| 命名延迟（热态，核显） | 34–66 s（首日 8192ctx 34-36s；16kctx 55-66s） | 81.1 s（8192ctx） |
| 冷加载 | 60–90 s | >90 s（曾超仲裁器超时） |
| 命名输出 | "行人经过/行人过街" + 如实 rationale | 同级，conf 更合理（0.95） |
| 规范符合 / undecidable 诚实性 | ✅ / ✅ | ✅ / ✅ |
| **判定** | **默认** | 备选（质量略优，延迟更高） |

- **命名 SLA（≤30s）在核显上不达标**（P95 55-66s），功能完整但时效降级；独显恢复为达标前提；
- **两个模型不可同时驻留**（6GB 级显存双载后连最小生成都超 100s——重压导致调度失效），生产单模型运行；
- 诚实弃权双向实测：帧黑场 → "画面全黑无有效监控内容"；行为定义不命中 → 照常给普通事件名不硬猜。

## 途中修复（全部落在 `bridge/arbiters.py`，探针驱动定位）

1. **上下文窗爆量**：3×320px 关键帧 = prompt 3491 token（1080p 原帧会膨胀到 6489——
   管线只发 320 宽帧），默认 4096 ctx 被思考链+正文撞满（`done_reason=length`、正文空）
   → `num_ctx: 16384` 留足余量；
2. **思考模型 token 预算**：Qwen3-VL 的 `think:false` 与 `/no_think` 在本栈
   （ollama 0.34 generate/chat 端点）均被无视，思考链长度随 prompt 复杂度波动 →
   `num_predict: 2048` 硬保障（1024 仍会被长思考烧穿）；
3. **conf 占位 0**：2B 对确定命名也输出 conf 0.0 → 非弃权时 conf≤0 与缺失同径回退 0.7；
4. **prompt 语义歧义**：模型曾把"事件名"与"行为命中"绑死，普通事件也被置 null →
   明确"未命中危险行为也必须给普通事件名，undecidable 仅留给画面本身不可用"；
5. `keep_alive: 30m`：命名按预算（30 次/时）稀疏到达，避免每次冷加载。

## 淘汰/备选记录

| 候选 | 许可证 | 判定 | 证据 |
|---|---|---|---|
| Qwen3-VL-4B | Apache-2.0 | ⏸ 备选 | 本机实测热态 81s，超命名 SLA；conf 输出质量更好 |
| Qwen2.5-VL-3B | Apache-2.0 | ⏸ 备选 | 上一代；量级相近但基准不及 Qwen3-VL |
| InternVL3.5-2B/4B | Apache-2.0 | ⏸ 备选 | 小模型基准强，ollama 官方库无、需手工 GGUF 导入，接入摩擦大 |
| MiniCPM-V 4.x | Apache-2.0 | ⏸ | 8B 对 6GB 显存偏紧 |
| Gemma3-4B | Gemma 条款 | ⏸ | 许可较 Apache 重；中文可用 |
| SmolVLM2 / moondream2 | 宽松 | ❌ 淘汰 | 中文能力不足——命名输出是中文硬需求 |
| llama3.2-vision-11B | Llama 条款 | ❌ 淘汰 | 6GB 显存放不下 |

## 网关实测（family gateway，path `cam`，2026-09-14）

- 网关在线（:8080=200）；HLS/WHEP 读路径与鉴权验证通过（mediaMTX cookie 检查 302 正常跟随，
  未授权/无流时返回规范 JSON 错误）；
- **`cam` 凭证为只读**（最小权限按设计生效）：RTSP ANNOUNCE 与 WHIP POST 均 401，
  发布只能走 `http://HOST:8080/u/cam` 浏览器页；
- 当日无推流方在线（轮询 20 分钟 404），实时命名待推流后补；**网关帧→本地命名的
  全链路已用替代帧验证通过**（"人员经过"，65.6s）：

```bash
# 推流方上线后：
HOST=<host> GATEWAY_PASS=<pass> bash scripts/family_stream_check.sh   # 轮询+NanoDet 检出验证
ffmpeg -ss 12 -i "http://<host>:8888/cam/index.m3u8?user=cam&pass=$GATEWAY_PASS" -frames:v 3 gw_%d.jpg
python scripts/test_local_naming.py qwen3-vl:2b --frames "gw_*.jpg"    # 网关帧 → 本地命名
```

注意：`-frames:v 3` 不带 `-ss` 会抓到黑场首帧——探针会诚实拒绝（"画面全黑"），
这是特性不是 bug。
