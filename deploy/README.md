# 语义摄像头部署指南（Linux NVR 版 + Win11 值守工作站）

本文件以 Linux NVR 版为主；Win11 值守工作站的安装、启动与 R3 两阶段原生重启验收见
文末「Win11 值守工作站」一节。两版不再共用启动入口。

## 前置条件

- Linux 设备（Debian/Ubuntu 推荐），Python 3.10+
- 至少一路 RTSP 摄像头（同网段）
- ollama 已安装（可选，用于 VLM 命名）

## 一键部署

```bash
# 在开发机上打包
cd 语义摄像头
tar czf scam-deploy.tar.gz --exclude='.git' --exclude='__pycache__' \
    --exclude='*.onnx' --exclude='storage' --exclude='.mimosa' .

# 拷到 NVR
scp scam-deploy.tar.gz user@nvr:/opt/

# 在 NVR 上
ssh user@nvr
cd /opt && mkdir -p scam && tar xzf scam-deploy.tar.gz -C scam && cd scam
bash deploy/install.sh
```

## install.sh 做的事

1. 创建 venv 并安装依赖（numpy/opencv-python/onnxruntime/pillow）+ 项目本身（`pip install -e .`）
2. 安装 vus（可选，本地路径或 pip；缺席时快系统用 cv2 回退源照常值守）
3. 生成 cameras.json 模板（唯一手工维护点）
4. 检测模型存在性检查（缺失时大声提示：该相机只跑门控，不产生检测告警）
5. systemd 服务注册——unit 内容由 `python3 -m scam.linux_unit render` 渲染
   （单一真值源，含显式运行用户/绝对路径/Restart=always/RestartSec=5/
   PYTHONUNBUFFERED=1/network-online 等待），本目录不放静态副本
6. 输出工作台地址 http://<NVR-IP>:8600（默认仅回环，远程走 SSH 隧道）

### 无 sudo 预览 unit（dry-run）

```bash
python3 -m scam.linux_unit render --user "$USER" --workdir "$(pwd)"
```

自定义服务运行用户：`SERVICE_USER=camsvc bash deploy/install.sh`。
CI 对同一渲染结果执行 `bash -n` 与 `systemd-analyze verify`（tests/test_linux_unit.py
断言必需键位；服务级行为冒烟见 tests/test_linux_service_smoke.py，仅 Linux 运行）。

## 首次使用流程

1. 浏览器打开 http://<NVR-IP>:8600
2. 全屏磨砂门 → 点【开始环境识别】
3. 识别完成后 → 圈选编辑器 → 点格子圈重点区域 → 绑定规则模板
4. 保存 → 值守开始

## Win11 值守工作站

```powershell
# 安装：创建 .venv、安装依赖、生成 start-nvr.bat
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\install-win11.ps1

# 启动值守（首次启动会打开本机摄像头接入向导，摄像头地址等由向导写入用户目录）
start-nvr.bat
```

### R3 两阶段原生重启验收

`deploy/run-win11-r3-acceptance.ps1` 只包装既有验收驱动
`python -m scam.win11_r3_acceptance` 的 before / after 两个阶段，兼容 Windows
PowerShell 5.1 与 PowerShell 7。它只以只读回环方式访问工作台：不启动/停止/重启/探测
任何进程，不访问摄像头凭据，不修改配置与区域。

```powershell
# 1) 重启前：采集事实并独占写状态文件（默认 http://127.0.0.1:8600）
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\run-win11-r3-acceptance.ps1 -Phase Before

# 2) 人工重启 Win11 值守应用，等运行日志提示工作台恢复在线

# 3) 重启后：复核事实是否仍成立并原子发布报告
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\run-win11-r3-acceptance.ps1 -Phase After
```

默认产物（可用 `-EvidenceRoot` / `-StateFile` / `-ReportFile` 改到别处；已存在的产物一律
拒绝覆盖，驱动自身的 no-clobber 仍是最终边界）：

| 产物 | 默认路径 |
|---|---|
| 状态文件 | `%LOCALAPPDATA%\semantic-camera\acceptance\win11-r3-state.json` |
| 报告文件 | `%LOCALAPPDATA%\semantic-camera\acceptance\win11-r3-report.json` |

退出码：`0` 通过 / `1` 门禁未过 / `2` 前置条件失败（以上三个都是 Python 驱动原样透传）；
`3` 表示脚本在调用 Python 之前就拒绝了（阶段非法、地址非法、缺 LOCALAPPDATA、产物已存在、
解释器不可用）。`3` 与驱动的 `0/1/2` 互不重叠，因此“退出码是 `0/1/2`”可直接判定驱动确实跑过。

其他参数：

- `-BaseUrl http://127.0.0.1:8600`：只接受 http + 回环主机（`127.0.0.1` / `localhost` / `::1`）
  + 显式端口，且不得携带用户信息、路径、查询或片段；仅 Before 使用。
- `-PythonCommand <解释器路径>`：默认优先 `<仓库>\.venv\Scripts\python.exe`，否则用 PATH 上的 `python`。

维护提示：该 `.ps1` 的源码保持纯 ASCII、不加 BOM，因为 Windows PowerShell 5.1 会用本机
ANSI 代码页解析无 BOM 脚本；如确要加入中文文本，请在同一次改动里补回 UTF-8 BOM。

边界：该脚本只产生 R3 原生重启**候选**证据；真实 RTSP、真实模型质量、告警延迟、干净安装
与长稳仍需在目标机上实测，脚本与驱动都不扩大任何结论。
