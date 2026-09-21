# 语义摄像头 Linux NVR 版部署指南

本文件只描述 Linux NVR 版。Win11 值守工作站使用
`deploy/install-win11.ps1` 和 `deploy/start-win11.bat`，两版不再共用启动入口。

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
