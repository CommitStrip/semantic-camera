# 语义摄像头 NVR 部署指南

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

1. 创建 venv 并安装依赖（numpy/opencv-python/onnxruntime/pillow）
2. 安装 vus（本地路径或 pip）
3. 生成 cameras.json / venue.json 模板
4. 注册 systemd 服务（scam-nvr.service）
5. 输出工作台地址 http://<NVR-IP>:8600

## 首次使用流程

1. 浏览器打开 http://<NVR-IP>:8600
2. 全屏磨砂门 → 点【开始环境识别】
3. 识别完成后 → 圈选编辑器 → 点格子圈重点区域 → 绑定规则模板
4. 保存 → 值守开始
