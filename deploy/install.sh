#!/usr/bin/env bash
# install.sh —— 语义摄像头 NVR 一键部署（Linux）
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== 语义摄像头 NVR 部署 ==="

# 1. Python 环境
if ! command -v python3 &>/dev/null; then
    echo "错误：需要 Python 3.10+"; exit 1
fi
echo "[1/5] Python $(python3 --version | cut -d' ' -f2) ✓"

# 2. venv + 依赖
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet numpy opencv-python-headless onnxruntime pillow
echo "[2/5] 依赖安装 ✓"

# 3. vus 接入（可选——无 vus 时快系统仍可运行）
VUS_DIR="${VUS_DIR:-}"
if [ -n "$VUS_DIR" ] && [ -d "$VUS_DIR" ]; then
    pip install --quiet -e "$VUS_DIR"
    echo "[3/5] vus 已接入 ✓"
else
    echo "[3/5] vus 未安装（跳过——快系统不依赖 vus）"
fi

# 4. 配置模板
if [ ! -f cameras.json ]; then
    cat > cameras.json << 'EOCFG'
{
  "cameras": [
    {
      "id": "front-door",
      "enabled": true,
      "source": "rtsp://admin:PASSWORD@192.168.1.64:554/Streaming/Channels/102",
      "detector": {"engine": "onnx", "model": "models/person-detector.onnx",
                   "classes": ["person"], "conf": 0.4},
      "grid": {"rows": 18, "cols": 22},
      "zones": [],
      "schedule": [{"from": "00:00", "to": "23:59"}]
    }
  ]
}
EOCFG
    echo "[4/5] cameras.json 模板已生成（请修改 RTSP 地址和密码）"
else
    echo "[4/5] cameras.json 已存在（跳过）"
fi

# 4.5 检测模型存在性（缺失时该相机只跑门控——大声告警，绝不静默零检测）
MODEL="$(python3 - << 'EOPY'
import json
try:
    cfg = json.load(open("cameras.json", encoding="utf-8"))
    print(cfg["cameras"][0].get("detector", {}).get("model", ""))
except Exception:
    print("")
EOPY
)"
if [ -n "$MODEL" ] && [ ! -f "$MODEL" ]; then
    echo "警告: 检测模型缺失: $MODEL"
    echo "  请放置 NanoDet-Plus ONNX 模型到该路径（README 有导出说明）；"
    echo "  模型缺失时相机会值守但不会产生检测告警。"
fi

# 5. systemd 服务
if [ -d /etc/systemd/system ]; then
    cat > /tmp/scam-nvr.service << EOSVC
[Unit]
Description=语义摄像头 NVR 值守
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/.venv/bin/python -m scam.nvr
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOSVC
    sudo cp /tmp/scam-nvr.service /etc/systemd/system/
    sudo systemctl daemon-reload
    echo "[5/5] systemd 服务已注册（sudo systemctl enable --now scam-nvr 启动）"
else
    echo "[5/5] 非 systemd 系统——请手动启动: python -m scam.nvr"
fi

echo ""
echo "=== 部署完成 ==="
echo "启动: sudo systemctl enable --now scam-nvr"
echo "工作台: http://127.0.0.1:8600（NVR 本机；远程用 ssh -L 8600:127.0.0.1:8600 隧道）"
echo "日志: journalctl -u scam-nvr -f"
