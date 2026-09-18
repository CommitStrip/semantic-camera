# Win11 部署脚本（PowerShell）
# 用法: 右键 → 使用 PowerShell 运行
# 或:   powershell -ExecutionPolicy Bypass -File install-win11.ps1

Write-Host "=== 语义摄像头 Win11 部署 ===" -ForegroundColor Cyan

# 检查 Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[错误] 未找到 Python——请安装 Python 3.10+" -ForegroundColor Red
    exit 1
}
$pyVer = python --version
Write-Host "[1/4] $pyVer ✓"

# 安装依赖
Write-Host "[2/4] 安装依赖…"
pip install --quiet numpy opencv-python-headless onnxruntime pillow 2>$null

# 生成配置模板
if (-not (Test-Path "cameras.json")) {
    @{
        cameras = @(
            @{
                id = "front-door"
                enabled = $true
                source = "rtsp://admin:PASSWORD@192.168.1.64:554/Streaming/Channels/102"
                detector = @{
                    engine = "onnx"
                    model = "models/person-detector.onnx"
                    classes = @("person")
                    conf = 0.4
                }
                grid = @{ rows = 18; cols = 22 }
                zones = @()
                schedule = @(@{ from = "00:00"; to = "23:59" })
            }
        )
    } | ConvertTo-Json -Depth 5 | Out-File -Encoding utf8 "cameras.json"
    Write-Host "[3/4] cameras.json 模板已生成（请修改 RTSP 地址和密码）"
} else {
    Write-Host "[3/4] cameras.json 已存在（跳过）"
}

# 创建启动快捷脚本
$batContent = @'
@echo off
chcp 65001 >nul 2>&1
title 语义摄像头 · NVR 值守
cd /d "%~dp0.."
python -m scam.nvr
pause
'@
$batContent | Out-File -Encoding utf8 "start-nvr.bat"

Write-Host "[4/4] 部署完成"
Write-Host ""
Write-Host "启动值守: 双击 start-nvr.bat 或命令行运行 python -m scam.nvr" -ForegroundColor Green
Write-Host "工作台: http://127.0.0.1:8600" -ForegroundColor Green
