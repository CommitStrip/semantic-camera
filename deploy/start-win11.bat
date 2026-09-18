@echo off
chcp 65001 >nul 2>&1
title 语义摄像头 · NVR 值守

REM 检查 Python
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未找到 Python——请安装 Python 3.10+
    pause
    exit /b 1
)

REM 安装依赖（如果缺失）
pip show numpy >nul 2>&1 || pip install numpy opencv-python-headless onnxruntime pillow

REM 启动 NVR 值守 + 工作台
echo [启动] 语义摄像头 NVR 值守…
echo [工作台] http://127.0.0.1:8600
python -m scam.nvr

pause
