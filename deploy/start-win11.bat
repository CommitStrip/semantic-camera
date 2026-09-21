@echo off
chcp 65001 >nul
title 语义摄像头 NVR 值守

REM 固定到仓库根（脚本位于 deploy\ 下）
cd /d "%~dp0.."

REM 优先用项目虚拟环境；没有 venv 时回退系统 python（依赖检查会兜底拦截）
set "PY=.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

REM 全量依赖导入检查——只查 numpy 不够，缺 onnxruntime/cv2/PIL 一样起不来
"%PY%" -c "import numpy, cv2, onnxruntime, PIL" >nul 2>&1
if errorlevel 1 (
    echo [错误] 依赖不完整或缺少虚拟环境——请先运行 deploy\install-win11.ps1
    pause
    exit /b 1
)

echo [启动] 语义摄像头 Win11 值守工作站...
echo [提示] 首次启动会打开本机摄像头接入向导；配置保存在 %%LOCALAPPDATA%%\semantic-camera
"%PY%" -m scam.win11
pause
