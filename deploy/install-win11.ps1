# Win11 部署脚本（PowerShell，兼容 Windows PowerShell 5.1 / PowerShell 7，文件带 BOM）
# 用法: powershell -ExecutionPolicy Bypass -File install-win11.ps1
# 特性: 仓库根自定位 / 项目虚拟环境 / 每步退出码校验 / 失败即非零退出（无虚假成功）

#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

function Invoke-Native {
    # 运行原生命令；退出码非 0 立即终止安装（错误输出不吞）
    $exe = $args[0]
    $rest = @()
    if ($args.Count -gt 1) { $rest = $args[1..($args.Count - 1)] }
    & $exe @rest
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[错误] 命令失败（退出码 $LASTEXITCODE）: $exe $rest" -ForegroundColor Red
        exit 1
    }
}

# 仓库根自定位——与调用者的当前目录无关（脚本可从任意目录启动）
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repoRoot
Write-Host '=== 语义摄像头 Win11 部署 ===' -ForegroundColor Cyan
Write-Host "仓库目录: $repoRoot"

# [1/6] Python >= 3.10（解析版本号，不满足即失败）
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host '[错误] 未找到 python——请安装 Python 3.10+ 并勾选 Add python.exe to PATH' -ForegroundColor Red
    exit 1
}
$verRaw = (& python --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    Write-Host "[错误] python --version 失败（退出码 $LASTEXITCODE）" -ForegroundColor Red
    exit 1
}
if ($verRaw -match 'Python\s+(\d+)\.(\d+)') {
    $verMajor = [int]$Matches[1]; $verMinor = [int]$Matches[2]
    if (($verMajor -lt 3) -or ($verMajor -eq 3 -and $verMinor -lt 10)) {
        Write-Host "[错误] 需要 Python >= 3.10，当前: $verRaw" -ForegroundColor Red
        exit 1
    }
    Write-Host "[1/6] Python $verRaw OK"
} else {
    Write-Host "[错误] 无法解析 Python 版本: $verRaw" -ForegroundColor Red
    exit 1
}

# [2/6] 项目虚拟环境 .venv（不污染全局 Python；后续一律用 venv 里的 python）
$venvDir = Join-Path $repoRoot '.venv'
$venvPython = Join-Path $venvDir 'Scripts\python.exe'
if (Test-Path $venvPython) {
    Write-Host '[2/6] 虚拟环境 .venv 已存在（跳过创建）'
} else {
    Write-Host '[2/6] 创建虚拟环境 .venv …'
    Invoke-Native python -m venv $venvDir
}

# [3/6] 安装运行依赖（venv 内；错误可见，失败即停）
Write-Host '[3/6] 安装依赖 numpy / opencv-python-headless / onnxruntime / pillow …'
Invoke-Native $venvPython -m pip install --upgrade pip
Invoke-Native $venvPython -m pip install numpy opencv-python-headless onnxruntime pillow

# [4/6] 导入自检——缺任何依赖都在这里失败，绝不带病声明成功
Write-Host '[4/6] 导入自检 …'
Invoke-Native $venvPython -c "import numpy, cv2, onnxruntime, PIL; import scam.monitor, scam.server, scam.source, scam.win11_setup; print('imports OK')"

# [5/6] 每用户数据目录。摄像头配置不再写仓库，也不要求安装目录可写；
# 首次双击启动时由仅回环浏览器向导原子创建 cameras.json，已有配置绝不覆盖。
$dataRoot = Join-Path $env:LOCALAPPDATA 'semantic-camera'
New-Item -ItemType Directory -Force -Path $dataRoot | Out-Null
$cfgPath = Join-Path $dataRoot 'cameras.json'
if (Test-Path $cfgPath) {
    Write-Host "[5/6] 已有用户配置（保留）: $cfgPath"
} else {
    Write-Host '[5/6] 用户数据目录已就绪——首次启动将打开本机摄像头接入向导'
}

# 检测模型放置点（缺模型时 nvr 明确提示"只跑门控"，不静默零检测）
$modelsDir = Join-Path $repoRoot 'models'
New-Item -ItemType Directory -Force -Path $modelsDir | Out-Null
if (-not (Test-Path (Join-Path $modelsDir 'person-detector.onnx'))) {
    Write-Host '      [提示] 尚无人物检测模型——首次向导会要求提供ONNX路径，或明确选择“仅预览不告警”'
}

# [6/6] 生成 start-nvr.bat（固定 venv 解释器 + 依赖导入检查 + 依赖缺失给出明确指引）
$batPath = Join-Path $repoRoot 'start-nvr.bat'
$bat = @"
@echo off
chcp 65001 >nul
title 语义摄像头 NVR 值守
cd /d `"%~dp0`"
set `"PY=$venvPython`"
if not exist `"%PY%`" set `"PY=python`"
`"%PY%`" -c `"import numpy, cv2, onnxruntime, PIL`" >nul 2>&1
if errorlevel 1 (
    echo [错误] 依赖不完整——请先运行 deploy\install-win11.ps1
    pause
    exit /b 1
)
echo [启动] 语义摄像头 Win11 值守工作站...
echo [提示] 首次启动会打开本机摄像头接入向导；配置保存在 %%LOCALAPPDATA%%\semantic-camera
`"%PY%`" -m scam.win11
pause
"@
[System.IO.File]::WriteAllText($batPath, $bat, (New-Object System.Text.UTF8Encoding($false)))
Write-Host '[6/6] start-nvr.bat 已生成'

Write-Host ''
Write-Host '部署完成。' -ForegroundColor Green
Write-Host '  启动值守: 双击 start-nvr.bat（或 .venv\Scripts\python -m scam.win11）'
Write-Host '  首次启动: 浏览器会打开仅本机可见的摄像头接入向导，保存后自动进入值守'
Write-Host '  工作台:   值守启动成功后日志会打印 http://127.0.0.1:8600（默认仅本机访问）'
Write-Host '  配置目录: %LOCALAPPDATA%\semantic-camera\cameras.json'
Write-Host '  数据目录: %LOCALAPPDATA%\semantic-camera\storage\'
