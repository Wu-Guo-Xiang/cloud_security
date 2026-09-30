<#
.SYNOPSIS
    Cloud Security 大模型安全管控平台与 GLM 监控服务 —— 本地一键启动脚本 (Windows PowerShell 7)
.DESCRIPTION
    1. 自动定位 Python 环境 (优先 D:\Anaconda\envs\hello-agents\python.exe)
    2. 后台启动 GLM 监控采集器 (端口 8790)
    3. 前台启动 Claude Audit 审计主平台 (端口 8787)
#>

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# 1. 查找可用 Python 解释器
$pyExe = "D:\Anaconda\envs\hello-agents\python.exe"
if (-not (Test-Path $pyExe)) {
    $pyCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pyCmd) {
        $pyExe = $pyCmd.Source
    } else {
        Write-Error "未找到 Python 解释器，请检查环境变量或安装路径。"
        exit 1
    }
}

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host " 🚀 Cloud Security 大模型安全管控平台 本地一键启动" -ForegroundColor Green
Write-Host " Python 解释器: $pyExe" -ForegroundColor Gray
Write-Host " 工作目录:      $scriptDir" -ForegroundColor Gray
Write-Host "=================================================" -ForegroundColor Cyan

# 2. 设置通用环境变量
$env:CLAUDE_AUDIT_CONFIG = "$scriptDir\_local_test_config.yml"
$env:AUDIT_ADMIN_USER = "admin"
$env:AUDIT_ADMIN_PASSWORD = "admin2026"
$env:AUDIT_SESSION_SECRET = "cloud-audit-local-secret-2026"
$env:GLM_MONITOR_HOST = "http://127.0.0.1:8790"
$env:GLM_MONITOR_DB = "$scriptDir\glm_monitor\glm_monitor_data.db"
$env:GLM_HTTP_PORT = "8790"
$env:GLM_HTTP_HOST = "0.0.0.0"
$env:PYTHONPATH = "$scriptDir\claude_audit;$scriptDir"

# 确保 plugins 目录存在
New-Item -ItemType Directory -Force -Path "$scriptDir\docker\data\plugins" | Out-Null

# 3. 检查并启动 GLM 监控服务 (端口 8790)
$glmPortInUse = Get-NetTCPConnection -LocalPort 8790 -ErrorAction SilentlyContinue
if (-not $glmPortInUse) {
    Write-Host "[1/2] 正在启动 GLM 监控采集器 (http://127.0.0.1:8790)..." -ForegroundColor Yellow
    $glmScript = "$scriptDir\glm_monitor\monitor.py"
    $glmProcess = Start-Process -FilePath $pyExe -ArgumentList "`"$glmScript`"" -WorkingDirectory "$scriptDir\glm_monitor" -PassThru -WindowStyle Hidden
    Write-Host "      GLM 监控采集器已在后台运行 (PID: $($glmProcess.Id))" -ForegroundColor Green
} else {
    Write-Host "[1/2] GLM 监控采集器已在运行 (端口 8790 已监听)" -ForegroundColor DarkCyan
}

# 4. 启动 Claude Audit 主平台 (端口 8787)
Write-Host "[2/2] 正在启动 Claude Audit 安全管控平台 (http://127.0.0.1:8787)..." -ForegroundColor Yellow
Write-Host "      默认管理员账号: admin" -ForegroundColor Green
Write-Host "      默认管理员密码: admin2026" -ForegroundColor Green
Write-Host "      按 Ctrl+C 可停止主服务。" -ForegroundColor DarkGray
Write-Host "-------------------------------------------------" -ForegroundColor Gray

Set-Location "$scriptDir\claude_audit"
& $pyExe -m claude_audit
