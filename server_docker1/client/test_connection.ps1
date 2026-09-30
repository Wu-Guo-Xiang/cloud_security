# ==========================================================
#   Claude Code 企业安全管控客户端 - 连通性与配置检查工具
# ==========================================================
[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Claude Code 客户端环境与管控连通性检测" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. 本机环境信息
$compName = $env:COMPUTERNAME
$userName = $env:USERNAME
$userDomain = $env:USERDOMAIN
$ipList = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } | 
    Select-Object -ExpandProperty IPAddress) -join ", "

Write-Host "[1] 员工电脑信息:" -ForegroundColor White
Write-Host "    计算机名: $compName" -ForegroundColor Gray
Write-Host "    当前用户: $userDomain\$userName" -ForegroundColor Gray
Write-Host "    局域网IP: $ipList" -ForegroundColor Gray
Write-Host ""

# 2. 检查系统策略文件
$targetFile = "C:\Program Files\ClaudeCode\managed-settings.json"
$progDataFile = "C:\ProgramData\ClaudeCode\managed-settings.json"

Write-Host "[2] 安全托管策略文件检测:" -ForegroundColor White
if (Test-Path $targetFile) {
    Write-Host "    [√] 系统级策略存在: $targetFile" -ForegroundColor Green
    try {
        $raw = Get-Content -Path $targetFile -Raw -Encoding UTF8
        $json = $raw | ConvertFrom-Json
        $serverUrl = $json.hooks.UserPromptSubmit[0].hooks[0].url
        Write-Host "    [i] 配置的管控接口: $serverUrl" -ForegroundColor Cyan
    } catch {
        Write-Host "    [!] 策略文件内容解析异常: $_" -ForegroundColor Red
    }
} else {
    Write-Host "    [X] 系统级策略不存在！请先运行【一键安装】进行配置。" -ForegroundColor Red
}

if (Test-Path $progDataFile) {
    Write-Host "    [√] 辅助策略存在: $progDataFile" -ForegroundColor Green
} else {
    Write-Host "    [-] 辅助策略不存在 (非必须)" -ForegroundColor DarkGray
}
Write-Host ""

# 3. 检查 Claude Code CLI 是否安装
Write-Host "[3] Claude Code 命令行工具检测:" -ForegroundColor White
$claudeCmd = Get-Command "claude" -ErrorAction SilentlyContinue
if ($claudeCmd) {
    Write-Host "    [√] 检测到已安装 Claude Code: $($claudeCmd.Source)" -ForegroundColor Green
} else {
    Write-Host "    [!] 未在系统环境变量 PATH 中找到 claude 命令。" -ForegroundColor Yellow
    Write-Host "        (若您已在特定终端/IDE下安装，可忽略此提示)" -ForegroundColor DarkGray
}
Write-Host ""

# 4. 测试与服务端网关的 HTTP 连通性
Write-Host "[4] 网关网络连通性测试:" -ForegroundColor White
if ($serverUrl) {
    try {
        $uri = [System.Uri]$serverUrl
        $baseHost = "$($uri.Scheme)://$($uri.Authority)"
        
        # 测试平台主页
        $loginUrl = "$baseHost/login"
        Write-Host "    [*] 正在测试访问平台入口: $loginUrl ..." -ForegroundColor Gray
        $t0 = [System.Diagnostics.Stopwatch]::StartNew()
        $resp = Invoke-WebRequest -Uri $loginUrl -Method Head -TimeoutSec 5 -ErrorAction Stop
        $t0.Stop()
        Write-Host "    [√] 平台服务连通正常！状态码: $($resp.StatusCode)，耗时: $($t0.ElapsedMilliseconds) ms" -ForegroundColor Green
        
        # 测试 Hook 接口
        Write-Host "    [*] 正在测试 Hook 审计通道: $serverUrl ..." -ForegroundColor Gray
        $testPayload = @{
            session_id = "test_check"
            prompt = "ping_test"
            cwd = "C:\"
        } | ConvertTo-Json
        
        $hookResp = Invoke-RestMethod -Uri $serverUrl -Method Post -Body $testPayload -ContentType "application/json" -TimeoutSec 5 -ErrorAction Stop
        Write-Host "    [√] Hook 审计接口通信正常！网关响应正常。" -ForegroundColor Green
    } catch {
        Write-Host "    [X] 连接网关失败: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "        请排查：1. 服务器是否开机；2. 局域网防火墙是否放行 8787 端口；3. 是否在同一公司局域网内。" -ForegroundColor Yellow
    }
} else {
    Write-Host "    [-] 未能获取网关地址，跳过网络连通测试。" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " 检测完成。" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""
$null = Read-Host "按【回车键】退出"
