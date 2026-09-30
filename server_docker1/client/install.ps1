# ==========================================================
#   Claude Code 企业托管安全策略一键部署脚本
#   目标路径: C:\Program Files\ClaudeCode\managed-settings.json
#   特性: 零 Python 依赖、自动提权、交互引导、连通性自检
# ==========================================================
[CmdletBinding()]
param(
    [string]$ServerHost = "",
    [int]$ServerPort = 8787,
    [switch]$NonInteractive = $false
)

$ErrorActionPreference = "Stop"

# 1. 检查管理员权限
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Yellow
    Write-Host " [*] 提示：写入系统托管策略需要 Windows 管理员权限。" -ForegroundColor Yellow
    Write-Host " [*] 正在请求提升权限 (UAC)..." -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Yellow
    $proc = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($ServerHost) { $argList += " -ServerHost `"$ServerHost`"" }
    Start-Process $proc -ArgumentList $argList -Verb RunAs
    exit 0
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Claude Code 企业安全管控策略一键部署" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 2. 引导输入服务器 IP
if (-not $ServerHost) {
    Write-Host ""
    Write-Host "请输入安全管控服务平台的 IP 地址：" -ForegroundColor White
    Write-Host "（例如: 192.168.3.117，如果就在本机测试可输入 127.0.0.1）" -ForegroundColor Gray
    Write-Host ""
    $inputIp = Read-Host "管控平台 IP [默认: 192.168.3.117]"
    if ([string]::IsNullOrWhiteSpace($inputIp)) {
        $ServerHost = "192.168.3.117"
    } else {
        $ServerHost = $inputIp.Trim()
    }
}

$baseUrl = "http://${ServerHost}:${ServerPort}"
Write-Host ""
Write-Host "[*] 目标管控网关: $baseUrl" -ForegroundColor Green

# 3. 连通性预检
Write-Host "[*] 正在测试与管控平台的网络连通性..." -ForegroundColor Yellow
try {
    $testResp = Invoke-WebRequest -Uri "$baseUrl/login" -Method Head -TimeoutSec 3 -ErrorAction Stop
    Write-Host "    [OK] 网关网络连接正常！(HTTP $($testResp.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "    [!] 警告: 无法连接到 $baseUrl/login" -ForegroundColor Yellow
    Write-Host "    原因: $($_.Exception.Message)" -ForegroundColor DarkGray
    Write-Host "    建议确认服务器已启动且局域网防火墙允许 8787 端口通信。" -ForegroundColor Yellow
}

# 4. 获取当前员工终端账号与主机名
$curUser = ""
try {
    $curUser = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
} catch {}
if (-not $curUser -or $curUser -match "Administrator") {
    $curUser = if ($env:USERDOMAIN) { "$env:USERDOMAIN\$env:USERNAME" } else { $env:USERNAME }
}

$uParts = $curUser -split '[\\/]'
$uNameOnly = if ($uParts.Count -gt 1) { $uParts[-1] } else { $curUser }
$compName = $env:COMPUTERNAME
$curHost = if ($compName -and $uNameOnly -and (-not $compName.EndsWith($uNameOnly))) { "$compName-$uNameOnly" } else { $compName }

$encUser = [System.Uri]::EscapeDataString($curUser)
$encHost = [System.Uri]::EscapeDataString($curHost)
$hookHeaders = @{
    "X-User" = $curUser
    "X-Hostname" = $curHost
}

Write-Host "[*] 识别到当前终端身份:" -ForegroundColor Green
Write-Host "    用户账号: $curUser" -ForegroundColor White
Write-Host "    客户端标识: $curHost" -ForegroundColor White

# 5. 生成托管策略 JSON
$policy = @{
    "`$schema" = "https://json.schemastore.org/claude-code-settings.json"
    "allowedChannel" = "enterprise"
    "permissions" = @{
        "deny" = @()
    }
    "hooks" = @{
        "SessionStart" = @(
            @{
                "matcher" = ".*"
                "hooks" = @(
                    @{
                        "type" = "http"
                        "url" = "$baseUrl/api/hooks/session-start?user=$encUser&hostname=$encHost"
                        "headers" = $hookHeaders
                        "timeout" = 5
                    }
                )
            }
        )
        "PreToolUse" = @(
            @{
                "matcher" = ".*"
                "hooks" = @(
                    @{
                        "type" = "http"
                        "url" = "$baseUrl/api/hooks/pre-tool-use?user=$encUser&hostname=$encHost"
                        "headers" = $hookHeaders
                        "timeout" = 5
                    }
                )
            }
        )
        "UserPromptSubmit" = @(
            @{
                "hooks" = @(
                    @{
                        "type" = "http"
                        "url" = "$baseUrl/api/hooks/user-prompt-submit?user=$encUser&hostname=$encHost"
                        "headers" = $hookHeaders
                        "timeout" = 5
                    }
                )
            }
        )
        "PostToolUse" = @(
            @{
                "matcher" = ".*"
                "hooks" = @(
                    @{
                        "type" = "http"
                        "url" = "$baseUrl/api/hooks/post-tool-use?user=$encUser&hostname=$encHost"
                        "headers" = $hookHeaders
                        "timeout" = 5
                    }
                )
            }
        )
        "Stop" = @(
            @{
                "hooks" = @(
                    @{
                        "type" = "http"
                        "url" = "$baseUrl/api/hooks/stop?user=$encUser&hostname=$encHost"
                        "headers" = $hookHeaders
                        "timeout" = 5
                    }
                )
            }
        )
    }
}

$jsonContent = $policy | ConvertTo-Json -Depth 10
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

# 5. 写入 C:\Program Files\ClaudeCode\managed-settings.json
$targetDir = "C:\Program Files\ClaudeCode"
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}
$targetFile = Join-Path $targetDir "managed-settings.json"
[System.IO.File]::WriteAllText($targetFile, $jsonContent, $utf8NoBom)
Write-Host "[√] 成功写入系统策略: $targetFile" -ForegroundColor Green

# 写入 ProgramData 作为双重兜底
$progDataDir = Join-Path $env:ProgramData "ClaudeCode"
if (-not (Test-Path $progDataDir)) {
    New-Item -ItemType Directory -Path $progDataDir -Force | Out-Null
}
$progDataFile = Join-Path $progDataDir "managed-settings.json"
[System.IO.File]::WriteAllText($progDataFile, $jsonContent, $utf8NoBom)
Write-Host "[√] 成功写入辅助策略: $progDataFile" -ForegroundColor Green

# 6. 清理旧版本地遗留 hooks 冲突
Write-Host ""
Write-Host "[*] 检查并清理旧版本地插件残留配置..." -ForegroundColor Yellow
$userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
foreach ($up in $userProfiles) {
    $settingsFile = Join-Path $up.FullName ".claude\settings.json"
    if (Test-Path $settingsFile) {
        try {
            $raw = [System.IO.File]::ReadAllText($settingsFile, [System.Text.Encoding]::UTF8)
            if ($raw -match "cloud-guard|input_scanner|output_scanner|prompt_guard") {
                $bak = "$settingsFile.bak_$(Get-Date -Format 'yyyyMMddHHmmss')"
                Copy-Item -Path $settingsFile -Destination $bak -Force
                $obj = $raw | ConvertFrom-Json
                if ($null -ne $obj.PSObject.Properties['hooks']) {
                    $obj.PSObject.Properties.Remove('hooks')
                }
                [System.IO.File]::WriteAllText($settingsFile, ($obj | ConvertTo-Json -Depth 20), $utf8NoBom)
                Write-Host "    [OK] 已清理旧版 hooks: $settingsFile (已备份为 $bak)" -ForegroundColor Green
            }
        } catch {
            Write-Host "    [!] 忽略处理 $settingsFile: $_" -ForegroundColor DarkGray
        }
    }
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [√] 部署成功！员工电脑已接入安全管控网关。" -ForegroundColor Green
Write-Host " 管控网关: $baseUrl" -ForegroundColor White
Write-Host " 策略文件: $targetFile" -ForegroundColor White
Write-Host " 特性: 员工无需安装 Python 或额外依赖，后续使用 Claude Code 即自动受控。" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "【自测验证方法】" -ForegroundColor Yellow
Write-Host " 1. 重新打开一个终端或 VS Code 会话。" -ForegroundColor White
Write-Host " 2. 执行 claude 并发送一条提示词（例如: hello）。" -ForegroundColor White
Write-Host " 3. 打开管控平台 Web 界面 (http://${ServerHost}:8787)，进入『实时事件』页面查看日志。" -ForegroundColor White
Write-Host ""

if (-not $NonInteractive) {
    $null = Read-Host "按【回车键】完成并退出"
}
