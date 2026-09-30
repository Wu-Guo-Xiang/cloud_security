# ==========================================================
#   Claude Code 企业托管安全策略一键卸载脚本
# ==========================================================
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# 1. 检查管理员权限
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Yellow
    Write-Host " [*] 提示：移除系统策略需要 Windows 管理员权限。" -ForegroundColor Yellow
    Write-Host " [*] 正在请求提升权限 (UAC)..." -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Yellow
    $proc = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }
    Start-Process $proc -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit 0
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Claude Code 企业安全管控策略一键卸载" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$confirm = Read-Host "确认要移除企业安全管控策略吗？(Y/N) [默认: N]"
if ($confirm -notmatch "^[Yy]") {
    Write-Host "操作已取消。" -ForegroundColor Gray
    exit 0
}

$targetFile = "C:\Program Files\ClaudeCode\managed-settings.json"
$progDataFile = "C:\ProgramData\ClaudeCode\managed-settings.json"

$removed = $false

if (Test-Path $targetFile) {
    Remove-Item -Path $targetFile -Force
    Write-Host "[√] 已删除系统策略: $targetFile" -ForegroundColor Green
    $removed = $true
}

if (Test-Path $progDataFile) {
    Remove-Item -Path $progDataFile -Force
    Write-Host "[√] 已删除辅助策略: $progDataFile" -ForegroundColor Green
    $removed = $true
}

if (-not $removed) {
    Write-Host "[i] 系统中未发现企业安全策略文件，无需移除。" -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host " [√] 卸载完成！Claude Code 已恢复为默认个人状态。" -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Cyan
}

Write-Host ""
$null = Read-Host "按【回车键】退出"
