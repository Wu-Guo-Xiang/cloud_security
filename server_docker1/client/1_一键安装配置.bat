@echo off
chcp 65001 >nul
title Claude Code 企业安全管控策略一键配置
cd /d "%~dp0"

:: 1. 检查管理员权限
net session >nul 2>&1
if %errorlevel% equ 0 goto RUN_ADMIN

:: 2. 自动请求管理员权限 (UAC)
echo [系统提示] 正在请求 Windows 管理员权限以写入系统策略目录...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b 0

:RUN_ADMIN
cd /d "%~dp0"
echo ==========================================================
echo    正在启动 Claude Code 企业安全策略一键部署...
echo ==========================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*

if %errorlevel% neq 0 (
    echo.
    echo ==========================================================
    echo [错误] 安装过程中遇到异常，请查看上方输出信息。
    echo ==========================================================
    pause
)
