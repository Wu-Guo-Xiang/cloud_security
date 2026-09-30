@echo off
chcp 65001 >nul
title Claude Code 客户端连通性与配置检查
cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0test_connection.ps1"

if %errorlevel% neq 0 (
    pause
)
