@echo off
REM claude_audit 服务器: FastAPI + ingest endpoint
REM 前台运行,窗口即为日志;Ctrl+C 停止
setlocal
set BASE=%~dp0
cd /d "%BASE%"
where py >nul 2>&1
if %errorlevel% equ 0 (
    py -3 -m claude_audit
) else (
    python -m claude_audit
)
