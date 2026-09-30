@echo off
REM claude_audit_client 启动脚本 (前台/debug 版本;会保留窗口便于看日志)
REM 常驻/开机自启请用 start_client.vbs
setlocal
set BASE=%~dp0
cd /d "%BASE%"
py -3 -m claude_audit_client --config "%BASE%client.yml"
