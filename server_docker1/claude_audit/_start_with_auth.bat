@echo off
REM 本地带管理员认证启动 claude_audit 平台
REM 密码: admin2026  (用户名: admin)
REM 前台运行,窗口即为日志;Ctrl+C 停止
setlocal
set BASE=%~dp0
cd /d "%BASE%"
set AUDIT_ADMIN_USER=admin
set "AUDIT_ADMIN_PASSWORD_HASH=$2b$12$IKf2Me.aYbDOzsDtvDpsbeiR0Xt05sRH/p9CD8JhzhmUj58sBS0Nq"
set "AUDIT_SESSION_SECRET=cloud-audit-local-secret-2026"
where py >nul 2>&1
if %errorlevel% equ 0 (
    py -3 -m claude_audit
) else (
    python -m claude_audit
)
