#!/usr/bin/env bash
# 本地启动 claude_audit 平台 (8787) + GLM 采集器已在 8790 后台运行
set -e
cd "$(dirname "$0")/claude_audit"
export CLAUDE_AUDIT_CONFIG='D:/cloud_security_deploy/server_docker1/_local_test_config.yml'
export AUDIT_ADMIN_USER='admin'
# bcrypt hash for password: admin2026  (单引号内 $ 不作变量展开)
export AUDIT_ADMIN_PASSWORD_HASH='$2b$12$IKf2Me.aYbDOzsDtvDpsbeiR0Xt05sRH/p9CD8JhzhmUj58sBS0Nq'
export AUDIT_SESSION_SECRET='cloud-audit-local-secret-2026'
exec py -3 -m claude_audit