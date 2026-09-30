#!/bin/sh
# 容器启动: 同时跑 GLM 采集器(monitor.py) + 审计平台(claude_audit)
# monitor.py 写 /data/glm_monitor_data.db(挂载卷, 持久化), 平台只读同一个 db。
# 采用 POSIX sh 兼容写法(python:3.12-slim 的 /bin/sh 是 dash, 不支持 wait -n)。
set -e

# 1) 若未配置外部 GLM_MONITOR_HOST(单容器模式)，则在后台运行采集器；若配置了则由独立容器运行
if [ -z "$GLM_MONITOR_HOST" ] || [ "$GLM_MONITOR_HOST" = "http://127.0.0.1:8790" ]; then
    GLM_MONITOR_DB=/data/glm_monitor_data.db \
    GLM_HTTP_PORT=8790 \
    python /app/glm_monitor/monitor.py &
fi

# 2) 审计平台前台运行(exec 替换主进程, 容器生命周期跟随它)
exec python -m claude_audit