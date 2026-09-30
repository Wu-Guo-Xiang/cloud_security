# claude_audit server Docker image
# Build:  docker build -t claude_audit:latest -f docker/Dockerfile .
# Run:    docker compose -f docker/docker-compose.yml up -d
#
# Layout inside container:
#   /app/claude_audit/         - python package (this repo's claude_audit/ subdir)
#   /app/config.yml            - server config (mounted from host or baked in)
#   /data/audit.db             - SQLite DB (mounted volume)
#   /data/logs/                - hook log jsonl files (unused in ingest-only mode)

FROM python:3.12-slim

# 1. system deps (sqlite3 CLI is handy for debugging; ca-certificates for HTTPS out)
RUN sed -i 's|http://deb.debian.org|https://mirrors.aliyun.com|g; s|http://security.debian.org|https://mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends sqlite3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2. python deps first (cached layer)
COPY claude_audit/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir \
      -i https://mirrors.aliyun.com/pypi/simple/ \
      --trusted-host mirrors.aliyun.com \
      --timeout 300 --retries 5 \
      -r /app/requirements.txt

# 3. server source (only the server-side package, NOT client / deploy / scripts)
COPY claude_audit/claude_audit /app/claude_audit
# GLM 监控采集器(写 /data/glm_monitor_data.db, 平台只读)
COPY glm_monitor /app/glm_monitor
COPY docker/config.docker.yml /app/config.yml
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# 4. data dir (will be mounted as a volume in compose)
RUN mkdir -p /data /app/claude_audit/api/data
ENV CLAUDE_AUDIT_CONFIG=/app/config.yml

EXPOSE 8787

# 同时启动 GLM 采集器 + 审计平台(见 entrypoint.sh)
CMD ["/app/entrypoint.sh"]
