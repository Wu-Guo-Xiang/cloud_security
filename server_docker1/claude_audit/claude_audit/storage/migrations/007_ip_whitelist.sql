-- 007: IP 白名单表
-- 管理允许访问 AI 的 IP / 网段, 不在白名单内的 IP 标记为异常
-- 支持单个 IP (如 172.16.1.100) 和 CIDR 网段 (如 172.16.0.0/16)
CREATE TABLE IF NOT EXISTS ip_whitelist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT    NOT NULL,     -- 单个IP 或 CIDR 网段
    comment     TEXT    DEFAULT '',   -- 备注, 如"上海办公网段"
    created_at  TEXT    NOT NULL,
    UNIQUE(ip)
);
