-- 008: 插件拉取/下载记录表
-- 服务端记录谁(IP)在何时拉取了 manifest / 下载了 zip, 用于追踪"谁更新了插件"。
-- IP -> 使用人 的解析复用 plugin_status 的 LiteLLM litellm_ip 映射, 此表只存 IP。
CREATE TABLE IF NOT EXISTS plugin_pulls (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,        -- 拉取时间 (CN 本地 YYYY-MM-DD HH:MM:SS)
    ip          TEXT    NOT NULL,        -- 请求方 IP (request.client.host)
    action      TEXT    NOT NULL,        -- 'manifest' 检查版本 / 'download' 下载zip
    version     TEXT    DEFAULT '',      -- 拉取的版本号
    filename    TEXT    DEFAULT '',      -- 下载的 zip 文件名 (download 时)
    user_agent  TEXT    DEFAULT ''       -- UA (辅助识别客户端)
);
CREATE INDEX IF NOT EXISTS ix_pulls_ts ON plugin_pulls(ts);
CREATE INDEX IF NOT EXISTS ix_pulls_ip ON plugin_pulls(ip);
CREATE INDEX IF NOT EXISTS ix_pulls_version ON plugin_pulls(version);
