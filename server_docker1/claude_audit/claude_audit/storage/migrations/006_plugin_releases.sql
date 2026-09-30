-- 006: 插件版本发布管理表
-- 支持插件自动更新：管理员上传 zip 后自动生成 manifest.json 供客户端拉取
-- 同一时刻只有一条 is_active=1（当前生效版本），发布新版时旧版自动置 0
CREATE TABLE IF NOT EXISTS plugin_releases (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    version       TEXT    NOT NULL,
    min_required  TEXT    NOT NULL DEFAULT '0.1.0',
    sha256        TEXT    NOT NULL,
    release_notes TEXT    DEFAULT '',
    released_at   TEXT    NOT NULL,
    released_by   TEXT    DEFAULT '',
    zip_filename  TEXT    NOT NULL,
    is_active     INTEGER NOT NULL DEFAULT 0,
    UNIQUE(version)
);
