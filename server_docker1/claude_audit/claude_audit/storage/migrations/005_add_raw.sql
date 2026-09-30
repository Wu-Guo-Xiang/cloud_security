-- 005: 存原始 JSON 那一行,详情页可直接展示,不再依赖回读客户端源文件
-- 老数据 raw 为 NULL,event_detail 会 fallback 到 open(source_file) 并友好降级
ALTER TABLE events ADD COLUMN raw TEXT;
