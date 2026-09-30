-- v2: 引入 client_id 维度,支持多设备上报同名 jsonl
ALTER TABLE events ADD COLUMN client_id TEXT;
CREATE INDEX IF NOT EXISTS idx_events_client ON events(client_id);

-- 复合唯一键:(client_id, source_file, line_no)
-- coalesce 兼容老数据(client_id=NULL 视为空串)
CREATE UNIQUE INDEX IF NOT EXISTS ux_events_client_line
  ON events(coalesce(client_id,''), source_file, line_no);
