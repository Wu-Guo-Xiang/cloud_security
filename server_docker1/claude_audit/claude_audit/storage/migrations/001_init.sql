PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            TEXT    NOT NULL,
  source_file   TEXT    NOT NULL,
  line_no       INTEGER NOT NULL,
  byte_offset   INTEGER NOT NULL,
  event         TEXT,
  stage         TEXT,
  session_id    TEXT,
  tool          TEXT,
  phase         TEXT,
  action        TEXT,
  skipped_reason TEXT,
  duration_ms   INTEGER,
  user          TEXT,
  vm_hostname   TEXT,
  pid           INTEGER,
  bash_command  TEXT,
  file_path     TEXT,
  url           TEXT,
  hook_match_count INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_event ON events(event);
CREATE INDEX IF NOT EXISTS idx_events_tool ON events(tool);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);

CREATE TABLE IF NOT EXISTS rule_hits (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id    INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  source      TEXT NOT NULL,
  rule_id     TEXT NOT NULL,
  severity    TEXT NOT NULL,
  matched     TEXT,
  meta_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_hits_event ON rule_hits(event_id);
CREATE INDEX IF NOT EXISTS idx_hits_severity ON rule_hits(severity);
CREATE INDEX IF NOT EXISTS idx_hits_rule ON rule_hits(rule_id);

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
  bash_command, file_path, url,
  content='events', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
  INSERT INTO events_fts(rowid, bash_command, file_path, url)
  VALUES (new.id, coalesce(new.bash_command,''), coalesce(new.file_path,''), coalesce(new.url,''));
END;

CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
  INSERT INTO events_fts(events_fts, rowid, bash_command, file_path, url)
  VALUES ('delete', old.id, coalesce(old.bash_command,''), coalesce(old.file_path,''), coalesce(old.url,''));
END;

CREATE TABLE IF NOT EXISTS collector_state (
  source_file   TEXT PRIMARY KEY,
  inode         INTEGER,
  size          INTEGER,
  offset        INTEGER,
  line_no       INTEGER,
  updated_at    TEXT
);
