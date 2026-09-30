-- v4: UserPromptSubmit 用户决策审计
-- block_reason 取值:
--   NULL                        无敏感,直接发送(无弹窗)
--   userprompt_no_redirect      自动脱敏后发送(无弹窗)
--   score_over_threshold        系统硬拦截(未弹窗给用户)
--   user_approved               弹窗后,用户确认继续发送
--   user_blocked                弹窗后,用户取消发送
ALTER TABLE events ADD COLUMN block_reason TEXT;
CREATE INDEX IF NOT EXISTS idx_events_block_reason ON events(block_reason);
