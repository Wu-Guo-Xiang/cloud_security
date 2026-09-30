-- v3: UserPromptSubmit 事件里对话框原文入库,用于展示"用户对话触发命中"的上下文
ALTER TABLE events ADD COLUMN prompt_text TEXT;
