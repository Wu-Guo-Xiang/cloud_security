"""Session 级缓存。

每个 Hook 调用是独立 Python 进程 → 跨进程靠 pickle 文件。
路径：{paths.session_cache}/{session_id}.pickle

存储两类数据：
  - 扫描结果（按 content+rules+wordlib+llm 多段版本组成 key）
  - 实体一致性字典（entity_map：同一 session 内同名实体使用同一占位符）

会话结束的清理由 SessionStart/SessionEnd Hook 负责（不在本模块范围）。
"""
