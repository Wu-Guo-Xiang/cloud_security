"""决策执行。

v2：matches 空 → 直接放行；非空 → desensitize_action 处理。
desensitize_action 内部按事件类型分发：
  PreToolUse + Read（T1）          → 生成脱敏副本 + redirect
  PreToolUse + Read（不支持格式）  → 阻断
  PreToolUse + Grep/WebFetch       → 阻断（无 redirect 通道）
  UserPromptSubmit                 → 阻断 + 给出脱敏建议
"""
