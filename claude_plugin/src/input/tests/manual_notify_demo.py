"""Notify 弹框手动验证脚本。运行后会真的弹出一个通知框(只有 OK),需要手动关闭。

跑法:py -3 D:\\cloud_security\\scripts\\input\\tests\\manual_notify_demo.py

预期:
  - 出现一个 SYSTEMMODAL + TOPMOST 弹框,标题"Claude 输入安全 — 提示词注入已阻断"
  - 只有 OK 按钮(不是 YES/NO)
  - 15 秒不点也会自动关掉
  - 函数无返回值
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.confirm import notify  # noqa: E402

title = "Claude 输入安全 — 提示词注入已阻断"
body = (
    "输入命中提示词注入硬规则,已阻断。\n"
    "命中模式:ignore_previous_instructions, zh_reveal_system_prompt\n"
    "本中间件不允许通过用户输入覆盖系统指令 / 提取系统提示词 / 切换到无限制角色。\n"
    "如果你在做安全研究需要讨论这些模板,请把它们放进文件让我 Read,而不是直接粘贴到对话里。"
)
notify(title, body)
print("notify returned (无返回值,已正常关闭弹框)")
