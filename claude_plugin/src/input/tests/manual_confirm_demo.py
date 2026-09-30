"""Confirm 弹框手动验证脚本。运行后会真的弹出一个对话框,需要手动操作。

跑法:py -3 D:\\cloud_security\\scripts\\input\\tests\\manual_confirm_demo.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.confirm import confirm  # noqa: E402

title = "Claude Code 安全检查 - 测试"
body = (
    "这是一次手动测试。\n\n"
    "默认按钮应该是 NO(取消)。直接按 Enter 应该走 False。\n"
    "点 YES 应该返回 True。\n"
    "什么都不点等 25 秒应该自动超时,返回 False。\n\n"
    "是否继续提交?"
)
result = confirm(title, body, timeout_ms=25_000)
print(f"confirm returned: {result!r}")
