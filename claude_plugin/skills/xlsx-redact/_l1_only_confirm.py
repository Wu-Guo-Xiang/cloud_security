"""L2 LLM 失败后弹 MessageBox 让用户决定是否接受 L1-only 输出。

设计同 cloud_security/scripts/input/lib/confirm.py:
  - Windows MessageBoxTimeoutW(undocumented 但 Win10/11 自带)
  - 默认焦点 NO(MB_DEFBUTTON2) + TOPMOST + SYSTEMMODAL
  - 25s 超时,到点按"否"处理(fail-CLOSED)
  - 非 Windows / 异常 / 超时 → 返回 False

为啥 skill 不直接 import 那个 confirm 模块:
  skill 设计为自包含(SKILL.md 里"不需要外部 cloud_security 代码"),
  搬一份过来,职责单一,改动只在本文件。
"""
from __future__ import annotations

import sys
from pathlib import Path


def confirm_l1_only(skill_name: str, input_path: Path, error: str) -> bool:
    """LLM 重试仍失败时,弹框让用户确认是否接受 L1-only 输出。

    返回 True 仅当用户主动点"是";否 / 超时 / 平台不支持 / 调用失败 → False。
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return False

    MB_YESNO         = 0x00000004
    MB_ICONWARNING   = 0x00000030
    MB_DEFBUTTON2    = 0x00000100   # 默认焦点在第 2 个按钮(NO),fail-safe
    MB_TOPMOST       = 0x00040000
    MB_SETFOREGROUND = 0x00010000
    MB_SYSTEMMODAL   = 0x00001000
    IDYES            = 6
    IDTIMEOUT        = 32000
    TIMEOUT_MS       = 25_000

    title = f"{skill_name} 脱敏:L2 LLM 失败"
    body = (
        f"文件:{input_path.name}\n"
        f"原因:{error}\n\n"
        "L2 LLM 重试一次后仍失败。\n\n"
        "选择「是」:接受 L1-only 输出。\n"
        "  仅手机/邮箱/卡号/身份证/USCC/凭据等结构化字段会脱敏,\n"
        "  人名/公司/产品/项目代号等语义实体会保留原文(有泄露风险)。\n\n"
        "选择「否」(默认):中断,不输出 .md(fail-CLOSED)。\n\n"
        "25 秒未操作 → 自动按「否」处理。"
    )

    flags = (
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2
        | MB_TOPMOST | MB_SETFOREGROUND | MB_SYSTEMMODAL
    )
    try:
        user32 = ctypes.windll.user32
        fn = getattr(user32, "MessageBoxTimeoutW", None)
        if fn is not None:
            fn.argtypes = [
                wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR,
                wintypes.UINT, wintypes.WORD, wintypes.DWORD,
            ]
            fn.restype = ctypes.c_int
            ret = fn(None, body, title, flags, 0, TIMEOUT_MS)
            if ret == IDTIMEOUT:
                return False   # fail-CLOSED
            return ret == IDYES
        # 没有 MessageBoxTimeoutW:回退到无超时的 MessageBoxW 是危险的
        # (用户不在线就永卡),fail-CLOSED 直接拒。
        return False
    except Exception:
        return False
