"""Bash 入口：把 .docx 脱敏成 .md，打印 .md 路径供 Claude 接着 Read。

为什么存在：
  Claude Code 升级后，Read 工具对 .docx 的二进制检查跑在 PreToolUse 之前，
  hook 收不到 .docx Read 事件 → 无法触发脱敏 → 原文又读不出来。
  解法：skill 让 Claude 改走 Bash → 本脚本 → 脚本走 input_scanner 跑同一套
  脱敏管线（L1 正则 + L2 LLM 实体 + 段级 markdown 渲染）→ 输出 .md → Claude Read .md。

用法：
  py docx_to_md.py <input.docx> [--session-id SID]

输出：
  stdout: 唯一一行，脱敏后 .md 副本的绝对路径
  exit 0：脱敏成功，Claude 应立即 Read 这个 .md
  exit 2：原文未命中任何敏感数据（罕见），stderr 给提示
  exit !=0,2：scanner 失败，stderr 是原始报错
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

# Windows Python 默认按 cp936 写 stdout → Claude 读到的中文路径会乱码 → Read 找不到文件。
# 强制 UTF-8 输出。
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except (AttributeError, Exception):
    pass

HERE = Path(__file__).resolve().parent
SCANNER = HERE.parent / "input_scanner.py"

# "请改读: <path>" — input_scanner 通过 lib/response.respond_redirect 写入 stderr
_REDIRECT_RE = re.compile(r"请改读:\s*(.+?)(?:\r?\n|$)")


def main() -> int:
    ap = argparse.ArgumentParser(description="Desensitize a .docx into a .md copy.")
    ap.add_argument("input_path", help="原始 .docx 路径")
    ap.add_argument(
        "--session-id",
        default=os.environ.get("CLAUDE_SESSION_ID") or f"docx_cli_{uuid.uuid4().hex[:8]}",
        help="会话 ID（影响副本目录），默认从 CLAUDE_SESSION_ID 取，没有则随机",
    )
    args = ap.parse_args()

    input_path = Path(args.input_path).expanduser().resolve()
    if not input_path.exists():
        sys.stderr.write(f"file not found: {input_path}\n")
        return 1
    if input_path.suffix.lower() != ".docx":
        sys.stderr.write(f"not a .docx: {input_path}\n")
        return 1

    payload = {
        "session_id": args.session_id,
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(input_path)},
    }

    # 用当前 Python 跑 scanner，避免 PATH 上 py/python 不一致
    proc = subprocess.run(
        [sys.executable, str(SCANNER), "--event", "PreToolUse"],
        input=json.dumps(payload).encode("utf-8"),
        capture_output=True,
    )
    stderr = proc.stderr.decode("utf-8", errors="replace")

    # exit_code 2 = 阻断+重定向（正常路径）；0 = 无命中放行
    if proc.returncode == 2:
        m = _REDIRECT_RE.search(stderr)
        if not m:
            sys.stderr.write("scanner blocked but no redirect path:\n" + stderr)
            return 3
        md_path = m.group(1).strip()
        sys.stdout.write(md_path + "\n")
        return 0

    if proc.returncode == 0:
        sys.stderr.write("no sensitive data detected in this .docx; no .md generated.\n")
        sys.stderr.write("you can fall back to other tools (e.g. python-docx) at your own risk.\n")
        return 2

    sys.stderr.write(f"scanner failed (exit={proc.returncode}):\n{stderr}")
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
