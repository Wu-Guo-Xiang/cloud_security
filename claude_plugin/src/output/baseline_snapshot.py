"""PreToolUse Hook — Stop-review 的 baseline 采集入口。

单一职责:在 Write/Edit/MultiEdit/NotebookEdit *即将* 修改文件时,把当前磁盘内容
拷一份存到 .claude/stop_review_baseline/<session_id>/。Stop hook 会用它算 diff。

不做:
  - 任何拦截决策(这活儿是 input_scanner 的,PreToolUse 已经跑过它)
  - 任何内容判定(留给 Stop-review 阶段和 output_scanner)
  - LLM 调用

退出码:
  始终 0(fail-OPEN)。抓失败也不能阻断 Claude Code 主循环。

时序保证:
  Claude Code 的 hooks 是同步串行,同 matcher 下多个 hook 按注册顺序执行。
  只要本 hook 挂在同一个 PreToolUse matcher 上,tool 落盘前必被调用。

kill switch:
  CLOUD_SEC_STOP_REVIEW=0 → 直接 return 0 不做任何事(方便临时关闭)
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from pathlib import Path

try:
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # pragma: no cover
    pass

_THIS_DIR = Path(__file__).resolve().parent
_INPUT_DIR = _THIS_DIR.parent / "input"

# output 自己的模块优先,再回退到 input 共享的 detectors / lib / config
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))
if str(_INPUT_DIR) not in sys.path:
    sys.path.insert(1, str(_INPUT_DIR))


_SUPPORTED_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})

# 与 output_scanner 一致的跳过路径(避免抓自己产物)
_SKIP_PATH_PARTS = (
    r"\test\logs",
    r"\test\temp",
    r"\test\output\desensitized_",
    r"\.claude\stop_review_baseline\\",
    r"\.git\\",
    r"\node_modules\\",
    r"\__pycache__\\",
)

_STAGE = "pre_baseline"


def _should_skip_path(file_path: str) -> str:
    if not file_path:
        return "no_path"
    low = file_path.replace("/", "\\").lower()
    for part in _SKIP_PATH_PARTS:
        if part.lower() in low:
            return f"path_filter:{part.strip('\\')}"
    return ""


def _extract_file_path(tool_name: str, tool_input: dict) -> str:
    """PreToolUse 阶段没有 tool_response,只能看 tool_input。"""
    if tool_name == "NotebookEdit":
        return str(tool_input.get("notebook_path", ""))
    return str(tool_input.get("file_path", ""))


def main() -> int:
    if os.environ.get("CLOUD_SEC_STOP_REVIEW", "") == "0":
        return 0

    start = time.time()
    session_id = ""
    tool_name = ""
    file_path = ""

    try:
        from output_logger import log
        from stop_review.baseline import capture, sweep_zombies

        try:
            # 读二进制 + utf-8-sig 吞掉可能的 UTF-8 BOM。
            raw = (sys.stdin.buffer.read() or b"{}").decode("utf-8-sig", errors="replace").lstrip("﻿")
            data = json.loads(raw)
        except Exception as exc:
            log({
                "stage": _STAGE,
                "event": "PreToolUse",
                "phase": "skipped",
                "skipped_reason": f"stdin_invalid:{exc}",
                "duration_ms": int((time.time() - start) * 1000),
            })
            return 0

        session_id = str(data.get("session_id", ""))
        tool_name = str(data.get("tool_name", ""))
        tool_input = data.get("tool_input") or {}

        if tool_name not in _SUPPORTED_TOOLS:
            return 0    # 静默:matcher 已过滤,这里是防御性检查,不写日志避免噪音

        file_path = _extract_file_path(tool_name, tool_input)
        skip = _should_skip_path(file_path)
        if skip:
            log({
                "stage": _STAGE,
                "event": "PreToolUse",
                "session_id": session_id,
                "tool": tool_name,
                "file_path": file_path,
                "phase": "skipped",
                "skipped_reason": skip,
                "duration_ms": int((time.time() - start) * 1000),
            })
            return 0

        status = capture(session_id, file_path)

        # 顺手清理僵尸 session(每次 PreToolUse 都做,幂等且便宜)
        cleaned = sweep_zombies()

        log({
            "stage": _STAGE,
            "event": "PreToolUse",
            "session_id": session_id,
            "tool": tool_name,
            "file_path": file_path,
            "phase": "captured",
            "status": status,
            "sweep_cleaned": cleaned,
            "duration_ms": int((time.time() - start) * 1000),
        })
        return 0

    except SystemExit:
        raise
    except Exception as exc:
        try:
            from output_logger import log
            log({
                "stage": _STAGE,
                "event": "baseline_failure",
                "session_id": session_id,
                "tool": tool_name,
                "file_path": file_path,
                "error": str(exc),
                "traceback": traceback.format_exc(),
                "duration_ms": int((time.time() - start) * 1000),
            })
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
