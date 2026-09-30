"""PostToolUse 事件解析。

lib/event.py 只覆盖 PreToolUse / UserPromptSubmit;PostToolUse 单独建模放在这里,
避免改 input/ 共享代码。

PostToolUse stdin JSON 形如:
  {
    "session_id": "...",
    "transcript_path": "...",
    "cwd": "...",
    "hook_event_name": "PostToolUse",
    "tool_name": "Write" | "Edit" | "MultiEdit" | "NotebookEdit" | ...,
    "tool_input":   { ... 与 PreToolUse 相同 ... },
    "tool_response":{ "success": true, "filePath": "...", ... }
  }
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PostToolEvent:
    raw: dict[str, Any]
    session_id: str
    cwd: str
    tool_name: str
    tool_input: dict[str, Any] = field(default_factory=dict)
    tool_response: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_stdin(cls) -> "PostToolEvent":
        # Windows 下 stdin 可能带 UTF-8 BOM;读二进制 + utf-8-sig 吞掉 BOM。
        raw_bytes = sys.stdin.buffer.read() or b"{}"
        raw = raw_bytes.decode("utf-8-sig", errors="replace").lstrip("﻿")
        data = json.loads(raw)
        return cls(
            raw=data,
            session_id=data.get("session_id", ""),
            cwd=data.get("cwd", ""),
            tool_name=data.get("tool_name", ""),
            tool_input=data.get("tool_input") or {},
            tool_response=data.get("tool_response") or {},
        )

    @property
    def file_path(self) -> str:
        """返回工具实际落盘的文件路径,覆盖 Write / Edit / MultiEdit / NotebookEdit。

        优先用 tool_response.filePath(Claude Code 实际写入的路径,已含规范化);
        回退 tool_input.file_path / notebook_path。
        """
        resp_path = self.tool_response.get("filePath") or self.tool_response.get("file_path")
        if resp_path:
            return str(resp_path)
        if self.tool_name == "NotebookEdit":
            return str(self.tool_input.get("notebook_path", ""))
        return str(self.tool_input.get("file_path", ""))

    @property
    def tool_success(self) -> bool:
        val = self.tool_response.get("success")
        if val is None:
            # 缺字段时按成功处理(Edit 工具回包没有 success 字段)
            return True
        return bool(val)
