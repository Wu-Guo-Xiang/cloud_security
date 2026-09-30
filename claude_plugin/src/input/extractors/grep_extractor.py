"""Grep 工具：抽取 pattern + path 供敏感识别。

Grep 自身的 pattern 可能含敏感关键字（最常见的写法：grep 'password=...' file）。
Step 3 暂不递归扫描 Grep 命中的文件内容（性能与时延考量）；
该能力放在 Step 4 完成 actions 后再评估。
"""
from __future__ import annotations

from typing import Any

from .base import ExtractResult


def extract(tool_input: dict[str, Any]) -> ExtractResult:
    pattern = str(tool_input.get("pattern", "")).strip()
    path = str(tool_input.get("path", "")).strip()
    glob = str(tool_input.get("glob", "")).strip()

    if not pattern and not path:
        return ExtractResult(skipped_reason="empty_grep")

    text_parts = []
    if pattern:
        text_parts.append(f"pattern: {pattern}")
    if path:
        text_parts.append(f"path: {path}")
    if glob:
        text_parts.append(f"glob: {glob}")

    return ExtractResult(
        text="\n".join(text_parts),
        source_label=f"grep:{path or '<no-path>'}",
    )
