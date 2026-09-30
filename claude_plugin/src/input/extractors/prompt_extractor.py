"""UserPromptSubmit 事件：直接以用户输入文本为扫描内容。"""
from __future__ import annotations

from .base import ExtractResult


def extract(prompt: str) -> ExtractResult:
    if not prompt:
        return ExtractResult(skipped_reason="empty_prompt")
    return ExtractResult(text=prompt, source_label="prompt")
