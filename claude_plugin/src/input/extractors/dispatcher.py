"""按 Hook event 分发到对应 extractor。

调用方：input_scanner.py
返回：ExtractResult（已含 skipped_reason / truncated 等元信息）

工具支持（Step 3 首批）：
  - PreToolUse + Read     → file_extractor
  - PreToolUse + Grep     → grep_extractor
  - PreToolUse + WebFetch → url_extractor
  - UserPromptSubmit      → prompt_extractor
  - 其他工具：skipped_reason="unsupported_tool"（input_scanner 视为 pass，由 matcher 把控）
"""
from __future__ import annotations

from lib.event import Event

from .base import ExtractResult
from .file_extractor import extract as _extract_file
from .grep_extractor import extract as _extract_grep
from .normalize import normalize as _normalize
from .prompt_extractor import extract as _extract_prompt
from .url_extractor import extract as _extract_url


def _apply_normalize(result: ExtractResult) -> ExtractResult:
    """对非 skip 的抽取结果做无害化重写,detector 直接消费归一化后文本。

    保证:skip / 空文本不动;原文若已是干净 ASCII,normalize 内部 short-circuit,
    不会产生新对象。
    """
    if result.is_skipped or not result.text:
        return result
    norm = _normalize(result.text)
    if not norm.changed:
        return result
    return ExtractResult(
        text=norm.text,
        source_label=result.source_label,
        skipped_reason=result.skipped_reason,
        truncated=result.truncated,
    )


def extract(event: Event) -> ExtractResult:
    if event.is_userprompt:
        return _apply_normalize(_extract_prompt(event.prompt))

    if not event.is_pretool:
        return ExtractResult(skipped_reason="unsupported_event")

    tool = event.tool_name
    if tool == "Read":
        return _apply_normalize(_extract_file(event.file_path))
    if tool == "Grep":
        return _apply_normalize(_extract_grep(event.tool_input))
    if tool == "WebFetch":
        return _apply_normalize(_extract_url(event.tool_input))
    return ExtractResult(skipped_reason=f"unsupported_tool:{tool}")
