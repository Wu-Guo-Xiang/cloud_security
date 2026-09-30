"""Extractor 输出契约。

text:           待扫描的纯文本，detectors 直接吃这个
source_label:   日志/审计标签（如 "file:..." / "url:..." / "prompt"）
skipped_reason: 非空表示 extractor 主动放弃（不支持的类型 / 超大文件 / 路径外）
                detectors 不应被调用；input_scanner 决定是否阻断。
truncated:      内容被截断（达到 size cap）→ 审计需关注
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExtractResult:
    text: str = ""
    source_label: str = ""
    skipped_reason: str = ""
    truncated: bool = False

    @property
    def is_skipped(self) -> bool:
        return bool(self.skipped_reason)
