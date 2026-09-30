"""落盘文件读取(带尺寸上限)。

Step 1 只关注 Write / Edit / MultiEdit / NotebookEdit 这 4 个工具的落盘结果。
Bash 通道(echo /heredoc /sed -i 直接写文件)留到 Step 2。

策略:
  - 不存在 / 不可读 → 返回空文本(fail-OPEN,不阻塞 Claude)
  - 文件 > 1MB → 读前 1MB,truncated=True(避免读大日志/二进制拖慢 hook)
  - 二进制启发判定(读 NUL) → 跳过,reason="binary"
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_MAX_BYTES = 1 * 1024 * 1024  # 1 MB
_BINARY_SNIFF = 8192


@dataclass(frozen=True)
class ReadResult:
    text: str
    source_label: str
    truncated: bool = False
    skipped_reason: str = ""

    @property
    def is_skipped(self) -> bool:
        return bool(self.skipped_reason)


def read_file(file_path: str) -> ReadResult:
    if not file_path:
        return ReadResult(text="", source_label="", skipped_reason="no_path")
    p = Path(file_path)
    if not p.exists():
        return ReadResult(text="", source_label=str(p), skipped_reason="missing")
    if not p.is_file():
        return ReadResult(text="", source_label=str(p), skipped_reason="not_a_file")
    try:
        size = p.stat().st_size
    except OSError as exc:
        return ReadResult(text="", source_label=str(p), skipped_reason=f"stat_failed:{exc}")
    if size == 0:
        return ReadResult(text="", source_label=str(p), skipped_reason="empty")

    try:
        with p.open("rb") as f:
            head = f.read(_BINARY_SNIFF)
            if b"\x00" in head:
                return ReadResult(text="", source_label=str(p), skipped_reason="binary")
            rest = b""
            if size > _BINARY_SNIFF:
                rest = f.read(max(0, _MAX_BYTES - _BINARY_SNIFF))
        data = head + rest
    except OSError as exc:
        return ReadResult(text="", source_label=str(p), skipped_reason=f"read_failed:{exc}")

    truncated = size > _MAX_BYTES
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = data.decode("latin-1", errors="replace")
    return ReadResult(text=text, source_label=str(p), truncated=truncated)
