"""Action 共享契约。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ActionOutcome:
    """Action 执行结果。

    exit_code:    Hook 进程退出码（0 / 2）
    audit:        附加到主审计日志的字段（如 redirect_path / block_reason）
    """
    exit_code: int
    audit: dict[str, Any] = field(default_factory=dict)
