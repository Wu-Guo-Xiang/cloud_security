"""轻量 Match 数据结构（原 lib/types.py，重命名避免与 stdlib types 冲突）。"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Match:
    """单一敏感数据类别的命中聚合。"""
    data_class: str
    count: int
    samples: tuple[str, ...] = ()
