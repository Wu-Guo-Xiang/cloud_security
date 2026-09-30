"""action 分发。

v2 已去掉评分门限：
  - 无命中 → 放行
  - 有命中 → 一律走 desensitize_action
  - 格式不支持等技术限制由 desensitize_action 内部降级为阻断
"""
from __future__ import annotations

from typing import Iterable

from cache.entity_map import EntityMap
from lib.event import Event
from lib.response import respond_pass
from lib.types import Match

from . import desensitize_action
from .base import ActionOutcome


def execute(
    *,
    event: Event,
    text: str,
    matches: list[Match],
    source_label: str,
    llm_entities: Iterable | None = None,
    entity_map: EntityMap | None = None,
) -> ActionOutcome:
    if not matches:
        return ActionOutcome(exit_code=respond_pass())

    return desensitize_action.run(
        event=event,
        text=text,
        matches=matches,
        source_label=source_label,
        llm_entities=llm_entities,
        entity_map=entity_map,
    )
