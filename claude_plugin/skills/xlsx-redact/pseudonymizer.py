"""L1 + L2 实体合并 + 一致性假名替换。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from llm_config import llm_config
from rules import rules
from entity_map import EntityMap

import mask_strategies


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    placeholder: str


def pseudonymize(
    text: str,
    l1_spans: Iterable[tuple[int, int, str]],
    llm_entities: Iterable,
    entity_map: EntityMap,
) -> tuple[str, dict[str, int]]:
    if not text:
        return text, {}

    spans: list[_Span] = []

    for start, end, type_name in l1_spans:
        if start >= end:
            continue
        placeholder = _l1_placeholder(text[start:end], type_name)
        spans.append(_Span(start, end, placeholder))

    for ent in llm_entities:
        if ent.start >= ent.end:
            continue
        strategy = llm_config.placeholder_strategy_of(ent.type)
        # 配置历史包袱：llm.yml 里 ID_NUMBER 写的是 placeholder=mask_id，
        # 但 mask_strategies 实际注册名是 id_number；做一次别名映射兼容。
        strategy_name = "id_number" if strategy == "mask_id" else strategy
        masked = (
            mask_strategies.apply(strategy_name, text[ent.start:ent.end])
            if strategy_name and strategy_name != "placeholder"
            else None
        )
        if masked is not None:
            placeholder = masked
        else:
            label = llm_config.label_of(ent.type)
            placeholder = entity_map.assign(ent.text, ent.type, label)
        spans.append(_Span(ent.start, ent.end, placeholder))

    return _apply_spans(text, spans)


def _l1_placeholder(original: str, type_name: str) -> str:
    cls = rules.get_class(type_name)
    strategy = cls.mask_strategy if cls else ""
    if strategy:
        masked = mask_strategies.apply(strategy, original)
        if masked is not None:
            return masked
    return f"[{type_name.upper()}]"


def _apply_spans(text: str, spans: list[_Span]) -> tuple[str, dict[str, int]]:
    if not spans:
        return text, {}

    spans = sorted(spans, key=lambda s: (s.start, -s.end))

    merged: list[_Span] = []
    for s in spans:
        if merged and s.start < merged[-1].end:
            prev = merged[-1]
            merged[-1] = _Span(prev.start, max(prev.end, s.end), prev.placeholder)
        else:
            merged.append(s)

    out: list[str] = []
    counts: dict[str, int] = {}
    cursor = 0
    for s in merged:
        if s.start > cursor:
            out.append(text[cursor:s.start])
        out.append(s.placeholder)
        counts[s.placeholder] = counts.get(s.placeholder, 0) + 1
        cursor = s.end
    if cursor < len(text):
        out.append(text[cursor:])
    return "".join(out), counts
