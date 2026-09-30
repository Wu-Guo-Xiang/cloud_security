"""L1 + L2 实体合并 + 一致性假名替换。

输入：
  - text          原文
  - l1_spans      L1 redactor 已识别的 spans（手机/邮箱/IP/卡号 等结构化）
  - llm_entities  L2 LLM 识别的语义实体（公司/人名/产品/金额）
  - entity_map    本 session 的实体字典（一致性来源）

输出：
  - 脱敏后文本
  - replacements 统计 {标签: 次数}，供日志审计

合并规则（优先级从高到低）：
  1. L1 spans（结构化数据更确定，不让 LLM 覆盖）
  2. L2 实体（去除与 L1 重叠的部分）
  3. 同段重叠 L2 实体：保留 start 较早、较长的一个

L1 用占位符样式 [PHONE] / [EMAIL] / [BANK_CARD] ...（按 type 大写）；
L2 用一致性占位符 [公司A] / [人员A] / [产品A] / [金额]（来自 EntityMap）。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from config.llm import llm_config
from config.rules import rules

from cache.entity_map import EntityMap

from . import mask_strategies


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    placeholder: str  # 直接用最终占位符，避免再分一层


def pseudonymize(
    text: str,
    l1_spans: Iterable[tuple[int, int, str]],
    llm_entities: Iterable,           # list[LLMEntity]，避免循环导入用 duck-type
    entity_map: EntityMap,
) -> tuple[str, dict[str, int]]:
    """合并 L1+L2 spans 并替换。返回 (脱敏文本, {placeholder: count})。"""
    if not text:
        return text, {}

    spans: list[_Span] = []

    # 1) L1：按类目的 mask_strategy 决定占位符（与 redactor 行为一致）
    for start, end, type_name in l1_spans:
        if start >= end:
            continue
        placeholder = _l1_placeholder(text[start:end], type_name)
        spans.append(_Span(start, end, placeholder))

    # 2) L2：按类型的 placeholder 策略分流
    #    - placeholder：进 EntityMap 取一致性顺序占位符（公司/人员）
    #    - 其余值（mask_id / password / ...）走 mask_strategies 对应保形掩码，不进 entity_map
    for ent in llm_entities:
        if ent.start >= ent.end:
            continue
        strategy = llm_config.placeholder_strategy_of(ent.type)
        if strategy != "placeholder":
            masked = mask_strategies.apply(strategy, text[ent.start:ent.end])
            placeholder = masked if masked is not None else f"[{ent.type}]"
        else:
            label = llm_config.label_of(ent.type)
            placeholder = entity_map.assign(ent.text, ent.type, label)
        spans.append(_Span(ent.start, ent.end, placeholder))

    return _apply_spans(text, spans)


def _l1_placeholder(original: str, type_name: str) -> str:
    """L1 占位符：配了 mask_strategy 走保形掩码，否则回退到 [TYPE]。"""
    cls = rules.get_class(type_name)
    strategy = cls.mask_strategy if cls else ""
    if strategy:
        masked = mask_strategies.apply(strategy, original)
        if masked is not None:
            return masked
    return f"[{type_name.upper()}]"


def _apply_spans(text: str, spans: list[_Span]) -> tuple[str, dict[str, int]]:
    """合并重叠 span（保留 start 早 / end 远 / 首个 placeholder）后替换。"""
    if not spans:
        return text, {}

    # 排序：start 升序，end 降序（同起点优先长的）
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
