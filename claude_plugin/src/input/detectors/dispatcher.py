"""Detector 协议与统一聚合入口。

L1（regex / wordlib / 凭证）detectors：暴露 `detect(text: str) -> list[Match]`，串行调用。
L2（LLM）detector：       暴露 `detect(text: str) -> LLMDetectResult`，返回 entities+matches+状态。

`detect_all(text)` 同时跑 L1 + L2，合并 matches 给下游 action。
v2 起没有"L1 命中致命项就跳过 L2"的剪枝：即使命中凭证，LLM 仍可能识别更多实体（人名、公司）让脱敏更彻底。
"""
from __future__ import annotations

from dataclasses import dataclass

from lib.types import Match

from .credential_detector import detect as _detect_credentials
from .pattern_detector import detect as _detect_patterns
from .presidio_detector import detect as _detect_presidio
from .llm_detector import LLMDetectResult, detect as _detect_llm


_L1_DETECTORS = (
    ("credential", _detect_credentials),
    ("pattern", _detect_patterns),
    ("presidio", _detect_presidio),
)


@dataclass(frozen=True)
class DetectAggregate:
    matches: tuple[Match, ...]
    ran_detectors: tuple[str, ...]
    llm_result: LLMDetectResult | None  # None = L2 未启用；非 None 但 ok=False = 失败


def detect_all(text: str, *, with_llm: bool = True, mode: str = "default") -> DetectAggregate:
    """跑 L1（始终）+ L2（with_llm=True 时），返回聚合结果。

    with_llm=False 用于 Grep/WebFetch：扫描对象是 URL/模式串而非 prose，
    LLM NER 收益低且容易把 "Python" / "GitHub" 这类常见技术词识别成 PRODUCT 导致误报。

    mode="ups" 透传给 LLM detector，启用 PASSWORD 等 UPS 专属类目；
    mode="default"（Read 路径）不识别 PASSWORD，避免代码注释里的"密码"误中。
    """
    if not text:
        return DetectAggregate(matches=(), ran_detectors=(), llm_result=None)

    matches: list[Match] = []
    ran: list[str] = []
    for name, fn in _L1_DETECTORS:
        result = fn(text)
        if result is None:
            continue
        ran.append(name)
        matches.extend(result)

    if not with_llm:
        return DetectAggregate(
            matches=tuple(matches),
            ran_detectors=tuple(ran),
            llm_result=None,
        )

    llm = _detect_llm(text, mode=mode)
    if llm.matches:
        matches.extend(llm.matches)
        ran.append("llm")
    elif llm.ok:
        ran.append("llm")

    return DetectAggregate(
        matches=tuple(matches),
        ran_detectors=tuple(ran),
        llm_result=llm,
    )
