"""文本脱敏：把检测到的敏感片段替换为占位符。

边界声明：
  - 本模块只处理纯文本；DOCX / PDF / Excel 等富文本格式不在此处理。
  - 用 detector 的同一组正则 + validator 二次扫描原文本，得到精确 span 后替换。
  - 替换占位符 = "[CLASS]"，与决策日志的 class 名一致便于审计。
  - bank_card / id_card 通过 validator 校验后才替换（与 detector 行为一致）。

后续目标四接入更完善的脱敏器后，本文件可整体替换为对其 API 的薄封装。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from config.rules import rules
from config.wordlib import wordlib
from lib.validators import id_card_loose, validate

from . import mask_strategies


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    label: str  # 用于占位符 [LABEL]


_BANK_CARD_CANDIDATE = re.compile(r"(?<!\d)\d(?:[ \-]?\d){11,18}(?!\d)")


def redact(text: str) -> tuple[str, dict[str, int]]:
    """返回 (redacted_text, replacements_by_class)。

    replacements_by_class：本次替换的类目 → 次数，供日志审计。
    替换不破坏文本长度统计逻辑，行号偏移不会显著影响阅读。

    仅 L1（regex + 词库）。L1+L2 合并替换走 actions/pseudonymizer.py。
    """
    if not text:
        return text, {}
    return _apply_spans(text, _collect_l1_spans(text))


def collect_l1_spans(text: str) -> list[tuple[int, int, str]]:
    """暴露 L1 spans 给 pseudonymizer：返回 [(start, end, class_name), ...]。

    与 redact() 共用同一组规则：rules.regex + bank_card 候选 + credential + 词库。
    用于 L1+L2 合并替换时无需重复扫描。
    """
    return [(s.start, s.end, s.label) for s in _collect_l1_spans(text)]


def _collect_l1_spans(text: str) -> list[_Span]:
    """L1 span 收集逻辑（regex + 词库 + 校验器）。"""
    spans: list[_Span] = []
    if not text:
        return spans

    # 1) rules.yml 中带 regex 的类目
    for class_name, cls in rules.data_classes.items():
        if not cls.enabled:
            continue
        if not cls.regex:
            continue
        try:
            pattern = re.compile(cls.regex)
        except re.error:
            continue
        for m in pattern.finditer(text):
            # 选择 span 范围：capture_group>0 时取该捕获组的 span
            if cls.capture_group > 0:
                try:
                    span_value = m.group(cls.capture_group)
                    span_start = m.start(cls.capture_group)
                    span_end = m.end(cls.capture_group)
                except IndexError:
                    span_value = m.group(0)
                    span_start, span_end = m.start(), m.end()
                if span_value is None:
                    continue
            else:
                span_value = m.group(0)
                span_start, span_end = m.start(), m.end()
            if cls.validator and not validate(cls.validator, span_value):
                continue
            spans.append(_Span(span_start, span_end, class_name))

    # 2) bank_card 候选 + luhn；先剔除"身份证形态"的 18 位串避免错误掩码
    bank_cls = rules.data_classes.get("bank_card")
    if bank_cls and bank_cls.enabled:
        for m in _BANK_CARD_CANDIDATE.finditer(text):
            value = m.group(0)
            if " " not in value and "-" not in value and id_card_loose(value):
                continue
            if not validate("luhn", value):
                continue
            spans.append(_Span(m.start(), m.end(), "bank_card"))

    # 3) credential 类正则（fatal + db_connection）
    spans.extend(_credential_spans(text))

    # 4) 词库
    for class_name, terms in wordlib.terms_by_class.items():
        cls = rules.data_classes.get(class_name)
        if cls and not cls.enabled:
            continue
        for term in terms:
            if not term:
                continue
            idx = 0
            while True:
                pos = text.find(term, idx)
                if pos < 0:
                    break
                spans.append(_Span(pos, pos + len(term), class_name))
                idx = pos + len(term)

    return spans


# --- helpers ---------------------------------------------------------

# 与 credential_detector 保持一致的形态（不引用其私变量以保模块独立）
_CRED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("api_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("api_key", re.compile(r"\bASIA[0-9A-Z]{16}\b")),
    ("api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("api_key", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("api_key", re.compile(r"\bgho_[0-9A-Za-z]{36}\b")),
    ("api_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("api_key", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("api_key", re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.=]{20,}\b", re.IGNORECASE)),
    ("api_key", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
    ("prod_password", re.compile(
        r"""(?ix)
        \b (?: password | passwd | pwd | secret )
        \s* [:=]\s*
        ['"]?
        (?=[^\s'"]{8,})
        (?=[^\s'"]*[A-Za-z])
        (?=[^\s'"]*[\d!@#\$%\^&\*\-_+=])
        [^\s'"]+
        ['"]?
        """
    )),
    ("db_connection", re.compile(
        r"""(?ix)
        \b (?: jdbc:[a-z]+ | postgres(?:ql)? | mysql | mongodb(?:\+srv)? | redis | mssql | oracle )
        ://
        (?: [^/\s:'"]+ : [^/@\s'"]+ @ )?
        [^/\s'"]+
        (?: /[^\s'"]* )?
        """
    )),
)


def _credential_spans(text: str) -> Iterable[_Span]:
    for class_name, pat in _CRED_PATTERNS:
        for m in pat.finditer(text):
            yield _Span(m.start(), m.end(), class_name)


def _apply_spans(text: str, spans: list[_Span]) -> tuple[str, dict[str, int]]:
    """合并重叠 span（取最大范围 + 第一个 label）后逐段替换。

    替换形式按类目的 mask_strategy 决定：
      - 配了策略 → 用 mask_strategies.apply(strategy, 原片段)
      - 未配 / 策略未注册 / 策略抛错 → 回退到 [LABEL] 占位符
    """
    if not spans:
        return text, {}

    spans = sorted(spans, key=lambda s: (s.start, -s.end))

    merged: list[_Span] = []
    for s in spans:
        if merged and s.start < merged[-1].end:
            # 重叠：扩大区间但保留首个 label
            prev = merged[-1]
            merged[-1] = _Span(prev.start, max(prev.end, s.end), prev.label)
        else:
            merged.append(s)

    out: list[str] = []
    counts: dict[str, int] = {}
    cursor = 0
    for s in merged:
        if s.start > cursor:
            out.append(text[cursor:s.start])
        out.append(_render_span(text[s.start:s.end], s.label))
        counts[s.label] = counts.get(s.label, 0) + 1
        cursor = s.end
    if cursor < len(text):
        out.append(text[cursor:])
    return "".join(out), counts


def _render_span(original: str, label: str) -> str:
    """按类目的 mask_strategy 决定替换形式；缺失时回退到 [LABEL]。"""
    cls = rules.get_class(label)
    strategy = cls.mask_strategy if cls else ""
    if strategy:
        masked = mask_strategies.apply(strategy, original)
        if masked is not None:
            return masked
    return f"[{label.upper()}]"
