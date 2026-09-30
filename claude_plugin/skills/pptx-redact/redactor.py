"""L1 文本脱敏：把检测到的敏感片段替换为占位符 / 保形掩码。"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from rules import rules
from wordlib import wordlib
from validators import id_card_loose, validate

import mask_strategies


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    label: str


_BANK_CARD_CANDIDATE = re.compile(r"(?<!\d)\d(?:[ \-]?\d){11,18}(?!\d)")


def redact(text: str) -> tuple[str, dict[str, int]]:
    """仅 L1（regex + 词库）。返回 (脱敏后文本, {class: 次数})。"""
    if not text:
        return text, {}
    return _apply_spans(text, _collect_l1_spans(text))


def collect_l1_spans(text: str) -> list[tuple[int, int, str]]:
    """暴露 L1 spans 给 pseudonymizer：[(start, end, class_name), ...]"""
    return [(s.start, s.end, s.label) for s in _collect_l1_spans(text)]


def _collect_l1_spans(text: str) -> list[_Span]:
    spans: list[_Span] = []
    if not text:
        return spans

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

    bank_cls = rules.data_classes.get("bank_card")
    if bank_cls and bank_cls.enabled:
        for m in _BANK_CARD_CANDIDATE.finditer(text):
            value = m.group(0)
            if " " not in value and "-" not in value and id_card_loose(value):
                continue
            if not validate("luhn", value):
                continue
            spans.append(_Span(m.start(), m.end(), "bank_card"))

    spans.extend(_credential_spans(text))

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
    if not spans:
        return text, {}

    spans = sorted(spans, key=lambda s: (s.start, -s.end))

    merged: list[_Span] = []
    for s in spans:
        if merged and s.start < merged[-1].end:
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
    cls = rules.get_class(label)
    strategy = cls.mask_strategy if cls else ""
    if strategy:
        masked = mask_strategies.apply(strategy, original)
        if masked is not None:
            return masked
    return f"[{label.upper()}]"
