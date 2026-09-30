"""通用格式 / 业务词库识别。

数据源：
  - rules.yml 中带 `regex` 的类目（id_card / phone / email / internal_ip）
  - rules.yml 中带 `validator` 的类目（bank_card → luhn；id_card → checksum）
    bank_card 没有 regex，单独提供长度 12-19 数字串候选再过 luhn
  - config/wordlib.wordlib 中按 data_class 列出的关键词列表（customer_name 等）

样本上限 5 条 / 类。
"""
from __future__ import annotations

import re

from config.rules import rules
from config.wordlib import wordlib
from lib.types import Match
from lib.validators import id_card_loose, validate


_SAMPLE_LIMIT = 5

# bank_card 没有 regex（rules.yml 设计），用通用候选 + luhn 校验
# 兼容空格/连字符分组（如 "6225 8100 1234 5679"）：12-19 位数字，可被单空格或连字符分隔
_BANK_CARD_CANDIDATE = re.compile(r"(?<!\d)\d(?:[ \-]?\d){11,18}(?!\d)")


def _is_id_card_shape(value: str) -> bool:
    """判断"纯数字"候选是否其实是身份证号：18 位纯数字（无空格/连字符）+ loose 通过。

    bank_card 候选与身份证有结构重叠（18 位都满足）。某些假身份证 Luhn 也能过，
    会被错误地以 bank_card 形式掩码（"3101 **** **** 4628"）。
    在 bank_card 阶段先剔除身份证形态，让其后续由 id_card 类目接管。
    """
    if any(c in value for c in (" ", "-")):
        return False
    return id_card_loose(value)


def detect(text: str) -> list[Match]:
    matches: list[Match] = []

    # 1) rules.yml 中带 regex 的类目（含 id_card 走 checksum）
    for class_name, cls in rules.data_classes.items():
        if not cls.enabled:
            continue
        if not cls.regex:
            continue
        try:
            pattern = re.compile(cls.regex)
        except re.error:
            continue  # 配置错误：单类跳过，不影响整体
        count, samples = _scan_regex(pattern, text, cls.validator, cls.capture_group)
        if count > 0:
            matches.append(Match(
                data_class=class_name,
                count=count,
                samples=tuple(samples),
            ))

    # 2) bank_card：候选数字串 → luhn 过滤
    bank_cls = rules.data_classes.get("bank_card")
    if bank_cls and bank_cls.enabled:
        count, samples = _scan_regex(_BANK_CARD_CANDIDATE, text, "luhn", 0,
                                     skip_predicate=_is_id_card_shape)
        if count > 0:
            matches.append(Match(
                data_class="bank_card",
                count=count,
                samples=tuple(samples),
            ))

    # 3) 公司词库：精确匹配（区分大小写依词库设定，这里默认大小写敏感）
    for class_name, terms in wordlib.terms_by_class.items():
        # 词库类目也受 rules.yml 的 enabled 开关控制（若声明在 rules.yml）
        cls = rules.data_classes.get(class_name)
        if cls and not cls.enabled:
            continue
        count = 0
        samples: list[str] = []
        for term in terms:
            if not term:
                continue
            occurrences = text.count(term)
            if occurrences > 0:
                count += occurrences
                if len(samples) < _SAMPLE_LIMIT:
                    samples.append(term)
        if count > 0:
            matches.append(Match(
                data_class=class_name,
                count=count,
                samples=tuple(samples),
            ))

    return matches


def _scan_regex(
    pattern: re.Pattern[str],
    text: str,
    validator_name: str,
    capture_group: int = 0,
    skip_predicate=None,
) -> tuple[int, list[str]]:
    """正则扫描；capture_group>0 时取该捕获组的内容做 sample 与 validator 校验。

    skip_predicate(value) → True 时跳过本次匹配（用于避免 bank_card 吞身份证号）。
    """
    count = 0
    samples: list[str] = []
    for m in pattern.finditer(text):
        if capture_group > 0:
            try:
                value = m.group(capture_group)
            except IndexError:
                value = m.group(0)
            if value is None:
                continue
        else:
            value = m.group(0)
        if skip_predicate is not None and skip_predicate(value):
            continue
        if validator_name and not validate(validator_name, value):
            continue
        count += 1
        if len(samples) < _SAMPLE_LIMIT:
            samples.append(_mask(value))
    return count, samples


def _mask(value: str) -> str:
    s = value.strip()
    if len(s) <= 6:
        return "***"
    return f"{s[:3]}***{s[-2:]}"
