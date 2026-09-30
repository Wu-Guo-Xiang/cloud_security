"""文本归一化原语:对 extract 出的原文做编码/控制字符无害化。

补 detect 层盲区:正则与词库都基于"可见明文"假设,攻击者用零宽字符、
全角、Unicode Tag、双向控制字符或 base64 编码就能让正则失配。本模块
在 extract 之后、detect 之前做一次无损/可追溯的重写:

  - 剥离零宽 / 软连字符 / BOM (ig\\u200bnore previous 不再绕过)
  - 剥离 Unicode Tag (E0000-E007F) (隐藏文本注入)
  - 剥离双向控制字符 (Trojan Source: U+202A-U+202E / U+2066-U+2069)
  - NFKC 归一化(全角→半角,兼容字符→标准)
  - 对长度 ≥20 的 base64 候选尝试解码,可打印 ASCII 追加到扫描串
    (而非替换,原文也仍参与检测,避免误删信息)
  - URL 百分号编码整段 unquote 追加(而非替换),覆盖 AKIA%49OSF... 类拆词

不做的事:
  - ROT13 解码 — 正常英文也常被误判为 ROT13 形态,误报率高
  - hex 解码 — 与十六进制数据冲突(IPv6/哈希值/十六进制 ID)
  - 中文同形字归一化 — 工程上代价高且业务场景常需保留

借鉴来源:Anthropic-Cybersecurity-Skills/skills/detecting-indirect-prompt-injection
(Apache-2.0) 的 normalize() 设计。
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field


_INVISIBLE = "".join((
    "​",  # ZERO WIDTH SPACE
    "‌",  # ZERO WIDTH NON-JOINER
    "‍",  # ZERO WIDTH JOINER
    "⁠",  # WORD JOINER
    "﻿",  # BYTE ORDER MARK
    "­",  # SOFT HYPHEN
    # [v1.1-patch-3] LRM/RLM 是 invisible bidi mark,可插入任意位置不改显示,
    # 历史上漏覆盖会让 i‎gnore 类拆词攻击绕过 STRONG 正则
    "‎",  # U+200E LEFT-TO-RIGHT MARK
    "‏",  # U+200F RIGHT-TO-LEFT MARK
))
_INVISIBLE_RE = re.compile(f"[{re.escape(_INVISIBLE)}]")

_UNICODE_TAG_RE = re.compile(r"[\U000e0000-\U000e007f]")

_BIDI_CONTROL_RE = re.compile(r"[‪-‮⁦-⁩]")

# Base64 候选:连续 20+ 的 [A-Za-z0-9+/] + 可选 = 填充。
# 长度下限 20 避开 SHA1/SHA256 hex 串、JWT 头部等短 token 误报。
_BASE64_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])"
)

# 解码后判断:可打印字符比例阈值。低于此值视为二进制噪音,丢弃。
_PRINTABLE_RATIO = 0.85
# 单次扫描最多尝试解码 N 个候选,bound CPU 与上下文增长。
_MAX_DECODE_ATTEMPTS = 8
# 解码后 < 此长度视为噪音(随机 base64 短串经常解码出"看起来像文本"的内容)。
_MIN_DECODED_LEN = 6

# URL 百分号编码:%XX 两位 hex。检测到即尝试整段 unquote 追加。
# 与 base64 一样"追加不替换":原文也参与扫描,不影响其他 detector 的正则形态。
_URL_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")


@dataclass(frozen=True)
class NormalizeResult:
    text: str                                            # 归一化后文本,detector 直接消费
    original_text: str                                   # 原文,审计追溯用
    transforms: tuple[str, ...] = field(default_factory=tuple)
    decoded_appended: tuple[str, ...] = field(default_factory=tuple)

    @property
    def changed(self) -> bool:
        return bool(self.transforms) or bool(self.decoded_appended)


def normalize(text: str) -> NormalizeResult:
    """对输入文本做"无害化重写",在不丢信息的前提下让后续 detector 更难绕过。

    设计原则:
      - 只剥离"零信息"字符(零宽 / Unicode Tag / 双向控制),不丢可读字符
      - NFKC 把全角/兼容字符合并到 ASCII,语义等价
      - base64 候选解码后"追加"而非"替换",原文也参与扫描
      - decoded 内容用清晰分隔符前缀,避免与正文拼接造成误匹配
    """
    if not text:
        return NormalizeResult(text=text, original_text=text)

    original = text
    transforms: list[str] = []

    if _INVISIBLE_RE.search(text):
        text = _INVISIBLE_RE.sub("", text)
        transforms.append("strip_zero_width")

    if _UNICODE_TAG_RE.search(text):
        text = _UNICODE_TAG_RE.sub("", text)
        transforms.append("strip_unicode_tag")

    if _BIDI_CONTROL_RE.search(text):
        text = _BIDI_CONTROL_RE.sub("", text)
        transforms.append("strip_bidi_control")

    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        text = nfkc
        transforms.append("nfkc")

    decoded = _try_decode_base64(text)
    if decoded:
        # 用清晰分隔符,便于审计与避免误匹配
        text = text + "\n\n[[DECODED_BASE64]]\n" + "\n".join(decoded)
        transforms.append(f"decoded_base64:{len(decoded)}")

    url_decoded = _try_decode_url(text)
    if url_decoded is not None:
        text = text + "\n\n[[DECODED_URL]]\n" + url_decoded
        transforms.append("decoded_url")

    return NormalizeResult(
        text=text,
        original_text=original,
        transforms=tuple(transforms),
        decoded_appended=tuple(decoded),
    )


def _try_decode_base64(text: str) -> list[str]:
    out: list[str] = []
    for i, m in enumerate(_BASE64_CANDIDATE_RE.finditer(text)):
        if i >= _MAX_DECODE_ATTEMPTS:
            break
        token = m.group(0)
        try:
            padded = token + "=" * (-len(token) % 4)
            raw = base64.b64decode(padded, validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        if len(decoded) < _MIN_DECODED_LEN:
            continue
        printable = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
        if printable / len(decoded) < _PRINTABLE_RATIO:
            continue
        out.append(decoded)
    return out


def _try_decode_url(text: str) -> str | None:
    """整段 URL unquote 追加(仅当含 %XX 且解码后有变化)。

    追加不替换,原文照样参与扫描;避免误伤把 %20 解成空格影响其他 detector 正则。
    单次 unquote(不做递归解码),errors="replace" 避免非 UTF-8 序列导致抛异常。
    """
    if not _URL_ENCODED_RE.search(text):
        return None
    try:
        decoded = urllib.parse.unquote(text, errors="replace")
    except Exception:
        return None
    if decoded == text:
        return None
    return decoded
