"""Unicode 安全清洗与混淆绕过防御模块 (借鉴自 DeepAgents 安全架构)。

专门防范黑客或内部违规人员利用以下欺骗手段绕过安全策略与关键词/正则检测：
1. 零宽隐蔽字符 (Zero-Width Characters，如 \\u200B, \\uFEFF, \\u200C 等)；
2. 双向文本控制欺骗 (BiDi Overrides / Isolates)；
3. 跨语言同形异义字欺骗 (Confusables / Homoglyphs，如西里尔字母 \\u0430 伪装拉丁字母 a)；
4. 全角/半角混合字符欺骗。
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Any

# 危险的零宽、不可见或格式化欺骗控制码
_DANGEROUS_CODEPOINTS: frozenset[int] = frozenset(
    {
        # BiDi 控制字符 (方向嵌入、强制覆盖、隔离)
        *range(0x202A, 0x202F),
        *range(0x2066, 0x206A),
        # 零宽与不可见控制字符 (最常被用于拆分关键字如 r\u200Bm -rf)
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x2060,  # WORD JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
        0x00AD,  # SOFT HYPHEN
        0x034F,  # COMBINING GRAPHEME JOINER
        0x115F,  # HANGUL CHOSEONG FILLER
        0x1160,  # HANGUL JUNGSEONG FILLER
    }
)

_DANGEROUS_CHARACTERS: frozenset[str] = frozenset(
    chr(cp) for cp in _DANGEROUS_CODEPOINTS
)

# 高危跨脚本同形异义字映射字典 (西里尔/希腊/全角 -> 标准 ASCII 字符)
CONFUSABLES: dict[str, str] = {
    # 西里尔字母 (Cyrillic)
    "\u0430": "a",  # CYRILLIC SMALL LETTER A
    "\u0435": "e",  # CYRILLIC SMALL LETTER IE
    "\u043e": "o",  # CYRILLIC SMALL LETTER O
    "\u0440": "p",  # CYRILLIC SMALL LETTER ER
    "\u0441": "c",  # CYRILLIC SMALL LETTER ES
    "\u0443": "y",  # CYRILLIC SMALL LETTER U
    "\u0445": "x",  # CYRILLIC SMALL LETTER HA
    "\u043d": "h",  # CYRILLIC SMALL LETTER EN
    "\u0456": "i",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "\u0458": "j",  # CYRILLIC SMALL LETTER JE
    "\u043a": "k",  # CYRILLIC SMALL LETTER KA
    "\u0455": "s",  # CYRILLIC SMALL LETTER DZE
    # 希腊字母 (Greek)
    "\u03b1": "a",  # GREEK SMALL LETTER ALPHA
    "\u03b5": "e",  # GREEK SMALL LETTER EPSILON
    "\u03bf": "o",  # GREEK SMALL LETTER OMICRON
    "\u03c1": "p",  # GREEK SMALL LETTER RHO
    "\u03c7": "x",  # GREEK SMALL LETTER CHI
    "\u03ba": "k",  # GREEK SMALL LETTER KAPPA
    "\u03bd": "v",  # GREEK SMALL LETTER NU
    "\u03c4": "t",  # GREEK SMALL LETTER TAU
    # 全角英文字符 (Fullwidth Latin)
    "\uff41": "a",
    "\uff42": "b",
    "\uff43": "c",
    "\uff44": "d",
    "\uff45": "e",
    "\uff46": "f",
    "\uff47": "g",
    "\uff48": "h",
    "\uff49": "i",
    "\uff4a": "j",
    "\uff4b": "k",
    "\uff4c": "l",
    "\uff4d": "m",
    "\uff4e": "n",
    "\uff4f": "o",
    "\uff50": "p",
    "\uff51": "q",
    "\uff52": "r",
    "\uff53": "s",
    "\uff54": "t",
    "\uff55": "u",
    "\uff56": "v",
    "\uff57": "w",
    "\uff58": "x",
    "\uff59": "y",
    "\uff5a": "z",
}


@dataclass(frozen=True)
class UnicodeEvasionIssue:
    """检测到的 Unicode 混淆绕过痕迹"""
    position: int
    char: str
    codepoint: str
    name: str


def strip_dangerous_unicode(text: str) -> str:
    """剔除文本中的所有零宽字符和隐蔽控制字符"""
    if not text:
        return ""
    return "".join(ch for ch in text if ch not in _DANGEROUS_CHARACTERS)


def normalize_confusables(text: str) -> str:
    """将同形异义字（如西里尔字母、全角字母）还原为其标准 ASCII 字符"""
    if not text:
        return ""
    # 首先执行 Unicode NFKC 兼容等价分解重组 (自动转换大部分全角字符等)
    normalized = unicodedata.normalize("NFKC", text)
    # 针对西里尔等高危同形字符执行精细映射替换
    chars = []
    for ch in normalized:
        chars.append(CONFUSABLES.get(ch, ch))
    return "".join(chars)


def sanitize_for_security_matching(text: str) -> str:
    """一站式安全预处理：剔除零宽字符 + 归一化同形异义字

    用于在正则与关键词匹配引擎中作为二级防绕过穿透检查。
    """
    if not text:
        return ""
    clean = strip_dangerous_unicode(text)
    clean = normalize_confusables(clean)
    return clean


def detect_unicode_evasion(text: str) -> list[UnicodeEvasionIssue]:
    """诊断文本中是否存在刻意的 Unicode 隐形与混淆绕过特征"""
    if not text:
        return []
    issues: list[UnicodeEvasionIssue] = []
    for idx, ch in enumerate(text):
        if ch in _DANGEROUS_CHARACTERS:
            issues.append(
                UnicodeEvasionIssue(
                    position=idx,
                    char=ch,
                    codepoint=f"U+{ord(ch):04X}",
                    name=unicodedata.name(ch, "UNKNOWN_INVISIBLE_CONTROL"),
                )
            )
        elif ch in CONFUSABLES:
            issues.append(
                UnicodeEvasionIssue(
                    position=idx,
                    char=ch,
                    codepoint=f"U+{ord(ch):04X}",
                    name=unicodedata.name(ch, "CONFUSABLE_CHARACTER"),
                )
            )
    return issues
