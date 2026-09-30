"""保形掩码策略：把命中的敏感片段按规则掩码，保留长度/部分明文。"""
from __future__ import annotations

import re
from typing import Callable


_STRATEGIES: dict[str, Callable[[str], str]] = {}


def _register(name: str):
    def deco(fn: Callable[[str], str]) -> Callable[[str], str]:
        _STRATEGIES[name] = fn
        return fn
    return deco


def _mask_middle(s: str, pre: int, post: int, ch: str = "*") -> str:
    if len(s) <= pre + post:
        return s
    if post <= 0:
        return s[:pre] + ch * (len(s) - pre)
    return s[:pre] + ch * (len(s) - pre - post) + s[-post:]


@_register("mobile_phone")
def mobile_phone(s: str) -> str:
    return _mask_middle(s, 3, 4)


@_register("fixed_phone")
def fixed_phone(s: str) -> str:
    if not s:
        return s
    digits_only = re.sub(r"\D", "", s)
    if len(digits_only) <= 6:
        return s
    masked_digits = _mask_middle(digits_only, 4, 2)
    out: list[str] = []
    idx = 0
    for ch in s:
        if ch.isdigit():
            out.append(masked_digits[idx])
            idx += 1
        else:
            out.append(ch)
    return "".join(out)


@_register("id_card")
def id_card(s: str) -> str:
    return _mask_middle(s, 1, 2)


@_register("id_number")
def id_number(s: str) -> str:
    n = len(s)
    if n >= 10:
        return _mask_middle(s, 4, 4)
    if n >= 6:
        return _mask_middle(s, 2, 2)
    if n >= 3:
        return _mask_middle(s, 1, 1)
    return "*" * n


@_register("email")
def email(s: str) -> str:
    if "@" not in s:
        return s
    local, _, domain = s.partition("@")
    if not local:
        return s
    return local[0] + "***@" + domain


@_register("bank_card")
def bank_card(s: str) -> str:
    digits = re.sub(r"\D", "", s)
    if len(digits) <= 10:
        return s
    return f"{digits[:4]} **** **** {digits[-4:]}"


@_register("ipv4")
def ipv4(s: str) -> str:
    parts = s.split(".")
    if len(parts) != 4:
        return s
    return parts[0] + ".*.*.*"


@_register("ipv6")
def ipv6(s: str) -> str:
    if ":" not in s:
        return s
    head = s.split(":", 1)[0]
    return head + ":*:*:*:*:*:*:*"


@_register("api_key")
def api_key(s: str) -> str:
    if len(s) <= 8:
        return "*" * len(s)
    return _mask_middle(s, 4, 4)


@_register("password")
def password(s: str) -> str:
    """密码保形掩码：保留首尾，中间打星。

    长度分档（参考 id_number）：
      ≥10 位 → 首尾各 2 位
      ≥6  位 → 首尾各 1 位
      <6  位 → 全打星（短密码熵小，留首尾接近明文）
    """
    n = len(s)
    if n >= 10:
        return _mask_middle(s, 2, 2)
    if n >= 6:
        return _mask_middle(s, 1, 1)
    return "*" * n


@_register("private_key")
def private_key(s: str) -> str:
    return "[PRIVATE_KEY_REDACTED]"


@_register("db_connection")
def db_connection(s: str) -> str:
    new = re.sub(
        r"(?P<sc>[a-z][a-z0-9+]*://)[^/@\s'\"]+@",
        r"\g<sc>***@",
        s,
        flags=re.IGNORECASE,
    )
    if new != s:
        return new
    m = re.match(
        r"(?P<sc>[a-z][a-z0-9+]*://)(?P<host>[^/\s'\"]+)(?P<tail>.*)",
        s,
        flags=re.IGNORECASE,
    )
    if not m:
        return s
    host = m.group("host")
    if len(host) > 4:
        masked_host = host[0] + "*" * (len(host) - 2) + host[-1]
    else:
        masked_host = "*" * len(host)
    return m.group("sc") + masked_host + m.group("tail")


@_register("first_mask")
def first_mask(s: str) -> str:
    if not s:
        return s
    return s[0] + "*" * (len(s) - 1)


@_register("company_emp_id")
def company_emp_id(s: str) -> str:
    if not s.startswith("PYT") or len(s) <= 3:
        return s
    return "PYT" + "*" * (len(s) - 3)


@_register("head_tail_mask")
def head_tail_mask(s: str) -> str:
    if not s:
        return s
    if len(s) <= 2:
        return "*" * len(s)
    return s[0] + "***" + s[-1]


@_register("clear")
def clear(s: str) -> str:
    return ""


def apply(strategy: str, text: str) -> str | None:
    fn = _STRATEGIES.get(strategy)
    if fn is None:
        return None
    try:
        return fn(text)
    except Exception:
        return None


def has(strategy: str) -> bool:
    return strategy in _STRATEGIES


def names() -> tuple[str, ...]:
    return tuple(_STRATEGIES.keys())
