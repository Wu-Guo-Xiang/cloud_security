"""保形掩码策略：把命中的敏感片段按规则掩码，保留长度/部分明文，
而非用 `[LABEL]` 占位符整段替换。

借鉴 com.lzhpo.sensitive-spring-boot-starter（Apache-2.0）的 21 种策略，
只移植适合"纯文本扫描 + 无注解"场景的子集，舍弃以下不适用项：
  - AES / DES / RSA / BASE64  需要密钥管理；脱敏目标是"不让数据外流"，
                              用可逆加密反而是反模式
  - CHINESE_NAME / ADDRESS    属语义类目，应由 L2 NER 走 pseudonymizer
                              的一致性占位符（[公司A]/[人员A]）处理
  - CUSTOMIZE_HANDLER         依赖 Java 反射 + Spring Bean

每个策略：纯函数 (str) -> str。失败时 caller 应回退到 [LABEL] 占位符。
"""
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
    """保留前 pre 位与后 post 位，中间用 ch 填充；长度不足时原样返回。"""
    if len(s) <= pre + post:
        return s
    if post <= 0:
        return s[:pre] + ch * (len(s) - pre)
    return s[:pre] + ch * (len(s) - pre - post) + s[-post:]


# --- 结构化字段 ---------------------------------------------------------


@_register("mobile_phone")
def mobile_phone(s: str) -> str:
    """13812345678 -> 138****5678"""
    return _mask_middle(s, 3, 4)


@_register("fixed_phone")
def fixed_phone(s: str) -> str:
    """010-86551122 / 01086551122 -> 010-86***22 / 0108****22

    保留原分隔符；先按数字位计算掩码位置，再回填到原串。
    """
    if not s:
        return s
    digits_only = re.sub(r"\D", "", s)
    if len(digits_only) <= 6:
        return s
    masked_digits = _mask_middle(digits_only, 4, 2)
    # 把原串里的数字按位替换为 masked_digits 对应位置
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
    """330106199410258824 -> 3***************24 (前 1 后 2)"""
    return _mask_middle(s, 1, 2)


@_register("id_number")
def id_number(s: str) -> str:
    """通用"号"型字段保形掩码：审计可读 + 中段不可见。

    给 LLM 识别出的 ID_NUMBER（编号 / 账号 / 信用代码 / 工号 / 行号 / 发票号 / 付款编号 等）
    以及 LLM 错把长字母数字串归到 PRODUCT 时使用，避免顺序占位符（[产品AF]）噪声。

    规则：
      - 长度 ≥ 10：保留前 4 + 后 4，中间统一打 *。
      - 长度 6-9：保留首 2 + 末 2。
      - 长度 ≤ 5：除首末各 1 字符外全部打 *。
    """
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
    """abc@def.com -> a***@def.com（保留首字符 + 整个域名）"""
    if "@" not in s:
        return s
    local, _, domain = s.partition("@")
    if not local:
        return s
    return local[0] + "***@" + domain


@_register("bank_card")
def bank_card(s: str) -> str:
    """6217 0010 2004 5576 812 -> 6217 **** **** 6812

    输入可能含空格/连字符；先抽数字、保留前 4 后 4，再统一用空格格式化。
    """
    digits = re.sub(r"\D", "", s)
    if len(digits) <= 10:
        return s
    return f"{digits[:4]} **** **** {digits[-4:]}"


@_register("ipv4")
def ipv4(s: str) -> str:
    """10.211.55.42 -> 10.*.*.*（只露第一段）"""
    parts = s.split(".")
    if len(parts) != 4:
        return s
    return parts[0] + ".*.*.*"


@_register("ipv6")
def ipv6(s: str) -> str:
    """2001:db8::1 -> 2001:*:*:*:*:*:*:*（只露第一段）"""
    if ":" not in s:
        return s
    head = s.split(":", 1)[0]
    return head + ":*:*:*:*:*:*:*"


# --- 凭证 / 密钥 -------------------------------------------------------


@_register("api_key")
def api_key(s: str) -> str:
    """AKIAIOSFODNN7EXAMPLE -> AKIA************MPLE（前 4 后 4）"""
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
    """完全掩盖（私钥不能露任何片段）。"""
    return "[PRIVATE_KEY_REDACTED]"


@_register("db_connection")
def db_connection(s: str) -> str:
    """mysql://user:pass@host:3306/db -> mysql://***@host:3306/db

    覆盖三种形态：
      1) scheme://user:pass@host... → 凭证段全部 ***
      2) scheme://user@host...      → 用户段 ***（如无密码）
      3) scheme://host...           → 主机前后各留 1 字符
    路径段（库名）保留以便审计；如需更激进，调用方自行追加 first_mask。
    """
    # 1) + 2)：有 @ 的情况，凭证段都打 ***
    new = re.sub(
        r"(?P<sc>[a-z][a-z0-9+]*://)[^/@\s'\"]+@",
        r"\g<sc>***@",
        s,
        flags=re.IGNORECASE,
    )
    if new != s:
        return new
    # 3) 无凭证：遮主机中段
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


# --- 通用 ---------------------------------------------------------------


@_register("first_mask")
def first_mask(s: str) -> str:
    """只露首字符，其余打星。"""
    if not s:
        return s
    return s[0] + "*" * (len(s) - 1)


@_register("company_emp_id")
def company_emp_id(s: str) -> str:
    """普雅公司工号 PYTxxx / PYExxx → PYT*** / PYE***：保留 3 字符前缀，数字位全打星。"""
    if len(s) <= 3 or s[:3] not in ("PYT", "PYE"):
        return s
    return s[:3] + "*" * (len(s) - 3)


@_register("head_tail_mask")
def head_tail_mask(s: str) -> str:
    """首末各保留 1 字符，中间固定 *** 三个星。

    用于不定长中文片段（地址 / 长机构名等），让 Claude 仍能看到结构性首末字
    （省/市/区/号），但中间细节全部抹去。

    示例：
      "广东省深圳市南山区科苑南路3168号" -> "广***号"
      "广东省深圳市"                  -> "广***市"
    """
    if not s:
        return s
    if len(s) <= 2:
        return "*" * len(s)
    return s[0] + "***" + s[-1]


@_register("clear")
def clear(s: str) -> str:
    """清空。"""
    return ""


# --- 派遣 ---------------------------------------------------------------


def apply(strategy: str, text: str) -> str | None:
    """按名查找并执行；未注册或抛错时返回 None，调用方应回退到 [LABEL] 占位符。"""
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
