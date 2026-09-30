"""凭证类敏感数据识别（fatal 类目优先）。

覆盖 rules.yml 中 severity=fatal 的三个类目，以及 db_connection：
  - api_key：AWS / Bearer / 通用 32+ hex/base64 形态
  - private_key：PEM 头部标记（RSA / EC / OPENSSH / PGP）
  - prod_password：生产密码模式（password = "..." / passwd: ...）
  - db_connection：JDBC / postgres / mysql / mongo / redis 等连接串

样本上限 5 条 / 类，避免日志膨胀；count 反映真实命中次数用于规模加权。
"""
from __future__ import annotations

import re

from lib.types import Match


_SAMPLE_LIMIT = 5


# --- 凭证识别正则 -------------------------------------------------------

# AWS Access Key ID / Secret + 通用强凭证形态
# _STRONG = True 标记的正则会被 detect_strong() 收纳:这些正则前缀 + 长度都极特异,
# 误报率极低,适合用作 Pre 阶段 fail-CLOSED 阻断(Step 3)。
# Bearer / JWT 误报率较高(演示文档常出现),不进 strong 子集,只在 detect() 里跑,
# 由 PostToolUse 弹框警告兜底。
_API_KEY_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), True),                       # AWS Access Key ID
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), True),                       # AWS STS temporary
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), True),                 # Google API Key
    (re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), True),                    # GitHub PAT (classic)
    (re.compile(r"\bgho_[0-9A-Za-z]{36}\b"), True),                    # GitHub OAuth
    # GitHub fine-grained PAT:github_pat_<22>_<59>,底数 82 位 alnum+_
    (re.compile(r"\bgithub_pat_[0-9A-Za-z]{22}_[0-9A-Za-z]{59}\b"), True),
    # OpenAI / Anthropic:字符类含 `-`,覆盖 sk-ant-api03-xxx / sk-proj-xxx-xxx 新格式
    # {20,} 保证不会被 `sk-a` 这种短前缀命中;\b 收尾容忍 `-` 结尾(见 probe boundary 用例)
    (re.compile(r"\bsk-[A-Za-z0-9\-]{20,}\b"), True),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), True),           # Slack
    (re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.=]{20,}\b", re.IGNORECASE), False),  # Bearer
    # JWT:三段 base64url(易误命中,弱)
    (re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"), False),
]

_PRIVATE_KEY_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), True),
]

# 生产密码：仅匹配 password / passwd / pwd 后的赋值，且值含字母+数字/符号（降低误报）
# 演示代码常出现 password = "test123" 等,误报率较高,不入 strong。
_PROD_PASSWORD_PATTERNS = [
    (re.compile(
        r"""(?ix)
        \b (?: password | passwd | pwd | secret )
        \s* [:=]\s*
        ['"]?
        (?=[^\s'"]{8,})           # 至少 8 位
        (?=[^\s'"]*[A-Za-z])      # 含字母
        (?=[^\s'"]*[\d!@#\$%\^&\*\-_+=])  # 含数字或符号
        [^\s'"]+
        ['"]?
        """
    ), False),
]

# DB 连接串误报率中等(配置示例常见),不入 strong
_DB_CONNECTION_PATTERNS = [
    (re.compile(
        r"""(?ix)
        \b (?: jdbc:[a-z]+ | postgres(?:ql)? | mysql | mongodb(?:\+srv)? | redis | mssql | oracle )
        ://
        (?: [^/\s:'"]+ : [^/@\s'"]+ @ )?     # 可选 user:pwd@
        [^/\s'"]+                            # host[:port]
        (?: /[^\s'"]* )?                     # 可选 db path
        """
    ), False),
]


_RULES = [
    ("private_key", _PRIVATE_KEY_PATTERNS),
    ("api_key", _API_KEY_PATTERNS),
    ("prod_password", _PROD_PASSWORD_PATTERNS),
    ("db_connection", _DB_CONNECTION_PATTERNS),
]


def detect(text: str) -> list[Match]:
    """全量检测:跑所有规则(含 strong + weak)。供 PostToolUse 警告链路使用。"""
    return _detect(text, strong_only=False)


def detect_strong(text: str) -> list[Match]:
    """强凭证检测:只跑 _STRONG=True 的规则,误报率极低。

    供 PreToolUse Write/Edit 内容预扫使用 — 命中即 fail-CLOSED 阻断,
    凭证根本不落盘。Bearer / JWT / password= / DB 连接串等高误报项不在此处,
    避免误阻断正常开发(由 PostToolUse 警告兜底)。
    """
    return _detect(text, strong_only=True)


def _detect(text: str, *, strong_only: bool) -> list[Match]:
    matches: list[Match] = []
    for class_name, patterns in _RULES:
        samples: list[str] = []
        count = 0
        for p, is_strong in patterns:
            if strong_only and not is_strong:
                continue
            for m in p.finditer(text):
                count += 1
                if len(samples) < _SAMPLE_LIMIT:
                    samples.append(_mask(m.group(0)))
        if count > 0:
            matches.append(Match(
                data_class=class_name,
                count=count,
                samples=tuple(samples),
            ))
    return matches


def _mask(value: str) -> str:
    """日志样本脱敏：保留前 4 / 后 2 字符，中间打码。"""
    s = value.strip()
    if len(s) <= 8:
        return "***"
    return f"{s[:4]}***{s[-2:]}"
