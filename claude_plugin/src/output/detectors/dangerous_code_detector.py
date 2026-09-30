"""落盘代码危险模式扫描 — 移植自 security-guidance 的 check_patterns()。

与 credential_detector 并列(PostToolUse fail-OPEN 告警):
  - credential_detector 覆盖"落盘凭证"(AWS/GH PAT/PEM 私钥/DB 连接串)
  - dangerous_code_detector 覆盖"落盘危险代码"(eval/exec、pickle.load、
    yaml.load、subprocess shell=True、innerHTML XSS、TLS 关校验、AES-ECB 等)

启用策略:
  Step 2 只启用 13 条 severity 硬的规则,其余走 dangerous_code_patterns._DEFAULT_DISABLED。
  detect() 在扫描前用 is_enabled(rule_name) 过滤。

fail-OPEN 语义:
  任何一条规则 regex 崩了就跳过它继续跑下一条,detect() 永远返回 list(可能为空)
  不抛异常。output_scanner.py 顶层的 try/except 兜底不变。

样例截断:
  每类最多 3 条样例(与 credential_detector 一致),单条 <= 80 字符,防止业务代码
  大段泄露到弹框/日志。
"""
from __future__ import annotations

import re

from lib.types import Match

from detectors.dangerous_code_patterns import SECURITY_PATTERNS, is_enabled


_MAX_SAMPLES_PER_RULE = 3
_SAMPLE_MAX_LEN = 80


def _snippet(text: str, span: tuple[int, int]) -> str:
    """从命中位置截 <=80 字符片段,strip + 单行化,避免弹框换行炸屏。"""
    start, end = span
    # 命中片段本身可能只有 3-5 字符(如 substring "innerHTML"),扩上下文各 20 字。
    ctx_start = max(0, start - 20)
    ctx_end = min(len(text), end + 20)
    raw = text[ctx_start:ctx_end]
    return raw.strip().replace("\n", " ").replace("\r", " ")[:_SAMPLE_MAX_LEN]


def detect(text: str, file_path: str) -> list[Match]:
    """扫描落盘文本,返回命中列表。每条启用规则最多产出一条 Match(聚合 count 与 samples)。

    Args:
        text: 落盘后从磁盘读回的文件内容(read_file 已做 truncate/skip)。
        file_path: 文件路径,用于 path_filter / path_check 判断,大小写不敏感,
                   反斜杠会被规范化。传空串表示"未知路径"——path_filter 规则会全部跳过。

    Returns:
        list[Match]。空列表表示无命中。detect() 不抛异常。
    """
    if not text:
        return []
    normalized_path = (file_path or "").replace("\\", "/").lstrip("/")
    out: list[Match] = []

    for pattern in SECURITY_PATTERNS:
        rule_name = pattern.get("ruleName", "")
        if not is_enabled(rule_name):
            continue

        # path_filter:门禁。不满足即整条规则跳过。
        if "path_filter" in pattern:
            try:
                if not pattern["path_filter"](normalized_path):
                    continue
            except Exception:
                continue  # 门禁本身崩了保守跳过,不当作命中

        samples: list[str] = []
        count = 0

        # path_check:纯路径规则(如 .github/workflows/)。当前默认全禁用,留兼容。
        if "path_check" in pattern:
            try:
                if pattern["path_check"](normalized_path):
                    count += 1
                    samples.append(f"[path:{normalized_path[:_SAMPLE_MAX_LEN - 6]}]")
            except Exception:
                pass

        # substrings:字面量子串。全文扫,不重叠。
        if "substrings" in pattern:
            for sub in pattern["substrings"]:
                if not sub:
                    continue
                idx = 0
                while True:
                    hit = text.find(sub, idx)
                    if hit < 0:
                        break
                    count += 1
                    if len(samples) < _MAX_SAMPLES_PER_RULE:
                        samples.append(_snippet(text, (hit, hit + len(sub))))
                    idx = hit + len(sub)

        # regex:正则。单条规则崩不影响其他规则(fail-OPEN)。
        if "regex" in pattern:
            try:
                for m in re.finditer(pattern["regex"], text):
                    count += 1
                    if len(samples) < _MAX_SAMPLES_PER_RULE:
                        samples.append(_snippet(text, m.span()))
            except Exception:
                pass

        if count > 0:
            out.append(Match(
                data_class=rule_name,
                count=count,
                samples=tuple(samples),
            ))

    return out
