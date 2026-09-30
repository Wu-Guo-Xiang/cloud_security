"""diff 构造 + additionalContext 文案组装。

从 baseline + 当前磁盘态生成 unified diff bundle,长度受限;
LLM 返回的 findings 再拼成一段给 Claude 看的 markdown-ish 文本。

分成独立模块是因为:
  1. 单元测试可以纯字符串跑,不依赖 hook 环境
  2. Stop hook 主入口保持薄
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path

from stop_review.baseline import BaselineEntry
from stop_review.llm import (
    Finding,
    MAX_DIFF_CHARS_PER_FILE,
    MAX_TOTAL_DIFF_CHARS,
)


_DIFF_CONTEXT_LINES = 3


@dataclass(frozen=True)
class FileDiff:
    file_path: str
    diff_text: str
    baseline_existed: bool
    current_exists: bool
    changed: bool           # True 表示确实有变化(不 changed 的不喂 LLM)
    skipped_reason: str = ""


def _read_current(file_path: str) -> tuple[str, bool, str]:
    """(text, exists, skipped_reason)。二进制/超大跳过。"""
    p = Path(file_path)
    if not p.exists():
        return "", False, ""
    try:
        size = p.stat().st_size
    except OSError as exc:
        return "", True, f"stat_failed:{exc}"
    if size > 1024 * 1024:
        return "", True, "too_large"
    try:
        with p.open("rb") as f:
            head = f.read(8192)
            if b"\x00" in head:
                return "", True, "binary"
            rest = f.read()
        data = head + rest
    except OSError as exc:
        return "", True, f"read_failed:{exc}"
    try:
        return data.decode("utf-8", errors="replace"), True, ""
    except Exception:
        return data.decode("latin-1", errors="replace"), True, ""


def build_file_diff(entry: BaselineEntry) -> FileDiff:
    if entry.skipped_reason:
        return FileDiff(
            file_path=entry.file_path, diff_text="",
            baseline_existed=entry.existed, current_exists=False,
            changed=False, skipped_reason=f"baseline_{entry.skipped_reason}",
        )

    current_text, current_exists, skip_now = _read_current(entry.file_path)
    if skip_now:
        return FileDiff(
            file_path=entry.file_path, diff_text="",
            baseline_existed=entry.existed, current_exists=current_exists,
            changed=False, skipped_reason=f"current_{skip_now}",
        )

    # 文件被删了 —— 也是一种"变化",但 Stop-review 关心的是引入了什么新代码,
    # 删除通常没有安全风险,跳过喂 LLM 但仍在日志里记一下
    if entry.existed and not current_exists:
        return FileDiff(
            file_path=entry.file_path, diff_text="",
            baseline_existed=True, current_exists=False,
            changed=True, skipped_reason="file_deleted",
        )

    before = entry.content
    after = current_text
    if before == after:
        return FileDiff(
            file_path=entry.file_path, diff_text="",
            baseline_existed=entry.existed, current_exists=True,
            changed=False,
        )

    diff = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{entry.file_path}" + ("" if entry.existed else "  (new file)"),
        tofile=f"b/{entry.file_path}",
        n=_DIFF_CONTEXT_LINES,
    )
    diff_text = "".join(diff)
    if len(diff_text) > MAX_DIFF_CHARS_PER_FILE:
        diff_text = diff_text[:MAX_DIFF_CHARS_PER_FILE] + "\n... [diff truncated] ...\n"
    return FileDiff(
        file_path=entry.file_path, diff_text=diff_text,
        baseline_existed=entry.existed, current_exists=True, changed=True,
    )


def bundle_diffs(file_diffs: list[FileDiff]) -> tuple[str, list[str]]:
    """把有效 diff 拼成一份大 bundle;返回 (bundle_text, included_file_paths)。

    超过 MAX_TOTAL_DIFF_CHARS 时按顺序截,已包含的完整,后面的丢弃(比中间截半好读)。
    """
    included: list[str] = []
    parts: list[str] = []
    total = 0
    for fd in file_diffs:
        if not fd.changed or not fd.diff_text:
            continue
        piece = f"=== {fd.file_path} ===\n{fd.diff_text}\n"
        if total + len(piece) > MAX_TOTAL_DIFF_CHARS:
            parts.append(f"\n[... {len(file_diffs) - len(included)} more file(s) omitted due to size cap ...]\n")
            break
        parts.append(piece)
        included.append(fd.file_path)
        total += len(piece)
    return "".join(parts), included


_HEADER = "[cloud-security] Stop-review(LLM 语义级)发现潜在安全问题:"
_FOOTER = (
    "以上是 LLM 语义审计发现的问题(正则/AST 抓不到的那些)。请评估:\n"
    "  1. 若确实是漏洞,请修复并重新写入文件\n"
    "  2. 若是误报,可在代码里加注释说明为什么此处安全\n"
    "  3. 若不清楚,可跟用户确认威胁模型"
)


def format_findings(findings: list[Finding]) -> str:
    if not findings:
        return ""
    lines = [_HEADER, ""]
    for i, f in enumerate(findings, 1):
        lines.append(f"{i}. [{f.severity}] {f.title}")
        lines.append(f"   文件: {f.file}")
        if f.evidence:
            lines.append(f"   证据: {f.evidence}")
        if f.why:
            lines.append(f"   影响: {f.why}")
        if f.fix:
            lines.append(f"   建议: {f.fix}")
        lines.append("")
    lines.append(_FOOTER)
    return "\n".join(lines)
