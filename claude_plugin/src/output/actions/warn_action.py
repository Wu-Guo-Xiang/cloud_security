"""warn_action:命中后 stderr + 弹框 + additionalContext 三通道告警,不阻断。

PostToolUse 阶段代码已经落盘,fail-CLOSED 没意义,只能 fail-OPEN 报警。三条通道各司其职:
  - additionalContext(主通道,给模型看):stdout JSON 里塞 hookSpecificOutput,
    Claude Code 会把 text 作为 system-reminder 注入回对话,模型能自己看到并回退/修复。
    exit 0 保留,不 block。参考 security-guidance/hooks/security_reminder_hook.py 2170 附近。
  - 弹框 (lib.confirm.notify):MB_OK + TOPMOST + SYSTEMMODAL,15s 自动关。给用户看,
    确保即使模型静默用户也知道。
  - stderr:CLI debug 用,VSCode 扩展不渲染 PostToolUse 的 stderr,但 CI/命令行能看到。
  - exit 0 不阻断:PostToolUse 的 exit 2 不会回滚已落盘文件。
  - 返回 audit 数据供 logger 写盘。

复用边界:lib.confirm 来自 input/,output_scanner.py 已 sys.path.insert input_dir。
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any

from detectors.dangerous_code_patterns import RULE_NAME_TO_REMINDER
from lib import confirm
from lib.types import Match


_CREDENTIAL_REMINDER = (
    "⚠️ Security Warning: 检测到凭证类敏感数据(API key / token / private key / "
    "密码等)已被写入代码。请立即:\n"
    "  1. 从代码中删除该值(不要 commit,不要 push)\n"
    "  2. 在对应控制台撤销 / 轮换该凭证 —— 已落盘 = 已泄漏\n"
    "  3. 改为从环境变量或 Secret Manager 读取"
)

_ADDITIONAL_CONTEXT_HEADER = "[cloud-security] PostToolUse 扫描发现问题,请查看:"
_ADDITIONAL_CONTEXT_FOOTER = (
    "请根据上述提示修复(删除敏感值 / 替换为安全 API),或在代码注释里说明为什么"
    "此处是安全的,然后重新写入文件。如果不修,Claude 用户可能在生产环境中触发风险。"
)


@dataclass(frozen=True)
class WarnOutcome:
    exit_code: int
    audit: dict[str, Any]
    additional_context: str = ""


def _reminder_for(data_class: str) -> str:
    """危险代码规则查表,否则按凭证类兜底。credential_detector 的 data_class
    命名不在 RULE_NAME_TO_REMINDER 里,统一给一个泛化的凭证提醒。"""
    hit = RULE_NAME_TO_REMINDER.get(data_class)
    if hit:
        return hit
    return _CREDENTIAL_REMINDER


def _build_additional_context(
    *, file_path: str, matches: list[Match], truncated: bool
) -> str:
    """给 Claude 看的 markdown-ish 文本。按 data_class 去重 reminder,避免同一条
    规则重复出现;单文件多命中在 header 里体现次数。"""
    lines = [_ADDITIONAL_CONTEXT_HEADER, "", f"文件: {file_path}", ""]
    seen_reminders: set[str] = set()
    for m in matches:
        reminder = _reminder_for(m.data_class)
        # 同一份 reminder 只贴一次(pickle / yaml 多规则共享同一段文案)
        key = f"{m.data_class}|{reminder}"
        if key in seen_reminders:
            continue
        seen_reminders.add(key)
        samples = ", ".join(m.samples[:3]) if m.samples else "(无样例)"
        lines.append(f"[{m.data_class}] 命中 {m.count} 处  样例: {samples}")
        lines.append(reminder)
        lines.append("")
    if truncated:
        lines.append("注: 文件超过 1MB,只扫描了前 1MB,可能有遗漏。")
        lines.append("")
    lines.append(_ADDITIONAL_CONTEXT_FOOTER)
    return "\n".join(lines)


def run(*, file_path: str, matches: list[Match], truncated: bool) -> WarnOutcome:
    if not matches:
        return WarnOutcome(
            exit_code=0,
            audit={"action": "pass", "match_count": 0},
            additional_context="",
        )

    # === stderr 通道(给 CLI debug / 上游修复后启用)===
    lines = [
        f"⚠️  PostToolUse 安全告警 — 代码已落盘: {file_path}",
        "  以下凭证类敏感数据被检出,请立即清理(从代码删除 + 撤销该凭证):",
    ]
    total = 0
    classes: list[str] = []
    for m in matches:
        total += m.count
        classes.append(m.data_class)
        samples = ", ".join(m.samples[:3]) if m.samples else "(无样例)"
        lines.append(f"    - {m.data_class}: {m.count} 处  样例: {samples}")
    if truncated:
        lines.append("  注: 文件超过 1MB,只扫描了前 1MB,可能有遗漏。")
    lines.append("")
    sys.stderr.write("\n".join(lines))
    sys.stderr.flush()

    # === 弹框通道(给用户看:即便模型没响应,用户也能看到)===
    # notify 是 best-effort:非 Windows / 测试旁路 / 超时全部静默,不影响 exit 0
    notify_title = "Claude 代码安全告警"
    notify_body = _build_popup_body(file_path, matches, truncated, total)
    confirm.notify(notify_title, notify_body)

    # === additionalContext(给模型看)===
    additional_context = _build_additional_context(
        file_path=file_path, matches=matches, truncated=truncated
    )

    return WarnOutcome(
        exit_code=0,  # fail-OPEN,不阻断
        audit={
            "action": "warn",
            "match_count": total,
            "data_classes": classes,
            "notify": "sent",  # 仅表示 notify 调用已发起,不代表用户真看到
            "additional_context_len": len(additional_context),
        },
        additional_context=additional_context,
    )


def _build_popup_body(file_path: str, matches: list[Match], truncated: bool, total: int) -> str:
    """弹框正文:简短一屏内可读,样例已 mask。"""
    parts = [
        f"Claude 生成的代码已落盘,检出 {total} 处凭证敏感数据:",
        f"文件: {file_path}",
        "",
    ]
    for m in matches:
        samples = ", ".join(m.samples[:3]) if m.samples else "(无样例)"
        parts.append(f"  • {m.data_class}: {m.count} 处  样例: {samples}")
    if truncated:
        parts.append("")
        parts.append("注: 文件超过 1MB,只扫描了前 1MB,可能有遗漏。")
    parts.append("")
    parts.append("行动建议:")
    parts.append("  1. 立即从代码中删除该凭证")
    parts.append("  2. 在控制台撤销 / 轮换该凭证")
    parts.append("  3. 改为从环境变量 / Secret Manager 读取")
    return "\n".join(parts)

