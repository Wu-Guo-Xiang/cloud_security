"""PostToolUse Hook 入口 — Step 1: Secret 落盘后告警(fail-OPEN)。

由 Claude Code 在 Write / Edit / MultiEdit / NotebookEdit 完成后调用。
读磁盘上的实际文件 → 跑 credential_detector → 命中即 stderr 警告 + 弹框 +
stdout JSON(hookSpecificOutput.additionalContext,让模型也能看到并修复)。

为什么和 input_scanner.py 分目录:
  - 时序语义不同:Pre 是 fail-CLOSED 拦截,Post 是 fail-OPEN 告警
  - 数据来源不同:Pre 看 tool_input,Post 看磁盘真值
  - 失败影响不同:Pre 崩了用户会被阻断,Post 崩了只是丢一次告警
  - 物理隔离方便后续 Step 2(加 SAST/SCA)迭代,不污染 input 链路

复用边界:
  - 共享: detectors/credential_detector.py(纯函数正则)、lib/types.Match、config/paths
  - 不共享: extractor / action / logger / event,output 自己持有

退出码:
  始终 0(fail-OPEN)。任何异常 except 兜底,日志写一条 scanner_failure 也返回 0。
"""
from __future__ import annotations

import json
import sys
import time
import traceback
from pathlib import Path

try:
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # pragma: no cover
    pass

_THIS_DIR = Path(__file__).resolve().parent
_INPUT_DIR = _THIS_DIR.parent / "input"

# output 自己的模块优先,再回退到 input 共享的 detectors / lib / config
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))
if str(_INPUT_DIR) not in sys.path:
    sys.path.insert(1, str(_INPUT_DIR))


# Step 1 只跑 Write / Edit / MultiEdit / NotebookEdit。Bash 通道留给 Step 2。
_SUPPORTED_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})

# 跳过我们自己产物 / 缓存目录,避免扫描误命中并自吞性能
_SKIP_PATH_PARTS = (
    r"\test\logs",
    r"\test\temp",
    r"\test\output\desensitized_",
    r"\.git\\",
    r"\node_modules\\",
    r"\__pycache__\\",
)

_STAGE = "post_step1"


def _should_skip_path(file_path: str) -> str:
    """返回非空 reason 表示跳过,空串继续。"""
    if not file_path:
        return "no_path"
    low = file_path.replace("/", "\\").lower()
    for part in _SKIP_PATH_PARTS:
        if part.lower() in low:
            return f"path_filter:{part.strip('\\')}"
    return ""


def _matches_to_log(matches) -> list[dict]:
    out = []
    for m in matches:
        out.append({
            "data_class": m.data_class,
            "count": m.count,
            "samples": list(m.samples),
        })
    return out


def _emit_additional_context(text: str) -> None:
    """把 additionalContext 塞到 stdout,格式来自 Claude Code hook 协议:
        {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                "additionalContext": "..."}}
    Claude Code 会把这段 text 作为 system-reminder 注入回对话让模型看到。
    参考 security-guidance/hooks/security_reminder_hook.py handle PostToolUse 分支。

    print 失败不抛(fail-OPEN):stdout 被上游关闭 / 编码故障时静默忽略,不影响
    exit 0 也不影响 stderr / 弹框通道。"""
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": text,
        }
    }
    try:
        sys.stdout.write(json.dumps(payload, ensure_ascii=False))
        sys.stdout.write("\n")
        sys.stdout.flush()
    except Exception:  # pragma: no cover
        pass


def main() -> int:
    start = time.time()
    session_id = ""
    tool_name = ""

    try:
        from actions.warn_action import run as warn_run
        from detectors.credential_detector import detect as detect_credentials
        from detectors.dangerous_code_detector import detect as detect_dangerous_code
        from extractor import read_file
        from output_logger import log
        from posttool_event import PostToolEvent

        event = PostToolEvent.from_stdin()
        session_id = event.session_id
        tool_name = event.tool_name

        # 非目标工具:直接放行(matcher 已经过滤,这里是 defense-in-depth)
        if tool_name not in _SUPPORTED_TOOLS:
            log({
                "stage": _STAGE,
                "event": "PostToolUse",
                "session_id": session_id,
                "tool": tool_name,
                "phase": "skipped",
                "skipped_reason": "unsupported_tool",
                "duration_ms": int((time.time() - start) * 1000),
            })
            return 0

        # 工具失败:Claude 自己已经看到错误,我们不再扫
        if not event.tool_success:
            log({
                "stage": _STAGE,
                "event": "PostToolUse",
                "session_id": session_id,
                "tool": tool_name,
                "phase": "skipped",
                "skipped_reason": "tool_failed",
                "duration_ms": int((time.time() - start) * 1000),
            })
            return 0

        file_path = event.file_path
        skip = _should_skip_path(file_path)
        if skip:
            log({
                "stage": _STAGE,
                "event": "PostToolUse",
                "session_id": session_id,
                "tool": tool_name,
                "file_path": file_path,
                "phase": "skipped",
                "skipped_reason": skip,
                "duration_ms": int((time.time() - start) * 1000),
            })
            return 0

        read = read_file(file_path)
        if read.is_skipped:
            log({
                "stage": _STAGE,
                "event": "PostToolUse",
                "session_id": session_id,
                "tool": tool_name,
                "file_path": file_path,
                "phase": "skipped",
                "skipped_reason": read.skipped_reason,
                "duration_ms": int((time.time() - start) * 1000),
            })
            return 0

        matches = detect_credentials(read.text) + detect_dangerous_code(read.text, file_path)
        outcome = warn_run(
            file_path=read.source_label,
            matches=matches,
            truncated=read.truncated,
        )

        # additionalContext:命中时把结构化反馈写到 stdout,让 Claude Code
        # 把它作为 system-reminder 注入回对话。exit code 保持 0(fail-OPEN)。
        # 空 additional_context 时**不**输出任何 stdout —— 避免每次无命中都
        # 塞一条空提醒进对话。
        if outcome.additional_context:
            _emit_additional_context(outcome.additional_context)

        log({
            "stage": _STAGE,
            "event": "PostToolUse",
            "session_id": session_id,
            "tool": tool_name,
            "file_path": file_path,
            "phase": "scanned",
            "truncated": read.truncated,
            "matches": _matches_to_log(matches),
            "duration_ms": int((time.time() - start) * 1000),
            **outcome.audit,
        })
        return outcome.exit_code

    except SystemExit:
        raise
    except Exception as exc:
        # fail-OPEN:任何异常都不阻断,只记一条日志
        try:
            from output_logger import log
            log({
                "stage": _STAGE,
                "event": "scanner_failure",
                "session_id": session_id,
                "tool": tool_name,
                "error": str(exc),
                "traceback": traceback.format_exc(),
                "duration_ms": int((time.time() - start) * 1000),
            })
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
