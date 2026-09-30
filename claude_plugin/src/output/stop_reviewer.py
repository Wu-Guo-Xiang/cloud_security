"""Stop Hook 入口 — L2 语义级审计。

时机:Claude Code 一轮响应结束(Stop 事件)时调用。
链路:
  1. 从 stdin 拿 session_id
  2. 从 .claude/stop_review_baseline/<session_id>/ 读回本轮所有 PreToolUse 抓的原文
  3. 对每个文件构造 unified diff(原文 vs 磁盘当前)
  4. 打包所有 diff → LLM(claude-opus-4-7)审计
  5. 有 findings → additionalContext 塞回对话(Claude 看到并自纠)
     无 findings → stdout 完全空(避免污染上下文)
  6. 清理本 session 的 baseline 目录

失败模式:
  - baseline 不存在 / 空 → 说明本轮没改文件 → 静默 return 0
  - LLM 超时 / 失败 → 日志一条 error 后 return 0(fail-OPEN)
  - 任何异常 → 日志一条 scanner_failure 后 return 0

kill switch:
  CLOUD_SEC_STOP_REVIEW=0 → 直接 return 0
  CLOUD_HOOKS_TEST=1 时也跑,方便 smoke(smoke 自己控 baseline 目录)

同步调用:
  MVP 就阻塞在 LLM 上,timeout 25s + 5s buffer 应能塞进 Stop hook 30s 上限。
  未来切 asyncRewake 时把 review_diffs 移到 background task,并保留 additionalContext 通道。
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
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))
if str(_INPUT_DIR) not in sys.path:
    sys.path.insert(1, str(_INPUT_DIR))


_STAGE = "stop_review"


def _emit_additional_context(text: str) -> None:
    """与 output_scanner 相同的 stdout JSON 通道,但 hookEventName=Stop。"""
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "Stop",
            "additionalContext": text,
        }
    }
    try:
        sys.stdout.write(json.dumps(payload, ensure_ascii=False))
        sys.stdout.write("\n")
        sys.stdout.flush()
    except Exception:  # pragma: no cover
        pass


def _findings_to_log(findings) -> list[dict]:
    return [
        {
            "file": f.file,
            "severity": f.severity,
            "title": f.title,
        }
        for f in findings
    ]


def main() -> int:
    import os as _os

    if _os.environ.get("CLOUD_SEC_STOP_REVIEW", "") == "0":
        return 0

    start = time.time()
    session_id = ""

    try:
        from stop_review.baseline import clear_session, load_session
        from stop_review.diff_bundle import bundle_diffs, build_file_diff, format_findings
        from stop_review.llm import review_diffs
        from stop_review.logger import log

        try:
            # 读二进制 + utf-8-sig 吞掉可能的 UTF-8 BOM。
            raw = (sys.stdin.buffer.read() or b"{}").decode("utf-8-sig", errors="replace").lstrip("﻿")
            data = json.loads(raw)
        except Exception as exc:
            log({
                "stage": _STAGE, "event": "Stop", "phase": "skipped",
                "skipped_reason": f"stdin_invalid:{exc}",
                "duration_ms": int((time.time() - start) * 1000),
            })
            return 0

        session_id = str(data.get("session_id", ""))
        if not session_id:
            log({
                "stage": _STAGE, "event": "Stop", "phase": "skipped",
                "skipped_reason": "no_session_id",
                "duration_ms": int((time.time() - start) * 1000),
            })
            return 0

        # stop_hook_active=True 表示这次 Stop 是"上次 Stop 被 block 后又触发",
        # 避免我们自己形成死循环:additionalContext 不算 block,理论上不会走进这条,
        # 但防御性 skip 一下更稳
        if data.get("stop_hook_active"):
            log({
                "stage": _STAGE, "event": "Stop", "session_id": session_id,
                "phase": "skipped", "skipped_reason": "stop_hook_active",
                "duration_ms": int((time.time() - start) * 1000),
            })
            return 0

        entries = load_session(session_id)
        if not entries:
            # 本轮没改过文件,或者只改了 test/logs 之类被 skip 掉的 —— 静默 exit
            log({
                "stage": _STAGE, "event": "Stop", "session_id": session_id,
                "phase": "no_baseline",
                "duration_ms": int((time.time() - start) * 1000),
            })
            return 0

        file_diffs = [build_file_diff(e) for e in entries]
        bundle, included_paths = bundle_diffs(file_diffs)

        if not bundle:
            # 有 baseline 但没有有效 diff(全被跳过 / 内容未变)
            log({
                "stage": _STAGE, "event": "Stop", "session_id": session_id,
                "phase": "no_diff",
                "baseline_count": len(entries),
                "diff_count": sum(1 for d in file_diffs if d.changed and d.diff_text),
                "skipped": [{"file": d.file_path, "reason": d.skipped_reason}
                            for d in file_diffs if d.skipped_reason],
                "duration_ms": int((time.time() - start) * 1000),
            })
            clear_session(session_id)
            return 0

        outcome = review_diffs(bundle)

        if not outcome.ok:
            log({
                "stage": _STAGE, "event": "Stop", "session_id": session_id,
                "phase": "llm_failed",
                "included_files": included_paths,
                "input_chars": outcome.input_chars,
                "latency_ms": outcome.latency_ms,
                "model": outcome.model,
                "error": outcome.error,
                "duration_ms": int((time.time() - start) * 1000),
            })
            clear_session(session_id)
            return 0

        if outcome.findings:
            text = format_findings(outcome.findings)
            _emit_additional_context(text)

        log({
            "stage": _STAGE, "event": "Stop", "session_id": session_id,
            "phase": "scanned",
            "included_files": included_paths,
            "input_chars": outcome.input_chars,
            "latency_ms": outcome.latency_ms,
            "model": outcome.model,
            "findings_count": len(outcome.findings),
            "findings": _findings_to_log(outcome.findings),
            "duration_ms": int((time.time() - start) * 1000),
        })
        clear_session(session_id)
        return 0

    except SystemExit:
        raise
    except Exception as exc:
        try:
            from stop_review.logger import log
            log({
                "stage": _STAGE, "event": "scanner_failure",
                "session_id": session_id,
                "error": str(exc), "traceback": traceback.format_exc(),
                "duration_ms": int((time.time() - start) * 1000),
            })
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
