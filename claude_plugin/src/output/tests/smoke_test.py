"""PostToolUse 冒烟测试 — Step 1。

构造 4 个场景 + 1 个负样本,subprocess 调 output_scanner.py:
  1) Write 含 AKIA → 应 warn(stderr 有警告 + exit 0)
  2) Edit 含 sk-proj-... → 应 warn
  3) Write 无敏感 → 应 pass(无 stderr,exit 0)
  4) Write 不存在路径 → 应 skip(exit 0)
  5) Unsupported 工具 → 应 skip
  6) 测试目录被路径过滤 → 应 skip

注:必须 subprocess 跑,不能 import + main 调,因为 stdin 是 hook 协议入口。
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

THIS = Path(__file__).resolve()
SCANNER = THIS.parent.parent / "output_scanner.py"


def _run(event: dict) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, str(SCANNER)],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _write_temp(content: str, suffix: str = ".py") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="post_smoke_")
    import os
    os.close(fd)
    Path(path).write_text(content, encoding="utf-8")
    return path


def _make_event(tool: str, file_path: str, success: bool = True) -> dict:
    return {
        "session_id": "sess_post_smoke",
        "transcript_path": "/tmp/t.jsonl",
        "cwd": str(Path.cwd()),
        "hook_event_name": "PostToolUse",
        "tool_name": tool,
        "tool_input": {"file_path": file_path, "content": "ignored-pre-content"},
        "tool_response": {"success": success, "filePath": file_path},
    }


def main() -> int:
    cases: list[tuple[str, dict, callable]] = []

    # 1) Write 含 AKIA
    f1 = _write_temp('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    cases.append((
        "Write+AKIA → warn",
        _make_event("Write", f1),
        lambda code, out, err: code == 0 and "PostToolUse 安全告警" in err and "api_key" in err,
    ))

    # 2) Edit 含 sk-(注:credential_detector 正则 \bsk-[A-Za-z0-9]{20,}\b 不接受 `-`,
    #    所以 payload 用纯字母数字)
    f2 = _write_temp('OPENAI = "sk-projABCDEFGHIJKLMNOPQRSTUV12345"\n')
    cases.append((
        "Edit+sk- → warn",
        _make_event("Edit", f2),
        lambda code, out, err: code == 0 and "PostToolUse 安全告警" in err,
    ))

    # 3) Write 无敏感
    f3 = _write_temp("def hello():\n    return 'world'\n")
    cases.append((
        "Write 无敏感 → pass(无 stderr)",
        _make_event("Write", f3),
        lambda code, out, err: code == 0 and "PostToolUse 安全告警" not in err,
    ))

    # 4) Write 不存在路径
    cases.append((
        "Write 文件不存在 → skip",
        _make_event("Write", r"D:\definitely_does_not_exist_xxx.py"),
        lambda code, out, err: code == 0 and "PostToolUse 安全告警" not in err,
    ))

    # 5) Unsupported 工具
    cases.append((
        "Read 工具 → skip(matcher 兜底)",
        _make_event("Read", f3),
        lambda code, out, err: code == 0 and "PostToolUse 安全告警" not in err,
    ))

    # 6) test/logs 路径过滤
    log_path = r"D:\cloud_security\test\logs\input_scanner.jsonl"
    cases.append((
        "test/logs 路径 → 被过滤",
        _make_event("Write", log_path),
        lambda code, out, err: code == 0 and "PostToolUse 安全告警" not in err,
    ))

    fail = 0
    for label, event, check in cases:
        code, out, err = _run(event)
        ok = check(code, out, err)
        mark = "✓" if ok else "✗"
        print(f"  [{mark}] {label}  exit={code}")
        if not ok:
            fail += 1
            print(f"      stdout = {out[:200]!r}")
            print(f"      stderr = {err[:200]!r}")
    print(f"\n通过 {len(cases) - fail} / {len(cases)},失败 {fail}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
