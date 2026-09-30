"""端到端 smoke:Stop-review 三条路径 + 一条 unit-level baseline 幂等测试。

覆盖:
  1) baseline_capture_idempotent — 同 session 同文件抓两次,只保留首次原文
  2) stop_no_baseline — 没抓过快照 → stdout 空, exit 0
  3) stop_clean_diff  — 干净的重构 diff → LLM 判 clean → stdout 空(允许偶尔误报,只要 exit 0)
  4) stop_ssrf_diff   — 引入 SSRF(user URL → requests.get)的 diff → 期望 stdout 有
     hookSpecificOutput.additionalContext 且 findings 非空

注意事项:
  - stop_reviewer 会真调 LLM,依赖 ANTHROPIC_BASE_URL 可达。不可达时全部 skip 到 exit 0
    (fail-OPEN 是 by design,不算失败)。这条 smoke 不测网络失败路径。
  - baseline 目录写死到 D:/cloud_security/.claude/stop_review_baseline/;
    smoke 用带 test- 前缀的 session_id 避免撞真实会话。
  - LLM 有不确定性,只断言"有 findings"或"clean=True",不断言具体标题。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


_THIS = Path(__file__).resolve()
_OUTPUT_DIR = _THIS.parent.parent
_STOP_REVIEWER = _OUTPUT_DIR / "stop_reviewer.py"
_BASELINE_ROOT = Path("D:/cloud_security/.claude/stop_review_baseline")


sys.path.insert(0, str(_OUTPUT_DIR))
sys.path.insert(0, str(_OUTPUT_DIR.parent / "input"))


def _new_session_id() -> str:
    return "test-" + uuid.uuid4().hex[:12]


def _capture_baseline(session_id: str, file_path: str) -> str:
    """直接调 stop_review.baseline.capture(),不走 subprocess。"""
    from stop_review.baseline import capture
    return capture(session_id, file_path)


def _run_stop_reviewer(session_id: str, extra_env: dict | None = None) -> tuple[int, str, str]:
    payload = json.dumps({
        "session_id": session_id,
        "hook_event_name": "Stop",
        "stop_hook_active": False,
    })
    env = os.environ.copy()
    env["CLAUDE_HOOKS_TEST"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [sys.executable, str(_STOP_REVIEWER)],
        input=payload,
        capture_output=True,
        text=True,
        timeout=45,
        env=env,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _parse_stdout_json(stdout: str):
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return None


def _cleanup_session(session_id: str) -> None:
    d = _BASELINE_ROOT / session_id
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)


def case_baseline_capture_idempotent() -> tuple[bool, str]:
    from stop_review.baseline import load_session
    session_id = _new_session_id()
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / "app.py"
        target.write_text("v1\n", encoding="utf-8")
        r1 = _capture_baseline(session_id, str(target))
        target.write_text("v2\n", encoding="utf-8")
        r2 = _capture_baseline(session_id, str(target))
        entries = load_session(session_id)
    _cleanup_session(session_id)
    if r1 != "captured":
        return False, f"first capture unexpected: {r1}"
    if r2 != "already_captured":
        return False, f"second capture should be no-op, got: {r2}"
    if len(entries) != 1:
        return False, f"expected 1 entry, got {len(entries)}"
    if entries[0].content.strip() != "v1":
        return False, f"baseline should retain v1, got {entries[0].content!r}"
    return True, "ok"


def case_stop_no_baseline() -> tuple[bool, str]:
    session_id = _new_session_id()  # 从未抓过 baseline
    rc, stdout, stderr = _run_stop_reviewer(session_id)
    if rc != 0:
        return False, f"exit={rc} expected 0  stderr={stderr[:200]}"
    if stdout.strip():
        return False, f"no-baseline should produce empty stdout, got {stdout[:200]}"
    return True, "ok"


def case_stop_clean_diff() -> tuple[bool, str]:
    """干净重构:改个函数名 + 加个 docstring,不引入任何风险。LLM 应判 clean。"""
    session_id = _new_session_id()
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / "clean_change.py"
        original = 'def add(a, b):\n    return a + b\n'
        target.write_text(original, encoding="utf-8")
        _capture_baseline(session_id, str(target))
        # 只做重命名 + 加注释
        updated = 'def sum_two(a, b):\n    """Return the sum of two numbers."""\n    return a + b\n'
        target.write_text(updated, encoding="utf-8")
        rc, stdout, stderr = _run_stop_reviewer(session_id)
    _cleanup_session(session_id)
    if rc != 0:
        return False, f"exit={rc} expected 0  stderr={stderr[:200]}"
    # LLM 有不确定性,只要 exit 0 就算通过;如果吐了 additionalContext 也是"soft pass"
    obj = _parse_stdout_json(stdout)
    if obj is None:
        return True, "clean (silent)"
    hso = obj.get("hookSpecificOutput") or {}
    if hso.get("hookEventName") != "Stop":
        return False, f"hookEventName wrong: {hso!r}"
    return True, "llm-emitted but non-fatal"


def case_stop_ssrf_diff() -> tuple[bool, str]:
    """SSRF pattern:接受用户 URL 直接 requests.get,LLM 语义级审计应命中。"""
    session_id = _new_session_id()
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / "webhook.py"
        original = (
            'def handle(request):\n'
            '    return {"ok": True}\n'
        )
        target.write_text(original, encoding="utf-8")
        _capture_baseline(session_id, str(target))
        # 引入 SSRF:用户提供 URL,无 allowlist,直接抓
        updated = (
            'import requests\n'
            '\n'
            'def handle(request):\n'
            '    target_url = request.json["url"]\n'
            '    resp = requests.get(target_url, timeout=10)\n'
            '    return {"body": resp.text[:1000]}\n'
        )
        target.write_text(updated, encoding="utf-8")
        rc, stdout, stderr = _run_stop_reviewer(session_id)
    _cleanup_session(session_id)
    if rc != 0:
        return False, f"exit={rc} expected 0  stderr={stderr[:200]}"
    obj = _parse_stdout_json(stdout)
    if obj is None:
        # LLM 有可能漏报,但这属于测试值得盯的信号 —— 明确报"未命中"让我判断
        return False, f"expected findings, got empty stdout  stderr={stderr[:200]}"
    hso = obj.get("hookSpecificOutput") or {}
    if hso.get("hookEventName") != "Stop":
        return False, f"hookEventName wrong: {hso!r}"
    ctx = hso.get("additionalContext") or ""
    if "Stop-review" not in ctx:
        return False, f"header missing  ctx={ctx[:200]}"
    return True, f"llm ok  ctx_len={len(ctx)}"


def case_kill_switch() -> tuple[bool, str]:
    """CLOUD_SEC_STOP_REVIEW=0 → 完全不跑 LLM,stdout 空,exit 0。"""
    session_id = _new_session_id()
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / "any.py"
        target.write_text("print(1)\n", encoding="utf-8")
        _capture_baseline(session_id, str(target))
        target.write_text("import pickle\n", encoding="utf-8")
        rc, stdout, _ = _run_stop_reviewer(session_id, {"CLOUD_SEC_STOP_REVIEW": "0"})
    _cleanup_session(session_id)
    if rc != 0:
        return False, f"exit={rc}"
    if stdout.strip():
        return False, f"kill switch should silence, got {stdout[:200]}"
    return True, "ok"


def main() -> int:
    cases = [
        ("baseline: 同 session 二次抓幂等", case_baseline_capture_idempotent),
        ("stop: 无 baseline → 静默", case_stop_no_baseline),
        ("stop: kill switch 生效", case_kill_switch),
        ("stop: 干净重构 → LLM 应判 clean", case_stop_clean_diff),
        ("stop: SSRF diff → LLM 应命中", case_stop_ssrf_diff),
    ]
    passed = 0
    for name, fn in cases:
        t0 = time.time()
        try:
            ok, msg = fn()
        except Exception as exc:
            ok, msg = False, f"exception: {type(exc).__name__}: {exc}"
        dt = int((time.time() - t0) * 1000)
        mark = "[+]" if ok else "[x]"
        print(f"  {mark} {name}  ({dt}ms): {msg[:250]}")
        if ok:
            passed += 1
    print(f"通过 {passed}/{len(cases)}")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
