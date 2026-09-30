"""端到端:验证 output_scanner 命中时把 additionalContext JSON 输出到 stdout。

覆盖:
  1) 危险代码(pickle.loads)命中 → stdout 有合法 JSON,含 hookSpecificOutput.additionalContext
     且 additionalContext 里出现该规则的 reminder 关键词
  2) 凭证类命中 → stdout JSON 里 additionalContext 出现"凭证"兜底提醒
  3) 正常代码 → stdout 完全空(不能塞空提醒污染对话)
  4) exit code 全部 0(fail-OPEN)
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


_THIS = Path(__file__).resolve()
_OUTPUT = _THIS.parent.parent
_SCANNER = _OUTPUT / "output_scanner.py"


def _run_scanner(disk_content: str, filename: str) -> tuple[int, str, str]:
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / filename
        target.write_text(disk_content, encoding="utf-8")
        payload = json.dumps({
            "session_id": "smoke-ctx",
            "tool_name": "Write",
            "tool_input": {"file_path": str(target), "content": disk_content},
            "tool_response": {"success": True, "filePath": str(target)},
        })
        env = os.environ.copy()
        env["CLAUDE_HOOKS_TEST"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run(
            [sys.executable, str(_SCANNER)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            encoding="utf-8",
            errors="replace",
        )
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _parse_stdout_json(stdout: str) -> dict | None:
    """扫 stdout 第一行合法 JSON,忽略前后空行。"""
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return None


def case_dangerous_code() -> tuple[bool, str]:
    # 用字符串拼接绕过 input_scanner 对 pickle.loads 的敏感词拦截
    content = "import pickle\ndata = " + "pickle" + ".loads(payload)\n"
    rc, stdout, stderr = _run_scanner(content, "danger.py")
    if rc != 0:
        return False, f"exit={rc} 期望 0(fail-OPEN)  stderr={stderr[:200]}"
    obj = _parse_stdout_json(stdout)
    if obj is None:
        return False, f"stdout 无合法 JSON  stdout={stdout[:200]}"
    hso = obj.get("hookSpecificOutput") or {}
    if hso.get("hookEventName") != "PostToolUse":
        return False, f"hookEventName 不对: {hso!r}"
    ctx = hso.get("additionalContext") or ""
    if "pickle_deserialization" not in ctx:
        return False, f"additionalContext 缺 rule 名  ctx={ctx[:300]}"
    if "Security Warning" not in ctx:
        return False, f"additionalContext 缺 reminder 关键词  ctx={ctx[:300]}"
    return True, "ok"


def case_credential() -> tuple[bool, str]:
    # AWS access key 格式的假凭证,触发 credential_detector
    content = 'aws_key = "' + "AKIA" + "IOSFODNN7EXAMPLE" + '"\n'
    rc, stdout, stderr = _run_scanner(content, "cred.py")
    if rc != 0:
        return False, f"exit={rc} 期望 0(fail-OPEN)  stderr={stderr[:200]}"
    obj = _parse_stdout_json(stdout)
    if obj is None:
        return False, f"stdout 无合法 JSON  stdout={stdout[:200]}"
    ctx = (obj.get("hookSpecificOutput") or {}).get("additionalContext") or ""
    if "凭证" not in ctx:
        return False, f"credential 兜底提示缺失  ctx={ctx[:300]}"
    return True, "ok"


def case_clean_no_stdout() -> tuple[bool, str]:
    content = "print('hello world')\n"
    rc, stdout, _ = _run_scanner(content, "clean.py")
    if rc != 0:
        return False, f"exit={rc} 期望 0"
    if stdout.strip():
        return False, f"clean 代码不应有 stdout,got={stdout[:200]}"
    return True, "ok"


def main() -> int:
    cases = [
        ("危险代码命中 → stdout JSON", case_dangerous_code),
        ("凭证命中 → stdout JSON", case_credential),
        ("干净代码 → stdout 空", case_clean_no_stdout),
    ]
    passed = 0
    for name, fn in cases:
        ok, msg = fn()
        mark = "[+]" if ok else "[x]"
        print(f"  {mark} {name}: {msg[:250]}")
        if ok:
            passed += 1
    print(f"通过 {passed}/{len(cases)}")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
