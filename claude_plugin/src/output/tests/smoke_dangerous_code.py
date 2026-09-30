"""端到端:构造一个真的落盘 .py 文件含 pickle.loads,喂给 output_scanner。

验证:
  1) output_scanner 能 import 混合 detectors package 而不炸
  2) dangerous_code_detector 被真实调用并命中
  3) exit code 仍为 0(fail-OPEN)
  4) stderr 里能看到 pickle_deserialization 告警
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


def run_case(name: str, tool_name: str, tool_input: dict, disk_content: str,
             expected_rule: str | None) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / tool_input["file_path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(disk_content, encoding="utf-8")
        tool_input["file_path"] = str(target)

        # 屏蔽弹框:notify 在测试模式会静默 (see lib/confirm.py),但保险起见走
        # SESSION_ID 空字段 + suppress 环境变量(如果没有就直接跑)
        payload = json.dumps({
            "session_id": "smoke-danger",
            "tool_name": tool_name,
            "tool_input": tool_input,
            "tool_response": {"success": True, "filePath": str(target)},
        })

        env = os.environ.copy()
        env["CLAUDE_HOOKS_TEST"] = "1"       # confirm.notify 会看这个
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
        stderr = proc.stderr or ""
        if proc.returncode != 0:
            return False, f"exit={proc.returncode} stderr={stderr[:200]}"
        if expected_rule is None:
            return (expected_rule is None and "PostToolUse 安全告警" not in stderr,
                    f"expected no warn, stderr={stderr[:200]}")
        hit = expected_rule in stderr
        return hit, f"expected rule={expected_rule} in stderr; got stderr={stderr[:300]}"


def main() -> int:
    cases = [
        ("pickle落盘触发", "Write",
         {"file_path": "danger.py", "content": ""},
         "import pickle\ndata = " + "pickle" + ".loads(payload)\n",
         "pickle_deserialization"),
        ("subprocess_shell落盘触发", "Write",
         {"file_path": "shell.py", "content": ""},
         "import subprocess\n" + "subprocess" + ".run(f'ls {u}', shell=True)\n",
         "python_subprocess_shell"),
        ("正常代码不触发", "Write",
         {"file_path": "ok.py", "content": ""},
         "print('hello')\n",
         None),
    ]
    passed = 0
    for name, tool, ti, content, exp in cases:
        ok, msg = run_case(name, tool, ti, content, exp)
        mark = "✓" if ok else "✗"
        print(f"  [{mark}] {name}: {msg[:200] if not ok else 'ok'}")
        if ok:
            passed += 1
    print(f"通过 {passed}/{len(cases)}")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
