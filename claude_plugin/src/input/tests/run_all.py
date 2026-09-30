"""伞型测试入口：依次运行本目录下所有 test_*.py 与 smoke_test.py,
然后跑项目根的 probe_*.py 做对抗性回归。

用法：
    "<anquan python>" tests/run_all.py
返回值：
    任一子测试失败 → 退出码 1；全部通过 → 0
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

TESTS_DIR = Path(__file__).resolve().parent
# tests/ -> input/ -> scripts/ -> cloud_security/(项目根,probe_*.py 所在地)
PROJECT_ROOT = TESTS_DIR.parent.parent.parent

# 顺序：先单元（validators / detectors / extractors / redactor / cache / actions / LLM 组件），再冒烟（端到端 Hook 流）
TEST_FILES = [
    "test_validators.py",
    "test_credential_detector.py",
    "test_pattern_detector.py",
    "test_extractors.py",
    "test_normalize.py",
    "test_redactor.py",
    "test_session_cache.py",
    "test_actions.py",
    "test_entity_map.py",
    "test_pseudonymizer.py",
    "test_llm_detector.py",
    "test_docx_writer.py",
    "smoke_test.py",
]

# 对抗性回归 probe:复现历史漏洞 / 边界绕过,exit 码 != 0 即视为失败
# 文件位于 PROJECT_ROOT (D:/cloud_security/)。新加 probe 时追加到这里。
# 行为说明:
#   - probe_cwd_aware / probe_injection_payloads / probe_office_bypass_v2
#     这几个内置 sys.exit(0/1) 断言,失败会直接让套件挂掉
#   - 其余 probe 是打印型(exit 0),run_all 仍跑它们,触发代码路径即起回归作用
#     (regression 关键是"代码路径被执行过",print 内容看不看由维护者决定)
PROBE_FILES = [
    "probe_actual_bypass.py",
    "probe_bash_bypass.py",
    "probe_cwd_aware.py",
    "probe_docx_bypass_chain.py",
    "probe_docx_skill_outdir.py",
    "probe_injection_payloads.py",
    "probe_new_guards_edges.py",
    "probe_office_bypass_v2.py",
    "probe_office_skill_outdir.py",
    "probe_pre_content_scan.py",
    "probe_pre_content_scan_adversarial.py",
    "probe_ups_logging.py",
]


def _run_one(path: Path, name: str) -> bool:
    """跑一个测试脚本,返回 True 表示通过(exit 0)。"""
    print(f"\n===== {name} =====")
    proc = subprocess.run(
        [sys.executable, str(path)],
        capture_output=False,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode == 0


def main() -> int:
    failed: list[str] = []

    print(">>> 单元 + 冒烟测试 <<<")
    for name in TEST_FILES:
        path = TESTS_DIR / name
        if not path.exists():
            print(f"[SKIP] {name} (not found)")
            continue
        if not _run_one(path, name):
            failed.append(name)

    print("\n\n>>> 对抗性回归 probe <<<")
    for name in PROBE_FILES:
        path = PROJECT_ROOT / name
        if not path.exists():
            print(f"[SKIP] {name} (not found at {path})")
            continue
        if not _run_one(path, name):
            failed.append(name)

    total = len(TEST_FILES) + len(PROBE_FILES)
    print("\n========== 汇总 ==========")
    print(f"测试文件数: {total} | 失败: {len(failed)}")
    for n in failed:
        print(f"  - {n}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
