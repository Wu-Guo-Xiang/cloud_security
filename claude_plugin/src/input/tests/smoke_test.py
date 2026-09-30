"""端到端 Hook 冒烟测试。

每个 case 声明：
  - 期望退出码（0=pass，2=block/redirect）
  - 期望 stderr 关键字（用于区分 block / redirect / 建议改写）

每轮跑测前清空本次涉及的 session_cache，保证可重复。

UPS 用例会触发系统 MessageBox 让用户确认是否放行;为了让 run_all.py /
CI 无人值守跑通,这里默认置 CLOUD_SECURITY_TEST_CONFIRM=no(等价于"用户点否"),
对应"建议改写"的 fail-closed 路径。若要手动验证 MessageBox 真实弹窗,
unset 这个环境变量再单跑某个 case。
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from config.paths import paths  # noqa: E402


SCANNER = ROOT / "input_scanner.py"
TESTS_DIR = Path(__file__).parent


# (event_type, sample_file, expected_exit, stderr_keyword, label, copy_must_contain, copy_is_docx)
# 注意：v2 起去掉评分门限，只要命中即脱敏：
#   - PreToolUse + Read   → 一律生成脱敏副本并 redirect（stderr 含 "请改读"）
#   - UserPromptSubmit    → 无法重写用户输入，仍 block 并给出"建议改写"
# copy_must_contain：可选 list，若非空则解析 stderr 中的副本路径并校验内容
# copy_is_docx：True 时用 python-docx 打开副本拼接段落/表格文本再做子串校验
CASES = [
    ("PreToolUse",       "sample_read_event.json",                   0, "",          "Read 干净文本",                                [],                                False),
    ("PreToolUse",       "sample_grep_event.json",                   0, "",          "Grep 仅关键字",                                [],                                False),
    ("PreToolUse",       "sample_webfetch_event.json",               0, "",          "WebFetch 公共域名",                            [],                                False),
    ("UserPromptSubmit", "sample_userprompt_event.json",             0, "",          "UserPrompt 干净",                              [],                                False),
    ("PreToolUse",       "sample_credentials_event.json",            2, "请改读",    "Read 含凭证 → 脱敏副本",                       [],                                False),
    ("UserPromptSubmit", "sample_userprompt_sensitive.json",         2, "建议改写",  "UserPrompt 含凭证 → 建议改写",                 [],                                False),
    ("PreToolUse",       "sample_pii_read_event.json",               2, "请改读",    "Read 含 PII → 脱敏副本",                       [],                                False),
    ("UserPromptSubmit", "sample_userprompt_pii.json",               2, "建议改写",  "UserPrompt 含 PII → 建议改写",                 [],                                False),
    ("PreToolUse",       "sample_biz_chinese_event.json",            2, "请改读",    "Read 中文业务 → LLM 脱敏（公司/人员/产品）",   ["[公司A]", "[人员A]", "[产品A]"], False),
    ("PreToolUse",       "sample_docx_event.json",                   2, "Skill 工具调用",  "Read .docx → 短路推回 docx skill(不进 L2)",   [],                                False),
    ("PreToolUse",       "sample_desensitized_reread_event.json",    0, "",          "Read 副本目录 → 递归短路放行",                 [],                                False),
]


def _clear_session_caches() -> None:
    """清空本次 case 涉及的 session_cache 文件，保证测试可重复。"""
    cache_dir = paths.session_cache
    if not cache_dir.exists():
        return
    for f in cache_dir.glob("sess_test_*.pickle"):
        try:
            f.unlink()
        except OSError:
            pass


def _ensure_docx_sample() -> None:
    """若 test/projects/biz_sample.docx 不在，现场用 python-docx 构造一份。

    内容含 1 个标题段 + 1 个公司/人员的正文段 + 1 个表格，足以同时触发 L1（手机/邮箱）和 L2（公司/人员）。
    """
    target = paths.projects / "biz_sample.docx"
    if target.exists():
        return
    from docx import Document

    target.parent.mkdir(parents=True, exist_ok=True)
    doc = Document()
    h = doc.add_paragraph("年度合作备忘")
    h.style = doc.styles["Heading 1"]
    doc.add_paragraph(
        "甲方：星河智联科技（北京）有限公司，项目经理 赵明哲，手机 13901234567，邮箱 zhao.mz@xinghezhilian.com。"
    )
    doc.add_paragraph(
        "乙方：润泽数据服务（上海）股份有限公司，对接人 王思琦，手机 15821988765。"
    )
    t = doc.add_table(rows=2, cols=2)
    t.rows[0].cells[0].text = "公司"
    t.rows[0].cells[1].text = "联系人"
    t.rows[1].cells[0].text = "星河智联科技（北京）有限公司"
    t.rows[1].cells[1].text = "赵明哲"

    doc.save(str(target))


def _ensure_recursion_event() -> None:
    """构造一个指向脱敏副本目录内某文件的事件 JSON。

    路径只用于触发 input_scanner 的前缀守卫，不要求文件真实存在。
    使用 paths.temp_desensitized 取真实根，避免与 paths.yml 漂移。
    """
    target = TESTS_DIR / "sample_desensitized_reread_event.json"
    fake_copy = paths.temp_desensitized / "sess_test_recursion" / "dummy.docx"
    payload = {
        "session_id": "sess_test_recursion",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": str(paths.controlled_workdir),
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(fake_copy)},
    }
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _ensure_docx_event() -> None:
    target = TESTS_DIR / "sample_docx_event.json"
    docx_path = paths.projects / "biz_sample.docx"
    payload = {
        "session_id": "sess_test_docx",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": str(paths.controlled_workdir),
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(docx_path)},
    }
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def run_case(event_type: str, sample_file: str) -> tuple[int, str, str]:
    sample = (TESTS_DIR / sample_file).read_text(encoding="utf-8")
    # UPS 用例必走 fail-closed,避免在自动化跑里弹出真实 MessageBox 卡死
    env = os.environ.copy()
    env.setdefault("CLOUD_SECURITY_TEST_CONFIRM", "no")
    proc = subprocess.run(
        [sys.executable, str(SCANNER), "--event", event_type],
        input=sample,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""


_REDIRECT_PATH_RE = re.compile(r"请改读\s*[:：]?\s*(.+?)\s*$", re.MULTILINE)


def _extract_copy_path(stderr: str) -> Path | None:
    m = _REDIRECT_PATH_RE.search(stderr)
    if not m:
        return None
    return Path(m.group(1).strip())


def _read_copy_text(copy_path: Path, is_docx: bool) -> str:
    if not is_docx:
        return copy_path.read_text(encoding="utf-8", errors="replace")
    from docx import Document
    doc = Document(str(copy_path))
    parts = [p.text for p in doc.paragraphs]
    for t in doc.tables:
        for row in t.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    parts.append(p.text)
    return "\n".join(parts)


def main() -> int:
    print(f"受控工作目录: {paths.controlled_workdir}")
    print(f"日志目录:     {paths.logs}")
    _clear_session_caches()
    _ensure_docx_sample()
    _ensure_docx_event()
    _ensure_recursion_event()
    print()

    failed = 0
    for event_type, sample_file, expected, keyword, label, copy_must_contain, copy_is_docx in CASES:
        code, _, stderr = run_case(event_type, sample_file)
        ok = code == expected
        if ok and keyword:
            ok = keyword in stderr

        copy_check_msg = ""
        if ok and copy_must_contain:
            copy_path = _extract_copy_path(stderr)
            if copy_path is None or not copy_path.exists():
                ok = False
                copy_check_msg = f"未能解析或读取脱敏副本：{copy_path}"
            else:
                content = _read_copy_text(copy_path, copy_is_docx)
                missing = [s for s in copy_must_contain if s not in content]
                if missing:
                    ok = False
                    copy_check_msg = f"副本缺少占位符 {missing}"
                else:
                    copy_check_msg = f"副本包含 {copy_must_contain}"

        status = "OK" if ok else "FAIL"
        print(
            f"[{status}] {event_type:18} {sample_file:42} "
            f"exit={code}(期望{expected}) — {label}"
        )
        if not ok:
            failed += 1
            if stderr.strip():
                first = stderr.strip().splitlines()[0]
                print(f"       stderr: {first}")
            if copy_check_msg:
                print(f"       check : {copy_check_msg}")
        elif code == 2 and stderr.strip():
            first = stderr.strip().splitlines()[0]
            print(f"       msg: {first}")
            if copy_check_msg:
                print(f"       ok  : {copy_check_msg}")

    total = len(CASES)
    print(f"\n用例总数: {total} | 通过: {total - failed} | 失败: {failed}")
    print(f"日志位置: {paths.logs / 'input_scanner.jsonl'}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
