"""actions 模块单元测试。

actions 都会 respond_block / respond_redirect 写 stderr，单测里捕获 stderr。
"""
from __future__ import annotations

import io
import sys
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from actions import desensitize_action  # noqa: E402
from actions.dispatcher import execute  # noqa: E402
from config.paths import paths  # noqa: E402
from lib.event import Event  # noqa: E402
from lib.types import Match  # noqa: E402


def _capture_stderr(fn):
    buf = io.StringIO()
    old = sys.stderr
    sys.stderr = buf
    try:
        result = fn()
    finally:
        sys.stderr = old
    return result, buf.getvalue()


@contextmanager
def _patch_confirm(approve: bool):
    """UPS 路径会弹系统 MessageBox，单测里用 stub 替掉，不弹真窗。"""
    orig = desensitize_action.confirm
    desensitize_action.confirm = lambda *a, **kw: approve
    try:
        yield
    finally:
        desensitize_action.confirm = orig


# --- desensitize_action: Read T1 ------------------------------------

def test_desensitize_read_text_creates_redirect():
    src = paths.controlled_workdir / "projects" / "tickets.txt"
    if not src.exists():
        return
    ev = Event.from_json(
        '{"hook_event_name":"PreToolUse","session_id":"sess_unit_redirect",'
        '"tool_name":"Read","tool_input":{"file_path":"'
        + str(src).replace("\\", "\\\\") + '"}}'
    )
    text = src.read_text(encoding="utf-8")

    outcome, err = _capture_stderr(lambda: desensitize_action.run(
        event=ev,
        text=text,
        matches=[Match("phone", 2), Match("email", 2)],
        source_label=f"file:{src}",
    ))
    assert outcome.exit_code == 2
    assert "请改读" in err
    copy_path = Path(outcome.audit["redirect_path"])
    try:
        assert copy_path.exists()
        content = copy_path.read_text(encoding="utf-8")
        assert "138****8000" in content
        assert "13800138000" not in content
    finally:
        if copy_path.exists():
            copy_path.unlink()


def test_desensitize_read_pdf_writes_txt_copy():
    """.pdf 源 → 副本扩展名强制为 .txt（让 Claude 走文本路径读副本）。"""
    src = paths.controlled_workdir / "projects" / "_unit_pdf.pdf"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_bytes(b"%PDF-1.4 stub")  # action 不读原 PDF，extractor 阶段才读
    try:
        ev = Event.from_json(
            '{"hook_event_name":"PreToolUse","session_id":"sess_unit_pdf",'
            '"tool_name":"Read","tool_input":{"file_path":"'
            + str(src).replace("\\", "\\\\") + '"}}'
        )
        outcome, err = _capture_stderr(lambda: desensitize_action.run(
            event=ev,
            text="联系电话 13800138000，邮箱 a@b.com",
            matches=[Match("phone", 1), Match("email", 1)],
            source_label=f"file:{src}",
        ))
        assert outcome.exit_code == 2
        assert "请改读" in err

        copy_path = Path(outcome.audit["redirect_path"])
        try:
            assert copy_path.exists()
            assert copy_path.suffix == ".txt", f"copy ext should be .txt, got {copy_path.suffix}"
            assert outcome.audit.get("source_ext") == ".pdf"
            assert outcome.audit.get("copy_ext") == ".txt"

            content = copy_path.read_text(encoding="utf-8")
            assert "138****8000" in content
            assert "13800138000" not in content
        finally:
            if copy_path.exists():
                copy_path.unlink()
    finally:
        if src.exists():
            src.unlink()


def test_desensitize_read_docx_routes_to_docx_writer():
    """.docx 不再 block，改走 docx_writer 段级脱敏 + 渲染 .md 副本。

    monkey-patch docx_writer.write_redacted_md：避免单测依赖真实 .docx 落盘。
    """
    src = Path("D:\\tmp\\foo.docx")  # 路径无需存在，docx_writer 被 mock
    ev = Event.from_json(
        '{"hook_event_name":"PreToolUse","session_id":"sess_unit_docx",'
        '"tool_name":"Read","tool_input":{"file_path":"D:\\\\tmp\\\\foo.docx"}}'
    )

    called: dict = {}

    def fake_write(*, original_path, md_path, desensitize):
        called["original_path"] = original_path
        called["md_path"] = md_path
        # touch the copy file so 后续 redirect 端断言能命中
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text("# stub\n", encoding="utf-8")
        return {"[公司A]": 1, "[人员A]": 1}

    real = desensitize_action.docx_writer.write_redacted_md
    desensitize_action.docx_writer.write_redacted_md = fake_write
    # 同时 mock _file_sha 避免去打开不存在的原文件
    real_sha = desensitize_action._file_sha
    desensitize_action._file_sha = lambda p: "abc123def456"

    try:
        outcome, err = _capture_stderr(lambda: desensitize_action.run(
            event=ev,
            text="(docx 文本已由 extractor 抽取)",
            matches=[Match("company", 1)],
            source_label="file:foo.docx",
        ))
    finally:
        desensitize_action.docx_writer.write_redacted_md = real
        desensitize_action._file_sha = real_sha
        if "md_path" in called and called["md_path"].exists():
            called["md_path"].unlink()

    assert outcome.exit_code == 2
    assert "请改读" in err
    assert outcome.audit.get("source_ext") == ".docx"
    assert outcome.audit.get("copy_ext") == ".md"
    assert called["original_path"] == src
    assert called["md_path"].suffix == ".md"
    assert "abc123def456" in called["md_path"].name


# --- desensitize_action: UserPromptSubmit ---------------------------

def test_desensitize_userprompt_user_rejects_blocks():
    ev = Event.from_json(
        '{"hook_event_name":"UserPromptSubmit","session_id":"sess_unit_ups",'
        '"prompt":"phone 13800138000 mail a@b.com"}'
    )
    text = "phone 13800138000 mail a@b.com"
    with _patch_confirm(approve=False):
        outcome, err = _capture_stderr(lambda: desensitize_action.run(
            event=ev,
            text=text,
            matches=[Match("phone", 1), Match("email", 1)],
            source_label="prompt",
        ))
    assert outcome.exit_code == 2
    assert outcome.audit["block_reason"] == "user_blocked"
    assert "建议改写" in err
    assert "138****8000" in err
    assert "13800138000" not in err
    # 新增字段：审计追源头依赖
    assert outcome.audit["prompt_text"] == text
    assert outcome.audit["cls_summary"]  # 非空
    assert "decision_latency_ms" in outcome.audit
    assert isinstance(outcome.audit["decision_latency_ms"], int)
    assert outcome.audit["decision_latency_ms"] >= 0


def test_desensitize_userprompt_user_approves_passes():
    ev = Event.from_json(
        '{"hook_event_name":"UserPromptSubmit","session_id":"sess_unit_ups_ok",'
        '"prompt":"phone 13800138000"}'
    )
    text = "phone 13800138000"
    with _patch_confirm(approve=True):
        outcome, err = _capture_stderr(lambda: desensitize_action.run(
            event=ev,
            text=text,
            matches=[Match("phone", 1)],
            source_label="prompt",
        ))
    assert outcome.exit_code == 0
    assert outcome.audit["block_reason"] == "user_approved"
    assert "已确认放行" in err
    # 新增字段：审计追源头依赖
    assert outcome.audit["prompt_text"] == text
    assert outcome.audit["cls_summary"]
    assert "decision_latency_ms" in outcome.audit
    assert isinstance(outcome.audit["decision_latency_ms"], int)
    assert outcome.audit["decision_latency_ms"] >= 0


def test_desensitize_grep_degrades_block():
    ev = Event.from_json(
        '{"hook_event_name":"PreToolUse","session_id":"sess_unit_grep",'
        '"tool_name":"Grep","tool_input":{"pattern":"x","path":"y"}}'
    )
    outcome, _err = _capture_stderr(lambda: desensitize_action.run(
        event=ev,
        text="x",
        matches=[],
        source_label="grep:y",
    ))
    assert outcome.exit_code == 2
    assert outcome.audit["block_reason"] == "no_redirect_channel"


# --- dispatcher ------------------------------------------------------

def test_dispatcher_no_matches_returns_pass():
    """matches 为空 → pass。"""
    ev = Event.from_json('{"hook_event_name":"UserPromptSubmit","prompt":"hi"}')
    outcome, err = _capture_stderr(lambda: execute(
        event=ev,
        text="hi",
        matches=[],
        source_label="prompt",
    ))
    assert outcome.exit_code == 0
    assert err == ""


def test_dispatcher_routes_any_hit_to_desensitize():
    """matches 非空 → 一律走 desensitize_action（UPS 上 confirm 拒绝 → block + 建议改写）。"""
    ev = Event.from_json('{"hook_event_name":"UserPromptSubmit","prompt":"phone 13800138000"}')
    with _patch_confirm(approve=False):
        outcome, err = _capture_stderr(lambda: execute(
            event=ev,
            text="phone 13800138000",
            matches=[Match("phone", 1)],
            source_label="prompt",
        ))
    assert outcome.exit_code == 2
    assert outcome.audit["block_reason"] == "user_blocked"
    assert "建议改写" in err


TESTS = [
    test_desensitize_read_text_creates_redirect,
    test_desensitize_read_pdf_writes_txt_copy,
    test_desensitize_read_docx_routes_to_docx_writer,
    test_desensitize_userprompt_user_rejects_blocks,
    test_desensitize_userprompt_user_approves_passes,
    test_desensitize_grep_degrades_block,
    test_dispatcher_no_matches_returns_pass,
    test_dispatcher_routes_any_hit_to_desensitize,
]


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    passed = failed = 0
    for t in TESTS:
        try:
            t()
            print(f"[OK]   {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {t.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERR]  {t.__name__}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n用例总数: {len(TESTS)} | 通过: {passed} | 失败: {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
