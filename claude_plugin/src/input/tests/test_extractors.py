"""extractors 单元测试。

覆盖：
  - file_extractor：T1 文本（UTF-8）/ 路径不在受控工作目录 / 不存在 / 不支持扩展名 / docx（若 docx 库可用）
  - grep_extractor：pattern+path / 空输入
  - url_extractor：含 prompt / 仅 URL / 空 URL
  - prompt_extractor：非空 / 空
  - dispatcher：按 event 分发正确
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from config.paths import paths  # noqa: E402
from extractors.dispatcher import extract as extract_event  # noqa: E402
from extractors.file_extractor import extract as extract_file  # noqa: E402
from extractors.grep_extractor import extract as extract_grep  # noqa: E402
from extractors.prompt_extractor import extract as extract_prompt  # noqa: E402
from extractors.url_extractor import extract as extract_url  # noqa: E402
from lib.event import Event  # noqa: E402


# --- file_extractor --------------------------------------------------

def test_file_extract_text_inside_workdir():
    target = paths.controlled_workdir / "projects" / "sample.txt"
    if not target.exists():
        # 测试 fixture 缺失：跳过而非失败
        return
    r = extract_file(str(target))
    assert not r.is_skipped
    assert "样例文本" in r.text or "sample" in r.text.lower()


def test_file_extract_outside_workdir():
    r = extract_file("C:\\Windows\\System32\\drivers\\etc\\hosts")
    assert r.skipped_reason == "outside_workdir"


def test_file_extract_not_found():
    target = paths.controlled_workdir / "projects" / "__missing__.txt"
    r = extract_file(str(target))
    assert r.skipped_reason == "not_a_file"


def test_file_extract_unsupported_ext():
    # 构造一个临时 .bin 文件
    target = paths.temp / "extractor_test.bin"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"\x00\x01\x02")
    try:
        r = extract_file(str(target))
        assert r.skipped_reason == "unsupported_format_v1"
    finally:
        target.unlink(missing_ok=True)


def test_file_extract_empty_path():
    r = extract_file("")
    assert r.skipped_reason == "empty_path"


def test_file_extract_docx_missing_lib_or_works():
    """docx 测试：库可用则正常抽文本；不可用则报 docx_lib_missing。"""
    target = paths.temp / "extractor_test.docx"
    target.parent.mkdir(parents=True, exist_ok=True)

    try:
        from docx import Document  # type: ignore[import-not-found]
        doc = Document()
        doc.add_paragraph("中文内容：联系电话 13800138000")
        doc.save(str(target))
        try:
            r = extract_file(str(target))
            assert not r.is_skipped
            assert "13800138000" in r.text
        finally:
            target.unlink(missing_ok=True)
    except ImportError:
        # 创建一个伪 docx（zip 头），验证报错
        target.write_bytes(b"PK\x03\x04 fake docx")
        try:
            r = extract_file(str(target))
            assert r.skipped_reason in ("docx_lib_missing", "docx_open_error:BadZipFile")
        finally:
            target.unlink(missing_ok=True)


def test_file_extract_pdf_with_text():
    """有文本层的 PDF：抽出来的内容包含原文关键字。"""
    try:
        import pdfplumber  # noqa: F401
    except ImportError:
        return  # 库不在 → 由 lib_missing 测试覆盖

    target = paths.temp / "extractor_test.pdf"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_minimal_pdf(target, "联系电话 13800138000")
    try:
        r = extract_file(str(target))
        assert not r.is_skipped, f"unexpected skip: {r.skipped_reason}"
        assert "13800138000" in r.text
    finally:
        target.unlink(missing_ok=True)


def test_file_extract_pdf_no_text_layer():
    """无文本层（伪扫描件）：返回 pdf_no_text_layer。

    这里用一个最小的、page 树存在但无内容流的 PDF 模拟。
    """
    try:
        import pdfplumber  # noqa: F401
    except ImportError:
        return

    target = paths.temp / "extractor_test_empty.pdf"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_empty_pdf(target)
    try:
        r = extract_file(str(target))
        # 真扫描件（无 /Contents）pdfplumber 有时直接抛错；两种都接受
        assert r.skipped_reason in ("pdf_no_text_layer",) or (
            r.skipped_reason or "").startswith("pdf_open_error:")
    finally:
        target.unlink(missing_ok=True)


def test_file_extract_pdf_lib_missing(monkeypatch=None):
    """pdfplumber 未安装：skipped_reason=pdf_lib_missing。"""
    import builtins
    import sys as _sys
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "pdfplumber":
            raise ImportError("simulated missing")
        return real_import(name, *a, **k)

    target = paths.temp / "extractor_test_libmiss.pdf"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"%PDF-1.4 fake")
    builtins.__import__ = fake_import
    _sys.modules.pop("pdfplumber", None)
    try:
        r = extract_file(str(target))
        assert r.skipped_reason == "pdf_lib_missing"
    finally:
        builtins.__import__ = real_import
        target.unlink(missing_ok=True)


def _write_minimal_pdf(path, text: str) -> None:
    """生成一个含一段文字的最小 PDF（不依赖 reportlab/fpdf）。

    不是教科书级合规 PDF，但 pdfplumber 能正常解析其文本内容。
    """
    # 最简方案：用 fpdf2 或 reportlab 都需要装包。直接写一个手工 PDF。
    body = (
        f"BT /F1 12 Tf 72 720 Td ({_pdf_escape(text)}) Tj ET\n"
    ).encode("latin-1", errors="replace")
    objs = []
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objs.append(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
    )
    objs.append(b"<< /Length " + str(len(body)).encode() + b" >>\nstream\n" + body + b"\nendstream")
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, obj in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objs)+1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode()
    path.write_bytes(bytes(out))


def _write_empty_pdf(path) -> None:
    """无 /Contents 的最小 PDF（模拟扫描件无文本层场景）。"""
    objs = []
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, obj in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objs)+1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode()
    path.write_bytes(bytes(out))


def _pdf_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


# --- grep_extractor --------------------------------------------------

def test_grep_extract_basic():
    r = extract_grep({"pattern": "password", "path": "D:\\test"})
    assert not r.is_skipped
    assert "password" in r.text
    assert "D:\\test" in r.text


def test_grep_extract_empty():
    r = extract_grep({})
    assert r.skipped_reason == "empty_grep"


# --- url_extractor ---------------------------------------------------

def test_url_extract_with_prompt():
    r = extract_url({"url": "https://example.com/path", "prompt": "summarize"})
    assert "https://example.com/path" in r.text
    assert "summarize" in r.text


def test_url_extract_only_url():
    r = extract_url({"url": "https://example.com/"})
    assert "https://example.com/" in r.text


def test_url_extract_empty():
    r = extract_url({})
    assert r.skipped_reason == "empty_url"


# --- prompt_extractor ------------------------------------------------

def test_prompt_extract_basic():
    r = extract_prompt("帮我总结一下")
    assert r.text == "帮我总结一下"
    assert r.source_label == "prompt"


def test_prompt_extract_empty():
    r = extract_prompt("")
    assert r.skipped_reason == "empty_prompt"


# --- dispatcher ------------------------------------------------------

def test_dispatch_userprompt():
    ev = Event.from_json('{"hook_event_name":"UserPromptSubmit","prompt":"hi"}')
    r = extract_event(ev)
    assert r.text == "hi"


def test_dispatch_pretool_read():
    target = paths.controlled_workdir / "projects" / "sample.txt"
    if not target.exists():
        return
    ev = Event.from_json(
        '{"hook_event_name":"PreToolUse","tool_name":"Read",'
        f'"tool_input":{{"file_path":"{str(target).replace(chr(92), chr(92)*2)}"}}}}'
    )
    r = extract_event(ev)
    assert not r.is_skipped


def test_dispatch_pretool_grep():
    ev = Event.from_json(
        '{"hook_event_name":"PreToolUse","tool_name":"Grep",'
        '"tool_input":{"pattern":"foo","path":"/tmp"}}'
    )
    r = extract_event(ev)
    assert "foo" in r.text


def test_dispatch_pretool_webfetch():
    ev = Event.from_json(
        '{"hook_event_name":"PreToolUse","tool_name":"WebFetch",'
        '"tool_input":{"url":"https://x.com/","prompt":"sum"}}'
    )
    r = extract_event(ev)
    assert "https://x.com/" in r.text


def test_dispatch_pretool_unsupported_tool():
    ev = Event.from_json(
        '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{}}'
    )
    r = extract_event(ev)
    assert r.skipped_reason.startswith("unsupported_tool")


TESTS = [
    test_file_extract_text_inside_workdir,
    test_file_extract_outside_workdir,
    test_file_extract_not_found,
    test_file_extract_unsupported_ext,
    test_file_extract_empty_path,
    test_file_extract_docx_missing_lib_or_works,
    test_file_extract_pdf_with_text,
    test_file_extract_pdf_no_text_layer,
    test_file_extract_pdf_lib_missing,
    test_grep_extract_basic,
    test_grep_extract_empty,
    test_url_extract_with_prompt,
    test_url_extract_only_url,
    test_url_extract_empty,
    test_prompt_extract_basic,
    test_prompt_extract_empty,
    test_dispatch_userprompt,
    test_dispatch_pretool_read,
    test_dispatch_pretool_grep,
    test_dispatch_pretool_webfetch,
    test_dispatch_pretool_unsupported_tool,
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
