"""docx_writer 单测。

聚焦：
  - 段级整段重建：命中段落原文被替换成脱敏后的 markdown
  - 段落 style（heading 等）渲染为 markdown heading 标记
  - 表格 cell 文本也被处理
  - counts 累加：跨段同字面归并到同一 placeholder
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from actions.docx_writer import write_redacted_md  # noqa: E402
from docx import Document  # noqa: E402


def _build_sample_docx(p: Path) -> None:
    doc = Document()
    h = doc.add_paragraph()
    h.add_run("机密报告")
    h.style = doc.styles["Heading 1"]

    doc.add_paragraph("背景：客户 机密 联系电话 13800000000。")
    doc.add_paragraph("正常段落不含敏感数据。")

    t = doc.add_table(rows=2, cols=2)
    t.rows[0].cells[0].text = "公司"
    t.rows[0].cells[1].text = "机密"
    t.rows[1].cells[0].text = "金额"
    t.rows[1].cells[1].text = "100 万"

    doc.save(str(p))


def _dummy_desensitize(text: str):
    counts: dict[str, int] = {}
    out = text
    if "机密" in out:
        n = out.count("机密")
        out = out.replace("机密", "[公司A]")
        counts["[公司A]"] = n
    return out, counts


def _read_docx(p: Path) -> "Document":
    return Document(str(p))


def test_hits_replace_to_placeholder():
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "a.docx"
        dst = Path(tmp) / "a_redacted.md"
        _build_sample_docx(src)
        counts = write_redacted_md(original_path=src, md_path=dst, desensitize=_dummy_desensitize)

        text = dst.read_text(encoding="utf-8")
        assert "机密" not in text, "命中文本应被替换"
        assert "[公司A]" in text
        # 机密 出现位置：标题 1 次 + 第二段 1 次 + 表格 cell 1 次 = 3 次
        assert counts.get("[公司A]") == 3, counts


def test_heading_style_preserved():
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "a.docx"
        dst = Path(tmp) / "a_redacted.md"
        _build_sample_docx(src)
        write_redacted_md(original_path=src, md_path=dst, desensitize=_dummy_desensitize)

        text = dst.read_text(encoding="utf-8")
        # Heading 1 → "# " 前缀
        assert text.startswith("# [公司A]报告"), text[:80]


def test_table_cells_also_redacted():
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "a.docx"
        dst = Path(tmp) / "a_redacted.md"
        _build_sample_docx(src)
        write_redacted_md(original_path=src, md_path=dst, desensitize=_dummy_desensitize)

        text = dst.read_text(encoding="utf-8")
        # 表格 row[0] 第二个 cell 原本是 "机密" → "[公司A]"，渲染进 markdown 表格
        assert "| [公司A] |" in text, text


def test_empty_paragraph_skipped_without_error():
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "a.docx"
        dst = Path(tmp) / "a_redacted.md"
        doc = Document()
        doc.add_paragraph("")           # 空段
        doc.add_paragraph("   ")        # 纯空白
        doc.add_paragraph("机密")
        doc.save(str(src))

        counts = write_redacted_md(original_path=src, md_path=dst, desensitize=_dummy_desensitize)
        assert counts.get("[公司A]") == 1


TESTS = [
    test_hits_replace_to_placeholder,
    test_heading_style_preserved,
    test_table_cells_also_redacted,
    test_empty_paragraph_skipped_without_error,
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
