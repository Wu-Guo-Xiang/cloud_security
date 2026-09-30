"""DOCX 脱敏渲染器。

打开原 .docx → 段落+表格逐段调脱敏函数 → 按 body 顺序渲染成 markdown 写到 md_path。

接口（被 docx_to_md 调用）：
  write_redacted_md(original_path, md_path, desensitize) → counts

表格 label-value 复原（v2）：
  cell 内的 "91310000MA1K35P57Y" 单独喂给 L1 正则匹配不到 USCC（正则需要
  "统一社会信用代码" 前缀做锚点）。表格里 label 和 value 分布在相邻 cell 中，
  失锚导致漏识别。改造：根据当前 cell 在表格中的位置查找候选 label cell
  （同行就近 + 列首行 header），临时拼成 "label: value" 喂给 desensitize，
  再把前缀剥回去。label cell 本身正常 desensitize（label 文本不是 PII）。
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Callable


DesensitizeFn = Callable[[str], "tuple[str, dict[str, int]]"]


# 与 rules.yml 中 6 类 label-value 正则的 label 字面值一一对应。
# 改 rules.yml 时记得同步这里；扩 label 集合后无需改正则。
_TABLE_LABEL_KEYWORDS = frozenset([
    # uscc
    "统一社会信用代码", "信用代码",
    # org_code
    "组织机构代码",
    # contract_no
    "合同编号", "协议编号", "文件编号", "文件号",
    # patent_code
    "专利申请号", "商标申请号", "著作权申请号",
    # landline
    "电话", "联系电话", "座机", "总机", "传真", "传真号码",
    # address
    "地址", "住所", "住址", "注册地址", "办公地址", "经营地址", "住所地",
])


def write_redacted_md(
    *,
    original_path: Path,
    md_path: Path,
    desensitize: DesensitizeFn,
) -> dict[str, int]:
    """段落级脱敏 + 按 body 顺序渲染成 markdown，返回类目累计计数。"""
    from docx import Document

    doc = Document(str(original_path))
    totals: Counter[str] = Counter()

    for para in doc.paragraphs:
        _desensitize_paragraph(para, desensitize, totals)

    for table in doc.tables:
        rows = list(table.rows)
        raw_table = _collect_raw_table(rows)
        for row_idx, row in enumerate(rows):
            cells = list(row.cells)
            for col_idx, cell in enumerate(cells):
                label = _find_table_label(raw_table, row_idx, col_idx)
                for para in cell.paragraphs:
                    _desensitize_paragraph(para, desensitize, totals, label=label)

    md_text = _render_markdown(doc)
    md_tmp = md_path.with_suffix(md_path.suffix + ".tmp")
    md_tmp.write_text(md_text, encoding="utf-8")
    md_tmp.replace(md_path)

    return dict(totals)


def _collect_raw_table(rows) -> list[list[str]]:
    """脱敏前快照：raw_table[row][col] = 该 cell 的原始拼接文本（label 匹配用）。"""
    out: list[list[str]] = []
    for row in rows:
        row_texts: list[str] = []
        for cell in row.cells:
            parts = [p.text.strip() for p in cell.paragraphs if p.text.strip()]
            row_texts.append(" / ".join(parts))
        out.append(row_texts)
    return out


def _normalize_label_text(text: str) -> str:
    """label cell 规整化：去首尾空白和冒号，方便和关键词集合比对。"""
    return text.strip().strip("：:").strip()


def _find_table_label(raw_table: list[list[str]], row_idx: int, col_idx: int) -> str | None:
    """查 cell 对应的 label：
      1. 同行就近：col_idx-1, col_idx-2, ... 任意一个是关键词
      2. 同列首行：raw_table[0][col_idx] 是关键词
    """
    if not raw_table:
        return None
    row = raw_table[row_idx]
    for prev_col in range(col_idx - 1, -1, -1):
        norm = _normalize_label_text(row[prev_col])
        if norm in _TABLE_LABEL_KEYWORDS:
            return norm
    if row_idx > 0 and col_idx < len(raw_table[0]):
        norm = _normalize_label_text(raw_table[0][col_idx])
        if norm in _TABLE_LABEL_KEYWORDS:
            return norm
    return None


def _desensitize_paragraph(
    para,
    desensitize: DesensitizeFn,
    totals: Counter,
    label: str | None = None,
) -> None:
    original = para.text
    if not original or not original.strip():
        return

    redacted: str | None = None
    counts: dict[str, int] | None = None

    if label and _normalize_label_text(original) not in _TABLE_LABEL_KEYWORDS:
        prefix = f"{label}: "
        composite = prefix + original
        red_comp, cnt = desensitize(composite)
        if red_comp != composite and red_comp.startswith(prefix):
            redacted = red_comp[len(prefix):]
            counts = cnt

    if redacted is None:
        redacted, counts = desensitize(original)

    if redacted == original:
        return

    totals.update(counts or {})
    for r in para.runs:
        r.text = ""
    para.add_run(redacted)


_HEADING_LEVEL_RE = re.compile(r"(\d+)")


def _render_markdown(doc) -> str:
    """按 body 顺序导出 markdown：段落+表格交错时走底层 element.iterchildren()。"""
    from docx.oxml.ns import qn
    from docx.text.paragraph import Paragraph
    from docx.table import Table

    blocks: list[str] = []
    for child in doc.element.body.iterchildren():
        tag = child.tag
        if tag == qn("w:p"):
            para = Paragraph(child, doc)
            rendered = _para_to_md(para)
            if rendered:
                blocks.append(rendered)
        elif tag == qn("w:tbl"):
            table = Table(child, doc)
            rendered = _table_to_md(table)
            if rendered:
                blocks.append(rendered)
    return "\n\n".join(blocks) + ("\n" if blocks else "")


def _para_to_md(para) -> str:
    text = para.text.strip()
    if not text:
        return ""
    style_name = ""
    try:
        style_name = (para.style.name or "").lower() if para.style else ""
    except Exception:
        pass
    if style_name.startswith("heading"):
        m = _HEADING_LEVEL_RE.search(style_name)
        level = int(m.group(1)) if m else 1
        level = max(1, min(level, 6))
        return f"{'#' * level} {text}"
    return text


def _table_to_md(table) -> str:
    rows_text: list[list[str]] = []
    for row in table.rows:
        cells_text: list[str] = []
        for cell in row.cells:
            parts = [p.text.strip() for p in cell.paragraphs if p.text.strip()]
            joined = " / ".join(parts).replace("|", "\\|").replace("\n", " ")
            cells_text.append(joined)
        rows_text.append(cells_text)
    if not rows_text:
        return ""
    n_cols = max(len(r) for r in rows_text)
    rows_text = [r + [""] * (n_cols - len(r)) for r in rows_text]
    header = "| " + " | ".join(rows_text[0]) + " |"
    sep = "| " + " | ".join(["---"] * n_cols) + " |"
    body = ["| " + " | ".join(r) + " |" for r in rows_text[1:]]
    return "\n".join([header, sep, *body])
