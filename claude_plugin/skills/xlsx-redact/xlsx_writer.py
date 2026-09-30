"""XLSX 脱敏渲染器。

按 sheet 遍历 → 每个 cell 调脱敏闭包 → 渲染成 markdown 表格写到 md_path。

接口（被 xlsx_to_md 调用）：
  write_redacted_md(workbook, md_path, desensitize) → counts

设计折中（v1）：
  - 单元格级脱敏：每个 cell 独立跑脱敏。跨单元格实体不识别，但 entity_map 在工作簿
    范围内保证同一原文映射到同一占位符。
  - 公式：取缓存计算值（CLI 层用 data_only=True 打开），未缓存的公式被读作 None。
  - 合并单元格：openpyxl 默认 top-left 持值、其他 None；这里按 None 渲染空，不复制。
  - 隐藏 sheet 仍渲染，标题加 " (hidden)" 标记。
  - 不处理：图表 / 透视表 / 图片 / 条件格式 / 公式本身（留给后续版本）。
"""
from __future__ import annotations

from collections import Counter
from datetime import date, datetime, time
from pathlib import Path
from typing import Callable


DesensitizeFn = Callable[[str], "tuple[str, dict[str, int]]"]


# 表格 label-value 复原：cell 单独喂 L1 正则会因失锚漏识别（如 "91310000MA1K35P57Y"
# 在裸 cell 里匹不到 USCC 规则）。改造：根据 cell 在表格中的位置查 label cell
# （同行就近 + 列首行），临时拼成 "label: value" 喂给 desensitize，再剥前缀。
# 与 rules.yml 中 6 类 label-value 正则的 label 字面值一一对应。
_TABLE_LABEL_KEYWORDS = frozenset([
    "统一社会信用代码", "信用代码",
    "组织机构代码",
    "合同编号", "协议编号", "文件编号", "文件号",
    "专利申请号", "商标申请号", "著作权申请号",
    "电话", "联系电话", "座机", "总机", "传真", "传真号码",
    "地址", "住所", "住址", "注册地址", "办公地址", "经营地址", "住所地",
])


def _normalize_label_text(text: str) -> str:
    return text.strip().strip("：:").strip()


def _find_table_label(raw_table: list[list[str]], row_idx: int, col_idx: int) -> str | None:
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


def _desensitize_with_label(
    text: str,
    label: str | None,
    desensitize: DesensitizeFn,
) -> tuple[str, dict[str, int]]:
    if label and _normalize_label_text(text) not in _TABLE_LABEL_KEYWORDS:
        prefix = f"{label}: "
        composite = prefix + text
        red_comp, cnt = desensitize(composite)
        if red_comp != composite and red_comp.startswith(prefix):
            return red_comp[len(prefix):], cnt
    return desensitize(text)


def write_redacted_md(
    *,
    workbook,
    md_path: Path,
    desensitize: DesensitizeFn,
) -> dict[str, int]:
    """按 sheet 顺序脱敏 + 渲染成 markdown，返回类目累计计数。"""
    totals: Counter[str] = Counter()
    blocks: list[str] = []

    for sheet_idx, ws in enumerate(workbook.worksheets, 1):
        title = (ws.title or "").strip()
        if title:
            redacted_title, counts = desensitize(title)
            totals.update(counts)
        else:
            redacted_title = ""

        hidden_mark = ""
        try:
            if ws.sheet_state and ws.sheet_state != "visible":
                hidden_mark = f" ({ws.sheet_state})"
        except AttributeError:
            pass

        heading_suffix = f": {redacted_title}" if redacted_title else ""
        blocks.append(f"## Sheet {sheet_idx}{heading_suffix}{hidden_mark}")

        rendered = _sheet_to_md(ws, desensitize, totals)
        if rendered:
            blocks.append(rendered)
        else:
            blocks.append("_(empty sheet)_")

    md_text = "\n\n".join(blocks) + ("\n" if blocks else "")
    md_tmp = md_path.with_suffix(md_path.suffix + ".tmp")
    md_tmp.write_text(md_text, encoding="utf-8")
    md_tmp.replace(md_path)

    return dict(totals)


def _sheet_to_md(ws, desensitize: DesensitizeFn, totals: Counter) -> str:
    """工作表 → markdown 表格。首行作 header，尾部全空行/列裁掉。

    label-value 复原：先收集 raw_table 用于查 label cell，再逐 cell 调
    _desensitize_with_label 让 L1 label-value 规则能命中。
    """
    raw_table: list[list[str]] = []
    for row in ws.iter_rows(values_only=True):
        row_texts: list[str] = []
        for v in row:
            row_texts.append(cell_to_str(v))
        raw_table.append(row_texts)

    rows_text: list[list[str]] = []
    for row_idx, raw_row in enumerate(raw_table):
        cells_text: list[str] = []
        for col_idx, s in enumerate(raw_row):
            if s:
                label = _find_table_label(raw_table, row_idx, col_idx)
                redacted, counts = _desensitize_with_label(s, label, desensitize)
                totals.update(counts)
                cells_text.append(_md_escape(redacted))
            else:
                cells_text.append("")
        rows_text.append(cells_text)

    # 裁尾部全空行
    while rows_text and not any(c for c in rows_text[-1]):
        rows_text.pop()
    if not rows_text:
        return ""

    # 列对齐 + 裁尾部全空列
    n_cols = max(len(r) for r in rows_text)
    rows_text = [r + [""] * (n_cols - len(r)) for r in rows_text]
    while n_cols > 0 and all(not r[n_cols - 1] for r in rows_text):
        n_cols -= 1
    if n_cols == 0:
        return ""
    rows_text = [r[:n_cols] for r in rows_text]

    # 表头空白的列名补占位（markdown 表格头部空字符串会被某些渲染器吞）
    header_cells = [c if c else f"_col{i+1}" for i, c in enumerate(rows_text[0])]
    header = "| " + " | ".join(header_cells) + " |"
    sep = "| " + " | ".join(["---"] * n_cols) + " |"
    body = ["| " + " | ".join(r) + " |" for r in rows_text[1:]]
    return "\n".join([header, sep, *body])


def cell_to_str(v) -> str:
    """单元格值 → 字符串。

    None → ""；bool → TRUE/FALSE；整数化的 float → int；datetime → isoformat；
    其余 → str() 后 strip。
    """
    if v is None:
        return ""
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v != v:  # NaN
            return ""
        if v.is_integer() and abs(v) < 1e16:
            return str(int(v))
        return repr(v) if abs(v) > 1e15 else f"{v:g}"
    if isinstance(v, (datetime, date, time)):
        try:
            return v.isoformat()
        except (ValueError, AttributeError):
            return str(v)
    return str(v).strip()


def _md_escape(text: str) -> str:
    """单元格文本进 markdown 表格前的最小转义。

    管道符必须转义；换行符折叠成空格避免破坏表格行；CR 去掉。
    """
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", "")
