"""PPTX 脱敏渲染器。

打开原 .pptx → 按幻灯片遍历 shapes / tables / 备注 → 逐段调脱敏闭包
→ 按幻灯片顺序渲染成 markdown 写到 md_path。

接口（被 pptx_to_md 调用）：
  write_redacted_md(original_path, md_path, desensitize) → counts

设计折中（与 docx_writer v1 一致）：
  - 段落级整段脱敏：合并 paragraph 所有 run.text → 跑脱敏 → 渲染。
  - 跨段实体不识别；段内混排粗体/斜体被规整。
  - 不处理图片 / SmartArt / 图表数据 / 母版 / 页眉页脚（留给目标六 Qwen-VL）。
"""
from __future__ import annotations

from collections import Counter
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
    """有 label 时先试 "label: text" 合成喂给 desensitize 再剥前缀；
    没命中或没 label 退化为直接 desensitize(text)。"""
    if label and _normalize_label_text(text) not in _TABLE_LABEL_KEYWORDS:
        prefix = f"{label}: "
        composite = prefix + text
        red_comp, cnt = desensitize(composite)
        if red_comp != composite and red_comp.startswith(prefix):
            return red_comp[len(prefix):], cnt
    return desensitize(text)


def write_redacted_md(
    *,
    original_path: Path,
    md_path: Path,
    desensitize: DesensitizeFn,
) -> dict[str, int]:
    """按幻灯片顺序脱敏 + 渲染成 markdown，返回类目累计计数。"""
    from pptx import Presentation

    prs = Presentation(str(original_path))
    totals: Counter[str] = Counter()
    blocks: list[str] = []

    for slide_idx, slide in enumerate(prs.slides, 1):
        title_shape = _title_shape(slide)
        title_text = _shape_plain_text(title_shape) if title_shape is not None else ""
        # python-pptx 在 slide.placeholders 和 slide.shapes 上返回的是不同的 wrapper
        # 对象,`is` 比较会漏过同一 shape,改用 shape_id 做身份比对。
        title_shape_id = title_shape.shape_id if title_shape is not None else None

        if title_text:
            redacted_title, counts = desensitize(title_text)
            totals.update(counts)
            blocks.append(f"## Slide {slide_idx}: {redacted_title}")
        else:
            blocks.append(f"## Slide {slide_idx}")

        for shape in slide.shapes:
            if title_shape_id is not None and shape.shape_id == title_shape_id:
                continue
            if shape.has_text_frame:
                rendered = _text_frame_to_md(shape.text_frame, desensitize, totals)
                if rendered:
                    blocks.append(rendered)
            elif shape.has_table:
                rendered = _table_to_md(shape.table, desensitize, totals)
                if rendered:
                    blocks.append(rendered)
            # 图片 / SmartArt / 图表 / 文本框组 → v1 不处理

        if slide.has_notes_slide:
            notes_md = _notes_to_md(slide.notes_slide.notes_text_frame, desensitize, totals)
            if notes_md:
                blocks.append(notes_md)

    md_text = "\n\n".join(blocks) + ("\n" if blocks else "")
    md_tmp = md_path.with_suffix(md_path.suffix + ".tmp")
    md_tmp.write_text(md_text, encoding="utf-8")
    md_tmp.replace(md_path)

    return dict(totals)


def _title_shape(slide):
    """找标题占位符。优先 placeholder_format.idx==0；fallback 用 type 判断。"""
    try:
        placeholders = slide.placeholders
    except (AttributeError, KeyError):
        return None
    for ph in placeholders:
        try:
            if ph.placeholder_format is None:
                continue
            if ph.placeholder_format.idx == 0:
                return ph
        except (AttributeError, ValueError):
            continue
    # fallback: 走 placeholder type（TITLE=13, CENTER_TITLE=14 in PP_PLACEHOLDER）
    for ph in placeholders:
        try:
            ptype = ph.placeholder_format.type if ph.placeholder_format else None
            if ptype is None:
                continue
            # int 形态对比，避免依赖枚举值变化
            if int(ptype) in (13, 14):
                return ph
        except (AttributeError, ValueError, TypeError):
            continue
    return None


def _shape_plain_text(shape) -> str:
    """拿 shape 的纯文本（用于标题渲染，单行）。"""
    if shape is None or not shape.has_text_frame:
        return ""
    text = shape.text_frame.text or ""
    # 标题里换行直接折叠成空格，避免破坏 markdown heading 单行约束
    return " ".join(line.strip() for line in text.splitlines() if line.strip())


def _text_frame_to_md(text_frame, desensitize: DesensitizeFn, totals: Counter) -> str:
    """段落列表渲染：每段一行，按 para.level 加缩进的项目符号。"""
    lines: list[str] = []
    for para in text_frame.paragraphs:
        text = (para.text or "").strip()
        if not text:
            continue
        redacted, counts = desensitize(text)
        totals.update(counts)
        level = max(0, int(getattr(para, "level", 0) or 0))
        if level == 0:
            lines.append(redacted)
        else:
            lines.append("  " * (level - 1) + "- " + redacted)
    return "\n".join(lines)


def _table_to_md(table, desensitize: DesensitizeFn, totals: Counter) -> str:
    """表格 → markdown 表格（首行作表头，与 docx_writer 一致）。

    label-value 复原：先把全表原文快照拿到（label cell 找邻居用），再逐 cell
    根据位置查 label，调 _desensitize_with_label 让 L1 label-value 规则能命中。
    """
    rows = list(table.rows)
    raw_table = _collect_raw_table(rows)
    rows_text: list[list[str]] = []
    for row_idx, row in enumerate(rows):
        cells_text: list[str] = []
        for col_idx, cell in enumerate(row.cells):
            label = _find_table_label(raw_table, row_idx, col_idx)
            parts: list[str] = []
            for para in cell.text_frame.paragraphs:
                text = (para.text or "").strip()
                if not text:
                    continue
                redacted, counts = _desensitize_with_label(text, label, desensitize)
                totals.update(counts)
                parts.append(redacted)
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


def _collect_raw_table(rows) -> list[list[str]]:
    """脱敏前快照：raw_table[row][col] = 该 cell 的原始拼接文本（label 匹配用）。"""
    out: list[list[str]] = []
    for row in rows:
        row_texts: list[str] = []
        for cell in row.cells:
            parts: list[str] = []
            for para in cell.text_frame.paragraphs:
                t = (para.text or "").strip()
                if t:
                    parts.append(t)
            row_texts.append(" / ".join(parts))
        out.append(row_texts)
    return out


def _notes_to_md(notes_tf, desensitize: DesensitizeFn, totals: Counter) -> str:
    """演讲者备注 → markdown 引用块。"""
    paras: list[str] = []
    for para in notes_tf.paragraphs:
        text = (para.text or "").strip()
        if not text:
            continue
        redacted, counts = desensitize(text)
        totals.update(counts)
        paras.append(redacted)
    if not paras:
        return ""
    quoted = "\n".join(f"> {line}" for line in paras)
    return f"> **Notes:**\n{quoted}"
