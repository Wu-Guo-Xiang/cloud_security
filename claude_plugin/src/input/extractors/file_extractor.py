"""Read 工具：文件内容抽取。

支持类型：
  - T1 纯文本/代码：扩展名白名单 + UTF-8 解码（兼容 GBK/GB18030 回退）
  - .docx：通过 python-docx 抽取段落与表格文本
  - .pdf：通过 pdfplumber 抽取每页文本；无文本层（扫描件）返回 pdf_no_text_layer

其余类型（Excel / PPT / 图片 / 压缩包 / 二进制）暂返回 skipped_reason="unsupported_format_v1"。
受控工作目录外的路径直接 skipped="outside_workdir"，避免越权读敏感盘符。
"""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from config.paths import paths
from .base import ExtractResult


# 允许读取但不受控的目录（脱敏后的输出目录等）。
# 这些目录内的文件不会触发自动脱敏，但允许 Claude 读取。
# 真正的判定走 paths.is_within_read_whitelist(受控目录 + read_whitelist);
# 这里保留常量仅为向后兼容/文档参考,不再被 extract() 直接使用。
_ALLOWED_READ_DIRS: list[Path] = [
    Path(r"D:\After-tuomin").resolve(),
]


# 最大读取大小（字节）：> 10MB 走截断 + truncated=True；后续步骤可扩展摘要模式
_MAX_BYTES = 10 * 1024 * 1024

# T1：文本 / 代码扩展名白名单
_TEXT_EXTS = frozenset({
    # 通用文本
    ".txt", ".log", ".md", ".rst", ".csv", ".tsv", ".json", ".jsonl",
    ".yaml", ".yml", ".xml", ".html", ".htm", ".ini", ".cfg", ".conf",
    ".env", ".properties", ".toml",
    # 代码
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".java", ".kt", ".scala", ".go", ".rs", ".rb", ".php", ".pl",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".sql", ".graphql", ".proto", ".tf", ".hcl", ".dockerfile",
    ".vue", ".svelte", ".scss", ".sass", ".css", ".less",
})


def extract(file_path: str) -> ExtractResult:
    if not file_path:
        return ExtractResult(skipped_reason="empty_path")

    try:
        p = Path(file_path).resolve()
    except (OSError, ValueError):
        return ExtractResult(skipped_reason="invalid_path")

    label = f"file:{p}"

    # 路径必须在受控目录或读白名单(D:\After-tuomin 副本)内,否则拒绝读取
    if not paths.is_within_read_whitelist(p):
        return ExtractResult(source_label=label, skipped_reason="outside_allowed_dirs")

    if not p.exists() or not p.is_file():
        return ExtractResult(source_label=label, skipped_reason="not_a_file")

    ext = p.suffix.lower()
    if ext == ".docx":
        return _extract_docx(p, label)
    if ext == ".pdf":
        return _extract_pdf(p, label)
    if ext in _TEXT_EXTS or ext == "":  # 无扩展名也按文本尝试（Dockerfile / Makefile 等）
        return _extract_text(p, label)

    return ExtractResult(source_label=label, skipped_reason="unsupported_format_v1")


def _extract_text(p: Path, label: str) -> ExtractResult:
    try:
        size = p.stat().st_size
        truncated = size > _MAX_BYTES
        with p.open("rb") as f:
            raw = f.read(_MAX_BYTES)
    except OSError as e:
        return ExtractResult(source_label=label, skipped_reason=f"read_error:{e.errno}")

    # UTF-8 优先，回退 GBK；最后用 errors=replace 兜底
    for enc in ("utf-8", "utf-8-sig", "gb18030"):
        try:
            text = raw.decode(enc)
            return ExtractResult(text=text, source_label=label, truncated=truncated)
        except UnicodeDecodeError:
            continue

    text = raw.decode("utf-8", errors="replace")
    return ExtractResult(text=text, source_label=label, truncated=truncated)


def _extract_docx(p: Path, label: str) -> ExtractResult:
    try:
        from docx import Document  # type: ignore[import-not-found]
    except ImportError:
        return ExtractResult(source_label=label, skipped_reason="docx_lib_missing")

    try:
        doc = Document(str(p))
    except Exception as e:
        return ExtractResult(source_label=label, skipped_reason=f"docx_open_error:{type(e).__name__}")

    parts: list[str] = []
    total_len = 0
    truncated = False

    for para in doc.paragraphs:
        if para.text:
            parts.append(para.text)
            total_len += len(para.text)
            if total_len > _MAX_BYTES:
                truncated = True
                break

    if not truncated:
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    if cell.text:
                        parts.append(cell.text)
                        total_len += len(cell.text)
                        if total_len > _MAX_BYTES:
                            truncated = True
                            break
                if truncated:
                    break
            if truncated:
                break

    return ExtractResult(
        text="\n".join(parts),
        source_label=label,
        truncated=truncated,
    )


def _extract_pdf(p: Path, label: str) -> ExtractResult:
    """pdfplumber 逐页抽文本。

    抽完做两步后处理：
      1. NFKC 归一化：把 PDF 里偏旁兼容字符（⽂/⼦/⻩/⼯）折叠回正常 CJK
         （否则 L2 NER 召回会明显掉档，正则也错位）
      2. 逻辑行合并：把 pdfplumber 按视觉强切的行拼回完整句子。
         判定规则：上一行非句末标记结尾 + 当前行非章节/列表标号开头 → 拼回。
         不加空格（中文正文不需要 word boundary）。

    无文本层（扫描件）→ skipped_reason=pdf_no_text_layer，由 input_scanner 走
    fail-closed 阻断而非放行；OCR 留给后续目标六的 Qwen-VL 阶段处理。
    """
    try:
        import pdfplumber  # type: ignore[import-not-found]
    except ImportError:
        return ExtractResult(source_label=label, skipped_reason="pdf_lib_missing")

    parts: list[str] = []
    total_len = 0
    truncated = False

    try:
        with pdfplumber.open(str(p)) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text() or ""
                if not page_text:
                    continue
                parts.append(page_text)
                total_len += len(page_text)
                if total_len > _MAX_BYTES:
                    truncated = True
                    break
    except Exception as e:
        return ExtractResult(source_label=label, skipped_reason=f"pdf_open_error:{type(e).__name__}")

    raw_text = "\n".join(parts)
    if not raw_text.strip():
        return ExtractResult(source_label=label, skipped_reason="pdf_no_text_layer")

    text = _postprocess_pdf_text(raw_text)
    return ExtractResult(text=text, source_label=label, truncated=truncated)


# 句末/分句标点：以这些字符结尾的行视为完整句子，下一行另起
_SENT_END_CHARS = "。！？!?；;:：）)】」』"
# 段首/章节标号：以这些 pattern 开头的行视为新段，不要被拼回上一行
_NEW_PARA_PATTERNS = [
    re.compile(r"^[一二三四五六七八九十]+[、.,]"),    # 一、 二.
    re.compile(r"^[（(][一二三四五六七八九十]+[）)]"),  # （一）
    re.compile(r"^\d+[、.)]\s?"),                     # 1、 1. 1)
    re.compile(r"^[（(]\d+[）)]"),                    # （1）
    re.compile(r"^#{1,6}\s"),                         # markdown #
    re.compile(r"^[甲乙丙丁戊己庚辛]方[：:]"),         # 甲方：
    re.compile(r"^—{2,}"),                            # —— 分隔线
]


def _is_new_paragraph(line: str) -> bool:
    return any(pat.match(line) for pat in _NEW_PARA_PATTERNS)


# CJK Radicals Supplement (U+2E80-2EFF) 段是部首字符，NFKC 不折叠。
# PDF 内嵌字体 CMap 异常时会把正字符（如"黄"）映到对应部首码位，
# 导致 L1 正则（仅认 U+4E00-9FFF）和 L2 NER 双双失效。手工补一张常见字映射。
_RADICAL_FOLD = {
    "⻁": "虎",  # 虎
    "⻅": "见",  # 见
    "⻈": "让",  # 讠
    "⻉": "贝",  # 贝
    "⻊": "足",  # 足
    "⻋": "车",  # 车
    "⻌": "辶",  # 辶
    "⻍": "辶",  # 辶
    "⻒": "长",  # 长（异体码位）
    "⻓": "长",  # 长
    "⻔": "门",  # 门
    "⻕": "韦",  # 韦
    "⻘": "青",  # 青
    "⻚": "页",  # 页
    "⻛": "风",  # 风
    "⻜": "飞",  # 飞
    "⻞": "饣",  # 饣
    "⻢": "马",  # 马
    "⻣": "骨",  # 骨
    "⻤": "鬼",  # 鬼
    "⻥": "鱼",  # 鱼
    "⻦": "鸟",  # 鸟
    "⻨": "麦",  # 麦
    "⻩": "黄",  # 黄
    "⻪": "黾",  # 黾
}
_RADICAL_TRANS = str.maketrans(_RADICAL_FOLD)


def _postprocess_pdf_text(text: str) -> str:
    """NFKC 归一化 + CJK 部首字符折叠 + 跨行合并。"""
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_RADICAL_TRANS)
    lines = text.split("\n")
    out: list[str] = []
    for line in lines:
        stripped = line.rstrip()
        if not stripped:
            out.append("")
            continue
        if not out or not out[-1]:
            out.append(stripped)
            continue
        prev = out[-1]
        prev_last = prev[-1]
        if prev_last in _SENT_END_CHARS or _is_new_paragraph(stripped):
            out.append(stripped)
        else:
            out[-1] = prev + stripped.lstrip()
    return "\n".join(out)
