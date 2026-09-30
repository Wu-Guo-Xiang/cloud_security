"""XLSX → 脱敏 .md 命令行入口（skill 自包含）。

为什么存在：
  Claude Code 的 Read 工具拒读 .xlsx 二进制（OOXML 压缩包）。
  本脚本由 xlsx-redact skill 触发：openpyxl 按工作表遍历 cells/merged ranges
  → L1 正则 + L2 LLM NER → 工作簿级一致性占位符替换 → 按 sheet 顺序渲染 markdown
  → 写到临时目录 → stdout 输出 .md 路径。

用法：
  py xlsx_to_md.py <input.xlsx>

输出：
  stdout: 唯一一行，脱敏后 .md 副本的绝对路径
  exit 0：脱敏成功 / 或文档无敏感数据但已转 markdown 供 Claude 阅读
  exit !=0：处理失败，stderr 是原因
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import time
import uuid
import warnings
from dataclasses import dataclass
from pathlib import Path

# Windows 默认 cp936：中文路径写到 stdout 会乱码 → 强制 UTF-8。
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except (AttributeError, Exception):
    pass

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from entity_map import EntityMap  # noqa: E402
from llm_detector import detect as llm_detect  # noqa: E402
from pseudonymizer import pseudonymize  # noqa: E402
from redactor import collect_l1_spans  # noqa: E402
from xlsx_writer import cell_to_str, write_redacted_md  # noqa: E402
from _l1_only_confirm import confirm_l1_only  # noqa: E402


@dataclass(frozen=True)
class _LocalEntity:
    text: str
    type: str
    start: int
    end: int


def main() -> int:
    ap = argparse.ArgumentParser(description="Desensitize a .xlsx into a .md copy.")
    ap.add_argument("input_path", help="原始 .xlsx 路径")
    ap.add_argument(
        "--session-id",
        default=os.environ.get("CLAUDE_SESSION_ID") or f"xlsx_cli_{uuid.uuid4().hex[:8]}",
        help="会话 ID（影响临时目录命名）",
    )
    ap.add_argument(
        "--out-dir",
        default=os.environ.get("XLSX_SKILL_OUT_DIR", ""),
        help="输出目录（默认：C:/After-tuomin/xlsx/{session_id}/）",
    )
    args = ap.parse_args()

    input_path = Path(args.input_path).expanduser().resolve()
    if not input_path.exists():
        sys.stderr.write(f"file not found: {input_path}\n")
        return 1

    ext = input_path.suffix.lower()
    if ext == ".xls":
        sys.stderr.write(
            "this skill does not support legacy .xls (Excel 97-2003 binary).\n"
            "please open the file in Excel and 'Save As' .xlsx, then retry.\n"
        )
        return 1
    if ext not in (".xlsx", ".xlsm"):
        sys.stderr.write(f"not a .xlsx/.xlsm: {input_path}\n")
        return 1

    try:
        from openpyxl import load_workbook
    except ImportError:
        sys.stderr.write("missing dependency: openpyxl (pip install openpyxl)\n")
        return 1

    # openpyxl 对 .xlsm 宏、未知扩展、data validation 等会发 UserWarning，
    # 这里全部静默：我们只读单元格值，不执行任何 VBA。
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        # data_only=True：公式取缓存计算值。若 .xlsx 从未在 Excel 中打开过，
        # 缓存可能为空 → 该单元格被读作 None。这是 v1 接受的限制。
        wb = load_workbook(str(input_path), data_only=True, read_only=False)

    full_text = _concat_workbook_text(wb)

    llm_result = llm_detect(full_text)
    llm_entities = list(llm_result.entities)
    l1_only_warning = ""

    # [v1.1-patch-5x] L2 fail-CLOSED:见 docx_to_md.py patch-5 同款理由。
    # [v1.2-patch-7x] 同 docx_to_md.py patch-7:重试 1 次 + MessageBox 用户授权。
    if not llm_result.ok and llm_result.error != "llm_disabled":
        sys.stderr.write(f"L2 LLM 首次失败({llm_result.error}),2s 后重试一次...\n")
        time.sleep(2)
        llm_result_retry = llm_detect(full_text)
        if llm_result_retry.ok:
            llm_result = llm_result_retry
            llm_entities = list(llm_result.entities)
            sys.stderr.write("L2 LLM 重试成功。\n")
        else:
            sys.stderr.write(
                f"L2 LLM 重试仍失败({llm_result_retry.error}),弹窗请用户确认...\n"
            )
            if not confirm_l1_only("xlsx-redact", input_path, llm_result_retry.error):
                sys.stderr.write(
                    f"L2 LLM 失败({llm_result_retry.error}),用户拒绝 / 超时 / 非 Windows,\n"
                    "fail-CLOSED 中断,不输出 .md。\n"
                    "请检查 LLM 服务可用性后重试;或在 llm.yml 中显式将 L2 关闭(disabled),\n"
                    "明示接受 L1-only 脱敏的覆盖率限制。\n"
                )
                return 2
            sys.stderr.write(
                f"用户授权 L1-only 输出({llm_result_retry.error})。\n"
                "  仅手机/邮箱/卡号/身份证/USCC/凭据等结构化字段会脱敏,\n"
                "  人名/公司/产品/项目代号等语义实体保留原文(已在 .md 头部明示)。\n"
            )
            llm_entities = []
            l1_only_warning = (
                "> ⚠ **L1-only 脱敏(LLM 不可用)**  \n"
                f"> 原因:`{llm_result_retry.error}`(重试 1 次仍失败)  \n"
                "> 影响:**人名 / 公司 / 产品 / 项目代号等语义实体未替换**,只有手机 /\n"
                "> 邮箱 / 卡号 / 身份证 / USCC / 凭据等结构化字段被脱敏。\n"
                "> 处置:用户已通过 MessageBox 主动授权本副本输出。后续如需完整脱敏,\n"
                "> 请在 LLM 服务恢复后重新运行 `xlsx_to_md.py`。\n\n"
            )

    entity_map = EntityMap()

    def desensitize(cell_text: str) -> tuple[str, dict[str, int]]:
        l1_spans = collect_l1_spans(cell_text)
        local_ents = _relocate_llm_entities(cell_text, llm_entities)
        if not l1_spans and not local_ents:
            return cell_text, {}
        return pseudonymize(
            text=cell_text,
            l1_spans=l1_spans,
            llm_entities=local_ents,
            entity_map=entity_map,
        )

    # [v1.1-patch-6x] _resolve_out_path 拒绝白名单外路径时抛 ValueError → return 2
    try:
        md_path = _resolve_out_path(args.out_dir, args.session_id, input_path)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 2
    md_path.parent.mkdir(parents=True, exist_ok=True)

    counts = write_redacted_md(
        workbook=wb,
        md_path=md_path,
        desensitize=desensitize,
    )

    # [v1.2-patch-7x] L1-only 授权时,.md 头部 prepend warning。
    if l1_only_warning:
        existing = md_path.read_text(encoding="utf-8")
        md_path.write_text(l1_only_warning + existing, encoding="utf-8")

    sys.stderr.write(f"redacted classes: {counts or '(none)'}\n")
    # [v1.1-patch-5x] L2 失败已在上方 fail-CLOSED;此处不再有 "warning + 继续输出" 路径

    sys.stdout.write(str(md_path) + "\n")
    return 0


def _concat_workbook_text(wb) -> str:
    """工作簿全文 → L2 LLM NER 输入。

    xlsx 重复值高发（分类列、状态列），这里去重：LLM NER 只需要每个实体出现一次
    就能识别，去重把 prompt 体积压到可控范围。同时也包含 sheet title。
    """
    parts: list[str] = []
    seen: set[str] = set()

    for ws in wb.worksheets:
        title = (ws.title or "").strip()
        if title and title not in seen:
            seen.add(title)
            parts.append(title)
        for row in ws.iter_rows(values_only=True):
            for v in row:
                s = cell_to_str(v).strip()
                if not s or s in seen:
                    continue
                seen.add(s)
                parts.append(s)

    return "\n".join(parts)


def _relocate_llm_entities(cell_text: str, llm_entities: list) -> list[_LocalEntity]:
    """把全文 llm_entities 在单元格内重新定位，type 沿用首次匹配的 type。"""
    out: list[_LocalEntity] = []
    for ent in llm_entities:
        if not ent.text or ent.text not in cell_text:
            continue
        idx = 0
        while True:
            pos = cell_text.find(ent.text, idx)
            if pos == -1:
                break
            out.append(_LocalEntity(ent.text, ent.type, pos, pos + len(ent.text)))
            idx = pos + len(ent.text)
    return out


_SAFE_RE = re.compile(r"[^A-Za-z0-9_\-]")


def _sanitize(value: str) -> str:
    return (_SAFE_RE.sub("_", value or "")[:80]) or "unknown"


# [v1.1-patch-6x] --out-dir 白名单根。见 docx_to_md.py patch-6 同款理由。
_ALLOWED_OUT_DIR_ROOTS = (
    Path(r"D:\After-tuomin").resolve(),
)


def _is_within_allowed_out_dir(candidate: Path) -> bool:
    try:
        resolved = candidate.resolve()
    except (OSError, ValueError):
        return False
    for root in _ALLOWED_OUT_DIR_ROOTS:
        if resolved == root or root in resolved.parents:
            return True
    return False


def _resolve_out_path(out_dir: str, session_id: str, original_path: Path) -> Path:
    """输出路径 = {out_dir or C:/After-tuomin/xlsx}/{session_id}/{stem}_{sha12}.md

    [v1.1-patch-6x] out_dir 不在 _ALLOWED_OUT_DIR_ROOTS 子树内时抛 ValueError。
    """
    if out_dir:
        base = Path(out_dir).expanduser().resolve()
        if not _is_within_allowed_out_dir(base):
            raise ValueError(
                f"--out-dir 不在白名单内: {base}\n"
                f"允许的根: {', '.join(str(r) for r in _ALLOWED_OUT_DIR_ROOTS)}"
            )
    else:
        base = Path(r"D:\After-tuomin\xlsx")
    base = base / _sanitize(session_id)
    digest = _file_sha(original_path)
    return base / f"{original_path.stem}_{digest}.md"


def _file_sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:12]


if __name__ == "__main__":
    sys.exit(main())
