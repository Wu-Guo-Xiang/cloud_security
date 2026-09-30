"""DOCX → 脱敏 .md 命令行入口（skill 自包含）。

为什么存在：
  Claude Code 的 Read 工具拒读 .docx 二进制（且 PreToolUse hook 钩不到 .docx Read）。
  本脚本由 docx skill 触发：python-docx 抽段 → L1 正则 + L2 LLM NER → 段级一致性
  占位符替换 → 按 body 顺序渲染 markdown → 写到临时目录 → stdout 输出 .md 路径。

用法：
  py docx_to_md.py <input.docx>

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
from dataclasses import dataclass
from pathlib import Path

# Windows 默认 cp936：中文路径写到 stdout 会乱码 → 强制 UTF-8。
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except (AttributeError, Exception):
    pass

# 同目录脚本走相对 import：把 skill 目录加到 sys.path 头部
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from docx_writer import write_redacted_md  # noqa: E402
from entity_map import EntityMap  # noqa: E402
from llm_detector import detect as llm_detect  # noqa: E402
from pseudonymizer import pseudonymize  # noqa: E402
from redactor import collect_l1_spans, redact  # noqa: E402
from _l1_only_confirm import confirm_l1_only  # noqa: E402


@dataclass(frozen=True)
class _LocalEntity:
    """duck-type LLMEntity（pseudonymize 只看 text/type/start/end）。"""
    text: str
    type: str
    start: int
    end: int


def main() -> int:
    ap = argparse.ArgumentParser(description="Desensitize a .docx into a .md copy.")
    ap.add_argument("input_path", help="原始 .docx 路径")
    ap.add_argument(
        "--session-id",
        default=os.environ.get("CLAUDE_SESSION_ID") or f"docx_cli_{uuid.uuid4().hex[:8]}",
        help="会话 ID（影响临时目录命名）",
    )
    ap.add_argument(
        "--out-dir",
        default=os.environ.get("DOCX_SKILL_OUT_DIR", ""),
        help="输出目录（默认：C:/After-tuomin/docx/{session_id}/）",
    )
    args = ap.parse_args()

    input_path = Path(args.input_path).expanduser().resolve()
    if not input_path.exists():
        sys.stderr.write(f"file not found: {input_path}\n")
        return 1
    if input_path.suffix.lower() != ".docx":
        sys.stderr.write(f"not a .docx: {input_path}\n")
        return 1

    try:
        from docx import Document
    except ImportError:
        sys.stderr.write("missing dependency: python-docx (pip install python-docx)\n")
        return 1

    # 拼出全文给 L2 LLM 做跨段 NER（实体一致性靠 entity_map 在段落渲染时维护）
    doc = Document(str(input_path))
    full_text = _concat_doc_text(doc)

    llm_result = llm_detect(full_text)
    llm_entities = list(llm_result.entities)
    l1_only_warning = ""

    # [v1.1-patch-5] L2 fail-CLOSED:LLM 失败(非"disabled"配置)时拒绝输出 .md。
    # 只 L1 正则覆盖证件/电话/银行卡/USCC/凭据/词库;人名、地址全名、未入库公司名
    # 全部漏脱,继续输出 .md 等于把"半脱敏"原文交给 Claude。
    # 与 cloud-security-hook-fail-open 教训对齐:fail-OPEN 是泄密通道。
    #
    # [v1.2-patch-7] 网络抖动友好度:不再首次失败就死。先 sleep 2s 重试 1 次,
    # 仍失败时弹 MessageBox 让用户决定是否接受 L1-only 输出。
    # 用户主动同意 → 写 .md 但加 warning 头明示;
    # 用户拒绝 / 超时 / 非 Windows → 仍然 fail-CLOSED。
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
            if not confirm_l1_only("docx", input_path, llm_result_retry.error):
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
                "> 请在 LLM 服务恢复后重新运行 `docx_to_md.py`。\n\n"
            )

    entity_map = EntityMap()

    def desensitize(para_text: str) -> tuple[str, dict[str, int]]:
        l1_spans = collect_l1_spans(para_text)
        local_ents = _relocate_llm_entities(para_text, llm_entities)
        if not l1_spans and not local_ents:
            return para_text, {}
        return pseudonymize(
            text=para_text,
            l1_spans=l1_spans,
            llm_entities=local_ents,
            entity_map=entity_map,
        )

    # [v1.1-patch-6] _resolve_out_path 拒绝白名单外路径时抛 ValueError → return 2
    try:
        md_path = _resolve_out_path(args.out_dir, args.session_id, input_path)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 2
    md_path.parent.mkdir(parents=True, exist_ok=True)

    counts = write_redacted_md(
        original_path=input_path,
        md_path=md_path,
        desensitize=desensitize,
    )

    # [v1.2-patch-7] L1-only 授权时,在 .md 头部 prepend warning,让阅读 .md 的
    # 后续 Claude 立刻看到"语义实体未脱敏",而不是默认按完全脱敏处理。
    if l1_only_warning:
        existing = md_path.read_text(encoding="utf-8")
        md_path.write_text(l1_only_warning + existing, encoding="utf-8")

    sys.stderr.write(f"redacted classes: {counts or '(none)'}\n")
    # [v1.1-patch-5] L2 失败已在上方 fail-CLOSED;此处不再有 "warning + 继续输出" 路径

    sys.stdout.write(str(md_path) + "\n")
    return 0


def _concat_doc_text(doc) -> str:
    parts: list[str] = []
    for para in doc.paragraphs:
        if para.text and para.text.strip():
            parts.append(para.text)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for para in cell.paragraphs:
                    if para.text and para.text.strip():
                        parts.append(para.text)
    return "\n".join(parts)


def _relocate_llm_entities(para_text: str, llm_entities: list) -> list[_LocalEntity]:
    """把全文 llm_entities 在段内重新定位，type 沿用首次匹配的 type。"""
    out: list[_LocalEntity] = []
    for ent in llm_entities:
        if not ent.text or ent.text not in para_text:
            continue
        idx = 0
        while True:
            pos = para_text.find(ent.text, idx)
            if pos == -1:
                break
            out.append(_LocalEntity(ent.text, ent.type, pos, pos + len(ent.text)))
            idx = pos + len(ent.text)
    return out


_SAFE_RE = re.compile(r"[^A-Za-z0-9_\-]")


def _sanitize(value: str) -> str:
    return (_SAFE_RE.sub("_", value or "")[:80]) or "unknown"


# [v1.1-patch-6] --out-dir 白名单根。任何 out_dir 必须落在某个白名单根的子树内,
# 否则拒绝(return 2)。防止 Claude 被诱导把 .md 副本写到任意路径(脚本是子进程,
# 不经过 write_guard,白名单只能在 skill 内部硬编码)。
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
    """输出路径 = {out_dir or C:/After-tuomin/docx}/{session_id}/{stem}_{sha12}.md

    [v1.1-patch-6] out_dir 不在 _ALLOWED_OUT_DIR_ROOTS 子树内时抛 ValueError,
    main() 捕获后 return 2。
    """
    if out_dir:
        base = Path(out_dir).expanduser().resolve()
        if not _is_within_allowed_out_dir(base):
            raise ValueError(
                f"--out-dir 不在白名单内: {base}\n"
                f"允许的根: {', '.join(str(r) for r in _ALLOWED_OUT_DIR_ROOTS)}"
            )
    else:
        base = Path(r"D:\After-tuomin\docx")
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
