"""脱敏动作。

执行路径：
  PreToolUse + Read（T1 文本）：调 pseudonymize() → 写 .{ext} 副本 →
      respond_redirect 阻断原读，提示 Claude 改读副本（CLAUDE.md 规则 8）
  PreToolUse + Read（.docx）：调 docx_writer 段级脱敏 + 按 body 顺序渲染 .md 副本 →
      重定向到 .md。Claude Code Read 不能读 .docx 二进制，所以副本走 .md
  PreToolUse + Read（.pdf）：抽出来已经是纯文本，副本写成 .txt（强制改后缀，
      让 Claude 走文本路径读副本，而不是再当 PDF 解析）→ 同上
  PreToolUse + Read（其他二进制格式）：脱敏暂未实现 → 退化为 block
  PreToolUse + Grep / WebFetch：无副本可生成 → 退化为 block，stderr 提示原因
  UserPromptSubmit：弹系统级 MessageBox 让用户确认 → 点是放行，点否/超时/异常阻断
      （之所以走弹框而非直接 block：VSCode 扩展不渲染 hook stderr，用户感知不到拦截）

L1+L2 合并替换：
  - 若调用方传入 entity_map，走 pseudonymizer.pseudonymize()，
    L1 用 [TYPE]，L2 用 [公司A]/[人员A]/[产品A]/[金额] 等一致性占位符。
  - 否则退回纯 L1 的 redact()（用于测试或 LLM 全失败的极端路径）。

副本路径：{paths.temp_desensitized}/{session_id}/{stem}_{sha[:12]}{副本扩展名}
其中副本扩展名：T1 → 原扩展名；.docx → .md；.pdf → .txt（强制覆写）。
"""
from __future__ import annotations

import hashlib
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cache.entity_map import EntityMap
from config.paths import paths
from lib.confirm import confirm
from lib.event import Event
from lib.response import respond_block, respond_pass, respond_redirect, respond_userprompt_block
from lib.types import Match

from . import docx_writer
from .base import ActionOutcome
from .pseudonymizer import pseudonymize
from .redactor import collect_l1_spans, redact


_T1_EXTS = frozenset({
    ".txt", ".log", ".md", ".rst", ".csv", ".tsv", ".json", ".jsonl",
    ".yaml", ".yml", ".xml", ".html", ".htm", ".ini", ".cfg", ".conf",
    ".env", ".properties", ".toml",
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".java", ".kt", ".scala", ".go", ".rs", ".rb", ".php", ".pl",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".sql", ".graphql", ".proto", ".tf", ".hcl", ".dockerfile",
    ".vue", ".svelte", ".scss", ".sass", ".css", ".less",
})


def run(
    *,
    event: Event,
    text: str,
    matches: list[Match],
    source_label: str,
    llm_entities: Iterable | None = None,
    entity_map: EntityMap | None = None,
) -> ActionOutcome:
    """根据 event 类型分发。

    llm_entities + entity_map 由 input_scanner 提供；为 None 时退回纯 L1 替换。
    """
    if event.is_pretool and event.tool_name == "Read":
        return _run_read(
            event=event, text=text, source_label=source_label,
            llm_entities=llm_entities, entity_map=entity_map,
        )

    if event.is_userprompt:
        return _run_userprompt(
            text=text, source_label=source_label,
            llm_entities=llm_entities, entity_map=entity_map,
        )

    # Grep / WebFetch / 其他：无副本通道 → 退化为 block
    return _degrade_block(matches=matches, source_label=source_label, reason="no_redirect_channel")


def _desensitize(
    text: str,
    llm_entities: Iterable | None,
    entity_map: EntityMap | None,
) -> tuple[str, dict[str, int]]:
    """统一脱敏入口：有 entity_map → L1+L2 合并；否则退回纯 L1 redact()。"""
    if entity_map is None:
        return redact(text)
    l1_spans = collect_l1_spans(text)
    return pseudonymize(
        text=text,
        l1_spans=l1_spans,
        llm_entities=llm_entities or (),
        entity_map=entity_map,
    )


def _run_read(
    *, event: Event, text: str, source_label: str,
    llm_entities: Iterable | None, entity_map: EntityMap | None,
) -> ActionOutcome:
    original_path = Path(event.file_path)
    ext = original_path.suffix.lower()

    if ext == ".docx":
        return _run_read_docx(
            event=event, original_path=original_path,
            llm_entities=llm_entities, entity_map=entity_map,
        )

    # .pdf 抽出来已经是纯文本：副本写成 .txt，让 Claude 走文本路径读副本，
    # 不是再当 PDF 解析（避免副本写成 .pdf 又被 Read 当二进制处理）。
    copy_ext_override: str | None = ".txt" if ext == ".pdf" else None

    if ext != ".pdf" and ext not in _T1_EXTS:
        return _degrade_block(
            matches=[], source_label=source_label,
            reason=f"unsupported_redact_ext:{ext}",
        )

    redacted, counts = _desensitize(text, llm_entities, entity_map)
    copy_path = _resolve_copy_path(
        event.session_id, original_path, redacted, ext_override=copy_ext_override,
    )
    _atomic_write_text(copy_path, redacted)

    exit_code = respond_redirect(str(copy_path), str(original_path))

    return ActionOutcome(
        exit_code=exit_code,
        audit={
            "redirect_path": str(copy_path),
            "redacted_counts": counts,
            **({"source_ext": ext, "copy_ext": copy_ext_override} if copy_ext_override else {}),
        },
    )


def _run_read_docx(
    *, event: Event, original_path: Path,
    llm_entities: Iterable | None, entity_map: EntityMap | None,
) -> ActionOutcome:
    """DOCX 分支：段级闭包脱敏 + 渲染成 markdown 副本。

    闭包共享 entity_map，保证占位符在跨段、跨表格 cell 内一致。
    全局 llm_entities 的 (start, end) 是相对"全文 join 后"的偏移，
    放进段文本里会越界 → 改用 text.find(ent.text) 在段内重新定位。

    与 PDF → .txt 同策略：Claude Code 的 Read 拒读 .docx 二进制，所以直接输出 .md。
    """
    llm_list = list(llm_entities or ())

    def desensitize_paragraph(para_text: str) -> tuple[str, dict[str, int]]:
        if entity_map is None:
            return redact(para_text)
        l1_spans = collect_l1_spans(para_text)
        local_ents = _relocate_llm_entities(para_text, llm_list)
        return pseudonymize(
            text=para_text,
            l1_spans=l1_spans,
            llm_entities=local_ents,
            entity_map=entity_map,
        )

    sha = _file_sha(original_path)
    md_path = _build_copy_path(event.session_id, original_path, sha, ext_override=".md")

    counts = docx_writer.write_redacted_md(
        original_path=original_path,
        md_path=md_path,
        desensitize=desensitize_paragraph,
    )

    exit_code = respond_redirect(str(md_path), str(original_path))
    return ActionOutcome(
        exit_code=exit_code,
        audit={
            "redirect_path": str(md_path),
            "redacted_counts": counts,
            "source_ext": ".docx",
            "copy_ext": ".md",
        },
    )


@dataclass(frozen=True)
class _LocalEntity:
    """段内重定位后的 LLM 实体，duck-type LLMEntity 用于喂给 pseudonymize。"""
    text: str
    type: str
    start: int
    end: int


def _relocate_llm_entities(para_text: str, llm_entities: Iterable) -> list[_LocalEntity]:
    """把全局 llm_entities 用 str.find 重新映射到 para_text 局部偏移。

    同一段里同字面可能出现多次（例如 "[公司A] 与 [公司A]" 这种），全部命中都收。
    type 取首个匹配实体的 type，避免重复 entity_map.assign 时分配不一致占位符。
    """
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
            idx = pos + len(ent.text)  # 不重叠扫描
    return out


def _run_userprompt(
    *, text: str, source_label: str,
    llm_entities: Iterable | None, entity_map: EntityMap | None,
) -> ActionOutcome:
    """UPS：弹系统确认框让用户决定放行还是阻断。

    走 confirm 是因为 VSCode 扩展不渲染 hook stderr / systemMessage（上游 bug，
    详见 lib.response 模块 docstring）；MessageBox 是系统级前台窗口，不受任何
    通知策略影响，且天然阻塞匹配 hook 同步语义。confirm 内部 fail-closed：
    超时 / 异常 / 非 Windows → 视为拒绝，走 block 路径。
    """
    redacted, counts = _desensitize(text, llm_entities, entity_map)
    cls_summary = ", ".join(f"{k}×{v}" for k, v in sorted(counts.items())) or "(无具体类目)"

    confirm_start = time.monotonic()
    approved = confirm("Claude Code 安全检查 — 检测到敏感信息",
                       _build_confirm_body(text, redacted, cls_summary))
    decision_latency_ms = int((time.monotonic() - confirm_start) * 1000)

    if approved:
        # 用户明确放行：放行原 prompt，但 audit 留痕。stderr 也写一条便于 CLI 看到。
        sys.stderr.write(f"[安全检查] 用户已确认放行（命中：{cls_summary}）\n")
        return ActionOutcome(
            exit_code=respond_pass(),
            audit={
                "block_reason": "user_approved",
                "redacted_counts": counts,
                "cls_summary": cls_summary,
                "decision_latency_ms": decision_latency_ms,
                "prompt_text": text,
            },
        )

    # 用户拒绝 / 超时 / 异常 → 阻断，stderr 给出脱敏建议（CLI 下可见）
    msg_lines = [
        f"输入命中敏感内容已阻断（命中类目：{cls_summary}）。",
        "建议改写为：",
        redacted[:2000],
    ]
    return ActionOutcome(
        exit_code=respond_userprompt_block("\n".join(msg_lines)),
        audit={
            "block_reason": "user_blocked",
            "redacted_counts": counts,
            "cls_summary": cls_summary,
            "decision_latency_ms": decision_latency_ms,
            "prompt_text": text,
        },
    )


# MessageBox 文本上限约 2KB,各段都做截断,留余量给固定模板
_CONFIRM_TEXT_LIMIT = 600


def _build_confirm_body(original: str, redacted: str, cls_summary: str) -> str:
    """拼弹框正文：命中类目 + 原文片段 + 脱敏建议 + 操作提示。"""
    return (
        "检测到你即将提交的输入含有以下敏感内容：\n\n"
        f"【命中类目】{cls_summary}\n\n"
        f"【原文】\n{_clip(original, _CONFIRM_TEXT_LIMIT)}\n\n"
        f"【建议改写为】\n{_clip(redacted, _CONFIRM_TEXT_LIMIT)}\n\n"
        "是否仍要原样提交？\n"
        "  是 = 原样提交（注意：可能泄露敏感信息）\n"
        "  否 = 取消提交，请手动修改后重试"
    )


def _clip(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def _degrade_block(
    *,
    matches: list[Match],
    source_label: str,
    reason: str,
    extra_hint: str = "",
) -> ActionOutcome:
    hit_classes = sorted({m.data_class for m in matches})
    summary = ", ".join(hit_classes) if hit_classes else "(无具体类目)"

    lines = [
        f"输入命中敏感内容，无法自动脱敏（{reason}），已阻断。",
        f"命中类目：{summary}。",
        f"来源：{source_label or '(unknown)'}",
    ]
    if extra_hint:
        lines.append(extra_hint)
    exit_code = respond_block("\n".join(lines))

    return ActionOutcome(
        exit_code=exit_code,
        audit={
            "block_reason": reason,
            "block_classes": hit_classes,
        },
    )


def _resolve_copy_path(
    session_id: str,
    original_path: Path,
    redacted_text: str,
    *,
    ext_override: str | None = None,
) -> Path:
    """文本副本路径：sha 用脱敏后文本算。

    ext_override 用于 .pdf → .txt 这种"源扩展名 ≠ 副本扩展名"的场景。
    """
    digest = hashlib.sha256(redacted_text.encode("utf-8", errors="replace")).hexdigest()[:12]
    return _build_copy_path(session_id, original_path, digest, ext_override=ext_override)


def _build_copy_path(
    session_id: str,
    original_path: Path,
    digest: str,
    *,
    ext_override: str | None = None,
) -> Path:
    """副本路径 = {temp_desensitized}/{session_id}/{stem}_{digest}{副本扩展名}"""
    safe_session = _sanitize(session_id)
    base = paths.temp_desensitized / safe_session
    base.mkdir(parents=True, exist_ok=True)
    suffix = ext_override if ext_override is not None else (original_path.suffix or ".txt")
    name = f"{original_path.stem}_{digest}{suffix}"
    return base / name


def _atomic_write_text(copy_path: Path, content: str) -> None:
    tmp = copy_path.with_suffix(copy_path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8", errors="replace")
    tmp.replace(copy_path)


def _file_sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:12]


_SAFE_RE = re.compile(r"[^A-Za-z0-9_\-]")


def _sanitize(value: str) -> str:
    return (_SAFE_RE.sub("_", value or "")[:80]) or "unknown"
