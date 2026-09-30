"""输入安全控制 Hook 入口。

由 Claude Code 在 PreToolUse / UserPromptSubmit 时调用，
通过 stdin 接收事件 JSON，输出决策（exit code + stderr）。

管线（v2，已去掉评分）：
  extract → cache lookup → detect → action

  - 无命中 → respond_pass
  - 有命中 → desensitize_action（Read 改读副本 / UPS 给出脱敏建议 / 不支持格式降级阻断）

所有异常 fail-closed 阻断。
"""
from __future__ import annotations

import hashlib
import sys
import time
import traceback
from pathlib import Path

# Windows 下 Python 默认 stdin/stdout/stderr 编码可能是 GBK。
try:
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # pragma: no cover
    pass

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

# fail-closed: 任何初始化异常都阻断
try:
    import argparse

    from actions.dispatcher import execute as run_action
    from cache.entity_map import EntityMap
    from cache.session_cache import SessionCache, build_cache_key
    from config.llm import llm_config
    from config.paths import paths
    from config.rules import rules
    from config.wordlib import wordlib
    from detectors.dispatcher import detect_all
    from detectors.llm_detector import LLMEntity
    from extractors.dispatcher import extract as extract_from_event
    from lib import bash_guard, injection_guard, write_guard
    from lib import confirm
    from lib.event import Event
    from lib.logger import log
    from lib.response import respond_block, respond_pass
    from lib.types import Match
except Exception:  # pragma: no cover
    # 初始化失败时必须把完整 traceback 打到 stderr,否则用户只能看到
    # "安全中间件初始化失败"这句固定文案,完全无法定位问题。
    # (很多人反馈"日志传不上来",根因就是这里静默吞了异常)
    import traceback as _tb
    sys.stderr.write(
        "安全中间件初始化失败，操作已阻断\n"
        "===== TRACEBACK =====\n"
        + _tb.format_exc()
        + "=====================\n"
    )
    sys.stderr.flush()
    sys.exit(2)


SUPPORTED_EVENTS = ("PreToolUse", "UserPromptSubmit")
_STAGE = "step4_e2e"


def _notify_async(title: str, body: str) -> None:
    """后台线程弹通知框,主线程立刻返回去 respond_block(exit 2)。

    confirm.notify 是阻塞式 Tk 对话框,若在 PreToolUse 主线程直接调,会把 hook
    卡到用户点确定(或 15s 超时)才返回 exit 2 —— 期间 Claude Code 一直没收到阻断,
    表现为"弹窗了但没阻断、还在继续读"。后台弹窗让阻断即时生效。
    best-effort:线程起不来也不影响阻断。
    """
    try:
        import threading
        threading.Thread(target=confirm.notify, args=(title, body), daemon=True).start()
    except Exception:
        pass

# 抽取被 skip 时，下面这些原因走 fail-closed 阻断（而非默认放行）。
# 之所以特别处理：Claude Code 的 Read 工具在 .pdf 这类"白名单二进制"上仍会把文件
# 内容塞给模型；如果我们这边因缺库或扫描件抽不出文本而放行，敏感数据就直接外泄。
_BLOCK_ON_SKIP = frozenset({
    "pdf_no_text_layer",     # 扫描件：无文本层；OCR 留给目标六
    "pdf_lib_missing",       # pdfplumber 没装
    "docx_lib_missing",      # python-docx 没装
    "outside_allowed_dirs",  # 文件在受控目录和允许读取目录之外
})

# Office 三件套 Read 必须走对应 skill,不能进 input_scanner 的 extract+L2 链路。
# 原因:9MB 真实 .docx 走 python-docx 抽 293k 字符 + 22 chunk LLM 实测 422s,
# Claude Code hook 超时是 fail-OPEN(超时即放行,见 hooks 文档 / heyuan110.com /
# morphllm.com 三处独立来源),所以这条路径必须毫秒级阻断,把 Claude 推回 skill 路径。
# skill 路径走轻量 PII 抽取 + 副本写盘,不发整文给 LLM,实际秒级完成。
#
# value 是 skill 名;脚本绝对路径放在 SKILL.md 内部,不在提示语里暴露
# (硬编码 username/绝对路径换机器就坏,且扩大攻击面)。
_OFFICE_SKILL_REDIRECT = {
    ".docx": "docx",
    ".xlsx": "xlsx-redact",
    ".pptx": "pptx-redact",
}


# 没有对应脱敏 skill 的"伪文本/办公"二进制格式。
# 这些扩展走 extract → unsupported_format_v1 → pass(放行)是漏洞:
# .rtf 是文本骨架可能被 Claude Code 当文本读;.odt/.odp/.ods/.pages/.key/.numbers
# 是 zip 容器,与 docx 同源风险;.doc/.ppt/.xls/.xlsb 是 legacy office 二进制。
# 一律 fail-CLOSED 阻断 + 给出转换建议,引导走已有的脱敏 skill。
_BINARY_FILE_BLOCK = {
    ".doc":     ("Word 97-2003 二进制(.doc)",       "请在 Word 中另存为 .docx 后重试,或先转为 PDF。"),
    ".ppt":     ("PowerPoint 97-2003 二进制(.ppt)", "请在 PowerPoint 中另存为 .pptx 后重试。"),
    ".xls":     ("Excel 97-2003 二进制(.xls)",      "请在 Excel 中另存为 .xlsx 后重试。"),
    ".xlsb":    ("Excel 二进制工作簿(.xlsb)",       "请在 Excel 中另存为 .xlsx 后重试。"),
    ".rtf":     ("RTF 富文本",                       "请在 Word 中另存为 .docx 后重试,或转为 .txt/.md。"),
    ".odt":     ("OpenDocument 文本(.odt)",         "请用 LibreOffice/Word 另存为 .docx 后重试。"),
    ".odp":     ("OpenDocument 演示(.odp)",         "请用 LibreOffice/PowerPoint 另存为 .pptx 后重试。"),
    ".ods":     ("OpenDocument 表格(.ods)",         "请用 LibreOffice/Excel 另存为 .xlsx 后重试。"),
    ".pages":   ("Apple Pages",                      "请在 Pages 中导出为 .docx 或 PDF 后重试。"),
    ".key":     ("Apple Keynote",                    "请在 Keynote 中导出为 .pptx 或 PDF 后重试。"),
    ".numbers": ("Apple Numbers",                    "请在 Numbers 中导出为 .xlsx 后重试。"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Claude 输入安全控制 Hook")
    parser.add_argument(
        "--event",
        required=True,
        choices=SUPPORTED_EVENTS,
        help="Hook 事件类型",
    )
    return parser.parse_args()


def _matches_to_log(matches: list[Match]) -> list[dict]:
    return [
        {"class": m.data_class, "count": m.count, "samples": list(m.samples)}
        for m in matches
    ]



def _extract_write_content(tool_name, tool_input):
    """从 Write/Edit/MultiEdit/NotebookEdit 的 tool_input 抽出待落盘文本。

    抽不出来即返回空串,fail-OPEN 不阻断 Claude(留给 PostToolUse 兜底)。
    """
    try:
        if tool_name == "Write":
            return str(tool_input.get("content") or "")
        if tool_name == "Edit":
            return str(tool_input.get("new_string") or "")
        if tool_name == "MultiEdit":
            edits = tool_input.get("edits") or []
            parts = []
            for e in edits:
                if not isinstance(e, dict):
                    continue
                ns = e.get("new_string")
                if ns:
                    parts.append(str(ns))
            return chr(10).join(parts)
        if tool_name == "NotebookEdit":
            return str(tool_input.get("new_source") or "")
    except Exception:
        return ""
    return ""


def _build_strong_block_msg(tool_name, file_path, matches):
    """阻断时的中文说明:文件 + 命中类别 + 行动建议。"""
    lines = [
        f"⛔ 已阻断 {tool_name} 写入 {file_path}",
        "原因:检出强凭证字面量(STRONG 子集),不允许落盘到代码:",
    ]
    for m in matches:
        samples = ", ".join(m.samples[:3]) if m.samples else "(无样例)"
        lines.append(f"  - {m.data_class}: {m.count} 处  样例: {samples}")
    lines.append("")
    lines.append("行动建议:")
    lines.append("  1. 从代码中删除该字面量")
    lines.append("  2. 改为从环境变量 / Secret Manager 读取(如 os.getenv)")
    lines.append("  3. 若该凭证已暴露到 Git/远端,立即在控制台撤销/轮换")
    lines.append("")
    lines.append("说明:中低风险(Bearer/JWT/password=/DB 连接串)不在此阻断,")
    lines.append("会在文件落盘后由 PostToolUse 弹框警告。")
    return chr(10).join(lines)


def _scan_and_act(event: Event, cache: SessionCache) -> tuple[int, dict]:
    """主流程：extract → cache → detect → action。

    返回 (exit_code, log_payload)。
    """
    # UserPromptSubmit 注入硬阻断:覆盖系统指令 / 提取系统提示词 / 角色越狱模板
    # 命中即阻断,不进 extract/detect 管线（这些是已知攻击模板,正则零延迟,
    # 不能让长 payload 触发 LLM 调用消耗 30s 预算）
    if event.is_userprompt:
        # extract 已经 normalize,但 prompt 还没;先就地 normalize 再匹配,
        # 避免攻击者用零宽/全角让正则失配
        from extractors.normalize import normalize as _ups_normalize
        norm_prompt = _ups_normalize(event.prompt).text
        block = injection_guard.check(norm_prompt)
        if block is not None:
            # VSCode Claude 扩展不渲染 hook stderr,用户直接 exit 2 看不到任何提示。
            # 后台弹框告诉用户"为什么"被阻断;主线程立刻 exit 2,不卡 hook。
            _notify_async(
                "Claude 输入安全 — 提示词注入已阻断",
                block.user_message,
            )
            return respond_block(block.user_message), {
                "phase": "injection_blocked",
                "rule": block.rule,
                "matched": list(block.matched),
                "source_label": "prompt",
                "prompt_text": event.prompt[:500],
            }

    # 递归短路：Claude 改读副本 .docx/.md 时不再触发抽取/检测，避免重复 LLM 调用
    if event.is_pretool and event.tool_name == "Read" and event.file_path:
        if paths.is_within_desensitized_dir(event.file_path):
            return respond_pass(), {
                "phase": "recursion_skipped",
                "reason": "desensitized_copy_reread",
                "source_label": f"file:{event.file_path}",
            }

    # 列目录 / 搜索类工具的目标路径白名单拦截:Glob / LS / Grep。
    # 这些工具会暴露受控目录外的文件名清单(本身即敏感),且之前不在 matcher 里完全没拦。
    # 只拦"显式指定了白名单外 path"的调用;不带 path 时 Claude 是在看当前工作目录
    # (cwd),那是正常行为 —— 用 cwd 兜底判定会把"cwd 不在受控目录的正常会话"误伤
    # (新开对话 Claude 初始化探查当前目录就被拦),所以不带 path 一律放行。
    if event.is_pretool and event.tool_name in ("Glob", "LS", "Grep"):
        raw_path = str(event.tool_input.get("path", "") or "").strip()
        if raw_path and not paths.is_within_read_whitelist(raw_path):
            tool = event.tool_name
            block_msg = (
                f"{tool} 被阻断：目标路径不在允许访问的目录内\n"
                f"路径：{raw_path}\n"
                f"\n"
                f"允许访问的目录：\n"
                f"  - {paths.controlled_workdir}（受控工作目录）\n"
                f"  - D:\\After-tuomin（脱敏输出目录）\n"
                f"\n"
                f"列目录/搜索受控目录外的路径会暴露敏感文件名清单。"
                f"请只在受控目录内操作。"
            )
            _notify_async(f"Claude 输入安全 — {tool} 路径不在允许目录内", block_msg)
            return respond_block(block_msg), {
                "phase": "path_blocked",
                "tool": tool,
                "blocked_path": raw_path,
                "source_label": f"{tool.lower()}:{raw_path}",
            }

    # Bash 硬阻断：office 抽取绕过 / 凭据外发等规则化高危命令模式
    # 命中即阻断,不进 extract/detect 管线（这些模式靠规则就能判定,无需 LLM NER）
    if event.is_pretool and event.tool_name == "Bash":
        command = event.tool_input.get("command", "") or ""
        block = bash_guard.check(command, cwd=event.cwd)
        if block is not None:
            return respond_block(block.user_message), {
                "phase": "bash_blocked",
                "rule": block.rule,
                "source_label": "bash:command",
                # 命令字符串可能很长,审计只截前 500 字符避免日志爆炸
                "command_sample": command[:500],
            }

    # Write/Edit/MultiEdit/NotebookEdit 写入侧硬阻断：路径白名单 + 副本只读 + 强凭证内容预扫
    # 流程:
    #   1) write_guard(路径白名单)— 路径外直接 exit 2
    #   2) Step 3 内容预扫 — 抽 content / new_string / new_source 跑 detect_strong,
    #      命中 STRONG(AKIA/ASIA/AIza/ghp_/gho_/sk-/xox/PEM)即 fail-CLOSED 阻断,
    #      代码根本不落盘。中低风险(Bearer/JWT/password=/DB 串)继续放行,
    #      由 PostToolUse(scripts/output/output_scanner.py)弹框警告兜底。
    #   3) 都过则 respond_pass — 内容外不外泄,且大概率是脚本/配置,
    #      送 LLM NER 会产生大量类名/路径误报。
    if event.is_pretool and event.tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        wblock = write_guard.check(event.tool_name, event.file_path)
        if wblock is not None:
            return respond_block(wblock.user_message), {
                "phase": "write_blocked",
                "rule": wblock.rule,
                "source_label": f"{event.tool_name.lower()}:{event.file_path}",
            }

        # Step 3:STRONG 凭证内容预扫,命中即 exit 2 阻断
        # Step 4:先跑 normalize 无害化(base64/URL/零宽/NFKC),detect_strong 消费归一化后文本;
        # 覆盖 AKIA%49OSF... / base64 编码后落盘 / AK<ZWSP>IA 拆词等旁路。
        from detectors.credential_detector import detect_strong as _detect_strong
        from extractors.normalize import normalize as _write_normalize
        content = _extract_write_content(event.tool_name, event.tool_input)
        if content:
            normalized = _write_normalize(content).text
            strong_matches = _detect_strong(normalized)
            if strong_matches:
                msg = _build_strong_block_msg(event.tool_name, event.file_path, strong_matches)
                # VSCode 扩展不渲染 PostToolUse stderr,后台弹框告知用户为什么阻断;
                # 主线程立刻 exit 2,不卡 hook。
                _notify_async("Claude 输出 — 强凭证写入已阻断", msg)
                return respond_block(msg), {
                    "phase": "write_strong_blocked",
                    "tool": event.tool_name,
                    "file_path": event.file_path,
                    "matches": _matches_to_log(strong_matches),
                    "source_label": f"{event.tool_name.lower()}:{event.file_path}",
                }

        return respond_pass(), {
            "phase": "write_passed",
            "tool": event.tool_name,
            "source_label": f"{event.tool_name.lower()}:{event.file_path}",
        }

    # Office 三件套 Read 硬阻断:走对应 skill,不进 extract+L2 链路。
    # 详见模块顶部 _OFFICE_SKILL_REDIRECT 注释。
    if event.is_pretool and event.tool_name == "Read" and event.file_path:
        ext = Path(event.file_path).suffix.lower()
        skill_name = _OFFICE_SKILL_REDIRECT.get(ext)
        if skill_name is not None:
            msg = (
                f"原文件 {event.file_path} 是 {ext} 二进制,不能直接 Read。\n"
                f"请通过 Skill 工具调用 `{skill_name}` skill 处理 —— skill 内部会:\n"
                f"  1. 自动调脱敏脚本,输出脱敏后的 .md 副本路径\n"
                f"  2. 提供操作流程说明(见 SKILL.md)\n"
                f"通常 30-90 秒完成;若 Bash 超 120s 自然 timeout,直接重新 invoke 即可,\n"
                f"**不要给 Bash 加 `timeout` 参数延长**(会绕过保护)——脚本已内置一次\n"
                f"重试,LLM 仍失败会弹 MessageBox 让你确认是否接受 L1-only 输出。\n"
                f"所有后续操作请基于 .md 副本,不要再读原 {ext}。"
            )
            return respond_block(msg), {
                "phase": "office_short_circuit",
                "extension": ext,
                "skill": skill_name,
                "source_label": f"file:{event.file_path}",
            }

    # 伪文本/办公二进制 fail-CLOSED 阻断(没对应 skill,走转换建议)。
    # 详见模块顶部 _BINARY_FILE_BLOCK 注释。
    if event.is_pretool and event.tool_name == "Read" and event.file_path:
        ext = Path(event.file_path).suffix.lower()
        binary = _BINARY_FILE_BLOCK.get(ext)
        if binary is not None:
            kind, suggestion = binary
            msg = (
                f"原文件 {event.file_path} 是 {kind},当前无对应脱敏 skill,已阻断。\n"
                f"原因:这类格式可能含敏感数据,且现有 skill 不覆盖。\n"
                f"建议:{suggestion}\n"
                f"转换后用 Read 触发对应 skill(docx/pptx-redact/xlsx-redact)或 PDF 抽取链路。"
            )
            return respond_block(msg), {
                "phase": "binary_format_blocked",
                "extension": ext,
                "kind": kind,
                "source_label": f"file:{event.file_path}",
            }

    extract = extract_from_event(event)

    if extract.is_skipped:
        if extract.skipped_reason in _BLOCK_ON_SKIP:
            # 文件在受控目录和允许读取目录之外 → 阻断 + 弹窗提示
            if extract.skipped_reason == "outside_allowed_dirs":
                block_msg = (
                    f"Read 被阻断：文件不在允许读取的目录内\n"
                    f"文件：{extract.source_label or '(unknown)'}\n"
                    f"\n"
                    f"允许读取的目录：\n"
                    f"  - {paths.controlled_workdir}（受控工作目录，读取时自动脱敏）\n"
                    f"  - D:\\After-tuomin（脱敏输出目录）\n"
                    f"\n"
                    f"请将文件移动到 {paths.controlled_workdir}\\projects\\ 下后再读取。"
                )
                # 弹窗与阻断并行:notify 是阻塞式 Tk 对话框,放主线程会卡住 hook
                # 直至用户点确定(或 15s 超时),期间 Claude Code 看不到 exit 2,
                # 表现为"弹窗了但没阻断、还在读"。改成后台线程弹窗,主线程立刻
                # respond_block 返回 exit 2。best-effort:线程起不来也不影响阻断。
                _notify_async("Claude 输入安全 — 文件路径不在允许目录内", block_msg)
                return respond_block(block_msg), {
                    "phase": "extract_blocked",
                    "skipped_reason": extract.skipped_reason,
                    "source_label": extract.source_label,
                }
            # fail-closed：能读到原文件、又抽不出脱敏需要的文本 → 阻断
            block_msg = (
                f"输入命中无法脱敏的文件类型（{extract.skipped_reason}），已阻断。\n"
                f"来源：{extract.source_label or '(unknown)'}"
            )
            return respond_block(block_msg), {
                "phase": "extract_blocked",
                "skipped_reason": extract.skipped_reason,
                "source_label": extract.source_label,
            }
        # 不支持的工具 / 路径外 / 二进制类型：放行（matcher 把关 + Claude 客户端会自己拒）
        return respond_pass(), {
            "phase": "extract_skipped",
            "skipped_reason": extract.skipped_reason,
            "source_label": extract.source_label,
        }

    # 缓存查询（content + rules.version + wordlib.version + llm.version + mode）
    content_sha = hashlib.sha256(extract.text.encode("utf-8", errors="replace")).hexdigest()
    # mode 必须编入键:UPS 走 mode=ups 启用 PASSWORD,与 default 的 L2 结果不一致;
    # 不编入则同 session 同 prompt 先 Read 后 UPS,后者会命中 default 缓存 → PASSWORD 漏检
    cache_mode = "ups" if event.is_userprompt else "default"
    cache_key = build_cache_key(
        content_sha,
        rules.version,
        wordlib.version,
        llm_version=llm_config.version,
        mode=cache_mode,
    )
    cached = cache.get_scan(cache_key)

    llm_entities: list = []
    write_cache = False
    if cached:
        matches: list[Match] = cached["matches"]
        ran_detectors: list[str] = cached["ran_detectors"]
        llm_entities = list(cached.get("llm_entities", []))
        llm_status: dict = cached.get("llm_status", {"ok": True, "skipped": True, "reason": "cached"})
        cache_hit = True
    else:
        # Grep / WebFetch 扫描的是 URL/模式串而非 prose，跳过 LLM 减少误报与延迟
        with_llm = not (event.is_pretool and event.tool_name in ("Grep", "WebFetch"))
        # UPS 走 mode=ups，启用 PASSWORD 等针对自然语言对话的扩展类目
        llm_mode = "ups" if event.is_userprompt else "default"
        agg = detect_all(extract.text, with_llm=with_llm, mode=llm_mode)
        matches = list(agg.matches)
        ran_detectors = list(agg.ran_detectors)
        llm_entities = list(agg.llm_result.entities) if agg.llm_result else []
        if agg.llm_result is None:
            llm_status = {
                "ok": True,
                "skipped": True,
                "reason": "disabled" if with_llm else "non_prose_input",
                "latency_ms": 0,
                "entity_count": 0,
            }
            write_cache = True
        else:
            llm_status = {
                "ok": agg.llm_result.ok,
                "skipped": False,
                "latency_ms": agg.llm_result.latency_ms,
                "error": agg.llm_result.error,
                "entity_count": len(agg.llm_result.entities),
            }
            # L2 失败不缓存（让下次重试）；L2 成功则缓存
            write_cache = agg.llm_result.ok
        cache_hit = False

    # 实体一致性字典（每次都从 cache 重建，session 内复用）
    entity_map = EntityMap(cache)

    outcome = run_action(
        event=event,
        text=extract.text,
        matches=matches,
        source_label=extract.source_label,
        llm_entities=[ent for ent in llm_entities if isinstance(ent, LLMEntity)],
        entity_map=entity_map,
    )

    # 缓存写入：仅缓存 detect 结果，不缓存 action
    if write_cache:
        cache.put_scan(cache_key, {
            "matches": matches,
            "ran_detectors": ran_detectors,
            "llm_entities": llm_entities,
            "llm_status": {**llm_status},
        })
    cache.save()

    payload = {
        "phase": "scanned",
        "source_label": extract.source_label,
        "truncated": extract.truncated,
        "rules_version": rules.version,
        "wordlib_version": wordlib.version,
        "llm_version": llm_config.version,
        "cache_hit": cache_hit,
        "ran_detectors": ran_detectors,
        "matches": _matches_to_log(matches),
        "llm": {
            **llm_status,
            "entity_count_used": len([e for e in llm_entities if isinstance(e, LLMEntity)]),
        },
        "entity_map_snapshot": entity_map.snapshot() if llm_entities else {},
        **outcome.audit,
    }
    return outcome.exit_code, payload


def handle_pretool(event: Event, cache: SessionCache) -> int:
    code, payload = _scan_and_act(event, cache)
    log({
        "stage": _STAGE,
        "event": "PreToolUse",
        "session_id": event.session_id,
        "tool": event.tool_name,
        "tool_input": event.tool_input,
        **payload,
    })
    return code


def handle_userprompt(event: Event, cache: SessionCache) -> int:
    code, payload = _scan_and_act(event, cache)
    log({
        "stage": _STAGE,
        "event": "UserPromptSubmit",
        "session_id": event.session_id,
        "prompt_len": len(event.prompt),
        "prompt_text": event.prompt[:500],
        **payload,
    })
    return code


_HANDLERS = {
    "PreToolUse": handle_pretool,
    "UserPromptSubmit": handle_userprompt,
}


def main() -> int:
    start = time.time()
    session_id = ""

    try:
        args = parse_args()
        event = Event.from_stdin()
        session_id = event.session_id

        # ---- 强制更新闸门(fail-OPEN) ----
        gate_reason = None
        try:
            from lib import update_gate
            gate_reason = update_gate.force_update_block_reason()
        except Exception:
            gate_reason = None  # fail-open

        if gate_reason is not None:
            # 先记录日志
            try:
                log({
                    "stage": _STAGE,
                    "event": "force_update_block",
                    "session_id": session_id,
                })
            except Exception:
                pass
            # 先阻断（exit 2），再弹窗通知（非阻塞）
            if args.event == "UserPromptSubmit":
                from lib.response import respond_userprompt_block
                try:
                    update_gate.notify_once(gate_reason)
                except Exception:
                    pass
                return respond_userprompt_block(gate_reason)
            try:
                update_gate.notify_once(gate_reason)
            except Exception:
                pass
            return respond_block(gate_reason)

        handler = _HANDLERS.get(args.event)
        if handler is None:
            return respond_block(f"未知 Hook 事件: {args.event}")

        cache = SessionCache(session_id)
        code = handler(event, cache)

        log({
            "stage": _STAGE,
            "event": "scanner_exit",
            "session_id": session_id,
            "duration_ms": int((time.time() - start) * 1000),
            "exit_code": code,
        })
        return code

    except SystemExit:
        raise
    except Exception as exc:
        # 运行时异常:尽量写日志,log() 失败也要把 traceback 打到 stderr。
        # 之前这里只返回固定文案"安全中间件异常,操作已阻断",完全不暴露根因,
        # 导致大量"日志传不上来"的问题无法定位。
        tb_str = traceback.format_exc()
        try:
            log({
                "stage": _STAGE,
                "event": "scanner_failure",
                "session_id": session_id,
                "error": str(exc),
                "traceback": tb_str,
                "duration_ms": int((time.time() - start) * 1000),
            })
        except Exception as log_exc:
            # log() 本身失败(如日志目录不存在/磁盘满),必须把根因打到 stderr
            sys.stderr.write(
                "===== SCANNER EXCEPTION (log() failed) =====\n"
                f"log_error: {log_exc}\n"
                f"original_error: {exc}\n"
                + tb_str
                + "============================================\n"
            )
            sys.stderr.flush()
        return respond_block(f"安全中间件异常，操作已阻断\n{tb_str}")


if __name__ == "__main__":
    sys.exit(main())
