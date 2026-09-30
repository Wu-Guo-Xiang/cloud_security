"""L2 LLM NER：基于 DeepSeek 兼容 API 做命名实体识别。

任何故障 → ok=False + error 描述。调用方应回退到纯 L1。

长文档处理（v2）：
  - max_input_chars 改成"单 chunk 上限"而非"总截断点"
  - 文档按 \\n\\n 块边界（段落/表格 block）切分，绝不切到 block 内部
  - 多 chunk 并发调 LLM，entities 在原文重新定位（_calibrate_entities 已有逻辑）
  - 任一 chunk 成功即视为 ok=True（best-effort），全失败才返回 ok=False
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from llm_config import llm_config
from llm_client import chat_json
from match import Match


@dataclass(frozen=True)
class LLMEntity:
    text: str
    type: str
    start: int
    end: int


@dataclass(frozen=True)
class LLMDetectResult:
    ok: bool
    entities: tuple[LLMEntity, ...] = ()
    matches: tuple[Match, ...] = ()
    latency_ms: int = 0
    error: str = ""
    raw_response: str = ""


def detect(text: str) -> LLMDetectResult:
    if not text:
        return LLMDetectResult(ok=True)

    if not llm_config.is_runnable:
        return LLMDetectResult(ok=False, error="llm_disabled")

    chunks = _split_into_chunks(
        text,
        max_input_chars=llm_config.call.max_input_chars,
        max_chunks=llm_config.call.max_chunks,
    )

    responses = _call_llm_parallel(chunks, concurrency=llm_config.call.concurrency)

    seen_pairs: set[tuple[str, str]] = set()
    merged_items: list[dict] = []
    total_latency = 0
    success_count = 0
    last_error = ""
    last_raw = ""
    for resp in responses:
        total_latency = max(total_latency, resp.latency_ms)
        if not resp.ok:
            last_error = resp.error
            last_raw = resp.raw_text
            continue
        success_count += 1
        last_raw = resp.raw_text
        for item in _extract_items(resp.parsed_json):
            key = (
                str(item.get("text", "")).strip(),
                str(item.get("type", "")).strip().upper(),
            )
            if not key[0] or key in seen_pairs:
                continue
            seen_pairs.add(key)
            merged_items.append(item)

    if success_count == 0:
        return LLMDetectResult(
            ok=False,
            latency_ms=total_latency,
            error=last_error or "all_chunks_failed",
            raw_response=last_raw,
        )

    entities = _calibrate_entities({"entities": merged_items}, text)
    matches = _entities_to_matches(entities)
    return LLMDetectResult(
        ok=True,
        entities=tuple(entities),
        matches=tuple(matches),
        latency_ms=total_latency,
        raw_response=last_raw,
    )


def _split_into_chunks(text: str, *, max_input_chars: int, max_chunks: int) -> list[str]:
    """按语义边界递降切分，保证每个 chunk ≤ max_input_chars。

    切分单位（递降优先级）：
      1. \\n\\n 块边界（段落 / 表格 / 章节）
      2. 单 block 超长 → 按 \\n 行边界（markdown 表格每行 `| col | col |` 是完整结构）
      3. 单行超长 → 按字符硬切（极端情况：压缩 JSON / base64 长串）
    最后把单元按顺序打包成 chunk（用 \\n\\n 衔接）。

    泛化性：对任意结构化文本（md / 纯文本 / 表格密集 / 长段落）都成立；
    不假设特定文档形态，不针对单文件做调参。
    超过 max_chunks 直接截断，防 token / 调用爆炸。
    """
    if not text:
        return []
    if len(text) <= max_input_chars:
        return [text]

    units = _split_to_units(text, max_input_chars)

    chunks: list[str] = []
    current: list[str] = []
    current_len = 0
    for unit in units:
        sep_len = 2 if current else 0
        projected = current_len + sep_len + len(unit)
        if current and projected > max_input_chars:
            chunks.append("\n\n".join(current))
            current = [unit]
            current_len = len(unit)
        else:
            current.append(unit)
            current_len = projected
    if current:
        chunks.append("\n\n".join(current))

    if len(chunks) > max_chunks:
        chunks = chunks[:max_chunks]
    return chunks


def _split_to_units(text: str, max_size: int) -> list[str]:
    """把 text 切成每段 ≤ max_size 的最小单元。

    递降：\\n\\n → \\n → 字符硬切。保证不破坏行结构（表格行不会切到一半）。
    """
    units: list[str] = []
    for block in text.split("\n\n"):
        if len(block) <= max_size:
            units.append(block)
            continue
        for line in block.split("\n"):
            if len(line) <= max_size:
                units.append(line)
                continue
            for i in range(0, len(line), max_size):
                units.append(line[i:i + max_size])
    return units


def _call_llm_parallel(chunks: list[str], *, concurrency: int):
    """串行 / 并发统一接口：单 chunk 直接同步；多 chunk 走线程池（I/O bound）。"""
    if not chunks:
        return []
    if len(chunks) == 1:
        return [_call_one(chunks[0])]
    workers = max(1, min(concurrency, len(chunks)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(_call_one, chunks))


def _call_one(chunk_text: str):
    messages = [
        {"role": "system", "content": llm_config.prompt.system},
        {"role": "user",   "content": llm_config.prompt.user_template.format(text=chunk_text)},
    ]
    return chat_json(messages)


def _allowed_types() -> set[str]:
    return {et.type for et in llm_config.entity_types}


def _extract_items(parsed: object) -> list[dict]:
    if isinstance(parsed, list):
        return [it for it in parsed if isinstance(it, dict)]
    if isinstance(parsed, dict):
        for key in ("entities", "data", "items"):
            v = parsed.get(key)
            if isinstance(v, list):
                return [it for it in v if isinstance(it, dict)]
    return []


def _calibrate_entities(parsed: object, original: str) -> list[LLMEntity]:
    allowed = _allowed_types()
    if not allowed:
        return []

    raw_items = _extract_items(parsed)
    seen: set[tuple[int, int]] = set()
    result: list[LLMEntity] = []

    for item in raw_items:
        ent_text = str(item.get("text", "")).strip()
        ent_type = str(item.get("type", "")).strip().upper()
        if not ent_text or ent_type not in allowed:
            continue

        idx = 0
        while True:
            pos = original.find(ent_text, idx)
            if pos < 0:
                break
            span = (pos, pos + len(ent_text))
            if span not in seen:
                seen.add(span)
                result.append(LLMEntity(text=ent_text, type=ent_type,
                                        start=span[0], end=span[1]))
            idx = pos + len(ent_text)

    result.sort(key=lambda e: (e.start, -e.end))
    return result


def _entities_to_matches(entities: list[LLMEntity]) -> list[Match]:
    by_type: dict[str, list[str]] = {}
    counts: dict[str, int] = {}
    for ent in entities:
        counts[ent.type] = counts.get(ent.type, 0) + 1
        samples = by_type.setdefault(ent.type, [])
        if len(samples) < 5:
            samples.append(_mask(ent.text))

    matches: list[Match] = []
    for type_, count in counts.items():
        matches.append(Match(
            data_class=type_.lower(),
            count=count,
            samples=tuple(by_type.get(type_, ())),
        ))
    return matches


def _mask(value: str) -> str:
    s = value.strip()
    if len(s) <= 2:
        return "**"
    if len(s) <= 4:
        return s[0] + "**" + s[-1]
    return f"{s[:2]}***{s[-1]}"
