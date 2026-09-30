"""L2 LLM 智能脱敏：基于 DeepSeek v4-flash 的命名实体识别。

与 L1 detector 的差别：
  - L1 输出 lib.types.Match（按 data_class 聚合的统计信息），供 scorer 累进评分
  - L2 输出 LLMEntity（每个实体的 span + text + type），供 pseudonymizer 做替换

  L2 命中也会以 Match(data_class=type.lower(), count=N) 的形式
  汇入 dispatcher 的 matches，参与评分；具体替换走独立的 entities 列表。

不依赖 L1，亦不阻塞 L1：LLM 不可用时返回空 entities + ok=False，
由调用方（dispatcher / desensitize_action）决定降级策略。

长文档处理（v2）：
  - max_input_chars 改成"单 chunk 上限"而非"总截断点"
  - 按 \\n\\n → \\n → 硬切 递降切分，不破坏 markdown 表格 / 段落语义
  - 多 chunk 并发调 LLM，entities 在原文重新定位（_calibrate_entities 已有）
  - 任一 chunk 成功即视为 ok=True（best-effort），全失败才返回 ok=False
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from config.llm import llm_config
from lib.llm_client import chat_json
from lib.types import Match


@dataclass(frozen=True)
class LLMEntity:
    """LLM 识别出的单个实体，已经过原文校准。"""
    text: str       # 原文片段
    type: str       # COMPANY / PERSON / PRODUCT / MONEY
    start: int      # 在原文中的字符索引（左闭）
    end: int        # 字符索引（右开）


@dataclass(frozen=True)
class LLMDetectResult:
    ok: bool                              # 是否成功调用并解析
    entities: tuple[LLMEntity, ...] = ()  # 校准后的实体（按 start 升序）
    matches: tuple[Match, ...] = ()       # 给 scorer 的统计形态
    latency_ms: int = 0
    error: str = ""                       # 失败原因（disabled / timeout / json_decode_error 等）
    raw_response: str = ""                # 模型原始 content（审计用）


def detect(text: str, *, mode: str = "default") -> LLMDetectResult:
    """对 text 跑 LLM NER，返回校准后的实体列表 + 评分用统计。

    mode:
      "default" → 常规识别（COMPANY/PERSON/PRODUCT/MONEY/ID_NUMBER），用于 Read
      "ups"     → 在 default 基础上额外识别 PASSWORD（明文密码语义），
                  用于用户对话框输入。仅 UPS 走 PASSWORD 是为了避免代码注释
                  里的"密码"被误中。

    永不抛异常。任何故障 → ok=False + error 描述。
    """
    if not text:
        return LLMDetectResult(ok=True)

    if not llm_config.is_runnable:
        return LLMDetectResult(ok=False, error="llm_disabled")

    chunks = _split_into_chunks(
        text,
        max_input_chars=llm_config.call.max_input_chars,
        max_chunks=llm_config.call.max_chunks,
    )

    responses = _call_llm_parallel(chunks, mode=mode, concurrency=llm_config.call.concurrency)

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

    entities = _calibrate_entities({"entities": merged_items}, text, mode=mode)
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


def _call_llm_parallel(chunks: list[str], *, mode: str, concurrency: int):
    """串行 / 并发统一接口：单 chunk 直接同步；多 chunk 走线程池（I/O bound）。"""
    if not chunks:
        return []
    if len(chunks) == 1:
        return [_call_one(chunks[0], mode=mode)]
    workers = max(1, min(concurrency, len(chunks)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(lambda c: _call_one(c, mode=mode), chunks))


def _call_one(chunk_text: str, *, mode: str):
    messages = [
        {"role": "system", "content": llm_config.prompt_system(mode=mode)},
        {"role": "user",   "content": llm_config.prompt.user_template.format(text=chunk_text)},
    ]
    return chat_json(messages)


# --- 解析 + 校准 ----------------------------------------------------

def _allowed_types(mode: str = "default") -> set[str]:
    return llm_config.allowed_types(mode=mode)


def _extract_items(parsed: object) -> list[dict]:
    """从模型 JSON 中拿到实体数组，兼容三种形态：
       1) {"entities": [...]}（首选，prompt 已强约束）
       2) {"data": [...]}      （备用）
       3) [...]                （旧式直接数组）
    其余形态返回 []。
    """
    if isinstance(parsed, list):
        return [it for it in parsed if isinstance(it, dict)]
    if isinstance(parsed, dict):
        for key in ("entities", "data", "items"):
            v = parsed.get(key)
            if isinstance(v, list):
                return [it for it in v if isinstance(it, dict)]
    return []


def _calibrate_entities(parsed: object, original: str, *, mode: str = "default") -> list[LLMEntity]:
    """把模型给的 text/type 在原文里重新定位，丢弃越界 / 未知类型 / 重叠的项。

    校准策略：
      - text 必须在原文里存在（否则可能是幻觉，丢弃）
      - type 必须在 entity_types 白名单内（按 mode 过滤 ups_only 类型）
      - 同一实体在原文多次出现 → 全部命中
      - 同一 span 被多次给出 → 去重（按 (start,end) 排重）
    """
    allowed = _allowed_types(mode)
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

        # 在原文搜索所有出现位置：模型给的 start 只作 hint，不信
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
    """汇总到 scorer 用的 Match：按 type 聚合 count + 样本（最多 5）。"""
    by_type: dict[str, list[str]] = {}
    counts: dict[str, int] = {}
    for ent in entities:
        counts[ent.type] = counts.get(ent.type, 0) + 1
        samples = by_type.setdefault(ent.type, [])
        if len(samples) < 5:
            samples.append(_mask(ent.text))

    matches: list[Match] = []
    for type_, count in counts.items():
        # data_class 用小写 type（与 rules.yml 兼容；rules 未定义该类目时 scorer 兜底为 0 分）
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
