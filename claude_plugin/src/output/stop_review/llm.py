"""Stop-review 的 LLM 调用封装。

复用 openai SDK(已经在项目里,且本地 litellm 代理 :4000 对 claude-opus-4-7 走
OpenAI /v1/chat/completions 已实测能通)对话。

对外只暴露一个函数 review_diffs(diffs) → ReviewOutcome。

设计要点:
  - 永不抛异常:所有失败通过 ReviewOutcome.error 传出,exit 0 fail-OPEN
  - endpoint / key 从环境变量取:ANTHROPIC_BASE_URL + ANTHROPIC_API_KEY
    (不复用 config/llm 因为那套是给 NER 脱敏的,参数完全不同)
  - 明确要求 JSON 输出;不用 response_format=json_object,兼容更广
  - 输入尺寸有上限(每文件 4000 字符 diff,整体 40000 字符),超出截断
  - LLM 客户端缓存单次进程实例,避免多次构造 openai client
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field


DEFAULT_MODEL = "claude-opus-4-7"
DEFAULT_TIMEOUT_SECONDS = 25.0
DEFAULT_MAX_TOKENS = 2048

# 上游 prompt 尺寸预算:一个文件 diff 不能吃掉整个上下文
MAX_DIFF_CHARS_PER_FILE = 4000
MAX_TOTAL_DIFF_CHARS = 40000


_SYSTEM_PROMPT = """You are a security code reviewer for AI-assisted code generation.
You will be given a bundle of unified diffs (before → after) of files just modified by the AI.

Your job: identify HIGH-CONFIDENCE security issues that pure regex/AST scanners cannot catch, such as:
  - Missing authorization / access-control checks
  - SSRF (fetching a URL derived from user input without allow-listing)
  - Business-logic auth bypass (e.g. trusting client-supplied user_id)
  - Cross-function taint (user input → sensitive sink over multiple hops)
  - Misuse of crypto/auth libraries (correct APIs, wrong semantics)
  - Unsafe defaults on new dependencies
  - Newly-introduced arbitrary-code-exec surfaces we haven't seen before

Do NOT flag:
  - Style, naming, docstrings, or generic "best practice" issues
  - Anything already trivially caught by regex (raw dynamic-eval calls, unsafe deserialization
    of untrusted binary formats, AES-ECB mode, hardcoded API keys) — those are handled by
    another layer and flagging them here is just noise
  - Speculative issues without direct evidence in the diff
  - Test/demo code that is obviously self-contained

Output STRICTLY the following JSON (no markdown fence, no prose):
{
  "clean": <bool>,
  "findings": [
    {
      "file": "<path from diff header>",
      "severity": "HIGH" | "MED",
      "title": "<short, imperative, <=80 chars>",
      "evidence": "<the specific line(s) or snippet from the diff that is the problem>",
      "why": "<one paragraph: what an attacker does, what breaks>",
      "fix": "<one paragraph: concrete remediation>"
    }
  ]
}

If clean is true, findings must be []. Be conservative; false positives are more costly than false negatives at this layer.
"""


@dataclass(frozen=True)
class Finding:
    file: str
    severity: str
    title: str
    evidence: str
    why: str
    fix: str


@dataclass(frozen=True)
class ReviewOutcome:
    ok: bool
    findings: list[Finding] = field(default_factory=list)
    raw_response: str = ""
    latency_ms: int = 0
    error: str = ""
    input_chars: int = 0
    model: str = ""


_client = None
_client_failed = False


def _get_client(timeout: float):
    global _client, _client_failed
    if _client_failed:
        return None
    if _client is not None:
        return _client
    base_url = (os.environ.get("ANTHROPIC_BASE_URL") or "").rstrip("/")
    api_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN") or ""
    if not base_url:
        _client_failed = True
        return None
    try:
        from openai import OpenAI
        _client = OpenAI(
            base_url=base_url,
            api_key=api_key or "EMPTY",
            timeout=timeout,
            max_retries=0,
        )
        return _client
    except Exception:
        _client_failed = True
        return None


def _strip_json_fence(text: str) -> str:
    """LLM 有时会包 ```json ... ``` 或加前后废话,尽量提取花括号内容。"""
    if not text:
        return ""
    t = text.strip()
    # ```json / ``` fence
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", t, re.DOTALL)
    if m:
        return m.group(1)
    # 找到第一个 { 到最后一个 } 的子串
    first = t.find("{")
    last = t.rfind("}")
    if first != -1 and last > first:
        return t[first : last + 1]
    return t


def _parse(raw_text: str) -> tuple[list[Finding], str]:
    body = _strip_json_fence(raw_text)
    try:
        obj = json.loads(body)
    except json.JSONDecodeError as e:
        return [], f"json_decode_error:{e}"
    if not isinstance(obj, dict):
        return [], "not_object"
    if obj.get("clean") is True:
        return [], ""
    raw_findings = obj.get("findings") or []
    if not isinstance(raw_findings, list):
        return [], "findings_not_list"
    out: list[Finding] = []
    for f in raw_findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity", "")).upper()
        if sev not in ("HIGH", "MED"):
            sev = "MED"
        out.append(Finding(
            file=str(f.get("file", "")),
            severity=sev,
            title=str(f.get("title", ""))[:200],
            evidence=str(f.get("evidence", ""))[:600],
            why=str(f.get("why", ""))[:600],
            fix=str(f.get("fix", ""))[:600],
        ))
    return out, ""


def review_diffs(
    diff_bundle: str,
    *,
    model: str = DEFAULT_MODEL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> ReviewOutcome:
    """把 diff_bundle 送给 LLM 审计,返回结构化 findings。

    diff_bundle 已由调用方按 MAX_TOTAL_DIFF_CHARS 截断,本函数不再截。
    """
    if not diff_bundle.strip():
        return ReviewOutcome(ok=True, model=model)

    client = _get_client(timeout=timeout)
    if client is None:
        return ReviewOutcome(ok=False, error="client_init_failed", model=model,
                             input_chars=len(diff_bundle))

    started = time.perf_counter()
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": diff_bundle},
            ],
            temperature=0.0,
            max_tokens=max_tokens,
            stream=False,
        )
    except Exception as exc:
        latency = int((time.perf_counter() - started) * 1000)
        return ReviewOutcome(
            ok=False, latency_ms=latency,
            error=f"{type(exc).__name__}:{str(exc)[:200]}",
            input_chars=len(diff_bundle), model=model,
        )
    latency = int((time.perf_counter() - started) * 1000)

    try:
        raw = resp.choices[0].message.content or ""
    except (IndexError, AttributeError) as exc:
        return ReviewOutcome(
            ok=False, latency_ms=latency,
            error=f"response_shape_invalid:{type(exc).__name__}",
            input_chars=len(diff_bundle), model=model,
        )

    findings, parse_err = _parse(raw)
    if parse_err:
        return ReviewOutcome(
            ok=False, latency_ms=latency, raw_response=raw[:2000],
            error=parse_err, input_chars=len(diff_bundle), model=model,
        )

    return ReviewOutcome(
        ok=True, findings=findings, latency_ms=latency,
        raw_response=raw[:2000], input_chars=len(diff_bundle), model=model,
    )
