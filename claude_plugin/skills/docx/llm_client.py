"""LLM HTTP 客户端（openai 兼容 SDK 封装）。"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from llm_config import llm_config


@dataclass(frozen=True)
class NerResponse:
    ok: bool
    raw_text: str = ""
    parsed_json: Any = None
    latency_ms: int = 0
    error: str = ""
    finish_reason: str = ""


_client = None
_client_failed = False


def _get_client():
    global _client, _client_failed
    if _client is not None or _client_failed:
        return _client
    if not llm_config.is_runnable:
        _client_failed = True
        return None
    try:
        from openai import OpenAI
        _client = OpenAI(
            base_url=llm_config.base_url,
            api_key=llm_config.api_key or "EMPTY",
            timeout=llm_config.call.timeout_seconds,
            max_retries=llm_config.call.retries,
        )
    except Exception:
        _client_failed = True
        _client = None
    return _client


def chat_json(messages: list[dict]) -> NerResponse:
    if not llm_config.is_runnable:
        return NerResponse(ok=False, error="llm_disabled")

    client = _get_client()
    if client is None:
        return NerResponse(ok=False, error="llm_client_init_failed")

    started = time.perf_counter()
    try:
        resp = client.chat.completions.create(
            model=llm_config.model,
            messages=messages,
            temperature=llm_config.call.temperature,
            max_tokens=llm_config.call.max_tokens,
            response_format={"type": "json_object"},
            stream=False,
        )
    except Exception as e:
        latency = int((time.perf_counter() - started) * 1000)
        return NerResponse(ok=False, latency_ms=latency, error=f"{type(e).__name__}: {e}")

    latency = int((time.perf_counter() - started) * 1000)

    try:
        choice = resp.choices[0]
        raw_text = choice.message.content or ""
        finish_reason = choice.finish_reason or ""
    except (IndexError, AttributeError) as e:
        return NerResponse(ok=False, latency_ms=latency,
                           error=f"response_shape_invalid: {type(e).__name__}: {e}")

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as e:
        return NerResponse(
            ok=False, raw_text=raw_text, latency_ms=latency,
            finish_reason=finish_reason,
            error=f"json_decode_error: {e}",
        )

    return NerResponse(
        ok=True,
        raw_text=raw_text,
        parsed_json=parsed,
        latency_ms=latency,
        finish_reason=finish_reason,
    )
