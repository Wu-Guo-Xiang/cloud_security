"""LLM HTTP 客户端（openai 兼容 SDK 封装，NL2SQL 精简版，支持原生 urllib 回退与连通性测试）。"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from .llm_config import llm_config

_client = None
_client_failed = False


def reset_client() -> None:
    """重置客户端实例缓存，触发下次调用重新读取最新 llm_config。"""
    global _client, _client_failed
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
            max_retries=0,
        )
    except Exception:
        _client_failed = True
        _client = None
    return _client


def _chat_urllib(messages: list[dict]) -> str:
    """使用 Python 原生 urllib.request 发起 OpenAI 兼容请求（零第三方依赖兜底）。"""
    url = llm_config.base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": llm_config.model,
        "messages": messages,
        "temperature": llm_config.call.temperature,
        "max_tokens": llm_config.call.max_tokens,
        "stream": False,
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if llm_config.api_key:
        req.add_header("Authorization", f"Bearer {llm_config.api_key}")

    with urllib.request.urlopen(req, timeout=llm_config.call.timeout_seconds) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    data = json.loads(raw)
    choice = data.get("choices", [{}])[0]
    return choice.get("message", {}).get("content", "") or ""


def chat(messages: list[dict]) -> str:
    """调用 LLM 并返回纯文本响应。优先使用 OpenAI SDK，失败时自动退回原生 urllib。"""
    if not llm_config.is_runnable:
        raise RuntimeError("LLM 未启用或配置缺失 (is_runnable=False)")

    client = _get_client()
    if client is not None:
        try:
            resp = client.chat.completions.create(
                model=llm_config.model,
                messages=messages,
                temperature=llm_config.call.temperature,
                max_tokens=llm_config.call.max_tokens,
                stream=False,
            )
            choice = resp.choices[0]
            return choice.message.content or ""
        except Exception:
            pass  # Fallback to urllib

    # Native urllib fallback
    return _chat_urllib(messages)


def call_llm(prompt: str) -> str:
    """简易纯文本单轮调用接口。"""
    return chat([{"role": "user", "content": prompt}])


def test_connection(
    base_url: str = "",
    api_key: str = "",
    model: str = "",
    timeout: float = 10.0,
) -> dict[str, Any]:
    """测试指定或当前 LLM 端点的连通性与响应延迟。"""
    url = (base_url or llm_config.base_url).rstrip("/") + "/chat/completions"
    key = api_key if (api_key and "****" not in api_key) else llm_config.api_key
    mdl = model or llm_config.model
    if not url or not mdl:
        return {"ok": False, "error": "缺少 Base URL 或 Model 配置"}

    payload = {
        "model": mdl,
        "messages": [
            {"role": "user", "content": "请仅回复一个词：pong"},
        ],
        "max_tokens": 16,
        "temperature": 0.0,
        "stream": False,
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("Authorization", f"Bearer {key}")

    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        data = json.loads(raw)
        reply = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        return {
            "ok": True,
            "latency_ms": elapsed_ms,
            "reply": reply.strip() or "OK",
            "model": mdl,
        }
    except Exception as e:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return {
            "ok": False,
            "latency_ms": elapsed_ms,
            "error": str(e),
        }
