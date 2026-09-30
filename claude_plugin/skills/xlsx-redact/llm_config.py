"""LLM 接入配置加载器（自包含版）。

凭据加载顺序：
  1) 进程环境变量 DEEPSEEK_ENDPOINT / DEEPSEEK_API_KEY / DEEPSEEK_MODEL
  2) 同目录 .env（key=value，# 开头注释；可写 base_url / api_key / model）

参数（timeout/max_tokens/prompt 等）来自同目录 llm.yml。
LLM 未启用 / 配置缺失 → is_runnable=False，调用方自动降级到纯 L1。
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_LLM_FILE = Path(__file__).parent / "llm.yml"
_ENV_FILE = Path(__file__).parent / ".env"


@dataclass(frozen=True)
class LLMCall:
    timeout_seconds: float = 5.0
    temperature: float = 0.0
    max_tokens: int = 1024
    max_input_chars: int = 8000
    max_chunks: int = 12
    concurrency: int = 4
    retries: int = 0


@dataclass(frozen=True)
class EntityType:
    type: str
    label: str
    placeholder: str


@dataclass(frozen=True)
class Prompt:
    system: str
    user_template: str


@dataclass(frozen=True)
class LLMConfig:
    enabled: bool
    base_url: str
    api_key: str
    model: str
    call: LLMCall
    on_failure: str
    entity_types: tuple[EntityType, ...]
    prompt: Prompt
    version: str

    @property
    def is_runnable(self) -> bool:
        return self.enabled and bool(self.base_url) and bool(self.model)

    def label_of(self, type_: str) -> str:
        for et in self.entity_types:
            if et.type == type_:
                return et.label
        return type_

    def placeholder_strategy_of(self, type_: str) -> str:
        for et in self.entity_types:
            if et.type == type_:
                return et.placeholder or "placeholder"
        return "placeholder"


def _content_hash(data: Any) -> str:
    serialized = json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()[:12]


def _load_dotenv_if_exists() -> dict[str, str]:
    if not _ENV_FILE.exists():
        return {}
    out: dict[str, str] = {}
    try:
        for raw in _ENV_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        return {}
    return out


def _load() -> LLMConfig:
    import yaml

    if not _LLM_FILE.exists():
        return LLMConfig(
            enabled=False, base_url="", api_key="", model="",
            call=LLMCall(), on_failure="degrade_to_l1",
            entity_types=(), prompt=Prompt(system="", user_template=""),
            version="empty",
        )

    with _LLM_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    env = _load_dotenv_if_exists()
    base_url = (os.environ.get("DEEPSEEK_ENDPOINT") or env.get("base_url", "")).rstrip("/")
    api_key  = os.environ.get("DEEPSEEK_API_KEY") or env.get("api_key", "")
    model    = os.environ.get("DEEPSEEK_MODEL") or env.get("model", "")

    call_cfg = data.get("call") or {}
    call = LLMCall(
        timeout_seconds=float(call_cfg.get("timeout_seconds", 5.0)),
        temperature=float(call_cfg.get("temperature", 0.0)),
        max_tokens=int(call_cfg.get("max_tokens", 1024)),
        max_input_chars=int(call_cfg.get("max_input_chars", 8000)),
        max_chunks=int(call_cfg.get("max_chunks", 12)),
        concurrency=int(call_cfg.get("concurrency", 4)),
        retries=int(call_cfg.get("retries", 0)),
    )

    entity_types = tuple(
        EntityType(
            type=str(it.get("type", "")),
            label=str(it.get("label", "")),
            placeholder=str(it.get("placeholder", "placeholder")),
        )
        for it in (data.get("entity_types") or [])
        if it.get("type")
    )

    prompt_cfg = data.get("prompt") or {}
    prompt = Prompt(
        system=str(prompt_cfg.get("system", "")),
        user_template=str(prompt_cfg.get("user_template", "文本：\n<<<{text}>>>")),
    )

    return LLMConfig(
        enabled=bool(data.get("enabled", False)),
        base_url=base_url,
        api_key=api_key,
        model=model,
        call=call,
        on_failure=str(data.get("on_failure", "degrade_to_l1")),
        entity_types=entity_types,
        prompt=prompt,
        version=_content_hash(data),
    )


llm_config: LLMConfig = _load()
