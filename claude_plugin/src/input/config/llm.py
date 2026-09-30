"""LLM 接入配置加载器。

加载 config/llm.yml（参数）与项目根 .env（敏感凭据）。

  - enabled / call / on_failure / entity_types / prompt 来自 llm.yml
  - base_url / api_key / model 来自项目根 .env（不入库）
  - version 是 llm.yml 内容哈希，用于 session_cache 的 key 失效

设计上 LLM 不可达 / 配置缺失时不应抛异常打断 Hook 主链路，
缺失项一律降级到 "未启用" 状态，由调用方继续走 L1。
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


_LLM_FILE = Path(__file__).parent / "llm.yml"
# 项目根 .env 路径推断：scripts/input/config/llm.py → 上溯 4 层（config / input / scripts / 项目根）
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"


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
    type: str         # COMPANY / PERSON / PRODUCT / MONEY / ID_NUMBER / PASSWORD
    label: str        # 占位符中文：公司 / 人员 / 产品 / 金额 / 号码 / 口令
    placeholder: str  # "placeholder"(默认顺序占位符) | mask_strategies 中的策略名（id_number / password / ...）
    ups_only: bool = False  # True = 仅 UPS 模式启用（PASSWORD 用，避免污染 Read 路径）


@dataclass(frozen=True)
class Prompt:
    system: str
    user_template: str  # 需含 {text} 占位
    system_ups: str = ""  # UPS 模式专用 system；缺省回退到 system


@dataclass(frozen=True)
class LLMConfig:
    enabled: bool
    base_url: str
    api_key: str
    model: str
    call: LLMCall
    on_failure: str        # degrade_to_l1 / block
    entity_types: tuple[EntityType, ...]
    prompt: Prompt
    version: str           # llm.yml 内容哈希（base_url/api_key 不参与版本）

    @property
    def is_runnable(self) -> bool:
        """是否可以发起真实调用：enabled + 至少有 base_url。"""
        return self.enabled and bool(self.base_url) and bool(self.model)

    def label_of(self, type_: str) -> str:
        for et in self.entity_types:
            if et.type == type_:
                return et.label
        return type_  # 未知类型用原文兜底，pseudonymizer 会再过滤

    def placeholder_strategy_of(self, type_: str) -> str:
        """该类型应使用什么占位策略。

        "placeholder" → EntityMap 顺序占位符（公司/人员）
        其他值        → mask_strategies 中已注册的策略名（id_number / password / ...）
        """
        for et in self.entity_types:
            if et.type == type_:
                return et.placeholder or "placeholder"
        return "placeholder"

    def allowed_types(self, *, mode: str = "default") -> set[str]:
        """该 mode 下白名单内的类型集合。

        mode="ups"     → 含 ups_only 类型（PASSWORD）
        mode="default" → 不含 ups_only 类型（即使模型偶然吐出来也会被丢弃）
        """
        return {
            et.type for et in self.entity_types
            if not et.ups_only or mode == "ups"
        }

    def prompt_system(self, *, mode: str = "default") -> str:
        """按 mode 选 system prompt；UPS 模式优先用 system_ups，缺失则回退 system。"""
        if mode == "ups" and self.prompt.system_ups:
            return self.prompt.system_ups
        return self.prompt.system


def _content_hash(data: Any) -> str:
    serialized = json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()[:12]


def _load_dotenv_if_exists() -> dict[str, str]:
    """轻量 .env 解析（不依赖 python-dotenv），key=value 形式，# 开头是注释。

    存在性失败 / 解析异常一律静默返回 {}，让 LLM 走未启用。
    """
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
        # 配置缺失：返回未启用占位，调用方自动跳过 L2
        return LLMConfig(
            enabled=False, base_url="", api_key="", model="",
            call=LLMCall(), on_failure="degrade_to_l1",
            entity_types=(), prompt=Prompt(system="", user_template=""),
            version="empty",
        )

    with _LLM_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    env = _load_dotenv_if_exists()
    base_url = (env.get("base_url") or os.environ.get("DEEPSEEK_ENDPOINT", "")).rstrip("/")
    api_key  = env.get("api_key")  or os.environ.get("DEEPSEEK_API_KEY", "")
    model    = env.get("model")    or os.environ.get("DEEPSEEK_MODEL", "")

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
            ups_only=bool(it.get("ups_only", False)),
        )
        for it in (data.get("entity_types") or [])
        if it.get("type")
    )

    prompt_cfg = data.get("prompt") or {}
    prompt = Prompt(
        system=str(prompt_cfg.get("system", "")),
        user_template=str(prompt_cfg.get("user_template", "文本：\n<<<{text}>>>")),
        system_ups=str(prompt_cfg.get("system_ups", "")),
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
