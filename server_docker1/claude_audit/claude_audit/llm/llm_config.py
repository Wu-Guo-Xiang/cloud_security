"""LLM 配置加载器（支持 Web 端热保存与实时重载）。

凭据加载顺序：
  1) 进程环境变量 LLM_BASE_URL / LLM_API_KEY / LLM_MODEL
  2) 同目录 .env（key=value，支持 # 注释）
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_CFG_FILE = Path(__file__).resolve().parent / "llm.yml"
_ENV_FILE = Path(__file__).resolve().parent / ".env"


@dataclass
class LLMCall:
    timeout_seconds: float = 30.0
    temperature: float = 0.1
    max_tokens: int = 2048


@dataclass
class LLMConfig:
    enabled: bool
    base_url: str
    api_key: str
    model: str
    call: LLMCall

    @property
    def is_runnable(self) -> bool:
        return self.enabled and bool(self.base_url) and bool(self.model)

    def update_from(self, other: LLMConfig) -> None:
        self.enabled = other.enabled
        self.base_url = other.base_url
        self.api_key = other.api_key
        self.model = other.model
        self.call.timeout_seconds = other.call.timeout_seconds
        self.call.temperature = other.call.temperature
        self.call.max_tokens = other.call.max_tokens

    def to_dict(self, mask_key: bool = True) -> dict[str, Any]:
        key = self.api_key or ""
        if mask_key and key:
            if len(key) <= 8:
                masked_key = "********"
            else:
                masked_key = f"{key[:6]}****{key[-4:]}"
        else:
            masked_key = key

        return {
            "enabled": self.enabled,
            "base_url": self.base_url,
            "api_key": masked_key,
            "api_key_masked": masked_key,
            "has_key": bool(self.api_key),
            "model": self.model,
            "timeout_seconds": self.call.timeout_seconds,
            "temperature": self.call.temperature,
            "max_tokens": self.call.max_tokens,
            "is_runnable": self.is_runnable,
        }


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

    if not _CFG_FILE.exists():
        return LLMConfig(enabled=False, base_url="", api_key="", model="", call=LLMCall())

    with _CFG_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    env = _load_dotenv_if_exists()
    base_url = (os.environ.get("LLM_BASE_URL") or env.get("base_url", "")).rstrip("/")
    api_key = os.environ.get("LLM_API_KEY") or env.get("api_key", "")
    model = os.environ.get("LLM_MODEL") or env.get("model", "")

    call_cfg = data.get("call") or {}
    call = LLMCall(
        timeout_seconds=float(call_cfg.get("timeout_seconds", 30.0)),
        temperature=float(call_cfg.get("temperature", 0.1)),
        max_tokens=int(call_cfg.get("max_tokens", 2048)),
    )

    return LLMConfig(
        enabled=bool(data.get("enabled", False)),
        base_url=base_url,
        api_key=api_key,
        model=model,
        call=call,
    )


llm_config: LLMConfig = _load()


def reload_llm_config() -> LLMConfig:
    """热重载 LLM 配置，并重置 client 缓存，使新配置立即对所有模块生效。"""
    global llm_config
    new_cfg = _load()
    llm_config.update_from(new_cfg)
    try:
        from . import llm_client
        llm_client.reset_client()
    except Exception:
        pass
    return llm_config


def save_llm_config(
    *,
    enabled: bool,
    base_url: str,
    api_key: str,
    model: str,
    timeout_seconds: float = 30.0,
    temperature: float = 0.1,
    max_tokens: int = 2048,
    sync_plugin: bool = True,
) -> LLMConfig:
    """落盘保存 LLM 配置，并热重载生效。支持同步更新端侧 claude_plugin/.env。"""
    import yaml

    cfg_data: dict[str, Any] = {}
    if _CFG_FILE.exists():
        try:
            with _CFG_FILE.open("r", encoding="utf-8") as f:
                cfg_data = yaml.safe_load(f) or {}
        except Exception:
            cfg_data = {}
    cfg_data["enabled"] = bool(enabled)
    if "call" not in cfg_data or not isinstance(cfg_data["call"], dict):
        cfg_data["call"] = {}
    cfg_data["call"]["timeout_seconds"] = float(timeout_seconds)
    cfg_data["call"]["temperature"] = float(temperature)
    cfg_data["call"]["max_tokens"] = int(max_tokens)

    with _CFG_FILE.open("w", encoding="utf-8") as f:
        yaml.safe_dump(cfg_data, f, allow_unicode=True)

    # 处理 api_key：如果用户传入空或掩码（含 ****），则保留原有 key
    current_env = _load_dotenv_if_exists()
    final_key = (api_key or "").strip()
    if not final_key or "****" in final_key:
        final_key = current_env.get("api_key", "")

    env_lines = [
        f"base_url={base_url.strip()}",
        f"api_key={final_key}",
        f"model={model.strip()}",
        "",
    ]
    _ENV_FILE.write_text("\n".join(env_lines), encoding="utf-8")

    # 可选同步至客户端插件
    if sync_plugin:
        try:
            plugin_env = Path("E:/cloud_security_deploy/claude_plugin/.env")
            if plugin_env.exists():
                plugin_env.write_text("\n".join(env_lines), encoding="utf-8")
        except Exception:
            pass

    return reload_llm_config()
