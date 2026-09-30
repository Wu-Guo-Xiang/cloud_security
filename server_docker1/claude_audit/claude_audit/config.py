from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List

import yaml


DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config.yml"

# GLM 监控采集器(glm_monitor/monitor.py)写的 SQLite, 平台只读
_DEFAULT_GLM_DB = Path(__file__).resolve().parent.parent.parent / "glm_monitor" / "glm_monitor_data.db"


def _resolve_glm_db(config_path: Path, configured) -> Path:
    """glm_monitor_db 解析优先级: 环境变量 > config.yml 相对(相对 config 文件目录) > 默认。"""
    env = os.environ.get("GLM_MONITOR_DB")
    if env:
        return Path(env)
    if configured:
        p = Path(str(configured))
        if not p.is_absolute():
            p = (config_path.parent / p).resolve()
        return p
    return _DEFAULT_GLM_DB


@dataclass
class WebConfig:
    host: str
    port: int


@dataclass
class IngestConfig:
    enabled: bool = True
    token: str | None = None  # 若设置,则要求 X-Ingest-Token 与之相等


@dataclass
class LiteLLMConfig:
    host: str = "http://192.168.3.124:4000"
    api_key: str = ""
    offline_threshold_hours: int = 3


@dataclass
class Config:
    log_sources: List[Path]
    watch_dir: Path
    database: Path
    rules_dir: Path
    web: WebConfig
    local_collector: bool = False
    ingest: IngestConfig = None  # type: ignore[assignment]
    plugins_dir: Path = Path("data/plugins")  # 插件 zip 文件存储目录
    litellm: LiteLLMConfig = None  # type: ignore[assignment]
    glm_monitor_db: Path = _DEFAULT_GLM_DB  # GLM 监控数据(只读)


def load(path: Path | str | None = None) -> Config:
    if path:
        p = Path(path)
    elif os.environ.get("CLAUDE_AUDIT_CONFIG"):
        p = Path(os.environ["CLAUDE_AUDIT_CONFIG"])
    else:
        p = DEFAULT_CONFIG
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    ing_raw = raw.get("ingest") or {}
    ll_raw = raw.get("litellm") or {}
    return Config(
        log_sources=[Path(s) for s in raw.get("log_sources") or []],
        watch_dir=Path(raw["watch_dir"]) if raw.get("watch_dir") else Path("."),
        database=Path(raw["database"]),
        rules_dir=Path(raw["rules_dir"]),
        web=WebConfig(host=raw["web"]["host"], port=int(raw["web"]["port"])),
        local_collector=bool(raw.get("local_collector", False)),
        ingest=IngestConfig(
            enabled=bool(ing_raw.get("enabled", True)),
            token=ing_raw.get("token") or None,
        ),
        plugins_dir=Path(raw.get("plugins_dir", "data/plugins")),
        litellm=LiteLLMConfig(
            host=(ll_raw.get("host") or "http://192.168.3.124:4000").rstrip("/"),
            api_key=os.environ.get("LITELLM_KEY") or ll_raw.get("api_key") or "",
            offline_threshold_hours=int(ll_raw.get("offline_threshold_hours", 3)),
        ),
        glm_monitor_db=_resolve_glm_db(p, raw.get("glm_monitor_db")),
    )
