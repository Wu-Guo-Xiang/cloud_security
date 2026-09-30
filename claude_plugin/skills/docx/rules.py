"""规则加载器：从 rules.yml 读取 data_classes。"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_RULES_FILE = Path(__file__).parent / "rules.yml"


@dataclass(frozen=True)
class SensitiveClass:
    name: str
    regex: str = ""
    validator: str = ""
    source: str = ""
    mask_strategy: str = ""
    enabled: bool = True
    capture_group: int = 0


@dataclass(frozen=True)
class Rules:
    data_classes: dict[str, SensitiveClass]
    version: str

    def get_class(self, name: str) -> SensitiveClass | None:
        return self.data_classes.get(name)


def _content_hash(data: Any) -> str:
    serialized = json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()[:12]


def _load() -> Rules:
    import yaml

    if not _RULES_FILE.exists():
        raise FileNotFoundError(f"规则文件不存在: {_RULES_FILE}")

    with _RULES_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    classes: dict[str, SensitiveClass] = {}
    for name, cfg in (data.get("data_classes") or {}).items():
        classes[name] = SensitiveClass(
            name=name,
            regex=str(cfg.get("regex", "")),
            validator=str(cfg.get("validator", "")),
            source=str(cfg.get("source", "")),
            mask_strategy=str(cfg.get("mask_strategy", "")),
            enabled=bool(cfg.get("enabled", True)),
            capture_group=int(cfg.get("capture_group", 0)),
        )

    return Rules(
        data_classes=classes,
        version=_content_hash(data),
    )


rules: Rules = _load()
