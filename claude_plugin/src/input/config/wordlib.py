"""词库加载器：从 word_library.yml 读取业务词；提供版本哈希给 cache key。

把词库独立成模块的原因：
  - pattern_detector / desensitize_action 都要消费词库
  - session_cache 需要词库版本作为 key 组成部分（词库更新 → 缓存失效）
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


_WORDLIB_FILE = Path(__file__).parent / "word_library.yml"


@dataclass(frozen=True)
class WordLibrary:
    terms_by_class: dict[str, tuple[str, ...]]
    version: str  # 12 位 SHA256；空词库时为固定标记 "empty"

    def is_empty(self) -> bool:
        return not self.terms_by_class


def _load() -> WordLibrary:
    if not _WORDLIB_FILE.exists():
        return WordLibrary(terms_by_class={}, version="empty")

    raw = _WORDLIB_FILE.read_bytes()
    version = "empty" if not raw.strip() else hashlib.sha256(raw).hexdigest()[:12]

    try:
        data: Any = yaml.safe_load(raw.decode("utf-8")) or {}
    except yaml.YAMLError:
        # 配置错误：fail-closed 在上游处理，这里返回空词库 + 标记版本
        return WordLibrary(terms_by_class={}, version="invalid")

    if not isinstance(data, dict):
        return WordLibrary(terms_by_class={}, version=version)

    by_class: dict[str, tuple[str, ...]] = {}
    for k, v in data.items():
        if isinstance(v, list):
            terms = tuple(str(t) for t in v if str(t).strip())
            if terms:
                by_class[str(k)] = terms

    return WordLibrary(terms_by_class=by_class, version=version)


wordlib: WordLibrary = _load()
