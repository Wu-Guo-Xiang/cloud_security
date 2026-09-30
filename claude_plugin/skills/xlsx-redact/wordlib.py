"""词库加载器：从 word_library.yml 读取业务词。"""
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
    version: str

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
