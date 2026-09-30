"""实体→占位符一致性字典（单进程内存版）。

原项目里这个对象的状态托管在 SessionCache 中以跨多个 Hook 调用复用；
本 skill 一次 docx_to_md.py 进程处理一个 .docx，无跨进程需求，
所以直接用进程内 dict 维护一致性，去掉 SessionCache 依赖。

核心约束：同一进程内，同一原文片段始终映射到同一占位符。
"""
from __future__ import annotations


_MERGE_TYPES = frozenset({"COMPANY"})
_MERGE_MIN_LEN = 4


class EntityMap:
    """实体→占位符分配（单进程内存）。"""

    _ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def __init__(self):
        self._by_text: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._by_text_type: dict[str, str] = {}

    def assign(self, text: str, entity_type: str, label: str) -> str:
        if text in self._by_text:
            return self._by_text[text]

        alias_ph = self._find_alias_placeholder(text, entity_type)
        if alias_ph is not None:
            self._by_text[text] = alias_ph
            self._by_text_type[text] = entity_type
            return alias_ph

        if entity_type == "MONEY":
            placeholder = "[金额]"
        else:
            n = self._counters.get(entity_type, 0) + 1
            self._counters[entity_type] = n
            placeholder = f"[{label}{self._index_to_suffix(n)}]"

        self._by_text[text] = placeholder
        self._by_text_type[text] = entity_type
        return placeholder

    def _find_alias_placeholder(self, text: str, entity_type: str) -> str | None:
        """同类型下、双方都 ≥ _MERGE_MIN_LEN 且互为子串 → 复用占位符。

        LLM 经常把 "星河智联科技（北京）有限公司" 和 "星河智联" 当作两个实体输出，
        但下游想看到 [公司A] 在两处一致。
        """
        if entity_type not in _MERGE_TYPES:
            return None
        if len(text) < _MERGE_MIN_LEN:
            return None
        for existing_text, existing_type in self._by_text_type.items():
            if existing_type != entity_type:
                continue
            if len(existing_text) < _MERGE_MIN_LEN:
                continue
            if text in existing_text or existing_text in text:
                return self._by_text.get(existing_text)
        return None

    def get(self, text: str) -> str | None:
        return self._by_text.get(text)

    def snapshot(self) -> dict[str, str]:
        return dict(self._by_text)

    @classmethod
    def _index_to_suffix(cls, n: int) -> str:
        if n <= 0:
            return ""
        out: list[str] = []
        while n > 0:
            n, rem = divmod(n - 1, 26)
            out.append(cls._ALPHABET[rem])
        return "".join(reversed(out))
