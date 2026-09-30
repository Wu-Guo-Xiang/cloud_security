"""实体→占位符一致性字典（session 级）。

核心约束：**同一 session 内，同一原文片段必须始终映射到同一占位符。**

存储复用 SessionCache 的 pickle 文件，存放在 `_data["__entity_map__"]`，
键 `__entity_map__` 不会与 cache_key 冲突（cache_key 含 sha + version，永不全等）。

不持久化跨 session：会话结束 → cache 文件被删 → 字典随之消失。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cache.session_cache import SessionCache


_ENTITY_MAP_KEY = "__entity_map__"


@dataclass
class EntityMapState:
    """可 pickle 的最小状态。"""
    # text → label, 例如 "腾讯科技" → "[公司A]"
    by_text: dict[str, str] = field(default_factory=dict)
    # type → 已分配数（用于继续编号 A/B/C/...）
    counters: dict[str, int] = field(default_factory=dict)
    # text → entity_type，给别名启发式做类型隔离用
    by_text_type: dict[str, str] = field(default_factory=dict)


# 别名启发式（全称 ↔ 简称归并）参数：
#   _MERGE_TYPES: 只对哪些类型启用。COMPANY 误并风险最低（"星河智联" ⊂ "星河智联科技…"）；
#                 PERSON 易把 "张三" 误并到 "张三丰"，PRODUCT 也常有版本变体，暂不启用。
#   _MERGE_MIN_LEN: 双方均需达到的最小长度。4 是经验值，避免 "中国"/"国际" 等高频前缀触发归并。
_MERGE_TYPES = frozenset({"COMPANY"})
_MERGE_MIN_LEN = 4


class EntityMap:
    """封装类型→标签的分配规则；状态托管在 SessionCache 中。

    设计上不持有 cache 写锁，每次 assign() 都会调 cache 标脏，
    最终由 cache.save() 一并落盘。
    """

    # 字母表：A-Z 然后 AA-AZ 然后 BA-... 保证 27 个以上仍可分配
    _ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def __init__(self, cache: "SessionCache"):
        self._cache = cache
        state = cache._data.get(_ENTITY_MAP_KEY)
        if not isinstance(state, EntityMapState):
            state = EntityMapState()
            cache._data[_ENTITY_MAP_KEY] = state
            cache._dirty = True
        # 旧 session pickle 可能没有 by_text_type；补一个空 dict 即可
        if not hasattr(state, "by_text_type") or state.by_text_type is None:
            state.by_text_type = {}
            cache._dirty = True
        self._state: EntityMapState = state

    # --- 分配 -----------------------------------------------------------

    def assign(self, text: str, entity_type: str, label: str) -> str:
        """返回 text 对应的占位符。若是新实体，分配下一个序号。

        label：中文类目标签（公司/人员/产品/金额），由 llm_config.label_of(type) 提供。
              特殊：MONEY 不做序号区分，全部映射为 "[金额]"（避免无意义编号噪声）。
        """
        if text in self._state.by_text:
            return self._state.by_text[text]

        alias_ph = self._find_alias_placeholder(text, entity_type)
        if alias_ph is not None:
            self._state.by_text[text] = alias_ph
            self._state.by_text_type[text] = entity_type
            self._cache._dirty = True
            return alias_ph

        if entity_type == "MONEY":
            placeholder = "[金额]"
        else:
            n = self._state.counters.get(entity_type, 0) + 1
            self._state.counters[entity_type] = n
            placeholder = f"[{label}{self._index_to_suffix(n)}]"

        self._state.by_text[text] = placeholder
        self._state.by_text_type[text] = entity_type
        self._cache._dirty = True
        return placeholder

    def _find_alias_placeholder(self, text: str, entity_type: str) -> str | None:
        """同类型下，text 与已记录的某 key 互为子串且双方都 ≥ _MERGE_MIN_LEN 时复用其占位符。

        Why: LLM 经常把 "星河智联科技（北京）有限公司" 和 "星河智联" 当作两个实体输出，
        下游需要把它们映射到同一个 [公司A]。
        """
        if entity_type not in _MERGE_TYPES:
            return None
        if len(text) < _MERGE_MIN_LEN:
            return None
        for existing_text, existing_type in self._state.by_text_type.items():
            if existing_type != entity_type:
                continue
            if len(existing_text) < _MERGE_MIN_LEN:
                continue
            if text in existing_text or existing_text in text:
                return self._state.by_text.get(existing_text)
        return None

    def get(self, text: str) -> str | None:
        return self._state.by_text.get(text)

    def snapshot(self) -> dict[str, str]:
        """返回 {原文: 占位符} 的拷贝，用于审计日志。"""
        return dict(self._state.by_text)

    # --- helpers --------------------------------------------------------

    @classmethod
    def _index_to_suffix(cls, n: int) -> str:
        """1->A, 2->B, ..., 26->Z, 27->AA, 28->AB, ..."""
        if n <= 0:
            return ""
        out: list[str] = []
        while n > 0:
            n, rem = divmod(n - 1, 26)
            out.append(cls._ALPHABET[rem])
        return "".join(reversed(out))
