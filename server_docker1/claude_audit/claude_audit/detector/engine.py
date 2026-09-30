from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..storage.models import EventRecord, RuleHit
from .unicode_security import sanitize_for_security_matching


_FIELDS = ("bash_command", "file_path", "url", "prompt_text")
_MODES = ("contains", "glob", "startswith", "endswith", "exact", "regex")


def _parse_match_key(key: str) -> tuple[str, str] | None:
    """解析匹配字段与模式类型，例如 prompt_text_contains -> ('prompt_text', 'contains')"""
    for mode in _MODES:
        suffix = f"_{mode}"
        if key.endswith(suffix):
            field = key[:-len(suffix)]
            if field in _FIELDS:
                return field, mode
    return None


def _glob_to_regex(glob_pat: str) -> re.Pattern:
    """将通配符 (如 rm -rf /* 或 *.env*) 转换为正则"""
    parts = []
    for c in glob_pat:
        if c == "*":
            parts.append(".*")
        elif c == "?":
            parts.append(".")
        else:
            parts.append(re.escape(c))
    return re.compile("^" + "".join(parts) + "$", re.IGNORECASE | re.DOTALL)


def _compile_matcher(field: str, mode: str, raw_val: Any) -> Any:
    """编译匹配器数据结构以供 evaluate 高速执行"""
    if mode == "regex":
        if not isinstance(raw_val, str):
            raw_val = str(raw_val)
        return re.compile(raw_val, re.IGNORECASE)

    # 对于 contains, glob, startswith, endswith, exact，支持单个字符串或列表
    if isinstance(raw_val, list):
        items = [str(x).strip() for x in raw_val if str(x).strip()]
    elif isinstance(raw_val, str):
        if mode in ("contains", "endswith"):
            items = [x.strip() for x in re.split(r"[,，\n]+", raw_val) if x.strip()]
        else:
            items = [raw_val.strip()] if raw_val.strip() else []
    else:
        items = [str(raw_val).strip()] if str(raw_val).strip() else []

    if mode == "contains":
        return [(item, item.lower()) for item in items]
    elif mode == "glob":
        return [(g, _glob_to_regex(g)) for g in items]
    elif mode == "startswith":
        return [(item, item.lower()) for item in items]
    elif mode == "endswith":
        return [(item, item.lower()) for item in items]
    elif mode == "exact":
        return [(item, item.strip().lower()) for item in items]
    raise ValueError(f"Unknown match mode: {mode}")


def _eval_matcher_raw(field_val: str, mode: str, compiled_data: Any) -> tuple[bool, str]:
    if not field_val:
        return False, ""
    val_lower = field_val.lower()

    if mode == "regex":
        m = compiled_data.search(field_val)
        if m:
            return True, m.group(0)
        return False, ""

    elif mode == "contains":
        for orig, sub in compiled_data:
            idx = val_lower.find(sub)
            if idx != -1:
                return True, field_val[idx:idx + len(sub)]
        return False, ""

    elif mode == "glob":
        for orig, pat in compiled_data:
            if pat.search(field_val):
                return True, field_val
        return False, ""

    elif mode == "startswith":
        for orig, prefix in compiled_data:
            if val_lower.startswith(prefix):
                return True, field_val[:len(prefix)]
        return False, ""

    elif mode == "endswith":
        for orig, suffix in compiled_data:
            if val_lower.endswith(suffix):
                return True, field_val[-len(suffix):]
        return False, ""

    elif mode == "exact":
        val_stripped = val_lower.strip()
        for orig, exact in compiled_data:
            if val_stripped == exact:
                return True, field_val
        return False, ""

    return False, ""


def _eval_matcher(field_val: str, mode: str, compiled_data: Any) -> tuple[bool, str]:
    """对输入文本执行多层规则匹配检测：

    1. 第一层：原始字符串常规快速匹配；
    2. 第二层（借鉴自 DeepAgents 威胁防御）：若包含零宽字符、BiDi 覆盖字符或跨语言同形混淆字，
       进行安全清洗与同形归一化后执行二次穿透检测，彻底防范利用隐蔽字符绕过策略拦截。
    """
    if not field_val:
        return False, ""

    # 第一层：原始字符串首轮匹配
    ok, snip = _eval_matcher_raw(field_val, mode, compiled_data)
    if ok:
        return True, snip

    # 第二层：零宽字符与同形异义字安全清洗穿透检测
    sanitized = sanitize_for_security_matching(field_val)
    if sanitized and sanitized != field_val:
        ok_s, snip_s = _eval_matcher_raw(sanitized, mode, compiled_data)
        if ok_s:
            return True, f"{snip_s} (已触发防零宽/同形字符混淆绕过拦截)"

    return False, ""


@dataclass
class _CompiledMatcher:
    field: str
    mode: str
    raw_key: str
    raw_val: Any
    compiled: Any


@dataclass
class _Rule:
    id: str
    when: dict[str, Any]
    matchers: list[_CompiledMatcher]
    raw_match: dict[str, Any] = field(default_factory=dict)
    severity: str = "warn"
    reason: str = ""
    file_name: str = ""


class RuleEngine:
    def __init__(self, rules_dir: Path):
        self.rules_dir = rules_dir
        self.rules: list[_Rule] = []
        self._lock = threading.RLock()
        self.load()

    def load(self) -> None:
        with self._lock:
            rules: list[_Rule] = []
            if not self.rules_dir.exists():
                self.rules_dir.mkdir(parents=True, exist_ok=True)
                self.rules = []
                return
            for yml in sorted(self.rules_dir.glob("*.yml")):
                try:
                    raw = yaml.safe_load(yml.read_text(encoding="utf-8")) or []
                except Exception:
                    continue
                if not isinstance(raw, list):
                    continue
                for item in raw:
                    if not isinstance(item, dict) or "id" not in item:
                        continue
                    try:
                        match_cfg = item.get("match", {})
                        matchers: list[_CompiledMatcher] = []
                        raw_match: dict[str, Any] = {}
                        for k, v in match_cfg.items():
                            parsed = _parse_match_key(k)
                            if not parsed:
                                continue
                            field, mode = parsed
                            compiled = _compile_matcher(field, mode, v)
                            matchers.append(_CompiledMatcher(
                                field=field,
                                mode=mode,
                                raw_key=k,
                                raw_val=v,
                                compiled=compiled,
                            ))
                            raw_match[k] = v
                        if matchers:
                            rules.append(_Rule(
                                id=str(item["id"]),
                                when=item.get("when") or {},
                                matchers=matchers,
                                raw_match=raw_match,
                                severity=str(item.get("severity") or "warn"),
                                reason=str(item.get("reason") or ""),
                                file_name=yml.name,
                            ))
                    except Exception:
                        continue
            self.rules = rules

    def reload(self) -> int:
        self.load()
        with self._lock:
            return len(self.rules)

    def list_rules(self) -> list[dict[str, Any]]:
        with self._lock:
            result = []
            for r in self.rules:
                result.append({
                    "id": r.id,
                    "when": r.when,
                    "match": r.raw_match,
                    "severity": r.severity,
                    "reason": r.reason,
                    "file_name": r.file_name,
                })
            return result

    def get_rule(self, rule_id: str) -> dict[str, Any] | None:
        with self._lock:
            for r in self.rules:
                if r.id == rule_id:
                    return {
                        "id": r.id,
                        "when": r.when,
                        "match": r.raw_match,
                        "severity": r.severity,
                        "reason": r.reason,
                        "file_name": r.file_name,
                    }
            return None

    def save_rule(self, rule_data: dict[str, Any], file_name: str | None = None) -> None:
        """保存或新增规则并立即重载生效。支持 contains, glob, startswith, endswith, exact, regex 多种模式。"""
        rule_id = str(rule_data.get("id") or "").strip()
        if not rule_id:
            raise ValueError("规则 ID 不能为空")

        match_cfg = rule_data.get("match") or {}
        if not isinstance(match_cfg, dict) or not match_cfg:
            raise ValueError("必须指定至少一个匹配模式 (match)")

        clean_match: dict[str, Any] = {}
        for k, v in match_cfg.items():
            parsed = _parse_match_key(k)
            if not parsed:
                valid_modes = ", ".join(f"_{m}" for m in _MODES)
                valid_fields = ", ".join(_FIELDS)
                raise ValueError(f"不支持的匹配字段或模式: {k}。必须以 [{valid_modes}] 结尾，且作用字段在 [{valid_fields}] 中")
            field, mode = parsed
            if mode == "regex":
                try:
                    re.compile(str(v), re.IGNORECASE)
                except re.error as e:
                    raise ValueError(f"正则表达式不合法 ({k}): {e}")
                clean_match[k] = str(v)
            elif mode in ("contains", "endswith"):
                if isinstance(v, list):
                    items = [str(x).strip() for x in v if str(x).strip()]
                elif isinstance(v, str):
                    items = [x.strip() for x in re.split(r"[,，\n]+", v) if x.strip()]
                else:
                    items = [str(v).strip()] if str(v).strip() else []
                if not items:
                    raise ValueError(f"匹配内容不能为空: {k}")
                clean_match[k] = items if len(items) > 1 else items[0]
            else: # glob, startswith, exact
                if isinstance(v, list):
                    items = [str(x).strip() for x in v if str(x).strip()]
                    if not items:
                        raise ValueError(f"匹配内容不能为空: {k}")
                    clean_match[k] = items if len(items) > 1 else items[0]
                else:
                    val_str = str(v).strip()
                    if not val_str:
                        raise ValueError(f"匹配内容不能为空: {k}")
                    clean_match[k] = val_str

        rule_entry = {
            "id": rule_id,
            "when": rule_data.get("when") or {},
            "match": clean_match,
            "severity": str(rule_data.get("severity") or "warn").lower(),
            "reason": str(rule_data.get("reason") or "").strip(),
        }

        with self._lock:
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            target_path: Path | None = None
            if file_name:
                target_path = self.rules_dir / file_name
            else:
                for r in self.rules:
                    if r.id == rule_id and r.file_name:
                        target_path = self.rules_dir / r.file_name
                        break

            if not target_path:
                target_path = self.rules_dir / "custom_rules.yml"

            existing_items: list[dict[str, Any]] = []
            if target_path.exists():
                try:
                    loaded = yaml.safe_load(target_path.read_text(encoding="utf-8"))
                    if isinstance(loaded, list):
                        existing_items = loaded
                except Exception:
                    existing_items = []

            found = False
            for i, item in enumerate(existing_items):
                if isinstance(item, dict) and str(item.get("id")) == rule_id:
                    existing_items[i] = rule_entry
                    found = True
                    break
            if not found:
                existing_items.append(rule_entry)

            target_path.write_text(
                yaml.dump(existing_items, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            self.load()

    def delete_rule(self, rule_id: str) -> bool:
        """删除指定规则并立即重载生效。"""
        with self._lock:
            deleted = False
            for yml in sorted(self.rules_dir.glob("*.yml")):
                try:
                    loaded = yaml.safe_load(yml.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if not isinstance(loaded, list):
                    continue

                new_list = [item for item in loaded if not (isinstance(item, dict) and str(item.get("id")) == rule_id)]
                if len(new_list) != len(loaded):
                    yml.write_text(
                        yaml.dump(new_list, allow_unicode=True, sort_keys=False),
                        encoding="utf-8",
                    )
                    deleted = True
                    break

            if deleted:
                self.load()
            return deleted

    @staticmethod
    def _when_matches(rule: _Rule, rec: EventRecord) -> bool:
        for k, expected in rule.when.items():
            actual = getattr(rec, k, None)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True

    def evaluate(self, rec: EventRecord) -> list[RuleHit]:
        with self._lock:
            hits: list[RuleHit] = []
            for rule in self.rules:
                if not self._when_matches(rule, rec):
                    continue
                snippet = ""
                all_ok = True
                for m in rule.matchers:
                    value = getattr(rec, m.field, None) or ""
                    ok, snip = _eval_matcher(value, m.mode, m.compiled)
                    if not ok:
                        all_ok = False
                        break
                    if snip:
                        snippet = snip
                if all_ok and rule.matchers:
                    hits.append(RuleHit(
                        source="engine",
                        rule_id=rule.id,
                        severity=rule.severity,
                        matched=snippet[:500],
                        meta={"reason": rule.reason},
                    ))
            return hits
