"""llm_detector 单元测试。

只测纯函数部分（calibrate / extract_items / entities_to_matches / mask）。
真实 HTTP 调用走 smoke 测试，不在这里跑。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detectors.llm_detector import (  # noqa: E402
    LLMEntity,
    _calibrate_entities,
    _entities_to_matches,
    _extract_items,
    _mask,
    detect,
)


def test_extract_items_handles_dict_entities_key():
    items = _extract_items({"entities": [{"text": "A", "type": "COMPANY"}]})
    assert items == [{"text": "A", "type": "COMPANY"}]


def test_extract_items_handles_dict_data_key():
    items = _extract_items({"data": [{"text": "A", "type": "PERSON"}]})
    assert items == [{"text": "A", "type": "PERSON"}]


def test_extract_items_handles_top_level_list():
    items = _extract_items([{"text": "A", "type": "COMPANY"}])
    assert items == [{"text": "A", "type": "COMPANY"}]


def test_extract_items_unknown_shape_returns_empty():
    assert _extract_items({"foo": "bar"}) == []
    assert _extract_items(None) == []
    assert _extract_items(42) == []


def test_calibrate_locates_text_position_in_original():
    parsed = {"entities": [
        {"text": "腾讯", "type": "COMPANY", "start": 99},  # start hint 错误，应被忽略
    ]}
    original = "今天腾讯发布新品"
    ents = _calibrate_entities(parsed, original)
    assert len(ents) == 1
    assert ents[0].text == "腾讯"
    assert ents[0].start == 2 and ents[0].end == 4


def test_calibrate_finds_all_occurrences_of_same_text():
    parsed = {"entities": [{"text": "腾讯", "type": "COMPANY"}]}
    original = "腾讯说腾讯赢了"
    ents = _calibrate_entities(parsed, original)
    assert len(ents) == 2
    assert (ents[0].start, ents[0].end) == (0, 2)
    assert (ents[1].start, ents[1].end) == (3, 5)


def test_calibrate_drops_hallucinated_text():
    parsed = {"entities": [{"text": "不存在的公司", "type": "COMPANY"}]}
    ents = _calibrate_entities(parsed, "今天天气很好")
    assert ents == []


def test_calibrate_drops_unknown_type():
    parsed = {"entities": [{"text": "A", "type": "UNKNOWN_TYPE"}]}
    ents = _calibrate_entities(parsed, "A是A")
    assert ents == []


def test_calibrate_normalizes_type_to_upper():
    parsed = {"entities": [{"text": "腾讯", "type": "company"}]}
    ents = _calibrate_entities(parsed, "腾讯")
    assert len(ents) == 1
    assert ents[0].type == "COMPANY"


def test_calibrate_dedupes_overlapping_spans():
    """同一 (start, end) 被多次给出 → 仅保留一份。"""
    parsed = {"entities": [
        {"text": "腾讯", "type": "COMPANY"},
        {"text": "腾讯", "type": "COMPANY"},
    ]}
    ents = _calibrate_entities(parsed, "腾讯")
    assert len(ents) == 1


def test_calibrate_password_filtered_in_default_mode():
    """PASSWORD 是 ups_only 类目，default mode 下白名单不包含它 → 即使模型吐出也被丢弃。

    避免 Read 路径上模型偶然把代码注释里的"密码"识别出来污染脱敏结果。
    """
    parsed = {"entities": [{"text": "Abc123!@#", "type": "PASSWORD"}]}
    ents = _calibrate_entities(parsed, "我的密码是 Abc123!@#")
    assert ents == []


def test_calibrate_password_accepted_in_ups_mode():
    """PASSWORD 在 ups mode 白名单内 → 应被识别并校准。"""
    parsed = {"entities": [{"text": "Abc123!@#", "type": "PASSWORD"}]}
    ents = _calibrate_entities(parsed, "我的密码是 Abc123!@#", mode="ups")
    assert len(ents) == 1
    assert ents[0].type == "PASSWORD"
    assert ents[0].text == "Abc123!@#"


def test_prompt_system_overlay_for_ups_mode():
    """llm_config.prompt_system(mode='ups') 应返回 system_ups（含 PASSWORD 说明）。"""
    from config.llm import llm_config
    sys_default = llm_config.prompt_system(mode="default")
    sys_ups = llm_config.prompt_system(mode="ups")
    # default 不应提到 PASSWORD 类型枚举
    assert "PASSWORD" not in sys_default
    # ups 应包含 PASSWORD 类目及典型示例语义
    assert "PASSWORD" in sys_ups
    assert "口令" in sys_ups or "密码" in sys_ups


def test_entities_to_matches_aggregates_by_type():
    ents = [
        LLMEntity("腾讯", "COMPANY", 0, 2),
        LLMEntity("字节", "COMPANY", 3, 5),
        LLMEntity("张三", "PERSON", 6, 8),
    ]
    matches = _entities_to_matches(ents)
    assert {m.data_class: m.count for m in matches} == {"company": 2, "person": 1}


def test_mask_short_and_long():
    assert _mask("ab") == "**"
    assert _mask("abcd") == "a**d"
    assert _mask("abcdefg") == "ab***g"


def test_detect_empty_text_returns_ok_no_entities():
    res = detect("")
    assert res.ok is True
    assert res.entities == ()
    assert res.matches == ()


def test_detect_with_llm_disabled_returns_disabled_error():
    """临时把 llm_config.enabled 切到 False，断言 detect() 立即短路返回 disabled。

    解耦 llm.yml 当前的实际配置 —— 实际管线通常 enabled=true，
    这条测试只验证"禁用"分支的语义，不应被全局配置影响。
    """
    from config.llm import llm_config
    original = llm_config.enabled
    # LLMConfig 是 frozen dataclass —— 用 object.__setattr__ 绕过冻结校验
    object.__setattr__(llm_config, "enabled", False)
    try:
        res = detect("腾讯科技投资字节跳动")
    finally:
        object.__setattr__(llm_config, "enabled", original)
    assert res.ok is False
    assert "disabled" in res.error or res.error == "llm_disabled"


TESTS = [
    test_extract_items_handles_dict_entities_key,
    test_extract_items_handles_dict_data_key,
    test_extract_items_handles_top_level_list,
    test_extract_items_unknown_shape_returns_empty,
    test_calibrate_locates_text_position_in_original,
    test_calibrate_finds_all_occurrences_of_same_text,
    test_calibrate_drops_hallucinated_text,
    test_calibrate_drops_unknown_type,
    test_calibrate_normalizes_type_to_upper,
    test_calibrate_dedupes_overlapping_spans,
    test_calibrate_password_filtered_in_default_mode,
    test_calibrate_password_accepted_in_ups_mode,
    test_prompt_system_overlay_for_ups_mode,
    test_entities_to_matches_aggregates_by_type,
    test_mask_short_and_long,
    test_detect_empty_text_returns_ok_no_entities,
    test_detect_with_llm_disabled_returns_disabled_error,
]


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    passed = failed = 0
    for t in TESTS:
        try:
            t()
            print(f"[OK]   {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {t.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERR]  {t.__name__}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n用例总数: {len(TESTS)} | 通过: {passed} | 失败: {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
