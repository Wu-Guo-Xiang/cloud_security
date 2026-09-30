"""pseudonymizer 单元测试（L1 + L2 合并替换）。"""
from __future__ import annotations

import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from actions.pseudonymizer import pseudonymize  # noqa: E402
from cache.entity_map import EntityMap  # noqa: E402
from cache.session_cache import SessionCache  # noqa: E402


@dataclass(frozen=True)
class _FakeEntity:
    """duck-type 替代 LLMEntity。pseudonymizer 只读 text/type/start/end。"""
    text: str
    type: str
    start: int
    end: int


_CREATED: list[SessionCache] = []


def _entity_map() -> EntityMap:
    sid = f"sess_ps_test_{uuid.uuid4().hex[:10]}"
    cache = SessionCache(sid)
    if cache.path.exists():
        cache.path.unlink()
    cache = SessionCache(sid)
    _CREATED.append(cache)
    return EntityMap(cache)


def _cleanup() -> None:
    for c in _CREATED:
        try:
            c.path.unlink(missing_ok=True)
        except Exception:
            pass


def test_l1_only_replaces_with_uppercase_placeholder():
    """L1 phone：现在按 mask_strategy=mobile_phone 走保形掩码。"""
    em = _entity_map()
    text = "联系 13800138000"
    out, counts = pseudonymize(text, [(3, 14, "phone")], [], em)
    assert out == "联系 138****8000"
    assert counts == {"138****8000": 1}


def test_l2_only_uses_consistent_chinese_placeholder():
    em = _entity_map()
    text = "腾讯科技投资了字节跳动"
    out, counts = pseudonymize(text, [], [
        _FakeEntity("腾讯科技", "COMPANY", 0, 4),
        _FakeEntity("字节跳动", "COMPANY", 7, 11),
    ], em)
    assert "[公司A]" in out and "[公司B]" in out
    assert counts == {"[公司A]": 1, "[公司B]": 1}


def test_same_l2_entity_repeated_uses_same_placeholder():
    em = _entity_map()
    text = "腾讯说腾讯赢了"
    out, counts = pseudonymize(text, [], [
        _FakeEntity("腾讯", "COMPANY", 0, 2),
        _FakeEntity("腾讯", "COMPANY", 3, 5),
    ], em)
    assert out.count("[公司A]") == 2
    assert counts == {"[公司A]": 2}


def test_l1_overrides_overlapping_l2():
    """L1 优先级高于 L2：手机号区间被 L2 覆盖，仍按 L1 策略掩码。"""
    em = _entity_map()
    text = "客户 13800138000 张总"
    # L1: phone @ 3..14, L2: 把 13800138000 误判为 PERSON
    out, counts = pseudonymize(
        text,
        [(3, 14, "phone")],
        [_FakeEntity("13800138000", "PERSON", 3, 14)],
        em,
    )
    assert "138****8000" in out
    assert "[人员A]" not in out
    assert counts == {"138****8000": 1}


def test_money_entity_uses_fixed_placeholder():
    em = _entity_map()
    text = "本次成交 3.5亿元，分期 1200万"
    out, _ = pseudonymize(text, [], [
        _FakeEntity("3.5亿", "MONEY", 5, 9),
        _FakeEntity("1200万", "MONEY", 14, 19),
    ], em)
    assert out.count("[金额]") == 2


def test_empty_text_short_circuits():
    em = _entity_map()
    out, counts = pseudonymize("", [], [], em)
    assert out == ""
    assert counts == {}


def test_no_spans_returns_text_unchanged():
    em = _entity_map()
    out, counts = pseudonymize("hello world", [], [], em)
    assert out == "hello world"
    assert counts == {}


def test_overlapping_l2_spans_keep_first_longer():
    """同起点 L2 实体：保留较长那个。"""
    em = _entity_map()
    text = "腾讯科技股份有限公司今天发布"
    out, _ = pseudonymize(text, [], [
        _FakeEntity("腾讯科技股份有限公司", "COMPANY", 0, 10),
        _FakeEntity("腾讯科技", "COMPANY", 0, 4),
    ], em)
    # 短的被长的吸收
    assert out.startswith("[公司A]") or out.startswith("[公司")


def test_l1_l2_disjoint_spans_both_applied():
    em = _entity_map()
    text = "腾讯负责人是 13800138000"
    # 手机号在文本中的实际位置：'腾讯负责人是 '(7 chars) + '13800138000'(11 chars) → 7..18
    out, counts = pseudonymize(
        text,
        [(7, 18, "phone")],
        [_FakeEntity("腾讯", "COMPANY", 0, 2)],
        em,
    )
    assert "[公司A]" in out and "138****8000" in out
    assert counts == {"[公司A]": 1, "138****8000": 1}


def test_id_number_uses_id_mask_not_placeholder():
    """ID_NUMBER 走 id_number 保形掩码，不进 entity_map 分配序号。"""
    em = _entity_map()
    text = "对公账户 6222021234567890123 用于结算"
    out, counts = pseudonymize(
        text,
        [],
        [_FakeEntity("6222021234567890123", "ID_NUMBER", 5, 24)],
        em,
    )
    assert "6222***********0123" in out
    assert "[号码A]" not in out
    assert "6222021234567890123" not in out
    assert counts == {"6222***********0123": 1}


def test_product_uses_placeholder_by_default():
    """PRODUCT 默认仍走顺序占位符（语义化产品名比掩码更可读）。"""
    em = _entity_map()
    text = "我们采购了灵犀云图 3.0"
    out, _ = pseudonymize(
        text,
        [],
        [_FakeEntity("灵犀云图 3.0", "PRODUCT", 5, 13)],
        em,
    )
    assert "[产品A]" in out


def test_id_number_same_text_each_time_still_consistent():
    """同字面 ID_NUMBER 反复出现，因为掩码是确定函数，输出仍然一致。"""
    em = _entity_map()
    text = "编号 INV20260318 与 INV20260318 是同一份"
    out, _ = pseudonymize(
        text,
        [],
        [
            _FakeEntity("INV20260318", "ID_NUMBER", 3, 14),
            _FakeEntity("INV20260318", "ID_NUMBER", 17, 28),
        ],
        em,
    )
    # 两处掩码完全相同
    assert out.count("INV2***0318") == 2


def test_password_entity_uses_password_mask():
    """PASSWORD 走 mask_strategies.password：保形掩码，保留首尾。

    PASSWORD 只在 UPS 路径被识别（detector 白名单），但 pseudonymizer 是后段，
    无 mode 概念 —— 只要拿到 PASSWORD 实体就按 password 策略掩码。
    """
    em = _entity_map()
    text = "我的密码是 Abc123!@#"
    out, counts = pseudonymize(
        text,
        [],
        [_FakeEntity("Abc123!@#", "PASSWORD", 6, 15)],
        em,
    )
    assert "Abc123!@#" not in out
    # 9 位 → 首尾各 1 位
    assert "A*******#" in out
    assert counts == {"A*******#": 1}


TESTS = [
    test_l1_only_replaces_with_uppercase_placeholder,
    test_l2_only_uses_consistent_chinese_placeholder,
    test_same_l2_entity_repeated_uses_same_placeholder,
    test_l1_overrides_overlapping_l2,
    test_money_entity_uses_fixed_placeholder,
    test_empty_text_short_circuits,
    test_no_spans_returns_text_unchanged,
    test_overlapping_l2_spans_keep_first_longer,
    test_l1_l2_disjoint_spans_both_applied,
    test_id_number_uses_id_mask_not_placeholder,
    test_product_uses_placeholder_by_default,
    test_id_number_same_text_each_time_still_consistent,
    test_password_entity_uses_password_mask,
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
    _cleanup()
    print(f"\n用例总数: {len(TESTS)} | 通过: {passed} | 失败: {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
