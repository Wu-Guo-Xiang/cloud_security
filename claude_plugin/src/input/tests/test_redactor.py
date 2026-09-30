"""redactor 单元测试。

替换形态由 rules.yml 的 mask_strategy 决定；本测试断言保形掩码后的结果，
并兼容"原文不残留"的核心契约。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from actions.redactor import redact  # noqa: E402


def test_redact_phone():
    out, counts = redact("联系我 13800138000")
    assert "138****8000" in out
    assert "13800138000" not in out
    assert counts["phone"] == 1


def test_redact_email_and_phone():
    out, counts = redact("phone 13800138000, mail abc@b.com")
    assert "138****8000" in out
    assert "a***@b.com" in out
    assert counts == {"phone": 1, "email": 1}


def test_redact_api_key():
    out, counts = redact("token=AKIAIOSFODNN7EXAMPLE")
    # AKIA + 12*'*' + MPLE = 20 chars 保形
    assert "AKIA************MPLE" in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    # rules.yml 把 AKIA/ASIA 拆到独立类目 aws_access_key,沿用 api_key 保形掩码
    assert counts.get("aws_access_key", 0) >= 1


def test_redact_id_card_valid_only():
    # loose 模式：结构合规即识别（含 checksum 错的业务测试样本）；
    # 结构非法（出生日期不存在）应保留原文。
    out, counts = redact("好 11010519491231002X 坏 110105199002300017")
    assert "1***************2X" in out
    assert "11010519491231002X" not in out
    assert "110105199002300017" in out  # 非法日期 → 保留
    assert counts.get("id_card", 0) == 1


def test_redact_bank_card_luhn_only():
    out, counts = redact("合法 4111111111111111 非法 4111111111111121")
    assert "4111 **** **** 1111" in out
    assert "4111111111111111" not in out
    assert "4111111111111121" in out
    assert counts.get("bank_card", 0) == 1


def test_redact_bank_card_with_spaces():
    # 带空格分组的合法卡号应整段替换为保形掩码
    out, counts = redact("工资卡 4111 1111 1111 1111 入账")
    assert "4111 **** **** 1111" in out
    assert "4111 1111 1111 1111" not in out
    assert counts.get("bank_card", 0) == 1


def test_redact_internal_ip_full_four_octets():
    # 10.0.5.23 → 10.*.*.* （第 4 段不应残留）
    out, counts = redact("内部服务器：10.0.5.23")
    assert "10.*.*.*" in out
    assert "10.0.5.23" not in out
    assert ".23" not in out
    assert counts.get("internal_ip", 0) == 1


def test_redact_empty_text():
    out, counts = redact("")
    assert out == ""
    assert counts == {}


def test_redact_no_matches():
    src = "今天天气很好"
    out, counts = redact(src)
    assert out == src
    assert counts == {}


def test_redact_overlapping_spans_merge():
    # Bearer 前缀同时被 bearer 与 jwt 模式命中 → 合并为一个 span，
    # 用 api_key 策略保形掩码（保前 4 后 4）
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB"
    out, counts = redact(text)
    assert "Bearer eyJhbGciOiJIUzI1NiJ9" not in out
    assert "dBjftJeZ4CVPmB" not in out
    assert counts.get("api_key", 0) == 1
    assert "Bear" in out and "VPmB" in out  # 前后缀保留


def test_redact_preserves_surrounding_text():
    src = "前缀 13800138000 后缀"
    out, _ = redact(src)
    assert out.startswith("前缀 ")
    assert out.endswith(" 后缀")


def test_redact_chinese_adjacent_to_digits():
    """中文汉字直接挨着数字/字母时，L1 正则必须仍然命中。

    回归点：YAML 里的 `\\b` 在 Python re Unicode 模式下，汉字（CJK 属于 Lo）
    被算作 \\w，相邻数字时不存在 word boundary → \\b1...\\b 不匹中。
    rules.yml 改用 (?<!...) / (?!...) 负向断言后才能命中此场景。
    """
    src = (
        "手机13800138000邮箱abc@x.com身份证11010519491231002X，"
        "工号PYT123服务器10.20.30.40。"
    )
    out, counts = redact(src)
    assert "138****8000" in out, f"phone 未命中: {out}"
    assert "a***@x.com" in out, f"email 未命中: {out}"
    assert "1***************2X" in out, f"id_card 未命中: {out}"
    assert "PYT***" in out or "P***" in out, f"employee_id 未命中: {out}"
    assert "10.*.*.*" in out, f"internal_ip 未命中: {out}"
    assert "13800138000" not in out
    assert "abc@x.com" not in out
    assert "11010519491231002X" not in out
    assert "10.20.30.40" not in out
    assert counts.get("phone", 0) == 1
    assert counts.get("email", 0) == 1
    assert counts.get("id_card", 0) == 1
    assert counts.get("internal_ip", 0) == 1


TESTS = [
    test_redact_phone,
    test_redact_email_and_phone,
    test_redact_api_key,
    test_redact_id_card_valid_only,
    test_redact_bank_card_luhn_only,
    test_redact_bank_card_with_spaces,
    test_redact_internal_ip_full_four_octets,
    test_redact_empty_text,
    test_redact_no_matches,
    test_redact_overlapping_spans_merge,
    test_redact_preserves_surrounding_text,
    test_redact_chinese_adjacent_to_digits,
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
