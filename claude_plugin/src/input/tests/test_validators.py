"""校验位算法单元测试：luhn / id_card_checksum。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.validators import id_card_checksum, id_card_loose, luhn, validate  # noqa: E402


def test_luhn_visa_valid():
    assert luhn("4111111111111111") is True


def test_luhn_visa_invalid():
    assert luhn("4111111111111121") is False


def test_luhn_too_short():
    assert luhn("12345") is False


def test_luhn_mixed_chars_strip():
    # 含连字符 / 空格仍可正确校验
    assert luhn("4111-1111-1111-1111") is True


def test_id_card_real_valid():
    # 11010519491231002X：常用示例（公开测试数据，非真人）
    assert id_card_checksum("11010519491231002X") is True


def test_id_card_wrong_length():
    assert id_card_checksum("11010519491231002") is False


def test_id_card_wrong_check_digit():
    assert id_card_checksum("110105194912310021") is False


# --- id_card_loose --------------------------------------------------

def test_id_card_loose_accepts_checksum_pass():
    assert id_card_loose("11010519491231002X") is True


def test_id_card_loose_accepts_checksum_fail_but_format_ok():
    # 业务测试样本：结构合规、出生日期合法，但 checksum 不过 —— loose 应接受
    assert id_card_loose("11010519910407226X") is True
    assert id_card_loose("320583198706154213") is True


def test_id_card_loose_rejects_impossible_date():
    # 2 月 30 号不存在 → 出生日期校验失败 → loose 拒绝
    assert id_card_loose("110105199002300017") is False


def test_id_card_loose_rejects_wrong_year_prefix():
    # 年份 17xx：超出 18/19/20 → 拒绝
    assert id_card_loose("110105170102030017") is False


def test_id_card_loose_rejects_leading_zero():
    # 地区码首位 0 → 拒绝
    assert id_card_loose("010105199203124628") is False


def test_id_card_loose_rejects_wrong_length():
    assert id_card_loose("11010519491231002") is False


def test_validate_unknown_passthrough():
    # 未知 validator 视为通过，避免规则配置错误漏报
    assert validate("nonexistent_validator", "anything") is True


def test_validate_dispatches_luhn():
    assert validate("luhn", "4111111111111111") is True
    assert validate("luhn", "4111111111111121") is False


def test_validate_dispatches_id_card_loose():
    assert validate("id_card_loose", "11010519910407226X") is True
    assert validate("id_card_loose", "110105199002300017") is False


TESTS = [
    test_luhn_visa_valid,
    test_luhn_visa_invalid,
    test_luhn_too_short,
    test_luhn_mixed_chars_strip,
    test_id_card_real_valid,
    test_id_card_wrong_length,
    test_id_card_wrong_check_digit,
    test_id_card_loose_accepts_checksum_pass,
    test_id_card_loose_accepts_checksum_fail_but_format_ok,
    test_id_card_loose_rejects_impossible_date,
    test_id_card_loose_rejects_wrong_year_prefix,
    test_id_card_loose_rejects_leading_zero,
    test_id_card_loose_rejects_wrong_length,
    test_validate_unknown_passthrough,
    test_validate_dispatches_luhn,
    test_validate_dispatches_id_card_loose,
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
