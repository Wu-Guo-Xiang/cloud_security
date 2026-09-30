"""pattern_detector 单元测试。

覆盖：
  - id_card：合法（带 checksum）/ 长度错 / checksum 错
  - phone：13/15/17/18 段
  - email：常见 + 边界
  - bank_card：luhn 通过 / 不通过
  - internal_ip：10/172.16-31/192.168 段
  - 清洁文本不命中
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detectors.pattern_detector import detect  # noqa: E402


def _classes(matches):
    return {m.data_class for m in matches}


def _count(matches, class_name):
    for m in matches:
        if m.data_class == class_name:
            return m.count
    return 0


# --- id_card ---------------------------------------------------------

def test_id_card_valid_detected():
    # 11010519491231002X 合法
    matches = detect("身份证号 11010519491231002X 已校验。")
    assert "id_card" in _classes(matches)


def test_id_card_checksum_fail_but_format_ok_still_detected():
    # 业务测试样本里大量结构合规但 checksum 不过的"假号" —— loose 校验应接受
    matches = detect("身份证号 11010519910407226X、320583198706154213 出现")
    assert _count(matches, "id_card") == 2


def test_id_card_invalid_date_not_detected():
    # 2 月 30 号不存在 → 出生日期校验失败 → 不应命中 id_card
    matches = detect("乱编的号 110105199002300017 不应触发")
    assert "id_card" not in _classes(matches)


def test_id_card_shape_not_misdetected_as_bank_card():
    # 回归：310115199203124628 / 142331198902187428 这类"checksum 失败、Luhn 巧合通过"
    # 的身份证号过去会被错识为 bank_card，新逻辑应让 id_card 接管、bank_card 不命中
    matches = detect(
        "身份证号 310115199203124628 与 142331198902187428 是假样本"
    )
    assert _count(matches, "id_card") == 2
    assert "bank_card" not in _classes(matches)


# --- phone -----------------------------------------------------------

def test_phone_138_detected():
    matches = detect("联系电话 13800138000")
    assert _count(matches, "phone") == 1


def test_phone_177_detected():
    matches = detect("17712345678 是手机号")
    assert _count(matches, "phone") == 1


def test_phone_invalid_prefix_not_detected():
    # 12 开头不是合法手机号
    matches = detect("number 12012345678")
    assert "phone" not in _classes(matches)


# --- email -----------------------------------------------------------

def test_email_detected():
    matches = detect("反馈邮箱：user.name+filter@example.com")
    assert _count(matches, "email") == 1


def test_email_multiple_counts():
    matches = detect("a@b.com c@d.org e@f.net")
    assert _count(matches, "email") == 3


# --- bank_card -------------------------------------------------------

def test_bank_card_luhn_valid_detected():
    matches = detect("卡号 4111111111111111 已校验")
    assert _count(matches, "bank_card") == 1


def test_bank_card_luhn_invalid_not_detected():
    matches = detect("数字串 4111111111111121")
    assert "bank_card" not in _classes(matches)


def test_bank_card_with_spaces_detected():
    # 回归：带空格分组的合法卡号（如 "6225 8100 1234 5679"）应被识别
    matches = detect("工资卡 4111 1111 1111 1111 入账")
    assert _count(matches, "bank_card") == 1


def test_bank_card_with_dashes_detected():
    matches = detect("test 4111-1111-1111-1111 end")
    assert _count(matches, "bank_card") == 1


# --- internal_ip -----------------------------------------------------

def test_internal_ip_10_detected():
    matches = detect("server: 10.20.30.40")
    assert _count(matches, "internal_ip") == 1


def test_internal_ip_10_full_four_octets():
    # 回归 bug：之前 10. 分支只匹配前 3 段，10.0.5.23 会被截成 10.0.5
    matches = detect("server: 10.0.5.23 end")
    assert _count(matches, "internal_ip") == 1
    # 命中样本应包含完整四段（_mask 对长度 <=6 返回 ***，10.0.5.23 长度 9 走 3+2 形态）
    sample = matches[[m.data_class for m in matches].index("internal_ip")].samples[0]
    assert sample.endswith("23")


def test_internal_ip_172_16_detected():
    matches = detect("dev: 172.16.0.1 prod: 172.31.255.254")
    assert _count(matches, "internal_ip") == 2


def test_internal_ip_172_15_not_detected():
    # 172.15 不属于内网段
    matches = detect("外网网关 172.15.0.1")
    assert "internal_ip" not in _classes(matches)


def test_public_ip_not_detected():
    matches = detect("外部地址 8.8.8.8")
    assert "internal_ip" not in _classes(matches)


# --- 清洁文本 --------------------------------------------------------

def test_clean_text_no_matches():
    matches = detect("今天天气晴朗，请帮我总结这段话。")
    assert _classes(matches) == set()


# --- 样本脱敏 --------------------------------------------------------

def test_samples_are_masked():
    matches = detect("13800138000 17712345678")
    for m in matches:
        for s in m.samples:
            # 7 位以下用 *** 兜底；7 位以上保留 3+2 共 5 位明文
            assert "***" in s


TESTS = [
    test_id_card_valid_detected,
    test_id_card_checksum_fail_but_format_ok_still_detected,
    test_id_card_invalid_date_not_detected,
    test_id_card_shape_not_misdetected_as_bank_card,
    test_phone_138_detected,
    test_phone_177_detected,
    test_phone_invalid_prefix_not_detected,
    test_email_detected,
    test_email_multiple_counts,
    test_bank_card_luhn_valid_detected,
    test_bank_card_luhn_invalid_not_detected,
    test_bank_card_with_spaces_detected,
    test_bank_card_with_dashes_detected,
    test_internal_ip_10_detected,
    test_internal_ip_10_full_four_octets,
    test_internal_ip_172_16_detected,
    test_internal_ip_172_15_not_detected,
    test_public_ip_not_detected,
    test_clean_text_no_matches,
    test_samples_are_masked,
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
