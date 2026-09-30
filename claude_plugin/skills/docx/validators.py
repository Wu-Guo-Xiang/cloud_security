"""敏感数据校验位算法（luhn / id_card_loose / id_card_checksum）。"""
from __future__ import annotations

from datetime import datetime


def luhn(card_number: str) -> bool:
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 12:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


_ID_CARD_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CARD_CHECK = ("1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2")


def _id_card_format_ok(s: str) -> bool:
    if len(s) != 18:
        return False
    if not s[:17].isdigit():
        return False
    if not (s[17].isdigit() or s[17] in "Xx"):
        return False
    if s[0] == "0":
        return False
    year = s[6:10]
    if year[:2] not in ("18", "19", "20"):
        return False
    try:
        datetime.strptime(s[6:14], "%Y%m%d")
    except ValueError:
        return False
    return True


def id_card_checksum(id_number: str) -> bool:
    s = id_number.strip().upper()
    if not _id_card_format_ok(s):
        return False
    total = sum(int(s[i]) * _ID_CARD_WEIGHTS[i] for i in range(17))
    return _ID_CARD_CHECK[total % 11] == s[17]


def id_card_loose(id_number: str) -> bool:
    return _id_card_format_ok(id_number.strip().upper())


_VALIDATORS = {
    "luhn": luhn,
    "id_card_checksum": id_card_checksum,
    "id_card_loose": id_card_loose,
}


def validate(validator_name: str, value: str) -> bool:
    fn = _VALIDATORS.get(validator_name)
    if fn is None:
        return True
    return fn(value)
