"""normalize.py 单元测试 —— 覆盖 Step 4 新增的 URL decode 分支,
以及既有的零宽 / bidi / NFKC / base64 append 路径。

跑法：
    py -3 scripts/input/tests/test_normalize.py

注意:所有会触发 STRONG 凭证匹配的 payload 都用字符串拼接构造,并且
本文件的注释/文档字符串里禁止出现"URL 编码的凭证",否则 Step 4 的
URL decode 一跑就会自我拦截。
"""
from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

_INPUT_DIR = Path(__file__).resolve().parent.parent
if str(_INPUT_DIR) not in sys.path:
    sys.path.insert(0, str(_INPUT_DIR))

from extractors.normalize import normalize  # noqa: E402


def _akia_plain() -> str:
    return "AKIA" + "IOSFODNN7EXAMPLE"


def _akia_b64() -> str:
    return base64.b64encode(_akia_plain().encode()).decode()


def _akia_percent_49() -> str:
    return "AKIA" + "%" + "49" + "OSFODNN7EXAMPLE"


def _akia_all_percent() -> str:
    return "%41%4B" + "%49%41" + "%49" + "%4F%53%46%4F%44%4E%4E%37%45%58%41%4D%50%4C%45"


class TestNormalize(unittest.TestCase):
    def test_empty(self):
        r = normalize("")
        self.assertEqual(r.text, "")
        self.assertFalse(r.changed)

    def test_plain_ascii_unchanged(self):
        r = normalize("hello world")
        self.assertEqual(r.text, "hello world")
        self.assertEqual(r.transforms, ())

    def test_strip_zero_width(self):
        s = "AK" + chr(0x200B) + "IA"
        r = normalize(s)
        self.assertIn("strip_zero_width", r.transforms)
        self.assertEqual(r.text, "AKIA")

    def test_strip_unicode_tag(self):
        s = "hi" + chr(0xE0041) + "!"
        r = normalize(s)
        self.assertIn("strip_unicode_tag", r.transforms)
        self.assertNotIn(chr(0xE0041), r.text)

    def test_strip_bidi(self):
        s = "abc" + chr(0x202E) + "def"
        r = normalize(s)
        self.assertIn("strip_bidi_control", r.transforms)
        self.assertEqual(r.text, "abcdef")

    def test_nfkc(self):
        s = "ＡKIA"
        r = normalize(s)
        self.assertIn("nfkc", r.transforms)
        self.assertTrue(r.text.startswith("AKIA"))

    def test_base64_append(self):
        s = "token: " + _akia_b64()
        r = normalize(s)
        self.assertTrue(any(t.startswith("decoded_base64") for t in r.transforms))
        self.assertIn(_akia_plain(), r.text)
        self.assertIn(_akia_b64(), r.text)

    def test_base64_binary_noise_skipped(self):
        raw = bytes(range(20))
        s = "noise: " + base64.b64encode(raw).decode()
        r = normalize(s)
        self.assertFalse(any(t.startswith("decoded_base64") for t in r.transforms))

    def test_url_decode_append(self):
        s = "url=" + _akia_percent_49()
        r = normalize(s)
        self.assertIn("decoded_url", r.transforms)
        self.assertIn(_akia_percent_49(), r.text)
        self.assertIn(_akia_plain(), r.text)
        self.assertIn("[[DECODED_URL]]", r.text)

    def test_url_decode_no_percent_untouched(self):
        s = "no percent here"
        r = normalize(s)
        self.assertNotIn("decoded_url", r.transforms)

    def test_url_decode_all_encoded(self):
        s = _akia_all_percent()
        r = normalize(s)
        self.assertIn("decoded_url", r.transforms)
        self.assertIn(_akia_plain(), r.text)

    def test_url_decode_invalid_percent_survives(self):
        s = "abc %ZZ def"
        r = normalize(s)
        self.assertNotIn("decoded_url", r.transforms)

    def test_url_decode_non_utf8_bytes_replace(self):
        s = "x=%FF%FE"
        r = normalize(s)
        self.assertIn("decoded_url", r.transforms)

    def test_combined_zwsp_and_url(self):
        s = "K=AK" + chr(0x200B) + "IA" + "%" + "49" + "OSFODNN7EXAMPLE"
        r = normalize(s)
        self.assertIn("strip_zero_width", r.transforms)
        self.assertIn("decoded_url", r.transforms)
        self.assertIn(_akia_plain(), r.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
