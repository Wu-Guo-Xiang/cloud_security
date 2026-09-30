"""credential_detector 单元测试。

覆盖 fatal 类目 + db_connection：
  - AWS / GitHub / OpenAI / Bearer / JWT API key 形态
  - RSA / OPENSSH 私钥 PEM 头
  - prod_password 各种赋值写法 + 长度/复杂度要求
  - JDBC / postgres / mysql / mongodb 连接串
  - 干净文本不命中（误报检查）
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detectors.credential_detector import detect  # noqa: E402


def _classes(matches):
    return {m.data_class for m in matches}


def _count(matches, class_name):
    for m in matches:
        if m.data_class == class_name:
            return m.count
    return 0


# --- api_key ---------------------------------------------------------

def test_aws_access_key_detected():
    matches = detect("token=AKIAIOSFODNN7EXAMPLE done.")
    assert "api_key" in _classes(matches)


def test_github_pat_detected():
    matches = detect("ghp_aB3cDe4FgHi5JkLm6NoPq7RsTu8VwXyZ9012")
    assert "api_key" in _classes(matches)


def test_openai_sk_key_detected():
    matches = detect("OPENAI_API_KEY=sk-abc12345xyz67890ABCDefghijklm")
    assert "api_key" in _classes(matches)


def test_bearer_token_detected():
    matches = detect("Authorization: Bearer eyJabc123xyzDEFghi789jkLMNoP")
    # bearer 也会匹配 JWT 子模式之一
    assert "api_key" in _classes(matches)


def test_jwt_detected():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB92K27u"
    matches = detect(f"token={jwt}")
    assert "api_key" in _classes(matches)


# --- private_key -----------------------------------------------------

def test_rsa_private_key_header_detected():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ..."
    matches = detect(text)
    assert "private_key" in _classes(matches)


def test_openssh_private_key_header_detected():
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\nblabla"
    matches = detect(text)
    assert "private_key" in _classes(matches)


# --- prod_password ---------------------------------------------------

def test_password_assignment_detected():
    matches = detect('password = "ProdAdmin#2024"')
    assert "prod_password" in _classes(matches)


def test_password_colon_form_detected():
    matches = detect('passwd: My$ecret123')
    assert "prod_password" in _classes(matches)


def test_password_short_not_detected():
    # 长度不够（< 8）不命中
    matches = detect("password=abc1")
    assert "prod_password" not in _classes(matches)


def test_password_no_digit_not_detected():
    # 缺数字与符号 → 不命中（降低误报）
    matches = detect("password=onlyletters")
    assert "prod_password" not in _classes(matches)


# --- db_connection ---------------------------------------------------

def test_postgres_url_detected():
    matches = detect("DB=postgres://user:pwd@db.internal:5432/app")
    assert "db_connection" in _classes(matches)


def test_jdbc_url_detected():
    matches = detect("conn=jdbc:mysql://localhost:3306/mydb")
    assert "db_connection" in _classes(matches)


def test_mongodb_srv_detected():
    matches = detect("uri=mongodb+srv://u:p@cluster.example.com/db")
    assert "db_connection" in _classes(matches)


# --- 清洁文本 --------------------------------------------------------

def test_clean_text_no_credentials():
    matches = detect("今天天气很好，我们去散步吧。文档说明：https://docs.python.org/3/")
    assert _classes(matches) == set()


def test_multiple_credentials_count_aggregates():
    text = "AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPL2"
    matches = detect(text)
    assert _count(matches, "api_key") >= 2


# --- 样本脱敏 --------------------------------------------------------

def test_samples_are_masked():
    matches = detect("AKIAIOSFODNN7EXAMPLE")
    for m in matches:
        for s in m.samples:
            assert "***" in s  # 不应明文出现完整 key


TESTS = [
    test_aws_access_key_detected,
    test_github_pat_detected,
    test_openai_sk_key_detected,
    test_bearer_token_detected,
    test_jwt_detected,
    test_rsa_private_key_header_detected,
    test_openssh_private_key_header_detected,
    test_password_assignment_detected,
    test_password_colon_form_detected,
    test_password_short_not_detected,
    test_password_no_digit_not_detected,
    test_postgres_url_detected,
    test_jdbc_url_detected,
    test_mongodb_srv_detected,
    test_clean_text_no_credentials,
    test_multiple_credentials_count_aggregates,
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
