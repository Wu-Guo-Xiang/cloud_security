"""session_cache 单元测试。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cache.session_cache import SessionCache, build_cache_key  # noqa: E402


def _fresh(session_id: str) -> SessionCache:
    cache = SessionCache(session_id)
    if cache.path.exists():
        cache.path.unlink()
    cache = SessionCache(session_id)
    return cache


def test_put_then_get():
    c = _fresh("sess_unit_put_get")
    c.put_scan("k1", {"matches": [], "ran_detectors": ["x"]})
    c.save()
    c2 = SessionCache("sess_unit_put_get")
    assert c2.get_scan("k1") == {"matches": [], "ran_detectors": ["x"]}
    c2.path.unlink(missing_ok=True)


def test_get_miss_returns_none():
    c = _fresh("sess_unit_miss")
    assert c.get_scan("nothing") is None
    c.path.unlink(missing_ok=True)


def test_empty_key_no_store():
    c = _fresh("sess_unit_empty_key")
    c.put_scan("", {"x": 1})
    assert c.get_scan("") is None
    c.path.unlink(missing_ok=True)


def test_safe_session_id_filters_traversal():
    c = SessionCache("../evil/../path")
    from config.paths import paths
    assert str(c.path).startswith(str(paths.session_cache))


def test_build_cache_key_format():
    key = build_cache_key("a" * 32, "rules_v1", "wordlib_v1")
    assert key == "a" * 16 + "|rules_v1|wordlib_v1"


def test_build_cache_key_with_llm_version():
    key = build_cache_key("a" * 32, "r", "w", llm_version="L")
    assert key == "a" * 16 + "|r|w|L"


def test_build_cache_key_empty():
    assert build_cache_key("", "x", "y") == ""


TESTS = [
    test_put_then_get,
    test_get_miss_returns_none,
    test_empty_key_no_store,
    test_safe_session_id_filters_traversal,
    test_build_cache_key_format,
    test_build_cache_key_with_llm_version,
    test_build_cache_key_empty,
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
