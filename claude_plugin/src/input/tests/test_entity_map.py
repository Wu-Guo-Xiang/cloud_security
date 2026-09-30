"""EntityMap 单元测试。

聚焦：
  - 同一实体多次 assign → 同一占位符（session 内一致性）
  - 不同实体按 A/B/C 递增
  - MONEY 不分配编号，统一映射 [金额]
  - 编号超 26 → AA/AB 序列
  - 状态正确持久到 SessionCache._data 并存活到下次实例化
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cache.entity_map import EntityMap  # noqa: E402
from cache.session_cache import SessionCache  # noqa: E402


_CREATED_SESSIONS: list[SessionCache] = []


def _fresh_cache() -> SessionCache:
    sid = f"sess_em_test_{uuid.uuid4().hex[:10]}"
    cache = SessionCache(sid)
    if cache.path.exists():
        cache.path.unlink()
    cache = SessionCache(sid)
    _CREATED_SESSIONS.append(cache)
    return cache


def _cleanup() -> None:
    for c in _CREATED_SESSIONS:
        try:
            c.path.unlink(missing_ok=True)
        except Exception:
            pass


def test_same_text_returns_same_placeholder():
    em = EntityMap(_fresh_cache())
    p1 = em.assign("腾讯科技", "COMPANY", "公司")
    p2 = em.assign("腾讯科技", "COMPANY", "公司")
    assert p1 == p2 == "[公司A]"


def test_different_companies_get_sequential_labels():
    em = EntityMap(_fresh_cache())
    assert em.assign("公司甲", "COMPANY", "公司") == "[公司A]"
    assert em.assign("公司乙", "COMPANY", "公司") == "[公司B]"
    assert em.assign("公司丙", "COMPANY", "公司") == "[公司C]"


def test_money_uses_fixed_placeholder_no_index():
    em = EntityMap(_fresh_cache())
    assert em.assign("3.5亿", "MONEY", "金额") == "[金额]"
    assert em.assign("1200万", "MONEY", "金额") == "[金额]"


def test_per_type_counters_are_independent():
    em = EntityMap(_fresh_cache())
    assert em.assign("张三", "PERSON", "人员") == "[人员A]"
    assert em.assign("腾讯", "COMPANY", "公司") == "[公司A]"
    assert em.assign("李四", "PERSON", "人员") == "[人员B]"


def test_index_overflow_to_double_letters():
    em = EntityMap(_fresh_cache())
    for i in range(27):
        em.assign(f"公司{i}", "COMPANY", "公司")
    assert em.get("公司25") == "[公司Z]"
    assert em.get("公司26") == "[公司AA]"


def test_state_persists_via_cache_save_load():
    cache = _fresh_cache()
    em = EntityMap(cache)
    em.assign("腾讯科技", "COMPANY", "公司")
    em.assign("3亿", "MONEY", "金额")
    cache.save()

    cache2 = SessionCache(cache.session_id)
    em2 = EntityMap(cache2)
    assert em2.get("腾讯科技") == "[公司A]"
    assert em2.get("3亿") == "[金额]"
    assert em2.assign("阿里巴巴", "COMPANY", "公司") == "[公司B]"


def test_snapshot_returns_full_mapping():
    em = EntityMap(_fresh_cache())
    em.assign("腾讯", "COMPANY", "公司")
    em.assign("张三", "PERSON", "人员")
    snap = em.snapshot()
    assert snap == {"腾讯": "[公司A]", "张三": "[人员A]"}


def test_company_alias_merges_to_existing_placeholder():
    em = EntityMap(_fresh_cache())
    full = em.assign("星河智联科技（北京）有限公司", "COMPANY", "公司")
    short = em.assign("星河智联", "COMPANY", "公司")
    assert full == short == "[公司A]"


def test_company_alias_merges_when_short_seen_first():
    em = EntityMap(_fresh_cache())
    short = em.assign("润泽数据", "COMPANY", "公司")
    full = em.assign("润泽数据服务（上海）股份有限公司", "COMPANY", "公司")
    assert short == full == "[公司A]"


def test_company_alias_does_not_merge_below_min_len():
    em = EntityMap(_fresh_cache())
    a = em.assign("国际", "COMPANY", "公司")
    b = em.assign("国际贸易公司", "COMPANY", "公司")
    assert a == "[公司A]" and b == "[公司B]"


def test_person_substring_does_not_merge():
    em = EntityMap(_fresh_cache())
    a = em.assign("张三", "PERSON", "人员")
    b = em.assign("张三丰", "PERSON", "人员")
    assert a == "[人员A]" and b == "[人员B]"


def test_cross_type_substring_does_not_merge():
    em = EntityMap(_fresh_cache())
    a = em.assign("智联未来", "COMPANY", "公司")
    b = em.assign("智联未来Pro", "PRODUCT", "产品")
    assert a == "[公司A]" and b == "[产品A]"


TESTS = [
    test_same_text_returns_same_placeholder,
    test_different_companies_get_sequential_labels,
    test_money_uses_fixed_placeholder_no_index,
    test_per_type_counters_are_independent,
    test_index_overflow_to_double_letters,
    test_state_persists_via_cache_save_load,
    test_snapshot_returns_full_mapping,
    test_company_alias_merges_to_existing_placeholder,
    test_company_alias_merges_when_short_seen_first,
    test_company_alias_does_not_merge_below_min_len,
    test_person_substring_does_not_merge,
    test_cross_type_substring_does_not_merge,
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
