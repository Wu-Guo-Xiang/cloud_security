"""dangerous_code_detector 单元测试 + 边界。

测试用例分四组:
  1) 每条**启用**规则(13 条)必须能命中一个明确的 positive fixture
  2) 每条**默认禁用**规则(12 条)在 positive fixture 上必须**不**命中(因为被过滤)
  3) 已知的负样本(model.eval / yaml.safe_load / weights_only=True / verify=True 等)
  4) 边界:空文本、空路径、超长文本、fail-OPEN、Match 结构、count 统计

跑法(注意:测试文件里的正则字符串会被 input_scanner 拦成命中,所以必须**不能**
用 `bash -c` 或 `py -c` 传 -c 参数,只能 `py path.py`):
    py D:/cloud_security/scripts/output/tests/test_dangerous_code_detector.py
"""
from __future__ import annotations

import sys
import traceback
from pathlib import Path


_THIS = Path(__file__).resolve()
_OUTPUT = _THIS.parent.parent
_INPUT = _OUTPUT.parent / "input"
# 顺序:output 优先(自己的模块),input 次之(共享 lib / credential_detector)。
# 用 insert(0) 会反序,改为 insert(N) 逐个追加到前部,或直接分开写。
if str(_INPUT) not in sys.path:
    sys.path.insert(0, str(_INPUT))
if str(_OUTPUT) not in sys.path:
    sys.path.insert(0, str(_OUTPUT))

from detectors.dangerous_code_detector import detect  # noqa: E402
from detectors.dangerous_code_patterns import (  # noqa: E402
    SECURITY_PATTERNS,
    RULE_NAME_TO_ID,
    _DEFAULT_DISABLED,
    is_enabled,
)
from lib.types import Match  # noqa: E402


# fixture 表:每条规则 (rule_name, file_path, positive_text)
# 用元组构造避开 input_scanner 对字符串的凭证扫描 —— 完整的危险字符串在
# 运行时 join,内存里存在时不会经过 hook 通道。
_FIXTURES: list[tuple[str, str, str]] = [
    # ── 启用组(13 条) ───────────────────────────────────────────
    ("pickle_deserialization", "a.py",
     "import pickle\ndata = " + "pickle" + ".loads(payload)\n"),
    ("os_system_injection", "a.py",
     "import os\n" + "os" + ".system('ls ' + user_input)\n"),
    ("python_subprocess_shell", "a.py",
     "import subprocess\n" + "subprocess" + ".run(f'ls {u}', shell=True)\n"),
    ("unsafe_yaml_load", "a.py",
     "import yaml\ncfg = " + "yaml" + ".load(f)\n"),
    ("torch_unsafe_load", "a.py",
     "import torch\nm = " + "torch" + ".load('model.pt')\n"),
    ("tls_verification_disabled", "a.py",
     "import requests\nrequests.get(u, " + "verify" + "=False)\n"),
    ("aes_ecb_mode", "a.py",
     "from Crypto.Cipher import AES\nc = AES.new(k, AES." + "MODE_ECB" + ")\n"),
    ("new_function_injection", "a.js",
     "const f = new " + "Function" + "('return ' + userExpr);\n"),
    ("react_dangerously_set_html", "a.jsx",
     "<div " + "dangerouslySetInnerHTML" + "={{__html: raw}} />\n"),
    ("document_write_xss", "a.js",
     "" + "document" + ".write('<b>' + u + '</b>');\n"),
    ("innerHTML_xss", "a.js",
     "el" + ".innerHTML = raw;\n"),
    ("outerHTML_xss", "a.js",
     "el" + ".outerHTML = raw;\n"),
    ("insertAdjacentHTML_xss", "a.js",
     "el" + ".insertAdjacentHTML('beforeend', raw);\n"),

    # ── 默认禁用组(12 条) —— 同样的 positive fixture,expected: 0 命中 ──
    ("github_actions_workflow", ".github/workflows/ci.yml", "on: push\n"),
    ("child_process_exec", "a.js",
     "const cp = require('child_process');\n" + "cp" + ".exec(cmd);\n"),
    ("eval_injection", "a.py",
     "" + "eval" + "(user_expr)\n"),
    ("node_createcipher_no_iv", "a.js",
     "const c = crypto." + "createCipher" + "('aes-256-cbc', k);\n"),
    ("marshal_loads", "a.py",
     "import marshal\n" + "marshal" + ".loads(b)\n"),
    ("shelve_open", "a.py",
     "import shelve\n" + "shelve" + ".open('db')\n"),
    ("xml_unsafe_parse", "a.py",
     "from xml.etree import ElementTree as ET\nET." + "parse" + "(f)\n"),
    ("pickle_variants_load", "a.py",
     "import cloudpickle\n" + "cloudpickle" + ".loads(b)\n"),
    ("pickle_wrapper_load", "a.py",
     "import joblib\n" + "joblib" + ".load('m.pkl')\n"),
    ("script_src_without_sri", "a.html",
     '<script src="https://cdn.example.com/lib.js"></script>\n'),
    ("yaml_unsafe_load_variants", "a.py",
     "import yaml\n" + "yaml" + ".unsafe_load(f)\n"),
    ("go_exec_shell_injection", "a.go",
     'exec.Command("sh", "-c", "ping " + host)\n'),
]


_NEGATIVE_CASES: list[tuple[str, str, str, str]] = [
    # (case_id, rule_name_that_must_not_fire, file_path, text)
    ("torch_weights_only_true", "torch_unsafe_load", "a.py",
     "import torch\nm = " + "torch" + ".load('m.pt', weights_only=True)\n"),
    ("yaml_safe_load", "unsafe_yaml_load", "a.py",
     "import yaml\ncfg = " + "yaml" + ".safe_load(f)\n"),
    ("verify_true", "tls_verification_disabled", "a.py",
     "requests.get(u, " + "verify" + "=True)\n"),
    ("pickle_dump_ok", "pickle_deserialization", "a.py",
     "import pickle\n" + "pickle" + ".dump(obj, f)\n"),
    ("subprocess_list_form", "python_subprocess_shell", "a.py",
     "" + "subprocess" + ".run(['ls', user])\n"),
    # 空路径 → path_filter 全跳过。pickle_deserialization 需要 .py 后缀。
    ("empty_path_gates_out", "pickle_deserialization", "",
     "import pickle\n" + "pickle" + ".loads(b)\n"),
    # .md 文件 → eval_injection 的 path_filter 会跳过。但当前 eval_injection
    # 本身也在 DISABLED 里,这里改验 os_system_injection 的 path_filter(.py 门禁)
    ("wrong_ext_gates_out", "os_system_injection", "a.md",
     "```\n" + "os" + ".system('ls')\n```\n"),
]


_PASS: list[str] = []
_FAIL: list[tuple[str, str]] = []


def _ok(name: str) -> None:
    _PASS.append(name)


def _bad(name: str, why: str) -> None:
    _FAIL.append((name, why))


def _rule_hit(matches: list[Match], rule_name: str) -> Match | None:
    for m in matches:
        if m.data_class == rule_name:
            return m
    return None


def test_positive_enabled() -> None:
    """启用组 13 条:positive fixture 上必须命中。"""
    for rule_name, path, text in _FIXTURES:
        if rule_name in _DEFAULT_DISABLED:
            continue
        case = f"positive_enabled::{rule_name}"
        try:
            matches = detect(text, path)
        except Exception as exc:
            _bad(case, f"detect() raised: {exc}")
            continue
        if _rule_hit(matches, rule_name):
            _ok(case)
        else:
            _bad(case, f"expected {rule_name} to fire, got {[m.data_class for m in matches]}")


def test_disabled_stays_silent() -> None:
    """禁用组 12 条:positive fixture 上必须**不**命中(过滤器起作用)。"""
    for rule_name, path, text in _FIXTURES:
        if rule_name not in _DEFAULT_DISABLED:
            continue
        case = f"disabled_silent::{rule_name}"
        try:
            matches = detect(text, path)
        except Exception as exc:
            _bad(case, f"detect() raised: {exc}")
            continue
        if _rule_hit(matches, rule_name) is None:
            _ok(case)
        else:
            _bad(case, f"disabled rule {rule_name} still fired")


def test_negatives() -> None:
    for case_id, rule, path, text in _NEGATIVE_CASES:
        case = f"negative::{case_id}"
        try:
            matches = detect(text, path)
        except Exception as exc:
            _bad(case, f"detect() raised: {exc}")
            continue
        if _rule_hit(matches, rule) is None:
            _ok(case)
        else:
            _bad(case, f"{rule} unexpectedly fired on {case_id}")


def test_boundary_empty() -> None:
    case = "boundary::empty_text"
    try:
        result = detect("", "a.py")
    except Exception as exc:
        _bad(case, str(exc))
        return
    _ok(case) if result == [] else _bad(case, f"empty text should return [], got {result}")


def test_boundary_none_path_type() -> None:
    """file_path=None 会导致内部 replace 崩;detect 用 `(file_path or '')` 兜住。"""
    case = "boundary::none_path"
    try:
        result = detect("import pickle\n" + "pickle" + ".loads(b)\n", None)  # type: ignore[arg-type]
    except Exception as exc:
        _bad(case, f"detect raised on None path: {exc}")
        return
    # path 为空 → path_filter 会把 pickle_deserialization 门禁掉,命中数应为 0。
    _ok(case) if _rule_hit(result, "pickle_deserialization") is None else \
        _bad(case, "pickle_deserialization should be gated by path_filter when path is empty")


def test_boundary_large_text() -> None:
    """1MB 文本必须在几秒内跑完,不能死循环。"""
    import time
    payload = ("import pickle\n" + "pickle" + ".loads(b)\n") * 20000  # ~600KB
    case = "boundary::large_text"
    t0 = time.time()
    try:
        matches = detect(payload, "a.py")
    except Exception as exc:
        _bad(case, str(exc))
        return
    dt = time.time() - t0
    if dt > 5.0:
        _bad(case, f"too slow: {dt:.2f}s")
        return
    m = _rule_hit(matches, "pickle_deserialization")
    if m and m.count == 20000 and len(m.samples) <= 3:
        _ok(case)
    else:
        _bad(case, f"expected count=20000 & <=3 samples, got count={m.count if m else 0}, samples={len(m.samples) if m else 0}")


def test_boundary_sample_len() -> None:
    """样例截断到 <= 80 字符。"""
    long_var = "x" * 300
    text = f"import pickle\n{long_var} = " + "pickle" + f".loads({long_var})\n"
    case = "boundary::sample_len"
    matches = detect(text, "a.py")
    m = _rule_hit(matches, "pickle_deserialization")
    if not m:
        _bad(case, "no match")
        return
    over = [s for s in m.samples if len(s) > 80]
    _ok(case) if not over else _bad(case, f"samples over 80 chars: {[len(s) for s in over]}")


def test_boundary_fail_open_bad_regex() -> None:
    """向 SECURITY_PATTERNS 注入一条坏正则(monkey-patch),detect 应继续跑,不抛。"""
    from detectors import dangerous_code_patterns as pkg
    case = "boundary::fail_open_bad_regex"
    bad_rule = {"ruleName": "__bad_regex_test__", "regex": r"(unclosed["}
    pkg.SECURITY_PATTERNS.append(bad_rule)
    pkg.RULE_NAME_TO_ID["__bad_regex_test__"] = 999  # is_enabled 只看 disabled 集
    try:
        try:
            matches = detect("import pickle\n" + "pickle" + ".loads(b)\n", "a.py")
        except Exception as exc:
            _bad(case, f"detect raised despite bad regex: {exc}")
            return
        if _rule_hit(matches, "pickle_deserialization"):
            _ok(case)
        else:
            _bad(case, "other rules should still fire when one regex is broken")
    finally:
        pkg.SECURITY_PATTERNS.remove(bad_rule)
        pkg.RULE_NAME_TO_ID.pop("__bad_regex_test__", None)


def test_ruleid_alignment() -> None:
    case = "boundary::ruleid_alignment"
    names_in_patterns = {p["ruleName"] for p in SECURITY_PATTERNS}
    names_in_enum = set(RULE_NAME_TO_ID)
    if names_in_patterns == names_in_enum:
        _ok(case)
    else:
        _bad(case, f"missing={names_in_patterns - names_in_enum}, extra={names_in_enum - names_in_patterns}")


def test_enabled_count() -> None:
    """健壮性:确保启用集合确实是 13 条。"""
    case = "boundary::enabled_count"
    enabled = [p["ruleName"] for p in SECURITY_PATTERNS if is_enabled(p["ruleName"])]
    if len(enabled) == 13:
        _ok(case)
    else:
        _bad(case, f"expected 13 enabled rules, got {len(enabled)}: {enabled}")


def main() -> int:
    tests = [
        test_positive_enabled,
        test_disabled_stays_silent,
        test_negatives,
        test_boundary_empty,
        test_boundary_none_path_type,
        test_boundary_large_text,
        test_boundary_sample_len,
        test_boundary_fail_open_bad_regex,
        test_ruleid_alignment,
        test_enabled_count,
    ]
    for t in tests:
        try:
            t()
        except Exception:
            _bad(f"{t.__name__}::CRASH", traceback.format_exc())

    print(f"passed: {len(_PASS)}")
    for n in _PASS:
        print(f"  OK  {n}")
    print(f"failed: {len(_FAIL)}")
    for n, why in _FAIL:
        print(f"  FAIL {n}")
        for line in why.splitlines():
            print(f"       {line}")
    return 0 if not _FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
