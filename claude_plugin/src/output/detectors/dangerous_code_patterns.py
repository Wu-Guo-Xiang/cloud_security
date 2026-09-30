"""危险代码模式库 — 从 security-guidance 移植的 25 条正则规则。

纯数据 + 一个 RuleId 枚举 + 一个默认禁用集合。不做 I/O、不读环境变量、不打日志,
保持无副作用,方便被 dangerous_code_detector.detect() 和单元测试直接 import。

来源:
  https://github.com/anthropics/claude-code plugins/security-guidance/hooks/patterns.py
  版本对应 D:/cloud_security/claude-code-main 快照。

_DEFAULT_DISABLED:
  当前 Step 2 只启用 severity 硬 / 误报低的 13 条(pickle/torch/yaml/subprocess-shell/
  os.system/TLS-off/AES-ECB + XSS 六件套)。其余 12 条列入禁用,后续按误报数据分批开。
  private-key 类风险已由 credential_detector._PRIVATE_KEY_PATTERNS 覆盖,不重复。
"""
from __future__ import annotations
from enum import IntEnum


_JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte")
_PY_EXTS = (".py", ".pyi", ".ipynb")
_DOC_EXTS = (".md", ".mdx", ".txt", ".rst", ".json", ".yaml", ".yml")


_UNSAFE_DESERIALIZATION_REMINDER = """⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.

For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.

If this is safe or is explicitly needed, briefly document that in a comment before continuing."""

_UNSAFE_YAML_LOAD_REMINDER = """⚠️ Security Warning: yaml.load() / yaml.unsafe_load() execute arbitrary Python via !!python/object tags.

Use yaml.safe_load() if the file only contains simple data structures (dicts, lists, strings, numbers). If you need typed objects, parse with safe_load and validate the result against a schema (pydantic, msgspec, marshmallow) — never use a custom Loader that constructs arbitrary types."""

_UNSAFE_TORCH_LOAD_REMINDER = """⚠️ Security Warning: torch.load() defaults to weights_only=False, which unpickles arbitrary Python objects and allows arbitrary code execution.

If the file only contains tensors and simple data structures, pass weights_only=True (or set TORCH_FORCE_WEIGHTS_ONLY_LOAD=1)."""


SECURITY_PATTERNS = [
    {
        "ruleName": "github_actions_workflow",
        "path_check": lambda path: ".github/workflows/" in path
        and (path.endswith(".yml") or path.endswith(".yaml")),
        "reminder": "⚠️ Security Warning: Editing a GitHub Actions workflow. Avoid interpolating untrusted event context into run: commands; use env: with quoted vars.",
    },
    {
        "ruleName": "child_process_exec",
        "path_filter": lambda p: p.endswith(_JS_EXTS),
        "substrings": ["child_process.exec", "execSync("],
        "regex": r"(?<![a-zA-Z0-9_\.])exec\(",
        "reminder": "⚠️ Security Warning: child_process.exec runs a shell. Use execFile()/spawn() with an argument array to avoid command injection.",
    },
    {
        "ruleName": "new_function_injection",
        "substrings": ["new Function"],
        "reminder": "⚠️ Security Warning: new Function() with interpolated strings is a code-injection sink. Never interpolate untrusted input into function bodies.",
    },
    {
        "ruleName": "eval_injection",
        "path_filter": lambda p: not p.endswith(_DOC_EXTS),
        "regex": r"(?<![a-zA-Z0-9_\.])eval\(",
        "reminder": "⚠️ Security Warning: eval() executes arbitrary code. Use JSON.parse() / ast.literal_eval() / a safe expression parser.",
    },
    {
        "ruleName": "react_dangerously_set_html",
        "substrings": ["dangerouslySetInnerHTML"],
        "reminder": "⚠️ Security Warning: dangerouslySetInnerHTML is an XSS sink. Sanitize with DOMPurify or use safe alternatives.",
    },
    {
        "ruleName": "document_write_xss",
        "substrings": ["document.write"],
        "reminder": "⚠️ Security Warning: document.write() is an XSS sink. Use DOM manipulation methods instead.",
    },
    {
        "ruleName": "innerHTML_xss",
        "substrings": [".innerHTML =", ".innerHTML="],
        "reminder": "⚠️ Security Warning: innerHTML assignment is an XSS sink. Use textContent, or sanitize with DOMPurify.",
    },
    {
        "ruleName": "pickle_deserialization",
        "path_filter": lambda p: p.endswith(_PY_EXTS),
        "regex": r"(?<![a-zA-Z0-9_])pickle\.(loads?|Unpickler)\b|(?<![a-zA-Z0-9_])pkl_load\(",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
    {
        "ruleName": "os_system_injection",
        "path_filter": lambda p: p.endswith(_PY_EXTS),
        "regex": r"\bos\.system\s*\(",
        "substrings": ["from os import system"],
        "reminder": "⚠️ Security Warning: os.system() runs a shell. Use subprocess.run([...]) with a list of args.",
    },
    {
        "ruleName": "python_subprocess_shell",
        "regex": r"subprocess\.(?:run|call|Popen|check_output|check_call)\(.*shell\s*=\s*True",
        "reminder": "⚠️ Security Warning: subprocess with shell=True enables command injection. Pass arguments as a list without shell.",
    },
    {
        "ruleName": "go_exec_shell_injection",
        "regex": r'exec\.Command\(\s*"(?:sh|bash|/bin/sh|/bin/bash)"',
        "reminder": "⚠️ Security Warning: exec.Command with a shell interpreter (sh/bash) enables command injection. Pass args directly.",
    },
    {
        "ruleName": "unsafe_yaml_load",
        "regex": r"\byaml\.load\s*\((?![^)\n]{0,80}\bSafe)",
        "reminder": _UNSAFE_YAML_LOAD_REMINDER,
    },
    {
        "ruleName": "node_createcipher_no_iv",
        "regex": r"\bcrypto\.(createCipher|createDecipher)\b",
        "reminder": "⚠️ Security Warning: Use crypto.createCipheriv() / createDecipheriv(). createCipher was removed in Node 22.",
    },
    {
        "ruleName": "aes_ecb_mode",
        "regex": r"\bAES\.MODE_ECB\b|\bmodes\.ECB\s*\(|[\x22\x27]aes-\d+-ecb[\x22\x27]",
        "reminder": "⚠️ Security Warning: Use AES-GCM or AES-CBC with HMAC. ECB mode leaks plaintext structure.",
    },
    {
        "ruleName": "tls_verification_disabled",
        "regex": r"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\x22\x27]?0|ssl\._create_unverified_context|check_hostname\s*=\s*False",
        "reminder": "⚠️ Security Warning: Don't disable TLS verification. This allows MITM attacks.",
    },
    {
        "ruleName": "marshal_loads",
        "regex": r"\bmarshal\.loads?\s*\(",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
    {
        "ruleName": "shelve_open",
        "regex": r"\bshelve\.open\s*\(",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
    {
        "ruleName": "xml_unsafe_parse",
        "regex": r"\b(xml\.etree\.ElementTree|ElementTree|ET)\.(parse|fromstring|XML)\s*\(|\bminidom\.(parse|parseString)\s*\(|\bxml\.sax\.(parse|make_parser)\b",
        "reminder": "⚠️ Security Warning: Use defusedxml. Python's stdlib XML parsers are vulnerable to XXE and billion-laughs.",
    },
    {
        "ruleName": "pickle_variants_load",
        "regex": r"\b(cPickle|cloudpickle|dill)\.(load|loads)\s*\(",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
    {
        "ruleName": "outerHTML_xss",
        "substrings": [".outerHTML =", ".outerHTML="],
        "reminder": "⚠️ Security Warning: outerHTML assignment is an XSS sink. Use textContent or sanitize with DOMPurify.",
    },
    {
        "ruleName": "insertAdjacentHTML_xss",
        "substrings": [".insertAdjacentHTML("],
        "reminder": "⚠️ Security Warning: insertAdjacentHTML is an XSS sink. Use insertAdjacentText() or sanitize with DOMPurify.",
    },
    {
        "ruleName": "script_src_without_sri",
        "regex": (
            r"<script\s+(?![^>]{0,400}integrity\s*=)"
            r"[^>]{0,200}src\s*=\s*[\x22\x27](?:https?:)?//"
            r"[^\x22\x27]{1,300}[\x22\x27]"
            r"[^>]{0,100}>"
        ),
        "reminder": '⚠️ Security Warning: Add integrity="sha384-..." crossorigin="anonymous" to external script tags.',
    },
    {
        "ruleName": "torch_unsafe_load",
        "regex": r"(?:\btorch\.load|\.torch_load)\s*\((?![^)\n]{0,200}weights_only\s*=\s*True)",
        "reminder": _UNSAFE_TORCH_LOAD_REMINDER,
    },
    {
        "ruleName": "yaml_unsafe_load_variants",
        "regex": r"(?:\byaml\.unsafe_load|\.yaml_unsafe_load)\s*\(",
        "reminder": _UNSAFE_YAML_LOAD_REMINDER,
    },
    {
        "ruleName": "pickle_wrapper_load",
        "regex": r"\bjoblib\.load\s*\(|\b(?:pd|pandas)\.read_pickle\s*\(|\.cloudpickle_load\s*\(|\b(?:np|numpy)\.load\s*\([^)\n]{0,200}allow_pickle\s*=\s*True",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
]


class RuleId(IntEnum):
    """稳定数字 ID,用于遥测。冻结,不重排,新增只能追加。"""
    GITHUB_ACTIONS_WORKFLOW = 1
    CHILD_PROCESS_EXEC = 2
    NEW_FUNCTION_INJECTION = 3
    EVAL_INJECTION = 4
    REACT_DANGEROUSLY_SET_HTML = 5
    DOCUMENT_WRITE_XSS = 6
    INNERHTML_XSS = 7
    PICKLE_DESERIALIZATION = 8
    OS_SYSTEM_INJECTION = 9
    PYTHON_SUBPROCESS_SHELL = 10
    GO_EXEC_SHELL_INJECTION = 11
    UNSAFE_YAML_LOAD = 12
    NODE_CREATECIPHER_NO_IV = 13
    AES_ECB_MODE = 14
    TLS_VERIFICATION_DISABLED = 15
    MARSHAL_LOADS = 16
    SHELVE_OPEN = 17
    XML_UNSAFE_PARSE = 18
    PICKLE_VARIANTS_LOAD = 19
    OUTERHTML_XSS = 20
    INSERTADJACENTHTML_XSS = 21
    SCRIPT_SRC_WITHOUT_SRI = 22
    TORCH_UNSAFE_LOAD = 23
    YAML_UNSAFE_LOAD_VARIANTS = 24
    PICKLE_WRAPPER_LOAD = 25


RULE_NAME_TO_ID: dict[str, RuleId] = {
    "github_actions_workflow": RuleId.GITHUB_ACTIONS_WORKFLOW,
    "child_process_exec": RuleId.CHILD_PROCESS_EXEC,
    "new_function_injection": RuleId.NEW_FUNCTION_INJECTION,
    "eval_injection": RuleId.EVAL_INJECTION,
    "react_dangerously_set_html": RuleId.REACT_DANGEROUSLY_SET_HTML,
    "document_write_xss": RuleId.DOCUMENT_WRITE_XSS,
    "innerHTML_xss": RuleId.INNERHTML_XSS,
    "pickle_deserialization": RuleId.PICKLE_DESERIALIZATION,
    "os_system_injection": RuleId.OS_SYSTEM_INJECTION,
    "python_subprocess_shell": RuleId.PYTHON_SUBPROCESS_SHELL,
    "go_exec_shell_injection": RuleId.GO_EXEC_SHELL_INJECTION,
    "unsafe_yaml_load": RuleId.UNSAFE_YAML_LOAD,
    "node_createcipher_no_iv": RuleId.NODE_CREATECIPHER_NO_IV,
    "aes_ecb_mode": RuleId.AES_ECB_MODE,
    "tls_verification_disabled": RuleId.TLS_VERIFICATION_DISABLED,
    "marshal_loads": RuleId.MARSHAL_LOADS,
    "shelve_open": RuleId.SHELVE_OPEN,
    "xml_unsafe_parse": RuleId.XML_UNSAFE_PARSE,
    "pickle_variants_load": RuleId.PICKLE_VARIANTS_LOAD,
    "outerHTML_xss": RuleId.OUTERHTML_XSS,
    "insertAdjacentHTML_xss": RuleId.INSERTADJACENTHTML_XSS,
    "script_src_without_sri": RuleId.SCRIPT_SRC_WITHOUT_SRI,
    "torch_unsafe_load": RuleId.TORCH_UNSAFE_LOAD,
    "yaml_unsafe_load_variants": RuleId.YAML_UNSAFE_LOAD_VARIANTS,
    "pickle_wrapper_load": RuleId.PICKLE_WRAPPER_LOAD,
}


# 默认禁用的 12 条 —— severity 相对软 / 误报率偏高 / 已被其他 detector 覆盖。
# 启用条件由 dangerous_code_detector 在扫描前过滤;此常量不 mutable 一次性冻结。
_DEFAULT_DISABLED: frozenset[str] = frozenset({
    "github_actions_workflow",     # path-based,以后单独开分支
    "child_process_exec",          # JS bare `exec(` 误报中
    "eval_injection",              # Python `eval(` 会命中 model.eval() 之外的一些框架
    "node_createcipher_no_iv",     # Node 22 已删除 API,存量代码扫到再开
    "marshal_loads",               # 使用面窄,先禁
    "shelve_open",                 # 同上
    "xml_unsafe_parse",            # 误报偏高:大部分 ElementTree 使用是可信输入
    "pickle_variants_load",        # 覆盖率增量小,pickle_deserialization 已启用
    "pickle_wrapper_load",         # 同上
    "script_src_without_sri",      # SRI 不是所有项目都要求
    "yaml_unsafe_load_variants",   # unsafe_yaml_load 已启用
    "go_exec_shell_injection",     # 项目里没 Go
})


def is_enabled(rule_name: str) -> bool:
    """默认策略:不在 _DEFAULT_DISABLED 集合里就启用。"""
    return rule_name not in _DEFAULT_DISABLED


# rule_name → reminder text 的 O(1) 查表,给 output_scanner 构造
# additionalContext 反馈给 Claude 时使用。SECURITY_PATTERNS 已冻结,
# 一次性生成安全。
RULE_NAME_TO_REMINDER: dict[str, str] = {
    p["ruleName"]: p["reminder"] for p in SECURITY_PATTERNS
}


# 启动期完整性检查:RuleId 与 SECURITY_PATTERNS 必须双向对齐。
# 单元测试也会跑到,双保险。
assert set(RULE_NAME_TO_ID) == {p["ruleName"] for p in SECURITY_PATTERNS}, (
    f"RuleId out of sync: "
    f"missing_in_enum={ {p['ruleName'] for p in SECURITY_PATTERNS} - set(RULE_NAME_TO_ID)}, "
    f"extra_in_enum={set(RULE_NAME_TO_ID) - {p['ruleName'] for p in SECURITY_PATTERNS}}"
)
assert _DEFAULT_DISABLED <= set(RULE_NAME_TO_ID), (
    f"_DEFAULT_DISABLED contains unknown rules: "
    f"{_DEFAULT_DISABLED - set(RULE_NAME_TO_ID)}"
)
