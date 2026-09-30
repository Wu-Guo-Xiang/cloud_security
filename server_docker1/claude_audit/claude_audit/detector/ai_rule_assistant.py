"""AI 智能策略生成器与自动化沙箱测试模块。

根据用户的自然语言安全需求，利用大模型自动编写高精度检测规则与正则表达式，
并在后台沙箱中自动运行高危攻击用例与合法业务用例的双向验证（正向拦截率 + 负向误报率），
测试通过后供用户一键启用生效。
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from .engine import _compile_matcher, _eval_matcher, _FIELDS, _MODES
from ..llm.llm_client import chat


_AI_RULE_SYSTEM_PROMPT = """你是一个顶级企业网络安全专家与规则引擎专家。你的任务是根据用户的自然语言安全管控需求，生成一条Cloud Security 大模型安全管控平台（Claude Code Managed Security Gateway）的标准安全检测与阻断规则，并同时生成自动化测试用例。

【平台规则引擎规范】
1. 目标作用域 (when):
   - 终端 Bash 命令: {"tool": "Bash"}
   - 用户提示词/提问: {"event": "UserPromptSubmit"}
   - 文件读取: {"tool": "Read"}
   - 文件写入/修改: {"tool": ["Edit", "Write"]}
   - 网络请求: {"tool": "WebFetch"}
   - 全局生效: {}
2. 检测字段 (match_field):
   - 只能在以下4个字段中选择一个: "bash_command", "file_path", "url", "prompt_text"
3. 匹配模式 (match_mode):
   - "regex" (正则表达式, 首选, 必须编写严密且高效的 Python re 正则, 避免回溯, 使用 (?i) 忽略大小写, 区分命令边界如 \\b；同时需具备高级防御意识，注意防范常见的包装器绕过手法如动态执行、管道传参或解释器封装)
   - "contains" (包含关键词, pattern 填写单个词或词组数组)
   - "glob" (通配符, 如 *.env, /etc/*)
   - "startswith" (前缀匹配)
   - "endswith" (后缀匹配, 如 .log, .pem)
4. 严重级别 (severity):
   - "critical": 致命危险操作，直接硬阻断，绝不放行（如删除关键文件、格式化磁盘、读取私钥、提问高危指令）
   - "high": 高危操作，直接硬阻断（如篡改配置、上传未知代码、外带网络数据）
   - "warn": 软性告警，在 UserPromptSubmit 时会提示确认
   - "allow": 白名单豁免放行
5. 拦截理由 (reason):
   - 必须使用中文，语气严谨专业，明确指出违反了什么企业安全策略（例如："企业安全策略严禁 AI 执行针对任何 .log 文件的删除或清空操作"）
6. 规则唯一标识 (id):
   - 英文小写下划线或短横线命名，简洁清晰（如 "block_delete_log_files"）
7. 自动化测试用例 (极其重要，系统将用于后台真实沙箱回归验证):
   - positive_cases: 至少 4 个典型的高危/违规测试样本，这些样本必须能被你编写的 pattern 成功匹配并拦截！
   - negative_cases: 至少 4 个类似的但合法的业务/开发测试样本，这些样本绝不能被你的 pattern 误杀（必须放行）！

【返回格式要求】
必须直接返回合法的 JSON 对象（可包裹在 ```json ``` 代码块中），不得包含任何其他多余文本：
{
  "id": "block_xxx",
  "when": {"tool": "Bash"},
  "match_field": "bash_command",
  "match_mode": "regex",
  "pattern": "(?i)...",
  "severity": "critical",
  "reason": "企业安全策略严禁...",
  "explanation": "本规则设计思路说明...",
  "positive_cases": ["高危测试样本1", "高危测试样本2", "高危测试样本3", "高危测试样本4"],
  "negative_cases": ["合法放行样本1", "合法放行样本2", "合法放行样本3", "合法放行样本4"]
}
"""


def _clean_json_str(raw: str) -> str:
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if m:
        return m.group(1).strip()
    m2 = re.search(r"(\{.*\})", raw, re.DOTALL)
    if m2:
        return m2.group(1).strip()
    return raw.strip()


def run_rule_self_test(
    match_field: str,
    match_mode: str,
    pattern: Any,
    positive_cases: list[str],
    negative_cases: list[str],
) -> dict[str, Any]:
    """使用 RuleEngine 底层匹配器对正向拦截样本与负向放行样本执行自动化测试。"""
    if match_field not in _FIELDS:
        return {
            "all_passed": False,
            "error": f"不支持的检测字段: {match_field}，合法字段为: {', '.join(_FIELDS)}",
            "positive_results": [],
            "negative_results": [],
        }
    if match_mode not in _MODES:
        return {
            "all_passed": False,
            "error": f"不支持的匹配模式: {match_mode}，合法模式为: {', '.join(_MODES)}",
            "positive_results": [],
            "negative_results": [],
        }

    try:
        compiled = _compile_matcher(match_field, match_mode, pattern)
    except Exception as e:
        return {
            "all_passed": False,
            "error": f"规则编译失败 (语法或正则错误): {e}",
            "positive_results": [],
            "negative_results": [],
        }

    pos_results = []
    for item in positive_cases:
        item_str = str(item).strip()
        if not item_str:
            continue
        try:
            matched, match_str = _eval_matcher(item_str, match_mode, compiled)
        except Exception as ex:
            matched, match_str = False, str(ex)
        pos_results.append({
            "input": item_str,
            "matched": matched,
            "match_text": match_str,
            "passed": matched,  # 正向用例：必须命中才算通过
        })

    neg_results = []
    for item in negative_cases:
        item_str = str(item).strip()
        if not item_str:
            continue
        try:
            matched, match_str = _eval_matcher(item_str, match_mode, compiled)
        except Exception as ex:
            matched, match_str = True, str(ex)
        neg_results.append({
            "input": item_str,
            "matched": matched,
            "match_text": match_str,
            "passed": not matched,  # 负向用例：绝不能命中（未命中才算通过）
        })

    pos_passed_count = sum(1 for r in pos_results if r["passed"])
    neg_passed_count = sum(1 for r in neg_results if r["passed"])
    total_pos = len(pos_results)
    total_neg = len(neg_results)

    all_passed = (total_pos > 0 and pos_passed_count == total_pos) and (
        total_neg == 0 or neg_passed_count == total_neg
    )

    if all_passed:
        summary = (
            f"✅ 自动化自测全部通过 (100%): "
            f"{pos_passed_count}/{total_pos} 个拦截样本精准阻断，"
            f"{neg_passed_count}/{total_neg} 个合法样本安全放行，无误杀风险。"
        )
    else:
        summary = (
            f"⚠️ 自动化自测存在未通过项: "
            f"拦截用例通过 {pos_passed_count}/{total_pos}，"
            f"放行用例通过 {neg_passed_count}/{total_neg}。"
        )

    return {
        "all_passed": all_passed,
        "summary": summary,
        "positive_passed_count": pos_passed_count,
        "positive_total_count": total_pos,
        "negative_passed_count": neg_passed_count,
        "negative_total_count": total_neg,
        "positive_results": pos_results,
        "negative_results": neg_results,
    }


def generate_and_test_rule(
    requirement: str,
    scope_hint: str = "",
    severity_hint: str = "",
) -> dict[str, Any]:
    """接收用户自然语言需求，调用 LLM 生成规则，并在后台执行沙箱自测，返回完整自测报告。"""
    user_prompt = f"【用户安全管控需求】:\n{requirement.strip()}"
    if scope_hint:
        user_prompt += f"\n【参考生效范围】: {scope_hint}"
    if severity_hint:
        user_prompt += f"\n【参考严重级别】: {severity_hint}"

    t0 = time.time()
    try:
        raw_output = chat([
            {"role": "system", "content": _AI_RULE_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ])
    except Exception as e:
        return {
            "ok": False,
            "error": f"调用大模型生成规则失败: {e}",
        }
    gen_time_ms = int((time.time() - t0) * 1000)

    # 解析 LLM 输出的 JSON
    try:
        json_str = _clean_json_str(raw_output)
        data = json.loads(json_str)
    except Exception as e:
        return {
            "ok": False,
            "error": f"解析大模型返回的规则 JSON 失败: {e}\n原始输出:\n{raw_output[:500]}",
        }

    # 规范化字段
    rule_id = str(data.get("id") or "custom_rule_" + str(int(time.time()))).strip()
    rule_id = re.sub(r"[^a-zA-Z0-9_\-\u4e00-\u9fa5]", "_", rule_id)

    match_field = str(data.get("match_field") or "bash_command").strip()
    match_mode = str(data.get("match_mode") or "regex").strip()
    pattern = data.get("pattern")
    if pattern is None:
        pattern = ""

    severity = str(data.get("severity") or "critical").strip().lower()
    if severity not in ("critical", "high", "warn", "allow", "info"):
        severity = "critical"

    reason = str(data.get("reason") or "违反企业安全合规策略").strip()
    explanation = str(data.get("explanation") or "").strip()

    when = data.get("when")
    if not isinstance(when, dict):
        if match_field == "bash_command":
            when = {"tool": "Bash"}
        elif match_field == "prompt_text":
            when = {"event": "UserPromptSubmit"}
        elif match_field == "file_path":
            when = {"tool": ["Read", "Edit", "Write"]}
        elif match_field == "url":
            when = {"tool": "WebFetch"}
        else:
            when = {}

    positive_cases = data.get("positive_cases") or []
    negative_cases = data.get("negative_cases") or []
    if not isinstance(positive_cases, list):
        positive_cases = [str(positive_cases)]
    if not isinstance(negative_cases, list):
        negative_cases = [str(negative_cases)]

    # 后台自动化沙箱执行自测
    test_report = run_rule_self_test(
        match_field=match_field,
        match_mode=match_mode,
        pattern=pattern,
        positive_cases=positive_cases,
        negative_cases=negative_cases,
    )

    # 构造可直接保存到 RuleEngine 的标准 match 对象
    match_key = f"{match_field}_{match_mode}"
    engine_match = {match_key: pattern}

    rule_dict = {
        "id": rule_id,
        "when": when,
        "match": engine_match,
        "match_field": match_field,
        "match_mode": match_mode,
        "pattern": pattern,
        "severity": severity,
        "reason": reason,
        "file_name": "custom_rules.yml",
    }

    return {
        "ok": True,
        "rule": rule_dict,
        "test_report": test_report,
        "explanation": explanation,
        "generation_time_ms": gen_time_ms,
        "positive_cases": positive_cases,
        "negative_cases": negative_cases,
    }
