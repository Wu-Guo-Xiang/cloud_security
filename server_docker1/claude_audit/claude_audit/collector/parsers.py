from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..storage.models import EventRecord, RuleHit

# 敏感信息类别 / 规则 ID → 中文名映射
# _lookup_label() 会先查此字典，再查 rule_labels.yml，最后调 LLM
SENSITIVE_CLASS_LABELS = {
    # input_scanner / output_scanner 敏感信息类别
    "api_key": "API密钥",
    "phone": "手机号",
    "email": "电子邮箱",
    "person": "个人姓名",
    "product": "产品名称",
    "id_number": "身份证号",
    "company": "公司名称",
    "db_connection": "数据库连接",
    "id_card": "证件号",
    "internal_ip": "内网IP",
    "money": "金额",
    "password": "密码",
    "address": "地址",
    "landline": "固定电话",
    "prod_password": "产品密码",
    "generic_api_key": "通用API密钥",
    "uscc": "统一社会信用代码",
    "company_email": "公司邮箱",
    # hook 通用回退
    "hook_match": "敏感命中",
    # output_scanner 安全漏洞/注入/XSS 类
    "document_write_xss": "文档写入XSS",
    "react_dangerously_set_html": "React危险HTML注入",
    "new_function_injection": "新函数注入",
    "os_system_injection": "OS系统命令注入",
    "unsafe_yaml_load": "不安全YAML加载",
    "command_injection": "命令注入",
    "sql_injection": "SQL注入",
    "path_traversal": "路径遍历",
    "ssrf": "SSRF服务端请求伪造",
    "hardcoded_password": "硬编码密码",
    "private_key": "私钥",
    "jwt_token": "JWT令牌",
    "oauth_token": "OAuth令牌",
    "aws_access_key": "AWS访问密钥",
    "azure_key": "Azure密钥",
    "gcp_key": "GCP密钥",
    # engine: credential_leak.yml
    "cred_read_env_file": "读取.env文件",
    "cred_edit_env_file": "编辑.env文件",
    "cred_touch_ssh_key": "触碰SSH/密钥凭证文件",
    "cred_bash_leaks_api_key": "Bash命令行API密钥泄露",
    "cred_windows_secret_paths": "访问Windows敏感系统文件",
    # engine: dangerous_bash.yml
    "bash_rm_rf_root": "rm -rf根目录/非临时目录",
    "bash_curl_exfil": "Bash疑似外传数据",
    "bash_chmod_777": "chmod 777赋予任意权限",
    "bash_force_push_main": "强推main/master分支",
    "bash_read_env": "Bash读取.env文件",
    "bash_read_ssh_key": "Bash读取SSH/密钥凭证",
    "bash_disable_hooks": "跳过git hook或签名",
    # engine: exfiltration.yml
    "webfetch_public_paste_or_webhook": "WebFetch访问已知外传服务",
    "webfetch_private_ip": "WebFetch访问私网/链路本地IP",
    "bash_dns_exfil": "DNS外泄回连域",
    "bash_reverse_shell": "反弹shell特征",
    # engine: hook_tamper.yml
    "hook_edit_settings_json": "修改.claude/settings.json",
    "hook_edit_hook_script": "修改.claude/hooks或skills脚本",
    "hook_edit_audit_state": "篡改audit client日志/状态/配置",
    "hook_bash_delete_claude_config": "删除.claude配置/hook/skill/memory",
    "hook_bash_kill_audit_client": "终止audit client进程",
    "hook_bash_stop_audit_service": "停止audit服务",
    "hook_disable_via_env": "环境变量禁用hook/audit",
    "hook_chmod_hooks_dir": "修改.claude目录权限",
    "hook_read_settings_snoop": "读取.claude/settings.json",
    "hook_edit_installer_launcher": "修改audit client启动器/exe",
    "hook_bash_overwrite_installer": "覆盖audit client启动器/exe",
    # ── ups_class_* 前缀版本（hook 推送的 class 类别名带 ups_class_ 前缀）──
    "ups_class_api_key": "API密钥",
    "ups_class_phone": "手机号",
    "ups_class_email": "电子邮箱",
    "ups_class_person": "个人姓名",
    "ups_class_product": "产品名称",
    "ups_class_id_number": "身份证号",
    "ups_class_company": "公司名称",
    "ups_class_db_connection": "数据库连接",
    "ups_class_id_card": "证件号",
    "ups_class_internal_ip": "内网IP",
    "ups_class_money": "金额",
    "ups_class_password": "密码",
    "ups_class_address": "地址",
    "ups_class_landline": "固定电话",
    "ups_class_prod_password": "产品密码",
    "ups_class_generic_api_key": "通用API密钥",
    "ups_class_uscc": "统一社会信用代码",
    "ups_class_company_email": "公司邮箱",
    "ups_class_document_write_xss": "文档写入XSS",
    "ups_class_react_dangerously_set_html": "React危险HTML注入",
    "ups_class_new_function_injection": "新函数注入",
    "ups_class_os_system_injection": "OS系统命令注入",
    "ups_class_unsafe_yaml_load": "不安全YAML加载",
    "ups_class_command_injection": "命令注入",
    "ups_class_sql_injection": "SQL注入",
    "ups_class_path_traversal": "路径遍历",
    "ups_class_ssrf": "SSRF服务端请求伪造",
    "ups_class_hardcoded_password": "硬编码密码",
    "ups_class_private_key": "私钥",
    "ups_class_jwt_token": "JWT令牌",
    "ups_class_oauth_token": "OAuth令牌",
    "ups_class_aws_access_key": "AWS访问密钥",
    "ups_class_azure_key": "Azure密钥",
    "ups_class_gcp_key": "GCP密钥",
    "ups_class_hook_match": "敏感命中",
}


def _detect_source_kind(source_file: str) -> str:
    name = Path(source_file).name.lower()
    if "input_scanner" in name:
        return "input"
    if "output_scanner" in name:
        return "output"
    if "stop_review" in name:
        return "stop"
    return "unknown"


def _hits_from_matches(matches: Any) -> list[RuleHit]:
    hits: list[RuleHit] = []
    if not isinstance(matches, list):
        return hits
    for m in matches:
        if isinstance(m, dict):
            # 兼容 4 种 hook 输出格式:
            #  A) {id/rule/name, severity/level, matched/snippet}
            #  B) {class, count, samples}          — input_scanner UserPromptSubmit
            #  C) {data_class, count, samples}     — output_scanner PostToolUse
            #  D) 其它字典 -> 回退 hook_match
            cls = m.get("class") or m.get("data_class")
            if cls:
                cls = str(cls)
                cnt = m.get("count") or 0
                samples = m.get("samples") or []
                snippet = ""
                if isinstance(samples, list) and samples:
                    snippet = str(samples[0])
                hits.append(RuleHit(
                    source="hook",
                    rule_id=f"ups_class_{cls}",
                    severity=str(m.get("severity") or "warn").lower(),
                    matched=snippet[:500],
                    meta={"class": cls, "data_class": cls, "count": cnt, "samples": samples},
                ))
                continue
            rid = str(m.get("id") or m.get("rule") or m.get("name") or "hook_match")
            sev = str(m.get("severity") or m.get("level") or "warn").lower()
            matched = str(m.get("matched") or m.get("snippet") or "")
            hits.append(RuleHit(source="hook", rule_id=rid, severity=sev,
                                matched=matched, meta=m))
        else:
            hits.append(RuleHit(source="hook", rule_id=str(m), severity="warn"))
    return hits


def _base_record(raw: dict, source_file: str, line_no: int, byte_offset: int) -> EventRecord:
    return EventRecord(
        ts=str(raw.get("timestamp") or ""),
        source_file=source_file,
        line_no=line_no,
        byte_offset=byte_offset,
        event=raw.get("event"),
        stage=raw.get("stage"),
        session_id=raw.get("session_id"),
        tool=raw.get("tool"),
        phase=raw.get("phase"),
        action=raw.get("action"),
        skipped_reason=raw.get("skipped_reason"),
        duration_ms=raw.get("duration_ms"),
        user=raw.get("user"),
        vm_hostname=raw.get("vm_hostname"),
        pid=raw.get("pid"),
    )


def _extract_from_tool_input(rec: EventRecord, tool_input: Any) -> None:
    if not isinstance(tool_input, dict):
        return
    if rec.tool == "Bash":
        cmd = tool_input.get("command")
        if isinstance(cmd, str):
            rec.bash_command = cmd
    if rec.tool in ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit"):
        fp = tool_input.get("file_path") or tool_input.get("notebook_path")
        if isinstance(fp, str):
            rec.file_path = fp
    if rec.tool in ("WebFetch", "WebSearch"):
        u = tool_input.get("url") or tool_input.get("query")
        if isinstance(u, str):
            rec.url = u


def parse_input(raw: dict, source_file: str, line_no: int, byte_offset: int) -> EventRecord | None:
    rec = _base_record(raw, source_file, line_no, byte_offset)
    _extract_from_tool_input(rec, raw.get("tool_input"))
    # UserPromptSubmit 事件: 记录对话框原文 + 用户决策
    if rec.event == "UserPromptSubmit":
        pt = raw.get("prompt_text")
        if isinstance(pt, str) and pt:
            rec.prompt_text = pt
        br = raw.get("block_reason")
        if isinstance(br, str) and br:
            rec.block_reason = br
    matches = raw.get("matches")
    rec.hits = _hits_from_matches(matches)
    if isinstance(matches, list):
        rec.hook_match_count = len(matches)
    return rec


def parse_output(raw: dict, source_file: str, line_no: int, byte_offset: int) -> EventRecord | None:
    rec = _base_record(raw, source_file, line_no, byte_offset)
    fp = raw.get("file_path")
    if isinstance(fp, str):
        rec.file_path = fp
    matches = raw.get("matches")
    mc = raw.get("match_count")
    rec.hits = _hits_from_matches(matches)
    if isinstance(mc, int):
        rec.hook_match_count = mc
    elif isinstance(matches, list):
        rec.hook_match_count = len(matches)
    return rec


def parse_stop(raw: dict, source_file: str, line_no: int, byte_offset: int) -> EventRecord | None:
    return _base_record(raw, source_file, line_no, byte_offset)


_PARSERS = {"input": parse_input, "output": parse_output, "stop": parse_stop}


def parse_line(raw_line: str, source_file: str, line_no: int, byte_offset: int) -> EventRecord | None:
    raw_line = raw_line.strip()
    if not raw_line:
        return None
    try:
        raw = json.loads(raw_line)
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict):
        return None
    kind = _detect_source_kind(source_file)
    parser = _PARSERS.get(kind)
    if not parser:
        return None
    rec = parser(raw, source_file, line_no, byte_offset)
    if rec is not None:
        rec.raw = raw_line
    return rec
