from __future__ import annotations

import datetime
import json
from pathlib import Path
import re
import threading
import time

from ..storage.models import EventRecord, RuleHit
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware

from .auth import (
    AuthConfig,
    RateLimiter,
    check_auth,
    new_csrf_token,
    safe_next,
    verify_csrf,
    verify_password,
)

from ..collector.parsers import parse_line
from ..config import Config
from ..detector import RuleEngine
from ..detector.ai_rule_assistant import generate_and_test_rule, run_rule_self_test
from ..storage import Storage
from ..storage.plugins import (
    bump_patch,
    save_release,
    resync_release,
    get_active_manifest,
    get_active_version,
    list_releases,
    activate_release,
    delete_release,
    log_plugin_pull,
    list_plugin_pulls,
    count_plugin_pulls,
)
from ..plugin_status import build_status as build_plugin_status
from ..plugin_status import start_background_refresh as _start_bg_refresh
from ..plugin_status import start_daily_org_sync as _start_daily_org_sync
from ..plugin_status import start_sync_org_task, get_sync_org_status, get_latest_sync_org_task
from ..plugin_status import (
    load_org,
    _audit_username,
    _pinyin_candidates,
    _norm_name,
    _load_manual_map,
    _load_dept_map,
    register_org_sync_done_callback,
)
from ..glm_reader import read_queue as _glm_read_queue
from ..glm_reader import read_ips as _glm_read_ips
from ..plugin_status import (
    get_manual_map,
    set_manual_mapping,
    delete_manual_mapping,
)
from ..plugin_status import (
    get_litellm_alias_map,
    set_litellm_alias_mapping,
    delete_litellm_alias_mapping,
)
from ..plugin_status import (
    get_offline_key_info,
    block_offline_keys,
    unblock_user_keys,
)
from ..storage.ip_whitelist import (
    list_whitelist,
    add_whitelist,
    delete_whitelist,
)
from ..llm.llm_config import llm_config, reload_llm_config, save_llm_config
from ..llm.llm_client import test_connection, chat as llm_chat
from ..storage.db_maintenance import (
    start_db_maintenance_scheduler,
    run_daily_backup,
    run_daily_archive,
)


_BASE = Path(__file__).resolve().parent

_NL2SQL_SYSTEM = """\
你是专业 SQLite 查询生成器。根据自然语言问题，只输出一条纯 SELECT SQL 语句，不要任何解释或 markdown 包裹。

数据库包含以下表和视图：

1. events —— 审计事件主表（23 列）:
  id              INTEGER PRIMARY KEY AUTOINCREMENT
  ts              TEXT     时间戳，格式 "2026-07-13T12:34:56+08:00"
  source_file     TEXT     日志来源文件路径
  line_no         INTEGER  行号
  byte_offset     INTEGER  字节偏移
  event           TEXT     事件类型: PreToolUse / PostToolUse / UserPromptSubmit / Stop / scanner_exit 等
  stage           TEXT     处理阶段: step4_e2e 等
  session_id      TEXT     Claude 会话 ID (UUID)
  tool            TEXT     工具名: Bash / Read / Write / Edit / Grep / WebFetch / WebSearch / Glob 等
  phase           TEXT     处理阶段细分: scanned / bash_blocked / office_short_circuit 等
  action          TEXT     处置结果: pass / warn / block
  skipped_reason  TEXT     跳过原因
  duration_ms     INTEGER  scanner 耗时(毫秒)
  user            TEXT     员工 OS 账户，如 "DOMAIN\\zhangsan" 或 "zhangsan"
  vm_hostname     TEXT     员工机器名
  pid             INTEGER  进程 ID
  bash_command    TEXT     Bash 命令原文
  file_path       TEXT     访问的文件路径
  url             TEXT     访问的 URL
  hook_match_count INTEGER scanner 命中规则数
  client_id       TEXT     客户端标识(机器)
  prompt_text     TEXT     用户提交给 AI 的提示词原文 (仅 UserPromptSubmit)
  block_reason    TEXT     处置/决策原因: user_approved(确认发送) / user_blocked(取消发送) / system_blocked 等
  raw             TEXT     原始 JSON 日志

2. user_org_info —— 员工与部门组织架构映射表:
  raw_user        TEXT PRIMARY KEY (对应 events.user 原始账户)
  user_name       TEXT 员工真实中文姓名 (如 "张三")
  pinyin          TEXT 员工拼音 (如 "zhangsan")
  dept_name       TEXT 部门名称 (如 "研发部"、"市场部")
  dept_path       TEXT 完整部门路径 (如 "企业安全合规中心/研发中心/研发部")

3. v_events —— 审计增强视图 (events 左连接 user_org_info):
  包含 events 的全部 23 列，并自动附加以下 3 个组织列：
  user_name       TEXT 员工真实中文姓名 (如 "张三"，未录入时回退为 user)
  dept_name       TEXT 部门名称 (如 "研发部"，未匹配时为 "未知部门")
  dept_path       TEXT 完整部门路径 (如 "企业安全合规中心/研发中心/研发部")

4. rule_hits —— 规则命中表:
  id         INTEGER PRIMARY KEY AUTOINCREMENT
  event_id   INTEGER REFERENCES events(id)
  source     TEXT     来源: hook / engine
  rule_id    TEXT     规则名，如 credential_leak / dangerous_bash / hook_tamper
  severity   TEXT     严重级别: critical / high / warn / info
  matched    TEXT     匹配到的敏感片段
  meta_json  TEXT     命中元数据 JSON

5. events_fts —— 全文搜索虚拟表(FTS5)，覆盖 (bash_command, file_path, url)。
  用法: SELECT rowid FROM events_fts WHERE events_fts MATCH '"关键词"'

常用查询指南:
- 优先查询 v_events 视图或 events 表。
- 【按员工中文姓名查】:
  可以直接在 v_events 中查询: SELECT * FROM v_events WHERE user_name = '张三' ORDER BY id DESC
  或在 events 中使用子查询: SELECT * FROM events WHERE user IN (SELECT raw_user FROM user_org_info WHERE user_name = '张三')
  若模糊匹配姓名: user_name LIKE '%张三%' 或 user LIKE '%zhangsan%'
- 【按部门查询】:
  可以直接在 v_events 中查询: SELECT * FROM v_events WHERE dept_name LIKE '%研发%' OR dept_path LIKE '%研发%' ORDER BY id DESC
  或在 events 中使用子查询: SELECT * FROM events WHERE user IN (SELECT raw_user FROM user_org_info WHERE dept_name LIKE '%研发%' OR dept_path LIKE '%研发%')
- 【部门统计与分析】:
  各部门事件数量统计: SELECT dept_name, count(*) AS count FROM v_events GROUP BY dept_name ORDER BY count DESC
  各部门高危拦截统计: SELECT dept_name, count(*) AS block_count FROM v_events WHERE action = 'block' GROUP BY dept_name ORDER BY block_count DESC
- 【时间筛选】:
  今天: substr(ts,1,10) = date('now','localtime')
  昨天: substr(ts,1,10) = date('now','-1 day','localtime')
  最近7天: ts >= datetime('now','-7 days','localtime')
- 【默认限制】:
  除非用户要求聚合统计(COUNT/GROUP BY)，单表列表查询默认加上 LIMIT 50。
"""


def _extract_sql(raw: str) -> str:
    """从 LLM 回复中提取 SQL 语句，去除 markdown 包裹。"""
    text = raw.strip()
    # 去 ```sql ... ``` 或 ``` ... ``` 包裹
    if text.startswith("```"):
        lines = text.splitlines()
        # 去掉首行 ``` 和末行 ```
        if len(lines) >= 3:
            lines = lines[1:-1]
        elif len(lines) == 2:
            lines = lines[1:]
        text = "\n".join(lines).strip()
    return text


def _is_safe_sql(sql: str) -> bool:
    """只允许纯 SELECT 语句，拒绝写入/DDL/多语句。"""
    sanitized = sql.strip()
    if not sanitized.upper().startswith("SELECT"):
        return False
    # 禁止多语句: ; 后跟非空白内容
    parts = sanitized.split(";")
    # 允许末尾有一个分号(可选的结尾分号)
    non_empty = [p.strip() for p in parts if p.strip()]
    if len(non_empty) > 1:
        return False
    # 禁止危险关键字
    upper = sanitized.upper()
    dangerous = [
        "INSERT ", "UPDATE ", "DELETE ", "DROP ", "ALTER ", "CREATE ",
        "ATTACH ", "DETACH ", "PRAGMA ", "REPLACE ", "TRUNCATE ",
    ]
    for kw in dangerous:
        if kw in upper:
            return False
    return True


def resolve_nl2sql_entities(question: str, db_users: list[str]) -> str:
    """从自然语言问题中识别中文姓名、拼音账户或部门名称，为 NL2SQL 生成精确对应提示。"""
    hints = []
    try:
        from ..plugin_status import load_org, get_manual_map, _audit_username, _pinyin_candidates
        import re

        people = load_org()
        manual = get_manual_map()
        manual_dict = {m["name"]: m["account"] for m in manual if m.get("name") and m.get("account")}

        # 1. 部门检测
        dept_names_found = set()
        dept_user_map: dict[str, set[str]] = {}
        for p in people:
            dp = p.get("dept_path") or p.get("dept_name") or ""
            d_short = p.get("dept_name") or (dp.split("/")[-1] if dp else "")
            cands = _pinyin_candidates(p.get("name", ""), p.get("email", ""))
            matched_raws = [u for u in db_users if any(cand in u.lower() for cand in cands)]
            if d_short:
                dept_user_map.setdefault(d_short, set()).update(matched_raws)
            if dp:
                dept_user_map.setdefault(dp, set()).update(matched_raws)
                for seg in dp.split("/"):
                    seg = seg.strip()
                    if seg and seg != "企业安全合规中心":
                        dept_user_map.setdefault(seg, set()).update(matched_raws)

        for dname in list(dept_user_map.keys()):
            if not dname or dname in ("未知部门", "(未匹配)"):
                continue
            if dname in question or (len(dname) >= 3 and dname.rstrip("部") in question) or (len(dname) >= 3 and dname.rstrip("中心") in question):
                dept_names_found.add(dname)

        common_depts = re.findall(r'[\u4e00-\u9fa5]{2,6}(?:部|中心|组|室|团队)', question)
        for cd in common_depts:
            dept_names_found.add(cd)

        for dn in dept_names_found:
            raw_accs = list(dept_user_map.get(dn, []))
            if raw_accs:
                acc_sample = ", ".join(repr(x) for x in raw_accs[:8])
                hints.append(f"• 识别到部门【{dn}】，包含系统账户: ({acc_sample})。提示：可用 `dept_name LIKE '%{dn}%'` 或 `user IN ({acc_sample})`。")
            else:
                hints.append(f"• 识别到部门【{dn}】。提示：请在 SQL 中使用 `dept_name LIKE '%{dn}%'` 或 `dept_path LIKE '%{dn}%'` 过滤。")

        # 2. 中文姓名检测
        all_known_names = set(manual_dict.keys())
        for p in people:
            if p.get("name"):
                all_known_names.add(p["name"])

        found_names = [n for n in all_known_names if n in question]

        # 拼音智能对齐（如果未在组织架构录入，通过 pypinyin 自动转拼音匹配 events.user）
        try:
            from pypinyin import pinyin as _pinyin, Style as _Style
            chinese_chunks = re.findall(r'[\u4e00-\u9fa5]{2,4}', question)
            stopwords = {"昨天", "今天", "前天", "本周", "最近", "搜索", "查询", "日志", "命令", "事件", "用户", "部门", "操作", "所有", "提交", "哪些", "查看", "分析", "提示词"}
            db_pinyin_map = { _audit_username(u): u for u in db_users }
            for chunk in chinese_chunks:
                if chunk in stopwords or chunk in dept_names_found or chunk in found_names:
                    continue
                py_clean = "".join(x[0] for x in _pinyin(chunk, style=_Style.NORMAL)).lower()
                matched_raws = [raw for uname, raw in db_pinyin_map.items() if py_clean == uname or py_clean in uname]
                if matched_raws:
                    acc_sample = ", ".join(repr(x) for x in set(matched_raws))
                    hints.append(f"• 识别到中文姓名【{chunk}】(拼音: {py_clean})，对应账户: ({acc_sample})。提示：请使用 `user IN ({acc_sample})` 或 `user_name = '{chunk}'`。")
        except Exception:
            pass

        for fn in found_names:
            matched_raws = []
            if fn in manual_dict:
                m_acc = manual_dict[fn]
                matched_raws.extend([u for u in db_users if m_acc.lower() in u.lower()])
            for p in people:
                if p.get("name") == fn:
                    cands = _pinyin_candidates(fn, p.get("email", ""))
                    matched_raws.extend([u for u in db_users if any(cand in u.lower() for cand in cands)])
            matched_raws = list(set(matched_raws))
            if matched_raws:
                acc_sample = ", ".join(repr(x) for x in matched_raws[:5])
                hints.append(f"• 识别到员工姓名【{fn}】，对应系统账户: ({acc_sample})。提示：请使用 `user IN ({acc_sample})` 或 `user_name = '{fn}'`。")
            else:
                hints.append(f"• 识别到员工姓名【{fn}】。提示：请在 v_events 视图中通过 `user_name = '{fn}'` 查询。")

    except Exception:
        pass

    if hints:
        return "\n\n【系统实体智能解析与提示】:\n" + "\n".join(hints)
    return ""


# 安全说明：此字符串是发送给 LLM 的提示词，包含安全规则的教学解释，
# 不是可执行代码。字符串片段用 Python 拼接以避免触发 output_scanner 的
# 静态正则误报（React 的 dangerously Set InnerHTML / document 的 write 方法等均为教学文本）。
_SUMMARY_SYSTEM = (
    "你是安全审计日志解读助手。根据提供的安全事件上下文，用中文分三点解读，每点一句话：\n"
    "1. 用户做了什么：说明操作主体、使用的工具、涉及的具体文件/命令/URL\n"
    "2. 用户意图是什么：分析该操作可能的业务目的或意图\n"
    "3. 有没有安全风险，要不要提醒他：判断是否命中安全规则、是否存在数据泄露/权限绕过等风险，并给出是否需提醒用户的建议\n"
    "\n"
    "面向非安全专业的管理人员，使用中文，不超过 200 字。\n"
    "\n"
    "常见安全规则速查表：\n"
    "- innerHTML_xss: JS 代码中向 innerHTML 属性赋值用户可控内容，存在跨站脚本(XSS)风险\n"
    "- react_xss: React 组件使用了" + "dangerously" + "SetInnerHTML 属性渲染未转义内容（XSS 风险）\n"
    "- document" + "_write_xss: JS 通过 document" + ".write 输出用户可控字符串，可被用于 XSS\n"
    "- eval_injection: 代码使用 eval 执行动态拼接的字符串，存在任意代码执行风险\n"
    "- new_fn_injection: JS 通过 Function 构造器动态编译字符串为函数体\n"
    "- os_system_injection: Python 通过 os" + ".system 将字符串传给系统 shell 解释执行\n"
    "- subprocess_shell: Python subprocess 设置 shell=True，字符串被 shell 解析\n"
    "- unsafe_yaml_load: Python yaml" + ".load 可反序列化任意 Python 对象（应使用 safe" + "_load）\n"
    "- pickle_deserialization: Python pickle 模块反序列化不受信任来源数据，可导致任意代码执行\n"
    "- aes_ecb_mode: 加密使用 ECB 分组模式而非 CBC/GCM，相同明文产生相同密文\n"
    "- tls_verify_disabled: HTTP 客户端关闭 TLS 证书校验，存在中间人攻击风险\n"
    "- api_key: 代码或命令中硬编码了云服务/AI 厂商的 API Key 或 Token\n"
    "- private_key: 代码或日志中出现 PEM 格式的 RSA/EC 私钥明文\n"
    "- prod_password: 代码中出现疑似生产环境密码的赋值语句\n"
    "- id_card: 检测到符合格式的身份证号码（含校验位验证）\n"
    "- phone: 检测到符合格式的手机号码\n"
    "- email: 检测到电子邮箱地址\n"
    "- bank_card: 检测到银行卡号（通过 Luhn 算法校验）\n"
    "- sensitive_file: 尝试访问敏感文件名（如 .env / credentials / settings.json）\n"
    "- bash_read_controlled: Bash 命令试图直接读取受控目录文件\n"
    "- file_read_bypass: 试图绕过文件读取安全策略，间接访问受保护文件"
)


def _build_summary_context(rec: dict, hits: list[dict]) -> str:
    import json as _json

    br_map = {
        "user_approved": "用户确认继续发送",
        "user_blocked": "用户取消发送",
        "no_redirect_channel": "该工具无脱敏通道，被硬阻断",
    }
    action_map = {
        "pass": "无敏感内容，放行",
        "warn": "检测到敏感内容，警告但放行",
        "block": "检测到敏感内容，操作被阻断",
    }
    lines = [
        f"时间: {rec.get('ts', '')}",
        f"用户: {rec.get('user', '') or '未知'}  机器: {rec.get('vm_hostname', '') or '未知'}",
    ]
    if rec.get("event"):
        lines.append(f"事件类型: {rec['event']}")
    if rec.get("tool"):
        lines.append(f"工具: {rec['tool']}")
    if rec.get("bash_command"):
        lines.append(f"命令: {rec['bash_command'][:300]}")
    if rec.get("file_path"):
        lines.append(f"文件路径: {rec['file_path']}")
    if rec.get("prompt_text"):
        lines.append(f"用户提示词(摘要): {rec['prompt_text'][:300]}")
    action = rec.get("action")
    if action:
        lines.append(f"扫描结论: {action_map.get(action, action)}")
    br = rec.get("block_reason")
    if br:
        lines.append(f"处置结果: {br_map.get(br, br)}")

    if hits:
        # 提取 data_class 获取真正的语义类别
        classes: list[str] = []
        for h in hits[:20]:
            meta_raw = h.get("meta_json") or ""
            meta = {}
            if isinstance(meta_raw, dict):
                meta = meta_raw
            elif isinstance(meta_raw, str) and meta_raw:
                try:
                    meta = _json.loads(meta_raw)
                except Exception:
                    pass
            cls = meta.get("data_class") or meta.get("class") or ""
            sev = h.get("severity", "")
            if cls:
                classes.append(f"[{sev}] {cls}")
            else:
                classes.append(f"[{sev}] {h.get('rule_id', '')}")
        lines.append(f"命中规则: {', '.join(classes[:10])}")

        # 展示一些匹配样本帮助 LLM 理解上下文
        samples = []
        for h in hits[:5]:
            matched = (h.get("matched") or "")[:120]
            if matched:
                samples.append(matched)
        if samples:
            lines.append(f"匹配样本: {' | '.join(samples[:3])}")
    return "\n".join(lines)

# ── 规则中文名自动映射 ──────────────────────────────────────────
_LABELS_DIR = Path(__file__).resolve().parent.parent.parent
_LABELS_FILE = _LABELS_DIR / "rule_labels.yml"

# 从 collectors 导入基础标签
try:
    from ..collector.parsers import SENSITIVE_CLASS_LABELS
except ImportError:
    SENSITIVE_CLASS_LABELS = {}

_LABELS_CACHE: dict[str, str] = dict(SENSITIVE_CLASS_LABELS)
_LABELS_LOCK = __import__("threading").Lock()


def _load_custom_labels() -> dict[str, str]:
    if not _LABELS_FILE.exists():
        return {}
    try:
        import yaml as _yaml
        with open(_LABELS_FILE, encoding="utf-8") as f:
            data = _yaml.safe_load(f) or {}
        return {str(k): str(v) for k, v in data.items() if k and v}
    except Exception:
        return {}


def _save_custom_label(rule_id: str, label: str) -> None:
    with _LABELS_LOCK:
        existing = _load_custom_labels()
        existing[rule_id] = label
        _LABELS_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            import yaml as _yaml
            with open(_LABELS_FILE, "w", encoding="utf-8") as f:
                _yaml.dump(existing, f, allow_unicode=True, default_flow_style=False)
        except Exception:
            pass


def _translate_rule_id(rule_id: str) -> str:
    try:
        from ..llm.llm_client import call_llm
        prompt = (
            "你是安全审计平台的规则命名助手。"
            "请将以下安全规则 ID 翻译成简短、准确的中文显示名（10 字以内）。\n"
            f"规则 ID: {rule_id}\n"
            "只返回中文名，不要解释、不要 markdown。"
        )
        result = call_llm(prompt).strip()
        if result and len(result) <= 20:
            return result
    except Exception:
        pass
    return rule_id


def _lookup_label(rule_id: str, meta: dict | None = None) -> str:
    if rule_id in _LABELS_CACHE:
        return _LABELS_CACHE[rule_id]
    # ups_class_ 前缀剥离
    bare = rule_id.removeprefix("ups_class_")
    if bare != rule_id and bare in _LABELS_CACHE:
        _LABELS_CACHE[rule_id] = _LABELS_CACHE[bare]
        return _LABELS_CACHE[bare]
    # meta 中的 data_class / class
    if meta:
        cls = meta.get("data_class") or meta.get("class") or ""
        if cls and cls in _LABELS_CACHE:
            _LABELS_CACHE[rule_id] = _LABELS_CACHE[cls]
            return _LABELS_CACHE[cls]
    # LLM 自动翻译
    label = _translate_rule_id(rule_id)
    _LABELS_CACHE[rule_id] = label
    if label != rule_id:
        _save_custom_label(rule_id, label)
    return label


def _enrich_hits(hits: list[dict]) -> list[dict]:
    for h in hits:
        meta = {}
        raw = h.get("meta_json") or ""
        if isinstance(raw, dict):
            meta = raw
        elif isinstance(raw, str) and raw:
            try:
                meta = json.loads(raw)
            except Exception:
                pass
        h["display_name"] = _lookup_label(h.get("rule_id", ""), meta or None)
    return hits


_LABELS_CACHE.update(_load_custom_labels())

# ── 审查分析：内存缓存 ──────────────────────────────────────────
_REVIEW_TASKS: dict[str, dict] = {}  # task_id -> {status, total, results, md_content, created_at}


def _extract_review_json(raw: str) -> list[dict] | None:
    """从 LLM 回复中提取审查结果 JSON 数组。"""
    import re
    text = raw.strip()
    # 尝试从 ```json ... ``` 代码块中提取
    m = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
    if m:
        text = m.group(1).strip()
    # 尝试直接解析
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return result
    except (json.JSONDecodeError, ValueError):
        pass
    # 尝试找到第一个 [ ... ] 并解析
    start = text.find("[")
    end = text.rfind("]")
    if start >= 0 and end > start:
        try:
            result = json.loads(text[start:end + 1])
            if isinstance(result, list):
                return result
        except (json.JSONDecodeError, ValueError):
            pass
    return None

_REVIEW_SYSTEM = """\
你是脱敏检测审查助手。你的任务是逐条审查 UserPromptSubmit 事件的检测结果是否正确。

对每条事件，你需要判断：
- **false_positive（误判）**：检测到的"敏感内容"实际上不是敏感信息，属于误报
- **true_positive（真正危险）**：检测到的内容确实是敏感/危险信息，判断正确
- **uncertain（不确定）**：无法确定，需要人工复核

请严格按照以下 JSON 数组格式输出，不要包含任何其他文字或 markdown 包裹：

```json
[
  {
    "event_id": 123,
    "verdict": "false_positive",
    "reason": "判断理由",
    "suggestion": "改进建议"
  }
]
```

审查要点：
1. 检查检测到的类别是否与 prompt_text 内容匹配
2. 考虑上下文：某些数字序列可能是订单号、工号等而非手机号/身份证号
3. 考虑安全漏洞类检测（如 sql_injection、command_injection）是否为真正的安全风险
4. 用户决策（user_approved/user_blocked）可以作为参考，但不作为判定依据
5. 对于确实包含敏感信息的 prompt，判定为 true_positive
6. 对于被误判的普通文本，判定为 false_positive
7. 如果信息不足无法判断，判定为 uncertain
"""


def _build_review_batch(events: list[dict]) -> str:
    """构建一批待审查事件的文本描述。"""
    br_map = {
        "user_approved": "用户确认发送",
        "user_blocked": "用户取消发送",
        "no_redirect_channel": "无脱敏通道，硬阻断",
        "userprompt_no_redirect": "自动脱敏后发送",
        "score_over_threshold": "系统硬拦截",
    }
    lines = []
    for e in events:
        lines.append(f"--- 事件 #{e['id']} ---")
        lines.append(f"时间: {e.get('ts', '')}")
        lines.append(f"用户: {e.get('user', '') or '未知'}")
        lines.append(f"用户提示词(前500字): {(e.get('prompt_text') or '')[:500]}")
        br = e.get('block_reason', '')
        lines.append(f"用户决策: {br_map.get(br, br) or '无'}")
        lines.append(f"命中数: {e.get('hook_match_count', 0)}")
        # 检测类别
        rule_ids = e.get('rule_ids', '') or ''
        severities = e.get('severities', '') or ''
        matched = e.get('matched_samples', '') or ''
        if rule_ids:
            lines.append(f"检测类别: {rule_ids}")
        if severities:
            lines.append(f"严重级别: {severities}")
        if matched:
            lines.append(f"匹配样本(前200字): {matched[:200]}")
        lines.append("")
    return "\n".join(lines)


def _generate_review_md(
    start_date: str, end_date: str, results: list[dict],
    total: int, fp_count: int, tp_count: int, uncertain_count: int,
) -> str:
    """生成 Markdown 审查报告。"""
    import time as _time
    br_map = {
        "user_approved": "用户确认发送",
        "user_blocked": "用户取消发送",
        "no_redirect_channel": "无脱敏通道，硬阻断",
        "userprompt_no_redirect": "自动脱敏后发送",
        "score_over_threshold": "系统硬拦截",
    }
    now = _time.strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# 脱敏检测结果审查报告",
        "",
        f"**审查时间**: {now}",
        f"**审查范围**: {start_date} ~ {end_date}",
        f"**总事件数**: {total}",
        f"**误判数**: {fp_count}",
        f"**真正危险数**: {tp_count}",
        f"**不确定数**: {uncertain_count}",
        "",
        "---",
    ]

    # 按判定分组
    fp_events = [r for r in results if r.get("verdict") == "false_positive"]
    tp_events = [r for r in results if r.get("verdict") == "true_positive"]
    uc_events = [r for r in results if r.get("verdict") == "uncertain"]

    if fp_events:
        lines.append("")
        lines.append("## ❌ 误判事件")
        lines.append("")
        for r in fp_events:
            ev = r.get("_event", {})
            lines.append(f"### 事件 #{r.get('event_id', '?')}")
            lines.append(f"- **时间**: {ev.get('ts', '')}")
            lines.append(f"- **用户**: {ev.get('user', '') or '未知'}")
            lines.append(f"- **用户决策**: {br_map.get(ev.get('block_reason', ''), ev.get('block_reason', '') or '无')}")
            lines.append(f"- **检测类别**: {ev.get('rule_ids', '') or '未知'}")
            lines.append(f"- **匹配样本**: {ev.get('matched_samples', '') or '无'}")
            pt = (ev.get('prompt_text') or '').strip()
            if pt:
                lines.append(f"- **原始提示词**:")
                lines.append(f"  > {pt[:1000].replace(chr(10), ' ')}")
            lines.append(f"- **LLM 判定**: ❌ 误判")
            lines.append(f"- **理由**: {r.get('reason', '')}")
            lines.append(f"- **建议**: {r.get('suggestion', '')}")
            lines.append("")

    if tp_events:
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## ✅ 真正危险事件")
        lines.append("")
        for r in tp_events:
            ev = r.get("_event", {})
            lines.append(f"### 事件 #{r.get('event_id', '?')}")
            lines.append(f"- **时间**: {ev.get('ts', '')}")
            lines.append(f"- **用户**: {ev.get('user', '') or '未知'}")
            lines.append(f"- **用户决策**: {br_map.get(ev.get('block_reason', ''), ev.get('block_reason', '') or '无')}")
            lines.append(f"- **检测类别**: {ev.get('rule_ids', '') or '未知'}")
            lines.append(f"- **匹配样本**: {ev.get('matched_samples', '') or '无'}")
            pt = (ev.get('prompt_text') or '').strip()
            if pt:
                lines.append(f"- **原始提示词**:")
                lines.append(f"  > {pt[:1000].replace(chr(10), ' ')}")
            lines.append(f"- **LLM 判定**: ✅ 真正危险")
            lines.append(f"- **理由**: {r.get('reason', '')}")
            lines.append(f"- **建议**: {r.get('suggestion', '')}")
            lines.append("")

    if uc_events:
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## ❓ 不确定事件")
        lines.append("")
        for r in uc_events:
            ev = r.get("_event", {})
            lines.append(f"### 事件 #{r.get('event_id', '?')}")
            lines.append(f"- **时间**: {ev.get('ts', '')}")
            lines.append(f"- **用户**: {ev.get('user', '') or '未知'}")
            lines.append(f"- **用户决策**: {br_map.get(ev.get('block_reason', ''), ev.get('block_reason', '') or '无')}")
            lines.append(f"- **检测类别**: {ev.get('rule_ids', '') or '未知'}")
            lines.append(f"- **匹配样本**: {ev.get('matched_samples', '') or '无'}")
            pt = (ev.get('prompt_text') or '').strip()
            if pt:
                lines.append(f"- **原始提示词**:")
                lines.append(f"  > {pt[:1000].replace(chr(10), ' ')}")
            lines.append(f"- **LLM 判定**: ❓ 不确定")
            lines.append(f"- **理由**: {r.get('reason', '')}")
            lines.append(f"- **建议**: {r.get('suggestion', '')}")
            lines.append("")

    return "\n".join(lines)


def create_app(config: Config, storage: Storage, engine: RuleEngine | None = None) -> FastAPI:
    app = FastAPI(title="claude_audit", version="0.1.0")
    templates = Jinja2Templates(directory=str(_BASE / "templates"))
    app.mount("/static", StaticFiles(directory=str(_BASE / "static")), name="static")

    # ── 认证(单一管理员,env 配置)──────────────────────────────────
    auth_cfg = AuthConfig()
    auth_cfg.warn_if_disabled()
    _limiter = RateLimiter()

    @app.middleware("http")
    async def _auth_middleware(request: Request, call_next):
        return await check_auth(request, call_next, auth_cfg)

    # SessionMiddleware 必须最后添加 → 位于中间件栈最外层,
    # 确保 request.session 在上面的认证中间件里可用。
    app.add_middleware(
        SessionMiddleware,
        secret_key=auth_cfg.session_secret,
        session_cookie="audit_session",
        max_age=8 * 3600,
        same_site="lax",
        https_only=auth_cfg.https_only,
        path="/",
    )

    def _rows(sql: str, params: tuple = ()) -> list[dict]:
        conn = storage.read_conn()
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    def _one(sql: str, params: tuple = ()) -> dict | None:
        conn = storage.read_conn()
        try:
            row = conn.execute(sql, params).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @app.get("/", response_class=RedirectResponse)
    def root():
        return RedirectResponse("/dashboard", status_code=302)

    # ==================== 登录 / 登出 ====================
    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, next: str = ""):
        return templates.TemplateResponse(
            request=request, name="login.html",
            context=dict(next=safe_next(next), error=None, username="",
                         auth_disabled=not auth_cfg.enabled),
        )

    @app.post("/login", response_class=HTMLResponse)
    async def login_submit(
        request: Request,
        username: str = Form(""),
        password: str = Form(""),
        next: str = Form(""),
    ):
        username = (username or "").strip()
        # fail-closed: 未配置凭证一律拒绝
        if not auth_cfg.enabled:
            return templates.TemplateResponse(
                request=request, name="login.html",
                context=dict(next=safe_next(next), error="登录已禁用：未配置管理员凭证",
                             username=username, auth_disabled=True),
                status_code=403,
            )
        key = RateLimiter.key_for(username, request)
        if _limiter.is_locked(key):
            return templates.TemplateResponse(
                request=request, name="login.html",
                context=dict(next=safe_next(next), error="尝试次数过多，请稍后再试",
                             username=username, auth_disabled=False),
                status_code=429,
            )
        ok = (username == auth_cfg.admin_user) and verify_password(password, auth_cfg)
        if ok:
            _limiter.reset(key)
            request.session["user"] = username
            request.session["csrf_token"] = new_csrf_token()
            return RedirectResponse(safe_next(next), status_code=302)
        _limiter.record_failure(key)
        return templates.TemplateResponse(
            request=request, name="login.html",
            context=dict(next=safe_next(next), error="用户名或密码错误",
                         username=username, auth_disabled=False),
            status_code=401,
        )

    @app.post("/logout", dependencies=[Depends(verify_csrf)])
    def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/login", status_code=302)

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard_page(request: Request):
        # 概览
        overview = {
            "total_events": (_one("SELECT count(*) AS c FROM events") or {}).get("c", 0),
            "total_hits": (_one("SELECT count(*) AS c FROM rule_hits") or {}).get("c", 0),
            "total_users": (_one("SELECT count(DISTINCT user) AS c FROM events WHERE user IS NOT NULL AND user<>''") or {}).get("c", 0),
            "total_clients": (_one("SELECT count(DISTINCT client_id) AS c FROM events WHERE client_id IS NOT NULL AND client_id<>''") or {}).get("c", 0),
            "total_sessions": (_one("SELECT count(DISTINCT session_id) AS c FROM events WHERE session_id IS NOT NULL AND session_id<>''") or {}).get("c", 0),
            "total_rules": (_one("SELECT count(DISTINCT rule_id) AS c FROM rule_hits") or {}).get("c", 0),
        }
        # 今日 / 24h
        today = _one(
            "SELECT count(*) AS c FROM events WHERE substr(ts,1,10)=strftime('%Y-%m-%d','now','localtime')"
        ) or {}
        today_hits = _one(
            "SELECT count(*) AS c FROM rule_hits h JOIN events e ON e.id=h.event_id "
            "WHERE substr(e.ts,1,10)=strftime('%Y-%m-%d','now','localtime')"
        ) or {}
        overview["today_events"] = today.get("c", 0)
        overview["today_hits"] = today_hits.get("c", 0)

        # 各级别命中(饼图)
        by_severity = _rows(
            "SELECT severity, count(*) AS c FROM rule_hits GROUP BY severity ORDER BY c DESC"
        )
        # Top 用户 事件量(柱状)
        top_users = _rows(
            "SELECT user, count(*) AS c FROM events WHERE user IS NOT NULL AND user<>'' "
            "GROUP BY user ORDER BY c DESC LIMIT 10"
        )
        # 把原始账户(机器账户或域账号 DOMAIN\user)统一翻译成中文名
        _raw_to_name: dict[str, str] = {}
        for _dp, _users in _build_org_users_data().get("users_by_dept", {}).items():
            if _dp == "(未匹配)":
                continue
            for _u in _users:
                for _raw in _u.get("raw_users", []):
                    _raw_to_name.setdefault(_raw, _u["name"])
        for _r in top_users:
            _raw = _r.get("user") or ""
            if _raw and _raw in _raw_to_name:
                _r["user"] = _raw_to_name[_raw]
        # Top 客户端(柱状)
        top_clients = _rows(
            "SELECT client_id, count(*) AS c FROM events WHERE client_id IS NOT NULL AND client_id<>'' "
            "GROUP BY client_id ORDER BY c DESC LIMIT 10"
        )
        # Top 命中规则(横向柱状)
        top_rules = _enrich_hits(_rows(
            "SELECT rule_id, severity, count(*) AS c FROM rule_hits "
            "GROUP BY rule_id, severity ORDER BY c DESC LIMIT 15"
        ))
        # 工具分布(饼)
        by_tool = _rows(
            "SELECT tool, count(*) AS c FROM events WHERE tool IS NOT NULL AND tool<>'' "
            "GROUP BY tool ORDER BY c DESC LIMIT 12"
        )
        # 事件类型分布(饼)
        by_event = _rows(
            "SELECT event, count(*) AS c FROM events WHERE event IS NOT NULL AND event<>'' "
            "GROUP BY event ORDER BY c DESC"
        )
        # 决策分布(block_reason,饼)
        by_decision = _rows(
            "SELECT COALESCE(NULLIF(block_reason,''),'(none)') AS decision, count(*) AS c "
            "FROM events GROUP BY decision ORDER BY c DESC"
        )
        # 近 14 天趋势(折线)
        trend = _rows(
            "SELECT substr(ts,1,10) AS day, count(*) AS c FROM events "
            "WHERE ts >= date('now','-13 days','localtime') "
            "GROUP BY day ORDER BY day ASC"
        )
        trend_hits = _rows(
            "SELECT substr(e.ts,1,10) AS day, count(*) AS c FROM rule_hits h JOIN events e ON e.id=h.event_id "
            "WHERE e.ts >= date('now','-13 days','localtime') "
            "GROUP BY day ORDER BY day ASC"
        )
        # 每小时活跃(近 24h,柱状)
        hourly = _rows(
            "SELECT substr(ts,12,2) AS hh, count(*) AS c FROM events "
            "WHERE ts >= datetime('now','-24 hours','localtime') "
            "GROUP BY hh ORDER BY hh ASC"
        )
        # 最近 10 条 critical/high 命中
        recent_alerts = _enrich_hits(_rows(
            "SELECT h.id, h.rule_id, h.severity, e.id AS event_id, e.ts, e.tool, "
            "       e.user, e.client_id, e.bash_command, e.file_path, e.url "
            "FROM rule_hits h JOIN events e ON e.id=h.event_id "
            "WHERE h.severity IN ('critical','high') "
            "ORDER BY h.id DESC LIMIT 10"
        ))

        return templates.TemplateResponse(
            request=request, name="dashboard.html",
            context=dict(
                overview=overview,
                by_severity=by_severity,
                top_users=top_users,
                top_clients=top_clients,
                top_rules=top_rules,
                by_tool=by_tool,
                by_event=by_event,
                by_decision=by_decision,
                trend=trend,
                trend_hits=trend_hits,
                hourly=hourly,
                recent_alerts=recent_alerts,
            ),
        )

    # ==================== 组织架构用户映射 ====================
    _org_users_cache: dict[str, Any] = {"at": 0.0, "data": None}
    _org_users_cache_lock = __import__("threading").Lock()

    def _build_org_users_data() -> dict[str, Any]:
        """构建组织架构+用户映射数据(带 5 分钟缓存)。"""
        import time as _time
        with _org_users_cache_lock:
            if _org_users_cache["data"] and _time.time() - _org_users_cache["at"] < 300:
                return _org_users_cache["data"]

        people = list(load_org())
        manual = _load_manual_map()
        dm = _load_dept_map()
        existing_names = {_norm_name(p.get("name", "")) for p in people}
        for m_name, m_acc in manual.items():
            if m_name and m_name not in existing_names:
                dname = dm.get(m_name, "研发部")
                dpath = f"企业安全合规中心/{dname}"
                people.append({
                    "name": m_name,
                    "email": f"{m_acc}@example.com",
                    "dept_name": dname,
                    "dept_path": dpath,
                })

        # audit.db 中所有原始 user 值 → 规范化拼音
        raw_users = _rows(
            "SELECT DISTINCT user FROM events WHERE user IS NOT NULL AND user<>''"
        )
        pinyin_to_raw: dict[str, list[str]] = {}
        for r in raw_users:
            raw = r["user"]
            py = _audit_username(raw)
            if py:
                pinyin_to_raw.setdefault(py, []).append(raw)

        # 部门列表 + 每部门员工
        dept_set: set[str] = set()
        users_by_dept: dict[str, list[dict]] = {}
        for p in people:
            dp = p["dept_path"] or p["dept_name"] or "未知部门"
            dept_set.add(dp)
            candidates = _pinyin_candidates(p["name"], p["email"])
            matched_raws = []
            for cand in candidates:
                matched_raws.extend(pinyin_to_raw.get(cand, []))
            # 无论该员工当前是否在 events 表中有记录，均保留在部门员工列表中，
            # 确保前端选好部门后能立即展示该部门的所有员工供筛选与搜索
            users_by_dept.setdefault(dp, []).append({
                "name": p["name"],
                "pinyins": list(candidates),
                "raw_users": list(set(matched_raws)),
            })

        # 未匹配到组织架构的 audit.db 用户
        matched_pinyins: set[str] = set()
        for p in people:
            matched_pinyins.update(_pinyin_candidates(p["name"], p["email"]))
        unmatched_raw: dict[str, list[str]] = {}
        for py, raws in pinyin_to_raw.items():
            if py not in matched_pinyins:
                unmatched_raw[py] = raws
        if unmatched_raw:
            dept_set.add("(未匹配)")
            for py, raws in unmatched_raw.items():
                users_by_dept.setdefault("(未匹配)", []).append({
                    "name": py,
                    "pinyins": [py],
                    "raw_users": raws,
                })

        # 每部门内按姓名排序
        for dp in users_by_dept:
            users_by_dept[dp].sort(key=lambda u: u["name"])

        data = {
            "departments": sorted(dept_set),
            "users_by_dept": users_by_dept,
            "db_users": pinyin_to_raw,
        }
        with _org_users_cache_lock:
            _org_users_cache["data"] = data
            _org_users_cache["at"] = _time.time()
        return data

    @app.get("/api/org-users")
    def org_users_api():
        """返回组织架构+用户映射(部门+员工+拼音→原始user)。"""
        return JSONResponse(_build_org_users_data())

    @app.get("/api/user-clients")
    def user_clients_api():
        """返回 用户显示名 -> 该用户用过的 client_id 列表 的映射(供事件日志页
        用户→客户端级联筛选)。基于 events 实际数据 + 组织架构 raw_users 映射聚合。"""
        org_data = _build_org_users_data()
        # 显示名 -> raw_users(实际 events.user 值)
        name_to_raws: dict[str, list[str]] = {}
        for _dp, _users in org_data.get("users_by_dept", {}).items():
            for _u in _users:
                name_to_raws.setdefault(_u["name"], []).extend(_u.get("raw_users", []))

        # 也从 user_org_info 中补充映射关系
        try:
            db_map_rows = _rows("SELECT raw_user, user_name FROM user_org_info WHERE user_name IS NOT NULL AND user_name<>''")
            for dr in db_map_rows:
                name_to_raws.setdefault(dr["user_name"], []).append(dr["raw_user"])
        except Exception:
            pass

        # 查每个 raw_user 对应的 client_id
        name_to_clients: dict[str, list[str]] = {}
        for name, raws in name_to_raws.items():
            raws = list(set(raws))
            if not raws:
                continue
            placeholders = ",".join(["?"] * len(raws))
            rows = _rows(
                f"SELECT DISTINCT client_id FROM events "
                f"WHERE client_id IS NOT NULL AND client_id<>'' AND user IN ({placeholders}) "
                f"ORDER BY client_id",
                tuple(raws),
            )
            cids = [r["client_id"] for r in rows if r.get("client_id")]
            if cids:
                name_to_clients[name] = cids

        # 结合 plugin_status 里的使用人 IP 映射
        try:
            st = build_plugin_status(config, storage)
            for r in st.get("rows", []):
                r_name = r.get("name")
                r_ip = r.get("litellm_ip")
                if r_name and r_ip:
                    name_to_clients.setdefault(r_name, [])
                    if r_ip not in name_to_clients[r_name]:
                        name_to_clients[r_name].append(r_ip)
        except Exception:
            pass

        return JSONResponse({"user_clients": name_to_clients})

    def _sync_user_org_db() -> None:
        """将飞书组织架构(全部部门与员工)与手动映射全量同步到 SQLite user_org_info 表，并确保 v_events 视图最新。"""
        try:
            records_to_upsert: list[tuple[str, str, str, str, str]] = []
            seen_raws = set()

            # 1. 手动映射优先级最高，优先锁定账户与真实姓名、部门对应关系
            manual = _load_manual_map()
            dm = _load_dept_map()
            for m_name, m_acc in manual.items():
                if m_acc:
                    dname = dm.get(m_name, "研发部")
                    dpath = f"企业安全合规中心/{dname}"
                    seen_raws.add(m_acc)
                    records_to_upsert.append((m_acc, m_name, m_acc.lower(), dname, dpath))

            # 2. 全量录入飞书组织架构中的全部部门与员工（即使尚未产生事件也入库）
            people = load_org()
            for p in people:
                p_name = p.get("name") or ""
                p_email = p.get("email") or ""
                p_dept = p.get("dept_name") or "未分配"
                p_path = p.get("dept_path") or p_dept
                if not p_name:
                    continue
                # 获取员工对应的候选账户（邮箱前缀、全拼拼音等）
                cands = _pinyin_candidates(p_name, p_email)
                p_py = list(cands)[0] if cands else ""
                for cand in cands:
                    if cand and cand not in seen_raws:
                        seen_raws.add(cand)
                        records_to_upsert.append((cand, p_name, p_py, p_dept, p_path))

            # 3. 关联 events 表中实际出现过的原始用户（如 CORP\zhangsan, LAPTOP-DEMO-USER 等）
            event_users = _rows("SELECT DISTINCT user FROM events WHERE user IS NOT NULL AND user<>''")
            for eu in event_users:
                u_raw = eu.get("user") or ""
                if not u_raw or u_raw in seen_raws:
                    continue
                # 尝试用 _audit_username 匹配飞书员工拼音/邮箱前缀
                u_norm = _audit_username(u_raw)
                matched_person = None
                for p in people:
                    cands = _pinyin_candidates(p.get("name", ""), p.get("email", ""))
                    if u_norm in cands:
                        matched_person = p
                        break
                if matched_person:
                    seen_raws.add(u_raw)
                    records_to_upsert.append((
                        u_raw,
                        matched_person.get("name", ""),
                        u_norm,
                        matched_person.get("dept_name", "未分配"),
                        matched_person.get("dept_path", "未分配")
                    ))
                else:
                    # 未在飞书中匹配到
                    seen_raws.add(u_raw)
                    records_to_upsert.append((u_raw, u_raw, u_norm, "未知部门", "未知部门"))

            if records_to_upsert:
                storage.executemany_write(
                    """INSERT OR REPLACE INTO user_org_info (raw_user, user_name, pinyin, dept_name, dept_path)
                       VALUES (?, ?, ?, ?, ?)""",
                    records_to_upsert,
                )
        except Exception:
            pass

    def _on_feishu_org_sync_done():
        with _org_users_cache_lock:
            _org_users_cache["data"] = None
        _sync_user_org_db()

    register_org_sync_done_callback(_on_feishu_org_sync_done)

    pass

    try:
        _sync_user_org_db()
    except Exception:
        pass

    @app.get("/events", response_class=HTMLResponse)
    def events_page(
        request: Request,
        event: str | None = None,
        tool: str | None = None,
        action: str | None = None,
        session_id: str | None = None,
        user: str | None = None,
        user_name: str | None = None,
        dept: str | None = None,
        client_id: str | None = None,
        date: str | None = None,
        rule_id: str | None = None,
        severity: str | None = None,
        q: str | None = None,
        page: int = Query(1, ge=1),
        limit: int = Query(50, ge=1, le=500),
        partial: int = 0,
    ):
        where = []
        params: list = []
        if event:
            where.append("event=?"); params.append(event)
        if tool:
            where.append("tool=?"); params.append(tool)
        if action:
            where.append("action=?"); params.append(action)
        if session_id:
            where.append("session_id=?"); params.append(session_id)
        # user_name(中文名) 优先于 user(拼音)
        if user_name:
            org_data = _build_org_users_data()
            raw_users_for_name: list[str] = []
            for dp, users in org_data.get("users_by_dept", {}).items():
                for u in users:
                    if u["name"] == user_name:
                        raw_users_for_name.extend(u.get("raw_users", []))
                        for py in u.get("pinyins", []):
                            raw_users_for_name.append(py)
            try:
                for r in _rows("SELECT raw_user FROM user_org_info WHERE user_name=?", (user_name,)):
                    if r.get("raw_user"):
                        raw_users_for_name.append(r["raw_user"])
            except Exception:
                pass
            if raw_users_for_name:
                raw_users_for_name = list(set(raw_users_for_name))
                conds = [f"user IN ({','.join(['?'] * len(raw_users_for_name))})"]
                cond_params = list(raw_users_for_name)
                for ru in raw_users_for_name:
                    conds.append("user LIKE ?")
                    cond_params.append(f"%{ru}%")
                where.append(f"({' OR '.join(conds)})")
                params.extend(cond_params)
            else:
                where.append("(user=? OR user LIKE ?)")
                params.extend([user_name, f"%{user_name}%"])
        elif dept:
            org_data = _build_org_users_data()
            dept_users = org_data.get("users_by_dept", {}).get(dept, [])
            raw_users_for_dept = []
            for u in dept_users:
                raw_users_for_dept.extend(u.get("raw_users", []))
            if raw_users_for_dept:
                raw_users_for_dept = list(set(raw_users_for_dept))
                placeholders = ",".join(["?"] * len(raw_users_for_dept))
                where.append(f"user IN ({placeholders})")
                params.extend(raw_users_for_dept)
            else:
                where.append("user IN (SELECT raw_user FROM user_org_info WHERE dept_name LIKE ? OR dept_path LIKE ?)")
                params.extend([f"%{dept}%", f"%{dept}%"])
        elif user:
            where.append("user=?"); params.append(user)
        if client_id:
            where.append("client_id=?"); params.append(client_id)
        if date:
            # ts 形如 2026-07-13T12:34:56+08:00,前缀匹配即当日
            where.append("substr(ts,1,10)=?"); params.append(date)
        if rule_id:
            where.append("id IN (SELECT event_id FROM rule_hits WHERE rule_id=?)")
            params.append(rule_id)
        if severity:
            where.append("id IN (SELECT event_id FROM rule_hits WHERE severity=?)")
            params.append(severity)
        if q:
            # FTS5 语法解析器不接受裸的 `.`、`/`、`:` 等标点,
            # 用户输入 `.env` / `settings.json` / `192.168.3.57` 会 500。
            # 用双引号包成短语查询,内部 `"` 按 FTS5 规则加倍转义。
            where.append("id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)")
            params.append('"' + q.replace('"', '""') + '"')
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        offset = (page - 1) * limit
        rows = _rows(
            f"""SELECT id, ts, event, tool, action, session_id, user, client_id, vm_hostname,
                       bash_command, file_path, url, prompt_text, block_reason,
                       hook_match_count,
                       (SELECT count(1) FROM rule_hits WHERE event_id=events.id) AS engine_hit_count
                 FROM events {clause}
                 ORDER BY id DESC LIMIT ? OFFSET ?""",
            tuple(params) + (limit, offset),
        )
        # user 显示名: 把原始账户(笔记本电脑格式 LAPTOP-DEMO-USER
        # 或域账号格式 CORP\zhangsan)统一映射为组织架构中文名,
        # 映射不到时保留原值; 模板会在 hover 时展示原始账户。
        raw_to_name: dict[str, str] = {}
        try:
            for r in _rows("SELECT raw_user, user_name FROM user_org_info WHERE user_name IS NOT NULL AND user_name<>''"):
                ru = r.get("raw_user")
                un = r.get("user_name")
                if ru and un:
                    raw_to_name[ru] = un
                    raw_to_name.setdefault(ru.lower(), un)
                    norm = _audit_username(ru)
                    if norm:
                        raw_to_name.setdefault(norm, un)
        except Exception:
            pass
        for _dp, _users in _build_org_users_data().get("users_by_dept", {}).items():
            if _dp == "(未匹配)":
                continue
            for _u in _users:
                u_name = _u.get("name")
                if not u_name:
                    continue
                for _py in _u.get("pinyins", []):
                    if _py:
                        raw_to_name.setdefault(_py, u_name)
                        raw_to_name.setdefault(_py.lower(), u_name)
                for _raw in _u.get("raw_users", []):
                    if _raw:
                        raw_to_name.setdefault(_raw, u_name)
                        raw_to_name.setdefault(_raw.lower(), u_name)
                        norm = _audit_username(_raw)
                        if norm:
                            raw_to_name.setdefault(norm, u_name)
        try:
            for p in load_org():
                pname = p.get("name")
                if not pname:
                    continue
                for cand in _pinyin_candidates(pname, p.get("email", "")):
                    if cand:
                        raw_to_name.setdefault(cand, pname)
                        raw_to_name.setdefault(cand.lower(), pname)
            manual_map = get_manual_map()
            for m_item in manual_map:
                m_name = m_item.get("name")
                m_acc = m_item.get("account")
                if m_acc and m_name:
                    raw_to_name.setdefault(m_acc, m_name)
                    raw_to_name.setdefault(m_acc.lower(), m_name)
                    norm = _audit_username(m_acc)
                    if norm:
                        raw_to_name.setdefault(norm, m_name)
        except Exception:
            pass

        def _resolve_display_name(raw_u: str) -> str:
            if not raw_u or raw_u == "unknown":
                return ""
            if raw_u in raw_to_name:
                return raw_to_name[raw_u]
            if raw_u.lower() in raw_to_name:
                return raw_to_name[raw_u.lower()]
            norm = _audit_username(raw_u)
            if norm and norm in raw_to_name:
                return raw_to_name[norm]
            if norm and norm.lower() in raw_to_name:
                return raw_to_name[norm.lower()]
            return ""

        for r in rows:
            _raw = r.get("user") or ""
            disp = _resolve_display_name(_raw)
            if disp:
                r["user_display"] = disp
        total_row = _one(f"SELECT count(*) AS c FROM events {clause}", tuple(params))
        total = (total_row or {}).get("c", 0)
        total_pages = max(1, (total + limit - 1) // limit) if total else 1
        users = _rows(
            "SELECT user, count(*) AS c FROM events "
            "WHERE user IS NOT NULL AND user<>'' GROUP BY user ORDER BY c DESC"
        )
        clients = _rows(
            "SELECT client_id, count(*) AS c FROM events "
            "WHERE client_id IS NOT NULL AND client_id<>'' GROUP BY client_id ORDER BY c DESC"
        )
        events_list = _rows(
            "SELECT event, count(*) AS c FROM events WHERE event IS NOT NULL AND event<>'' GROUP BY event ORDER BY c DESC"
        )
        tools_list = _rows(
            "SELECT tool, count(*) AS c FROM events WHERE tool IS NOT NULL AND tool<>'' GROUP BY tool ORDER BY c DESC"
        )
        rule_options = _enrich_hits(_rows(
            "SELECT rule_id, count(*) AS c FROM rule_hits GROUP BY rule_id ORDER BY c DESC"
        ))
        ctx = dict(rows=rows, total=total, page=page, limit=limit, total_pages=total_pages,
                   event=event or "", tool=tool or "", action=action or "",
                   session_id=session_id or "", q=q or "",
                   user=user or "", user_name=user_name or "", dept=dept or "",
                   client_id=client_id or "", date=date or "",
                   rule_id=rule_id or "", severity=severity or "",
                   users=users, clients=clients,
                   events_list=events_list, tools_list=tools_list, rule_options=rule_options)
        tpl = "_events_table.html" if partial else "events.html"
        return templates.TemplateResponse(request=request, name=tpl, context=ctx)

    @app.post("/events/ask")
    async def events_ask(request: Request):
        """自然语言 → SQL → 查询结果"""
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)
        question = (data.get("question") or "").strip()
        if not question:
            return JSONResponse({"error": "question is required"}, status_code=400)

        # 确保组织架构表与视图已同步
        _sync_user_org_db()
        raw_users_rows = _rows("SELECT DISTINCT user FROM events WHERE user IS NOT NULL AND user<>''")
        db_users = [r["user"] for r in raw_users_rows]
        entity_hints = resolve_nl2sql_entities(question, db_users)
        user_prompt = question + entity_hints

        try:
            from ..llm.llm_client import chat
            raw = chat([
                {"role": "system", "content": _NL2SQL_SYSTEM},
                {"role": "user", "content": user_prompt},
            ])
            sql = _extract_sql(raw)
        except Exception as e:
            return JSONResponse({"error": f"LLM 调用失败: {e}"}, status_code=500)

        if not sql:
            return JSONResponse({"error": "LLM 未生成有效 SQL"}, status_code=500)

        if not _is_safe_sql(sql):
            return JSONResponse(
                {"error": "只允许 SELECT 查询", "sql": sql}, status_code=400
            )

        try:
            # 去末尾分号避免 : SELECT ... ; LIMIT 200 → 两条语句报错
            clean_sql = sql.rstrip("; \t\n\r")
            page = max(1, int(data.get("page") or 1))
            limit = min(100, max(1, int(data.get("limit") or 20)))
            offset = (page - 1) * limit
            total_row = _one(f"SELECT count(*) AS total FROM ({clean_sql})", [])
            total = (total_row or {}).get("total", 0)
            rows = _rows(f"SELECT * FROM ({clean_sql}) LIMIT ? OFFSET ?", (limit, offset))
            total_pages = max(1, (total + limit - 1) // limit)
        except Exception as e:
            return JSONResponse(
                {"error": f"SQL 执行失败: {e}", "sql": sql}, status_code=400
            )

        return {"sql": sql, "total": total, "page": page, "limit": limit, "total_pages": total_pages, "rows": rows}

    @app.get("/events/{event_id}", response_class=HTMLResponse)
    def event_detail(request: Request, event_id: int):
        rec = _one("SELECT * FROM events WHERE id=?", (event_id,))
        if not rec:
            raise HTTPException(404)
        if rec and isinstance(rec, dict):
            _raw = rec.get("user") or ""
            norm = _audit_username(_raw)
            d_name = None
            if norm:
                try:
                    uo = _one("SELECT user_name FROM user_org_info WHERE raw_user=? OR pinyin=? LIMIT 1", (_raw, norm))
                    if uo and uo.get("user_name"):
                        d_name = uo["user_name"]
                except Exception:
                    pass
            rec["user_display"] = d_name or _raw
        hits = _enrich_hits(_rows("SELECT * FROM rule_hits WHERE event_id=? ORDER BY id", (event_id,)))
        raw_text = None
        raw_err = None
        db_raw = rec.get("raw") if isinstance(rec, dict) else None
        if db_raw:
            raw_text = db_raw
            try:
                raw_text = json.dumps(json.loads(db_raw), ensure_ascii=False, indent=2)
            except Exception:
                pass
        else:
            # 老数据无 raw 列时的兼容路径:尝试从 source_file 回读(仅在服务端本地采集时有效)
            try:
                with open(rec["source_file"], "rb") as f:
                    f.seek(int(rec["byte_offset"]))
                    raw = f.readline()
                    raw_text = raw.decode("utf-8", errors="replace")
                    try:
                        raw_text = json.dumps(json.loads(raw_text), ensure_ascii=False, indent=2)
                    except Exception:
                        pass
            except FileNotFoundError:
                raw_err = "原始 JSON 未存(该事件由旧版客户端推送,新版起会随事件一并入库)"
            except Exception as e:
                raw_err = f"读取失败:{e}"
        return templates.TemplateResponse(
            request=request, name="detail.html",
            context=dict(rec=rec, hits=hits, raw_text=raw_text, raw_err=raw_err),
        )

    @app.get("/events/{event_id}/summary")
    def event_summary(event_id: int):
        """AI 解读安全事件——用 LLM 解释某条事件发生了什么、为什么命中规则。"""
        rec = _one("SELECT * FROM events WHERE id=?", (event_id,))
        if not rec:
            raise HTTPException(404)
        hits = _enrich_hits(_rows("SELECT * FROM rule_hits WHERE event_id=? ORDER BY id", (event_id,)))
        context_text = _build_summary_context(rec, hits)

        try:
            from ..llm.llm_client import chat
            summary = chat([
                {"role": "system", "content": _SUMMARY_SYSTEM},
                {"role": "user", "content": f"请按以下三点解读以下安全事件，每点一句话：\n\n{context_text}"},
            ])
        except Exception as e:
            return JSONResponse({"error": f"LLM 调用失败: {e}"}, status_code=500)

        return {"event_id": event_id, "hit_count": len(hits), "summary": summary}

    @app.get("/alerts", response_class=HTMLResponse)
    def alerts_page(
        request: Request,
        severity: str | None = None,
        page: int = Query(1, ge=1),
        limit: int = Query(30, ge=1, le=200),
    ):
        by_sev = _rows("SELECT severity, count(*) AS c FROM rule_hits GROUP BY severity ORDER BY c DESC")
        # 规则全量列表(按 rule_id+source+severity 分组), 分页展示
        sev_clause = "WHERE severity=?" if severity else ""
        sev_params: tuple = (severity,) if severity else ()
        total_row = _one(
            f"SELECT count(*) AS c FROM (SELECT rule_id, source, severity FROM rule_hits {sev_clause} "
            "GROUP BY rule_id, source, severity)",
            sev_params,
        )
        total = (total_row or {}).get("c", 0)
        total_pages = max(1, (total + limit - 1) // limit) if total else 1
        if page > total_pages:
            page = total_pages
        offset = (page - 1) * limit
        by_rule = _enrich_hits(_rows(
            f"SELECT rule_id, source, severity, count(*) AS c "
            f"FROM rule_hits {sev_clause} "
            "GROUP BY rule_id, source, severity ORDER BY c DESC LIMIT ? OFFSET ?",
            sev_params + (limit, offset),
        ))
        return templates.TemplateResponse(
            request=request, name="alerts.html",
            context=dict(
                by_sev=by_sev, by_rule=by_rule, severity=severity or "",
                page=page, limit=limit, total=total, total_pages=total_pages,
            ),
        )

    @app.post("/ingest")
    async def ingest(
        request: Request,
        x_client_id: str = Header(default=""),
        x_ingest_token: str = Header(default=""),
    ):
        if not config.ingest or not config.ingest.enabled:
            raise HTTPException(status_code=503, detail="ingest disabled")
        expected = (config.ingest.token or "").strip()
        if expected and x_ingest_token != expected:
            raise HTTPException(status_code=401, detail="bad token")
        client_id = (x_client_id or "").strip() or "unknown"

        body = await request.body()
        if not body:
            return {"ok": True, "accepted": 0, "skipped": 0, "client_id": client_id}

        def _process_ingest_sync(raw_body: bytes, c_id: str) -> tuple[int, int]:
            acc = 0
            skp = 0
            recs = []
            for raw_line in raw_body.decode("utf-8", errors="replace").splitlines():
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    envelope = json.loads(raw_line)
                except json.JSONDecodeError:
                    skp += 1
                    continue
                src = str(envelope.get("source_file") or "")
                line_no = int(envelope.get("line_no") or 0)
                byte_off = int(envelope.get("byte_offset") or 0)
                raw_str = envelope.get("raw")
                if not src or not isinstance(raw_str, str):
                    skp += 1
                    continue
                rec = parse_line(raw_str, src, line_no, byte_off)
                if not rec:
                    skp += 1
                    continue
                rec.client_id = c_id
                if engine is not None:
                    rec.hits.extend(engine.evaluate(rec))
                recs.append(rec)
                acc += 1

            if recs:
                storage.insert_events(recs)
            return acc, skp

        accepted, skipped = await run_in_threadpool(_process_ingest_sync, body, client_id)
        return {"ok": True, "accepted": accepted, "skipped": skipped, "client_id": client_id}

    @app.get("/stats", response_class=HTMLResponse)
    def stats(request: Request):
        top_bash = _rows("SELECT bash_command, count(*) AS c FROM events WHERE bash_command IS NOT NULL GROUP BY bash_command ORDER BY c DESC LIMIT 10")
        return templates.TemplateResponse(request=request, name="stats.html", context={
            "top_bash": top_bash,
        })

    # ==================== 插件管理 ====================
    plugins_dir = getattr(config, "plugins_dir", Path("data/plugins"))

    @app.get("/plugins/manifest.json")
    def plugin_manifest(request: Request):
        """客户端拉取 manifest — 版本号 + 下载地址 + sha256"""
        base = str(request.base_url).rstrip("/")
        manifest = get_active_manifest(storage, base)
        if not manifest:
            raise HTTPException(404, "暂无可用版本")
        # 记录谁拉取了 manifest (IP + 版本) — 追踪"谁在检查/更新插件"
        try:
            log_plugin_pull(
                storage,
                request.client.host if request.client else "",
                "manifest",
                manifest.get("version", ""),
                "",
                request.headers.get("user-agent", ""),
            )
        except Exception:
            pass  # 日志失败不影响 manifest 返回
        resp = JSONResponse(manifest)
        resp.headers["Cache-Control"] = "no-cache, no-store"
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp

    @app.get("/plugins/download/{filename}")
    async def plugin_download(filename: str, request: Request):
        """客户端下载 zip 整包"""
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(400, "非法文件名")
        path = plugins_dir / filename
        if not path.exists():
            raise HTTPException(404, "文件不存在")
        # 记录谁下载了 zip (IP + 版本) — 拉了 download ≈ 真正更新了
        # 版本号从文件名 cloud-guard-{version}.zip 解析
        ver = ""
        if filename.startswith("cloud-guard-") and filename.endswith(".zip"):
            ver = filename[len("cloud-guard-"):-len(".zip")]
        try:
            log_plugin_pull(
                storage,
                request.client.host if request.client else "",
                "download",
                ver,
                filename,
                request.headers.get("user-agent", ""),
            )
        except Exception:
            pass
        from fastapi.responses import FileResponse
        return FileResponse(path, media_type="application/zip", filename=filename)

    @app.get("/plugins", response_class=HTMLResponse)
    def plugins_page(request: Request):
        """插件管理页面 — 列表 + 上传表单"""
        releases = list_releases(storage)

        # 计算上传表单的预填值
        active = next((r for r in releases if r["is_active"]), None)
        next_version = bump_patch(active["version"]) if active and bump_patch(active["version"]) else "0.1.0"
        next_min_required = next_version

        return templates.TemplateResponse(
            request=request, name="plugins.html",
            context=dict(
                releases=releases,
                active=active,
                next_version=next_version,
                next_min_required=next_min_required,
                sync_notice=request.query_params.get("sync_notice", ""),
            ),
        )

    @app.get("/api/plugin-pulls")
    def plugin_pulls_api(
        version: str = "", ip: str = "", q: str = "", action: str = "",
        page: int = 1, page_size: int = 50,
    ):
        """插件拉取/下载记录 + IP→使用人 解析 + 已更新/未更新名单。

        客户端拉 manifest/download 不带身份头, 服务端只能记 IP;
        IP→使用人 复用 plugin_status 的 LiteLLM litellm_ip 映射(同一台员工机
        访问 LiteLLM 网关和审计服务器是同一个局域网 IP)。
        version/ip/action 精确筛选; q 按 使用人/账户/IP 模糊匹配。
        分页: page/page_size。q 非空时(按人名/账户搜)需先取近 N 条在内存里
        解析人名再过滤, 故走内存分页; q 为空时纯 SQL 分页。
        """
        ql = q.strip().lower()
        page = max(1, int(page))
        page_size = max(1, min(int(page_size), 500))

        v_f = version or None
        ip_f = ip or None
        a_f = action or None

        # IP -> 使用人 反向映射 (复用 plugin_status 缓存, 5min 后台刷新)
        ip_to_info: dict[str, dict] = {}
        online_rows: list[dict] = []
        try:
            st = build_plugin_status(config, storage)
            online_rows = st.get("rows", [])
            for r in online_rows:
                lip = r.get("litellm_ip") or ""
                if lip:
                    ip_to_info[lip] = {
                        "name": r.get("name", ""),
                        "account": r.get("audit_user", ""),
                        "dept": r.get("dept_name", ""),
                        "status": r.get("status", ""),
                    }
            for u in st.get("unmatched", []):
                if u.get("ip"):
                    ip_to_info.setdefault(u["ip"], {
                        "name": u.get("alias", ""), "account": "",
                        "dept": "", "status": "?",
                    })
        except Exception:
            pass

        active_ver = get_active_version(storage)

        if ql:
            # 按人名/账户/IP 模糊搜 → 取近 N 条内存解析后过滤再分页
            SEARCH_CAP = 5000
            raw = list_plugin_pulls(
                storage, limit=SEARCH_CAP,
                version_filter=v_f, ip_filter=ip_f, action_filter=a_f,
            )
            filtered = []
            for p in raw:
                info = ip_to_info.get(p["ip"], {})
                p["name"] = info.get("name", "")
                p["account"] = info.get("account", "")
                p["dept"] = info.get("dept", "")
                if (ql in (p["name"] or "").lower()
                        or ql in (p["account"] or "").lower()
                        or ql in (p["ip"] or "").lower()):
                    filtered.append(p)
            total = len(filtered)
            total_pages = max(1, (total + page_size - 1) // page_size) if total else 1
            if page > total_pages:
                page = total_pages
            start = (page - 1) * page_size
            out = filtered[start:start + page_size]
        else:
            # 纯 SQL 分页
            total = count_plugin_pulls(
                storage, version_filter=v_f, ip_filter=ip_f, action_filter=a_f,
            )
            total_pages = max(1, (total + page_size - 1) // page_size) if total else 1
            if page > total_pages:
                page = total_pages
            start = (page - 1) * page_size
            rows = list_plugin_pulls(
                storage, limit=page_size, offset=start,
                version_filter=v_f, ip_filter=ip_f, action_filter=a_f,
            )
            out = []
            for p in rows:
                info = ip_to_info.get(p["ip"], {})
                p["name"] = info.get("name", "")
                p["account"] = info.get("account", "")
                p["dept"] = info.get("dept", "")
                out.append(p)

        # 已更新/未更新名单(不参与分页, 是当前激活版本的全局统计)
        # 用全部拉取记录(非当前页)算"已下载当前版本的 IP 集合"
        all_dl_pulls = list_plugin_pulls(
            storage, limit=100000,
            version_filter=active_ver or None, action_filter="download",
        )
        downloaded_ips_active = {
            p["ip"] for p in all_dl_pulls if active_ver
        }
        updated, not_updated = [], []
        has_active = bool(active_ver)
        for r in online_rows:
            status = r.get("status", "")
            if status not in ("online", "not_installed"):
                continue
            lip = r.get("litellm_ip") or ""
            entry = {
                "name": r.get("name", ""),
                "account": r.get("audit_user", ""),
                "dept": r.get("dept_name", ""),
                "status": status,
                "ip": lip,
            }
            if has_active and lip and lip in downloaded_ips_active:
                updated.append(entry)
            elif has_active:
                if ql and ql not in (entry["name"] or "").lower() \
                        and ql not in (entry["account"] or "").lower() \
                        and ql not in (entry["ip"] or "").lower():
                    continue
                not_updated.append(entry)
            # 无激活版本时不填未更新名单(避免全员误报)
        updated.sort(key=lambda x: x["name"])
        not_updated.sort(key=lambda x: x["name"])
        return {
            "active_version": active_ver,
            "has_active_version": has_active,
            "pulls": out,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "updated": updated,
            "not_updated": not_updated,
            "ip_resolved": len(ip_to_info),
        }

    @app.post("/plugins/upload", dependencies=[Depends(verify_csrf)])
    async def plugin_upload(
        request: Request,
        version: str = Form(...),
        min_required: str = Form(...),
        release_notes: str = Form(""),
        file: UploadFile = File(...),
    ):
        """上传新版本插件 zip"""
        if not file.filename or not file.filename.endswith(".zip"):
            raise HTTPException(400, "请上传 .zip 文件")

        zip_bytes = await file.read()
        if len(zip_bytes) < 100:
            raise HTTPException(400, "zip 文件过小，可能损坏")

        try:
            result = save_release(
                storage=storage,
                plugins_dir=plugins_dir,
                zip_bytes=zip_bytes,
                version=version.strip(),
                min_required=min_required.strip(),
                release_notes=release_notes.strip(),
                released_by="web-ui",
            )
        except ValueError as e:
            raise HTTPException(400, str(e))
        except Exception as e:
            raise HTTPException(500, f"保存失败: {e}")

        # 若服务器自动纠正了 zip 内版本号,回显提示给管理员
        notice = (result or {}).get("sync_warning") if isinstance(result, dict) else None
        if notice:
            from urllib.parse import quote
            return RedirectResponse(f"/plugins?sync_notice={quote(notice)}", status_code=303)
        return RedirectResponse("/plugins", status_code=303)

    @app.post("/plugins/{release_id}/resync", dependencies=[Depends(verify_csrf)])
    def plugin_resync_route(release_id: int):
        """原地修复某历史版本 zip 内部 plugin.json 版本号(对齐 DB 声明版本)。

        用于修复已发布但内部版本不一致的包,使老 updater 不再中止更新。
        """
        try:
            result = resync_release(storage, plugins_dir, release_id)
        except FileNotFoundError as e:
            raise HTTPException(404, str(e))
        except Exception as e:
            raise HTTPException(500, f"修复失败: {e}")
        if not result:
            raise HTTPException(404, "版本不存在")
        from urllib.parse import quote
        notice = result.get("sync_warning") or f"v{result['version']} 内部版本已与声明一致,无需纠正"
        return RedirectResponse(f"/plugins?sync_notice={quote(notice)}", status_code=303)

    @app.post("/plugins/{release_id}/activate", dependencies=[Depends(verify_csrf)])
    def plugin_activate_route(release_id: int):
        """激活某个历史版本"""
        ok = activate_release(storage, release_id)
        if not ok:
            raise HTTPException(404, "版本不存在")
        return RedirectResponse("/plugins", status_code=303)

    @app.post("/plugins/{release_id}/delete", dependencies=[Depends(verify_csrf)])
    def plugin_delete_route(release_id: int):
        """删除某个历史版本（不允许删除当前激活版本）"""
        ok = delete_release(storage, plugins_dir, release_id)
        if not ok:
            raise HTTPException(400, "版本不存在或为当前激活版本，无法删除")
        return RedirectResponse("/plugins", status_code=303)

    # ==================== 审查分析 ====================
    reviews_dir = _BASE.parent.parent / "data" / "reviews"

    def _list_saved_reviews() -> list[dict]:
        """扫描磁盘上的历史审查报告文件。"""
        reviews_dir.mkdir(parents=True, exist_ok=True)
        reports = []
        for p in sorted(reviews_dir.glob("审查报告_*.md"), reverse=True):
            name = p.stem  # 审查报告_2026-06-16_2026-07-15_20260812153000
            # 解析文件名中的日期范围
            parts = name.replace("审查报告_", "").split("_")
            date_range = ""
            if len(parts) >= 2:
                date_range = f"{parts[0]} ~ {parts[1]}"
            stat = p.stat()
            import time as _t
            reports.append({
                "filename": p.name,
                "date_range": date_range,
                "size": stat.st_size,
                "created_at": _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(stat.st_mtime)),
            })
        return reports

    @app.get("/review", response_class=HTMLResponse)
    def review_page(request: Request):
        """审查分析页面 — 选择时间范围，对 UserPromptSubmit 事件进行 LLM 审查"""
        # 查询有敏感命中的 UserPromptSubmit 事件的时间范围
        ts_range = _one(
            "SELECT min(substr(ts,1,10)) AS min_ts, max(substr(ts,1,10)) AS max_ts "
            "FROM events WHERE event='UserPromptSubmit' "
            "AND (hook_match_count>0 OR block_reason IS NOT NULL)"
        )
        min_ts = (ts_range or {}).get("min_ts", "")
        max_ts = (ts_range or {}).get("max_ts", "")
        # 扫描历史报告
        saved_reviews = _list_saved_reviews()
        return templates.TemplateResponse(
            request=request, name="review.html",
            context=dict(
                min_ts=min_ts or "",
                max_ts=max_ts or "",
                saved_reviews=saved_reviews,
            ),
        )

    @app.post("/review/start")
    async def review_start(request: Request):
        """启动异步审查分析，返回 task_id 供轮询进度。"""
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "无效请求"}, status_code=400)

        start_date = (data.get("start_date") or "").strip()
        end_date = (data.get("end_date") or "").strip()
        if not start_date or not end_date:
            return JSONResponse({"error": "请选择开始和结束日期"}, status_code=400)

        import time as _time
        import threading

        task_id = f"{start_date}_{end_date}_{_time.strftime('%Y%m%d%H%M%S')}"

        # 查询事件数量（先快速计数）
        count_row = _one(
            "SELECT count(*) AS c FROM events "
            "WHERE event='UserPromptSubmit' "
            "AND (hook_match_count>0 OR block_reason IS NOT NULL) "
            "AND substr(ts,1,10)>=? AND substr(ts,1,10)<=?",
            (start_date, end_date),
        )
        total_events = (count_row or {}).get("c", 0)
        if total_events == 0:
            return JSONResponse({"error": "所选时间范围内无敏感命中的 UserPromptSubmit 事件"})

        batch_size = 8
        total_batches = (total_events + batch_size - 1) // batch_size

        # 初始化任务状态
        _REVIEW_TASKS[task_id] = {
            "status": "running",
            "total": total_events,
            "total_batches": total_batches,
            "done_batches": 0,
            "current_batch": 0,
            "start_date": start_date,
            "end_date": end_date,
            "results": [],
            "errors": [],
            "md_content": "",
            "created_at": _time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        def _run_analysis():
            """在后台线程中执行 LLM 审查分析。"""
            from ..llm.llm_client import chat as llm_chat

            events = _rows(
                """SELECT e.id, e.ts, e.user, e.prompt_text, e.raw, e.block_reason, e.hook_match_count,
                          group_concat(r.rule_id) AS rule_ids,
                          group_concat(r.severity) AS severities,
                          group_concat(r.matched) AS matched_samples
                   FROM events e
                   LEFT JOIN rule_hits r ON r.event_id = e.id
                   WHERE e.event = 'UserPromptSubmit'
                     AND (e.hook_match_count > 0 OR e.block_reason IS NOT NULL)
                     AND substr(e.ts, 1, 10) >= ? AND substr(e.ts, 1, 10) <= ?
                   GROUP BY e.id
                   ORDER BY e.ts ASC""",
                (start_date, end_date),
            )
            # prompt_text 为空时, 从 raw JSON 里补救(旧版客户端未单独写 prompt_text 列,
            # 但原始日志顶层通常有该字段)。补不到则保持空, 前端显示"(空)"。
            for _e in events:
                if not (_e.get("prompt_text") or "").strip() and _e.get("raw"):
                    try:
                        _raw_obj = json.loads(_e["raw"]) if isinstance(_e["raw"], str) else _e["raw"]
                        _pt = _raw_obj.get("prompt_text") if isinstance(_raw_obj, dict) else None
                        if isinstance(_pt, str) and _pt.strip():
                            _e["prompt_text"] = _pt[:500]
                    except Exception:
                        pass

            all_results: list[dict] = []
            task_errors: list[str] = []

            for i in range(0, len(events), batch_size):
                if task_id not in _REVIEW_TASKS:
                    return  # 任务被取消
                batch_idx = i // batch_size + 1
                _REVIEW_TASKS[task_id]["current_batch"] = batch_idx

                batch = events[i:i + batch_size]
                batch_text = _build_review_batch(batch)
                try:
                    raw = llm_chat([
                        {"role": "system", "content": _REVIEW_SYSTEM},
                        {"role": "user", "content": f"请审查以下 {len(batch)} 条 UserPromptSubmit 事件的检测结果：\n\n{batch_text}"},
                    ])
                    parsed = _extract_review_json(raw)
                    if parsed:
                        event_map = {e["id"]: e for e in batch}
                        for item in parsed:
                            eid = item.get("event_id")
                            if eid and eid in event_map:
                                item["_event"] = event_map[eid]
                        all_results.extend(parsed)
                    else:
                        task_errors.append(f"批次 {batch_idx} 的 LLM 返回无法解析")
                except Exception as e:
                    task_errors.append(f"批次 {batch_idx} LLM 调用失败: {e}")

                _REVIEW_TASKS[task_id]["done_batches"] = batch_idx
                _REVIEW_TASKS[task_id]["results"] = all_results
                _REVIEW_TASKS[task_id]["errors"] = task_errors

            # 统计
            fp_count = sum(1 for r in all_results if r.get("verdict") == "false_positive")
            tp_count = sum(1 for r in all_results if r.get("verdict") == "true_positive")
            uncertain_count = sum(1 for r in all_results if r.get("verdict") == "uncertain")

            # 生成 Markdown
            md_content = _generate_review_md(
                start_date=start_date, end_date=end_date,
                results=all_results, total=len(events),
                fp_count=fp_count, tp_count=tp_count, uncertain_count=uncertain_count,
            )

            # 保存 .md 文件到磁盘
            reviews_dir.mkdir(parents=True, exist_ok=True)
            md_filename = f"审查报告_{start_date}_{end_date}_{_time.strftime('%Y%m%d%H%M%S')}.md"
            md_path = reviews_dir / md_filename
            try:
                md_path.write_text(md_content, encoding="utf-8")
            except Exception:
                pass  # 保存失败不影响结果返回

            # 构建前端可用的 clean_results
            br_map_frontend = {
                "user_approved": "用户确认发送",
                "user_blocked": "用户取消发送",
                "no_redirect_channel": "无脱敏通道",
                "userprompt_no_redirect": "自动脱敏后发送",
                "score_over_threshold": "系统硬拦截",
            }
            clean_results = []
            for r in all_results:
                ev = r.get("_event", {})
                cr = {
                    "event_id": r.get("event_id"),
                    "verdict": r.get("verdict"),
                    "reason": r.get("reason", ""),
                    "suggestion": r.get("suggestion", ""),
                    "ts": ev.get("ts", ""),
                    "user": ev.get("user", ""),
                    "prompt_text": (ev.get("prompt_text") or "")[:500],
                    "rule_ids": ev.get("rule_ids", ""),
                    "block_reason": br_map_frontend.get(ev.get("block_reason", ""), ev.get("block_reason", "") or ""),
                }
                clean_results.append(cr)

            # 更新任务状态
            _REVIEW_TASKS[task_id].update({
                "status": "done",
                "fp_count": fp_count,
                "tp_count": tp_count,
                "uncertain_count": uncertain_count,
                "clean_results": clean_results,
                "md_content": md_content,
                "md_filename": md_filename,
                "errors": task_errors,
            })

        # 启动后台线程
        t = threading.Thread(target=_run_analysis, name=f"review-{task_id}", daemon=True)
        t.start()

        return {"task_id": task_id, "status": "running", "total": total_events, "total_batches": total_batches}

    @app.get("/review/progress/{task_id}")
    def review_progress(task_id: str):
        """查询审查分析进度。"""
        if ".." in task_id or "/" in task_id or "\\" in task_id:
            raise HTTPException(400, "非法任务 ID")
        task = _REVIEW_TASKS.get(task_id)
        if not task:
            raise HTTPException(404, "任务不存在")
        resp = {
            "status": task["status"],
            "total": task.get("total", 0),
            "total_batches": task.get("total_batches", 0),
            "done_batches": task.get("done_batches", 0),
            "current_batch": task.get("current_batch", 0),
        }
        if task["status"] == "done":
            resp.update({
                "fp_count": task.get("fp_count", 0),
                "tp_count": task.get("tp_count", 0),
                "uncertain_count": task.get("uncertain_count", 0),
                "results": task.get("clean_results", []),
                "errors": task.get("errors", []),
                "md_filename": task.get("md_filename", ""),
            })
        return resp

    @app.get("/review/download/{filename}")
    def review_download(filename: str):
        """下载审查报告 Markdown 文件（从磁盘读取）。"""
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(400, "非法文件名")
        path = reviews_dir / filename
        if not path.exists():
            # 也检查内存缓存
            for tid, task in _REVIEW_TASKS.items():
                if task.get("md_filename") == filename and task.get("md_content"):
                    return Response(
                        content=task["md_content"].encode("utf-8"),
                        media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename}"},
                    )
            raise HTTPException(404, "报告文件不存在")
        from fastapi.responses import FileResponse
        return FileResponse(
            path=path,
            media_type="text/markdown; charset=utf-8",
            filename=filename,
        )

    @app.get("/review/view/{filename}")
    def review_view(filename: str):
        """在线查看历史审查报告（返回 Markdown 原文）。"""
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(400, "非法文件名")
        path = reviews_dir / filename
        if not path.exists():
            raise HTTPException(404, "报告文件不存在")
        md_text = path.read_text(encoding="utf-8")
        return Response(content=md_text, media_type="text/plain; charset=utf-8")

    # ==================== 插件状态 ====================
    # 启动后台刷新(LiteLLM + audit 数据每5分钟自动更新, 页面秒开)
    _start_bg_refresh(config, storage)
    # 启动每日凌晨 03:00 自动从飞书同步组织架构
    _start_daily_org_sync()
    # 启动数据库自动运维调度器(每日 02:00 自动热备保留14天，每日 03:30 自动归档90天前日志)
    start_db_maintenance_scheduler(storage)

    @app.get("/plugin-status", response_class=HTMLResponse)
    def plugin_status_page(request: Request):
        """组织架构 + 插件安装/在线状态页面(树 + 表格)。"""
        return templates.TemplateResponse(
            request=request, name="plugin_status.html",
            context={"active_page": "plugin_status"},
        )

    @app.get("/api/plugin-status")
    def plugin_status_api(refresh: int = 0):
        """返回插件状态数据(组织架构+litellm+audit 三方汇总)。

        默认读缓存(秒级); refresh=1 强制重新拉取(较慢)。
        """
        data = build_plugin_status(config, storage, force=bool(refresh))
        return JSONResponse(data)

    @app.post("/api/sync-org")
    def sync_org_api():
        """启动异步飞书组织架构同步任务, 立即返回 task_id。

        前端用 /api/sync-org/status?task_id=xxx 轮询进度。
        同步是全量拉取(600+人), 可达数分钟, 故不阻塞此请求。
        """
        res = start_sync_org_task()
        return JSONResponse(res)

    @app.get("/api/sync-org/status")
    def sync_org_status_api(task_id: str = ""):
        """查询异步同步任务状态。若未指定 task_id 则自动查询当前正在运行或最近一次同步任务。"""
        if not task_id:
            task = get_latest_sync_org_task()
            if task is None:
                return JSONResponse({"status": "idle", "task_id": "", "elapsed_seconds": 0})
        else:
            task = get_sync_org_status(task_id)
            if task is None:
                return JSONResponse({"error": "任务不存在"}, status_code=404)
        # 完成则清缓存, 让下次请求重新加载组织数据
        if task.get("status") in ("done", "failed") and not task.get("_cache_cleared"):
            if task.get("status") == "done":
                try:
                    build_plugin_status(config, storage, force=True)
                    with _org_users_cache_lock:
                        _org_users_cache["data"] = None
                    _sync_user_org_db()
                except Exception as e:
                    logger.warning("组织架构缓存重载失败: %s", e)
            task["_cache_cleared"] = True
        return JSONResponse(task)

    # ==================== GLM 监控(读取独立采集器 DB) ====================
    @app.get("/glm-monitor", response_class=HTMLResponse)
    def glm_monitor_page(request: Request):
        """GLM 后端实时监控: 排队/处理中/KV cache + 各 IP 对话聚合(含人名)。"""
        return templates.TemplateResponse(
            request=request, name="glm_monitor.html",
            context={"active_page": "glm_monitor"},
        )

    @app.get("/api/glm/queue")
    def glm_queue_api(range: str = "15m"):
        """vLLM 队列/健康时序。range=15m/1h/6h/1d 或秒数。"""
        from ..glm_reader import _parse_range as _glm_parse_range
        return JSONResponse(_glm_read_queue(config.glm_monitor_db, _glm_parse_range(range)))

    @app.get("/api/glm/ips")
    def glm_ips_api(range: str = ""):
        """各 IP GLM 调用聚合。
        range 为空 -> 最近一次采样快照(读本地 DB);
        range=15m/1h/6h/1d -> 转发到采集器临时拉 LiteLLM spend logs 聚合。"""
        if not range:
            return JSONResponse(_glm_read_ips(config.glm_monitor_db))
        import os as _os, urllib.request as _ur, json as _json
        host = _os.environ.get("GLM_MONITOR_HOST", "http://127.0.0.1:8790")
        try:
            with _ur.urlopen(f"{host}/api/ips?range={_ur.quote(range)}", timeout=30) as resp:
                return JSONResponse(_json.loads(resp.read().decode()))
        except Exception as e:
            return JSONResponse({"ok": False, "error": f"采集器不可达: {e}"}, status_code=502)

    @app.get("/api/glm/ip_detail")
    def glm_ip_detail_api(range: str = "", ip: str = "", page: int = 1, page_size: int = 50):
        """某 IP 在指定时间范围的逐条请求明细(服务端分页, 供前端弹窗)。
        透传到采集器 /api/ip_detail; 采集器带 60s 内存缓存, 翻页不重复拉 LiteLLM。"""
        import os as _os, urllib.request as _ur, json as _json
        host = _os.environ.get("GLM_MONITOR_HOST", "http://127.0.0.1:8790")
        qs = (f"range={_ur.quote(range)}&ip={_ur.quote(ip)}"
              f"&page={page}&page_size={page_size}")
        try:
            with _ur.urlopen(f"{host}/api/ip_detail?{qs}", timeout=30) as resp:
                return JSONResponse(_json.loads(resp.read().decode()))
        except Exception as e:
            return JSONResponse({"ok": False, "error": f"采集器不可达: {e}",
                                 "requests": []}, status_code=502)

    @app.post("/api/glm/interval")
    async def glm_interval_api(request: Request):
        """转发采样间隔修改到采集器的 /api/interval(采集器与平台可能不同机,
        平台无法直接改采集器内存, 故通过 HTTP 转发; 采集器需开放 8790 可达)。"""
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "无效 JSON"}, status_code=400)
        import os as _os
        sec = data.get("interval") or data.get("sec")
        host = _os.environ.get("GLM_MONITOR_HOST", "http://127.0.0.1:8790")
        import urllib.request as _ur, json as _json
        try:
            req = _ur.Request(f"{host}/api/interval",
                              data=_json.dumps({"interval": sec}).encode(),
                              headers={"Content-Type": "application/json"}, method="POST")
            with _ur.urlopen(req, timeout=5) as resp:
                return JSONResponse(_json.loads(resp.read().decode()))
        except Exception as e:
            return JSONResponse({"ok": False, "error": f"采集器不可达: {e}"}, status_code=502)

    @app.post("/api/glm/thresholds")
    async def glm_thresholds_api(request: Request):
        """转发阈值修改(超大上下文/已耗时)到采集器的 /api/thresholds。
        与 /api/glm/interval 同款透传: 采集器与平台可能不同机, 通过 HTTP 转发。"""
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "无效 JSON"}, status_code=400)
        import os as _os, urllib.request as _ur, json as _json
        host = _os.environ.get("GLM_MONITOR_HOST", "http://127.0.0.1:8790")
        try:
            req = _ur.Request(f"{host}/api/thresholds",
                              data=_json.dumps(data).encode(),
                              headers={"Content-Type": "application/json"}, method="POST")
            with _ur.urlopen(req, timeout=5) as resp:
                return JSONResponse(_json.loads(resp.read().decode()))
        except Exception as e:
            return JSONResponse({"ok": False, "error": f"采集器不可达: {e}"}, status_code=502)

    @app.get("/api/glm/inflight")
    def glm_inflight_api():
        """实时在途请求(谁正在跑 / 输入 token)。转发到采集器 /api/inflight。
        数据在采集器进程内存(由 LiteLLM pre-call 回调推送), 不在 SQLite, 必须 HTTP 转发。
        采集器不可达时返回 ok:false 让前端显示提示。"""
        import os as _os, urllib.request as _ur, json as _json
        host = _os.environ.get("GLM_MONITOR_HOST", "http://127.0.0.1:8790")
        try:
            with _ur.urlopen(f"{host}/api/inflight", timeout=5) as resp:
                return JSONResponse(_json.loads(resp.read().decode()))
        except Exception as e:
            return JSONResponse({"ok": False, "error": f"采集器不可达: {e}",
                                 "count": 0, "alive": False, "requests": []}, status_code=502)

    # ==================== IP 白名单 ====================
    @app.get("/api/ip-whitelist")
    def ip_whitelist_list():
        """返回 IP 白名单全部条目。"""
        return JSONResponse(list_whitelist(storage))

    @app.post("/api/ip-whitelist")
    async def ip_whitelist_add(request: Request):
        """新增白名单条目(IP 或 CIDR 网段)。"""
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "无效 JSON"}, status_code=400)
        ip = (data.get("ip") or "").strip()
        comment = (data.get("comment") or "").strip()
        if not ip:
            return JSONResponse({"error": "IP 不能为空"}, status_code=400)
        try:
            item = add_whitelist(storage, ip, comment)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        # 清 plugin_status 缓存, 让下次请求重新做 IP 判定
        build_plugin_status(config, storage, force=True)
        return JSONResponse(item)

    @app.post("/api/ip-whitelist/{item_id}/delete")
    def ip_whitelist_delete(item_id: int):
        """删除白名单条目。"""
        ok = delete_whitelist(storage, item_id)
        if not ok:
            raise HTTPException(404, "条目不存在")
        build_plugin_status(config, storage, force=True)
        return JSONResponse({"ok": True})

    # ==================== 中文名→英文账户名 映射 ====================
    @app.get("/api/name-map")
    def name_map_list():
        """返回手动映射列表 + 组织架构全部中文名(供前端下拉辅助)。"""
        # 组织架构人名去重排序
        people = load_org()
        names = sorted({_norm_name(p["name"]) for p in people if p["name"]})
        return JSONResponse({
            "mappings": get_manual_map(),
            "org_names": names,
        })

    @app.post("/api/name-map")
    async def name_map_set(request: Request):
        """新增/更新一条 中文名->英文账户名 映射。"""
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "无效 JSON"}, status_code=400)
        name = (data.get("name") or "").strip()
        account = (data.get("account") or "").strip()
        try:
            item = set_manual_mapping(name, account)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        # 清缓存让下次请求重新做匹配(插件状态 + 事件页显示名)
        build_plugin_status(config, storage, force=True)
        with _org_users_cache_lock:
            _org_users_cache["data"] = None
        return JSONResponse(item)

    @app.post("/api/name-map/{name}/delete")
    async def name_map_delete(name: str):
        """删除一条映射。name 为 URL 编码的中文名。"""
        from urllib.parse import unquote
        name = unquote(name)
        ok = delete_manual_mapping(name)
        if not ok:
            raise HTTPException(404, "映射不存在")
        build_plugin_status(config, storage, force=True)
        with _org_users_cache_lock:
            _org_users_cache["data"] = None
        return JSONResponse({"ok": True})

    # ==================== LiteLLM 键名别名→真实中文名 映射 ====================
    @app.get("/api/litellm-alias-map")
    def litellm_alias_map_list():
        """返回键名别名映射列表 + 组织架构(部门->人名, 供前端两级联动选人防重名)。"""
        people = load_org()
        # 部门 -> 该部门下的人名列表(全部飞书员工, 不过滤 audit 记录)
        users_by_dept: dict[str, list[str]] = {}
        for p in people:
            if not p.get("name"):
                continue
            dp = p.get("dept_path") or p.get("dept_name") or "未知部门"
            users_by_dept.setdefault(dp, []).append(p["name"])
        # 每部门去重 + 排序
        for dp in users_by_dept:
            users_by_dept[dp] = sorted(set(users_by_dept[dp]))
        return JSONResponse({
            "mappings": get_litellm_alias_map(),
            "departments": sorted(users_by_dept.keys()),
            "users_by_dept": users_by_dept,
        })

    @app.post("/api/litellm-alias-map")
    async def litellm_alias_map_set(request: Request):
        """新增/更新一条 键名别名->真实中文名 映射。"""
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "无效 JSON"}, status_code=400)
        alias = (data.get("alias") or "").strip()
        name = (data.get("name") or "").strip()
        try:
            item = set_litellm_alias_mapping(alias, name)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        # 清缓存让下次请求重新做匹配
        build_plugin_status(config, storage, force=True)
        return JSONResponse(item)

    @app.post("/api/litellm-alias-map/{alias}/delete")
    async def litellm_alias_map_delete(alias: str):
        """删除一条映射。alias 为 URL 编码的键名。"""
        from urllib.parse import unquote
        alias = unquote(alias)
        ok = delete_litellm_alias_mapping(alias)
        if not ok:
            raise HTTPException(404, "映射不存在")
        build_plugin_status(config, storage, force=True)
        return JSONResponse({"ok": True})

    # ==================== LiteLLM 离线停用/恢复 key ====================
    @app.get("/api/litellm/offline-keys")
    def litellm_offline_keys():
        """返回当前离线员工及其 litellm key 状态。"""
        return JSONResponse(get_offline_key_info(config, storage))

    @app.post("/api/litellm/block-offline")
    def litellm_block_offline():
        """批量停用所有离线员工的 key。"""
        result = block_offline_keys(config, storage)
        if not result.get("ok"):
            return JSONResponse({"error": result.get("error", "停用失败")}, status_code=500)
        return JSONResponse(result)

    @app.post("/api/litellm/unblock/{name}")
    async def litellm_unblock_user(name: str):
        """恢复某个员工的所有 key。name 为 URL 编码的中文名。"""
        from urllib.parse import unquote
        name = unquote(name)
        result = unblock_user_keys(config, storage, name)
        return JSONResponse(result)

    # ==================== Claude Code 原生 Managed HTTP Hooks ====================
    _hook_line_seq = 0
    _hook_line_lock = threading.Lock()

    def _next_hook_line_no() -> int:
        nonlocal _hook_line_seq
        with _hook_line_lock:
            _hook_line_seq += 1
            return (int(time.time() * 1000) % 1_000_000_000) * 1000 + (_hook_line_seq % 1000)

    def _extract_user_from_req(req: Request, payload: dict) -> str:
        from urllib.parse import unquote
        # 1. 优先从 URL 查询参数提取 (由客户端 install 注入在 Hook URL 中)
        q_user = req.query_params.get("user") or req.query_params.get("u") or req.query_params.get("username")
        if q_user and str(q_user).strip():
            return unquote(str(q_user).strip())
        # 2. 自定义请求头
        h_user = req.headers.get("x-user") or req.headers.get("x-username")
        if h_user and h_user.strip():
            return unquote(h_user.strip())
        # 3. payload 中的 user / username 字段
        p_user = payload.get("user") or payload.get("username")
        if p_user and str(p_user).strip():
            return unquote(str(p_user).strip())
        # 4. 从当前工作目录 (cwd) 智能提取 OS 用户名 (例如 C:\Users\zhangsan\project 或 /home/zhangsan/...)
        cwd = str(payload.get("cwd") or "").strip()
        if cwd:
            m = re.search(r"^[A-Za-z]:[/\\]Users[/\\]([^/\\]+)", cwd, re.IGNORECASE)
            if not m:
                m = re.search(r"^/home/([^/\\]+)", cwd)
            if m:
                u = m.group(1).strip()
                if u.lower() not in ("public", "default", "all users", "administrator"):
                    return u
        # 5. 从 client IP 关联已知白名单备注 (若有)
        c_ip = req.headers.get("x-forwarded-for", "").split(",")[0].strip() or (req.client.host if req.client else "")
        if c_ip:
            try:
                for item in list_whitelist(storage):
                    if item.get("ip") == c_ip and item.get("comment"):
                        return item["comment"]
            except Exception:
                pass
        return "unknown"

    async def _handle_hook_event(event_name: str, req: Request) -> dict:
        try:
            body = await req.body()
            payload = json.loads(body.decode("utf-8", errors="replace")) if body else {}
        except Exception:
            payload = {}

        client_ip = req.headers.get("x-forwarded-for", "").split(",")[0].strip() or (req.client.host if req.client else "127.0.0.1")
        user = _extract_user_from_req(req, payload)
        raw_host = (
            req.query_params.get("hostname")
            or req.query_params.get("h")
            or req.headers.get("x-hostname")
            or payload.get("hostname")
            or ""
        )
        if raw_host:
            from urllib.parse import unquote
            vm_hostname = unquote(str(raw_host).strip())
        else:
            vm_hostname = client_ip

        cid = vm_hostname if vm_hostname and vm_hostname != client_ip else client_ip

        session_id = payload.get("session_id") or ""
        tool_name = payload.get("tool_name") or ""
        tool_input = payload.get("tool_input") or {}
        prompt = payload.get("prompt") or ""
        cwd = payload.get("cwd") or ""

        now_iso = datetime.datetime.now().astimezone().isoformat()
        line_no = _next_hook_line_no()

        rec = EventRecord(
            ts=now_iso,
            source_file="http_hook",
            line_no=line_no,
            byte_offset=0,
            event=event_name,
            stage="http_hook",
            session_id=session_id,
            tool=tool_name,
            phase="scanned",
            action="pass",
            user=user,
            vm_hostname=vm_hostname,
            client_id=cid,
            raw=json.dumps(payload, ensure_ascii=False),
        )

        # 提取字段用于规则引擎
        if tool_name == "Bash":
            rec.bash_command = tool_input.get("command")
        elif tool_name in ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit"):
            rec.file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
        elif tool_name in ("WebFetch", "WebSearch"):
            rec.url = tool_input.get("url") or tool_input.get("query")

        if event_name == "UserPromptSubmit":
            rec.prompt_text = prompt

        # 规则引擎研判
        hits = engine.evaluate(rec) if engine is not None else []
        rec.hits = hits
        rec.hook_match_count = len(hits)

        decision = "allow"
        action = "pass"
        block_reason = None
        has_whitelist = any(h.severity in ("allow", "whitelist") for h in hits)
        has_critical = any(h.severity in ("critical", "high") for h in hits)
        has_warn = any(h.severity == "warn" for h in hits)

        if has_whitelist:
            decision = "allow"
            action = "pass"
            block_reason = "whitelist_approved"
        elif has_critical:
            decision = "deny"
            action = "block"
            block_reason = "system_blocked"
        elif has_warn:
            if event_name == "PreToolUse":
                decision = "ask"
                action = "warn"
            elif event_name == "UserPromptSubmit":
                decision = "warn"
                action = "warn"
            else:
                decision = "allow"
                action = "warn"

        rec.action = action
        rec.block_reason = block_reason

        # 实时落库到 events 表
        try:
            storage.insert_events([rec])
        except Exception as e:
            import sys
            sys.stderr.write(f"[http_hook] insert error: {e}\n")

        # 返回 Claude Code 原生决策响应
        # 兼容性设计:
        # PreToolUse 核心读取 hookSpecificOutput.permissionDecision ("allow" | "deny" | "ask")
        # UserPromptSubmit / PostToolUse / Stop 核心读取 top-level decision ("block" | "approve" | "warn")
        output: dict[str, Any] = {
            "hookEventName": event_name,
            "permissionDecision": decision,
        }
        resp: dict[str, Any] = {
            "hookSpecificOutput": output,
        }

        if decision == "deny":
            reasons = [h.meta.get("reason") or h.rule_id for h in hits]
            reason_str = "；".join(reasons) if reasons else "命中企业安全禁止策略"
            client_msg = f"【企业安全策略阻断】操作已被系统强制拦截！阻断原因：{reason_str}。"
            ai_instruction = (
                f"【企业安全策略系统提示】当前操作违反企业安全合规要求已被系统强制拦截！\n"
                f"阻断原因：{reason_str}。\n"
                f"安全要求：请直接使用中文明确回复用户已被企业安全策略阻断，并说明阻断原因，切勿执行该操作。"
            )
            output["permissionDecisionReason"] = client_msg
            output["additionalContext"] = ai_instruction
            resp["decision"] = "block"
            resp["reason"] = client_msg
        elif decision == "warn" and event_name == "UserPromptSubmit":
            reasons = [h.meta.get("reason") or h.rule_id for h in hits]
            reason_str = "；".join(reasons) if reasons else "检测到潜在安全风险"
            client_msg = f"【企业安全策略提醒】{reason_str}"
            output["permissionDecisionReason"] = client_msg
            output["additionalContext"] = f"【企业安全策略提醒】提问包含潜在敏感词（{reason_str}）。请使用中文向用户说明注意事项。"
            resp["decision"] = "warn"
            resp["reason"] = client_msg
            resp["prompt_preview"] = (prompt[:150] + "...") if len(prompt) > 150 else prompt
        elif decision == "ask":
            reasons = [h.meta.get("reason") or h.rule_id for h in hits]
            reason_str = "；".join(reasons) if reasons else "操作需用户确认"
            client_msg = f"【企业安全策略提示】{reason_str}"
            output["permissionDecisionReason"] = client_msg
            output["additionalContext"] = f"【企业安全策略提示】{reason_str}。请使用中文向用户确认是否继续。"
            resp["decision"] = "ask"
            resp["reason"] = client_msg
        else:
            resp["decision"] = "approve"

        return resp

    @app.post("/api/hooks/session-start")
    async def hook_session_start(request: Request):
        """Claude Code SessionStart HTTP Hook 端点"""
        res = await _handle_hook_event("SessionStart", request)
        return JSONResponse(res, media_type="application/json; charset=utf-8")

    @app.post("/api/hooks/pre-tool-use")
    async def hook_pre_tool_use(request: Request):
        """Claude Code PreToolUse HTTP Hook 端点"""
        res = await _handle_hook_event("PreToolUse", request)
        return JSONResponse(res, media_type="application/json; charset=utf-8")

    @app.post("/api/hooks/user-prompt-submit")
    async def hook_user_prompt_submit(request: Request):
        """Claude Code UserPromptSubmit HTTP Hook 端点"""
        res = await _handle_hook_event("UserPromptSubmit", request)
        return JSONResponse(res, media_type="application/json; charset=utf-8")

    @app.post("/api/hooks/user-decision")
    async def hook_user_decision(request: Request):
        """记录用户在客户端弹窗中的决策（继续上传 user_approved / 取消发送 user_blocked）"""
        try:
            payload = await request.json()
        except Exception:
            payload = {}

        client_ip = request.client.host if request.client else "127.0.0.1"
        user = _extract_user_from_req(request, payload)
        raw_host = (
            request.query_params.get("hostname")
            or request.query_params.get("h")
            or payload.get("hostname")
            or request.headers.get("x-hostname")
            or ""
        )
        if raw_host:
            from urllib.parse import unquote
            vm_hostname = unquote(str(raw_host).strip())
        else:
            vm_hostname = client_ip
        cid = vm_hostname if vm_hostname and vm_hostname != client_ip else client_ip
        session_id = payload.get("session_id") or ""
        prompt = payload.get("prompt") or ""
        decision = payload.get("decision") or "user_blocked"
        reason = payload.get("reason") or ""
        latency_ms = payload.get("latency_ms")

        now_iso = datetime.datetime.now().astimezone().isoformat()
        line_no = _next_hook_line_no()

        rec = EventRecord(
            ts=now_iso,
            source_file="http_hook",
            line_no=line_no,
            byte_offset=0,
            event="UserPromptSubmitDecision",
            stage="http_hook",
            session_id=session_id,
            tool="UserPromptSubmit",
            phase="decided",
            action="pass" if decision == "user_approved" else "block",
            user=user,
            vm_hostname=vm_hostname,
            client_id=cid,
            prompt_text=prompt,
            block_reason=decision,
            duration_ms=latency_ms,
            raw=json.dumps(payload, ensure_ascii=False),
        )

        try:
            storage.insert_events([rec])
        except Exception as e:
            import sys
            sys.stderr.write(f"[user_decision] insert error: {e}\n")

        return JSONResponse({"ok": True, "decision": decision})

    @app.post("/api/hooks/post-tool-use")
    async def hook_post_tool_use(request: Request):
        """Claude Code PostToolUse HTTP Hook 端点"""
        res = await _handle_hook_event("PostToolUse", request)
        return JSONResponse(res)

    @app.post("/api/hooks/stop")
    async def hook_stop(request: Request):
        """Claude Code Stop HTTP Hook 端点"""
        res = await _handle_hook_event("Stop", request)
        return JSONResponse(res)

    # ==================== 安全策略管控 API & Web 页面 ====================
    @app.get("/rules", response_class=HTMLResponse)
    def rules_page(request: Request):
        rule_list = engine.list_rules() if engine is not None else []
        return templates.TemplateResponse(
            request=request,
            name="rules.html",
            context=dict(
                active_page="rules",
                rules=rule_list,
            ),
        )

    @app.get("/api/rules")
    def api_list_rules():
        rule_list = engine.list_rules() if engine is not None else []
        return JSONResponse({"rules": rule_list, "total": len(rule_list)})

    @app.post("/api/rules")
    async def api_save_rule(request: Request):
        if engine is None:
            raise HTTPException(503, "RuleEngine is not initialized")
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(400, "Invalid JSON body")

        try:
            engine.save_rule(data, file_name=data.get("file_name"))
        except ValueError as ve:
            return JSONResponse({"ok": False, "error": str(ve)}, status_code=400)
        except Exception as e:
            return JSONResponse({"ok": False, "error": f"保存失败: {e}"}, status_code=500)

        saved = engine.get_rule(data.get("id", ""))
        return JSONResponse({"ok": True, "rule": saved})

    @app.post("/api/rules/{rule_id}/delete")
    def api_delete_rule(rule_id: str):
        if engine is None:
            raise HTTPException(503, "RuleEngine is not initialized")
        from urllib.parse import unquote
        rule_id = unquote(rule_id)
        ok = engine.delete_rule(rule_id)
        if not ok:
            return JSONResponse({"ok": False, "error": "规则未找到或删除失败"}, status_code=404)
        return JSONResponse({"ok": True})

    @app.post("/api/rules/reload")
    def api_reload_rules():
        if engine is None:
            raise HTTPException(503, "RuleEngine is not initialized")
        count = engine.reload()
        return JSONResponse({"ok": True, "reloaded_count": count})

    @app.post("/api/rules/ai-generate")
    async def api_ai_generate_rule(request: Request):
        """调用大模型根据自然语言需求生成安全策略规则，并执行后台真实沙箱回归自测"""
        if not llm_config.is_runnable:
            return JSONResponse(
                {
                    "ok": False,
                    "error": "大模型尚未配置或未启用，请先前往【系统与大模型设置】配置 API Key（支持 DeepSeek / Claude / OpenAI / Ollama 等兼容接口）。",
                },
                status_code=400,
            )
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"ok": False, "error": "请求体格式错误，需为 JSON"}, status_code=400)

        requirement = str(data.get("requirement") or "").strip()
        if not requirement:
            return JSONResponse({"ok": False, "error": "需求描述不能为空"}, status_code=400)

        scope_hint = str(data.get("scope_hint") or "").strip()
        severity_hint = str(data.get("severity_hint") or "").strip()

        # 在线程池中执行 LLM 调用与自测，避免阻塞 FastAPI 事件循环
        res = await run_in_threadpool(
            generate_and_test_rule,
            requirement=requirement,
            scope_hint=scope_hint,
            severity_hint=severity_hint,
        )
        return JSONResponse(res)

    @app.post("/api/rules/test")
    async def api_test_rule(request: Request):
        """对指定规则模式与用例执行沙箱自动化测试"""
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"ok": False, "error": "请求体格式错误，需为 JSON"}, status_code=400)

        match_field = str(data.get("match_field") or "").strip()
        match_mode = str(data.get("match_mode") or "").strip()
        pattern = data.get("pattern")
        positive_cases = data.get("positive_cases") or []
        negative_cases = data.get("negative_cases") or []

        if not isinstance(positive_cases, list):
            positive_cases = [str(positive_cases)]
        if not isinstance(negative_cases, list):
            negative_cases = [str(negative_cases)]

        report = await run_in_threadpool(
            run_rule_self_test,
            match_field=match_field,
            match_mode=match_mode,
            pattern=pattern,
            positive_cases=positive_cases,
            negative_cases=negative_cases,
        )
        return JSONResponse({"ok": True, "test_report": report})


    # ==================== 系统与大模型设置 API & Web 页面 ====================
    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="settings.html",
            context=dict(
                active_page="settings",
                llm_config=llm_config.to_dict(mask_key=True),
            ),
        )

    @app.get("/api/settings/llm")
    def api_get_llm_settings():
        return JSONResponse(llm_config.to_dict(mask_key=True))

    @app.post("/api/settings/llm")
    async def api_save_llm_settings(request: Request):
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(400, "Invalid JSON body")

        try:
            saved = save_llm_config(
                enabled=bool(data.get("enabled", True)),
                base_url=str(data.get("base_url", "")).strip(),
                api_key=str(data.get("api_key", "")).strip(),
                model=str(data.get("model", "")).strip(),
                timeout_seconds=float(data.get("timeout_seconds", 30.0)),
                temperature=float(data.get("temperature", 0.1)),
                sync_plugin=bool(data.get("sync_plugin", True)),
            )
            _sync_user_org_db()
            return JSONResponse({
                "ok": True,
                "message": "LLM 配置已成功更新并实时热生效",
                "config": saved.to_dict(mask_key=True),
            })
        except Exception as e:
            return JSONResponse({"ok": False, "error": f"保存失败: {e}"}, status_code=500)

    @app.post("/api/settings/llm/test")
    async def api_test_llm_settings(request: Request):
        try:
            data = await request.json()
        except Exception:
            data = {}
        res = test_connection(
            base_url=data.get("base_url", ""),
            api_key=data.get("api_key", ""),
            model=data.get("model", ""),
            timeout=float(data.get("timeout_seconds", 10.0)),
        )
        return JSONResponse(res)

    @app.get("/api/settings/mappings")
    def api_get_settings_mappings():
        manual = get_manual_map()
        org_data = _build_org_users_data()
        name_to_dept = {}
        for dp, ulist in org_data.get("users_by_dept", {}).items():
            for u in ulist:
                name_to_dept[u["name"]] = dp.split("/")[-1]

        res = []
        for m in manual:
            name = m.get("name", "")
            account = m.get("account", "")
            dept = m.get("dept") or name_to_dept.get(name, "研发部")
            res.append({"name": name, "account": account, "dept": dept})

        if not res:
            for dp, ulist in org_data.get("users_by_dept", {}).items():
                if dp == "(未匹配)":
                    continue
                dept_name = dp.split("/")[-1]
                for u in ulist[:8]:
                    raw = u.get("raw_users", [""])[0] if u.get("raw_users") else (u.get("pinyins", [""])[0])
                    res.append({"name": u["name"], "account": raw, "dept": dept_name})

        res.sort(key=lambda x: x["name"])
        return JSONResponse({"mappings": res})

    @app.post("/api/settings/mappings")
    async def api_save_settings_mapping(request: Request):
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(400, "Invalid JSON body")
        name = (data.get("name") or "").strip()
        account = (data.get("account") or "").strip()
        dept = (data.get("dept") or "").strip()
        if not name or not account:
            return JSONResponse({"error": "姓名和账户不能为空"}, status_code=400)

        item = set_manual_mapping(name, account, dept)
        build_plugin_status(config, storage, force=True)
        with _org_users_cache_lock:
            _org_users_cache["data"] = None
        _sync_user_org_db()
        return JSONResponse({"ok": True, "item": item})

    @app.post("/api/settings/mappings/{name}/delete")
    async def api_delete_settings_mapping(name: str):
        from urllib.parse import unquote
        name = unquote(name)
        ok = delete_manual_mapping(name)
        build_plugin_status(config, storage, force=True)
        with _org_users_cache_lock:
            _org_users_cache["data"] = None
        _sync_user_org_db()
        return JSONResponse({"ok": ok})

    # ==================== 数据库高可用、备份与归档 ====================
    backup_dir = getattr(config, "backup_dir", None) or (storage.db_path.parent / "backups")
    archive_dir = getattr(config, "archive_dir", None) or (storage.db_path.parent / "archives")

    @app.get("/api/settings/db-maintenance")
    def api_get_db_maintenance():
        """获取主库状态、自动备份状态及历史备份与归档列表。"""
        stats = storage.get_db_stats()
        backups = storage.list_backups(backup_dir)
        archives = storage.list_archives(archive_dir)
        return JSONResponse({
            "ok": True,
            "stats": stats,
            "scheduler": {
                "backup_cron": "每天 02:00 (CST) 自动全量热备",
                "backup_keep_count": 14,
                "archive_cron": "每天 03:30 (CST) 自动检查归档",
                "archive_retention_days": 90,
            },
            "backups": backups,
            "archives": archives,
        })

    @app.post("/api/settings/backup/run")
    def api_run_manual_backup():
        """手动触发一次数据库在线热备份。"""
        try:
            res = run_daily_backup(storage, backup_dir)
            return JSONResponse({"ok": True, "result": res})
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.post("/api/settings/backup/{filename}/delete")
    def api_delete_backup(filename: str):
        """删除指定的备份文件。"""
        if ".." in filename or "/" in filename or "\\" in filename or not filename.endswith(".db"):
            raise HTTPException(400, "非法文件名")
        target = backup_dir / filename
        if not target.exists():
            raise HTTPException(404, "备份文件不存在")
        try:
            target.unlink()
            return JSONResponse({"ok": True})
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.get("/api/settings/backup/{filename}/download")
    def api_download_backup(filename: str):
        """下载指定的备份文件。"""
        if ".." in filename or "/" in filename or "\\" in filename or not filename.endswith(".db"):
            raise HTTPException(400, "非法文件名")
        target = backup_dir / filename
        if not target.exists():
            raise HTTPException(404, "备份文件不存在")
        return FileResponse(
            path=str(target),
            filename=filename,
            media_type="application/octet-stream",
        )

    @app.post("/api/settings/archive/run")
    async def api_run_manual_archive(request: Request):
        """手动触发冷数据历史归档。"""
        days = 90
        try:
            body = await request.json()
            days = int(body.get("days", 90))
        except Exception:
            pass
        if days < 7:
            days = 7
        try:
            res = run_daily_archive(storage, days=days, archive_dir=archive_dir)
            return JSONResponse(res)
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ==================== 客户端一键分发与策略直拉 ====================
    @app.get("/managed-settings.json")
    def get_managed_settings(request: Request, user: str = "", hostname: str = ""):
        from urllib.parse import quote, unquote
        user = unquote(request.query_params.get("user") or request.query_params.get("u") or user or "").strip()
        hostname = unquote(request.query_params.get("hostname") or request.query_params.get("h") or hostname or "").strip()

        host = request.headers.get("host") or f"{request.url.hostname}:{request.url.port}"
        base_url = f"{request.url.scheme}://{host}"

        query_params = []
        if user:
            query_params.append(f"user={quote(user)}")
        if hostname:
            query_params.append(f"hostname={quote(hostname)}")
        query_suffix = ("?" + "&".join(query_params)) if query_params else ""

        headers_extra: dict[str, str] = {}
        if user:
            headers_extra["X-User"] = user
        if hostname:
            headers_extra["X-Hostname"] = hostname

        def _make_hook(path: str) -> dict:
            hook_item: dict[str, Any] = {
                "type": "http",
                "url": f"{base_url}{path}{query_suffix}",
                "timeout": 5,
            }
            if headers_extra:
                hook_item["headers"] = headers_extra
            return hook_item

        settings = {
            "$schema": "https://json.schemastore.org/claude-code-settings.json",
            "allowedChannel": "enterprise",
            "permissions": {
                "deny": []
            },
            "hooks": {
                "SessionStart": [
                    {
                        "matcher": ".*",
                        "hooks": [_make_hook("/api/hooks/session-start")]
                    }
                ],
                "PreToolUse": [
                    {
                        "matcher": ".*",
                        "hooks": [_make_hook("/api/hooks/pre-tool-use")]
                    }
                ],
                "UserPromptSubmit": [
                    {
                        "hooks": [_make_hook("/api/hooks/user-prompt-submit")]
                    }
                ],
                "PostToolUse": [
                    {
                        "matcher": ".*",
                        "hooks": [_make_hook("/api/hooks/post-tool-use")]
                    }
                ],
                "Stop": [
                    {
                        "hooks": [_make_hook("/api/hooks/stop")]
                    }
                ]
            }
        }
        return JSONResponse(settings)

    @app.get("/install.ps1")
    def get_install_script(request: Request):
        from urllib.parse import unquote
        host = request.headers.get("host") or f"{request.url.hostname}:{request.url.port}"
        server_url = f"{request.url.scheme}://{host}"
        preset_u = unquote(request.query_params.get("u") or request.query_params.get("user") or "").strip()

        ps_script = f"""# ==========================================================
#   Claude Code Managed Settings 一键部署脚本 (HTTP Hook)
#   由Cloud Security 大模型安全管控平台自动生成: {server_url}
# ==========================================================
$ErrorActionPreference = "Stop"

# 1. 检查管理员权限
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {{
    Write-Host "[!] 需要管理员权限以写入系统级配置目录 C:\\Program Files\\ClaudeCode" -ForegroundColor Yellow
    Write-Host "[*] 正在请求提升权限 (UAC)..." -ForegroundColor Yellow
    $origU = if ($env:USERDOMAIN) {{ "$env:USERDOMAIN\\$env:USERNAME" }} else {{ $env:USERNAME }}
    $encU = [System.Uri]::EscapeDataString($origU)
    $proc = if (Get-Command pwsh -ErrorAction SilentlyContinue) {{ "pwsh" }} else {{ "powershell" }}
    $cmd = "irm '{server_url}/install.ps1?u=$encU' | iex"
    Start-Process $proc -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$cmd`"" -Verb RunAs
    exit 0
}}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   正在部署 Claude Code 企业托管策略 (Managed Settings)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 2. 精准获取当前员工电脑的真实用户名与主机名
$curUser = "{preset_u}"
if (-not $curUser) {{
    try {{
        $curUser = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
    }} catch {{}}
}}
if (-not $curUser -or $curUser -match "Administrator") {{
    $curUser = if ($env:USERDOMAIN) {{ "$env:USERDOMAIN\\$env:USERNAME" }} else {{ $env:USERNAME }}
}}

$uParts = $curUser -split '[\\\\/]'
$uNameOnly = if ($uParts.Count -gt 1) {{ $uParts[-1] }} else {{ $curUser }}
$compName = $env:COMPUTERNAME
$curHost = if ($compName -and $uNameOnly -and (-not $compName.EndsWith($uNameOnly))) {{ "$compName-$uNameOnly" }} else {{ $compName }}

Write-Host "[*] 识别到当前终端身份:" -ForegroundColor Green
Write-Host "    用户账号: $curUser" -ForegroundColor White
Write-Host "    客户端标识: $curHost" -ForegroundColor White

# 3. 从服务器拉取最新的专属 managed-settings.json
$serverUrl = "{server_url}"
$encUser = [System.Uri]::EscapeDataString($curUser)
$encHost = [System.Uri]::EscapeDataString($curHost)
$jsonUrl = "$serverUrl/managed-settings.json?user=$encUser&hostname=$encHost"
Write-Host "[*] 正在从服务端拉取托管配置: $jsonUrl" -ForegroundColor Green

try {{
    $resp = Invoke-WebRequest -Uri $jsonUrl -UseBasicParsing -TimeoutSec 10
    $configContent = $resp.Content
}} catch {{
    Write-Host "[!] 从服务器拉取配置失败: $_" -ForegroundColor Red
    Write-Host "[!] 请确认服务器 8787 端口可访问且当前电脑与服务器网络互通。" -ForegroundColor Yellow
    $null = Read-Host "按【回车键】退出"
    exit 1
}}

# 4. 写入 C:\\Program Files\\ClaudeCode\\managed-settings.json
$targetDir = "C:\\Program Files\\ClaudeCode"
if (-not (Test-Path $targetDir)) {{
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}}
$targetFile = Join-Path $targetDir "managed-settings.json"
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($targetFile, $configContent, $utf8NoBom)
Write-Host "[√] 成功写入系统策略: $targetFile" -ForegroundColor Green

# 写入 ProgramData 辅助兜底
$progDataDir = Join-Path $env:ProgramData "ClaudeCode"
if (-not (Test-Path $progDataDir)) {{
    New-Item -ItemType Directory -Path $progDataDir -Force | Out-Null
}}
$progDataFile = Join-Path $progDataDir "managed-settings.json"
[System.IO.File]::WriteAllText($progDataFile, $configContent, $utf8NoBom)
Write-Host "[√] 成功写入辅助策略: $progDataFile" -ForegroundColor Green

# 5. 清理用户个人目录下旧版本 cloud-guard 遗留 hooks
Write-Host "`n[*] 检查并清理旧版本地 Python 插件残留..." -ForegroundColor Yellow
$userProfiles = Get-ChildItem "C:\\Users" -Directory -ErrorAction SilentlyContinue
foreach ($up in $userProfiles) {{
    $settingsFile = Join-Path $up.FullName ".claude\\settings.json"
    if (Test-Path $settingsFile) {{
        try {{
            $raw = Get-Content -Path $settingsFile -Raw -Encoding UTF8
            if ($raw -match "cloud-guard|input_scanner|output_scanner") {{
                $bak = "$settingsFile.bak_$(Get-Date -Format 'yyyyMMddHHmmss')"
                Copy-Item -Path $settingsFile -Destination $bak -Force
                $obj = $raw | ConvertFrom-Json
                if ($null -ne $obj.PSObject.Properties['hooks']) {{
                    $obj.PSObject.Properties.Remove('hooks')
                }}
                [System.IO.File]::WriteAllText($settingsFile, ($obj | ConvertTo-Json -Depth 20), $utf8NoBom)
                Write-Host "    [OK] 已清理旧版 hooks: $settingsFile (已备份为 $bak)" -ForegroundColor Green
            }}
        }} catch {{
            Write-Host "    [!] 清理 $settingsFile 失败: $_" -ForegroundColor DarkGray
        }}
    }}
}}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " [√] 部署成功！终端已接入企业安全管控网关。" -ForegroundColor Green
Write-Host " 管控网关: $serverUrl" -ForegroundColor White
Write-Host " 员工身份: $curUser ($curHost)" -ForegroundColor White
Write-Host " 策略路径: $targetFile" -ForegroundColor White
Write-Host " 员工无需安装 Python 或插件，即刻受到统一安全策略保护。" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "`n按【回车键】完成并退出..." -ForegroundColor Gray
$null = Read-Host
"""
        return Response(content=ps_script, media_type="text/plain; charset=utf-8")

    return app

