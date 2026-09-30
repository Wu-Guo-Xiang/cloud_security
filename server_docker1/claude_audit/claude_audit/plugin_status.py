"""插件安装/在线状态统计。

数据源:
  1. 组织架构 CSV (api/data/org_structure.csv) — 部门树 + 员工姓名/邮箱
  2. LiteLLM 网关 /key/list + /spend/logs/v2 — 每个 key(中文名)最近一次请求的时间与 IP
  3. audit.db events.user — 插件实际上报记录(OS 账户, 拼音)

匹配逻辑:
  LiteLLM key_alias 是中文名; audit.db user 是拼音("CORP\zhangsan" 取最后一段)。
  中文名 -> 拼音: 优先用 CSV 邮箱前缀, 再用 pypinyin 全拼兜底(处理 steven_luo 这类特殊邮箱)。

状态判定(对员工):
  litellm 近24h有日志 且 audit 无记录          -> 未安装
  litellm 最新时间 比 audit 最新时间晚 > 阈值h  -> 离线(插件被关)
  litellm 有日志 且 audit 有记录且时间差 <= 阈值 -> 在线
  litellm 近24h无日志                          -> 未使用(无法判断, 插件不上报属正常)

性能优化:
  后台守护线程每隔 5 分钟自动刷新 LiteLLM + audit 数据,
  页面始终读缓存, 秒级响应; "刷新数据"按钮可手动触发立即更新。
"""
from __future__ import annotations

import csv
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

from .storage.ip_whitelist import check_ip as _check_ip_allowed

# ── 路径 ─────────────────────────────────────────────────────────
_DEFAULT_CSV = Path(__file__).resolve().parent / "api" / "data" / "org_structure.csv"
# sync_org.py 与本文件同包(claude_audit/claude_audit/sync_org.py), 路径相对 __file__,
# 不依赖外部目录结构, 改 server_docker1 文件夹名也不受影响。
_DEFAULT_SYNC_SCRIPT = Path(__file__).resolve().parent / "sync_org.py"

# 中文名 -> 英文/别名账户名 手动映射(组织架构姓名对不上 OS 账户时人工指定)
_DEFAULT_MAP = Path(__file__).resolve().parent / "api" / "data" / "name_pinyin_map.json"
# LiteLLM 键名别名 -> 真实中文名 映射(litellm key_alias 写错字时人工纠错)
_DEFAULT_LL_ALIAS_MAP = Path(__file__).resolve().parent / "api" / "data" / "litellm_alias_map.json"

# 确保数据目录存在
try:
    _DEFAULT_CSV.parent.mkdir(parents=True, exist_ok=True)
except Exception:
    pass

CST = timezone(timedelta(hours=8))
_REFRESH_INTERVAL = 300  # 秒, 后台自动刷新间隔
_REQUEST_TIMEOUT = 20

# 非员工的 key 别名(服务/测试用途), 不参与人员统计但列入"未匹配"
_NON_PERSON_HINTS = ("test", "dify", "ai", "邮箱", "管理", "体验")

# ── 缓存 ─────────────────────────────────────────────────────────
_cache_lock = threading.Lock()
_cache: dict[str, Any] = {"at": 0.0, "data": None}
_bg_thread: threading.Thread | None = None
_bg_stop = threading.Event()


def _norm_name(name: str) -> str:
    """规整姓名: 去空白、去括号工号后缀(如 张敏(PYE583))。"""
    n = re.sub(r"\s+", "", name or "")
    n = re.sub(r"[(（][^)）]*[)）]\s*$", "", n)
    return n


def _norm_alias(alias: str) -> str:
    """规整 litellm key 别名: 去空白、去尾部 _1 / _2 之类序号。"""
    a = re.sub(r"\s+", "", alias or "")
    a = re.sub(r"_\d+$", "", a)
    return a


def _pinyin_candidates(name: str, email: str) -> set[str]:
    """一个员工可能对应的 OS 账户名(小写) 候选集合。

    优先级: 手动映射(name_pinyin_map.json) > 邮箱前缀 > pypinyin 全拼兜底。
    手动映射用于组织架构中文名对不上实际英文/别名账户的情况。
    """
    out: set[str] = set()
    # 1) 手动映射(最权威, 可覆盖邮箱/拼音兜底匹配不上的英文账户名)
    manual = _load_manual_map()
    mapped = manual.get(_norm_name(name)) or manual.get(name or "")
    if mapped:
        mapped = mapped.strip().lower()
        if mapped:
            out.add(mapped)
    # 2) 邮箱前缀
    prefix = (email or "").split("@")[0].strip().lower()
    if prefix:
        out.add(prefix)
        stripped = prefix.rstrip("0123456789")
        if stripped and stripped != prefix:
            out.add(stripped)
    # 3) pypinyin 全拼兜底
    try:
        from pypinyin import Style, pinyin

        full = "".join(p[0] for p in pinyin(_norm_name(name), style=Style.NORMAL)).lower()
        if full:
            out.add(full)
    except Exception:
        pass
    return out


def _audit_username(raw_user: str) -> str:
    """从 audit.db 的 user 字段提取账户名: 按 \\ / - 分段取最后一段, 小写。

    例: "CORP\zhangsan" -> "zhangsan";  "zhangsan" -> "zhangsan"
    """
    parts = [p for p in re.split(r"[\\/\-\s]+", raw_user or "") if p]
    return parts[-1].lower() if parts else ""


# ── 中文名→英文账户名 手动映射 ────────────────────────────────────
# 当飞书组织架构里的中文名与实际 OS 账户名(英文/别名)对不上时,
# 管理员在此手动指定映射, 覆盖拼音/邮箱兜底匹配。
_map_lock = threading.Lock()
_map_cache: dict[str, str] | None = None  # None 表示尚未加载
_DEFAULT_DEPT_MAP = Path(__file__).resolve().parent / "api" / "data" / "name_dept_map.json"


def _dept_map_path() -> Path:
    return _DEFAULT_DEPT_MAP


def _load_dept_map() -> dict[str, str]:
    path = _dept_map_path()
    if path.exists():
        try:
            import json as _json
            raw = _json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return {str(k): str(v) for k, v in raw.items()}
        except Exception:
            pass
    return {}


def _save_dept_map(m: dict[str, str]) -> None:
    import json as _json
    path = _dept_map_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_json.dumps(m, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _map_path() -> Path:
    return Path(os.environ.get("CLAUDE_AUDIT_NAME_MAP") or _DEFAULT_MAP)


def _load_manual_map() -> dict[str, str]:
    """加载手动映射(带内存缓存)。返回 {规整中文名: 账户名}。"""
    global _map_cache
    if _map_cache is not None:
        return _map_cache
    path = _map_path()
    data: dict[str, str] = {}
    if path.exists():
        try:
            import json as _json

            raw = _json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for k, v in raw.items():
                    nk = _norm_name(k)
                    nv = (str(v) if v is not None else "").strip()
                    if nk and nv:
                        data[nk] = nv
        except Exception:
            pass
    _map_cache = data
    return data


def get_manual_map() -> list[dict[str, str]]:
    """返回映射列表(供 API 展示), 按中文名排序。"""
    m = _load_manual_map()
    dm = _load_dept_map()
    return [{"name": k, "account": v, "dept": dm.get(k, "研发部")} for k, v in sorted(m.items(), key=lambda x: x[0])]


def set_manual_mapping(name: str, account: str, dept: str = "研发部") -> dict[str, str]:
    """新增/更新一条映射并落盘。返回 {name, account, dept}。"""
    global _map_cache
    nk = _norm_name(name)
    acc = (account or "").strip()
    dept = (dept or "").strip() or "研发部"
    if not nk or not acc:
        raise ValueError("中文名和英文账户名都不能为空")
    with _map_lock:
        m = _load_manual_map().copy()
        m[nk] = acc
        _save_manual_map(m)
        _map_cache = m
        dm = _load_dept_map()
        dm[nk] = dept
        _save_dept_map(dm)
    return {"name": nk, "account": acc, "dept": dept}


def delete_manual_mapping(name: str) -> bool:
    """删除一条映射。返回是否确实删除了。"""
    global _map_cache
    nk = _norm_name(name)
    with _map_lock:
        m = _load_manual_map()
        if nk not in m:
            return False
        m = {k: v for k, v in m.items() if k != nk}
        _save_manual_map(m)
        _map_cache = m
        dm = _load_dept_map()
        if nk in dm:
            dm.pop(nk, None)
            _save_dept_map(dm)
    return True


def _save_manual_map(m: dict[str, str]) -> None:
    """以可读格式落盘(保留中文, 键排序)。"""
    import json as _json

    path = _map_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = {k: m[k] for k in sorted(m)}
    path.write_text(
        _json.dumps(ordered, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


# ── LiteLLM 键名别名 → 真实中文名 映射 ───────────────────────────
# litellm 的 key_alias 若写错字(如 "王佳建" 应为 "王佳键"),
# 会与飞书真实姓名匹配不上, 在此手动纠错。
_ll_alias_lock = threading.Lock()
_ll_alias_cache: dict[str, str] | None = None


def _ll_alias_path() -> Path:
    return Path(os.environ.get("CLAUDE_AUDIT_LL_ALIAS_MAP") or _DEFAULT_LL_ALIAS_MAP)


def _load_litellm_alias_map() -> dict[str, str]:
    """加载 litellm 键名别名映射(带缓存)。返回 {规整别名: 真实中文名}。"""
    global _ll_alias_cache
    if _ll_alias_cache is not None:
        return _ll_alias_cache
    path = _ll_alias_path()
    data: dict[str, str] = {}
    if path.exists():
        try:
            import json as _json

            raw = _json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for k, v in raw.items():
                    nk = _norm_alias(k)
                    nv = _norm_name(v)
                    if nk and nv:
                        data[nk] = nv
        except Exception:
            pass
    _ll_alias_cache = data
    return data


def get_litellm_alias_map() -> list[dict[str, str]]:
    """返回映射列表(供 API 展示), 按别名排序。"""
    m = _load_litellm_alias_map()
    return [{"alias": k, "name": v} for k, v in sorted(m.items(), key=lambda x: x[0])]


def set_litellm_alias_mapping(alias: str, name: str) -> dict[str, str]:
    """新增/更新一条 键名别名->真实中文名 映射并落盘。"""
    global _ll_alias_cache
    nk = _norm_alias(alias)
    nv = _norm_name(name)
    if not nk or not nv:
        raise ValueError("键名别名和真实中文名都不能为空")
    with _ll_alias_lock:
        m = _load_litellm_alias_map().copy()
        m[nk] = nv
        _save_litellm_alias_map(m)
        _ll_alias_cache = m
    return {"alias": nk, "name": nv}


def delete_litellm_alias_mapping(alias: str) -> bool:
    """删除一条映射。返回是否确实删除了。"""
    global _ll_alias_cache
    nk = _norm_alias(alias)
    with _ll_alias_lock:
        m = _load_litellm_alias_map()
        if nk not in m:
            return False
        m = {k: v for k, v in m.items() if k != nk}
        _save_litellm_alias_map(m)
        _ll_alias_cache = m
    return True


def _save_litellm_alias_map(m: dict[str, str]) -> None:
    """落盘(键排序, 保留中文)。"""
    import json as _json

    path = _ll_alias_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = {k: m[k] for k in sorted(m)}
    path.write_text(
        _json.dumps(ordered, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


# ── 组织架构 ─────────────────────────────────────────────────────
def _csv_path() -> Path:
    return Path(os.environ.get("CLAUDE_AUDIT_ORG_CSV") or _DEFAULT_CSV)


def load_org(csv_path: Path | None = None) -> list[dict[str, str]]:
    """读取组织架构 CSV, 返回员工列表(只含有 user_name 的行)。"""
    path = csv_path or _csv_path()
    people: list[dict[str, str]] = []
    if not path.exists():
        return people
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            name = (row.get("user_name") or "").strip()
            if not name:
                continue
            people.append(
                {
                    "name": name,
                    "email": (row.get("user_email") or "").strip(),
                    "dept_path": (row.get("dept_path") or "").strip(),
                    "dept_name": (row.get("dept_name") or "").strip(),
                }
            )
    return people


def sync_org_from_feishu(csv_path: Path | None = None) -> dict[str, Any]:
    """调用 sync_org.py 从飞书同步最新组织架构到 CSV。

    返回: {"ok": bool, "output": str, "error": str}
    """
    csv_path = csv_path or _csv_path()
    script = Path(os.environ.get("CLAUDE_AUDIT_SYNC_SCRIPT") or _DEFAULT_SYNC_SCRIPT)

    if not script.exists():
        return {"ok": False, "output": "", "error": f"sync_org.py 不存在: {script}"}

    cmd = [sys.executable, str(script), "--csv", str(csv_path)]
    try:
        # 不设超时: 飞书全量拉取(600+人)实测可达 250s+, 由调用方异步轮询控制
        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        ok = result.returncode == 0
        output = (result.stdout or "")[-500:]  # 只保留最后500字符
        error = result.stderr[-500:] if result.stderr else ""
        return {"ok": ok, "output": output, "error": error}
    except Exception as e:
        return {"ok": False, "output": "", "error": str(e)}


# ── 异步同步任务 ──────────────────────────────────────────────────
# 避免前端 HTTP 请求长时间挂起(飞书全量同步可达数分钟)。
# 点同步 → 立即返回 task_id → 前端轮询 /api/sync-org/status → 完成后刷新。
_sync_tasks: dict[str, dict[str, Any]] = {}
_sync_lock = threading.Lock()
_org_sync_done_callbacks: list = []


def register_org_sync_done_callback(cb) -> None:
    """注册飞书组织架构同步完成后的回调函数。"""
    if cb not in _org_sync_done_callbacks:
        _org_sync_done_callbacks.append(cb)


def _notify_org_sync_done() -> None:
    for cb in _org_sync_done_callbacks:
        try:
            cb()
        except Exception as e:
            _log(f"[org-sync-callback] error: {e}")


def start_sync_org_task() -> dict[str, Any]:
    """启动一个异步同步任务。返回 {"task_id": str}。

    同一时刻只允许一个同步任务运行; 已有任务在跑则返回该任务状态。
    """
    now_ts = time.time()
    now_str = datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S")
    with _sync_lock:
        # 检查是否有正在运行的任务
        for tid, t in _sync_tasks.items():
            if t.get("status") == "running":
                info = dict(t)
                info["task_id"] = tid
                info["already_running"] = True
                if info.get("started_ts"):
                    info["elapsed_seconds"] = int(time.time() - info["started_ts"])
                return info
        # 生成 task_id (线程安全: 用递增计数器, 不依赖时间)
        if not hasattr(start_sync_org_task, "_seq"):
            start_sync_org_task._seq = 0
        start_sync_org_task._seq += 1
        task_id = f"sync_{start_sync_org_task._seq}"
        _sync_tasks[task_id] = {
            "task_id": task_id,
            "status": "running",
            "output": "",
            "error": "",
            "started_ts": now_ts,
            "started_at": now_str,
            "finished_at": "",
            "elapsed_seconds": 0,
        }

    def _run():
        try:
            result = sync_org_from_feishu()
            ok = bool(result["ok"])
            finished_str = datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S")
            elapsed = int(time.time() - now_ts)
            with _sync_lock:
                _sync_tasks[task_id].update({
                    "status": "done" if ok else "failed",
                    "output": result.get("output", ""),
                    "error": result.get("error", ""),
                    "finished_at": finished_str,
                    "elapsed_seconds": elapsed,
                })
            if ok:
                with _cache_lock:
                    _cache["data"] = None
                _notify_org_sync_done()
        except Exception as e:
            finished_str = datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S")
            elapsed = int(time.time() - now_ts)
            with _sync_lock:
                _sync_tasks[task_id].update({
                    "status": "failed",
                    "error": str(e),
                    "finished_at": finished_str,
                    "elapsed_seconds": elapsed,
                })

    t = threading.Thread(target=_run, name=f"sync-org-{task_id}", daemon=True)
    t.start()
    return {"task_id": task_id, "status": "running", "elapsed_seconds": 0}


def get_sync_org_status(task_id: str) -> dict[str, Any] | None:
    """查询指定同步任务状态。动态计算当前已耗时秒数。"""
    with _sync_lock:
        t = _sync_tasks.get(task_id)
        if not t:
            return None
        info = dict(t)
        info["task_id"] = task_id
        if info.get("status") == "running" and info.get("started_ts"):
            info["elapsed_seconds"] = int(time.time() - info["started_ts"])
        return info


def get_latest_sync_org_task() -> dict[str, Any] | None:
    """获取最新的一次同步任务（优先正在运行中的，否则返回最近一次完成的）。"""
    with _sync_lock:
        if not _sync_tasks:
            return None
        # 优先返回 running 的任务
        for tid in reversed(list(_sync_tasks.keys())):
            t = _sync_tasks[tid]
            if t.get("status") == "running":
                info = dict(t)
                info["task_id"] = tid
                if info.get("started_ts"):
                    info["elapsed_seconds"] = int(time.time() - info["started_ts"])
                return info
        # 否则返回最后一条任务
        last_tid = list(_sync_tasks.keys())[-1]
        info = dict(_sync_tasks[last_tid])
        info["task_id"] = last_tid
        return info


# ── LiteLLM ─────────────────────────────────────────────────────
def _fetch_key_aliases(host: str, api_key: str) -> dict[str, str]:
    """api_key hash -> key_alias(中文名)"""
    mapping: dict[str, str] = {}
    page = 1
    while True:
        resp = requests.get(
            f"{host}/key/list",
            params={"page": page, "size": 100, "return_full_object": "true"},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        for k in data.get("keys") or []:
            token = k.get("token") or ""
            alias = k.get("key_alias") or k.get("key_name") or ""
            if token:
                mapping[token] = alias
        if page * 100 >= (data.get("total_count") or 0):
            break
        page += 1
    return mapping


def _fetch_last_use_per_key(
    host: str, api_key: str, aliases: dict[str, str]
) -> dict[str, dict[str, Any]]:
    """拉取近24h全部日志, 按 api_key 分组取每 key 最新一条(时间+IP)。

    返回: {alias原文: {"last_utc": datetime, "ip": str, "count_24h": int}}
    同一个中文名可能有多个 key, 调用方负责合并。
    """
    today = datetime.now(CST).strftime("%Y-%m-%d")
    yesterday = (datetime.now(CST) - timedelta(days=1)).strftime("%Y-%m-%d")
    start = f"{yesterday} 00:00:00"
    end = f"{today} 23:59:59"

    # 先拿总数, 决定翻页策略
    page_size = 100  # v2 接口上限
    try:
        first = requests.get(
            f"{host}/spend/logs/v2",
            params={"page": 1, "page_size": page_size, "start_date": start, "end_date": end},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=_REQUEST_TIMEOUT,
        )
        first.raise_for_status()
        first_data = first.json()
    except Exception:
        return {}

    total = first_data.get("total", 0)
    all_logs = list(first_data.get("data") or [])

    # 剩余页
    total_pages = first_data.get("total_pages", 1)
    for page in range(2, total_pages + 1):
        try:
            resp = requests.get(
                f"{host}/spend/logs/v2",
                params={"page": page, "page_size": page_size, "start_date": start, "end_date": end},
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=_REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            all_logs.extend(resp.json().get("data") or [])
        except Exception:
            break

    # 按 api_key 分组取最新
    best_by_key: dict[str, dict[str, Any]] = {}
    for lg in all_logs:
        token = lg.get("api_key") or ""
        raw = lg.get("startTime") or ""
        if not token or token not in aliases:
            continue
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
        cur = best_by_key.get(token)
        if cur is None or dt > cur["last_utc"]:
            best_by_key[token] = {
                "last_utc": dt,
                "ip": lg.get("requester_ip_address") or "",
            }

    # 转成 alias -> info
    out: dict[str, dict[str, Any]] = {}
    for token, info in best_by_key.items():
        alias = aliases.get(token, "")
        if not alias:
            continue
        cur = out.get(alias)
        if cur is None or info["last_utc"] > cur["last_utc"]:
            out[alias] = {
                "last_utc": info["last_utc"],
                "ip": info["ip"],
                "count_24h": 0,  # 批量模式无法精确统计每key条数, 略
            }
    return out


# ── LiteLLM key 停用/恢复(员工离线时停用其 key) ─────────────────────
def _fetch_key_details(host: str, api_key: str) -> dict[str, dict[str, Any]]:
    """拉取 litellm 全部 key 的详情: token -> {alias, blocked}。"""
    details: dict[str, dict[str, Any]] = {}
    page = 1
    while True:
        resp = requests.get(
            f"{host}/key/list",
            params={"page": page, "size": 100, "return_full_object": "true"},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        for k in data.get("keys") or []:
            token = k.get("token") or ""
            alias = k.get("key_alias") or k.get("key_name") or ""
            if token:
                details[token] = {
                    "alias": alias,
                    "blocked": bool(k.get("blocked", False)),
                }
        if page * 100 >= (data.get("total_count") or 0):
            break
        page += 1
    return details


def _block_one_key(host: str, api_key: str, token: str) -> dict[str, Any]:
    """停用单个 key。返回 {ok, error}。"""
    try:
        resp = requests.post(
            f"{host}/key/block",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"key": token},
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            return {"ok": True, "error": ""}
        return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _unblock_one_key(host: str, api_key: str, token: str) -> dict[str, Any]:
    """恢复单个 key。返回 {ok, error}。"""
    try:
        resp = requests.post(
            f"{host}/key/unblock",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"key": token},
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            return {"ok": True, "error": ""}
        return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def get_offline_key_info(config, storage) -> dict[str, Any]:
    """返回当前离线员工及其 litellm key 状态(供页面展示 + 停用/恢复)。

    返回: {"offline": [{name, dept_path, keys: [{token, alias, blocked}], blocked_count, total_count}]}
    """
    ll = getattr(config, "litellm", None)
    if not ll or not ll.host or not ll.api_key:
        return {"offline": [], "error": "未配置 litellm"}

    data = build_status(config, storage)  # 读缓存(含状态判定)
    offline_rows = [r for r in data.get("rows", []) if r["status"] == "offline"]

    try:
        details = _fetch_key_details(ll.host, ll.api_key)  # token -> {alias, blocked}
    except Exception as e:
        return {"offline": [], "error": f"拉取 litellm key 失败: {e}"}

    # 反查 alias(中文名) -> tokens
    offline = []
    for r in offline_rows:
        norm = _norm_name(r["name"])
        keys = [
            {"token": t, "alias": d["alias"], "blocked": d["blocked"]}
            for t, d in details.items()
            if _norm_alias(d["alias"]) == norm
        ]
        offline.append({
            "name": r["name"],
            "dept_path": r.get("dept_path", ""),
            "keys": keys,
            "blocked_count": sum(1 for k in keys if k["blocked"]),
            "total_count": len(keys),
        })
    return {"offline": offline, "error": ""}


def block_offline_keys(config, storage) -> dict[str, Any]:
    """批量停用所有离线员工的 key(跳过已 block 的)。"""
    ll = getattr(config, "litellm", None)
    if not ll or not ll.host or not ll.api_key:
        return {"ok": False, "blocked": [], "failed": [], "error": "未配置 litellm"}

    info = get_offline_key_info(config, storage)
    if info.get("error"):
        return {"ok": False, "blocked": [], "failed": [], "error": info["error"]}

    blocked: list[str] = []      # 成功停用的员工名
    failed: list[dict] = []      # 失败记录
    for u in info["offline"]:
        for k in u["keys"]:
            if k["blocked"]:
                continue  # 已停用, 跳过
            r = _block_one_key(ll.host, ll.api_key, k["token"])
            if r["ok"]:
                blocked.append(u["name"])
            else:
                failed.append({"name": u["name"], "alias": k["alias"], "error": r["error"]})
    # 去重
    blocked = sorted(set(blocked))
    return {"ok": True, "blocked": blocked, "failed": failed, "error": ""}


def unblock_user_keys(config, storage, name: str) -> dict[str, Any]:
    """恢复某个员工的所有 key。name 为中文名。"""
    ll = getattr(config, "litellm", None)
    if not ll or not ll.host or not ll.api_key:
        return {"ok": False, "unblocked": [], "failed": [], "error": "未配置 litellm"}

    info = get_offline_key_info(config, storage)
    # 该员工可能在 offline 列表里, 也可能已恢复在线; 直接从 details 反查更可靠
    try:
        details = _fetch_key_details(ll.host, ll.api_key)
    except Exception as e:
        return {"ok": False, "unblocked": [], "failed": [], "error": f"拉取 litellm key 失败: {e}"}

    norm = _norm_name(name)
    tokens = [t for t, d in details.items() if _norm_alias(d["alias"]) == norm and d["blocked"]]
    unblocked = 0
    failed = []
    for t in tokens:
        r = _unblock_one_key(ll.host, ll.api_key, t)
        if r["ok"]:
            unblocked += 1
        else:
            failed.append({"alias": details[t]["alias"], "error": r["error"]})
    return {"ok": True, "unblocked": unblocked, "failed": failed, "error": ""}


# ── audit.db ────────────────────────────────────────────────────
def _fetch_audit_last(storage) -> dict[str, datetime]:
    """audit.db 中每个 OS 账户名(拼音) 的最新事件时间(aware datetime)。"""
    conn = storage.read_conn()
    try:
        rows = conn.execute(
            "SELECT user, MAX(ts) AS last_ts FROM events "
            "WHERE user IS NOT NULL AND user<>'' GROUP BY user"
        ).fetchall()
    finally:
        conn.close()
    out: dict[str, datetime] = {}
    for r in rows:
        uname = _audit_username(r["user"])
        if not uname:
            continue
        raw = r["last_ts"] or ""
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=CST)
        except ValueError:
            continue
        if uname not in out or dt > out[uname]:
            out[uname] = dt
    return out


# ── 汇总 ─────────────────────────────────────────────────────────
def build_status(config, storage, force: bool = False) -> dict[str, Any]:
    """组装全部状态数据。

    - force=True: 立即重新拉取(忽略缓存)
    - force=False: 有缓存则直接返回
    """
    with _cache_lock:
        if not force and _cache["data"] is not None:
            return _cache["data"]

    ll = getattr(config, "litellm", None)
    threshold = timedelta(hours=getattr(ll, "offline_threshold_hours", 3) if ll else 3)

    people = load_org()
    aliases: dict[str, str] = {}
    litellm_by_alias: dict[str, dict[str, Any]] = {}
    audit_by_user: dict[str, datetime] = {}
    litellm_error = ""

    if ll and ll.host and ll.api_key:
        try:
            aliases = _fetch_key_aliases(ll.host, ll.api_key)
            litellm_by_alias = _fetch_last_use_per_key(ll.host, ll.api_key, aliases)
        except Exception as e:
            litellm_error = str(e)
    else:
        litellm_error = "未配置 litellm.host / litellm.api_key"

    try:
        audit_by_user = _fetch_audit_last(storage)
    except Exception:
        audit_by_user = {}

    # 别名(规整后) -> litellm 信息(同人多个 key 取最新)
    # 先应用键名别名映射: litellm key_alias 写错字(如 "王佳建") 映射回真实名("王佳键")
    ll_alias_map = _load_litellm_alias_map()
    litellm_by_name: dict[str, dict[str, Any]] = {}
    for alias, info in litellm_by_alias.items():
        key = _norm_alias(alias)
        # 键名纠错: 错误别名 -> 真实中文名
        mapped = ll_alias_map.get(key)
        if mapped:
            key = _norm_name(mapped)
        cur = litellm_by_name.get(key)
        if cur is None or info["last_utc"] > cur["last_utc"]:
            merged = dict(info)
            merged["aliases"] = (cur.get("aliases") if cur else []) + [alias]
            litellm_by_name[key] = merged
        else:
            cur.setdefault("aliases", []).append(alias)

    rows: list[dict[str, Any]] = []
    matched_names: set[str] = set()

    for p in people:
        norm = _norm_name(p["name"])
        ll_info = litellm_by_name.get(norm)
        if ll_info is not None:
            matched_names.add(norm)
        candidates = _pinyin_candidates(p["name"], p["email"])
        audit_last = None
        audit_user = ""
        for cand in candidates:
            dt = audit_by_user.get(cand)
            if dt and (audit_last is None or dt > audit_last):
                audit_last = dt
                audit_user = cand

        ll_last = ll_info["last_utc"] if ll_info else None
        if ll_last is None and audit_last is None:
            status = "unused"
        elif ll_last is not None and audit_last is None:
            status = "not_installed"
        elif ll_last is not None and audit_last is not None:
            status = "offline" if (ll_last - audit_last) > threshold else "online"
        else:  # ll_last is None, audit_last is not None
            status = "unused"  # 装过但近24h未通过网关调用

        # IP 白名单判定
        ip_allowed = _check_ip_allowed(storage, (ll_info or {}).get("ip", "")) if (ll_info or {}).get("ip") else True

        rows.append(
            {
                "name": p["name"],
                "email": p["email"],
                "dept_path": p["dept_path"],
                "dept_name": p["dept_name"],
                "status": status,
                "ip_allowed": ip_allowed,
                "litellm_last": ll_last.astimezone(CST).strftime("%Y-%m-%d %H:%M:%S") if ll_last else "",
                "litellm_ip": (ll_info or {}).get("ip", ""),
                "litellm_count_24h": (ll_info or {}).get("count_24h", 0),
                "audit_last": audit_last.astimezone(CST).strftime("%Y-%m-%d %H:%M:%S") if audit_last else "",
                "audit_user": audit_user,
            }
        )

    # litellm 里有但组织里匹配不到中文名的 key
    unmatched = []
    for alias, info in litellm_by_alias.items():
        key = _norm_alias(alias)
        # 若该别名经键名映射已归入某真实名, 不再算"未匹配"
        if key in matched_names or ll_alias_map.get(key) in matched_names:
            continue
        unmatched.append(
            {
                "alias": alias,
                "ip": info.get("ip", ""),
                "last": info["last_utc"].astimezone(CST).strftime("%Y-%m-%d %H:%M:%S"),
                "count_24h": info.get("count_24h", 0),
                "hint": "service" if any(h in alias.lower() for h in _NON_PERSON_HINTS) else "unknown",
            }
        )
    unmatched.sort(key=lambda x: x["last"], reverse=True)

    summary = {
        "total": len(rows),
        "online": sum(1 for r in rows if r["status"] == "online"),
        "offline": sum(1 for r in rows if r["status"] == "offline"),
        "not_installed": sum(1 for r in rows if r["status"] == "not_installed"),
        "unused": sum(1 for r in rows if r["status"] == "unused"),
        "ip_blocked": sum(1 for r in rows if not r.get("ip_allowed", True)),
        "unmatched_keys": len(unmatched),
    }

    data = {
        "generated_at": datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S"),
        "threshold_hours": int(threshold.total_seconds() // 3600),
        "litellm_error": litellm_error,
        "total_keys": len(aliases),
        "rows": rows,
        "unmatched": unmatched,
        "summary": summary,
    }
    with _cache_lock:
        _cache["data"] = data
        _cache["at"] = time.time()
    return data


# ── 后台刷新 ─────────────────────────────────────────────────────
def start_background_refresh(config, storage, interval: int = _REFRESH_INTERVAL) -> None:
    """启动后台守护线程, 每隔 interval 秒自动刷新数据。

    服务器启动时调用一次即可。页面始终读缓存, 秒级响应。
    """
    global _bg_thread

    if _bg_thread is not None and _bg_thread.is_alive():
        return  # 已在运行

    def _loop():
        while not _bg_stop.is_set():
            try:
                build_status(config, storage, force=True)
            except Exception:
                pass  # 刷新失败不影响页面
            _bg_stop.wait(interval)  # 可被 stop 提前唤醒

    _bg_stop.clear()
    _bg_thread = threading.Thread(target=_loop, name="plugin-status-bg-refresh", daemon=True)
    _bg_thread.start()


def stop_background_refresh() -> None:
    """停止后台刷新(服务关闭时调用)。"""
    _bg_stop.set()


# ── 每天凌晨自动同步组织架构 ───────────────────────────────────────
_DAILY_SYNC_HOUR = 3  # 每天 03:00 (CST) 自动同步, 避开 0 点日志轮转/备份高峰
_daily_sync_thread: threading.Thread | None = None
_daily_sync_stop = threading.Event()


def _log(msg: str) -> None:
    """写 stderr, 容忍 Windows GBK 终端无法编码中文的情况。"""
    import sys
    try:
        sys.stderr.write(msg + "\n")
    except UnicodeEncodeError:
        sys.stderr.buffer.write((msg + "\n").encode("utf-8", "replace"))


def _seconds_until_next_run(hour: int) -> float:
    """计算从现在到下一个每天 hour 点(CST)的秒数。"""
    now = datetime.now(CST)
    target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


def start_daily_org_sync() -> None:
    """启动后台守护线程, 每天凌晨 _DAILY_SYNC_HOUR 点自动从飞书同步组织架构。

    服务器启动时调用一次。同步复用 start_sync_org_task 的任务机制,
    自动清缓存, 失败不影响服务(下次凌晨再试)。
    """
    global _daily_sync_thread
    if _daily_sync_thread is not None and _daily_sync_thread.is_alive():
        return  # 已在运行

    def _loop():
        while not _daily_sync_stop.is_set():
            wait_s = _seconds_until_next_run(_DAILY_SYNC_HOUR)
            if _daily_sync_stop.wait(wait_s):
                return  # 被停止唤醒
            try:
                import sys
                _log(f"[daily-sync] 开始每日 {_DAILY_SYNC_HOUR}:00 组织架构自动同步")
                start_sync_org_task()
            except Exception as e:
                _log(f"[daily-sync] 自动同步失败: {e}")

    _daily_sync_stop.clear()
    _daily_sync_thread = threading.Thread(
        target=_loop, name="daily-org-sync", daemon=True
    )
    _daily_sync_thread.start()


def stop_daily_org_sync() -> None:
    """停止每日自动同步(服务关闭时调用)。"""
    _daily_sync_stop.set()
