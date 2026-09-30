"""GLM 后端实时监控 —— 采集 + 存储 + Web 服务 (纯标准库, 零依赖)。

数据源:
  1) vLLM  192.168.3.128:30080 + 192.168.3.129:30080 (同型号同角色的两台, 合并为一个 GLM 池)
     -> 实时队列 (waiting/running/preemption) + KV cache + 缓存命中
  2) LiteLLM  192.168.3.124:4000                -> 近窗口 spend logs, 按 IP 聚合
                                                  (请求数 / 对话session数 / 平均耗时)

存储: SQLite  ./glm_monitor_data.db
  - samples_vllm(ts, backend, waiting, running, preemption, gpu_cache_usage)
  - samples_litellm(ts, ip, requests, sessions, avg_ms, max_ms, fail, models)
  (litellm 表每次采样整窗覆盖: 先删该 ts 再写)

Web:
  GET /            页面 (内嵌 Chart.js CDN, 离线降级表格)
  GET /api/queue?range=秒  队列时序 (按范围降采样, 默认 900=15分钟)
  GET /api/ips     当前各 IP 对话/请求聚合 (+采集诊断信息)
  GET /api/status  采集线程存活 + 最近一次采样时间

启动:
  python monitor.py
  浏览器打开 http://127.0.0.1:8790
"""
from __future__ import annotations
import sqlite3, threading, time, json, re, urllib.request, urllib.parse, urllib.error
import os
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections import defaultdict

# ── 配置 ────────────────────────────────────────────────
# 128/129 是同型号、同角色、都跑 GLM-5.2-Int8 的两台 vLLM 实例, 组成一个 GPU 池。
# 页面合并为单个「GLM」序列(不再分两条曲线):
#   - waiting/running/preemption/prompt/gen 等计数类指标 -> 两台求和(池总量)
#   - prefix_hit_rate -> 用合并后的 cached总量/prompt总量 重算
#   - kv_cache_usage -> 两台均值(同规格, 均值即整体占用)
VLLM_ENDPOINTS = [
    ("GLM-128", os.environ.get("GLM_VLLM_HOST", "http://192.168.3.128:30080")),
    ("GLM-129", os.environ.get("GLM_VLLM_HOST2", "http://192.168.3.129:30080")),
]
VLLM_BACKENDS = ["GLM"]   # 合并后的逻辑后端名(页面/库只认这一个)
LITELLM_HOST = os.environ.get("GLM_LITELLM_HOST", "http://192.168.3.124:4000")
LITELLM_KEY  = os.environ.get("GLM_LITELLM_KEY", "sk-litellm-demo-key")

VLLM_INTERVAL   = 5      # 秒, vLLM 队列采样(默认; 页面可实时调)
LITELLM_INTERVAL = 15    # 秒, LiteLLM 日志拉取
LITELLM_WINDOW  = 5      # 分钟, 采集线程的固定聚合窗口(实时快照)
RETENTION_SEC   = 7*24*3600  # 数据保留 7 天 (支持 7 天趋势视图)
MAX_CHART_POINTS = 240   # /api/queue 降采样后的最大返回点数
MAX_IPS_PAGES   = 25     # /api/ips 自选范围时最多拉取的 spend logs 页数(每页100条, 上限2500条)
GLM_MODEL_PARAM = "GLM-5.2-Int8"  # spend logs v2 服务端 model 过滤参数

# 显示时间统一用北京时间(UTC+8)。服务器若为 UTC 时区, datetime.now()/fromtimestamp()
# 会用 UTC 导致显示慢 8 小时, 故所有展示时间显式指定 CN_TZ。
CN_TZ = timezone(timedelta(hours=8))

# IP 聚合只统计这些模型 (其余如 kimi-k3 / embedding 不计入 "GLM 对话")
GLM_MODEL_FILTER = ("GLM-5.2-Int8",)
def is_glm_model(model: str) -> bool:
    if not model:
        return False
    return any(model.startswith(p) for p in GLM_MODEL_FILTER)

# DB 路径: 优先环境变量(Docker 里指向 /data 持久化卷);
# 默认 monitor.py 同目录 (= glm_monitor/glm_monitor_data.db), 与平台 config(claude_audit/config.yml
# 的 ../glm_monitor/glm_monitor_data.db) 解析到同一文件, 无需设环境变量即对齐。
# (历史坑: 曾用 "glm_monitor_data.db" 相对 cwd, 从项目根启动会落到错误位置致平台"暂无采样数据")
DB_PATH = os.environ.get(
    "GLM_MONITOR_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "glm_monitor_data.db"))
HTTP_PORT = int(os.environ.get("GLM_HTTP_PORT", "8790"))
# 监听地址: 默认 0.0.0.0 以便 LiteLLM 回调能 POST 到 /api/inflight (见 custom_callbacks/inflight_logger.py)。
# 只想本机访问可设 GLM_HTTP_HOST=127.0.0.1 (但那样 LiteLLM 推不到)。
HTTP_HOST = os.environ.get("GLM_HTTP_HOST", "0.0.0.0")

# 超大上下文阈值(token): 在途表格红标 + 顶部计数 + 明细弹窗输入token 的统一阈值。
# 环境变量 GLM_BIG_CONTEXT 只作初始默认值, 页面"⚙ 阈值"可实时改并持久化(见 THRESHOLDS)。
# 默认 200K —— 正常负载十几万, 默认 20万才标红, 突出真正异常的超大请求。
BIG_CONTEXT = int(os.environ.get("GLM_BIG_CONTEXT", "200000"))
# 已耗时阈值(秒): 在途请求"已耗时"列红标 + 顶部计数的统一阈值。
# 环境变量 GLM_SLOW_SEC 只作初始默认值, 页面可实时改。默认 120 秒标"超时"。
SLOW_SEC = int(os.environ.get("GLM_SLOW_SEC", "120"))

# ── DB ──────────────────────────────────────────────────
def db_conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.execute("""CREATE TABLE IF NOT EXISTS samples_vllm(
        ts REAL, backend TEXT, waiting REAL, running REAL,
        preemption REAL, gpu_cache_usage REAL, kv_cache_usage REAL,
        prompt_tokens REAL, gen_tokens REAL, prefix_hit_rate REAL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS samples_litellm(
        ts REAL, ip TEXT, requests INTEGER, sessions INTEGER,
        avg_ms REAL, max_ms REAL, fail INTEGER, models TEXT, names TEXT)""")
    c.execute("CREATE INDEX IF NOT EXISTS ix_vllm_ts ON samples_vllm(ts)")
    c.execute("CREATE INDEX IF NOT EXISTS ix_ll_ts ON samples_litellm(ts)")
    # 阈值等运行时可改配置(页面改后持久化, 重启保留)
    c.execute("""CREATE TABLE IF NOT EXISTS monitor_settings(
        key TEXT PRIMARY KEY, val TEXT)""")
    # 兼容旧 db: 补新列
    vcols = [r[1] for r in c.execute("PRAGMA table_info(samples_vllm)").fetchall()]
    for col, ddl in [("kv_cache_usage","REAL DEFAULT 0"),
                     ("prompt_tokens","REAL DEFAULT 0"),
                     ("gen_tokens","REAL DEFAULT 0"),
                     ("prefix_hit_rate","REAL DEFAULT 0")]:
        if col not in vcols:
            c.execute(f"ALTER TABLE samples_vllm ADD COLUMN {col} {ddl}")
    lcols = [r[1] for r in c.execute("PRAGMA table_info(samples_litellm)").fetchall()]
    if "names" not in lcols:
        c.execute("ALTER TABLE samples_litellm ADD COLUMN names TEXT DEFAULT ''")
    c.commit()
    return c

DB = db_conn()
DB_LOCK = threading.Lock()

# ── 阈值(运行时可改 + 持久化到 monitor_settings) ────────
# 页面"⚙ 阈值"实时改; 存 SQLite, 重启采集器后仍保留; 环境变量只作初始默认值。
THRESHOLD_LOCK = threading.Lock()
THRESHOLDS = {"big_context": BIG_CONTEXT, "slow_sec": SLOW_SEC}


def _load_thresholds():
    """启动时从 monitor_settings 恢复页面改过的阈值(没存过则用环境变量默认值)。"""
    try:
        for k, v in DB.execute("SELECT key, val FROM monitor_settings").fetchall():
            if k in THRESHOLDS:
                try:
                    THRESHOLDS[k] = int(v)
                except (ValueError, TypeError):
                    pass
    except Exception:
        pass


def set_thresholds(big_context=None, slow_sec=None) -> dict:
    """运行时修改阈值并持久化。返回新的 {big_context, slow_sec}。"""
    with THRESHOLD_LOCK:
        if big_context is not None:
            try:
                bc = int(big_context)
                if 1000 <= bc <= 100_000_000:
                    THRESHOLDS["big_context"] = bc
            except (ValueError, TypeError):
                pass
        if slow_sec is not None:
            try:
                ss = int(slow_sec)
                if 1 <= ss <= 3600:
                    THRESHOLDS["slow_sec"] = ss
            except (ValueError, TypeError):
                pass
        cur = dict(THRESHOLDS)
    try:
        with DB_LOCK:
            DB.execute("INSERT OR REPLACE INTO monitor_settings(key,val) VALUES('big_context',?)",
                       (str(cur["big_context"]),))
            DB.execute("INSERT OR REPLACE INTO monitor_settings(key,val) VALUES('slow_sec',?)",
                       (str(cur["slow_sec"]),))
            DB.commit()
    except Exception:
        pass
    return {"ok": True, "big_context": cur["big_context"], "slow_sec": cur["slow_sec"]}


_load_thresholds()

# 清理历史后端名残留(曾把 128/129 当两个独立后端采集, 现在合并为单个 GLM)
with DB_LOCK:
    DB.execute("DELETE FROM samples_vllm WHERE backend != 'GLM'")
    DB.commit()

# ── 采集状态 ────────────────────────────────────────────
# vllm_interval 可由前端 /api/interval 实时修改(页面下拉框选 5s/10s/30s/1min)
VLLM_INTERVAL_CURRENT = VLLM_INTERVAL
INTERVAL_LOCK = threading.Lock()

STATE = {
    "vllm_last": {},        # backend -> iso ts
    "litellm_last": "",
    "vllm_err": {},
    "litellm_err": "",
    "started": time.time(),
    "vllm_interval": VLLM_INTERVAL,
}

# ── 实时在途请求 (LiteLLM pre-call 回调推送) ─────────────
# request_id -> {name, ip, model, prompt_tokens, prompt_tokens_est, prompt_tokens_actual,
#                completion_tokens, status, start_ts, end_ts}
# 请求到达 LiteLLM 即 push "start"(估算 token); 结束 push "finish"(真实 token)。
# finish 后不立即删, 保留 INFLIGHT_GRACE 秒让人看到"刚跑完的真实大小", 再清。
INFLIGHT: dict[str, dict] = {}
INFLIGHT_LOCK = threading.Lock()
INFLIGHT_TTL = 1860         # running 超过 request_timeout(1800s)+余量 未收到 finish -> 标 STALE
INFLIGHT_GRACE = 30         # finish/stale 后保留 30s 显示, 再删
INFLIGHT_LAST_PUSH = 0.0    # 最近一次收到回调的时间; 用来判断回调是否已部署

# ── HTTP 抓取 ───────────────────────────────────────────
def http_get(url, timeout=15, auth=None):
    headers = {}
    if auth:
        headers["Authorization"] = f"Bearer {auth}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")

def gauge(text, name):
    """取 vLLM gauge 当前值 (跳过 reason= 明细行)."""
    vals = []
    for line in text.splitlines():
        if line.startswith("#"): continue
        if not (line.startswith(name + " ") or line.startswith(name + "{")): continue
        if "reason=" in line: continue
        m = re.search(r"\s([0-9.e+-]+)$", line)
        if m: vals.append(float(m.group(1)))
    return vals[-1] if vals else 0.0

def hist_quantile(text, name, q):
    """从 prometheus histogram 估算分位数 (基于 bucket 累计计数)。
    返回秒。name 不含 _bucket 后缀。"""
    buckets = []  # [(le, count)]
    inf_count = 0
    for line in text.splitlines():
        if line.startswith("#"): continue
        if not line.startswith(name + "_bucket"): continue
        mle = re.search(r'le="([^"]+)"', line)
        mval = re.search(r"\s([0-9.e+-]+)$", line)
        if not (mle and mval): continue
        le = mle.group(1)
        cnt = float(mval.group(1))
        if le == "+Inf":
            inf_count = cnt
        else:
            try: buckets.append((float(le), cnt))
            except ValueError: pass
    total = inf_count if inf_count else (buckets[-1][1] if buckets else 0)
    if total <= 0:
        return 0.0
    target = total * q
    buckets.sort(key=lambda x: x[0])
    prev_le, prev_cnt = 0.0, 0.0
    for le, cnt in buckets:
        if cnt >= target:
            if cnt == prev_cnt:
                return le
            frac = (target - prev_cnt) / (cnt - prev_cnt)
            return prev_le + frac * (le - prev_le)
        prev_le, prev_cnt = le, cnt
    return prev_le

def counter(text, name):
    """取 counter 当前累计值 (跳过 _created)。"""
    vals = []
    for line in text.splitlines():
        if line.startswith("#"): continue
        if line.startswith(name + "_created"): continue
        if not (line.startswith(name + " ") or line.startswith(name + "{")): continue
        m = re.search(r"\s([0-9.e+-]+)$", line)
        if m: vals.append(float(m.group(1)))
    return sum(vals) if vals else 0.0

# ── token -> 人名映射 (LiteLLM key_alias) ───────────────
TOKEN2ALIAS: dict[str, str] = {}
TOKEN2ALIAS_LOCK = threading.Lock()
KEYLIST_REFRESH = 300  # 10 分钟刷新一次 key 列表

def refresh_token_alias():
    """拉 /key/list 建 token->key_alias(中文名) 映射。失败保留旧映射, 不抛异常。"""
    global TOKEN2ALIAS
    try:
        mapping = {}
        page = 1
        while True:
            d = json.loads(http_get(
                f"{LITELLM_HOST}/key/list?page={page}&size=100&return_full_object=true",
                timeout=20, auth=LITELLM_KEY))
            for k in d.get("keys") or []:
                token = k.get("token") or ""
                alias = k.get("key_alias") or k.get("key_name") or ""
                if token and alias:
                    mapping[token] = alias
            if page * 100 >= (d.get("total_count") or 0):
                break
            page += 1
            if page > 20:  # 防失控
                break
        if mapping:
            with TOKEN2ALIAS_LOCK:
                TOKEN2ALIAS.clear()
                TOKEN2ALIAS.update(mapping)
            STATE["alias_count"] = len(mapping)
            STATE["alias_err"] = ""
    except Exception as e:
        STATE["alias_err"] = f"{type(e).__name__}: {e}"

def alias_of(token: str) -> str:
    if not token:
        return ""
    with TOKEN2ALIAS_LOCK:
        return TOKEN2ALIAS.get(token, "")

# ── vLLM 采集线程 ───────────────────────────────────────
def collect_vllm():
    while True:
        metrics = []  # 每台抓到的原始指标 (计数求和, kv 记下再平均)
        for name, base in VLLM_ENDPOINTS:
            try:
                body = http_get(base + "/metrics", timeout=12)
                if "vllm:num_requests_running" not in body:
                    STATE["vllm_err"][name] = f"{base} 响应不含 vLLM 指标"
                    continue
            except Exception as e:
                STATE["vllm_err"][name] = f"{base} {type(e).__name__}: {e}"
                continue
            try:
                prompt_tok = counter(body, "vllm:prompt_tokens_total")
                cached_tok = counter(body, "vllm:prompt_tokens_cached_total")
                metrics.append({
                    "waiting": gauge(body, "vllm:num_requests_waiting"),
                    "running": gauge(body, "vllm:num_requests_running"),
                    "preemption": gauge(body, "vllm:num_preemptions_total"),
                    "kv": gauge(body, "vllm:kv_cache_usage_perc"),
                    "prompt_tokens": prompt_tok,
                    "gen_tokens": counter(body, "vllm:generation_tokens_total"),
                    "cached_tokens": cached_tok,
                })
                STATE["vllm_last"][name] = datetime.now(CN_TZ).strftime("%H:%M:%S")
                STATE["vllm_err"].pop(name, None)
            except Exception as e:
                STATE["vllm_err"][name] = f"{type(e).__name__}: {e}"
        if metrics:
            try:
                # 合并: 计数类求和(池总量), kv 均值, hit_rate 用合并后的 cached/prompt 重算
                prompt_tok = sum(m["prompt_tokens"] for m in metrics)
                cached_tok = sum(m["cached_tokens"] for m in metrics)
                hit_rate = (cached_tok / prompt_tok) if prompt_tok > 0 else 0.0
                kv = sum(m["kv"] for m in metrics) / len(metrics)
                rec = {
                    "ts": time.time(),
                    "backend": "GLM",
                    "waiting": sum(m["waiting"] for m in metrics),
                    "running": sum(m["running"] for m in metrics),
                    "preemption": sum(m["preemption"] for m in metrics),
                    "gpu_cache_usage": kv,
                    "kv_cache_usage": kv,
                    "prompt_tokens": prompt_tok,
                    "gen_tokens": sum(m["gen_tokens"] for m in metrics),
                    "prefix_hit_rate": hit_rate,
                }
                with DB_LOCK:
                    DB.execute(
                        "INSERT INTO samples_vllm VALUES "
                        "(:ts,:backend,:waiting,:running,:preemption,:gpu_cache_usage,"
                        ":kv_cache_usage,:prompt_tokens,:gen_tokens,:prefix_hit_rate)",
                        rec)
                    DB.execute("DELETE FROM samples_vllm WHERE ts < ?", (time.time()-RETENTION_SEC,))
                    DB.commit()
            except Exception as e:
                STATE["vllm_err"]["GLM"] = f"{type(e).__name__}: {e}"
        # 动态采样间隔(前端可调)
        with INTERVAL_LOCK:
            sleep_s = VLLM_INTERVAL_CURRENT
        time.sleep(sleep_s)

# ── LiteLLM 采集线程 ────────────────────────────────────
def collect_litellm():
    last_alias_refresh = 0
    while True:
        # 周期刷新 token->人名 映射
        if time.time() - last_alias_refresh > KEYLIST_REFRESH:
            refresh_token_alias()
            last_alias_refresh = time.time()
        try:
            now = datetime.now(timezone.utc)
            start = (now - timedelta(minutes=LITELLM_WINDOW)).strftime("%Y-%m-%d %H:%M:%S")
            end   = now.strftime("%Y-%m-%d %H:%M:%S")
            page_size = 100
            params = urllib.parse.urlencode(
                {"page":1,"page_size":page_size,"start_date":start,"end_date":end})
            first = json.loads(http_get(
                f"{LITELLM_HOST}/spend/logs/v2?{params}", timeout=20, auth=LITELLM_KEY))
            total_pages = first.get("total_pages", 1)
            logs = list(first.get("data") or [])
            # 近 10 分钟通常不多, 拉全 (上限 5 页防失控)
            for p in range(2, min(total_pages, 5)+1):
                params = urllib.parse.urlencode(
                    {"page":p,"page_size":page_size,"start_date":start,"end_date":end})
                try:
                    d = json.loads(http_get(
                        f"{LITELLM_HOST}/spend/logs/v2?{params}", timeout=20, auth=LITELLM_KEY))
                    logs.extend(d.get("data") or [])
                except Exception:
                    break

            # 按 IP 聚合 (只统计 GLM 模型, 同时用 api_key 反查人名)
            by_ip = defaultdict(lambda: {"req":0,"sess":set(),"durs":[],"fail":0,"models":set(),"names":set()})
            skipped_non_glm = 0
            for lg in logs:
                model = lg.get("model") or "?"
                if not is_glm_model(model):
                    skipped_non_glm += 1
                    continue
                ip = lg.get("requester_ip_address") or "unknown"
                sid = lg.get("session_id") or ""
                dur = lg.get("request_duration_ms")
                st = lg.get("status") or ""
                tok = lg.get("api_key") or ""
                a = by_ip[ip]
                a["req"] += 1
                if sid: a["sess"].add(sid)
                if dur is not None: a["durs"].append(dur)
                if st != "success": a["fail"] += 1
                a["models"].add(model)
                nm = alias_of(tok)
                if nm: a["names"].add(nm)

            ts = time.time()
            with DB_LOCK:
                DB.execute("DELETE FROM samples_litellm WHERE ts = ?", (ts,))
                for ip, a in by_ip.items():
                    durs = a["durs"]
                    DB.execute(
                        "INSERT INTO samples_litellm VALUES (?,?,?,?,?,?,?,?,?)",
                        (ts, ip, a["req"], len(a["sess"]),
                         sum(durs)/len(durs) if durs else 0,
                         max(durs) if durs else 0,
                         a["fail"], ",".join(sorted(a["models"])),
                         ",".join(sorted(a["names"]))))
                DB.execute("DELETE FROM samples_litellm WHERE ts < ?", (time.time()-RETENTION_SEC,))
                DB.commit()
            STATE["litellm_last"] = datetime.now(CN_TZ).strftime("%H:%M:%S")
            STATE["litellm_err"] = ""
            STATE["litellm_glm_ips"] = len(by_ip)
            STATE["litellm_skipped"] = skipped_non_glm
        except Exception as e:
            STATE["litellm_err"] = f"{type(e).__name__}: {e}"
        # 清理在途记录 (TTL 自愈):
        #  - running 超 INFLIGHT_TTL(1860s=request_timeout+60) 未收到 finish -> 标 STALE,
        #    不再算正常 inflight, 但保留 INFLIGHT_GRACE 秒让人看到"疑似丢失的超大请求"
        #  - finished/failed/stale 超 INFLIGHT_GRACE(30s) -> 看够了, 删
        with INFLIGHT_LOCK:
            now_cl = time.time()
            expired = []
            for rid, v in INFLIGHT.items():
                if v["status"] == "running":
                    if now_cl - v["start_ts"] > INFLIGHT_TTL:
                        v["status"] = "stale"   # 先标记, 不立即删
                        v["end_ts"] = now_cl
                elif v.get("end_ts") and now_cl - v["end_ts"] > INFLIGHT_GRACE:
                    expired.append(rid)
            for rid in expired:
                INFLIGHT.pop(rid, None)
        time.sleep(LITELLM_INTERVAL)

# ── API 查询 ────────────────────────────────────────────
def _parse_range(r: str) -> int:
    """'15m'/'1h'/'6h'/'1d' 或纯秒数 -> 秒。默认 900(15min)。"""
    r = (r or "15m").strip().lower()
    mult = {"s":1, "m":60, "h":3600, "d":86400}
    if r and r[-1] in mult:
        try: return max(60, int(float(r[:-1])) * mult[r[-1]])
        except ValueError: pass
    try: return max(60, int(r))
    except ValueError: return 900

def api_queue(range_sec=900):
    """返回队列/KV-cache 时序(按 range 降采样到 <=MAX_CHART_POINTS 点) + latest 快照。
    gauge 类(waiting/running/kv/hit)按桶取均值; 无数据的桶补 None(图表断点)。"""
    now = time.time()
    since = now - range_sec
    with DB_LOCK:
        rows = DB.execute(
            "SELECT ts,backend,waiting,running,preemption,gpu_cache_usage,"
            "kv_cache_usage,prompt_tokens,gen_tokens,prefix_hit_rate "
            "FROM samples_vllm WHERE ts >= ? ORDER BY ts", (since,)).fetchall()
    backends = list(VLLM_BACKENDS)
    n_bucket = max(1, min(MAX_CHART_POINTS, int(range_sec // VLLM_INTERVAL) or 1))
    span = max(float(range_sec), 1.0)
    buckets = defaultdict(lambda: defaultdict(list))  # bucket_idx -> backend -> [row,...]
    for r in rows:
        bi = int((r[0] - since) / span * n_bucket)
        if bi >= n_bucket: bi = n_bucket - 1
        if bi < 0: continue
        buckets[bi][r[1]].append(r)
    fmt = "%H:%M:%S" if range_sec <= 1800 else ("%H:%M" if range_sec <= 6*3600 else "%m-%d %H:%M")
    labels = []
    series = {be: {"waiting": [], "running": [], "kv": [], "hit": []} for be in backends}
    for bi in range(n_bucket):
        t0 = since + (bi + 0.5) / n_bucket * span
        labels.append(datetime.fromtimestamp(t0, CN_TZ).strftime(fmt))
        for be in backends:
            rs = buckets.get(bi, {}).get(be, [])
            if rs:
                n = len(rs)
                series[be]["waiting"].append(round(sum(x[2] for x in rs)/n, 2))
                series[be]["running"].append(round(sum(x[3] for x in rs)/n, 2))
                series[be]["kv"].append(round(sum(x[6] for x in rs)/n*100, 1))
                series[be]["hit"].append(round(sum(x[9] for x in rs)/n*100, 1))
            else:
                for k in ("waiting", "running", "kv", "hit"):
                    series[be][k].append(None)
    # 前向填充: gauge 类指标(waiting/running/kv/hit)空桶沿用上一个已知值,
    # 避免采集漏点导致折线断开。开头仍无值的桶保持 None。
    for be in backends:
        last = {"waiting": None, "running": None, "kv": None, "hit": None}
        for bi in range(n_bucket):
            for k in ("waiting", "running", "kv", "hit"):
                v = series[be][k][bi]
                if v is None and last[k] is not None:
                    series[be][k][bi] = last[k]
                elif v is not None:
                    last[k] = v
    latest = {}
    for be in backends:
        be_rows = [r for r in rows if r[1] == be]
        if be_rows:
            r = be_rows[-1]
            latest[be] = {"waiting": r[2], "running": r[3], "preemption": r[4],
                          "kv": round(r[6]*100, 1), "prompt_tokens": r[7],
                          "gen_tokens": r[8], "prefix_hit_rate": round(r[9]*100, 1)}
    return {"labels": labels, "series": series, "latest": latest, "range_sec": range_sec}

def _fetch_litellm_glm_logs(range_sec):
    """从 LiteLLM /spend/logs/v2 拉取近 range_sec 秒的 GLM 请求日志(服务端按 model 过滤)。
    分页拉全, 上限 MAX_IPS_PAGES 页(2500条)。返回 (logs, truncated, total)。"""
    now = datetime.now(timezone.utc)
    start = (now - timedelta(seconds=range_sec)).strftime("%Y-%m-%d %H:%M:%S")
    end   = now.strftime("%Y-%m-%d %H:%M:%S")
    logs = []
    truncated = False
    total = 0
    try:
        params = urllib.parse.urlencode(
            {"page":1,"page_size":100,"start_date":start,"end_date":end,
             "model":GLM_MODEL_PARAM})
        first = json.loads(http_get(
            f"{LITELLM_HOST}/spend/logs/v2?{params}", timeout=20, auth=LITELLM_KEY))
        total = first.get("total", 0) or 0
        total_pages = first.get("total_pages", 1) or 1
        logs.extend(first.get("data") or [])
        max_pages = min(total_pages, MAX_IPS_PAGES)
        if total_pages > MAX_IPS_PAGES:
            truncated = True
        # 并发拉剩余分页(第 2~max_pages 页), 大范围(1天≈48页)从串行~4s 降到并发~1s
        rest_pages = list(range(2, max_pages + 1))
        if rest_pages:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            def _fetch_page(p):
                params = urllib.parse.urlencode(
                    {"page":p,"page_size":100,"start_date":start,"end_date":end,
                     "model":GLM_MODEL_PARAM})
                try:
                    return json.loads(http_get(
                        f"{LITELLM_HOST}/spend/logs/v2?{params}", timeout=20, auth=LITELLM_KEY))
                except Exception:
                    return {}
            with ThreadPoolExecutor(max_workers=min(10, len(rest_pages))) as ex:
                futs = {ex.submit(_fetch_page, p): p for p in rest_pages}
                page_data = {}
                for fut in as_completed(futs):
                    page_data[futs[fut]] = fut.result().get("data") or []
                # 按页号顺序拼回(保持时间序)
                for p in rest_pages:
                    logs.extend(page_data.get(p, []))
    except Exception:
        pass
    return logs, truncated, total

def _aggregate_by_ip(logs):
    """把 spend logs 列表按 IP 聚合成前端表格所需结构(复用采集线程的同款逻辑)。"""
    by_ip = defaultdict(lambda: {"req":0,"sess":set(),"durs":[],"fail":0,"models":set(),"names":set(),
                                 "first_start":None,"last_start":None})
    for lg in logs:
        model = lg.get("model") or "?"
        if not is_glm_model(model):
            continue
        ip = lg.get("requester_ip_address") or "unknown"
        sid = lg.get("session_id") or ""
        dur = lg.get("request_duration_ms")
        st = lg.get("status") or ""
        tok = lg.get("api_key") or ""
        st_iso = lg.get("startTime") or ""
        a = by_ip[ip]
        a["req"] += 1
        if sid: a["sess"].add(sid)
        if dur is not None: a["durs"].append(dur)
        if st != "success": a["fail"] += 1
        a["models"].add(model)
        nm = alias_of(tok)
        if nm: a["names"].add(nm)
        # 请求时间(ISO 字符串字典序即时间序): 记该 IP 最早/最晚请求开始时间
        if st_iso:
            if a["first_start"] is None or st_iso < a["first_start"]:
                a["first_start"] = st_iso
            if a["last_start"] is None or st_iso > a["last_start"]:
                a["last_start"] = st_iso
    ips = []
    for ip, a in by_ip.items():
        durs = a["durs"]
        ips.append({"ip":ip, "names":",".join(sorted(a["names"])) or "",
                    "requests":a["req"], "sessions":len(a["sess"]),
                    "avg_ms":round(sum(durs)/len(durs)) if durs else 0,
                    "max_ms":round(max(durs)) if durs else 0,
                    "fail":a["fail"], "models":",".join(sorted(a["models"])),
                    "first_start":_iso_to_cn(a["first_start"]),
                    "last_start":_iso_to_cn(a["last_start"])})
    ips.sort(key=lambda x: x["requests"], reverse=True)
    return ips

def _iso_to_cn(iso_str):
    """LiteLLM spend logs 的 startTime(ISO 8601 带 +00:00) -> 北京时间字符串。失败返回空。"""
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.astimezone(CN_TZ).strftime("%m-%d %H:%M:%S")
    except Exception:
        return ""

def _iso_to_epoch(iso_str):
    """LiteLLM ISO 8601 startTime -> epoch 秒(用于服务端按时间排序/过滤)。失败返回 0。"""
    if not iso_str:
        return 0.0
    try:
        return datetime.fromisoformat(iso_str.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0

def api_ips(range_sec=None):
    """各 IP 对话/请求聚合。
    range_sec=None -> 返回采集线程最新一次快照(近 LITELLM_WINDOW, 实时对比条用)。
    range_sec=数值 -> 临时从 LiteLLM spend logs 拉取该范围聚合(用户自选时间范围)。"""
    # 实时快照模式(无 range): 取 samples_litellm 最新一条, 用于 gap bar 等
    if range_sec is None:
        with DB_LOCK:
            r = DB.execute("SELECT MAX(ts) FROM samples_litellm").fetchone()
            if not r or r[0] is None:
                return {"ts":None, "window_min":LITELLM_WINDOW, "ips":[],
                        "range_sec":None, "truncated":False}
            max_ts = r[0]
            rows = DB.execute(
                "SELECT ip,requests,sessions,avg_ms,max_ms,fail,models,names "
                "FROM samples_litellm WHERE ts=? ORDER BY requests DESC", (max_ts,)).fetchall()
        ips = []
        for ip, req, sess, avg, mx, fail, models, names in rows:
            ips.append({"ip":ip, "names":names or "", "requests":req, "sessions":sess,
                        "avg_ms":round(avg), "max_ms":round(mx),
                        "fail":fail, "models":models})
        return {"ts":max_ts, "window_min":LITELLM_WINDOW,
                "ts_str":datetime.fromtimestamp(max_ts, CN_TZ).strftime("%H:%M:%S"),
                "ips":ips, "range_sec":None, "truncated":False,
                "summary":{"glm_ips":len(ips),
                           "total_req":sum(x["requests"] for x in ips),
                           "total_sessions":sum(x["sessions"] for x in ips)}}

    # 自选范围模式: 临时拉 LiteLLM spend logs 聚合
    logs, truncated, total = _fetch_litellm_glm_logs(range_sec)
    ips = _aggregate_by_ip(logs)
    now_ts = time.time()
    return {"ts":now_ts, "window_min":int(range_sec/60),
            "ts_str":datetime.now(CN_TZ).strftime("%H:%M:%S"),
            "ips":ips, "range_sec":range_sec, "truncated":truncated,
            "total_logs":total,
            "summary":{"glm_ips":len(ips),
                       "total_req":sum(x["requests"] for x in ips),
                       "total_sessions":sum(x["sessions"] for x in ips)}}


def _parse_detail(logs):
    """把 spend logs 列表解析成逐条明细 dict 列表(复用: api_requests + api_ip_detail)。
    每条含: names/ip/model/prompt_tokens/completion_tokens/cached_tokens/total_tokens/
    duration_ms/status/start/end/start_ts/request_id/hit_rate/kv_tokens。
    start_ts=startTime epoch(服务端排序用); hit_rate=逐条缓存命中率%(cached/prompt);
    kv_tokens=prompt_tokens-cached_tokens (未命中缓存的输入 token, 即真正占显存的 KV 近似值;
    cached 部分复用已有 KV block 不新增显存, 故这条请求的 KV 占用 ≈ kv_tokens)。"""
    glms = [lg for lg in logs if is_glm_model(lg.get("model") or "")]
    glms.sort(key=lambda x: x.get("startTime") or "", reverse=True)
    reqs = []
    for lg in glms:
        meta = lg.get("metadata") or {}
        usage = meta.get("usage_object") if isinstance(meta, dict) else None
        ptd = (usage.get("prompt_tokens_details") or {}) if usage else {}
        cached = ptd.get("cached_tokens") or 0
        dur = lg.get("request_duration_ms")
        tok = lg.get("api_key") or ""
        pt = lg.get("prompt_tokens") or 0
        reqs.append({
            "names": alias_of(tok),
            "ip": lg.get("requester_ip_address") or "unknown",
            "model": lg.get("model") or "?",
            "prompt_tokens": pt,
            "completion_tokens": lg.get("completion_tokens") or 0,
            "cached_tokens": cached,
            "total_tokens": lg.get("total_tokens") or 0,
            "duration_ms": round(dur) if dur is not None else 0,
            "status": lg.get("status") or "",
            "start": _iso_to_cn(lg.get("startTime") or ""),
            "end": _iso_to_cn(lg.get("endTime") or ""),
            "start_ts": _iso_to_epoch(lg.get("startTime") or ""),
            "request_id": lg.get("request_id") or "",
            "hit_rate": round(cached / pt * 100, 1) if pt > 0 else 0.0,
            "kv_tokens": max(0, pt - cached),   # 未命中缓存的输入 token = 真正占显存的 KV 近似
        })
    return reqs

# ── 明细缓存: 翻页/切人只过滤内存, 不重复拉 LiteLLM(大范围 1~4s) ──
_DETAIL_CACHE = {}        # range_sec -> (detail_list, fetch_ts, truncated, total)
_DETAIL_CACHE_TTL = 60    # 秒

def _get_detail_cached(range_sec):
    """取某范围的逐条明细(带 60s 内存缓存)。返回 (detail_list, truncated, total)。"""
    now = time.time()
    cached = _DETAIL_CACHE.get(range_sec)
    if cached and now - cached[1] < _DETAIL_CACHE_TTL:
        return cached[0], cached[2], cached[3]
    logs, truncated, total = _fetch_litellm_glm_logs(range_sec)
    detail = _parse_detail(logs)
    _DETAIL_CACHE[range_sec] = (detail, now, truncated, total)
    return detail, truncated, total

def api_requests(range_sec=None):
    """每条 GLM 请求的明细 (使用人 / IP / 输入输出 token / 缓存命中 / 耗时 / 状态)。
    range_sec=None -> 实时窗口(LITELLM_WINDOW 分钟, 与 /api/ips 快照一致);
    range_sec=数值 -> 临时拉 LiteLLM spend logs 该范围明细(走缓存)。
    spend logs 是请求结束后才落库, 故 "在跑" 用 "刚跑完" 近似。"""
    if range_sec is None:
        range_sec = LITELLM_WINDOW * 60
    reqs, truncated, total = _get_detail_cached(range_sec)
    return {"ts": time.time(),
            "ts_str": datetime.now(CN_TZ).strftime("%H:%M:%S"),
            "range_sec": range_sec, "window_min": int(range_sec / 60),
            "truncated": truncated, "total_logs": total,
            "requests": reqs, "count": len(reqs)}

def api_ip_detail(range_sec, ip, page=1, page_size=50):
    """某 IP 在指定范围的逐条请求明细(服务端分页)。
    复用 _get_detail_cached 的明细列表 -> 按 ip 过滤 -> 按 start_ts 倒序 -> 分页切片。
    附 vllm_hit: 各 backend 最近一次整体前缀缓存命中率%(作上下文, 非逐条)。"""
    detail, truncated, total = _get_detail_cached(range_sec)
    # 按 IP 过滤 + 收集该 IP 的所有人名(去重)
    filtered = [d for d in detail if d["ip"] == ip]
    names = sorted({d["names"] for d in filtered if d["names"]})
    filtered.sort(key=lambda x: x.get("start_ts") or 0, reverse=True)
    total_f = len(filtered)
    pages = max(1, (total_f + page_size - 1) // page_size)
    page = max(1, min(page, pages))
    slc = filtered[(page - 1) * page_size: page * page_size]
    # vLLM 整体命中率(最近采样, 按 backend)
    vllm_hit = {}
    try:
        with DB_LOCK:
            for be in VLLM_BACKENDS:
                r = DB.execute(
                    "SELECT prefix_hit_rate FROM samples_vllm WHERE backend=? "
                    "ORDER BY ts DESC LIMIT 1", (be,)).fetchone()
                if r and r[0] is not None:
                    vllm_hit[be] = round(r[0], 1)
    except Exception:
        pass
    return {"ip": ip, "names": ",".join(names),
            "page": page, "pages": pages, "total": total_f,
            "page_size": page_size, "range_sec": range_sec,
            "truncated": truncated, "vllm_hit": vllm_hit,
            "big_threshold": THRESHOLDS["big_context"],
            "requests": slc}


def set_vllm_interval(sec: int) -> dict:
    """前端实时修改 vLLM 采样间隔(秒)。限定 2~300 防失控。"""
    global VLLM_INTERVAL_CURRENT
    try:
        sec = int(sec)
    except Exception:
        return {"ok": False, "error": "间隔必须是整数"}
    if sec < 2 or sec > 300:
        return {"ok": False, "error": "间隔需在 2~300 秒之间"}
    with INTERVAL_LOCK:
        VLLM_INTERVAL_CURRENT = sec
    STATE["vllm_interval"] = sec
    return {"ok": True, "interval": sec}

# ── 实时在途请求 (LiteLLM pre-call 回调推送) ─────────────
def handle_inflight(data: dict) -> dict:
    """处理 LiteLLM 回调推送的 start/finish 事件。
    start: 请求到达, 存估算 token;
    finish: 请求结束(success/failure), 更新真实 token + 标记状态, 不立即删(走 grace)。"""
    global INFLIGHT_LAST_PUSH
    action = data.get("action")
    rid = data.get("request_id") or ""
    ts = data.get("ts") or time.time()
    if not rid:
        return {"ok": False, "error": "no request_id"}
    if action == "start":
        with INFLIGHT_LOCK:
            INFLIGHT[rid] = {
                "name": data.get("name") or "",
                "ip": data.get("ip") or "",
                "model": data.get("model") or "",
                "prompt_tokens": int(data.get("prompt_tokens_est") or 0),  # 初始用估算值
                "prompt_tokens_est": int(data.get("prompt_tokens_est") or 0),
                "prompt_tokens_actual": 0,
                "completion_tokens": 0,
                "status": "running",
                "start_ts": float(ts),
                "end_ts": None,
            }
        INFLIGHT_LAST_PUSH = time.time()
        # 脱敏配对日志: 上线后观察 START/FINISH 的 request_id 是否前后一致
        print(f"[inflight] START rid={rid} name={data.get('name') or ''} est={data.get('prompt_tokens_est') or 0}")
        return {"ok": True}
    if action == "finish":
        status = data.get("status") or "success"
        with INFLIGHT_LOCK:
            rec = INFLIGHT.get(rid)
            if rec:
                # ⑤ 有真实 token 就覆盖估算值
                actual = int(data.get("prompt_tokens_actual") or 0)
                if actual > 0:
                    rec["prompt_tokens"] = actual
                    rec["prompt_tokens_actual"] = actual
                rec["completion_tokens"] = int(data.get("completion_tokens") or 0)
                rec["status"] = "finished" if status == "success" else "failed"
                rec["end_ts"] = time.time()
                had_start = True
            else:
                # finish 找不到对应 start (start 丢了/重启): 仍记录一条 finished 供回看
                INFLIGHT[rid] = {
                    "name": "", "ip": "", "model": "",
                    "prompt_tokens": int(data.get("prompt_tokens_actual") or 0),
                    "prompt_tokens_est": 0,
                    "prompt_tokens_actual": int(data.get("prompt_tokens_actual") or 0),
                    "completion_tokens": int(data.get("completion_tokens") or 0),
                    "status": "finished" if status == "success" else "failed",
                    "start_ts": float(ts), "end_ts": time.time(),
                }
                had_start = False
        INFLIGHT_LAST_PUSH = time.time()
        print(f"[inflight] FINISH rid={rid} status={status} actual={data.get('prompt_tokens_actual') or 0} paired={had_start}")
        return {"ok": True}
    if action in ("end", "done"):
        # 旧版兜底: 直接删 (新版用 finish, 但兼容老回调)
        with INFLIGHT_LOCK:
            INFLIGHT.pop(rid, None)
        INFLIGHT_LAST_PUSH = time.time()
        return {"ok": True}
    return {"ok": False, "error": f"unknown action {action}"}

def api_inflight() -> dict:
    """返回当前在途请求列表 (谁正在跑 / 输入 token / IP / 状态)。
    running 优先(按 prompt_tokens 降序), finished/failed 在后(按 end_ts 降序)。"""
    now = time.time()
    with INFLIGHT_LOCK:
        items = []
        for rid, v in INFLIGHT.items():
            items.append({
                "name": v["name"],
                "ip": v["ip"],
                "model": v["model"],
                "prompt_tokens": v["prompt_tokens"],
                "prompt_tokens_est": v.get("prompt_tokens_est", 0),
                "prompt_tokens_actual": v.get("prompt_tokens_actual", 0),
                "completion_tokens": v.get("completion_tokens", 0),
                "status": v["status"],
                "start_ts": v["start_ts"],
                "end_ts": v.get("end_ts"),
                "elapsed": round(now - v["start_ts"]),
                "start_str": datetime.fromtimestamp(v["start_ts"], CN_TZ).strftime("%H:%M:%S"),
            })
    # running 优先; running 内按 prompt_tokens 降序; finished/failed 按 end_ts 降序; stale 最后
    items.sort(key=lambda x: (
        0 if x["status"] == "running" else (1 if x["status"] != "stale" else 2),
        -(x["prompt_tokens"] if x["status"] == "running" else (x["end_ts"] or 0))
    ))
    alive = (now - INFLIGHT_LAST_PUSH) < 600 if INFLIGHT_LAST_PUSH else False
    running = sum(1 for x in items if x["status"] == "running")
    big = sum(1 for x in items if x["status"] == "running" and x["prompt_tokens"] >= THRESHOLDS["big_context"])
    slow = sum(1 for x in items if x["status"] == "running" and x["elapsed"] >= THRESHOLDS["slow_sec"])
    return {"count": len(items), "running": running, "alive": alive, "big": big, "slow": slow,
            "big_threshold": THRESHOLDS["big_context"], "slow_threshold": THRESHOLDS["slow_sec"],
            "requests": items, "now": now}


# ── Web 服务 ────────────────────────────────────────────
PAGE = r"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>GLM 后端实时监控</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}
.bar{background:#1a2029;padding:14px 20px;border-bottom:1px solid #2a3340;display:flex;gap:24px;align-items:center;flex-wrap:wrap}
.bar h1{margin:0;font-size:18px;font-weight:600}
.pill{background:#2a3340;padding:6px 12px;border-radius:6px;font-size:13px}
.err{color:#ff6b6b}
.ok{color:#51cf66}
.wrap{max-width:1400px;margin:0 auto;padding:20px}
.card{background:#1a2029;border:1px solid #2a3340;border-radius:8px;padding:16px;margin-bottom:20px}
.card h2{margin:0 0 12px 0;font-size:15px;color:#8ab4f8}
.kpis{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:8px}
.kpi{background:#0f1419;border:1px solid #2a3340;border-radius:6px;padding:10px 16px;min-width:120px}
.kpi .lab{font-size:11px;color:#8a94a6;margin-bottom:4px}
.kpi .val{font-size:22px;font-weight:700}
.kpi .val.wait{color:#ffb84d} .kpi .val.run{color:#51cf66} .kpi .val.pre{color:#ff6b6b}
.kpi .val.kv{color:#74c0fc} .kpi .val.hit{color:#51cf66}
.kpi .src{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:9px;color:#5a6577;margin:1px 0 3px;word-break:break-all;line-height:1.2}
.chartbox{height:280px;position:relative}
.healthgrid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #2a3340}
th{color:#8a94a6;font-weight:600;font-size:12px}
tr:hover td{background:#222b36}
.many{color:#ff6b6b;font-weight:700}
.mid{color:#ffb84d}
.foot{color:#5a6478;font-size:12px;text-align:center;padding:16px}
.ctrl{display:flex;gap:10px;align-items:center;margin-left:auto}
.ctrl label{font-size:12px;color:#8a94a6}
.ctrl select{background:#0f1419;color:#e6e6e6;border:1px solid #2a3340;border-radius:4px;padding:4px 8px;font-size:13px;cursor:pointer}
.ctrl select:hover{border-color:#4a5568}
</style></head><body>
<div class="bar">
  <h1>GLM 后端实时监控</h1>
  <span class="pill" id="status">…</span>
  <span class="pill">LiteLLM 窗口 5min / 采样 15s</span>
  <div class="ctrl">
    <label>采样间隔
      <select id="sel-interval">
        <option value="5" selected>5s</option>
        <option value="10">10s</option>
        <option value="30">30s</option>
        <option value="60">1min</option>
      </select>
    </label>
    <label>图表范围
      <select id="sel-range">
        <option value="15m" selected>15分钟</option>
        <option value="1h">1小时</option>
        <option value="6h">6小时</option>
        <option value="1d">1天</option>
        <option value="2d">2天</option>
        <option value="3d">3天</option>
        <option value="7d">7天</option>
      </select>
    </label>
  </div>
</div>
<div class="wrap">

  <div class="card" id="inflightCard">
    <h2 style="display:flex;align-items:center;flex-wrap:wrap">🔴 实时在途请求 — 谁正在跑 / 输入 token 大小
      <span id="ifCount" style="margin-left:10px;font-size:13px;font-weight:normal;color:#8a94a6">在途 0 个</span>
      <span id="ifBig" style="display:none;margin-left:8px;font-size:12px;color:#ff6b6b">⚠ 超大 <b id="ifBigN">0</b> 个</span>
      <span id="ifSlow" style="display:none;margin-left:8px;font-size:12px;color:#ff6b6b">⚠ 超时 <b id="ifSlowN">0</b> 个</span>
      <span id="ifDead" style="display:none;margin-left:8px;font-size:12px;color:#ffb84d">⚠ 未收到 LiteLLM 在途推送 — 回调未部署或不可达，见页面底部说明</span>
      <span style="margin-left:auto;font-size:12px;font-weight:normal;color:#8a94a6;white-space:nowrap">超大上下文阈值 <b id="ifBigTh" style="color:#ff6b6b">20万</b> · 超时阈值 <b id="ifSlowTh" style="color:#ff6b6b">120s</b></span>
    </h2>
    <div style="margin-bottom:8px;color:#8a94a6;font-size:12px">
      请求<b>到达 LiteLLM 即显示</b>（不用等跑完）· 输入 token 为到达时估算值（标「估」），结束后显示真实值（标「实」）· finished 行灰显保留 30s 供回看
    </div>
    <table id="inflightTable">
      <thead><tr><th>使用人</th><th>模型</th><th>输入 token</th><th>输出 token</th><th>状态</th><th>已耗时</th><th>开始于</th></tr></thead>
      <tbody><tr><td colspan="7" style="color:#5a6478;text-align:center;padding:20px">等待 LiteLLM 回调推送…</td></tr></tbody>
    </table>
    <div style="margin-top:10px;display:flex;gap:12px;align-items:center;flex-wrap:wrap">
      <label style="font-size:13px;color:#8a94a6">每页
        <select id="ifPs" style="background:#0f1419;color:#e6e6e6;border:1px solid #2a3340;border-radius:4px;padding:2px 6px">
          <option>10</option><option selected>20</option><option>50</option>
        </select> 条
      </label>
      <span style="font-size:13px;color:#8a94a6">共 <span id="ifTotal">0</span> 条</span>
      <div style="margin-left:auto;display:flex;gap:6px;align-items:center">
        <button id="ifPrev" style="background:#2a3340;color:#e6e6e6;border:none;border-radius:4px;padding:4px 12px;cursor:pointer">上一页</button>
        <span id="ifPageInfo" style="font-size:13px;color:#8a94a6;min-width:70px;text-align:center">1 / 1</span>
        <button id="ifNext" style="background:#2a3340;color:#e6e6e6;border:none;border-radius:4px;padding:4px 12px;cursor:pointer">下一页</button>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>排队中的请求（还没轮到 GPU 处理；大于 0 说明 GPU 忙不过来，新请求要等）</h2>
    <div class="kpis" id="kpis"></div>
    <div class="chartbox"><canvas id="chartWait"></canvas></div>
  </div>

  <div class="card">
    <h2>GPU 正在同时处理的请求数（请求 ≠ 对话：一个对话可能同时发出多个请求）</h2>
    <div class="chartbox"><canvas id="chartRun"></canvas></div>
  </div>

  <div class="card">
    <h2>后端健康 — 显存 KV cache 占用率 (左轴%) + 前缀缓存命中率 (右轴%) + 累计吞吐</h2>
    <div class="kpis" id="healthKpis"></div>
    <div class="chartbox"><canvas id="chartKv"></canvas></div>
    <div style="margin-top:8px;color:#8a94a6;font-size:12px">
      <span style="color:#74c0fc">■ KV cache 占用率</span> = 已用显存 KV block / 总量, 接近 100% 时 vLLM 会排队+抢占请求 (慢的根因之一)<br>
      <span style="color:#51cf66">■ 前缀缓存命中率</span> = 命中缓存的 prompt token / 总 prompt token, 越高越省算力
    </div>
  </div>

  <div class="card">
    <h2>各 IP 对话/请求聚合 (近 <span id="win">10</span> 分钟, 仅 GLM-5.2-Int8, LiteLLM)
      <span style="margin-left:14px;font-size:13px;font-weight:normal;color:#8a94a6">日志范围
        <select id="ips-range" style="background:#1a2029;color:#e6e6e6;border:1px solid #2a3340;border-radius:4px;padding:2px 6px">
          <option value="" selected>实时(5min快照)</option>
          <option value="15m">15分钟</option>
          <option value="1h">1小时</option>
          <option value="6h">6小时</option>
          <option value="1d">1天</option>
        </select>
      </span>
      <span id="ips-trunc" style="display:none;margin-left:8px;color:#ffb84d;font-size:12px">⚠ 该范围超过2500条上限, 仅聚合最近2500条</span>
    </h2>
    <div style="margin-bottom:10px;color:#8a94a6;font-size:12px">
      概念区分: <b>对话数</b> = 该 IP 开了几个 Claude Code 窗口 ·
      <b>请求数</b> = 发出的 API 调用条数（一个任务会发出多条）·
      上面图的"处理中" = 某一刻 GPU 同时在算的请求数，和对话数没有固定换算关系
    </div>
    <div id="gm-gap" style="margin-bottom:10px;padding:8px 12px;border-radius:6px;background:#1a2029;border:1px solid #2a3340;font-size:12px;color:#8a94a6;display:none">
      <b>实时对比：</b>vLLM 当前 排队 <span id="gm-gap-w" style="color:#ffb84d">0</span> / 处理中 <span id="gm-gap-r" style="color:#51cf66">0</span>，
      本表（已完成）覆盖 <span id="gm-gap-done" style="color:#8ab4f8">0</span> 条请求
      <span id="gm-gap-warn" style="display:none;margin-left:8px;color:#ff6b6b">⚠ 有 <b id="gm-gap-stuck">0</b> 个请求正在排队/处理中尚未完成，不计入下表（卡住时看不到是谁，只能看到数量）</span>
    </div>
    <div style="margin-bottom:10px;display:flex;gap:12px;align-items:center;flex-wrap:wrap">
      <label style="font-size:13px;color:#8a94a6">每页
        <select id="pageSize" style="background:#0f1419;color:#e6e6e6;border:1px solid #2a3340;border-radius:4px;padding:2px 6px">
          <option>10</option><option selected>20</option><option>50</option><option>100</option>
        </select> 条
      </label>
      <span style="font-size:13px;color:#8a94a6">共 <span id="ipTotal">0</span> 条</span>
      <div style="margin-left:auto;display:flex;gap:6px;align-items:center">
        <button id="prevPage" style="background:#2a3340;color:#e6e6e6;border:none;border-radius:4px;padding:4px 12px;cursor:pointer">上一页</button>
        <span id="pageInfo" style="font-size:13px;color:#8a94a6;min-width:70px;text-align:center">1 / 1</span>
        <button id="nextPage" style="background:#2a3340;color:#e6e6e6;border:none;border-radius:4px;padding:4px 12px;cursor:pointer">下一页</button>
      </div>
    </div>
    <table id="ipTable">
      <thead><tr><th>使用人</th><th>客户端 IP</th><th>请求数 (API 调用条数)</th><th>对话数 (session)</th><th>平均耗时</th><th>最大耗时</th><th>失败</th><th>首次请求时间</th><th>末次请求时间</th><th>模型</th></tr></thead>
      <tbody></tbody>
    </table>
    <div style="margin-top:10px;color:#8a94a6;font-size:13px">更新于: <span id="llTs">—</span> · GLM 调用 IP <span id="ipCount">0</span> 个 · 窗口内 GLM 请求 <span id="totalReq">0</span> 条 / 对话 <span id="totalSess">0</span> 个</div>
  </div>

  <div class="card">
    <h2>每条请求明细 — 谁在跑 / 输入输出上下文 (近 <span id="reqWin">5</span> 分钟, 仅 GLM-5.2-Int8)
      <span style="margin-left:14px;font-size:13px;font-weight:normal;color:#8a94a6">日志范围
        <select id="req-range" style="background:#1a2029;color:#e6e6e6;border:1px solid #2a3340;border-radius:4px;padding:2px 6px">
          <option value="" selected>实时(5min快照)</option>
          <option value="15m">15分钟</option>
          <option value="1h">1小时</option>
          <option value="6h">6小时</option>
          <option value="1d">1天</option>
        </select>
      </span>
      <span id="req-trunc" style="display:none;margin-left:8px;color:#ffb84d;font-size:12px">⚠ 超过2500条上限, 仅显示最近2500条</span>
    </h2>
    <div style="margin-bottom:10px;color:#8a94a6;font-size:12px">
      <b>输入tokens</b> = 该请求的 prompt 上下文大小 · <b>缓存命中</b> = 其中命中前缀缓存的 token · <b>输出tokens</b> = 生成内容
      · 日志在请求<b>结束后</b>才落库, 故此处是"刚跑完"的请求(正在排队/处理中的看不到人, 只能看上面的数量)
    </div>
    <div style="margin-bottom:10px;display:flex;gap:12px;align-items:center;flex-wrap:wrap">
      <label style="font-size:13px;color:#8a94a6">每页
        <select id="reqPageSize" style="background:#0f1419;color:#e6e6e6;border:1px solid #2a3340;border-radius:4px;padding:2px 6px">
          <option>20</option><option selected>50</option><option>100</option><option>200</option>
        </select> 条
      </label>
      <span style="font-size:13px;color:#8a94a6">共 <span id="reqTotal">0</span> 条</span>
      <label style="font-size:13px;color:#8a94a6;margin-left:12px">按人筛选
        <input id="reqFilterName" placeholder="人名/IP" style="background:#0f1419;color:#e6e6e6;border:1px solid #2a3340;border-radius:4px;padding:3px 8px;font-size:13px;width:120px">
      </label>
      <div style="margin-left:auto;display:flex;gap:6px;align-items:center">
        <button id="reqPrevPage" style="background:#2a3340;color:#e6e6e6;border:none;border-radius:4px;padding:4px 12px;cursor:pointer">上一页</button>
        <span id="reqPageInfo" style="font-size:13px;color:#8a94a6;min-width:70px;text-align:center">1 / 1</span>
        <button id="reqNextPage" style="background:#2a3340;color:#e6e6e6;border:none;border-radius:4px;padding:4px 12px;cursor:pointer">下一页</button>
      </div>
    </div>
    <table id="reqTable">
      <thead><tr><th>使用人</th><th>客户端 IP</th><th>输入 tokens</th><th>缓存命中</th><th>输出 tokens</th><th>合计</th><th>耗时</th><th>状态</th><th>开始时间</th><th>模型</th></tr></thead>
      <tbody></tbody>
    </table>
    <div style="margin-top:10px;color:#8a94a6;font-size:13px">更新于: <span id="reqTs">—</span> · 明细 <span id="reqCount">0</span> 条</div>
  </div>

</div>
<div class="foot">数据源: vLLM 128/129 /metrics + LiteLLM /spend/logs/v2 + LiteLLM pre-call 回调 (在途) · 在途卡片需部署 custom_callbacks/inflight_logger.py</div>

<script>
let cw, cr, ck;
function mk(ctx){
  return new Chart(ctx, {type:'line', data:{labels:[],datasets:[]},
    options:{animation:false,responsive:true,maintainAspectRatio:false,
      interaction:{intersect:false,mode:'index'},
      scales:{x:{ticks:{maxTicksLimit:10,color:'#5a6478'},grid:{color:'#222b36'}},
              y:{beginAtZero:true,ticks:{color:'#5a6478'},grid:{color:'#222b36'}}},
      plugins:{legend:{labels:{color:'#e6e6e6',font:{size:12}}}}}});
}
function init(){
  if(typeof Chart==='undefined'){document.getElementById('status').innerHTML='<span class=err>Chart.js CDN 加载失败 (离线), 仅显示表格</span>';}
  else{
    cw=mk(document.getElementById('chartWait').getContext('2d'));
    cr=mk(document.getElementById('chartRun').getContext('2d'));
    // KV cache 图: 双 Y 轴 (左 KV%, 右 命中率%)
    ck=new Chart(document.getElementById('chartKv').getContext('2d'),{type:'line',data:{labels:[],datasets:[]},
      options:{animation:false,responsive:true,maintainAspectRatio:false,
        interaction:{intersect:false,mode:'index'},
        scales:{x:{ticks:{maxTicksLimit:10,color:'#5a6478'},grid:{color:'#222b36'}},
          y:{beginAtZero:true,max:100,ticks:{color:'#74c0fc',callback:v=>v+'%'},grid:{color:'#222b36'},position:'left',title:{display:true,text:'KV cache 占用 %',color:'#74c0fc'}},
          y1:{beginAtZero:true,max:100,ticks:{color:'#51cf66',callback:v=>v+'%'},grid:{drawOnChartArea:false},position:'right',title:{display:true,text:'缓存命中率 %',color:'#51cf66'}}},
        plugins:{legend:{labels:{color:'#e6e6e6',font:{size:12}}}}}});
  }
}
function ds(label,color,data){const pt=data.length<=120?4:0;return{label,data,borderColor:color,backgroundColor:color+'33',borderWidth:2,pointRadius:pt,pointHoverRadius:6,pointBackgroundColor:color,pointBorderColor:'#fff',pointBorderWidth:1.5,tension:0.3,fill:true,spanGaps:true};}
function dsY1(label,color,data){const pt=data.length<=120?4:0;return{label,data,borderColor:color,backgroundColor:'transparent',borderWidth:2,pointRadius:pt,pointHoverRadius:6,pointBackgroundColor:color,pointBorderColor:'#fff',pointBorderWidth:1.5,tension:0.3,fill:false,yAxisID:'y1',spanGaps:true};}
function fmtTok(n){n=n||0; if(n>=1e8)return (n/1e8).toFixed(2)+'亿'; if(n>=1e4)return (n/1e4).toFixed(1)+'万'; return n;}
async function loadQueue(){
  try{
    const range=document.getElementById('sel-range').value;
    const d=await (await fetch('/api/queue?range='+encodeURIComponent(range))).json();
    const live=d.range_sec<=1800;  // 15分钟内显示"实时"字样
    document.getElementById('status').innerHTML=
      `<span class=ok>● 采集运行中</span> · ${Object.entries(d.latest).map(([be,x])=>`${be}: 排队${Math.round(x.waiting)} / 处理中${Math.round(x.running)}`).join(' · ')}${live?' · 实时':' · 趋势'}`;
    if(!cw) return;
    cw.data.labels=d.labels; cr.data.labels=d.labels; ck.data.labels=d.labels;
    cw.data.datasets=[]; cr.data.datasets=[]; ck.data.datasets=[];
    // 128/129 已合并为单一 GLM 池, 只用一套配色
    const BCOLORS={'GLM':{w:'#ffb84d',r:'#f59e0b',kv:'#f59e0b',hit:'#fbbf24'}};
    function bcol(be,key){const c=BCOLORS[be];return c?c[key]:'#94a3b8';}
    for(const be in d.series){
      cw.data.datasets.push(ds(`${be} 排队`,bcol(be,'w'),d.series[be].waiting));
      cr.data.datasets.push(ds(`${be} 处理中`,bcol(be,'r'),d.series[be].running));
      ck.data.datasets.push(ds(`${be} KV cache %`,bcol(be,'kv'),d.series[be].kv));
      ck.data.datasets.push(dsY1(`${be} 缓存命中 %`,bcol(be,'hit'),d.series[be].hit));
    }
    cw.update('none'); cr.update('none'); ck.update('none');
    // 队列 KPI
    let html='';
    for(const be in d.latest){const x=d.latest[be];
      html+=`<div class=kpi><div class=lab>${be} 排队中</div><div class=src>vllm:num_requests_waiting</div><div class="val wait">${Math.round(x.waiting)}</div></div>`;
      html+=`<div class=kpi><div class=lab>${be} 处理中</div><div class=src>vllm:num_requests_running</div><div class="val run">${Math.round(x.running)}</div></div>`;
      html+=`<div class=kpi><div class=lab>${be} 累计抢占</div><div class=src>vllm:num_preemptions_total</div><div class="val pre">${Math.round(x.preemption||0)}</div></div>`;
    }
    document.getElementById('kpis').innerHTML=html;
    // 健康 KPI
    let hh='';
    for(const be in d.latest){const x=d.latest[be];
      hh+=`<div class=kpi><div class=lab>${be} KV cache</div><div class=src>vllm:kv_cache_usage_perc</div><div class="val kv">${(x.kv||0).toFixed(1)}%</div></div>`;
      hh+=`<div class=kpi><div class=lab>${be} 缓存命中</div><div class=src>cached_total ÷ prompt_tokens_total</div><div class="val hit">${(x.prefix_hit_rate||0).toFixed(1)}%</div></div>`;
      hh+=`<div class=kpi><div class=lab>${be} 累计prompt</div><div class=src>vllm:prompt_tokens_total</div><div class="val" style="font-size:16px;color:#e6e6e6">${fmtTok(x.prompt_tokens)}</div></div>`;
      hh+=`<div class=kpi><div class=lab>${be} 累计生成</div><div class=src>vllm:generation_tokens_total</div><div class="val" style="font-size:16px;color:#e6e6e6">${fmtTok(x.gen_tokens)}</div></div>`;
    }
    document.getElementById('healthKpis').innerHTML=hh;
    // 存最新 vLLM 状态供 IP 表对比条使用
    LAST_VLLM=d.latest||{};
    updateGapBar();
  }catch(e){document.getElementById('status').innerHTML='<span class=err>queue err '+e+'</span>';}
}
function cls(n){return n>=3?'many':n>=2?'mid':'';}
// ── 实时对比条: vLLM 排队/处理中 vs LiteLLM 已完成 ──
let LAST_VLLM={}, LAST_DONE=0;
function updateGapBar(){
  const box=document.getElementById('gm-gap');
  if(!box) return;
  // 合计各后端的排队+处理中
  let w=0,r=0;
  for(const be in LAST_VLLM){const x=LAST_VLLM[be];w+=(x.waiting||0);r+=(x.running||0);}
  const stuck=w+r;
  document.getElementById('gm-gap-w').textContent=Math.round(w);
  document.getElementById('gm-gap-r').textContent=Math.round(r);
  document.getElementById('gm-gap-done').textContent=LAST_DONE;
  const warn=document.getElementById('gm-gap-warn');
  if(stuck>0){
    box.style.display='block';
    warn.style.display='inline';
    document.getElementById('gm-gap-stuck').textContent=Math.round(stuck);
  }else{
    // 无排队/处理中时也显示对比(信息), 但不告警
    box.style.display='block';
    warn.style.display='none';
  }
}
// ── IP 表分页 ──
let IP_DATA=[], IP_PAGE=1, IP_PAGESIZE=20;
function renderIps(){
  const total=IP_DATA.length;
  const pages=Math.max(1,Math.ceil(total/IP_PAGESIZE));
  if(IP_PAGE>pages) IP_PAGE=pages;
  if(IP_PAGE<1) IP_PAGE=1;
  const start=(IP_PAGE-1)*IP_PAGESIZE;
  const slice=IP_DATA.slice(start,start+IP_PAGESIZE);
  const tb=document.querySelector('#ipTable tbody'); tb.innerHTML='';
  for(const r of slice){
    const tr=document.createElement('tr');
    const names=r.names||'';
    const namesHtml=names?`<span style="color:#8ab4f8">${names}</span>`:'<span style="color:#5a6478">—</span>';
    tr.innerHTML=`<td>${namesHtml}</td><td>${r.ip}</td><td>${r.requests}</td>
      <td class="${cls(r.sessions)}">${r.sessions}</td>
      <td>${r.avg_ms? (r.avg_ms/1000).toFixed(1)+'s':'-'}</td>
      <td>${r.max_ms? (r.max_ms/1000).toFixed(1)+'s':'-'}</td>
      <td>${r.fail?`<span style="color:#ff6b6b">${r.fail}</span>`:'-'}</td>
      <td style="color:#8a94a6;font-size:12px;white-space:nowrap">${r.first_start||'<span style="color:#5a6478">—</span>'}</td>
      <td style="color:#8a94a6;font-size:12px;white-space:nowrap">${r.last_start||'<span style="color:#5a6478">—</span>'}</td>
      <td style="color:#8a94a6;font-size:12px">${r.models}</td>`;
    tb.appendChild(tr);
  }
  document.getElementById('ipTotal').textContent=total;
  document.getElementById('pageInfo').textContent=`${IP_PAGE} / ${pages}`;
}
async function loadIps(){
  const r=document.getElementById('ips-range').value;
  const url=r?('/api/ips?range='+encodeURIComponent(r)):'/api/ips';
  if(r){const tb=document.querySelector('#ipTable tbody'); if(tb) tb.innerHTML='<tr><td colspan="10" style="color:#8a94a6">加载中（正在从 LiteLLM 拉取 '+r+' 日志…）</td></tr>';}
  try{
    const d=await (await fetch(url)).json();
    document.getElementById('win').textContent=d.window_min;
    document.getElementById('llTs').textContent=d.ts_str||'—';
    document.getElementById('ipCount').textContent=d.ips.length;
    const s=d.summary||{};
    document.getElementById('totalReq').textContent=s.total_req||0;
    document.getElementById('totalSess').textContent=s.total_sessions||0;
    LAST_DONE=s.total_req||0;
    IP_DATA=d.ips;
    renderIps();
    document.getElementById('ips-trunc').style.display=d.truncated?'inline':'none';
    // gap bar 仅在实时快照模式有意义; 自选范围的已完成总数与实时排队数不可比, 隐藏
    const ipsR=document.getElementById('ips-range').value;
    document.getElementById('gm-gap').style.display = ipsR ? 'none' : 'block';
    if(!ipsR) updateGapBar();
  }catch(e){document.getElementById('llTs').textContent='err '+e;}
}
// ── 实时在途请求 (LiteLLM 回调推送) ──
function ifTok(n){n=n||0; if(n>=1e8)return (n/1e8).toFixed(2)+'亿'; if(n>=1e4)return (n/1e4).toFixed(1)+'万'; return n;}
let IF_DATA=[], IF_PAGE=1, IF_PS=20, IF_META={};
// 输入 token 单元格: running/stale 显示估, finished 显示实 + 与估的差值
function ifInTokHtml(r,d){
  const isRun=r.status==='running', isStale=r.status==='stale';
  const isBig=r.prompt_tokens>=(d.big_threshold||200000);
  let tok, lab, diff='';
  if(isRun||isStale){
    tok=r.prompt_tokens; lab='估';
  }else{
    const est=r.prompt_tokens_est||0, act=r.prompt_tokens_actual||0;
    tok=act||r.prompt_tokens; lab='实';
    if(act>0 && est>0 && act!==est){
      const delta=act-est;
      const sign=delta>0?'+':'−';
      diff=`<span style="font-size:11px;color:#8a94a6"> (估${ifTok(est)} ${sign}${ifTok(Math.abs(delta))})</span>`;
    }
  }
  return isBig
    ?`<span style="color:#ff6b6b;font-weight:700">${ifTok(tok)} ${lab} ⚠超大</span>${diff}`
    :`<span style="color:#ffb84d">${ifTok(tok)} ${lab}</span>${diff}`;
}
function renderInflight(){
  const total=IF_DATA.length, pages=Math.max(1,Math.ceil(total/IF_PS));
  if(IF_PAGE>pages) IF_PAGE=pages;
  if(IF_PAGE<1) IF_PAGE=1;
  const slice=IF_DATA.slice((IF_PAGE-1)*IF_PS,IF_PAGE*IF_PS);
  const tb=document.querySelector('#inflightTable tbody'); tb.innerHTML='';
  const d=IF_META||{};
  if(!slice.length){
    tb.innerHTML='<tr><td colspan="7" style="color:#51cf66;text-align:center;padding:14px">当前无在途请求 — 没人正在跑</td></tr>';
  }else{
    for(const r of slice){
      const tr=document.createElement('tr');
      const names=r.name||'';
      const namesHtml=names?`<span style="color:#8ab4f8;font-weight:600">${names}</span>`:'<span style="color:#5a6478">—</span>';
      const isRun=r.status==='running';
      const isFin=!isRun;
      const tokHtml=ifInTokHtml(r,d);
      const outTok=r.completion_tokens||0;
      const outHtml=outTok?`<span style="color:#74c0fc">${ifTok(outTok)}</span>`:'<span style="color:#5a6478">—</span>';
      const stHtml = r.status==='running'
        ?'<span style="color:#51cf66">● 跑</span>'
        : r.status==='failed'
          ?'<span style="color:#ff6b6b">✗ 败</span>'
          : r.status==='stale'
            ?'<span style="color:#ffa94d">⚠ 僵</span>'
            :'<span style="color:#5a6478">✓ 完</span>';
      const el=r.elapsed;
      const elHtml=el>=(d.slow_threshold||120)?`<span style="color:#ff6b6b">${el}s ⚠超</span>`:`<span>${el}s</span>`;
      const rowStyle=isFin?'style="opacity:0.5"':'';
      tr.innerHTML=`<td ${rowStyle}>${namesHtml}</td>
        <td ${rowStyle} style="color:#8a94a6;font-size:12px">${r.model||'-'}</td>
        <td ${rowStyle}>${tokHtml}</td><td ${rowStyle}>${outHtml}</td>
        <td ${rowStyle}>${stHtml}</td><td ${rowStyle}>${elHtml}</td>
        <td ${rowStyle} style="color:#8a94a6;font-size:12px">${r.start_str}</td>`;
      tb.appendChild(tr);
    }
  }
  document.getElementById('ifTotal').textContent=total;
  document.getElementById('ifPageInfo').textContent=`${IF_PAGE} / ${pages}`;
}
async function loadInflight(){
  try{
    const d=await (await fetch('/api/inflight')).json();
    document.getElementById('ifCount').textContent='在途 '+(d.running||0)+' 跑 / '+(d.count||0)+' 总';
    document.getElementById('ifDead').style.display=d.alive?'none':'inline';
    const big=document.getElementById('ifBig');
    if(d.big>0){big.style.display='inline'; document.getElementById('ifBigN').textContent=d.big;}
    else{big.style.display='none';}
    const slowEl=document.getElementById('ifSlow');
    if(d.slow>0){slowEl.style.display='inline'; document.getElementById('ifSlowN').textContent=d.slow;}
    else{slowEl.style.display='none';}
    document.getElementById('ifBigTh').textContent=ifTok(d.big_threshold||200000);
    document.getElementById('ifSlowTh').textContent=(d.slow_threshold||120)+'s';
    IF_META=d; IF_DATA=d.requests||[]; renderInflight();
  }catch(e){}
}
init(); loadQueue(); loadIps(); loadInflight();
setInterval(loadInflight,5000);
// 在途请求分页
document.getElementById('ifPs').addEventListener('change',e=>{IF_PS=parseInt(e.target.value);IF_PAGE=1;renderInflight();});
document.getElementById('ifPrev').addEventListener('click',()=>{IF_PAGE--;renderInflight();});
document.getElementById('ifNext').addEventListener('click',()=>{IF_PAGE++;renderInflight();});
// 刷新频率: 15分钟范围按采样间隔刷新; 大范围(1h+)降低到 30s 减少开销
let queueTimer=null, ipsTimer=null;
function scheduleQueue(){
  if(queueTimer) clearInterval(queueTimer);
  const range=document.getElementById('sel-range').value;
  // 小范围实时刷, 大范围(趋势)30s刷一次足够
  const ms = (range==='15m'||range==='1h') ? Math.max(3000, CUR_INTERVAL*1000) : 30000;
  queueTimer=setInterval(loadQueue, ms);
}
let CUR_INTERVAL=5;  // 当前采样间隔(秒), 与后端同步
scheduleQueue();
function scheduleIps(){
  if(ipsTimer) clearInterval(ipsTimer);
  const r=document.getElementById('ips-range').value;
  // 实时快照 15s 刷; 自选大范围(临时拉 LiteLLM 多页)降低到 60s 减开销
  const ms = (!r) ? 15000 : 60000;
  ipsTimer=setInterval(loadIps, ms);
}
scheduleIps();

// ── 每条请求明细表 ──
let REQ_DATA=[], REQ_PAGE=1, REQ_PAGESIZE=50;
function fmtTok2(n){n=n||0; if(n>=1e8)return (n/1e8).toFixed(2)+'亿'; if(n>=1e4)return (n/1e4).toFixed(1)+'万'; return n;}
function renderReqs(){
  // 按人/IP 筛选
  const f=(document.getElementById('reqFilterName').value||'').trim().toLowerCase();
  let data=REQ_DATA;
  if(f){
    data=data.filter(r=>((r.names||'')+' '+(r.ip||'')).toLowerCase().includes(f));
  }
  const total=data.length;
  const pages=Math.max(1,Math.ceil(total/REQ_PAGESIZE));
  if(REQ_PAGE>pages) REQ_PAGE=pages;
  if(REQ_PAGE<1) REQ_PAGE=1;
  const start=(REQ_PAGE-1)*REQ_PAGESIZE;
  const slice=data.slice(start,start+REQ_PAGESIZE);
  const tb=document.querySelector('#reqTable tbody'); tb.innerHTML='';
  for(const r of slice){
    const tr=document.createElement('tr');
    const namesHtml=r.names?`<span style="color:#8ab4f8">${r.names}</span>`:'<span style="color:#5a6478">—</span>';
    const stHtml = r.status && r.status!=='success'
      ? `<span style="color:#ff6b6b">${r.status}</span>`
      : (r.status==='success' ? `<span style="color:#51cf66">${r.status}</span>` : '<span style="color:#5a6478">—</span>');
    const cacheHit = r.prompt_tokens>0 ? Math.round(r.cached_tokens/r.prompt_tokens*100) : 0;
    const cacheTxt = r.cached_tokens>0
      ? `${fmtTok2(r.cached_tokens)} <span style="color:#51cf66;font-size:11px">(${cacheHit}%)</span>`
      : '<span style="color:#5a6478">—</span>';
    tr.innerHTML=`<td>${namesHtml}</td><td>${r.ip}</td>
      <td style="color:#ffb84d">${fmtTok2(r.prompt_tokens)}</td>
      <td>${cacheTxt}</td>
      <td style="color:#74c0fc">${fmtTok2(r.completion_tokens)}</td>
      <td style="color:#8a94a6">${fmtTok2(r.total_tokens)}</td>
      <td>${r.duration_ms? (r.duration_ms/1000).toFixed(1)+'s':'-'}</td>
      <td>${stHtml}</td>
      <td style="color:#8a94a6;font-size:12px;white-space:nowrap">${r.start||'<span style="color:#5a6478">—</span>'}</td>
      <td style="color:#8a94a6;font-size:12px">${r.model}</td>`;
    tb.appendChild(tr);
  }
  document.getElementById('reqTotal').textContent=total;
  document.getElementById('reqCount').textContent=total;
  document.getElementById('reqPageInfo').textContent=`${REQ_PAGE} / ${pages}`;
}
async function loadReqs(){
  try{
    const r=document.getElementById('req-range').value;
    const url=r?('/api/requests?range='+encodeURIComponent(r)):'/api/requests';
    const d=await (await fetch(url)).json();
    document.getElementById('reqWin').textContent=d.window_min;
    document.getElementById('reqTs').textContent=d.ts_str||'—';
    REQ_DATA=d.requests||[];
    REQ_PAGE=1;
    renderReqs();
    document.getElementById('req-trunc').style.display=d.truncated?'inline':'none';
  }catch(e){document.getElementById('reqTs').textContent='err '+e;}
}
let reqTimer=null;
function scheduleReqs(){
  if(reqTimer) clearInterval(reqTimer);
  const r=document.getElementById('req-range').value;
  // 实时快照 15s 刷; 自选大范围(临时拉 LiteLLM 多页)60s
  const ms = (!r) ? 15000 : 60000;
  reqTimer=setInterval(loadReqs, ms);
}
loadReqs(); scheduleReqs();
document.getElementById('req-range').addEventListener('change',()=>{REQ_PAGE=1;loadReqs();scheduleReqs();});
document.getElementById('reqPageSize').addEventListener('change',e=>{REQ_PAGESIZE=parseInt(e.target.value);REQ_PAGE=1;renderReqs();});
document.getElementById('reqPrevPage').addEventListener('click',()=>{REQ_PAGE--;renderReqs();});
document.getElementById('reqNextPage').addEventListener('click',()=>{REQ_PAGE++;renderReqs();});
document.getElementById('reqFilterName').addEventListener('input',()=>{REQ_PAGE=1;renderReqs();});

// 采样间隔下拉框 -> POST 到后端改间隔 + 调整本地图表刷新频率
document.getElementById('sel-interval').addEventListener('change',async e=>{
  const sec=parseInt(e.target.value);
  try{
    const r=await fetch('/api/interval',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({interval:sec})});
    const d=await r.json();
    if(d.ok){CUR_INTERVAL=d.interval;scheduleQueue();loadQueue();}
    else{alert('设置失败: '+(d.error||'未知错误')); e.target.value=CUR_INTERVAL;}
  }catch(err){alert('请求失败: '+err); e.target.value=CUR_INTERVAL;}
});
// 图表范围下拉框 -> 立即重载 + 调整刷新频率
document.getElementById('sel-range').addEventListener('change',()=>{loadQueue();scheduleQueue();});
// IP 表日志范围下拉框 -> 立即重载 + 调整刷新频率
document.getElementById('ips-range').addEventListener('change',()=>{IP_PAGE=1;loadIps();scheduleIps();});
document.getElementById('pageSize').addEventListener('change',e=>{IP_PAGESIZE=parseInt(e.target.value);IP_PAGE=1;renderIps();});
document.getElementById('prevPage').addEventListener('click',()=>{IP_PAGE--;renderIps();});
document.getElementById('nextPage').addEventListener('click',()=>{IP_PAGE++;renderIps();});
// 启动时从后端同步当前采样间隔
fetch('/api/status').then(r=>r.json()).then(d=>{
  if(d.vllm_interval){CUR_INTERVAL=d.vllm_interval;document.getElementById('sel-interval').value=d.vllm_interval;scheduleQueue();}
}).catch(()=>{});
</script></body></html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, obj):
        b = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Cache-Control","no-store")
        self.send_header("Content-Length",str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        if path == "/":
            b = PAGE.encode("utf-8")
            self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
        elif path == "/api/queue":
            # range=15m/1h/6h/1d 或 range=900(秒)
            r = (qs.get("range") or ["15m"])[0]
            range_sec = _parse_range(r)
            self._json(api_queue(range_sec))
        elif path == "/api/ips":
            # range 缺省 -> 实时快照(采集线程最新); range=15m/1h/6h/1d -> 临时拉 LiteLLM 聚合
            r = (qs.get("range") or [None])[0]
            range_sec = _parse_range(r) if r else None
            self._json(api_ips(range_sec))
        elif path == "/api/ip_detail":
            # 某 IP 在指定范围的逐条请求明细(服务端分页, 供前端弹窗)
            # range 缺省 -> 实时窗口; range=15m/1h... -> 对应范围
            r = (qs.get("range") or [None])[0]
            range_sec = _parse_range(r) if r else LITELLM_WINDOW * 60
            ip = (qs.get("ip") or [""])[0]
            try: page = int((qs.get("page") or ["1"])[0])
            except ValueError: page = 1
            try: page_size = int((qs.get("page_size") or ["50"])[0])
            except ValueError: page_size = 50
            self._json(api_ip_detail(range_sec, ip, page, page_size))
        elif path == "/api/requests":
            # range 缺省 -> 实时窗口(LITELLM_WINDOW); range=15m/1h... -> 临时拉明细
            r = (qs.get("range") or [None])[0]
            range_sec = _parse_range(r) if r else None
            self._json(api_requests(range_sec))
        elif path == "/api/inflight":
            # 实时在途请求 (LiteLLM pre-call 回调推送, 见 custom_callbacks/inflight_logger.py)
            self._json(api_inflight())
        elif path == "/api/status":
            self._json(STATE)
        else:
            self.send_response(404); self.end_headers()
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/interval":
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            try:
                data = json.loads(body) if body else {}
            except Exception:
                data = {}
            sec = data.get("interval") or data.get("sec")
            self._json(set_vllm_interval(sec))
        elif parsed.path == "/api/thresholds":
            # 页面"⚙ 阈值"修改超大上下文 / 已耗时阈值
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            try:
                data = json.loads(body) if body else {}
            except Exception:
                data = {}
            self._json(set_thresholds(data.get("big_context"), data.get("slow_sec")))
        elif parsed.path == "/api/inflight":
            # LiteLLM 回调推送 start/end 事件
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            try:
                data = json.loads(body) if body else {}
            except Exception:
                data = {}
            self._json(handle_inflight(data))
        else:
            self.send_response(404); self.end_headers()

def main():
    threading.Thread(target=collect_vllm, daemon=True).start()
    threading.Thread(target=collect_litellm, daemon=True).start()
    srv = ThreadingHTTPServer((HTTP_HOST, HTTP_PORT), Handler)
    print(f"GLM 监控已启动: http://{HTTP_HOST}:{HTTP_PORT}  (回调推送 -> POST /api/inflight)")
    print(f"  vLLM 后端: {[n for n, _ in VLLM_ENDPOINTS]} -> 合并为 {VLLM_BACKENDS}")
    print(f"  LiteLLM:   {LITELLM_HOST}")
    print(f"  数据库:    {DB_PATH}")
    srv.serve_forever()

if __name__ == "__main__":
    main()
