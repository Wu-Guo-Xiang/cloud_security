"""GLM 监控数据读取(只读)。

数据由独立采集器 glm_monitor/monitor.py 写入 SQLite:
  samples_vllm(ts, backend, waiting, running, preemption, gpu_cache_usage,
               kv_cache_usage, prompt_tokens, gen_tokens, prefix_hit_rate)
  samples_litellm(ts, ip, requests, sessions, avg_ms, max_ms, fail, models, names)

本模块只做 SELECT, 用只读连接打开, 不影响采集器写入。
采集器离线时返回 ok=False + 最后采样时间, 由页面提示。
"""
from __future__ import annotations

import sqlite3
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

HISTORY_POINTS = 180   # 队列曲线返回最近多少个采样点(5s*180=15min)
STALE_SECONDS = 30     # vLLM 最新采样超过该秒数 => 判定采集器离线
# LiteLLM 聚合窗口(分钟), 需与采集器 glm_monitor/monitor.py 的 LITELLM_WINDOW 保持一致
LITELLM_WINDOW_MIN = 5
# 显示时间统一用北京时间(UTC+8), 避免服务器 UTC 时区导致显示慢 8 小时
CN_TZ = timezone(timedelta(hours=8))
# 降采样后的最大返回点数(与采集器 monitor.py 的 MAX_CHART_POINTS 一致)
MAX_CHART_POINTS = 240
# 默认采样间隔(秒), 用于估算桶数; 实际以 DB 数据为准
DEFAULT_INTERVAL = 5


def _connect_ro(db_path: Path) -> sqlite3.Connection:
    """只读连接; DB 不存在时抛 sqlite3.OperationalError 由调用方转错误信息。"""
    p = Path(db_path)
    if not p.exists():
        raise FileNotFoundError(str(p))
    conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=3)
    conn.row_factory = sqlite3.Row
    return conn


def _parse_range(r: str) -> int:
    """'15m'/'1h'/'6h'/'1d' 或纯秒数 -> 秒。默认 900(15min)。"""
    r = (r or "15m").strip().lower()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if r and r[-1] in mult:
        try:
            return max(60, int(float(r[:-1])) * mult[r[-1]])
        except ValueError:
            pass
    try:
        return max(60, int(r))
    except ValueError:
        return 900


def read_queue(db_path: Path, range_sec: int = 900) -> dict:
    """vLLM 队列/健康时序(按 range_sec 降采样到 <=MAX_CHART_POINTS 点)。
    返回 {ok, error?, labels, series, latest, age_s, collector_online, range_sec}"""
    try:
        conn = _connect_ro(db_path)
    except (FileNotFoundError, sqlite3.OperationalError) as e:
        return {"ok": False, "error": f"监控数据库不可读: {e}", "collector_online": False}

    now = time.time()
    since = now - range_sec
    try:
        rows = conn.execute(
            "SELECT ts, backend, waiting, running, preemption, gpu_cache_usage, "
            "kv_cache_usage, prompt_tokens, gen_tokens, prefix_hit_rate "
            "FROM samples_vllm WHERE ts >= ? ORDER BY ts",
            (since,)).fetchall()
    except sqlite3.OperationalError as e:
        return {"ok": False, "error": f"查询失败(表不存在?): {e}", "collector_online": False}
    finally:
        conn.close()

    if not rows:
        return {"ok": False, "error": "暂无采样数据(采集器刚启动/该时间范围无数据?)", "collector_online": False}

    backends: list[str] = []
    for r in rows:
        be = r["backend"]
        if be not in backends:
            backends.append(be)

    # 按时间桶降采样: n_bucket 个桶, 每桶取均值; 空桶补 None(图表断点)
    n_bucket = max(1, min(MAX_CHART_POINTS, int(range_sec // DEFAULT_INTERVAL) or 1))
    span = max(float(range_sec), 1.0)
    buckets: dict[int, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for r in rows:
        bi = int((r["ts"] - since) / span * n_bucket)
        if bi >= n_bucket:
            bi = n_bucket - 1
        if bi < 0:
            continue
        buckets[bi][r["backend"]].append(r)

    fmt = "%H:%M:%S" if range_sec <= 1800 else ("%H:%M" if range_sec <= 6 * 3600 else "%m-%d %H:%M")
    labels: list[str] = []
    series: dict[str, dict] = {be: {"waiting": [], "running": [], "kv": [], "hit": []}
                               for be in backends}
    for bi in range(n_bucket):
        t0 = since + (bi + 0.5) / n_bucket * span
        labels.append(datetime.fromtimestamp(t0, CN_TZ).strftime(fmt))
        for be in backends:
            rs = buckets.get(bi, {}).get(be, [])
            if rs:
                n = len(rs)
                series[be]["waiting"].append(round(sum(x["waiting"] for x in rs) / n, 2))
                series[be]["running"].append(round(sum(x["running"] for x in rs) / n, 2))
                series[be]["kv"].append(round(sum(x["kv_cache_usage"] for x in rs) / n * 100, 1))
                series[be]["hit"].append(round(sum(x["prefix_hit_rate"] for x in rs) / n * 100, 1))
            else:
                for k in ("waiting", "running", "kv", "hit"):
                    series[be][k].append(None)

    # 前向填充: gauge 类指标空桶沿用上一个已知值, 避免采集漏点导致折线断开。
    # 开头仍无值的桶保持 None。
    for be in backends:
        last = {"waiting": None, "running": None, "kv": None, "hit": None}
        for bi in range(n_bucket):
            for k in ("waiting", "running", "kv", "hit"):
                v = series[be][k][bi]
                if v is None and last[k] is not None:
                    series[be][k][bi] = last[k]
                elif v is not None:
                    last[k] = v

    # latest = 该时间范围内最后一个有效采样点(各后端各自的最后一条)
    latest: dict[str, dict] = {}
    for be in backends:
        be_rows = [r for r in rows if r["backend"] == be]
        if be_rows:
            r = be_rows[-1]
            latest[be] = {
                "waiting": round(r["waiting"] or 0),
                "running": round(r["running"] or 0),
                "preemption": round(r["preemption"] or 0),
                "kv": round((r["kv_cache_usage"] or 0) * 100, 1),
                "prompt_tokens": round(r["prompt_tokens"] or 0),
                "gen_tokens": round(r["gen_tokens"] or 0),
                "prefix_hit_rate": round((r["prefix_hit_rate"] or 0) * 100, 1),
            }

    # 采集器在线判定: 用全局最新一条(不限范围)的 ts
    last_ts = rows[-1]["ts"]
    age_s = round(now - last_ts)
    return {
        "ok": True,
        "labels": labels,
        "series": series,
        "latest": latest,
        "age_s": age_s,
        "ts_str": datetime.fromtimestamp(last_ts, CN_TZ).strftime("%H:%M:%S"),
        "collector_online": age_s <= STALE_SECONDS,
        "range_sec": range_sec,
    }


def read_ips(db_path: Path) -> dict:
    """最近一次 LiteLLM 采样的各 IP 聚合(仅 GLM 模型, 采集器已过滤)。"""
    try:
        conn = _connect_ro(db_path)
    except (FileNotFoundError, sqlite3.OperationalError) as e:
        return {"ok": False, "error": f"监控数据库不可读: {e}"}

    try:
        r = conn.execute("SELECT MAX(ts) FROM samples_litellm").fetchone()
        if not r or r[0] is None:
            return {"ok": False, "error": "暂无数据"}
        max_ts = r[0]
        rows = conn.execute(
            "SELECT ip, requests, sessions, avg_ms, max_ms, fail, models, names "
            "FROM samples_litellm WHERE ts=? ORDER BY requests DESC",
            (max_ts,)).fetchall()
    except sqlite3.OperationalError as e:
        return {"ok": False, "error": f"查询失败: {e}"}
    finally:
        conn.close()

    ips = []
    for row in rows:
        ips.append({
            "ip": row["ip"],
            "names": row["names"] or "",
            "requests": row["requests"],
            "sessions": row["sessions"],
            "avg_ms": round(row["avg_ms"] or 0),
            "max_ms": round(row["max_ms"] or 0),
            "fail": row["fail"],
            "models": row["models"] or "",
        })
    age_s = round(time.time() - max_ts)
    return {
        "ok": True,
        "ts": max_ts,
        "ts_str": datetime.fromtimestamp(max_ts, CN_TZ).strftime("%H:%M:%S"),
        "age_s": age_s,
        "window_min": LITELLM_WINDOW_MIN,
        "ips": ips,
        "summary": {
            "glm_ips": len(ips),
            "total_req": sum(x["requests"] for x in ips),
            "total_sessions": sum(x["sessions"] for x in ips),
        },
    }