"""IP 白名单存储 — SQLite ip_whitelist 表。

供 api/main.py 的白名单管理路由 + plugin_status.py 的 IP 校验调用。

核心函数:
- list_whitelist()     列出全部白名单条目
- add_whitelist()      新增 IP 或网段
- delete_whitelist()   删除条目
- check_ip()           判断某个 IP 是否在白名单内
- load_whitelist_nets()  加载白名单为 ip_network 列表(缓存用)
"""
from __future__ import annotations

import ipaddress
import time
from typing import Any

from .db import Storage, _WRITE_LOCK

# ── 内存缓存(避免每次 check_ip 都查 DB) ──────────────────────────
_nets_cache: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
_nets_cache_at: float = 0.0
_NETS_CACHE_TTL = 60  # 秒


def list_whitelist(storage: Storage) -> list[dict[str, Any]]:
    """列出全部白名单条目(id, ip, comment, created_at)。"""
    conn = storage.read_conn()
    try:
        rows = conn.execute(
            "SELECT id, ip, comment, created_at FROM ip_whitelist ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def add_whitelist(storage: Storage, ip: str, comment: str = "") -> dict[str, Any]:
    """新增白名单条目。ip 可以是单个 IP 或 CIDR 网段。

    自动校验格式, 返回新记录 dict。格式错误抛 ValueError。
    """
    ip = ip.strip()
    if not ip:
        raise ValueError("IP 不能为空")

    # 校验: 是合法 IP 或 CIDR
    try:
        if "/" in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"IP 格式无效: {ip!r}，应为 172.16.1.100 或 172.16.0.0/16")

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _WRITE_LOCK:
        conn = storage._writer
        try:
            conn.execute(
                "INSERT OR IGNORE INTO ip_whitelist(ip, comment, created_at) VALUES(?, ?, ?)",
                (ip, comment, now),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # 清缓存
    _invalidate_cache()
    return {"ip": ip, "comment": comment, "created_at": now}


def delete_whitelist(storage: Storage, item_id: int) -> bool:
    """删除白名单条目。返回 True 成功, False 不存在。"""
    with _WRITE_LOCK:
        conn = storage._writer
        try:
            cur = conn.execute("SELECT id FROM ip_whitelist WHERE id = ?", (item_id,))
            if not cur.fetchone():
                return False
            conn.execute("DELETE FROM ip_whitelist WHERE id = ?", (item_id,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    _invalidate_cache()
    return True


def _invalidate_cache() -> None:
    global _nets_cache_at
    _nets_cache_at = 0.0


def load_whitelist_nets(storage: Storage) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """加载白名单为 ip_network 列表(带 60 秒缓存)。

    单个 IP 如 172.16.1.100 自动转为 /32 或 /128 网络。
    """
    global _nets_cache, _nets_cache_at
    now = time.time()
    if _nets_cache and now - _nets_cache_at < _NETS_CACHE_TTL:
        return _nets_cache

    conn = storage.read_conn()
    try:
        rows = conn.execute("SELECT ip FROM ip_whitelist").fetchall()
    finally:
        conn.close()

    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for r in rows:
        raw = r["ip"].strip()
        if not raw:
            continue
        try:
            if "/" in raw:
                nets.append(ipaddress.ip_network(raw, strict=False))
            else:
                addr = ipaddress.ip_address(raw)
                nets.append(ipaddress.ip_network(f"{addr}/{'32' if addr.version == 4 else '128'}"))
        except ValueError:
            continue  # 跳过格式异常的旧数据

    _nets_cache = nets
    _nets_cache_at = now
    return nets


def check_ip(storage: Storage, ip_str: str) -> bool:
    """判断某个 IP 是否在白名单内。

    白名单为空时返回 True(无白名单=不限制)。
    """
    if not ip_str or not ip_str.strip():
        return True  # 无 IP 的记录不判

    nets = load_whitelist_nets(storage)
    if not nets:
        return True  # 没配白名单=全部放行

    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return True  # 格式异常不判

    return any(addr in net for net in nets)
