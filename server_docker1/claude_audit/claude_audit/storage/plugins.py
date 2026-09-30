"""插件版本存储 — zip 文件系统 + SQLite plugin_releases 表

供 api/main.py 的插件管理路由调用，核心函数：
- save_release()     上传新版本（保存 zip、计算 sha256、写 DB、自动激活）
- get_active_manifest()  获取当前激活版本的 manifest dict（客户端拉取用）
- list_releases()    列出所有版本
- activate_release() 激活某个历史版本（回滚用）
- delete_release()   删除某个历史版本
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import sqlite3
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .db import Storage, _WRITE_LOCK

# 显示时间统一北京时间(UTC+8), 与 monitor.py / plugin_status.py 一致
_CN_TZ = timezone(timedelta(hours=8))


# ---------------------------------------------------------------------------
# 版本号工具
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def parse_version(text: str) -> tuple[int, ...] | None:
    """'0.2.1' → (0, 2, 1)；格式不符返回 None"""
    m = _VERSION_RE.match(text.strip().lstrip("vV"))
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def bump_patch(version: str) -> str | None:
    """'0.2.0' → '0.2.1'；格式不符返回 None"""
    t = parse_version(version)
    if t is None:
        return None
    return f"{t[0]}.{t[1]}.{t[2] + 1}"


# ---------------------------------------------------------------------------
# zip 内 plugin.json 版本同步
# ---------------------------------------------------------------------------
#
# 根因:管理员手动打包 zip 时经常忘记 bump .claude-plugin/plugin.json 的版本号,
# 但上传时手填了新版本 → manifest 声明新版本、zip 内部却是旧版本 → 员工机的
# 老 updater 在 updater.py 里硬校验两者相等,不一致就 "可能是打包错误,已中止",
# 整个更新流程卡死(见 error.png)。员工机跑的是老 updater,本地改代码救不了已
# 部署的机器(鸡生蛋),所以必须在服务器侧保证下发的 zip 内版本 == manifest 版本。
#
# 做法:上传存盘前读 zip 内 plugin.json 版本,若与手填 version 不符,自动改写该
# 条目的 version 字段并重建 zip(其余条目原样复制,权限/路径不变),再算 sha256
# 存盘。这样老 updater 永远撞不到不一致,不再报错。


def _find_zip_plugin_json(zf: zipfile.ZipFile) -> str | None:
    """在 zip 内查找 .claude-plugin/plugin.json 条目名。

    打包方式不同,plugin.json 可能在:
      - .claude-plugin/plugin.json                  (扁平打包)
      - claude_plugin/.claude-plugin/plugin.json    (连顶层目录一起压缩)
    两种都匹配后缀 .claude-plugin/plugin.json,与客户端 updater 的 rglob 查找一致。
    """
    for name in zf.namelist():
        if name.endswith("/"):
            continue
        if name.endswith(".claude-plugin/plugin.json"):
            return name
    return None


def sync_zip_version(zip_bytes: bytes, target_version: str) -> tuple[bytes, str | None]:
    """确保 zip 内 .claude-plugin/plugin.json 的 version == target_version。

    返回 (zip_bytes, warning):
      - 版本已一致           → (原 bytes, None)
      - 已纠正               → (新 bytes, 纠正说明)
      - 无 plugin.json/损坏  → (原 bytes, 提示;不阻断,老 updater 只在 plugin.json
                                存在时才校验,无 plugin.json 不会撞此分支)
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    except zipfile.BadZipFile:
        return zip_bytes, "zip 文件损坏,无法校验内部版本号"

    with zf:
        pj_name = _find_zip_plugin_json(zf)
        if not pj_name:
            return zip_bytes, "zip 内未找到 .claude-plugin/plugin.json,已跳过版本同步"

        try:
            data = json.loads(zf.read(pj_name).decode("utf-8"))
        except Exception as exc:
            return zip_bytes, f"读取 zip 内 plugin.json 失败: {exc}"

        inner_ver = (data.get("version") or "").strip()
        if inner_ver == target_version:
            return zip_bytes, None  # 一致,无需纠正

        # 改写 version,重建 zip:仅替换 plugin.json 条目,其余条目原样复制
        # (传入原 ZipInfo 对象 → 保留 external_attr 权限、时间戳、压缩方式)
        data["version"] = target_version
        new_pj_bytes = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zf.infolist():
                if item.is_dir():
                    continue  # 目录条目由文件条目的路径自动重建
                if item.filename == pj_name:
                    zout.writestr(item, new_pj_bytes)
                else:
                    zout.writestr(item, zf.read(item.filename))
        corrected = out.getvalue()

        return corrected, (
            f"zip 内版本 ({inner_ver}) 与声明版本 ({target_version}) 不一致,"
            f"已自动纠正 zip 内 plugin.json 版本为 {target_version}"
        )


def resync_release(storage: Storage, plugins_dir: Path, release_id: int) -> dict | None:
    """对已存储的某个版本 zip 原地修复其内部 plugin.json 版本。

    用于修复历史上已经上传、但内部版本与声明版本不一致的包(老 updater 会中止)。
    把 zip 内 plugin.json 版本对齐到 DB 记录的 version,重算 sha256 并更新 DB。
    返回 {version, sha256, sync_warning} 或 None(id 不存在)。
    """
    conn = storage.read_conn()
    try:
        row = conn.execute(
            "SELECT id, version, zip_filename FROM plugin_releases WHERE id = ?",
            (release_id,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None

    r = dict(row)
    zip_path = plugins_dir / r["zip_filename"]
    if not zip_path.exists():
        raise FileNotFoundError(f"zip 文件不存在: {zip_path}")

    zip_bytes = zip_path.read_bytes()
    corrected, warning = sync_zip_version(zip_bytes, r["version"])
    new_sha = hashlib.sha256(corrected).hexdigest()

    # 确实改写了才写盘 + 更新 DB(避免无谓 IO 和 sha 抖动)
    if corrected != zip_bytes:
        zip_path.write_bytes(corrected)
        with _WRITE_LOCK:
            conn = storage._writer
            try:
                conn.execute(
                    "UPDATE plugin_releases SET sha256 = ? WHERE id = ?",
                    (new_sha, release_id),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    return {"version": r["version"], "sha256": new_sha, "sync_warning": warning}


# ---------------------------------------------------------------------------
# 核心 CRUD
# ---------------------------------------------------------------------------

def save_release(
    storage: Storage,
    plugins_dir: Path,
    zip_bytes: bytes,
    version: str,
    min_required: str,
    release_notes: str,
    released_by: str,
) -> dict:
    """保存上传的 zip，计算 sha256，写入数据库，自动激活。

    返回新插入的记录 dict。
    """
    # 校验版本号格式
    if not parse_version(version):
        raise ValueError(f"版本号格式错误: {version!r}，应为 x.y.z")
    if not parse_version(min_required):
        raise ValueError(f"最低要求版本号格式错误: {min_required!r}，应为 x.y.z")

    # 版本同步:确保 zip 内 plugin.json 版本 == 手填 version。
    # 若不一致(管理员打包忘 bump plugin.json),自动改写 zip 内版本,避免老 updater
    # 在 updater.py 硬校验两者相等时中止更新。
    zip_bytes, sync_warning = sync_zip_version(zip_bytes, version)
    if sync_warning:
        print(f"[plugins] {sync_warning}")

    # 计算 sha256(在版本同步之后,保证校验值对应最终下发的 zip)
    sha = hashlib.sha256(zip_bytes).hexdigest()

    # 保存 zip 到磁盘
    plugins_dir.mkdir(parents=True, exist_ok=True)
    filename = f"cloud-guard-{version}.zip"
    dest = plugins_dir / filename
    dest.write_bytes(zip_bytes)

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    with _WRITE_LOCK:
        conn = storage._writer
        try:
            # 先把所有旧版本 is_active → 0
            conn.execute("UPDATE plugin_releases SET is_active = 0")
            # 插入新记录（is_active = 1）
            conn.execute(
                """
                INSERT INTO plugin_releases
                  (version, min_required, sha256, release_notes, released_at,
                   released_by, zip_filename, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (version, min_required, sha, release_notes, now,
                 released_by, filename),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            # 清理已写入的 zip
            if dest.exists():
                dest.unlink(missing_ok=True)
            raise

    return dict(
        id=None,
        version=version,
        min_required=min_required,
        sha256=sha,
        release_notes=release_notes,
        released_at=now,
        released_by=released_by,
        zip_filename=filename,
        is_active=1,
        sync_warning=sync_warning,
    )


def get_active_manifest(storage: Storage, base_url: str) -> dict | None:
    """获取当前激活版本的 manifest dict（供客户端 GET /plugins/manifest.json 调用）。

    base_url 如 'http://192.168.3.57:8787'，用于拼接下载 URL。
    返回 None 表示暂无可用版本。
    """
    conn = storage.read_conn()
    try:
        cur = conn.execute(
            "SELECT version, min_required, sha256, release_notes, released_at, zip_filename "
            "FROM plugin_releases WHERE is_active = 1 LIMIT 1"
        )
        row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        return None

    r = dict(row)
    download_url = f"{base_url.rstrip('/')}/plugins/download/{r['zip_filename']}"
    return {
        "version": r["version"],
        "min_required": r["min_required"],
        "url": download_url,
        "sha256": r["sha256"],
        "release_notes": r["release_notes"] or "",
        "released_at": r["released_at"],
    }


def list_releases(storage: Storage) -> list[dict]:
    """列出所有版本（按 id DESC，最新在前）。

    容错: 若 plugin_releases 表不存在(旧库未迁移)则返回空列表, 避免页面 500。
    """
    conn = storage.read_conn()
    try:
        rows = conn.execute(
            "SELECT id, version, min_required, sha256, release_notes, "
            "       released_at, released_by, zip_filename, is_active "
            "FROM plugin_releases ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError as e:
        if "no such table" in str(e).lower():
            return []
        raise
    finally:
        conn.close()


def activate_release(storage: Storage, release_id: int) -> bool:
    """激活指定版本（旧的 is_active 全部置 0，指定 id 置 1）。

    返回 True 表示成功，False 表示 id 不存在。
    """
    with _WRITE_LOCK:
        conn = storage._writer
        try:
            cur = conn.execute(
                "SELECT id FROM plugin_releases WHERE id = ?", (release_id,)
            )
            if not cur.fetchone():
                return False
            conn.execute("UPDATE plugin_releases SET is_active = 0")
            conn.execute(
                "UPDATE plugin_releases SET is_active = 1 WHERE id = ?",
                (release_id,),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return True


def delete_release(storage: Storage, plugins_dir: Path, release_id: int) -> bool:
    """删除某个历史版本（zip 文件 + DB 记录）。

    不允许删除当前激活版本。返回 True 成功，False 表示不存在或为激活版本。
    """
    conn = storage.read_conn()
    try:
        cur = conn.execute(
            "SELECT id, is_active, zip_filename FROM plugin_releases WHERE id = ?",
            (release_id,),
        )
        row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        return False

    r = dict(row)
    if r["is_active"]:
        return False  # 不允许删除激活版本

    with _WRITE_LOCK:
        conn = storage._writer
        try:
            conn.execute("DELETE FROM plugin_releases WHERE id = ?", (release_id,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # 删除 zip 文件（best-effort）
    zip_path = plugins_dir / r["zip_filename"]
    zip_path.unlink(missing_ok=True)
    return True


# ---------------------------------------------------------------------------
# 插件拉取/下载记录 (谁在何时拉了哪个版本)
# ---------------------------------------------------------------------------
# 服务端在 /plugins/manifest.json (检查版本) 和 /plugins/download/{filename}
# (下载 zip) 两个接口记录请求方 IP + 版本, 用来追踪"谁更新了插件"。
# 客户端拉取不带任何身份头, 只能拿到 IP; IP -> 使用人 的解析在 API 层复用
# plugin_status 的 LiteLLM litellm_ip 映射完成。

def log_plugin_pull(
    storage: Storage,
    ip: str,
    action: str,
    version: str = "",
    filename: str = "",
    user_agent: str = "",
) -> None:
    """记录一次插件拉取/下载事件。失败静默(不影响接口返回)。"""
    ts = datetime.now(_CN_TZ).strftime("%Y-%m-%d %H:%M:%S")
    try:
        with _WRITE_LOCK:
            conn = storage._writer
            conn.execute(
                """
                INSERT INTO plugin_pulls(ts, ip, action, version, filename, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (ts, ip or "", action, version, filename, user_agent[:300]),
            )
            conn.commit()
    except Exception:
        pass  # 日志失败不影响插件接口


def list_plugin_pulls(
    storage: Storage,
    limit: int = 1000,
    offset: int = 0,
    version_filter: str | None = None,
    ip_filter: str | None = None,
    action_filter: str | None = None,
) -> list[dict]:
    """返回拉取记录(最新在前)。容错: 表不存在返回空列表。"""
    conn = storage.read_conn()
    try:
        sql = (
            "SELECT id, ts, ip, action, version, filename, user_agent "
            "FROM plugin_pulls"
        )
        clauses, params = [], []
        if version_filter:
            clauses.append("version = ?")
            params.append(version_filter)
        if ip_filter:
            clauses.append("ip = ?")
            params.append(ip_filter)
        if action_filter:
            clauses.append("action = ?")
            params.append(action_filter)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.append(limit)
        params.append(offset)
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError as e:
        if "no such table" in str(e).lower():
            return []
        raise
    finally:
        conn.close()


def count_plugin_pulls(
    storage: Storage,
    version_filter: str | None = None,
    ip_filter: str | None = None,
    action_filter: str | None = None,
) -> int:
    """返回满足筛选条件的拉取记录总数。容错: 表不存在返回 0。"""
    conn = storage.read_conn()
    try:
        sql = "SELECT count(*) FROM plugin_pulls"
        clauses, params = [], []
        if version_filter:
            clauses.append("version = ?")
            params.append(version_filter)
        if ip_filter:
            clauses.append("ip = ?")
            params.append(ip_filter)
        if action_filter:
            clauses.append("action = ?")
            params.append(action_filter)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        return conn.execute(sql, params).fetchone()[0]
    except sqlite3.OperationalError as e:
        if "no such table" in str(e).lower():
            return 0
        raise
    finally:
        conn.close()


def get_active_version(storage: Storage) -> str:
    """当前激活版本号, 无则返回 ''。"""
    conn = storage.read_conn()
    try:
        cur = conn.execute(
            "SELECT version FROM plugin_releases WHERE is_active = 1 LIMIT 1"
        )
        row = cur.fetchone()
        return row["version"] if row else ""
    except sqlite3.OperationalError:
        return ""
    finally:
        conn.close()
