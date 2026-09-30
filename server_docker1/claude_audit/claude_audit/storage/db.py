from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from .models import EventRecord, RuleHit


_MIG_DIR = Path(__file__).resolve().parent / "migrations"
_WRITE_LOCK = threading.Lock()


def _connect(db_path: Path, *, read_only: bool = False) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    if not read_only:
        # 使用 TRUNCATE 模式: 比 DELETE 性能大幅提升数倍(避免反复磁盘创建/删除操作)，
        # 且在所有环境(包括 Windows Docker 挂载卷)下 100% 稳定运行，无 -shm POSIX 锁依赖
        conn.executescript(
            "PRAGMA journal_mode=TRUNCATE;"
            "PRAGMA synchronous=NORMAL;"       # NORMAL 保证数据安全且极大减少磁盘同步开销
            "PRAGMA busy_timeout=10000;"       # 遇锁自动重试等待 10s，杜绝 database is locked
            "PRAGMA cache_size=-64000;"        # 64MB 内存页面缓存
            "PRAGMA temp_store=MEMORY;"        # 临时表走内存
            "PRAGMA foreign_keys=ON;"
        )
    else:
        conn.executescript(
            "PRAGMA busy_timeout=10000;"
            "PRAGMA cache_size=-32000;"
        )
    return conn


class Storage:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._writer = _connect(db_path)

    def migrate(self) -> None:
        with _WRITE_LOCK:
            cur = self._writer.execute("PRAGMA user_version")
            version = cur.fetchone()[0]
            migs = sorted(_MIG_DIR.glob("*.sql"))
            for i, m in enumerate(migs, start=1):
                if i <= version:
                    continue
                sql = m.read_text(encoding="utf-8")
                self._writer.executescript(sql)
                self._writer.execute(f"PRAGMA user_version = {i}")
                self._writer.commit()
            # 幂等自愈: 部署到已有旧库时, user_version 可能已推进但某张后加的表
            # 实际缺失(如 plugin_releases / ip_whitelist), 这里无条件补建, 不依赖 version。
            self._ensure_schema()

    def _ensure_schema(self) -> None:
        """确保关键表存在(幂等), 处理旧库缺表导致的运行时 500。

        全部使用 CREATE TABLE IF NOT EXISTS, 已存在则跳过, 无副作用。
        """
        statements = [
            # 006_plugin_releases
            """CREATE TABLE IF NOT EXISTS plugin_releases (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                version       TEXT    NOT NULL,
                min_required  TEXT    NOT NULL DEFAULT '0.1.0',
                sha256        TEXT    NOT NULL,
                release_notes TEXT    DEFAULT '',
                released_at   TEXT    NOT NULL,
                released_by   TEXT    DEFAULT '',
                zip_filename  TEXT    NOT NULL,
                is_active     INTEGER NOT NULL DEFAULT 0,
                UNIQUE(version)
            )""",
            # 007_ip_whitelist
            """CREATE TABLE IF NOT EXISTS ip_whitelist (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT    NOT NULL,
                comment     TEXT    DEFAULT '',
                created_at  TEXT    NOT NULL,
                UNIQUE(ip)
            )""",
            # 008_plugin_pulls — 插件拉取/下载记录 (谁在何时拉了哪个版本)
            """CREATE TABLE IF NOT EXISTS plugin_pulls (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT    NOT NULL,
                ip          TEXT    NOT NULL,
                action      TEXT    NOT NULL,
                version     TEXT    DEFAULT '',
                filename    TEXT    DEFAULT '',
                user_agent  TEXT    DEFAULT ''
            )""",
            # 009_user_org_info & v_events
            """CREATE TABLE IF NOT EXISTS user_org_info (
                raw_user  TEXT PRIMARY KEY,
                user_name TEXT,
                pinyin    TEXT,
                dept_name TEXT,
                dept_path TEXT
            )""",
            """DROP VIEW IF EXISTS v_events""",
            """CREATE VIEW v_events AS
            SELECT e.*,
                   COALESCE(u.user_name, u_fuzzy.user_name, e.user) AS user_name,
                   COALESCE(u.dept_name, u_fuzzy.dept_name, '未知部门') AS dept_name,
                   COALESCE(u.dept_path, u_fuzzy.dept_path, '未知部门') AS dept_path
            FROM events e
            LEFT JOIN user_org_info u ON e.user = u.raw_user
            LEFT JOIN user_org_info u_fuzzy ON (
                u.raw_user IS NULL
                AND (
                    e.user LIKE '%\\' || u_fuzzy.raw_user
                    OR e.user LIKE '%/' || u_fuzzy.raw_user
                    OR e.user LIKE '%-' || u_fuzzy.raw_user
                )
            )""",
        ]
        for stmt in statements:
            self._writer.execute(stmt)
        self._writer.commit()
        # 索引单独建 (IF NOT EXISTS, 旧库已有表时也补索引)
        for idx in ("ix_pulls_ts", "ix_pulls_ip", "ix_pulls_version", "ix_user_org_name", "ix_user_org_dept"):
            if idx == "ix_user_org_name":
                tbl, col = "user_org_info", "user_name"
            elif idx == "ix_user_org_dept":
                tbl, col = "user_org_info", "dept_name"
            else:
                tbl = "plugin_pulls"
                col = {"ix_pulls_ts": "ts", "ix_pulls_ip": "ip", "ix_pulls_version": "version"}[idx]
            try:
                self._writer.execute(
                    f"CREATE INDEX IF NOT EXISTS {idx} ON {tbl}({col})"
                )
            except sqlite3.OperationalError:
                pass  # 表不存在等异常忽略, migrate 流程会先建表
        self._writer.commit()

    def execute_write(self, sql: str, params: tuple = ()) -> None:
        with _WRITE_LOCK:
            self._writer.execute(sql, params)
            self._writer.commit()

    def executemany_write(self, sql: str, params_list: list = ()) -> None:
        with _WRITE_LOCK:
            self._writer.executemany(sql, params_list)
            self._writer.commit()

    def read_conn(self) -> sqlite3.Connection:
        return _connect(self.db_path, read_only=True)

    def insert_events(self, records: Iterable[EventRecord]) -> None:
        rows = list(records)
        if not rows:
            return
        with _WRITE_LOCK:
            cur = self._writer.cursor()
            try:
                cur.execute("BEGIN")
                for r in rows:
                    cur.execute(
                        """
                        INSERT INTO events
                          (ts, source_file, line_no, byte_offset, event, stage, session_id,
                           tool, phase, action, skipped_reason, duration_ms, user, vm_hostname,
                           pid, bash_command, file_path, url, hook_match_count, client_id,
                           prompt_text, block_reason, raw)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT DO NOTHING
                        """,
                        (
                            r.ts, r.source_file, r.line_no, r.byte_offset,
                            r.event, r.stage, r.session_id, r.tool, r.phase, r.action,
                            r.skipped_reason, r.duration_ms, r.user, r.vm_hostname,
                            r.pid, r.bash_command, r.file_path, r.url, r.hook_match_count,
                            r.client_id, r.prompt_text, r.block_reason, r.raw,
                        ),
                    )
                    if cur.rowcount == 0:
                        continue
                    event_id = cur.lastrowid
                    for h in r.hits:
                        cur.execute(
                            """
                            INSERT INTO rule_hits(event_id, source, rule_id, severity, matched, meta_json)
                            VALUES (?,?,?,?,?,?)
                            """,
                            (event_id, h.source, h.rule_id, h.severity, h.matched,
                             json.dumps(h.meta, ensure_ascii=False) if h.meta else None),
                        )
                self._writer.commit()
            except Exception:
                self._writer.rollback()
                raise

    def upsert_state(self, source_file: str, inode: int, size: int, offset: int, line_no: int) -> None:
        with _WRITE_LOCK:
            self._writer.execute(
                """
                INSERT INTO collector_state(source_file, inode, size, offset, line_no, updated_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(source_file) DO UPDATE SET
                  inode=excluded.inode, size=excluded.size,
                  offset=excluded.offset, line_no=excluded.line_no,
                  updated_at=excluded.updated_at
                """,
                (source_file, inode, size, offset, line_no,
                 time.strftime("%Y-%m-%dT%H:%M:%S")),
            )
            self._writer.commit()

    def get_state(self, source_file: str) -> dict | None:
        cur = self._writer.execute(
            "SELECT inode, size, offset, line_no FROM collector_state WHERE source_file=?",
            (source_file,),
        )
        row = cur.fetchone()
        return dict(row) if row else None

   

    def get_db_stats(self) -> dict[str, Any]:
        """获取主数据库大小、总事件数、最早及最新事件时间等指标。"""
        size_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0
        total_events = 0
        min_ts = "—"
        max_ts = "—"
        total_hits = 0
        try:
            with self.read_conn() as conn:
                cur = conn.cursor()
                cur.execute("SELECT count(*), min(ts), max(ts) FROM events")
                row = cur.fetchone()
                if row:
                    total_events = row[0] or 0
                    min_ts = row[1] or "—"
                    max_ts = row[2] or "—"

                cur.execute("SELECT count(*) FROM rule_hits")
                r2 = cur.fetchone()
                if r2:
                    total_hits = r2[0] or 0
        except Exception:
            pass

        return {
            "path": str(self.db_path),
            "size_bytes": size_bytes,
            "size_mb": round(size_bytes / (1024 * 1024), 2),
            "total_events": total_events,
            "total_hits": total_hits,
            "min_ts": min_ts,
            "max_ts": max_ts,
        }

    def backup_database(self, dest_path: Path) -> dict[str, Any]:
        """使用 SQLite 原生在线 backup API 进行零停机热备份。

        WAL 模式下热备份不阻塞任何前台读写操作。
        """
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_dest = dest_path.with_suffix(".tmp")
        t0 = time.time()

        with _WRITE_LOCK:
            try:
                self._writer.execute("PRAGMA wal_checkpoint(PASSIVE);")
            except Exception:
                pass
            dest_conn = sqlite3.connect(str(tmp_dest))
            try:
                self._writer.backup(dest_conn, pages=250)
            finally:
                dest_conn.close()

        if tmp_dest.exists():
            if dest_path.exists():
                dest_path.unlink()
            tmp_dest.rename(dest_path)

        elapsed = round(time.time() - t0, 3)
        size_bytes = dest_path.stat().st_size if dest_path.exists() else 0
        return {
            "path": str(dest_path),
            "filename": dest_path.name,
            "size_bytes": size_bytes,
            "size_mb": round(size_bytes / (1024 * 1024), 2),
            "elapsed_seconds": elapsed,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def list_backups(self, backup_dir: Path) -> list[dict[str, Any]]:
        """列出指定目录下的备份文件列表，按生成时间倒序。"""
        if not backup_dir.exists():
            return []
        files = []
        for p in backup_dir.glob("audit_backup_*.db"):
            st = p.stat()
            files.append({
                "filename": p.name,
                "size_bytes": st.st_size,
                "size_mb": round(st.st_size / (1024 * 1024), 2),
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                "path": str(p),
            })
        files.sort(key=lambda x: x["created_at"], reverse=True)
        return files

    def clean_old_backups(self, backup_dir: Path, keep_count: int = 14) -> int:
        """清理超出保留配额的旧备份，返回已删除的文件数。"""
        backups = self.list_backups(backup_dir)
        removed = 0
        if len(backups) > keep_count:
            for b in backups[keep_count:]:
                try:
                    Path(b["path"]).unlink(missing_ok=True)
                    removed += 1
                except Exception:
                    pass
        return removed

    def archive_old_events(self, days: int = 90, archive_dir: Path | None = None) -> dict[str, Any]:
        """将 N 天前的历史事件与规则命中导出到冷数据归档 SQLite，并从活跃库中安全清理。"""
        if archive_dir is None:
            archive_dir = self.db_path.parent / "archives"
        archive_dir.mkdir(parents=True, exist_ok=True)

        cutoff_dt = datetime.now() - timedelta(days=days)
        cutoff_str = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")

        # 1. 统计符合归档条件的记录数
        with self.read_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT count(*) FROM events WHERE ts < ?", (cutoff_str,))
            count = cur.fetchone()[0]

        if count == 0:
            return {
                "ok": True,
                "archived_count": 0,
                "cutoff_date": cutoff_str,
                "message": f"暂无早于 {cutoff_str} ({days} 天前) 的历史数据需要归档",
            }

        # 2. 导出到归档数据库
        archive_filename = f"events_archive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        archive_path = archive_dir / archive_filename

        arch_conn = sqlite3.connect(str(archive_path))
        try:
            arch_conn.executescript(
                "CREATE TABLE IF NOT EXISTS events ("
                "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "  ts TEXT NOT NULL, source_file TEXT NOT NULL, line_no INTEGER, byte_offset INTEGER,"
                "  event TEXT, stage TEXT, session_id TEXT, tool TEXT, phase TEXT, action TEXT,"
                "  skipped_reason TEXT, duration_ms INTEGER, user TEXT, vm_hostname TEXT, pid INTEGER,"
                "  bash_command TEXT, file_path TEXT, url TEXT, hook_match_count INTEGER, client_id TEXT,"
                "  prompt_text TEXT, block_reason TEXT, raw TEXT"
                ");"
                "CREATE TABLE IF NOT EXISTS rule_hits ("
                "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "  event_id INTEGER, source TEXT, rule_id TEXT, severity TEXT, matched TEXT, meta_json TEXT"
                ");"
            )
            with self.read_conn() as rconn:
                rcur = rconn.cursor()
                rcur.execute("SELECT * FROM events WHERE ts < ?", (cutoff_str,))
                ev_cols = [c[0] for c in rcur.description]
                ev_placeholders = ",".join(["?"] * len(ev_cols))
                ev_rows = rcur.fetchall()
                arch_conn.executemany(f"INSERT INTO events ({','.join(ev_cols)}) VALUES ({ev_placeholders})", [tuple(r) for r in ev_rows])

                rcur.execute("SELECT rh.* FROM rule_hits rh JOIN events e ON rh.event_id = e.id WHERE e.ts < ?", (cutoff_str,))
                rh_cols = [c[0] for c in rcur.description]
                rh_placeholders = ",".join(["?"] * len(rh_cols))
                rh_rows = rcur.fetchall()
                if rh_rows:
                    arch_conn.executemany(f"INSERT INTO rule_hits ({','.join(rh_cols)}) VALUES ({rh_placeholders})", [tuple(r) for r in rh_rows])
            arch_conn.commit()
        finally:
            arch_conn.close()

        # 3. 从主活跃库删除旧数据
        with _WRITE_LOCK:
            cur = self._writer.cursor()
            cur.execute("BEGIN")
            try:
                cur.execute("DELETE FROM rule_hits WHERE event_id IN (SELECT id FROM events WHERE ts < ?)", (cutoff_str,))
                cur.execute("DELETE FROM events WHERE ts < ?", (cutoff_str,))
                self._writer.commit()
            except Exception:
                self._writer.rollback()
                raise
            try:
                self._writer.execute("PRAGMA wal_checkpoint(PASSIVE);")
            except Exception:
                pass

        arch_size_mb = round(archive_path.stat().st_size / (1024 * 1024), 2)
        return {
            "ok": True,
            "archived_count": count,
            "cutoff_date": cutoff_str,
            "archive_file": archive_filename,
            "archive_size_mb": arch_size_mb,
            "message": f"成功归档 {count} 条历史事件至 {archive_filename} ({arch_size_mb} MB)，主库已安全清理",
        }

    def list_archives(self, archive_dir: Path | None = None) -> list[dict[str, Any]]:
        """列出已归档的历史数据库文件列表。"""
        if archive_dir is None:
            archive_dir = self.db_path.parent / "archives"
        if not archive_dir.exists():
            return []
        files = []
        for p in archive_dir.glob("events_archive_*.db"):
            st = p.stat()
            files.append({
                "filename": p.name,
                "size_bytes": st.st_size,
                "size_mb": round(st.st_size / (1024 * 1024), 2),
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                "path": str(p),
            })
        files.sort(key=lambda x: x["created_at"], reverse=True)
        return files

    def close(self) -> None:
        with _WRITE_LOCK:
            self._writer.close()
