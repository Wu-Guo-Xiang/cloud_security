from __future__ import annotations

import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .db import Storage

CST = timezone(timedelta(hours=8))

_BACKUP_HOUR = 2   # 每天 02:00 (CST) 自动全量热备份
_ARCHIVE_HOUR = 3  # 每天 03:30 (CST) 自动归档90天前旧数据
_ARCHIVE_MINUTE = 30
_KEEP_BACKUP_COUNT = 14  # 保留最近 14 份备份
_DEFAULT_ARCHIVE_DAYS = 90  # 默认保留最近 90 天日志

_maint_thread: threading.Thread | None = None
_maint_stop = threading.Event()


def _log(msg: str) -> None:
    try:
        sys.stderr.write(f"[db-maintenance] {msg}\n")
    except UnicodeEncodeError:
        sys.stderr.buffer.write(f"[db-maintenance] {msg}\n".encode("utf-8", "replace"))


def _seconds_until_next_time(hour: int, minute: int = 0) -> float:
    now = datetime.now(CST)
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


def run_daily_backup(storage: Storage, backup_dir: Path | None = None) -> dict[str, Any]:
    """执行一次安全在线热备份，并自动清理超期旧备份。"""
    if backup_dir is None:
        backup_dir = storage.db_path.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)

    filename = f"audit_backup_{datetime.now(CST).strftime('%Y%m%d_%H%M%S')}.db"
    dest = backup_dir / filename
    _log(f"开始执行数据库在线热备份: {dest}...")
    res = storage.backup_database(dest)
    _log(f"备份完成: 大小 {res.get('size_mb')} MB, 耗时 {res.get('elapsed_seconds')}s")

    cleaned = storage.clean_old_backups(backup_dir, keep_count=_KEEP_BACKUP_COUNT)
    if cleaned > 0:
        _log(f"已自动清理 {cleaned} 份超期备份，保持最新 {_KEEP_BACKUP_COUNT} 份配额")
    res["cleaned_old_count"] = cleaned
    return res


def run_daily_archive(storage: Storage, days: int = _DEFAULT_ARCHIVE_DAYS, archive_dir: Path | None = None) -> dict[str, Any]:
    """执行一次历史事件冷数据归档与清理。"""
    _log(f"开始检查早于 {days} 天前的历史事件归档...")
    res = storage.archive_old_events(days=days, archive_dir=archive_dir)
    if res.get("archived_count", 0) > 0:
        _log(f"归档完成: {res.get('message')}")
    else:
        _log(f"归档检查完成: {res.get('message')}")
    return res


def start_db_maintenance_scheduler(storage: Storage, backup_dir: Path | None = None, archive_dir: Path | None = None) -> None:
    """启动数据库自动备份与归档守护线程。

    - 每天 02:00 (CST) 自动在线热备份，保留 14 天；
    - 每天 03:30 (CST) 自动归档 90 天前数据。
    """
    global _maint_thread
    if _maint_thread is not None and _maint_thread.is_alive():
        return

    if backup_dir is None:
        backup_dir = storage.db_path.parent / "backups"
    if archive_dir is None:
        archive_dir = storage.db_path.parent / "archives"

    def _loop():
        _log(f"自动运维调度器已启动: 每日 {_BACKUP_HOUR:02d}:00 执行热备份(保留 {_KEEP_BACKUP_COUNT} 份), 每日 {_ARCHIVE_HOUR:02d}:{_ARCHIVE_MINUTE:02d} 执行归档(保留 {_DEFAULT_ARCHIVE_DAYS} 天)")
        while not _maint_stop.is_set():
            # 计算到 02:00 的秒数和到 03:30 的秒数
            sec_backup = _seconds_until_next_time(_BACKUP_HOUR, 0)
            sec_archive = _seconds_until_next_time(_ARCHIVE_HOUR, _ARCHIVE_MINUTE)

            # 等待最近的一个时间点
            wait_s = min(sec_backup, sec_archive)
            # 最小步长限制在 30 秒，防止浮点偏差瞬间重触发
            wait_s = max(30.0, wait_s)

            if _maint_stop.wait(wait_s):
                return

            now = datetime.now(CST)
            # 如果在 02:00 ~ 02:05 之间，触发备份
            if now.hour == _BACKUP_HOUR and now.minute < 5:
                try:
                    run_daily_backup(storage, backup_dir)
                except Exception as e:
                    _log(f"自动备份异常: {e}")

            # 如果在 03:30 ~ 03:35 之间，触发归档
            if now.hour == _ARCHIVE_HOUR and 30 <= now.minute < 35:
                try:
                    run_daily_archive(storage, days=_DEFAULT_ARCHIVE_DAYS, archive_dir=archive_dir)
                except Exception as e:
                    _log(f"自动归档异常: {e}")

    _maint_stop.clear()
    _maint_thread = threading.Thread(target=_loop, name="db-maintenance-scheduler", daemon=True)
    _maint_thread.start()


def stop_db_maintenance_scheduler() -> None:
    """停止后台维护调度器。"""
    _maint_stop.set()
