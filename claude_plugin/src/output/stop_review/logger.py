"""Stop-review 独立日志。

与 output_scanner.jsonl 分开写:
  - stop_review 一次调用可能几十秒 + 花钱,和"命中数"一起看会污染 output_scanner 的分位
  - 独立文件方便按 session_id grep 一次会话完整轨迹
  - 也方便未来做 cost 面板

复用 output_logger 的字段(timestamp/user/host/pid)。
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
from typing import Any

from config.paths import paths


_LOG_FILE = paths.logs / "stop_review.jsonl"
_HOSTNAME = socket.gethostname()


def _resolve_user() -> tuple[str, str]:
    if sys.platform == "win32":
        try:
            import win32api  # type: ignore[import-not-found]
            return win32api.GetUserNameEx(2), "token"
        except Exception:
            pass
    env = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    return env, ("env" if env else "")


_USER, _USER_SOURCE = _resolve_user()


def log(entry: dict[str, Any]) -> None:
    full = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
        "user": _USER,
        "user_source": _USER_SOURCE,
        "vm_hostname": _HOSTNAME,
        "pid": os.getpid(),
        **entry,
    }
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(full, ensure_ascii=False) + "\n")
    except Exception as exc:  # pragma: no cover
        sys.stderr.write(f"[stop_review_logger] failed: {exc}\n")
