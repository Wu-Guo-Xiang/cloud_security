"""output 模块独立日志。

写到 {paths.logs}/output_scanner.jsonl,与 input_scanner.jsonl 分流便于查问题。
复用 lib/logger 的 user 解析,但不复用 _LOG_FILE(那个写死到 input_scanner.jsonl)。
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
from typing import Any

from config.paths import paths


_LOG_FILE = paths.logs / "output_scanner.jsonl"
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
        sys.stderr.write(f"[output_logger] 写日志失败: {exc}\n")
