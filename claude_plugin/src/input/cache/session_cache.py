"""Session 级缓存读写。

设计要点：
  - 单文件 per session：{paths.session_cache}/{session_id}.pickle
  - 文件内容是一个 dict：{cache_key: payload, ...}
  - 原子写：写 .tmp 再 rename
  - 读取失败、版本不一致：当作 miss，不抛异常
  - session_id 必须经过 sanitize（防 path traversal）

不持久化跨 Session 数据：会话结束 Hook 直接 rm 整个文件。
"""
from __future__ import annotations

import os
import pickle
import re
import tempfile
from pathlib import Path
from typing import Any

from config.paths import paths


_SAFE_SESSION_ID = re.compile(r"[^A-Za-z0-9_\-]")


class SessionCache:
    """Session 内的扫描结果缓存。

    所有方法 fail-safe：任何异常都视为 miss，不向上抛。
    """

    def __init__(self, session_id: str):
        self.session_id = _safe_id(session_id)
        self.path = paths.session_cache / f"{self.session_id}.pickle"
        self._data: dict[str, Any] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        try:
            if self.path.exists():
                with self.path.open("rb") as f:
                    obj = pickle.load(f)
                if isinstance(obj, dict):
                    self._data = obj
        except Exception:
            self._data = {}

    def save(self) -> None:
        """原子写（tmp + rename）；失败静默吞掉。"""
        if not self._dirty:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(
                prefix=f".{self.session_id}.",
                suffix=".tmp",
                dir=str(self.path.parent),
            )
            try:
                with os.fdopen(fd, "wb") as f:
                    pickle.dump(self._data, f, protocol=pickle.HIGHEST_PROTOCOL)
                os.replace(tmp_name, self.path)
                self._dirty = False
            except Exception:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
        except Exception:
            pass

    # --- 扫描结果缓存 -------------------------------------------------

    def get_scan(self, key: str) -> Any | None:
        if not key:
            return None
        return self._data.get(key)

    def put_scan(self, key: str, payload: Any) -> None:
        if not key:
            return
        self._data[key] = payload
        self._dirty = True


def _safe_id(session_id: str) -> str:
    cleaned = _SAFE_SESSION_ID.sub("_", session_id or "")
    return cleaned[:80] or "unknown"


def build_cache_key(
    content_sha: str,
    rules_version: str,
    wordlib_version: str,
    llm_version: str = "",
    mode: str = "",
) -> str:
    """key = content_sha[:16] + "|" + rules_version + "|" + wordlib_version
            [+ "|" + llm_version] [+ "|m:" + mode]

    mode 必须编入键:UPS 走 mode=ups 会启用 PASSWORD 等扩展类目,
    与 mode=default 的 L2 结果不一致;同 session 内同 prompt 先 Read 再 UPS,
    若不带 mode 会命中 default 的缓存导致 PASSWORD 漏检。
    """
    if not content_sha:
        return ""
    base = f"{content_sha[:16]}|{rules_version}|{wordlib_version}"
    if llm_version:
        base = f"{base}|{llm_version}"
    if mode:
        base = f"{base}|m:{mode}"
    return base
