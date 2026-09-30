"""Stop-review baseline 存取 — session_id + 文件路径 → 原始内容快照。

在 PreToolUse(Write/Edit/MultiEdit/NotebookEdit)时把当前磁盘内容抓一份存起来,
Stop 阶段再用 baseline vs 当前磁盘生成 unified diff 喂给 LLM。

目录布局:
  {security_script_dir}/../.claude/stop_review_baseline/
      <session_id>/
          <hash>.json     # {"path": "...", "existed": bool, "content": "..."}

设计要点:
  - 单文件 > 1MB / 二进制 → 记录一条"skipped=true"的 sentinel,不存内容(diff 阶段跳过)
  - 首次改动才存;同一 session 内同一文件多次改动只保留最早的原始态(反映"本轮起点")
  - 会话结束(Stop hook)完成后删除本 session 目录;超过 24h 的僵尸目录也一并清理
  - 一切失败静默(fail-OPEN),PreToolUse 主链路已由 input_scanner 保护,不允许再抛
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from config.paths import paths

# baseline 目录基于 paths.yml 的 security_script_dir 派生,不再硬编码
_BASELINE_ROOT = paths.security_script_dir.parent / ".claude" / "stop_review_baseline"

_MAX_BYTES = 1 * 1024 * 1024   # 1MB — 与 output_scanner extractor 对齐
_BINARY_SNIFF = 8192
_ZOMBIE_TTL_SECONDS = 24 * 3600


@dataclass(frozen=True)
class BaselineEntry:
    """Stop 阶段读回的一条快照记录。"""
    file_path: str
    existed: bool
    content: str
    skipped_reason: str = ""   # 非空表示 diff 阶段应跳过


def _session_dir(session_id: str) -> Path:
    """规范化 session_id 防路径穿越:只保留字母数字下划线短横线。"""
    safe = "".join(c for c in session_id if c.isalnum() or c in ("-", "_"))
    if not safe:
        safe = "_no_session"
    return _BASELINE_ROOT / safe[:64]


def _file_key(file_path: str) -> str:
    """路径 hash 做文件名(避免 Windows 路径分隔符/长度问题)。"""
    norm = str(Path(file_path).resolve()).lower()
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


def _read_disk_text(p: Path) -> tuple[str, str]:
    """(text, skipped_reason)。skipped_reason 非空表示别存内容,只留 sentinel。"""
    try:
        size = p.stat().st_size
    except OSError as exc:
        return "", f"stat_failed:{exc}"
    if size == 0:
        return "", ""    # 空文件不算 skip,存空串
    if size > _MAX_BYTES:
        return "", "too_large"
    try:
        with p.open("rb") as f:
            head = f.read(_BINARY_SNIFF)
            if b"\x00" in head:
                return "", "binary"
            rest = f.read(max(0, _MAX_BYTES - _BINARY_SNIFF))
    except OSError as exc:
        return "", f"read_failed:{exc}"
    try:
        return (head + rest).decode("utf-8", errors="replace"), ""
    except Exception:
        return (head + rest).decode("latin-1", errors="replace"), ""


def capture(session_id: str, file_path: str) -> str:
    """把 file_path 的当前磁盘态存到 baseline;返回状态串给日志用。

    幂等:同一 session 同一文件重复调用只保留首次(保留"本轮起点")。
    """
    if not session_id or not file_path:
        return "no_key"
    try:
        p = Path(file_path)
        key = _file_key(file_path)
        sess = _session_dir(session_id)
        sess.mkdir(parents=True, exist_ok=True)
        target = sess / f"{key}.json"
        if target.exists():
            return "already_captured"

        if not p.exists():
            payload = {
                "path": str(p),
                "existed": False,
                "content": "",
                "captured_at": int(time.time()),
            }
        else:
            text, skipped = _read_disk_text(p)
            payload = {
                "path": str(p),
                "existed": True,
                "content": text if not skipped else "",
                "skipped_reason": skipped,
                "captured_at": int(time.time()),
            }

        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, target)
        return "captured" if payload.get("existed") else "captured_new_file"
    except Exception as exc:  # pragma: no cover
        return f"capture_failed:{type(exc).__name__}"


def load_session(session_id: str) -> list[BaselineEntry]:
    """Stop 阶段读出该 session 所有 baseline,顺序无关。"""
    sess = _session_dir(session_id)
    if not sess.exists():
        return []
    out: list[BaselineEntry] = []
    for f in sess.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        out.append(BaselineEntry(
            file_path=str(data.get("path", "")),
            existed=bool(data.get("existed", False)),
            content=str(data.get("content", "")),
            skipped_reason=str(data.get("skipped_reason", "")),
        ))
    return out


def clear_session(session_id: str) -> None:
    """Stop 完成后清理本次 session 目录。失败静默。"""
    sess = _session_dir(session_id)
    if not sess.exists():
        return
    try:
        for f in sess.iterdir():
            try:
                f.unlink()
            except OSError:
                pass
        sess.rmdir()
    except OSError:
        pass


def sweep_zombies() -> int:
    """清理 24h 前遗留的僵尸 session 目录;返回清理数量。"""
    if not _BASELINE_ROOT.exists():
        return 0
    cleaned = 0
    now = time.time()
    try:
        for d in _BASELINE_ROOT.iterdir():
            if not d.is_dir():
                continue
            try:
                mtime = d.stat().st_mtime
            except OSError:
                continue
            if now - mtime <= _ZOMBIE_TTL_SECONDS:
                continue
            for f in d.iterdir():
                try:
                    f.unlink()
                except OSError:
                    pass
            try:
                d.rmdir()
                cleaned += 1
            except OSError:
                pass
    except OSError:
        pass
    return cleaned
