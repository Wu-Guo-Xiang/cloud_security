from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from ..detector.engine import RuleEngine
from ..storage import Storage
from ..storage.models import EventRecord
from .parsers import parse_line


BATCH = 200
FLUSH_INTERVAL_S = 2.0


class _Tailer:
    """维护一组 (source_file → offset) 状态,收到 modified 事件就 drain 到 EOF。"""

    def __init__(self, sources: list[Path], storage: Storage, engine: RuleEngine, log=None):
        self.sources = {str(p.resolve()): p for p in sources}
        self.storage = storage
        self.engine = engine
        self.log = log or (lambda s: sys.stderr.write(s + "\n"))
        self._lock = threading.Lock()

    def _drain(self, src: Path) -> None:
        key = str(src.resolve())
        if key not in self.sources:
            return
        with self._lock:
            try:
                st = os.stat(src)
            except OSError:
                return
            state = self.storage.get_state(str(src)) or {"inode": 0, "size": 0, "offset": 0, "line_no": 0}
            cur_inode = st.st_ino if os.name != "nt" else 0
            if st.st_size < state["size"] or (cur_inode and state["inode"] and cur_inode != state["inode"]):
                self.log(f"[tail] {src.name} rotated/truncated, restart")
                state = {"inode": cur_inode, "size": 0, "offset": 0, "line_no": 0}
            if state["offset"] >= st.st_size:
                return

            batch: list[EventRecord] = []
            last_line = state["line_no"]
            last_offset = state["offset"]
            with src.open("rb") as f:
                f.seek(state["offset"])
                while True:
                    offset = f.tell()
                    raw = f.readline()
                    if not raw:
                        break
                    last_line += 1
                    text = raw.decode("utf-8", errors="replace")
                    rec = parse_line(text, str(src), last_line, offset)
                    last_offset = offset + len(raw)
                    if rec is None:
                        continue
                    hits = self.engine.evaluate(rec)
                    if hits:
                        rec.hits.extend(hits)
                    batch.append(rec)
                    if len(batch) >= BATCH:
                        self.storage.insert_events(batch)
                        batch.clear()
            if batch:
                self.storage.insert_events(batch)
            st2 = os.stat(src)
            self.storage.upsert_state(str(src), cur_inode, st2.st_size, last_offset, last_line)

    def drain_all(self) -> None:
        for p in self.sources.values():
            self._drain(p)


class _Handler(FileSystemEventHandler):
    def __init__(self, tailer: _Tailer):
        self.tailer = tailer

    def _maybe_drain(self, path: str) -> None:
        p = Path(path).resolve()
        if str(p) in self.tailer.sources:
            self.tailer._drain(p)

    def on_modified(self, event):
        if not event.is_directory:
            self._maybe_drain(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._maybe_drain(event.src_path)


def run(watch_dir: Path, sources: list[Path], storage: Storage, engine: RuleEngine,
        stop_event: threading.Event, log=None) -> None:
    tailer = _Tailer(sources, storage, engine, log)
    observer = Observer()
    observer.schedule(_Handler(tailer), str(watch_dir), recursive=False)
    observer.start()
    log = log or (lambda s: sys.stderr.write(s + "\n"))
    log(f"[tail] watching {watch_dir}")
    try:
        while not stop_event.is_set():
            # 兜底轮询:某些 Windows 场景 watchdog 事件可能丢
            tailer.drain_all()
            stop_event.wait(FLUSH_INTERVAL_S)
    finally:
        observer.stop()
        observer.join(timeout=5)
        log("[tail] stopped")
