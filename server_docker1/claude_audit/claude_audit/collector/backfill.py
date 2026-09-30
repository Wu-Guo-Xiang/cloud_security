from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Iterable

from ..detector.engine import RuleEngine
from ..storage import Storage
from ..storage.models import EventRecord
from .parsers import parse_line


BATCH = 500


def _iter_records_from_file(path: Path, start_offset: int, start_line: int) -> Iterable[EventRecord]:
    with path.open("rb") as f:
        f.seek(start_offset)
        line_no = start_line
        while True:
            offset = f.tell()
            raw = f.readline()
            if not raw:
                break
            line_no += 1
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                continue
            rec = parse_line(text, str(path), line_no, offset)
            if rec is not None:
                yield rec
    return


def _apply_engine(records: list[EventRecord], engine: RuleEngine) -> None:
    for r in records:
        engine_hits = engine.evaluate(r)
        if engine_hits:
            r.hits.extend(engine_hits)


def run(sources: list[Path], storage: Storage, engine: RuleEngine, log=None) -> None:
    """一次性回填每个 source 里从 state.offset 到文件尾的所有行。"""
    log = log or (lambda s: sys.stderr.write(s + "\n"))
    for src in sources:
        if not src.exists():
            log(f"[backfill] skip missing {src}")
            continue
        try:
            st = os.stat(src)
        except OSError as e:
            log(f"[backfill] stat failed {src}: {e}")
            continue

        state = storage.get_state(str(src)) or {"inode": 0, "size": 0, "offset": 0, "line_no": 0}
        cur_inode = st.st_ino if os.name != "nt" else 0
        # 文件被截断或轮转:从头开始
        if st.st_size < state["size"] or (cur_inode and state["inode"] and cur_inode != state["inode"]):
            log(f"[backfill] {src.name} truncated/rotated, restart from 0")
            state = {"inode": cur_inode, "size": 0, "offset": 0, "line_no": 0}

        if state["offset"] >= st.st_size:
            log(f"[backfill] {src.name} up-to-date (offset={state['offset']})")
            continue

        log(f"[backfill] {src.name}: offset {state['offset']} → {st.st_size} ({st.st_size - state['offset']} bytes)")
        batch: list[EventRecord] = []
        last_offset = state["offset"]
        last_line = state["line_no"]
        total = 0
        for rec in _iter_records_from_file(src, state["offset"], state["line_no"]):
            batch.append(rec)
            last_offset = rec.byte_offset
            last_line = rec.line_no
            if len(batch) >= BATCH:
                _apply_engine(batch, engine)
                storage.insert_events(batch)
                total += len(batch)
                batch.clear()
        if batch:
            _apply_engine(batch, engine)
            storage.insert_events(batch)
            total += len(batch)

        # 更新 state 为文件末尾(即使最后一行是空)
        st2 = os.stat(src)
        end_offset = st2.st_size
        storage.upsert_state(str(src), cur_inode, st2.st_size, end_offset, last_line)
        log(f"[backfill] {src.name}: inserted {total} records, offset now {end_offset}")
