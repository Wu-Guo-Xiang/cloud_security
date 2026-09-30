from __future__ import annotations

import signal
import sys
import threading

import uvicorn

from .api import create_app
from .collector import backfill, tail
from .config import load as load_config
from .detector import RuleEngine
from .storage import Storage


def main() -> None:
    cfg = load_config()
    storage = Storage(cfg.database)
    storage.migrate()

    engine = RuleEngine(cfg.rules_dir)
    sys.stderr.write(f"[main] loaded {len(engine.rules)} rules from {cfg.rules_dir}\n")

    stop_event = threading.Event()
    tail_thread: threading.Thread | None = None

    if cfg.local_collector:
        sys.stderr.write("[main] local_collector=true; running backfill + tail\n")
        backfill.run(cfg.log_sources, storage, engine)
        tail_thread = threading.Thread(
            target=tail.run,
            args=(cfg.watch_dir, cfg.log_sources, storage, engine, stop_event),
            name="collector-tail",
            daemon=True,
        )
        tail_thread.start()
    else:
        sys.stderr.write("[main] local_collector=false; ingest-only mode (POST /ingest)\n")

    def _shutdown(*_a):
        sys.stderr.write("[main] shutting down\n")
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    try:
        signal.signal(signal.SIGTERM, _shutdown)
    except (AttributeError, ValueError):
        pass

    app = create_app(cfg, storage, engine)
    try:
        uvicorn.run(app, host=cfg.web.host, port=cfg.web.port, log_level="info")
    finally:
        stop_event.set()
        if tail_thread is not None:
            tail_thread.join(timeout=6)
        storage.close()


if __name__ == "__main__":
    main()
