"""claude_audit 辅助 CLI:`py -m claude_audit.cli <sub>`"""
from __future__ import annotations

import argparse
import json
import sys

from .config import load as load_config
from .detector import RuleEngine
from .storage import Storage
from .storage.models import EventRecord


def cmd_query(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    storage = Storage(cfg.database)
    conn = storage.read_conn()
    try:
        where = []
        params: list = []
        if args.tool:
            where.append("tool=?"); params.append(args.tool)
        if args.event:
            where.append("event=?"); params.append(args.event)
        if args.action:
            where.append("action=?"); params.append(args.action)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        rows = conn.execute(
            f"SELECT id, ts, event, tool, action, bash_command, file_path, url "
            f"FROM events {clause} ORDER BY id DESC LIMIT ?",
            tuple(params) + (args.limit,),
        ).fetchall()
        for r in rows:
            print(json.dumps(dict(r), ensure_ascii=False))
    finally:
        conn.close()
        storage.close()
    return 0


def cmd_rule_test(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    engine = RuleEngine(cfg.rules_dir)
    print(f"loaded {len(engine.rules)} rules from {cfg.rules_dir}")

    samples: list[EventRecord] = [
        EventRecord(ts="", source_file="cli", line_no=0, byte_offset=0,
                    event="PreToolUse", tool="Bash", bash_command="rm -rf /"),
        EventRecord(ts="", source_file="cli", line_no=0, byte_offset=0,
                    event="PreToolUse", tool="Bash", bash_command="curl https://webhook.site/abc"),
        EventRecord(ts="", source_file="cli", line_no=0, byte_offset=0,
                    event="PreToolUse", tool="Bash", bash_command="cat .env"),
        EventRecord(ts="", source_file="cli", line_no=0, byte_offset=0,
                    event="PreToolUse", tool="Read", file_path="C:/proj/.env"),
        EventRecord(ts="", source_file="cli", line_no=0, byte_offset=0,
                    event="PreToolUse", tool="WebFetch", url="https://192.168.1.1/admin"),
        EventRecord(ts="", source_file="cli", line_no=0, byte_offset=0,
                    event="PreToolUse", tool="Bash", bash_command="echo hello world"),
    ]
    for rec in samples:
        hits = engine.evaluate(rec)
        label = rec.bash_command or rec.file_path or rec.url or "(empty)"
        if hits:
            for h in hits:
                print(f"  HIT  [{h.severity:>8}] {h.rule_id:<35} <- {label}")
        else:
            print(f"  ---                                       <- {label}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="claude_audit.cli")
    p.add_argument("--config", default=None, help="config.yml 路径")
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("query", help="查询最近事件")
    q.add_argument("--tool")
    q.add_argument("--event")
    q.add_argument("--action")
    q.add_argument("--limit", type=int, default=20)
    q.set_defaults(func=cmd_query)

    r = sub.add_parser("rule", help="规则相关")
    rsub = r.add_subparsers(dest="rulecmd", required=True)
    rt = rsub.add_parser("test", help="用样例数据测试规则命中")
    rt.set_defaults(func=cmd_rule_test)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
