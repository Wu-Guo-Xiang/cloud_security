# claude_audit

Claude Code hook 日志审计平台(一期)。

- 采集 `D:\cloud_security\test\logs\*.jsonl`(input_scanner / output_scanner / stop_review)
- SQLite (WAL) 存储,原文冗存(数据库只存热字段与 byte_offset 指针)
- FastAPI + Jinja + HTMX 单页面板
- YAML 规则引擎补 hook 之外的审计视角

## 启动

```
cd D:\cloud_security\claude_audit
py -m pip install -r requirements.txt
py -m claude_audit
```

浏览器打开 http://127.0.0.1:8787/events

## CLI

```
py -m claude_audit.cli rule test  # 用样例数据测规则
py -m claude_audit.cli query --tool Bash --limit 20
```
