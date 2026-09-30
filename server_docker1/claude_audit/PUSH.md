# 推送链路改造 (PUSH mode)

> 记录 2026-07-09 这轮把 `claude_audit` 从"服务端本地读盘"改造成"客户端 Agent 定时 POST"的全部工作。
> 目标: 员工机开机自启常驻 → 定时把 hook 日志推到中心平台;后续 30+ 人在 Linux 服务器上部署时只改地址与 token。
> 当前阶段: **只跑我自己一台机**。

---

## 1. 架构

```
┌────────────────────────┐      HTTPS/HTTP           ┌────────────────────────────┐
│  员工机 (Windows)       │                            │  中心平台 (先本机,后 Linux)  │
│                        │                            │                            │
│  Claude Code hooks     │                            │   FastAPI  (uvicorn)       │
│   ├─ input_scanner ──┐ │                            │    ├─ POST /ingest         │
│   ├─ output_scanner ─┤ │                            │    ├─ GET  /events         │
│   └─ stop_review ────┘ │                            │    ├─ GET  /alerts         │
│         │              │                            │    └─ GET  /stats          │
│         ▼              │                            │           │                │
│  D:\...\test\logs\*.jsonl                           │       RuleEngine (YAML)    │
│         │              │                            │           │                │
│         ▼              │  NDJSON /ingest            │       SQLite (WAL)         │
│  claude_audit_client   │────POST X-Client-Id───────▶│    events + rule_hits      │
│   (pythonw 后台常驻)    │  X-Ingest-Token (可选)     │    + client_id 维度         │
│    tick=15s            │                            │                            │
│   state.json 记 offset │                            │                            │
└────────────────────────┘                            └────────────────────────────┘
```

关键约束:
- **服务端不再主动读盘** (`local_collector: false`),数据只从 `/ingest` 进
- **Agent 完全无状态依赖 server**,断网期间累积 offset,恢复后接着推
- **规则引擎在 server 侧跑** — client 只做搬运,不参与判定,方便集中升级规则

---

## 2. 本轮新增 / 改动

### 服务端 (`claude_audit/`)

| 文件 | 变更 |
| --- | --- |
| `storage/models.py` | `EventRecord` 新增 `client_id: str \| None = None` |
| `storage/db.py` | `insert_events` INSERT 带 `client_id`;`INSERT OR IGNORE` → `ON CONFLICT DO NOTHING` |
| `storage/migrations/001_init.sql` | 移除表内 `UNIQUE(source_file, line_no)`(改由 migration 002 提供复合索引) |
| `storage/migrations/002_client_id.sql` | **新增**:`ALTER TABLE events ADD client_id`;复合唯一索引 `(coalesce(client_id,''), source_file, line_no)` |
| `config.py` + `config.yml` | 新增 `local_collector: bool` 和 `ingest: {enabled, token}` |
| `api/main.py` | **新增** `POST /ingest` 端点;`create_app(cfg, storage, engine)` 签名增加 engine 参数 |
| `__main__.py` | 按 `local_collector` flag 决定是否起 backfill + tail |

### 客户端 (`claude_audit_client/`,新增独立包)

| 文件 | 说明 |
| --- | --- |
| `__init__.py` | 包声明 |
| `config.py` | 加载 `client.yml`;自动用 `hostname-username` 作为 client_id |
| `state.py` | 本地进度文件:tmp+`os.replace` 原子写,防中途崩掉写坏 |
| `agent.py` | 核心:`_drain_source` + `_post_ndjson` + `run_forever`(interval loop) |
| `__main__.py` | `python -m claude_audit_client [--config X] [--once]` |

### 配置与启动脚本 (根目录)

| 文件 | 说明 |
| --- | --- |
| `client.yml` | client agent 配置 |
| `start_server.bat` | 前台跑 server(窗口即日志) |
| `start_client.bat` | 前台跑 client(debug 用,保留窗口看日志) |
| `start_client.vbs` | 无窗口后台启动,配合 Startup 目录做开机自启 |

### 数据 / 测试

| 文件 | 说明 |
| --- | --- |
| `data/push_smoke.py` | 端到端 smoke test:伪造 input_scanner 事件 → `--once` 推 → 校验 DB 落库 |
| `data/audit.db` | SQLite 数据库(WAL + FTS5) |
| `data/client_state.json` | client agent 运行时写(每源一条 offset) |
| `data/client_agent.log` | agent 运行日志 |

---

## 3. `POST /ingest` 协议

### 请求

- **Method**: POST
- **URL**: `/ingest`
- **Content-Type**: `application/x-ndjson`
- **Headers**:
  - `X-Client-Id` — 上报方标识(hostname-username 或人工指定)
  - `X-Ingest-Token` — 可选,当 server 端 `ingest.token` 非空时必须匹配

### Body (NDJSON,每行一个 envelope)

```json
{"source_file":"D:\\cloud_security\\test\\logs\\input_scanner.jsonl","line_no":42,"byte_offset":15680,"raw":"{\"timestamp\":\"2026-07-09T11:53:30\",\"event\":\"PreToolUse\",\"tool\":\"Bash\",...}"}
```

- `source_file` — 原始 jsonl 的绝对路径(server 只做溯源展示用)
- `line_no` / `byte_offset` — 与 client 本地一致,用作幂等键
- `raw` — 原始 hook 输出的完整 JSON 字符串(server 侧再 parse)

### 响应

```json
{"ok": true, "accepted": 2, "skipped": 0, "client_id": "hostname-user"}
```

### 幂等性

复合唯一索引 `(coalesce(client_id,''), source_file, line_no)` 保证:
- 同一 client 重推同 (file, line) → 忽略
- 不同 client 推同 (file, line) → 各自入库(不同 client_id)
- 老数据 `client_id=NULL` 与新推送 `client_id='xxx'` 不冲突

---

## 4. 启动流程

### 服务端

```bat
cd D:\cloud_security\claude_audit
py -3 -m pip install -r requirements.txt   :: 首次
py -3 -m claude_audit
```

或双击 `start_server.bat`。默认监听 `0.0.0.0:8787`;浏览器打开 http://127.0.0.1:8787/events。

### 客户端 (前台 debug)

```bat
D:\cloud_security\claude_audit\start_client.bat
```

窗口里会看到:
```
INFO agent up: server=http://127.0.0.1:8787 client_id=DESKTOP-XXX-wuguoxiang interval=15s sources=3
INFO pushed N lines from D:\...\input_scanner.jsonl -> offset=NNNN
INFO tick done: pushed=N bytes=NNN errors=0
```

### 客户端 (开机自启,无窗口)

1. `Win+R` → 输入 `shell:startup` → 打开当前用户的 Startup 文件夹
2. 把 `D:\cloud_security\claude_audit\start_client.vbs` 的**快捷方式**拖到该文件夹
   (或直接把 .vbs 文件本身拖进去)
3. 下次登录:`pythonw.exe` 后台常驻,无控制台窗口
4. 排错查 `data\client_agent.log`
5. 手动停:任务管理器 → 结束 `pythonw.exe`

---

## 5. 配置说明

### server: `config.yml`

```yaml
local_collector: false           # true=保留本地读盘;false=只吃 POST /ingest

# local_collector=false 时下列 3 项可留空,不影响运行
log_sources: [ ... ]
watch_dir: ...

database: D:\cloud_security\claude_audit\data\audit.db
rules_dir: D:\cloud_security\claude_audit\claude_audit\detector\rules

web:
  host: 0.0.0.0                  # 让局域网其他机也能推
  port: 8787

ingest:
  enabled: true
  token: ""                      # 生产环境务必填 32+ 位随机串
```

### client: `client.yml`

```yaml
server_url: http://127.0.0.1:8787   # 本机自测;上 Linux 后改成 http://内网IP:8787
client_id: ""                       # 留空自动 hostname-username
token: ""                           # 与 server 端 ingest.token 保持一致

interval_seconds: 15                # 推送节奏
batch_size: 500                     # 单源单轮最多多少行
max_bytes_per_push: 2097152         # 2MB
timeout_seconds: 10

log_sources:
  - D:\cloud_security\test\logs\input_scanner.jsonl
  - D:\cloud_security\test\logs\output_scanner.jsonl
  - D:\cloud_security\test\logs\stop_review.jsonl

state_file: D:\cloud_security\claude_audit\data\client_state.json
log_file:   D:\cloud_security\claude_audit\data\client_agent.log
```

---

## 6. 端到端验证结果

```
[smoke] before total_events=11774
[smoke] agent stderr: pushed 2 lines from ...input_scanner.jsonl -> offset=468
[smoke] after  total_events=11776 (delta=2)
```

DB 抽查:
```
id=11775  tool=Bash  client_id=smoke-smoke-1783569210  bash_command=echo smoke-test-hello
id=11776  tool=Read  client_id=smoke-smoke-1783569210  file_path=D:/cloud_security/README.md

client_id 分布:
  NULL                   : 11774   (历史 backfill 数据)
  smoke-smoke-...        :     2   (本次 push)
```

复跑 `py -3 data/push_smoke.py` 可复现。

---

## 7. 安全说明

- **TLS**:agent 走 `urllib.request.urlopen` 默认信任链,代码里没有关闭校验的开关。
  自签证书场景请把公司 CA 加入系统 trust store,不要改代码。
- **token 鉴权**:目前 `ingest.token=""` 是无鉴权,仅适用于本机 loopback。
  上 Linux 前:server 与所有 client 同步 32+ 位随机串。
- **敏感字段**:hook 日志本身可能带命令行/文件路径(SSH key、`.env`、API key),
  DB 里只存热字段与 `byte_offset` 指针,原文仍在源机;上 Linux 后 agent 会把原文推过去,请对 server 磁盘做全盘加密。
- **未决:凭证泄露风险**:上一轮 audit 在 `C:\Users\wuguoxiang\.claude\settings.json:3`
  发现硬编码 API key(关联网关 `192.168.3.124:4000`),**尚未轮换**,请尽快处理。
  完整值参考 audit DB 中 rule_id=`cred_bash_leaks_api_key` 的最新命中。

---

## 8. 下一步 (未做)

- [ ] 上 Linux server:改 `config.yml` 里 host/db 路径 + 生成 token,client.yml 同步
- [ ] 员工机 rollout:打包成 zip(含 py 依赖 wheel)或做成 msi
- [ ] server 端加 `client_id` 维度筛选(events 页 / alerts 页各加一个下拉)
- [ ] Prometheus /metrics 端点(agent 侧 push 计数、失败计数、延迟)
- [ ] agent 失败重试的指数退避(目前是简单地"下轮再试")
- [ ] 大文件保护:当单文件累积到 GB 级时限制单轮扫描范围
- [ ] 关闭事件 (`SIGTERM` / logout) 时的优雅退出,先 flush 一次再退
