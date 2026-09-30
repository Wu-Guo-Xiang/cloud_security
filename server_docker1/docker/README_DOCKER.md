# claude_audit 服务端 Docker 部署

## 架构

```
[员工机 A] claude_audit_client.exe --+
[员工机 B] claude_audit_client.exe --|--HTTP POST /ingest--> [服务器: docker claude_audit] --> SQLite /data/audit.db
[员工机 C] claude_audit_client.exe --+                                                    \--> Web UI :8787
```

服务端只做两件事:

1. 接收员工机推来的 hook 日志 (`POST /ingest`)
2. 提供 Web UI 查询 (`GET /events`, `/alerts`, `/detail/...`)

**不**在服务端本地读日志文件 (`local_collector: false`)。

## 一、需要拷到服务器的文件

从仓库根目录 (`D:\cloud_security\`) 拷这三样到服务器,保持相对路径:

```
<server_dir>/
├── claude_audit/                 <- 整个服务端 python 包
│   ├── claude_audit/             <-   实际包代码
│   ├── requirements.txt
│   └── ... (config.yml 等,但会被容器 override)
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── config.docker.yml
└── .dockerignore                 <- 仓库根 (容器构建 context)
```

`scripts/` (hook 脚本)、`claude_audit/claude_audit_client/` (客户端)、`claude_audit/deploy/` (打包脚本)
**不需要**拷到服务器 —— `.dockerignore` 会自动排除。

### 打包命令 (在你 Windows 本机跑)

PowerShell:

```powershell
$staging = "D:\cloud_security\deploy_pkg\server_docker"
Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $staging | Out-Null

# 只拷需要的
Copy-Item -Recurse "D:\cloud_security\claude_audit"  "$staging\claude_audit"
Copy-Item -Recurse "D:\cloud_security\docker"        "$staging\docker"
Copy-Item          "D:\cloud_security\.dockerignore" "$staging\.dockerignore"

# 清理 pyc / db / 客户端零件 (不影响 build 但让包更小)
Get-ChildItem "$staging" -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
Remove-Item -Recurse -Force "$staging\claude_audit\claude_audit_client" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$staging\claude_audit\deploy"              -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$staging\claude_audit\data"                -ErrorAction SilentlyContinue

Compress-Archive -Path "$staging\*" `
                 -DestinationPath "D:\cloud_security\deploy_pkg\claude_audit_server_docker.zip" -Force
"OK: D:\cloud_security\deploy_pkg\claude_audit_server_docker.zip"
```

产物 `claude_audit_server_docker.zip` (~200KB) 就是要传到服务器上的。

## 二、服务器上的部署 (Linux)

### 前提

服务器上装好 Docker + Docker Compose Plugin:

```bash
# Ubuntu / Debian
curl -fsSL https://get.docker.com | sudo bash
sudo systemctl enable --now docker
sudo usermod -aG docker $USER   # 加完要重新登录
docker compose version           # 确认 compose 可用
```

### 部署

```bash
# 1. 传 zip 到服务器,解压到 /opt/claude_audit
sudo mkdir -p /opt/claude_audit
sudo chown $USER: /opt/claude_audit
cd /opt/claude_audit
unzip ~/claude_audit_server_docker.zip -d .

# 2. (可选) 编辑 config,主要看要不要设 ingest.token
nano docker/config.docker.yml

# 3. 拷出来作为容器挂载的 config,方便以后改不用 rebuild
cp docker/config.docker.yml docker/config.yml

# 4. 启动
cd docker
docker compose up -d --build

# 5. 看启动日志
docker compose logs -f
```

看到类似:

```
INFO:     Uvicorn running on http://0.0.0.0:8787
[main] loaded N rules from /app/claude_audit/detector/rules
[main] local_collector=false; ingest-only mode (POST /ingest)
```

就是起来了。

### 验证

```bash
# 服务器本机
curl -i http://127.0.0.1:8787/

# 从员工机 (确认防火墙 / 安全组开了 8787)
curl -i http://<服务器内网IP>:8787/
```

## 三、员工机客户端指向服务器

员工机装 `claude_audit_setup.exe` 时,"服务端 URL" 那栏填:

```
http://<服务器内网IP>:8787
```

如果你在 config.docker.yml 里设了 `ingest.token`,那客户端的 `client.yml` 里也要填**同一个** token,不然 401。

装完客户端后台跑,`%LOCALAPPDATA%\claude_audit\client\agent.log` 应该有:

```
push OK n=... bytes=...
```

## 四、常用运维

| 场景 | 命令 |
|---|---|
| 查看实时日志 | `docker compose -f /opt/claude_audit/docker/docker-compose.yml logs -f` |
| 重启 | `docker compose -f /opt/claude_audit/docker/docker-compose.yml restart` |
| 改 config 后生效 | 改 `/opt/claude_audit/docker/config.yml` -> `docker compose restart` |
| 代码更新 | 传新 zip 覆盖 -> `docker compose up -d --build` |
| 停止并删除 | `docker compose down` (数据还在 `/opt/claude_audit/docker/data/`) |
| 备份 DB | `cp /opt/claude_audit/docker/data/audit.db* /backup/` (含 -wal/-shm) |
| 进容器 debug | `docker exec -it claude_audit bash` -> `sqlite3 /data/audit.db` |

## 五、防火墙 / 反向代理

### 只在内网开放

```bash
# ufw 示例: 只允许员工内网段
sudo ufw allow from 192.168.0.0/16 to any port 8787
```

### 用 nginx / caddy 加 HTTPS (员工在公网时必须)

Caddy 示例 (`/etc/caddy/Caddyfile`):

```
audit.yourcorp.com {
    reverse_proxy 127.0.0.1:8787
}
```

然后员工客户端 URL 填 `https://audit.yourcorp.com`,并**务必**在 config.docker.yml 里设 `ingest.token`。

## 六、常见问题

| 现象 | 原因 | 解决 |
|---|---|---|
| `docker compose up` 报 `pull access denied` | 网络问题拉不到 python:3.12-slim | 换镜像源: `docker pull registry.cn-hangzhou.aliyuncs.com/library/python:3.12-slim` 然后 tag 成 `python:3.12-slim` |
| 容器起来但 curl 8787 拒绝连接 | 防火墙 / 安全组没开 | `sudo ufw status`,云上还要开安全组 |
| 员工客户端 push 报 401 | client.yml 的 token != config.docker.yml 的 token | 对齐 token,或 config 里清空 token |
| 员工客户端 push 报 timeout | 服务器 IP / 端口填错 或 网络不通 | 员工机上 `Test-NetConnection <server_ip> -Port 8787` |
| 容器一直 restart | 看 `docker compose logs` 里的 python traceback | 常见是 config.yml 语法错 |
| SQLite `database is locked` | 容器内多进程写? 目前单进程 uvicorn 不会 | 如果真出现,把 config.yml 里 web 换 workers=1 |

## 七、后续切 MySQL

现在还是 SQLite,DB 在 `/opt/claude_audit/docker/data/audit.db`。以后切 MySQL 时:

1. compose 加一个 `mysql:8.0` service
2. 改 config 里 `database:` 为 MySQL DSN
3. 改 `storage/db.py` 用 PyMySQL
4. 迁移方案在另一个文档里
