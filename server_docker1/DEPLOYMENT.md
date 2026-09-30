# 企业级 AI 审计与安全管控平台 · 服务器部署指南

本文档指导如何将 `server_docker1` 完整部署到目标服务器（IP: `102.168.3.117`），包含 **Cloud Security AI 日志监控审计主平台 (8787)** 以及 **GLM 后端实时性能监控服务 (8790)**。

---

## 一、部署前确认与端口规划

### 1. 服务与端口规划
| 服务名称 | 监听端口 | 说明 | 访问地址 |
| :--- | :--- | :--- | :--- |
| **Cloud Security AI 日志审计主平台** | **8787** | Web 监控平台、策略分发、客户端日志上报网关 (`/ingest`) | `http://102.168.3.117:8787` |
| **GLM 推理实时监控服务** | **8790** | vLLM 实例状态采集、LiteLLM 调用统计、队列监控 | `http://102.168.3.117:8790` |

> [!NOTE]
> **关于服务器 IP 说明**：
> 本文以您指定的服务器地址 **`102.168.3.117`** 为准；若该地址为局域网私网环境（如笔误实际为 `192.168.3.117`），请以服务器实际 `ip addr` / `ifconfig` 网卡 IP 为准替换。

### 2. 数据库与数据清零状态
- 持久化数据目录：`server_docker1/docker/data/`
- **状态已就绪**：目录下的历史日志、测试数据、备份及归档文件**已全部清零完毕**。首次启动时，系统将全自动建表并完成所有 9 个阶段的版本初始化迁移（`migrate` 幂等自愈）。

---

## 二、推荐部署方案：Docker Compose 一键启动（支持 Audit + GLM Monitor）

项目已在 `server_docker1/docker/docker-compose.yml` 中集成了 `claude_audit` 与 `glm_monitor` 两个常驻服务，实现一键全自动拉起与自愈。

### 步骤 1：将目录复制到目标服务器
将整个 `server_docker1` 文件夹打包或通过 SCP/rsync 传输到服务器，例如放到 `/opt/cloud_security_deploy/server_docker1`。

```bash
# 示例：通过 scp 将整个 server_docker1 拷贝到服务器
scp -r E:\cloud_security_deploy\server_docker1 user@102.168.3.117:/opt/cloud_security_deploy/
```

### 步骤 2：检查并修改配置文件（可选）
进入 `server_docker1/docker` 目录：
1. **`docker-compose.yml`**：
   - 默认管理员账号：`admin`
   - 默认管理员密码：`admin2026`（如需修改可在 `AUDIT_ADMIN_PASSWORD` 处自定义）
2. **`config.yml`**：
   - `ingest.token`：上报鉴权 Token（默认 `your-audit-ingest-token-2026`，客户端需与之保持一致）
   - `litellm.host`：网关地址（默认为 `http://192.168.3.124:4000`）

### 步骤 3：一键构建并启动服务
在 `server_docker1/docker` 目录下执行：

```bash
# 构建镜像并后台启动所有服务
docker compose up -d --build
```

### 步骤 4：查看服务运行状态
```bash
# 查看容器状态（两项服务状态均应为 Up）
docker compose ps

# 查看日志输出
docker compose logs -f
```
看到输出如下日志即代表两项服务均成功启动并已就绪：
- `[main] local_collector=false; ingest-only mode (POST /ingest)`
- `[db-maintenance] 自动运维调度器已启动: 每日 02:00 执行热备份(保留 14 份), 每日 03:30 执行归档(保留 90 天)`
- `Uvicorn running on http://0.0.0.0:8787`
- `GLM 后端实时监控服务 running on http://0.0.0.0:8790`

---

## 三、备选部署方案：原生 Python 进程部署（无 Docker 环境）

如果目标服务器未安装 Docker，也可直接使用服务器本地 Python 3.10+ 原生运行。

### 1. 启动 `claude_audit` 主审计平台
```bash
cd server_docker1/claude_audit
pip install -r requirements.txt

# Linux 生产环境后台启动 (开启4进程多Worker)
nohup uvicorn claude_audit.api.main:app --host 0.0.0.0 --port 8787 --workers 4 > /var/log/claude_audit.log 2>&1 &
```

### 2. 启动 `glm_monitor` 监控服务
`glm_monitor/monitor.py` 为**纯 Python 标准库开发，零第三方依赖**，无需安装任何 pip 包：
```bash
cd server_docker1/glm_monitor

# 指定数据库存储到统一的 data 目录
export GLM_MONITOR_DB="../docker/data/glm_monitor_data.db"
export GLM_HTTP_PORT=8790
export GLM_HTTP_HOST=0.0.0.0

# 后台运行
nohup python3 monitor.py > /var/log/glm_monitor.log 2>&1 &
```

---

## 四、客户端配置与远端安全策略集中下发 (Managed Settings)

平台原生支持**远端安全策略集中下发**与**终端一键纳管**，管理员无需逐台电脑登录即可实现统一企业级安全防护。

### 1. 远端安全策略工作机制
- **集中托管策略 (`/managed-settings.json`)**：服务端对外提供系统级托管策略，包含：
  - **强制阻止规则 (Deny List)**：默认拦截 `rm -rf /*`、`rmdir /s /q C:\`、`format *:*`、`diskpart` 等毁灭性系统命令；
  - **动态安全拦截 Hook**：定义 `PreToolUse`、`UserPromptSubmit`、`PostToolUse`、`Stop` 4 大审计切片，将调用实时交由服务端安全检测网关拦截；
  - **规则引擎动态生效**：内置 31 条企业安全规则（凭证泄漏、反弹 Shell、敏感路径等），支持在 Web 端【安全策略】页面实时新增与热更新规则。

### 2. 员工终端一键拉取远端安全策略
员工电脑（Windows 终端）以管理员身份打开 PowerShell，执行以下单行命令，即可自动拉取并注入远端托管安全策略：

```powershell
# 员工机器执行一键安装（自动拉取远端策略并注册安全审计）：
irm http://102.168.3.117:8787/install.ps1 | iex
```

*该脚本会自动完成：*
1. 创建系统级托管策略目录 `C:\Program Files\ClaudeCode\`；
2. 自动拉取并写入最新的 `managed-settings.json`；
3. 检查并清理旧版本地遗留 hooks，确保所有终端统一受远端策略保护。

### 3. 日志上报客户端配置 (`client.yml`)
对于需要采集本地终端执行日志的客户端代理，更新 `client.yml` 配置：

```yaml
# 远端管控与日志摄取网关
server_url: http://102.168.3.117:8787

# 上报 Token (与 server_docker1/docker/config.yml 保持一致)
token: "your-audit-ingest-token-2026"

# 采集与上报周期(秒)
interval_seconds: 15
batch_size: 500
```

---

## 五、防火墙与连通性验证

请确保服务器防火墙开放了 **`8787`** 和 **`8790`** 端口：

```bash
# Linux (firewalld)
sudo firewall-cmd --zone=public --add-port=8787/tcp --permanent
sudo firewall-cmd --zone=public --add-port=8790/tcp --permanent
sudo firewall-cmd --reload

# Linux (ufw)
sudo ufw allow 8787/tcp
sudo ufw allow 8790/tcp
```

### 连通性测试命令：
1. **测试主 Web 与 Ingest 接口**：
   ```bash
   curl -I http://102.168.3.117:8787/login
   # 预期返回: HTTP/1.1 200 OK
   ```
2. **测试 GLM 监控接口**：
   ```bash
   curl http://102.168.3.117:8790/api/status
   # 预期返回: {"ok": true, ...}
   ```

---

## 六、日常运维与数据管理

1. **管理登录**：
   - 浏览器访问：`http://102.168.3.117:8787`
   - 默认账号密码：`admin` / `admin2026`
2. **自动热备份管理**：
   - 系统每天凌晨 **02:00 (CST)** 自动全量在线热备份，自动保留最近 **14 天**备份文件；
   - 管理员可随时进入【系统设置】点击**【立即在线热备份】**或直接**下载备份 `.db` 文件**；
   - 备份文件物理落盘路径：`server_docker1/docker/data/backups/`。
3. **冷数据自动归档管理**：
   - 系统每天凌晨 **03:30 (CST)** 自动检查超期旧数据，将 90 天前的事件与命中记录导出到独立归档库；
   - 归档文件物理落盘路径：`server_docker1/docker/data/archives/`。
