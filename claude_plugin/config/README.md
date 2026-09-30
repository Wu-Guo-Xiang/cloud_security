# config/ — 规则与运行时配置

这个目录留给可被员工机管理员/中心配置系统覆盖的**外部化配置**。

## 分层策略

打包成 exe 后,规则文件如果被 PyInstaller 打进 exe 内部,员工机上就没法灵活更新。所以约定:

1. **默认规则** —— 打包在 exe 里(读 `sys._MEIPASS`),保证纯净机器也能开箱即用。
2. **本目录覆盖** —— 如果 `${CLAUDE_PLUGIN_ROOT}/config/*.yml` 存在,优先加载,覆盖打包内默认值。
3. **企业下发**(未来) —— 后续可让 audit 服务端在员工机启动时下发 `config/dynamic.yml`,实现"改规则不换客户端"。

## 建议放这里的文件

| 文件 | 内容 |
| --- | --- |
| `rules.yml`         | 敏感词/正则/上下文规则(覆盖 `scripts/input/config/rules.yml`) |
| `deny_bash.yml`     | Bash 命令黑名单(curl/wget/nc 等) |
| `write_whitelist.yml` | Write/Edit 允许写入的根目录 |
| `endpoint.yml`      | claude_audit 服务端地址/token(现在硬编码在 client) |

**当前是空的** —— 待打包时,由 `build.py` 决定是否把 `scripts/input/config/*` 复制进来做默认值。
