# cloud-guard 安全插件 — 运维手册

> 版本：v0.1.0 | 更新：2025-08

---

## 1. 插件是干什么的

cloud-guard 是部署在员工电脑上的 Claude Code 安全插件，在企业使用 AI 编程助手时提供三层防护：

| 层级 | 时机 | 做什么 |
|---|---|---|
| **输入扫描** | Claude 调用工具前（PreToolUse） | 检测用户输入/文件内容中的敏感信息（身份证、手机号、API Key 等），自动脱敏后再喂给 Claude |
| **输出扫描** | Claude 写入文件后（PostToolUse） | 检测 Claude 输出中是否包含敏感信息泄漏 |
| **会话审计** | Claude 一轮响应结束后（Stop） | 对本轮所有文件改动做 diff 审计，由 LLM 判断是否存在安全风险 |

同时提供 3 个 **脱敏 Skill**（docx / pptx-redact / xlsx-redact），员工可直接在 Claude Code 里调用，将 Office 文件脱敏后读取。

---

## 2. 目录结构总览（员工机部署后）

```
D:\ClaudeSecurity\                          ← SCRIPT_DIR：内嵌 Python
  python\                                   ← embeddable Python 3.x
    python.exe
    Lib\site-packages\...                   ← pyyaml, httpx 等依赖

C:\Users\<用户>\.claude\plugins\cloud-guard\  ← PLUGIN_DIR：插件本体
  .claude-plugin\plugin.json                ← 插件注册信息
  hooks\hooks.json                          ← Hook 事件注册（Claude Code 框架自动加载）
  bin\
    input_scanner.cmd                       ← Hook 入口脚本
    output_scanner.cmd
    stop_reviewer.cmd
  src\
    input\                                  ← 输入扫描模块
      input_scanner.py
      config\
        paths.yml                           ← ★ 路径配置（安装时由模板渲染）
        rules.yml                           ← 敏感数据分类规则
        word_library.yml                    ← 业务词库
      lib\
        write_guard.py                      ← 写入白名单校验
        bash_guard.py                       ← Bash 命令阻断
      actions\
        desensitize_action.py               ← 文件脱敏引擎
    output\                                 ← 输出扫描 + Stop 审计模块
      output_scanner.py
      stop_reviewer.py
      stop_review\
        baseline.py                         ← 改动快照存储
  skills\
    docx\                                   ← Word 脱敏 Skill
    pptx-redact\                            ← PPT 脱敏 Skill
    xlsx-redact\                            ← Excel 脱敏 Skill
    safe-coding-guard\                      ← 安全编码参考文档（只读）

D:\work\                                    ← WORKDIR：受控工作目录
  projects\                                 ← 员工项目文件（Claude 可读）
  output\                                   ← 员工输出（Claude 可写 ✓）
  temp\                                     ← 临时文件（Claude 可写 ✓）
    desensitized_\                          ← 脱敏副本目录（只读 ✗，不可 Claude 写）
    session_cache\                          ← 扫描结果缓存
  logs\                                     ← （本地开发版；部署版见下方 LOG_DIR）

C:\Users\<用户>\claude_logs\                 ← LOG_DIR：Hook 审计日志
  input_scanner.jsonl                       ← 输入扫描审计日志
  output_scanner.jsonl                      ← 输出扫描审计日志
  stop_review.jsonl                         ← Stop 审计日志

D:\After-tuomin\                            ← 脱敏 Skill 输出目录
  docx\<session_id>\<文件名>_<hash>.md
  pptx\<session_id>\<文件名>_<hash>.md
  xlsx\<session_id>\<文件名>_<hash>.md
```

---

## 3. 路径配置详解

### 3.1 根路径

| 变量 | 默认值 | 说明 |
|---|---|---|
| `SCRIPT_DIR` | `D:\ClaudeSecurity` | 内嵌 Python 安装位置 |
| `WORKDIR` | `D:\work` | 受控工作目录（所有员工文件在此） |
| `PLUGIN_DIR` | `C:\Users\<用户>\.claude\plugins\cloud-guard` | 插件本体（Claude Code 自动扫描） |
| `LOG_DIR` | `C:\Users\<用户>\claude_logs` | Hook 日志（claude_audit_setup.exe 监听此目录） |

### 3.2 派生路径（paths.yml）

| 键 | 员工机展开值 | 说明 |
|---|---|---|
| `controlled_workdir` | `D:\work` | 受控目录根 |
| `security_script_dir` | `<PLUGIN_DIR>\src` | 插件代码根 |
| `projects` | `D:\work\projects` | 项目文件 |
| `output` | `D:\work\output` | 输出目录 |
| `temp` | `D:\work\temp` | 临时目录 |
| `temp_desensitized` | `D:\work\temp\desensitized_` | 脱敏副本（只读） |
| `logs` | `C:\Users\<用户>\claude_logs` | 审计日志 |
| `session_cache` | `D:\work\temp\session_cache` | 扫描缓存 |
| `input_module` | `<PLUGIN_DIR>\src\input` | 输入模块 |
| `config_dir` | `<PLUGIN_DIR>\src\input\config` | 配置目录 |

### 3.3 paths.yml 的生成链路

```
install_plugin.bat
  │
  ├─ robocopy claude_plugin/ → %PLUGIN_DIR%/
  │    （此时 paths.yml 是本地开发版，会被下一步覆盖）
  │
  └─ _gen_paths_yml.py paths.template.yml → %PLUGIN_DIR%\src\input\config\paths.yml
       读取模板，替换占位符：
         __WORKDIR__      → %WORKDIR%
         __PLUGIN_SRC__   → %PLUGIN_DIR%\src
         __PLUGIN_DIR__   → %PLUGIN_DIR%
         __USERPROFILE__  → %USERPROFILE%
         __LOG_DIR__      → %LOG_DIR%
```

> ⚠️ 仓库里的 `claude_plugin/src/input/config/paths.yml` 是**本地开发版**，仅供开发测试。
> 员工机生效的是安装时渲染的版本，两者独立。

---

## 4. 受控目录与读写权限

### 4.1 Claude 的读权限

Claude 可以**读取磁盘上任何路径的文件**，不受"受控目录"限制。"受控目录"只决定 input_scanner 是否自动脱敏：

| 文件位置 | Claude 能读？ | 自动脱敏？ | 原因 |
|---|---|---|---|
| `D:\work\projects\报告.docx` | ✅ | ✅ | 在受控目录内，input_scanner 拦截脱敏 |
| `D:\After-tuomin\docx\报告.md` | ✅ | ❌ | 受控目录外，但文件已是脱敏后的，无需再脱敏 |
| `D:\other\某个文件.txt` | ✅ | ❌ | 受控目录外，原文直接读取 |

> ⚠️ 只有放在 `D:\work\` 下的文件才会触发自动脱敏。员工应把工作文件放在 `D:\work\projects\` 下，不要放在其他位置。

对以下文件类型，input_scanner 会在读取受控目录内文件时自动脱敏（详见第 5 节）：
- `.docx` / `.pptx` / `.xlsx` — 通过 Skill 脱敏为 `.md`
- `.pdf` — 提取文本后脱敏
- `.txt` / `.py` / `.js` 等 — 提取文本后脱敏

### 4.2 Claude 的写权限（write_guard 白名单）

Claude 的 Write / Edit / MultiEdit / NotebookEdit 工具**只能写入**以下目录：

| 白名单路径 | 员工机展开值 | 用途 |
|---|---|---|
| `{controlled_workdir}\output` | `D:\work\output` | 员工工作输出 |
| `{controlled_workdir}\temp` | `D:\work\temp` | 临时文件 |
| `D:\After-tuomin` | `D:\After-tuomin` | Skill 脱敏输出 |
| `__USERPROFILE__\.claude\projects` | `C:\Users\<用户>\.claude\projects` | Claude auto memory |
| `__PLUGIN_DIR__` | `C:\Users\<用户>\.claude\plugins\cloud-guard` | 插件自身 config |

**白名单外的路径一律拒绝。** 写入被拦截时 Claude 会收到提示，告知应挪到哪个白名单目录。

### 4.3 特殊只读规则

| 目录 | 规则 | 原因 |
|---|---|---|
| `D:\work\temp\desensitized_` | 只读，即使父目录 `temp` 在白名单内也拦 | 防止 Claude 把脱敏占位符替换回原文 |

### 4.4 Bash 命令阻断（bash_guard + permissions.deny）

Claude 执行 Bash 命令时受两层拦截：

**第一层：bash_guard（插件内）**
- 在受控目录内用 Bash 直接读文件 → 阻断（必须走 Read 工具，经过脱敏）
- 同时含凭据 + 网络命令 → 阻断（防凭据外发）

**第二层：settings.json permissions.deny（框架级）**

| 类别 | 拦截命令 |
|---|---|
| 删除 | rm, del, rmdir, rd, Remove-Item, shred, truncate, git clean, git reset --hard, git rm |
| 卸载 | npm uninstall, pip uninstall, docker rmi/rm/volume rm/network rm, kubectl delete |
| 外发 | curl, wget, nc, scp, rsync, ssh, sftp |
| 泄露 | env, printenv, set |
| 绕过 | xxd, base64 |
| 格式化 | format, mkfs, diskpart |

---

## 5. 脱敏机制

> **重要：脱敏有两条独立的路径，不要混淆：**
>
> | | Read 自动脱敏 | Skill 手动脱敏 |
> |---|---|---|
> | **触发** | Claude Read 受控目录文件时，input_scanner 自动介入 | 员工主动调用 `/docx` `/pptx-redact` `/xlsx-redact` |
> | **输出到** | `D:\work\temp\desensitized_\<session_id>\` | `D:\After-tuomin\<类型>\<session_id>\` |
> > | **用户可见** | 副本在磁盘上，员工可浏览 `temp\desensitized_\` 查看，但不会主动展示 | 是（员工可直接打开 `D:\After-tuomin\` 查看） |
> | **脱敏引擎** | 文本: L1 正则；Office: 调用 Skill 子进程 | LLM 实体识别 + 掩码 |
> | **只读保护** | 副本目录对 Claude 只读，禁止回写 | Skill 内部白名单校验 |

### 5.1 哪些文件会被脱敏

当 Claude 使用 Read 工具读取受控目录（`D:\work`）内的文件时，input_scanner 自动介入：

| 文件类型 | 处理方式 | 输出格式 |
|---|---|---|
| `.docx` | 调用 docx Skill → LLM 实体识别 + 掩码 | `.md`（Markdown） |
| `.pptx` | 调用 pptx-redact Skill → LLM 实体识别 + 掩码 | `.md`（Markdown） |
| `.xlsx` | 调用 xlsx-redact Skill → LLM 实体识别 + 掩码 | `.md`（Markdown） |
| `.pdf` | 提取文本 → L1 正则脱敏 | `.txt` |
| 其他文本 | 提取文本 → L1 正则脱敏 | 保留原扩展名 |

### 5.2 脱敏后文件到哪里

**方式一：Read 工具自动脱敏（受控目录内文件）**

Claude Read 受控目录内的文件时，input_scanner 生成脱敏副本，让 Claude 改读副本：

```
原文件：D:\work\projects\合同.docx
副本：  D:\work\temp\desensitized_\<session_id>\合同_<hash12>.md
```

- 副本在磁盘上，员工可浏览 `D:\work\temp\desensitized_\` 查看脱敏后的内容
- 副本目录 `desensitized_` 对 Claude **只读**（防止回写击穿脱敏）
- 同一 session 内同一文件只脱敏一次（缓存命中直接返回副本）
- 脱敏了哪些内容，记录在 `%LOG_DIR%\input_scanner.jsonl` 日志中

**方式二：Skill 手动脱敏（Office 文件）**

员工可在 Claude Code 中调用 `/docx`、`/pptx-redact`、`/xlsx-redact`：

```
输入：D:\work\projects\报表.xlsx
输出：D:\After-tuomin\xlsx\<session_id>\报表_<hash12>.md
```

- 输出固定在 `D:\After-tuomin\` 下
- 原子写入：先写 `.md.tmp`，再 rename 为 `.md`
- Skill 内部也有白名单校验，只允许写到 `D:\After-tuomin`

### 5.3 脱敏的数据类型

| 类目 | 识别方式 | 脱敏策略 | 示例 |
|---|---|---|---|
| 身份证号 | 正则 + 校验位 | 保留前 3 后 1，中间掩码 | `310***X` |
| 手机号 | 正则 | 保留前 3 后 2 | `138****56` |
| 银行卡号 | Luhn 校验 | 保留前 4 后 4 | `6222****1234` |
| 公司邮箱 | 正则（@example.com） | 首字母 + 掩码 | `z***@example.com` |
| 通用邮箱 | 正则 | 首字母 + 掩码 | `z***@example.com` |
| 工号 | 正则（PYT/PYE+数字） | 保留前缀 + 掩码 | `PYT***` |
| API Key | 专用 detector | 整体掩码 | `[API_KEY]` |
| AWS Key | 正则（AKIA/ASIA 前缀） | 整体掩码 | `[AWS_KEY]` |
| 私钥 | 专用 detector | 整体掩码 | `[PRIVATE_KEY]` |
| 内网 IP | 正则（10.x / 172.16-31 / 192.168） | 掩码 | `10.***.***.***` |
| 客户名称 | 业务词库 | 首字 + 掩码 | `张*` |
| 统一社会信用代码 | 正则（标签：值 形态） | 首字掩码 | `9***` |
| 地址 | 正则（标签：值 形态） | 头尾保留 | `上***号` |

> 金额和日期**不脱敏**：金额走 L2 LLM 占位符，日期本身不是 PII。

---

## 6. Hook 事件流

```
用户输入 Prompt
    │
    ├─ UserPromptSubmit ──→ input_scanner ──→ 检测 prompt 中的敏感信息
    │
    ▼
Claude 调用工具
    │
    ├─ PreToolUse ──→ input_scanner
    │     ├─ Read/Grep/WebFetch → 文件内容脱敏
    │     ├─ Write/Edit/MultiEdit/NotebookEdit → write_guard 白名单校验
    │     └─ Bash → bash_guard 命令阻断
    │
    ▼
工具执行完成
    │
    ├─ PostToolUse ──→ output_scanner ──→ 检测写入内容中的敏感信息泄漏
    │
    ▼
Claude 响应结束
    │
    └─ Stop ──→ stop_reviewer ──→ 本轮所有文件改动的 diff 审计
```

---

## 7. 审计日志

所有 Hook 事件均写入 JSONL 日志，供 `claude_audit_setup.exe` 实时采集上传。

| 日志文件 | 路径 | 内容 |
|---|---|---|
| `input_scanner.jsonl` | `%LOG_DIR%\input_scanner.jsonl` | 每次输入扫描的结果（工具名、文件路径、命中的敏感类目、脱敏动作） |
| `output_scanner.jsonl` | `%LOG_DIR%\output_scanner.jsonl` | 每次输出扫描的结果 |
| `stop_review.jsonl` | `%LOG_DIR%\stop_review.jsonl` | Stop 审计结果（diff 摘要、LLM 审计结论） |

每条日志为独立 JSON 行，包含 `session_id`、`timestamp`、事件类型和扫描详情。

---

## 8. 安装部署

### 8.1 安装步骤

```
1. 解压 claude_audit.zip 到员工电脑
2. 双击 install_plugin.bat（或命令行传参）
3. 按提示输入：SCRIPT_DIR、WORKDIR、LLM_URL、LLM_TOKEN、LLM_MODEL
4. 等待自动安装完成
5. 注销重新登录（CLOUD_GUARD_PYTHON 生效）
6. 打开 Claude Code → /plugin → 添加 marketplace → 启用 cloud-guard
7. 安装 claude_audit_setup.exe（日志上传客户端）
```

### 8.2 install_plugin.bat 做了什么

| 步骤 | 操作 |
|---|---|
| 1 | 定位 zip 内的 `python\` 和 `claude_plugin\` |
| 2 | robocopy 内嵌 Python → `D:\ClaudeSecurity\python\` |
| 3 | robocopy 插件 → `C:\Users\<用户>\.claude\plugins\cloud-guard\` |
| 4 | 创建 `D:\work\` 骨架目录 + `C:\Users\<用户>\claude_logs\` |
| 5 | 渲染 `paths.template.yml` → 插件内 `paths.yml` |
| 6 | setx `CLOUD_GUARD_PYTHON`（用户环境变量） |
| 7 | Smoke test input_scanner |
| 8 | merge_settings_env.ps1 → `~/.claude/settings.json`（写入 LLM env、清旧 hooks、加 permissions.deny） |

### 8.3 merge_settings_env.ps1 做了什么

| 操作 | 说明 |
|---|---|
| merge env | 写入 `ANTHROPIC_BASE_URL`、`ANTHROPIC_AUTH_TOKEN`、`ANTHROPIC_DEFAULT_*_MODEL` |
| clear hooks | 清空 settings.json 中的 hooks 段（避免和 plugin hooks 双跑），备份到 `.hooks_bak_*.json` |
| merge permissions.deny | 合并危险命令黑名单（删/外发/泄露/绕过/格式化） |

---

## 9. 配置文件速查

| 文件 | 位置 | 改了什么效果 |
|---|---|---|
| `paths.yml` | `<PLUGIN_DIR>\src\input\config\paths.yml` | 修改受控目录、日志路径、白名单 |
| `rules.yml` | `<PLUGIN_DIR>\src\input\config\rules.yml` | 增删敏感数据类目、调整正则/脱敏策略 |
| `word_library.yml` | `<PLUGIN_DIR>\src\input\config\word_library.yml` | 更新业务词库（客户名称等） |
| `settings.json` | `~/.claude/settings.json` | LLM 配置、permissions.deny 黑名单 |
| `hooks.json` | `<PLUGIN_DIR>\hooks\hooks.json` | Hook 事件注册（一般不改） |
| `llm.yml` | `<PLUGIN_DIR>\skills\docx\llm.yml` 等 | Skill LLM 配置（DeepSeek endpoint/key） |

---

## 10. 环境变量

| 变量 | 用途 | 设置方式 |
|---|---|---|
| `CLOUD_GUARD_PYTHON` | 插件使用的 Python 路径 | install_plugin.bat → setx |
| `CLAUDE_PLUGIN_ROOT` | 插件安装目录（Claude Code 框架注入） | 自动 |
| `CLAUDE_SESSION_ID` | 当前会话 ID（Claude Code 注入） | 自动 |
| `ANTHROPIC_BASE_URL` | LLM 网关地址 | merge_settings_env.ps1 |
| `ANTHROPIC_AUTH_TOKEN` | LLM Token | merge_settings_env.ps1 |
| `DEEPSEEK_ENDPOINT` | Skill LLM endpoint | 技能 .env |
| `DEEPSEEK_API_KEY` | Skill LLM key | 技能 .env |
| `CLOUD_SEC_STOP_REVIEW` | =0 时禁用 Stop 审计 | 手动设置 |

---

## 11. 故障排查

| 症状 | 可能原因 | 排查 |
|---|---|---|
| Claude 工具调用静默中断 | settings.json 里有旧 hooks 和 plugin hooks 双跑 | 检查 `~/.claude/settings.json` 的 `hooks` 段是否为 `{}` |
| Write 被拦截"不在白名单内" | 目标路径不在 write_whitelist | 检查 `paths.yml` 的 `write_whitelist`，或把文件挪到白名单目录 |
| Bash 命令被拦截 | 命中 permissions.deny 或 bash_guard | 检查 settings.json 的 `permissions.deny` 或 bash_guard 规则 |
| claude_audit_setup.exe 无日志 | LOG_DIR 和插件 logs 路径不一致 | 检查 `paths.yml` 的 `logs` 值是否 = claude_audit_setup.exe 监听目录 |
| 脱敏不生效 | 文件不在受控目录内 | 确认文件在 `D:\work\projects\` 下，不在外部路径 |
| Skill 报错"输出目录不允许" | out-dir 不在 `_ALLOWED_OUT_DIR_ROOTS` | Skill 输出必须在 `D:\After-tuomin\` 下 |
| input_scanner.jsonl 无内容 | hook 未注册或 Python 路径错误 | 检查 `CLOUD_GUARD_PYTHON` 是否指向正确 python.exe |
