# cloud-guard — Claude Code 安全插件

Cloud Security AI 日志监控 / DLP 防护的**自包含插件**。开发/生产双模,通过 `.cmd` 启动器自动切换。

## 目录结构

```
claude_plugin/
├── .claude-plugin/plugin.json     # 插件清单(name/version/author)
├── hooks/hooks.json               # 4 个 hook 注册(镜像旧 settings.json)
├── src/                           # ← 检测代码副本(从 scripts/input + scripts/output 复制而来)
│   ├── input/
│   │   ├── input_scanner.py       # PreToolUse + UserPromptSubmit 入口
│   │   ├── detectors/  extractors/  actions/  lib/  cache/  tools/
│   │   ├── config/                # 规则 YAML
│   │   ├── requirements.txt
│   │   └── tests/
│   └── output/
│       ├── output_scanner.py      # PostToolUse 入口
│       ├── stop_reviewer.py       # Stop 入口
│       └── detectors/  actions/  stop_review/  tests/
├── skills/                        # ← Claude Code Skills(从 ~/.claude/skills/ 复制)
│   ├── docx/                      # Word 脱敏 skill(+run.cmd)
│   ├── pptx-redact/               # PPT 脱敏 skill(+run.cmd)
│   ├── xlsx-redact/               # Excel 脱敏 skill(+run.cmd)
│   └── safe-coding-guard/         # 通用安全代码守则
├── bin/
│   ├── input_scanner.cmd          # 启动器:有 exe 走 exe,没有回落 ..\src\input\input_scanner.py
│   ├── output_scanner.cmd
│   ├── stop_reviewer.cmd
│   ├── input_scanner.exe          # ← build.py 生成(现在没有)
│   ├── output_scanner.exe
│   ├── stop_reviewer.exe
│   └── _internal/                 # PyInstaller onedir 运行时 —— skill 也复用它
├── config/                        # 规则外部化(现在空,build 后覆盖 src/input/config)
├── build.py                       # PyInstaller 打包脚本(骨架)
└── README.md
```

## 与旧 `scripts/` 的关系

**已经完全解耦。** `src/` 是从 `D:\cloud_security\scripts\input\` 和 `scripts\output\` **复制**过来的一份快照。

- 现在这份插件目录**自包含**,拷到任何一台机器上都能跑(有 Python 或者 exe 打好都行)。
- **代价**:代码有两份 —— 后续检测逻辑应该在**这里**(`claude_plugin/src/`)演进,老的 `scripts/` 目录退化为"调试脚本 + 历史存档"。
- 迁移完成后建议:把老的 `settings.json` 里指向 `D:\cloud_security\scripts\` 的 hook 段注释掉,只保留插件路径。

## 两种运行模式

### 开发模式(你的机器 = 有 Python)

`bin/` 里**没有** exe,只有 `.cmd` 启动器。启动器检测到没有 exe 就 fallback 到:

```cmd
py -3 %~dp0..\src\input\input_scanner.py --event PreToolUse
```

改 `src/` 下的一行 py 立即生效,不用重打包。

### 生产模式(员工机)

推荐走 **embeddable Python** 路线(hook 冷启动 ~50ms,比 exe 500ms+ 快):

1. 打包端跑 [build_embeddable.ps1](../claude_audit/deploy/build_embeddable.ps1) 生成 `deploy_pkg\python\`(已经扫 scanner + 3 个 skill 依赖)
2. 打包 zip:`python\` + `claude_plugin\` + `claude_audit_setup.exe` + `claude_audit\deploy\`(含 [install_plugin.bat](../claude_audit/deploy/install_plugin.bat))
3. 员工机双击 [install_plugin.bat](../claude_audit/deploy/install_plugin.bat) 自动完成:
   - 拷 embeddable Python → `C:\ProgramData\ClaudeSecurity\python\`(路径可改)
   - 拷 `claude_plugin\` → `%USERPROFILE%\.claude\plugins\cloud-guard\`
   - 渲染 `paths.yml` 到 plugin 里
   - `setx CLOUD_GUARD_PYTHON` 用户环境变量(bin/*.cmd 和 skills/*/run.cmd 靠这个找 Python)
   - merge LLM URL/Token 进 `~/.claude/settings.json` 的 `env` 键
4. 员工**登出/登入一次**让环境变量生效,然后 `/plugin` 启用 `cloud-guard`
5. 双击 `claude_audit_setup.exe` 装上报客户端(和 plugin 化无关,照旧)

**PyInstaller onedir 路线**(把 `bin/*.exe` + `bin/_internal/` 一起打进 plugin,员工机彻底无 Python)——`build.py` 骨架已在,`--hidden-import` / `--add-data` 还没补全,暂缓。

## 试用步骤(开发机)

1. **备份**旧 `settings.json`,把里面 4 个指向 `D:\cloud_security\scripts\` 的 hook 段临时删掉/注释掉,免得双跑
2. 把 `claude_plugin/` 挂进 Claude 插件目录:
   - `mklink /D "%USERPROFILE%\.claude\plugins\cloud-guard" "D:\cloud_security\claude_plugin"`
3. Claude 会话里 `/plugin` 命令启用 `cloud-guard`
4. 试触发一个敏感操作(比如 Bash `curl`),应该看到 hook 拦截 —— 说明插件通道走通了

## 现在还差什么

### 短期(能上员工机)
- [ ] `build.py` 里 `--add-data` / `--hidden-import` 需要按 `src/input/detectors/`, `extractors/`, `actions/` 等动态加载目录补齐
- [ ] `build.py` 需要**扫 skills/*/requirements.txt 追加 --hidden-import**(python-docx / python-pptx / openpyxl / openai 都在 skill 里),不然员工机跑 skill 会 ModuleNotFoundError
- [ ] `openai` / `python-docx` / `pdfplumber` / `pywin32` 打包体积测试,视情况加 `--exclude-module`
- [ ] 员工机 audit 上报 endpoint/token 外部化到 `config/endpoint.yml`(现在硬编码在客户端)
- [ ] **LLM 凭据外部化** —— 3 个脱敏 skill 都用 DeepSeek,现在 `.env`/`llm.yml` 可能明文写 api_key。统一放 `config/llm.yml`,员工机通过环境变量注入
- [ ] **skill 输出目录改盘符无关** —— 现在写死 `D:\After-tuomin\`,应该改 `%LOCALAPPDATA%\cloud-guard\redact\`
- [ ] 在 `src/input/input_scanner.py` 里加"规则文件加载优先级":`${CLAUDE_PLUGIN_ROOT}/config/*.yml`  优先于 `src/input/config/*.yml`

### 长期
- [ ] 卸载脚本 / 静默升级机制
- [ ] `libs/sec_detect/` 抽出纯检测层(为 Codex 适配预留)
- [ ] Windows Defender / 安装白名单流程(exe 首次可能被拦)
