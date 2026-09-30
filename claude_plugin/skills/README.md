# skills/ — 插件自带的 Claude Code Skills

4 个 skill,3 个 Office 文件脱敏 + 1 个通用安全代码守则。全部**从
`C:\Users\wuguoxiang\.claude\skills\` 复制而来**,路径已改为
`${CLAUDE_PLUGIN_ROOT}` 相对形式,员工机可以直接用。

## 清单

| skill | 触发 | 作用 |
|---|---|---|
| [docx/](docx/)                 | `.docx` 相关操作(读/总结/翻译/编辑/合并) | L1 正则 + L2 LLM NER 脱敏,写 markdown 副本给 Claude 读 |
| [pptx-redact/](pptx-redact/)   | `.pptx` 相关操作                          | 同上,针对 PPT 幻灯片 |
| [xlsx-redact/](xlsx-redact/)   | `.xlsx` / `.xlsm` 相关操作                | 同上,针对 Excel 表格 |
| [safe-coding-guard/](safe-coding-guard/) | 生成/修改/执行代码,任何认证/凭据/RLS/API key 场景 | 通用安全规范,禁止危险操作,提示先向用户确认 |

## `run.cmd` 桥接开发/生产

3 个脱敏 skill 目录下都有 `run.cmd`,SKILL.md 里的 Bash 命令都指向它:

```
Bash: "${CLAUDE_PLUGIN_ROOT}\skills\docx\run.cmd" "<.docx 路径>"
```

`run.cmd` **按优先级**选 Python 解释器:

1. **`CLOUD_GUARD_PYTHON` 环境变量** —— 员工机部署脚本在安装时写入
   (例:`C:\ProgramData\ClaudeSecurity\python\python.exe`,路径可随部署自定义)
2. **`bin\_internal\python.exe`** —— 未来若走 PyInstaller onedir 时用
3. **`py -3`** —— 开发机回落

不用改 SKILL.md,一份文件覆盖三种场景。**员工机安装时把 `CLOUD_GUARD_PYTHON` 写到系统
环境变量或 `settings.json` 的 `env` 段,run.cmd 就能自动找到那份 embeddable Python。**

## Python 依赖(部署时的重点)

3 个脱敏 skill 都依赖:
- `python-docx` / `python-pptx` / `openpyxl` (对应文档格式解析)
- `PyYAML` (rules.yml 加载)
- `openai` (DeepSeek 兼容 API,L2 LLM NER)

这些依赖必须**打进 `bin\_internal\`**(由 `../build.py` 处理)。当前 `build.py` 只
打了 3 个 scanner exe,skill 里的依赖需要在 `--hidden-import` 里补:

```
--hidden-import=docx
--hidden-import=pptx
--hidden-import=openpyxl
--hidden-import=yaml
--hidden-import=openai
```

或者让 `build.py` 扫 `skills/*/requirements.txt` 自动追加。**未实现,后续补。**

## LLM API 凭据

3 个脱敏 skill 的 `.env` / `llm.yml` 里可能会有 DeepSeek 的 `base_url` / `api_key`。
分发到员工机之前一定要:

1. 检查 `skills/docx/.env`、`skills/pptx-redact/.env`、`skills/xlsx-redact/.env`
   有没有明文 key(现在没拷 .env,如果原目录有需要单独确认)
2. 改成从**统一配置文件**读取(比如 `${CLAUDE_PLUGIN_ROOT}/config/llm.yml`),或者走环境变量 `DEEPSEEK_ENDPOINT` / `DEEPSEEK_API_KEY` / `DEEPSEEK_MODEL`
3. 员工机部署时通过 GPO / 安装脚本注入这些环境变量,而不是把 key 写死进 exe

## 输出目录

3 个脱敏 skill 目前写死输出到 `D:\After-tuomin\<类型>\<session>\`。员工机上如果
用户没有 C: 盘写权限就会失败。建议未来改为 `%LOCALAPPDATA%\cloud-guard\redact\`。

已在 SKILL.md 提到可用环境变量覆盖:
- `DOCX_SKILL_OUT_DIR`
- `PPTX_SKILL_OUT_DIR`(如果 pptx-redact 支持)
- `XLSX_SKILL_OUT_DIR`(如果 xlsx-redact 支持)

## 试用步骤

1. 挂符号链接到 Claude plugin 目录(见顶层 [README.md](../README.md))
2. `/plugin` 启用 `cloud-guard`
3. 让 Claude 读一个 `.docx`,应该:
   - 看到 SKILL.md 描述,决定用 skill
   - 调 `Bash: "${CLAUDE_PLUGIN_ROOT}\skills\docx\run.cmd" "path.docx"`
   - `run.cmd` 落到 `py -3 docx_to_md.py path.docx`
   - 拿 stdout 里的 .md 路径 Read

## 与原 `C:\Users\wuguoxiang\.claude\skills\` 的关系

已复制,**未删原目录**。理由:
- 你现在的 Claude Code 会话仍然通过老 skill 目录触发脱敏 —— 冒然删了会中断服务
- 等插件路径试通、能取代老配置时,再删老目录
