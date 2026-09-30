---
name: docx
description: Use this skill for ANY operation on .docx files (Microsoft Word documents) — reading content, summarizing, extracting text or tables, translating, editing, merging, splitting, or converting. Invoke this skill BEFORE using python-docx, docx2txt, pandoc, libreoffice, unzip on document.xml, or attempting to Read the .docx directly. Claude Code's Read rejects .docx as binary, so you MUST go through the bundled docx_to_md.py CLI which performs L1 (regex) + L2 (LLM NER) desensitization and produces a readable .md copy.
---

# DOCX 处理 — 安全合规约束

本 skill 自带脱敏脚本与所需的全部 Python 依赖，**不需要外部 cloud_security 代码**。
.docx 不能直接 Read（Claude Code 会以 binary 拒绝），必须先用本 skill 下的
`docx_to_md.py` 把 .docx 脱敏成 .md，再 Read .md。

## 强制工作流

### 第 1 步：用 Bash 调脚本

```
Bash: "${CLAUDE_PLUGIN_ROOT}\skills\docx\run.cmd" "<原 .docx 绝对路径>"
```

⏰ **耗时预期**:LLM 脱敏走远程服务,典型耗时 **30-90 秒**(大文件 / LLM 负载高时
   可能更久)。请告知用户"正在脱敏,大约 1 分钟,请稍候",然后耐心等待 Bash
   命令返回:
   - 若超 120s 触发 Bash 默认 timeout,**不要给 Bash 加 `timeout` 参数延长**
     (会绕过保护)——直接重新 invoke 即可。脚本内部已经做了一次重试,LLM 仍
     失败会弹 MessageBox 让用户确认是否接受 L1-only 输出。
   - **不要中途中断或在原命令未返回时另起一条**——重复调起会加倍占用 LLM 配额。

脚本内部：
- python-docx 抽段落 + 表格
- L1 正则 + L2 LLM 实体识别（DeepSeek 兼容 API）
- 段级一致性占位符替换（[人员A]/[公司A]/[产品A]/[金额]）
- 按 body 顺序渲染成 markdown（heading → `#`/`##`、表格 → markdown 表格）
- 写到固定输出目录 `D:\After-tuomin\docx\{session_id}\{原文件名}_{12位hash}.md`
- **stdout 输出该 .md 的绝对路径**（UTF-8 编码），exit 0

可选环境变量 `DOCX_SKILL_OUT_DIR` 覆盖输出目录。

### 第 2 步：Read 脚本输出的 .md 路径

```
Read(file_path="<脚本 stdout 的 .md 路径>")
```

读到脱敏后内容：
- 姓名 → `[人员A]` `[人员B]` ...
- 公司 → `[公司A]` `[公司B]` ...
- 产品 / 项目代号 → `[产品A]` ...
- 金额 → `[金额]`
- 手机 → `138****8000`
- 邮箱 → `z***@example.com`
- 身份证 / 银行卡 → 中间位掩码

### 第 3 步：所有后续操作基于 .md 副本

总结、翻译、提取、对比、问答 —— 一律在 .md 上进行。**不要**再回头 Read 原 .docx，
也不要用其他工具直接抽原文。

## 严禁的绕过行为

以下做法绕过脱敏，**严禁使用**：

- ❌ `Read(file_path="xxx.docx")` —— Claude Code Read 会以 binary 为由拒绝
- ❌ `python -c "from docx import Document; doc = Document('xxx.docx'); ..."`
- ❌ `python -m docx2txt xxx.docx`
- ❌ `pandoc xxx.docx -o xxx.txt`
- ❌ `libreoffice --headless --convert-to txt xxx.docx`
- ❌ `unzip xxx.docx -d /tmp/x && cat /tmp/x/word/document.xml`
- ❌ 在临时脚本里 `import docx` 后直接 print 段落

如果你已经"想到"要写这种脚本，**立即停下来改走 docx_to_md.py**。

## 编辑 / 创建 / 转换场景

| 场景 | 正确做法 |
|---|---|
| 总结 / 问答 / 翻译原 .docx | Bash 调 docx_to_md.py → Read .md → 在 .md 上回答 |
| 修改原 .docx 内容 | Bash → Read .md → 在 .md 上理解 → 用 python-docx 写**新 .docx 文件**（基于 .md 内容生成），**不回写原文件** |
| 从 .docx 生成报告 | 同上，写新 .docx，不动原文 |
| 创建全新 .docx（无原文输入） | 直接用 python-docx 写，无脱敏依赖 |
| 合并多个 .docx | 每个原 .docx 各自 docx_to_md.py → 在多个 .md 基础上合并 |

## 给用户的标准应答模板

当用户说"帮我看下 / 总结 / 翻译 / 处理这个 .docx"时，第一句先说明流程，再调 Bash：

```
我先用 docx_to_md.py 把这个 .docx 脱敏成 .md（Claude Code 的 Read 拒读 .docx 二进制），
然后基于 .md 做后续操作，确保敏感数据不外发。
```

接着立即调用：
```
Bash: "${CLAUDE_PLUGIN_ROOT}\skills\docx\run.cmd" "<用户给的 .docx 路径>"
```
拿到 stdout 的 .md 路径后立刻 Read 它。

## 文件清单（本 skill 自包含）

- `docx_to_md.py`：CLI 入口（编排脚本）
- `docx_writer.py`：docx → markdown 渲染器
- `redactor.py` / `pseudonymizer.py`：L1+L2 合并替换
- `llm_detector.py` / `llm_client.py` / `llm_config.py`：L2 LLM NER
- `entity_map.py`：跨段一致性占位符分配
- `mask_strategies.py`：保形掩码策略
- `rules.py` + `rules.yml`：L1 正则规则
- `wordlib.py` + `word_library.yml`：业务词库
- `validators.py`：luhn / 身份证校验
- `match.py`：Match 数据结构
- `requirements.txt`：python-docx, PyYAML, openai
- `.env`（可选）：LLM 凭据 `base_url` / `api_key` / `model`（也可走环境变量
  `DEEPSEEK_ENDPOINT` / `DEEPSEEK_API_KEY` / `DEEPSEEK_MODEL`）

L2 LLM 不可达时自动降级到纯 L1（手机 / 邮箱 / 卡号 等结构化字段仍可脱敏，
姓名 / 公司 / 产品等语义实体会保留原文）。
