---
name: pptx-redact
description: Use this skill for ANY operation on .pptx files (Microsoft PowerPoint presentations) — reading content, summarizing, extracting slides/tables/notes, translating, editing, merging, splitting, or converting. Invoke this skill BEFORE using python-pptx, pptx2txt, pandoc, libreoffice, unzip on slide xml, or attempting to Read the .pptx directly. Claude Code's Read rejects .pptx as binary, so you MUST go through the bundled pptx_to_md.py CLI which performs L1 (regex) + L2 (LLM NER) desensitization and produces a readable .md copy.
---

# PPTX 处理 — 安全合规约束

本 skill 自带脱敏脚本与所需的全部 Python 依赖,**不需要外部 cloud_security 代码**。
.pptx 不能直接 Read(Claude Code 会以 binary 拒绝),必须先用本 skill 下的
`pptx_to_md.py` 把 .pptx 脱敏成 .md,再 Read .md。

## 强制工作流

### 第 1 步:用 Bash 调脚本

```
Bash: "${CLAUDE_PLUGIN_ROOT}\skills\pptx-redact\run.cmd" "<原 .pptx 绝对路径>"
```

⏰ **耗时预期**:LLM 脱敏走远程服务,典型耗时 **30-90 秒**(大文件 / LLM 负载高时
   可能更久)。请告知用户"正在脱敏,大约 1 分钟,请稍候",然后耐心等待 Bash
   命令返回:
   - 若超 120s 触发 Bash 默认 timeout,**不要给 Bash 加 `timeout` 参数延长**
     (会绕过保护)——直接重新 invoke 即可。脚本内部已经做了一次重试,LLM 仍
     失败会弹 MessageBox 让用户确认是否接受 L1-only 输出。
   - **不要中途中断或在原命令未返回时另起一条**——重复调起会加倍占用 LLM 配额。

脚本内部:
- python-pptx 按幻灯片遍历 shapes / tables / 演讲者备注
- L1 正则 + L2 LLM 实体识别(DeepSeek 兼容 API)
- 段级一致性占位符替换([人员A]/[公司A]/[产品A]/[金额])
- 按幻灯片顺序渲染成 markdown(`## Slide N: 标题` → 正文段落 → 表格 → 备注)
- 写到固定输出目录 `D:\After-tuomin\pptx\{session_id}\{原文件名}_{12位hash}.md`
- **stdout 输出该 .md 的绝对路径**(UTF-8 编码),exit 0

可选环境变量 `PPTX_SKILL_OUT_DIR` 覆盖输出目录。

### 第 2 步:Read 脚本输出的 .md 路径

```
Read(file_path="<脚本 stdout 的 .md 路径>")
```

读到脱敏后内容:
- 姓名 → `[人员A]` `[人员B]` ...
- 公司 → `[公司A]` `[公司B]` ...
- 产品 / 项目代号 → `[产品A]` ...
- 金额 → `[金额]`
- 手机 → `138****8000`
- 邮箱 → `z***@example.com`
- 身份证 / 银行卡 → 中间位掩码

幻灯片结构在 .md 里体现为:
- `## Slide 1: 标题`(每张幻灯片一节)
- 正文段落保留缩进层级(`-` / `  -` 表示项目符号层级)
- 表格走 markdown 表格语法
- 演讲者备注以 `> **Notes:**` 引用块呈现

### 第 3 步:所有后续操作基于 .md 副本

总结、翻译、提取、对比、问答 —— 一律在 .md 上进行。**不要**再回头 Read 原 .pptx,
也不要用其他工具直接抽原文。

## .ppt 旧二进制格式

本 skill **不支持 `.ppt`(PowerPoint 97-2003 二进制)**。python-pptx 仅支持 OOXML
格式的 `.pptx`,LibreOffice 转换链路体积大且不稳定。

遇到 `.ppt` 时:**告诉用户在 PowerPoint 里打开并"另存为 .pptx"后再来**。脚本会
直接 exit 1 报错,不要尝试用其他工具(libreoffice / pandoc)绕过。

## 严禁的绕过行为

以下做法绕过脱敏,**严禁使用**:

- ❌ `Read(file_path="xxx.pptx")` —— Claude Code Read 会以 binary 为由拒绝
- ❌ `python -c "from pptx import Presentation; prs = Presentation('xxx.pptx'); ..."`
- ❌ `python -m pptx2txt xxx.pptx` 或类似第三方抽取工具
- ❌ `pandoc xxx.pptx -o xxx.txt`
- ❌ `libreoffice --headless --convert-to txt xxx.pptx`
- ❌ `unzip xxx.pptx -d /tmp/x && cat /tmp/x/ppt/slides/slide1.xml`
- ❌ 在临时脚本里 `from pptx import Presentation` 后直接 print 段落

如果你已经"想到"要写这种脚本,**立即停下来改走 pptx_to_md.py**。

## 编辑 / 创建 / 转换场景

| 场景 | 正确做法 |
|---|---|
| 总结 / 问答 / 翻译原 .pptx | Bash 调 pptx_to_md.py → Read .md → 在 .md 上回答 |
| 修改原 .pptx 内容 | Bash → Read .md → 在 .md 上理解 → 用 python-pptx 写**新 .pptx 文件**(基于 .md 内容生成),**不回写原文件** |
| 从 .pptx 生成报告 | 同上,写新 .pptx 或 .docx,不动原文 |
| 创建全新 .pptx(无原文输入) | 直接用 python-pptx 写,无脱敏依赖(可参考下载的 `pptx` skill) |
| 合并多个 .pptx | 每个原 .pptx 各自 pptx_to_md.py → 在多个 .md 基础上合并 |

## v1 已知限制

以下内容**不脱敏、不渲染**(留给后续 Qwen-VL 图片识别阶段补齐):

- 幻灯片中的**图片**(包括截图、Logo、扫描件)
- **SmartArt** 图示(python-pptx 不支持读取)
- **图表(Chart)内嵌数据**(柱状图/饼图的标签和数据点)
- **页眉页脚 / 母版** 上的固定文字
- **形状内部的复杂样式**(段内混排粗体/斜体会被规整,与 docx_writer 一致)
- **动画 / 切换效果 / 配色方案**(脱敏副本目标是给 LLM 读,不是给人放 PPT)

如果用户的关键信息全在图片里(例如纯图片版的合同截图 PPT),提示用户该 PPT 当前
版本无法自动脱敏图片内容,需手动处理或等待 Qwen-VL 接入。

## 给用户的标准应答模板

当用户说"帮我看下 / 总结 / 翻译 / 处理这个 .pptx"时,第一句先说明流程,再调 Bash:

```
我先用 pptx_to_md.py 把这个 .pptx 脱敏成 .md(Claude Code 的 Read 拒读 .pptx 二进制),
然后基于 .md 做后续操作,确保敏感数据不外发。
```

接着立即调用:
```
Bash: "${CLAUDE_PLUGIN_ROOT}\skills\pptx-redact\run.cmd" "<用户给的 .pptx 路径>"
```
拿到 stdout 的 .md 路径后立刻 Read 它。

## 文件清单(本 skill 自包含)

- `pptx_to_md.py`:CLI 入口(编排脚本)
- `pptx_writer.py`:pptx → markdown 渲染器
- `redactor.py` / `pseudonymizer.py`:L1+L2 合并替换
- `llm_detector.py` / `llm_client.py` / `llm_config.py`:L2 LLM NER
- `entity_map.py`:跨幻灯片一致性占位符分配
- `mask_strategies.py`:保形掩码策略
- `rules.py` + `rules.yml`:L1 正则规则
- `wordlib.py` + `word_library.yml`:业务词库
- `validators.py`:luhn / 身份证校验
- `match.py`:Match 数据结构
- `requirements.txt`:python-pptx, PyYAML, openai
- `.env`(可选):LLM 凭据 `base_url` / `api_key` / `model`(也可走环境变量
  `DEEPSEEK_ENDPOINT` / `DEEPSEEK_API_KEY` / `DEEPSEEK_MODEL`)

L2 LLM 不可达时自动降级到纯 L1(手机 / 邮箱 / 卡号 等结构化字段仍可脱敏,
姓名 / 公司 / 产品等语义实体会保留原文)。
