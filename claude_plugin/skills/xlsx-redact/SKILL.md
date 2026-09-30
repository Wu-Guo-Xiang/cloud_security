---
name: xlsx-redact
description: Use this skill for ANY operation on .xlsx / .xlsm files (Microsoft Excel workbooks) — reading content, summarizing, extracting sheets/tables, translating, filtering, pivoting, editing, merging, or converting. Invoke this skill BEFORE using openpyxl, pandas.read_excel, xlrd, pandoc, libreoffice, unzip on sheet xml, or attempting to Read the .xlsx directly. Claude Code's Read rejects .xlsx as binary, so you MUST go through the bundled xlsx_to_md.py CLI which performs L1 (regex) + L2 (LLM NER) desensitization and produces a readable .md copy.
---

# XLSX 处理 — 安全合规约束

本 skill 自带脱敏脚本与所需的全部 Python 依赖,**不需要外部 cloud_security 代码**。
.xlsx 不能直接 Read(Claude Code 会以 binary 拒绝),必须先用本 skill 下的
`xlsx_to_md.py` 把 .xlsx 脱敏成 .md,再 Read .md。

## 强制工作流

### 第 1 步:用 Bash 调脚本

```
Bash: "${CLAUDE_PLUGIN_ROOT}\skills\xlsx-redact\run.cmd" "<原 .xlsx 绝对路径>"
```

⏰ **耗时预期**:LLM 脱敏走远程服务,典型耗时 **30-90 秒**(大文件 / LLM 负载高时
   可能更久)。请告知用户"正在脱敏,大约 1 分钟,请稍候",然后耐心等待 Bash
   命令返回:
   - 若超 120s 触发 Bash 默认 timeout,**不要给 Bash 加 `timeout` 参数延长**
     (会绕过保护)——直接重新 invoke 即可。脚本内部已经做了一次重试,LLM 仍
     失败会弹 MessageBox 让用户确认是否接受 L1-only 输出。
   - **不要中途中断或在原命令未返回时另起一条**——重复调起会加倍占用 LLM 配额。

脚本内部:
- openpyxl 按工作表遍历所有单元格(`data_only=True` 取公式缓存值)
- L1 正则 + L2 LLM 实体识别(DeepSeek 兼容 API)
- 工作簿级一致性占位符替换([人员A]/[公司A]/[产品A]/[金额])
- 按 sheet 顺序渲染成 markdown(`## Sheet N: SheetName` → markdown 表格)
- 写到固定输出目录 `D:\After-tuomin\xlsx\{session_id}\{原文件名}_{12位hash}.md`
- **stdout 输出该 .md 的绝对路径**(UTF-8 编码),exit 0

可选环境变量 `XLSX_SKILL_OUT_DIR` 覆盖输出目录。

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

工作簿结构在 .md 里体现为:
- `## Sheet 1: SheetName`(每个工作表一节)
- 隐藏 sheet 标题加 ` (hidden)` 标记,仍渲染内容
- 每张表的首行作 markdown 表头,其余作 body
- 空表渲染为 `_(empty sheet)_`
- 单元格内的换行折叠成空格,管道符 `|` 转义,避免破坏 markdown 表格

### 第 3 步:所有后续操作基于 .md 副本

总结、翻译、提取、对比、统计、问答 —— 一律在 .md 上进行。**不要**再回头 Read 原 .xlsx,
也不要用其他工具直接抽原文。

## .xls 旧二进制格式 / .xlsm 宏

| 格式 | 支持 |
|---|---|
| `.xlsx` | ✅ 完整支持 |
| `.xlsm`(含 VBA 宏) | ✅ 当作 .xlsx 读取,**不执行宏**,只读单元格值 |
| `.xls`(Excel 97-2003 二进制) | ❌ openpyxl 不支持,脚本 exit 1 |
| `.xlsb`(二进制工作簿) | ❌ 当前不支持 |

遇到 `.xls` / `.xlsb` 时:**告诉用户在 Excel 里打开并"另存为 .xlsx"后再来**。脚本会
直接 exit 1 报错,不要尝试用其他工具(xlrd / libreoffice / pandoc)绕过。

## 严禁的绕过行为

以下做法绕过脱敏,**严禁使用**:

- ❌ `Read(file_path="xxx.xlsx")` —— Claude Code Read 会以 binary 为由拒绝
- ❌ `python -c "import openpyxl; wb = openpyxl.load_workbook('xxx.xlsx'); ..."`
- ❌ `python -c "import pandas as pd; print(pd.read_excel('xxx.xlsx'))"`
- ❌ `pandoc xxx.xlsx -o xxx.csv` 或 `xlsx2csv xxx.xlsx`
- ❌ `libreoffice --headless --convert-to csv xxx.xlsx`
- ❌ `unzip xxx.xlsx -d /tmp/x && cat /tmp/x/xl/sharedStrings.xml`
- ❌ 在临时脚本里 `from openpyxl import load_workbook` 后直接 print 单元格

如果你已经"想到"要写这种脚本,**立即停下来改走 xlsx_to_md.py**。

## 编辑 / 创建 / 转换场景

| 场景 | 正确做法 |
|---|---|
| 总结 / 问答 / 翻译原 .xlsx | Bash 调 xlsx_to_md.py → Read .md → 在 .md 上回答 |
| 统计 / 过滤 / 透视原 .xlsx | Bash → Read .md → 在 .md 表格基础上做分析(必要时让 Claude 写新 .xlsx) |
| 修改原 .xlsx 内容 | Bash → Read .md → 在 .md 上理解 → 用 openpyxl 写**新 .xlsx 文件**,**不回写原文件** |
| 从 .xlsx 生成报告 | 同上,写新 .xlsx 或 .docx,不动原文 |
| 创建全新 .xlsx(无原文输入) | 直接用 openpyxl 写,无脱敏依赖 |
| 合并多个 .xlsx | 每个原 .xlsx 各自 xlsx_to_md.py → 在多个 .md 基础上合并 |

## v1 已知限制

以下内容**不脱敏、不渲染**:

- **图表(Chart)**:折线图/饼图/柱状图的标签和数据系列
- **透视表(PivotTable)**:仅渲染源数据区,透视表本身不展开
- **图片**(嵌入的 Logo、截图、扫描件)
- **形状 / 文本框**(漂浮在 sheet 上的注释框)
- **批注(Comment)**:openpyxl 能读但 v1 不渲染
- **条件格式 / 数据验证 / 单元格样式**(脱敏副本目标是给 LLM 读,不还原格式)
- **公式本身**:取的是缓存计算值;若 .xlsx 从未在 Excel 中打开过,缓存可能为空 → 该单元格为空
- **合并单元格**:openpyxl 默认 top-left 持值、其他 None,这里按 None 渲染空,**不复制 top-left 的值**到其他单元格
- **超宽工作表**:50+ 列的 sheet 渲染成 markdown 表格后人眼很难读,但 LLM 仍能解析

如果用户的关键信息在图表 / 图片 / 批注里,提示用户该 sheet 当前版本无法自动脱敏这些内容,
需手动导出或等待后续版本。

## 给用户的标准应答模板

当用户说"帮我看下 / 总结 / 统计 / 处理这个 .xlsx"时,第一句先说明流程,再调 Bash:

```
我先用 xlsx_to_md.py 把这个 .xlsx 脱敏成 .md(Claude Code 的 Read 拒读 .xlsx 二进制),
然后基于 .md 做后续操作,确保敏感数据不外发。
```

接着立即调用:
```
Bash: "${CLAUDE_PLUGIN_ROOT}\skills\xlsx-redact\run.cmd" "<用户给的 .xlsx 路径>"
```
拿到 stdout 的 .md 路径后立刻 Read 它。

## 文件清单(本 skill 自包含)

- `xlsx_to_md.py`:CLI 入口(编排脚本)
- `xlsx_writer.py`:xlsx → markdown 渲染器
- `redactor.py` / `pseudonymizer.py`:L1+L2 合并替换
- `llm_detector.py` / `llm_client.py` / `llm_config.py`:L2 LLM NER
- `entity_map.py`:跨 sheet / 跨单元格一致性占位符分配
- `mask_strategies.py`:保形掩码策略
- `rules.py` + `rules.yml`:L1 正则规则
- `wordlib.py` + `word_library.yml`:业务词库
- `validators.py`:luhn / 身份证校验
- `match.py`:Match 数据结构
- `requirements.txt`:openpyxl, PyYAML, openai
- `llm.yml`:L2 LLM 类型映射(姓名→人员、公司→公司 等)
- `.env`(可选):LLM 凭据 `base_url` / `api_key` / `model`(也可走环境变量
  `DEEPSEEK_ENDPOINT` / `DEEPSEEK_API_KEY` / `DEEPSEEK_MODEL`)

L2 LLM 不可达时自动降级到纯 L1(手机 / 邮箱 / 卡号 等结构化字段仍可脱敏,
姓名 / 公司 / 产品等语义实体会保留原文)。
