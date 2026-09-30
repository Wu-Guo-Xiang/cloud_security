# Claude 输入安全控制

> 对应文档：[doc/目标三-Claude输入安全控制-实施方案.md](../../doc/目标三-Claude输入安全控制-实施方案.md)

Claude Code 的输入侧安全中间件，通过 Hook 在两个时机介入：
- **PreToolUse**（内容流入类工具：`Read` / `Grep` / `WebFetch` / `Bash` / `Write` / `Edit` / `MultiEdit` / `NotebookEdit`）— Claude 准备读取或落盘外部内容前
- **UserPromptSubmit** — 用户提交 prompt 前（防粘贴）

入口 [input_scanner.py](input_scanner.py) 是 Hook 拉起的一次性脚本，stdin 收事件 JSON，exit code + stderr 回应决策。任何异常 → **fail-closed** 阻断。

## 流水线

```
Hook 事件 → extract → cache lookup → detect (L1 + L2) → action
            │           │              │                 │
            │           │              │                 ├─ 无命中 → pass (exit 0)
            │           │              │                 ├─ Read 文本/docx/pdf → 写脱敏副本 + redirect (exit 2)
            │           │              │                 ├─ UPS → 弹系统 MessageBox 确认 → 是=pass(exit 0) / 否|超时=block(exit 2)
            │           │              │                 └─ Grep / WebFetch / 不支持格式 → 降级阻断 (exit 2)
            │           │              │
            │           │              ├─ L1 credential / pattern regex
            │           │              └─ L2 DeepSeek NER（COMPANY / PERSON / PRODUCT / MONEY / ID_NUMBER；UPS 路径额外启用 PASSWORD）
            │           │                 长文档按 \n\n → \n → 字符硬切递降切块，并发调用合并（见 doc/目标三-LLM长文档切块设计.md）
            │           │
            │           └─ key = sha256(content) | rules.v | wordlib.v | llm.v
            │              session pickle；L2 失败不写缓存
            │
            └─ 受控目录外、不支持工具 → skip 放行
               扫描件 PDF / 缺库 → fail-closed 阻断（_BLOCK_ON_SKIP）
```

## 目录结构

```
input\
├── input_scanner.py            # Hook 入口（PreToolUse / UserPromptSubmit 共用）
├── requirements.txt            # PyYAML + python-docx + pdfplumber + openai
├── README.md                   # 本文件
│
├── config\                     # 配置
│   ├── paths.py / paths.yml    # 路径配置（本地测试 / 云桌面唯一切换点）
│   ├── rules.py / rules.yml    # 敏感分类（regex / validator / mask_strategy / capture_group）
│   ├── llm.py / llm.yml        # L2 LLM 接入（base_url/api_key/model 走 .env）
│   ├── wordlib.py              # 词库加载 + 版本哈希
│   ├── word_library.yml        # 公司业务词库（运营维护）
│   └── identity.yml            # 本地用户→部门映射（云桌面接 LDAP 时替换）
│
├── lib\                        # 通用基础
│   ├── event.py                # Hook JSON 事件解析（Event 数据类）
│   ├── response.py             # Hook 返回值构造（pass / block / redirect / ups_block）
│   ├── confirm.py              # UPS 命中后弹系统 MessageBox 让用户确认（绕过 VSCode 扩展不渲染 stderr 的 bug）
│   ├── logger.py               # 结构化 JSONL 审计日志
│   ├── llm_client.py           # DeepSeek HTTP 封装（OpenAI 兼容，永不抛异常）
│   ├── validators.py           # luhn / id_card 校验位
│   └── types.py                # Match 数据类
│
├── extractors\                 # 抽取
│   ├── base.py                 # ExtractResult 契约
│   ├── dispatcher.py           # 按事件类型分发
│   ├── file_extractor.py       # Read：T1 文本 + .docx + .pdf（pdfplumber + NFKC + 跨行合并）
│   ├── grep_extractor.py       # Grep：pattern + path（不读匹配到的文件）
│   ├── url_extractor.py        # WebFetch：URL + prompt（不抓远端内容）
│   └── prompt_extractor.py     # UserPromptSubmit：透传 prompt
│
├── detectors\                  # 识别
│   ├── dispatcher.py           # 串行 L1 → 可选 L2，合并为 DetectAggregate
│   ├── credential_detector.py  # L1：API Key / 私钥 / 密码 / DB URI
│   ├── pattern_detector.py     # L1：rules.yml 规则 + bank_card Luhn 候选 + 词库
│   ├── presidio_detector.py    # 备选 NER（stub，未启用）
│   └── llm_detector.py         # L2：DeepSeek NER + span 原文复核（防幻觉）
│
├── actions\                    # 决策动作
│   ├── base.py                 # ActionOutcome 契约
│   ├── dispatcher.py           # 无命中→pass；有命中→desensitize_action
│   ├── desensitize_action.py   # 主编排：Read 副本 / UPS 弹框确认 / 降级阻断
│   ├── docx_writer.py          # .docx 段级回写（段落+表格 cell 逐段调脱敏闭包）
│   ├── redactor.py             # L1 span 合并 + 替换
│   ├── pseudonymizer.py        # L1+L2 span 合并 + 一致性假名化
│   └── mask_strategies.py      # 保形掩码集（手机/邮箱/卡号/IP/api_key/...）
│
├── cache\                      # Session 级缓存（pickle）
│   ├── session_cache.py        # 扫描结果缓存；key 含 rules/wordlib/llm 三版本
│   └── entity_map.py           # 实体→占位符字典（COMPANY 子串别名归并）
│
└── tests\
    ├── run_all.py              # 伞型测试入口
    ├── smoke_test.py           # 端到端 Hook 冒烟
    ├── llm_smoke.py            # LLM 连通性独立烟雾测试（不依赖正式管线）
    ├── test_validators.py
    ├── test_credential_detector.py
    ├── test_pattern_detector.py
    ├── test_extractors.py
    ├── test_redactor.py
    ├── test_session_cache.py
    ├── test_actions.py
    ├── test_entity_map.py
    ├── test_pseudonymizer.py
    ├── test_llm_detector.py
    ├── test_docx_writer.py
    └── sample_*.json           # 各类 Hook 事件样本
```

## 决策映射（v2：命中即脱敏，无评分门限）

| 命中情况 | 事件 / 抽取结果 | 行为 | exit |
|---|---|---|---|
| 无命中 | 任意 | `respond_pass` | 0 |
| 有命中 | Read 文本（T1）/ Word（.docx）/ PDF（.pdf） | 生成脱敏副本 → `respond_redirect`（stderr 提示改读副本路径） | 2 |
| 有命中 | UserPromptSubmit | 弹系统 MessageBox 让用户确认：点是 → `respond_pass`；点否/超时/异常 → `respond_userprompt_block`（stderr 给出脱敏建议） | 0 / 2 |
| 有命中 | Grep / WebFetch / 不支持的 Read 扩展名 | `respond_block`（无 redirect 通道，降级阻断） | 2 |

脱敏副本路径：`{paths.temp_desensitized}\<session_id>\<stem>_<sha[:12]><ext>`。
PDF 副本写成 `.txt`（避免再次按二进制解析）。

## 关键设计点

- **重定向递归短路**：[input_scanner.py:94](input_scanner.py#L94) 用 `paths.is_within_desensitized_dir` 在脱敏副本被 Claude 改读时短路整条管线，`phase=recursion_skipped`，避免重复 LLM 调用。
- **L1 优先于 L2**：[actions/pseudonymizer.py](actions/pseudonymizer.py) 合并 span 时 L1 优先，与 L1 重叠的 L2 实体被丢弃；防止 L1 保形掩码（`138****5678`）被 L2 占位符（`[号码]`）覆盖丢失类目语义。
- **L2 长文档切块**：`call.max_input_chars` 是**单 chunk 上限**，不是全文截断点。超长文档按 `\n\n → \n → 字符硬切` 递降切分，`ThreadPoolExecutor` 并发调用 LLM，结果用全文 `find` 重定位后去重合并。详见 [doc/目标三-LLM长文档切块设计.md](../../doc/目标三-LLM长文档切块设计.md)。
- **一致性占位符**：[cache/entity_map.py](cache/entity_map.py) 按 type 维护 `text → 占位符` 字典；COMPANY 启用"互为子串"启发式，"腾讯科技" / "腾讯科技有限公司" 共用 `[公司A]`；PERSON / PRODUCT 关闭以防误并；MONEY 统一塌缩到 `[金额]`，不分桶。
- **.docx 段级回写**：[actions/docx_writer.py](actions/docx_writer.py) 走段落 + 表格 cell，逐段调注入的脱敏闭包，共享同一个 `EntityMap` 保跨段一致；段内 run 级字体丢失（v1 已知限制，不影响安全性）。
- **fail-closed 兜底闸门**：[input_scanner.py](input_scanner.py) 顶部 `_BLOCK_ON_SKIP` 列出三种 skip 原因（`pdf_no_text_layer` / `pdf_lib_missing` / `docx_lib_missing`）强制阻断 —— 这类文件 Claude 仍能拿到原内容，不阻断会直接泄露。
- **Grep / WebFetch 不走 L2**：[input_scanner.py:143](input_scanner.py#L143) 主动短路 LLM。URL 和 pattern 串走 NER 收益低、误报高。
- **缓存键三版本绑定**：`sha256(content) | rules.version | wordlib.version | llm.version`，任一配置改动即全量失效；L2 真失败不写缓存（避免把瞬时网络抖动固化成永久 L1 降级）。
- **UPS 弹框确认**：[lib/confirm.py](lib/confirm.py) 用 ctypes 调 `user32.MessageBoxTimeoutW`,UPS 命中后弹系统 MessageBox(默认焦点 NO + TOPMOST + 25s 超时,fail-closed)。原本想走 hook 协议 `decision:block` 让 VSCode 渲染拦截原因,但实测扩展 webview 不渲染 stderr/systemMessage（上游已知 bug anthropics/claude-code#10964、#15021、#31285），block 生效但用户在 UI 上看不到原因。MessageBox 是系统级前台窗口，不受任何通知策略影响，且天然阻塞匹配 hook 同步语义。

## 本地测试

```bash
# 1. 安装依赖（PyYAML + python-docx + pdfplumber + openai）
py -m pip install -r requirements.txt

# 2. 调整 config/paths.yml 中的 controlled_workdir
#    （当前默认: D:\cloud_security\test）

# 3. （可选）配置 .env 启用 L2 LLM；不配的话只跑 L1
#    项目根 .env 需要：base_url / api_key / model 三个变量

# 4. LLM 连通性自检（首次接入新环境必跑）
py tests\llm_smoke.py --dry-run        # 只打模板，不发请求
py tests\llm_smoke.py                  # 实际探测

# 5. 全量测试
py tests\run_all.py

# 6. 检查日志
type "D:\cloud_security\test\logs\input_scanner.jsonl"
```

## Hook 接入

在 Windows 全局托管配置 `C:\ProgramData\ClaudeCode\managed-settings.json` 中：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Grep|WebFetch|Bash|Write|Edit|MultiEdit|NotebookEdit",
        "hooks": [{
          "type": "command",
          "command": "py C:\\ProgramData\\ClaudeSecurity\\input\\input_scanner.py --event PreToolUse",
          "timeout": 30000
        }]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [{
          "type": "command",
          "command": "py C:\\ProgramData\\ClaudeSecurity\\input\\input_scanner.py --event UserPromptSubmit",
          "timeout": 30000
        }]
      }
    ]
  }
}
```

> UPS hook 的 `timeout` 必须 ≥ `confirm.py` 的弹框超时 + 缓冲（当前 25s + 5s = 30s）。把 hook timeout 调短会让弹框还没等到用户点击就被 Claude Code 强杀,行为不可预期。
>
> matcher 把 `Bash` / `Write` / `Edit` / `MultiEdit` / `NotebookEdit` 一起纳入，是为了堵住 `Read` 被拦后 Claude 改用 `cat` / `type` / `Get-Content` 经 Bash 绕读、或把外部内容直接写入工作区文件再读的旁路。L2 切块开关、超时、并发统一在 [config/llm.yml](config/llm.yml) 中维护。

## 云桌面部署

仅需修改 [config/paths.yml](config/paths.yml) 中的两个根路径：

```yaml
controlled_workdir:  'D:\工作'
security_script_dir: 'C:\ProgramData\ClaudeSecurity'
```

派生路径会基于这两个根自动展开，其他代码不需要改动。
身份识别仍走本地 `config/identity.yml`，云桌面接入 LDAP 时只需替换查询实现，调用方契约不变。
