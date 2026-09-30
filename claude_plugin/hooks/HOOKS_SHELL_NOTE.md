# hooks.json 执行形式说明

## 现在用 command + args 形式(不经 shell)

`hooks/hooks.json` 里每个 hook 用 **command + args** 形式,Claude Code 直接
`exec` python,**不经过 CMD / PowerShell / Git Bash 解析**:

```json
{
  "type": "command",
  "command": "D:\\ClaudeSecurity\\python\\python.exe",
  "args": ["C:\\...\\src\\input\\input_scanner.py", "--event", "PreToolUse"],
  "timeout": 30000
}
```

- `command` 是 python.exe 绝对路径,`args` 是脚本路径 + 参数。
- Claude Code 直接启动进程,不再有 shell 参与 → 员工机默认 shell 是 cmd / PowerShell /
  Git Bash 都不影响 hook,彻底解决跨 shell 解析差异。
- python 的 `sys.exit(2)` 退出码由 Claude Code **直接读取**,无需 shell 层转发,
  避开旧写法里 PowerShell 引号 / `; exit $LASTEXITCODE` 传播 / .cmd 启动器吞 exit 2
  等一系列历史坑。

## 已知代价:python.exe 缺失时 fail-open

command 指向的 python.exe 若被删除/改名/移动,Claude Code **spawn 失败时不会阻断**
(fail-open),操作会放行。旧的 PowerShell 写法靠 `if ($LASTEXITCODE -eq $null) { exit 2 }`
做 fail-closed 兜底,command+args 形式下没有这一层。

**兜底手段**:安装始终传入嵌入式 python 绝对路径;`bin/diagnose.py` 会校验
command / args 引用的 python.exe 与脚本是否存在,缺失即报 bad。

## 修改 hooks.json 形式时需同步的文件

- `claude_plugin/hooks/hooks.json`(源码模板,带占位符)
- `deploy/hooks.template.json`(部署模板)
- `deploy/_gen_hooks_json.py` / `deploy/_render_hooks.py`(渲染脚本,纯文本替换占位符)
- `claude_plugin/src/updater/updater.py` 的 `_render_hooks`(更新流程渲染)
- `claude_plugin/bin/diagnose.py`(Section B/D 形式校验、Section E 直接 `subprocess.run([command, *args])` 自检)
- `deploy/fix_hooks_quoting.py`(把旧 shell 命令串一键迁移到 command+args)

相关排查文档:`docx/FIX_hooks_not_firing.md`、`docx/FIX_hooks_exit_code_lost.md`
