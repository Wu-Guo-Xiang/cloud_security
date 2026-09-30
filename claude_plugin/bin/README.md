# bin/ — 打包产物目录

> 这个目录 **在提交时是空的**(只有 .cmd 启动器),真正的 exe 由 `build.py` 生成后落盘。

## 结构

| 文件 | 说明 |
| --- | --- |
| `input_scanner.cmd`  | 启动器 → 优先跑本目录 `input_scanner.exe`,不存在则回落 `py -3 ../src/input/input_scanner.py` |
| `output_scanner.cmd` | 同上,回落 `../src/output/output_scanner.py` |
| `stop_reviewer.cmd`  | 同上,回落 `../src/output/stop_reviewer.py` |
| `*.exe`              | 由 PyInstaller onedir 打包(见 `../build.py`),员工机部署时和 `.cmd` 一起分发 |
| `_internal/`         | PyInstaller onedir 的 Python 运行时目录(自动生成,不要手改) |

## 为什么用 .cmd 中转

hooks.json 里写死 `.cmd` 路径,不管员工机装没装 Python 都能拉起:

- **开发机(有 Python)**: 没有 exe → 走源码路径,改一行 py 立刻生效,不用重新打包
- **员工机(纯净)**: 有 exe → 跑打包版本,不需要装 Python / 装依赖

## PowerShell 用户注意

`.cmd` 从 PS 里也能启,但 Claude Code hook 默认用 `cmd.exe` 拉起,所以无所谓。
