# -*- coding: utf-8 -*-
"""cloud-guard 员工机自检脚本 — 定位"不写日志"断在哪一环。

在员工机上用 embeddable python 运行:
    "D:\\ClaudeSecurity\\python\\python.exe" "%USERPROFILE%\\.claude\\plugins\\cloud-guard\\bin\\diagnose.py"

加 --fix 自动修复能自动修的问题(改 settings.json 前自动备份 .bak_diagnose_*):
  - enabledPlugins 被禁用(false)   → 改回 true
  - env.CLOUD_GUARD_PYTHON 缺失     → 写入找到的 embeddable python 路径
  - settings.json 旧 hooks 非空    → 清空为 {}(防双跑)
  - hooks.json 占位符残留          → 渲染为绝对路径
  - 缓存与安装目录不一致           → 从安装目录同步
修完自动复检,输出最终报告。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

USERPROFILE = Path(os.environ.get("USERPROFILE", str(Path.home())))
CLAUDE_DIR = USERPROFILE / ".claude"
PLUGIN_DIR = CLAUDE_DIR / "plugins" / "cloud-guard"
SETTINGS = CLAUDE_DIR / "settings.json"
IP_JSON = CLAUDE_DIR / "plugins" / "installed_plugins.json"
DEFAULT_PY = Path(r"D:\ClaudeSecurity\python\python.exe")

_results: list[tuple[str, str, str]] = []
_fixed_count = 0


def ok(item, detail=""):
    _results.append(("OK ", item, detail))
    print(f"OK   {item}" + (f"  — {detail}" if detail else ""))

def warn(item, detail=""):
    _results.append(("WARN", item, detail))
    print(f"WARN {item}" + (f"  — {detail}" if detail else ""))

def bad(item, detail=""):
    _results.append(("XXX ", item, detail))
    print(f"XXX  {item}" + (f"  — {detail}" if detail else ""))

def fixed(item, detail=""):
    global _fixed_count
    _fixed_count += 1
    print(f"FIX  {item}" + (f"  — {detail}" if detail else ""))

def section(title):
    print()
    print(f"=== {title} ===")


def find_python() -> Path | None:
    try:
        env = json.loads(SETTINGS.read_text(encoding="utf-8")).get("env") or {}
        p = env.get("CLOUD_GUARD_PYTHON")
        if p and Path(p).exists():
            return Path(p)
    except Exception:
        pass
    p = os.environ.get("CLOUD_GUARD_PYTHON")
    if p and Path(p).exists():
        return Path(p)
    if DEFAULT_PY.exists():
        return DEFAULT_PY
    return None


def _backup_settings() -> Path:
    bak = SETTINGS.with_name(SETTINGS.name + f".bak_diagnose_{time.strftime('%Y%m%d_%H%M%S')}")
    shutil.copy2(SETTINGS, bak)
    return bak


def _load_settings() -> dict:
    return json.loads(SETTINGS.read_text(encoding="utf-8"))


def _save_settings(d: dict) -> None:
    SETTINGS.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")


def fix_enabled_plugins() -> bool:
    d = _load_settings()
    en = d.get("enabledPlugins") or {}
    keys = [k for k in en if k.startswith("cloud-guard@")]
    if not keys or all(en[k] for k in keys):
        return False
    _backup_settings()
    d.setdefault("enabledPlugins", {})
    for k in keys:
        d["enabledPlugins"][k] = True
    _save_settings(d)
    return True


def fix_env_python(py: Path) -> bool:
    d = _load_settings()
    env = d.get("env") or {}
    if env.get("CLOUD_GUARD_PYTHON") == str(py):
        return False
    _backup_settings()
    d.setdefault("env", {})["CLOUD_GUARD_PYTHON"] = str(py)
    _save_settings(d)
    return True


def fix_clear_old_hooks() -> bool:
    d = _load_settings()
    if not (d.get("hooks") or {}):
        return False
    _backup_settings()
    d["hooks"] = {}
    _save_settings(d)
    return True


def fix_render_hooks_file(hooks_file: Path, plugin_dir: Path, py: Path | None) -> bool:
    text = hooks_file.read_text(encoding="utf-8")
    if "__PLUGIN_DIR__" not in text and "__PYTHON_EXE__" not in text:
        return False
    text = text.replace("__PLUGIN_DIR__", str(plugin_dir).replace("\\", "\\\\"))
    if py:
        text = text.replace("__PYTHON_EXE__", str(py).replace("\\", "\\\\"))
    hooks_file.write_text(text, encoding="utf-8")
    return True


def fix_sync_cache(cache_dir: Path) -> int:
    exclude = {".git", "__pycache__", "build", "dist", "release", ".pytest_cache", "tests"}
    n = 0
    for item in PLUGIN_DIR.rglob("*"):
        if item.is_dir():
            continue
        rel = item.relative_to(PLUGIN_DIR)
        if any(p in exclude for p in rel.parts):
            continue
        dst = cache_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dst.exists() or hashlib.md5(dst.read_bytes()).hexdigest() != hashlib.md5(item.read_bytes()).hexdigest():
            shutil.copy2(item, dst)
            n += 1
    for item in cache_dir.rglob("*"):
        if item.is_dir():
            continue
        rel = item.relative_to(cache_dir)
        if any(p in exclude for p in rel.parts):
            continue
        if not (PLUGIN_DIR / rel).exists():
            item.unlink(missing_ok=True)
    return n


def run_checks(fix: bool) -> None:
    _results.clear()
    print("cloud-guard 员工机自检" + ("（--fix 自动修复模式）" if fix else ""))
    print(f"用户目录: {USERPROFILE}")

    # ============ A. Python 环境 ============
    section("A. Python 环境")
    py = find_python()
    if not py:
        bad("embeddable python", f"未找到(试过 settings.json env / 环境变量 / {DEFAULT_PY})")
        print("     人工修复: 重跑 install_plugin.bat 部署 python")
    else:
        ok("embeddable python 存在", str(py))
        try:
            r = subprocess.run([str(py), "--version"], capture_output=True, text=True, timeout=10)
            ok("python 可启动", (r.stdout or r.stderr).strip())
        except Exception as e:
            bad("python 无法启动", str(e))
        # 单进程一次 import 全部依赖(避免逐个起进程 + pdfplumber 冷启动慢
        # 导致的超时误报),60s 超时对慢机器也够。
        _dep_code = (
            "import importlib\n"
            "mods=['yaml','docx','pdfplumber','openpyxl','pptx','win32api']\n"
            "bad=[]\n"
            "for m in mods:\n"
            "    try:\n"
            "        importlib.import_module(m)\n"
            "    except Exception:\n"
            "        bad.append(m)\n"
            "print(','.join(bad))\n"
        )
        missing = []
        try:
            r = subprocess.run([str(py), "-c", _dep_code],
                               capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                missing = [m for m in r.stdout.strip().split(",") if m]
            else:
                missing = ["<依赖检测进程本身失败>"]
        except subprocess.TimeoutExpired:
            missing = ["<依赖检测超时(>60s),机器过慢或被杀毒扫描,请手动复核>"]
        if missing:
            bad("python 依赖", f"缺失: {', '.join(missing)}")
            print(f'     人工修复: "{py}" -m pip install pdfplumber python-docx openpyxl python-pptx pywin32 pyyaml')
        else:
            ok("python 依赖完整", "yaml/docx/pdfplumber/openpyxl/pptx/win32api")

    # ============ B. 插件文件 ============
    section("B. 插件文件")
    if not PLUGIN_DIR.exists():
        bad("插件安装目录", f"不存在: {PLUGIN_DIR}")
        print("     人工修复: 重跑 install_plugin.bat")
    else:
        ok("插件安装目录", str(PLUGIN_DIR))

    pj = PLUGIN_DIR / ".claude-plugin" / "plugin.json"
    plugin_ver = "?"
    if pj.exists():
        try:
            plugin_ver = json.loads(pj.read_text(encoding="utf-8")).get("version", "?")
            ok("plugin.json", f"version={plugin_ver}")
        except Exception as e:
            bad("plugin.json 解析失败", str(e))
    else:
        bad("plugin.json", "不存在")

    hooks_path = PLUGIN_DIR / "hooks" / "hooks.json"
    hook_cmds = {}
    hook_args = {}
    if not hooks_path.exists():
        bad("hooks.json", f"不存在: {hooks_path}")
    else:
        try:
            raw = hooks_path.read_text(encoding="utf-8")
            leftover = next((x for x in ("__PLUGIN_DIR__", "__PYTHON_EXE__", "${CLAUDE_PLUGIN_ROOT}") if x in raw), None)
            if leftover:
                if fix and leftover != "${CLAUDE_PLUGIN_ROOT}" and fix_render_hooks_file(hooks_path, PLUGIN_DIR, py):
                    fixed("hooks.json 渲染", f"已替换占位符 {leftover}")
                    raw = hooks_path.read_text(encoding="utf-8")
                else:
                    bad("hooks.json 未渲染", f"残留占位符 {leftover}")
                    print("     人工修复: 重跑 install_plugin.bat(或 diagnose.py --fix 仅修 __ 占位符)")
            if leftover is None or fix:
                try:
                    hj = json.loads(hooks_path.read_text(encoding="utf-8"))
                    for ev, ms in hj.get("hooks", {}).items():
                        for m in ms:
                            for h in m.get("hooks", []):
                                # command+args 形式:command=python.exe, args=[脚本,...]
                                hook_cmds[ev] = h.get("command", "")
                                hook_args[ev] = h.get("args", []) or []
                    miss = False
                    for ev, cmd in hook_cmds.items():
                        # command(python.exe)与 args 里的脚本路径都要检查存在性。
                        tokens = [cmd] + list(hook_args.get(ev, []))
                        for token in tokens:
                            t = token.strip().strip('"').strip("'")
                            if t.lower().endswith((".py", ".exe", ".cmd")) and ":" in t:
                                if not Path(t).exists():
                                    bad(f"hook 命令引用文件缺失({ev})", t)
                                    miss = True
                                    break
                        if miss:
                            break
                    if not miss and hook_cmds:
                        ok("hook 命令引用的文件", "全部存在")
                    # command+args 形式校验:command 应是 python.exe 直连,不应残留旧
                    # PowerShell 单命令串(& '...' / $LASTEXITCODE)。旧形式依赖 shell 解析,
                    # 跨 shell 不稳,必须迁移到 args 形式。
                    old_form = [ev for ev, c in hook_cmds.items()
                                if ("$LASTEXITCODE" in c or c.strip().startswith("&"))]
                    if old_form:
                        bad("hook 仍是旧 shell 命令串", f"{old_form} 未迁移到 command+args 形式")
                        print("     修复: 重跑 install_plugin.bat 重新渲染 hooks.json")
                    no_args = [ev for ev, c in hook_cmds.items()
                               if c and c.lower().endswith((".exe",)) and not hook_args.get(ev)]
                    if no_args:
                        warn("hook command 指向 exe 但无 args", f"{no_args} 缺 args(脚本路径)")
                except Exception as e:
                    bad("hooks.json 解析失败", str(e))
        except Exception as e:
            bad("hooks.json 读取失败", str(e))

    # ============ C. 插件启用与 settings.json ============
    section("C. 插件启用与 settings.json")
    if not SETTINGS.exists():
        bad("settings.json", f"不存在: {SETTINGS}")
    else:
        try:
            st = _load_settings()
            en = st.get("enabledPlugins") or {}
            cg = {k: v for k, v in en.items() if k.startswith("cloud-guard@")}
            if not cg:
                # 首次安装后、/plugin 安装前是预期状态,不算阻断;
                # 只有"有条目但被禁用(false)"才是阻断。
                warn("enabledPlugins", "没有 cloud-guard 条目(插件尚未在 /plugin 中安装)")
                print("     下一步: Claude Code /plugin 里安装并启用 cloud-guard")
            elif not any(cg.values()):
                if fix and fix_enabled_plugins():
                    fixed("enabledPlugins 恢复启用", "cloud-guard@* 已置 true(settings.json 已备份)")
                    print("     注意: 需重开 Claude Code 才生效")
                else:
                    bad("enabledPlugins 被禁用(插件整体停用!)", f"{cg}")
                    print("     修复: diagnose.py --fix 自动改回,或 /plugin 里 Enable")
            else:
                ok("enabledPlugins", f"{cg}")

            env = st.get("env") or {}
            pyp = env.get("CLOUD_GUARD_PYTHON", "")
            if pyp and Path(pyp).exists():
                ok("env.CLOUD_GUARD_PYTHON", pyp)
            elif pyp:
                bad("env.CLOUD_GUARD_PYTHON", f"指向不存在的文件: {pyp}")
                if fix and py and fix_env_python(py):
                    fixed("env.CLOUD_GUARD_PYTHON 纠正", str(py))
            else:
                if fix and py and fix_env_python(py):
                    fixed("env.CLOUD_GUARD_PYTHON 补写", str(py))
                else:
                    warn("env.CLOUD_GUARD_PYTHON", "未设置(hooks.json 直调 python 时可不设,建议补上)")

            if st.get("hooks") or {}:
                if fix and fix_clear_old_hooks():
                    fixed("settings.json 旧 hooks 清空", "已置 {}(已备份)")
                else:
                    bad("settings.json hooks 非空", "旧 hook 会与插件 hook 双跑")
                    print("     修复: diagnose.py --fix 自动清空(先备份)")
            else:
                ok("settings.json hooks", "{} 无旧 hook")
        except Exception as e:
            bad("settings.json 解析失败", str(e))

    # ============ D. 缓存副本 ============
    section("D. 缓存副本(Claude Code 实际加载的可能是它)")
    if not IP_JSON.exists():
        warn("installed_plugins.json", "不存在 — 插件可能从未通过 /plugin 安装")
        print("     人工修复: Claude Code /plugin 添加 marketplace 并安装 cloud-guard")
    else:
        try:
            ip = json.loads(IP_JSON.read_text(encoding="utf-8"))
            entries = []
            for k, v in (ip.get("plugins") or {}).items():
                if k.startswith("cloud-guard@"):
                    entries.extend(v if isinstance(v, list) else [])
            if not entries:
                warn("installed_plugins.json", "无 cloud-guard 条目 — /plugin 里安装它")
            for e in entries:
                ipath = Path(e.get("installPath", ""))
                iver = e.get("version", "?")
                if not ipath.exists():
                    bad("缓存目录", f"记录的路径不存在: {ipath}")
                    print("     人工修复: /plugin 里 Disable→Enable 强制重建缓存")
                    continue
                ok("缓存目录", f"{ipath} (v{iver})")
                chooks = ipath / "hooks" / "hooks.json"
                if not chooks.exists():
                    # 缓存目录存在但 hooks.json 缺失 —— 常见于重跑 install_plugin.bat
                    # (只更新安装目录不碰缓存)或缓存被部分清理。--fix 时从安装目录
                    # 全量同步(含 hooks/),比 /plugin Disable→Enable 省事。
                    if fix and PLUGIN_DIR.exists():
                        n = fix_sync_cache(ipath)
                        fixed("缓存 hooks.json 缺失,已从安装目录同步", f"更新 {n} 个文件")
                    else:
                        bad("缓存 hooks.json", "不存在")
                        print("     修复: diagnose.py --fix 自动同步,或 /plugin Disable→Enable")
                    continue
                craw = chooks.read_text(encoding="utf-8")
                if any(x in craw for x in ("__PLUGIN_DIR__", "__PYTHON_EXE__", "${CLAUDE_PLUGIN_ROOT}")):
                    if fix and hooks_path.exists() and fix_sync_cache(ipath) >= 0:
                        fixed("缓存从安装目录同步", "hooks.json 等已刷新")
                    else:
                        bad("缓存 hooks.json 未渲染", "有占位符残留")
                        print("     修复: diagnose.py --fix 同步,或 /plugin Disable→Enable")
                else:
                    # 已渲染(无占位符),但检查是否已迁移到 command+args 形式。
                    # 缓存里若残留旧 & '...' / $LASTEXITCODE shell 命令串,跨 shell 不稳。
                    try:
                        cdata = json.loads(craw)
                        ccmds = [h.get("command","") for ms in (cdata.get("hooks") or {}).values() for m in ms for h in m.get("hooks",[])]
                        cold = [i for i, c in enumerate(ccmds)
                                if ("$LASTEXITCODE" in c or c.strip().startswith("&"))]
                        if cold:
                            bad("缓存 hook 仍是旧 shell 命令串", f"{len(cold)} 条未迁移到 command+args")
                            print("     修复: diagnose.py --fix 同步,或 /plugin Disable→Enable")
                        else:
                            ok("缓存 hooks.json 已渲染", "command+args 形式")
                    except Exception:
                        ok("缓存 hooks.json 已渲染", "")
                rel = Path("src/input/input_scanner.py")
                a, b = PLUGIN_DIR / rel, ipath / rel
                if a.exists() and b.exists():
                    if hashlib.md5(a.read_bytes()).hexdigest() != hashlib.md5(b.read_bytes()).hexdigest():
                        if fix:
                            n = fix_sync_cache(ipath)
                            fixed("缓存代码与安装目录同步", f"更新 {n} 个文件")
                        else:
                            warn("缓存与安装目录代码不一致", "input_scanner.py md5 不同")
                            print("     修复: diagnose.py --fix 同步,或跑 updater")
                    else:
                        ok("缓存与安装目录代码一致", "input_scanner.py")
                if iver != plugin_ver:
                    warn("缓存版本 ≠ 安装目录版本", f"缓存 v{iver} vs 安装 v{plugin_ver}")
        except Exception as e:
            bad("installed_plugins.json 解析失败", str(e))

    # ============ E. 实际执行 hook ============
    section("E. 实际执行 hook(模拟 Claude Code 调用)")
    jsonl_hint = None
    if py and hook_cmds.get("UserPromptSubmit"):
        cmd = hook_cmds["UserPromptSubmit"]
        cmd_args = hook_args.get("UserPromptSubmit", [])
        log_dir = None
        pyml = PLUGIN_DIR / "src" / "input" / "config" / "paths.yml"
        if pyml.exists():
            for line in pyml.read_text(encoding="utf-8").splitlines():
                ls = line.strip()
                if ls.startswith("logs:"):
                    log_dir = ls.split(":", 1)[1].strip().strip("'").strip('"')
                    break
        jsonl = Path(log_dir) / "input_scanner.jsonl" if log_dir else None
        before = sum(1 for _ in jsonl.open(encoding="utf-8")) if jsonl and jsonl.exists() else 0

        test_json = json.dumps({"hook_event_name": "UserPromptSubmit",
                                "session_id": "diagnose-selftest", "prompt": "自检"})
        try:
            # command+args 形式:Claude Code 直接 exec [command, *args],不经 shell。
            # 这里用 subprocess.run([cmd, *cmd_args]) 复现真实调用路径,无 shell 参与。
            r = subprocess.run([cmd, *cmd_args],
                               input=test_json.encode("utf-8"),
                               capture_output=True, timeout=30)
            if r.returncode in (0, 2):
                ok("hook 命令可执行", f"exit={r.returncode}")
            else:
                bad("hook 命令执行异常", f"exit={r.returncode}: {r.stderr.decode('utf-8','replace')[:150]}")

            if jsonl:
                after = sum(1 for _ in jsonl.open(encoding="utf-8")) if jsonl.exists() else 0
                if after > before:
                    ok("日志落盘", f"{jsonl} (+{after - before} 行)")
                    jsonl_hint = jsonl
                else:
                    bad("日志未落盘", f"{jsonl} 行数未增加({before}→{after})")
        except subprocess.TimeoutExpired:
            bad("hook 执行超时", ">30s(可能弹窗卡住或 LLM 调用超时)")
        except Exception as e:
            bad("hook 执行失败", str(e))
    else:
        bad("无法模拟执行", "python 或 UserPromptSubmit 命令缺失")

    # ============ F. 日志上传 client ============
    section("F. 日志上传 client(传日志到平台)")
    client_yml = Path(os.environ.get("LOCALAPPDATA", "")) / "claude_audit" / "client" / "client.yml"
    agent_log = client_yml.parent / "agent.log"
    if not client_yml.exists():
        warn("上传 client", f"client.yml 不存在: {client_yml}")
        print("     说明: 未安装 claude_audit_setup.exe,日志只落盘不上传")
    else:
        ok("client.yml 存在", str(client_yml))
        try:
            import yaml
            cy = yaml.safe_load(client_yml.read_text(encoding="utf-8")) or {}
            sources = [str(s).replace("/", "\\").lower() for s in (cy.get("log_sources") or [])]
            if jsonl_hint:
                target = str(jsonl_hint).replace("/", "\\").lower()
                if target in sources:
                    ok("log_sources 指向", "与 hook 实际写入的 jsonl 一致")
                else:
                    bad("log_sources 不一致", f"hook 写 {jsonl_hint},但 client.yml 未包含它")
        except Exception as e:
            warn("client.yml 解析失败", str(e))
        if agent_log.exists():
            try:
                lines = agent_log.read_text(encoding="utf-8", errors="replace").strip().splitlines()
                pushed = [l for l in lines if "pushed" in l]
                if pushed:
                    ok("client 正在上传", pushed[-1].strip()[:100])
                else:
                    warn("agent.log 无 pushed 记录", "client 可能刚装或连不上服务器")
            except Exception:
                pass
        else:
            warn("agent.log 不存在", "client 可能从未运行")


def report() -> int:
    section("汇总")
    bads = [r for r in _results if r[0] == "XXX "]
    warns = [r for r in _results if r[0] == "WARN"]
    if not bads:
        print(f"未发现阻断性问题({len(warns)} 个警告)。写日志链路应正常。")
    else:
        print(f"发现 {len(bads)} 个阻断性问题,按上面每条的提示处理:")
        for _, item, detail in bads:
            print(f"  - {item}" + (f": {detail}" if detail else ""))
    print()
    print("如全部 OK 但仍不写日志:把本输出 + VSCode 日志(")
    print("  %APPDATA%\\Code\\logs\\<最新>\\window*\\exthost\\Anthropic.claude-code\\Claude VSCode.log")
    print(")里 hook 相关行发给安全团队。")
    return 1 if bads else 0


def main() -> int:
    global _fixed_count
    _fixed_count = 0
    fix_mode = "--fix" in sys.argv

    run_checks(fix_mode)
    if fix_mode and _fixed_count:
        print()
        print(f"--- 已自动修复 {_fixed_count} 项,复检 ---")
        print()
        run_checks(False)
    elif fix_mode:
        print("（没有可自动修复的项）")

    rc = report()
    if fix_mode and _fixed_count:
        print()
        print("提醒: 修复了 enabledPlugins / settings.json 的,需重开 Claude Code 才生效。")
    return rc


if __name__ == "__main__":
    sys.exit(main())
