"""插件自动更新 — 整包更新器。

员工手动运行 bin\\update.cmd 触发。
下载整包 zip → sha256 校验 → 备份 → 镜像替换 → 失败回滚。

执行流程（共 13 步）：
  1. frozen 自我重入（仅 exe 模式，Windows 不允许覆盖运行中的 exe）
  2. 拉取 manifest
  3. 确认提示（除非 --yes）
  4. 进程占用检查
  5. 下载整包 zip（流式 + sha256 计算）
  6. sha256 校验
  7. 备份当前版本（保留最近 2 份）
  8. 解压 zip 到 staging（防 zip-slip）
  9. 镜像替换 staging → 插件目录（保留 paths.yml）
  10. 重新渲染 paths.yml
  11. 重新合并 settings.json
  12. 删除缓存
  13. 输出完成信息

源码模式保护：如果 target 指向自身仓库，拒绝执行（防止误删开发文件）。
需要 --target 指向一个部署副本。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

# 让 uplib 可以从同目录 import
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

try:
    from uplib import (
        evaluate,
        current_version,
        manifest_url,
        fetch_manifest,
        write_cache,
        read_cache,
        delete_cache,
        resolve_download_url,
        message_box,
    )
except Exception as exc:
    print(f"[updater] 导入 uplib 失败: {exc}", file=sys.stderr)
    sys.exit(1)

# 插件根目录（updater.py 在 src/updater/ 下，往上 2 级）
_PLUGIN_ROOT = Path(__file__).resolve().parent.parent.parent

# 镜像替换保留名单（不删除、不覆盖）
_MIRROR_SKIP = {
    "src/input/config/paths.yml",  # 部署态文件，安装时渲染
}

# 镜像替换排除名单（不拷贝进插件目录）
_MIRROR_EXCLUDE_DIRS = {
    ".git", "release", "build", "dist", "__pycache__",
}

# 备份保留数量
_MAX_BACKUPS = 2

# 下载超时（秒）
_DOWNLOAD_TIMEOUT = 60

# 进程占用检查名单
# 注意:现在 hooks.json 直接调 python.exe(不再用 bin/*.cmd 启动器),
# 进程名是 python.exe 而不是 input_scanner.exe。
# 但直接匹配 python.exe 太宽泛(可能误杀其他 python 进程),
# 所以检查命令行参数包含 input_scanner.py / output_scanner.py 等的 python 进程。
_PROCESS_NAMES = [
    "python.exe",
    "py.exe",
]

# 进程命令行关键词(用于精准确认是插件的 python 进程)
_PROCESS_KEYWORDS = [
    "input_scanner.py",
    "output_scanner.py",
    "stop_reviewer.py",
    "version_check.py",
    "updater.py",
]

# frozen 自我重入标记
_STAGED_ENV = "CLOUD_UPDATER_STAGED"


# ---------------------------------------------------------------------------
# 1. frozen 自我重入
# ---------------------------------------------------------------------------

def _frozen_reentry() -> None:
    """exe 模式下，复制自身到 %TEMP% 再运行，避免文件锁。

    Windows 不允许覆盖正在运行的 exe。updater.exe 在 bin/ 下，
    更新要替换 bin/ 下的所有 exe，所以必须先把自己移到别处。
    源码模式下（py -3 updater.py）不需要重入。
    """
    if getattr(sys, "frozen", False) and not os.environ.get(_STAGED_ENV):
        exe_path = Path(sys.executable).resolve()
        staging_dir = Path(os.environ.get("TEMP", "/tmp")) / "cloud-guard-updater-run"
        staging_dir.mkdir(parents=True, exist_ok=True)
        staging_exe = staging_dir / exe_path.name

        print(f"[updater] frozen 模式，复制自身到 {staging_exe}")
        shutil.copy2(exe_path, staging_exe)

        # 把同目录的 _internal 也拷过去（PyInstaller onedir 模式需要）
        internal_src = exe_path.parent / "_internal"
        internal_dst = staging_dir / "_internal"
        if internal_src.is_dir() and not internal_dst.is_dir():
            print(f"[updater] 复制 _internal 目录...")
            shutil.copytree(internal_src, internal_dst)

        # 启动副本
        env = os.environ.copy()
        env[_STAGED_ENV] = "1"
        result = subprocess.run([str(staging_exe)] + sys.argv[1:], env=env)
        sys.exit(result.returncode)

    # 已重入或源码模式，等待 1s 让原进程完全退出
    if os.environ.get(_STAGED_ENV):
        time.sleep(1)


# ---------------------------------------------------------------------------
# 2. 拉取 manifest
# ---------------------------------------------------------------------------

def _get_manifest(root: Path) -> tuple[dict, str] | None:
    """拉取 manifest 并评估版本。返回 (manifest, status) 或 None。"""
    url = manifest_url(root)
    if not url:
        print("[updater] 无法推导 manifest URL，请检查 plugin.json 的 homepage 字段")
        return None

    print(f"[updater] 拉取 manifest: {url}")
    try:
        manifest = fetch_manifest(url, timeout=5)
    except Exception as exc:
        print(f"[updater] 拉取 manifest 失败: {exc}")
        print("[updater] 请检查网络连接，确保能访问服务器")
        return None

    ver = current_version(root)
    if not ver:
        print("[updater] 无法读取当前版本号，请检查 plugin.json")
        return None

    status = evaluate(manifest, ver)
    if status == "ok":
        server_ver = manifest.get("version", "?")
        print(f"[updater] 当前版本 v{ver} 已是最新，无需更新（服务器最新: v{server_ver}）")
        return None

    return manifest, status


# ---------------------------------------------------------------------------
# 3. 确认提示
# ---------------------------------------------------------------------------

def _confirm(manifest: dict, current_ver: str, yes: bool) -> bool:
    """确认更新提示。--yes 时跳过。"""
    server_ver = manifest.get("version", "?")
    min_ver = manifest.get("min_required", "?")
    notes = manifest.get("release_notes", "")

    print()
    print(f"  当前版本: v{current_ver}")
    print(f"  最新版本: v{server_ver}")
    if min_ver != server_ver:
        print(f"  最低要求: v{min_ver}")
    if notes:
        print(f"  更新说明: {notes}")
    print()

    if yes:
        return True

    try:
        answer = input("  确认更新? [Y/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False

    return answer in ("", "y", "yes")


# ---------------------------------------------------------------------------
# 4. 进程占用检查
# ---------------------------------------------------------------------------

def _check_processes() -> list[str]:
    """检查是否有扫描器进程在运行，返回正在运行的进程名列表。

    关键防护：
    1. 必须排除自身 PID (updater.py 自身由 python.exe 运行)
    2. 必须排除父进程 PID (一键更新弹窗进程，命令行也含 updater.py)
    3. 排除弹窗脚本 wrapper (命令行含 -c 与 MessageBoxW)
    4. 优先使用 PowerShell 查询命令行 (兼容 Windows 11 24H2+ 已废弃 wmic 的环境)
    5. tasklist 降级时必须解析 PID 排除自身，绝不能盲目判定 python.exe 存在
    """
    running = []
    if os.name != "nt":
        return running

    my_pid = str(os.getpid())
    parent_pid = str(os.getppid()) if hasattr(os, "getppid") else ""

    # 1. 优先使用 PowerShell 查询进程命令行 (Windows 7/10/11 均内置，不受 wmic 移除影响)
    try:
        ps_cmd = [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "Get-CimInstance Win32_Process | "
            "Where-Object { $_.Name -match '^(python|py)\\.exe$' } | "
            "ForEach-Object { [string]$_.ProcessId + ':::' + [string]$_.CommandLine }"
        ]
        result = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=8)
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if ":::" not in line:
                    continue
                pid_str, cmdline = line.split(":::", 1)
                pid_str = pid_str.strip()
                if pid_str in (my_pid, parent_pid):
                    continue
                # 排除弹窗临时包装脚本
                if "-c" in cmdline and "MessageBoxW" in cmdline:
                    continue
                cmdline_lower = cmdline.lower()
                for keyword in _PROCESS_KEYWORDS:
                    if keyword.lower() in cmdline_lower:
                        running.append(keyword)
            return list(dict.fromkeys(running))
    except Exception:
        pass

    # 2. 回退到 wmic (旧版 Windows 10/7 兼容)
    try:
        result = subprocess.run(
            ["wmic", "process", "where", "name like 'python%' or name like 'py%'",
             "get", "ProcessId,Name,CommandLine", "/format:csv"],
            capture_output=True, text=True, timeout=8,
        )
        import csv, io
        reader = csv.DictReader(io.StringIO(result.stdout))
        for row in reader:
            pid = (row.get("ProcessId") or "").strip()
            if pid in (my_pid, parent_pid):
                continue
            cmdline = (row.get("CommandLine") or "")
            if "-c" in cmdline and "MessageBoxW" in cmdline:
                continue
            cmdline_lower = cmdline.lower()
            for keyword in _PROCESS_KEYWORDS:
                if keyword.lower() in cmdline_lower:
                    running.append(keyword)
        running = list(dict.fromkeys(running))
        if running:
            return running
    except Exception:
        pass

    # 3. 降级到 tasklist: 必须解析 PID，排查是否存在除自身与父进程以外的 python 进程
    try:
        import csv, io
        result = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=5,
        )
        reader = csv.reader(io.StringIO(result.stdout))
        other_py = False
        for row in reader:
            if not row or len(row) < 2:
                continue
            proc_name = row[0].strip().lower()
            proc_pid = row[1].strip()
            if proc_name in ("python.exe", "py.exe"):
                if proc_pid not in (my_pid, parent_pid):
                    other_py = True
                    break
        # tasklist 无法读取命令行参数，仅当确有其他第三方 python 进程时才报警告
        if other_py and not running:
            # 无法进一步确认命令行的保守处理：若无法判断则不误阻断 updater
            pass
    except Exception:
        pass

    return running


# ---------------------------------------------------------------------------
# 5. 下载整包 zip（流式 + sha256）
# ---------------------------------------------------------------------------

def _download(url: str, dest: Path, timeout: int = _DOWNLOAD_TIMEOUT) -> str:
    """流式下载文件，边下边算 sha256。返回 sha256 hex 字符串。"""
    print(f"[updater] 下载: {url}")
    sha256 = hashlib.sha256()
    total_size = 0

    req = Request(url)
    with urlopen(req, timeout=timeout) as resp:
        # 尝试获取 Content-Length 用于进度显示
        content_length = resp.headers.get("Content-Length")
        total = int(content_length) if content_length else None

        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)
                sha256.update(chunk)
                total_size += len(chunk)

                if total:
                    pct = total_size * 100 // total
                    print(f"\r[updater] 下载进度: {total_size}/{total} ({pct}%)", end="", flush=True)

    print(f"\r[updater] 下载完成: {total_size} bytes" + " " * 20)
    return sha256.hexdigest()


# ---------------------------------------------------------------------------
# 6. sha256 校验
# ---------------------------------------------------------------------------

def _verify_sha256(actual: str, expected: str) -> bool:
    """校验 sha256 是否匹配。"""
    if actual.lower() == expected.lower():
        return True
    return False


# ---------------------------------------------------------------------------
# 7. 备份当前版本
# ---------------------------------------------------------------------------

def _state_dir() -> Path:
    """状态目录，与 uplib 共用同一逻辑。"""
    env = os.environ.get("CLOUD_GUARD_STATE_DIR")
    if env:
        return Path(env)
    local_app = os.environ.get("LOCALAPPDATA")
    if local_app:
        return Path(local_app) / "cloud-guard"
    return Path(os.environ.get("TEMP", "/tmp")) / "cloud-guard"


def _backup(target: Path) -> Path:
    """备份当前插件目录到 %LOCALAPPDATA%\\cloud-guard\\backup\\vX.Y.Z-<timestamp>\\

    只保留最近 _MAX_BACKUPS 份备份。
    """
    ver = current_version(target) or "unknown"
    ts = time.strftime("%Y%m%d_%H%M%S")
    backup_dir = _state_dir() / "backup" / f"v{ver}-{ts}"
    backup_dir.mkdir(parents=True, exist_ok=True)

    print(f"[updater] 备份当前版本到: {backup_dir}")
    # 只备份关键目录（不备份 __pycache__、.git 等）
    _mirror(target, backup_dir, skip=set(), exclude_dirs={".git", "__pycache__", "build", "dist", "release"})

    # 清理旧备份，只保留 _MAX_BACKUPS 份
    backup_root = _state_dir() / "backup"
    if backup_root.is_dir():
        backups = sorted(backup_root.iterdir(), key=lambda p: p.stat().st_mtime)
        while len(backups) > _MAX_BACKUPS:
            old = backups.pop(0)
            print(f"[updater] 清理旧备份: {old.name}")
            shutil.rmtree(old, ignore_errors=True)

    return backup_dir


# ---------------------------------------------------------------------------
# 8. 解压 zip 到 staging（防 zip-slip）
# ---------------------------------------------------------------------------

def _extract_zip_safely(zip_path: Path, dest: Path) -> None:
    """解压 zip 到目标目录，检查 zip-slip 攻击。"""
    import zipfile

    dest_resolved = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)

    print(f"[updater] 解压: {zip_path.name}")
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            # 跳过目录条目
            if info.is_dir():
                continue

            target_path = (dest / info.filename).resolve()

            # zip-slip 防护：解压路径不能逃出目标目录
            if dest_resolved not in target_path.parents and target_path != dest_resolved:
                raise ValueError(f"zip 内含非法路径（zip-slip）: {info.filename}")

            # 创建父目录
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # 解压文件
            with zf.open(info) as src, open(target_path, "wb") as dst:
                shutil.copyfileobj(src, dst)

    print(f"[updater] 解压完成")


def _strip_top_dir(staging: Path) -> Path:
    """如果 zip 解压后只有一个顶层目录（如 claude_plugin/），自动剥离。

    管理员打包时可能直接压缩了 claude_plugin/ 文件夹，
    导致解压后 staging/claude_plugin/.claude-plugin/... 而不是
    staging/.claude-plugin/...。此函数检测这种情况并返回内层目录。

    如果没有单一顶层目录（正常打包），原样返回 staging。
    """
    # 如果根目录已直接包含插件核心文件，直接返回
    if (staging / ".claude-plugin" / "plugin.json").exists() or (staging / "hooks" / "hooks.json").exists():
        return staging

    # 过滤掉系统元数据目录（如 __MACOSX、.DS_Store 等）
    ignore_names = {"__MACOSX", ".DS_Store", "desktop.ini", "Thumbs.db"}
    subdirs = [c for c in staging.iterdir() if c.is_dir() and c.name not in ignore_names]

    if len(subdirs) == 1:
        top_dir = subdirs[0]
        # 验证内层是否包含插件标志性文件
        markers = [
            top_dir / ".claude-plugin" / "plugin.json",
            top_dir / "hooks" / "hooks.json",
            top_dir / "src",
        ]
        found = sum(1 for m in markers if m.exists())
        if found >= 2:
            print(f"[updater] 检测到顶层目录 {top_dir.name}/，自动剥离")
            return top_dir

    return staging


# ---------------------------------------------------------------------------
# 9. 镜像替换 staging → 插件目录
# ---------------------------------------------------------------------------

def _mirror(
    src: Path,
    dst: Path,
    skip: set[str] | None = None,
    exclude_dirs: set[str] | None = None,
) -> None:
    """镜像替换：从 src 复制所有文件到 dst，保持一致。

    - skip: 相对路径集合，跳过这些文件（如 paths.yml）
    - exclude_dirs: 目录名集合，跳过这些目录（如 .git）
    """
    skip = skip or set()
    exclude_dirs = exclude_dirs or set()

    src_resolved = src.resolve()
    dst_resolved = dst.resolve()

    # 1. 复制 src 中所有文件到 dst
    for item in src.rglob("*"):
        if item.is_dir():
            continue

        # Windows 8.3 短名兼容：item 可能含 WUGUOX~1，resolve 后是 wuguoxiang
        # 必须两边都 resolve 再算相对路径
        rel = item.resolve().relative_to(src_resolved)
        parts = rel.parts
        if any(p in exclude_dirs for p in parts):
            continue

        # 检查是否在跳过名单
        rel_str = str(rel).replace("\\", "/")
        if rel_str in skip:
            continue

        dst_file = dst_resolved / rel
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, dst_file)

    # 2. 删除 dst 中多余文件（保证 dst = src）
    for item in dst_resolved.rglob("*"):
        if item.is_dir():
            continue

        rel = item.resolve().relative_to(dst_resolved)
        parts = rel.parts
        if any(p in exclude_dirs for p in parts):
            continue

        rel_str = str(rel).replace("\\", "/")
        if rel_str in skip:
            continue

        src_file = src_resolved / rel
        if not src_file.exists():
            # 检查是否整个父目录都不在 src 中
            item.unlink(missing_ok=True)

    # 3. 清理空目录
    for item in sorted(dst_resolved.rglob("*"), reverse=True):
        if item.is_dir() and not any(item.iterdir()):
            # 不删除排除目录和根目录
            if item != dst_resolved:
                item.rmdir()


# ---------------------------------------------------------------------------
# 10. 重新渲染 paths.yml
# ---------------------------------------------------------------------------

def _re_render_paths(
    old_paths_yml: str,
    template_path: Path,
    target_paths_yml: Path,
) -> None:
    """用旧 paths.yml 的值渲染新版 paths.template.yml。

    逻辑：
    1. 解析旧 paths.yml 中的 controlled_workdir / security_script_dir / logs 实际值
    2. 用这些值替换 template 中的占位符
    3. 推导新版可能新增的占位符
    4. 写回 paths.yml
    """
    import re
    import yaml

    # 解析旧 paths.yml 的关键值
    old_values: dict[str, str] = {}
    try:
        old_data = yaml.safe_load(old_paths_yml) or {}
        old_values["controlled_workdir"] = old_data.get("controlled_workdir", "")
        old_values["security_script_dir"] = old_data.get("security_script_dir", "")

        # 从 derived 段提取 logs
        derived = old_data.get("derived") or {}
        old_values["logs"] = derived.get("logs", "")

        # 从 write_whitelist 提取 PLUGIN_DIR 和 USERPROFILE
        whitelist = old_data.get("write_whitelist") or []
        for entry in whitelist:
            entry_str = str(entry)
            if "__PLUGIN_DIR__" in entry_str:
                # 部署版的 write_whitelist 里有 __PLUGIN_DIR__ 占位符
                pass
    except Exception as exc:
        print(f"[updater] 解析旧 paths.yml 失败: {exc}")

    # 推导占位符值
    replacements: dict[str, str] = {}

    # __WORKDIR__ = controlled_workdir
    if old_values.get("controlled_workdir"):
        replacements["__WORKDIR__"] = old_values["controlled_workdir"]

    # __PLUGIN_SRC__ = security_script_dir
    if old_values.get("security_script_dir"):
        replacements["__PLUGIN_SRC__"] = old_values["security_script_dir"]

    # __LOG_DIR__ = logs
    if old_values.get("logs"):
        replacements["__LOG_DIR__"] = old_values["logs"]

    # __PLUGIN_DIR__ = security_script_dir 的父目录（src 的上级）
    if old_values.get("security_script_dir"):
        plugin_dir = str(Path(old_values["security_script_dir"]).parent)
        replacements["__PLUGIN_DIR__"] = plugin_dir

    # __PYTHON_EXE__ = CLOUD_GUARD_PYTHON 环境变量(部署时 setx 写入)。
    # hooks.json 直接调 python.exe 而非 bin/*.cmd —— .cmd 的 exit /b %errorlevel%
    # 在 Claude Code 管道调用下会吞掉 exit code 2(阻断信号)返回 0(放行)。
    # 详见 docx/FIX_hooks_exit_code_lost.md。
    guard_python = os.environ.get("CLOUD_GUARD_PYTHON", "")
    if guard_python:
        replacements["__PYTHON_EXE__"] = guard_python

    # __USERPROFILE__ = 从路径推导
    # 典型路径: C:\Users\<user>\.claude\plugins\cloud-guard\src\input
    # → USERPROFILE = C:\Users\<user>
    if old_values.get("security_script_dir"):
        script_path = Path(old_values["security_script_dir"])
        parts = script_path.parts
        for i, p in enumerate(parts):
            if p == ".claude" and i > 0:
                replacements["__USERPROFILE__"] = str(Path(*parts[:i]))
                break

    # 如果没从路径推导出来，用环境变量
    if "__USERPROFILE__" not in replacements:
        userprofile = os.environ.get("USERPROFILE", "")
        if userprofile:
            replacements["__USERPROFILE__"] = userprofile

    # 读模板
    if not template_path.exists():
        print(f"[updater] paths.template.yml 不存在: {template_path}，跳过渲染")
        return

    template_text = template_path.read_text(encoding="utf-8")

    # 替换占位符
    for placeholder, value in replacements.items():
        template_text = template_text.replace(placeholder, value)

    # 检查是否还有未替换的占位符
    remaining = re.findall(r"__[A-Z_]+__", template_text)
    if remaining:
        print(f"[updater] 警告: paths.yml 中仍有未替换的占位符: {remaining}")

    # 写回
    target_paths_yml.parent.mkdir(parents=True, exist_ok=True)
    target_paths_yml.write_text(template_text, encoding="utf-8")
    print(f"[updater] paths.yml 已重新渲染: {target_paths_yml}")


# ---------------------------------------------------------------------------
# 11. 重新合并 settings.json
# ---------------------------------------------------------------------------

def _re_merge_settings(target: Path) -> None:
    """调用 merge_settings_env.ps1 重新合并 settings.json。

    从旧 settings.json 读取 LLM 配置，幂等合并。
    """
    if os.name != "nt":
        print("[updater] 非 Windows 平台，跳过 settings.json 合并")
        return

    settings_path = Path.home() / ".claude" / "settings.json"

    # 从旧 settings.json 读取 LLM 配置
    llm_url = ""
    llm_token = ""
    llm_model = ""
    py_exe = ""

    try:
        if settings_path.exists():
            data = json.loads(settings_path.read_text(encoding="utf-8"))
            env = data.get("env") or {}
            llm_url = env.get("ANTHROPIC_BASE_URL", "")
            llm_token = env.get("ANTHROPIC_AUTH_TOKEN", "")
            py_exe = env.get("CLOUD_GUARD_PYTHON", "")
            # 取第一个非空的 model 值
            for key in ("ANTHROPIC_DEFAULT_HAIKU_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
                        "ANTHROPIC_DEFAULT_OPUS_MODEL"):
                val = env.get(key, "")
                if val:
                    llm_model = val
                    break
    except Exception as exc:
        print(f"[updater] 读取 settings.json 失败: {exc}")

    # 如果 settings.json 里没有 CLOUD_GUARD_PYTHON,从环境变量或默认路径推导
    if not py_exe:
        py_exe = os.environ.get("CLOUD_GUARD_PYTHON", "")
    if not py_exe:
        # 默认路径: D:\ClaudeSecurity\python\python.exe
        default_py = Path("D:\\ClaudeSecurity\\python\\python.exe")
        if default_py.exists():
            py_exe = str(default_py)

    # 查找 merge_settings_env.ps1
    # 优先从插件 deploy 目录找，其次从 staging 找
    merge_ps1 = target / "deploy" / "merge_settings_env.ps1"
    if not merge_ps1.exists():
        print(f"[updater] merge_settings_env.ps1 不存在: {merge_ps1}，跳过 settings.json 合并")
        return

    print(f"[updater] 重新合并 settings.json...")
    cmd = [
        "powershell", "-ExecutionPolicy", "Bypass",
        "-File", str(merge_ps1),
        "-Settings", str(settings_path),
    ]
    if llm_url:
        cmd.extend(["-LlmUrl", llm_url])
    if llm_token:
        cmd.extend(["-LlmToken", llm_token])
    if llm_model:
        cmd.extend(["-LlmModel", llm_model])
    # CLOUD_GUARD_PYTHON 必须传 —— 否则更新后 settings.json env 段缺这个值,
    # hook 仍找不到 Python(就是老员工机更新完仍不写日志的根因)。
    if py_exe:
        cmd.extend(["-PyExe", py_exe])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("[updater] settings.json 合并完成")
        else:
            print(f"[updater] settings.json 合并失败: {result.stderr.strip()}")
    except Exception as exc:
        print(f"[updater] settings.json 合并异常: {exc}")


# ---------------------------------------------------------------------------
# 11b. 重新渲染 hooks.json
# ---------------------------------------------------------------------------

def _render_hooks(target: Path) -> None:
    """把 hooks.json 中的 __PLUGIN_DIR__ / __PYTHON_EXE__ 占位符替换成实际路径。

    镜像替换后 hooks.json 可能被新版覆盖(带占位符),必须重新渲染,
    否则路径断裂导致 hook 不触发。

    hook 采用 command + args 形式(command=python.exe, args=[脚本,...]):
    Claude Code 直接 exec python,不经 CMD / PowerShell / Git Bash,python 的
    sys.exit(2) 退出码由 Claude Code 直接读取。本函数只做占位符文本替换
    (占位符可能出现在 command 或 args 字符串里,替换对两处都生效)。
    注意:command 指向的 python.exe 若被删/移动,Claude Code spawn 失败时不阻断
    (fail-open),运维侧靠 diagnose.py 校验 python.exe 存在性兜底。

    如果 __PYTHON_EXE__ 替换后仍残留(CLOUD_GUARD_PYTHON 环境变量为空),
    command 用 `py` 兜底(经 PATH 查找),确保 hook 至少能执行。
    """
    hooks_path = target / "hooks" / "hooks.json"
    if not hooks_path.exists():
        print("[updater] hooks.json 不存在，跳过渲染")
        return

    text = hooks_path.read_text(encoding="utf-8")
    if "__PLUGIN_DIR__" not in text and "__PYTHON_EXE__" not in text:
        print("[updater] hooks.json 无占位符，无需渲染")
        return

    # JSON 里反斜杠要转义
    plugin_dir_escaped = str(target).replace("\\", "\\\\")
    text = text.replace("__PLUGIN_DIR__", plugin_dir_escaped)

    # 优先使用环境变量 CLOUD_GUARD_PYTHON
    guard_python = os.environ.get("CLOUD_GUARD_PYTHON", "").strip()
    if not guard_python:
        # 1. 尝试当前正在运行的 Python 路径 (若非 frozen 打包产物)
        if Path(sys.executable).exists() and not getattr(sys, "frozen", False):
            guard_python = str(Path(sys.executable).resolve())
    if not guard_python:
        # 2. 尝试从 ~/.claude/settings.json 读取 env.CLOUD_GUARD_PYTHON
        try:
            settings_path = Path.home() / ".claude" / "settings.json"
            if settings_path.exists():
                data = json.loads(settings_path.read_text(encoding="utf-8"))
                guard_python = ((data.get("env") or {}).get("CLOUD_GUARD_PYTHON") or "").strip()
        except Exception:
            pass
    if not guard_python:
        # 3. 尝试默认部署路径 D:\ClaudeSecurity\python\python.exe
        default_py = Path(r"D:\ClaudeSecurity\python\python.exe")
        if default_py.exists():
            guard_python = str(default_py)

    if guard_python:
        python_escaped = guard_python.replace("\\", "\\\\")
        text = text.replace("__PYTHON_EXE__", python_escaped)
        print(f"[updater] hooks.json 使用 Python 解释器: {guard_python}")
    else:
        # 环境变量及已知路径均为空，才用 py 启动器兜底
        print("[updater] 警告: 未找到 Python 路径, __PYTHON_EXE__ 用 py 兜底")
        text = text.replace("__PYTHON_EXE__", "py")

    hooks_path.write_text(text, encoding="utf-8")
    print(f"[updater] hooks.json 已重新渲染: {hooks_path}")


# ---------------------------------------------------------------------------
# 11c. 同步 Claude Code 插件缓存目录
# ---------------------------------------------------------------------------

def _sync_cache_dir(target: Path, server_ver: str) -> None:
    """更新成功后,把插件目录内容同步到 Claude Code 的插件缓存目录。

    为什么必须做:Claude Code 安装插件时会拷贝一份到缓存目录
    (~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/),
    部分场景实际加载的是缓存副本而非安装目录。只更新安装目录 →
    缓存副本还是旧代码 → "更新了但没生效"(本次排查已踩过此坑)。

    做法:
      1. 读 installed_plugins.json 找 cloud-guard@* 的 installPath
      2. installPath 存在且 ≠ target → 镜像同步 + 渲染其 hooks.json
      3. 同步更新该条目的 version 字段(先备份原文件)

    任何失败只告警不中止 —— 安装目录已更新成功,缓存同步失败最多
    导致个别场景加载旧副本,用户 /plugin 重装可恢复。
    """
    ip_json = Path.home() / ".claude" / "plugins" / "installed_plugins.json"
    if not ip_json.exists():
        print("[updater] installed_plugins.json 不存在,跳过缓存同步")
        return

    try:
        data = json.loads(ip_json.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[updater] 读取 installed_plugins.json 失败: {exc},跳过缓存同步")
        return

    plugins = data.get("plugins") or {}
    changed = False
    try:
        target_resolved = target.resolve()
    except Exception:
        target_resolved = target

    for key, entries in plugins.items():
        if not key.startswith("cloud-guard@"):
            continue
        if not isinstance(entries, list):
            continue
        for entry in entries:
            install_path_str = entry.get("installPath", "")
            if not install_path_str:
                continue
            install_path = Path(install_path_str)
            try:
                if install_path.resolve() == target_resolved:
                    continue  # installPath 就是安装目录本身,无需同步
            except Exception:
                pass
            if not install_path.exists():
                continue

            print(f"[updater] 同步缓存目录: {install_path}")
            try:
                _mirror(target, install_path, skip=set(), exclude_dirs=_MIRROR_EXCLUDE_DIRS)
                # 重新修正缓存目录中 hooks.json 的路径（从 target 替换为 install_path）
                chooks = install_path / "hooks" / "hooks.json"
                if chooks.exists():
                    target_escaped = str(target).replace("\\", "\\\\")
                    install_escaped = str(install_path).replace("\\", "\\\\")
                    craw = chooks.read_text(encoding="utf-8")
                    craw = craw.replace(target_escaped, install_escaped).replace(str(target), str(install_path))
                    chooks.write_text(craw, encoding="utf-8")
                _render_hooks(install_path)
                if entry.get("version") != server_ver:
                    entry["version"] = server_ver
                    changed = True
            except Exception as exc:
                print(f"[updater] 警告: 缓存目录同步失败({exc}),"
                      f"如遇插件未生效请在 Claude Code /plugin 中重装")

    if changed:
        try:
            bak = ip_json.with_suffix(".json.bak_before_sync")
            shutil.copy2(ip_json, bak)
            ip_json.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"[updater] installed_plugins.json 版本号已同步为 v{server_ver}(备份: {bak.name})")
        except Exception as exc:
            print(f"[updater] 警告: installed_plugins.json 写回失败: {exc}")


# ---------------------------------------------------------------------------
# 回滚
# ---------------------------------------------------------------------------

def _rollback(backup: Path, target: Path, saved_paths_yml: str | None = None) -> None:
    """从备份回滚插件目录。"""
    print(f"[updater] 正在回滚...")
    try:
        _mirror(backup, target, skip=set(), exclude_dirs={".git", "__pycache__"})

        # 恢复旧 paths.yml
        if saved_paths_yml is not None:
            paths_yml = target / "src" / "input" / "config" / "paths.yml"
            paths_yml.parent.mkdir(parents=True, exist_ok=True)
            paths_yml.write_text(saved_paths_yml, encoding="utf-8")

        print("[updater] 回滚完成，插件已恢复为更新前状态")
    except Exception as exc:
        print(f"[updater] 回滚失败: {exc}")
        print(f"[updater] 请手动从备份恢复: {backup}")


# ---------------------------------------------------------------------------
# 源码模式保护
# ---------------------------------------------------------------------------

def _check_source_mode(target: Path) -> None:
    """如果 target 指向当前仓库，拒绝执行（防止误删开发文件）。"""
    try:
        # 比较两个路径是否指向同一个位置
        target_resolved = target.resolve()
        self_root = _PLUGIN_ROOT.resolve()

        # 如果 target 就是当前脚本所在的插件目录
        if target_resolved == self_root:
            # 检查是否有 .git 目录（开发仓库特征）
            if (self_root / ".git").exists():
                print(f"[updater] 拒绝: 目标目录是开发仓库 ({self_root})")
                print(f"[updater] 请使用 --target 指向一个部署副本，或先打包再更新")
                sys.exit(1)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="cloud-guard 整包更新器")
    parser.add_argument("--yes", "-y", action="store_true", help="跳过确认提示")
    parser.add_argument("--target", type=str, help="插件目录（默认自动检测）")
    args = parser.parse_args()

    # 确定插件目录
    target = Path(args.target).resolve() if args.target else _PLUGIN_ROOT

    print("=" * 60)
    print("  cloud-guard 整包更新器")
    print("=" * 60)
    print()

    # 0. 源码模式保护
    _check_source_mode(target)

    # 1. frozen 自我重入（仅 exe 模式）
    _frozen_reentry()

    # 2. 拉取 manifest
    result = _get_manifest(target)
    if result is None:
        return 0  # 已是最新或网络问题，不算错误

    manifest, status = result
    current_ver = current_version(target) or "?"
    server_ver = manifest.get("version", "?")

    # 3. 确认提示
    if not _confirm(manifest, current_ver, args.yes):
        print("[updater] 已取消")
        return 0

    # 4. 进程占用检查
    running = _check_processes()
    if running:
        err_msg = f"检测到以下插件进程正在运行:\n{', '.join(running)}\n\n请先完全退出 Claude Code，然后重新运行更新。"
        print(f"[updater] {err_msg}")
        message_box("cloud-guard 更新受阻", err_msg)
        return 1

    # 5. 下载整包 zip
    download_url = resolve_download_url(manifest, target)
    if not download_url:
        err_msg = "manifest 中缺少下载地址 (url 字段)"
        print(f"[updater] {err_msg}")
        message_box("cloud-guard 更新失败", err_msg)
        return 1

    expected_sha = manifest.get("sha256", "")
    if not expected_sha:
        err_msg = "manifest 中缺少 sha256 字段，无法校验完整性。\n请联系安全团队排查服务器配置。"
        print(f"[updater] {err_msg}")
        message_box("cloud-guard 更新失败", err_msg)
        return 1

    temp_dir = Path(tempfile.mkdtemp(prefix="cloud-guard-update-"))
    zip_path = temp_dir / f"cloud-guard-{server_ver}.zip"

    try:
        actual_sha = _download(download_url, zip_path)
    except Exception as exc:
        err_msg = f"下载插件安装包失败: {exc}\n请检查网络连接。"
        print(f"[updater] {err_msg}")
        message_box("cloud-guard 更新失败", err_msg)
        shutil.rmtree(temp_dir, ignore_errors=True)
        return 1

    # 6. sha256 校验
    if not _verify_sha256(actual_sha, expected_sha):
        err_msg = f"校验失败: sha256 不匹配。\n期望: {expected_sha}\n实际: {actual_sha}\n文件可能损坏，更新已中止。"
        print(f"[updater] {err_msg}")
        message_box("cloud-guard 更新失败", err_msg)
        shutil.rmtree(temp_dir, ignore_errors=True)
        return 1

    print("[updater] sha256 校验通过")

    # 保存旧 paths.yml 内容（步骤 9-10 用）
    saved_paths_yml: str | None = None
    paths_yml_path = target / "src" / "input" / "config" / "paths.yml"
    if paths_yml_path.exists():
        try:
            saved_paths_yml = paths_yml_path.read_text(encoding="utf-8")
        except Exception:
            pass

    # 7. 备份当前版本
    backup_dir: Path | None = None
    try:
        backup_dir = _backup(target)
    except Exception as exc:
        print(f"[updater] 备份失败: {exc}")
        print("[updater] 为了安全，不执行更新（无备份不可回滚）")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return 1

    # 8. 解压 zip 到 staging
    staging_dir = temp_dir / "staging"
    try:
        _extract_zip_safely(zip_path, staging_dir)
    except Exception as exc:
        print(f"[updater] 解压失败: {exc}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return 1

    # 8.1 自动剥离多余的顶层目录（如 claude_plugin/）
    effective_staging = _strip_top_dir(staging_dir)

    # 校验 staging 内的 plugin.json 版本与 manifest 一致
    staging_plugin_json = None
    # 查找 staging 目录中的 plugin.json（可能在根目录或 .claude-plugin/ 下）
    for candidate in effective_staging.rglob("plugin.json"):
        if ".claude-plugin" in str(candidate):
            staging_plugin_json = candidate
            break
    if not staging_plugin_json:
        staging_plugin_json = effective_staging / ".claude-plugin" / "plugin.json"

    if staging_plugin_json.exists():
        try:
            staging_data = json.loads(staging_plugin_json.read_text(encoding="utf-8"))
            staging_ver = staging_data.get("version", "")
            if staging_ver != server_ver:
                print(f"[updater] 警告: zip 内版本 ({staging_ver}) 与 manifest 版本 ({server_ver}) 不一致")
                print("[updater] 可能是打包错误，已中止")
                shutil.rmtree(temp_dir, ignore_errors=True)
                return 1
        except Exception:
            pass

    # 开始更新（后续步骤失败则回滚）
    try:
        # 9. 镜像替换 staging → 插件目录
        print("[updater] 镜像替换...")
        _mirror(effective_staging, target, skip=_MIRROR_SKIP, exclude_dirs=_MIRROR_EXCLUDE_DIRS)

        # 10. 重新渲染 paths.yml
        template_path = target / "deploy" / "paths.template.yml"
        if not template_path.exists():
            # 模板可能在 staging 里还没被拷过来，也在 deploy 目录下
            template_path = effective_staging / "deploy" / "paths.template.yml"
        if saved_paths_yml and template_path.exists():
            _re_render_paths(saved_paths_yml, template_path, paths_yml_path)
        elif saved_paths_yml:
            # 没有模板，写回旧 paths.yml
            paths_yml_path.parent.mkdir(parents=True, exist_ok=True)
            paths_yml_path.write_text(saved_paths_yml, encoding="utf-8")
            print("[updater] 无新版 paths.template.yml，保留旧 paths.yml")

        # 11. 重新合并 settings.json
        _re_merge_settings(target)

        # 11b. 重新渲染 hooks.json(镜像替换可能覆盖成带 __PLUGIN_DIR__ 占位符的新版)
        _render_hooks(target)

        # 11c. 同步 Claude Code 插件缓存目录(否则缓存副本还是旧代码,更新不生效)
        _sync_cache_dir(target, server_ver)

        # 12. 删除缓存
        delete_cache()
        print("[updater] 已清理版本缓存")

        # 13. 输出完成信息
        print()
        print("=" * 60)
        print(f"  更新完成: v{current_ver} → v{server_ver}")
        print(f"  请重新打开 Claude Code")
        print("=" * 60)

        # 弹窗提醒
        message_box(
            "cloud-guard 更新完成",
            f"已更新到 v{server_ver}\n\n请重新打开 Claude Code。",
        )

    except Exception as exc:
        print(f"[updater] 更新失败: {exc}")
        # 弹窗提醒更新失败
        message_box(
            "cloud-guard 更新失败",
            f"更新过程中发生异常: {exc}\n\n已尝试自动从备份回滚。",
        )
        # 回滚
        if backup_dir:
            _rollback(backup_dir, target, saved_paths_yml)
        return 1

    finally:
        # 清理临时目录
        shutil.rmtree(temp_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
