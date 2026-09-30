"""插件自动更新 — 共享库。

所有更新逻辑的底层函数，version_check 和 updater 共用。

核心函数：
- parse_version()     版本号解析：'0.1.0' → (0,1,0)
- evaluate()         版本评估：ok / update_available / update_required
- manifest_url()     从 plugin.json 的 homepage 推导 manifest 地址
- fetch_manifest()   urllib GET 拉取 manifest.json
- write_cache()      写本地缓存
- read_cache()       读本地缓存
- delete_cache()     删本地缓存
- message_box()      Win32 原生弹窗（仅用于 version_check 提醒）
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

# ---------------------------------------------------------------------------
# 版本号工具
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", re.IGNORECASE)


def parse_version(text: str) -> tuple[int, ...] | None:
    """'0.1.0' / 'v0.2' / '1.0.0-beta' → (0, 1, 0) / (0, 2, 0) / (1, 0, 0)

    去掉前缀 v/V，按 . 分割，取每段前导数字，不足 3 段补 0，非数字后缀丢弃。
    返回可比较的元组：(0,1,0) < (0,2,0) → True。
    格式不符返回 None。
    """
    if not text or not isinstance(text, str):
        return None
    m = _VERSION_RE.match(text.strip())
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2)) if m.group(2) is not None else 0
    patch = int(m.group(3)) if m.group(3) is not None else 0
    return (major, minor, patch)


def evaluate(manifest: dict, current_version: str) -> str:
    """版本评估。

    返回：
      'ok'              当前版本 ≥ 最新版
      'update_available' 当前版本 ≥ min_required 但 < version（可选更新）
      'update_required'  当前版本 < min_required（强制更新）
    """
    v_server = parse_version(manifest.get("version", "0.0.0"))
    v_min = parse_version(manifest.get("min_required", "0.0.0"))
    v_current = parse_version(current_version)

    if v_current is None:
        return "ok"  # 读不到版本号，fail-open

    # 优先检查强制更新要求
    if v_min is not None and v_current < v_min:
        return "update_required"

    # 其次检查是否有更高版本可用
    if v_server is not None and v_current < v_server:
        return "update_available"

    return "ok"


# ---------------------------------------------------------------------------
# Manifest URL 推导
# ---------------------------------------------------------------------------

def manifest_url(root: Path) -> str | None:
    """从 plugin.json 的 homepage 字段推导 manifest 地址。

    推导规则：
      1. 环境变量 CLOUD_GUARD_MANIFEST_URL 覆盖优先
      2. 否则读 plugin.json 的 homepage（如 http://192.168.3.57:8787）
      3. 拼上固定路径 /plugins/manifest.json
         （若 homepage 已含 /plugins 前缀则不重复拼接，便于把插件服务
           和审计面板分开部署，如 homepage=http://host:8787/plugins）
      4. 最终 URL：http://192.168.3.57:8787/plugins/manifest.json
    """
    env_url = os.environ.get("CLOUD_GUARD_MANIFEST_URL")
    if env_url:
        return env_url.strip()

    plugin_json = root / ".claude-plugin" / "plugin.json"
    try:
        data = json.loads(plugin_json.read_text(encoding="utf-8"))
        homepage = (data.get("homepage") or "").strip()
    except Exception:
        return None

    if not homepage:
        return None

    base = homepage.rstrip("/")
    if base.endswith("/plugins"):
        return base + "/manifest.json"
    return base + "/plugins/manifest.json"


# ---------------------------------------------------------------------------
# 缓存读写
# ---------------------------------------------------------------------------

_CACHE_SCHEMA = 1
_CACHE_FILENAME = "update_cache.json"


def _state_dir() -> Path:
    """状态目录：环境变量 CLOUD_GUARD_STATE_DIR > %LOCALAPPDATA%\\cloud-guard > %TEMP%\\cloud-guard"""
    env = os.environ.get("CLOUD_GUARD_STATE_DIR")
    if env:
        return Path(env)
    local_app = os.environ.get("LOCALAPPDATA")
    if local_app:
        return Path(local_app) / "cloud-guard"
    return Path(os.environ.get("TEMP", "/tmp")) / "cloud-guard"


def write_cache(
    manifest: dict | None = None,
    fetch_error: str | None = None,
) -> None:
    """写入本地缓存。

    关键设计：fetch 失败时保留旧 manifest 不覆盖。
    如果 manifest=None，只更新 checked_at 和 fetch_error，保留已有的 manifest 字段。
    """
    cache_path = _state_dir() / _CACHE_FILENAME
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    # 读取现有缓存（保留旧 manifest）
    existing: dict = {}
    if cache_path.exists():
        try:
            existing = json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    entry: dict = {
        "schema": _CACHE_SCHEMA,
        "checked_at": int(time.time()),
        "fetch_error": fetch_error,
    }

    # manifest=None 时保留旧值，不写 None
    if manifest is not None:
        entry["manifest"] = manifest
    elif "manifest" in existing:
        entry["manifest"] = existing["manifest"]

    try:
        cache_path.write_text(json.dumps(entry, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass  # best-effort


def read_cache() -> dict | None:
    """读本地缓存，返回 dict 或 None。"""
    cache_path = _state_dir() / _CACHE_FILENAME
    if not cache_path.exists():
        return None
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        if data.get("schema") != _CACHE_SCHEMA:
            return None
        return data
    except Exception:
        return None


def delete_cache() -> None:
    """删除本地缓存。"""
    cache_path = _state_dir() / _CACHE_FILENAME
    try:
        cache_path.unlink(missing_ok=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 网络
# ---------------------------------------------------------------------------

def fetch_manifest(url: str, timeout: int = 3) -> dict:
    """urllib GET 请求，3 秒超时，返回解析后的 manifest dict。

    使用标准库 urllib，不依赖 requests（PyInstaller 打包体积更小）。
    校验返回值必须是 dict 且包含 version 字段。
    任何异常抛出，由调用方 fail-open 处理。
    """
    req = Request(url, headers={"Accept": "application/json"})
    with urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    data = json.loads(body)
    if not isinstance(data, dict) or "version" not in data:
        raise ValueError("manifest.json 格式错误：缺少 version 字段")
    return data


def resolve_download_url(manifest: dict, root: Path) -> str | None:
    """manifest 里的 url 支持绝对路径和相对路径。

    - http:// / https:// 开头 → 直接用
    - /plugins/xxx.zip 开头 → 相对 homepage 拼接
    """
    url = manifest.get("url", "")
    if not url:
        return None
    if url.startswith("http://") or url.startswith("https://"):
        return url

    # 相对路径：从 plugin.json homepage 拼接
    plugin_json = root / ".claude-plugin" / "plugin.json"
    try:
        data = json.loads(plugin_json.read_text(encoding="utf-8"))
        homepage = (data.get("homepage") or "").strip().rstrip("/")
        return homepage + url if homepage else url
    except Exception:
        return url


# ---------------------------------------------------------------------------
# 当前版本读取
# ---------------------------------------------------------------------------

def current_version(root: Path) -> str | None:
    """从 plugin.json 读取当前版本号。"""
    plugin_json = root / ".claude-plugin" / "plugin.json"
    try:
        data = json.loads(plugin_json.read_text(encoding="utf-8"))
        return (data.get("version") or "").strip() or None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Windows 弹窗
# ---------------------------------------------------------------------------

def message_box(title: str, text: str) -> None:
    """原生 MessageBoxW: WARNING 图标 + 置顶 + 抢前台。零依赖。

    不复用 lib/confirm.py 的 Tkinter 弹窗（那个是为长文本设计的，
    拖进 updater 会增大打包体积和冷启动时间）。
    best-effort，任何失败静默。
    """
    if os.name != "nt":
        return
    try:
        import ctypes
        MB_OK = 0x00000000
        MB_ICONWARNING = 0x00000030
        MB_TOPMOST = 0x00040000
        MB_SETFOREGROUND = 0x00010000
        flags = MB_OK | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND
        ctypes.windll.user32.MessageBoxW(None, text, title, flags)
    except Exception:
        pass


def spawn_update_prompt(
    current_ver: str,
    server_ver: str,
    *,
    min_ver: str = "",
    notes: str = "",
    required: bool = False,
    updater_script: Path | None = None,
) -> None:
    """弹"立即更新 / 稍后"对话框;点"是"直接启动更新,无需用户手动跑 update.cmd。

    为什么做成独立进程两级结构:
      - hook(SessionStart / PreToolUse)有 10-30s 超时,绝不能阻塞;
        本函数 Popen 出独立弹窗进程后立即返回。
      - 弹窗进程里 MessageBoxW 阻塞等用户点按钮;点"是"再 Popen 启动
        updater(新控制台窗口,--yes 跳过二次确认),弹窗进程随即退出。

    为什么不走 bin\\update.cmd:
      .cmd 启动器依赖 CLOUD_GUARD_PYTHON 环境变量(setx 未生效时回退 py -3
      会失败),且 exit code 传递有坑。这里直接用 sys.executable(就是当前
      正在跑 hook 的 embeddable python)调 updater.py,零环境依赖。

    required=True 时标题带"强制"且按"否"也会提示下次仍会被阻断。
    best-effort:任何异常静默返回,不影响 hook 主流程。
    """
    if os.name != "nt":
        return
    try:
        import subprocess
        import sys

        if updater_script is None:
            updater_script = Path(__file__).resolve().parent / "updater.py"
        updater_script = Path(updater_script)
        if not updater_script.exists():
            return

        title = "cloud-guard 强制更新" if required else "cloud-guard 有新版本"
        lines = [
            f"当前版本: v{current_ver}",
            f"最新版本: v{server_ver}",
        ]
        if min_ver and min_ver != server_ver:
            lines.append(f"最低要求: v{min_ver}")
        if notes:
            lines.append(f"更新说明: {notes}")
        lines.append("")
        if required:
            lines.append("当前版本已低于最低要求,继续使用将被阻断。")
            lines.append("")
        lines.append("点击「是」立即更新(推荐);点击「否」稍后手动更新。")
        body = "\n".join(lines)

        # 独立进程脚本:弹 YESNO 对话框,是 → 新控制台跑 updater --yes
        # CREATE_NEW_CONSOLE=0x10 让用户能看到下载/校验进度;updater 结束
        # 自己会弹"更新完成"提示,用户不会错过结果。
        script = (
            "import ctypes, subprocess\n"
            "ret = ctypes.windll.user32.MessageBoxW(None, "
            f"{body!r}, {title!r}, "
            "0x4 | 0x30 | 0x40000 | 0x10000)\n"  # YESNO|WARN|TOPMOST|SETFG
            "if ret == 6:\n"  # IDYES
            f"    subprocess.Popen([{sys.executable!r}, {str(updater_script)!r}, '--yes'], "
            "creationflags=0x10)\n"
        )
        subprocess.Popen(
            [sys.executable, "-c", script],
            creationflags=0x08000000 if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
    except Exception:
        pass  # best-effort
