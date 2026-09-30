"""版本检查 — SessionStart hook 入口。

每次会话启动/恢复/清屏时由 Claude Code 调用。
拉取 manifest.json，写入本地缓存，根据版本状态提醒用户。

执行流程：
  1. 读缓存 → 缓存新鲜(<1h) → 跳过网络；过期 → 拉取 manifest(3s 超时)
  2. evaluate() 评估版本状态
  3. ok → 静默；update_available → stdout additionalContext；update_required → 弹窗+additionalContext
  4. 永远 exit 0

为什么永远 exit 0：SessionStart hook 的非零退出可能被 Claude Code 记为 hook 错误，
影响会话启动。提醒是锦上添花，阻断由 update_gate 负责。
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# 让 uplib 可以从同目录 import
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

# Windows 下 stdout 默认可能是 GBK;additionalContext 里的中文需按 UTF-8 输出,
# 否则 Claude Code 按 UTF-8 解析会乱码。
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # pragma: no cover
    pass

try:
    from uplib import (
        evaluate,
        current_version,
        manifest_url,
        fetch_manifest,
        write_cache,
        read_cache,
        spawn_update_prompt,
    )
except Exception:
    # import 失败时静默退出，不阻断会话启动
    sys.exit(0)

# 插件根目录（version_check.py 在 src/updater/ 下，往上 2 级）
_PLUGIN_ROOT = Path(__file__).resolve().parent.parent.parent

# 缓存新鲜阈值：1 小时（秒）
_CACHE_FRESH_SEC = 3600


def _output_additional_context(text: str) -> None:
    """向 stdout 输出 SessionStart additionalContext JSON。

    Claude Code 会把 additionalContext 注入到 Claude 的上下文中，
    Claude 会主动告知用户需要更新。
    """
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": text,
        }
    }
    sys.stdout.write(json.dumps(payload, ensure_ascii=False))
    sys.stdout.flush()


def _read_write_policy_context() -> str:
    """生成读写规范提示文本，注入 Claude 上下文作引导(配合 hook 硬拦截)。

    路径从 src/input/config/paths.yml 读取，不写死;读不到则退化为不含具体盘符的
    通用提示。任何异常都返回空串，调用方静默处理 —— 提示词是锦上添花，不能阻断会话。
    """
    try:
        input_cfg = _PLUGIN_ROOT / "src" / "input" / "config" / "paths.yml"
        if not input_cfg.exists():
            raise FileNotFoundError(str(input_cfg))
        import yaml  # 延迟 import,失败不影响版本检查
        data = yaml.safe_load(input_cfg.read_text(encoding="utf-8")) or {}
        workdir = (data.get("controlled_workdir") or "").strip() or "受控工作目录"
    except Exception:
        workdir = "受控工作目录"

    return (
        "[cloud-guard 读写规范]\n"
        f"- 受控工作目录:{workdir}。所有文件读写请保持在该目录内。\n"
        f"- 读取 {workdir} 外的文件(C 盘等)会被安全策略阻断;请先把文件移入 "
        f"{workdir}\\projects\\ 后再读取。\n"
        f"- 写入/编辑只允许落在 {workdir}\\output、{workdir}\\temp、"
        "D:\\After-tuomin 内,其余路径会被阻断。\n"
        "- Office 文件(.docx/.xlsx/.pptx)请用对应 skill 脱敏,不要直接 Read 原文件。\n"
        "- 不要用 Bash 的 cat / type / Get-Content 读取文件内容,统一用 Read 工具。"
    )


def main() -> int:
    try:
        policy = _read_write_policy_context()
        # 1. 读缓存
        cache = read_cache()
        now = time.time()

        should_fetch = True
        if cache is not None:
            checked_at = cache.get("checked_at", 0)
            if now - checked_at < _CACHE_FRESH_SEC:
                should_fetch = False

        # 2. 拉取 manifest（缓存过期或不存在时）
        if should_fetch:
            url = manifest_url(_PLUGIN_ROOT)
            if url:
                try:
                    manifest = fetch_manifest(url, timeout=3)
                    write_cache(manifest=manifest, fetch_error=None)
                except Exception as exc:
                    write_cache(manifest=None, fetch_error=str(exc)[:200])
            else:
                # 无法推导 URL，仍注入读写规范
                _output_additional_context(policy)
                return 0

        # 3. 评估版本状态
        cache = read_cache()
        if cache is None or "manifest" not in cache:
            # 无 manifest，也注入读写规范
            _output_additional_context(policy)
            return 0

        manifest = cache["manifest"]
        ver = current_version(_PLUGIN_ROOT)
        if not ver:
            _output_additional_context(policy)
            return 0

        status = evaluate(manifest, ver)

        # 4. 根据状态输出(版本信息 + 读写规范拼接,一次注入)
        if status == "ok":
            _output_additional_context(f"[cloud-guard] v{ver} 运行正常\n\n{policy}")
            return 0

        server_ver = manifest.get("version", "?")
        min_ver = manifest.get("min_required", "?")
        notes = manifest.get("release_notes", "")

        if status == "update_required":
            msg = (
                f"【cloud-guard 强制更新】当前插件 v{ver} 低于最低要求 v{min_ver}，"
                f"已阻断使用。请更新到 v{server_ver}。"
            )
            if notes:
                msg += f"\n更新说明：{notes}"
            # 一键更新弹窗:非阻塞(独立进程),点「是」直接启动 updater,
            # 用户无需手动找 update.cmd;也不卡 SessionStart hook。
            try:
                spawn_update_prompt(
                    ver, server_ver,
                    min_ver=min_ver, notes=notes, required=True,
                    updater_script=_PLUGIN_ROOT / "src" / "updater" / "updater.py",
                )
            except Exception:
                pass
            _output_additional_context(msg + "\n\n" + policy)

        elif status == "update_available":
            msg = (
                f"【cloud-guard 可选更新】当前插件 v{ver}，最新版本 v{server_ver}。"
                f"建议更新。"
            )
            if notes:
                msg += f"\n更新说明：{notes}"
            # 可选更新也弹出一键更新窗口：用户点击「是」即可自动更新，点击「否」稍后手动更新
            try:
                spawn_update_prompt(
                    ver, server_ver,
                    min_ver=min_ver, notes=notes, required=False,
                    updater_script=_PLUGIN_ROOT / "src" / "updater" / "updater.py",
                )
            except Exception:
                pass
            _output_additional_context(msg + "\n\n" + policy)

    except Exception:
        pass  # 任何异常都静默，不阻断会话启动

    return 0


if __name__ == "__main__":
    sys.exit(main())
