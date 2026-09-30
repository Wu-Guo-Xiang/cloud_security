"""
build.py —— PyInstaller onedir 打包骨架

用法:
    py -3 build.py           # 打三个 exe 到 bin/
    py -3 build.py clean     # 清理 build/ dist/ __pycache__

TODO(未实现,只是骨架):
    - 目前只做参数解析和目录准备,真跑 PyInstaller 之前需要:
      1) pip install pyinstaller
      2) 在 ../scripts/ 那份代码验证 py -3 <script>.py --event PreToolUse 单机可跑
      3) 补 --hidden-import(比如动态加载的 detectors 目录)
      4) --add-data 把 config/, skills/ 打进去

设计目标:
    - onedir(不是 onefile) —— onefile 每次启动都要解压到临时目录,首次几百 ms
      对 Claude hook 是致命延迟。onedir 直接跑,冷启动 ~50ms。
    - 三个入口分别打 —— input_scanner / output_scanner / stop_reviewer 共享
      Python 运行时会浪费空间;但独立 exe 便于分别调试和失败隔离。
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"

BIN = ROOT / "bin"
BUILD = ROOT / "build"
DIST = ROOT / "dist"

TARGETS = [
    # (entry_script,                                  exe_name)
    (SRC / "input"  / "input_scanner.py",             "input_scanner"),
    (SRC / "output" / "output_scanner.py",            "output_scanner"),
    (SRC / "output" / "stop_reviewer.py",             "stop_reviewer"),
    (SRC / "updater" / "version_check.py",            "version_check"),
    (SRC / "updater" / "updater.py",                  "updater"),
]


def clean() -> None:
    for d in (BUILD, DIST):
        if d.exists():
            shutil.rmtree(d)
            print(f"[clean] removed {d}")
    for spec in ROOT.glob("*.spec"):
        spec.unlink()
        print(f"[clean] removed {spec.name}")


def build_one(entry: Path, name: str) -> None:
    if not entry.exists():
        print(f"[skip] entry not found: {entry}", file=sys.stderr)
        return
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--onedir",
        "--name", name,
        "--distpath", str(DIST),
        "--workpath", str(BUILD),
        "--specpath", str(ROOT),
        # TODO: --add-data / --hidden-import
        str(entry),
    ]
    print(f"[build] {name}: {' '.join(cmd)}")
    subprocess.check_call(cmd)
    src_dir = DIST / name
    dst_dir = BIN / f"_{name}"
    if dst_dir.exists():
        shutil.rmtree(dst_dir)
    shutil.copytree(src_dir, dst_dir)
    exe_src = dst_dir / f"{name}.exe"
    exe_dst = BIN / f"{name}.exe"
    if exe_dst.exists():
        exe_dst.unlink()
    shutil.copy2(exe_src, exe_dst)
    print(f"[ok] {exe_dst}")


def build_all() -> None:
    BIN.mkdir(exist_ok=True)
    for entry, name in TARGETS:
        build_one(entry, name)
    print("\nDone. Push bin/ to employees together with hooks.json and .claude-plugin/.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        clean()
    else:
        build_all()
