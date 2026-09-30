"""路径配置加载器。

paths.yml 是本地测试与云桌面部署的唯一切换点；本模块负责加载与解析。
代码层通过 `from config.paths import paths; paths.controlled_workdir` 引用。
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import yaml


_CONFIG_FILE = Path(__file__).parent / "paths.yml"


@dataclass(frozen=True)
class Paths:
    controlled_workdir: Path
    security_script_dir: Path

    projects: Path
    output: Path
    temp: Path
    temp_desensitized: Path
    # skill 脱敏副本输出根(docx/pptx/xlsx skill 子进程写,固定 D:\After-tuomin)。
    # 与 temp_desensitized(内联脱敏副本)是两个目录;write_guard 只读保护两者,
    # input_scanner 递归短路只对 temp_desensitized(见 is_within_desensitized_dir)。
    skill_desensitized_dir: Path
    logs: Path
    session_cache: Path
    input_module: Path
    config_dir: Path

    write_whitelist: tuple[Path, ...] = ()
    # 读白名单(受控目录之外的额外允许读取目录,如 skill 脱敏副本所在的
    # D:\After-tuomin)。受控目录本身永远可读,不在此列。
    read_whitelist: tuple[Path, ...] = ()

    def is_within_controlled_workdir(self, path: str | Path) -> bool:
        """判断给定路径是否在受控工作目录内（用于 Hook 路径校验）。"""
        try:
            resolved = Path(path).resolve()
            root = self.controlled_workdir.resolve()
            return resolved == root or root in resolved.parents
        except (OSError, ValueError):
            return False

    def _within_any(self, path: str | Path, roots) -> bool:
        try:
            resolved = Path(path).resolve()
        except (OSError, ValueError):
            return False
        for root in roots:
            try:
                root_resolved = root.resolve()
            except (OSError, ValueError):
                continue
            if resolved == root_resolved or root_resolved in resolved.parents:
                return True
        return False

    def is_within_desensitized_dir(self, path: str | Path) -> bool:
        r"""判断路径是否落在内联脱敏副本目录下(temp_desensitized)。

        供 input_scanner 短路 Claude 改读内联副本的递归触发。
        注意:skill 副本(D:\After-tuomin)不在此判内 —— 读 skill 副本不短路,
        走完整检测作为 write_guard 的兜底。写保护见 is_within_skill_desensitized_dir。
        """
        try:
            resolved = Path(path).resolve()
            root = self.temp_desensitized.resolve()
            return resolved == root or root in resolved.parents
        except (OSError, ValueError):
            return False

    def is_within_skill_desensitized_dir(self, path: str | Path) -> bool:
        r"""判断路径是否落在 skill 脱敏副本目录(D:\After-tuomin)下,供 write_guard 拦写。

        skill 副本由 docx/pptx-redact/xlsx-redact 子进程生成(不经 write_guard),
        Claude 直接改写副本会把占位符替换回原文,击穿脱敏。write_guard 必须拦写,
        但 input_scanner 递归短路**不**用此方法 —— 读 skill 副本走完整检测(兜底)。
        """
        try:
            resolved = Path(path).resolve()
            root = self.skill_desensitized_dir.resolve()
            return resolved == root or root in resolved.parents
        except (OSError, ValueError):
            return False

    def is_within_read_whitelist(self, path: str | Path) -> bool:
        """判断是否可读:受控目录内,或读白名单(After-tuomin 副本目录)内。

        统一的"读取/列出目录"白名单判定,Read / Grep / Glob / LS 共用。
        副本目录 temp_desensitized 本身在受控目录内,天然被覆盖。
        """
        if self.is_within_controlled_workdir(path):
            return True
        return self._within_any(path, self.read_whitelist)

    def is_within_write_whitelist(self, path: str | Path) -> bool:
        """判断路径是否落在写入白名单内任意一项下（write_guard 用）。"""
        return self._within_any(path, self.write_whitelist)


def _substitute(template: str, variables: Mapping[str, str]) -> str:
    result = template
    for key, value in variables.items():
        result = result.replace("{" + key + "}", value)
    return result


def _load() -> Paths:
    if not _CONFIG_FILE.exists():
        raise FileNotFoundError(f"路径配置文件不存在: {_CONFIG_FILE}")

    with _CONFIG_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    controlled = data["controlled_workdir"]
    script = data["security_script_dir"]
    variables = {
        "controlled_workdir": controlled,
        "security_script_dir": script,
    }

    derived = data.get("derived", {}) or {}
    resolved = {key: _substitute(value, variables) for key, value in derived.items()}

    write_whitelist_raw = data.get("write_whitelist", []) or []
    write_whitelist = tuple(
        Path(_substitute(item, variables)) for item in write_whitelist_raw if item
    )

    # 读白名单(受控目录之外的额外允许读取目录)。skill 脱敏副本固定落在
    # D:\After-tuomin,默认纳入;paths.yml 可用 read_whitelist 覆盖。
    # 默认值同时包含 ~/.claude/projects(Claude auto-memory):写白名单已放行该目录,
    # 若读侧默认不含,老员工机(paths.yml 无 read_whitelist 段)会出现
    # "memory 能写不能读"的互搏。
    read_whitelist_raw = data.get("read_whitelist")
    if read_whitelist_raw is None:
        read_whitelist = (
            Path(r"D:\After-tuomin"),
            Path.home() / ".claude" / "projects",
        )
    else:
        read_whitelist = tuple(
            Path(_substitute(item, variables)) for item in read_whitelist_raw if item
        )

    # skill 脱敏副本输出根:paths.yml 可配 desensitized_output_dir,缺省 D:\After-tuomin
    # (老员工机 paths.yml 无此字段时兜底,不崩)
    skill_desensitized_dir = Path(data.get("desensitized_output_dir") or r"D:\After-tuomin")

    return Paths(
        controlled_workdir=Path(controlled),
        security_script_dir=Path(script),
        projects=Path(resolved["projects"]),
        output=Path(resolved["output"]),
        temp=Path(resolved["temp"]),
        temp_desensitized=Path(resolved["temp_desensitized"]),
        skill_desensitized_dir=skill_desensitized_dir,
        logs=Path(resolved["logs"]),
        session_cache=Path(resolved["session_cache"]),
        input_module=Path(resolved["input_module"]),
        config_dir=Path(resolved["config_dir"]),
        write_whitelist=write_whitelist,
        read_whitelist=read_whitelist,
    )


paths: Paths = _load()
