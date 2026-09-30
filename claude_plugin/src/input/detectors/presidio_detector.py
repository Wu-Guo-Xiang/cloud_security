"""Microsoft Presidio NER detector（占位）。

Step 3 暂未启用 —— 安装 presidio 后再切换实现。
当前 `detect()` 直接返回 None，dispatcher 据此跳过本 detector。

启用步骤（后续）：
  1) pip install presidio-analyzer transformers torch
  2) 下载中文 NER 模型权重至本地缓存
  3) 用 AnalyzerEngine 构造单例 + 转换 RecognizerResult → Match
  4) 把本函数体替换为真实实现
"""
from __future__ import annotations

from lib.types import Match

_ENABLED = False


def detect(text: str) -> list[Match] | None:
    if not _ENABLED:
        return None
    # TODO Step 3+: Presidio AnalyzerEngine 接入
    return []
