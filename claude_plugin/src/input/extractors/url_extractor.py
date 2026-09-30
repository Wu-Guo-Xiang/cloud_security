"""WebFetch 工具：抽取 URL + prompt 供敏感识别。

不在本步骤抓取 URL 内容（涉及外网请求 + 时延），仅扫描：
  - URL 本身（可能含内部域名、内部 IP、token query 参数）
  - prompt（即 Claude 要对 URL 内容做什么，常带敏感关键词）

域名白名单校验放在 Step 4 actions 层（config/url_whitelist.yml）。
"""
from __future__ import annotations

from typing import Any

from .base import ExtractResult


def extract(tool_input: dict[str, Any]) -> ExtractResult:
    url = str(tool_input.get("url", "")).strip()
    prompt = str(tool_input.get("prompt", "")).strip()

    if not url:
        return ExtractResult(skipped_reason="empty_url")

    parts = [f"url: {url}"]
    if prompt:
        parts.append(f"prompt: {prompt}")

    return ExtractResult(
        text="\n".join(parts),
        source_label=f"url:{url}",
    )
